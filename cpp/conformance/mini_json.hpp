// SPDX-License-Identifier: Apache-2.0
//
// A compact, dependency-free JSON reader for the conformance harness only — it
// parses the vendored vectors.json and corpus fixtures. It is intentionally
// small and auditable rather than a general-purpose library; numbers are parsed
// with strtod (correct nearest double, matching serde_json / encoding/json).

#ifndef AJAR_MINI_JSON_HPP
#define AJAR_MINI_JSON_HPP

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mini_json {

struct Value {
  enum class Type { Null, Bool, Number, String, Array, Object };
  Type type = Type::Null;
  bool boolean = false;
  double number = 0.0;
  std::string str;
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> object;

  bool is_null() const { return type == Type::Null; }
  const Value* find(const std::string& key) const {
    for (const auto& kv : object)
      if (kv.first == key) return &kv.second;
    return nullptr;
  }
  const Value& at(const std::string& key) const {
    if (const Value* v = find(key)) return *v;
    throw std::runtime_error("json: missing key '" + key + "'");
  }
};

class Parser {
 public:
  explicit Parser(const std::string& src) : s_(src) {}

  Value parse() {
    skip_ws();
    Value v = parse_value();
    skip_ws();
    if (i_ != s_.size()) throw std::runtime_error("json: trailing data");
    return v;
  }

 private:
  const std::string& s_;
  std::size_t i_ = 0;

  [[noreturn]] void fail(const char* msg) {
    throw std::runtime_error(std::string("json: ") + msg + " at offset " + std::to_string(i_));
  }
  void skip_ws() {
    while (i_ < s_.size()) {
      char c = s_[i_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        ++i_;
      else
        break;
    }
  }
  char peek() { return i_ < s_.size() ? s_[i_] : '\0'; }

  Value parse_value() {
    skip_ws();
    char c = peek();
    switch (c) {
      case '{': return parse_object();
      case '[': return parse_array();
      case '"': {
        Value v;
        v.type = Value::Type::String;
        v.str = parse_string();
        return v;
      }
      case 't': case 'f': return parse_bool();
      case 'n': return parse_null();
      default: return parse_number();
    }
  }

  Value parse_object() {
    Value v;
    v.type = Value::Type::Object;
    ++i_;  // '{'
    skip_ws();
    if (peek() == '}') { ++i_; return v; }
    while (true) {
      skip_ws();
      if (peek() != '"') fail("expected string key");
      std::string key = parse_string();
      skip_ws();
      if (peek() != ':') fail("expected ':'");
      ++i_;
      Value val = parse_value();
      v.object.emplace_back(std::move(key), std::move(val));
      skip_ws();
      char c = peek();
      if (c == ',') { ++i_; continue; }
      if (c == '}') { ++i_; break; }
      fail("expected ',' or '}'");
    }
    return v;
  }

  Value parse_array() {
    Value v;
    v.type = Value::Type::Array;
    ++i_;  // '['
    skip_ws();
    if (peek() == ']') { ++i_; return v; }
    while (true) {
      v.array.push_back(parse_value());
      skip_ws();
      char c = peek();
      if (c == ',') { ++i_; continue; }
      if (c == ']') { ++i_; break; }
      fail("expected ',' or ']'");
    }
    return v;
  }

  std::string parse_string() {
    ++i_;  // opening quote
    std::string out;
    while (i_ < s_.size()) {
      char c = s_[i_++];
      if (c == '"') return out;
      if (c == '\\') {
        if (i_ >= s_.size()) fail("unterminated escape");
        char e = s_[i_++];
        switch (e) {
          case '"': out.push_back('"'); break;
          case '\\': out.push_back('\\'); break;
          case '/': out.push_back('/'); break;
          case 'b': out.push_back('\b'); break;
          case 'f': out.push_back('\f'); break;
          case 'n': out.push_back('\n'); break;
          case 'r': out.push_back('\r'); break;
          case 't': out.push_back('\t'); break;
          case 'u': out += parse_unicode_escape(); break;
          default: fail("bad escape");
        }
      } else {
        out.push_back(c);  // raw byte (UTF-8 passes through verbatim)
      }
    }
    fail("unterminated string");
  }

  std::string parse_unicode_escape() {
    auto hex4 = [&]() -> unsigned {
      if (i_ + 4 > s_.size()) fail("short \\u escape");
      unsigned v = 0;
      for (int k = 0; k < 4; ++k) {
        char c = s_[i_++];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A' + 10);
        else fail("bad hex digit");
      }
      return v;
    };
    unsigned cp = hex4();
    if (cp >= 0xD800 && cp <= 0xDBFF) {  // high surrogate
      if (s_[i_] == '\\' && s_[i_ + 1] == 'u') {
        i_ += 2;
        unsigned lo = hex4();
        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
      }
    }
    std::string out;
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
  }

  Value parse_bool() {
    Value v;
    v.type = Value::Type::Bool;
    if (s_.compare(i_, 4, "true") == 0) { v.boolean = true; i_ += 4; }
    else if (s_.compare(i_, 5, "false") == 0) { v.boolean = false; i_ += 5; }
    else fail("bad literal");
    return v;
  }

  Value parse_null() {
    if (s_.compare(i_, 4, "null") != 0) fail("bad literal");
    i_ += 4;
    return Value{};
  }

  Value parse_number() {
    std::size_t start = i_;
    while (i_ < s_.size()) {
      char c = s_[i_];
      if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E')
        ++i_;
      else
        break;
    }
    if (i_ == start) fail("invalid value");
    Value v;
    v.type = Value::Type::Number;
    v.number = std::strtod(s_.c_str() + start, nullptr);
    return v;
  }
};

inline Value parse(const std::string& src) { return Parser(src).parse(); }

}  // namespace mini_json

#endif  // AJAR_MINI_JSON_HPP
