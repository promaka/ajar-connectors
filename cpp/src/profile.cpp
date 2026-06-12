// SPDX-License-Identifier: Apache-2.0

#include "ajar/connector.hpp"

#include <charconv>
#include <cstdio>
#include <sstream>

namespace ajar {
namespace {

std::string hex_encode(const std::array<std::uint8_t, 32>& bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (std::uint8_t b : bytes) {
    out.push_back(digits[b >> 4]);
    out.push_back(digits[b & 0x0f]);
  }
  return out;
}

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c);
    }
  }
  return out;
}

// Shortest round-trippable double, with a trailing ".0" for integer values, to
// match the Rust (serde/ryu) and Go (normalized) profile JSON byte-for-byte.
std::string json_number(double v) {
  char buf[32];
  auto res = std::to_chars(buf, buf + sizeof(buf), v);
  std::string s(buf, res.ptr);
  if (s.find_first_of(".eE") == std::string::npos) s += ".0";
  return s;
}

}  // namespace

ConnectorProfile::ConnectorProfile(std::string source_id,
                                   std::array<std::uint8_t, 32> verifying_key)
    : source_id_(std::move(source_id)), verifying_key_(verifying_key) {}

ConnectorProfile& ConnectorProfile::allow_entity_type(std::string entity_type) {
  allowed_entity_types_.push_back(std::move(entity_type));
  return *this;
}
ConnectorProfile& ConnectorProfile::max_payload_bytes(std::uint64_t max) {
  max_payload_bytes_ = max;
  return *this;
}
ConnectorProfile& ConnectorProfile::rate_limit(std::uint32_t capacity, double refill_per_sec) {
  rate_capacity_ = capacity;
  rate_refill_per_sec_ = refill_per_sec;
  return *this;
}

std::string ConnectorProfile::to_json() const {
  std::ostringstream o;
  o << "{\"source_id\":\"" << json_escape(source_id_) << "\",\"allowed_entity_types\":[";
  for (std::size_t i = 0; i < allowed_entity_types_.size(); ++i) {
    if (i) o << ',';
    o << '"' << json_escape(allowed_entity_types_[i]) << '"';
  }
  o << "],\"max_payload_bytes\":" << max_payload_bytes_
    << ",\"rate_capacity\":" << rate_capacity_
    << ",\"rate_refill_per_sec\":" << json_number(rate_refill_per_sec_)
    << ",\"verifying_key_hex\":\"" << hex_encode(verifying_key_) << "\"}";
  return o.str();
}

std::string ConnectorProfile::to_json_pretty() const {
  std::ostringstream o;
  o << "{\n  \"source_id\": \"" << json_escape(source_id_) << "\",\n";
  o << "  \"allowed_entity_types\": [";
  if (allowed_entity_types_.empty()) {
    o << ']';
  } else {
    o << '\n';
    for (std::size_t i = 0; i < allowed_entity_types_.size(); ++i) {
      o << "    \"" << json_escape(allowed_entity_types_[i]) << '"';
      o << (i + 1 < allowed_entity_types_.size() ? ",\n" : "\n");
    }
    o << "  ]";
  }
  o << ",\n  \"max_payload_bytes\": " << max_payload_bytes_
    << ",\n  \"rate_capacity\": " << rate_capacity_
    << ",\n  \"rate_refill_per_sec\": " << json_number(rate_refill_per_sec_)
    << ",\n  \"verifying_key_hex\": \"" << hex_encode(verifying_key_) << "\"\n}";
  return o.str();
}

}  // namespace ajar
