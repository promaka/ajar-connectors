// SPDX-License-Identifier: Apache-2.0

#include "cot_connector.hpp"

#include <charconv>
#include <map>
#include <optional>
#include <stdexcept>

namespace cot {
namespace {

// Parses a run of key="value" XML attributes.
std::map<std::string, std::string> parse_attrs(const std::string& s) {
  std::map<std::string, std::string> m;
  std::size_t i = 0, n = s.size();
  auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
  while (i < n) {
    while (i < n && is_space(s[i])) ++i;
    std::size_t key_start = i;
    while (i < n && s[i] != '=' && !is_space(s[i])) ++i;
    if (i >= n || s[i] != '=') break;
    std::string key = s.substr(key_start, i - key_start);
    ++i;  // '='
    if (i >= n || s[i] != '"') break;
    ++i;  // opening quote
    std::size_t val_start = i;
    while (i < n && s[i] != '"') ++i;
    if (i >= n) break;
    m[key] = s.substr(val_start, i - val_start);
    ++i;  // closing quote
  }
  return m;
}

// Returns the attributes of the first <tag ...> (or <tag ... />) element.
std::optional<std::map<std::string, std::string>> tag_attrs(const std::string& xml,
                                                            const std::string& tag) {
  const std::string open = "<" + tag;
  std::size_t start = xml.find(open);
  if (start == std::string::npos) return std::nullopt;
  std::size_t after = start + open.size();
  if (after >= xml.size()) return std::nullopt;
  char c = xml[after];
  if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '>' && c != '/') return std::nullopt;
  std::size_t end = xml.find('>', after);
  if (end == std::string::npos) return std::nullopt;
  std::string attr_str = xml.substr(after, end - after);
  while (!attr_str.empty() && (attr_str.back() == '/' || attr_str.back() == ' ')) attr_str.pop_back();
  return parse_attrs(attr_str);
}

std::string cot_type_to_entity(const std::string& t) {
  if (t == "a-f-A" || t == "a-f-A-M-F-Q") return "mim:aircraft";
  if (t == "a-f-S") return "mim:vessel";
  if (t == "a-f-G-U-C-D") return "mim:drone";
  std::string slug = t;
  for (char& ch : slug)
    if (ch == '-') ch = '_';
  return "x:cot:" + slug;
}

std::string entity_to_cot(const std::string& e) {
  if (e == "mim:aircraft") return "a-f-A";
  if (e == "mim:vessel") return "a-f-S";
  if (e == "mim:drone") return "a-f-G-U-C-D";
  if (e.rfind("x:cot:", 0) == 0) {
    std::string slug = e.substr(6);
    for (char& ch : slug)
      if (ch == '_') ch = '-';
    return slug;
  }
  return "a-u-G";
}

// Shortest round-trippable double, so location survives canonical -> CoT -> canonical.
std::string fmt_double(double v) {
  char buf[32];
  auto res = std::to_chars(buf, buf + sizeof(buf), v);
  return std::string(buf, res.ptr);
}

}  // namespace

ajar::Event CotConnector::normalize(const std::string& native) const {
  auto event_attrs = tag_attrs(native, "event");
  if (!event_attrs) throw std::runtime_error("malformed CoT: no <event>");
  auto need = [&](const char* k) -> const std::string& {
    auto it = event_attrs->find(k);
    if (it == event_attrs->end()) throw std::runtime_error(std::string("malformed CoT: event/@") + k);
    return it->second;
  };

  ajar::EventBuilder b(source_id_, cot_type_to_entity(need("type")));
  b.id(need("uid")).timestamp(need("time"));

  if (auto point = tag_attrs(native, "point")) {
    auto lat = point->find("lat");
    auto lon = point->find("lon");
    if (lat != point->end() && lon != point->end()) {
      double hae = 0.0;
      if (auto h = point->find("hae"); h != point->end()) hae = std::strtod(h->second.c_str(), nullptr);
      b.location(std::strtod(lat->second.c_str(), nullptr),
                 std::strtod(lon->second.c_str(), nullptr), hae);
    }
  }
  return b.build();
}

std::string CotConnector::render(const ajar::Event& event) const {
  const std::string cot_type = entity_to_cot(event.entity_type());
  double lat = 0, lon = 0, hae = 0;
  if (event.has_location()) {
    lat = event.location().latitude();
    lon = event.location().longitude();
    hae = event.location().altitude_m();
  }
  std::string out = "<event version=\"2.0\" uid=\"" + event.id() + "\" type=\"" + cot_type +
                    "\" time=\"" + event.timestamp() + "\" start=\"" + event.timestamp() +
                    "\" stale=\"" + event.timestamp() + "\">" + "<point lat=\"" + fmt_double(lat) +
                    "\" lon=\"" + fmt_double(lon) + "\" hae=\"" + fmt_double(hae) +
                    "\" ce=\"9999999.0\" le=\"9999999.0\"/>" + "</event>";
  return out;
}

}  // namespace cot
