// SPDX-License-Identifier: Apache-2.0

#include "ajar/connector.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <random>

namespace ajar {
namespace {

// True if entity_type follows mim:<type> or x:<vendor>:<type>.
bool is_namespaced(const std::string& e) {
  if (e.rfind("mim:", 0) == 0) {
    const std::string rest = e.substr(4);
    return !rest.empty() && rest.find(':') == std::string::npos;
  }
  if (e.rfind("x:", 0) == 0) {
    const std::string rest = e.substr(2);
    const auto colon = rest.find(':');
    if (colon == std::string::npos) return false;
    const std::string vendor = rest.substr(0, colon);
    const std::string ty = rest.substr(colon + 1);
    return !vendor.empty() && !ty.empty() && ty.find(':') == std::string::npos;
  }
  return false;
}

// A UUIDv7 string: 48-bit ms timestamp + version/variant + random.
std::string new_uuid_v7() {
  std::array<std::uint8_t, 16> b{};
  const auto now = std::chrono::system_clock::now();
  const std::uint64_t ms = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
  b[0] = static_cast<std::uint8_t>(ms >> 40);
  b[1] = static_cast<std::uint8_t>(ms >> 32);
  b[2] = static_cast<std::uint8_t>(ms >> 24);
  b[3] = static_cast<std::uint8_t>(ms >> 16);
  b[4] = static_cast<std::uint8_t>(ms >> 8);
  b[5] = static_cast<std::uint8_t>(ms);

  std::random_device rd;
  for (std::size_t i = 6; i < b.size(); ++i) b[i] = static_cast<std::uint8_t>(rd());
  b[6] = static_cast<std::uint8_t>((b[6] & 0x0f) | 0x70);  // version 7
  b[8] = static_cast<std::uint8_t>((b[8] & 0x3f) | 0x80);  // RFC 4122 variant

  char out[37];
  std::snprintf(out, sizeof(out),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                b[12], b[13], b[14], b[15]);
  return std::string(out);
}

std::string rfc3339_now() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  char out[32];
  std::strftime(out, sizeof(out), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(out);
}

}  // namespace

EventBuilder::EventBuilder(std::string source_id, std::string entity_type)
    : source_id_(std::move(source_id)), entity_type_(std::move(entity_type)) {}

EventBuilder& EventBuilder::id(std::string id) {
  id_ = std::move(id);
  return *this;
}
EventBuilder& EventBuilder::new_id() {
  id_ = new_uuid_v7();
  return *this;
}
EventBuilder& EventBuilder::timestamp(std::string ts) {
  timestamp_ = std::move(ts);
  return *this;
}
EventBuilder& EventBuilder::now() {
  timestamp_ = rfc3339_now();
  return *this;
}
EventBuilder& EventBuilder::location(double latitude, double longitude, double altitude_m) {
  has_location_ = true;
  lat_ = latitude;
  lon_ = longitude;
  alt_ = altitude_m;
  return *this;
}
EventBuilder& EventBuilder::payload(std::string bytes) {
  payload_ = std::move(bytes);
  return *this;
}
EventBuilder& EventBuilder::policy_tag(std::string tag) {
  policy_tags_.push_back(std::move(tag));
  return *this;
}
EventBuilder& EventBuilder::confidence(double confidence) {
  confidence_ = confidence;
  return *this;
}
EventBuilder& EventBuilder::metadata(std::string key, std::string value) {
  metadata_.emplace_back(std::move(key), std::move(value));
  return *this;
}

EventBuilder& EventBuilder::attribute(std::string key, std::string value) {
  attributes_.emplace_back(std::move(key), std::move(value));
  return *this;
}
EventBuilder& EventBuilder::allow_unnamespaced_entity_type() {
  strict_entity_namespace_ = false;
  return *this;
}

Event EventBuilder::build() const {
  if (id_.empty()) throw BuildError("missing required field: id");
  if (timestamp_.empty()) throw BuildError("missing required field: timestamp");
  if (source_id_.empty()) throw BuildError("missing required field: source_id");
  if (entity_type_.empty()) throw BuildError("missing required field: entity_type");
  if (strict_entity_namespace_ && !is_namespaced(entity_type_)) {
    throw BuildError("entity_type '" + entity_type_ +
                     "' is not namespaced as mim:<type> or x:<vendor>:<type>");
  }
  if (confidence_ < 0.0 || confidence_ > 1.0) {
    throw BuildError("confidence " + std::to_string(confidence_) + " is outside [0.0, 1.0]");
  }
  if (policy_tags_.size() > kMaxPolicyTags) {
    throw BuildError("too many policy tags: " + std::to_string(policy_tags_.size()));
  }
  if (attributes_.size() > kMaxAttributes) {
    throw BuildError("too many attributes: " + std::to_string(attributes_.size()));
  }
  if (metadata_.size() > kMaxMetadata) {
    throw BuildError("too many metadata entries: " + std::to_string(metadata_.size()));
  }

  // Canonical rule: attributes sorted by key, unique.
  auto attrs = attributes_;
  std::stable_sort(attrs.begin(), attrs.end(),
                   [](const auto& a, const auto& b) { return a.first < b.first; });
  for (std::size_t i = 1; i < attrs.size(); ++i) {
    if (attrs[i].first == attrs[i - 1].first) {
      throw BuildError("duplicate attribute key: " + attrs[i].first);
    }
  }

  // Metadata follows the identical canonical rule: sorted by key, unique.
  auto meta = metadata_;
  std::stable_sort(meta.begin(), meta.end(),
                   [](const auto& a, const auto& b) { return a.first < b.first; });
  for (std::size_t i = 1; i < meta.size(); ++i) {
    if (meta[i].first == meta[i - 1].first) {
      throw BuildError("duplicate metadata key: " + meta[i].first);
    }
  }

  Event e;
  e.set_schema_version("v1");
  e.set_id(id_);
  e.set_source_id(source_id_);
  e.set_entity_type(entity_type_);
  e.set_timestamp(timestamp_);
  // received_at intentionally left empty — Ajar stamps its own clock.
  if (has_location_) {
    GeoPoint* g = e.mutable_location();
    g->set_latitude(lat_);
    g->set_longitude(lon_);
    g->set_altitude_m(alt_);
  }
  e.set_payload(payload_);
  for (const auto& tag : policy_tags_) e.add_policy_tags(tag);
  e.set_confidence(confidence_);
  for (const auto& kv : attrs) {
    Attribute* a = e.add_attributes();
    a->set_key(kv.first);
    a->set_value(kv.second);
  }
  for (const auto& kv : meta) {
    Attribute* m = e.add_metadata();
    m->set_key(kv.first);
    m->set_value(kv.second);
  }
  return e;
}

}  // namespace ajar
