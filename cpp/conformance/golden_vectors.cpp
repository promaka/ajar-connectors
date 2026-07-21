// SPDX-License-Identifier: Apache-2.0
//
// THE gate (C++): for every corpus fixture, reproduce the same canonicalSha256
// + sealedSha256 the Rust and Go SDKs do, from the SAME
// vendor/contract/vectors.json. Exit 0 iff all 12 hashes match.

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ajar/connector.hpp"
#include "mini_json.hpp"

extern "C" {
#include "sha256.h"
}

#ifndef AJAR_CONTRACT_DIR
#error "AJAR_CONTRACT_DIR must be defined (path to vendor/contract)"
#endif

namespace {

std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("cannot open " + path);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::string sha256_hex(const std::uint8_t* data, std::size_t len) {
  SHA256_CTX ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  std::uint8_t hash[SHA256_BLOCK_SIZE];
  sha256_final(&ctx, hash);
  static const char* d = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (unsigned char b : hash) {
    out.push_back(d[b >> 4]);
    out.push_back(d[b & 0x0f]);
  }
  return out;
}

std::array<std::uint8_t, 32> hex32(const std::string& hex) {
  std::array<std::uint8_t, 32> out{};
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error("bad hex");
  };
  for (std::size_t i = 0; i < 32; ++i)
    out[i] = static_cast<std::uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
  return out;
}

std::string base64_decode(const std::string& in) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;  // '=' or padding
  };
  std::string out;
  int buf = 0, bits = 0;
  for (char c : in) {
    int v = val(c);
    if (v < 0) continue;
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xFF));
    }
  }
  return out;
}

// Build a canonical Event from a corpus fixture JSON, verbatim (including
// received_at, which a live connector leaves for Ajar to stamp) — bypassing
// EventBuilder so byte-exact replay uses the raw fixture values.
ajar::Event fixture_to_event(const mini_json::Value& f) {
  ajar::Event e;
  e.set_schema_version(f.at("schemaVersion").str);
  e.set_id(f.at("id").str);
  e.set_source_id(f.at("sourceId").str);
  e.set_entity_type(f.at("entityType").str);
  e.set_timestamp(f.at("timestamp").str);
  if (const auto* r = f.find("receivedAt")) e.set_received_at(r->str);
  if (const auto* loc = f.find("location"); loc && !loc->is_null()) {
    ajar::GeoPoint* g = e.mutable_location();
    g->set_latitude(loc->at("latitude").number);
    g->set_longitude(loc->at("longitude").number);
    if (const auto* a = loc->find("altitudeM")) g->set_altitude_m(a->number);
  }
  if (const auto* p = f.find("payload")) e.set_payload(base64_decode(p->str));
  if (const auto* tags = f.find("policyTags"))
    for (const auto& t : tags->array) e.add_policy_tags(t.str);
  if (const auto* c = f.find("confidence")) e.set_confidence(c->number);
  if (const auto* attrs = f.find("attributes")) {
    for (const auto& a : attrs->array) {
      ajar::Attribute* out = e.add_attributes();
      out->set_key(a.at("key").str);
      out->set_value(a.at("value").str);
    }
  }
  if (const auto* meta = f.find("metadata")) {
    for (const auto& m : meta->array) {
      ajar::Attribute* out = e.add_metadata();
      out->set_key(m.at("key").str);
      out->set_value(m.at("value").str);
    }
  }
  return e;
}

}  // namespace

int main() {
  const std::string dir = AJAR_CONTRACT_DIR;
  int failures = 0;

  try {
    const mini_json::Value vectors = mini_json::parse(read_file(dir + "/vectors.json"));
    const std::string seed_hex = vectors.at("signingSeedHex").str;
    const std::string verifying_key_hex = vectors.at("verifyingKeyHex").str;

    const auto seed = hex32(seed_hex);
    const ajar::SigningKey key = ajar::SigningKey::from_seed(seed);

    // 1. verifying key derives from the TEST seed.
    std::string got_vk;
    {
      static const char* d = "0123456789abcdef";
      for (std::uint8_t b : key.verifying_key()) {
        got_vk.push_back(d[b >> 4]);
        got_vk.push_back(d[b & 0x0f]);
      }
    }
    if (got_vk != verifying_key_hex) {
      std::printf("FAIL verifying key: got %s want %s\n", got_vk.c_str(),
                  verifying_key_hex.c_str());
      ++failures;
    } else {
      std::printf("ok   verifying key derives from TEST seed\n");
    }

    // 2. each fixture: canonical + sealed hashes.
    const mini_json::Value& v = vectors.at("vectors");
    for (const auto& kv : v.object) {
      const std::string& name = kv.first;
      const std::string want_canon = kv.second.at("canonicalSha256").str;
      const std::string want_sealed = kv.second.at("sealedSha256").str;

      const mini_json::Value fixture =
          mini_json::parse(read_file(dir + "/corpus/" + name + ".json"));
      const ajar::Event event = fixture_to_event(fixture);

      const std::string canonical = ajar::canonical_bytes(event);
      const std::string got_canon =
          sha256_hex(reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size());

      const std::vector<std::uint8_t> sealed = ajar::seal(canonical, key);
      const std::string got_sealed = sha256_hex(sealed.data(), sealed.size());

      bool ok = (got_canon == want_canon) && (got_sealed == want_sealed);
      if (!ok) {
        ++failures;
        std::printf("FAIL %s\n  canonical got %s\n           want %s\n  sealed    got %s\n"
                    "           want %s\n",
                    name.c_str(), got_canon.c_str(), want_canon.c_str(), got_sealed.c_str(),
                    want_sealed.c_str());
      } else {
        std::printf("ok   %s\n", name.c_str());
      }
    }
  } catch (const std::exception& ex) {
    std::printf("ERROR: %s\n", ex.what());
    return 2;
  }

  if (failures) {
    std::printf("\n%d conformance failure(s)\n", failures);
    return 1;
  }
  std::printf("\nall conformance vectors reproduced\n");
  return 0;
}
