// SPDX-License-Identifier: Apache-2.0
//
// THE gate (embedded / nanopb): the no-heap encode path must reproduce the same
// canonicalSha256 + sealedSha256 as the Rust, Go, and desktop-C++ SDKs, from the
// SAME vendor/contract/vectors.json. This harness links ONLY nanopb + the
// vendored crypto — no libprotobuf — and encodes into a fixed stack buffer with
// fully static message structs. Exit 0 iff all 12 hashes match.
//
// (The fixture reader uses std::string for convenience; the encode path under
// test — pb_encode into a stack buffer — allocates nothing on the heap.)

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "mini_json.hpp"
#include "pb_encode.h"
#include "event.pb.h"

extern "C" {
#include "monocypher-ed25519.h"
#include "sha256.h"
}

#ifndef AJAR_CONTRACT_DIR
#error "AJAR_CONTRACT_DIR must be defined"
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
  for (unsigned char b : hash) {
    out.push_back(d[b >> 4]);
    out.push_back(d[b & 0x0f]);
  }
  return out;
}

std::string hex_of(const std::uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < n; ++i) {
    out.push_back(d[p[i] >> 4]);
    out.push_back(d[p[i] & 0x0f]);
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
    return -1;
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

// Copies a JSON string into a fixed nanopb char buffer, refusing truncation.
template <std::size_t N>
void put(char (&dst)[N], const std::string& s) {
  if (s.size() + 1 > N) throw std::runtime_error("field too long for static buffer: " + s);
  std::memcpy(dst, s.data(), s.size());
  dst[s.size()] = '\0';
}

// Fills a fully static nanopb Event from a corpus fixture, verbatim.
void fixture_to_nanopb(const mini_json::Value& f, ajar_event_v1_Event& e) {
  e = ajar_event_v1_Event_init_zero;
  put(e.schema_version, f.at("schemaVersion").str);
  put(e.id, f.at("id").str);
  put(e.source_id, f.at("sourceId").str);
  put(e.entity_type, f.at("entityType").str);
  put(e.timestamp, f.at("timestamp").str);
  if (const auto* r = f.find("receivedAt")) put(e.received_at, r->str);

  if (const auto* loc = f.find("location"); loc && !loc->is_null()) {
    e.has_location = true;
    e.location.latitude = loc->at("latitude").number;
    e.location.longitude = loc->at("longitude").number;
    if (const auto* a = loc->find("altitudeM")) e.location.altitude_m = a->number;
  }
  if (const auto* p = f.find("payload")) {
    const std::string bytes = base64_decode(p->str);
    if (bytes.size() > sizeof(e.payload.bytes)) throw std::runtime_error("payload too large");
    std::memcpy(e.payload.bytes, bytes.data(), bytes.size());
    e.payload.size = static_cast<pb_size_t>(bytes.size());
  }
  if (const auto* tags = f.find("policyTags")) {
    e.policy_tags_count = 0;
    for (const auto& t : tags->array) put(e.policy_tags[e.policy_tags_count++], t.str);
  }
  if (const auto* c = f.find("confidence")) e.confidence = c->number;
  if (const auto* attrs = f.find("attributes")) {
    e.attributes_count = 0;
    for (const auto& a : attrs->array) {
      put(e.attributes[e.attributes_count].key, a.at("key").str);
      put(e.attributes[e.attributes_count].value, a.at("value").str);
      ++e.attributes_count;
    }
  }
  if (const auto* meta = f.find("metadata")) {
    e.metadata_count = 0;
    for (const auto& m : meta->array) {
      put(e.metadata[e.metadata_count].key, m.at("key").str);
      put(e.metadata[e.metadata_count].value, m.at("value").str);
      ++e.metadata_count;
    }
  }
}

}  // namespace

int main() {
  const std::string dir = AJAR_CONTRACT_DIR;
  int failures = 0;

  try {
    const mini_json::Value vectors = mini_json::parse(read_file(dir + "/vectors.json"));
    const auto seed = hex32(vectors.at("signingSeedHex").str);
    const std::string verifying_key_hex = vectors.at("verifyingKeyHex").str;

    // Derive the key once (heap-free).
    std::array<std::uint8_t, 32> seed_copy = seed;
    std::array<std::uint8_t, 64> secret_key{};
    std::array<std::uint8_t, 32> public_key{};
    crypto_ed25519_key_pair(secret_key.data(), public_key.data(), seed_copy.data());
    if (hex_of(public_key.data(), 32) != verifying_key_hex) {
      std::printf("FAIL verifying key\n");
      ++failures;
    } else {
      std::printf("ok   verifying key derives from TEST seed (nanopb path)\n");
    }

    const mini_json::Value& v = vectors.at("vectors");
    for (const auto& kv : v.object) {
      const std::string& name = kv.first;
      const std::string want_canon = kv.second.at("canonicalSha256").str;
      const std::string want_sealed = kv.second.at("sealedSha256").str;

      const mini_json::Value fixture =
          mini_json::parse(read_file(dir + "/corpus/" + name + ".json"));

      // Static struct + stack buffer: no heap on the encode path.
      ajar_event_v1_Event event;
      fixture_to_nanopb(fixture, event);

      std::uint8_t buf[512];
      pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
      if (!pb_encode(&stream, &ajar_event_v1_Event_msg, &event)) {
        std::printf("FAIL %s: pb_encode: %s\n", name.c_str(), PB_GET_ERROR(&stream));
        ++failures;
        continue;
      }
      const std::size_t len = stream.bytes_written;

      const std::string got_canon = sha256_hex(buf, len);

      // Seal: 64-byte detached signature ++ canonical bytes.
      std::uint8_t sealed[64 + 512];
      crypto_ed25519_sign(sealed, secret_key.data(), buf, len);
      std::memcpy(sealed + 64, buf, len);
      const std::string got_sealed = sha256_hex(sealed, 64 + len);

      if (got_canon != want_canon || got_sealed != want_sealed) {
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
    std::printf("\n%d embedded conformance failure(s)\n", failures);
    return 1;
  }
  std::printf("\nall embedded (nanopb) conformance vectors reproduced\n");
  return 0;
}
