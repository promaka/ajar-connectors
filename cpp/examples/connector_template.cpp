// SPDX-License-Identifier: Apache-2.0
//
// Connector template (C++): a copy-me starting point for a new Ajar connector.
// Make the two edits marked EDIT 1 and EDIT 2, then build and run.
//
// Build (from the repo root):
//   cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release && cmake --build cpp/build -j
//
// Print a sealed event without a key, NATS or a feed. The demo input is one
// record per line, "lat lon alt_m quality":
//   echo "26.4 50.9 11000 0.9" | ./cpp/build/connector_template --dry-run
//
// Run against NATS (key from scripts/gen-connector-key.sh; mTLS materials and
// endpoint from your operator). Publishing needs the cnats client, detected by
// CMake; without it the binary only runs in --dry-run:
//   AJAR_TLS_CA=ca.pem AJAR_TLS_CERT=client.pem AJAR_TLS_KEY=client.key \
//   AJAR_SIGNING_SEED=connector.seed AJAR_SOURCE_ID=acme-radar-1 \
//   NATS_URL=tls://nats.you.mil:443  ./cpp/build/connector_template
//
// A malformed or unmappable record is logged and skipped, so one bad input cannot
// stop the connector.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "ajar/connector.hpp"
#ifdef AJAR_WITH_NATS
#include <nats/nats.h>
#endif

namespace {

// EDIT 1: one record from your feed and how to parse a line of it.
struct MyRecord {
  double lat = 0, lon = 0, alt_m = 0, quality = 0;
};

bool parse_record(const std::string& line, MyRecord& out) {
  std::istringstream is(line);
  return static_cast<bool>(is >> out.lat >> out.lon >> out.alt_m >> out.quality);
}

// EDIT 2: map a record to an Event. Use the entity_type your operator assigned,
// and add .attribute(k, v) for attributes its ontology declares.
ajar::Event to_event(const std::string& source_id, const MyRecord& r) {
  return ajar::EventBuilder(source_id, "mim:aircraft")
      .new_id()
      .now()
      .location(r.lat, r.lon, r.alt_m)
      .confidence(r.quality)
      .build();
}

std::string env_or(const char* key, const char* def) {
  const char* v = std::getenv(key);
  return (v && *v) ? std::string(v) : std::string(def);
}

// Loads the seed from the file named by AJAR_SIGNING_SEED; in --dry-run with
// none set, mints a random ephemeral seed.
std::array<std::uint8_t, 32> load_seed(bool dry_run) {
  const char* path = std::getenv("AJAR_SIGNING_SEED");
  if (path && *path) {
    std::ifstream f(path, std::ios::binary);
    std::array<std::uint8_t, 32> seed{};
    if (!f.read(reinterpret_cast<char*>(seed.data()), seed.size()) || f.gcount() != 32)
      throw std::runtime_error("signing seed file must be exactly 32 bytes");
    return seed;
  }
  if (dry_run) {
    std::fprintf(stderr, "[connector] no AJAR_SIGNING_SEED set — ephemeral throwaway key (dry-run only)\n");
    std::array<std::uint8_t, 32> seed{};
    std::random_device rd;
    for (auto& b : seed) b = static_cast<std::uint8_t>(rd());
    return seed;
  }
  throw std::runtime_error("set AJAR_SIGNING_SEED to your 32-byte seed file (see scripts/gen-connector-key.sh)");
}

}  // namespace

// Usually no edits are needed below here.

int main(int argc, char** argv) {
  bool dry_run = false;
  bool check_only = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--dry-run") == 0) dry_run = true;
    if (std::strcmp(argv[i], "--check") == 0) check_only = true;
  }

  // --check validates what to_event builds against the vendored ontology and
  // exits, with no key, feed or network; run it in CI.
  if (check_only) {
    const ajar::Event probe = to_event("check", MyRecord{});
    const auto faults = ajar::validate(probe);
    for (const auto& f : faults)
      std::fprintf(stderr, "[check] %s\n", f.message().c_str());
    std::fprintf(stderr, "[check] %s against ontology %s\n",
                 faults.empty() ? "mapping is clean" : "mapping has faults",
                 ajar::ontology_version());
    return faults.empty() ? 0 : 1;
  }

  const std::string source_id = env_or("AJAR_SOURCE_ID", "demo-connector");
  const std::string prefix = env_or("AJAR_INGEST_PREFIX", "ajar.ingest");
  const std::string nats_url = env_or("NATS_URL", "nats://127.0.0.1:4222");
  const std::string subject = prefix + "." + source_id;

  ajar::SigningKey key = ajar::SigningKey::from_seed(load_seed(dry_run));

#ifdef AJAR_WITH_NATS
  natsConnection* conn = nullptr;
  if (!dry_run) {
    std::fprintf(stderr, "[connector] connecting to NATS at %s\n", nats_url.c_str());
    natsOptions* opts = nullptr;
    natsOptions_Create(&opts);
    natsOptions_SetURL(opts, nats_url.c_str());
    // mTLS when AJAR_TLS_CA/CERT/KEY are all set, else plaintext.
    const char* ca = std::getenv("AJAR_TLS_CA");
    const char* cert = std::getenv("AJAR_TLS_CERT");
    const char* keyf = std::getenv("AJAR_TLS_KEY");
    if (ca && *ca && cert && *cert && keyf && *keyf) {
      std::fprintf(stderr, "[connector] mTLS enabled (client cert = source identity)\n");
      natsOptions_SetSecure(opts, true);
      natsOptions_LoadCATrustedCertificates(opts, ca);
      natsOptions_LoadCertificatesChain(opts, cert, keyf);
    } else {
      std::fprintf(stderr, "[connector] no AJAR_TLS_* set — connecting without TLS (dev only)\n");
    }
    natsStatus st = natsConnection_Connect(&conn, opts);
    natsOptions_Destroy(opts);
    if (st != NATS_OK) {
      std::fprintf(stderr, "connect NATS: %s\n", natsStatus_GetText(st));
      return 1;
    }
  }
#else
  if (!dry_run) {
    std::fprintf(stderr, "built without the NATS client — rebuild with cnats to publish, or use --dry-run\n");
    return 1;
  }
#endif

  std::fprintf(stderr, "[connector] source_id=%s  subject=%s%s\n", source_id.c_str(),
               subject.c_str(), dry_run ? "  [dry-run]" : "");

  // EDIT: the feed is one record per line on stdin; swap this loop for your
  // socket, file, API or serial port.
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.empty()) continue;
    MyRecord rec;
    if (!parse_record(line, rec)) {
      std::fprintf(stderr, "[connector] skip: malformed record: %s\n", line.c_str());
      continue;
    }
    ajar::Event event;
    try {
      event = to_event(source_id, rec);
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "[connector] skip: cannot map record: %s\n", ex.what());
      continue;
    }
    const std::string canonical = ajar::canonical_bytes(event);
    const std::vector<std::uint8_t> sealed = ajar::seal(canonical, key);
#ifdef AJAR_WITH_NATS
    if (conn) {
      natsStatus st = natsConnection_Publish(conn, subject.c_str(), sealed.data(),
                                             static_cast<int>(sealed.size()));
      if (st != NATS_OK) {
        std::fprintf(stderr, "[connector] publish error (continuing): %s\n", natsStatus_GetText(st));
        continue;
      }
    }
#endif
    std::printf("%s -> %s (%zu sealed bytes)%s\n", event.id().c_str(), subject.c_str(),
                sealed.size(), dry_run ? "  [dry-run]" : "");
  }

#ifdef AJAR_WITH_NATS
  if (conn) {
    natsConnection_Flush(conn);
    natsConnection_Destroy(conn);
  }
#endif
  return 0;
}
