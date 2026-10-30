// SPDX-License-Identifier: Apache-2.0
//
// synthetic_radar: stream synthetic mim:aircraft tracks into a locally running
// Ajar Core so a developer can watch the full path
// connector -> NATS -> Core -> audit + Postgres. Each tick it builds, seals and
// publishes one event per track over cnats, which only this example links.
//
// Run:
//   ./synthetic_radar                 # publish to nats://127.0.0.1:4222
//   ./synthetic_radar --dry-run       # build+seal+print, no NATS
//   ./synthetic_radar --dry-run --ticks 3   # bounded (CI)
//
// Env overrides: NATS_URL, AJAR_SOURCE_ID, AJAR_INGEST_PREFIX.

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <fstream>
#include <random>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <nats/nats.h>

#include "ajar/connector.hpp"

namespace {

// The seed file named by AJAR_SIGNING_SEED (the demo stack mints one), or an
// ephemeral seed for this run, whose events a registry refuses.
std::array<std::uint8_t, 32> load_seed() {
  std::array<std::uint8_t, 32> s{};
  if (const char* path = std::getenv("AJAR_SIGNING_SEED")) {
    std::ifstream f(path, std::ios::binary);
    if (!f.read(reinterpret_cast<char*>(s.data()), s.size()) || f.gcount() != 32)
      throw std::runtime_error("AJAR_SIGNING_SEED file must be exactly 32 bytes");
    return s;
  }
  std::fprintf(stderr, "[synthetic-radar] no AJAR_SIGNING_SEED — ephemeral throwaway key\n");
  std::random_device rd;
  for (auto& b : s) b = static_cast<std::uint8_t>(rd());
  return s;
}

// A synthetic platform moving over a region around the Gulf, matching the
// corpus fixtures. heading is in radians; speed_deg is degrees per tick.
struct Track {
  // mim:aircraft, mim:surface-vessel or mim:ground-vehicle.
  const char* entity_type;
  // friendly, hostile, neutral, or "" for unknown.
  const char* affiliation;
  const char* label;
  double lat, lon, alt_m, heading, speed_deg;
  // Per-track id, set once at startup and reused as the event id every tick so
  // a C2 (ATAK/iTAK) moves one marker per track instead of adding a contact.
  // A demo shortcut: real connectors mint a fresh id and put this in metadata.
  std::string uid;

  void advance() {
    lat += std::cos(heading) * speed_deg;
    lon += std::sin(heading) * speed_deg;
    // Bounce inside the region. A lat wall reflects the north-south component
    // (heading -> PI - heading); a lon wall the east-west one (heading -> -heading).
    if (lat < 25.0 || lat > 28.0) {
      heading = M_PI - heading;
      lat = std::max(25.0, std::min(28.0, lat));
    }
    if (lon < 49.0 || lon > 52.0) {
      heading = -heading;
      lon = std::max(49.0, std::min(52.0, lon));
    }
  }
};

std::string env_or(const char* key, const char* def) {
  const char* v = std::getenv(key);
  return (v && *v) ? std::string(v) : std::string(def);
}

}  // namespace

int main(int argc, char** argv) {
  bool dry_run = false;
  long max_ticks = 0;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--dry-run") == 0) {
      dry_run = true;
    } else if (std::strcmp(argv[i], "--ticks") == 0 && i + 1 < argc) {
      max_ticks = std::strtol(argv[++i], nullptr, 10);
    }
  }

  const std::string source_id = env_or("AJAR_SOURCE_ID", "demo-connector");
  const std::string prefix = env_or("AJAR_INGEST_PREFIX", "ajar.ingest");
  const std::string nats_url = env_or("NATS_URL", "nats://127.0.0.1:4222");

  // source_id must equal Core's AJAR_SOURCE_ID; Core's ingest listens on subject.
  const std::string subject = prefix + "." + source_id;
  const ajar::SigningKey key = ajar::SigningKey::from_seed(load_seed());

  natsConnection* conn = nullptr;
  if (dry_run) {
    std::fprintf(stderr, "[synthetic-radar] --dry-run: building + sealing events, not publishing\n");
  } else {
    std::fprintf(stderr, "[synthetic-radar] connecting to NATS at %s\n", nats_url.c_str());
    natsOptions* opts = nullptr;
    natsOptions_Create(&opts);
    natsOptions_SetURL(opts, nats_url.c_str());
    // mTLS when AJAR_TLS_CA/CERT/KEY are all set (the client-cert CN is the
    // source_id; the Helm chart mounts them under /etc/ajar/tls), else plaintext.
    const char* ca = std::getenv("AJAR_TLS_CA");
    const char* cert = std::getenv("AJAR_TLS_CERT");
    const char* keyf = std::getenv("AJAR_TLS_KEY");
    if (ca && *ca && cert && *cert && keyf && *keyf) {
      std::fprintf(stderr, "[synthetic-radar] mTLS enabled (client cert = source identity)\n");
      natsOptions_SetSecure(opts, true);
      natsOptions_LoadCATrustedCertificates(opts, ca);
      natsOptions_LoadCertificatesChain(opts, cert, keyf);
    } else {
      std::fprintf(stderr, "[synthetic-radar] no AJAR_TLS_* set — connecting without TLS (dev only)\n");
    }
    natsStatus st = natsConnection_Connect(&conn, opts);
    natsOptions_Destroy(opts);
    if (st != NATS_OK) {
      std::fprintf(stderr, "connect NATS: %s\n", natsStatus_GetText(st));
      return 1;
    }
  }

  std::fprintf(stderr,
               "[synthetic-radar] source_id=%s  subject=%s\n"
               "[synthetic-radar] multi-domain: mim:aircraft + mim:surface-vessel + "
               "mim:ground-vehicle, with an `affiliation` attribute (friendly/hostile/"
               "neutral; omitted = unknown). Core stamps received_at\n"
               "[synthetic-radar] Ctrl-C to stop.\n",
               source_id.c_str(), subject.c_str());

  // EDIT: replace this track list and the t.advance() loop below with reads
  // from your feed (socket, file, API or serial), one record per iteration.
  // Air, surface and ground tracks of mixed affiliation; AJX-02 has none, as a
  // raw sensor hit may carry no IFF.
  std::vector<Track> tracks = {
      // Air, fastest. uid is assigned below.
      {"mim:aircraft", "friendly", "AJX-01", 26.4, 50.9, 11000, 0.3 * M_PI, 0.020, {}},
      {"mim:aircraft", "", "AJX-02", 25.6, 51.4, 9500, 1.1 * M_PI, 0.018, {}},
      {"mim:aircraft", "hostile", "AJX-03", 27.2, 49.7, 12500, 1.7 * M_PI, 0.024, {}},
      // Surface vessels (sea level, slower).
      {"mim:surface-vessel", "friendly", "NAV-01", 26.0, 50.4, 0, 0.6 * M_PI, 0.010, {}},
      {"mim:surface-vessel", "neutral", "NAV-02", 25.3, 51.0, 0, 1.4 * M_PI, 0.008, {}},
      {"mim:surface-vessel", "hostile", "NAV-03", 26.8, 51.7, 0, 0.1 * M_PI, 0.011, {}},
      // Ground vehicles (near-surface, slow).
      {"mim:ground-vehicle", "friendly", "GND-01", 25.8, 49.6, 10, 0.9 * M_PI, 0.006, {}},
      {"mim:ground-vehicle", "hostile", "GND-02", 27.0, 50.2, 15, 1.9 * M_PI, 0.007, {}},
  };

  // One UUIDv7 per track, reused every tick.
  for (Track& t : tracks) {
    t.uid = ajar::EventBuilder(source_id, t.entity_type)
                .new_id()
                .now()
                .location(t.lat, t.lon, t.alt_m)
                .build()
                .id();
  }

  int rc = 0;
  for (long tick = 0;; ++tick) {
    for (Track& t : tracks) {
      t.advance();

      // 1. Normalize (synthesised here). EDIT: map one record to an Event. Use the
      // entity_type your operator registered, and add .attribute(k, v) for
      // attributes its ontology declares.
      ajar::Event event;
      try {
        ajar::EventBuilder builder(source_id, t.entity_type);
        builder.id(t.uid)
            .now()
            .location(t.lat, t.lon, t.alt_m)
            .confidence(0.9)
            .policy_tag("air-defence");
        // A track with no affiliation emits no attribute.
        if (t.affiliation && *t.affiliation) {
          builder.attribute("affiliation", t.affiliation);
        }
        event = builder.build();
      } catch (const std::exception& ex) {
        std::fprintf(stderr, "build event: %s\n", ex.what());
        rc = 1;
        break;
      }

      // 2. Seal.
      const std::string canonical = ajar::canonical_bytes(event);
      const std::vector<std::uint8_t> sealed = ajar::seal(canonical, key);

      // 3. Publish.
      if (conn != nullptr) {
        natsStatus st = natsConnection_Publish(conn, subject.c_str(), sealed.data(),
                                               static_cast<int>(sealed.size()));
        if (st != NATS_OK) {
          std::fprintf(stderr, "publish: %s\n", natsStatus_GetText(st));
          rc = 1;
          break;
        }
      }

      std::printf("%s %6s  lat=%8.4f lon=%8.4f alt=%7.0fm  -> %s (%zu sealed bytes)%s\n",
                  event.id().c_str(), t.label, t.lat, t.lon, t.alt_m, subject.c_str(),
                  sealed.size(), conn ? "" : "  [dry-run]");
    }
    if (rc != 0) break;

    // Flush before idling, and before exiting after --ticks.
    if (conn != nullptr) natsConnection_Flush(conn);

    if (max_ticks > 0 && tick + 1 >= max_ticks) break;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  if (conn != nullptr) natsConnection_Destroy(conn);
  nats_Close();
  return rc;
}
