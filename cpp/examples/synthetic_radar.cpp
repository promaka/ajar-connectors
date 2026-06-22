// SPDX-License-Identifier: Apache-2.0
//
// synthetic_radar: stream synthetic mim:aircraft tracks into a locally running
// Ajar Core so a developer can watch the full path
// connector -> NATS -> Core -> audit + Postgres.
//
// The shape every connector follows is the three steps in the loop below:
//   1. normalize a native observation into a canonical Event (here we synthesise
//      it; a real radar connector would parse a vendor frame),
//   2. seal it (detached Ed25519 signature ++ canonical bytes),
//   3. publish the sealed bytes to the connector's NATS ingest subject.
//
// This is a clearly-marked example: it carries a dev-only signing seed and picks
// a transport (NATS, via the real nats.c / cnats client). The SDK itself stays
// transport-free — the NATS client is linked only into this example.
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
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <nats/nats.h>

#include "ajar/connector.hpp"

namespace {

// Dev-only signing seed: 32 bytes of 0x03. Matches the default Core's registered
// dev connector profile, so the local demo's signatures are accepted with zero
// core changes. Documented TEST seed (cf. golden 0x47) — never production.
std::array<std::uint8_t, 32> dev_seed() {
  std::array<std::uint8_t, 32> s{};
  s.fill(0x03);
  return s;
}

// A synthetic platform moving over a region (around the Gulf, matching the
// corpus fixtures). `entity_type` is a canonical MIM type the seed ontology
// already knows (air / surface / ground), so a mixed multi-domain picture flows
// through with no ontology change. heading in radians; speed_deg is deg per tick.
struct Track {
  const char* entity_type;  // mim:aircraft | mim:surface-vessel | mim:ground-vehicle
  const char* affiliation;  // friendly | hostile | neutral | "" (unknown)
  const char* label;
  double lat, lon, alt_m, heading, speed_deg;
  // Stable per-track id (set once at startup). Reused as the event id every tick
  // so a C2 (ATAK/iTAK) updates ONE moving marker per track instead of piling up
  // a new contact each tick. (A production connector would model the track id as
  // a dedicated attribute; here we reuse the event id for a clean demo picture.)
  std::string uid;

  void advance() {
    lat += std::cos(heading) * speed_deg;
    lon += std::sin(heading) * speed_deg;
    // Bounce inside the region lat [25, 28], lon [49, 52]. A horizontal (lat) wall
    // reflects the north-south component (heading -> PI - heading); a vertical
    // (lon) wall reflects the east-west component (heading -> -heading).
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

  // source must equal the Core's AJAR_SOURCE_ID; the subject is the one the
  // Core's ingest is listening on.
  const std::string subject = prefix + "." + source_id;
  const ajar::SigningKey key = ajar::SigningKey::from_seed(dev_seed());

  // Connect the real NATS client (skipped in --dry-run, which needs no infra).
  natsConnection* conn = nullptr;
  if (dry_run) {
    std::fprintf(stderr, "[synthetic-radar] --dry-run: building + sealing events, not publishing\n");
  } else {
    std::fprintf(stderr, "[synthetic-radar] connecting to NATS at %s\n", nats_url.c_str());
    natsOptions* opts = nullptr;
    natsOptions_Create(&opts);
    natsOptions_SetURL(opts, nats_url.c_str());
    // mTLS when AJAR_TLS_CA/CERT/KEY are all set (production; client-cert
    // CN = source_id, mounted by the Helm chart under /etc/ajar/tls). Unset ->
    // plaintext for local dev.
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

  // A mixed multi-domain picture: air, surface, and ground over the Gulf. All
  // three types exist in the seed ontology, so this flows through unchanged and
  // renders as distinct air/sea/ground icons in ATAK/iTAK.
  // A mixed multi-domain, mixed-affiliation picture. One track is left unknown
  // (empty affiliation) on purpose — honest: a raw sensor hit may carry no IFF.
  std::vector<Track> tracks = {
      // Air (alt in metres) — fastest.
      {"mim:aircraft", "friendly", "AJX-01", 26.4, 50.9, 11000, 0.3 * M_PI, 0.020},
      {"mim:aircraft", "", "AJX-02", 25.6, 51.4, 9500, 1.1 * M_PI, 0.018},
      {"mim:aircraft", "hostile", "AJX-03", 27.2, 49.7, 12500, 1.7 * M_PI, 0.024},
      // Surface vessels (sea level, slower).
      {"mim:surface-vessel", "friendly", "NAV-01", 26.0, 50.4, 0, 0.6 * M_PI, 0.010},
      {"mim:surface-vessel", "neutral", "NAV-02", 25.3, 51.0, 0, 1.4 * M_PI, 0.008},
      {"mim:surface-vessel", "hostile", "NAV-03", 26.8, 51.7, 0, 0.1 * M_PI, 0.011},
      // Ground vehicles (near-surface, slow).
      {"mim:ground-vehicle", "friendly", "GND-01", 25.8, 49.6, 10, 0.9 * M_PI, 0.006},
      {"mim:ground-vehicle", "hostile", "GND-02", 27.0, 50.2, 15, 1.9 * M_PI, 0.007},
  };

  // Assign each track a stable UUIDv7 once, up front (reused every tick below).
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

      // 1. Normalize -> canonical Event. A real connector parses a native radar
      //    frame here; we synthesise the track. Attributes MUST be empty: the
      //    seed mim:aircraft has no attribute schema, so any attribute is
      //    rejected as UnknownAttribute.
      ajar::Event event;
      try {
        ajar::EventBuilder builder(source_id, t.entity_type);
        builder.id(t.uid)  // STABLE per-track id -> one moving marker per track
            .now()
            .location(t.lat, t.lon, t.alt_m)
            .confidence(0.9)
            .policy_tag("air-defence");
        // Affiliation is a governed attribute (seed ontology declares it optional);
        // it drives the friend/foe colour the C2 renders. Omitted -> unknown.
        if (t.affiliation && *t.affiliation) {
          builder.attribute("affiliation", t.affiliation);
        }
        event = builder.build();
      } catch (const std::exception& ex) {
        std::fprintf(stderr, "build event: %s\n", ex.what());
        rc = 1;
        break;
      }

      // 2. Seal: detached Ed25519 signature ++ canonical bytes.
      const std::string canonical = ajar::canonical_bytes(event);
      const std::vector<std::uint8_t> sealed = ajar::seal(canonical, key);

      // 3. Publish the sealed bytes to the ingest subject.
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

    // Ensure messages are on the wire before we idle (and before exit in the
    // bounded --ticks case).
    if (conn != nullptr) natsConnection_Flush(conn);

    if (max_ticks > 0 && tick + 1 >= max_ticks) break;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  if (conn != nullptr) natsConnection_Destroy(conn);
  nats_Close();
  return rc;
}
