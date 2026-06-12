// SPDX-License-Identifier: Apache-2.0
//
//! Synthetic radar: stream synthetic `mim:aircraft` tracks into a locally
//! running Ajar Core so a developer can watch the full path
//! `connector -> NATS -> Core -> audit + Postgres`.
//!
//! The shape every connector follows is the three steps in the loop below:
//!
//! 1. **normalize** a native observation into a canonical [`Event`] (here we
//!    synthesise it; a real radar connector would parse a vendor frame),
//! 2. **seal** it (detached Ed25519 signature ++ canonical bytes),
//! 3. **publish** the sealed bytes to the connector's NATS ingest subject.
//!
//! This is a clearly-marked **example**: it carries a dev-only signing seed and
//! it picks a transport (NATS). The `ajar-connector` crate itself stays minimal
//! and transport-free — the NATS client lives here, in the example.
//!
//! ## Run against a default local Core
//!
//! ```text
//! cd rust/examples
//! cargo run -p synthetic-radar                 # publish to 127.0.0.1:4222
//! cargo run -p synthetic-radar -- --dry-run    # build+seal+print, no NATS
//! cargo run -p synthetic-radar -- --dry-run --ticks 3   # bounded (CI)
//! ```
//!
//! Env overrides: `NATS_URL`, `AJAR_SOURCE_ID`, `AJAR_INGEST_PREFIX`.

use std::env;
use std::error::Error;
use std::time::Duration;

use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

/// Dev-only signing seed: 32 bytes of `0x03`. This matches the default Core's
/// registered dev connector profile, so the local demo's signatures are
/// accepted with zero core changes. Like the golden-vectors `0x47` seed, it is
/// a documented TEST seed — NEVER use it for production signing.
const DEV_SEED: [u8; 32] = [0x03; 32];

/// A synthetic aircraft track moving over a region (around the Gulf, matching
/// the corpus fixtures). Heading is in radians; speed is in degrees/tick.
struct Track {
    label: &'static str,
    lat: f64,
    lon: f64,
    alt_m: f64,
    heading: f64,
    speed_deg: f64,
}

impl Track {
    /// Advances the track one tick, reflecting off the region bounds so it stays
    /// on screen.
    fn advance(&mut self) {
        self.lat += self.heading.cos() * self.speed_deg;
        self.lon += self.heading.sin() * self.speed_deg;
        // Region: lat [25, 28], lon [49, 52].
        if self.lat < 25.0 || self.lat > 28.0 {
            self.heading = -self.heading;
            self.lat = self.lat.clamp(25.0, 28.0);
        }
        if self.lon < 49.0 || self.lon > 52.0 {
            self.heading = std::f64::consts::PI - self.heading;
            self.lon = self.lon.clamp(49.0, 52.0);
        }
    }
}

fn initial_tracks() -> Vec<Track> {
    use std::f64::consts::PI;
    vec![
        Track {
            label: "AJX-01",
            lat: 26.4,
            lon: 50.9,
            alt_m: 11_000.0,
            heading: 0.3 * PI,
            speed_deg: 0.012,
        },
        Track {
            label: "AJX-02",
            lat: 25.6,
            lon: 51.4,
            alt_m: 9_500.0,
            heading: 1.1 * PI,
            speed_deg: 0.009,
        },
        Track {
            label: "AJX-03",
            lat: 27.2,
            lon: 49.7,
            alt_m: 12_500.0,
            heading: 1.7 * PI,
            speed_deg: 0.015,
        },
    ]
}

/// Parses `--ticks N` (run a bounded number of ticks, then exit) if present.
fn parse_max_ticks(args: &[String]) -> Option<u64> {
    let i = args.iter().position(|a| a == "--ticks")?;
    args.get(i + 1).and_then(|n| n.parse().ok())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let max_ticks = parse_max_ticks(&args);

    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-connector".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "127.0.0.1:4222".to_string());

    // `source` must equal the Core's AJAR_SOURCE_ID; the subject is the one the
    // Core's ingest is listening on.
    let subject = format!("{prefix}.{source_id}");
    let key = SigningKey::from_bytes(&DEV_SEED);

    // Connect the real NATS client (skipped in --dry-run, which needs no infra).
    let client = if dry_run {
        eprintln!("[synthetic-radar] --dry-run: building + sealing events, not publishing");
        None
    } else {
        eprintln!("[synthetic-radar] connecting to NATS at {nats_url}");
        Some(async_nats::connect(&nats_url).await?)
    };

    eprintln!(
        "[synthetic-radar] source_id={source_id}  subject={subject}\n\
         [synthetic-radar] entity_type=mim:aircraft, no attributes (seed ontology \
         has no aircraft attribute schema), Core stamps received_at\n\
         [synthetic-radar] Ctrl-C to stop."
    );

    let mut tracks = initial_tracks();
    let mut tick: u64 = 0;
    loop {
        for track in tracks.iter_mut() {
            track.advance();

            // 1. Normalize -> canonical Event. A real connector parses a native
            //    radar frame here; we synthesise the track. Attributes MUST be
            //    empty: the seed `mim:aircraft` has no attribute schema, so any
            //    attribute is rejected as UnknownAttribute.
            let event = EventBuilder::new(&source_id, "mim:aircraft")
                .new_id() // fresh UUIDv7 per event
                .now()
                .location(track.lat, track.lon, track.alt_m)
                .confidence(0.9)
                .policy_tag("air-defence")
                .build()?;

            // 2. Seal: detached Ed25519 signature ++ canonical bytes.
            let canonical = canonical_bytes(&event);
            let sealed = seal(&canonical, &key);

            // 3. Publish the sealed bytes to the ingest subject.
            if let Some(client) = &client {
                client
                    .publish(subject.clone(), bytes::Bytes::from(sealed.clone()))
                    .await?;
            }

            println!(
                "{} {:>6}  lat={:8.4} lon={:8.4} alt={:>7.0}m  -> {} ({} sealed bytes){}",
                event.id,
                track.label,
                track.lat,
                track.lon,
                track.alt_m,
                subject,
                sealed.len(),
                if client.is_some() { "" } else { "  [dry-run]" },
            );
        }

        // Ensure messages are on the wire before we idle (and before we exit in
        // the bounded --ticks case).
        if let Some(client) = &client {
            client.flush().await?;
        }

        tick += 1;
        if max_ticks.is_some_and(|max| tick >= max) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}
