// SPDX-License-Identifier: Apache-2.0
//
//! Synthetic radar: stream synthetic `mim:aircraft` tracks into a locally
//! running Ajar Core so a developer can watch the full path
//! `connector -> NATS -> Core -> audit + Postgres`.
//!
//! Each tick (~1/sec) it advances a handful of tracks, builds a sealed event
//! with the SDK, and publishes the sealed bytes to NATS subject
//! `ajar.ingest.<source>`.
//!
//! This is a clearly-marked **example**: it carries a dev-only signing seed and
//! talks NATS. The `ajar-connector` crate itself stays minimal and
//! transport-free — the choice of NATS lives here. To avoid depending on (and
//! bit-rotting against) a NATS client crate, the example speaks the NATS PUB
//! wire protocol directly over TCP in [`nats`]; a production connector would use
//! a maintained client such as `async-nats`.
//!
//! ## Run against a default local Core
//!
//! ```text
//! cargo run -p synthetic-radar               # publish to 127.0.0.1:4222
//! cargo run -p synthetic-radar -- --dry-run  # build+seal+print, no NATS
//! ```
//!
//! Env overrides: `NATS_URL`, `AJAR_SOURCE_ID`, `AJAR_INGEST_PREFIX`.

mod nats;

use std::env;
use std::error::Error;
use std::thread;
use std::time::Duration;

use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

use crate::nats::NatsPublisher;

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

fn main() -> Result<(), Box<dyn Error>> {
    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-connector".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "127.0.0.1:4222".to_string());
    let dry_run = env::args().any(|a| a == "--dry-run");

    let subject = format!("{prefix}.{source_id}");
    let key = SigningKey::from_bytes(&DEV_SEED);

    let mut publisher = if dry_run {
        eprintln!("[synthetic-radar] --dry-run: building + sealing events, not publishing");
        None
    } else {
        eprintln!("[synthetic-radar] connecting to NATS at {nats_url}");
        Some(NatsPublisher::connect(&nats_url)?)
    };

    eprintln!(
        "[synthetic-radar] source_id={source_id}  subject={subject}\n\
         [synthetic-radar] entity_type=mim:aircraft, no attributes (seed ontology \
         has no aircraft attribute schema), Core stamps received_at\n\
         [synthetic-radar] Ctrl-C to stop."
    );

    let mut tracks = initial_tracks();
    loop {
        for track in tracks.iter_mut() {
            track.advance();

            // attributes MUST be empty: the seed `mim:aircraft` has no attribute
            // schema, so any attribute is rejected as UnknownAttribute.
            let event = EventBuilder::new(&source_id, "mim:aircraft")
                .new_id() // fresh UUIDv7 per event
                .now()
                .location(track.lat, track.lon, track.alt_m)
                .confidence(0.9)
                .policy_tag("air-defence")
                .build()?;

            let canonical = canonical_bytes(&event);
            let sealed = seal(&canonical, &key);

            if let Some(publisher) = publisher.as_mut() {
                publisher.publish(&subject, &sealed)?;
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
                if publisher.is_some() {
                    ""
                } else {
                    "  [dry-run]"
                },
            );
        }
        thread::sleep(Duration::from_secs(1));
    }
}
