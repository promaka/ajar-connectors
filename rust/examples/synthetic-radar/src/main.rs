// SPDX-License-Identifier: Apache-2.0
//
//! Synthetic radar: stream synthetic `mim:aircraft` tracks into a locally
//! running Ajar Core so a developer can watch the full path
//! `connector -> NATS -> Core -> audit + Postgres`.
//!
//! Each tracked aircraft follows a **flight path** (a looping waypoint route),
//! and the connector emits a position update for every track each sweep. The
//! overall rate is configurable, so it can stream **thousands of records a
//! minute**.
//!
//! The shape every connector follows is the three steps in the loop:
//!   1. normalize a native observation into a canonical Event (here synthesised),
//!   2. seal it (detached Ed25519 signature ++ canonical bytes),
//!   3. publish the sealed bytes to the connector's NATS ingest subject.
//!
//! Clearly-marked example: dev-only signing seed + a transport (NATS). The
//! `ajar-connector` crate stays transport-free.
//!
//! ## Run
//!
//! ```text
//! cd rust/examples
//! cargo run -p synthetic-radar                 # ~3000 records/min by default
//! cargo run -p synthetic-radar -- --dry-run    # build+seal+print, no NATS
//! ```
//!
//! Env overrides: `NATS_URL`, `AJAR_SOURCE_ID`, `AJAR_INGEST_PREFIX`,
//! `AJAR_TRACKS` (number of aircraft, default 50), `AJAR_RATE_PER_MIN`
//! (target records/minute, default 3000).

use std::env;
use std::error::Error;
use std::time::{Duration, Instant};

use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

/// Dev-only signing seed: 32 bytes of `0x03`. Matches the default Core's
/// registered dev connector profile. Documented TEST seed — never production.
const DEV_SEED: [u8; 32] = [0x03; 32];

/// A synthetic aircraft that follows a looping waypoint route — a flight path,
/// not random motion. Each tick it advances toward the current waypoint along a
/// straight leg, then turns to the next when it arrives.
struct Track {
    label: String,
    route: Vec<(f64, f64)>, // waypoints (lat, lon)
    leg: usize,             // index of the waypoint currently flown toward
    lat: f64,
    lon: f64,
    alt_m: f64,
    step_deg: f64, // ground speed, degrees per sweep
}

impl Track {
    fn advance(&mut self) {
        let (tlat, tlon) = self.route[self.leg];
        let (dlat, dlon) = (tlat - self.lat, tlon - self.lon);
        let dist = (dlat * dlat + dlon * dlon).sqrt();
        if dist <= self.step_deg || dist == 0.0 {
            // Reached the waypoint: snap to it and turn toward the next (loop).
            self.lat = tlat;
            self.lon = tlon;
            self.leg = (self.leg + 1) % self.route.len();
        } else {
            self.lat += dlat / dist * self.step_deg;
            self.lon += dlon / dist * self.step_deg;
        }
    }
}

/// Builds `n` aircraft, each on a diamond racetrack (a clean looping flight
/// path) at a spread of positions, altitudes, and speeds over the Gulf region.
fn make_tracks(n: usize) -> Vec<Track> {
    let mut tracks = Vec::with_capacity(n);
    for i in 0..n {
        // Spread orbit centres across the region in a grid.
        let cx = 25.3 + (i % 7) as f64 * 0.38; // latitude  25.3 .. 27.6
        let cy = 49.4 + ((i / 7) % 7) as f64 * 0.42; // longitude 49.4 .. 51.9
        let r = 0.12 + (i % 4) as f64 * 0.06; // racetrack radius
        let route = vec![(cx + r, cy), (cx, cy + r), (cx - r, cy), (cx, cy - r)];
        let (lat, lon) = route[0];
        tracks.push(Track {
            label: format!("AJX-{:03}", i + 1),
            route,
            leg: 1,
            lat,
            lon,
            alt_m: 8000.0 + (i % 12) as f64 * 500.0,
            step_deg: 0.02 + (i % 5) as f64 * 0.004,
        });
    }
    tracks
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
        .max(1)
}

fn env_f64(key: &str, default: f64) -> f64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let max_ticks: Option<u64> = flag_value(&args, "--ticks").and_then(|v| v.parse().ok());
    // Negative test: also emit one deliberately-bad track that Ajar Core MUST
    // reject. Off by default so the normal demo stays clean.
    let inject_rejected = args.iter().any(|a| a == "--inject-rejected")
        || env::var("AJAR_INJECT_REJECTED")
            .map(|v| !v.is_empty())
            .unwrap_or(false);

    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-connector".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());

    let n_tracks = env_usize("AJAR_TRACKS", 50);
    let rate_per_min = env_f64("AJAR_RATE_PER_MIN", 3000.0).max(1.0);

    // One "sweep" emits a position for every track. Pick the sweep interval so
    // `n_tracks * sweeps_per_sec` hits the requested records/minute.
    let sweeps_per_sec = (rate_per_min / 60.0) / n_tracks as f64;
    let interval = Duration::from_secs_f64((1.0 / sweeps_per_sec).clamp(0.005, 5.0));

    let subject = format!("{prefix}.{source_id}");
    let key = SigningKey::from_bytes(&DEV_SEED);

    let client = if dry_run {
        eprintln!("[synthetic-radar] --dry-run: building + sealing, not publishing");
        None
    } else {
        eprintln!("[synthetic-radar] connecting to NATS at {nats_url}");
        Some(async_nats::connect(&nats_url).await?)
    };

    eprintln!(
        "[synthetic-radar] source_id={source_id}  subject={subject}\n\
         [synthetic-radar] {n_tracks} aircraft on flight paths, target ~{rate_per_min:.0} records/min\n\
         [synthetic-radar] entity_type=mim:aircraft, no attributes, Core stamps received_at. Ctrl-C to stop."
    );
    if inject_rejected {
        eprintln!(
            "[synthetic-radar] ⚠ INJECTING 1 known-bad track per sweep (label RJX-666): a\n\
             [synthetic-radar]   well-formed, validly-SIGNED mim:aircraft carrying an undeclared\n\
             [synthetic-radar]   attribute. Ajar Core MUST reject it (UnknownAttribute) — if any\n\
             [synthetic-radar]   are ACCEPTED, that's a boundary failure. Watch Core's audit/reject log."
        );
    }

    let mut tracks = make_tracks(n_tracks);
    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut total: u64 = 0;
    let mut poison_total: u64 = 0;
    let mut tick: u64 = 0;

    loop {
        for track in tracks.iter_mut() {
            track.advance();

            // 1. normalize (synthesised) — no attributes: seed mim:aircraft has
            //    no attribute schema, so any attribute is rejected.
            let event = EventBuilder::new(&source_id, "mim:aircraft")
                .new_id()
                .now()
                .location(track.lat, track.lon, track.alt_m)
                .confidence(0.9)
                .policy_tag("air-defence")
                .build()?;

            // 2. seal, 3. publish
            let sealed = seal(&canonical_bytes(&event), &key);
            if let Some(client) = &client {
                client
                    .publish(subject.clone(), bytes::Bytes::from(sealed))
                    .await?;
            }
            total += 1;
        }

        // Negative test: one known-bad track ("RJX-666"). Well-formed and validly
        // SIGNED, but it carries an UNDECLARED attribute — so it isolates Core's
        // ontology/validation boundary (UnknownAttribute), not the auth boundary.
        // Core MUST reject it; if it's accepted, that's the vulnerability.
        if inject_rejected {
            let poison = EventBuilder::new(&source_id, "mim:aircraft")
                .new_id()
                .now()
                .location(26.0, 50.5, 10_000.0)
                .confidence(0.9)
                .policy_tag("air-defence")
                .attribute("inject", "1") // not in the entity type's schema
                .build()?;
            let sealed = seal(&canonical_bytes(&poison), &key);
            if let Some(client) = &client {
                client
                    .publish(subject.clone(), bytes::Bytes::from(sealed))
                    .await?;
            }
            poison_total += 1;
        }

        if let Some(client) = &client {
            client.flush().await?;
        }

        // Throttled status (~1/sec) — printing every event would swamp stdout at
        // thousands/min. Shows a live total, rate, and a sample track position.
        if max_ticks.is_some() || last_report.elapsed() >= Duration::from_secs(1) {
            let secs = start.elapsed().as_secs_f64().max(0.001);
            let sample = &tracks[0];
            eprintln!(
                "[+{:>4.0}s] {} tracks  published {:>7} events  (~{:.0}/min)  e.g. {} @ {:.3},{:.3} {:.0}m{}",
                secs,
                n_tracks,
                total,
                total as f64 / secs * 60.0,
                sample.label,
                sample.lat,
                sample.lon,
                sample.alt_m,
                if client.is_some() { "" } else { "  [dry-run]" },
            );
            if inject_rejected {
                eprintln!(
                    "          + {} injected bad events (RJX-666) — expect ALL rejected by Core",
                    poison_total
                );
            }
            last_report = Instant::now();
        }

        tick += 1;
        if max_ticks.is_some_and(|m| tick >= m) {
            break;
        }
        tokio::time::sleep(interval).await;
    }

    Ok(())
}
