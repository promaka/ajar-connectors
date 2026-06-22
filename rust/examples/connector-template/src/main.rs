// SPDX-License-Identifier: Apache-2.0
//
//! # Connector template — your starting point
//!
//! Copy this crate, make the **two edits** marked `EDIT 1` and `EDIT 2` below,
//! and you have a working connector. Everything else is done for you.
//!
//! **See a sealed event right now — no key, no NATS, no feed:**
//! ```text
//! echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' \
//!   | cargo run -p connector-template -- --dry-run
//! ```
//!
//! **Then run for real** (key from `scripts/gen-connector-key.sh`):
//! ```text
//! AJAR_SIGNING_SEED=connector.seed AJAR_SOURCE_ID=acme-radar-1 \
//! NATS_URL=tls://nats.you.mil:4222  cargo run -p connector-template
//! ```
//!
//! **Production behaviour (built in, no edits needed):**
//! - A malformed or un-mappable record is **logged and skipped**, never fatal —
//!   one bad input can't take the connector down.
//! - A NATS publish error is logged and the connector keeps going; the client
//!   retries the initial connection and auto-reconnects after a drop.
//! - Set `AJAR_HEALTH_ADDR=0.0.0.0:9090` to expose `GET /healthz` (liveness) and
//!   `GET /metrics` (Prometheus counters: published / skipped / publish_errors).

use std::env;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ajar_connector::{canonical_bytes, seal, BuildError, Event, EventBuilder, SigningKey};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ EDIT 1 — describe ONE record from your feed.                              ║
// ║ (These fields match the demo JSON above; change them to match your data.) ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
#[derive(Debug, Deserialize)]
struct MyRecord {
    lat: f64,
    lon: f64,
    alt_m: f64,
    quality: f64,
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ EDIT 2 — map your record into a canonical Event.                          ║
// ║ Use the entity_type Ajar assigned you. Add .attribute(k, v) only for      ║
// ║ attributes your entity type's ontology schema defines.                    ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
fn to_event(source_id: &str, r: &MyRecord) -> Result<Event, BuildError> {
    EventBuilder::new(source_id, "mim:aircraft")
        .new_id()
        .now()
        .location(r.lat, r.lon, r.alt_m)
        .confidence(r.quality)
        .build()
}

// ─────────────────────────────────────────────────────────────────────────────
// You usually don't need to touch anything below this line.
// ─────────────────────────────────────────────────────────────────────────────

/// Process counters, surfaced at `/metrics` and useful in logs.
#[derive(Default)]
struct Metrics {
    published: AtomicU64,
    skipped: AtomicU64,
    publish_errors: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let dry_run = env::args().any(|a| a == "--dry-run");

    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-connector".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let subject = format!("{prefix}.{source_id}");
    let key = SigningKey::from_bytes(&load_seed(dry_run));

    let metrics = Arc::new(Metrics::default());
    spawn_health(metrics.clone()); // no-op unless AJAR_HEALTH_ADDR is set

    let client = if dry_run {
        eprintln!("[connector] --dry-run: building + sealing, not publishing");
        None
    } else {
        eprintln!("[connector] connecting to NATS at {nats_url}");
        // retry_on_initial_connect: tolerate NATS not being up yet (pod ordering),
        // and async-nats auto-reconnects after a later drop.
        Some(
            async_nats::ConnectOptions::new()
                .retry_on_initial_connect()
                .connect(&nats_url)
                .await?,
        )
    };
    eprintln!("[connector] source_id={source_id}  subject={subject}");

    // Your feed: by default, newline-delimited JSON on stdin. Swap this reader
    // for your TCP socket / file / API / serial port — the rest stays the same.
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        // Resilient: a bad record is logged and skipped, never fatal.
        let record: MyRecord = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[connector] skip: malformed record: {e}");
                metrics.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let event = match to_event(&source_id, &record) {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("[connector] skip: cannot map record: {e}");
                metrics.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let canonical = canonical_bytes(&event);
        let sealed = seal(&canonical, &key); // sign it

        if let Some(client) = &client {
            if let Err(e) = client
                .publish(subject.clone(), bytes::Bytes::from(sealed.clone()))
                .await
            {
                // Non-fatal: keep running; the client reconnects underneath us.
                eprintln!("[connector] publish error (continuing): {e}");
                metrics.publish_errors.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        }
        metrics.published.fetch_add(1, Ordering::Relaxed);
        println!(
            "{} -> {} ({} sealed bytes){}",
            event.id,
            subject,
            sealed.len(),
            if client.is_some() { "" } else { "  [dry-run]" }
        );
    }
    Ok(())
}

/// Loads your 32-byte Ed25519 seed from the file named by `AJAR_SIGNING_SEED`.
/// In `--dry-run` with no seed set, falls back to a dev seed so you can try it
/// instantly — never used for real publishing.
fn load_seed(dry_run: bool) -> [u8; 32] {
    match env::var("AJAR_SIGNING_SEED") {
        Ok(path) => std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read AJAR_SIGNING_SEED {path}: {e}"))
            .as_slice()
            .try_into()
            .expect("signing seed file must be exactly 32 bytes"),
        Err(_) if dry_run => {
            eprintln!("[connector] no AJAR_SIGNING_SEED set — using a DEV seed (dry-run only)");
            [0x03; 32]
        }
        Err(_) => panic!(
            "set AJAR_SIGNING_SEED to your 32-byte key file (see scripts/gen-connector-key.sh)"
        ),
    }
}

/// Spawns a tiny health/metrics HTTP endpoint when `AJAR_HEALTH_ADDR` is set
/// (e.g. `0.0.0.0:9090`). `GET /healthz` → liveness; `GET /metrics` → Prometheus
/// text. Std-only — no extra dependency, no impact unless you opt in.
fn spawn_health(metrics: Arc<Metrics>) {
    let addr = match env::var("AJAR_HEALTH_ADDR") {
        Ok(a) if !a.is_empty() => a,
        _ => return,
    };
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[connector] health endpoint disabled: bind {addr}: {e}");
                return;
            }
        };
        eprintln!("[connector] health/metrics on http://{addr}/healthz and /metrics");
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/");
            let body = if path.starts_with("/metrics") {
                format!(
                    "# TYPE ajar_connector_published_total counter\n\
                     ajar_connector_published_total {}\n\
                     # TYPE ajar_connector_skipped_total counter\n\
                     ajar_connector_skipped_total {}\n\
                     # TYPE ajar_connector_publish_errors_total counter\n\
                     ajar_connector_publish_errors_total {}\n",
                    metrics.published.load(Ordering::Relaxed),
                    metrics.skipped.load(Ordering::Relaxed),
                    metrics.publish_errors.load(Ordering::Relaxed),
                )
            } else {
                "ok\n".to_string()
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
}
