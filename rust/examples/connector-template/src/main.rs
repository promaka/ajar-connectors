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

use std::env;
use std::error::Error;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let dry_run = env::args().any(|a| a == "--dry-run");

    let source_id = env::var("AJAR_SOURCE_ID").unwrap_or_else(|_| "demo-connector".to_string());
    let prefix = env::var("AJAR_INGEST_PREFIX").unwrap_or_else(|_| "ajar.ingest".to_string());
    let nats_url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string());
    let subject = format!("{prefix}.{source_id}");
    let key = SigningKey::from_bytes(&load_seed(dry_run));

    let client = if dry_run {
        eprintln!("[connector] --dry-run: building + sealing, not publishing");
        None
    } else {
        eprintln!("[connector] connecting to NATS at {nats_url}");
        Some(async_nats::connect(&nats_url).await?)
    };
    eprintln!("[connector] source_id={source_id}  subject={subject}");

    // Your feed: by default, newline-delimited JSON on stdin. Swap this reader
    // for your TCP socket / file / API / serial port — the rest stays the same.
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let record: MyRecord = serde_json::from_str(&line)?; // parse one record
        let event = to_event(&source_id, &record)?; //            EDIT 2 maps it
        let canonical = canonical_bytes(&event);
        let sealed = seal(&canonical, &key); //                    sign it

        if let Some(client) = &client {
            client
                .publish(subject.clone(), bytes::Bytes::from(sealed.clone()))
                .await?; //                                        publish it
        }
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
