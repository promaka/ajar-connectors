// SPDX-License-Identifier: Apache-2.0
//
//! Connector template: copy this crate and make the two edits marked `EDIT 1`
//! and `EDIT 2`. It reads newline-delimited JSON on stdin, maps each record to
//! an event, seals it and publishes it to NATS; a bad record is logged and
//! skipped. The README shows how to run it.

use std::env;
use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ajar_connector::{BuildError, Event, EventBuilder, SigningKey};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};

// =============================================================================
// EDIT 1: describe one record from your feed. These fields match the README
// demo; change them to match your data.
// =============================================================================
#[derive(Debug, Deserialize)]
struct MyRecord {
    lat: f64,
    lon: f64,
    alt_m: f64,
    quality: f64,
}

// =============================================================================
// EDIT 2: map your record to an Event. Use the entity type your operator
// assigned, and add .attribute(k, v) for attributes its schema declares.
// =============================================================================
fn to_event(source_id: &str, r: &MyRecord) -> Result<Event, BuildError> {
    EventBuilder::new(source_id, "mim:aircraft")
        .new_id()
        .now()
        .location(r.lat, r.lon, r.alt_m)
        .confidence(r.quality)
        .build()
}

// =============================================================================
// Nothing below this line usually needs changing, except the feed reader
// marked EDIT.
// =============================================================================

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
    spawn_health(metrics.clone());

    let client = if dry_run {
        eprintln!("[connector] --dry-run: building + sealing, not publishing");
        None
    } else {
        eprintln!("[connector] connecting to NATS at {nats_url}");
        Some(nats_connect(&nats_url).await?)
    };
    eprintln!("[connector] source_id={source_id}  subject={subject}");

    // EDIT: swap stdin for your socket, file, API or serial port.
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
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
        let sealed = ajar_connector::seal(&ajar_connector::canonical_bytes(&event), &key);

        if let Some(client) = &client {
            if let Err(e) = client
                .publish(subject.clone(), bytes::Bytes::from(sealed.clone()))
                .await
            {
                // The client reconnects on its own, so keep going.
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

/// Connects to NATS over mTLS when `AJAR_TLS_CA`, `AJAR_TLS_CERT` and
/// `AJAR_TLS_KEY` are all set, else in plaintext. The client certificate's CN is
/// your `source_id`.
async fn nats_connect(url: &str) -> Result<async_nats::Client, async_nats::ConnectError> {
    let mut opts = async_nats::ConnectOptions::new().retry_on_initial_connect();
    match (
        env::var("AJAR_TLS_CA"),
        env::var("AJAR_TLS_CERT"),
        env::var("AJAR_TLS_KEY"),
    ) {
        (Ok(ca), Ok(cert), Ok(key)) if !ca.is_empty() && !cert.is_empty() && !key.is_empty() => {
            eprintln!("[connector] mTLS enabled (client cert = source identity)");
            opts = opts
                .require_tls(true)
                .add_root_certificates(ca.into())
                .add_client_certificate(cert.into(), key.into());
        }
        _ => eprintln!("[connector] no AJAR_TLS_* set, connecting without TLS (dev only)"),
    }
    opts.connect(url).await
}

/// Loads the Ed25519 seed named by `AJAR_SIGNING_SEED`, or mints an ephemeral
/// key under `--dry-run`, where nothing is published.
fn load_seed(dry_run: bool) -> [u8; 32] {
    match env::var("AJAR_SIGNING_SEED") {
        Ok(path) => {
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|e| panic!("read AJAR_SIGNING_SEED {path}: {e}"));
            parse_seed(&bytes).expect("signing seed must be 32 raw bytes or 64 hex chars")
        }
        Err(_) if dry_run => {
            eprintln!("[connector] no AJAR_SIGNING_SEED set, ephemeral throwaway key (dry-run only)");
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
                .expect("reading /dev/urandom");
            seed
        }
        Err(_) => panic!(
            "set AJAR_SIGNING_SEED to your key file (32 raw bytes or 64 hex chars; see scripts/gen-connector-key.sh)"
        ),
    }
}

/// A seed file is 32 raw bytes or the 64 hex characters `ajar keygen` writes,
/// surrounding whitespace tolerated.
fn parse_seed(bytes: &[u8]) -> Option<[u8; 32]> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Some(raw);
    }
    let decoded = hex::decode(std::str::from_utf8(bytes).ok()?.trim()).ok()?;
    decoded.try_into().ok()
}

/// Serves `GET /healthz` and Prometheus `GET /metrics` on `AJAR_HEALTH_ADDR`
/// (e.g. `0.0.0.0:9090`), if set.
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
