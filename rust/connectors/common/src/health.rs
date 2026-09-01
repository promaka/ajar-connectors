// SPDX-License-Identifier: Apache-2.0
//! A dependency-free health/metrics endpoint. Opt-in via `AJAR_HEALTH_ADDR`
//! (e.g. `0.0.0.0:9110`); left unset, nothing is opened. Deliberately raw
//! `std::net` so a connector pulls in no HTTP framework just to answer a probe.
//!
//! Serves `GET /healthz` → `ok` and `GET /metrics` → Prometheus text. The ingest
//! runtime wires its own counters in; other binaries (e.g. an egress relay with
//! different metric names) use [`spawn_counters`] with whatever counters they
//! keep.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::runtime::Metrics;

/// Start the health server on its own OS thread if `AJAR_HEALTH_ADDR` is set,
/// exposing the given named counters on `/metrics`. Counter names should follow
/// Prometheus conventions (`*_total` for monotonic counters).
pub fn spawn_counters(counters: Vec<(&'static str, Arc<AtomicU64>)>) {
    let addr = match std::env::var("AJAR_HEALTH_ADDR") {
        Ok(a) if !a.is_empty() => a,
        _ => return,
    };
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(addr = %addr, error = %e, "health endpoint disabled (bind failed)");
                return;
            }
        };
        tracing::info!(addr = %addr, "health endpoint on /healthz and /metrics");
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // A connection that opens and sends nothing (a port scanner, a
            // half-configured probe) must not wedge the single-threaded loop.
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body = if req.starts_with("GET /metrics") {
                let mut out = String::new();
                for (name, value) in &counters {
                    out.push_str(name);
                    out.push(' ');
                    out.push_str(&value.load(Ordering::Relaxed).to_string());
                    out.push('\n');
                }
                out
            } else {
                "ok".to_string()
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
}

/// The ingest runtime's standard counters, plus any the parser publishes.
pub(crate) fn spawn(metrics: Arc<Metrics>, extra: Vec<(&'static str, Arc<AtomicU64>)>) {
    let mut counters = vec![
        ("connector_received_total", metrics.received.clone()),
        ("connector_published_total", metrics.published.clone()),
        ("connector_rejected_total", metrics.rejected.clone()),
        (
            "connector_dropped_backpressure_total",
            metrics.dropped_backpressure.clone(),
        ),
        // Spool counters: zero (and honest) when no spool is configured.
        ("connector_spooled_total", metrics.spooled.clone()),
        ("connector_drained_total", metrics.drained.clone()),
        (
            "connector_spool_corrupt_total",
            metrics.spool_corrupt.clone(),
        ),
        (
            "connector_spool_dropped_segments_total",
            metrics.spool_dropped_segments.clone(),
        ),
        ("connector_spool_failed_total", metrics.spool_failed.clone()),
    ];
    counters.extend(extra);
    spawn_counters(counters);
}
