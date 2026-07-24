// SPDX-License-Identifier: Apache-2.0
//! TAK info-egress relay: governed CoT from Ajar's NATS egress to a TAK Server.
//!
//! Pure transport. Core has already done all governance — verification, policy,
//! ontology, anonymization — before publishing to the egress subject, so this
//! relay does **not** sign, parse, alter, or "improve" anything: each NATS
//! payload is forwarded to the TAK stream **byte-verbatim**. That verbatim rule
//! is what preserves the governed guarantee end-to-end.
//!
//! Resilience model: async-nats reconnects the Ajar side by itself; the TAK side
//! reconnects with pacing here. While the TAK Server is unreachable, events queue
//! in a bounded in-memory buffer; on overflow the OLDEST is dropped and
//! `egress_gap_dropped_total` increments — bounded and lossy by design for a
//! live picture feed (a durable no-gap egress is a deliberate non-goal here).

pub mod config;
pub mod tak;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ajar_connector_common::{health, nats};
use anyhow::Context;
use futures_util::StreamExt;

pub use config::{EgressConfig, TakConfig};
pub use tak::TakLink;

/// How often a non-empty buffer retries the TAK link.
const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Relay counters, exposed on `/metrics` (via `AJAR_HEALTH_ADDR`).
#[derive(Default, Clone)]
pub struct RelayMetrics {
    pub delivered: Arc<AtomicU64>,
    pub gap_dropped: Arc<AtomicU64>,
}

/// The bounded store-and-forward buffer between NATS and the TAK link.
pub struct Relay {
    buffer: VecDeque<bytes::Bytes>,
    max: usize,
    pub metrics: RelayMetrics,
}

impl Relay {
    pub fn new(max: usize) -> Relay {
        Relay {
            buffer: VecDeque::new(),
            max: max.max(1),
            metrics: RelayMetrics::default(),
        }
    }

    /// Queue one governed payload. At capacity the oldest event is dropped (the
    /// freshest picture wins) and the gap counter increments.
    pub fn push(&mut self, payload: bytes::Bytes) {
        if self.buffer.len() >= self.max {
            self.buffer.pop_front();
            self.metrics.gap_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                buffered = self.buffer.len(),
                "buffer full — dropped oldest (gap)"
            );
        }
        self.buffer.push_back(payload);
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Forward buffered events to the TAK link, oldest first, verbatim, until
    /// the buffer empties or a send fails (the link paces reconnection).
    pub async fn drain(&mut self, link: &mut TakLink) {
        while let Some(front) = self.buffer.front() {
            match link.send(front).await {
                Ok(()) => {
                    self.buffer.pop_front();
                    self.metrics.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => break, // link is down; keep buffering
            }
        }
    }
}

/// Run the relay until the NATS subscription ends or a shutdown signal arrives:
/// subscribe to the egress subject, buffer, and forward verbatim to the TAK
/// Server.
pub async fn run(cfg: EgressConfig) -> anyhow::Result<()> {
    let mut link = TakLink::new(&cfg.tak)?;
    let mut relay = Relay::new(cfg.tak.buffer_max);

    health::spawn_counters(vec![
        ("egress_delivered_total", relay.metrics.delivered.clone()),
        (
            "egress_gap_dropped_total",
            relay.metrics.gap_dropped.clone(),
        ),
        ("egress_tak_reconnects_total", link.reconnects.clone()),
        ("egress_tak_link_up", link.up.clone()),
    ]);

    let client = nats::connect(&cfg.nats_url)
        .await
        .context("connecting to Ajar NATS")?;
    let mut sub = client
        .subscribe(cfg.egress_subject.clone())
        .await
        .with_context(|| format!("subscribing {}", cfg.egress_subject))?;

    tracing::info!(
        subject = %cfg.egress_subject,
        tak = %cfg.tak.endpoint(),
        buffer_max = cfg.tak.buffer_max,
        "egress relay starting"
    );

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        // Forward whatever is queued (no-op when the link is down).
        relay.drain(&mut link).await;

        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal — attempting final drain");
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    relay.drain(&mut link),
                )
                .await;
                break;
            }
            msg = sub.next() => {
                match msg {
                    Some(m) => relay.push(m.payload),
                    None => {
                        tracing::warn!("NATS subscription ended");
                        break;
                    }
                }
            }
            // A non-empty buffer means the TAK link is down: retry on a pace
            // even if no new NATS traffic arrives.
            _ = tokio::time::sleep(RETRY_INTERVAL), if !relay.is_empty() => {}
        }
    }

    tracing::info!(
        delivered = relay.metrics.delivered.load(Ordering::Relaxed),
        gap_dropped = relay.metrics.gap_dropped.load(Ordering::Relaxed),
        "egress relay stopped"
    );
    Ok(())
}

/// Complete on SIGTERM/SIGINT — a service stop or Ctrl-C.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_drops_oldest_and_counts_the_gap() {
        let mut relay = Relay::new(2);
        relay.push(bytes::Bytes::from_static(b"a"));
        relay.push(bytes::Bytes::from_static(b"b"));
        relay.push(bytes::Bytes::from_static(b"c")); // evicts "a"
        assert_eq!(relay.buffer.len(), 2);
        assert_eq!(relay.buffer.front().unwrap().as_ref(), b"b");
        assert_eq!(relay.metrics.gap_dropped.load(Ordering::Relaxed), 1);
    }
}
