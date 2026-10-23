// SPDX-License-Identifier: Apache-2.0
//! SAPIENT (BSI Flex 335) egress: Ajar as a sensor node on a fusion node.
//!
//! The connector subscribes to governed egress, verifies every envelope under
//! Core's egress key, and turns each released event into a SAPIENT detection
//! report for the fusion node, which sees one more registered node that
//! reports status on the cadence it declared. What reaches the fusion node is
//! therefore what Core's policy released, with the sovereign's marking, and
//! nothing that failed to verify.
//!
//! Reports are buffered, bounded, while the fusion node is unreachable; the
//! link reconnects and re-registers by itself. Status reports are not
//! buffered: a stale heartbeat says nothing true.

pub mod config;
pub mod link;
pub mod report;
pub mod ulid;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ajar_connector_common::{health, nats};
use ajar_generic_egress::{accept, Dedupe};
use ajar_sapient_wire::v2;
use anyhow::Context;
use futures_util::StreamExt;

pub use config::{EgressConfig, SapientConfig, Site};
pub use link::FusionLink;
pub use report::{Mapper, Node, Skip};

const RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// Event ids remembered for deduplication across a reconnect to the bus.
const DEDUPE_WINDOW: usize = 10_000;

#[derive(Default, Clone)]
pub struct Metrics {
    /// Detection reports the fusion node accepted onto the wire.
    pub delivered: Arc<AtomicU64>,
    /// Envelopes that did not verify under the egress key.
    pub rejected: Arc<AtomicU64>,
    /// Events seen twice on the bus and sent once.
    pub deduped: Arc<AtomicU64>,
    /// Events with no position, which a detection report cannot carry.
    pub unlocated: Arc<AtomicU64>,
    /// Reports dropped because the buffer was full while the link was down.
    pub gap_dropped: Arc<AtomicU64>,
    /// Status reports sent.
    pub status_sent: Arc<AtomicU64>,
    /// Tasks from the fusion node refused.
    pub tasks_refused: Arc<AtomicU64>,
}

/// The bounded queue of reports waiting for the link.
pub struct Relay {
    buffer: VecDeque<v2::SapientMessage>,
    max: usize,
    metrics: Metrics,
}

impl Relay {
    pub fn new(max: usize, metrics: Metrics) -> Relay {
        Relay {
            buffer: VecDeque::new(),
            max: max.max(1),
            metrics,
        }
    }

    pub fn push(&mut self, message: v2::SapientMessage) {
        if self.buffer.len() >= self.max {
            self.buffer.pop_front();
            self.metrics.gap_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                buffered = self.buffer.len(),
                "buffer full; dropped the oldest report"
            );
        }
        self.buffer.push_back(message);
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Send everything queued, oldest first, stopping at the first failure
    /// so order is kept.
    pub async fn drain(&mut self, link: &mut FusionLink) {
        while let Some(front) = self.buffer.front() {
            match link.send(front).await {
                Ok(()) => {
                    self.buffer.pop_front();
                    self.metrics.delivered.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(error = %e, buffered = self.buffer.len(), "fusion node unreachable; holding reports");
                    break;
                }
            }
        }
    }
}

pub async fn run(cfg: EgressConfig) -> anyhow::Result<()> {
    let egress_key = cfg.verifying_key()?;
    let node = Node::from_config(&cfg);
    let mut mapper = Mapper::new(&cfg);
    let metrics = Metrics::default();
    let mut relay = Relay::new(cfg.sapient.buffer_max, metrics.clone());
    let mut dedupe = Dedupe::new(DEDUPE_WINDOW);
    let mut link = FusionLink::new(&cfg.sapient.fusion_node, node.clone());

    health::spawn_counters(vec![
        ("egress_delivered_total", metrics.delivered.clone()),
        ("egress_rejected_total", metrics.rejected.clone()),
        ("egress_deduped_total", metrics.deduped.clone()),
        ("egress_unlocated_total", metrics.unlocated.clone()),
        ("egress_gap_dropped_total", metrics.gap_dropped.clone()),
        (
            "egress_sapient_status_sent_total",
            metrics.status_sent.clone(),
        ),
        (
            "egress_sapient_tasks_refused_total",
            metrics.tasks_refused.clone(),
        ),
        ("egress_sapient_reconnects_total", link.reconnects.clone()),
        (
            "egress_sapient_registrations_rejected_total",
            link.rejected_registrations.clone(),
        ),
        ("egress_sapient_link_up", link.up.clone()),
    ]);

    let client = nats::connect(&cfg.nats_url)
        .await
        .context("connecting to Ajar NATS")?;
    let mut sub = client
        .subscribe(cfg.subject.clone())
        .await
        .with_context(|| format!("subscribing {}", cfg.subject))?;

    tracing::info!(
        subject = %cfg.subject,
        fusion_node = %cfg.sapient.fusion_node,
        node_id = %node.node_id,
        status_interval_s = cfg.sapient.status_interval_s,
        buffer_max = cfg.sapient.buffer_max,
        "sapient egress starting"
    );

    let mut status_tick =
        tokio::time::interval(Duration::from_secs_f64(cfg.sapient.status_interval_s));
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut first_status = true;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        if !link.connected() {
            match link.ensure_registered().await {
                Ok(()) => first_status = true,
                Err(e) => {
                    tracing::warn!(error = %e, buffered = relay.len(), "fusion node unreachable; retrying")
                }
            }
        }
        relay.drain(&mut link).await;

        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal — attempting final drain");
                let _ = tokio::time::timeout(Duration::from_secs(2), relay.drain(&mut link)).await;
                break;
            }
            msg = sub.next() => {
                match msg {
                    Some(m) => {
                        match accept(&m.payload, &egress_key) {
                            Ok(event) => {
                                if !dedupe.first_time(&event.id) {
                                    metrics.deduped.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    match mapper.detection(&node, &event) {
                                        Ok(report) => relay.push(report),
                                        Err(Skip::NoLocation) => {
                                            metrics.unlocated.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(error = %e, "egress envelope refused");
                            }
                        }
                    }
                    None => {
                        tracing::warn!("NATS subscription ended");
                        break;
                    }
                }
            }
            _ = status_tick.tick() => {
                if link.connected() {
                    match link.send(&node.status(first_status)).await {
                        Ok(()) => {
                            first_status = false;
                            metrics.status_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => tracing::warn!(error = %e, "status report not delivered"),
                    }
                }
            }
            inbound = link.next_inbound(), if link.connected() => {
                if let Ok(message) = inbound {
                    match link.answer(&message).await {
                        Ok(true) => {
                            metrics.tasks_refused.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(false) => {}
                        Err(e) => tracing::warn!(error = %e, "reply to the fusion node failed"),
                    }
                }
            }
            _ = tokio::time::sleep(RETRY_INTERVAL), if !link.connected() || !relay.is_empty() => {}
        }
    }

    tracing::info!(
        delivered = metrics.delivered.load(Ordering::Relaxed),
        gap_dropped = metrics.gap_dropped.load(Ordering::Relaxed),
        "sapient egress stopped"
    );
    Ok(())
}

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
        let metrics = Metrics::default();
        let mut relay = Relay::new(2, metrics.clone());
        for i in 0..3 {
            relay.push(v2::SapientMessage {
                node_id: Some(i.to_string()),
                ..Default::default()
            });
        }
        assert_eq!(relay.len(), 2);
        assert_eq!(relay.buffer.front().unwrap().node_id.as_deref(), Some("1"));
        assert_eq!(metrics.gap_dropped.load(Ordering::Relaxed), 1);
    }
}
