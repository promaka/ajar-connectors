// SPDX-License-Identifier: Apache-2.0
//! The connector run loop: receive frames, normalize, seal, publish. This is the
//! part every connector shares; the only thing a specific connector supplies is a
//! [`FrameParser`] and a [`FrameSource`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ajar_connector::{canonical_bytes, seal, Event};
use anyhow::Context;

use crate::config::Config;
use crate::{health, key, nats};

/// A parse failure. Boxed so each connector keeps its own typed error, while the
/// runtime only needs it to be printable for the operator's dropped-frame log.
pub type ParseError = Box<dyn std::error::Error + Send + Sync>;

/// Normalizes one native frame into zero or more canonical [`Event`]s. This is the
/// only format-specific code a connector writes. It must never panic on hostile
/// input — return an error instead; dropped frames are counted and logged with the
/// reason, never silently swallowed.
///
/// The result is a `Vec` because one frame may carry no event (a keep-alive, an
/// unmapped message type, a fragment held back pending reassembly → empty vec),
/// exactly one (the common case), or several (a batched block such as an ASTERIX
/// data block with multiple target records). An empty vec is a normal outcome, not
/// a drop.
pub trait FrameParser: Send + Sync + 'static {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError>;

    /// Extra named counters this parser publishes on `/metrics` — e.g. carry-forward
    /// frames dropped when a per-entity buffer overflows. Default: none. Names
    /// follow Prometheus conventions (`*_total` for monotonic counters).
    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        Vec::new()
    }
}

/// A source of native frames (a UDP socket, a TCP stream, a serial port). The
/// runtime is transport-agnostic; it just asks for the next frame.
#[async_trait::async_trait]
pub trait FrameSource: Send {
    /// Read the next frame into `buf`, returning its length.
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// A short human description of where frames come from (for logs).
    fn describe(&self) -> String;
}

/// Live counters — the connector's honest state, for logs and `/metrics`.
/// `Arc<AtomicU64>` per counter so the health endpoint can hold them by name.
#[derive(Default)]
pub(crate) struct Metrics {
    pub received: Arc<AtomicU64>,
    pub published: Arc<AtomicU64>,
    pub rejected: Arc<AtomicU64>,
    /// Events shed because the publish path stalled past its deadline (NATS
    /// down/slow with a full client buffer). Sustained growth = the link, not the
    /// source, is the bottleneck.
    pub dropped_backpressure: Arc<AtomicU64>,
}

/// How long one publish may stall before the event is shed. Load-shedding keeps
/// the ingest loop live when the link is degraded: dropping the freshest track
/// update is recoverable (the next report supersedes it); freezing ingest is not.
const PUBLISH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// Run the connector until a shutdown signal: receive → parse → seal → publish,
/// with reconnecting NATS, an opt-in health endpoint, a heartbeat log, and a
/// flush-on-shutdown so no in-flight event is dropped on a clean stop.
pub async fn run(
    cfg: Config,
    mut source: Box<dyn FrameSource>,
    parser: impl FrameParser,
) -> anyhow::Result<()> {
    let key = key::load(&cfg.signing_key_path)?;
    let subject = format!("{}.{}", cfg.subject_prefix, cfg.source_id);

    tracing::info!(
        source = %cfg.source_id,
        transport = %source.describe(),
        subject = %subject,
        "connector starting"
    );

    let metrics = Arc::new(Metrics::default());
    health::spawn(metrics.clone(), parser.counters());

    let client = nats::connect(&cfg.nats_url)
        .await
        .context("connecting to NATS")?;
    spawn_heartbeat(metrics.clone());

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal — flushing pending publishes, stopping ingest");
                let _ = client.flush().await;
                break;
            }
            recv = source.recv(&mut buf) => {
                let n = match recv {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(error = %e, "receive error");
                        // Back off so a persistently-failing source cannot spin the
                        // loop (a closed pipe, an unreadable device).
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                };
                metrics.received.fetch_add(1, Ordering::Relaxed);
                match parser.parse(&buf[..n]) {
                    // Zero events (keep-alive, unmapped, buffered fragment) simply
                    // publishes nothing; a batched frame publishes each in turn.
                    Ok(events) => {
                        for event in events {
                            let sealed = seal(&canonical_bytes(&event), &key);
                            let publish = client.publish(subject.clone(), bytes::Bytes::from(sealed));
                            match tokio::time::timeout(PUBLISH_DEADLINE, publish).await {
                                Ok(Ok(())) => {
                                    metrics.published.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(Err(e)) => {
                                    // Non-fatal: the client reconnects underneath us.
                                    tracing::warn!(error = %e, "publish error (continuing)");
                                }
                                // Deadline hit: shed the event so a stalled link
                                // degrades instead of freezing ingest.
                                Err(_) => {
                                    metrics.dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(
                                        deadline = ?PUBLISH_DEADLINE,
                                        "publish stalled — shedding event (backpressure)"
                                    );
                                }
                            }
                        }
                    }
                    Err(reason) => {
                        metrics.rejected.fetch_add(1, Ordering::Relaxed);
                        // The reason is surfaced, not just counted — an operator
                        // debugging live equipment needs to see *why* it dropped.
                        tracing::warn!(reason = %reason, "dropping unparseable frame");
                    }
                }
            }
        }
    }

    tracing::info!(
        received = metrics.received.load(Ordering::Relaxed),
        published = metrics.published.load(Ordering::Relaxed),
        rejected = metrics.rejected.load(Ordering::Relaxed),
        dropped_backpressure = metrics.dropped_backpressure.load(Ordering::Relaxed),
        "connector stopped cleanly"
    );
    Ok(())
}

/// A once-every-15s line so an operator watching logs sees it's alive and flowing.
fn spawn_heartbeat(metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tick.tick().await;
            tracing::info!(
                received = metrics.received.load(Ordering::Relaxed),
                published = metrics.published.load(Ordering::Relaxed),
                rejected = metrics.rejected.load(Ordering::Relaxed),
                dropped_backpressure = metrics.dropped_backpressure.load(Ordering::Relaxed),
                "heartbeat"
            );
        }
    });
}

/// Complete on SIGTERM/SIGINT — a service stop or Ctrl-C — for a clean shutdown.
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
