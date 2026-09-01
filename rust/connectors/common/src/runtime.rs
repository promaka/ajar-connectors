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
    /// Events written to the disk spool instead of shed (spool configured).
    pub spooled: Arc<AtomicU64>,
    /// Spooled events replayed and confirmed delivered.
    pub drained: Arc<AtomicU64>,
    /// Spooled records that failed signature verification on drain (disk
    /// corruption): skipped and counted, never published.
    pub spool_corrupt: Arc<AtomicU64>,
    /// Oldest spool segments dropped to stay under the configured bound.
    pub spool_dropped_segments: Arc<AtomicU64>,
    /// Spool appends that FAILED (disk full, permissions): the event is lost
    /// and this says so, instead of a phantom increment of `spooled`.
    pub spool_failed: Arc<AtomicU64>,
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

    // Optional store-and-forward spool (#76): sealed events survive link
    // outages on local disk and a paced drain replays them byte-identical.
    let spool = match &cfg.spool_config() {
        Some(spool_cfg) => {
            let spool = Arc::new(tokio::sync::Mutex::new(
                crate::spool::Spool::open(spool_cfg).context("opening the disk spool")?,
            ));
            tracing::info!(dir = %spool_cfg.dir, drain_rate = spool_cfg.drain_rate,
                "disk spool enabled");
            spawn_drain(
                spool.clone(),
                client.clone(),
                subject.clone(),
                key.verifying_key(),
                spool_cfg.drain_rate,
                metrics.clone(),
            );
            Some(spool)
        }
        None => None,
    };

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut buf = vec![0u8; crate::MAX_FRAME_BYTES];
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
                                    let headers = ingest_headers(&event.id);
                                    let sealed = seal(&canonical_bytes(&event), &key);
                                    // Link known down + spool configured: spool at
                                    // line rate instead of paying the publish
                                    // deadline per event. (The async client buffers
                                    // publishes while reconnecting, so without this
                                    // check a short outage hides in the buffer and a
                                    // long one stalls the loop event by event.)
                                    if let Some(spool) = &spool {
                                        use async_nats::connection::State;
                                        if client.connection_state() != State::Connected {
                                            match spool.lock().await.append(&event.id, &sealed) {
                                                Ok(dropped) => {
                                                    metrics.spooled.fetch_add(1, Ordering::Relaxed);
                                                    if dropped {
                                                        metrics
                                                            .spool_dropped_segments
                                                            .fetch_add(1, Ordering::Relaxed);
                                                    }
                                                }
                                                Err(e) => {
                                                    metrics.spool_failed.fetch_add(1, Ordering::Relaxed);
                                                    tracing::warn!(error = %e, "spool append FAILED - event lost");
                                                }
                                            }
                                            continue;
                                        }
                                    }
                                    let publish = client.publish_with_headers(
                                        subject.clone(),
                                        headers,
                                        bytes::Bytes::from(sealed.clone()),
                                    );
                                    match tokio::time::timeout(PUBLISH_DEADLINE, publish).await {
                                        Ok(Ok(())) => {
                                            metrics.published.fetch_add(1, Ordering::Relaxed);
                                        }
                                        // Publish failed or stalled: spool when
                                        // configured, shed (counted) when not.
                                        Ok(Err(_)) | Err(_) => match &spool {
                                            Some(spool) => {
                                                match spool.lock().await.append(&event.id, &sealed) {
                                                    Ok(dropped) => {
                                                        metrics.spooled.fetch_add(1, Ordering::Relaxed);
                                                        if dropped {
                                                            metrics
                                                                .spool_dropped_segments
                                                                .fetch_add(1, Ordering::Relaxed);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        metrics
                                                            .spool_failed
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        tracing::warn!(error = %e,
                                                            "spool append FAILED - event lost");
                                                    }
                                                }
                                            }
        None => {
                                                metrics.dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                                                tracing::warn!(
                                                    deadline = ?PUBLISH_DEADLINE,
                                                    "publish stalled, shedding event (backpressure)"
                                                );
                                            }
                                        },
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

    if let Some(spool) = &spool {
        spool.lock().await.sync();
    }
    tracing::info!(
        received = metrics.received.load(Ordering::Relaxed),
        published = metrics.published.load(Ordering::Relaxed),
        rejected = metrics.rejected.load(Ordering::Relaxed),
        dropped_backpressure = metrics.dropped_backpressure.load(Ordering::Relaxed),
        spooled = metrics.spooled.load(Ordering::Relaxed),
        drained = metrics.drained.load(Ordering::Relaxed),
        "connector stopped cleanly"
    );
    Ok(())
}

/// The spool drain: replay spooled events oldest-first, paced, advancing the
/// cursor only on confirmed delivery.
///
/// Pacing is correctness, not politeness: Core's per-source token bucket ACKs
/// and destroys over-rate events, and live traffic shares the bucket, so the
/// drain must stay well under the registered rate (the config guidance is
/// 70-80% of it).
///
/// Delivery confirmation prefers a JetStream PubAck (the ingest subject is
/// captured by Core's stream, so the ack proves the bytes are stored). When
/// no stream exists (a dev sink on plain NATS), it falls back to
/// publish+flush, which proves the broker received the bytes: the same
/// guarantee the live path has.
fn spawn_drain(
    spool: Arc<tokio::sync::Mutex<crate::spool::Spool>>,
    client: async_nats::Client,
    subject: String,
    verifying_key: ed25519_dalek::VerifyingKey,
    drain_rate: f64,
    metrics: Arc<Metrics>,
) {
    use ed25519_dalek::Verifier as _;
    let js = async_nats::jetstream::new(client.clone());
    let gap = std::time::Duration::from_secs_f64(1.0 / drain_rate.max(0.1));
    tokio::spawn(async move {
        let mut js_mode = true;
        loop {
            let item = spool.lock().await.peek();
            let (cursor, record) = match item {
                Ok(Some(hit)) => hit,
                // Empty (or unreadable) spool: idle gently.
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            };

            // Verify with the connector's own key before sending: a record
            // that rotted on disk is counted and skipped, never published.
            let valid = record.sealed.len() > crate::seal_signature_len()
                && ed25519_dalek::Signature::from_slice(
                    &record.sealed[..crate::seal_signature_len()],
                )
                .map(|sig| {
                    verifying_key
                        .verify(&record.sealed[crate::seal_signature_len()..], &sig)
                        .is_ok()
                })
                .unwrap_or(false);
            if !valid {
                metrics.spool_corrupt.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(event_id = %record.event_id,
                    "spooled record failed verification (disk corruption), skipping");
                if spool.lock().await.advance(cursor).is_err() {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                continue;
            }

            let headers = ingest_headers(&record.event_id);
            let payload = bytes::Bytes::from(record.sealed.clone());
            let delivered = if js_mode {
                match js
                    .publish_with_headers(subject.clone(), headers.clone(), payload.clone())
                    .await
                {
                    Ok(ack) => match ack.await {
                        Ok(_) => true,
                        Err(e) => {
                            let text = e.to_string();
                            if text.contains("no responders") {
                                tracing::info!(
                                    "no JetStream stream on the ingest subject,                                      draining with publish+flush"
                                );
                                js_mode = false;
                            } else {
                                tracing::warn!(error = %text, "drain publish not acked, retrying");
                            }
                            false
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "drain publish failed, retrying");
                        false
                    }
                }
            } else {
                false
            };
            let delivered = if !delivered && !js_mode {
                client
                    .publish_with_headers(subject.clone(), headers, payload)
                    .await
                    .is_ok()
                    && client.flush().await.is_ok()
            } else {
                delivered
            };

            if delivered {
                if let Err(e) = spool.lock().await.advance(cursor) {
                    tracing::warn!(error = %e, "spool cursor advance failed");
                }
                metrics.drained.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(gap).await;
            } else {
                // Link still down (or mode just flipped): back off, keep the
                // cursor where it is. Replay duplicates from this retry are
                // absorbed by the broker's Nats-Msg-Id window.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    });
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

/// Headers for an ingest publish. `Nats-Msg-Id` carries the event id so the
/// broker's duplicate window (Core's ingest stream sets 120s) dedupes retries
/// and reconnect races for free; without the header the window is inert. The
/// id is already unique per event (UUIDv7 from the builder), so no state is
/// needed here.
pub fn ingest_headers(event_id: &str) -> async_nats::HeaderMap {
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", event_id);
    headers
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_ingest_publish_carries_the_event_id_for_broker_dedupe() {
        let headers = super::ingest_headers("0198b1c0-aaaa-bbbb-cccc-121212121212");
        assert_eq!(
            headers.get("Nats-Msg-Id").map(|v| v.as_str()),
            Some("0198b1c0-aaaa-bbbb-cccc-121212121212")
        );
    }
}
