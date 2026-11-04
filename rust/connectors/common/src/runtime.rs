// SPDX-License-Identifier: Apache-2.0
//! The connector run loop: receive a frame, parse, seal, publish.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ajar_connector::Event;
use anyhow::Context;
use async_nats::connection::State;
use bytes::Bytes;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::spool::Spool;
use crate::{health, key, nats, ontology};

/// A parse failure. Boxed so each connector keeps its own typed error.
pub type ParseError = Box<dyn std::error::Error + Send + Sync>;

/// Normalizes one native frame into zero or more canonical [`Event`]s. An empty
/// vec (a keep-alive, an unmapped type, a fragment held for reassembly) is a
/// normal outcome, not a drop; an error is counted and logged with its reason.
pub trait FrameParser: Send + Sync + 'static {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError>;

    /// Extra named counters for `/metrics`, `*_total` for monotonic ones.
    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        Vec::new()
    }
}

/// A source of native frames (a UDP socket, a TCP stream, a serial port).
#[async_trait::async_trait]
pub trait FrameSource: Send {
    /// Read the next frame into `buf`, returning its length.
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Where frames come from, for logs.
    fn describe(&self) -> String;
}

#[derive(Default)]
pub(crate) struct Metrics {
    pub received: Arc<AtomicU64>,
    pub published: Arc<AtomicU64>,
    pub rejected: Arc<AtomicU64>,
    /// Events shed because a publish stalled past [`PUBLISH_DEADLINE`] with no
    /// spool configured.
    pub dropped_backpressure: Arc<AtomicU64>,
    pub spooled: Arc<AtomicU64>,
    /// Spooled events replayed and confirmed delivered.
    pub drained: Arc<AtomicU64>,
    /// Spooled records that failed signature verification on drain.
    pub spool_corrupt: Arc<AtomicU64>,
    pub spool_dropped_segments: Arc<AtomicU64>,
    /// Spool appends that failed (disk full, permissions): the event is lost.
    pub spool_failed: Arc<AtomicU64>,
    /// Events carrying an attribute their entity type does not govern.
    pub ungoverned: Arc<AtomicU64>,
}

/// How long one publish may stall before the event is shed or spooled. Shedding
/// the freshest update is recoverable, since the next report supersedes it;
/// freezing ingest is not.
const PUBLISH_DEADLINE: Duration = Duration::from_secs(2);

const HEARTBEAT_EVERY: Duration = Duration::from_secs(15);

/// Run the connector until SIGTERM or SIGINT, then flush pending publishes.
pub async fn run(
    cfg: Config,
    mut source: Box<dyn FrameSource>,
    parser: impl FrameParser,
) -> anyhow::Result<()> {
    let key = key::load(&cfg.signing_key_path)?;
    let subject = async_nats::Subject::from(format!("{}.{}", cfg.subject_prefix, cfg.source_id));
    // Stamped before sealing, so the marking is inside the signature.
    let marking = cfg.marking()?;
    if let Some(m) = &marking {
        tracing::info!(tags = %m, "every event carries the configured marking");
    }
    let mut reported = BTreeSet::new();

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

    let spool = match &cfg.spool_config() {
        Some(spool_cfg) => {
            let spool = Arc::new(Mutex::new(
                Spool::open(spool_cfg).context("opening the disk spool")?,
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
        let n = tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal, flushing pending publishes");
                let _ = client.flush().await;
                break;
            }
            recv = source.recv(&mut buf) => match recv {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(error = %e, "receive error");
                    // Back off so a persistently failing source cannot spin.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            },
        };
        metrics.received.fetch_add(1, Ordering::Relaxed);
        let events = match parser.parse(&buf[..n]) {
            Ok(events) => events,
            Err(reason) => {
                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(reason = %reason, "dropping unparseable frame");
                continue;
            }
        };
        for mut event in events {
            if let Some(m) = &marking {
                m.apply(&mut event);
            }
            report_ungoverned(&event, &metrics, &mut reported);
            let canonical = ajar_connector::canonical_bytes(&event);
            let sealed = Bytes::from(ajar_connector::seal(&canonical, &key));
            publish_or_spool(
                &client,
                &subject,
                spool.as_deref(),
                &metrics,
                &event.id,
                sealed,
            )
            .await;
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

/// Count, and log once per entity type and attribute, what Core will not
/// govern, since nothing fails at this end.
fn report_ungoverned(event: &Event, metrics: &Metrics, reported: &mut BTreeSet<(String, String)>) {
    if !ontology::knows_type(&event.entity_type) {
        metrics.ungoverned.fetch_add(1, Ordering::Relaxed);
        if reported.insert((event.entity_type.clone(), String::new())) {
            tracing::warn!(
                entity_type = %event.entity_type,
                ontology = ontology::version(),
                "entity type is not in the ontology; Core will reject these events on every site"
            );
        }
        return;
    }
    let lost = ontology::ungoverned(event);
    if !lost.is_empty() {
        metrics.ungoverned.fetch_add(1, Ordering::Relaxed);
    }
    for name in lost {
        if reported.insert((event.entity_type.clone(), name.clone())) {
            tracing::warn!(
                entity_type = %event.entity_type,
                attribute = %name,
                ontology = ontology::version(),
                "attribute is not governed on this entity type; Core will quarantine it or, on a strict site, reject the event: put it in metadata"
            );
        }
    }
}

/// Publish one sealed event; spool it when the publish fails or stalls and a
/// spool is configured, shed it (counted) when not. With the link known down
/// the event goes straight to the spool: the client buffers publishes while
/// reconnecting, so a long outage would otherwise cost the deadline per event.
async fn publish_or_spool(
    client: &async_nats::Client,
    subject: &async_nats::Subject,
    spool: Option<&Mutex<Spool>>,
    metrics: &Metrics,
    event_id: &str,
    sealed: Bytes,
) {
    if let Some(spool) = spool {
        if client.connection_state() != State::Connected {
            spool_append(spool, metrics, event_id, &sealed).await;
            return;
        }
    }
    let publish =
        client.publish_with_headers(subject.clone(), ingest_headers(event_id), sealed.clone());
    match tokio::time::timeout(PUBLISH_DEADLINE, publish).await {
        Ok(Ok(())) => {
            metrics.published.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Err(_)) | Err(_) => match spool {
            Some(spool) => spool_append(spool, metrics, event_id, &sealed).await,
            None => {
                metrics.dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    deadline = ?PUBLISH_DEADLINE,
                    "publish stalled, shedding event"
                );
            }
        },
    }
}

async fn spool_append(spool: &Mutex<Spool>, metrics: &Metrics, event_id: &str, sealed: &[u8]) {
    match spool.lock().await.append(event_id, sealed) {
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
            tracing::warn!(error = %e, "spool append failed, event lost");
        }
    }
}

/// Replay spooled events oldest first, paced at `drain_rate` per second,
/// advancing the cursor only on confirmed delivery.
///
/// Pacing matters because Core's per-source token bucket acknowledges and
/// discards over-rate events, live traffic shares the bucket, and the cursor
/// has already advanced. Confirmation is a JetStream PubAck, which proves the
/// bytes are stored, not that Core kept them; with no stream on the subject
/// (a dev sink on plain NATS) it falls back to publish and flush, the same
/// guarantee the live path has.
fn spawn_drain(
    spool: Arc<Mutex<Spool>>,
    client: async_nats::Client,
    subject: async_nats::Subject,
    verifying_key: ed25519_dalek::VerifyingKey,
    drain_rate: f64,
    metrics: Arc<Metrics>,
) {
    let js = async_nats::jetstream::new(client.clone());
    let gap = Duration::from_secs_f64(1.0 / drain_rate.max(0.1));
    tokio::spawn(async move {
        let mut js_mode = true;
        loop {
            let item = spool.lock().await.peek();
            let Ok(Some((cursor, record))) = item else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };

            // A record that rotted on disk is counted and skipped, never published.
            if ajar_connector::verify(&record.sealed, &verifying_key).is_err() {
                metrics.spool_corrupt.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(event_id = %record.event_id,
                    "spooled record failed verification, skipping");
                if spool.lock().await.advance(cursor).is_err() {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                continue;
            }

            let headers = ingest_headers(&record.event_id);
            let payload = Bytes::from(record.sealed);
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
                // Keep the cursor; a duplicate from this retry is absorbed by
                // the broker's Nats-Msg-Id window.
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });
}

fn spawn_heartbeat(metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT_EVERY);
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

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{self, SignalKind};
        let mut term = unix::signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = unix::signal(SignalKind::interrupt()).expect("SIGINT handler");
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

/// `Nats-Msg-Id` carries the event id, so the broker's duplicate window
/// dedupes retries and reconnect races.
fn ingest_headers(event_id: &str) -> async_nats::HeaderMap {
    let mut headers = async_nats::HeaderMap::new();
    headers.insert("Nats-Msg-Id", event_id);
    headers
}

#[cfg(test)]
mod tests {
    #[test]
    fn ingest_publish_carries_the_event_id() {
        let headers = super::ingest_headers("0198b1c0-aaaa-bbbb-cccc-121212121212");
        assert_eq!(
            headers.get("Nats-Msg-Id").map(|v| v.as_str()),
            Some("0198b1c0-aaaa-bbbb-cccc-121212121212")
        );
    }
}
