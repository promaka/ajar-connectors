// SPDX-License-Identifier: Apache-2.0
//! The consume side of the SDK: a verified stream of governed events.
//!
//! Feature-gated (`features = ["consumer"]`) so the default crate stays
//! transport-free. You bring the connected `async_nats::Client` (your
//! connection, your TLS); this module owns the security-critical middle:
//! the stream only ever yields events whose Ed25519 signature verified
//! under the deployment's egress key. Tampered events are counted and
//! dropped inside the stream - your code never sees one.
//!
//! ```no_run
//! # async fn go() -> Result<(), Box<dyn std::error::Error>> {
//! use ajar_connector::consumer::{verified_events, Guards, Stats};
//! use std::sync::Arc;
//!
//! let client = async_nats::connect("nats://127.0.0.1:4222").await?;
//! let key = ajar_connector::VerifyingKey::from_bytes(&[0u8; 32])?;
//! let stats = Arc::new(Stats::default());
//! let mut events =
//!     verified_events(&client, "ajar.egress.geojson.>", key, Guards::default(), stats).await?;
//! use futures_util::StreamExt as _;
//! while let Some(delivery) = events.next().await {
//!     // delivery.event verified; delivery.payload is the rendered bytes.
//! }
//! # Ok(()) }
//! ```

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use futures_util::StreamExt as _;
use prost::Message as _;

use crate::{verify, Event, VerifyingKey};

/// One verified governed event, as delivered.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// The decoded canonical event. Its signature verified; you never see
    /// one that did not.
    pub event: Event,
    /// The event's rendered payload bytes (GeoJSON, CoT, native frame...).
    pub payload: Vec<u8>,
    /// The subject it arrived on.
    pub subject: String,
}

/// The skip rules a deriving platform needs: its own events come back out of
/// egress like everything else, and without a guard the loop assesses its
/// own output forever.
#[derive(Debug, Clone, Default)]
pub struct Guards {
    /// Drop events published under these identities (your own producer id).
    pub skip_source_ids: HashSet<String>,
    /// Drop any event carrying a `model` attribute - anything produced by an
    /// AI/analytics platform.
    pub skip_derived: bool,
}

/// Live counters. Rejected events were dropped inside the stream and never
/// reached your code.
#[derive(Debug, Default)]
pub struct Stats {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub skipped: AtomicU64,
}

/// Subscribe and return the verified stream. See the module docs.
pub async fn verified_events(
    client: &async_nats::Client,
    subject: &str,
    egress_key: VerifyingKey,
    guards: Guards,
    stats: Arc<Stats>,
) -> Result<impl futures_util::Stream<Item = Delivery>, async_nats::SubscribeError> {
    let sub = client.subscribe(subject.to_string()).await?;
    // Verification is synchronous, so the per-message future is `ready(..)`
    // and the returned stream stays Unpin (callers can `.next()` it plainly).
    Ok(sub.filter_map(move |msg| std::future::ready(process(&msg, &egress_key, &guards, &stats))))
}

fn process(
    msg: &async_nats::Message,
    egress_key: &VerifyingKey,
    guards: &Guards,
    stats: &Stats,
) -> Option<Delivery> {
    let canonical = match verify(&msg.payload, egress_key) {
        Ok(c) => c,
        Err(_) => {
            let n = stats.rejected.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                total_rejected = n,
                "rejected an event that does not verify under the egress key"
            );
            return None;
        }
    };
    let event = match Event::decode(canonical) {
        Ok(e) => e,
        Err(e) => {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %e, "rejected: verified bytes are not an event");
            return None;
        }
    };
    if guards.skip_source_ids.contains(&event.source_id)
        || (guards.skip_derived && event.attributes.iter().any(|a| a.key == "model"))
    {
        stats.skipped.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    stats.accepted.fetch_add(1, Ordering::Relaxed);
    let payload = event.payload.clone();
    Some(Delivery {
        event,
        payload,
        subject: msg.subject.to_string(),
    })
}
