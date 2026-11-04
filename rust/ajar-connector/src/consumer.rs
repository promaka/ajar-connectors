// SPDX-License-Identifier: Apache-2.0
//! The consume side of the SDK: a verified stream of governed events.
//!
//! Behind the `consumer` feature, so the default crate stays transport-free. You bring
//! the connected `async_nats::Client` (your connection, your TLS). The stream yields
//! only events whose Ed25519 seal verified under the deployment's egress key. Tampered
//! events are counted and dropped inside the stream, so your code never sees one.
//!
//! ```no_run
//! # async fn go() -> Result<(), Box<dyn std::error::Error>> {
//! use ajar_connector::consumer::{Guards, Stats};
//! use std::sync::Arc;
//!
//! let client = async_nats::connect("nats://127.0.0.1:4222").await?;
//! let key = ajar_connector::VerifyingKey::from_bytes(&[0u8; 32])?;
//! let stats = Arc::new(Stats::default());
//! let mut events = ajar_connector::consumer::verified_events(
//!     &client,
//!     "ajar.egress.signed.>",
//!     key,
//!     Guards::default(),
//!     stats,
//! )
//! .await?;
//! use futures_util::StreamExt as _;
//! while let Some(delivery) = events.next().await {
//!     println!("{} on {}", delivery.event.id, delivery.subject);
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
    /// The decoded canonical event, whose seal verified.
    pub event: Event,
    /// The event's rendered payload bytes (GeoJSON, CoT, native frame), a copy of
    /// `event.payload`.
    pub payload: Vec<u8>,
    /// The subject it arrived on.
    pub subject: String,
}

/// Skip rules for a platform that publishes derived events: its own events come back
/// out of egress like everything else, and without a guard it assesses its own output
/// forever.
#[derive(Debug, Clone, Default)]
pub struct Guards {
    /// Skip events from these source ids, such as your own producer id.
    pub skip_source_ids: HashSet<String>,
    /// Skip events that carry a `model` attribute: anything produced by an AI or
    /// analytics platform.
    pub skip_derived: bool,
}

/// Live counters for a verified stream.
#[derive(Debug, Default)]
pub struct Stats {
    /// Events yielded to the caller.
    pub accepted: AtomicU64,
    /// Events dropped because the seal did not verify or the bytes did not decode.
    pub rejected: AtomicU64,
    /// Events dropped by [`Guards`].
    pub skipped: AtomicU64,
}

/// Subscribes to `subject` and returns the stream of verified deliveries.
pub async fn verified_events(
    client: &async_nats::Client,
    subject: &str,
    egress_key: VerifyingKey,
    guards: Guards,
    stats: Arc<Stats>,
) -> Result<impl futures_util::Stream<Item = Delivery>, async_nats::SubscribeError> {
    let sub = client.subscribe(subject.to_string()).await?;
    // `ready` keeps the stream Unpin, so callers can call `.next()` directly.
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
            tracing::warn!(total_rejected = n, "event failed seal verification");
            return None;
        }
    };
    let event = match Event::decode(canonical) {
        Ok(e) => e,
        Err(e) => {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %e, "verified bytes are not an event");
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
