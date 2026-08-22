// SPDX-License-Identifier: Apache-2.0
//! Governed events out of Ajar, as consumer-shaped JSON over HTTP.
//!
//! The pipeline per event: verify Core's egress signature, decode, dedupe on
//! the event id, render through the field mapping, deliver. Verification comes
//! first and is not optional: this is the only open egress path, and its point
//! is that what leaves the plane is provably what Core governed. An envelope
//! that does not verify under the configured egress key is counted and dropped,
//! never delivered.
//!
//! Delivery is bounded and lossy (`buffer_max`, oldest dropped, counted) —
//! the live-picture posture ingress already documents. The dedupe window exists
//! for the durable leg: when the JetStream consumer lands, redelivery becomes
//! normal and consumers must not see the same event twice from one connector.

pub mod config;
pub mod map;

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use ajar_connector::{verify, Event, VerifyingKey};
use prost::Message as _;

pub use config::Config;

/// Recent event ids remembered for dedupe. Bounded: at 4096 the oldest id is
/// forgotten, which is far wider than any redelivery window the durable leg
/// will use.
pub const DEDUPE_WINDOW: usize = 4096;

#[derive(Default, Clone)]
pub struct EgressMetrics {
    /// Events delivered to the consumer (2xx received).
    pub delivered: Arc<AtomicU64>,
    /// Envelopes that failed verification under the egress key.
    pub rejected: Arc<AtomicU64>,
    /// Duplicates suppressed by id.
    pub deduped: Arc<AtomicU64>,
    /// Events dropped on buffer overflow or delivery exhaustion.
    pub gap_dropped: Arc<AtomicU64>,
}

/// Verify one egress envelope and decode the governed event.
pub fn accept(sealed: &[u8], egress_key: &VerifyingKey) -> Result<Event, String> {
    let canonical = verify(sealed, egress_key).map_err(|e| e.to_string())?;
    Event::decode(canonical).map_err(|e| format!("verified bytes are not an event: {e}"))
}

/// Bounded id window answering "have I delivered this event already?".
pub struct Dedupe {
    seen: HashSet<String>,
    order: VecDeque<String>,
    max: usize,
}

impl Dedupe {
    pub fn new(max: usize) -> Dedupe {
        Dedupe {
            seen: HashSet::new(),
            order: VecDeque::new(),
            max: max.max(1),
        }
    }

    /// True if this id is new; remembers it either way.
    pub fn first_time(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return false;
        }
        if self.order.len() >= self.max {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.order.push_back(id.to_string());
        self.seen.insert(id.to_string());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

    fn egress_key() -> SigningKey {
        // Any key: tests mint their own, the same way Core's egress key store
        // does. No fixed value.
        let mut seed = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            .unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn governed(key: &SigningKey) -> (Vec<u8>, Event) {
        let event = EventBuilder::new("coastal-radar", "mim:vessel")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(59.33, 18.07, 0.0)
            .build()
            .unwrap();
        (seal(&canonical_bytes(&event), key), event)
    }

    #[test]
    fn a_governed_envelope_verifies_and_decodes() {
        let key = egress_key();
        let (sealed, event) = governed(&key);
        let got = accept(&sealed, &key.verifying_key()).unwrap();
        assert_eq!(got.id, event.id);
    }

    #[test]
    fn a_tampered_envelope_is_refused() {
        let key = egress_key();
        let (mut sealed, _) = governed(&key);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(accept(&sealed, &key.verifying_key()).is_err());
    }

    #[test]
    fn an_envelope_under_another_key_is_refused() {
        let (sealed, _) = governed(&egress_key());
        assert!(accept(&sealed, &egress_key().verifying_key()).is_err());
    }

    #[test]
    fn dedupe_suppresses_a_redelivery_and_stays_bounded() {
        let mut d = Dedupe::new(3);
        assert!(d.first_time("a"));
        assert!(!d.first_time("a"));
        assert!(d.first_time("b"));
        assert!(d.first_time("c"));
        assert!(d.first_time("d")); // evicts "a"
        assert!(
            d.first_time("a"),
            "evicted ids may recur; the window is bounded"
        );
        assert!(!d.first_time("d"));
    }
}
