// SPDX-License-Identifier: Apache-2.0
//! Governed events out of Ajar, as consumer-shaped JSON over HTTP.
//!
//! Per event: verify Core's egress signature, decode, dedupe on the event id,
//! render through the field mapping, deliver. An envelope that does not verify
//! under the egress key is counted and dropped.

pub mod config;
pub mod label;
pub mod map;

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use ajar_connector::{Event, SealError, VerifyingKey};
use prost::Message as _;

pub use config::Config;

/// Recent event ids remembered for dedupe.
pub const DEDUPE_WINDOW: usize = 4096;

#[derive(Default, Clone)]
pub struct EgressMetrics {
    /// Events the consumer answered with a 2xx.
    pub delivered: Arc<AtomicU64>,
    /// Envelopes that failed verification or decoding.
    pub rejected: Arc<AtomicU64>,
    pub deduped: Arc<AtomicU64>,
    /// Events refused by the mapping or not delivered within the attempts.
    pub gap_dropped: Arc<AtomicU64>,
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error(transparent)]
    Verify(#[from] SealError),
    #[error("verified bytes are not an event: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Verify one egress envelope and decode the governed event.
pub fn accept(sealed: &[u8], egress_key: &VerifyingKey) -> Result<Event, AcceptError> {
    Ok(Event::decode(ajar_connector::verify(sealed, egress_key)?)?)
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

    /// True if this id is new; remembers it either way, forgetting the oldest
    /// id over the cap.
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
    use ajar_connector::{EventBuilder, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn governed(key: &SigningKey) -> (Vec<u8>, Event) {
        let event = EventBuilder::new("coastal-radar", "mim:vessel")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(59.33, 18.07, 0.0)
            .build()
            .unwrap();
        (
            ajar_connector::seal(&ajar_connector::canonical_bytes(&event), key),
            event,
        )
    }

    #[test]
    fn governed_envelope_verifies_and_decodes() {
        let key = signing_key(1);
        let (sealed, event) = governed(&key);
        let got = accept(&sealed, &key.verifying_key()).unwrap();
        assert_eq!(got.id, event.id);
    }

    #[test]
    fn tampered_envelope_is_refused() {
        let key = signing_key(1);
        let (mut sealed, _) = governed(&key);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(accept(&sealed, &key.verifying_key()).is_err());
    }

    #[test]
    fn envelope_under_another_key_is_refused() {
        let (sealed, _) = governed(&signing_key(1));
        assert!(accept(&sealed, &signing_key(2).verifying_key()).is_err());
    }

    #[test]
    fn dedupe_suppresses_redelivery() {
        let mut d = Dedupe::new(3);
        assert!(d.first_time("a"));
        assert!(!d.first_time("a"));
    }

    #[test]
    fn dedupe_forgets_oldest_over_cap() {
        let mut d = Dedupe::new(3);
        for id in ["a", "b", "c", "d"] {
            assert!(d.first_time(id));
        }
        assert!(d.first_time("a"), "a was evicted by d");
        assert!(!d.first_time("d"));
    }
}
