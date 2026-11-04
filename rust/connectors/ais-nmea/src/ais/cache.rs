// SPDX-License-Identifier: Apache-2.0
//! Per-MMSI state: the cached static identity and the raw sentences carried
//! forward to the vessel's next position event.

use std::collections::{HashMap, VecDeque};

// MMSIs come from the feed, so a spoofing sender must not grow a cache without
// bound. The oldest vessel is evicted first.
const MAX_VESSELS: usize = 10_000;
pub(super) const MAX_PENDING_FRAMES: usize = 64;
const MAX_PENDING_BYTES: usize = 16 * 1024;

/// What a vessel advertises in its static messages.
#[derive(Debug, Clone, Default, PartialEq)]
pub(super) struct Identity {
    pub(super) name: Option<String>,
    pub(super) callsign: Option<String>,
    pub(super) ship_type: Option<&'static str>,
    pub(super) imo: Option<u32>,
}

#[derive(Default)]
pub(super) struct MmsiCache<V> {
    map: HashMap<u32, V>,
    order: VecDeque<u32>,
}

impl<V: Default> MmsiCache<V> {
    pub(super) fn get(&self, mmsi: u32) -> Option<&V> {
        self.map.get(&mmsi)
    }

    pub(super) fn entry(&mut self, mmsi: u32) -> &mut V {
        if !self.map.contains_key(&mmsi) {
            if self.order.len() >= MAX_VESSELS {
                if let Some(oldest) = self.order.pop_front() {
                    self.map.remove(&oldest);
                }
            }
            self.order.push_back(mmsi);
        }
        self.map.entry(mmsi).or_default()
    }
}

/// Raw sentences for one vessel received since its last event.
#[derive(Default)]
pub(super) struct Carry {
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    dropped_since_emit: bool,
}

impl Carry {
    /// Returns how many of the oldest pending sentences were dropped over the cap.
    pub(super) fn push_raw(&mut self, raw: Vec<u8>) -> u64 {
        self.pending_bytes += raw.len();
        self.pending.push_back(raw);
        let mut dropped = 0;
        while self.pending.len() > MAX_PENDING_FRAMES || self.pending_bytes > MAX_PENDING_BYTES {
            let Some(old) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes -= old.len();
            self.dropped_since_emit = true;
            dropped += 1;
        }
        dropped
    }

    /// The pending sentences followed by `tail`, newline-joined, and whether
    /// any pending sentence was dropped.
    pub(super) fn drain_with(&mut self, tail: Vec<Vec<u8>>) -> (Vec<u8>, bool) {
        let mut frames = Vec::with_capacity(self.pending.len() + tail.len());
        frames.extend(self.pending.drain(..));
        self.pending_bytes = 0;
        let truncated = std::mem::take(&mut self.dropped_since_emit);
        frames.extend(tail);
        (frames.join(&b'\n'), truncated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_evicts_oldest_vessel_at_cap() {
        let mut cache = MmsiCache::<Identity>::default();
        let newest = MAX_VESSELS as u32 + 99;
        for mmsi in 0..=newest {
            cache.entry(mmsi).name = Some(format!("V{mmsi}"));
        }
        assert_eq!(cache.map.len(), MAX_VESSELS, "cache must stay bounded");
        assert!(cache.get(0).is_none(), "oldest entries evicted first");
        assert!(cache.get(newest).is_some(), "newest kept");
        cache.entry(newest).imo = Some(1);
        assert_eq!(cache.map.len(), MAX_VESSELS, "re-touch does not grow");
        assert_eq!(cache.order.len(), MAX_VESSELS, "re-touch does not reorder");
    }
}
