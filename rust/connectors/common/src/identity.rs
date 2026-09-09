// SPDX-License-Identifier: Apache-2.0
//! Governed identity: the producer's native identifier for the thing observed,
//! under the standard that minted it (`alt_id`, `alt_id_standard`, contract
//! revision 3). The two keys only mean something together, so they are set
//! together, and an identifier that could not be one (empty, or longer than any
//! standard's) is left out rather than published as a correlation key.

use ajar_connector::EventBuilder;

/// The longest identifier any supported standard mints; anything longer is a
/// malformed frame, not an identity.
pub const MAX_ALT_ID_LEN: usize = 128;

/// Sets `alt_id` and `alt_id_standard` as a pair, or neither.
pub trait GovernedIdentity: Sized {
    fn identity(self, standard: &'static str, id: impl Into<String>) -> Self;
}

impl GovernedIdentity for EventBuilder {
    fn identity(self, standard: &'static str, id: impl Into<String>) -> Self {
        let id = id.into();
        if id.is_empty() || id.len() > MAX_ALT_ID_LEN {
            tracing::debug!(
                len = id.len(),
                standard,
                "identifier not usable as alt_id; omitted"
            );
            return self;
        }
        self.attribute("alt_id", id)
            .attribute("alt_id_standard", standard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr<'a>(ev: &'a ajar_connector::Event, k: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .find(|a| a.key == k)
            .map(|a| a.value.as_str())
    }
    fn builder() -> EventBuilder {
        EventBuilder::new("t", "mim:object")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
    }

    #[test]
    fn the_pair_is_set_together() {
        let ev = builder().identity("AIS", "002320001").build().unwrap();
        assert_eq!(attr(&ev, "alt_id"), Some("002320001"));
        assert_eq!(attr(&ev, "alt_id_standard"), Some("AIS"));
    }

    #[test]
    fn an_empty_or_oversized_identifier_sets_neither() {
        let ev = builder().identity("CoT", "").build().unwrap();
        assert_eq!(attr(&ev, "alt_id"), None);
        assert_eq!(attr(&ev, "alt_id_standard"), None);
        let ev = builder()
            .identity("CoT", "x".repeat(MAX_ALT_ID_LEN + 1))
            .build()
            .unwrap();
        assert_eq!(attr(&ev, "alt_id"), None);
    }
}
