// SPDX-License-Identifier: Apache-2.0
//! The parser sits on an untrusted edge; its one absolute obligation is to never
//! panic. Random bytes, hostile armor, absurd fragment counts — all must return
//! `Ok` or a typed error, never abort.

use ajar_ais_nmea::AisParser;
use ajar_connector_common::Enrichment;
use proptest::prelude::*;

fn parser() -> AisParser {
    AisParser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parser().parse_sentence(&bytes);
    }

    /// AIVDM-shaped input with hostile fragment counts and armor must never panic.
    #[test]
    fn aivdm_shaped_input_never_panics(
        count in 0u16..300,
        num in 0u16..300,
        seq in 0u16..300,
        payload in "[\\x20-\\x7e]{0,80}",
        fill in 0u16..20,
    ) {
        let body = format!("!AIVDM,{count},{num},{seq},A,{payload},{fill}");
        let sum = body[1..].bytes().fold(0u8, |a, b| a ^ b);
        let sentence = format!("{body}*{sum:02X}");
        let _ = parser().parse_sentence(sentence.as_bytes());
    }
}
