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

use ajar_connector_common::FrameParser;

proptest::proptest! {
    /// The radar path (TTM/GGA/RMC dispatch, geolocation, tag-block stripping)
    /// enters through FrameParser::parse, so it is fuzzed there: arbitrary
    /// bytes and TTM-shaped sentences must never panic, whatever the field
    /// soup and whether or not a tag block precedes it.
    #[test]
    fn arbitrary_bytes_never_panic_the_full_parse(
        bytes in proptest::collection::vec(any::<u8>(), 0..1024)
    ) {
        let _ = parser().parse(&bytes);
    }

    #[test]
    fn ttm_shaped_input_never_panics(
        tag in proptest::option::of("[ -~]{0,40}"),
        fields in proptest::collection::vec("[ -~]{0,12}", 0..20),
    ) {
        let body = format!("RATTM,{}", fields.join(","));
        let cs = body.bytes().fold(0u8, |a, b| a ^ b);
        let sentence = match tag {
            Some(t) => format!("\\{t}\\${body}*{cs:02X}"),
            None => format!("${body}*{cs:02X}"),
        };
        let _ = parser().parse(sentence.as_bytes());
    }

    #[test]
    fn ownship_shaped_input_never_panics(
        kind in proptest::sample::select(vec!["GPGGA", "GPRMC"]),
        fields in proptest::collection::vec("[0-9A-Za-z.\\-]{0,10}", 0..16),
    ) {
        let body = format!("{kind},{}", fields.join(","));
        let cs = body.bytes().fold(0u8, |a, b| a ^ b);
        let _ = parser().parse(format!("${body}*{cs:02X}").as_bytes());
    }
}
