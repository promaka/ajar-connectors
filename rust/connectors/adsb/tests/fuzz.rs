// SPDX-License-Identifier: Apache-2.0
//! The parser sits on an untrusted edge; its one absolute obligation is to never
//! panic. Random bytes, truncated lines, absurd field counts — all must return
//! `Ok` or a typed error, never abort.

use ajar_adsb::AdsbParser;
use ajar_connector_common::Enrichment;
use proptest::prelude::*;

fn parser() -> AdsbParser {
    AdsbParser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parser().parse_line(&bytes);
    }

    /// SBS-shaped input with hostile field values and counts must never panic.
    #[test]
    fn sbs_shaped_input_never_panics(
        tx in 0u16..300,
        icao in "[0-9A-Fa-f]{0,10}",
        callsign in "[\\x20-\\x7e]{0,16}",
        alt in "[\\x2d0-9]{0,8}",
        lat in "[\\x2d0-9.]{0,12}",
        lon in "[\\x2d0-9.]{0,12}",
        extra in 0usize..8,
    ) {
        let mut line = format!(
            "MSG,{tx},1,1,{icao},1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,{callsign},{alt},,,{lat},{lon},,,,,,"
        );
        for _ in 0..extra {
            line.push(',');
        }
        let _ = parser().parse_line(line.as_bytes());
    }
}
