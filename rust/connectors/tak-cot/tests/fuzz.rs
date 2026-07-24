// SPDX-License-Identifier: Apache-2.0
//! The parser sits on an untrusted edge, so its one absolute obligation is: never
//! panic. Whatever arrives — random bytes, truncated XML, absurd numbers, gigabyte
//! attribute names — it must return `Ok` or a typed error, never abort the process.

use std::collections::HashMap;

use ajar_connector_common::Enrichment;
use ajar_tak_cot::CotParser;
use proptest::prelude::*;

fn parser() -> CotParser {
    CotParser::new("fuzz", HashMap::new(), Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Arbitrary bytes must never panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parser().to_event(&bytes);
    }

    /// Structurally CoT-shaped input with hostile field values must never panic —
    /// the numeric and type paths are exercised, not just the XML reader.
    #[test]
    fn cot_shaped_input_never_panics(
        uid in "[\\x20-\\x7e]{0,64}",
        ty in "[\\x20-\\x7e]{0,32}",
        lat in "[\\x20-\\x7e]{0,24}",
        lon in "[\\x20-\\x7e]{0,24}",
    ) {
        let xml = format!(
            r#"<event uid="{uid}" type="{ty}" time="2026-01-01T00:00:00Z"><point lat="{lat}" lon="{lon}" hae="0"/></event>"#
        );
        let _ = parser().to_event(xml.as_bytes());
    }
}
