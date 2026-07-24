// SPDX-License-Identifier: Apache-2.0
//! The mapping parser eats untrusted records; it must never panic — arbitrary
//! bytes, malformed JSON, short CSV rows all return `Ok` or a typed error.

use ajar_connector_common::Enrichment;
use ajar_generic::{GenericParser, Mapping};
use proptest::prelude::*;

fn json_parser() -> GenericParser {
    #[derive(serde::Deserialize)]
    struct W {
        mapping: Mapping,
    }
    let m = toml::from_str::<W>(
        r#"
        [mapping]
        format = "json"
        entity_type = "mim:sensor"
        timestamp_field = "ts"
        lat_field = "lat"
        lon_field = "lon"
        "#,
    )
    .unwrap()
    .mapping;
    GenericParser::new("fuzz", m, Enrichment::default())
}

fn csv_parser() -> GenericParser {
    #[derive(serde::Deserialize)]
    struct W {
        mapping: Mapping,
    }
    let m = toml::from_str::<W>(
        r#"
        [mapping]
        format = "csv"
        columns = ["ts","lat","lon"]
        entity_type = "mim:sensor"
        timestamp_field = "ts"
        lat_field = "lat"
        lon_field = "lon"
        "#,
    )
    .unwrap()
    .mapping;
    GenericParser::new("fuzz", m, Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = json_parser().to_event(&bytes);
        let _ = csv_parser().to_event(&bytes);
    }

    /// JSON-object-shaped input with hostile field values must never panic.
    #[test]
    fn json_shaped_never_panics(
        ts in "[\\x20-\\x7e]{0,32}",
        lat in "[\\x20-\\x7e]{0,24}",
        lon in "[\\x20-\\x7e]{0,24}",
    ) {
        let frame = format!(r#"{{"ts":"{ts}","lat":"{lat}","lon":"{lon}"}}"#);
        let _ = json_parser().to_event(frame.as_bytes());
    }
}
