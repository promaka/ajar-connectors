// SPDX-License-Identifier: Apache-2.0
//! Arbitrary and KLV-shaped input never panics the parser.

use ajar_connector_common::Enrichment;
use ajar_klv::KlvParser;
use proptest::prelude::*;

const KEY: [u8; 16] = [
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

fn parser() -> KlvParser {
    KlvParser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parser().parse_set(&bytes);
    }

    #[test]
    fn klv_shaped_input_never_panics(body in proptest::collection::vec(any::<u8>(), 0..400)) {
        let n = body.len();
        let mut set = KEY.to_vec();
        set.push(0x82);
        set.push((n >> 8) as u8);
        set.push((n & 0xff) as u8);
        set.extend_from_slice(&body);
        let _ = parser().parse_set(&set);
    }
}
