// SPDX-License-Identifier: Apache-2.0
//! Arbitrary and GMTI-shaped input never panics the parser.

use ajar_connector_common::Enrichment;
use ajar_gmti::GmtiParser;
use proptest::prelude::*;

fn parser() -> GmtiParser {
    GmtiParser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parser().parse_packet(&bytes);
    }

    #[test]
    fn gmti_shaped_input_never_panics(
        size in 0u32..4096,
        body in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let mut pkt = vec![0x03, 0x01];
        pkt.extend_from_slice(&size.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 26]); // rest of the 32-byte header
        pkt.extend_from_slice(&body);
        let _ = parser().parse_packet(&pkt);
    }
}
