// SPDX-License-Identifier: Apache-2.0
//! Arbitrary and category-shaped input never panics the decoder.

use ajar_asterix::AsterixParser;
use ajar_connector_common::Enrichment;
use proptest::prelude::*;

fn parser() -> AsterixParser {
    AsterixParser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parser().parse_block(&bytes);
    }

    #[test]
    fn category_shaped_input_never_panics(
        cat in prop::sample::select(vec![10u8, 21, 34, 48, 62]),
        body in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        let len = (body.len() + 3) as u16;
        let mut block = vec![cat, (len >> 8) as u8, len as u8];
        block.extend_from_slice(&body);
        let _ = parser().parse_datagram(&block);
    }
}
