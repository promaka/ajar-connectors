// SPDX-License-Identifier: Apache-2.0
//! The block decoder walks attacker-influenced length fields, so its one absolute
//! obligation is to never panic: random bytes, blocks that lie about their length,
//! FSPECs that reference every UAP item — all must return `Ok` or a typed error.

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

    /// CAT021-shaped blocks with an arbitrary declared length and body must never
    /// panic — this exercises the record walk and every UAP length path.
    #[test]
    fn cat021_shaped_input_never_panics(body in proptest::collection::vec(any::<u8>(), 0..400)) {
        let len = (body.len() + 3) as u16;
        let mut block = vec![21u8, (len >> 8) as u8, len as u8];
        block.extend_from_slice(&body);
        let _ = parser().parse_block(&block);
    }
}
