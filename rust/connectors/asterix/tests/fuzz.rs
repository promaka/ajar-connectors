// SPDX-License-Identifier: Apache-2.0
//! The ASTERIX decoder walks attacker-influenced FSPEC bitmaps, compound primary
//! bitmaps, and REP/Explicit length fields, so its one absolute obligation is to
//! never panic: random bytes, blocks that lie about their length, and FSPECs that
//! reference every UAP item must all return `Ok` or a typed error.

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

    /// A real category byte, an arbitrary declared length, and a random record
    /// body — exercises the FSPEC walk, compound bitmaps, and every length model
    /// across CAT021/048/062. Must never panic.
    #[test]
    fn category_shaped_input_never_panics(
        cat in prop::sample::select(vec![21u8, 48, 62]),
        body in proptest::collection::vec(any::<u8>(), 0..400),
    ) {
        let len = (body.len() + 3) as u16;
        let mut block = vec![cat, (len >> 8) as u8, len as u8];
        block.extend_from_slice(&body);
        let _ = parser().parse_block(&block);
    }
}
