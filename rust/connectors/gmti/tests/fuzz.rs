// SPDX-License-Identifier: Apache-2.0
//! GMTI has no checksum and walks attacker-influenced packet/segment/existence-
//! mask length fields, so its one absolute obligation is to never panic: random
//! bytes, packets that lie about their size, dwell masks that reference every
//! optional field — all must return `Ok` or a typed error.

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

    /// GMTI-shaped input: edition byte 0x03, an arbitrary declared packet size,
    /// and a body of random segments. Exercises the segment walk and, when a dwell
    /// segment appears, the existence-mask-driven field/target reads. Must never
    /// panic.
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
