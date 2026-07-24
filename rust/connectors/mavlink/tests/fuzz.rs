// SPDX-License-Identifier: Apache-2.0
//! The frame decoder must never panic on hostile input — random bytes, frames
//! that lie about their length, valid magic with garbage bodies.

use ajar_connector_common::Enrichment;
use ajar_mavlink::MavParser;
use proptest::prelude::*;

fn parser() -> MavParser {
    MavParser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parser().parse_frame(&bytes);
    }

    /// Frames that start with a real MAVLink magic byte but carry an arbitrary,
    /// possibly length-lying body must never panic.
    #[test]
    fn framed_input_never_panics(
        magic in prop::sample::select(vec![0xFEu8, 0xFD, 0x00, 0xAB]),
        body in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut frame = vec![magic];
        frame.extend_from_slice(&body);
        let _ = parser().parse_frame(&frame);
    }
}
