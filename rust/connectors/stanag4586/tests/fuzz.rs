// SPDX-License-Identifier: Apache-2.0
//! Arbitrary and wrapper-shaped input never panics the parser.

use ajar_connector_common::Enrichment;
use ajar_stanag4586::S4586Parser;
use proptest::prelude::*;

fn parser() -> S4586Parser {
    S4586Parser::new("fuzz", Enrichment::default())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parser().to_events(&bytes);
    }

    #[test]
    fn wrapper_shaped_input_never_panics(
        message_type in prop::sample::select(vec![20u32, 101, 200, 3000, 0xFFFF_FFFF]),
        declared_len in any::<u32>(),
        body in proptest::collection::vec(any::<u8>(), 0..200),
        fix_checksum in any::<bool>(),
    ) {
        let mut m = Vec::new();
        m.extend_from_slice(b"8\0\0\0\0\0\0\0\0\0");
        m.extend_from_slice(&1u32.to_be_bytes());
        m.extend_from_slice(&message_type.to_be_bytes());
        m.extend_from_slice(&declared_len.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        m.extend_from_slice(&body);
        if fix_checksum {
            let sum = m.iter().fold(0u32, |a, &b| a.wrapping_add(b as u32));
            m.extend_from_slice(&sum.to_be_bytes());
        } else {
            m.extend_from_slice(&0u32.to_be_bytes());
        }
        let _ = parser().to_events(&m);
    }
}
