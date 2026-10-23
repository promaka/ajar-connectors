// SPDX-License-Identifier: Apache-2.0
//! The decoder sits on a TCP port any edge node can reach, so its one absolute
//! obligation is to never panic: random bytes, valid envelopes with mutated
//! bodies, and oversized or lying frames must all return `Ok` or a typed error.

use ajar_connector_common::{Enrichment, FrameParser};
use ajar_sapient::SapientParser;
use proptest::prelude::*;

fn parser() -> SapientParser {
    SapientParser::new("fuzz", Enrichment::default())
}

/// A valid detection report, to mutate.
fn detection() -> Vec<u8> {
    use ajar_sapient_wire::v2::sapient_message::Content;
    use ajar_sapient_wire::v2::{self, detection_report};
    ajar_sapient_wire::encode(&v2::SapientMessage {
        timestamp: Some(ajar_sapient_wire::now()),
        node_id: Some("node".into()),
        destination_id: None,
        content: Some(Content::DetectionReport(v2::DetectionReport {
            object_id: Some("o".into()),
            location_oneof: Some(detection_report::LocationOneof::Location(v2::Location {
                x: Some(1.0),
                y: Some(2.0),
                coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
                datum: Some(v2::LocationDatum::Wgs84E as i32),
                ..Default::default()
            })),
            ..Default::default()
        })),
        additional_information: None,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parser().parse(&bytes);
    }

    /// A real message with bytes flipped anywhere in it: the protobuf decoder
    /// and every conversion after it must refuse or accept, never panic.
    #[test]
    fn a_mutated_real_message_never_panics(
        flips in proptest::collection::vec((0usize..200, any::<u8>()), 1..8),
    ) {
        let mut bytes = detection();
        for (at, with) in flips {
            if at < bytes.len() {
                bytes[at] = with;
            }
        }
        let _ = parser().parse(&bytes);
    }

    /// Framing on arbitrary bytes: a prefix that lies is refused, never
    /// allocated for or waited on.
    #[test]
    fn framing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = ajar_sapient_wire::unframe(&bytes);
    }
}
