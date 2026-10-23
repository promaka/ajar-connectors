// SPDX-License-Identifier: Apache-2.0
//! The SAPIENT wire format, BSI Flex 335: the UK MOD interface between sensor
//! edge nodes and a fusion node, used for counter-UAS.
//!
//! Two things live here and nothing else, so the ingress and egress connectors
//! share one definition of the bytes:
//!
//! - the published protobuf schema, compiled to Rust in [`v2`] (and [`v1`]
//!   behind the `v1` feature), from the files vendored under `proto/`;
//! - the framing the standard puts around each message on a TCP stream: a
//!   4-byte little-endian length, then the protobuf bytes.
//!
//! Decoding is prost's; the helpers here add the framing and the few
//! conversions every connector needs (timestamps, the frame size bound).

use prost::Message;

/// BSI Flex 335 v2.0, the current schema.
pub mod v2 {
    // Generated from the standard's own files, comments included; they are
    // not written to Rust's lint conventions and are kept verbatim.
    #![allow(clippy::all)]
    include!(concat!(
        env!("OUT_DIR"),
        "/sapient_msg.bsi_flex_335_v2_0.rs"
    ));
}

/// BSI Flex 335 v1.0, for a site still on it. Compiled only with the `v1`
/// feature.
#[cfg(feature = "v1")]
pub mod v1 {
    #![allow(clippy::all)]
    include!(concat!(
        env!("OUT_DIR"),
        "/sapient_msg.bsi_flex_335_v1_0.rs"
    ));
}

/// The standard's version string a v2.0 node declares in its registration.
pub const ICD_VERSION_V2: &str = "BSI Flex 335 v2.0";

/// Bytes in the length prefix.
pub const PREFIX_LEN: usize = 4;

/// The largest message a connector accepts, prefix excluded. A detection
/// report with every optional field is a few kilobytes; this bound exists so
/// a hostile prefix cannot make a reader allocate or wait.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Why a frame could not be taken from a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than four bytes: no prefix yet.
    NeedPrefix,
    /// The prefix declares more than [`MAX_MESSAGE_LEN`].
    TooLong(usize),
    /// The prefix is whole but the payload is not all there yet.
    Incomplete { declared: usize, have: usize },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedPrefix => write!(f, "fewer than {PREFIX_LEN} bytes: no length prefix"),
            Self::TooLong(n) => write!(
                f,
                "frame declares {n} bytes, above the {MAX_MESSAGE_LEN} bound"
            ),
            Self::Incomplete { declared, have } => {
                write!(f, "frame declares {declared} bytes, {have} present")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Wrap one encoded message in the standard's framing.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREFIX_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Take one frame off the front of `bytes`: the payload and the rest.
pub fn unframe(bytes: &[u8]) -> Result<(&[u8], &[u8]), FrameError> {
    if bytes.len() < PREFIX_LEN {
        return Err(FrameError::NeedPrefix);
    }
    let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if declared > MAX_MESSAGE_LEN {
        return Err(FrameError::TooLong(declared));
    }
    let have = bytes.len() - PREFIX_LEN;
    if have < declared {
        return Err(FrameError::Incomplete { declared, have });
    }
    let (payload, rest) = bytes[PREFIX_LEN..].split_at(declared);
    Ok((payload, rest))
}

/// Encode a v2.0 message to its protobuf bytes, unframed.
pub fn encode(message: &v2::SapientMessage) -> Vec<u8> {
    message.encode_to_vec()
}

/// Decode a v2.0 message from its protobuf bytes, unframed.
pub fn decode(bytes: &[u8]) -> Result<v2::SapientMessage, prost::DecodeError> {
    v2::SapientMessage::decode(bytes)
}

/// A protobuf timestamp as the RFC 3339 string an event carries, or `None`
/// for one outside the representable range.
pub fn rfc3339(ts: &prost_types::Timestamp) -> Option<String> {
    let nanos = i128::from(ts.seconds) * 1_000_000_000 + i128::from(ts.nanos);
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    t.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// The current time as a protobuf timestamp.
pub fn now() -> prost_types::Timestamp {
    let t = time::OffsetDateTime::now_utc();
    prost_types::Timestamp {
        seconds: t.unix_timestamp(),
        nanos: t.nanosecond() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2::sapient_message::Content;

    fn detection() -> v2::SapientMessage {
        v2::SapientMessage {
            timestamp: Some(prost_types::Timestamp {
                seconds: 1_780_000_000,
                nanos: 250_000_000,
            }),
            node_id: Some("2f1c6a1e-4a5e-4b7e-9b1a-0d3f2e6c7a11".into()),
            destination_id: None,
            content: Some(Content::DetectionReport(v2::DetectionReport {
                report_id: Some("01J8Z1V4Q8K6T2N3S4W5X6Y7Z8".into()),
                object_id: Some("01J8Z1V4Q8K6T2N3S4W5X6Y7A1".into()),
                location_oneof: Some(v2::detection_report::LocationOneof::Location(
                    v2::Location {
                        x: Some(-0.1278),
                        y: Some(51.5074),
                        z: Some(120.0),
                        coordinate_system: Some(v2::LocationCoordinateSystem::LatLngDegM as i32),
                        datum: Some(v2::LocationDatum::Wgs84E as i32),
                        ..Default::default()
                    },
                )),
                detection_confidence: Some(0.9),
                ..Default::default()
            })),
            additional_information: None,
        }
    }

    #[test]
    fn a_message_survives_encode_frame_unframe_decode() {
        let framed = frame(&encode(&detection()));
        assert_eq!(&framed[..4], &(framed.len() as u32 - 4).to_le_bytes());
        let (payload, rest) = unframe(&framed).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decode(payload).unwrap(), detection());
    }

    #[test]
    fn two_frames_split_where_the_prefixes_say() {
        let mut bytes = frame(b"abc");
        bytes.extend(frame(b""));
        let (first, rest) = unframe(&bytes).unwrap();
        assert_eq!(first, b"abc");
        let (second, rest) = unframe(rest).unwrap();
        assert_eq!(second, b"");
        assert!(rest.is_empty());
        assert_eq!(unframe(rest), Err(FrameError::NeedPrefix));
    }

    #[test]
    fn a_short_or_hostile_prefix_is_refused_not_waited_for() {
        assert_eq!(unframe(&[1, 0]), Err(FrameError::NeedPrefix));
        assert_eq!(
            unframe(&[5, 0, 0, 0, 1, 2]),
            Err(FrameError::Incomplete {
                declared: 5,
                have: 2
            })
        );
        assert_eq!(
            unframe(&[0xff, 0xff, 0xff, 0xff]),
            Err(FrameError::TooLong(u32::MAX as usize))
        );
    }

    #[test]
    fn the_encoding_is_pinned() {
        // The bytes a v2.0 node puts on the wire for this report. A change here
        // is a change to what every SAPIENT peer sees.
        let hex: String = encode(&detection())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "0a0b0880cae2d0061080e59a77122432663163366131652d346135652d346237652d396231612d3064336632653663376131313a5e0a1a30314a385a31563451384b3654324e3353345735583659375a38121a30314a385a31563451384b3654324e3353345735583659374131321f09ebe2361ac05bc0bf11c5feb27bf2c04940190000000000005e40380140013d6666663f",
            "see the note above"
        );
    }

    #[test]
    fn timestamps_render_as_rfc3339_and_bad_ones_as_none() {
        let ts = prost_types::Timestamp {
            seconds: 1_780_000_000,
            nanos: 0,
        };
        assert_eq!(rfc3339(&ts).as_deref(), Some("2026-05-28T20:26:40Z"));
        let bad = prost_types::Timestamp {
            seconds: i64::MAX,
            nanos: 0,
        };
        assert_eq!(rfc3339(&bad), None);
    }
}
