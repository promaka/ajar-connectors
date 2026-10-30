// SPDX-License-Identifier: Apache-2.0
//! The SAPIENT (BSI Flex 335) wire format shared by the ingress and egress
//! connectors: the vendored protobuf schema compiled to Rust in [`v2`] (and
//! [`v1`] behind the `v1` feature), and the stream framing, a 4-byte
//! little-endian length followed by the protobuf bytes.

use std::io;

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt};

/// BSI Flex 335 v2.0, the current schema.
pub mod v2 {
    // Generated from the standard's files and kept verbatim.
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

pub const PREFIX_LEN: usize = 4;

/// The largest message accepted, prefix excluded, so a hostile prefix cannot
/// make a reader allocate or wait.
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Why a frame could not be taken from a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("fewer than {PREFIX_LEN} bytes: no length prefix")]
    NeedPrefix,
    #[error("frame declares {0} bytes, above the {MAX_MESSAGE_LEN} bound")]
    TooLong(usize),
    #[error("frame declares {declared} bytes, {have} present")]
    Incomplete { declared: usize, have: usize },
}

/// Why a frame could not be read from a stream.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("frame declares {0} bytes, above the {MAX_MESSAGE_LEN} bound")]
    TooLong(usize),
    #[error("peer closed the connection")]
    Closed,
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl From<ReadError> for io::Error {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::Io(e) => e,
            ReadError::Closed => io::Error::new(io::ErrorKind::UnexpectedEof, e),
            ReadError::TooLong(_) => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}

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
    Ok(bytes[PREFIX_LEN..].split_at(declared))
}

/// Read the next frame's payload from `reader`. `held` keeps the bytes read
/// past that frame for the next call.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    held: &mut Vec<u8>,
) -> Result<Vec<u8>, ReadError> {
    let mut chunk = [0u8; 8192];
    loop {
        match unframe(held) {
            Ok((payload, _)) => {
                let payload = payload.to_vec();
                held.drain(..PREFIX_LEN + payload.len());
                return Ok(payload);
            }
            Err(FrameError::TooLong(n)) => return Err(ReadError::TooLong(n)),
            Err(FrameError::NeedPrefix | FrameError::Incomplete { .. }) => {}
        }
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Err(ReadError::Closed);
        }
        held.extend_from_slice(&chunk[..n]);
    }
}

/// Encode a v2.0 message to its protobuf bytes, unframed.
pub fn encode(message: &v2::SapientMessage) -> Vec<u8> {
    message.encode_to_vec()
}

/// Decode a v2.0 message from its protobuf bytes, unframed.
pub fn decode(bytes: &[u8]) -> Result<v2::SapientMessage, prost::DecodeError> {
    v2::SapientMessage::decode(bytes)
}

/// A protobuf timestamp as RFC 3339, or `None` outside the representable range.
pub fn rfc3339(ts: &prost_types::Timestamp) -> Option<String> {
    let nanos = i128::from(ts.seconds) * 1_000_000_000 + i128::from(ts.nanos);
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
    t.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

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
    fn encode_frame_unframe_decode_round_trips() {
        let framed = frame(&encode(&detection()));
        assert_eq!(&framed[..4], &(framed.len() as u32 - 4).to_le_bytes());
        let (payload, rest) = unframe(&framed).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decode(payload).unwrap(), detection());
    }

    #[test]
    fn two_frames_split_at_their_prefixes() {
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
    fn short_or_oversized_prefix_is_refused() {
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

    #[tokio::test]
    async fn read_frame_keeps_bytes_past_the_frame() {
        let mut bytes = frame(b"abc");
        bytes.extend(frame(b"de"));
        let mut reader = &bytes[..];
        let mut held = Vec::new();
        assert_eq!(read_frame(&mut reader, &mut held).await.unwrap(), b"abc");
        assert_eq!(read_frame(&mut reader, &mut held).await.unwrap(), b"de");
        assert!(matches!(
            read_frame(&mut reader, &mut held).await,
            Err(ReadError::Closed)
        ));
        let mut oversized = &[0xff, 0xff, 0xff, 0xff][..];
        assert!(matches!(
            read_frame(&mut oversized, &mut Vec::new()).await,
            Err(ReadError::TooLong(_))
        ));
    }

    #[test]
    fn the_encoding_is_pinned() {
        let hex: String = encode(&detection())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "0a0b0880cae2d0061080e59a77122432663163366131652d346135652d346237652d396231612d3064336632653663376131313a5e0a1a30314a385a31563451384b3654324e3353345735583659375a38121a30314a385a31563451384b3654324e3353345735583659374131321f09ebe2361ac05bc0bf11c5feb27bf2c04940190000000000005e40380140013d6666663f",
            "the bytes every SAPIENT peer sees for this report"
        );
    }

    #[test]
    fn timestamps_render_as_rfc3339() {
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
