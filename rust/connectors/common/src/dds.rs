// SPDX-License-Identifier: Apache-2.0
//! DDS transport: subscribe to one topic and hand the parser each sample's CDR
//! body, or the single `sequence<octet>` or `string` field a plain CDR body
//! carries (see [`DdsPayload`]). Topic and type names must match the
//! publisher's exactly; a mismatch is silence, not an error.

use std::convert::Infallible;
use std::net::IpAddr;

use anyhow::Context;
use futures_util::StreamExt;
use rustdds::no_key::{BareDataReaderStream, DataReader, DefaultDecoder, DeserializerAdapter};
use rustdds::serialization::RepresentationIdentifier;
use rustdds::{
    policy, DomainParticipant, DomainParticipantBuilder, QosPolicies, QosPolicyBuilder, Subscriber,
    Topic, TopicKind,
};

use crate::config::{DdsPayload, DdsReliability};
use crate::runtime::FrameSource;

pub type Options = crate::config::DdsOptions;

/// The highest DDS domain id: RTPS port numbers are 7400 + 250 * domain and
/// must fit in 16 bits.
pub const MAX_DOMAIN: u16 = 232;

/// Samples the reader holds before dropping the oldest: several radar
/// rotations' worth of blocks.
pub const SAMPLE_BUFFER: i32 = 4096;

/// One sample as it came off the wire, without the encapsulation header, and
/// the encoding it declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSample {
    pub encoding: RepresentationIdentifier,
    pub bytes: Vec<u8>,
}

impl RawSample {
    pub fn little_endian(&self) -> bool {
        LITTLE_ENDIAN.contains(&self.encoding)
    }
    /// Whether the first field starts at byte 0, with no delimiter header or
    /// parameter list before it.
    pub fn plain_cdr(&self) -> bool {
        PLAIN_CDR.contains(&self.encoding)
    }
}

/// Accepts every CDR encoding and hands the body back untouched.
pub struct RawAdapter;

#[derive(Clone)]
pub struct RawDecoder;
impl<'de> rustdds::no_key::Decode<'de, RawSample> for RawDecoder {
    type Error = Infallible;
    fn decode_bytes(
        self,
        input: &'de [u8],
        encoding: RepresentationIdentifier,
    ) -> Result<RawSample, Infallible> {
        Ok(RawSample {
            encoding,
            bytes: input.to_vec(),
        })
    }
}

static ALL_ENCODINGS: [RepresentationIdentifier; 16] = [
    RepresentationIdentifier::CDR_BE,
    RepresentationIdentifier::CDR_LE,
    RepresentationIdentifier::PL_CDR_BE,
    RepresentationIdentifier::PL_CDR_LE,
    RepresentationIdentifier::CDR2_BE,
    RepresentationIdentifier::CDR2_LE,
    RepresentationIdentifier::PL_CDR2_BE,
    RepresentationIdentifier::PL_CDR2_LE,
    RepresentationIdentifier::D_CDR_BE,
    RepresentationIdentifier::D_CDR_LE,
    RepresentationIdentifier::XCDR2_BE,
    RepresentationIdentifier::XCDR2_LE,
    RepresentationIdentifier::PL_XCDR2_BE,
    RepresentationIdentifier::PL_XCDR2_LE,
    RepresentationIdentifier::D_CDR2_BE,
    RepresentationIdentifier::D_CDR2_LE,
];
static LITTLE_ENDIAN: [RepresentationIdentifier; 8] = [
    RepresentationIdentifier::CDR_LE,
    RepresentationIdentifier::PL_CDR_LE,
    RepresentationIdentifier::CDR2_LE,
    RepresentationIdentifier::PL_CDR2_LE,
    RepresentationIdentifier::D_CDR_LE,
    RepresentationIdentifier::XCDR2_LE,
    RepresentationIdentifier::PL_XCDR2_LE,
    RepresentationIdentifier::D_CDR2_LE,
];
/// Encodings whose first field begins at byte 0 of the body.
static PLAIN_CDR: [RepresentationIdentifier; 6] = [
    RepresentationIdentifier::CDR_BE,
    RepresentationIdentifier::CDR_LE,
    RepresentationIdentifier::CDR2_BE,
    RepresentationIdentifier::CDR2_LE,
    RepresentationIdentifier::XCDR2_BE,
    RepresentationIdentifier::XCDR2_LE,
];

impl DeserializerAdapter<RawSample> for RawAdapter {
    type Error = Infallible;
    type Decoded = RawSample;
    fn supported_encodings() -> &'static [RepresentationIdentifier] {
        &ALL_ENCODINGS
    }
    fn transform_decoded(d: RawSample) -> RawSample {
        d
    }
}
impl DefaultDecoder<RawSample> for RawAdapter {
    type Decoder = RawDecoder;
    const DECODER: RawDecoder = RawDecoder;
}

/// The bytes of a `struct { sequence<octet> data; }` sample: a length prefix in
/// the sample's byte order, that many bytes, then at most CDR padding. `None`
/// for any other shape.
pub fn unwrap_octets(sample: &RawSample) -> Option<&[u8]> {
    if !sample.plain_cdr() {
        return None;
    }
    let head: [u8; 4] = sample.bytes.get(..4)?.try_into().ok()?;
    let len = if sample.little_endian() {
        u32::from_le_bytes(head)
    } else {
        u32::from_be_bytes(head)
    } as usize;
    let end = 4usize.checked_add(len)?;
    let data = sample.bytes.get(4..end)?;
    let trailing = sample.bytes.len() - end;
    (trailing < 4).then_some(data)
}

/// The text of a `struct { string s; }` sample, without the terminating NUL
/// the CDR length counts. `None` for any other shape.
pub fn unwrap_string(sample: &RawSample) -> Option<&[u8]> {
    match unwrap_octets(sample)?.split_last() {
        Some((0, text)) => Some(text),
        _ => None,
    }
}

pub fn frame_of(sample: &RawSample, payload: DdsPayload) -> Option<&[u8]> {
    match payload {
        DdsPayload::Body => Some(&sample.bytes),
        DdsPayload::Octets => unwrap_octets(sample),
        DdsPayload::String => unwrap_string(sample),
    }
}

pub struct DdsSource {
    stream: BareDataReaderStream<RawSample, RawAdapter>,
    describe: String,
    payload: DdsPayload,
    // Held: dropping these tears the reader down.
    _topic: Topic,
    _subscriber: Subscriber,
    _participant: DomainParticipant,
}

#[async_trait::async_trait]
impl FrameSource for DdsSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let sample = match self.stream.next().await {
                Some(Ok(sample)) => sample,
                Some(Err(e)) => {
                    tracing::warn!(error = ?e, "dds sample unreadable, skipped");
                    continue;
                }
                None => return Err(std::io::Error::other("dds reader stream ended")),
            };
            let Some(bytes) = frame_of(&sample, self.payload) else {
                tracing::warn!(
                    len = sample.bytes.len(),
                    encoding = ?sample.encoding,
                    payload = ?self.payload,
                    "dds sample not in the payload shape, skipped"
                );
                continue;
            };
            if bytes.len() > buf.len() {
                tracing::warn!(
                    len = bytes.len(),
                    limit = buf.len(),
                    "dds sample over the frame limit, dropped"
                );
                continue;
            }
            buf[..bytes.len()].copy_from_slice(bytes);
            return Ok(bytes.len());
        }
    }

    fn describe(&self) -> String {
        self.describe.clone()
    }
}

pub fn reader_qos(reliability: DdsReliability) -> QosPolicies {
    let reliability = match reliability {
        DdsReliability::BestEffort => policy::Reliability::BestEffort,
        DdsReliability::Reliable => policy::Reliability::Reliable {
            max_blocking_time: rustdds::Duration::from_secs(1),
        },
    };
    // KeepAll, since keep-latest drops the rest of a burst before the reader
    // takes it; the explicit limit replaces the stack's small default bound.
    QosPolicyBuilder::new()
        .reliability(reliability)
        .history(policy::History::KeepAll)
        .resource_limits(policy::ResourceLimits {
            max_samples: SAMPLE_BUFFER,
            max_instances: 1,
            max_samples_per_instance: SAMPLE_BUFFER,
        })
        .build()
}

/// A participant on `domain`, optionally pinned to the interface holding
/// `interface_ip`.
pub fn participant(domain: u16, interface_ip: Option<&str>) -> anyhow::Result<DomainParticipant> {
    if domain > MAX_DOMAIN {
        anyhow::bail!(
            "dds domain {domain} is out of range: DDS domain ids run from 0 to {MAX_DOMAIN}"
        );
    }
    let mut builder = DomainParticipantBuilder::new(domain);
    if let Some(ip) = interface_ip {
        let ip: IpAddr = ip
            .parse()
            .with_context(|| format!("dds interface_ip {ip:?} is not an IP address"))?;
        builder = builder.with_only_networks([ip]);
    }
    builder
        .build()
        .with_context(|| format!("joining DDS domain {domain}"))
}

/// A raw reader on `topic` with `type_name`, in the default partition.
pub fn raw_reader(
    participant: &DomainParticipant,
    topic: &str,
    type_name: &str,
    reliability: DdsReliability,
) -> anyhow::Result<(Topic, Subscriber, DataReader<RawSample, RawAdapter>)> {
    let qos = reader_qos(reliability);
    let topic = participant
        .create_topic(
            topic.to_string(),
            type_name.to_string(),
            &qos,
            TopicKind::NoKey,
        )
        .with_context(|| format!("dds topic {topic:?}"))?;
    let subscriber = participant
        .create_subscriber(&qos)
        .context("dds subscriber")?;
    let reader = subscriber
        .create_datareader_no_key::<RawSample, RawAdapter>(&topic, None)
        .with_context(|| format!("dds reader on {topic:?}"))?;
    Ok((topic, subscriber, reader))
}

/// Join the domain and subscribe. The first frame arrives once discovery finds
/// a publisher with the same topic and type name.
pub fn open(opts: &Options) -> anyhow::Result<DdsSource> {
    let participant = participant(opts.domain, opts.interface_ip.as_deref())?;
    let (topic, subscriber, reader) =
        raw_reader(&participant, &opts.topic, &opts.type_name, opts.reliability)?;
    Ok(DdsSource {
        stream: reader.async_bare_sample_stream(),
        describe: opts.to_string(),
        payload: opts.payload,
        _topic: topic,
        _subscriber: subscriber,
        _participant: participant,
    })
}

/// What a bounded wait learns about a topic, for the doctor.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Probe {
    /// A publisher with the same topic and type name was matched.
    pub matched: bool,
    pub first_sample_len: Option<usize>,
    /// Remote publishers heard during the wait, as (topic name, type name).
    /// This reader's own topic is never in it.
    pub publishers: Vec<(String, String)>,
}

/// Join the domain, subscribe, and wait at most `wait` for a match and then a
/// sample. Publishes nothing.
pub fn probe(opts: &Options, wait: std::time::Duration) -> anyhow::Result<Probe> {
    use rustdds::{DataReaderStatus, StatusEvented};
    let participant = participant(opts.domain, opts.interface_ip.as_deref())?;
    let (_topic, _subscriber, mut reader) =
        raw_reader(&participant, &opts.topic, &opts.type_name, opts.reliability)?;
    let deadline = std::time::Instant::now() + wait;
    let mut out = Probe::default();
    while std::time::Instant::now() < deadline {
        while let Some(status) = reader.try_recv_status() {
            if let DataReaderStatus::SubscriptionMatched { current, .. } = status {
                if current.count() > 0 {
                    out.matched = true;
                }
            }
        }
        if out.matched {
            if let Ok(Some(sample)) = reader.take_next_sample() {
                out.first_sample_len = Some(sample.value().bytes.len());
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    out.publishers = participant
        .discovered_writers()
        .into_iter()
        .map(|w| {
            (
                w.publication_topic_data.topic_name,
                w.publication_topic_data.type_name,
            )
        })
        .collect();
    out.publishers.sort();
    out.publishers.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(encoding: RepresentationIdentifier, bytes: &[u8]) -> RawSample {
        RawSample {
            encoding,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn octets_unwrap_in_the_samples_byte_order() {
        let le = sample(
            RepresentationIdentifier::CDR_LE,
            &[3, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0],
        );
        assert_eq!(unwrap_octets(&le), Some(&[0xAA, 0xBB, 0xCC][..]));
        let be = sample(RepresentationIdentifier::CDR_BE, &[0, 0, 0, 2, 0x11, 0x22]);
        assert_eq!(unwrap_octets(&be), Some(&[0x11, 0x22][..]));
        let xcdr2 = sample(RepresentationIdentifier::XCDR2_LE, &[1, 0, 0, 0, 0x7F]);
        assert_eq!(unwrap_octets(&xcdr2), Some(&[0x7F][..]));
    }

    #[test]
    fn body_that_is_not_a_bare_sequence_is_refused() {
        let short = sample(RepresentationIdentifier::CDR_LE, &[9, 0, 0, 0, 1, 2]);
        assert_eq!(unwrap_octets(&short), None, "length past the body");
        let tiny = sample(RepresentationIdentifier::CDR_LE, &[1, 0]);
        assert_eq!(unwrap_octets(&tiny), None);
        let empty = sample(RepresentationIdentifier::CDR_LE, &[0, 0, 0, 0]);
        assert_eq!(unwrap_octets(&empty), Some(&[][..]));
        // struct { uint32 id; sequence<octet> block; } with id = 7.
        let other_first = sample(
            RepresentationIdentifier::CDR_LE,
            &[
                7, 0, 0, 0, 12, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ],
        );
        assert_eq!(
            unwrap_octets(&other_first),
            None,
            "more than padding follows"
        );
        for enc in [
            RepresentationIdentifier::D_CDR2_LE,
            RepresentationIdentifier::PL_CDR_LE,
            RepresentationIdentifier::PL_XCDR2_BE,
        ] {
            let s = sample(enc, &[3, 0, 0, 0, 1, 2, 3, 0]);
            assert_eq!(
                unwrap_octets(&s),
                None,
                "headers precede the field: {enc:?}"
            );
            assert_eq!(frame_of(&s, DdsPayload::Body).map(<[u8]>::len), Some(8));
        }
    }

    #[test]
    fn strings_drop_only_their_terminating_nul() {
        let s = sample(
            RepresentationIdentifier::CDR_LE,
            &[6, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', 0, 0, 0],
        );
        assert_eq!(unwrap_string(&s), Some(&b"hello"[..]));
        assert_eq!(frame_of(&s, DdsPayload::String), Some(&b"hello"[..]));
        assert_eq!(frame_of(&s, DdsPayload::Octets), Some(&b"hello\0"[..]));
        assert_eq!(frame_of(&s, DdsPayload::Body).map(<[u8]>::len), Some(12));
        let bin = sample(RepresentationIdentifier::CDR_LE, &[2, 0, 0, 0, 0xFF, 0x01]);
        assert_eq!(unwrap_string(&bin), None, "no NUL terminator");
        assert_eq!(unwrap_octets(&bin), Some(&[0xFF, 0x01][..]));
    }

    #[test]
    fn raw_adapter_keeps_bytes_and_encoding() {
        let s = <RawAdapter as DeserializerAdapter<RawSample>>::from_bytes(
            &[0xDE, 0xAD],
            RepresentationIdentifier::PL_CDR2_BE,
        )
        .unwrap();
        assert_eq!(s.bytes, vec![0xDE, 0xAD]);
        assert_eq!(s.encoding, RepresentationIdentifier::PL_CDR2_BE);
        assert!(!s.little_endian());
        assert!(!s.plain_cdr());
        assert_eq!(
            <RawAdapter as DeserializerAdapter<RawSample>>::supported_encodings().len(),
            16
        );
    }

    #[test]
    fn bad_domain_and_interface_are_named() {
        let err = participant(233, None).unwrap_err().to_string();
        assert!(err.contains("233") && err.contains("0 to 232"), "{err}");
        let err = participant(0, Some("not-an-ip")).unwrap_err().to_string();
        assert!(err.contains("not-an-ip"), "{err}");
    }

    #[test]
    fn reader_keeps_sample_buffer_samples() {
        let qos = reader_qos(DdsReliability::BestEffort);
        assert_eq!(qos.history(), Some(policy::History::KeepAll));
        assert_eq!(
            qos.resource_limits().map(|r| r.max_samples),
            Some(SAMPLE_BUFFER)
        );
    }
}
