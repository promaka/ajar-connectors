// SPDX-License-Identifier: Apache-2.0
//! DDS transport: subscribe to one topic on a DDS domain and take each sample's
//! serialized bytes as a frame. Requires the `dds` feature.
//!
//! DDS (OMG Data Distribution Service) is the brokerless publish-subscribe bus
//! inside naval combat systems and under ROS 2. The connector joins the domain
//! as one more reader on a topic the ship's own systems already publish;
//! nothing on the ship changes, and the bytes are signed the moment they cross
//! into Ajar. The two buses never meet: this source is the seam.
//!
//! What arrives is the sample's CDR body exactly as the publisher serialized
//! it, without the four-byte encapsulation header (the encoding it named is
//! kept alongside). A parser that understands the publisher's type reads it
//! directly (`payload = "body"`). Two common shapes are unwrapped for it: a
//! struct whose first field is a `sequence<octet>` of raw protocol bytes
//! (`payload = "octets"`), and a struct whose first field is a `string`, such
//! as a ROS 2 `std_msgs/String` or a JSON line (`payload = "string"`).
//! Unwrapping is only done for plain CDR bodies; a delimited or parameter-list
//! encoding carries headers before the first field and is skipped with a
//! warning rather than misread.
//!
//! Matching in DDS needs the topic name and the registered type name to be
//! equal on both sides, and a reader's reliability to be no stricter than the
//! writer's; a mismatch produces silence, not an error. The doctor's transport
//! step says which of those it is. Only the default partition is joined.
//!
//! Samples are buffered until the connector reads them, up to
//! [`SAMPLE_BUFFER`] of them; beyond that the oldest are dropped, which is the
//! only bound and is stated here rather than hidden.

use std::convert::Infallible;
use std::net::IpAddr;

use futures_util::StreamExt;
use rustdds::no_key::{BareDataReaderStream, DataReader, DefaultDecoder, DeserializerAdapter};
use rustdds::serialization::RepresentationIdentifier;
use rustdds::{
    policy, DomainParticipant, DomainParticipantBuilder, QosPolicies, QosPolicyBuilder, Subscriber,
    Topic, TopicKind,
};

use crate::config::{DdsPayload, DdsReliability};
use crate::runtime::FrameSource;

/// The transport's settings: the config's own struct, passed through.
pub type Options = crate::config::DdsOptions;

/// The highest DDS domain id: RTPS port numbers are 7400 + 250 * domain and
/// must fit in 16 bits.
pub const MAX_DOMAIN: u16 = 232;

/// How many samples the reader holds for the connector before dropping the
/// oldest. A surveillance radar's rotation is a burst of a few hundred blocks;
/// this covers a rotation several times over while the runtime publishes.
pub const SAMPLE_BUFFER: i32 = 4096;

/// One sample exactly as it came off the wire, plus the encoding it declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSample {
    pub encoding: RepresentationIdentifier,
    pub bytes: Vec<u8>,
}

impl RawSample {
    /// Whether the declared encoding is little-endian (every `*_LE` variant).
    pub fn little_endian(&self) -> bool {
        LITTLE_ENDIAN.contains(&self.encoding)
    }
    /// Whether the body is plain CDR: the first field starts at byte 0, with
    /// no delimiter header or parameter list before it.
    pub fn plain_cdr(&self) -> bool {
        PLAIN_CDR.contains(&self.encoding)
    }
}

/// An adapter that refuses to interpret: it accepts every CDR encoding and
/// hands the body back untouched. Interpretation is the parser's job.
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

/// The bytes of a `struct { sequence<octet> data; }` sample: the length prefix
/// read in the sample's own byte order, then exactly that many bytes, followed
/// by nothing but CDR padding. `None` when the body is not plain CDR, the
/// prefix runs past the body, or more than padding follows: a sample that does
/// not have that shape.
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

/// The text of a `struct { string s; }` sample: like `unwrap_octets`, then the
/// terminating NUL the CDR string length counts is dropped. `None` when the
/// body does not have that shape or the string is not NUL-terminated.
pub fn unwrap_string(sample: &RawSample) -> Option<&[u8]> {
    match unwrap_octets(sample)?.split_last() {
        Some((0, text)) => Some(text),
        _ => None,
    }
}

/// What the parser is handed for one sample under a payload setting.
pub fn frame_of(sample: &RawSample, payload: DdsPayload) -> Option<&[u8]> {
    match payload {
        DdsPayload::Body => Some(&sample.bytes),
        DdsPayload::Octets => unwrap_octets(sample),
        DdsPayload::String => unwrap_string(sample),
    }
}

/// The reader, its stream, and everything that must stay alive around it.
pub struct DdsSource {
    stream: BareDataReaderStream<RawSample, RawAdapter>,
    describe: String,
    payload: DdsPayload,
    // Dropping these tears the reader down; they are held, not used.
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
                    tracing::warn!(error = ?e, "dds sample could not be read; skipped");
                    continue;
                }
                None => return Err(std::io::Error::other("dds reader stream ended")),
            };
            let Some(bytes) = frame_of(&sample, self.payload) else {
                tracing::warn!(
                    len = sample.bytes.len(),
                    encoding = ?sample.encoding,
                    payload = ?self.payload,
                    "dds sample does not have the configured payload shape; skipped (a typed \
                     struct wants payload = \"body\")"
                );
                continue;
            };
            // Fail closed on size, never truncate: half a record would parse
            // into a wrong event under a valid signature.
            if bytes.len() > buf.len() {
                tracing::warn!(
                    len = bytes.len(),
                    limit = buf.len(),
                    "dds sample larger than the frame limit; dropped"
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

/// The reader QoS for a reliability choice.
pub fn reader_qos(reliability: DdsReliability) -> QosPolicies {
    let reliability = match reliability {
        DdsReliability::BestEffort => policy::Reliability::BestEffort,
        DdsReliability::Reliable => policy::Reliability::Reliable {
            max_blocking_time: rustdds::Duration::from_secs(1),
        },
    };
    // Keep samples until the connector has read them: a radar publishes in
    // bursts, and the DDS default of keeping only the latest would drop the
    // rest of a burst before the reader takes them. KeepAll alone is bounded
    // by the stack's own default of 64 samples, so the bound is set here,
    // explicitly, to SAMPLE_BUFFER.
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
            .map_err(|_| anyhow::anyhow!("dds interface_ip {ip:?} is not an IP address"))?;
        builder = builder.with_only_networks([ip]);
    }
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("joining DDS domain {domain}: {e:?}"))
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
        .map_err(|e| anyhow::anyhow!("dds topic {topic:?}: {e:?}"))?;
    let subscriber = participant
        .create_subscriber(&qos)
        .map_err(|e| anyhow::anyhow!("dds subscriber: {e:?}"))?;
    let reader = subscriber
        .create_datareader_no_key::<RawSample, RawAdapter>(&topic, None)
        .map_err(|e| anyhow::anyhow!("dds reader on {topic:?}: {e:?}"))?;
    Ok((topic, subscriber, reader))
}

/// Join the domain and subscribe. Discovery runs underneath; the first frame
/// arrives once a publisher with the same topic and type name is found.
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

/// What a preflight can learn about a topic in a bounded time, for the doctor.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Probe {
    /// A publisher with the same topic and type name was matched.
    pub matched: bool,
    /// Bytes of the first sample received after matching, if any arrived.
    pub first_sample_len: Option<usize>,
    /// Remote publishers seen on the domain during the wait, as (topic name,
    /// type name). This reader's own topic is never in it, so an empty list
    /// means nothing on the domain publishes anything this box can hear.
    pub publishers: Vec<(String, String)>,
}

/// Join the domain, subscribe, and wait up to `wait` for a match and then a
/// sample. Never blocks longer than `wait`; the caller decides what each
/// outcome means. Read-only on the wire like every doctor step: a reader
/// announces itself, publishes nothing.
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
    fn octets_unwrap_in_the_samples_own_byte_order() {
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
    fn a_body_that_is_not_a_bare_sequence_is_refused_not_misread() {
        // Length claims more than is there: a typed struct, or a torn sample.
        let short = sample(RepresentationIdentifier::CDR_LE, &[9, 0, 0, 0, 1, 2]);
        assert_eq!(unwrap_octets(&short), None);
        let tiny = sample(RepresentationIdentifier::CDR_LE, &[1, 0]);
        assert_eq!(unwrap_octets(&tiny), None);
        let empty = sample(RepresentationIdentifier::CDR_LE, &[0, 0, 0, 0]);
        assert_eq!(unwrap_octets(&empty), Some(&[][..]));
        // A struct { uint32 id; sequence<octet> block; } with id = 7: the
        // first field is not the sequence, so the "length" 7 is followed by
        // far more than padding. Refused rather than handed to a parser.
        let other_first = sample(
            RepresentationIdentifier::CDR_LE,
            &[
                7, 0, 0, 0, 12, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ],
        );
        assert_eq!(unwrap_octets(&other_first), None);
        // A delimited or parameter-list body carries headers before the first
        // field; unwrapping would misread them. Refused, whatever it holds.
        for enc in [
            RepresentationIdentifier::D_CDR2_LE,
            RepresentationIdentifier::PL_CDR_LE,
            RepresentationIdentifier::PL_XCDR2_BE,
        ] {
            let s = sample(enc, &[3, 0, 0, 0, 1, 2, 3, 0]);
            assert_eq!(unwrap_octets(&s), None, "{enc:?}");
            assert_eq!(frame_of(&s, DdsPayload::Body).map(<[u8]>::len), Some(8));
        }
    }

    #[test]
    fn strings_drop_their_terminating_nul_and_nothing_else() {
        let s = sample(
            RepresentationIdentifier::CDR_LE,
            &[6, 0, 0, 0, b'h', b'e', b'l', b'l', b'o', 0, 0, 0],
        );
        assert_eq!(unwrap_string(&s), Some(&b"hello"[..]));
        assert_eq!(frame_of(&s, DdsPayload::String), Some(&b"hello"[..]));
        assert_eq!(frame_of(&s, DdsPayload::Octets), Some(&b"hello\0"[..]));
        assert_eq!(frame_of(&s, DdsPayload::Body).map(<[u8]>::len), Some(12));
        // A binary payload that happens to end in zero is not a string.
        let bin = sample(RepresentationIdentifier::CDR_LE, &[2, 0, 0, 0, 0xFF, 0x01]);
        assert_eq!(unwrap_string(&bin), None);
        assert_eq!(unwrap_octets(&bin), Some(&[0xFF, 0x01][..]));
    }

    #[test]
    fn the_raw_adapter_keeps_bytes_and_encoding_verbatim() {
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
    fn bad_domains_and_interfaces_are_named_before_any_socket_opens() {
        let err = participant(233, None).unwrap_err().to_string();
        assert!(err.contains("233") && err.contains("0 to 232"), "{err}");
        let err = participant(0, Some("not-an-ip")).unwrap_err().to_string();
        assert!(err.contains("not-an-ip"), "{err}");
    }

    #[test]
    fn the_reader_keeps_a_stated_number_of_samples_not_the_stacks_default() {
        let qos = reader_qos(DdsReliability::BestEffort);
        assert_eq!(qos.history(), Some(policy::History::KeepAll));
        assert_eq!(
            qos.resource_limits().map(|r| r.max_samples),
            Some(SAMPLE_BUFFER)
        );
    }
}
