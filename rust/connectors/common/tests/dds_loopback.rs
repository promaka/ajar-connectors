// SPDX-License-Identifier: Apache-2.0
//! The DDS transport end to end on one host: a publisher on a topic, the
//! connector's source subscribed to it, and the frames the connector would
//! parse. Discovery is real (multicast on the host's multicast-capable
//! interface, looped back to this process), so the tests wait for it rather
//! than assuming it.
#![cfg(feature = "dds")]

use ajar_connector_common::dds::{self, Options};
use ajar_connector_common::{DdsPayload, DdsReliability, FrameSource};
use rustdds::no_key::DataWriter;
use rustdds::serialization::CDRSerializerAdapter;
use rustdds::{DomainParticipant, Publisher, Topic, TopicKind};
use std::time::{Duration, Instant};

const TYPE_NAME: &str = "Ajar::Octets";

/// The tests share one DDS domain in one process; run them one at a time so
/// no test's publisher is another test's evidence. The oversize and probe
/// tests each saw the other's topic when they ran in parallel in CI.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A publisher of `Vec<u8>` (a CDR `sequence<octet>`) on `topic`, with the
/// same QoS the source's reader asks for so the two pair.
struct Writer {
    writer: DataWriter<Vec<u8>, CDRSerializerAdapter<Vec<u8>>>,
    _publisher: Publisher,
    _topic: Topic,
    _participant: DomainParticipant,
}

fn writer(topic: &str) -> Writer {
    let participant = dds::participant(0, None).expect("publisher participant");
    let qos = dds::reader_qos(DdsReliability::Reliable);
    let topic = participant
        .create_topic(
            topic.to_string(),
            TYPE_NAME.to_string(),
            &qos,
            TopicKind::NoKey,
        )
        .expect("topic");
    let publisher = participant.create_publisher(&qos).expect("publisher");
    let writer = publisher
        .create_datawriter_no_key::<Vec<u8>, CDRSerializerAdapter<Vec<u8>>>(&topic, None)
        .expect("writer");
    Writer {
        writer,
        _publisher: publisher,
        _topic: topic,
        _participant: participant,
    }
}

fn options(topic: &str, payload: DdsPayload) -> Options {
    Options {
        domain: 0,
        topic: topic.to_string(),
        type_name: TYPE_NAME.to_string(),
        reliability: DdsReliability::Reliable,
        payload,
        interface_ip: None,
    }
}

/// Publish `payloads` repeatedly until the source has received `payloads.len()`
/// frames or the deadline passes; returns the frames in arrival order.
async fn roundtrip(topic: &str, payload: DdsPayload, payloads: &[&[u8]]) -> Vec<Vec<u8>> {
    let _serial = ONE_AT_A_TIME.lock().await;
    let w = writer(topic);
    let mut source = dds::open(&options(topic, payload)).expect("source");
    assert!(source.describe().contains(topic));

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut got = Vec::new();
    let mut buf = vec![0u8; 4096];
    while got.len() < payloads.len() && Instant::now() < deadline {
        // Keep publishing until the reader is matched and has caught up.
        for p in payloads {
            w.writer.write(p.to_vec(), None).expect("write");
        }
        loop {
            match tokio::time::timeout(Duration::from_millis(300), source.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    got.push(buf[..n].to_vec());
                    if got.len() >= payloads.len() {
                        break;
                    }
                }
                Ok(Err(e)) => panic!("recv: {e}"),
                Err(_) => break, // nothing yet; publish again
            }
        }
    }
    got
}

#[tokio::test]
async fn octet_topics_arrive_as_the_bytes_the_publisher_sent() {
    let payloads: [&[u8]; 3] = [b"\x30\x00\x06\x00\x00\x00", b"hello", b""];
    let got = roundtrip("AjarLoopbackOctets", DdsPayload::Octets, &payloads).await;
    assert!(got.len() >= 3, "expected three frames, got {}", got.len());
    for p in payloads {
        assert!(got.iter().any(|g| g == p), "missing frame {p:?} in {got:?}");
    }
}

#[tokio::test]
async fn without_unwrapping_the_cdr_body_is_delivered_intact() {
    let got = roundtrip("AjarLoopbackBody", DdsPayload::Body, &[b"abc"]).await;
    assert!(!got.is_empty(), "no frames");
    // CDR of a sequence<octet> "abc": u32 length 3, the bytes, then padding
    // to a four-byte boundary. The body is delivered as serialized.
    let body = &got[0];
    assert!(body.len() >= 7, "{body:?}");
    let len = u32::from_le_bytes(body[..4].try_into().unwrap());
    assert_eq!(len, 3);
    assert_eq!(&body[4..7], b"abc");
}

#[tokio::test]
async fn a_sample_larger_than_the_frame_limit_is_dropped_not_truncated() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let big = vec![0x41u8; 300];
    let small = b"ok";
    let w = writer("AjarLoopbackOversize");
    let mut source =
        dds::open(&options("AjarLoopbackOversize", DdsPayload::Octets)).expect("source");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut buf = vec![0u8; 64]; // a limit the big sample exceeds
    let mut got = Vec::new();
    while got.is_empty() && Instant::now() < deadline {
        w.writer.write(big.clone(), None).expect("write");
        w.writer.write(small.to_vec(), None).expect("write");
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), source.recv(&mut buf)).await
        {
            got.push(buf[..n].to_vec());
        }
    }
    // Only the small one is ever handed over; the big one is dropped whole,
    // never cut to the buffer.
    assert_eq!(got.first().map(Vec::as_slice), Some(&small[..]), "{got:?}");
}

#[test]
fn the_probe_reports_a_match_and_a_sample_when_a_publisher_exists() {
    let _serial = ONE_AT_A_TIME.blocking_lock();
    let w = writer("AjarProbeTopic");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let feeder = std::thread::spawn(move || {
        while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = w.writer.write(b"probe".to_vec(), None);
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let probe = dds::probe(
        &options("AjarProbeTopic", DdsPayload::Octets),
        Duration::from_secs(20),
    )
    .expect("probe");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    feeder.join().unwrap();
    assert!(probe.matched, "{probe:?}");
    assert!(probe.first_sample_len.is_some(), "{probe:?}");
    assert!(
        probe
            .publishers
            .iter()
            .any(|(n, t)| n == "AjarProbeTopic" && t == TYPE_NAME),
        "{probe:?}"
    );
}

#[test]
fn the_probe_reports_no_match_and_no_publishers_when_nobody_publishes() {
    // A domain id nobody else in these tests uses, so no other test's
    // publisher is heard: the list must be empty, not merely lacking the topic.
    let _serial = ONE_AT_A_TIME.blocking_lock();
    let mut o = options("AjarNobodyPublishesHere", DdsPayload::Body);
    o.domain = 7;
    let probe = dds::probe(&o, Duration::from_secs(2)).expect("probe");
    assert!(!probe.matched, "{probe:?}");
    assert_eq!(probe.first_sample_len, None);
    assert!(
        probe.publishers.is_empty(),
        "own topic leaked into the list: {probe:?}"
    );
}
