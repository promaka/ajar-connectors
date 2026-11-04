// SPDX-License-Identifier: Apache-2.0
//! The disk spool against a real nats-server with JetStream: kill the broker
//! mid-stream, keep feeding, restart it, and check every outage event arrives
//! byte-identical, exactly once, at the paced rate.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, SigningKey, Verifier};
use futures_util::StreamExt as _;
use tokio::sync::mpsc;

use common::{Broker, ChannelSource, RecordingParser, SEED};

const SOURCE: &str = "spool-gate";
const SUBJECT: &str = "ajar.ingest.spool-gate";
/// Slow, so the pacing assertion can fail.
const DRAIN_RATE: f64 = 10.0;
const OUTAGE_EVENTS: usize = 15;
const LIVE_EVENTS: usize = 5;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outage_becomes_replication_lag_not_loss() {
    let Some(bin) = common::nats_server("spool") else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("js");
    let spool_dir = dir.path().join("spool");
    let port = common::free_port();

    let broker = Broker::start(&bin, port, Some(&store));
    common::wait_until_up(port).await;

    // The ingest stream as Core creates it: a duplicate window on Nats-Msg-Id.
    let admin = async_nats::connect(format!("nats://127.0.0.1:{port}"))
        .await
        .expect("admin connect");
    let js = async_nats::jetstream::new(admin.clone());
    js.create_stream(async_nats::jetstream::stream::Config {
        name: "AJAR_INGEST".into(),
        subjects: vec![SUBJECT.into()],
        duplicate_window: Duration::from_secs(120),
        ..Default::default()
    })
    .await
    .expect("create stream");

    let cfg = common::config(
        dir.path(),
        SOURCE,
        &format!("nats://127.0.0.1:{port}"),
        &format!(
            "[spool]\ndir = \"{}\"\ndrain_rate = {DRAIN_RATE}\n",
            spool_dir.display()
        ),
    );

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let built = Arc::new(Mutex::new(Vec::new()));
    let parser = RecordingParser {
        source: SOURCE,
        built: built.clone(),
    };
    let connector = tokio::spawn(ajar_connector_common::run(
        cfg,
        Box::new(ChannelSource(rx)),
        parser,
    ));

    for i in 0..LIVE_EVENTS {
        tx.send(format!("live-{i}").into_bytes()).unwrap();
    }
    wait_for_stream_count(&js, LIVE_EVENTS as u64, Duration::from_secs(10)).await;

    drop(broker);
    // Let the client notice the drop.
    tokio::time::sleep(Duration::from_millis(600)).await;
    for i in 0..OUTAGE_EVENTS {
        tx.send(format!("outage-{i}").into_bytes()).unwrap();
    }
    let spool_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let spooled = std::fs::read_dir(&spool_dir)
            .map(|d| d.count())
            .unwrap_or(0);
        if spooled > 0 {
            break;
        }
        assert!(Instant::now() < spool_deadline, "nothing reached the spool");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let restarted_at = Instant::now();
    let _broker2 = Broker::start(&bin, port, Some(&store));
    common::wait_until_up(port).await;

    let total = (LIVE_EVENTS + OUTAGE_EVENTS) as u64;
    wait_for_stream_count(&js, total, Duration::from_secs(60)).await;
    let drained_in = restarted_at.elapsed();

    // One PubAck per drain gap: at least OUTAGE_EVENTS - 1 gaps.
    let floor = Duration::from_secs_f64((OUTAGE_EVENTS as f64 - 1.0) / DRAIN_RATE);
    assert!(
        drained_in >= floor,
        "backlog of {OUTAGE_EVENTS} drained in {drained_in:?}, faster than the \
         paced floor {floor:?}: the drain is bursting"
    );

    let stream = js.get_stream("AJAR_INGEST").await.expect("stream");
    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            durable_name: Some("gate".into()),
            ..Default::default()
        })
        .await
        .expect("consumer");
    let mut delivered: Vec<Vec<u8>> = Vec::new();
    let mut batch = consumer
        .fetch()
        .max_messages(2 * (LIVE_EVENTS + OUTAGE_EVENTS))
        .expires(Duration::from_secs(5))
        .messages()
        .await
        .expect("fetch");
    while let Some(msg) = batch.next().await {
        let msg = msg.expect("message");
        delivered.push(msg.payload.to_vec());
        msg.ack().await.expect("ack");
    }
    assert_eq!(delivered.len() as u64, total, "exactly-once delivery");

    let key = SigningKey::from_bytes(&SEED);
    let built = built.lock().expect("no poisoned lock").clone();
    assert_eq!(built.len() as u64, total, "every frame produced one event");
    let mut matched = vec![false; built.len()];
    for payload in &delivered {
        assert!(payload.len() > 64, "payload shorter than a signature");
        let (sig, canonical) = payload.split_at(64);
        let sig = Signature::from_slice(sig).expect("signature parse");
        key.verifying_key()
            .verify(canonical, &sig)
            .expect("replayed event must verify under the connector key");
        let idx = built
            .iter()
            .position(|(_, c)| c == canonical)
            .expect("delivered payload matches a recorded canonical byte-for-byte");
        assert!(!matched[idx], "an event was delivered twice");
        matched[idx] = true;
    }
    assert!(matched.iter().all(|m| *m), "every built event arrived");

    connector.abort();
}

async fn wait_for_stream_count(js: &async_nats::jetstream::Context, want: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let count = match js.get_stream("AJAR_INGEST").await {
            Ok(mut stream) => stream.info().await.map(|i| i.state.messages).unwrap_or(0),
            Err(_) => 0,
        };
        if count >= want {
            assert_eq!(count, want, "more messages than expected (duplicates?)");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "stream stuck at {count}, wanted {want}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
