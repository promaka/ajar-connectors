// SPDX-License-Identifier: Apache-2.0
//! The disk spool's acceptance gate (#76), against a REAL nats-server with
//! JetStream: kill the broker mid-stream, keep feeding, restart it, and prove
//! that every event produced during the outage arrives byte-identical, exactly
//! once, at a paced rate, with the cursor advanced only on PubAck.
//!
//! Requires a `nats-server` binary. In CI it is installed by the workflow and
//! the test FAILS if missing (a silently-skipped gate is no gate); locally it
//! skips with a notice so `cargo test` stays green on machines without it.

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ajar_connector::{canonical_bytes, Event};
use ajar_connector_common as common;
use ed25519_dalek::{Signature, SigningKey, Verifier};
use tokio::sync::mpsc;

const SOURCE: &str = "spool-gate";
const SUBJECT: &str = "ajar.ingest.spool-gate";
/// Deliberately slow so the pacing assertion has teeth.
const DRAIN_RATE: f64 = 10.0;
const OUTAGE_EVENTS: usize = 15;
const LIVE_EVENTS: usize = 5;

fn nats_server_path() -> Option<String> {
    let explicit = std::env::var("NATS_SERVER_BIN").ok();
    let candidate = explicit.unwrap_or_else(|| "nats-server".to_string());
    let found = Command::new(&candidate)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if found {
        Some(candidate)
    } else if std::env::var("CI").is_ok() {
        panic!("nats-server is required in CI: the spool gate must run, not skip");
    } else {
        eprintln!("spool gate SKIPPED: no nats-server binary (brew install nats-server)");
        None
    }
}

/// A broker child process, killed on drop so a panicking test cannot leak it.
struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_broker(bin: &str, port: u16, store: &std::path::Path) -> Broker {
    let child = Command::new(bin)
        .args([
            "-js",
            "-p",
            &port.to_string(),
            "-sd",
            store.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawning nats-server");
    Broker(child)
}

async fn wait_until_up(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        assert!(Instant::now() < deadline, "nats-server did not come up");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Frames arrive from the test through a channel; the runtime treats it like
/// any other transport.
struct ChannelSource(mpsc::UnboundedReceiver<Vec<u8>>);

#[async_trait::async_trait]
impl common::FrameSource for ChannelSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.recv().await {
            Some(frame) => {
                buf[..frame.len()].copy_from_slice(&frame);
                Ok(frame.len())
            }
            // Channel closed: block forever, the test aborts the task.
            None => std::future::pending().await,
        }
    }
    fn describe(&self) -> String {
        "test channel".into()
    }
}

/// What the parser records per event: (id, canonical bytes), so the test can
/// later assert delivered payloads are byte-identical to what was sealed.
type Built = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Builds one event per frame and records it, outage or not.
struct RecordingParser {
    built: Built,
}

impl common::FrameParser for RecordingParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, common::ParseError> {
        let n = String::from_utf8_lossy(frame).to_string();
        let event = ajar_connector::EventBuilder::new(SOURCE, "mim:vessel")
            .new_id()
            .now()
            .attribute("track_number", &n)
            .build()
            .map_err(|e| -> common::ParseError { format!("{e}").into() })?;
        self.built
            .lock()
            .expect("no poisoned lock")
            .push((event.id.clone(), canonical_bytes(&event)));
        Ok(vec![event])
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outage_becomes_replication_lag_not_loss() {
    let Some(bin) = nats_server_path() else {
        return;
    };

    let dir = std::env::temp_dir().join(format!("ajar-spool-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = dir.join("js");
    let spool_dir = dir.join("spool");

    // A port of our own: bind, read, release.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let broker = start_broker(&bin, port, &store);
    wait_until_up(port).await;

    // Create the ingest stream the way Core does: capture the subject, keep a
    // duplicate window keyed on Nats-Msg-Id.
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

    // The connector under test: real key, real config, spool enabled.
    let seed = [0x42u8; 32];
    let seed_path = dir.join("gate.seed");
    std::fs::write(&seed_path, seed).unwrap();
    let config_text = format!(
        "source_id = \"{SOURCE}\"\n\
         nats_url = \"nats://127.0.0.1:{port}\"\n\
         signing_key_path = \"{}\"\n\
         [transport]\n\
         kind = \"udp\"\n\
         bind = \"127.0.0.1:0\"\n\
         [spool]\n\
         dir = \"{}\"\n\
         drain_rate = {DRAIN_RATE}\n",
        seed_path.display(),
        spool_dir.display()
    );
    let config_path = dir.join("gate.toml");
    std::fs::write(&config_path, config_text).unwrap();
    let cfg = common::Config::load(config_path.to_str().unwrap()).unwrap();

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let built = Arc::new(Mutex::new(Vec::new()));
    let parser = RecordingParser {
        built: built.clone(),
    };
    let connector = tokio::spawn(common::run(cfg, Box::new(ChannelSource(rx)), parser));

    // Phase 1: live traffic flows into the stream.
    for i in 0..LIVE_EVENTS {
        tx.send(format!("live-{i}").into_bytes()).unwrap();
    }
    wait_for_stream_count(&js, LIVE_EVENTS as u64, Duration::from_secs(10)).await;

    // Phase 2: KILL the broker mid-stream and keep the sensor talking.
    drop(broker);
    tokio::time::sleep(Duration::from_millis(600)).await; // client notices the drop
    for i in 0..OUTAGE_EVENTS {
        tx.send(format!("outage-{i}").into_bytes()).unwrap();
    }
    // Every outage event must land on disk, none shed.
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

    // Phase 3: the link returns (same port, same JetStream store).
    let restarted_at = Instant::now();
    let _broker2 = start_broker(&bin, port, &store);
    wait_until_up(port).await;

    // The drain must deliver everything: total = live + outage.
    let total = (LIVE_EVENTS + OUTAGE_EVENTS) as u64;
    wait_for_stream_count(&js, total, Duration::from_secs(60)).await;
    let drained_in = restarted_at.elapsed();

    // PACING: the backlog must not arrive as a burst. With the cursor
    // advancing one PubAck at a time at DRAIN_RATE, the floor is
    // (OUTAGE_EVENTS - 1) gaps. Reconnect wobble only ADDS time.
    let floor = Duration::from_secs_f64((OUTAGE_EVENTS as f64 - 1.0) / DRAIN_RATE);
    assert!(
        drained_in >= floor,
        "backlog of {OUTAGE_EVENTS} drained in {drained_in:?}, faster than the \
         paced floor {floor:?}: the drain is bursting"
    );

    // BYTE-IDENTITY + EXACTLY-ONCE: fetch everything and check each payload
    // is signature(64) ++ the exact canonical bytes recorded at build time,
    // verifying under the connector's key, every id exactly once.
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
    use futures_util::StreamExt as _;
    while let Some(msg) = batch.next().await {
        let msg = msg.expect("message");
        delivered.push(msg.payload.to_vec());
        msg.ack().await.expect("ack");
    }
    assert_eq!(delivered.len() as u64, total, "exactly-once delivery");

    let key = SigningKey::from_bytes(&seed);
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
    let _ = std::fs::remove_dir_all(&dir);
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
