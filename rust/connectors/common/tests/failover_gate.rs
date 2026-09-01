// SPDX-License-Identifier: Apache-2.0
//! The two-box failover gate: a connector given TWO endpoints in nats_url
//! keeps publishing when the box it is connected to dies.
//!
//! This pins the resiliency story for a dual-Core deployment: box A down ->
//! the client fails over to box B and traffic continues; BOTH boxes down is
//! the spool's job (spool_gate.rs). The comma-separated nats_url form is a
//! documented contract only because this test proves it against real
//! brokers; if the client library ever stops splitting the list, this fails
//! in CI, not on a ship.
//!
//! Requires a `nats-server` binary, same policy as the spool gate: CI
//! installs it and the test fails rather than skips there; locally it skips
//! with a notice.

use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ajar_connector::Event;
use ajar_connector_common as common;
use tokio::sync::mpsc;

const SOURCE: &str = "failover-gate";
const SUBJECT: &str = "ajar.ingest.failover-gate";

fn nats_server_path() -> Option<String> {
    let candidate = std::env::var("NATS_SERVER_BIN").unwrap_or_else(|_| "nats-server".to_string());
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
        panic!("nats-server is required in CI: the failover gate must run, not skip");
    } else {
        eprintln!("failover gate SKIPPED: no nats-server binary (brew install nats-server)");
        None
    }
}

struct Broker(Child);

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_broker(bin: &str, port: u16) -> Broker {
    let child = Command::new(bin)
        .args(["-p", &port.to_string()])
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

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct ChannelSource(mpsc::UnboundedReceiver<Vec<u8>>);

#[async_trait::async_trait]
impl common::FrameSource for ChannelSource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.recv().await {
            Some(frame) => {
                buf[..frame.len()].copy_from_slice(&frame);
                Ok(frame.len())
            }
            None => std::future::pending().await,
        }
    }
    fn describe(&self) -> String {
        "test channel".into()
    }
}

struct CountingParser;

impl common::FrameParser for CountingParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, common::ParseError> {
        let n = String::from_utf8_lossy(frame).to_string();
        let event = ajar_connector::EventBuilder::new(SOURCE, "mim:vessel")
            .new_id()
            .now()
            .attribute("track_number", &n)
            .build()
            .map_err(|e| -> common::ParseError { format!("{e}").into() })?;
        Ok(vec![event])
    }
}

/// Subscribe on a broker and count arrivals on the ingest subject.
async fn count_arrivals(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let nc = async_nats::connect(format!("nats://127.0.0.1:{port}"))
        .await
        .expect("subscriber connect");
    let mut sub = nc.subscribe(SUBJECT.to_string()).await.expect("subscribe");
    tokio::spawn(async move {
        use futures_util::StreamExt as _;
        while let Some(msg) = sub.next().await {
            let id = msg
                .headers
                .as_ref()
                .and_then(|h| h.get("Nats-Msg-Id"))
                .map(|v| v.as_str().to_string())
                .unwrap_or_default();
            seen.lock().expect("no poisoned lock").push(id);
        }
        drop(nc);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_box_means_failover_not_silence() {
    let Some(bin) = nats_server_path() else {
        return;
    };

    // Two independent boxes, no clustering: the CLIENT owns the failover.
    let port_a = free_port();
    let port_b = free_port();
    let broker_a = start_broker(&bin, port_a);
    let _broker_b = start_broker(&bin, port_b);
    wait_until_up(port_a).await;
    wait_until_up(port_b).await;

    let seen_b = Arc::new(Mutex::new(Vec::new()));
    count_arrivals(port_b, seen_b.clone()).await;
    let seen_a = Arc::new(Mutex::new(Vec::new()));
    count_arrivals(port_a, seen_a.clone()).await;

    // The connector under test, given BOTH endpoints in one nats_url.
    let dir = std::env::temp_dir().join(format!("ajar-failover-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gate.seed"), [0x42u8; 32]).unwrap();
    let config_path = dir.join("gate.toml");
    std::fs::write(
        &config_path,
        format!(
            "source_id = \"{SOURCE}\"\n\
             nats_url = \"nats://127.0.0.1:{port_a},nats://127.0.0.1:{port_b}\"\n\
             signing_key_path = \"{}\"\n\
             [transport]\n\
             kind = \"udp\"\n\
             bind = \"127.0.0.1:0\"\n",
            dir.join("gate.seed").display()
        ),
    )
    .unwrap();
    let cfg = common::Config::load(config_path.to_str().unwrap()).unwrap();

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let connector = tokio::spawn(common::run(
        cfg,
        Box::new(ChannelSource(rx)),
        CountingParser,
    ));

    // Phase 1: traffic flows to whichever box the client picked.
    for i in 0..5 {
        tx.send(format!("pre-{i}").into_bytes()).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let total = seen_a.lock().unwrap().len() + seen_b.lock().unwrap().len();
        if total >= 5 {
            break;
        }
        assert!(Instant::now() < deadline, "no traffic before the kill");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Phase 2: kill box A. Whether or not the client was connected to it,
    // the surviving box must carry everything from here on.
    drop(broker_a);
    tokio::time::sleep(Duration::from_millis(800)).await; // reconnect window
    let b_before = seen_b.lock().unwrap().len();
    for i in 0..10 {
        tx.send(format!("post-{i}").into_bytes()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let b_now = seen_b.lock().unwrap().len();
        // At least 8 of 10 post-kill events on box B: the client may lose the
        // one in flight during the reconnect race; sustained delivery is the
        // contract (total loss would show as b_now == b_before).
        if b_now >= b_before + 8 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "box B saw {} events after the kill (had {b_before} before): no failover",
            b_now - b_before
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    connector.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
