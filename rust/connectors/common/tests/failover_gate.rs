// SPDX-License-Identifier: Apache-2.0
//! The failover gate: a connector given two endpoints in `nats_url` keeps
//! publishing when the broker it is connected to dies.

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use tokio::sync::mpsc;

use common::{Broker, ChannelSource, RecordingParser};

const SOURCE: &str = "failover-gate";
const SUBJECT: &str = "ajar.ingest.failover-gate";

/// Subscribe on a broker and record the `Nats-Msg-Id` of each arrival.
async fn count_arrivals(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let nc = async_nats::connect(format!("nats://127.0.0.1:{port}"))
        .await
        .expect("subscriber connect");
    let mut sub = nc.subscribe(SUBJECT.to_string()).await.expect("subscribe");
    tokio::spawn(async move {
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
    let Some(bin) = common::nats_server("failover") else {
        return;
    };

    // Two independent brokers, no clustering: the client owns the failover.
    let port_a = common::free_port();
    let port_b = common::free_port();
    let broker_a = Broker::start(&bin, port_a, None);
    let _broker_b = Broker::start(&bin, port_b, None);
    common::wait_until_up(port_a).await;
    common::wait_until_up(port_b).await;

    let seen_b = Arc::new(Mutex::new(Vec::new()));
    count_arrivals(port_b, seen_b.clone()).await;
    let seen_a = Arc::new(Mutex::new(Vec::new()));
    count_arrivals(port_a, seen_a.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(
        dir.path(),
        SOURCE,
        &format!("nats://127.0.0.1:{port_a},nats://127.0.0.1:{port_b}"),
        "",
    );

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let parser = RecordingParser {
        source: SOURCE,
        built: Default::default(),
    };
    let connector = tokio::spawn(ajar_connector_common::run(
        cfg,
        Box::new(ChannelSource(rx)),
        parser,
    ));

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

    // Whichever broker the client was on, B must carry everything from here.
    drop(broker_a);
    // Reconnect window.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let b_before = seen_b.lock().unwrap().len();
    for i in 0..10 {
        tx.send(format!("post-{i}").into_bytes()).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let b_now = seen_b.lock().unwrap().len();
        // The event in flight during the reconnect may be lost.
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
}
