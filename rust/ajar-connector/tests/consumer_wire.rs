// SPDX-License-Identifier: Apache-2.0
//! The verified consumer stream against a real broker: valid events reach
//! the caller, tampered ones are counted and dropped inside the stream, and
//! the self-consume guards hold. Same nats-server policy as every wire gate:
//! required in CI, skipped locally without the binary.
#![cfg(feature = "consumer")]

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ajar_connector::consumer::{verified_events, Guards, Stats};
use ajar_connector::{canonical_bytes, seal, EventBuilder, SigningKey};

fn nats_server() -> Option<String> {
    let bin = std::env::var("NATS_SERVER_BIN").unwrap_or_else(|_| "nats-server".into());
    let ok = Command::new(&bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Some(bin)
    } else if std::env::var("CI").is_ok() {
        panic!("nats-server is required in CI: the consumer wire gate must run, not skip");
    } else {
        eprintln!("consumer wire gate SKIPPED: no nats-server binary");
        None
    }
}

fn sealed(key: &SigningKey, source_id: &str, payload: &[u8], model: Option<&str>) -> Vec<u8> {
    let mut b = EventBuilder::new(source_id, "mim:vessel")
        .new_id()
        .now()
        .payload(payload.to_vec());
    if let Some(m) = model {
        b = b.attribute("model", m);
    }
    seal(&canonical_bytes(&b.build().unwrap()), key)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stream_yields_only_what_verifies_and_passes_the_guards() {
    let Some(bin) = nats_server() else { return };
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut broker = Command::new(&bin)
        .args(["-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "broker did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }

    let egress = SigningKey::from_bytes(&[0x55u8; 32]);
    let client = async_nats::connect(format!("nats://127.0.0.1:{port}"))
        .await
        .unwrap();
    let stats = Arc::new(Stats::default());
    let mut guards = Guards {
        skip_derived: true,
        ..Default::default()
    };
    guards.skip_source_ids.insert("me".into());
    let mut stream = verified_events(
        &client,
        "ajar.egress.t.>",
        egress.verifying_key(),
        guards,
        stats.clone(),
    )
    .await
    .unwrap();

    let publisher = async_nats::connect(format!("nats://127.0.0.1:{port}"))
        .await
        .unwrap();
    let subj = "ajar.egress.t.x".to_string();
    publisher
        .publish(
            subj.clone(),
            sealed(&egress, "radar-1", b"one", None).into(),
        )
        .await
        .unwrap();
    let mut tampered = sealed(&egress, "radar-1", b"evil", None);
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    publisher
        .publish(subj.clone(), tampered.into())
        .await
        .unwrap();
    publisher
        .publish(subj.clone(), sealed(&egress, "me", b"mine", None).into())
        .await
        .unwrap();
    publisher
        .publish(
            subj.clone(),
            sealed(&egress, "ai-1", b"derived", Some("m@1")).into(),
        )
        .await
        .unwrap();
    publisher
        .publish(
            subj.clone(),
            sealed(&egress, "radar-1", b"two", None).into(),
        )
        .await
        .unwrap();
    publisher.flush().await.unwrap();

    use futures_util::StreamExt as _;
    let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.payload, b"one");
    assert_eq!(first.event.source_id, "radar-1");
    assert_eq!(first.subject, subj);
    let second = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second.payload, b"two",
        "everything between was refused or skipped"
    );

    use std::sync::atomic::Ordering;
    assert_eq!(stats.accepted.load(Ordering::Relaxed), 2);
    assert_eq!(stats.rejected.load(Ordering::Relaxed), 1);
    assert_eq!(stats.skipped.load(Ordering::Relaxed), 2);

    let _ = broker.kill();
    let _ = broker.wait();
}
