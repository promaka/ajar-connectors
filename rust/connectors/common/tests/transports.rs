// SPDX-License-Identifier: Apache-2.0
//! The transport layer against real I/O: sockets, files, directories and child
//! processes, no mocks. Each transport is exercised on its happy path and on
//! the failure branch a field deployment actually hits: rotation, disconnect,
//! a process that dies. The live CI gates prove one happy path each; the
//! rest is proven here.

use ajar_connector_common::{dir, exec, file, health, tcp, tcp_server, FrameSource, Framing};
use std::io::Write as _;
use std::time::Duration;

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ajar-transport-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn recv_string(src: &mut (impl FrameSource + ?Sized)) -> String {
    let mut buf = vec![0u8; 64 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), src.recv(&mut buf))
        .await
        .expect("transport delivered nothing within 10s")
        .expect("transport errored");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test]
async fn file_tails_appends_and_survives_rotation() {
    let path = tmp("file").join("feed.log");
    std::fs::write(&path, "old line\n").unwrap();

    let mut src = file::open(path.to_str().unwrap(), false).await.unwrap();
    let p = path.clone();
    tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(300));
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "first").unwrap();
    });
    assert_eq!(recv_string(&mut src).await, "first");

    // Rotation: replaced with a shorter file; the tail must reopen from the
    // start rather than sleeping on a stale offset forever.
    let p = path.clone();
    tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(&p, "rotated\n").unwrap();
    });
    assert_eq!(recv_string(&mut src).await, "rotated");
}

#[tokio::test]
async fn file_from_start_replays_existing_content() {
    let path = tmp("file-replay").join("feed.log");
    std::fs::write(&path, "already here\n").unwrap();
    let mut src = file::open(path.to_str().unwrap(), true).await.unwrap();
    assert_eq!(recv_string(&mut src).await, "already here");
}

#[tokio::test]
async fn file_open_refuses_a_missing_path() {
    assert!(file::open("/nonexistent/feed.log", false).await.is_err());
}

#[tokio::test]
async fn dir_delivers_a_dropped_file_once_settled() {
    let drop_dir = tmp("dir");
    let mut src = dir::open(drop_dir.to_str().unwrap(), false).unwrap();
    let d = drop_dir.clone();
    tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(d.join("drop-001.json"), "{\"lat\":1.0}\n").unwrap();
    });
    assert_eq!(recv_string(&mut src).await, "{\"lat\":1.0}");
}

#[tokio::test]
async fn exec_reads_the_child_stdout_line_by_line() {
    let mut src = exec::open("/bin/sh", &["-c".into(), "printf 'a\\nb\\n'".into()]).unwrap();
    assert_eq!(recv_string(&mut src).await, "a");
    assert_eq!(recv_string(&mut src).await, "b");
}

#[tokio::test]
async fn exec_respawns_when_the_command_exits() {
    // The documented contract: a command that exits is respawned. One shot of
    // output per run, so a second delivery proves a second spawn.
    let mut src = exec::open("/bin/sh", &["-c".into(), "printf 'shot\n'".into()]).unwrap();
    assert_eq!(recv_string(&mut src).await, "shot");
    assert_eq!(recv_string(&mut src).await, "shot");
}

#[tokio::test]
async fn exec_retries_a_missing_binary_without_panicking() {
    // A missing binary is retried like any down feed, never a crash and never
    // a delivery. Not receiving within the window IS the contract.
    let mut src = exec::open("/nonexistent-binary", &[]).unwrap();
    let mut buf = vec![0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), src.recv(&mut buf)).await {
        Err(_) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("a missing binary delivered {n} bytes"),
    }
}

#[tokio::test]
async fn tcp_client_receives_line_framed_data_and_reconnects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut s, b"one\n")
            .await
            .unwrap();
        drop(s); // force a reconnect
        let (mut s, _) = listener.accept().await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut s, b"two\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut src = tcp::open(&addr.to_string(), Framing::Line).unwrap();
    assert_eq!(recv_string(&mut src).await, "one");
    assert_eq!(recv_string(&mut src).await, "two");
}

#[tokio::test]
async fn tcp_server_accepts_a_pusher_and_frames_lines() {
    let mut src = tcp_server::open("127.0.0.1:19315", Framing::Line)
        .await
        .unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut s = tokio::net::TcpStream::connect("127.0.0.1:19315")
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut s, b"pushed\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    assert_eq!(recv_string(&mut src).await, "pushed");
}

#[tokio::test]
async fn health_serves_healthz_and_counters() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let counter = Arc::new(AtomicU64::new(0));
    counter.store(41, Ordering::Relaxed);

    std::env::set_var("AJAR_HEALTH_ADDR", "127.0.0.1:19314");
    health::spawn_counters(vec![("connector_test_total", counter)]);
    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut s = tokio::net::TcpStream::connect("127.0.0.1:19314")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut s, b"GET /metrics HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let mut body = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut s, &mut body)
        .await
        .unwrap();
    assert!(body.contains("connector_test_total 41"), "{body}");

    let mut s = tokio::net::TcpStream::connect("127.0.0.1:19314")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut s, b"GET /healthz HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    let mut ok = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut s, &mut ok)
        .await
        .unwrap();
    assert!(ok.contains("200"), "{ok}");
}

#[tokio::test]
async fn udp_delivers_a_datagram_per_frame() {
    use ajar_connector_common::udp;
    let mut src = udp::open("127.0.0.1:19316", None, None).unwrap();
    // The IPv4-only guard names the fix instead of "Invalid argument (os error 22)".
    let err = match udp::open("[::]:19317", None, None) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("IPv6 bind must be refused"),
    };
    assert!(err.contains("IPv4-only"), "{err}");
    // A bad multicast interface is named as transport.interface, not a bare errno.
    let err = match udp::open("0.0.0.0:19318", Some("239.9.9.9"), Some("not-an-ip")) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a bad interface must be refused"),
    };
    assert!(err.contains("transport.interface"), "{err}");
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.send_to(b"datagram", "127.0.0.1:19316").await.unwrap();
    });
    assert_eq!(recv_string(&mut src).await, "datagram");
}

#[cfg(feature = "serial")]
#[tokio::test]
async fn serial_retries_a_missing_device_without_delivering() {
    use ajar_connector_common::serial;
    // Open is lazy and a missing device is retried like any down feed, the
    // same contract as every transport. Pinned here: no delivery and no panic
    // while the device is absent.
    let mut src = serial::open("/dev/nonexistent-tty", 4800).unwrap();
    let mut buf = vec![0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), src.recv(&mut buf)).await {
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("a missing device delivered {n} bytes"),
    }
}
