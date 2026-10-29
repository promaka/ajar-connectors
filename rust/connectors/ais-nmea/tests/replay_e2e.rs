// SPDX-License-Identifier: Apache-2.0
//! A recorded pcap capture replays through the parser at its original pacing.

use std::time::Duration;

use ajar_ais_nmea::AisParser;
use ajar_connector_common::replay;
use ajar_connector_common::{Enrichment, FrameParser, FrameSource};

const T1: &[u8] = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23";

/// A little-endian pcap of Ethernet/IPv4/UDP packets, each `(ts_us, dst_port, payload)`.
fn pcap(packets: &[(u64, u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&[2, 0, 4, 0]);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (ts_us, port, payload) in packets {
        let frame = eth_udp(*port, payload);
        out.extend_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        out.extend_from_slice(&frame);
    }
    out
}

fn eth_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&(ip_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0; 4]);
    ip.push(64);
    ip.push(17);
    ip.extend_from_slice(&[0; 2]);
    ip.extend_from_slice(&[10, 0, 0, 1, 239, 2, 3, 1]);
    f.extend_from_slice(&ip);
    f.extend_from_slice(&9999u16.to_be_bytes());
    f.extend_from_slice(&dst_port.to_be_bytes());
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&[0; 2]);
    f.extend_from_slice(payload);
    f
}

#[tokio::test(start_paused = true)]
async fn capture_replays_with_original_pacing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bridge.pcap");
    std::fs::write(
        &path,
        pcap(&[
            (0, 10110, T1),
            (200_000, 5631, b"not-the-feed"),
            (400_000, 10110, T1),
        ]),
    )
    .unwrap();

    let parser = AisParser::new("replay-eval-1", Enrichment::default());
    let mut src = replay::open(path.to_str().unwrap(), 1.0, false, Some(10110), 5_000).unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let t0 = tokio::time::Instant::now();

    let n = src.recv(&mut buf).await.unwrap();
    let first = parser.parse(&buf[..n]).unwrap();
    assert_eq!(first.len(), 1, "a position report becomes one event");
    assert_eq!(first[0].source_id, "replay-eval-1");

    let n = src.recv(&mut buf).await.unwrap();
    let second = parser.parse(&buf[..n]).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(
        t0.elapsed(),
        Duration::from_millis(400),
        "the off-port packet keeps its share of the timeline"
    );
}
