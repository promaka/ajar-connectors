// SPDX-License-Identifier: Apache-2.0
//! A recorded capture through the real parser: the evaluate-on-your-own-
//! recording path, end to end minus the broker (the broker leg is the same
//! one every other gate already proves).

use ajar_connector_common::replay;
use ajar_connector_common::{Enrichment, FrameParser, FrameSource};
use ajar_nmea_test_support::*;

// The crate has no test-support lib; build the pcap by hand here.
mod ajar_nmea_test_support {
    pub fn pcap(packets: &[(u64, u16, &[u8])]) -> Vec<u8> {
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
}

#[tokio::test(start_paused = true)]
async fn a_recorded_ais_capture_becomes_events_with_original_pacing() {
    let dir = std::env::temp_dir().join(format!("ajar-replay-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bridge.pcap");
    // Two real AIS sentences 400ms apart, with an off-port packet between.
    std::fs::write(
        &path,
        pcap(&[
            (0, 10110, b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23"),
            (200_000, 5631, b"not-the-feed"),
            (
                400_000,
                10110,
                b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23",
            ),
        ]),
    )
    .unwrap();

    let parser = ajar_ais_nmea::AisParser::new("replay-eval-1", Enrichment::default());
    let mut src = replay::open(path.to_str().unwrap(), 1.0, false, Some(10110), 5_000).unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let t0 = tokio::time::Instant::now();

    let n = src.recv(&mut buf).await.unwrap();
    let first = parser.parse(&buf[..n]).unwrap();
    assert_eq!(first.len(), 1, "a real position report becomes one event");
    assert_eq!(first[0].source_id, "replay-eval-1");

    let n = src.recv(&mut buf).await.unwrap();
    let second = parser.parse(&buf[..n]).unwrap();
    assert_eq!(second.len(), 1);
    // Original pacing held: the off-port packet contributed its share of the
    // timeline but no frame.
    assert_eq!(t0.elapsed(), std::time::Duration::from_millis(400));
    let _ = std::fs::remove_dir_all(&dir);
}
