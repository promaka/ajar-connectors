// SPDX-License-Identifier: Apache-2.0
//! Capture replay: each UDP payload in a classic pcap (v2.4, Ethernet, IPv4,
//! optional 802.1Q tags) becomes one frame, delivered with the original
//! inter-packet timing scaled by `speed`. Other packets are skipped and
//! counted.

use std::time::Duration;

use anyhow::Context;

use crate::runtime::FrameSource;

/// One datagram and the delay since the previous one.
#[derive(Debug, Clone, PartialEq)]
pub struct Datagram {
    pub delay: Duration,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct Capture {
    pub datagrams: Vec<Datagram>,
    /// Packets that were not IPv4/UDP or did not match the port filter.
    pub skipped: u64,
}

/// Parse a classic pcap capture, extracting UDP payloads (optionally only
/// those to `port`) with their inter-packet timing.
pub fn parse_pcap(data: &[u8], port: Option<u16>) -> anyhow::Result<Capture> {
    if data.len() < 24 {
        anyhow::bail!(
            "not a pcap: {} bytes is shorter than the global header",
            data.len()
        );
    }
    let magic = [data[0], data[1], data[2], data[3]];
    // The magic gives byte order and timestamp resolution.
    let (le, nanos) = match u32::from_le_bytes(magic) {
        0xa1b2_c3d4 => (true, false),
        0xa1b2_3c4d => (true, true),
        _ => match u32::from_be_bytes(magic) {
            0xa1b2_c3d4 => (false, false),
            0xa1b2_3c4d => (false, true),
            other => anyhow::bail!(
                "not a classic pcap (magic {other:#010x}). A .pcapng converts with: \
                 tshark -F pcap -r in.pcapng -w out.pcap"
            ),
        },
    };
    let u32_at = |off: usize| -> anyhow::Result<u32> {
        let Some(&[b0, b1, b2, b3]) = data.get(off..off + 4) else {
            anyhow::bail!("pcap truncated");
        };
        let b = [b0, b1, b2, b3];
        Ok(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let linktype = u32_at(20)?;
    if linktype != 1 {
        anyhow::bail!(
            "pcap link type {linktype} is not Ethernet (1); radar recorders emit \
             Ethernet captures, and anything else needs re-capturing or conversion"
        );
    }

    let mut datagrams = Vec::new();
    let mut skipped = 0u64;
    let mut prev_ts_ns: Option<u64> = None;
    let mut off = 24usize;
    while off + 16 <= data.len() {
        let ts_sec = u32_at(off)? as u64;
        let ts_frac = u32_at(off + 4)? as u64;
        let incl_len = u32_at(off + 8)? as usize;
        off += 16;
        // A torn tail record from a killed recorder ends the capture.
        let Some(frame) = data.get(off..off + incl_len) else {
            break;
        };
        off += incl_len;
        let ts_ns = ts_sec * 1_000_000_000 + if nanos { ts_frac } else { ts_frac * 1_000 };

        match udp_payload(frame, port) {
            Some(payload) => {
                let delay = match prev_ts_ns {
                    Some(p) => Duration::from_nanos(ts_ns.saturating_sub(p)),
                    None => Duration::ZERO,
                };
                prev_ts_ns = Some(ts_ns);
                datagrams.push(Datagram {
                    delay,
                    payload: payload.to_vec(),
                });
            }
            None => skipped += 1,
        }
    }
    Ok(Capture { datagrams, skipped })
}

/// The UDP payload of an Ethernet/IPv4 frame, if it is one.
fn udp_payload(frame: &[u8], port: Option<u16>) -> Option<&[u8]> {
    // Ethernet: dst(6) src(6) ethertype(2), with optional 802.1Q tag(s).
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes(frame.get(off..off + 2)?.try_into().ok()?);
    off += 2;
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        ethertype = u16::from_be_bytes(frame.get(off + 2..off + 4)?.try_into().ok()?);
        off += 4;
    }
    // 0x0800: IPv4
    if ethertype != 0x0800 {
        return None;
    }
    let ip = frame.get(off..)?;
    let ihl = (usize::from(*ip.first()?) & 0x0f) * 4;
    // Protocol 17: UDP
    if ihl < 20 || *ip.get(9)? != 17 {
        return None;
    }
    let udp = ip.get(ihl..)?;
    let dst_port = u16::from_be_bytes(udp.get(2..4)?.try_into().ok()?);
    if let Some(want) = port {
        if dst_port != want {
            return None;
        }
    }
    let udp_len = u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?) as usize;
    if udp_len < 8 {
        return None;
    }
    udp.get(8..udp_len.min(udp.len()))
}

/// Each payload delivered after its original delay scaled by `speed`, gaps
/// clamped to `max_gap` so an idle recorder does not stall the replay.
pub struct ReplaySource {
    datagrams: Vec<Datagram>,
    next: usize,
    speed: f64,
    max_gap: Duration,
    looping: bool,
    describe: String,
    done_logged: bool,
}

pub fn open(
    path: &str,
    speed: f64,
    looping: bool,
    port: Option<u16>,
    max_gap_ms: u64,
) -> anyhow::Result<ReplaySource> {
    if speed <= 0.0 {
        anyhow::bail!("transport.speed must be positive (1.0 = real time, 10 = ten times faster)");
    }
    let data = std::fs::read(path).with_context(|| format!("reading capture {path}"))?;
    let capture = parse_pcap(&data, port).with_context(|| format!("parsing capture {path}"))?;
    if capture.datagrams.is_empty() {
        anyhow::bail!(
            "capture {path} contains no matching UDP datagrams \
             ({} packets skipped as non-UDP/other-port); check the port filter \
             against what the recorder actually captured",
            capture.skipped
        );
    }
    tracing::info!(
        capture = %path,
        datagrams = capture.datagrams.len(),
        skipped = capture.skipped,
        speed,
        "replaying capture"
    );
    Ok(ReplaySource {
        datagrams: capture.datagrams,
        next: 0,
        speed,
        max_gap: Duration::from_millis(max_gap_ms),
        looping,
        describe: format!("pcap-replay {path} (x{speed})"),
        done_logged: false,
    })
}

#[async_trait::async_trait]
impl FrameSource for ReplaySource {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.datagrams.get(self.next) {
                Some(d) => {
                    self.next += 1;
                    let scaled = d.delay.div_f64(self.speed).min(self.max_gap);
                    if !scaled.is_zero() {
                        tokio::time::sleep(scaled).await;
                    }
                    let n = d.payload.len().min(buf.len());
                    buf[..n].copy_from_slice(&d.payload[..n]);
                    return Ok(n);
                }
                None if self.looping => {
                    self.next = 0;
                }
                None => {
                    if !self.done_logged {
                        self.done_logged = true;
                        tracing::info!("capture fully replayed");
                    }
                    std::future::pending::<()>().await;
                }
            }
        }
    }
    fn describe(&self) -> String {
        self.describe.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 8600;

    /// Craft a classic pcap (LE, microseconds) of Ethernet/IPv4/UDP packets:
    /// (ts_micros, dst_port, payload).
    fn pcap(packets: &[(u64, u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&[2, 0, 4, 0]); // version 2.4
        out.extend_from_slice(&[0; 8]); // thiszone + sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&1u32.to_le_bytes()); // linktype ethernet
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

    /// A capture file holding `pcap(packets)`.
    fn capture_file(packets: &[(u64, u16, &[u8])]) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), pcap(packets)).unwrap();
        f
    }

    fn eth_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut ip = vec![0x45, 0]; // v4, ihl 5
        ip.extend_from_slice(&(ip_len as u16).to_be_bytes());
        ip.extend_from_slice(&[0; 4]); // id + flags
        ip.push(64); // ttl
        ip.push(17); // UDP
        ip.extend_from_slice(&[0; 2]); // checksum (unchecked)
        ip.extend_from_slice(&[10, 0, 0, 1, 239, 2, 3, 1]); // src, dst
        f.extend_from_slice(&ip);
        f.extend_from_slice(&9999u16.to_be_bytes()); // src port
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&(udp_len as u16).to_be_bytes());
        f.extend_from_slice(&[0; 2]); // checksum
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn payloads_and_timing_round_trip() {
        let data = pcap(&[
            (1_000_000, PORT, b"first"),
            (1_250_000, PORT, b"second"),
            (1_250_000 + 300_000, PORT, b"third"),
        ]);
        let cap = parse_pcap(&data, None).unwrap();
        assert_eq!(cap.skipped, 0);
        let d: Vec<_> = cap.datagrams.iter().map(|d| d.payload.as_slice()).collect();
        assert_eq!(d, vec![&b"first"[..], b"second", b"third"]);
        assert_eq!(cap.datagrams[0].delay, Duration::ZERO);
        assert_eq!(cap.datagrams[1].delay, Duration::from_millis(250));
        assert_eq!(cap.datagrams[2].delay, Duration::from_millis(300));
    }

    #[test]
    fn capture_noise_is_skipped_and_counted() {
        // An ARP frame (ethertype 0x0806) after a UDP packet.
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0; 28]);
        let mut data = pcap(&[(0, PORT, b"a")]);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(arp.len() as u32).to_le_bytes());
        data.extend_from_slice(&(arp.len() as u32).to_le_bytes());
        data.extend_from_slice(&arp);
        let cap = parse_pcap(&data, None).unwrap();
        assert_eq!(cap.datagrams.len(), 1);
        assert_eq!(cap.skipped, 1);
    }

    #[test]
    fn port_filter_selects_the_feed() {
        let data = pcap(&[
            (0, PORT, b"radar"),
            (100, 5631, b"ais"),
            (200, PORT, b"radar2"),
        ]);
        let cap = parse_pcap(&data, Some(PORT)).unwrap();
        assert_eq!(cap.datagrams.len(), 2);
        assert_eq!(cap.skipped, 1);
    }

    #[test]
    fn pcapng_error_names_the_conversion() {
        // pcapng section header block magic.
        let data = [
            0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let err = parse_pcap(&data, None).unwrap_err().to_string();
        assert!(err.contains("tshark -F pcap"), "{err}");
    }

    #[test]
    fn torn_tail_replays_what_was_captured() {
        let mut data = pcap(&[(0, PORT, b"whole")]);
        // A record header promising more bytes than exist.
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&999u32.to_le_bytes());
        data.extend_from_slice(&999u32.to_le_bytes());
        data.extend_from_slice(&[0; 10]);
        let cap = parse_pcap(&data, None).unwrap();
        assert_eq!(cap.datagrams.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn replay_paces_to_timing_scaled_by_speed() {
        let f = capture_file(&[(0, PORT, b"a"), (1_000_000, PORT, b"b")]);
        let mut src = open(f.path().to_str().unwrap(), 2.0, false, None, 5_000).unwrap();
        let mut buf = [0u8; 64];
        let t0 = tokio::time::Instant::now();
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"a");
        let n = src.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"b");
        assert_eq!(t0.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn long_gaps_are_clamped() {
        let f = capture_file(&[(0, PORT, b"a"), (600_000_000, PORT, b"b")]);
        let mut src = open(f.path().to_str().unwrap(), 1.0, false, None, 5_000).unwrap();
        let mut buf = [0u8; 64];
        let t0 = tokio::time::Instant::now();
        src.recv(&mut buf).await.unwrap();
        src.recv(&mut buf).await.unwrap();
        assert_eq!(t0.elapsed(), Duration::from_secs(5));
    }

    #[test]
    fn filtered_out_capture_names_the_port_filter() {
        let f = capture_file(&[(0, 5631, b"ais")]);
        let err = open(f.path().to_str().unwrap(), 1.0, false, Some(PORT), 5_000)
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("port filter"), "{err}");
    }
}
