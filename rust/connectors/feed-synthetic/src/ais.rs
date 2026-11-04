// SPDX-License-Identifier: Apache-2.0
//! AIS: the vessel as `!AIVDM` sentences, read by the `ais-nmea` connector.
//! Type 1 position reports, and type 5 static and voyage data as a multipart
//! the decoder joins onto the position by MMSI. AIS carries no accuracy in
//! metres, so none is emitted.

use crate::scenario::{Vessel, VesselState, MPS_TO_KN};

/// The six-bit ASCII armouring every AIS payload character uses.
fn armour(six: u8) -> u8 {
    let v = six + 48;
    if v > 87 {
        v + 8
    } else {
        v
    }
}

/// A big-endian bit writer for an AIS payload.
#[derive(Default)]
struct Bits {
    bits: Vec<bool>,
}

impl Bits {
    fn u(&mut self, value: u64, width: usize) -> &mut Self {
        for i in (0..width).rev() {
            self.bits.push((value >> i) & 1 == 1);
        }
        self
    }

    fn i(&mut self, value: i64, width: usize) -> &mut Self {
        self.u((value as u64) & ((1u64 << width) - 1), width)
    }

    /// Six-bit text, space-padded to `chars` characters: `@` is 0, `A` is 1,
    /// digits and space sit in the upper half.
    fn text(&mut self, s: &str, chars: usize) -> &mut Self {
        let mut it = s.bytes();
        for _ in 0..chars {
            let c = it.next().unwrap_or(b' ').to_ascii_uppercase();
            let six = match c {
                b'@'..=b'_' => c - 64,
                b' '..=b'?' => c,
                _ => 32,
            } as u64;
            self.u(six, 6);
        }
        self
    }

    /// The armoured payload and the fill bits that pad it to whole characters.
    fn armoured(&self) -> (String, u8) {
        let fill = (6 - self.bits.len() % 6) % 6;
        let mut out = String::with_capacity(self.bits.len().div_ceil(6));
        let mut i = 0;
        while i < self.bits.len() {
            let mut six = 0u8;
            for k in 0..6 {
                six <<= 1;
                if self.bits.get(i + k).copied().unwrap_or(false) {
                    six |= 1;
                }
            }
            out.push(armour(six) as char);
            i += 6;
        }
        (out, fill as u8)
    }
}

/// One NMEA 0183 sentence with its checksum: the XOR of every byte between `!`
/// and `*`, as two upper-case hex digits.
fn sentence(body: &str) -> String {
    let sum = body.bytes().fold(0u8, |a, b| a ^ b);
    format!("!{body}*{sum:02X}\r\n")
}

/// The sentences for one payload: one, or a multipart set sharing a sequence
/// id.
fn sentences(payload: &str, fill: u8, seq: u8, channel: char) -> Vec<String> {
    const MAX_CHARS: usize = 56;
    let chunks: Vec<&str> = {
        let b = payload.as_bytes();
        (0..b.len())
            .step_by(MAX_CHARS)
            .map(|i| std::str::from_utf8(&b[i..(i + MAX_CHARS).min(b.len())]).expect("ascii"))
            .collect()
    };
    let total = chunks.len();
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let seq_field = if total > 1 {
                seq.to_string()
            } else {
                String::new()
            };
            // Fill bits belong to the final fragment only.
            let f = if i + 1 == total { fill } else { 0 };
            sentence(&format!(
                "AIVDM,{total},{},{seq_field},{channel},{chunk},{f}",
                i + 1
            ))
        })
        .collect()
}

/// Type 1: a class A position report.
pub fn position_report(v: &VesselState, timestamp_s: u8) -> String {
    let mut b = Bits::default();
    b.u(1, 6) // message type
        .u(0, 2) // repeat indicator
        .u(Vessel::MMSI as u64, 30)
        .u(Vessel::NAV_STATUS as u64, 4)
        .i(0, 8) // rate of turn
        .u((v.speed_mps * MPS_TO_KN * 10.0).round() as u64, 10) // SOG, 1/10 kn
        .u(1, 1) // position accuracy flag: better than 10 m
        .i((v.fix.lon * 600_000.0).round() as i64, 28) // 1/10000 min
        .i((v.fix.lat * 600_000.0).round() as i64, 27)
        .u((v.course_deg * 10.0).round() as u64, 12) // COG, 1/10 deg
        .u(v.course_deg.round() as u64 % 360, 9) // true heading: along the course
        .u(timestamp_s as u64 % 60, 6) // UTC second
        .u(0, 2) // manoeuvre indicator: not available
        .u(0, 3) // spare
        .u(0, 1) // RAIM not in use
        .u(0, 19); // radio status
    let (payload, fill) = b.armoured();
    sentences(&payload, fill, 0, 'A').concat()
}

/// Type 5: class A static and voyage data, as a two-fragment multipart.
pub fn static_report(seq: u8) -> String {
    let mut b = Bits::default();
    b.u(5, 6)
        .u(0, 2)
        .u(Vessel::MMSI as u64, 30)
        .u(0, 2) // AIS version
        .u(0, 30) // IMO number: not available
        .text(Vessel::CALLSIGN, 7)
        .text(Vessel::NAME, 20)
        .u(Vessel::SHIP_TYPE as u64, 8)
        .u(180, 9) // dimension to bow, m
        .u(120, 9) // to stern
        .u(20, 6) // to port
        .u(25, 6) // to starboard
        .u(1, 4) // position fix type: GPS
        .u(0, 20) // ETA: not available
        .u(105, 8) // draught, 1/10 m
        .text("ROTTERDAM", 20)
        .u(0, 1) // DTE
        .u(0, 1); // spare
    let (payload, fill) = b.armoured();
    sentences(&payload, fill, seq, 'A').concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{attr, num, EVENT_TIME};
    use ajar_ais_nmea::AisParser;
    use ajar_connector_common::Enrichment;

    fn decoder() -> AisParser {
        AisParser::new("ais-shore-1", Enrichment::default())
    }

    #[test]
    fn position_report_decodes_to_vessel() {
        let v = Vessel::at(90.0);
        let line = position_report(&v, 30);
        assert!(line.starts_with("!AIVDM,1,1,,A,"), "{line}");
        let p = decoder()
            .parse_sentence(line.trim_end().as_bytes())
            .expect("a valid sentence")
            .expect("a position report yields a position");
        assert_eq!(p.msg_type, 1);
        assert_eq!(p.mmsi, Vessel::MMSI);
        assert!((p.lat.unwrap() - v.fix.lat).abs() < 2e-6, "{:?}", p.lat);
        assert!((p.lon.unwrap() - v.fix.lon).abs() < 2e-6, "{:?}", p.lon);
        assert!((p.cog_deg.unwrap() - Vessel::COURSE_DEG).abs() < 0.11);
        assert!((p.heading_deg.unwrap() - Vessel::COURSE_DEG).abs() < 0.5);
        assert!(
            (p.sog_kn.unwrap() - Vessel::SPEED_MPS * MPS_TO_KN).abs() < 0.06,
            "{:?}",
            p.sog_kn
        );
        assert_eq!(p.nav_status, Some("under-way-using-engine"));
        let ev = decoder().to_event_at(p, EVENT_TIME).unwrap();
        let speed = num(&ev, "speed");
        assert!(
            (speed - Vessel::SPEED_MPS).abs() < 0.03,
            "{speed}: the event carries m/s"
        );
    }

    #[test]
    fn static_report_joins_onto_next_position() {
        let d = decoder();
        let stat = static_report(3);
        let lines: Vec<&str> = stat.lines().collect();
        assert_eq!(lines.len(), 2, "{stat}");
        assert!(lines[0].starts_with("!AIVDM,2,1,3,A,"), "{}", lines[0]);
        assert!(lines[1].starts_with("!AIVDM,2,2,3,A,"), "{}", lines[1]);
        for l in &lines {
            assert!(d.parse_sentence(l.as_bytes()).unwrap().is_none(), "{l}");
        }
        let p = d
            .parse_sentence(position_report(&Vessel::at(0.0), 1).trim_end().as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(p.callsign.as_deref(), Some(Vessel::CALLSIGN));
        assert_eq!(p.name.as_deref(), Some(Vessel::NAME));
        assert_eq!(p.ship_type, Some("cargo"));
        let ev = d.to_event_at(p, EVENT_TIME).unwrap();
        assert_eq!(ev.entity_type, "mim:vessel");
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("235009870"));
        assert_eq!(attr(&ev, "alt_id_standard").as_deref(), Some("AIS"));
        assert_eq!(attr(&ev, "callsign").as_deref(), Some("MSCL"));
        assert!(
            attr(&ev, "position_accuracy_h_m").is_none(),
            "AIS has no accuracy in metres"
        );
    }

    #[test]
    fn flipped_byte_fails_checksum() {
        let good = position_report(&Vessel::at(0.0), 0);
        let mut bad = good.trim_end().as_bytes().to_vec();
        bad[20] ^= 0x01;
        assert!(decoder().parse_sentence(&bad).is_err());
    }

    #[test]
    fn armouring_matches_alphabet() {
        assert_eq!(armour(0), b'0');
        assert_eq!(armour(39), b'W');
        assert_eq!(armour(40), b'`');
        assert_eq!(armour(63), b'w');
    }
}
