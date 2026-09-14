// SPDX-License-Identifier: Apache-2.0
//! AIS: the vessel's position and static reports as `!AIVDM` sentences, what
//! the `ais-nmea` connector reads.
//!
//! What AIS carries, and therefore what this emits: identity (MMSI, callsign,
//! name), position, course, heading, speed, navigational status. It does not
//! carry accuracy in metres: AIS has a one-bit "better or worse than ten
//! metres" flag and relays the ship's own GPS, so no accuracy is emitted.
//!
//! Two message types, because that is how a real transponder splits it: type 1
//! is the position report every few seconds, type 5 is the static and voyage
//! data every few minutes, and the decoder joins them on the MMSI. Type 5 is
//! 424 bits, which does not fit one sentence, so it goes as a two-fragment
//! multipart exactly as a receiver would relay it. A generator that emitted a
//! single fat sentence would exercise a path no real receiver uses.

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
struct Bits {
    bits: Vec<bool>,
}

impl Bits {
    fn new() -> Self {
        Bits { bits: Vec::new() }
    }

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
        let mut out = String::new();
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
/// id, each of at most 56 payload characters as a receiver relays them.
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

/// Type 1: a class A position report, the sentence every few seconds.
pub fn position_report(v: &VesselState, timestamp_s: u8) -> String {
    let mut b = Bits::new();
    b.u(1, 6) // message type
        .u(0, 2) // repeat indicator
        .u(Vessel::MMSI as u64, 30)
        .u(Vessel::NAV_STATUS as u64, 4)
        .i(0, 8) // rate of turn: 0, not turning
        .u((v.speed_mps * MPS_TO_KN * 10.0).round() as u64, 10) // SOG, 1/10 kn
        .u(1, 1) // position accuracy: better than 10 m (a flag, not a figure)
        .i((v.fix.lon * 600_000.0).round() as i64, 28) // 1/10000 min
        .i((v.fix.lat * 600_000.0).round() as i64, 27)
        .u((v.course_deg * 10.0).round() as u64, 12) // COG, 1/10 deg
        .u(v.course_deg.round() as u64 % 360, 9) // true heading: along the course
        .u(timestamp_s as u64 % 60, 6) // UTC second of the report
        .u(0, 2) // manoeuvre indicator: not available
        .u(0, 3) // spare
        .u(0, 1) // RAIM not in use
        .u(0, 19); // radio status
    let (payload, fill) = b.armoured();
    sentences(&payload, fill, 0, 'A').concat()
}

/// Type 5: class A static and voyage data, as a two-fragment multipart.
pub fn static_report(seq: u8) -> String {
    let mut b = Bits::new();
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
    use ajar_ais_nmea::AisParser;
    use ajar_connector_common::Enrichment;

    fn decoder() -> AisParser {
        AisParser::new("ais-shore-1", Enrichment::default())
    }

    #[test]
    fn a_position_report_decodes_to_the_vessel_where_the_scenario_put_her() {
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
        assert!((p.cog.unwrap() - Vessel::COURSE_DEG).abs() < 0.11);
        assert!((p.heading.unwrap() - Vessel::COURSE_DEG).abs() < 0.5);
        // The decoder keeps the wire's knots on the position and converts to
        // the contract's metres per second only in the event.
        assert!(
            (p.sog.unwrap() - Vessel::SPEED_MPS * MPS_TO_KN).abs() < 0.06,
            "{:?}",
            p.sog
        );
        assert_eq!(p.nav_status, Some("under-way-using-engine"));
        let ev = decoder().to_event_at(&p, "2026-06-10T08:00:00Z").unwrap();
        let speed: f64 = ev
            .attributes
            .iter()
            .find(|a| a.key == "speed")
            .map(|a| a.value.parse().unwrap())
            .expect("speed is governed");
        assert!((speed - Vessel::SPEED_MPS).abs() < 0.03, "{speed}");
    }

    #[test]
    fn the_static_report_is_a_multipart_the_decoder_joins_onto_the_next_position() {
        let d = decoder();
        let stat = static_report(3);
        let lines: Vec<&str> = stat.lines().collect();
        assert_eq!(lines.len(), 2, "{stat}");
        assert!(lines[0].starts_with("!AIVDM,2,1,3,A,"), "{}", lines[0]);
        assert!(lines[1].starts_with("!AIVDM,2,2,3,A,"), "{}", lines[1]);
        for l in &lines {
            assert!(d.parse_sentence(l.as_bytes()).unwrap().is_none(), "{l}");
        }
        // The next position carries the identity the static report gave it.
        let p = d
            .parse_sentence(position_report(&Vessel::at(0.0), 1).trim_end().as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(p.callsign.as_deref(), Some(Vessel::CALLSIGN));
        assert_eq!(p.name.as_deref(), Some(Vessel::NAME));
        assert_eq!(p.ship_type, Some("cargo"));
        let ev = d.to_event_at(&p, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:vessel");
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.clone())
        };
        assert_eq!(attr("alt_id").as_deref(), Some("235009870"));
        assert_eq!(attr("alt_id_standard").as_deref(), Some("AIS"));
        assert_eq!(attr("callsign").as_deref(), Some("MSCL"));
        assert!(
            attr("position_accuracy_h_m").is_none(),
            "AIS has no accuracy in metres"
        );
    }

    #[test]
    fn every_sentence_checksums_and_a_flipped_byte_is_refused() {
        let good = position_report(&Vessel::at(0.0), 0);
        let mut bad = good.trim_end().as_bytes().to_vec();
        bad[20] ^= 0x01;
        assert!(decoder().parse_sentence(&bad).is_err());
    }

    #[test]
    fn armouring_matches_the_published_alphabet() {
        assert_eq!(armour(0), b'0');
        assert_eq!(armour(39), b'W');
        assert_eq!(armour(40), b'`');
        assert_eq!(armour(63), b'w');
    }
}
