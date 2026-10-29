// SPDX-License-Identifier: Apache-2.0
//! AIS over NMEA 0183 (`!--VDM`/`!--VDO`, ITU-R M.1371) to `mim:vessel` events.
//! Position reports (types 1, 2, 3, 18, 19) emit an event; static data (types
//! 5, 24 and the inline part of 19) is cached per MMSI and attached to the
//! vessel's next position. Bit offsets match the pyais reference decoder.

mod bits;
mod cache;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::GovernedIdentity;
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

use crate::ttm::TtmState;
use bits::Bits;
use cache::{Carry, Identity, MmsiCache};
use Layout::{ClassA, ClassB};

const KNOTS_TO_MPS: f64 = 0.514_444;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum AisError {
    #[error("AIS frame not ASCII")]
    NotAscii,
    #[error("not an NMEA sentence")]
    NotNmea,
    #[error("NMEA checksum missing or mismatched")]
    Checksum,
    #[error("malformed AIVDM fields")]
    Fields,
    #[error("bad 6-bit armor character {0:#04x}")]
    Armor(u8),
    #[error("AIS payload too short for message type")]
    Truncated,
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

/// A position report with the vessel's cached identity.
#[derive(Debug, Clone, PartialEq)]
pub struct AisPosition {
    pub msg_type: u8,
    pub mmsi: u32,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub cog_deg: Option<f64>,
    pub sog_kn: Option<f64>,
    /// True heading.
    pub heading_deg: Option<f64>,
    /// Rate of turn in degrees per minute, positive to starboard.
    pub rot_degmin: Option<f64>,
    pub nav_status: Option<&'static str>,
    pub ship_type: Option<&'static str>,
    pub name: Option<String>,
    pub callsign: Option<String>,
    pub imo: Option<u32>,
    /// Every sentence received for this vessel since its last event,
    /// newline-joined, ending with the position's own.
    pub raw: Vec<u8>,
    /// Sentences were dropped from `raw` over the per-vessel cap.
    pub truncated: bool,
}

/// Reassembly key for a multi-fragment sentence. The sequential message id is
/// only 0-9 and chosen per transmitter, so the talker and radio channel are
/// part of the key to keep another receiver's or channel's fragments out of a
/// vessel's payload. Two vessels on one receiver and channel picking the same
/// id within `REASM_TTL` can still collide; fragments carry no vessel id.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ReasmKey {
    talker: String,
    channel: String,
    seq: u8,
}

// Fragments of one message arrive milliseconds apart; an older partial is an
// orphan and is discarded so an unrelated later fragment cannot complete it.
const REASM_TTL: Duration = Duration::from_secs(10);

struct Pending {
    total: u8,
    payload: String,
    raws: Vec<Vec<u8>>,
    first_seen: Instant,
}

impl Pending {
    fn new(total: u8, now: Instant) -> Self {
        Self {
            total,
            payload: String::new(),
            raws: Vec::new(),
            first_seen: now,
        }
    }

    /// Fragment `frag_num` of `frag_count` is the next one this message needs.
    fn continues(&self, frag_count: u8, frag_num: u8) -> bool {
        self.total == frag_count && self.raws.len() + 1 == frag_num as usize
    }
}

pub struct AisParser {
    source_id: String,
    enrichment: Enrichment,
    pending: Mutex<HashMap<ReasmKey, Pending>>,
    identities: Mutex<MmsiCache<Identity>>,
    carry: Mutex<MmsiCache<Carry>>,
    dropped: Arc<AtomicU64>,
    radar: TtmState,
}

impl AisParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            pending: Mutex::new(HashMap::new()),
            identities: Mutex::new(MmsiCache::default()),
            carry: Mutex::new(MmsiCache::default()),
            dropped: Arc::new(AtomicU64::new(0)),
            radar: TtmState::new(None),
        }
    }

    /// A fixed observer site for TTM targets from a shore-mounted radar. A
    /// live GGA/RMC fix on the feed takes precedence.
    pub fn with_site(mut self, lat: f64, lon: f64) -> Self {
        self.radar = TtmState::new(Some((lat, lon)));
        self
    }

    /// `Some` for a position report; `None` for a static or unmapped message,
    /// a buffered fragment, or an NMEA sentence that is not AIS.
    pub fn parse_sentence(&self, frame: &[u8]) -> Result<Option<AisPosition>, AisError> {
        let s = std::str::from_utf8(frame).map_err(|_| AisError::NotAscii)?;
        let original = s.trim();
        let s = strip_tag_block(original);
        if !(s.starts_with('!') || s.starts_with('$')) {
            return Err(AisError::NotNmea);
        }
        verify_checksum(s)?;

        let star = s.find('*').unwrap_or(s.len());
        let fields: Vec<&str> = s[1..star].split(',').collect();
        // A bridge bus carries heading, depth, wind and other sentences
        // alongside AIS; only one that claims to be VDM/VDO is held to its shape.
        if !(fields[0].ends_with("VDM") || fields[0].ends_with("VDO")) {
            return Ok(None);
        }
        if fields.len() < 7 {
            return Err(AisError::Fields);
        }
        let frag_count: u8 = fields[1].parse().map_err(|_| AisError::Fields)?;
        let frag_num: u8 = fields[2].parse().map_err(|_| AisError::Fields)?;
        let seq: u8 = fields[3].parse().unwrap_or(0);
        let payload = fields[5];
        // The fill bits belong to the final fragment.
        let fill: u8 = fields[6].parse().unwrap_or(0);
        if frag_count == 0 || frag_num == 0 || frag_num > frag_count {
            return Err(AisError::Fields);
        }

        let raw = original.as_bytes().to_vec();
        if frag_count == 1 {
            let bits = Bits::from_payload(payload, fill)?;
            return self.decode(&bits, vec![raw]);
        }

        let key = ReasmKey {
            talker: fields[0].to_string(),
            channel: fields[4].to_string(),
            seq,
        };
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("reassembly mutex");
        pending.retain(|_, p| now.duration_since(p.first_seen) < REASM_TTL);
        let mut entry = if frag_num == 1 {
            Pending::new(frag_count, now)
        } else {
            match pending.remove(&key) {
                Some(e) if e.continues(frag_count, frag_num) => e,
                _ => return Ok(None),
            }
        };
        entry.payload.push_str(payload);
        entry.raws.push(raw);
        if frag_num < frag_count {
            pending.insert(key, entry);
            return Ok(None);
        }
        drop(pending);
        let bits = Bits::from_payload(&entry.payload, fill)?;
        self.decode(&bits, entry.raws)
    }

    fn decode(&self, bits: &Bits, raws: Vec<Vec<u8>>) -> Result<Option<AisPosition>, AisError> {
        if bits.valid_bits < 38 {
            return Err(AisError::Truncated);
        }
        let msg_type = bits.u(0, 6) as u8;
        let mmsi = bits.u(8, 30) as u32;

        let layout = match msg_type {
            1..=3 => Some(ClassA),
            18 => Some(ClassB { extended: false }),
            19 => Some(ClassB { extended: true }),
            5 => {
                self.static_class_a(bits, mmsi);
                None
            }
            24 => {
                self.static_class_b(bits, mmsi);
                None
            }
            _ => None,
        };

        let mut carry = self.carry.lock().expect("carry mutex");
        let entry = carry.entry(mmsi);
        let Some(layout) = layout else {
            for raw in raws {
                let dropped = entry.push_raw(raw);
                if dropped > 0 {
                    self.dropped.fetch_add(dropped, Ordering::Relaxed);
                    tracing::warn!(dropped, mmsi, "ais: carry-forward buffer over cap");
                }
            }
            return Ok(None);
        };
        let (raw, truncated) = entry.drain_with(raws);
        drop(carry);
        let mut pos = self.position(bits, msg_type, mmsi, layout);
        pos.raw = raw;
        pos.truncated = truncated;
        Ok(Some(pos))
    }

    /// A position report, with the vessel's cached identity.
    fn position(&self, bits: &Bits, msg_type: u8, mmsi: u32, layout: Layout) -> AisPosition {
        let (sog_off, lon_off, lat_off, cog_off, hdg_off) = layout.offsets();

        // Only class A carries navigation status and rate of turn.
        let (nav_status, rot_degmin) = match layout {
            ClassA => (
                bits.opt_u(38, 4).and_then(nav_status),
                bits.opt_i(42, 8).and_then(decode_rot),
            ),
            ClassB { .. } => (None, None),
        };

        if matches!(layout, ClassB { extended: true }) {
            let name = bits.opt_text(143, 120);
            let ship_type = bits.opt_u(263, 8).and_then(|c| ship_type(c as u8));
            self.merge_identity(mmsi, name, None, ship_type, None);
        }
        let id = self
            .identities
            .lock()
            .expect("identity mutex")
            .get(mmsi)
            .cloned()
            .unwrap_or_default();

        AisPosition {
            msg_type,
            mmsi,
            lat: bits
                .opt_i(lat_off, 27)
                .map(|v| v as f64 / 600_000.0)
                .filter(|d| (-90.0..=90.0).contains(d)),
            lon: bits
                .opt_i(lon_off, 28)
                .map(|v| v as f64 / 600_000.0)
                .filter(|d| (-180.0..=180.0).contains(d)),
            // 1023 = not available
            sog_kn: bits
                .opt_u(sog_off, 10)
                .filter(|&v| v != 1023)
                .map(|v| v as f64 / 10.0),
            // 3600 = not available
            cog_deg: bits
                .opt_u(cog_off, 12)
                .filter(|&v| v != 3600)
                .map(|v| v as f64 / 10.0),
            // 511 = not available
            heading_deg: bits
                .opt_u(hdg_off, 9)
                .filter(|&v| v != 511)
                .map(|v| v as f64),
            rot_degmin,
            nav_status,
            ship_type: id.ship_type,
            name: id.name,
            callsign: id.callsign,
            imo: id.imo,
            raw: Vec::new(),
            truncated: false,
        }
    }

    /// Type 5: class A static and voyage data.
    fn static_class_a(&self, bits: &Bits, mmsi: u32) {
        let imo = bits.opt_u(40, 30).map(|v| v as u32).filter(|&v| v != 0);
        let callsign = bits.opt_text(70, 42);
        let name = bits.opt_text(112, 120);
        let ship_type = bits.opt_u(232, 8).and_then(|c| ship_type(c as u8));
        self.merge_identity(mmsi, name, callsign, ship_type, imo);
    }

    /// Type 24: class B static data. Part A carries the name, part B the ship
    /// type and call sign.
    fn static_class_b(&self, bits: &Bits, mmsi: u32) {
        match bits.opt_u(38, 2) {
            Some(0) => {
                let name = bits.opt_text(40, 120);
                self.merge_identity(mmsi, name, None, None, None);
            }
            Some(1) => {
                let ship_type = bits.opt_u(40, 8).and_then(|c| ship_type(c as u8));
                let callsign = bits.opt_text(90, 42);
                self.merge_identity(mmsi, None, callsign, ship_type, None);
            }
            _ => {}
        }
    }

    /// Fold newly seen fields into the cache; an empty field never overwrites.
    fn merge_identity(
        &self,
        mmsi: u32,
        name: Option<String>,
        callsign: Option<String>,
        ship_type: Option<&'static str>,
        imo: Option<u32>,
    ) {
        let mut cache = self.identities.lock().expect("identity mutex");
        let e = cache.entry(mmsi);
        if let Some(v) = name.filter(|v| !v.is_empty()) {
            e.name = Some(v);
        }
        if let Some(v) = callsign.filter(|v| !v.is_empty()) {
            e.callsign = Some(v);
        }
        if ship_type.is_some() {
            e.ship_type = ship_type;
        }
        if imo.is_some() {
            e.imo = imo;
        }
    }

    fn base_builder(&self, p: AisPosition) -> EventBuilder {
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:vessel")
            .new_id()
            .payload(p.raw)
            .metadata("source_uid", p.mmsi.to_string())
            .metadata("mmsi", p.mmsi.to_string());
        // The governed MMSI is nine digits with leading zeros. An unconfigured
        // transponder sends 0 and a corrupt frame can exceed nine digits.
        if (1..=999_999_999).contains(&p.mmsi) {
            b = b.identity("AIS", format!("{:09}", p.mmsi));
        }
        if let (Some(lat), Some(lon)) = (p.lat, p.lon) {
            b = b.location(lat, lon, 0.0);
        }
        if let Some(imo) = p.imo {
            b = b.metadata("imo", imo.to_string());
        }
        if p.truncated {
            b = b.metadata("payload_truncated", "true");
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(kn) = p.sog_kn {
            b = b.attribute("speed", format!("{:.2}", kn * KNOTS_TO_MPS));
            b = b.metadata("speed_kn", format!("{kn:.1}"));
        }
        if let Some(deg) = p.cog_deg {
            b = b.attribute("course", format!("{deg:.1}"));
        }
        if let Some(deg) = p.heading_deg {
            b = b.attribute("heading", format!("{deg:.0}"));
        }
        if let Some(rot) = p.rot_degmin {
            b = b.attribute("rate_of_turn", format!("{rot:.1}"));
        }
        if let Some(ns) = p.nav_status {
            b = b.attribute("nav_status", ns);
        }
        if let Some(vt) = p.ship_type {
            b = b.attribute("vessel_type", vt);
        }
        if let Some(name) = p.name {
            b = b.attribute("vessel_name", name);
        }
        if let Some(cs) = p.callsign {
            b = b.attribute("callsign", cs);
        }
        b
    }

    pub fn to_event_at(&self, p: AisPosition, observed: &str) -> Result<Event, AisError> {
        Ok(self.base_builder(p).timestamp(observed).build()?)
    }
}

impl FrameParser for AisParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        // TTM targets and the GGA/RMC own-ship fixes that place them share the
        // bus with AIS.
        if let Ok(s) = std::str::from_utf8(frame) {
            let s = strip_tag_block(s.trim());
            if (s.starts_with('$') || s.starts_with('!')) && TtmState::wants(&s[1..]) {
                verify_checksum(s)?;
                let star = s.find('*').unwrap_or(s.len());
                let fields: Vec<&str> = s[1..star].split(',').collect();
                let Some(target) = self.radar.handle(&fields, s.as_bytes().to_vec())? else {
                    return Ok(Vec::new());
                };
                let event = crate::ttm::to_event(&self.source_id, &self.enrichment, target)
                    .map_err(AisError::from)?;
                return Ok(vec![event]);
            }
        }
        let Some(pos) = self.parse_sentence(frame)? else {
            return Ok(Vec::new());
        };
        // AIS position reports carry no absolute time, so stamp the time of receipt.
        let event = self
            .base_builder(pos)
            .now()
            .build()
            .map_err(AisError::from)?;
        Ok(vec![event])
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        vec![
            ("connector_dropped_carryforward_total", self.dropped.clone()),
            ("ttm_non_tracking_total", self.radar.non_tracking.clone()),
        ]
    }
}

/// Strip an NMEA 4.0 TAG block (`\...\` before the sentence). The block's own
/// checksum covers only the block; the payload keeps the frame with it.
fn strip_tag_block(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('\\') {
        if let Some(end) = rest.find('\\') {
            return &rest[end + 1..];
        }
    }
    s
}

/// Class A (types 1-3) and class B (18, 19) place the kinematic fields at
/// different bit offsets.
#[derive(Clone, Copy, PartialEq)]
enum Layout {
    ClassA,
    ClassB { extended: bool },
}

impl Layout {
    /// `(sog, lon, lat, cog, heading)` bit offsets.
    fn offsets(self) -> (usize, usize, usize, usize, usize) {
        match self {
            ClassA => (50, 61, 89, 116, 128),
            ClassB { .. } => (46, 57, 85, 112, 124),
        }
    }
}

/// ITU-R M.1371 navigation status; 15 is undefined.
fn nav_status(code: u64) -> Option<&'static str> {
    Some(match code {
        0 => "under-way-using-engine",
        1 => "at-anchor",
        2 => "not-under-command",
        3 => "restricted-manoeuvrability",
        4 => "constrained-by-draught",
        5 => "moored",
        6 => "aground",
        7 => "engaged-in-fishing",
        8 => "under-way-sailing",
        9..=13 => "reserved",
        14 => "ais-sart",
        _ => return None,
    })
}

/// Ship-type code (0-99) to category; 0 is not available.
fn ship_type(code: u8) -> Option<&'static str> {
    Some(match code {
        20..=29 => "wing-in-ground",
        30 => "fishing",
        31 | 32 => "towing",
        33 => "dredging",
        34 => "diving-ops",
        35 => "military-ops",
        36 => "sailing",
        37 => "pleasure-craft",
        40..=49 => "high-speed-craft",
        50 => "pilot-vessel",
        51 => "search-and-rescue",
        52 => "tug",
        53 => "port-tender",
        54 => "anti-pollution",
        55 => "law-enforcement",
        58 => "medical-transport",
        60..=69 => "passenger",
        70..=79 => "cargo",
        80..=89 => "tanker",
        90..=99 => "other-vessel",
        _ => return None,
    })
}

/// Rate-of-turn indicator to degrees per minute; -128 is not available.
fn decode_rot(raw: i64) -> Option<f64> {
    if raw <= -128 || raw > 127 {
        return None;
    }
    let s = raw as f64 / 4.733;
    Some((s * s) * (raw.signum() as f64))
}

/// The trailing `*HH` is the XOR of every byte between the `!`/`$` and the `*`.
fn verify_checksum(s: &str) -> Result<(), AisError> {
    let star = s.rfind('*').ok_or(AisError::Checksum)?;
    let given = s.get(star + 1..star + 3).ok_or(AisError::Checksum)?;
    let given = u8::from_str_radix(given, 16).map_err(|_| AisError::Checksum)?;
    let actual = s[1..star].bytes().fold(0u8, |a, b| a ^ b);
    if actual == given {
        Ok(())
    } else {
        Err(AisError::Checksum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // pyais-verified. Type 1, MMSI 227006760, 49.475577 N 0.131380 E, COG 36.7,
    // under way using engine.
    const T1: &[u8] = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23";
    // Type 5 for MMSI 603916439: IMO 439303422, call sign ZA83R, ARCO AVON,
    // ship type 69 (passenger).
    const T5A: &[u8] =
        b"!AIVDO,2,1,0,A,58wt8Ui`g??q`7S=80058<v05Htp00000000001500000000000000000000,0*60";
    const T5B: &[u8] = b"!AIVDO,2,2,0,A,00000000000,2*26";
    // Type 1 for MMSI 603916439: SOG 10.0, COG 90, heading 90.
    const POS_ARCO: &[u8] = b"!AIVDO,1,1,,A,18wt8UhP1T04Tv0LW3P3Q2l1P000,0*1D";
    const OBSERVED: &str = "2026-06-10T08:00:00Z";

    fn parser() -> AisParser {
        AisParser::new("ais-coast-1", Enrichment::default())
    }

    fn configured() -> AisParser {
        AisParser::new(
            "ais-coast-1",
            Enrichment::default().with_hostility("Neutral"),
        )
    }

    /// `body` with its leading `!`/`$`, followed by the computed `*HH`.
    fn with_checksum(body: &str) -> Vec<u8> {
        let cs = body[1..].bytes().fold(0u8, |a, b| a ^ b);
        format!("{body}*{cs:02X}").into_bytes()
    }

    fn attr_of<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .find(|a| a.key == k)
            .map(|a| a.value.as_str())
    }

    fn meta_of<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
        ev.metadata
            .iter()
            .find(|m| m.key == k)
            .map(|m| m.value.as_str())
    }

    #[test]
    fn other_bridge_sentences_are_ignored() {
        let parser = parser();
        for body in [
            "$HEHDT,274.07,T",
            "$TIROT,-2.5,A",
            "$SDDPT,23.9,0.0",
            "$WIMWV,214.0,R,4.2,N,A",
            "$HCHDG,271.1,,,5.1,W",
            "$GPGLL,5432.11,N,01832.15,E,102834,A",
        ] {
            let out = parser
                .parse(&with_checksum(body))
                .unwrap_or_else(|e| panic!("{body}: must be ignored, got error {e}"));
            assert!(out.is_empty(), "{body}: ignored means no events");
        }
        assert!(
            parser.parse(&with_checksum("$AIVDM,1,1")).is_err(),
            "a sentence claiming AIVDM is held to its shape"
        );
    }

    #[test]
    fn decodes_position_and_kinematics() {
        let p = parser().parse_sentence(T1).unwrap().unwrap();
        assert_eq!(p.mmsi, 227006760);
        assert!((p.lat.unwrap() - 49.475577).abs() < 1e-5);
        assert!((p.cog_deg.unwrap() - 36.7).abs() < 1e-6);
        assert_eq!(p.sog_kn, Some(0.0));
        assert_eq!(p.nav_status, Some("under-way-using-engine"));
        assert_eq!(p.heading_deg, None, "511 is not available");
        assert_eq!(p.rot_degmin, None, "-128 is not available");
    }

    #[test]
    fn static_data_joins_later_positions() {
        let p = parser();
        assert_eq!(p.parse_sentence(T5A).unwrap(), None);
        assert_eq!(p.parse_sentence(T5B).unwrap(), None);
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert_eq!(pos.mmsi, 603916439);
        assert_eq!(pos.name.as_deref(), Some("ARCO AVON"));
        assert_eq!(pos.callsign.as_deref(), Some("ZA83R"));
        assert_eq!(pos.ship_type, Some("passenger"));
        assert_eq!(pos.imo, Some(439303422));
        assert!((pos.sog_kn.unwrap() - 10.0).abs() < 1e-6);
    }

    #[test]
    fn interleaved_fragments_on_other_channel_stay_apart() {
        let p = parser();
        let decoy = with_checksum("!AIVDO,2,1,0,B,1234567890,0");
        assert_eq!(p.parse_sentence(T5A).unwrap(), None);
        assert_eq!(p.parse_sentence(&decoy).unwrap(), None);
        assert_eq!(p.parse_sentence(T5B).unwrap(), None);
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert_eq!(pos.mmsi, 603916439);
        assert_eq!(pos.name.as_deref(), Some("ARCO AVON"), "not spliced");
        assert_eq!(pos.callsign.as_deref(), Some("ZA83R"));
    }

    #[test]
    fn event_has_canonical_attributes_and_native_units() {
        let p = configured();
        p.parse_sentence(T5A).unwrap();
        p.parse_sentence(T5B).unwrap();
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "hostility"), Some("Neutral"));
        assert_eq!(attr_of(&ev, "speed"), Some("5.14"));
        assert_eq!(meta_of(&ev, "speed_kn"), Some("10.0"));
        assert_eq!(attr_of(&ev, "vessel_name"), Some("ARCO AVON"));
        assert_eq!(attr_of(&ev, "vessel_type"), Some("passenger"));
        assert_eq!(meta_of(&ev, "source_uid"), Some("603916439"));
        assert_eq!(meta_of(&ev, "mmsi"), Some("603916439"));
        assert!(meta_of(&ev, "imo").is_some());
        assert_eq!(attr_of(&ev, "alt_id"), Some("603916439"));
        assert_eq!(attr_of(&ev, "alt_id_standard"), Some("AIS"));
    }

    #[test]
    fn governed_mmsi_is_nine_digits_and_nonzero() {
        let p = configured();
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        let coast = AisPosition {
            mmsi: 2_320_001,
            ..pos.clone()
        };
        let ev = p.to_event_at(coast, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "alt_id"), Some("002320001"));
        let blank = AisPosition { mmsi: 0, ..pos };
        let ev = p.to_event_at(blank, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "alt_id"), None);
        assert_eq!(meta_of(&ev, "mmsi"), Some("0"));
    }

    #[test]
    fn hostility_absent_without_config() {
        let p = parser();
        let pos = p.parse_sentence(T1).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "hostility"), None);
        assert_eq!(meta_of(&ev, "hostility"), None);
    }

    #[test]
    fn raw_sentence_sealed_in_payload() {
        let p = parser();
        let pos = p.parse_sentence(T1).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(ev.payload.as_slice(), T1);
    }

    #[test]
    fn static_sentences_ride_into_payload() {
        let p = configured();
        assert_eq!(p.parse_sentence(T5A).unwrap(), None);
        assert_eq!(p.parse_sentence(T5B).unwrap(), None);
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert!(!pos.truncated);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        let want = [T5A, T5B, POS_ARCO].join(&b'\n');
        assert_eq!(ev.payload, want);

        let pos2 = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        let ev2 = p.to_event_at(pos2, OBSERVED).unwrap();
        assert_eq!(
            ev2.payload.as_slice(),
            POS_ARCO,
            "carried sentences attach to one event only"
        );
    }

    #[test]
    fn over_cap_drops_oldest_and_marks_truncated() {
        let p = configured();
        for _ in 0..cache::MAX_PENDING_FRAMES {
            p.parse_sentence(T5A).unwrap();
            p.parse_sentence(T5B).unwrap();
        }
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert!(pos.truncated);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(meta_of(&ev, "payload_truncated"), Some("true"));
        assert!(p.counters()[0].1.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn type24_part_a_caches_the_name() {
        let p = parser();
        // Part A for MMSI 271041815, name PROGUY.
        let part_a = b"!AIVDO,1,1,,A,H42O55i18tMET000000000000000,0*5D";
        assert_eq!(p.parse_sentence(part_a).unwrap(), None);
        let name = p
            .identities
            .lock()
            .unwrap()
            .get(271041815)
            .and_then(|id| id.name.clone());
        assert_eq!(name.as_deref(), Some("PROGUY"));
    }

    #[test]
    fn wrong_checksum_is_rejected() {
        let bad = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*24";
        assert_eq!(parser().parse_sentence(bad), Err(AisError::Checksum));
    }

    #[test]
    fn non_ais_talker_is_ignored() {
        let gga = b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        assert_eq!(parser().parse_sentence(gga).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics() {
        assert_eq!(
            parser().parse_sentence(b"\xff\x00not nmea"),
            Err(AisError::NotAscii)
        );
    }

    #[test]
    fn tag_block_parses_and_stays_in_payload() {
        // Captured from the Norwegian coastal administration's public feed.
        let framed = br"\s:2573335,c:1787847115*0D\!BSVDM,1,1,,A,13n2@S00000kU7DU6k09vVad08PC,0*30";
        let pos = parser().parse_sentence(framed).unwrap().unwrap();
        let ev = parser().to_event_at(pos, "2026-08-27T12:00:00Z").unwrap();
        assert_eq!(ev.payload, framed.to_vec());
    }
}
