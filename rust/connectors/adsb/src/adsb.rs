// SPDX-License-Identifier: Apache-2.0
//! ADS-B as SBS-1 "BaseStation" CSV (dump1090/readsb, TCP port 30003) to
//! `mim:aircraft` events. One aircraft's identity, velocity and squawk arrive in
//! separate messages, so they are cached per ICAO address and attached to the
//! next position report (MSG,2 surface or MSG,3 airborne).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::GovernedIdentity;
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

const FT_TO_M: f64 = 0.3048;
const FTMIN_TO_MPS: f64 = FT_TO_M / 60.0;
const KNOTS_TO_MPS: f64 = 0.514_444;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum AdsbError {
    #[error("ADS-B line not ASCII")]
    NotAscii,
    #[error("not an SBS-1 line")]
    NotSbs,
    #[error("SBS-1 MSG line missing ICAO address")]
    NoIcao,
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

/// A position report with the aircraft's latest cached state.
#[derive(Debug, Clone, PartialEq)]
pub struct AdsbPosition {
    /// 24-bit ICAO address, uppercase hex.
    pub icao: String,
    /// SBS transmission type: 2 surface, 3 airborne.
    pub msg_type: u8,
    pub lat: f64,
    pub lon: f64,
    /// Barometric altitude; 0 until an altitude has been seen.
    pub alt_m: f64,
    pub state: AircraftState,
    /// Every SBS line received for this aircraft since its last event,
    /// newline-joined.
    pub raw: Vec<u8>,
    /// Lines were dropped from `raw` over the per-aircraft cap.
    pub truncated: bool,
}

/// Latest non-positional state of one aircraft; a field stays `None` until a
/// message carries it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AircraftState {
    pub callsign: Option<String>,
    pub squawk: Option<String>,
    pub ground_speed_kn: Option<f64>,
    pub track_deg: Option<f64>,
    pub vertical_rate_ftmin: Option<f64>,
    pub altitude_ft: Option<f64>,
    pub on_ground: Option<bool>,
}

// ICAO addresses come from the feed, so a spoofing sender must not grow the
// cache without bound. The oldest aircraft is evicted first.
const MAX_AIRCRAFT: usize = 10_000;
const MAX_PENDING_FRAMES: usize = 64;
const MAX_PENDING_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct Entry {
    state: AircraftState,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    dropped_since_emit: bool,
}

impl Entry {
    /// Returns how many of the oldest pending lines were dropped over the cap.
    fn push_raw(&mut self, raw: &[u8]) -> u64 {
        self.pending.push_back(raw.to_vec());
        self.pending_bytes += raw.len();
        let mut dropped = 0;
        while self.pending.len() > MAX_PENDING_FRAMES || self.pending_bytes > MAX_PENDING_BYTES {
            match self.pending.pop_front() {
                Some(old) => {
                    self.pending_bytes -= old.len();
                    self.dropped_since_emit = true;
                    dropped += 1;
                }
                None => break,
            }
        }
        dropped
    }

    /// The pending lines newline-joined, and whether any were dropped.
    fn drain_payload(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(self.pending_bytes + self.pending.len());
        for (i, f) in self.pending.drain(..).enumerate() {
            if i > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(&f);
        }
        self.pending_bytes = 0;
        let truncated = std::mem::take(&mut self.dropped_since_emit);
        (out, truncated)
    }
}

#[derive(Default)]
struct StateCache {
    map: HashMap<String, Entry>,
    order: VecDeque<String>,
}

impl StateCache {
    fn entry(&mut self, icao: &str) -> &mut Entry {
        if !self.map.contains_key(icao) {
            if self.order.len() >= MAX_AIRCRAFT {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.order.push_back(icao.to_string());
        }
        self.map.entry(icao.to_string()).or_default()
    }
}

pub struct AdsbParser {
    source_id: String,
    enrichment: Enrichment,
    aircraft: Mutex<StateCache>,
    dropped: Arc<AtomicU64>,
}

impl AdsbParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            aircraft: Mutex::new(StateCache::default()),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// `Some` for a MSG,2 or MSG,3 line with a valid fix; `None` for a line that
    /// only updates the cache or a non-MSG record.
    pub fn parse_line(&self, frame: &[u8]) -> Result<Option<AdsbPosition>, AdsbError> {
        let text = std::str::from_utf8(frame).map_err(|_| AdsbError::NotAscii)?;
        let line = text.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(None);
        }
        // An SBS-1 record has 22 fields.
        let mut parts = Vec::with_capacity(22);
        parts.extend(line.split(','));

        match parts[0] {
            "MSG" => {}
            // Valid SBS record types that carry no track.
            "SEL" | "ID" | "AIR" | "STA" | "CLK" => return Ok(None),
            _ => return Err(AdsbError::NotSbs),
        }

        let icao = field(&parts, 4)
            .ok_or(AdsbError::NoIcao)?
            .to_ascii_uppercase();
        let tx = field(&parts, 1).and_then(|s| s.parse::<u8>().ok());

        let mut cache = self.aircraft.lock().expect("aircraft mutex");
        let entry = cache.entry(&icao);
        let dropped = entry.push_raw(line.as_bytes());
        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
            tracing::warn!(dropped, %icao, "adsb: carry-forward buffer over cap");
        }
        let s = &mut entry.state;
        if let Some(cs) = field(&parts, 10) {
            s.callsign = Some(cs.trim().to_string());
        }
        if let Some(ft) = num(&parts, 11) {
            s.altitude_ft = Some(ft);
        }
        if let Some(kn) = num(&parts, 12) {
            s.ground_speed_kn = Some(kn);
        }
        if let Some(deg) = num(&parts, 13) {
            s.track_deg = Some(deg);
        }
        if let Some(ftmin) = num(&parts, 16) {
            s.vertical_rate_ftmin = Some(ftmin);
        }
        if let Some(sq) = field(&parts, 17) {
            s.squawk = Some(sq.to_string());
        }
        if let Some(g) = field(&parts, 21) {
            // Receivers send -1 or 0 for airborne and 1 for on ground.
            s.on_ground = Some(g == "1");
        }

        let Some(msg_type @ (2 | 3)) = tx else {
            return Ok(None);
        };
        let (Some(lat), Some(lon)) = (num(&parts, 14), num(&parts, 15)) else {
            return Ok(None);
        };
        if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
            return Ok(None);
        }
        let state = entry.state.clone();
        let (raw, truncated) = entry.drain_payload();
        Ok(Some(AdsbPosition {
            icao,
            msg_type,
            lat,
            lon,
            alt_m: state.altitude_ft.map(|ft| ft * FT_TO_M).unwrap_or(0.0),
            state,
            raw,
            truncated,
        }))
    }

    fn base_builder(&self, p: AdsbPosition) -> EventBuilder {
        let s = p.state;
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(p.lat, p.lon, p.alt_m)
            .payload(p.raw)
            .metadata("source_uid", p.icao.clone())
            .metadata("icao", p.icao.clone())
            .identity("ICAO24", p.icao);

        if p.truncated {
            b = b.metadata("payload_truncated", "true");
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        macro_rules! attr {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    b = b.attribute($key, v);
                }
            };
        }
        attr!("callsign", s.callsign.filter(|c| !c.is_empty()));
        if let Some(kn) = s.ground_speed_kn {
            b = b.attribute("speed", format!("{:.2}", kn * KNOTS_TO_MPS));
            b = b.metadata("speed_kn", format!("{kn:.1}"));
        }
        attr!("course", s.track_deg.map(|deg| format!("{deg:.1}")));
        if let Some(ftmin) = s.vertical_rate_ftmin {
            let mps = ftmin * FTMIN_TO_MPS;
            b = b.attribute(
                "vertical_rate",
                format!("{:.1}", if mps == 0.0 { 0.0 } else { mps }),
            );
            b = b.metadata("vertical_rate_ftmin", format!("{ftmin:.0}"));
        }
        if let Some(ft) = s.altitude_ft {
            b = b.metadata("altitude_ft", format!("{ft:.0}"));
        }
        attr!("squawk", s.squawk.filter(|q| !q.is_empty()));
        attr!(
            "on_ground",
            s.on_ground.map(|g| if g { "true" } else { "false" })
        );
        b
    }

    pub fn to_event_at(&self, p: AdsbPosition, observed: &str) -> Result<Event, AdsbError> {
        Ok(self.base_builder(p).timestamp(observed).build()?)
    }
}

impl FrameParser for AdsbParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let Some(pos) = self.parse_line(frame)? else {
            return Ok(Vec::new());
        };
        // SBS timestamps are the receiver's clock, so stamp the time of receipt.
        let event = self
            .base_builder(pos)
            .now()
            .build()
            .map_err(AdsbError::from)?;
        Ok(vec![event])
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        vec![("connector_dropped_carryforward_total", self.dropped.clone())]
    }
}

/// A trimmed, non-empty field; SBS leaves unused fields blank.
fn field<'a>(parts: &[&'a str], idx: usize) -> Option<&'a str> {
    parts.get(idx).map(|s| s.trim()).filter(|s| !s.is_empty())
}

fn num(parts: &[&str], idx: usize) -> Option<f64> {
    field(parts, idx).and_then(|s| s.parse::<f64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // MSG,3 for ICAO 4CA2D6 at 51.5 N, 0.5 W, 38000 ft, airborne.
    const AIRBORNE: &str =
        "MSG,3,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,38000,,,51.50000,-0.50000,,,,,,0";
    const IDENT: &str =
        "MSG,1,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,BAW123,,,,,,,,,,0";
    // 450 kt, track 270, -1024 ft/min.
    const VELOCITY: &str =
        "MSG,4,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,,450,270,,,-1024,,,,,";
    const OBSERVED: &str = "2026-06-10T08:00:00Z";

    fn parser() -> AdsbParser {
        AdsbParser::new("adsb-1", Enrichment::default())
    }

    fn governed() -> AdsbParser {
        AdsbParser::new("adsb-1", Enrichment::default().with_hostility("Neutral"))
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
    fn decodes_airborne_position() {
        let p = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert_eq!(p.icao, "4CA2D6");
        assert_eq!(p.msg_type, 3);
        assert!((p.lat - 51.5).abs() < 1e-6);
        assert!((p.lon - (-0.5)).abs() < 1e-6);
        assert!((p.alt_m - 38000.0 * FT_TO_M).abs() < 1e-6);
    }

    #[test]
    fn icao_is_source_uid() {
        let p = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = parser().to_event_at(p, OBSERVED).unwrap();
        assert_eq!(meta_of(&ev, "source_uid"), Some("4CA2D6"));
        assert_eq!(meta_of(&ev, "icao"), Some("4CA2D6"));
        assert_eq!(attr_of(&ev, "alt_id"), Some("4CA2D6"));
        assert_eq!(attr_of(&ev, "alt_id_standard"), Some("ICAO24"));
    }

    #[test]
    fn callsign_joins_next_position() {
        let p = governed();
        assert_eq!(p.parse_line(IDENT.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert_eq!(pos.state.callsign.as_deref(), Some("BAW123"));
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "callsign"), Some("BAW123"));
        assert_eq!(attr_of(&ev, "hostility"), Some("Neutral"));
    }

    #[test]
    fn velocity_joins_next_position_in_si() {
        let p = governed();
        assert_eq!(p.parse_line(VELOCITY.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "speed"), Some("231.50"));
        assert_eq!(meta_of(&ev, "speed_kn"), Some("450.0"));
        assert_eq!(attr_of(&ev, "course"), Some("270.0"));
        assert_eq!(attr_of(&ev, "vertical_rate"), Some("-5.2"));
        assert_eq!(meta_of(&ev, "vertical_rate_ftmin"), Some("-1024"));
    }

    #[test]
    fn squawk_joins_next_position() {
        let p = governed();
        let sq =
            "MSG,6,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,,,,,,,7700,,,,";
        assert_eq!(p.parse_line(sq.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "squawk"), Some("7700"));
    }

    #[test]
    fn hostility_absent_without_config() {
        let pos = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = parser().to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "hostility"), None);
        assert_eq!(meta_of(&ev, "hostility"), None);
    }

    #[test]
    fn raw_line_sealed_in_payload() {
        let pos = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = parser().to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(ev.payload.as_slice(), AIRBORNE.as_bytes());
    }

    #[test]
    fn cache_only_lines_ride_into_payload() {
        let p = governed();
        assert_eq!(p.parse_line(IDENT.as_bytes()).unwrap(), None);
        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        let want = format!("{IDENT}\n{AIRBORNE}");
        assert_eq!(ev.payload.as_slice(), want.as_bytes());
        assert_eq!(attr_of(&ev, "callsign"), Some("BAW123"));

        let pos2 = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev2 = p.to_event_at(pos2, OBSERVED).unwrap();
        assert_eq!(
            ev2.payload.as_slice(),
            AIRBORNE.as_bytes(),
            "carried lines attach to one event only"
        );
    }

    #[test]
    fn over_cap_drops_oldest_and_marks_truncated() {
        let p = governed();
        for _ in 0..(MAX_PENDING_FRAMES + 5) {
            assert_eq!(p.parse_line(VELOCITY.as_bytes()).unwrap(), None);
        }
        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert!(pos.truncated);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(meta_of(&ev, "payload_truncated"), Some("true"));
        assert!(p.counters()[0].1.load(Ordering::Relaxed) >= 5);
    }

    #[test]
    fn surface_position_msg2_emits() {
        let surface =
            "MSG,2,1,1,3C6DD2,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,0,15,90,50.03000,8.55000,,,,,,1";
        let pos = parser().parse_line(surface.as_bytes()).unwrap().unwrap();
        assert_eq!(pos.icao, "3C6DD2");
        assert_eq!(pos.state.on_ground, Some(true));
        assert!((pos.lat - 50.03).abs() < 1e-6);
    }

    #[test]
    fn aircraft_state_stays_per_icao() {
        let p = governed();
        let other =
            "MSG,1,1,1,AABBCC,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,SPY001,,,,,,,,,,0";
        assert_eq!(p.parse_line(other.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert_eq!(pos.icao, "4CA2D6");
        assert_eq!(pos.state.callsign, None);
    }

    #[test]
    fn non_msg_records_are_ignored() {
        let status = "STA,,1,1,4CA2D6,1,2026/06/10,08:00:00.000,,,,,,,,,,,,,RM";
        assert_eq!(parser().parse_line(status.as_bytes()).unwrap(), None);
        let sel = "SEL,,1,1,4CA2D6,1,,,,,BAW123,,,,,,,,,,";
        assert_eq!(parser().parse_line(sel.as_bytes()).unwrap(), None);
    }

    #[test]
    fn position_without_fix_does_not_emit() {
        let no_fix =
            "MSG,3,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,38000,,,,,,,,,,0";
        assert_eq!(parser().parse_line(no_fix.as_bytes()).unwrap(), None);
    }

    #[test]
    fn msg_without_icao_is_rejected() {
        let no_icao = "MSG,3,1,1,,1,2026/06/10,08:00:00.000,,,,38000,,,51.5,-0.5,,,,,,0";
        assert_eq!(
            parser().parse_line(no_icao.as_bytes()),
            Err(AdsbError::NoIcao)
        );
    }

    #[test]
    fn garbage_never_panics() {
        assert_eq!(
            parser().parse_line(b"not,an,sbs,line"),
            Err(AdsbError::NotSbs)
        );
        assert_eq!(
            parser().parse_line(b"\xff\xfe\x00"),
            Err(AdsbError::NotAscii)
        );
        assert_eq!(parser().parse_line(b"").unwrap(), None);
        assert_eq!(parser().parse_line(b"MSG"), Err(AdsbError::NoIcao));
    }
}
