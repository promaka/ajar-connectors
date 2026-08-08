// SPDX-License-Identifier: Apache-2.0
//! ADS-B (SBS-1 / BaseStation) aircraft reports -> canonical Ajar event.
//!
//! `dump1090`, `readsb`, and every compatible receiver emit decoded ADS-B as
//! line-delimited **SBS-1 "BaseStation"** CSV on TCP port 30003 — the de-facto
//! streaming format for a cooperative air picture. One line is one message; point
//! the `tcp-client` transport (line framing) at the receiver and each line is a
//! frame here. (Raw 1090ES/Beast with CPR position decode is a separate, heavier
//! path; SBS-1 is what receivers already speak.)
//!
//! This is an untrusted edge: a line can be truncated, non-CSV, or hostile, so
//! every field is read defensively and every failure is a typed error — it never
//! panics and never fabricates a field.
//!
//! Scope (military operating picture): an SBS-1 stream fragments one aircraft
//! across message types — identity (callsign) in MSG,1; velocity (ground speed,
//! track, vertical rate) in MSG,4; squawk in MSG,6; position in MSG,2 (surface)
//! and MSG,3 (airborne). So the connector keeps a small per-ICAO state cache and
//! emits a track when a position arrives, enriched with that aircraft's latest
//! known identity and kinematics. The 24-bit ICAO address is emitted as the
//! stable `source_uid` (and `icao`), so Core keeps every airframe its own track
//! rather than collapsing them onto the connector `source_id`.
//!
//! SBS-1 field layout (0-based, 22 comma-separated fields) is per the published
//! BaseStation port-30003 specification and verified against constructed lines.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

/// 1 foot in metres.
const FT_TO_M: f64 = 0.3048;
/// 1 foot/minute in metres/second.
const FTMIN_TO_MPS: f64 = FT_TO_M / 60.0;
/// 1 knot in metres/second. The governed `speed` attribute is m/s; SBS ground
/// speed is knots, so normalise (ADR-0019) and keep the native knots in metadata.
const KNOTS_TO_MPS: f64 = 0.514_444;

/// Why an SBS-1 line could not be turned into a track.
#[derive(Debug, PartialEq, Eq)]
pub enum AdsbError {
    /// The line was not valid ASCII/UTF-8.
    NotAscii,
    /// Not an SBS-1 line (unknown leading record type).
    NotSbs,
    /// A `MSG` line without the mandatory ICAO address field.
    NoIcao,
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for AdsbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdsbError::NotAscii => write!(f, "ADS-B line not ASCII"),
            AdsbError::NotSbs => write!(f, "not an SBS-1 line"),
            AdsbError::NoIcao => write!(f, "SBS-1 MSG line missing ICAO address"),
            AdsbError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for AdsbError {}

/// A decoded ADS-B position enriched with the aircraft's latest known state.
#[derive(Debug, Clone, PartialEq)]
pub struct AdsbPosition {
    /// 24-bit ICAO address, uppercase hex — the stable per-airframe identity.
    pub icao: String,
    /// SBS-1 transmission type that produced this position (2 surface, 3 airborne).
    pub msg_type: u8,
    pub lat: f64,
    pub lon: f64,
    /// Barometric altitude, metres.
    pub alt_m: f64,
    /// Latest known state for this aircraft.
    pub state: AircraftState,
    /// Every raw SBS line that contributed to this event — the anchor position
    /// line plus any cache-only lines (callsign, velocity, squawk) that arrived
    /// since the last emit — newline-delimited, carried verbatim into the signed
    /// `payload` so nothing is lost.
    pub raw: Vec<u8>,
    /// True if the per-ICAO buffer dropped one or more raw lines before this
    /// emit (over the cap). The event marks itself `payload_truncated` so a
    /// re-parser can tell "all contributing frames" from "some were discarded".
    pub truncated: bool,
}

/// An aircraft's latest known non-positional state, cached by ICAO address.
/// Every field is optional: absent until a message carries it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AircraftState {
    /// Flight/callsign (MSG,1).
    pub callsign: Option<String>,
    /// Mode 3/A squawk code, four octal digits (MSG,6).
    pub squawk: Option<String>,
    /// Ground speed, knots (MSG,2 / MSG,4).
    pub ground_speed: Option<f64>,
    /// Track angle, degrees (MSG,2 / MSG,4).
    pub track: Option<f64>,
    /// Vertical rate, native ft/min (MSG,4); emitted as m/s + kept in metadata.
    pub vertical_speed: Option<f64>,
    /// Barometric altitude, native feet (most types); located in metres.
    pub altitude: Option<f64>,
    /// On-ground flag (SBS field 21).
    pub on_ground: Option<bool>,
}

/// Upper bound on cached aircraft. The 24-bit ICAO space is ~16M and is
/// attacker-controllable — a hostile feed spoofing addresses must cost bounded
/// memory. At capacity the oldest-inserted entry is evicted (FIFO); a live
/// aircraft's next message simply re-caches it. A dense TMA is a few thousand.
const MAX_AIRCRAFT: usize = 10_000;

/// Per-aircraft cap on raw SBS lines carried forward before the next emit, and
/// on their total bytes. A feed streaming identity/velocity lines for an
/// aircraft that never reports a position must cost bounded memory: past the cap
/// the oldest pending line is dropped (with a warning), never the whole event.
const MAX_PENDING_FRAMES: usize = 64;
const MAX_PENDING_BYTES: usize = 16 * 1024;

/// One aircraft: latest parsed state, plus the raw SBS lines received since its
/// last emitted event (carried forward so cache-only lines are not lost).
#[derive(Default)]
struct Entry {
    state: AircraftState,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    /// Set when a pending line was dropped over the cap since the last emit;
    /// cleared on drain. Drives the event's `payload_truncated` marker.
    dropped_since_emit: bool,
}

impl Entry {
    /// Remember one raw line, dropping the oldest pending line(s) past the cap.
    /// Returns how many were dropped (for the metric).
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

    /// Drain all pending lines into one newline-delimited payload (a re-parse
    /// splits on `\n`), and report whether any were dropped since the last emit.
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

/// A bounded ICAO → [`Entry`] cache with FIFO eviction of whole aircraft.
#[derive(Default)]
struct StateCache {
    map: HashMap<String, Entry>,
    order: VecDeque<String>,
}

impl StateCache {
    /// The entry for `icao`, creating it (and evicting the oldest aircraft if at
    /// capacity) on first sight.
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

/// Normalizes an SBS-1 stream for one connector identity, caching per-ICAO state.
pub struct AdsbParser {
    source_id: String,
    enrichment: Enrichment,
    aircraft: Mutex<StateCache>,
    /// Carry-forward lines dropped over the per-ICAO cap, since start.
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

    /// Parse one SBS-1 line. Returns a position for a CRC-valid position message
    /// (MSG,2 / MSG,3 carrying lat+lon); `Ok(None)` for a message that only
    /// updates the state cache, or a non-`MSG` record (SEL/ID/STA/CLK/AIR).
    pub fn parse_line(&self, frame: &[u8]) -> Result<Option<AdsbPosition>, AdsbError> {
        let text = std::str::from_utf8(frame).map_err(|_| AdsbError::NotAscii)?;
        let line = text.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(None);
        }
        let parts: Vec<&str> = line.split(',').collect();

        match parts[0] {
            "MSG" => {}
            // Other SBS record types are valid but carry no track.
            "SEL" | "ID" | "AIR" | "STA" | "CLK" => return Ok(None),
            _ => return Err(AdsbError::NotSbs),
        }

        let icao = field(&parts, 4)
            .ok_or(AdsbError::NoIcao)?
            .to_ascii_uppercase();
        let tx = field(&parts, 1).and_then(|s| s.parse::<u8>().ok());

        // Carry this raw line forward, then fold whatever it carries into state.
        let mut cache = self.aircraft.lock().expect("aircraft mutex");
        let entry = cache.entry(&icao);
        let dropped = entry.push_raw(line.as_bytes());
        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
            tracing::warn!(dropped, %icao, "adsb: carry-forward buffer over cap");
        }
        {
            let s = &mut entry.state;
            if let Some(cs) = field(&parts, 10) {
                s.callsign = Some(cs.trim().to_string());
            }
            if let Some(a) = num(&parts, 11) {
                s.altitude = Some(a); // native feet
            }
            if let Some(gs) = num(&parts, 12) {
                s.ground_speed = Some(gs);
            }
            if let Some(t) = num(&parts, 13) {
                s.track = Some(t);
            }
            if let Some(vr) = num(&parts, 16) {
                s.vertical_speed = Some(vr); // native ft/min; converted at emit
            }
            if let Some(sq) = field(&parts, 17) {
                s.squawk = Some(sq.to_string());
            }
            if let Some(g) = field(&parts, 21) {
                // SBS uses -1/0 for airborne, 1 for on-ground (receivers vary).
                s.on_ground = Some(g == "1");
            }
        }

        // A position report (surface=2, airborne=3) with a fix emits a track,
        // draining every raw line carried since the last emit into its payload.
        // A cache-only line (or a position without a fix) leaves them pending.
        match tx {
            Some(2) | Some(3) => {
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
                    msg_type: tx.expect("matched above"),
                    lat,
                    lon,
                    alt_m: state.altitude.map(|ft| ft * FT_TO_M).unwrap_or(0.0),
                    state,
                    raw,
                    truncated,
                }))
            }
            _ => Ok(None),
        }
    }

    fn base_builder(&self, p: &AdsbPosition) -> EventBuilder {
        let s = &p.state;

        // Every raw line that produced this event is preserved verbatim in the
        // signed payload (newline-delimited) — nothing the parser does not yet map
        // is ever lost, and a future ontology can re-extract from it. The ICAO
        // address is the stable identity (source_uid = track key; `icao` = native).
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(p.lat, p.lon, p.alt_m)
            .payload(p.raw.clone())
            .metadata("source_uid", p.icao.clone())
            .metadata("icao", p.icao.clone())
            // The ICAO address is the airframe's stable track key — the governed
            // correlation key a consumer keys on (`track_id`), not just provenance.
            .attribute("track_id", p.icao.clone());

        // If the carry-forward buffer dropped lines, the payload is incomplete —
        // say so, so a re-parser never mistakes it for the full set of frames.
        if p.truncated {
            b = b.metadata("payload_truncated", "true");
        }

        // Parse every field into attributes; Core auto-demotes undeclared keys.
        // Affiliation is only ever the operator's explicit assertion — never a
        // connector-invented default (ADS-B carries none of its own).
        if let Some(aff) = self.enrichment.affiliation.as_deref() {
            b = b.attribute("affiliation", aff);
        }
        macro_rules! attr {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    b = b.attribute($key, v);
                }
            };
        }
        attr!("callsign", s.callsign.clone().filter(|c| !c.is_empty()));
        // Governed `speed` is m/s; keep the native knots in metadata (ADR-0019).
        if let Some(kn) = s.ground_speed {
            b = b.attribute("speed", format!("{:.2}", kn * KNOTS_TO_MPS));
            b = b.metadata("speed_kn", format!("{kn:.1}"));
        }
        attr!("course", s.track.map(|v| format!("{v:.1}"))); // deg, course over ground
                                                             // Governed vertical_rate is m/s; keep native ft/min in metadata (ADR-0019).
        if let Some(ftmin) = s.vertical_speed {
            let mps = ftmin * FTMIN_TO_MPS;
            b = b.attribute(
                "vertical_rate",
                format!("{:.1}", if mps == 0.0 { 0.0 } else { mps }),
            );
            b = b.metadata("vertical_rate_ftmin", format!("{ftmin:.0}"));
        }
        // Altitude is located in metres (GeoPoint); keep native feet in metadata.
        if let Some(ft) = s.altitude {
            b = b.metadata("altitude_ft", format!("{ft:.0}"));
        }
        attr!("squawk", s.squawk.clone().filter(|q| !q.is_empty()));
        attr!(
            "on_ground",
            s.on_ground.map(|g| if g { "true" } else { "false" })
        );
        b
    }

    /// Build with an explicit observation timestamp (tests pin this path).
    pub fn to_event_at(&self, p: &AdsbPosition, observed: &str) -> Result<Event, AdsbError> {
        self.base_builder(p)
            .timestamp(observed)
            .build()
            .map_err(|e| AdsbError::Build(e.to_string()))
    }

    /// Build stamped with receipt time — the SBS-1 timestamps are the receiver's
    /// clock, so observation time is when we saw it.
    fn to_event_now(&self, p: &AdsbPosition) -> Result<Event, AdsbError> {
        self.base_builder(p)
            .now()
            .build()
            .map_err(|e| AdsbError::Build(e.to_string()))
    }
}

impl FrameParser for AdsbParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        match self.parse_line(frame).map_err(box_err)? {
            Some(pos) => Ok(vec![self.to_event_now(&pos).map_err(box_err)?]),
            None => Ok(Vec::new()),
        }
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        vec![("connector_dropped_carryforward_total", self.dropped.clone())]
    }
}

fn box_err(e: AdsbError) -> ParseError {
    Box::new(e) as ParseError
}

/// A trimmed, non-empty field at `idx`, or `None` (missing or blank — SBS lines
/// leave irrelevant fields empty).
fn field<'a>(parts: &[&'a str], idx: usize) -> Option<&'a str> {
    parts.get(idx).map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// A numeric field at `idx`, or `None` if missing/blank/unparseable.
fn num(parts: &[&str], idx: usize) -> Option<f64> {
    field(parts, idx).and_then(|s| s.parse::<f64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real airborne-position line (MSG,3): ICAO 4CA2D6, 51.5 N, -0.5 E,
    // 38000 ft. Fields after the four date/time columns: callsign(empty),
    // alt=38000, gs, track, lat=51.5, lon=-0.5, vrate, squawk, alert, emerg, spi,
    // ground=0.
    const AIRBORNE: &str =
        "MSG,3,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,38000,,,51.50000,-0.50000,,,,,,0";

    fn parser() -> AdsbParser {
        AdsbParser::new("adsb-1", Enrichment::default())
    }

    fn governed() -> AdsbParser {
        AdsbParser::new("adsb-1", Enrichment::default().with_affiliation("neutral"))
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
    fn decodes_airborne_position_and_altitude() {
        let p = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert_eq!(p.icao, "4CA2D6");
        assert_eq!(p.msg_type, 3);
        assert!((p.lat - 51.5).abs() < 1e-6);
        assert!((p.lon - (-0.5)).abs() < 1e-6);
        assert!((p.alt_m - 38000.0 * FT_TO_M).abs() < 1e-6); // ~11582.4 m
    }

    #[test]
    fn icao_becomes_stable_source_uid() {
        let p = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = parser().to_event_at(&p, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(meta_of(&ev, "source_uid"), Some("4CA2D6"));
        assert_eq!(attr_of(&ev, "track_id"), Some("4CA2D6")); // governed correlation key
        assert_eq!(meta_of(&ev, "icao"), Some("4CA2D6"));
    }

    #[test]
    fn callsign_from_msg1_correlates_into_positions() {
        let p = governed();
        // MSG,1 carries the callsign only; it caches, no event.
        let ident =
            "MSG,1,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,BAW123,,,,,,,,,,0";
        assert_eq!(p.parse_line(ident.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert_eq!(pos.state.callsign.as_deref(), Some("BAW123"));
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "callsign"), Some("BAW123"));
        assert_eq!(attr_of(&ev, "affiliation"), Some("neutral"));
    }

    #[test]
    fn velocity_from_msg4_correlates_into_positions() {
        let p = governed();
        // MSG,4: ground speed 450 kt, track 270, vertical rate -1024 ft/min.
        let vel =
            "MSG,4,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,,450,270,,,-1024,,,,,";
        assert_eq!(p.parse_line(vel.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        // Governed speed is m/s (450 kt * 0.514444); native knots kept in metadata.
        assert_eq!(attr_of(&ev, "speed"), Some("231.50"));
        assert_eq!(meta_of(&ev, "speed_kn"), Some("450.0"));
        assert_eq!(attr_of(&ev, "course"), Some("270.0"));
        // -1024 ft/min = -5.2 m/s (descending).
        assert_eq!(attr_of(&ev, "vertical_rate"), Some("-5.2"));
        assert_eq!(meta_of(&ev, "vertical_rate_ftmin"), Some("-1024"));
    }

    #[test]
    fn squawk_from_msg6_correlates_into_positions() {
        let p = governed();
        let sq =
            "MSG,6,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,,,,,,,7700,,,,";
        assert_eq!(p.parse_line(sq.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "squawk"), Some("7700")); // emergency
    }

    #[test]
    fn absent_affiliation_is_not_invented_and_raw_is_preserved() {
        // Default mode: no operator affiliation -> none is invented (absent stays
        // absent), and the raw SBS line is preserved verbatim in the signed payload.
        let pos = parser().parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = parser().to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert!(!ev.attributes.iter().any(|a| a.key == "affiliation"));
        assert!(!ev.metadata.iter().any(|m| m.key == "affiliation"));
        assert_eq!(ev.payload.as_slice(), AIRBORNE.as_bytes());
    }

    #[test]
    fn carries_cache_only_frames_forward_into_payload() {
        // A callsign-only line (MSG,1) does not emit; its raw must ride into the
        // next position event's payload, newline-joined with the position line.
        let p = governed();
        let ident =
            "MSG,1,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,BAW123,,,,,,,,,,0";
        assert_eq!(p.parse_line(ident.as_bytes()).unwrap(), None); // cached, no event
        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        // payload = both raw lines, newline-delimited (re-parse splits on \n).
        let want = format!("{ident}\n{AIRBORNE}");
        assert_eq!(ev.payload.as_slice(), want.as_bytes());
        // ...and the parsed callsign still surfaces as an attribute.
        assert_eq!(attr_of(&ev, "callsign"), Some("BAW123"));

        // Attached once: the NEXT position emits only its own line.
        let pos2 = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev2 = p.to_event_at(&pos2, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev2.payload.as_slice(), AIRBORNE.as_bytes());
    }

    #[test]
    fn bytes_per_event_before_vs_after_raw_payload() {
        use ajar_connector::canonical_bytes;
        let p = governed();
        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let after = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        let mut before = after.clone();
        before.payload.clear();
        let (b, a) = (
            canonical_bytes(&before).len(),
            canonical_bytes(&after).len(),
        );
        println!(
            "ADSB canonical bytes/event: before(no payload)={b}  after(raw payload)={a}  raw={}  sealed_after={}",
            after.payload.len(),
            a + 64
        );
        assert!(a > b); // raw is carried
    }

    #[test]
    fn over_cap_drops_oldest_and_marks_payload_truncated() {
        let p = governed();
        let vel =
            "MSG,4,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,,450,270,,,-1024,,,,,";
        // Flood one ICAO with cache-only lines past the frame cap.
        for _ in 0..(MAX_PENDING_FRAMES + 5) {
            assert_eq!(p.parse_line(vel.as_bytes()).unwrap(), None);
        }
        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        assert!(pos.truncated);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(meta_of(&ev, "payload_truncated"), Some("true"));
        // The dropped-frame metric advanced.
        assert!(p.counters()[0].1.load(Ordering::Relaxed) >= 5);
    }

    #[test]
    fn bytes_per_event_realistic_frame_mix() {
        use ajar_connector::canonical_bytes;
        let p = governed();
        // A realistic burst contributing to one position event: identity, two
        // velocity updates, a squawk, then the airborne position (5 frames).
        let frames = [
            "MSG,1,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,BAW123,,,,,,,,,,0",
            "MSG,4,1,1,4CA2D6,1,2026/06/10,08:00:00.100,2026/06/10,08:00:00.100,,,450,270,,,-1024,,,,,",
            "MSG,4,1,1,4CA2D6,1,2026/06/10,08:00:00.200,2026/06/10,08:00:00.200,,,451,271,,,-960,,,,,",
            "MSG,6,1,1,4CA2D6,1,2026/06/10,08:00:00.300,2026/06/10,08:00:00.300,,,,,,,,7700,,,,",
        ];
        for f in &frames {
            assert_eq!(p.parse_line(f.as_bytes()).unwrap(), None);
        }
        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        let sealed = canonical_bytes(&ev).len() + 64;
        let per_day = |rate: f64| (50.0 * rate * sealed as f64 * 86_400.0) / 1e9;
        println!(
            "ADSB realistic: {}frames/event  payload={}B  sealed={sealed}B  => {:.1} GB/day @1Hz, {:.1} GB/day @2Hz (50 aircraft)",
            frames.len() + 1,
            ev.payload.len(),
            per_day(1.0),
            per_day(2.0),
        );
        assert!(sealed > 363);
    }

    #[test]
    fn surface_position_msg2_emits() {
        // MSG,2 surface position with ground speed + track inline, on-ground=1.
        let surface =
            "MSG,2,1,1,3C6DD2,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,0,15,90,50.03000,8.55000,,,,,,1";
        let pos = parser().parse_line(surface.as_bytes()).unwrap().unwrap();
        assert_eq!(pos.icao, "3C6DD2");
        assert_eq!(pos.state.on_ground, Some(true));
        assert!((pos.lat - 50.03).abs() < 1e-6);
    }

    #[test]
    fn distinct_icao_keep_separate_tracks() {
        let p = governed();
        // Cache a callsign for a DIFFERENT aircraft; it must not bleed across.
        let other =
            "MSG,1,1,1,AABBCC,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,SPY001,,,,,,,,,,0";
        assert_eq!(p.parse_line(other.as_bytes()).unwrap(), None);

        let pos = p.parse_line(AIRBORNE.as_bytes()).unwrap().unwrap(); // 4CA2D6
        assert_eq!(pos.icao, "4CA2D6");
        assert_eq!(pos.state.callsign, None); // not SPY001
    }

    #[test]
    fn non_msg_records_are_ignored_not_errored() {
        let status = "STA,,1,1,4CA2D6,1,2026/06/10,08:00:00.000,,,,,,,,,,,,,RM";
        assert_eq!(parser().parse_line(status.as_bytes()).unwrap(), None);
        // A selection-change record, likewise ignored.
        let sel = "SEL,,1,1,4CA2D6,1,,,,,BAW123,,,,,,,,,,";
        assert_eq!(parser().parse_line(sel.as_bytes()).unwrap(), None);
    }

    #[test]
    fn position_without_fix_does_not_emit() {
        // MSG,3 but lat/lon empty (common — altitude-only airborne report).
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
        assert!(parser().parse_line(b"not,an,sbs,line").is_err()); // unknown record type
        assert!(parser().parse_line(b"\xff\xfe\x00").is_err()); // non-UTF8
        assert_eq!(parser().parse_line(b"").unwrap(), None); // empty line
        assert!(parser().parse_line(b"MSG").is_err()); // MSG with no ICAO field -> NoIcao
    }
}
