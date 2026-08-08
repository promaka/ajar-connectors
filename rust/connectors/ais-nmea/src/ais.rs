// SPDX-License-Identifier: Apache-2.0
//! AIS (Automatic Identification System) over NMEA 0183 -> canonical Ajar event.
//!
//! AIS messages arrive as `!AIVDM`/`!AIVDO` sentences whose payload is a 6-bit
//! ASCII-armored bit stream (ITU-R M.1371). This is an untrusted edge: sentences
//! can be malformed, truncated, mis-checksummed, or hostile, so every step is
//! checked and every failure is a typed error — it never panics and never
//! fabricates a field.
//!
//! Scope (military operating picture):
//!  - **Position reports** (types 1, 2, 3, 18, 19) → vessel track with position,
//!    speed over ground, course, heading, rate of turn, and navigation status.
//!  - **Static/voyage data** (types 5, 24, and the inline data in type 19) →
//!    vessel name, call sign, ship type, IMO. These arrive in *separate* messages,
//!    so the connector keeps a small per-MMSI identity cache and enriches each
//!    position report with the latest known identity for that vessel.
//!
//! All field offsets below are verified against the `pyais` reference decoder.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

/// 1 knot in metres/second. The governed `speed` attribute is m/s; AIS speed over
/// ground is knots, so normalise (ADR-0019) and keep the native knots in metadata.
const KNOTS_TO_MPS: f64 = 0.514_444;

/// Why an AIS sentence could not be turned into a position. Counted and logged
/// with the reason; never silently swallowed.
#[derive(Debug, PartialEq, Eq)]
pub enum AisError {
    /// The frame was not valid ASCII/UTF-8.
    NotAscii,
    /// Not an NMEA sentence (no `!`/`$` talker).
    NotNmea,
    /// The NMEA checksum was missing or did not match.
    Checksum,
    /// The sentence did not have the expected comma-separated fields.
    Fields,
    /// The 6-bit payload contained a character outside the armor alphabet.
    Armor(u8),
    /// The payload was too short for the fields the message type requires.
    Truncated,
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for AisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AisError::NotAscii => write!(f, "AIS frame not ASCII"),
            AisError::NotNmea => write!(f, "not an NMEA sentence"),
            AisError::Checksum => write!(f, "NMEA checksum missing or mismatched"),
            AisError::Fields => write!(f, "malformed AIVDM fields"),
            AisError::Armor(c) => write!(f, "bad 6-bit armor character {c:#04x}"),
            AisError::Truncated => write!(f, "AIS payload too short for message type"),
            AisError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for AisError {}

/// A decoded AIS position report enriched with the vessel's known identity — the
/// wire facts plus cache, no clock. Deterministic given the same inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct AisPosition {
    pub msg_type: u8,
    pub mmsi: u32,
    /// WGS-84 latitude, if the report carried a valid one.
    pub lat: Option<f64>,
    /// WGS-84 longitude, if valid.
    pub lon: Option<f64>,
    /// Course over ground, degrees.
    pub cog: Option<f64>,
    /// Speed over ground, knots.
    pub sog: Option<f64>,
    /// True heading, degrees.
    pub heading: Option<f64>,
    /// Rate of turn, degrees/minute (positive = turning right).
    pub rot: Option<f64>,
    /// Navigation status (under way, at anchor, fishing, …).
    pub nav_status: Option<&'static str>,
    /// Ship-type category (cargo, tanker, fishing, military, …).
    pub ship_type: Option<&'static str>,
    /// Vessel name, from static data.
    pub name: Option<String>,
    /// Call sign, from static data.
    pub callsign: Option<String>,
    /// IMO number, from static data.
    pub imo: Option<u32>,
    /// Every raw NMEA sentence that contributed to this event — the position
    /// sentence(s) plus any static/unmapped sentences for this MMSI that arrived
    /// since the last emit — newline-delimited, carried verbatim into the signed
    /// `payload` so nothing (including fields we do not yet decode) is lost.
    pub raw: Vec<u8>,
    /// True if the per-MMSI carry-forward buffer dropped one or more sentences
    /// before this emit (over the cap); the event marks itself `payload_truncated`.
    pub truncated: bool,
}

/// The identity a vessel advertises in its static messages, cached by MMSI.
#[derive(Debug, Clone, Default, PartialEq)]
struct Identity {
    name: Option<String>,
    callsign: Option<String>,
    ship_type: Option<&'static str>,
    imo: Option<u32>,
}

/// Upper bound on cached vessel identities. A dense coastal picture is a few
/// thousand vessels; the bound exists because MMSI is attacker-controllable — a
/// hostile feed spoofing millions of MMSIs must cost bounded memory. At capacity
/// the oldest-inserted identity is evicted (FIFO); a live vessel's next static
/// message simply re-caches it.
const MAX_IDENTITIES: usize = 10_000;

/// A bounded MMSI → [`Identity`] cache with FIFO eviction.
#[derive(Default)]
struct IdentityCache {
    map: HashMap<u32, Identity>,
    order: std::collections::VecDeque<u32>,
}

impl IdentityCache {
    fn get(&self, mmsi: u32) -> Option<&Identity> {
        self.map.get(&mmsi)
    }

    /// The entry for `mmsi`, inserting (and evicting the oldest, if at capacity)
    /// when new.
    fn entry(&mut self, mmsi: u32) -> &mut Identity {
        if !self.map.contains_key(&mmsi) {
            while self.map.len() >= MAX_IDENTITIES {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.map.remove(&oldest);
                    }
                    None => break, // order drifted; never spin
                }
            }
            self.order.push_back(mmsi);
        }
        self.map.entry(mmsi).or_default()
    }
}

/// Per-MMSI cap on raw NMEA sentences carried forward before the next emit, and
/// on their total bytes. A feed streaming static/unmapped sentences for a vessel
/// that never reports a position must cost bounded memory: past the cap the oldest
/// pending sentence is dropped (with a warning), never the whole event.
const MAX_PENDING_FRAMES: usize = 64;
const MAX_PENDING_BYTES: usize = 16 * 1024;

/// One vessel's raw sentences received since its last emitted event — static
/// (types 5/24) and unmapped messages carried forward so their bytes reach the
/// signed payload of the next position for that MMSI.
#[derive(Default)]
struct Carry {
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    /// Set when a pending sentence was dropped over the cap since the last emit;
    /// cleared on drain. Drives the event's `payload_truncated` marker.
    dropped_since_emit: bool,
}

impl Carry {
    /// Remember one raw sentence, dropping the oldest pending sentence(s) past the
    /// cap. Returns how many were dropped (for the metric).
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
}

/// A bounded MMSI → [`Carry`] cache with FIFO eviction of whole vessels. Bounded
/// for the same reason as the identity cache: MMSI is attacker-controllable.
#[derive(Default)]
struct CarryCache {
    map: HashMap<u32, Carry>,
    order: VecDeque<u32>,
}

impl CarryCache {
    /// The carry buffer for `mmsi`, creating it (and evicting the oldest vessel if
    /// at capacity) on first sight.
    fn entry(&mut self, mmsi: u32) -> &mut Carry {
        if !self.map.contains_key(&mmsi) {
            if self.order.len() >= MAX_IDENTITIES {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.order.push_back(mmsi);
        }
        self.map.entry(mmsi).or_default()
    }
}

/// Reassembly key for a multi-fragment sentence.
///
/// The AIS sequential message id (`seq`) is only 0–9 and is chosen per-transmitter,
/// so it is **not** unique across vessels. Keying reassembly on `seq` alone lets an
/// interleaved multipart message from another vessel splice its fragment into this
/// one's payload — which, once the raw is sealed into a signed event, means another
/// vessel's bytes in a provenance record. We therefore key on the talker/formatter
/// (`fields[0]`, distinguishes receivers) and the radio channel (`fields[4]`) as
/// well. This removes cross-receiver and cross-channel collisions; the residual —
/// two vessels on the same receiver *and* channel that pick the same `seq` within
/// the reassembly window — is inherent to AIS (fragments carry no vessel id) and is
/// bounded by the TTL sweep below.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ReasmKey {
    talker: String,
    channel: String,
    seq: u8,
}

/// How long a partial reassembly may sit before it is discarded. AIS fragments of
/// one message arrive milliseconds apart, so anything older is an orphan (a lost
/// fragment); dropping it stops a much-later, unrelated fragment from completing
/// it. Deterministic decode is unaffected — only orphan eviction is time-based.
const REASM_TTL: Duration = Duration::from_secs(10);

/// One in-progress multi-fragment sentence.
struct Pending {
    total: u8,
    next: u8,
    payload: String,
    /// The raw sentence bytes of each fragment seen so far, so every contributing
    /// fragment reaches the payload once the message is reassembled and routed.
    raws: Vec<Vec<u8>>,
    /// When the first fragment arrived — drives the TTL sweep.
    first_seen: Instant,
}

/// Normalizes AIS for one connector identity. Holds the fragment-reassembly buffer
/// and the per-MMSI identity cache; a `Mutex` because the [`FrameParser`] contract
/// is `&self` and the single-consumer loop never contends them.
pub struct AisParser {
    source_id: String,
    enrichment: Enrichment,
    pending: Mutex<HashMap<ReasmKey, Pending>>,
    identities: Mutex<IdentityCache>,
    /// Per-MMSI raw sentences awaiting the vessel's next position emit.
    carry: Mutex<CarryCache>,
    /// Carry-forward sentences dropped over the per-MMSI cap, since start.
    dropped: Arc<AtomicU64>,
}

impl AisParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            pending: Mutex::new(HashMap::new()),
            identities: Mutex::new(IdentityCache::default()),
            carry: Mutex::new(CarryCache::default()),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Parse one NMEA sentence. Returns an enriched position for a position report;
    /// `Ok(None)` for a static message (which updates the identity cache), an
    /// unmapped type, or a buffered fragment.
    pub fn parse_sentence(&self, frame: &[u8]) -> Result<Option<AisPosition>, AisError> {
        let s = std::str::from_utf8(frame).map_err(|_| AisError::NotAscii)?;
        let s = s.trim();
        if !(s.starts_with('!') || s.starts_with('$')) {
            return Err(AisError::NotNmea);
        }
        verify_checksum(s)?;
        // The verbatim (whitespace-trimmed) sentence, carried into the payload of
        // whatever position event this message contributes to.
        let raw = s.as_bytes().to_vec();

        let star = s.find('*').unwrap_or(s.len());
        let fields: Vec<&str> = s[1..star].split(',').collect();
        if fields.len() < 7 {
            return Err(AisError::Fields);
        }
        if !(fields[0].ends_with("VDM") || fields[0].ends_with("VDO")) {
            return Ok(None); // an NMEA sentence, just not AIS
        }
        let frag_count: u8 = fields[1].parse().map_err(|_| AisError::Fields)?;
        let frag_num: u8 = fields[2].parse().map_err(|_| AisError::Fields)?;
        let seq: u8 = fields[3].parse().unwrap_or(0);
        let payload = fields[5];
        let fill: u8 = fields[6].parse().unwrap_or(0);
        if frag_count == 0 || frag_num == 0 || frag_num > frag_count {
            return Err(AisError::Fields);
        }

        if frag_count == 1 {
            let bits = Bits::from_payload(payload, fill)?;
            return self.decode(&bits, vec![raw]);
        }

        // Multi-fragment: accumulate in order, decode when the last arrives. The
        // fill bits belong to the final fragment. Keyed on (talker, channel, seq)
        // so an interleaved multipart message from another vessel cannot splice its
        // fragment into this one's (and thus into a signed payload).
        let key = ReasmKey {
            talker: fields[0].to_string(),
            channel: fields[4].to_string(),
            seq,
        };
        let now = Instant::now();
        let mut pending = self.pending.lock().expect("reassembly mutex");
        // Discard orphaned partials so a lost fragment can never be completed later
        // by an unrelated vessel that reuses the same key. This also bounds memory.
        pending.retain(|_, p| now.duration_since(p.first_seen) < REASM_TTL);
        if frag_num == 1 {
            pending.insert(
                key.clone(),
                Pending {
                    total: frag_count,
                    next: 1,
                    payload: String::new(),
                    raws: Vec::new(),
                    first_seen: now,
                },
            );
        }
        let done = {
            let entry = match pending.get_mut(&key) {
                Some(e) if e.total == frag_count && e.next == frag_num => e,
                _ => {
                    pending.remove(&key);
                    return Ok(None);
                }
            };
            entry.payload.push_str(payload);
            entry.raws.push(raw);
            entry.next += 1;
            frag_num == frag_count
        };
        if done {
            let full = pending.remove(&key).expect("entry present");
            drop(pending);
            let bits = Bits::from_payload(&full.payload, fill)?;
            return self.decode(&bits, full.raws);
        }
        Ok(None)
    }

    fn decode(&self, bits: &Bits, raws: Vec<Vec<u8>>) -> Result<Option<AisPosition>, AisError> {
        if bits.total() < 38 {
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
            _ => None, // a valid AIS message, just not one we map
        };

        match layout {
            Some(layout) => {
                // A position emits: drain every sentence carried for this MMSI
                // since its last emit and append this message's own sentence(s),
                // so the signed payload holds all contributing frames verbatim.
                let mut pos = self.position(bits, msg_type, mmsi, layout);
                let (raw, truncated) = self.carry_drain(mmsi, raws);
                pos.raw = raw;
                pos.truncated = truncated;
                Ok(Some(pos))
            }
            // Static/unmapped: no event, but carry the raw sentence(s) forward so
            // their bytes reach the next position event for this vessel.
            None => {
                self.carry_push(mmsi, &raws);
                Ok(None)
            }
        }
    }

    /// Buffer raw sentences for a vessel that produced no event, bounding the
    /// per-MMSI buffer and counting any dropped over the cap.
    fn carry_push(&self, mmsi: u32, raws: &[Vec<u8>]) {
        let mut cache = self.carry.lock().expect("carry mutex");
        let entry = cache.entry(mmsi);
        for raw in raws {
            let dropped = entry.push_raw(raw);
            if dropped > 0 {
                self.dropped.fetch_add(dropped, Ordering::Relaxed);
                tracing::warn!(dropped, mmsi, "ais: carry-forward buffer over cap");
            }
        }
    }

    /// Drain the carried sentences for `mmsi`, append this position's own
    /// sentence(s), and newline-join them into the payload (a re-parse splits on
    /// `\n`). Also reports whether any carried sentence was dropped over the cap.
    fn carry_drain(&self, mmsi: u32, position_raws: Vec<Vec<u8>>) -> (Vec<u8>, bool) {
        let mut cache = self.carry.lock().expect("carry mutex");
        let entry = cache.entry(mmsi);
        let mut frames: Vec<Vec<u8>> = entry.pending.drain(..).collect();
        entry.pending_bytes = 0;
        let truncated = std::mem::take(&mut entry.dropped_since_emit);
        frames.extend(position_raws);
        let mut out = Vec::new();
        for (i, f) in frames.iter().enumerate() {
            if i > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(f);
        }
        (out, truncated)
    }

    /// Decode a position report of the given layout and enrich it with the
    /// vessel's cached identity.
    fn position(&self, bits: &Bits, msg_type: u8, mmsi: u32, layout: Layout) -> AisPosition {
        let (sog_off, lon_off, lat_off, cog_off, hdg_off) = layout.offsets();

        // Class A carries navigation status and rate of turn; class B does not.
        let (nav_status, rot) = match layout {
            ClassA => (
                bits.opt_u(38, 4).and_then(nav_status),
                bits.opt_i(42, 8).and_then(decode_rot),
            ),
            ClassB { .. } => (None, None),
        };

        let mut pos = AisPosition {
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
            sog: bits
                .opt_u(sog_off, 10)
                .filter(|&v| v != 1023)
                .map(|v| v as f64 / 10.0),
            cog: bits
                .opt_u(cog_off, 12)
                .filter(|&v| v != 3600)
                .map(|v| v as f64 / 10.0),
            heading: bits
                .opt_u(hdg_off, 9)
                .filter(|&v| v != 511)
                .map(|v| v as f64),
            rot,
            nav_status,
            ship_type: None,
            name: None,
            callsign: None,
            imo: None,
            // Filled by `decode` once the carry-forward buffer is drained.
            raw: Vec::new(),
            truncated: false,
        };

        // Type 19 carries identity inline; fold it into the cache too.
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
            .cloned();
        if let Some(id) = id {
            pos.name = id.name;
            pos.callsign = id.callsign;
            pos.ship_type = id.ship_type;
            pos.imo = id.imo;
        }
        pos
    }

    /// Type 5: class A static and voyage data (IMO, call sign, name, ship type).
    fn static_class_a(&self, bits: &Bits, mmsi: u32) {
        let imo = bits.opt_u(40, 30).map(|v| v as u32).filter(|&v| v != 0);
        let callsign = bits.opt_text(70, 42);
        let name = bits.opt_text(112, 120);
        let ship_type = bits.opt_u(232, 8).and_then(|c| ship_type(c as u8));
        self.merge_identity(mmsi, name, callsign, ship_type, imo);
    }

    /// Type 24: class B static, in two parts — A carries the name, B the ship type
    /// and call sign.
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

    /// Merge newly-seen identity fields into the cache (never overwrite a known
    /// field with an empty one).
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
        if let Some(v) = name {
            if !v.is_empty() {
                e.name = Some(v);
            }
        }
        if let Some(v) = callsign {
            if !v.is_empty() {
                e.callsign = Some(v);
            }
        }
        if ship_type.is_some() {
            e.ship_type = ship_type;
        }
        if imo.is_some() {
            e.imo = imo;
        }
    }

    fn base_builder(&self, p: &AisPosition) -> EventBuilder {
        // Every raw sentence that produced this event is preserved verbatim in the
        // signed payload (newline-delimited) — nothing the parser does not yet map
        // is lost. MMSI is the stable identity (source_uid = track key; `mmsi` =
        // native); IMO stays a native identifier in metadata.
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:vessel")
            .new_id()
            .payload(p.raw.clone())
            .metadata("source_uid", p.mmsi.to_string())
            .metadata("mmsi", p.mmsi.to_string())
            // MMSI is the vessel's stable track key — the governed correlation key a
            // consumer keys on (`track_id`), not just provenance metadata.
            .attribute("track_id", p.mmsi.to_string());
        if let (Some(lat), Some(lon)) = (p.lat, p.lon) {
            b = b.location(lat, lon, 0.0);
        }
        if let Some(imo) = p.imo {
            b = b.metadata("imo", imo.to_string());
        }

        // If the carry-forward buffer dropped sentences, the payload is incomplete
        // — say so, so a re-parser never mistakes it for the full set of frames.
        if p.truncated {
            b = b.metadata("payload_truncated", "true");
        }

        // Parse every field into attributes; Core auto-demotes undeclared keys.
        // Affiliation is only ever the operator's explicit assertion — never a
        // connector-invented default (AIS carries none of its own).
        if let Some(aff) = self.enrichment.affiliation.as_deref() {
            b = b.attribute("affiliation", aff);
        }
        // Governed `speed` is m/s; keep the native knots in metadata (ADR-0019).
        if let Some(kn) = p.sog {
            b = b.attribute("speed", format!("{:.2}", kn * KNOTS_TO_MPS));
            b = b.metadata("speed_kn", format!("{kn:.1}"));
        }
        // course (track over ground) and heading (where the bow points) are
        // distinct — do not cross them.
        if let Some(cog) = p.cog {
            b = b.attribute("course", format!("{cog:.1}")); // degrees
        }
        if let Some(h) = p.heading {
            b = b.attribute("heading", format!("{h:.0}")); // degrees true
        }
        if let Some(rot) = p.rot {
            b = b.attribute("rate_of_turn", format!("{rot:.1}")); // deg/min
        }
        if let Some(ns) = p.nav_status {
            b = b.attribute("nav_status", ns);
        }
        if let Some(vt) = p.ship_type {
            b = b.attribute("vessel_type", vt);
        }
        if let Some(name) = &p.name {
            b = b.attribute("vessel_name", name.clone());
        }
        if let Some(cs) = &p.callsign {
            b = b.attribute("callsign", cs.clone());
        }
        b
    }

    /// Build a canonical event with an explicit observation timestamp (tests pin
    /// this path for determinism).
    pub fn to_event_at(&self, p: &AisPosition, observed: &str) -> Result<Event, AisError> {
        self.base_builder(p)
            .timestamp(observed)
            .build()
            .map_err(|e| AisError::Build(e.to_string()))
    }

    /// Build a canonical event stamped with receipt time — AIS position reports
    /// carry no absolute timestamp, so observation time is when we saw it.
    fn to_event_now(&self, p: &AisPosition) -> Result<Event, AisError> {
        self.base_builder(p)
            .now()
            .build()
            .map_err(|e| AisError::Build(e.to_string()))
    }
}

impl FrameParser for AisParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        match self.parse_sentence(frame).map_err(box_err)? {
            Some(pos) => Ok(vec![self.to_event_now(&pos).map_err(box_err)?]),
            None => Ok(Vec::new()),
        }
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        vec![("connector_dropped_carryforward_total", self.dropped.clone())]
    }
}

fn box_err(e: AisError) -> ParseError {
    Box::new(e) as ParseError
}

/// Position-report field layout: class A (types 1/2/3) and class B (18/19) place
/// speed/lon/lat/course/heading at different bit offsets.
#[derive(Clone, Copy, PartialEq)]
enum Layout {
    ClassA,
    ClassB { extended: bool },
}
use Layout::{ClassA, ClassB};

impl Layout {
    /// `(sog, lon, lat, cog, heading)` bit offsets.
    fn offsets(self) -> (usize, usize, usize, usize, usize) {
        match self {
            ClassA => (50, 61, 89, 116, 128),
            ClassB { .. } => (46, 57, 85, 112, 124),
        }
    }
}

/// AIS navigation status (ITU-R M.1371 table). 15 (undefined) → `None`.
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

/// Ship-type code (0–99) → operational category. 0 / unknown → `None`.
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

/// Decode the AIS rate-of-turn indicator to degrees/minute. `-128` (not
/// available) and out-of-range values → `None`.
fn decode_rot(raw: i64) -> Option<f64> {
    if raw <= -128 || raw > 127 {
        return None;
    }
    let s = raw as f64 / 4.733;
    Some((s * s) * (raw.signum() as f64))
}

/// Verify the trailing `*HH` NMEA checksum: XOR of every byte between the `!`/`$`
/// talker and the `*`.
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

/// The AIS 6-bit character set (value 0–63), used for names, call signs, etc.
const SIXBIT_ASCII: &[u8; 64] =
    b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?";

/// A view over the 6-bit-armored payload, indexable by absolute bit position
/// (MSB-first within each 6-bit group).
struct Bits {
    six: Vec<u8>,
    valid_bits: usize,
}

impl Bits {
    fn from_payload(payload: &str, fill: u8) -> Result<Bits, AisError> {
        let mut six = Vec::with_capacity(payload.len());
        for c in payload.bytes() {
            let mut v = c as i16 - 48;
            if v > 40 {
                v -= 8;
            }
            if !(0..=63).contains(&v) {
                return Err(AisError::Armor(c));
            }
            six.push(v as u8);
        }
        let valid_bits = (six.len() * 6).saturating_sub(fill as usize);
        Ok(Bits { six, valid_bits })
    }

    fn total(&self) -> usize {
        self.valid_bits
    }

    fn u(&self, start: usize, n: usize) -> u64 {
        let mut val = 0u64;
        for i in 0..n {
            let bit = start + i;
            let b = (self.six[bit / 6] >> (5 - (bit % 6))) & 1;
            val = (val << 1) | b as u64;
        }
        val
    }

    fn i(&self, start: usize, n: usize) -> i64 {
        let u = self.u(start, n);
        if u & (1 << (n - 1)) != 0 {
            u as i64 - (1i64 << n)
        } else {
            u as i64
        }
    }

    /// Read `n` bits as unsigned, or `None` if they run past the valid payload.
    fn opt_u(&self, start: usize, n: usize) -> Option<u64> {
        (start + n <= self.valid_bits).then(|| self.u(start, n))
    }

    /// Read `n` bits as signed, or `None` if they run past the valid payload.
    fn opt_i(&self, start: usize, n: usize) -> Option<i64> {
        (start + n <= self.valid_bits).then(|| self.i(start, n))
    }

    /// Read a `bits`-long 6-bit ASCII string, trimmed of `@` padding and
    /// whitespace. `None` if it runs past the payload or is empty.
    fn opt_text(&self, start: usize, bits: usize) -> Option<String> {
        if start + bits > self.valid_bits {
            return None;
        }
        let mut s = String::with_capacity(bits / 6);
        for i in 0..(bits / 6) {
            let v = self.u(start + i * 6, 6) as usize;
            s.push(SIXBIT_ASCII[v] as char);
        }
        let s = s.trim_end_matches('@').trim().to_string();
        (!s.is_empty()).then_some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real, pyais-verified sentences (see the connector's verification notes):
    // type 1, MMSI 227006760, 49.475577 N 0.131380 E, COG 36.7, nav under-way.
    const T1: &[u8] = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*23";
    // type 5 static for MMSI 603916439: IMO 439303422, callsign ZA83R, name
    // ARCO AVON, ship type 69 (passenger). Regenerated with pyais (valid checksums).
    const T5A: &[u8] =
        b"!AIVDO,2,1,0,A,58wt8Ui`g??q`7S=80058<v05Htp00000000001500000000000000000000,0*60";
    const T5B: &[u8] = b"!AIVDO,2,2,0,A,00000000000,2*26";
    // type 1 position for the SAME MMSI 603916439 (SOG 10.0, COG 90, hdg 90).
    const POS_ARCO: &[u8] = b"!AIVDO,1,1,,A,18wt8UhP1T04Tv0LW3P3Q2l1P000,0*1D";

    fn parser() -> AisParser {
        AisParser::new("ais-coast-1", Enrichment::default())
    }

    /// A parser with an operator-asserted affiliation (own the COP's neutral fill).
    fn configured() -> AisParser {
        AisParser::new(
            "ais-coast-1",
            Enrichment::default().with_affiliation("neutral"),
        )
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
    fn decodes_position_and_kinematics() {
        let p = parser().parse_sentence(T1).unwrap().unwrap();
        assert_eq!(p.mmsi, 227006760);
        assert!((p.lat.unwrap() - 49.475577).abs() < 1e-5);
        assert!((p.cog.unwrap() - 36.7).abs() < 1e-6);
        assert_eq!(p.sog, Some(0.0));
        assert_eq!(p.nav_status, Some("under-way-using-engine"));
        assert_eq!(p.heading, None); // 511 = not available
        assert_eq!(p.rot, None); // -128 = not available
    }

    #[test]
    fn static_data_correlates_into_later_positions() {
        let p = parser();
        // Static message arrives first (two fragments) — no event, cached.
        assert_eq!(p.parse_sentence(T5A).unwrap(), None);
        assert_eq!(p.parse_sentence(T5B).unwrap(), None);
        // A later position for the same MMSI is enriched with the identity.
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert_eq!(pos.mmsi, 603916439);
        assert_eq!(pos.name.as_deref(), Some("ARCO AVON"));
        assert_eq!(pos.callsign.as_deref(), Some("ZA83R"));
        assert_eq!(pos.ship_type, Some("passenger"));
        assert_eq!(pos.imo, Some(439303422));
        assert!((pos.sog.unwrap() - 10.0).abs() < 1e-6);
    }

    /// Append the correct NMEA `*HH` checksum to a sentence body (for crafting
    /// interleaving fixtures).
    fn with_checksum(body: &str) -> Vec<u8> {
        let cs = body[1..].bytes().fold(0u8, |a, b| a ^ b);
        format!("{body}*{cs:02X}").into_bytes()
    }

    #[test]
    fn interleaved_multipart_on_same_seq_do_not_contaminate() {
        // MMSI 603916439's type-5 static arrives as two fragments on channel A,
        // seq 0. Between them, an UNRELATED multipart from another transmission
        // arrives with the SAME seq 0 but on channel B. Keyed on seq alone, the
        // decoy would overwrite the partial and be completed by T5B, splicing the
        // wrong bytes into the reassembly (and, post-payload, into a signed event).
        // Keyed on (talker, channel, seq) the two stay separate.
        let p = parser();
        let decoy = with_checksum("!AIVDO,2,1,0,B,1234567890,0");
        assert_eq!(p.parse_sentence(T5A).unwrap(), None); // A frag 1/2 -> key (AIVDO,A,0)
        assert_eq!(p.parse_sentence(&decoy).unwrap(), None); // B frag 1/2 -> key (AIVDO,B,0)
        assert_eq!(p.parse_sentence(T5B).unwrap(), None); // A frag 2/2 -> completes T5A
                                                          // The static identity for 603916439 was reassembled correctly (not spliced
                                                          // from the decoy), so a later position for that MMSI is enriched as expected.
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert_eq!(pos.mmsi, 603916439);
        assert_eq!(pos.name.as_deref(), Some("ARCO AVON"));
        assert_eq!(pos.callsign.as_deref(), Some("ZA83R"));
    }

    #[test]
    fn event_carries_canonical_attributes_and_native_units() {
        let p = configured();
        p.parse_sentence(T5A).unwrap();
        p.parse_sentence(T5B).unwrap();
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "affiliation"), Some("neutral"));
        // Governed `speed` is m/s (10 kn * 0.514444); native knots kept in metadata.
        assert_eq!(attr_of(&ev, "speed"), Some("5.14"));
        assert_eq!(meta_of(&ev, "speed_kn"), Some("10.0"));
        assert_eq!(attr_of(&ev, "vessel_name"), Some("ARCO AVON"));
        assert_eq!(attr_of(&ev, "vessel_type"), Some("passenger"));
        // MMSI is the stable track identity (source_uid) and native id; IMO native.
        assert_eq!(meta_of(&ev, "source_uid"), Some("603916439"));
        assert_eq!(attr_of(&ev, "track_id"), Some("603916439")); // governed correlation key
        assert_eq!(meta_of(&ev, "mmsi"), Some("603916439"));
        assert!(ev.metadata.iter().any(|m| m.key == "imo"));
    }

    #[test]
    fn absent_affiliation_is_not_invented_and_raw_is_preserved() {
        // Default mode: no operator affiliation -> none is invented (absent stays
        // absent), and the raw sentence is preserved verbatim in the signed payload.
        let p = parser();
        let pos = p.parse_sentence(T1).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert!(!ev.attributes.iter().any(|a| a.key == "affiliation"));
        assert!(!ev.metadata.iter().any(|m| m.key == "affiliation"));
        assert_eq!(ev.payload.as_slice(), T1);
    }

    #[test]
    fn carries_static_frames_forward_into_payload() {
        // The two static fragments (types 5) do not emit; their raw must ride into
        // the next position event's payload, newline-joined with the position line.
        let p = configured();
        assert_eq!(p.parse_sentence(T5A).unwrap(), None);
        assert_eq!(p.parse_sentence(T5B).unwrap(), None);
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert!(!pos.truncated);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        let t5a = std::str::from_utf8(T5A).unwrap();
        let t5b = std::str::from_utf8(T5B).unwrap();
        let arco = std::str::from_utf8(POS_ARCO).unwrap();
        assert_eq!(
            ev.payload.as_slice(),
            format!("{t5a}\n{t5b}\n{arco}").as_bytes()
        );
        // Attached once: the NEXT position for this MMSI carries only its own line.
        let pos2 = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        let ev2 = p.to_event_at(&pos2, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev2.payload.as_slice(), POS_ARCO);
    }

    #[test]
    fn over_cap_drops_oldest_and_marks_payload_truncated() {
        // Flood one MMSI's carry buffer with complete static messages (2 raws each)
        // past the frame cap, then emit a position for that MMSI.
        let p = configured();
        for _ in 0..(MAX_PENDING_FRAMES) {
            p.parse_sentence(T5A).unwrap();
            p.parse_sentence(T5B).unwrap(); // completes -> carries T5A,T5B (2 raws)
        }
        let pos = p.parse_sentence(POS_ARCO).unwrap().unwrap();
        assert!(pos.truncated);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(meta_of(&ev, "payload_truncated"), Some("true"));
        assert!(p.counters()[0].1.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn type24_provides_a_name() {
        let p = parser();
        // Part A carries the name for MMSI 271041815 ("PROGUY").
        assert_eq!(
            p.parse_sentence(b"!AIVDO,1,1,,A,H42O55i18tMET000000000000000,0*5D")
                .unwrap(),
            None
        );
        assert_eq!(
            p.identities
                .lock()
                .unwrap()
                .get(271041815)
                .unwrap()
                .name
                .as_deref(),
            Some("PROGUY")
        );
    }

    #[test]
    fn identity_cache_is_bounded_with_fifo_eviction() {
        let mut cache = IdentityCache::default();
        for mmsi in 0..(MAX_IDENTITIES as u32 + 100) {
            cache.entry(mmsi).name = Some(format!("V{mmsi}"));
        }
        assert_eq!(cache.map.len(), MAX_IDENTITIES, "cache must stay bounded");
        assert!(cache.get(0).is_none(), "oldest entries evicted first");
        assert!(
            cache.get(MAX_IDENTITIES as u32 + 99).is_some(),
            "newest kept"
        );
        // Re-touching an existing key must not grow the cache or duplicate order.
        cache.entry(MAX_IDENTITIES as u32 + 99).imo = Some(1);
        assert_eq!(cache.map.len(), MAX_IDENTITIES);
        assert_eq!(cache.order.len(), MAX_IDENTITIES);
    }

    #[test]
    fn wrong_checksum_is_rejected() {
        let bad = b"!AIVDM,1,1,,A,13HOI:0P0000VOHLCnHQKwvL05Ip,0*24";
        assert_eq!(parser().parse_sentence(bad), Err(AisError::Checksum));
    }

    #[test]
    fn non_ais_talker_is_ignored_not_errored() {
        let gga = b"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47";
        assert_eq!(parser().parse_sentence(gga).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics_and_is_rejected() {
        assert!(parser().parse_sentence(b"\xff\x00not nmea").is_err());
    }
}
