// SPDX-License-Identifier: Apache-2.0
//! STANAG 4676 (NATO ISR Tracking Standard, AEDP-12 Edition B) XML -> canonical
//! Ajar events.
//!
//! 4676 is the **fused track layer** above raw GMTI/ISR detections: a tracker
//! associates observations over time into tracks with a stable identity, so this
//! connector complements the [`ajar-gmti`] dot feed with the recognised ground/air
//! track. One `nitsRoot` message carries many tracks, each with many track points,
//! so one frame produces many sealed events — one per track point.
//!
//! This is an untrusted edge: field XML can be malformed, truncated, prefixed with
//! any namespace binding, or hostile. Parsing uses a real streaming XML reader,
//! matches purely on **local element names** (never a literal prefix), bounds every
//! numeric conversion, and never panics or fabricates a field. The canonical
//! invariants then hold by construction via [`EventBuilder`].
//!
//! ## What a track point carries, and the traps
//!
//! There are no `latitude`/`longitude`/`speed`/`heading` elements. The load-bearing
//! facts are packed unusually and are exactly what a naive decoder gets wrong:
//!
//! * **Stable id** — `track/uid` is Base64 of a raw 16-byte UUID, not a hyphenated
//!   string. Decoded and formatted, it becomes `source_uid`.
//! * **Position/velocity** — space-separated numeric lists in `<pos>`/`<vel>` under
//!   `<dynamics>`, in the coordinate system named by the `cs` attribute. For
//!   `cs="WGS_84"` that is `lat lon ellipsoid-height-m`, and the velocity horizontal
//!   components are **degrees/second**, not m/s.
//! * **Time** — reconstructed as `message/baseTime + relTime * relTimeIncrement`;
//!   there is no ISO timestamp on the point.
//! * **Status** — lives on the enclosing `segment`, mapped to new/update/coast/drop.
//! * **Identity** — `track/object/id1241`, drawn from STANAG 1241.
//!
//! [`ajar-gmti`]: https://github.com/promaka/ajar-connectors

use std::collections::HashMap;

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// Mean Earth radius (metres) — used to convert WGS-84 angular velocity (°/s) into
/// a ground speed and course. A spherical model is ample for a velocity direction
/// and magnitude; the native components are preserved in metadata regardless.
const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// Why a 4676 message could not be normalized. Dropped frames are counted and
/// logged with the reason by the shared runtime — never silently swallowed.
#[derive(Debug, PartialEq, Eq)]
pub enum S4676Error {
    /// The bytes were not well-formed XML.
    Xml(String),
    /// A track point built no valid canonical event (a propagated invariant
    /// violation from [`EventBuilder::build`]).
    Build(String),
}

impl std::fmt::Display for S4676Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S4676Error::Xml(e) => write!(f, "malformed STANAG 4676 XML: {e}"),
            S4676Error::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for S4676Error {}

/// Normalizes STANAG 4676 for one connector identity, with optional
/// environment -> entity-type overrides and a default hostility.
pub struct S4676Parser {
    source_id: String,
    /// `environment` value (e.g. `AIR`) -> Ajar entity type, from config
    /// `[entity_map]`; overrides the built-in mapping.
    overrides: HashMap<String, String>,
    enrichment: Enrichment,
}

/// The per-track point facts accumulated while streaming; flushed to an event when
/// the enclosing `<track>` closes (identity/`object` follows the points in document
/// order, so a point cannot be emitted until its track is fully read).
#[derive(Default)]
struct PointCtx {
    rel_time: Option<i64>,
    status: Option<String>,
    cs: Option<String>,
    pos: Option<Vec<f64>>,
    vel: Option<Vec<f64>>,
}

/// The per-track facts accumulated while streaming its segments and object.
#[derive(Default)]
struct TrackCtx {
    uid: Option<String>,
    identity: Option<String>,
    environment: Option<String>,
    object_class: Option<String>,
    points: Vec<PointCtx>,
    /// Byte offset of this `<track>`'s start tag in the source, to seal the raw
    /// track element verbatim into each of its events' payloads.
    start: usize,
}

impl S4676Parser {
    /// Build a parser for one connector identity. `overrides` maps a 4676
    /// `environment` to an Ajar entity type; `enrichment` supplies the default
    /// hostility for points whose identity is absent or unrecognised.
    pub fn new(
        source_id: impl Into<String>,
        overrides: HashMap<String, String>,
        enrichment: Enrichment,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            overrides,
            enrichment,
        }
    }

    /// Parse one `nitsRoot` message into a canonical event per track point. A
    /// well-formed message with no tracks (e.g. a detection-only or empty message)
    /// yields an empty vec, which the runtime treats as "nothing to publish", not an
    /// error.
    pub fn to_events(&self, native: &[u8]) -> Result<Vec<Event>, S4676Error> {
        let mut reader = Reader::from_reader(native);
        let mut buf = Vec::new();
        let mut stack: Vec<String> = Vec::new();

        // Message-level context, set once and applied to every event.
        let mut base_time: Option<String> = None;
        let mut rel_increment: Option<f64> = None;
        let mut nits_version: Option<String> = None;
        let mut classification: Option<String> = None;

        // Rolling context.
        let mut track = TrackCtx::default();
        let mut in_track = false;
        let mut seg_status: Option<String> = None;
        let mut tp = PointCtx::default();
        let mut cur_cs: Option<String> = None;

        let mut events = Vec::new();

        loop {
            let pos_before = reader.buffer_position() as usize;
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(e)) => {
                    let ln = local(e.name().as_ref()).to_string();
                    match ln.as_str() {
                        "track" => {
                            track = TrackCtx {
                                start: pos_before,
                                ..Default::default()
                            };
                            in_track = true;
                        }
                        "dynamics" => cur_cs = read_attr(&e, "cs"),
                        _ => {}
                    }
                    stack.push(ln);
                }
                Ok(XmlEvent::Empty(e)) => {
                    // Self-closing element: attributes only, no text. The one we care
                    // about is a `cs`-bearing dynamics with an inline (rare) form; it
                    // still carries no position, so nothing to capture.
                    let _ = &e;
                }
                Ok(XmlEvent::End(e)) => {
                    let name = e.name();
                    let ln = local(name.as_ref());
                    match ln {
                        "tp" => {
                            track.points.push(PointCtx {
                                status: seg_status.clone(),
                                ..std::mem::take(&mut tp)
                            });
                        }
                        "dynamics" => cur_cs = None,
                        "segment" => seg_status = None,
                        "track" => {
                            let end = reader.buffer_position() as usize;
                            let raw = native.get(track.start..end).unwrap_or(native);
                            self.flush_track(
                                &track,
                                raw,
                                base_time.as_deref(),
                                rel_increment,
                                nits_version.as_deref(),
                                classification.as_deref(),
                                &mut events,
                            )?;
                            in_track = false;
                            track = TrackCtx::default();
                        }
                        _ => {}
                    }
                    stack.pop();
                }
                Ok(XmlEvent::Text(t)) => {
                    let text = t.xml10_content();
                    let text = text.trim();
                    if !text.is_empty() {
                        let cur = stack.last().map(String::as_str).unwrap_or("");
                        let parent = stack
                            .len()
                            .checked_sub(2)
                            .map(|i| stack[i].as_str())
                            .unwrap_or("");
                        route_text(
                            parent,
                            cur,
                            text,
                            in_track,
                            &cur_cs,
                            &mut base_time,
                            &mut rel_increment,
                            &mut nits_version,
                            &mut classification,
                            &mut seg_status,
                            &mut track,
                            &mut tp,
                        );
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => return Err(S4676Error::Xml(e.to_string())),
                _ => {}
            }
            buf.clear();
        }

        Ok(events)
    }

    /// Emit one event per buffered track point, applying the fully-read track and
    /// message context.
    #[allow(clippy::too_many_arguments)]
    fn flush_track(
        &self,
        track: &TrackCtx,
        raw: &[u8],
        base_time: Option<&str>,
        rel_increment: Option<f64>,
        nits_version: Option<&str>,
        classification: Option<&str>,
        out: &mut Vec<Event>,
    ) -> Result<(), S4676Error> {
        let source_uid = track.uid.clone();
        let entity = self.entity_type(track.environment.as_deref());
        let hostility = self.hostility(track.identity.as_deref());

        for p in &track.points {
            let mut b = EventBuilder::new(self.source_id.clone(), entity.clone())
                .new_id()
                .payload(raw.to_vec())
                .attribute("hostility", hostility.clone());

            match point_time(base_time, rel_increment, p.rel_time) {
                Some(ts) => b = b.timestamp(ts),
                None => b = b.now(),
            }
            if let Some(uid) = &source_uid {
                b = b.metadata("source_uid", uid.clone());
            }
            if let Some(cls) = classification {
                b = b.policy_tag(cls.to_string());
            }
            if let Some(v) = nits_version {
                b = b.metadata("nits_version", v.to_string());
            }
            if let Some(id) = &track.identity {
                b = b.metadata("identity", id.clone());
            }
            // Always emitted: an absent or unrecognised domain is UNKNOWN, which
            // is a value Core governs, rather than a missing attribute.
            let env_code = environment_code(track.environment.as_deref());
            b = b.attribute("environment", env_code);
            if env_code == "UNKNOWN" {
                if let Some(raw) = &track.environment {
                    if raw != "UNKNOWN" {
                        // A producer using a token outside STANAG 1241. Keep it so
                        // the oddity is visible rather than flattened away.
                        b = b.metadata("environment_source", raw.clone());
                    }
                }
            }
            if let Some(oc) = &track.object_class {
                b = b.attribute("object_class", oc.clone());
            }
            if let Some(st) = &p.status {
                b = b.attribute("track_status", normalize_status(st));
                b = b.metadata("s4676_status", st.clone());
            }
            if let Some(rt) = p.rel_time {
                b = b.metadata("rel_time", rt.to_string());
            }

            b = apply_kinematics(b, p);

            let ev = b.build().map_err(|e| S4676Error::Build(e.to_string()))?;
            out.push(ev);
        }
        Ok(())
    }

    /// Map a 4676 `environment` to an Ajar entity type. A config `[entity_map]`
    /// override wins; otherwise the standard domains map to governed types and
    /// anything else (including a missing environment) falls back to a vendor
    /// namespace, so nothing is silently dropped — Core's ontology decides what it
    /// then accepts.
    fn entity_type(&self, environment: Option<&str>) -> String {
        let env = environment.unwrap_or("");
        // A deployment that knows its feed better can still map an environment to
        // a specific type in `[entity_map]`.
        // Keyed on either the wire token or the normalised code, so an operator
        // writing SUBSURFACE or SUB-SURFACE both work.
        if let Some(mapped) = self
            .overrides
            .get(env)
            .or_else(|| self.overrides.get(environment_code(environment)))
        {
            return mapped.clone();
        }
        // Every value of `environment` is a domain, not a classification. AIR does
        // not mean aircraft: it can be a missile, a balloon or a bird, exactly as
        // LAND can be a person or a facility. Emitting a specific type here would
        // assert what the tracker never said, so the track is `mim:object` and the
        // domain rides alongside as an attribute.
        //
        // When the message carries `objectClass` — an APP-6 code, which genuinely
        // is a classification — that is the field a specific type should come
        // from. Mapping APP-6 onto MIM is its own piece of work.
        "mim:object".to_string()
    }

    /// Hostility from the STANAG 1241 identity.
    ///
    /// MIM 5.3 carries the same distinctions STANAG 1241 does, so the mapping is
    /// now one-to-one and nothing is discarded. Previously only FRIEND, HOSTILE
    /// and NEUTRAL had anywhere to go and ASSUMED_FRIEND and SUSPECT were flattened
    /// to unknown, which lost exactly the nuance an operator cares about.
    ///
    /// An absent or unrecognised identity falls back to the operator's configured
    /// default, and to `Unknown` if they set none: a connector does not invent a
    /// friend or a foe.
    fn hostility(&self, identity: Option<&str>) -> String {
        match identity {
            Some("FRIEND") => "Friend".to_string(),
            Some("ASSUMED_FRIEND") => "AssumedFriend".to_string(),
            Some("HOSTILE") => "Hostile".to_string(),
            Some("SUSPECT") => "Suspect".to_string(),
            Some("NEUTRAL") => "Neutral".to_string(),
            _ => self
                .enrichment
                .hostility
                .clone()
                .unwrap_or_else(|| "Unknown".to_string()),
        }
    }
}

/// Normalise a STANAG 1241 environment onto the closed set Core governs.
///
/// Core drives the CoT battle dimension from this attribute, so an AIR contact of
/// unknown type renders in the air dimension rather than as a bare unknown. That
/// only works while the value is inside the set: anything else is quarantined and
/// the track silently loses its dimension on the map.
///
/// Two reasons not to pass the wire value through. STANAG 1241 hyphenates
/// `SUB-SURFACE` where Core does not, and its enums are extensible, so a producer
/// may legitimately send a token no one has seen. Both normalise here.
///
/// `environment` is an Ajar extension rather than MIM vocabulary: MIM 5.3 has no
/// domain concept.
fn environment_code(raw: Option<&str>) -> &'static str {
    match raw.map(str::trim) {
        Some("AIR") => "AIR",
        Some("LAND") => "LAND",
        Some("SURFACE") => "SURFACE",
        Some("SUB-SURFACE" | "SUBSURFACE") => "SUBSURFACE",
        Some("SPACE") => "SPACE",
        _ => "UNKNOWN",
    }
}

/// Route an element's text into the right context slot, keyed on (parent, element)
/// local names so a value is never captured from the wrong nesting level (`uid`
/// appears under track, segment, and tp — only the track's is the stable id).
#[allow(clippy::too_many_arguments)]
fn route_text(
    parent: &str,
    cur: &str,
    text: &str,
    in_track: bool,
    cur_cs: &Option<String>,
    base_time: &mut Option<String>,
    rel_increment: &mut Option<f64>,
    nits_version: &mut Option<String>,
    classification: &mut Option<String>,
    seg_status: &mut Option<String>,
    track: &mut TrackCtx,
    tp: &mut PointCtx,
) {
    match (parent, cur) {
        ("nitsRoot", "nitsVersion") => *nits_version = Some(text.to_string()),
        ("message", "baseTime") => *base_time = Some(text.to_string()),
        ("message", "relTimeIncrement") => *rel_increment = text.parse().ok(),
        ("ConfidentialityInformation", "Classification") => {
            *classification = Some(text.to_string())
        }
        ("track", "uid") if in_track => {
            track.uid = decode_uid(text);
        }
        ("id1241", "identity") => track.identity = Some(text.to_string()),
        ("id1241", "environment") => track.environment = Some(text.to_string()),
        ("objectClass", "code") => track.object_class = Some(text.to_string()),
        ("segment", "status") => *seg_status = Some(text.to_string()),
        ("tp", "relTime") => tp.rel_time = text.parse().ok(),
        ("dynamics", "pos") => set_vector(&mut tp.pos, &mut tp.cs, cur_cs, text),
        ("dynamics", "vel") => {
            // Velocity shares the position's coordinate system; only record the cs
            // once (via pos), but keep the vector.
            if let Some(v) = parse_floats(text) {
                prefer_wgs(&mut tp.vel, tp.cs.as_deref(), cur_cs.as_deref(), v);
            }
        }
        _ => {}
    }
}

/// Store a position vector, preferring a WGS-84 `dynamics` block if a point carries
/// several coordinate representations (position first-seen otherwise).
fn set_vector(
    pos: &mut Option<Vec<f64>>,
    cs: &mut Option<String>,
    cur_cs: &Option<String>,
    text: &str,
) {
    let Some(v) = parse_floats(text) else { return };
    let is_wgs = cur_cs.as_deref() == Some("WGS_84");
    if pos.is_none() || (is_wgs && cs.as_deref() != Some("WGS_84")) {
        *pos = Some(v);
        *cs = cur_cs.clone();
    }
}

/// Prefer a WGS-84 velocity vector when several coordinate representations exist.
fn prefer_wgs(
    slot: &mut Option<Vec<f64>>,
    have_cs: Option<&str>,
    new_cs: Option<&str>,
    v: Vec<f64>,
) {
    let is_wgs = new_cs == Some("WGS_84");
    if slot.is_none() || (is_wgs && have_cs != Some("WGS_84")) {
        *slot = Some(v);
    }
}

/// Attach location and (for WGS-84) derived kinematics to the builder. Position and
/// velocity are only interpreted as a geographic fix when the coordinate system is
/// WGS-84; other systems (ECEF, local Cartesian) ride as metadata for a later pass
/// rather than being mis-projected onto the map. The raw XML is sealed regardless,
/// so nothing is lost.
fn apply_kinematics(mut b: EventBuilder, p: &PointCtx) -> EventBuilder {
    let is_wgs = p.cs.as_deref() == Some("WGS_84");
    let pos = p.pos.as_deref();

    if is_wgs {
        if let Some(pos) = pos {
            if pos.len() >= 2 {
                let (lat, lon) = (pos[0], pos[1]);
                let alt = pos.get(2).copied().unwrap_or(0.0);
                b = b.location(lat, lon, alt);

                // Velocity in WGS-84 is [d(lat)/s, d(lon)/s, d(alt m)/s] in °/s; turn
                // it into a ground speed (m/s) and course (deg), preserving the native
                // angular components in metadata (ADR-0019: canonical unit + native).
                if let Some(vel) = p.vel.as_deref() {
                    if vel.len() >= 2 {
                        let vn = vel[0].to_radians() * EARTH_RADIUS_M;
                        let ve = vel[1].to_radians() * EARTH_RADIUS_M * lat.to_radians().cos();
                        let speed = vn.hypot(ve);
                        let mut course = ve.atan2(vn).to_degrees();
                        if course < 0.0 {
                            course += 360.0;
                        }
                        b = b.attribute("speed", format!("{speed:.2}"));
                        b = b.attribute("course", format!("{course:.1}"));
                        b = b.metadata("vel_lat_dps", format!("{:.6}", vel[0]));
                        b = b.metadata("vel_lon_dps", format!("{:.6}", vel[1]));
                        if let Some(vz) = vel.get(2) {
                            b = b.attribute("vertical_rate", format!("{vz:.2}"));
                        }
                    }
                }
            }
        }
    } else if let Some(cs) = &p.cs {
        b = b.metadata("coordinate_system", cs.clone());
        if let Some(pos) = pos {
            let joined = pos
                .iter()
                .map(|x| format!("{x}"))
                .collect::<Vec<_>>()
                .join(" ");
            b = b.metadata("position_raw", joined);
        }
    }
    b
}

/// The STANAG 4676 track-segment status, mapped to the connector's lifecycle
/// vocabulary a COP consumes. The exact source token is preserved in metadata.
fn normalize_status(status: &str) -> &'static str {
    match status {
        "INITIATING" => "new",
        "MAINTAINING" => "update",
        "SEARCHING" => "coast",
        "TERMINATED" => "drop",
        "GROUND_TRUTH" => "truth",
        _ => "unknown",
    }
}

/// `message/baseTime + relTime * relTimeIncrement`, formatted RFC3339. Returns
/// `None` (caller falls back to receipt time) if there is no base time or it does
/// not parse.
fn point_time(base: Option<&str>, incr: Option<f64>, rel: Option<i64>) -> Option<String> {
    let dt = OffsetDateTime::parse(base?, &Rfc3339).ok()?;
    // relTime and the increment are attacker-influenced; a huge or non-finite
    // product must not overflow the date arithmetic. Both steps are checked, so an
    // out-of-range time falls back to receipt time rather than panicking.
    let seconds = rel.unwrap_or(0) as f64 * incr.unwrap_or(0.0);
    let dur = Duration::checked_seconds_f64(seconds)?;
    dt.checked_add(dur)?.format(&Rfc3339).ok()
}

/// Decode a `<uid>` (Base64 of a raw 16-byte UUID) into the canonical hyphenated
/// UUID string. `None` if it is not valid Base64 of at least 16 bytes.
fn decode_uid(text: &str) -> Option<String> {
    let bytes = base64_decode(text)?;
    (bytes.len() >= 16).then(|| {
        let b = &bytes[..16];
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    })
}

/// Standard Base64 decode (RFC 4648 alphabet, padding and inner whitespace
/// tolerated). Hand-rolled to avoid a dependency; returns `None` on any invalid
/// symbol or a truncated final group.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut chunk = [0u8; 4];
    let mut n = 0;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        chunk[n] = val(c)?;
        n += 1;
        if n == 4 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
            out.push((chunk[2] << 6) | chunk[3]);
            n = 0;
        }
    }
    match n {
        0 => {}
        2 => out.push((chunk[0] << 2) | (chunk[1] >> 4)),
        3 => {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        _ => return None, // a lone trailing symbol is not valid Base64
    }
    Some(out)
}

/// Parse a space-separated list of doubles. `None` if any token is not a number, so
/// a partially-garbled vector never yields a misaligned position.
fn parse_floats(text: &str) -> Option<Vec<f64>> {
    text.split_whitespace()
        .map(|t| t.parse::<f64>().ok())
        .collect()
}

/// Read a start tag's attribute by local name (prefix-insensitive).
fn read_attr(e: &quick_xml::events::BytesStart<'_>, key: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find_map(|a| (local(a.key.as_ref()) == key).then(|| a.value.into_owned()))
}

/// The local part of a possibly-prefixed XML name (`ns2:track` -> `track`), so
/// matching never depends on which namespace prefix a producer chose.
fn local(qname: &str) -> &str {
    match qname.find(':') {
        Some(i) => &qname[i + 1..],
        None => qname,
    }
}

/// The glue into the shared runtime: one 4676 message maps to zero or more events.
impl FrameParser for S4676Parser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        self.to_events(frame).map_err(|e| Box::new(e) as ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> S4676Parser {
        S4676Parser::new("isr-tracker-1", HashMap::new(), Enrichment::default())
    }

    fn tactical<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .chain(ev.metadata.iter())
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    /// A clean-room air track: two points a second apart, WGS-84 position + velocity,
    /// MAINTAINING status, FRIEND identity, AIR environment. Prefix `ns2:` bound to
    /// 4676, default namespace 4774 (one of the prefix bindings seen in the wild).
    const AIR_TRACK: &str = r#"<?xml version="1.0"?>
<ns2:nitsRoot xmlns:ns2="urn:nato:niia:stanag:4676:isrtrackingstandard:b:1" xmlns="urn:nato:stanag:4774:confidentialitymetadatalabel:1:0">
  <originatorConfidentialityLabel>
    <ConfidentialityInformation>
      <PolicyIdentifier>TEST</PolicyIdentifier>
      <Classification>NATO UNCLASSIFIED</Classification>
    </ConfidentialityInformation>
  </originatorConfidentialityLabel>
  <ns2:nitsVersion>B.1</ns2:nitsVersion>
  <ns2:message>
    <ns2:baseTime>2026-08-06T12:00:00.000Z</ns2:baseTime>
    <ns2:relTimeIncrement>0.001</ns2:relTimeIncrement>
    <ns2:track>
      <ns2:uid>DFjLwA22RXiKSAWh2eBOGQ==</ns2:uid>
      <ns2:segment>
        <ns2:status>MAINTAINING</ns2:status>
        <ns2:tp>
          <ns2:relTime>0</ns2:relTime>
          <ns2:dynamics cs="WGS_84">
            <ns2:pos>26.30000 50.60000 3000.0</ns2:pos>
            <ns2:vel>0.0 0.0009 5.0</ns2:vel>
          </ns2:dynamics>
        </ns2:tp>
        <ns2:tp>
          <ns2:relTime>1000</ns2:relTime>
          <ns2:dynamics cs="WGS_84">
            <ns2:pos>26.30100 50.60000 3005.0</ns2:pos>
          </ns2:dynamics>
        </ns2:tp>
      </ns2:segment>
      <ns2:object>
        <ns2:id1241>
          <ns2:identity>FRIEND</ns2:identity>
          <ns2:environment>AIR</ns2:environment>
        </ns2:id1241>
      </ns2:object>
    </ns2:track>
  </ns2:message>
</ns2:nitsRoot>"#;

    #[test]
    fn base64_uid_decodes_to_canonical_uuid() {
        // Known vector: the sample track uid decodes to this UUID.
        assert_eq!(
            decode_uid("DFjLwA22RXiKSAWh2eBOGQ=="),
            Some("0c58cbc0-0db6-4578-8a48-05a1d9e04e19".to_string())
        );
    }

    #[test]
    fn decodes_an_air_track_into_two_points() {
        let evs = parser().to_events(AIR_TRACK.as_bytes()).unwrap();
        assert_eq!(evs.len(), 2, "two track points -> two events");

        // Identity carried across both points from the track's `object` block, which
        // in document order follows the points — proving the deferred flush is right.
        for ev in &evs {
            // A domain is not a classification: AIR says where, not what.
            assert_eq!(ev.entity_type, "mim:object");
            assert_eq!(tactical(ev, "hostility"), Some("Friend"));
            assert_eq!(tactical(ev, "track_status"), Some("update")); // MAINTAINING
            assert_eq!(
                tactical(ev, "source_uid"),
                Some("0c58cbc0-0db6-4578-8a48-05a1d9e04e19")
            );
            assert_eq!(tactical(ev, "environment"), Some("AIR"));
        }

        // First point: position + derived kinematics from the WGS-84 velocity.
        let p0 = &evs[0];
        let loc = p0.location.as_ref().unwrap();
        assert!((loc.latitude - 26.3).abs() < 1e-6);
        assert!((loc.longitude - 50.6).abs() < 1e-6);
        assert!((loc.altitude_m - 3000.0).abs() < 1e-6);
        // vel = [0, 0.0009 deg/s lon, 5 m/s up]: ~due-east, ~90 deg course.
        let course: f64 = tactical(p0, "course").unwrap().parse().unwrap();
        assert!(
            (course - 90.0).abs() < 1.0,
            "course {course} should be ~east"
        );
        // 0.0009 deg/s of longitude at lat 26.3 -> ~89.7 m/s east.
        let speed: f64 = tactical(p0, "speed").unwrap().parse().unwrap();
        assert!(
            speed > 85.0 && speed < 95.0,
            "speed {speed} m/s at ~0.0009 deg/s lon"
        );
        assert_eq!(tactical(p0, "vertical_rate"), Some("5.00"));
    }

    #[test]
    fn point_time_reconstructs_from_base_plus_reltime() {
        let evs = parser().to_events(AIR_TRACK.as_bytes()).unwrap();
        // relTime 0 -> baseTime; relTime 1000 * 0.001 s -> +1 s. RFC3339 drops the
        // fractional part when it is zero.
        assert_eq!(evs[0].timestamp, "2026-08-06T12:00:00Z");
        assert_eq!(evs[1].timestamp, "2026-08-06T12:00:01Z");
    }

    #[test]
    fn classification_becomes_policy_tag() {
        let ev = &parser().to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        assert_eq!(ev.policy_tags, vec!["NATO UNCLASSIFIED".to_string()]);
    }

    #[test]
    fn raw_track_is_sealed_verbatim() {
        let ev = &parser().to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        // The payload is exactly the <track>…</track> element bytes from the source.
        let raw = String::from_utf8_lossy(&ev.payload);
        assert!(raw.starts_with("<ns2:track>"));
        assert!(raw.trim_end().ends_with("</ns2:track>"));
        assert!(raw.contains("DFjLwA22RXiKSAWh2eBOGQ=="));
    }

    #[test]
    fn prefix_binding_is_irrelevant() {
        // Same message, different prefix (foo:) bound to the 4676 namespace: must
        // decode identically because matching is on local names only.
        let alt = AIR_TRACK
            .replace("ns2:", "foo:")
            .replace("xmlns:ns2", "xmlns:foo");
        let evs = parser().to_events(alt.as_bytes()).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(
            tactical(&evs[0], "source_uid"),
            Some("0c58cbc0-0db6-4578-8a48-05a1d9e04e19")
        );
    }

    #[test]
    fn non_wgs84_position_rides_as_metadata_not_a_fix() {
        let ecef = AIR_TRACK
            .replace(r#"cs="WGS_84""#, r#"cs="ECEF""#)
            .replace("26.30000 50.60000 3000.0", "4000000 3000000 5000000");
        let evs = parser().to_events(ecef.as_bytes()).unwrap();
        // No geographic fix invented from ECEF metres.
        assert!(evs[0].location.is_none());
        assert_eq!(tactical(&evs[0], "coordinate_system"), Some("ECEF"));
    }

    #[test]
    fn environment_and_identity_overrides_and_defaults() {
        // The environment no longer picks a type; only the hostility changes.
        let sea = AIR_TRACK
            .replace("<ns2:environment>AIR", "<ns2:environment>SURFACE")
            .replace("<ns2:identity>FRIEND", "<ns2:identity>HOSTILE");
        let ev = &parser().to_events(sea.as_bytes()).unwrap()[0];
        assert_eq!(ev.entity_type, "mim:object");
        assert_eq!(tactical(ev, "hostility"), Some("Hostile"));

        // ASSUMED_FRIEND now has somewhere to go: MIM carries the same distinction,
        // so it survives instead of being flattened.
        let assumed = AIR_TRACK.replace("<ns2:identity>FRIEND", "<ns2:identity>ASSUMED_FRIEND");
        let ev = &parser().to_events(assumed.as_bytes()).unwrap()[0];
        assert_eq!(tactical(ev, "hostility"), Some("AssumedFriend"));
        assert_eq!(tactical(ev, "identity"), Some("ASSUMED_FRIEND"));
    }

    #[test]
    fn no_environment_picks_a_specific_type() {
        // Every STANAG 1241 environment is a domain. None of them says what the
        // thing is, so none of them may choose a type; the domain rides as an
        // attribute instead. A specific type must come from `objectClass`.
        // The wire token on the left, the value Core governs on the right.
        for (wire, code) in [
            ("AIR", "AIR"),
            ("SURFACE", "SURFACE"),
            ("LAND", "LAND"),
            // STANAG 1241 hyphenates this; Core's closed set does not. Passing the
            // wire value through would quarantine it and lose the CoT dimension.
            ("SUB-SURFACE", "SUBSURFACE"),
            ("SPACE", "SPACE"),
            ("UNKNOWN", "UNKNOWN"),
        ] {
            let xml =
                AIR_TRACK.replace("<ns2:environment>AIR", &format!("<ns2:environment>{wire}"));
            let ev = &parser().to_events(xml.as_bytes()).unwrap()[0];
            assert_eq!(ev.entity_type, "mim:object", "environment {wire}");
            assert_eq!(
                tactical(ev, "environment"),
                Some(code),
                "environment {wire}"
            );
        }
    }

    #[test]
    fn an_unrecognised_environment_is_unknown_and_the_token_is_kept() {
        // 4676's enums are extensible, so a producer may send something outside
        // STANAG 1241. Emitting it verbatim would be quarantined by Core and the
        // track would lose its battle dimension without anyone noticing.
        let xml = AIR_TRACK.replace("<ns2:environment>AIR", "<ns2:environment>LITTORAL");
        let ev = &parser().to_events(xml.as_bytes()).unwrap()[0];
        assert_eq!(tactical(ev, "environment"), Some("UNKNOWN"));
        assert_eq!(tactical(ev, "environment_source"), Some("LITTORAL"));
    }

    #[test]
    fn a_track_with_no_environment_still_carries_one() {
        let xml = AIR_TRACK.replace("<ns2:environment>AIR</ns2:environment>", "");
        let ev = &parser().to_events(xml.as_bytes()).unwrap()[0];
        assert_eq!(tactical(ev, "environment"), Some("UNKNOWN"));
    }

    #[test]
    fn config_entity_override_wins() {
        let mut ov = HashMap::new();
        ov.insert("AIR".to_string(), "mim:aircraft".to_string());
        let p = S4676Parser::new("t", ov, Enrichment::default());
        let ev = &p.to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        assert_eq!(ev.entity_type, "mim:aircraft");
    }

    #[test]
    fn message_with_no_tracks_yields_no_events() {
        let empty = r#"<ns2:nitsRoot xmlns:ns2="urn:nato:niia:stanag:4676:isrtrackingstandard:b:1">
          <ns2:message><ns2:baseTime>2026-08-06T12:00:00Z</ns2:baseTime></ns2:message>
        </ns2:nitsRoot>"#;
        assert!(parser().to_events(empty.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn malformed_xml_is_rejected_not_panicked() {
        assert!(matches!(
            parser().to_events(b"<ns2:nitsRoot><ns2:track <<<garbage"),
            Err(S4676Error::Xml(_))
        ));
    }

    #[test]
    fn garbled_position_yields_no_fix() {
        let bad = AIR_TRACK.replace("26.30000 50.60000 3000.0", "NORTH 50.6 3000");
        let evs = parser().to_events(bad.as_bytes()).unwrap();
        // A non-numeric token drops the whole vector rather than misaligning lat/lon.
        assert!(evs[0].location.is_none());
    }

    #[test]
    fn base64_decode_rejects_bad_symbol() {
        assert_eq!(base64_decode("!!!!"), None);
        assert_eq!(decode_uid("short"), None);
    }
}
