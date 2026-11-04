// SPDX-License-Identifier: Apache-2.0
//! STANAG 4676 (NATO ISR Tracking Standard, AEDP-12 Edition B) XML to canonical
//! events, one per track point. Elements match on local name, so any namespace
//! prefix works. A track's `object` follows its points in document order, so
//! points are buffered and emitted when the `<track>` closes; each event's
//! payload is its whole `<track>` element.

use std::collections::HashMap;

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use ajar_connector_common::{GovernedAttribute, GovernedIdentity};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

/// Spherical mean, for turning WGS-84 angular velocity into ground speed.
const EARTH_RADIUS_M: f64 = 6_371_000.0;

#[derive(Debug, thiserror::Error)]
pub enum S4676Error {
    #[error("malformed STANAG 4676 XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

pub struct S4676Parser {
    source_id: String,
    /// `[entity_map]`: a 4676 `environment` to an entity type.
    overrides: HashMap<String, String>,
    enrichment: Enrichment,
}

/// Facts that apply to every track in the message.
#[derive(Default)]
struct MessageCtx {
    base_time: Option<String>,
    rel_increment: Option<f64>,
    nits_version: Option<String>,
    classification: Option<String>,
    policy_id: Option<String>,
}

#[derive(Default)]
struct PointCtx {
    rel_time: Option<i64>,
    status: Option<String>,
    cs: Option<String>,
    pos: Option<Vec<f64>>,
    vel: Option<Vec<f64>>,
}

#[derive(Default)]
struct TrackCtx {
    uid: Option<String>,
    identity: Option<String>,
    environment: Option<String>,
    object_class: Option<String>,
    points: Vec<PointCtx>,
    /// Byte offset of the `<track>` start tag.
    start: usize,
}

/// Everything accumulated while streaming one message.
#[derive(Default)]
struct Walk {
    msg: MessageCtx,
    track: TrackCtx,
    seg_status: Option<String>,
    tp: PointCtx,
    /// The `cs` attribute of the enclosing `<dynamics>`.
    dynamics_cs: Option<String>,
}

impl Walk {
    /// Keyed on (parent, element) local names: `uid` appears under track,
    /// segment and tp, and only the track's is the stable id.
    fn route_text(&mut self, parent: &str, cur: &str, text: &str) {
        let tp = &mut self.tp;
        match (parent, cur) {
            ("nitsRoot", "nitsVersion") => self.msg.nits_version = Some(text.to_string()),
            ("message", "baseTime") => self.msg.base_time = Some(text.to_string()),
            ("message", "relTimeIncrement") => self.msg.rel_increment = text.parse().ok(),
            ("ConfidentialityInformation", "Classification") => {
                self.msg.classification = Some(text.to_string())
            }
            ("ConfidentialityInformation", "PolicyIdentifier") => {
                self.msg.policy_id = Some(text.to_string())
            }
            ("track", "uid") => self.track.uid = decode_uid(text),
            ("id1241", "identity") => self.track.identity = Some(text.to_string()),
            ("id1241", "environment") => self.track.environment = Some(text.to_string()),
            ("objectClass", "code") => self.track.object_class = Some(text.to_string()),
            ("segment", "status") => self.seg_status = Some(text.to_string()),
            ("tp", "relTime") => tp.rel_time = text.parse().ok(),
            ("dynamics", "pos") => {
                let Some(v) = parse_floats(text) else { return };
                if prefer_wgs(
                    &mut tp.pos,
                    tp.cs.as_deref(),
                    self.dynamics_cs.as_deref(),
                    v,
                ) {
                    tp.cs = self.dynamics_cs.clone();
                }
            }
            // The velocity is in the position's coordinate system.
            ("dynamics", "vel") => {
                let Some(v) = parse_floats(text) else { return };
                prefer_wgs(
                    &mut tp.vel,
                    tp.cs.as_deref(),
                    self.dynamics_cs.as_deref(),
                    v,
                );
            }
            _ => {}
        }
    }
}

impl S4676Parser {
    /// `enrichment` supplies the hostility for a track whose identity is absent
    /// or unrecognised.
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

    /// One event per track point in one `nitsRoot` message.
    pub fn to_events(&self, native: &[u8]) -> Result<Vec<Event>, S4676Error> {
        let mut reader = Reader::from_reader(native);
        let mut stack: Vec<String> = Vec::new();
        let mut w = Walk::default();
        let mut events = Vec::new();

        loop {
            let pos_before = reader.buffer_position() as usize;
            match reader.read_event()? {
                XmlEvent::Start(e) => {
                    let ln = local(e.name().as_ref()).to_string();
                    match ln.as_str() {
                        "track" => {
                            w.track = TrackCtx {
                                start: pos_before,
                                ..Default::default()
                            };
                        }
                        "dynamics" => {
                            w.dynamics_cs = e.attributes().flatten().find_map(|a| {
                                (local(a.key.as_ref()) == "cs").then(|| a.value.into_owned())
                            })
                        }
                        _ => {}
                    }
                    stack.push(ln);
                }
                XmlEvent::End(e) => {
                    match local(e.name().as_ref()) {
                        "tp" => {
                            w.track.points.push(PointCtx {
                                status: w.seg_status.clone(),
                                ..std::mem::take(&mut w.tp)
                            });
                        }
                        "dynamics" => w.dynamics_cs = None,
                        "segment" => w.seg_status = None,
                        "track" => {
                            let end = reader.buffer_position() as usize;
                            let raw = native.get(w.track.start..end).unwrap_or(native);
                            self.flush_track(&w.track, raw, &w.msg, &mut events)?;
                            w.track = TrackCtx::default();
                        }
                        _ => {}
                    }
                    stack.pop();
                }
                XmlEvent::Text(t) => {
                    let text = t.xml10_content();
                    let text = text.trim();
                    if !text.is_empty() {
                        let mut names = stack.iter().rev().map(String::as_str);
                        let cur = names.next().unwrap_or("");
                        let parent = names.next().unwrap_or("");
                        w.route_text(parent, cur, text);
                    }
                }
                XmlEvent::Eof => break,
                _ => {}
            }
        }

        Ok(events)
    }

    fn flush_track(
        &self,
        track: &TrackCtx,
        raw: &[u8],
        msg: &MessageCtx,
        out: &mut Vec<Event>,
    ) -> Result<(), S4676Error> {
        let entity = self.entity_type(track.environment.as_deref());
        let hostility = self.hostility(track.identity.as_deref());

        for p in &track.points {
            let mut b = EventBuilder::new(self.source_id.clone(), entity.clone())
                .new_id()
                .payload(raw.to_vec())
                .attribute("hostility", hostility.clone());

            match point_time(msg.base_time.as_deref(), msg.rel_increment, p.rel_time) {
                Some(ts) => b = b.timestamp(ts),
                None => b = b.now(),
            }
            if let Some(uid) = &track.uid {
                b = b.metadata("source_uid", uid.clone());
                b = b.identity("STANAG4676", uid.clone());
            }
            // The STANAG 4774 label becomes the policy tags Core reads, e.g.
            // `NATO SECRET` under policy `NATO` gives `class:secret` and
            // `policy:NATO`; an unknown spelling is stamped at the top level.
            if let Some(pid) = &msg.policy_id {
                b = b.metadata("nits_policy_identifier", pid.clone());
            }
            if let Some(cls) = &msg.classification {
                b = b.metadata("nits_classification", cls.clone());
                let tags = ajar_connector_common::marking::wire_classification(
                    cls,
                    msg.policy_id.as_deref(),
                );
                for t in tags {
                    b = b.policy_tag(t);
                }
            }
            if let Some(v) = &msg.nits_version {
                b = b.metadata("nits_version", v.clone());
            }
            if let Some(id) = &track.identity {
                b = b.metadata("identity", id.clone());
            }
            // Governed only on the untyped class, so on an operator's typed
            // override the domain lands in metadata.
            let env_code = environment_code(track.environment.as_deref());
            b = b.governed(&entity, "environment", env_code);
            if let Some(wire) = &track.environment {
                if env_code == "UNKNOWN" && wire != "UNKNOWN" {
                    b = b.metadata("environment_source", wire.clone());
                }
            }
            if let Some(oc) = &track.object_class {
                b = b.governed(&entity, "object_class", oc.clone());
            }
            if let Some(st) = &p.status {
                b = b.governed(&entity, "track_status", normalize_status(st));
                b = b.metadata("s4676_status", st.clone());
            }
            if let Some(rt) = p.rel_time {
                b = b.metadata("rel_time", rt.to_string());
            }

            out.push(apply_kinematics(b, p).build()?);
        }
        Ok(())
    }

    /// An `[entity_map]` entry, keyed on the wire token or its normalised code,
    /// else `mim:object`. An environment is a domain, not a type: AIR can be an
    /// aircraft, a missile or a balloon.
    fn entity_type(&self, environment: Option<&str>) -> String {
        let env = environment.unwrap_or("");
        self.overrides
            .get(env)
            .or_else(|| self.overrides.get(environment_code(environment)))
            .cloned()
            .unwrap_or_else(|| "mim:object".to_string())
    }

    /// From the STANAG 1241 identity; otherwise the configured default, else
    /// `Unknown`.
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

impl FrameParser for S4676Parser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        Ok(self.to_events(frame)?)
    }
}

/// A STANAG 1241 environment on the closed set Core governs. STANAG 1241
/// hyphenates `SUB-SURFACE`, and its enums are extensible, so an unseen token
/// becomes `UNKNOWN`.
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

/// Stores `v` if the slot is empty, or if `v` is WGS-84 and the point's
/// coordinate system is not. Returns whether it stored.
fn prefer_wgs(
    slot: &mut Option<Vec<f64>>,
    have_cs: Option<&str>,
    new_cs: Option<&str>,
    v: Vec<f64>,
) -> bool {
    let is_wgs = new_cs == Some("WGS_84");
    let store = slot.is_none() || (is_wgs && have_cs != Some("WGS_84"));
    if store {
        *slot = Some(v);
    }
    store
}

/// A WGS-84 point becomes a location, speed and course. Any other coordinate
/// system goes to metadata unprojected.
fn apply_kinematics(mut b: EventBuilder, p: &PointCtx) -> EventBuilder {
    if p.cs.as_deref() != Some("WGS_84") {
        if let Some(cs) = &p.cs {
            b = b.metadata("coordinate_system", cs.clone());
            if let Some(pos) = &p.pos {
                let joined = pos
                    .iter()
                    .map(|x| format!("{x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                b = b.metadata("position_raw", joined);
            }
        }
        return b;
    }
    let Some(&[lat, lon, ref pos_rest @ ..]) = p.pos.as_deref() else {
        return b;
    };
    b = b.location(lat, lon, pos_rest.first().copied().unwrap_or(0.0));

    // WGS-84 velocity is [lat deg/s, lon deg/s, height m/s].
    let Some(&[lat_dps, lon_dps, ref vel_rest @ ..]) = p.vel.as_deref() else {
        return b;
    };
    let north_mps = lat_dps.to_radians() * EARTH_RADIUS_M;
    let east_mps = lon_dps.to_radians() * EARTH_RADIUS_M * lat.to_radians().cos();
    let speed_mps = north_mps.hypot(east_mps);
    let course_deg = east_mps.atan2(north_mps).to_degrees().rem_euclid(360.0);
    b = b.attribute("speed", format!("{speed_mps:.2}"));
    b = b.attribute("course", format!("{course_deg:.1}"));
    b = b.metadata("vel_lat_dps", format!("{lat_dps:.6}"));
    b = b.metadata("vel_lon_dps", format!("{lon_dps:.6}"));
    if let Some(up_mps) = vel_rest.first() {
        b = b.attribute("vertical_rate", format!("{up_mps:.2}"));
    }
    b
}

/// A STANAG 4676 segment status as a track lifecycle state.
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

/// `message/baseTime + relTime * relTimeIncrement` as RFC 3339; `None` without
/// a parseable base time or when the sum is out of range.
fn point_time(base: Option<&str>, incr_s: Option<f64>, rel: Option<i64>) -> Option<String> {
    let dt = OffsetDateTime::parse(base?, &Rfc3339).ok()?;
    let seconds = rel.unwrap_or(0) as f64 * incr_s.unwrap_or(0.0);
    let dur = Duration::checked_seconds_f64(seconds)?;
    dt.checked_add(dur)?.format(&Rfc3339).ok()
}

/// A `<uid>`, Base64 of a raw 16-byte UUID, as a hyphenated UUID string.
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

/// RFC 4648 Base64, ignoring padding and whitespace.
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
        // A single trailing symbol.
        _ => return None,
    }
    Some(out)
}

/// `None` if any token is not a number, so a garbled vector never shifts.
fn parse_floats(text: &str) -> Option<Vec<f64>> {
    text.split_whitespace()
        .map(|t| t.parse::<f64>().ok())
        .collect()
}

/// `ns2:track` to `track`.
fn local(qname: &str) -> &str {
    match qname.find(':') {
        Some(i) => &qname[i + 1..],
        None => qname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACK_UUID: &str = "0c58cbc0-0db6-4578-8a48-05a1d9e04e19";

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

    /// Two WGS-84 points a second apart, MAINTAINING, FRIEND, AIR; `ns2:` bound
    /// to 4676 and the default namespace to 4774.
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
    fn base64_uid_decodes_to_uuid() {
        assert_eq!(
            decode_uid("DFjLwA22RXiKSAWh2eBOGQ=="),
            Some(TRACK_UUID.to_string())
        );
    }

    #[test]
    fn decodes_air_track_into_two_points() {
        let evs = parser().to_events(AIR_TRACK.as_bytes()).unwrap();
        assert_eq!(evs.len(), 2);
        for ev in &evs {
            assert_eq!(ev.entity_type, "mim:object");
            assert_eq!(
                tactical(ev, "hostility"),
                Some("Friend"),
                "identity after the points reaches every point"
            );
            assert_eq!(tactical(ev, "track_status"), Some("update"));
            assert_eq!(tactical(ev, "source_uid"), Some(TRACK_UUID));
            assert_eq!(tactical(ev, "environment"), Some("AIR"));
        }

        let p0 = &evs[0];
        let loc = p0.location.as_ref().unwrap();
        assert!((loc.latitude - 26.3).abs() < 1e-6);
        assert!((loc.longitude - 50.6).abs() < 1e-6);
        assert!((loc.altitude_m - 3000.0).abs() < 1e-6);
        let course: f64 = tactical(p0, "course").unwrap().parse().unwrap();
        assert!(
            (course - 90.0).abs() < 1.0,
            "course {course} should be ~east"
        );
        let speed: f64 = tactical(p0, "speed").unwrap().parse().unwrap();
        assert!(
            speed > 85.0 && speed < 95.0,
            "speed {speed} m/s at ~0.0009 deg/s lon"
        );
        assert_eq!(tactical(p0, "vertical_rate"), Some("5.00"));
    }

    #[test]
    fn point_time_is_base_plus_rel_time() {
        let evs = parser().to_events(AIR_TRACK.as_bytes()).unwrap();
        assert_eq!(evs[0].timestamp, "2026-08-06T12:00:00Z");
        assert_eq!(evs[1].timestamp, "2026-08-06T12:00:01Z");
    }

    #[test]
    fn confidentiality_label_to_policy_tags() {
        let ev = &parser().to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        assert_eq!(ev.policy_tags, ["class:unclassified", "policy:TEST"]);
        let meta = |k: &str| {
            ev.metadata
                .iter()
                .find(|m| m.key == k)
                .map(|m| m.value.as_str())
        };
        assert_eq!(meta("nits_classification"), Some("NATO UNCLASSIFIED"));
        assert_eq!(meta("nits_policy_identifier"), Some("TEST"));
    }

    #[test]
    fn label_wording_names_policy_without_identifier() {
        let xml = AIR_TRACK.replace("<PolicyIdentifier>TEST</PolicyIdentifier>", "");
        let ev = &parser().to_events(xml.as_bytes()).unwrap()[0];
        assert_eq!(ev.policy_tags, ["class:unclassified", "policy:NATO"]);
    }

    #[test]
    fn unknown_classification_is_top_secret() {
        let xml = AIR_TRACK.replace("NATO UNCLASSIFIED", "PROTECTED B");
        let ev = &parser().to_events(xml.as_bytes()).unwrap()[0];
        assert_eq!(ev.policy_tags, ["class:top-secret", "policy:TEST"]);
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "nits_classification" && m.value == "PROTECTED B"));
    }

    #[test]
    fn raw_track_sealed_in_payload() {
        let ev = &parser().to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        let raw = String::from_utf8_lossy(&ev.payload);
        assert!(raw.starts_with("<ns2:track>"));
        assert!(raw.trim_end().ends_with("</ns2:track>"));
        assert!(raw.contains("DFjLwA22RXiKSAWh2eBOGQ=="));
    }

    #[test]
    fn prefix_binding_is_irrelevant() {
        let alt = AIR_TRACK
            .replace("ns2:", "foo:")
            .replace("xmlns:ns2", "xmlns:foo");
        let evs = parser().to_events(alt.as_bytes()).unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(tactical(&evs[0], "source_uid"), Some(TRACK_UUID));
    }

    #[test]
    fn non_wgs84_position_goes_to_metadata() {
        let ecef = AIR_TRACK
            .replace(r#"cs="WGS_84""#, r#"cs="ECEF""#)
            .replace("26.30000 50.60000 3000.0", "4000000 3000000 5000000");
        let evs = parser().to_events(ecef.as_bytes()).unwrap();
        assert!(evs[0].location.is_none());
        assert_eq!(tactical(&evs[0], "coordinate_system"), Some("ECEF"));
    }

    #[test]
    fn identity_maps_to_hostility() {
        let sea = AIR_TRACK
            .replace("<ns2:environment>AIR", "<ns2:environment>SURFACE")
            .replace("<ns2:identity>FRIEND", "<ns2:identity>HOSTILE");
        let ev = &parser().to_events(sea.as_bytes()).unwrap()[0];
        assert_eq!(ev.entity_type, "mim:object");
        assert_eq!(tactical(ev, "hostility"), Some("Hostile"));

        let assumed = AIR_TRACK.replace("<ns2:identity>FRIEND", "<ns2:identity>ASSUMED_FRIEND");
        let ev = &parser().to_events(assumed.as_bytes()).unwrap()[0];
        assert_eq!(tactical(ev, "hostility"), Some("AssumedFriend"));
        assert_eq!(tactical(ev, "identity"), Some("ASSUMED_FRIEND"));
    }

    #[test]
    fn environment_is_normalised_not_typed() {
        for (wire, code) in [
            ("AIR", "AIR"),
            ("SURFACE", "SURFACE"),
            ("LAND", "LAND"),
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
    fn unrecognised_environment_kept_as_source() {
        let xml = AIR_TRACK.replace("<ns2:environment>AIR", "<ns2:environment>LITTORAL");
        let ev = &parser().to_events(xml.as_bytes()).unwrap()[0];
        assert_eq!(tactical(ev, "environment"), Some("UNKNOWN"));
        assert_eq!(tactical(ev, "environment_source"), Some("LITTORAL"));
    }

    #[test]
    fn typed_override_moves_environment_to_metadata() {
        let mut ov = HashMap::new();
        ov.insert("AIR".to_string(), "mim:aircraft".to_string());
        let p = S4676Parser::new("isr-1", ov, Enrichment::default());
        let ev = &p.to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert!(
            !ev.attributes.iter().any(|a| a.key == "environment"),
            "a typed class must not claim a domain: {:?}",
            ev.attributes
        );
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "environment" && m.value == "AIR"));
        let ev = &parser().to_events(AIR_TRACK.as_bytes()).unwrap()[0];
        assert_eq!(ev.entity_type, "mim:object");
        assert!(ev.attributes.iter().any(|a| a.key == "environment"));
    }

    #[test]
    fn missing_environment_is_unknown() {
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
    fn malformed_xml_is_rejected() {
        assert!(matches!(
            parser().to_events(b"<ns2:nitsRoot><ns2:track <<<garbage"),
            Err(S4676Error::Xml(_))
        ));
    }

    #[test]
    fn garbled_position_yields_no_fix() {
        let bad = AIR_TRACK.replace("26.30000 50.60000 3000.0", "NORTH 50.6 3000");
        let evs = parser().to_events(bad.as_bytes()).unwrap();
        assert!(evs[0].location.is_none());
    }

    #[test]
    fn base64_decode_rejects_bad_symbol() {
        assert_eq!(base64_decode("!!!!"), None);
        assert_eq!(decode_uid("short"), None);
    }
}
