// SPDX-License-Identifier: Apache-2.0
//! Cursor-on-Target (CoT) XML to canonical Ajar events: one `<event>` per frame,
//! hostility from the type's affiliation code, entity type from its battle
//! dimension or the configured overrides.

use std::collections::HashMap;

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::GovernedIdentity;
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum CotError {
    #[error("malformed CoT XML: {0}")]
    Xml(String),
    #[error("CoT missing {0}")]
    Missing(&'static str),
    #[error("CoT bad number in {0}")]
    BadNumber(&'static str),
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

pub struct CotParser {
    source_id: String,
    overrides: HashMap<String, String>,
}

impl CotParser {
    /// CoT carries its own hostility, so `_enrichment` is unused; it keeps the
    /// constructor shape of the other connectors.
    pub fn new(
        source_id: impl Into<String>,
        overrides: HashMap<String, String>,
        _enrichment: Enrichment,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            overrides,
        }
    }

    pub fn to_event(&self, native: &[u8]) -> Result<Event, CotError> {
        let mut reader = Reader::from_reader(native);

        let mut uid: Option<String> = None;
        let mut cot_type: Option<String> = None;
        let mut time: Option<String> = None;
        let mut lat: Option<f64> = None;
        let mut lon: Option<f64> = None;
        let mut hae_m: f64 = 0.0;
        let mut callsign: Option<String> = None;
        let mut course_deg: Option<f64> = None;
        let mut speed_mps: Option<f64> = None;
        let mut confidence: Option<f64> = None;
        let mut in_confidence = false;
        let mut saw_event = false;

        loop {
            match reader.read_event() {
                Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => match e.name().as_ref() {
                    "event" => {
                        saw_event = true;
                        for a in e.attributes().flatten() {
                            match a.key.as_ref() {
                                "uid" => uid = Some(a.value.into_owned()),
                                "type" => cot_type = Some(a.value.into_owned()),
                                "time" => time = Some(a.value.into_owned()),
                                _ => {}
                            }
                        }
                    }
                    "point" => {
                        for a in e.attributes().flatten() {
                            let s = a.value;
                            match a.key.as_ref() {
                                "lat" => {
                                    lat = Some(
                                        s.parse().map_err(|_| CotError::BadNumber("point/@lat"))?,
                                    )
                                }
                                "lon" => {
                                    lon = Some(
                                        s.parse().map_err(|_| CotError::BadNumber("point/@lon"))?,
                                    )
                                }
                                "hae" => hae_m = s.parse().unwrap_or(0.0),
                                _ => {}
                            }
                        }
                    }
                    "contact" => {
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == "callsign" {
                                callsign = Some(a.value.into_owned());
                            }
                        }
                    }
                    // CoT course is degrees from true north and speed is m/s, the
                    // governed units. A non-numeric value is skipped and the
                    // track kept.
                    "track" => {
                        for a in e.attributes().flatten() {
                            match a.key.as_ref() {
                                "course" => course_deg = parse_finite(&a.value),
                                "speed" => speed_mps = parse_finite(&a.value),
                                _ => {}
                            }
                        }
                    }
                    // Not standard CoT: accepted as <confidence value="0.87"/> or
                    // <confidence>0.87</confidence>.
                    "confidence" => {
                        in_confidence = true;
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == "value" {
                                confidence = normalize_confidence(&a.value);
                            }
                        }
                    }
                    _ => {}
                },
                Ok(XmlEvent::Text(t)) if in_confidence => {
                    in_confidence = false;
                    let text = t.xml10_content();
                    if confidence.is_none() {
                        confidence = normalize_confidence(text.trim());
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => return Err(CotError::Xml(e.to_string())),
                _ => {}
            }
        }

        if !saw_event {
            return Err(CotError::Missing("<event>"));
        }
        let uid = uid.ok_or(CotError::Missing("event/@uid"))?;
        let cot_type = cot_type.ok_or(CotError::Missing("event/@type"))?;
        let time = time.ok_or(CotError::Missing("event/@time"))?;

        let mut builder = EventBuilder::new(self.source_id.clone(), self.map_type(&cot_type))
            .new_id()
            .payload(native.to_vec())
            .timestamp(time)
            .metadata("source_uid", uid.clone())
            .identity("CoT", uid)
            .attribute("hostility", hostility(&cot_type));
        if let Some(callsign) = callsign {
            builder = builder.attribute("callsign", callsign);
        }
        // A negative speed or a course outside the circle is out of the governed
        // bounds and is dropped.
        if let Some(course_deg) = course_deg.filter(|c| (0.0..=360.0).contains(c)) {
            builder = builder.attribute("course", format!("{course_deg:.1}"));
        }
        if let Some(speed_mps) = speed_mps.filter(|s| *s >= 0.0) {
            builder = builder.attribute("speed", format!("{speed_mps:.2}"));
        }
        if let Some(confidence) = confidence {
            builder = builder.confidence(confidence);
        }
        if let (Some(lat), Some(lon)) = (lat, lon) {
            builder = builder.location(lat, lon, hae_m);
        }
        Ok(builder.build()?)
    }

    /// Config overrides first, then the battle dimension (third type field);
    /// anything else goes to the `x:cot:` namespace.
    fn map_type(&self, cot_type: &str) -> String {
        if let Some(mapped) = self.overrides.get(cot_type) {
            return mapped.clone();
        }
        match cot_type.split('-').nth(2) {
            Some("A") => "mim:aircraft".to_string(),
            Some("S") => "mim:vessel".to_string(),
            // Subsurface, CoT revision 2.
            Some("U") => "mim:subsurface-vessel".to_string(),
            _ => format!("x:cot:{}", cot_type.replace('-', "_")),
        }
    }
}

impl FrameParser for CotParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        Ok(vec![self.to_event(frame)?])
    }
}

fn parse_finite(raw: &str) -> Option<f64> {
    raw.trim().parse::<f64>().ok().filter(|v| v.is_finite())
}

/// Hostility from the type's affiliation code (second field). `j` and `k` are
/// the exercise codes Joker and Faker. Anything else, or no second field, is
/// `Unknown`.
fn hostility(cot_type: &str) -> &'static str {
    match cot_type.split('-').nth(1) {
        Some("f") => "Friend",
        Some("a") => "AssumedFriend",
        Some("h") => "Hostile",
        Some("s") => "Suspect",
        Some("n") => "Neutral",
        Some("p") => "Pending",
        Some("j") => "Joker",
        Some("k") => "Faker",
        _ => "Unknown",
    }
}

/// Confidence clamped to [0, 1]; a value above 1 is a percentage.
fn normalize_confidence(raw: &str) -> Option<f64> {
    let v: f64 = raw.parse().ok()?;
    let v = if v > 1.0 { v / 100.0 } else { v };
    Some(v.clamp(0.0, 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<event version="2.0" uid="AD-7741" type="a-f-A-M-F-Q" time="2026-06-10T08:00:00Z" start="2026-06-10T08:00:00Z" stale="2026-06-10T08:00:30Z"><point lat="26.4" lon="50.9" hae="1200.0" ce="10" le="10"/></event>"#;

    // As ATAK sends it: contact callsign and track kinematics in <detail>.
    const WITH_TRACK: &str = r#"<event version="2.0" uid="EAGLE-1" type="a-f-A" time="2026-06-10T08:00:00Z"><point lat="51.5" lon="-0.12" hae="9100.0"/><detail><contact callsign="EAGLE01"/><track course="128.4" speed="221.5"/></detail></event>"#;

    fn parser() -> CotParser {
        CotParser::new("tak-field-1", HashMap::new(), Enrichment::default())
    }

    fn attr<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    #[test]
    fn track_element_becomes_course_and_speed() {
        let ev = parser().to_event(WITH_TRACK.as_bytes()).unwrap();
        assert_eq!(attr(&ev, "course"), Some("128.4"));
        assert_eq!(attr(&ev, "speed"), Some("221.50"));
        assert_eq!(attr(&ev, "callsign"), Some("EAGLE01"));
    }

    #[test]
    fn no_track_element_sets_no_kinematics() {
        let ev = parser().to_event(SAMPLE.as_bytes()).unwrap();
        assert_eq!(attr(&ev, "course"), None);
        assert_eq!(attr(&ev, "speed"), None);
    }

    #[test]
    fn malformed_kinematics_are_skipped() {
        for (course, speed) in [
            ("", "12.0"),
            ("north", "12.0"),
            ("nan", "12.0"),
            ("400.0", "12.0"),
            ("-1.0", "12.0"),
            ("128.4", "-3.0"),
        ] {
            let xml = format!(
                r#"<event uid="U" type="a-f-A" time="2026-06-10T08:00:00Z"><point lat="51.5" lon="-0.12" hae="0"/><detail><track course="{course}" speed="{speed}"/></detail></event>"#
            );
            let ev = parser().to_event(xml.as_bytes()).unwrap_or_else(|e| {
                panic!("course {course:?} speed {speed:?} lost the track: {e}")
            });
            let bad_course = course
                .parse::<f64>()
                .ok()
                .is_none_or(|c| !(0.0..=360.0).contains(&c));
            if bad_course {
                assert_eq!(attr(&ev, "course"), None, "course {course:?}");
            }
            if speed.starts_with('-') {
                assert_eq!(attr(&ev, "speed"), None, "speed {speed:?}");
            }
            assert!(ev.location.is_some(), "the position survives regardless");
        }
    }

    #[test]
    fn parses_a_valid_cot_track() {
        let ev = parser().to_event(SAMPLE.as_bytes()).unwrap();
        assert_ne!(ev.id, "AD-7741");
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == "AD-7741"));
        assert_eq!(attr(&ev, "alt_id"), Some("AD-7741"));
        assert_eq!(attr(&ev, "alt_id_standard"), Some("CoT"));
        assert_eq!(ev.entity_type, "mim:aircraft");
        let loc = ev.location.as_ref().unwrap();
        assert_eq!(loc.latitude, 26.4);
        assert_eq!(loc.altitude_m, 1200.0);
        assert_eq!(attr(&ev, "hostility"), Some("Friend"));
    }

    #[test]
    fn hostility_is_attribute_and_raw_kept() {
        let ev = parser().to_event(SAMPLE.as_bytes()).unwrap();
        assert!(ev.attributes.iter().any(|a| a.key == "hostility"));
        assert!(!ev.metadata.iter().any(|m| m.key == "hostility"));
        assert_eq!(ev.payload.as_slice(), SAMPLE.as_bytes());
    }

    #[test]
    fn extracts_hostility_callsign_and_confidence() {
        let cot = r#"<event version="2.0" uid="X-1" type="a-h-G-U-C-I" time="2026-06-10T08:00:00Z" start="2026-06-10T08:00:00Z" stale="2026-06-10T08:00:30Z">
            <point lat="1.0" lon="2.0" hae="0"/>
            <detail><contact callsign="EAGLE01"/><confidence>0.87</confidence></detail>
        </event>"#;
        let ev = parser().to_event(cot.as_bytes()).unwrap();
        assert_eq!(attr(&ev, "hostility"), Some("Hostile"));
        assert_eq!(attr(&ev, "callsign"), Some("EAGLE01"));
        assert!((ev.confidence - 0.87).abs() < 1e-9);
    }

    #[test]
    fn confidence_accepts_percent_and_attribute_form() {
        let cot = r#"<event uid="X" type="a-n-A" time="2026-06-10T08:00:00Z"><detail><confidence value="87"/></detail></event>"#;
        let ev = parser().to_event(cot.as_bytes()).unwrap();
        assert!((ev.confidence - 0.87).abs() < 1e-9);
        assert_eq!(attr(&ev, "hostility"), Some("Neutral"));
    }

    #[test]
    fn missing_affiliation_is_unknown_hostility() {
        let cot = r#"<event uid="X" type="a" time="2026-06-10T08:00:00Z"/>"#;
        let ev = parser().to_event(cot.as_bytes()).unwrap();
        assert_eq!(attr(&ev, "hostility"), Some("Unknown"));
    }

    #[test]
    fn every_affiliation_code_maps() {
        for (code, expected) in [
            ("f", "Friend"),
            ("a", "AssumedFriend"),
            ("h", "Hostile"),
            ("s", "Suspect"),
            ("n", "Neutral"),
            ("p", "Pending"),
            ("j", "Joker"),
            ("k", "Faker"),
            ("x", "Unknown"),
        ] {
            let cot = format!(r#"<event uid="X" type="a-{code}-A" time="2026-06-10T08:00:00Z"/>"#);
            let ev = parser().to_event(cot.as_bytes()).unwrap();
            assert_eq!(
                attr(&ev, "hostility"),
                Some(expected),
                "CoT affiliation code {code:?}"
            );
        }
    }

    #[test]
    fn overrides_win_over_defaults() {
        let mut ov = HashMap::new();
        ov.insert("a-f-A-M-F-Q".to_string(), "mim:aircraft".to_string());
        let p = CotParser::new("tak-field-1", ov, Enrichment::default());
        assert_eq!(
            p.to_event(SAMPLE.as_bytes()).unwrap().entity_type,
            "mim:aircraft"
        );
    }

    #[test]
    fn unknown_type_falls_back_to_vendor_namespace() {
        let cot = r#"<event uid="G1" type="a-f-G-U-C" time="2026-06-10T08:00:00Z"><point lat="1" lon="2" hae="0"/></event>"#;
        assert_eq!(
            parser().to_event(cot.as_bytes()).unwrap().entity_type,
            "x:cot:a_f_G_U_C"
        );
    }

    #[test]
    fn malformed_xml_is_rejected() {
        assert!(matches!(
            parser().to_event(b"<event uid=\"x\" type=\"a-f-A\" <<<garbage"),
            Err(CotError::Xml(_)) | Err(CotError::Missing(_))
        ));
    }

    #[test]
    fn missing_required_attr_is_rejected() {
        let no_uid = r#"<event type="a-f-A" time="2026-06-10T08:00:00Z"/>"#;
        assert_eq!(
            parser().to_event(no_uid.as_bytes()),
            Err(CotError::Missing("event/@uid"))
        );
    }

    #[test]
    fn bad_coordinate_is_rejected() {
        let bad =
            r#"<event uid="x" type="a-f-A" time="t"><point lat="NORTH" lon="2" hae="0"/></event>"#;
        assert_eq!(
            parser().to_event(bad.as_bytes()),
            Err(CotError::BadNumber("point/@lat"))
        );
    }
}
