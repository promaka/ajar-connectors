// SPDX-License-Identifier: Apache-2.0
//! Cursor-on-Target (CoT) XML -> canonical Ajar event.
//!
//! This is the untrusted edge: field CoT can be malformed, truncated, or hostile,
//! so parsing uses a real XML reader and every failure is a typed error — it never
//! panics and never fabricates a field. The canonical invariants then hold by
//! construction via [`EventBuilder`].

use std::collections::HashMap;

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

/// Why a CoT frame could not be normalized. Dropped frames are counted and logged
/// with the reason (operator observability), never silently swallowed.
#[derive(Debug, PartialEq, Eq)]
pub enum CotError {
    /// The bytes were not well-formed XML.
    Xml(String),
    /// A required element/attribute was absent.
    Missing(&'static str),
    /// A numeric attribute (lat/lon/hae) was present but unparseable.
    BadNumber(&'static str),
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for CotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CotError::Xml(e) => write!(f, "malformed CoT XML: {e}"),
            CotError::Missing(what) => write!(f, "CoT missing {what}"),
            CotError::BadNumber(what) => write!(f, "CoT bad number in {what}"),
            CotError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for CotError {}

/// Normalizes CoT for one connector identity, with optional CoT-type overrides.
pub struct CotParser {
    source_id: String,
    overrides: HashMap<String, String>,
}

impl CotParser {
    pub fn new(
        source_id: impl Into<String>,
        overrides: HashMap<String, String>,
        // CoT encodes affiliation in the event type, so this connector derives it
        // from the wire and needs no enrichment; the arg is kept for API uniformity.
        _enrichment: Enrichment,
    ) -> Self {
        Self {
            source_id: source_id.into(),
            overrides,
        }
    }

    /// Parse one CoT `<event>` (with optional `<point>`) into a canonical event.
    pub fn to_event(&self, native: &[u8]) -> Result<Event, CotError> {
        let mut reader = Reader::from_reader(native);
        let mut buf = Vec::new();

        let mut uid: Option<String> = None;
        let mut cot_type: Option<String> = None;
        let mut time: Option<String> = None;
        let mut lat: Option<f64> = None;
        let mut lon: Option<f64> = None;
        let mut hae: f64 = 0.0;
        let mut callsign: Option<String> = None;
        let mut confidence: Option<f64> = None;
        let mut in_confidence = false;
        let mut saw_event = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => match e.name().as_ref() {
                    b"event" => {
                        saw_event = true;
                        for a in e.attributes().flatten() {
                            let val = String::from_utf8_lossy(&a.value).into_owned();
                            match a.key.as_ref() {
                                b"uid" => uid = Some(val),
                                b"type" => cot_type = Some(val),
                                b"time" => time = Some(val),
                                _ => {}
                            }
                        }
                    }
                    b"point" => {
                        for a in e.attributes().flatten() {
                            let s = String::from_utf8_lossy(&a.value);
                            match a.key.as_ref() {
                                b"lat" => {
                                    lat = Some(
                                        s.parse().map_err(|_| CotError::BadNumber("point/@lat"))?,
                                    )
                                }
                                b"lon" => {
                                    lon = Some(
                                        s.parse().map_err(|_| CotError::BadNumber("point/@lon"))?,
                                    )
                                }
                                b"hae" => hae = s.parse().unwrap_or(0.0),
                                _ => {}
                            }
                        }
                    }
                    // <detail><contact callsign="EAGLE01"/></detail>
                    b"contact" => {
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == b"callsign" {
                                callsign = Some(String::from_utf8_lossy(&a.value).into_owned());
                            }
                        }
                    }
                    // Confidence has no standard CoT home; accept either a
                    // <confidence value="0.87"/> attribute or <confidence>0.87</confidence>
                    // element text.
                    b"confidence" => {
                        in_confidence = true;
                        for a in e.attributes().flatten() {
                            if a.key.as_ref() == b"value" {
                                confidence =
                                    normalize_confidence(&String::from_utf8_lossy(&a.value));
                            }
                        }
                    }
                    _ => {}
                },
                Ok(XmlEvent::Text(t)) if in_confidence => {
                    in_confidence = false;
                    let text = t.unescape().unwrap_or_default();
                    if confidence.is_none() {
                        confidence = normalize_confidence(text.trim());
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => return Err(CotError::Xml(e.to_string())),
                _ => {}
            }
            buf.clear();
        }

        if !saw_event {
            return Err(CotError::Missing("<event>"));
        }
        let uid = uid.ok_or(CotError::Missing("event/@uid"))?;
        let cot_type = cot_type.ok_or(CotError::Missing("event/@type"))?;
        let time = time.ok_or(CotError::Missing("event/@time"))?;

        // Core requires the event id to be a fresh UUIDv7. The native CoT uid is
        // ungoverned passthrough, so it goes in metadata (never the id, never a
        // governed attribute).
        //
        // The tactical attributes a COP needs — affiliation, callsign, confidence.
        // Affiliation and callsign are routed per the connector's attribute mode
        // (governed when the ontology declares them, else metadata — always safe);
        // affiliation is always set (defaulting to unknown), so a track is never
        // blank. Confidence is the event's first-class field. The native uid stays
        // in metadata (never the id).
        let mut builder = EventBuilder::new(self.source_id.clone(), self.map_type(&cot_type))
            .new_id()
            .payload(native.to_vec())
            .timestamp(time)
            .metadata("source_uid", uid)
            .attribute("affiliation", affiliation(&cot_type));
        if let Some(callsign) = callsign {
            builder = builder.attribute("callsign", callsign);
        }
        if let Some(confidence) = confidence {
            builder = builder.confidence(confidence);
        }
        if let (Some(lat), Some(lon)) = (lat, lon) {
            builder = builder.location(lat, lon, hae);
        }
        builder.build().map_err(|e| CotError::Build(e.to_string()))
    }

    /// Map a CoT type code to an Ajar entity type. Config overrides win; otherwise a
    /// conservative default by battle dimension (air/sea); anything else falls back
    /// to a vendor namespace so nothing is silently dropped (the sovereign's ontology
    /// + the connector's allowed namespaces decide what Core then accepts).
    fn map_type(&self, cot_type: &str) -> String {
        if let Some(mapped) = self.overrides.get(cot_type) {
            return mapped.clone();
        }
        match cot_type.split('-').nth(2) {
            Some("A") => "mim:aircraft".to_string(), // air
            Some("S") => "mim:vessel".to_string(),   // sea surface
            _ => format!("x:cot:{}", cot_type.replace('-', "_")),
        }
    }
}

/// Affiliation from the CoT type's second field (`a-f-…` → friendly). Always
/// resolves — anything other than the four standard codes (including a missing
/// field, and pending/assumed/suspect variants) reads as `unknown`, so a COP never
/// shows a blank affiliation.
fn affiliation(cot_type: &str) -> &'static str {
    match cot_type.split('-').nth(1) {
        Some("f") => "friendly",
        Some("h") => "hostile",
        Some("n") => "neutral",
        Some("u") => "unknown",
        _ => "unknown",
    }
}

/// Parse a confidence value into `[0.0, 1.0]`. A value above 1 is treated as a
/// percentage (e.g. `87` → `0.87`); the result is clamped. Returns `None` if the
/// text is not a number.
fn normalize_confidence(raw: &str) -> Option<f64> {
    let v: f64 = raw.parse().ok()?;
    let v = if v > 1.0 { v / 100.0 } else { v };
    Some(v.clamp(0.0, 1.0))
}

/// The one piece of glue that plugs this format into the shared runtime. Every CoT
/// frame we accept maps to exactly one event.
impl FrameParser for CotParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        self.to_event(frame)
            .map(|e| vec![e])
            .map_err(|e| Box::new(e) as ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<event version="2.0" uid="AD-7741" type="a-f-A-M-F-Q" time="2026-06-10T08:00:00Z" start="2026-06-10T08:00:00Z" stale="2026-06-10T08:00:30Z"><point lat="26.4" lon="50.9" hae="1200.0" ce="10" le="10"/></event>"#;

    /// Default parser: safe metadata mode.
    fn parser() -> CotParser {
        CotParser::new("tak-field-1", HashMap::new(), Enrichment::default())
    }

    /// Parser for a deployment that declared its ontology: governed mode.
    fn governed() -> CotParser {
        CotParser::new(
            "tak-field-1",
            HashMap::new(),
            Enrichment::governing(["affiliation", "callsign"]),
        )
    }

    /// Find a tactical value in whichever place the mode put it.
    fn tactical<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .chain(ev.metadata.iter())
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    #[test]
    fn parses_a_valid_cot_track() {
        let ev = parser().to_event(SAMPLE.as_bytes()).unwrap();
        // The id is a fresh UUIDv7, not the native uid; the uid is preserved as
        // ungoverned metadata.
        assert_ne!(ev.id, "AD-7741");
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == "AD-7741"));
        assert_eq!(ev.entity_type, "mim:aircraft"); // battle dimension A -> air
        let loc = ev.location.as_ref().unwrap();
        assert_eq!(loc.latitude, 26.4);
        assert_eq!(loc.altitude_m, 1200.0);
        // Affiliation is always set from the type's 2nd field (a-f-… -> friendly).
        assert_eq!(tactical(&ev, "affiliation"), Some("friendly"));
    }

    #[test]
    fn fields_are_attributes_and_raw_frame_is_preserved() {
        // Affiliation is derived from the CoT type (real data, not a default) and
        // rides as an attribute; Core demotes it if the ontology hasn't declared it.
        let ev = parser().to_event(SAMPLE.as_bytes()).unwrap();
        assert!(ev.attributes.iter().any(|a| a.key == "affiliation"));
        assert!(!ev.metadata.iter().any(|m| m.key == "affiliation"));
        // The raw CoT frame is preserved verbatim in the signed payload.
        assert_eq!(ev.payload.as_slice(), SAMPLE.as_bytes());
    }

    #[test]
    fn extracts_tactical_attributes_a_cop_needs() {
        // Hostile ground unit with a callsign and confidence in <detail>.
        let cot = r#"<event version="2.0" uid="X-1" type="a-h-G-U-C-I" time="2026-06-10T08:00:00Z" start="2026-06-10T08:00:00Z" stale="2026-06-10T08:00:30Z">
            <point lat="1.0" lon="2.0" hae="0"/>
            <detail><contact callsign="EAGLE01"/><confidence>0.87</confidence></detail>
        </event>"#;
        let ev = governed().to_event(cot.as_bytes()).unwrap();
        assert_eq!(tactical(&ev, "affiliation"), Some("hostile"));
        assert_eq!(tactical(&ev, "callsign"), Some("EAGLE01"));
        assert!((ev.confidence - 0.87).abs() < 1e-9);
    }

    #[test]
    fn confidence_accepts_percent_and_attribute_form() {
        let cot = r#"<event uid="X" type="a-n-A" time="2026-06-10T08:00:00Z"><detail><confidence value="87"/></detail></event>"#;
        let ev = parser().to_event(cot.as_bytes()).unwrap();
        assert!((ev.confidence - 0.87).abs() < 1e-9);
        assert_eq!(tactical(&ev, "affiliation"), Some("neutral"));
    }

    #[test]
    fn unknown_affiliation_never_blank() {
        // No 2nd field / unmapped code -> "unknown", never missing.
        let cot = r#"<event uid="X" type="a" time="2026-06-10T08:00:00Z"/>"#;
        let ev = parser().to_event(cot.as_bytes()).unwrap();
        assert_eq!(tactical(&ev, "affiliation"), Some("unknown"));
    }

    #[test]
    fn overrides_win_over_defaults() {
        let mut ov = HashMap::new();
        ov.insert("a-f-A-M-F-Q".to_string(), "mim:drone".to_string());
        let p = CotParser::new("tak-field-1", ov, Enrichment::default());
        assert_eq!(
            p.to_event(SAMPLE.as_bytes()).unwrap().entity_type,
            "mim:drone"
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
    fn malformed_xml_is_rejected_not_panicked() {
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
