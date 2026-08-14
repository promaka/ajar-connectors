// SPDX-License-Identifier: Apache-2.0
//! Reference connector: **Cursor-on-Target (CoT)** XML <-> canonical Ajar event.
//!
//! This is a teaching example, not a production CoT stack. It shows the shape of
//! an inbound [`Connector`] (CoT XML -> canonical [`Event`]) and a paired
//! [`OutboundProfile`] (event -> CoT XML), and it carries a round-trip
//! conformance test proving the modeled fields survive `canonical -> CoT ->
//! canonical` unchanged.
//!
//! The XML handling is deliberately minimal (no XML dependency) so the data flow
//! stays readable; real connectors should use a hardened parser.

use std::collections::HashMap;

use ajar_connector::{Connector, Event, EventBuilder, OutboundProfile};

/// A CoT connector bound to one source identity.
///
/// CoT messages do not carry an Ajar source identity, so it comes from the
/// connector's configuration (and matches the connector's signing-key profile).
#[derive(Debug, Clone)]
pub struct CotConnector {
    source_id: String,
}

/// Failure modes when normalizing a CoT message.
#[derive(Debug, PartialEq, Eq)]
pub enum CotError {
    /// No `<event>` element, or it was missing a required attribute.
    Malformed(&'static str),
    /// The canonical event failed to build (propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for CotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CotError::Malformed(what) => write!(f, "malformed CoT: {what}"),
            CotError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for CotError {}

impl CotConnector {
    /// Creates a connector that signs as `source_id`.
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
        }
    }
}

impl Connector for CotConnector {
    type Error = CotError;

    fn normalize(&self, native: &[u8]) -> Result<Event, Self::Error> {
        let xml = std::str::from_utf8(native).map_err(|_| CotError::Malformed("not UTF-8"))?;

        let event_attrs = tag_attrs(xml, "event").ok_or(CotError::Malformed("no <event>"))?;
        let uid = event_attrs
            .get("uid")
            .ok_or(CotError::Malformed("event/@uid"))?;
        let cot_type = event_attrs
            .get("type")
            .ok_or(CotError::Malformed("event/@type"))?;
        let time = event_attrs
            .get("time")
            .ok_or(CotError::Malformed("event/@time"))?;

        let mut builder = EventBuilder::new(self.source_id.clone(), cot_type_to_entity(cot_type))
            .id(uid.clone())
            .timestamp(time.clone());

        if let Some(point) = tag_attrs(xml, "point") {
            if let (Some(lat), Some(lon)) = (point.get("lat"), point.get("lon")) {
                let lat = lat.parse().map_err(|_| CotError::Malformed("point/@lat"))?;
                let lon = lon.parse().map_err(|_| CotError::Malformed("point/@lon"))?;
                let hae = point.get("hae").and_then(|h| h.parse().ok()).unwrap_or(0.0);
                builder = builder.location(lat, lon, hae);
            }
        }

        builder.build().map_err(|e| CotError::Build(e.to_string()))
    }
}

impl OutboundProfile for CotConnector {
    fn target(&self) -> &str {
        "Cursor-on-Target"
    }
    fn slug(&self) -> &str {
        "tak-cot"
    }
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn modeled_fields(&self) -> &[&str] {
        &["id", "entity_type", "timestamp", "location"]
    }
    fn lossy_fields(&self) -> &[&str] {
        // CoT has no home for these, so an outbound CoT render drops them.
        &[
            "source_id",
            "payload",
            "policy_tags",
            "confidence",
            "attributes",
        ]
    }

    fn render(&self, event: &Event) -> Vec<u8> {
        let cot_type = entity_to_cot(&event.entity_type);
        let (lat, lon, hae) = match &event.location {
            Some(g) => (g.latitude, g.longitude, g.altitude_m),
            None => (0.0, 0.0, 0.0),
        };
        let xml = format!(
            "<event version=\"2.0\" uid=\"{uid}\" type=\"{ty}\" time=\"{t}\" start=\"{t}\" stale=\"{t}\">\
<point lat=\"{lat}\" lon=\"{lon}\" hae=\"{hae}\" ce=\"9999999.0\" le=\"9999999.0\"/>\
</event>",
            uid = event.id,
            ty = cot_type,
            t = event.timestamp,
        );
        xml.into_bytes()
    }
}

/// Maps a CoT type code to a namespaced entity type. Unknown codes fall back to
/// a vendor extension namespace so nothing is silently dropped.
fn cot_type_to_entity(cot_type: &str) -> String {
    match cot_type {
        "a-f-A" | "a-f-A-M-F-Q" => "mim:aircraft".to_string(),
        "a-f-S" => "mim:vessel".to_string(),
        "a-f-G-U-C-D" => "mim:unit".to_string(),
        other => format!("x:cot:{}", other.replace('-', "_")),
    }
}

/// Inverse of [`cot_type_to_entity`] for the canonical mappings.
fn entity_to_cot(entity_type: &str) -> String {
    match entity_type {
        "mim:aircraft" => "a-f-A".to_string(),
        "mim:vessel" => "a-f-S".to_string(),
        "mim:unit" => "a-f-G-U-C-D".to_string(),
        other => other
            .strip_prefix("x:cot:")
            .map(|s| s.replace('_', "-"))
            .unwrap_or_else(|| "a-u-G".to_string()),
    }
}

/// Returns the attribute map of the first `<tag ...>` (or `<tag ... />`) element.
fn tag_attrs(xml: &str, tag: &str) -> Option<HashMap<String, String>> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after = &xml[start + open.len()..];
    // The next char after the tag name must be whitespace or the close, so we
    // don't match e.g. <eventfoo when looking for <event.
    let first = after.chars().next()?;
    if !first.is_whitespace() && first != '>' && first != '/' {
        return None;
    }
    let end = after.find('>')?;
    let attr_str = after[..end].trim_end_matches('/').trim();
    Some(parse_attrs(attr_str))
}

/// Parses a run of `key="value"` XML attributes.
fn parse_attrs(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            break;
        }
        let key = &s[key_start..i];
        i += 1; // '='
        if i >= bytes.len() || bytes[i] != b'"' {
            break;
        }
        i += 1; // opening quote
        let val_start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let val = &s[val_start..i];
        i += 1; // closing quote
        map.insert(key.to_string(), val.to_string());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::canonical_bytes;

    const SAMPLE: &str = r#"<event version="2.0" uid="0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d" type="a-f-A" time="2026-06-04T02:00:00Z" start="2026-06-04T02:00:00Z" stale="2026-06-04T02:00:30Z"><point lat="26.4" lon="50.9" hae="1200.0" ce="10.0" le="10.0"/></event>"#;

    #[test]
    fn normalizes_cot_to_canonical_event() {
        let conn = CotConnector::new("ad-radar-7");
        let event = conn.normalize(SAMPLE.as_bytes()).unwrap();
        assert_eq!(event.entity_type, "mim:aircraft");
        assert_eq!(event.id, "0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d");
        let loc = event.location.as_ref().unwrap();
        assert_eq!(loc.latitude, 26.4);
        assert_eq!(loc.altitude_m, 1200.0);
    }

    /// Round-trip conformance: canonical -> CoT -> canonical is identity over the
    /// modeled fields (lossy fields left at defaults so full bytes match).
    #[test]
    fn round_trip_preserves_modeled_fields() {
        let conn = CotConnector::new("ad-radar-7");
        let original = EventBuilder::new("ad-radar-7", "mim:aircraft")
            .id("0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d")
            .timestamp("2026-06-04T02:00:00Z")
            .location(26.4, 50.9, 1200.0)
            .build()
            .unwrap();

        let rendered = conn.render(&original);
        let back = conn.normalize(&rendered).unwrap();

        assert_eq!(
            canonical_bytes(&original),
            canonical_bytes(&back),
            "modeled fields must survive the CoT round trip"
        );
    }
}
