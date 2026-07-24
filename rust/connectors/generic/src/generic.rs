// SPDX-License-Identifier: Apache-2.0
//! The config-driven parser: a native JSON object or CSV row in, a canonical event
//! out, entirely under the control of a [`Mapping`]. No per-source code.
//!
//! Like every connector it is fail-closed on untrusted input: a record that is not
//! valid JSON/CSV, or is missing a mapped required field, is a typed error the
//! runtime counts and logs — never a panic, never a fabricated field.

use std::collections::BTreeMap;

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError, Tactical};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::mapping::{Format, Mapping, TimestampFormat};

/// Why a record could not be mapped to an event.
#[derive(Debug, PartialEq, Eq)]
pub enum GenericError {
    /// The frame was not valid UTF-8 / JSON / CSV for the configured format.
    Decode(String),
    /// A field the mapping requires was absent from the record.
    Missing(String),
    /// A numeric field (lat/lon/alt/timestamp) was present but unparseable.
    BadNumber(String),
    /// A timestamp could not be converted to RFC 3339.
    Time(String),
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for GenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenericError::Decode(e) => write!(f, "cannot decode record: {e}"),
            GenericError::Missing(k) => write!(f, "record missing mapped field {k:?}"),
            GenericError::BadNumber(k) => write!(f, "field {k:?} is not a number"),
            GenericError::Time(e) => write!(f, "bad timestamp: {e}"),
            GenericError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for GenericError {}

/// Maps records to events per a [`Mapping`], for one connector identity.
pub struct GenericParser {
    source_id: String,
    mapping: Mapping,
    enrichment: Enrichment,
}

impl GenericParser {
    pub fn new(source_id: impl Into<String>, mapping: Mapping, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            mapping,
            enrichment,
        }
    }

    /// Flatten one native frame into `field -> string value`.
    fn record(&self, frame: &[u8]) -> Result<BTreeMap<String, String>, GenericError> {
        let text =
            std::str::from_utf8(frame).map_err(|_| GenericError::Decode("not UTF-8".into()))?;
        match self.mapping.format {
            Format::Json => {
                let value: serde_json::Value = serde_json::from_str(text.trim())
                    .map_err(|e| GenericError::Decode(e.to_string()))?;
                let obj = value
                    .as_object()
                    .ok_or_else(|| GenericError::Decode("expected a JSON object".into()))?;
                Ok(obj
                    .iter()
                    .map(|(k, v)| (k.clone(), json_scalar(v)))
                    .collect())
            }
            Format::Csv => {
                let parts = text.trim().split(&self.mapping.delimiter);
                Ok(self
                    .mapping
                    .columns
                    .iter()
                    .cloned()
                    .zip(parts.map(|p| p.trim().to_string()))
                    .collect())
            }
        }
    }

    /// Map one native frame into a canonical event.
    pub fn to_event(&self, frame: &[u8]) -> Result<Event, GenericError> {
        let rec = self.record(frame)?;
        let m = &self.mapping;

        let mut b = EventBuilder::new(self.source_id.clone(), m.entity_type.clone()).new_id();

        // Observation time: mapped field (converted to RFC 3339) or receipt time.
        b = match &m.timestamp_field {
            Some(field) => {
                let raw = rec
                    .get(field)
                    .ok_or_else(|| GenericError::Missing(field.clone()))?;
                b.timestamp(to_rfc3339(raw, m.timestamp_format)?)
            }
            None => b.now(),
        };

        // Location only when both lat and lon are mapped and present.
        if let (Some(latf), Some(lonf)) = (&m.lat_field, &m.lon_field) {
            if let (Some(lat), Some(lon)) = (rec.get(latf), rec.get(lonf)) {
                let lat = lat
                    .parse()
                    .map_err(|_| GenericError::BadNumber(latf.clone()))?;
                let lon = lon
                    .parse()
                    .map_err(|_| GenericError::BadNumber(lonf.clone()))?;
                let alt = match &m.alt_field {
                    Some(altf) => rec
                        .get(altf)
                        .map(|v| v.parse().map_err(|_| GenericError::BadNumber(altf.clone())))
                        .transpose()?
                        .unwrap_or(0.0),
                    None => 0.0,
                };
                b = b.location(lat, lon, alt);
            }
        }

        // Detection/track confidence -> the event's first-class field.
        if let Some(field) = &m.confidence_field {
            if let Some(raw) = rec.get(field) {
                let v: f64 = raw
                    .parse()
                    .map_err(|_| GenericError::BadNumber(field.clone()))?;
                let v = if v > 1.0 { v / 100.0 } else { v };
                b = b.confidence(v.clamp(0.0, 1.0));
            }
        }

        // A configured default affiliation, so a generic feed reads consistently
        // on the COP alongside the format-specific connectors.
        if let Some(aff) = &self.enrichment.affiliation {
            b = b.tactical(&self.enrichment, "affiliation", aff.clone());
        }

        // Explicitly-mapped governed attributes and ungoverned metadata.
        for (src, key) in &m.attributes {
            if let Some(v) = rec.get(src) {
                b = b.attribute(key.as_str(), v.as_str());
            }
        }
        for (src, key) in &m.metadata {
            if let Some(v) = rec.get(src) {
                b = b.metadata(key.as_str(), v.as_str());
            }
        }

        b.build().map_err(|e| GenericError::Build(e.to_string()))
    }
}

impl FrameParser for GenericParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        Ok(vec![self
            .to_event(frame)
            .map_err(|e| Box::new(e) as ParseError)?])
    }
}

/// A JSON scalar as a plain string (strings unquoted, numbers/bools stringified);
/// nested structures fall back to their JSON text.
fn json_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn to_rfc3339(raw: &str, format: TimestampFormat) -> Result<String, GenericError> {
    let dt = match format {
        TimestampFormat::Rfc3339 => return Ok(raw.to_string()),
        TimestampFormat::EpochMillis => {
            let ms: i128 = raw
                .parse()
                .map_err(|_| GenericError::Time(format!("{raw:?}")))?;
            OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000)
                .map_err(|e| GenericError::Time(e.to_string()))?
        }
        TimestampFormat::EpochSeconds => {
            let s: i64 = raw
                .parse()
                .map_err(|_| GenericError::Time(format!("{raw:?}")))?;
            OffsetDateTime::from_unix_timestamp(s).map_err(|e| GenericError::Time(e.to_string()))?
        }
    };
    dt.format(&Rfc3339)
        .map_err(|e| GenericError::Time(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::Mapping;

    fn mapping(toml_str: &str) -> Mapping {
        #[derive(serde::Deserialize)]
        struct W {
            mapping: Mapping,
        }
        toml::from_str::<W>(toml_str).unwrap().mapping
    }

    fn json_mapping() -> Mapping {
        mapping(
            r#"
            [mapping]
            format = "json"
            entity_type = "mim:sensor"
            timestamp_field = "ts"
            lat_field = "lat"
            lon_field = "lon"
            [mapping.attributes]
            speed = "speed"
            [mapping.metadata]
            device = "device_id"
            "#,
        )
    }

    #[test]
    fn maps_confidence_field_and_default_affiliation() {
        let m = mapping(
            r#"
            [mapping]
            format = "json"
            entity_type = "mim:sensor"
            timestamp_field = "ts"
            confidence_field = "quality"
            "#,
        );
        let enrichment = Enrichment::governing(["affiliation"]).with_affiliation("friendly");
        let ev = GenericParser::new("gen-1", m, enrichment)
            .to_event(br#"{"ts":"2026-06-10T08:00:00Z","quality":87}"#)
            .unwrap();
        assert!((ev.confidence - 0.87).abs() < 1e-9); // percent normalized
        assert!(ev
            .attributes
            .iter()
            .any(|a| a.key == "affiliation" && a.value == "friendly"));
    }

    #[test]
    fn maps_a_json_record() {
        let p = GenericParser::new("gen-1", json_mapping(), Enrichment::default());
        let ev = p
            .to_event(br#"{"device":"abc-123","ts":"2026-06-10T08:00:00Z","lat":26.4,"lon":50.9,"speed":110}"#)
            .unwrap();
        assert_eq!(ev.entity_type, "mim:sensor");
        assert_eq!(ev.timestamp, "2026-06-10T08:00:00Z");
        assert_eq!(ev.location.as_ref().unwrap().latitude, 26.4);
        assert!(ev
            .attributes
            .iter()
            .any(|a| a.key == "speed" && a.value == "110"));
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "device_id" && m.value == "abc-123"));
    }

    #[test]
    fn maps_a_csv_row_with_epoch_time() {
        let m = mapping(
            r#"
            [mapping]
            format = "csv"
            columns = ["t","id","lat","lon"]
            entity_type = "mim:vessel"
            timestamp_field = "t"
            timestamp_format = "epoch-seconds"
            lat_field = "lat"
            lon_field = "lon"
            [mapping.metadata]
            id = "hull"
            "#,
        );
        let ev = GenericParser::new("gen-2", m, Enrichment::default())
            .to_event(b"1781078400,HULL7,26.4,50.9")
            .unwrap();
        assert_eq!(ev.timestamp, "2026-06-10T08:00:00Z");
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "hull" && m.value == "HULL7"));
    }

    #[test]
    fn malformed_json_is_rejected_not_panicked() {
        let p = GenericParser::new("gen-1", json_mapping(), Enrichment::default());
        assert!(matches!(
            p.to_event(b"{not json"),
            Err(GenericError::Decode(_))
        ));
    }

    #[test]
    fn missing_timestamp_field_is_rejected() {
        let p = GenericParser::new("gen-1", json_mapping(), Enrichment::default());
        assert_eq!(
            p.to_event(br#"{"lat":1,"lon":2}"#),
            Err(GenericError::Missing("ts".into()))
        );
    }
}
