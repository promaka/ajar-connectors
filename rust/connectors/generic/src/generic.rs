// SPDX-License-Identifier: Apache-2.0
//! The config-driven parser: one JSON object or CSV row per frame, mapped to one
//! event by a [`Mapping`].

use std::borrow::Cow;
use std::collections::BTreeMap;

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::mapping::{Format, Mapping, TimestampFormat};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum GenericError {
    #[error("cannot decode record: {0}")]
    Decode(String),
    #[error("record missing mapped field {0:?}")]
    Missing(String),
    #[error("field {0:?} is not a number")]
    BadNumber(String),
    #[error("bad timestamp: {0}")]
    Time(String),
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

enum Record {
    Json(Value),
    Csv(BTreeMap<String, String>),
}

impl Record {
    /// A field's value as text: a JSON key, a JSON pointer starting with `/`, or a CSV column.
    fn get(&self, field: &str) -> Option<Cow<'_, str>> {
        match self {
            Record::Json(value) => match field.starts_with('/') {
                true => value.pointer(field),
                false => value.get(field),
            }
            .map(json_text),
            Record::Csv(columns) => columns.get(field).map(|v| Cow::Borrowed(v.as_str())),
        }
    }
}

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

    fn record(&self, frame: &[u8]) -> Result<Record, GenericError> {
        let text =
            std::str::from_utf8(frame).map_err(|_| GenericError::Decode("not UTF-8".into()))?;
        match self.mapping.format {
            Format::Json => {
                let value: Value = serde_json::from_str(text.trim())
                    .map_err(|e| GenericError::Decode(e.to_string()))?;
                if !value.is_object() {
                    return Err(GenericError::Decode("expected a JSON object".into()));
                }
                Ok(Record::Json(value))
            }
            Format::Csv => {
                let parts = text.trim().split(&self.mapping.delimiter);
                Ok(Record::Csv(
                    self.mapping
                        .columns
                        .iter()
                        .cloned()
                        .zip(parts.map(|p| p.trim().to_string()))
                        .collect(),
                ))
            }
        }
    }

    pub fn to_event(&self, frame: &[u8]) -> Result<Event, GenericError> {
        let rec = self.record(frame)?;
        let m = &self.mapping;

        let entity_type = m
            .entity_type_field
            .as_ref()
            .and_then(|field| rec.get(field))
            .and_then(|value| m.entity_types.get(value.as_ref()))
            .unwrap_or(&m.entity_type);
        let mut b = EventBuilder::new(self.source_id.clone(), entity_type.clone())
            .new_id()
            .payload(frame.to_vec());

        b = match &m.timestamp_field {
            Some(field) => {
                let raw = rec
                    .get(field)
                    .ok_or_else(|| GenericError::Missing(field.clone()))?;
                b.timestamp(to_rfc3339(&raw, m.timestamp_format)?)
            }
            None => b.now(),
        };

        if let (Some(latf), Some(lonf)) = (&m.lat_field, &m.lon_field) {
            if let (Some(lat), Some(lon)) = (rec.get(latf), rec.get(lonf)) {
                let lat = lat
                    .parse()
                    .map_err(|_| GenericError::BadNumber(latf.clone()))?;
                let lon = lon
                    .parse()
                    .map_err(|_| GenericError::BadNumber(lonf.clone()))?;
                let alt_m = match &m.alt_field {
                    Some(altf) => rec
                        .get(altf)
                        .map(|v| v.parse().map_err(|_| GenericError::BadNumber(altf.clone())))
                        .transpose()?
                        .unwrap_or(0.0),
                    None => 0.0,
                };
                b = b.location(lat, lon, alt_m);
            }
        }

        if let Some(field) = &m.confidence_field {
            if let Some(raw) = rec.get(field) {
                let v: f64 = raw
                    .parse()
                    .map_err(|_| GenericError::BadNumber(field.clone()))?;
                // A value above 1 is a percentage.
                let v = if v > 1.0 { v / 100.0 } else { v };
                b = b.confidence(v.clamp(0.0, 1.0));
            }
        }

        if let Some(aff) = &self.enrichment.hostility {
            b = b.attribute("hostility", aff.clone());
        }

        for (src, key) in &m.attributes {
            let Some(raw) = rec.get(src) else {
                continue;
            };
            let value = match m.values.get(key) {
                Some(table) => table.get(raw.as_ref()).map(String::as_str),
                None => Some(raw.as_ref()),
            };
            if let Some(value) = value {
                b = b.attribute(key.as_str(), value);
            }
        }
        for (src, key) in &m.metadata {
            if let Some(v) = rec.get(src) {
                b = b.metadata(key.as_str(), v.as_ref());
            }
        }

        Ok(b.build()?)
    }
}

impl FrameParser for GenericParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        Ok(vec![self.to_event(frame)?])
    }
}

/// Strings unquoted, null empty, arrays and objects as JSON text.
fn json_text(v: &Value) -> Cow<'_, str> {
    match v {
        Value::String(s) => Cow::Borrowed(s),
        Value::Null => Cow::Borrowed(""),
        other => Cow::Owned(other.to_string()),
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
    fn maps_confidence_field_and_default_hostility() {
        let m = mapping(
            r#"
            [mapping]
            format = "json"
            entity_type = "mim:sensor"
            timestamp_field = "ts"
            confidence_field = "quality"
            "#,
        );
        let enrichment = Enrichment::default().with_hostility("Friend");
        let ev = GenericParser::new("gen-1", m, enrichment)
            .to_event(br#"{"ts":"2026-06-10T08:00:00Z","quality":87}"#)
            .unwrap();
        assert!((ev.confidence - 0.87).abs() < 1e-9, "percent normalised");
        assert!(ev
            .attributes
            .iter()
            .any(|a| a.key == "hostility" && a.value == "Friend"));
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

    fn track_mapping() -> Mapping {
        mapping(
            r#"
            [mapping]
            format = "json"
            entity_type = "mim:object"
            entity_type_field = "/kind"
            timestamp_field = "/position/time"
            lat_field = "/position/lat"
            lon_field = "/position/lon"
            [mapping.entity_types]
            AIR = "mim:aircraft"
            [mapping.attributes]
            "/affiliation" = "hostility"
            [mapping.values.hostility]
            H = "Hostile"
            F = "Friend"
            [mapping.metadata]
            "/ref/id" = "source_uid"
            "/affiliation" = "affiliation_code"
            "#,
        )
    }

    fn track(kind: &str, affiliation: &str) -> Event {
        let frame = format!(
            r#"{{"kind":"{kind}","affiliation":"{affiliation}","ref":{{"id":"T-7"}},
               "position":{{"time":"2026-06-10T08:00:00Z","lat":60.1,"lon":10.2}}}}"#
        );
        GenericParser::new("gen-1", track_mapping(), Enrichment::default())
            .to_event(frame.as_bytes())
            .unwrap()
    }

    fn attribute<'e>(ev: &'e Event, key: &str) -> Option<&'e str> {
        ev.attributes
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    #[test]
    fn json_pointers_reach_nested_fields() {
        let ev = track("AIR", "H");
        assert_eq!(ev.timestamp, "2026-06-10T08:00:00Z");
        assert_eq!(ev.location.as_ref().unwrap().longitude, 10.2);
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == "T-7"));
    }

    #[test]
    fn value_table_translates_an_attribute() {
        let ev = track("AIR", "H");
        assert_eq!(attribute(&ev, "hostility"), Some("Hostile"));
        assert!(
            ev.metadata
                .iter()
                .any(|m| m.key == "affiliation_code" && m.value == "H"),
            "metadata keeps the native code"
        );
    }

    #[test]
    fn value_missing_from_its_table_emits_no_attribute() {
        assert_eq!(attribute(&track("AIR", "Q"), "hostility"), None);
    }

    #[test]
    fn entity_type_follows_the_type_field() {
        assert_eq!(track("AIR", "F").entity_type, "mim:aircraft");
        assert_eq!(track("SURFACE", "F").entity_type, "mim:object");
    }

    #[test]
    fn declared_covers_every_entity_type() {
        let declared = track_mapping().declared(None);
        let types: Vec<&str> = declared.iter().map(|d| d.entity_type.as_str()).collect();
        assert_eq!(types, ["mim:object", "mim:aircraft"]);
    }

    #[test]
    fn declared_checks_table_values_and_default_hostility() {
        let fixed = &track_mapping().declared(Some("Unknown"))[0].fixed_values;
        assert!(fixed.contains(&("hostility".into(), "Hostile".into())));
        assert!(fixed.contains(&("hostility".into(), "Unknown".into())));
    }

    #[test]
    fn json_pointer_in_a_csv_mapping_is_refused() {
        let mut m = track_mapping();
        m.format = Format::Csv;
        m.columns = vec!["kind".into()];
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("CSV mapping"), "{err}");
    }

    #[test]
    fn value_table_for_an_unmapped_attribute_is_refused() {
        let mut m = track_mapping();
        m.values.insert("speed".into(), BTreeMap::new());
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("[mapping.values.speed]"), "{err}");
    }

    #[test]
    fn type_field_without_a_table_is_refused() {
        let mut m = track_mapping();
        m.entity_types.clear();
        assert!(m.validate().is_err());
    }

    #[test]
    fn unknown_mapping_key_is_refused() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)] // only parsed
        struct W {
            mapping: Mapping,
        }
        let err = toml::from_str::<W>(
            "[mapping]\nformat = \"json\"\nentity_type = \"mim:object\"\nlat = \"y\"",
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown field `lat`"), "{err}");
    }

    #[test]
    fn malformed_json_is_rejected() {
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
