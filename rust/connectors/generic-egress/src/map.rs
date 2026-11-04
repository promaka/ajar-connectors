// SPDX-License-Identifier: Apache-2.0
//! Render a governed event as the consumer's JSON: consumer field names on the
//! left of the mapping, event paths on the right. A path absent from an event
//! is omitted from that object, not sent as null.

use std::collections::BTreeMap;

use ajar_connector::Event;
use serde_json::{Map, Number, Value};

use crate::label::{confidentiality_label, LabelConfig};

/// The event paths a mapping may name.
const PATHS: [&str; 9] = [
    "id",
    "source_id",
    "entity_type",
    "timestamp",
    "lat",
    "lon",
    "alt_m",
    "confidence",
    "policy_tags",
];

/// Checked at startup, so a mistyped path fails there instead of never
/// delivering its field.
pub fn validate_path(path: &str) -> anyhow::Result<()> {
    if PATHS.contains(&path) || path.starts_with("attr:") || path.starts_with("meta:") {
        return Ok(());
    }
    anyhow::bail!(
        "unknown event path {path:?}: expected one of {PATHS:?}, attr:<name> or meta:<name>"
    )
}

fn lookup(event: &Event, path: &str) -> Option<Value> {
    if let Some(name) = path.strip_prefix("attr:") {
        return event
            .attributes
            .iter()
            .find(|a| a.key == name)
            .map(|a| Value::String(a.value.clone()));
    }
    if let Some(name) = path.strip_prefix("meta:") {
        return event
            .metadata
            .iter()
            .find(|m| m.key == name)
            .map(|m| Value::String(m.value.clone()));
    }
    let num = |v: f64| Number::from_f64(v).map(Value::Number);
    match path {
        "id" => Some(Value::String(event.id.clone())),
        "source_id" => Some(Value::String(event.source_id.clone())),
        "entity_type" => Some(Value::String(event.entity_type.clone())),
        "timestamp" => Some(Value::String(event.timestamp.clone())),
        "lat" => event.location.as_ref().and_then(|l| num(l.latitude)),
        "lon" => event.location.as_ref().and_then(|l| num(l.longitude)),
        "alt_m" => event.location.as_ref().and_then(|l| num(l.altitude_m)),
        "confidence" => num(event.confidence),
        "policy_tags" => Some(Value::Array(
            event
                .policy_tags
                .iter()
                .map(|t| Value::String(t.clone()))
                .collect(),
        )),
        _ => None,
    }
}

/// What happens to governed content the mapping does not name. There is no
/// drop variant, so a mapping cannot strip content off a marked track.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unmapped {
    /// Deliver it under `unmapped`.
    #[default]
    Include,
    /// Refuse the whole event.
    Refuse,
}

/// One consumer object for one governed event, or `None` when
/// `Unmapped::Refuse` rejects it.
///
/// The event id, the policy tags and the governance block are in every object.
/// A mapping can rename the id and the tags by naming their paths; it cannot
/// omit them.
pub fn render(
    event: &Event,
    fields: &BTreeMap<String, String>,
    unmapped: Unmapped,
    label: Option<&LabelConfig>,
) -> Option<Value> {
    let mut out = Map::new();
    let mut mapped_paths: Vec<&str> = Vec::with_capacity(fields.len());
    for (consumer_name, path) in fields {
        mapped_paths.push(path.as_str());
        if let Some(v) = lookup(event, path) {
            out.insert(consumer_name.clone(), v);
        }
    }

    if !mapped_paths.contains(&"id") {
        out.insert("event_id".into(), Value::String(event.id.clone()));
    }
    if !mapped_paths.contains(&"policy_tags") {
        out.insert(
            "policy_tags".into(),
            lookup(event, "policy_tags").unwrap_or(Value::Array(vec![])),
        );
    }
    out.insert(
        "governance".into(),
        serde_json::json!({ "egress_signature": "verified" }),
    );

    if let Some(cfg) = label {
        if let Some(l) = confidentiality_label(cfg, event) {
            out.insert("confidentiality_label".into(), l);
        }
    }

    let mut extra_attrs = Map::new();
    for a in &event.attributes {
        let name = a.key.as_str();
        if !mapped_paths
            .iter()
            .any(|p| p.strip_prefix("attr:") == Some(name))
        {
            extra_attrs.insert(a.key.clone(), Value::String(a.value.clone()));
        }
    }
    let mut extra_meta = Map::new();
    for m in &event.metadata {
        let name = m.key.as_str();
        if !mapped_paths
            .iter()
            .any(|p| p.strip_prefix("meta:") == Some(name))
        {
            extra_meta.insert(m.key.clone(), Value::String(m.value.clone()));
        }
    }
    if !extra_attrs.is_empty() || !extra_meta.is_empty() {
        match unmapped {
            Unmapped::Refuse => return None,
            Unmapped::Include => {
                let mut u = Map::new();
                if !extra_attrs.is_empty() {
                    u.insert("attributes".into(), Value::Object(extra_attrs));
                }
                if !extra_meta.is_empty() {
                    u.insert("metadata".into(), Value::Object(extra_meta));
                }
                out.insert("unmapped".into(), Value::Object(u));
            }
        }
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector::EventBuilder;

    fn mapping(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn event() -> Event {
        EventBuilder::new("coastal-radar", "mim:vessel")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .location(59.33, 18.07, 0.0)
            .attribute("speed", "8.20")
            .metadata("source_uid", "MMSI-265547210")
            .build()
            .unwrap()
    }

    #[test]
    fn renders_the_consumer_shape() {
        let out = render(
            &event(),
            &mapping(&[
                ("vesselId", "meta:source_uid"),
                ("speedMs", "attr:speed"),
                ("latitude", "lat"),
                ("kind", "entity_type"),
            ]),
            Unmapped::Include,
            None,
        )
        .unwrap();
        assert_eq!(out["vesselId"], "MMSI-265547210");
        assert_eq!(out["speedMs"], "8.20");
        assert_eq!(out["kind"], "mim:vessel");
        assert!((out["latitude"].as_f64().unwrap() - 59.33).abs() < 1e-9);
    }

    #[test]
    fn id_and_markings_always_delivered() {
        let out = render(
            &event(),
            &mapping(&[("s", "attr:speed")]),
            Unmapped::Include,
            None,
        )
        .unwrap();
        assert!(out["event_id"].is_string());
        assert!(out["policy_tags"].is_array());
        assert_eq!(out["governance"]["egress_signature"], "verified");
        assert!(
            out.get("confidentiality_label").is_none(),
            "no label config means the delivered format is unchanged"
        );
    }

    fn label_cfg() -> LabelConfig {
        LabelConfig {
            policy_identifier: "TEST-POLICY".into(),
        }
    }

    #[test]
    fn label_is_added_alongside_the_tags() {
        let tagged = EventBuilder::new("coastal-radar", "mim:vessel")
            .new_id()
            .timestamp("2026-06-10T08:00:00Z")
            .policy_tag("class:secret")
            .policy_tag("rel:NATO")
            .build()
            .unwrap();
        let out = render(
            &tagged,
            &mapping(&[]),
            Unmapped::Include,
            Some(&label_cfg()),
        )
        .unwrap();
        assert!(out["event_id"].is_string());
        assert!(out["policy_tags"].is_array());
        assert_eq!(
            out["confidentiality_label"]["policyIdentifier"],
            "TEST-POLICY"
        );
        assert_eq!(out["confidentiality_label"]["classification"], "SECRET");
    }

    #[test]
    fn untagged_event_gets_no_label() {
        let out = render(
            &event(),
            &mapping(&[]),
            Unmapped::Include,
            Some(&label_cfg()),
        )
        .unwrap();
        assert!(out.get("confidentiality_label").is_none());
    }

    #[test]
    fn renamed_markings_are_not_duplicated() {
        let out = render(
            &event(),
            &mapping(&[
                ("trackRef", "id"),
                ("marking", "policy_tags"),
                ("s", "attr:speed"),
                ("u", "meta:source_uid"),
            ]),
            Unmapped::Include,
            None,
        )
        .unwrap();
        assert!(out["trackRef"].is_string());
        assert!(out["marking"].is_array());
        assert!(out.get("event_id").is_none(), "renamed, not duplicated");
        assert_eq!(out["governance"]["egress_signature"], "verified");
    }

    #[test]
    fn unmapped_content_is_included() {
        let out = render(
            &event(),
            &mapping(&[("latitude", "lat")]),
            Unmapped::Include,
            None,
        )
        .unwrap();
        assert_eq!(out["unmapped"]["attributes"]["speed"], "8.20");
        assert_eq!(out["unmapped"]["metadata"]["source_uid"], "MMSI-265547210");
    }

    #[test]
    fn refuse_rejects_unmapped_content() {
        assert!(render(
            &event(),
            &mapping(&[("latitude", "lat")]),
            Unmapped::Refuse,
            None
        )
        .is_none());
    }

    #[test]
    fn refuse_accepts_fully_mapped_event() {
        assert!(render(
            &event(),
            &mapping(&[
                ("latitude", "lat"),
                ("s", "attr:speed"),
                ("u", "meta:source_uid")
            ]),
            Unmapped::Refuse,
            None
        )
        .is_some());
    }

    #[test]
    fn absent_field_is_omitted() {
        let out = render(
            &event(),
            &mapping(&[
                ("callsign", "attr:callsign"),
                ("s", "attr:speed"),
                ("u", "meta:source_uid"),
            ]),
            Unmapped::Include,
            None,
        )
        .unwrap();
        assert!(out.get("callsign").is_none());
    }

    #[test]
    fn unknown_path_is_refused() {
        assert!(validate_path("meta:anything").is_ok());
        assert!(validate_path("attrs:speed").is_err());
        assert!(validate_path("latitude").is_err());
    }
}
