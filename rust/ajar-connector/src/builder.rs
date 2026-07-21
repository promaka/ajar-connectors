// SPDX-License-Identifier: Apache-2.0
//! Ergonomic, fail-closed construction of canonical [`Event`]s.
//!
//! [`EventBuilder`] exists so a connector author *cannot* emit a non-canonical
//! event by accident. It auto-sorts attributes, rejects duplicate keys, enforces
//! the contract's required fields and limits, and offers UUIDv7 / RFC 3339
//! helpers. `received_at` is intentionally not exposed — Ajar stamps its own
//! authoritative ingest clock; a connector that sets it would be ignored.

use crate::error::BuildError;
use crate::event::{Attribute, Event, GeoPoint};

/// Maximum number of attributes per event (contract limit, §3).
pub const MAX_ATTRIBUTES: usize = 128;
/// Maximum number of metadata entries per event (contract limit, §3).
pub const MAX_METADATA: usize = 128;
/// Maximum number of policy tags per event (contract limit, §3).
pub const MAX_POLICY_TAGS: usize = 64;

const SCHEMA_VERSION: &str = "v1";

/// Builds a canonical [`Event`]. Construct with [`EventBuilder::new`], chain
/// setters, then call [`EventBuilder::build`].
#[derive(Debug, Clone)]
pub struct EventBuilder {
    source_id: String,
    entity_type: String,
    id: Option<String>,
    timestamp: Option<String>,
    location: Option<GeoPoint>,
    payload: Vec<u8>,
    policy_tags: Vec<String>,
    confidence: f64,
    attributes: Vec<(String, String)>,
    metadata: Vec<(String, String)>,
    strict_entity_namespace: bool,
}

impl EventBuilder {
    /// Starts a builder for the given source identity and entity type.
    ///
    /// `entity_type` is expected to be namespaced (`mim:<type>` or
    /// `x:<vendor>:<type>`); see [`EventBuilder::allow_unnamespaced_entity_type`]
    /// to opt out for migration.
    pub fn new(source_id: impl Into<String>, entity_type: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            entity_type: entity_type.into(),
            id: None,
            timestamp: None,
            location: None,
            payload: Vec::new(),
            policy_tags: Vec::new(),
            confidence: 0.0,
            attributes: Vec::new(),
            metadata: Vec::new(),
            strict_entity_namespace: true,
        }
    }

    /// Sets the event id explicitly. Prefer [`EventBuilder::new_id`] unless you
    /// are carrying an id through from an upstream system.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Generates a fresh UUIDv7 id (time-ordered, recommended).
    pub fn new_id(mut self) -> Self {
        self.id = Some(uuid::Uuid::now_v7().to_string());
        self
    }

    /// Sets the source observation timestamp (RFC 3339).
    pub fn timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    /// Sets the source observation timestamp to now (RFC 3339, UTC).
    pub fn now(mut self) -> Self {
        let now = time::OffsetDateTime::now_utc();
        // Rfc3339 formatting of a valid OffsetDateTime cannot fail.
        self.timestamp = Some(
            now.format(&time::format_description::well_known::Rfc3339)
                .expect("RFC 3339 formatting of current time"),
        );
        self
    }

    /// Sets an optional geospatial position.
    pub fn location(mut self, latitude: f64, longitude: f64, altitude_m: f64) -> Self {
        self.location = Some(GeoPoint {
            latitude,
            longitude,
            altitude_m,
        });
        self
    }

    /// Sets the opaque payload bytes. Keep this small — a reference or metadata,
    /// never bulk media.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Adds one policy tag (e.g. `class:secret`, `rel:DEU`).
    pub fn policy_tag(mut self, tag: impl Into<String>) -> Self {
        self.policy_tags.push(tag.into());
        self
    }

    /// Sets the detection/correlation confidence in `[0.0, 1.0]`.
    pub fn confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    /// Adds one structured attribute. Order does not matter — the builder sorts
    /// by key at [`EventBuilder::build`]. Duplicate keys are rejected there.
    pub fn attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Adds one ungoverned passthrough metadata entry (ADR-0030): a vendor-specific
    /// field carried and audited opaquely, but not type-validated or correlated
    /// (e.g. a source's native identifier). Order does not matter — the builder
    /// sorts by key at [`EventBuilder::build`]. Duplicate keys are rejected there.
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    /// Disables the default `mim:` / `x:` entity-type namespace check.
    pub fn allow_unnamespaced_entity_type(mut self) -> Self {
        self.strict_entity_namespace = false;
        self
    }

    /// Validates invariants and produces the canonical [`Event`].
    pub fn build(self) -> Result<Event, BuildError> {
        let id = self.id.ok_or(BuildError::MissingField("id"))?;
        let timestamp = self
            .timestamp
            .ok_or(BuildError::MissingField("timestamp"))?;
        // Fail closed on malformed content the boundary would reject anyway: a
        // non-RFC3339 timestamp or an off-planet position must not be signed.
        if !is_rfc3339(&timestamp) {
            return Err(BuildError::InvalidTimestamp(timestamp));
        }
        if let Some(loc) = &self.location {
            let ok = loc.latitude.is_finite()
                && loc.longitude.is_finite()
                && loc.altitude_m.is_finite()
                && (-90.0..=90.0).contains(&loc.latitude)
                && (-180.0..=180.0).contains(&loc.longitude);
            if !ok {
                return Err(BuildError::InvalidLocation {
                    latitude: loc.latitude,
                    longitude: loc.longitude,
                });
            }
        }
        if self.source_id.is_empty() {
            return Err(BuildError::MissingField("source_id"));
        }
        if self.entity_type.is_empty() {
            return Err(BuildError::MissingField("entity_type"));
        }
        if self.strict_entity_namespace && !is_namespaced(&self.entity_type) {
            return Err(BuildError::UnnamespacedEntityType(self.entity_type));
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(BuildError::ConfidenceOutOfRange(self.confidence));
        }
        if self.policy_tags.len() > MAX_POLICY_TAGS {
            return Err(BuildError::TooManyPolicyTags {
                count: self.policy_tags.len(),
                max: MAX_POLICY_TAGS,
            });
        }
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(BuildError::TooManyAttributes {
                count: self.attributes.len(),
                max: MAX_ATTRIBUTES,
            });
        }
        if self.metadata.len() > MAX_METADATA {
            return Err(BuildError::TooManyMetadata {
                count: self.metadata.len(),
                max: MAX_METADATA,
            });
        }

        // Canonical rule: attributes sorted by key, unique. Sort first (stable),
        // then reject any adjacent equal key.
        let mut attrs = self.attributes;
        attrs.sort_by(|a, b| a.0.cmp(&b.0));
        for pair in attrs.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(BuildError::DuplicateAttributeKey(pair[0].0.clone()));
            }
        }
        let attributes = attrs
            .into_iter()
            .map(|(key, value)| Attribute { key, value })
            .collect();

        // Metadata follows the identical canonical rule: sorted by key, unique.
        let mut meta = self.metadata;
        meta.sort_by(|a, b| a.0.cmp(&b.0));
        for pair in meta.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(BuildError::DuplicateMetadataKey(pair[0].0.clone()));
            }
        }
        let metadata = meta
            .into_iter()
            .map(|(key, value)| Attribute { key, value })
            .collect();

        Ok(Event {
            schema_version: SCHEMA_VERSION.to_string(),
            id,
            source_id: self.source_id,
            entity_type: self.entity_type,
            timestamp,
            received_at: String::new(), // Ajar stamps its own clock.
            location: self.location,
            payload: self.payload,
            policy_tags: self.policy_tags,
            confidence: self.confidence,
            attributes,
            metadata,
        })
    }
}

/// True if `s` is an RFC 3339 date-time: `YYYY-MM-DDThh:mm:ss[.frac](Z|±hh:mm)`,
/// with in-range date/time components. Hand-rolled because the SDK deliberately
/// carries no datetime-parsing dependency (see the workspace notes on `time`).
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let d = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let c = |i: usize, ch: u8| b.get(i) == Some(&ch);
    let num = |i: usize, n: usize| -> u32 {
        b[i..i + n]
            .iter()
            .fold(0u32, |a, &x| a * 10 + (x - b'0') as u32)
    };
    let digits = |i: usize, n: usize| (0..n).all(|k| d(i + k));
    if !(digits(0, 4)
        && c(4, b'-')
        && digits(5, 2)
        && c(7, b'-')
        && digits(8, 2)
        && (c(10, b'T') || c(10, b't'))
        && digits(11, 2)
        && c(13, b':')
        && digits(14, 2)
        && c(16, b':')
        && digits(17, 2))
    {
        return false;
    }
    if !((1..=12).contains(&num(5, 2))
        && (1..=31).contains(&num(8, 2))
        && num(11, 2) <= 23
        && num(14, 2) <= 59
        && num(17, 2) <= 60)
    {
        return false;
    }
    let mut i = 19;
    if c(i, b'.') {
        i += 1;
        let start = i;
        while d(i) {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') | Some(b'z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            digits(i + 1, 2)
                && c(i + 3, b':')
                && digits(i + 4, 2)
                && i + 6 == b.len()
                && num(i + 1, 2) <= 23
                && num(i + 4, 2) <= 59
        }
        _ => false,
    }
}

/// True if `entity_type` follows the controlled-vocab namespacing:
/// `mim:<type>` (standards base) or `x:<vendor>:<type>` (extension).
fn is_namespaced(entity_type: &str) -> bool {
    if let Some(rest) = entity_type.strip_prefix("mim:") {
        return !rest.is_empty() && !rest.contains(':');
    }
    if let Some(rest) = entity_type.strip_prefix("x:") {
        // x:<vendor>:<type> — exactly one more colon, both halves non-empty.
        let mut parts = rest.splitn(2, ':');
        return matches!((parts.next(), parts.next()),
            (Some(vendor), Some(ty)) if !vendor.is_empty() && !ty.is_empty() && !ty.contains(':'));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_attributes_and_sets_defaults() {
        let event = EventBuilder::new("sensor-1", "mim:drone")
            .new_id()
            .now()
            .attribute("speed", "110")
            .attribute("heading", "225")
            .build()
            .unwrap();
        assert_eq!(event.schema_version, "v1");
        assert!(event.received_at.is_empty());
        let keys: Vec<_> = event.attributes.iter().map(|a| a.key.as_str()).collect();
        assert_eq!(keys, ["heading", "speed"]);
    }

    #[test]
    fn sorts_metadata_and_rejects_duplicate_keys() {
        let event = EventBuilder::new("sensor-1", "mim:drone")
            .new_id()
            .now()
            .metadata("mmsi", "227006760")
            .metadata("callsign", "F-ABCD")
            .build()
            .unwrap();
        let keys: Vec<_> = event.metadata.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(keys, ["callsign", "mmsi"]);

        let err = EventBuilder::new("sensor-1", "mim:drone")
            .new_id()
            .now()
            .metadata("mmsi", "1")
            .metadata("mmsi", "2")
            .build()
            .unwrap_err();
        assert_eq!(err, BuildError::DuplicateMetadataKey("mmsi".into()));
    }

    #[test]
    fn rejects_duplicate_attribute_keys() {
        let err = EventBuilder::new("sensor-1", "mim:drone")
            .new_id()
            .now()
            .attribute("heading", "225")
            .attribute("heading", "226")
            .build()
            .unwrap_err();
        assert_eq!(err, BuildError::DuplicateAttributeKey("heading".into()));
    }

    #[test]
    fn requires_id_and_timestamp() {
        let err = EventBuilder::new("sensor-1", "mim:drone")
            .build()
            .unwrap_err();
        assert_eq!(err, BuildError::MissingField("id"));
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for bad in [
            "t",
            "2026-06-10",
            "2026-13-10T08:00:00Z",
            "2026-06-10T25:00:00Z",
            "2026-06-10T08:00:00",
        ] {
            let err = EventBuilder::new("sensor-1", "mim:drone")
                .new_id()
                .timestamp(bad)
                .build()
                .unwrap_err();
            assert_eq!(err, BuildError::InvalidTimestamp(bad.into()), "{bad}");
        }
        for good in [
            "2026-06-10T08:00:00Z",
            "2026-06-10T08:00:00.123Z",
            "2026-06-10T08:00:00+02:00",
        ] {
            assert!(
                EventBuilder::new("sensor-1", "mim:drone")
                    .new_id()
                    .timestamp(good)
                    .build()
                    .is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_coordinates() {
        for (lat, lon) in [(9999.0, 2.0), (1.0, 999.0), (f64::NAN, 2.0), (-91.0, 0.0)] {
            let err = EventBuilder::new("sensor-1", "mim:drone")
                .new_id()
                .now()
                .location(lat, lon, 0.0)
                .build()
                .unwrap_err();
            assert!(
                matches!(err, BuildError::InvalidLocation { .. }),
                "{lat},{lon}"
            );
        }
        assert!(EventBuilder::new("sensor-1", "mim:drone")
            .new_id()
            .now()
            .location(-90.0, 180.0, 11000.0)
            .build()
            .is_ok());
    }

    #[test]
    fn rejects_out_of_range_confidence() {
        let err = EventBuilder::new("sensor-1", "mim:drone")
            .new_id()
            .now()
            .confidence(1.5)
            .build()
            .unwrap_err();
        assert_eq!(err, BuildError::ConfidenceOutOfRange(1.5));
    }

    #[test]
    fn namespacing_is_enforced_by_default_and_can_be_relaxed() {
        let err = EventBuilder::new("sensor-1", "drone")
            .new_id()
            .now()
            .build()
            .unwrap_err();
        assert_eq!(err, BuildError::UnnamespacedEntityType("drone".into()));

        assert!(EventBuilder::new("sensor-1", "drone")
            .new_id()
            .now()
            .allow_unnamespaced_entity_type()
            .build()
            .is_ok());
    }

    #[test]
    fn accepts_vendor_extension_namespace() {
        assert!(is_namespaced("x:acme:widget"));
        assert!(!is_namespaced("x:acme"));
        assert!(!is_namespaced("mim:"));
        assert!(is_namespaced("mim:vessel"));
    }
}
