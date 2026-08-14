// SPDX-License-Identifier: Apache-2.0
//! Connector profile: the self-declaration a connector publishes so Ajar knows
//! what it is allowed to emit and how to authenticate it.
//!
//! The profile is a *declaration*, not policy: Ajar's core decides what to do
//! with it. The SDK's job is to let an author state it correctly and serialize
//! it deterministically (the verifying key is emitted as lowercase hex).

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

/// A connector's published profile.
#[derive(Debug, Clone)]
pub struct ConnectorProfile {
    /// Stable source identity this connector signs as.
    pub source_id: String,
    /// Entity types this connector is permitted to emit (namespaced).
    pub allowed_entity_types: Vec<String>,
    /// Upper bound on `payload` size in bytes.
    pub max_payload_bytes: u64,
    /// Token-bucket capacity (burst) for ingest rate limiting.
    pub rate_capacity: u32,
    /// Token-bucket refill rate, tokens per second.
    pub rate_refill_per_sec: f64,
    /// Ed25519 public key Ajar uses to verify this connector's sealed events.
    pub verifying_key: VerifyingKey,
}

/// Serialization view: the verifying key projected to lowercase hex.
#[derive(Serialize)]
struct ProfileWire<'a> {
    source_id: &'a str,
    allowed_entity_types: &'a [String],
    max_payload_bytes: u64,
    rate_capacity: u32,
    rate_refill_per_sec: f64,
    verifying_key_hex: String,
}

impl ConnectorProfile {
    /// Convenience constructor.
    pub fn new(source_id: impl Into<String>, verifying_key: VerifyingKey) -> Self {
        Self {
            source_id: source_id.into(),
            allowed_entity_types: Vec::new(),
            max_payload_bytes: 64 * 1024,
            rate_capacity: 100,
            rate_refill_per_sec: 10.0,
            verifying_key,
        }
    }

    /// Adds an allowed (namespaced) entity type.
    pub fn allow_entity_type(mut self, entity_type: impl Into<String>) -> Self {
        self.allowed_entity_types.push(entity_type.into());
        self
    }

    /// Sets the payload-size ceiling in bytes.
    pub fn max_payload_bytes(mut self, max: u64) -> Self {
        self.max_payload_bytes = max;
        self
    }

    /// Sets the ingest rate-limit bucket (capacity / refill-per-second).
    pub fn rate_limit(mut self, capacity: u32, refill_per_sec: f64) -> Self {
        self.rate_capacity = capacity;
        self.rate_refill_per_sec = refill_per_sec;
        self
    }

    fn wire(&self) -> ProfileWire<'_> {
        ProfileWire {
            source_id: &self.source_id,
            allowed_entity_types: &self.allowed_entity_types,
            max_payload_bytes: self.max_payload_bytes,
            rate_capacity: self.rate_capacity,
            rate_refill_per_sec: self.rate_refill_per_sec,
            verifying_key_hex: hex::encode(self.verifying_key.to_bytes()),
        }
    }

    /// Serializes the profile to compact JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.wire()).expect("profile serialization")
    }

    /// Serializes the profile to pretty (indented) JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(&self.wire()).expect("profile serialization")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn serializes_verifying_key_as_hex() {
        let vk = SigningKey::from_bytes(&[0x47; 32]).verifying_key();
        let profile = ConnectorProfile::new("sensor-123", vk)
            .allow_entity_type("mim:aircraft")
            .max_payload_bytes(4096)
            .rate_limit(50, 5.0);
        let json = profile.to_json();
        assert!(json.contains("\"source_id\":\"sensor-123\""));
        assert!(json.contains(&hex::encode(vk.to_bytes())));
        assert!(json.contains("mim:aircraft"));
    }
}
