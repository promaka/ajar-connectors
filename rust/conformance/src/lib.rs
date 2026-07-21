// SPDX-License-Identifier: Apache-2.0
//! Shared loaders for the golden-vector conformance gate. The actual assertions
//! live in `tests/golden_vectors.rs`; this module just turns the vendored JSON
//! fixtures into canonical [`Event`]s so the test can hash them.

use ajar_connector::{Attribute, Event, GeoPoint};
use base64::Engine;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Absolute path to the vendored contract directory.
pub fn contract_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = rust/conformance ; contract = ../../vendor/contract
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/contract")
        .canonicalize()
        .expect("vendored contract directory exists")
}

/// The parsed `vectors.json` golden file.
#[derive(Debug, Deserialize)]
pub struct Vectors {
    /// TEST signing seed (32 bytes, hex). Never a production key.
    #[serde(rename = "signingSeedHex")]
    pub signing_seed_hex: String,
    /// Verifying key derived from the seed (hex), for cross-checking.
    #[serde(rename = "verifyingKeyHex")]
    pub verifying_key_hex: String,
    /// Per-fixture expected hashes, keyed by corpus fixture name.
    pub vectors: BTreeMap<String, ExpectedHashes>,
}

/// Expected hashes for one corpus fixture.
#[derive(Debug, Deserialize)]
pub struct ExpectedHashes {
    #[serde(rename = "canonicalSha256")]
    pub canonical_sha256: String,
    #[serde(rename = "sealedSha256")]
    pub sealed_sha256: String,
}

/// Loads and parses `vendor/contract/vectors.json`.
pub fn load_vectors() -> Vectors {
    let path = contract_dir().join("vectors.json");
    let raw = std::fs::read_to_string(&path).expect("read vectors.json");
    serde_json::from_str(&raw).expect("parse vectors.json")
}

/// JSON projection of an [`Event`] as stored in `corpus/*.json` (camelCase, with
/// `payload` base64-encoded). JSON is a debug projection only — never canonical.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureEvent {
    schema_version: String,
    id: String,
    source_id: String,
    entity_type: String,
    timestamp: String,
    #[serde(default)]
    received_at: String,
    #[serde(default)]
    location: Option<FixtureGeo>,
    #[serde(default)]
    payload: String,
    #[serde(default)]
    policy_tags: Vec<String>,
    #[serde(default)]
    confidence: f64,
    #[serde(default)]
    attributes: Vec<FixtureAttr>,
    #[serde(default)]
    metadata: Vec<FixtureAttr>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureGeo {
    latitude: f64,
    longitude: f64,
    #[serde(default)]
    altitude_m: f64,
}

#[derive(Debug, Deserialize)]
struct FixtureAttr {
    key: String,
    value: String,
}

/// Loads `corpus/<name>.json` and converts it to a canonical [`Event`].
///
/// The fixture is taken verbatim (including `received_at`, which a live
/// connector would leave for Ajar to stamp) so the canonical bytes match what
/// core hashed when it blessed these vectors.
pub fn load_fixture(name: &str) -> Event {
    let path = contract_dir().join("corpus").join(format!("{name}.json"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}.json: {e}"));
    let f: FixtureEvent =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {name}.json: {e}"));

    let payload = if f.payload.is_empty() {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(f.payload.as_bytes())
            .unwrap_or_else(|e| panic!("base64 payload in {name}.json: {e}"))
    };

    Event {
        schema_version: f.schema_version,
        id: f.id,
        source_id: f.source_id,
        entity_type: f.entity_type,
        timestamp: f.timestamp,
        received_at: f.received_at,
        location: f.location.map(|g| GeoPoint {
            latitude: g.latitude,
            longitude: g.longitude,
            altitude_m: g.altitude_m,
        }),
        payload,
        policy_tags: f.policy_tags,
        confidence: f.confidence,
        attributes: f
            .attributes
            .into_iter()
            .map(|a| Attribute {
                key: a.key,
                value: a.value,
            })
            .collect(),
        metadata: f
            .metadata
            .into_iter()
            .map(|a| Attribute {
                key: a.key,
                value: a.value,
            })
            .collect(),
    }
}
