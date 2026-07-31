// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the TAK/CoT connector.
//!
//! Two things Core relies on, checked here without importing Core (its rules are
//! mirrored, not linked):
//!  1. the produced event satisfies Core's **content** contract — the id is a
//!     UUIDv7 and the timestamp is RFC 3339 (the two rules the encoding vectors do
//!     not cover, and the ones that rejected real events in the field);
//!  2. the seal verifies under the published contract key.
//!
//! Plus a mapping check: the native CoT uid is preserved as an attribute, never
//! used as the id.

use std::collections::HashMap;

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ajar_tak_cot::CotParser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

// A realistic native CoT uid (an ATAK endpoint id), deliberately NOT UUID-shaped —
// the connector must not let it reach the event id field.
const SAMPLE: &str = r#"<event version="2.0" uid="ANDROID-a1b2c3d4" type="a-f-A-M-F-Q" time="2026-06-10T08:00:00Z" start="2026-06-10T08:00:00Z" stale="2026-06-10T08:00:30Z"><point lat="26.4" lon="50.9" hae="1200.0" ce="10" le="10"/></event>"#;

fn contract() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../vendor/contract/vectors.json"
    );
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading contract vectors {path}: {e}"));
    serde_json::from_str(&text).expect("contract vectors are valid JSON")
}

fn hex32(v: &serde_json::Value, key: &str) -> [u8; 32] {
    let s = v[key].as_str().unwrap_or_else(|| panic!("{key} missing"));
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn connector_event() -> ajar_connector::Event {
    // Governed mode: a deployment that declared its ontology, so the tactical
    // attributes ride as governed attributes (what the conformance below asserts).
    let enrichment = Enrichment::default();
    CotParser::new("tak-field-1", HashMap::new(), enrichment)
        .to_event(SAMPLE.as_bytes())
        .expect("sample parses")
}

#[test]
fn event_satisfies_core_content_contract() {
    let ev = connector_event();
    let uuid = Uuid::parse_str(&ev.id).expect("id must be a UUID");
    assert_eq!(uuid.get_version_num(), 7, "id must be a UUIDv7");
    assert!(is_rfc3339(&ev.timestamp), "timestamp must be RFC 3339");
    assert!(!ev.source_id.is_empty());
    assert!(!ev.entity_type.is_empty());
}

#[test]
fn native_uid_is_preserved_as_metadata_not_id() {
    let ev = connector_event();
    assert_eq!(ev.entity_type, "mim:aircraft"); // battle dimension A -> air
    assert_ne!(ev.id, "ANDROID-a1b2c3d4");
    // The CoT uid is ungoverned passthrough: in metadata, never a governed
    // attribute, never the id.
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == "ANDROID-a1b2c3d4"),
        "CoT uid must be preserved as metadata"
    );
    assert!(!ev.attributes.iter().any(|a| a.key == "source_uid"));
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
    // The tactical attributes a COP reads are governed (and canonical): the
    // sample's a-f-… type is friendly.
    assert!(
        ev.attributes
            .iter()
            .any(|a| a.key == "affiliation" && a.value == "friendly"),
        "affiliation must be a governed attribute"
    );
    assert!(is_canonical(&ev.attributes), "attributes must be canonical");
    let loc = ev.location.as_ref().expect("located track has a location");
    assert_eq!(loc.latitude, 26.4);
}

#[test]
fn seal_verifies_under_the_published_contract_key() {
    let contract = contract();
    let seed = hex32(&contract, "signingSeedHex");
    let vk = VerifyingKey::from_bytes(&hex32(&contract, "verifyingKeyHex"))
        .expect("published verifying key is valid");

    let canonical = canonical_bytes(&connector_event());
    let sealed = seal(&canonical, &SigningKey::from_bytes(&seed));

    assert_eq!(sealed.len(), SEAL_SIGNATURE_LEN + canonical.len());
    let (sig, body) = sealed.split_at(SEAL_SIGNATURE_LEN);
    assert_eq!(body, &canonical[..]);
    let sig = Signature::from_slice(sig).expect("64-byte signature");
    vk.verify(body, &sig)
        .expect("seal signature must verify under the contract key");
}

/// Canonical repeated `Attribute`: keys strictly increasing (sorted + unique).
fn is_canonical(entries: &[ajar_connector::Attribute]) -> bool {
    entries.windows(2).all(|w| w[0].key < w[1].key)
}

/// Mirror Core's timestamp rule without importing it: RFC 3339, `Z` or numeric
/// offset, optional fractional seconds.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let d = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    let c = |i: usize, ch: u8| b.get(i) == Some(&ch);
    if !(d(0)
        && d(1)
        && d(2)
        && d(3)
        && c(4, b'-')
        && d(5)
        && d(6)
        && c(7, b'-')
        && d(8)
        && d(9)
        && c(10, b'T')
        && d(11)
        && d(12)
        && c(13, b':')
        && d(14)
        && d(15)
        && c(16, b':')
        && d(17)
        && d(18))
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
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            d(i + 1) && d(i + 2) && c(i + 3, b':') && d(i + 4) && d(i + 5) && i + 6 == b.len()
        }
        _ => false,
    }
}
