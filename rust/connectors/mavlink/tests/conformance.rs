// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the MAVLink connector.
//!
//! Two things Core relies on, checked here without importing Core (its rules are
//! mirrored, not linked):
//!  1. the produced event satisfies Core's **content** contract — the id is a
//!     UUIDv7 and the timestamp is RFC 3339 (the two rules the encoding vectors do
//!     not cover, and the ones that rejected real events in the field);
//!  2. the seal verifies under the published contract key.
//!
//! Plus a mapping check: the native system id is preserved as an attribute, never
//! used as the id.

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ajar_mavlink::MavParser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

// Ground-truth GLOBAL_POSITION_INT frame (CRC-correct), sysid 1: 47.397742 N,
// 8.545594 E, 500.0 m, heading 90.0.
const V1: &str = "fe1c00010121e80300004c52401c44f4170520a10700000000000000000000002823bb57";
const OBSERVED: &str = "2026-06-10T08:00:00Z";

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

fn parser() -> MavParser {
    // Governed mode: a deployment that declared its ontology.
    MavParser::new(
        "uav-flight-1",
        Enrichment::default().with_hostility("Friend"),
    )
}

fn connector_event() -> ajar_connector::Event {
    let frame = hex::decode(V1).unwrap();
    let p = parser();
    let pos = p
        .parse_frame(&frame)
        .expect("frame parses")
        .expect("is a position message");
    p.to_event_at(&pos, OBSERVED).expect("builds")
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
fn native_sysid_is_preserved_as_metadata_not_id() {
    let ev = connector_event();
    assert_eq!(ev.entity_type, "mim:aircraft");
    assert_ne!(ev.id, "mav:1");
    // The system id is ungoverned passthrough: in metadata, never a governed
    // attribute, never the id.
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "mav_sysid" && m.value == "1"),
        "MAVLink system id must be preserved as metadata"
    );
    assert!(!ev.attributes.iter().any(|a| a.key == "mav_sysid"));
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
    let loc = ev
        .location
        .as_ref()
        .expect("located vehicle has a location");
    assert!((loc.latitude - 47.397742).abs() < 1e-6);
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
