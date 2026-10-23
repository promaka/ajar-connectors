// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the SAPIENT connector, checked on a detection
//! report with a WGS-84 position.
//!
//! Verified without importing Core (its rules are mirrored, not linked):
//!  1. the produced event satisfies Core's content contract — UUIDv7 id, RFC 3339
//!     timestamp, canonical attribute and metadata order;
//!  2. the seal verifies under the published contract key;
//!  3. the native identity (node and object) is preserved as `source_uid`
//!     metadata, and the message bytes as the payload.

mod support;

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::{Enrichment, FrameParser};
use ajar_sapient::SapientParser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

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

/// The scenario's third message: the first detection, after the node has
/// reported where it is.
fn connector_event() -> (ajar_connector::Event, Vec<u8>) {
    let parser = SapientParser::new(
        "sapient-fusion-1",
        Enrichment::default().with_hostility("Suspect"),
    );
    let messages = support::messages();
    let status = ajar_sapient_wire::encode(&messages[1]);
    parser.parse(&status).expect("status parses");
    let detection = ajar_sapient_wire::encode(&messages[2]);
    let mut events = parser.parse(&detection).expect("detection parses");
    assert_eq!(events.len(), 1);
    (events.remove(0), detection)
}

#[test]
fn event_satisfies_core_content_contract() {
    let (ev, _) = connector_event();
    let uuid = Uuid::parse_str(&ev.id).expect("id must be a UUID");
    assert_eq!(uuid.get_version_num(), 7, "id must be a UUIDv7");
    assert!(is_rfc3339(&ev.timestamp), "timestamp must be RFC 3339");
    assert_eq!(
        ev.timestamp, "2026-05-28T20:26:42Z",
        "the message's own time"
    );
    assert!(!ev.source_id.is_empty());
    assert_eq!(ev.entity_type, "sapient:track");
    assert!(is_canonical(&ev.attributes), "attributes must be canonical");
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
}

#[test]
fn native_identity_and_bytes_are_preserved() {
    let (ev, raw) = connector_event();
    let native = format!("{}:{}", support::NODE, support::OBJECT);
    assert_ne!(ev.id, native);
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == native),
        "node and object ids must be preserved as source_uid metadata"
    );
    assert_eq!(ev.payload, raw, "the message is sealed verbatim");
    let loc = ev.location.as_ref().expect("geolocated against the node");
    assert!(loc.latitude > 51.47 && loc.longitude > -0.4543);
    assert!(ev
        .attributes
        .iter()
        .any(|a| a.key == "hostility" && a.value == "Suspect"));
}

#[test]
fn seal_verifies_under_the_published_contract_key() {
    let contract = contract();
    let seed = hex32(&contract, "signingSeedHex");
    let vk = VerifyingKey::from_bytes(&hex32(&contract, "verifyingKeyHex"))
        .expect("published verifying key is valid");

    let canonical = canonical_bytes(&connector_event().0);
    let sealed = seal(&canonical, &SigningKey::from_bytes(&seed));

    assert_eq!(sealed.len(), SEAL_SIGNATURE_LEN + canonical.len());
    let (sig, body) = sealed.split_at(SEAL_SIGNATURE_LEN);
    assert_eq!(body, &canonical[..]);
    let sig = Signature::from_slice(sig).expect("64-byte signature");
    vk.verify(body, &sig)
        .expect("seal signature must verify under the contract key");
}

/// Canonical repeated entries: keys strictly increasing (sorted + unique).
fn is_canonical(entries: &[ajar_connector::Attribute]) -> bool {
    entries.windows(2).all(|w| w[0].key < w[1].key)
}

/// Mirror Core's timestamp rule without importing it.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && (s.ends_with('Z') || s.contains('+') || s[19..].contains('-'))
}
