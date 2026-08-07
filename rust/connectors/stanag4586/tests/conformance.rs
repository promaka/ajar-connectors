// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the STANAG 4586 connector, checked on a Message #101
//! Inertial States report.
//!
//! Verified without importing Core (its rules are mirrored, not linked):
//!  1. the produced event satisfies Core's content contract — UUIDv7 id, RFC 3339
//!     timestamp;
//!  2. the native vehicle identity is preserved as `source_uid`;
//!  3. the raw message (wrapper + body + checksum) is sealed verbatim into payload;
//!  4. the seal verifies under the published contract key.
//!
//! The frame is hand-built here (big-endian, correct checksum) so the test is
//! self-contained; the message model is implemented from the public NATO
//! UNCLASSIFIED STANAG 4586 Edition 2 field tables (no reference-implementation
//! code was copied).

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ajar_stanag4586::S4586Parser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

/// A #101 Inertial States message: vehicle 7 at 26.3 N 50.6 E, 1500 m, tracking
/// north-east at 50 m/s, climbing. Big-endian throughout, correct trailing checksum.
fn inertial_frame() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_754_000_000.0f64.to_be_bytes()); // time stamp (unix s)
    body.extend_from_slice(&7u32.to_be_bytes()); // vehicle id
    body.extend_from_slice(&3u32.to_be_bytes()); // cucs id
    body.extend_from_slice(&26.3f64.to_radians().to_be_bytes()); // latitude
    body.extend_from_slice(&50.6f64.to_radians().to_be_bytes()); // longitude
    body.extend_from_slice(&1500.0f32.to_be_bytes()); // altitude m
    body.push(3); // altitude type = WGS-84
    body.extend_from_slice(&30.0f32.to_be_bytes()); // U_Speed north
    body.extend_from_slice(&40.0f32.to_be_bytes()); // V_Speed east
    body.extend_from_slice(&(-5.0f32).to_be_bytes()); // W_Speed down
    for _ in 0..3 {
        body.extend_from_slice(&0.0f32.to_be_bytes()); // U/V/W accel
    }
    body.extend_from_slice(&0.0f32.to_be_bytes()); // roll
    body.extend_from_slice(&0.0f32.to_be_bytes()); // pitch
    body.extend_from_slice(&1.5707964f32.to_be_bytes()); // yaw ~90 deg
    for _ in 0..3 {
        body.extend_from_slice(&0.0f32.to_be_bytes()); // roll/pitch/yaw rates
    }
    body.extend_from_slice(&0.0f32.to_be_bytes()); // magnetic variation

    let mut m = Vec::new();
    m.extend_from_slice(b"8\0\0\0\0\0\0\0\0\0"); // IDD version (Edition 2)
    m.extend_from_slice(&1u32.to_be_bytes()); // instance
    m.extend_from_slice(&101u32.to_be_bytes()); // message type
    m.extend_from_slice(&(body.len() as u32).to_be_bytes()); // length
    m.extend_from_slice(&0u32.to_be_bytes()); // stream id
    m.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // packet seq = -1
    m.extend_from_slice(&body);
    let sum = m.iter().fold(0u32, |a, &b| a.wrapping_add(b as u32));
    m.extend_from_slice(&sum.to_be_bytes());
    m
}

fn parser() -> S4586Parser {
    S4586Parser::new(
        "uas-vsm-1",
        Enrichment::default().with_affiliation("friendly"),
    )
}

fn connector_event() -> ajar_connector::Event {
    let evs = parser().to_events(&inertial_frame()).expect("frame parses");
    assert_eq!(evs.len(), 1, "one inertial-states message -> one event");
    evs.into_iter().next().unwrap()
}

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

#[test]
fn event_satisfies_core_content_contract() {
    let ev = connector_event();
    let uuid = Uuid::parse_str(&ev.id).expect("id must be a UUID");
    assert_eq!(uuid.get_version_num(), 7, "id must be a UUIDv7");
    assert!(is_rfc3339(&ev.timestamp), "timestamp must be RFC 3339");
    assert_eq!(ev.timestamp, "2025-07-31T22:13:20Z");
    assert!(!ev.source_id.is_empty());
    assert_eq!(ev.entity_type, "mim:drone");
}

#[test]
fn native_identity_is_preserved_as_metadata_not_id() {
    let ev = connector_event();
    let native = "s4586:vehicle:7";
    assert_ne!(ev.id, native);
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == native),
        "vehicle id must be preserved as source_uid metadata"
    );
    assert!(is_canonical(&ev.attributes), "attributes must be canonical");
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");

    // The raw message is sealed verbatim.
    assert_eq!(ev.payload.as_slice(), inertial_frame().as_slice());

    let loc = ev.location.as_ref().expect("located track has a location");
    assert!((loc.latitude - 26.3).abs() < 1e-6);
    assert!((loc.longitude - 50.6).abs() < 1e-6);
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

/// Canonical repeated entries: keys strictly increasing (sorted + unique).
fn is_canonical(entries: &[ajar_connector::Attribute]) -> bool {
    entries.windows(2).all(|w| w[0].key < w[1].key)
}

/// Mirror Core's timestamp rule without importing it.
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
