// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the ASTERIX connector (checked on a CAT062 system
//! track, the fused air picture).
//!
//! Verified without importing Core (its rules are mirrored, not linked):
//!  1. the produced event satisfies Core's content contract — UUIDv7 id, RFC 3339
//!     timestamp;
//!  2. the seal verifies under the published contract key;
//!  3. the native identity (ICAO address) is preserved as `source_uid` metadata.

use ajar_asterix::AsterixParser;
use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

const OBSERVED: &str = "2026-06-10T08:00:00Z";

// A minimal valid CAT062 record: data source (I062/010), WGS-84 position
// (I062/105) at 60 N 25 E, and Aircraft Derived Data (I062/380) carrying the
// ICAO address. Built here so the test is self-contained.
fn cat062_block() -> Vec<u8> {
    const LSB: f64 = 180.0 / (1u64 << 25) as f64;
    let lat = (60.0 / LSB) as i32;
    let lon = (25.0 / LSB) as i32;
    // FSPEC: FRN 1 (o1 b8) + FRN 5 (o1 b4) + FX, then FRN 11 (o2 b5 = I062/380).
    let mut record = vec![0b1000_1001, 0b0001_0000];
    record.extend_from_slice(&[25, 10]); // I062/010 SAC/SIC
    record.extend_from_slice(&lat.to_be_bytes()); // I062/105 latitude
    record.extend_from_slice(&lon.to_be_bytes()); // I062/105 longitude
    record.push(0x80); // I062/380 primary: ADR present, FX=0
    record.extend_from_slice(&[0x40, 0x62, 0x01]); // ADR ICAO address
    let len = 3 + record.len();
    let mut b = vec![62u8, (len >> 8) as u8, (len & 0xff) as u8];
    b.extend_from_slice(&record);
    b
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

fn parser() -> AsterixParser {
    AsterixParser::new(
        "radar-adsb-1",
        Enrichment::default().with_hostility("Neutral"),
    )
}

fn connector_event() -> ajar_connector::Event {
    let p = parser();
    let targets = p.parse_block(&cat062_block()).expect("block parses");
    p.to_event_at(&targets[0], OBSERVED).expect("builds")
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
fn native_identity_is_preserved_as_metadata_not_id() {
    let ev = connector_event();
    assert_eq!(ev.entity_type, "mim:aircraft");
    let native = "icao:406201";
    assert_ne!(ev.id, native);
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == native),
        "ICAO address must be preserved as source_uid metadata"
    );
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
    // The raw record (everything after the 3-byte block header) is sealed verbatim.
    assert_eq!(ev.payload.as_slice(), &cat062_block()[3..]);
    let loc = ev.location.as_ref().expect("located track has a location");
    assert!((loc.latitude - 60.0).abs() < 1e-4);
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
