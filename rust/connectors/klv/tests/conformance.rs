// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the KLV (MISB ST 0601) connector.
//!
//! Two things Core relies on, checked here without importing Core (its rules are
//! mirrored, not linked):
//!  1. the produced event satisfies Core's **content** contract — the id is a
//!     UUIDv7 and the timestamp is RFC 3339;
//!  2. the seal verifies under the published contract key.
//!
//! Plus a mapping check: the native platform identity (tail number) is preserved
//! as `source_uid` metadata, never used as the event id.

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ajar_klv::KlvParser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

const OBSERVED: &str = "2026-06-10T08:00:00Z";

// A valid ST 0601 UAS Local Set: tail AB123, PREDATOR, 60.176822 N, 24.935508 E,
// 500 m, heading 270. Built here with a local encoder so the test is self-contained.
const KEY: [u8; 16] = [
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

fn ber_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n <= 0xff {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
    }
}
fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(ber_len(val.len()));
    v.extend_from_slice(val);
    v
}
fn bcc(bytes: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in bytes.iter().enumerate() {
        sum = sum.wrapping_add((b as u16) << (8 * ((i + 1) % 2)));
    }
    sum
}
fn sample() -> Vec<u8> {
    let lat = (60.176822_f64 * i32::MAX as f64 / 90.0) as i32;
    let lon = (24.935508_f64 * i32::MAX as f64 / 180.0) as i32;
    let hdg = (270.0_f64 / 360.0 * 65_535.0) as u16;
    let alt = ((500.0_f64 + 900.0) / 19_900.0 * 65_535.0) as u16;
    let items = [
        tlv(2, &1_700_000_000_000_000u64.to_be_bytes()),
        tlv(4, b"AB123"),
        tlv(5, &hdg.to_be_bytes()),
        tlv(10, b"PREDATOR"),
        tlv(13, &lat.to_be_bytes()),
        tlv(14, &lon.to_be_bytes()),
        tlv(15, &alt.to_be_bytes()),
        tlv(65, &[15]),
    ];
    let mut inner = Vec::new();
    for it in &items {
        inner.extend_from_slice(it);
    }
    inner.extend_from_slice(&[0x01, 0x02]); // checksum tag + length
    let set_len = inner.len() + 2;
    let mut pkt = KEY.to_vec();
    pkt.extend(ber_len(set_len));
    pkt.extend_from_slice(&inner);
    let c = bcc(&pkt);
    pkt.extend_from_slice(&c.to_be_bytes());
    pkt
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

fn parser() -> KlvParser {
    KlvParser::new("uas-klv-1", Enrichment::default().with_hostility("Friend"))
}

fn connector_event() -> ajar_connector::Event {
    let p = parser();
    let m = p
        .parse_set(&sample())
        .expect("set parses")
        .expect("has a position");
    p.to_event_at(&m, OBSERVED).expect("builds")
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
    // Tail number is the stable identity: source_uid metadata, never the event id.
    assert_ne!(ev.id, "AB123");
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == "AB123"),
        "tail number must be preserved as source_uid metadata"
    );
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
    // The whole raw KLV set is sealed in the payload (losslessness).
    assert_eq!(ev.payload.as_slice(), sample().as_slice());
    let loc = ev
        .location
        .as_ref()
        .expect("located platform has a location");
    assert!((loc.latitude - 60.176822).abs() < 1e-4);
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
