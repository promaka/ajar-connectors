// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the STANAG 4607 (GMTI) connector.
//!
//! Checked without importing Core (its rules are mirrored, not linked):
//!  1. the produced event satisfies Core's content contract — UUIDv7 id, RFC 3339
//!     timestamp;
//!  2. the seal verifies under the published contract key;
//!  3. the native detection identity is preserved as `source_uid` metadata.

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ajar_gmti::GmtiParser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

const OBSERVED: &str = "2026-06-10T08:00:00Z";
const T_LAT: f64 = 60.1;
const T_LON: f64 = 24.9;

fn sa32_enc(deg: f64) -> i32 {
    (deg * 33_554_432.0 / 1.406_25) as i32
}
fn ba32_enc(deg: f64) -> u32 {
    (deg * 16_777_216.0 / 1.406_25) as u32
}

/// A minimal valid GMTI packet: 32-byte header + one Dwell segment with a single
/// absolute-position target. Built with a local encoder so the test is self-contained.
fn sample_packet() -> Vec<u8> {
    let mask: [u8; 8] = [0xFF, 0x00, 0x03, 0xC3, 0x98, 0x00, 0x00, 0x00];
    let mut d = Vec::new();
    d.extend_from_slice(&mask);
    d.extend_from_slice(&7u16.to_be_bytes()); // revisit index
    d.extend_from_slice(&3u16.to_be_bytes()); // dwell index
    d.push(1); // last dwell of revisit
    d.extend_from_slice(&1u16.to_be_bytes()); // target report count
    d.extend_from_slice(&123_456i32.to_be_bytes()); // dwell time ms
    d.extend_from_slice(&sa32_enc(60.0).to_be_bytes()); // sensor lat
    d.extend_from_slice(&ba32_enc(25.0).to_be_bytes()); // sensor lon
    d.extend_from_slice(&150_000i32.to_be_bytes()); // sensor alt cm
    d.extend_from_slice(&sa32_enc(60.05).to_be_bytes()); // dwell centre lat
    d.extend_from_slice(&ba32_enc(24.95).to_be_bytes()); // dwell centre lon
    d.extend_from_slice(&0u16.to_be_bytes()); // range half-extent
    d.extend_from_slice(&0u16.to_be_bytes()); // angle half-extent
    d.extend_from_slice(&42u16.to_be_bytes()); // mti index
    d.extend_from_slice(&sa32_enc(T_LAT).to_be_bytes()); // hi-res lat
    d.extend_from_slice(&ba32_enc(T_LON).to_be_bytes()); // hi-res lon
    d.extend_from_slice(&120i16.to_be_bytes()); // geodetic height m
    d.extend_from_slice(&(-450i16).to_be_bytes()); // radial cm/s

    let seg_size = (5 + d.len()) as u32;
    let mut seg = vec![2u8]; // dwell segment type
    seg.extend_from_slice(&seg_size.to_be_bytes());
    seg.extend_from_slice(&d);

    let packet_size = (32 + seg.len()) as u32;
    let mut pkt = vec![0x03, 0x01]; // edition 3, version 1
    pkt.extend_from_slice(&packet_size.to_be_bytes());
    pkt.extend_from_slice(b"XN"); // nationality
    pkt.push(1); // classification
    pkt.extend_from_slice(b"  "); // classification system
    pkt.extend_from_slice(&0u16.to_be_bytes()); // packet security
    pkt.push(0); // exercise indicator
    pkt.extend_from_slice(b"REAPER-01 "); // platform id
    pkt.extend_from_slice(&77u32.to_be_bytes()); // mission id
    pkt.extend_from_slice(&9001u32.to_be_bytes()); // job id
    pkt.extend_from_slice(&seg);
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

fn parser() -> GmtiParser {
    GmtiParser::new(
        "gmti-radar-1",
        Enrichment::default().with_affiliation("unknown"),
    )
}

fn connector_event() -> ajar_connector::Event {
    let p = parser();
    let targets = p.parse_packet(&sample_packet()).expect("packet parses");
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
fn detection_identity_is_preserved_as_metadata_not_id() {
    let ev = connector_event();
    assert_eq!(ev.entity_type, "mim:ground-track");
    let native = "REAPER-01:9001:3:42";
    assert_ne!(ev.id, native);
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == native),
        "detection identity must be preserved as source_uid metadata"
    );
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
    // The raw dwell segment is sealed in the payload (losslessness).
    assert!(
        ev.payload.first() == Some(&2u8),
        "payload starts with the dwell segment"
    );
    let loc = ev.location.as_ref().expect("located target has a location");
    assert!((loc.latitude - T_LAT).abs() < 1e-3);
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
