// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the ADS-B (SBS-1) connector.
//!
//! Two things Core relies on, checked here without importing Core (its rules are
//! mirrored, not linked):
//!  1. the produced event satisfies Core's **content** contract — the id is a
//!     UUIDv7 and the timestamp is RFC 3339;
//!  2. the seal verifies under the published contract key.
//!
//! Plus a mapping check: the native ICAO address is preserved as the stable
//! `source_uid` (and `icao`) metadata, never used as the id.

use ajar_adsb::AdsbParser;
use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use uuid::Uuid;

// A real airborne-position SBS-1 line: ICAO 4CA2D6, 51.5 N, -0.5 E, 38000 ft.
const REAL: &[u8] =
    b"MSG,3,1,1,4CA2D6,1,2026/06/10,08:00:00.000,2026/06/10,08:00:00.000,,38000,,,51.50000,-0.50000,,,,,,0";
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

fn parser() -> AdsbParser {
    AdsbParser::new(
        "adsb-tower-1",
        Enrichment::default().with_affiliation("neutral"),
    )
}

fn connector_event() -> ajar_connector::Event {
    let p = parser();
    let pos = p
        .parse_line(REAL)
        .expect("line parses")
        .expect("is a position report");
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
fn native_icao_is_preserved_as_source_uid_not_id() {
    let ev = connector_event();
    assert_eq!(ev.entity_type, "mim:aircraft");
    assert_ne!(ev.id, "4CA2D6");
    // ICAO is ungoverned passthrough: source_uid + icao metadata, never the id,
    // never a governed attribute.
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == "4CA2D6"),
        "ICAO must be the stable source_uid"
    );
    assert!(ev
        .metadata
        .iter()
        .any(|m| m.key == "icao" && m.value == "4CA2D6"));
    assert!(!ev.attributes.iter().any(|a| a.key == "icao"));
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");
    let loc = ev
        .location
        .as_ref()
        .expect("located aircraft has a location");
    assert!((loc.latitude - 51.5).abs() < 1e-5);
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
