// SPDX-License-Identifier: Apache-2.0
//! Contract conformance for the STANAG 4676 connector, checked on a WGS-84 air
//! track.
//!
//! Verified without importing Core (its rules are mirrored, not linked):
//!  1. the produced event satisfies Core's content contract — UUIDv7 id, RFC 3339
//!     timestamp;
//!  2. the native track identity (the 4676 UUID) is preserved as `source_uid`;
//!  3. the raw `<track>` element is sealed verbatim into the payload;
//!  4. the seal verifies under the published contract key.
//!
//! The message here is clean-room (authored for this test), not copied from any
//! reference corpus.

use ajar_connector::{canonical_bytes, seal, SEAL_SIGNATURE_LEN};
use ajar_connector_common::Enrichment;
use ajar_stanag4676::S4676Parser;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use std::collections::HashMap;
use uuid::Uuid;

// One WGS-84 air track: FRIEND, AIR, one maintaining point at 26.3 N 50.6 E. The
// uid Base64-decodes to 0c58cbc0-0db6-4578-8a48-05a1d9e04e19.
fn message() -> &'static str {
    r#"<ns2:nitsRoot xmlns:ns2="urn:nato:niia:stanag:4676:isrtrackingstandard:b:1" xmlns="urn:nato:stanag:4774:confidentialitymetadatalabel:1:0">
  <originatorConfidentialityLabel><ConfidentialityInformation>
    <Classification>NATO UNCLASSIFIED</Classification>
  </ConfidentialityInformation></originatorConfidentialityLabel>
  <ns2:nitsVersion>B.1</ns2:nitsVersion>
  <ns2:message>
    <ns2:baseTime>2026-06-10T08:00:00.000Z</ns2:baseTime>
    <ns2:relTimeIncrement>0.001</ns2:relTimeIncrement>
    <ns2:track>
      <ns2:uid>DFjLwA22RXiKSAWh2eBOGQ==</ns2:uid>
      <ns2:segment>
        <ns2:status>MAINTAINING</ns2:status>
        <ns2:tp>
          <ns2:relTime>0</ns2:relTime>
          <ns2:dynamics cs="WGS_84"><ns2:pos>26.3 50.6 3000.0</ns2:pos></ns2:dynamics>
        </ns2:tp>
      </ns2:segment>
      <ns2:object><ns2:id1241>
        <ns2:identity>FRIEND</ns2:identity>
        <ns2:environment>AIR</ns2:environment>
      </ns2:id1241></ns2:object>
    </ns2:track>
  </ns2:message>
</ns2:nitsRoot>"#
}

const UID: &str = "0c58cbc0-0db6-4578-8a48-05a1d9e04e19";

fn parser() -> S4676Parser {
    S4676Parser::new("isr-tracker-1", HashMap::new(), Enrichment::default())
}

fn connector_event() -> ajar_connector::Event {
    let evs = parser()
        .to_events(message().as_bytes())
        .expect("message parses");
    assert_eq!(evs.len(), 1, "one track point -> one event");
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
    assert_eq!(ev.timestamp, "2026-06-10T08:00:00Z"); // baseTime + relTime 0
    assert!(!ev.source_id.is_empty());
    assert_eq!(ev.entity_type, "mim:object");
}

#[test]
fn native_identity_is_preserved_as_metadata_not_id() {
    let ev = connector_event();
    assert_ne!(ev.id, UID);
    assert!(
        ev.metadata
            .iter()
            .any(|m| m.key == "source_uid" && m.value == UID),
        "track UUID must be preserved as source_uid metadata"
    );
    assert!(is_canonical(&ev.attributes), "attributes must be canonical");
    assert!(is_canonical(&ev.metadata), "metadata must be canonical");

    // The raw <track> element is sealed verbatim.
    let raw = String::from_utf8_lossy(&ev.payload);
    assert!(raw.starts_with("<ns2:track>") && raw.trim_end().ends_with("</ns2:track>"));

    let loc = ev.location.as_ref().expect("located track has a location");
    assert!((loc.latitude - 26.3).abs() < 1e-6);
    assert!((loc.longitude - 50.6).abs() < 1e-6);

    // The message classification rides as a policy tag (governance provenance).
    assert_eq!(ev.policy_tags, vec!["NATO UNCLASSIFIED".to_string()]);
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
