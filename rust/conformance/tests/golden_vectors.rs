// SPDX-License-Identifier: Apache-2.0
//! Golden vectors: canonical and sealed SHA-256 of every corpus fixture.

use ajar_connector::SigningKey;
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn test_signing_key(seed_hex: &str) -> SigningKey {
    let seed = hex::decode(seed_hex).expect("decode signing seed hex");
    let seed: [u8; 32] = seed.try_into().expect("signing seed is 32 bytes");
    SigningKey::from_bytes(&seed)
}

#[test]
fn verifying_key_derives_from_test_seed() {
    let vectors = conformance::load_vectors();
    let key = test_signing_key(&vectors.signing_seed_hex);
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        vectors.verifying_key_hex,
        "verifying key derived from the test seed must match vectors.json"
    );
}

#[test]
fn golden_vectors_are_reproduced() {
    let vectors = conformance::load_vectors();
    let key = test_signing_key(&vectors.signing_seed_hex);

    assert!(!vectors.vectors.is_empty(), "no vectors to check");

    for (name, expected) in &vectors.vectors {
        let event = conformance::load_fixture(name);

        let canonical = ajar_connector::canonical_bytes(&event);
        assert_eq!(
            sha256_hex(&canonical),
            expected.canonical_sha256,
            "canonical SHA-256 mismatch for fixture {name}"
        );

        let sealed = ajar_connector::seal(&canonical, &key);
        assert_eq!(
            sha256_hex(&sealed),
            expected.sealed_sha256,
            "sealed SHA-256 mismatch for fixture {name}"
        );
    }
}
