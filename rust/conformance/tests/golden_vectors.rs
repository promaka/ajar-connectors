// SPDX-License-Identifier: Apache-2.0
//! THE conformance gate. For every corpus fixture the SDK must:
//!   1. build the Event, compute canonical_bytes, assert SHA-256 == canonicalSha256
//!   2. seal it with the TEST seed, assert SHA-256 == sealedSha256
//!
//! Passing this is the definition of "byte-compatible with Ajar".

use ajar_connector::{canonical_bytes, seal};
use conformance::{load_fixture, load_vectors};
use ed25519_dalek::SigningKey;
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
    let vectors = load_vectors();
    let key = test_signing_key(&vectors.signing_seed_hex);
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        vectors.verifying_key_hex,
        "verifying key derived from TEST seed must match vectors.json"
    );
}

#[test]
fn golden_vectors_are_reproduced() {
    let vectors = load_vectors();
    let key = test_signing_key(&vectors.signing_seed_hex);

    assert!(!vectors.vectors.is_empty(), "no vectors to check");

    for (name, expected) in &vectors.vectors {
        let event = load_fixture(name);

        let canonical = canonical_bytes(&event);
        assert_eq!(
            sha256_hex(&canonical),
            expected.canonical_sha256,
            "canonical SHA-256 mismatch for fixture {name}"
        );

        let sealed = seal(&canonical, &key);
        assert_eq!(
            sha256_hex(&sealed),
            expected.sealed_sha256,
            "sealed SHA-256 mismatch for fixture {name}"
        );
    }
}
