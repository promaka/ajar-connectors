// SPDX-License-Identifier: Apache-2.0
//! Verification is the egress hot path; a change that makes it slow fails here.

use ajar_connector::{EventBuilder, SigningKey};

#[test]
fn verify_throughput_floor() {
    let key = SigningKey::from_bytes(&[0x47; 32]);
    let event = EventBuilder::new("acme-radar-1", "mim:aircraft")
        .new_id()
        .timestamp("2026-06-10T08:00:00Z")
        .location(25.27, 51.52, 10600.0)
        .attribute("hostility", "Friend")
        .build()
        .unwrap();
    let sealed = ajar_connector::seal(&ajar_connector::canonical_bytes(&event), &key);
    let verifying_key = key.verifying_key();

    const N: u32 = 5000;
    let start = std::time::Instant::now();
    for _ in 0..N {
        ajar_connector::verify(&sealed, &verifying_key).unwrap();
    }
    let per_sec = f64::from(N) / start.elapsed().as_secs_f64();
    assert!(per_sec > 1000.0, "{per_sec:.0} verifications/sec");
}
