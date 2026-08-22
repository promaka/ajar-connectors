// SPDX-License-Identifier: Apache-2.0
//! Verification is the egress hot path, so its speed is a tested property, not
//! a README claim: a change that makes it slow fails here rather than quietly
//! degrading a consumer.

use ajar_connector::{canonical_bytes, seal, verify, EventBuilder, SigningKey};

#[test]
fn verify_throughput_is_hot_path_grade() {
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
        .unwrap();
    let key = SigningKey::from_bytes(&seed);
    let event = EventBuilder::new("acme-radar-1", "mim:aircraft")
        .new_id()
        .timestamp("2026-06-10T08:00:00Z")
        .location(25.27, 51.52, 10600.0)
        .attribute("hostility", "Friend")
        .build()
        .unwrap();
    let sealed = seal(&canonical_bytes(&event), &key);
    let vk = key.verifying_key();

    const N: u32 = 5000;
    let start = std::time::Instant::now();
    for _ in 0..N {
        verify(&sealed, &vk).unwrap();
    }
    let per_sec = f64::from(N) / start.elapsed().as_secs_f64();
    println!("verify: {per_sec:.0} envelopes/sec on one core");
    assert!(
        per_sec > 1000.0,
        "verification unexpectedly slow: {per_sec:.0}/sec"
    );
}
