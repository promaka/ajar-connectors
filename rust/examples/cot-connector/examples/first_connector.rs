// SPDX-License-Identifier: Apache-2.0
//! Your first connector, end to end: native CoT in, signed canonical event out.
//!
//! Run with: `cargo run -p cot-connector --example first_connector`

use ajar_connector::{canonical_bytes, seal, Connector, ConnectorProfile, SigningKey};
use cot_connector::CotConnector;

fn main() {
    // A CoT message off the wire (a TAK/radar feed).
    let native = br#"<event version="2.0" uid="0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d"
        type="a-f-A" time="2026-06-04T02:00:00Z" start="2026-06-04T02:00:00Z"
        stale="2026-06-04T02:00:30Z">
        <point lat="26.4" lon="50.9" hae="1200.0" ce="10.0" le="10.0"/>
    </event>"#;

    // 1. Normalize native -> canonical event.
    let connector = CotConnector::new("ad-radar-7");
    let event = connector.normalize(native).expect("normalize CoT");

    // 2. Canonicalize and sign with this connector's own key.
    //    In production, generate one key per connector and persist it securely;
    //    this fixed demo key is for illustration only — never sign real events
    //    with it.
    let signing_key = SigningKey::from_bytes(&DEMO_KEY);
    let canonical = canonical_bytes(&event);
    let sealed = seal(&canonical, &signing_key);

    // 3. Declare the profile Ajar registers for this connector.
    let profile = ConnectorProfile::new("ad-radar-7", signing_key.verifying_key())
        .allow_entity_type("mim:aircraft")
        .rate_limit(200, 20.0);

    println!("entity_type : {}", event.entity_type);
    println!("canonical   : {} bytes", canonical.len());
    println!(
        "sealed      : {} bytes (64-byte sig + canonical)",
        sealed.len()
    );
    println!("profile     :\n{}", profile.to_json_pretty());
}

/// Demo signing key — illustration only. Generate and persist a real per-
/// connector key for anything that leaves your machine.
const DEMO_KEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
