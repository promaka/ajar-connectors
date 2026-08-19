// SPDX-License-Identifier: Apache-2.0
//! The smallest thing `ajar-conformance` can test: read a fixture on stdin,
//! write canonical or sealed bytes on stdout.
//!
//! It exists to show a partner exactly what the harness expects of their own
//! implementation, in any language — read stdin, emit raw bytes, exit 0 — and to
//! give the harness something real to run in CI.
//!
//! ```text
//! conformance-adapter canonical < fixture.json
//! AJAR_TEST_SIGNING_SEED=<hex> conformance-adapter sealed < fixture.json
//! ```

use std::io::{Read, Write};

use ajar_connector::{canonical_bytes, seal};
use ed25519_dalek::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_default();

    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body)?;

    // The fixture is the contract's own JSON shape; the loader that the golden
    // tests use turns it into an Event, so the adapter and the gate cannot drift.
    let event = conformance::fixture_from_str(&body)?;
    let canonical = canonical_bytes(&event);

    let out: Vec<u8> = match mode.as_str() {
        "canonical" => canonical,
        "sealed" => {
            let seed_hex = std::env::var("AJAR_TEST_SIGNING_SEED")
                .map_err(|_| "sealed mode requires AJAR_TEST_SIGNING_SEED")?;
            let seed: [u8; 32] = hex::decode(seed_hex.trim())?
                .try_into()
                .map_err(|_| "signing seed must decode to exactly 32 bytes")?;
            seal(&canonical, &SigningKey::from_bytes(&seed))
        }
        other => {
            return Err(format!("unknown mode {other:?}: expected canonical or sealed").into())
        }
    };

    std::io::stdout().write_all(&out)?;
    Ok(())
}
