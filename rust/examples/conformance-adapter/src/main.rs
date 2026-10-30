// SPDX-License-Identifier: Apache-2.0
//! The smallest implementation `ajar-conformance` can test: reads a fixture on
//! stdin and writes its canonical or sealed bytes on stdout.
//!
//! Usage: `conformance-adapter canonical|sealed < fixture.json`; `sealed` reads
//! the hex seed from `AJAR_TEST_SIGNING_SEED`.

use std::io::{Read, Write};

use ed25519_dalek::SigningKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_default();

    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body)?;

    // The golden tests' own fixture loader, so the adapter and the gate agree.
    let event = conformance::fixture_from_str(&body)?;
    let canonical = ajar_connector::canonical_bytes(&event);

    let out: Vec<u8> = match mode.as_str() {
        "canonical" => canonical,
        "sealed" => {
            let seed_hex = std::env::var("AJAR_TEST_SIGNING_SEED")
                .map_err(|_| "sealed mode requires AJAR_TEST_SIGNING_SEED")?;
            let seed: [u8; 32] = hex::decode(seed_hex.trim())?
                .try_into()
                .map_err(|_| "signing seed must decode to exactly 32 bytes")?;
            ajar_connector::seal(&canonical, &SigningKey::from_bytes(&seed))
        }
        other => {
            return Err(format!("unknown mode {other:?}: expected canonical or sealed").into())
        }
    };

    std::io::stdout().write_all(&out)?;
    Ok(())
}
