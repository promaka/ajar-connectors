// SPDX-License-Identifier: Apache-2.0
//! Loading the connector's Ed25519 signing seed.

use anyhow::anyhow;
use ed25519_dalek::SigningKey;

/// Load the signing seed from `path`: either 32 raw bytes, or 64-char hex text
/// (both are portable in an air-gap bundle). Fails closed on anything else.
pub fn load(path: &str) -> anyhow::Result<SigningKey> {
    let raw = std::fs::read(path).map_err(|e| anyhow!("reading signing key {path}: {e}"))?;
    let seed: [u8; 32] = if raw.len() == 32 {
        raw.as_slice().try_into().expect("length checked")
    } else {
        let text = String::from_utf8_lossy(&raw);
        let bytes = hex::decode(text.trim())
            .map_err(|_| anyhow!("signing key {path}: neither 32 raw bytes nor 64-char hex"))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("signing key {path}: hex must decode to exactly 32 bytes"))?
    };
    Ok(SigningKey::from_bytes(&seed))
}
