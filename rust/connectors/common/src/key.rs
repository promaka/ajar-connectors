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

#[cfg(test)]
mod tests {
    use super::load;
    use ed25519_dalek::SigningKey;
    use std::io::Write as _;

    fn tmp(tag: &str, contents: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ajar-key-{tag}-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents).unwrap();
        p
    }

    #[test]
    fn accepts_the_64_hex_ajar_keygen_writes() {
        // `ajar keygen` emits 64 hex chars, commonly with a trailing newline.
        let seed = [0x11u8; 32];
        let p = tmp("hex", format!("{}\n", hex::encode(seed)).as_bytes());
        let key = load(p.to_str().unwrap()).unwrap();
        assert_eq!(key.to_bytes(), seed);
        // The verifying key must match what `ajar connector add` wrote to the registry.
        assert_eq!(
            key.verifying_key().to_bytes(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn still_accepts_32_raw_bytes() {
        let seed = [0x22u8; 32];
        let p = tmp("raw", &seed);
        assert_eq!(load(p.to_str().unwrap()).unwrap().to_bytes(), seed);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rejects_garbage_fail_closed() {
        let p = tmp("bad", b"not a valid key");
        assert!(load(p.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
