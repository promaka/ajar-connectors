// SPDX-License-Identifier: Apache-2.0
//! Loading the connector's Ed25519 signing seed.

use ed25519_dalek::SigningKey;

/// Load the signing seed from `path`: 32 raw bytes, or 64 hex characters.
pub fn load(path: &str) -> anyhow::Result<SigningKey> {
    let raw = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "signing key {path} not found. If your operator issued a packet, \
                 `ajar-up <packet.tar>` places it there; a key you generated yourself \
                 goes at this path as 32 raw bytes or 64 hex characters (onboarding \
                 guide, Keys)"
            )
        } else {
            anyhow::anyhow!("reading signing key {path}: {e}")
        }
    })?;
    let seed: [u8; 32] = match raw.as_slice().try_into() {
        Ok(seed) => seed,
        Err(_) => {
            let text = String::from_utf8_lossy(&raw);
            let bytes = hex::decode(text.trim()).map_err(|_| {
                anyhow::anyhow!("signing key {path}: neither 32 raw bytes nor 64-char hex")
            })?;
            bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("signing key {path}: hex must decode to exactly 32 bytes")
            })?
        }
    };
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::load;
    use ed25519_dalek::SigningKey;
    use std::io::Write as _;

    fn seed_file(contents: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f
    }

    fn load_file(f: &tempfile::NamedTempFile) -> anyhow::Result<SigningKey> {
        load(f.path().to_str().unwrap())
    }

    #[test]
    fn missing_seed_says_where_it_comes_from() {
        let msg = load("/nonexistent/dir/x.seed").unwrap_err().to_string();
        assert!(msg.contains("not found"), "{msg}");
        assert!(msg.contains("ajar-up <packet.tar>"), "{msg}");
    }

    #[test]
    fn accepts_hex_with_trailing_newline() {
        let seed = [0x11u8; 32];
        let f = seed_file(format!("{}\n", hex::encode(seed)).as_bytes());
        let key = load_file(&f).unwrap();
        assert_eq!(key.to_bytes(), seed);
        assert_eq!(
            key.verifying_key().to_bytes(),
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
    }

    #[test]
    fn accepts_32_raw_bytes() {
        let seed = [0x22u8; 32];
        assert_eq!(load_file(&seed_file(&seed)).unwrap().to_bytes(), seed);
    }

    #[test]
    fn rejects_garbage() {
        assert!(load_file(&seed_file(b"not a valid key")).is_err());
    }
}
