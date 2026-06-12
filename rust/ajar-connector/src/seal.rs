// SPDX-License-Identifier: Apache-2.0
//! The seal envelope: detached Ed25519 signature prefixed to canonical bytes.
//!
//! ```text
//! sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
//!          └────────────── 64-byte detached signature ─────────────┘
//! ```
//!
//! Each production connector holds its own signing key; Ajar registers the
//! matching public key in the connector's profile. The seed used by the golden
//! vectors is a published TEST seed — never sign production events with it.

use ed25519_dalek::{Signer, SigningKey};

/// Length in bytes of the Ed25519 signature prefix on a sealed envelope.
pub const SEAL_SIGNATURE_LEN: usize = 64;

/// Seals `canonical` bytes: signs them with `signing_key` and returns the
/// 64-byte detached signature followed by the canonical bytes themselves.
///
/// The verifier splits at [`SEAL_SIGNATURE_LEN`], checks the signature over the
/// remainder with the connector's registered verifying key, and recovers the
/// canonical event from the suffix.
pub fn seal(canonical: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(canonical);
    let mut out = Vec::with_capacity(SEAL_SIGNATURE_LEN + canonical.len());
    out.extend_from_slice(&signature.to_bytes());
    out.extend_from_slice(canonical);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn sealed_layout_is_signature_then_canonical() {
        let key = SigningKey::from_bytes(&[0x47; 32]);
        let canonical = b"hello ajar";
        let sealed = seal(canonical, &key);

        assert_eq!(sealed.len(), SEAL_SIGNATURE_LEN + canonical.len());
        let (sig_bytes, body) = sealed.split_at(SEAL_SIGNATURE_LEN);
        assert_eq!(body, canonical);

        let sig = ed25519_dalek::Signature::from_slice(sig_bytes).unwrap();
        key.verifying_key().verify(canonical, &sig).unwrap();
    }
}
