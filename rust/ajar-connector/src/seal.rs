// SPDX-License-Identifier: Apache-2.0
//! The seal envelope: a detached Ed25519 signature prefixed to the canonical bytes.
//!
//! ```text
//! sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

/// Length in bytes of the Ed25519 signature prefix on a sealed envelope.
pub const SEAL_SIGNATURE_LEN: usize = 64;

/// Why a sealed envelope was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SealError {
    /// Shorter than the signature prefix, so it carries no canonical bytes.
    #[error(
        "sealed envelope is {len} bytes, shorter than the {}-byte signature",
        SEAL_SIGNATURE_LEN
    )]
    Truncated {
        /// Length supplied.
        len: usize,
    },
    /// The signature is not a well-formed Ed25519 signature.
    #[error("signature prefix is not a valid Ed25519 signature")]
    MalformedSignature,
    /// The signature did not verify under the key, or the bytes were altered.
    #[error("signature did not verify under the given key")]
    Unverified,
}

/// Seals `canonical` bytes: signs them with `signing_key` and returns the 64-byte
/// detached signature followed by the canonical bytes.
///
/// ```text
/// sealed = ed25519_sign(signing_key, canonical_bytes) ++ canonical_bytes
/// ```
///
/// The verifier splits at [`SEAL_SIGNATURE_LEN`], checks the signature over the
/// remainder with the connector's registered verifying key, and recovers the
/// canonical event from the suffix.
///
/// Each production connector holds its own signing key; Ajar registers the matching
/// public key in the connector's profile. The seed used by the golden vectors is a
/// published test seed: never sign production events with it.
pub fn seal(canonical: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(canonical);
    let mut out = Vec::with_capacity(SEAL_SIGNATURE_LEN + canonical.len());
    out.extend_from_slice(&signature.to_bytes());
    out.extend_from_slice(canonical);
    out
}

/// Verifies a sealed envelope against `verifying_key` and returns the canonical
/// bytes it carries. The inverse of [`seal`].
///
/// It answers whether these exact bytes were sealed by the holder of this key,
/// unaltered since. A caller holding a connector's registered verifying key can
/// establish provenance without the connector, the broker or Ajar Core being present
/// or trusted.
///
/// The returned slice borrows from `sealed`, so verifying costs no copy. Decode it
/// with `prost::Message::decode` to recover the [`crate::event::Event`]. A 64-byte
/// envelope carries zero canonical bytes, which is well-formed; the caller decides
/// whether an empty event is meaningful.
///
/// ```
/// use ajar_connector::{EventBuilder, SigningKey};
///
/// let key = SigningKey::from_bytes(&[0x47; 32]);
/// let event = EventBuilder::new("acme-radar-1", "mim:aircraft")
///     .new_id()
///     .now()
///     .build()?;
///
/// let sealed = ajar_connector::seal(&ajar_connector::canonical_bytes(&event), &key);
/// let canonical = ajar_connector::verify(&sealed, &key.verifying_key())?;
/// assert_eq!(canonical, ajar_connector::canonical_bytes(&event));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn verify<'a>(sealed: &'a [u8], verifying_key: &VerifyingKey) -> Result<&'a [u8], SealError> {
    if sealed.len() < SEAL_SIGNATURE_LEN {
        return Err(SealError::Truncated { len: sealed.len() });
    }
    let (prefix, canonical) = sealed.split_at(SEAL_SIGNATURE_LEN);
    let signature = Signature::from_slice(prefix).map_err(|_| SealError::MalformedSignature)?;
    verifying_key
        .verify(canonical, &signature)
        .map_err(|_| SealError::Unverified)?;
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x47; 32])
    }

    #[test]
    fn sealed_layout_is_signature_then_canonical() {
        let key = test_key();
        let canonical = b"hello ajar";
        let sealed = seal(canonical, &key);

        assert_eq!(sealed.len(), SEAL_SIGNATURE_LEN + canonical.len());
        let (sig_bytes, body) = sealed.split_at(SEAL_SIGNATURE_LEN);
        assert_eq!(body, canonical);

        let sig = ed25519_dalek::Signature::from_slice(sig_bytes).unwrap();
        key.verifying_key().verify(canonical, &sig).unwrap();
    }

    #[test]
    fn verify_returns_the_canonical_bytes() {
        let key = test_key();
        let canonical = b"hello ajar";
        let sealed = seal(canonical, &key);
        assert_eq!(verify(&sealed, &key.verifying_key()).unwrap(), canonical);
    }

    #[test]
    fn verify_rejects_a_tampered_body() {
        let key = test_key();
        let mut sealed = seal(b"hello ajar", &key);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(
            verify(&sealed, &key.verifying_key()),
            Err(SealError::Unverified)
        );
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let key = test_key();
        let mut sealed = seal(b"hello ajar", &key);
        sealed[0] ^= 0x01;
        assert!(matches!(
            verify(&sealed, &key.verifying_key()),
            Err(SealError::Unverified) | Err(SealError::MalformedSignature)
        ));
    }

    #[test]
    fn verify_rejects_another_keys_seal() {
        let mine = test_key();
        let theirs = SigningKey::from_bytes(&[0x11; 32]);
        let sealed = seal(b"hello ajar", &theirs);
        assert_eq!(
            verify(&sealed, &mine.verifying_key()),
            Err(SealError::Unverified)
        );
    }

    #[test]
    fn verify_rejects_a_truncated_envelope() {
        let key = test_key();
        let sealed = seal(b"hello ajar", &key);
        let short = &sealed[..SEAL_SIGNATURE_LEN - 1];
        assert_eq!(
            verify(short, &key.verifying_key()),
            Err(SealError::Truncated {
                len: SEAL_SIGNATURE_LEN - 1
            })
        );
    }

    #[test]
    fn an_empty_body_is_still_a_valid_seal() {
        let key = test_key();
        let sealed = seal(b"", &key);
        assert_eq!(sealed.len(), SEAL_SIGNATURE_LEN);
        assert_eq!(verify(&sealed, &key.verifying_key()).unwrap(), b"");
    }

    #[test]
    fn truncated_error_names_both_lengths() {
        assert_eq!(
            SealError::Truncated { len: 10 }.to_string(),
            "sealed envelope is 10 bytes, shorter than the 64-byte signature"
        );
    }
}
