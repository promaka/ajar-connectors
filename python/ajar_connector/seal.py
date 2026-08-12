# SPDX-License-Identifier: Apache-2.0
"""The seal envelope: detached Ed25519 signature prefixed to canonical bytes."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SEAL_SIGNATURE_LEN = 64
"""Length in bytes of the Ed25519 signature prefix on a sealed envelope."""


class SigningKey:
    """An Ed25519 signing key.

    Each production connector holds its own; Ajar registers the matching
    verifying key in the connector's profile. The golden-vector seed (32 x
    0x47) is a published TEST seed — never sign production events with it.
    """

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    @classmethod
    def from_seed(cls, seed: bytes) -> "SigningKey":
        """Derive a key from a 32-byte seed."""
        if len(seed) != 32:
            raise ValueError(f"signing seed must be 32 bytes, got {len(seed)}")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def verifying_key(self) -> bytes:
        """The 32-byte Ed25519 public (verifying) key."""
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, data: bytes) -> bytes:
        """Return the 64-byte detached signature over ``data``."""
        return self._key.sign(data)


def seal(canonical: bytes, key: SigningKey) -> bytes:
    """Seal canonical bytes: ``sign(key, canonical) ++ canonical``.

    The verifier splits at :data:`SEAL_SIGNATURE_LEN`, checks the signature over
    the remainder with the connector's registered verifying key, and recovers
    the canonical event from the suffix.
    """
    return key.sign(canonical) + canonical


class SealVerificationError(Exception):
    """A sealed envelope was not accepted."""


def verify(sealed: bytes, verifying_key: bytes) -> bytes:
    """Verify a sealed envelope and return the canonical bytes it carries.

    The inverse of :func:`seal`, and the whole trust model in one call: it
    answers whether these exact bytes were sealed by the holder of
    ``verifying_key`` and are unaltered since. A recipient holding a
    connector's registered verifying key can establish provenance without the
    connector, the broker or Ajar Core being present or trusted.

    ``verifying_key`` is the 32-byte raw Ed25519 public key, as published in the
    connector's profile.

    Raises :class:`SealVerificationError` if the envelope is too short, the key
    is not a valid Ed25519 public key, or the signature does not verify.
    """
    if len(verifying_key) != 32:
        raise SealVerificationError(
            f"verifying key must be 32 bytes, got {len(verifying_key)}"
        )
    if len(sealed) < SEAL_SIGNATURE_LEN:
        raise SealVerificationError(
            f"sealed envelope is {len(sealed)} bytes, shorter than the "
            f"{SEAL_SIGNATURE_LEN}-byte signature"
        )
    signature, canonical = sealed[:SEAL_SIGNATURE_LEN], sealed[SEAL_SIGNATURE_LEN:]
    try:
        Ed25519PublicKey.from_public_bytes(verifying_key).verify(signature, canonical)
    except InvalidSignature as exc:
        raise SealVerificationError(
            "signature did not verify under the given key"
        ) from exc
    except ValueError as exc:
        raise SealVerificationError(f"invalid verifying key: {exc}") from exc
    return canonical
