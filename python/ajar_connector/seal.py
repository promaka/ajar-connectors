# SPDX-License-Identifier: Apache-2.0
"""The seal envelope: detached Ed25519 signature prefixed to canonical bytes."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
