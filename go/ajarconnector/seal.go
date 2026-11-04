// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"fmt"
)

// SealSignatureLen is the length in bytes of the Ed25519 signature prefix on a
// sealed envelope.
const SealSignatureLen = ed25519.SignatureSize

// SigningKeyFromSeed derives a connector signing key from an
// ed25519.SeedSize-byte seed, returning an error on a wrong length where
// ed25519.NewKeyFromSeed would panic. The golden-vector seed (0x47 repeated)
// is public and only for tests; load a per-connector seed from a secret store.
func SigningKeyFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Seal signs canonical with key and returns the 64-byte detached signature
// followed by the canonical bytes:
//
//	sealed = ed25519_sign(key, canonical) ++ canonical
//
// The verifier splits at SealSignatureLen, checks the signature over the
// remainder with the connector's registered public key, and recovers the
// canonical event from the suffix. Each production connector holds its own key.
func Seal(canonical []byte, key ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(key, canonical)
	out := make([]byte, 0, len(sig)+len(canonical))
	out = append(out, sig...)
	out = append(out, canonical...)
	return out
}
