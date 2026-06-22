// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"fmt"
)

// SealSignatureLen is the length in bytes of the Ed25519 signature prefix on a
// sealed envelope.
const SealSignatureLen = ed25519.SignatureSize // 64

// SigningKeyFromSeed derives a connector signing key from a 32-byte seed,
// returning a clear error if the seed is the wrong length. Prefer this over
// ed25519.NewKeyFromSeed, which panics with a cryptic message on a bad length.
// Mirrors the Python/C++ SDKs' from_seed for cross-language parity.
//
// The golden-vector seed (32 x 0x47) is a published TEST seed — never sign
// production events with it; load a real per-connector seed from your secret
// store.
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
// canonical event from the suffix.
//
// Each production connector holds its own key; the golden-vector seed
// (32 x 0x47) is a published TEST seed — never sign production events with it.
func Seal(canonical []byte, key ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(key, canonical)
	out := make([]byte, 0, len(sig)+len(canonical))
	out = append(out, sig...)
	out = append(out, canonical...)
	return out
}
