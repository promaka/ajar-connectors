// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import "crypto/ed25519"

// SealSignatureLen is the length in bytes of the Ed25519 signature prefix on a
// sealed envelope.
const SealSignatureLen = ed25519.SignatureSize // 64

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
