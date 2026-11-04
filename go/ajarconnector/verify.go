// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ErrUnverified is returned when a sealed envelope's signature does not check
// under the given key: these bytes were not sealed by the holder of that key,
// or they were altered afterwards.
var ErrUnverified = errors.New("signature did not verify under the given key")

// Verify checks a sealed envelope and returns the canonical bytes it carries,
// to decode with the generated Event type. On ingress, pass a producer's
// registered public key to prove origin; on egress, Core's egress key from the
// handover pack to prove the event passed governance unaltered. A holder of the
// key can establish this without the connector, the broker or Ajar Core being
// present or trusted. The returned slice aliases sealed.
func Verify(sealed []byte, verifyingKey ed25519.PublicKey) ([]byte, error) {
	if len(sealed) < SealSignatureLen {
		return nil, fmt.Errorf("sealed envelope is %d bytes, shorter than the %d-byte signature",
			len(sealed), SealSignatureLen)
	}
	if len(verifyingKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("verifying key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(verifyingKey))
	}
	sig, canonical := sealed[:SealSignatureLen], sealed[SealSignatureLen:]
	if !ed25519.Verify(verifyingKey, canonical, sig) {
		return nil, ErrUnverified
	}
	return canonical, nil
}
