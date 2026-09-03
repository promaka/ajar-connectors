// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func sealedFor(t *testing.T, key ed25519.PrivateKey, sourceID string, payload []byte, model string) []byte {
	t.Helper()
	b := NewEventBuilder(sourceID, "mim:vessel").NewID().Now().Payload(payload)
	if model != "" {
		b = b.Attribute("model", model)
	}
	event, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalBytes(event)
	if err != nil {
		t.Fatal(err)
	}
	return Seal(canonical, key)
}

func TestVerifyingHandlerIsTheUnskippableMiddle(t *testing.T) {
	seed := bytes.Repeat([]byte{0x55}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)

	var stats ConsumerStats
	var got []Delivery
	deliver := VerifyingHandler(pub, ConsumerGuards{
		SkipSourceIDs: map[string]bool{"me": true},
		SkipDerived:   true,
	}, &stats, func(d Delivery) { got = append(got, d) })

	// Valid: reaches the handler with the payload and subject intact.
	deliver(sealedFor(t, key, "radar-1", []byte("one"), ""), "ajar.egress.t.x")
	// Tampered: rejected inside, handler never sees it.
	tampered := sealedFor(t, key, "radar-1", []byte("evil"), "")
	tampered[len(tampered)-1] ^= 0xFF
	deliver(tampered, "ajar.egress.t.x")
	// Own event and a derived event: skipped by the guards.
	deliver(sealedFor(t, key, "me", []byte("mine"), ""), "ajar.egress.t.x")
	deliver(sealedFor(t, key, "ai-1", []byte("derived"), "m@1"), "ajar.egress.t.x")
	// Valid again: the loop survived everything above.
	deliver(sealedFor(t, key, "radar-1", []byte("two"), ""), "ajar.egress.t.x")

	if len(got) != 2 || string(got[0].Payload) != "one" || string(got[1].Payload) != "two" {
		t.Fatalf("handler saw %v", got)
	}
	if got[0].Subject != "ajar.egress.t.x" || got[0].Event.SourceId != "radar-1" {
		t.Fatalf("delivery metadata wrong: %+v", got[0])
	}
	if stats.Accepted != 2 || stats.Rejected != 1 || stats.Skipped != 2 {
		t.Fatalf("stats wrong: %+v", stats)
	}
}
