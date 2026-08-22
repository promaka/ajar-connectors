// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func sealed(t *testing.T) ([]byte, ed25519.PublicKey, []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	canonical := []byte("hello ajar")
	return Seal(canonical, key), key.Public().(ed25519.PublicKey), canonical
}

func TestVerifyRoundTripsSeal(t *testing.T) {
	env, pub, canonical := sealed(t)
	got, err := Verify(env, pub)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(canonical) {
		t.Fatalf("canonical bytes differ")
	}
}

func TestVerifyRefusesTamperAnywhere(t *testing.T) {
	env, pub, _ := sealed(t)
	for _, i := range []int{0, SealSignatureLen - 1, SealSignatureLen, len(env) - 1} {
		bad := append([]byte(nil), env...)
		bad[i] ^= 0x01
		if _, err := Verify(bad, pub); err == nil {
			t.Fatalf("tamper at byte %d was accepted", i)
		}
	}
}

func TestVerifyRefusesTruncationAndWrongKey(t *testing.T) {
	env, _, _ := sealed(t)
	if _, err := Verify(env[:SealSignatureLen-1], nil); err == nil {
		t.Fatal("truncated envelope accepted")
	}
	_, otherPub, _ := sealed(t)
	if _, err := Verify(env, otherPub); err == nil {
		t.Fatal("another key's seal accepted")
	}
}

func TestVerifyThroughputIsHotPathGrade(t *testing.T) {
	env, pub, _ := sealed(t)
	const n = 5000
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := Verify(env, pub); err != nil {
			t.Fatal(err)
		}
	}
	perSec := float64(n) / time.Since(start).Seconds()
	t.Logf("verify: %.0f envelopes/sec on one core", perSec)
	if perSec < 1000 {
		t.Fatalf("verification unexpectedly slow: %.0f/sec", perSec)
	}
}
