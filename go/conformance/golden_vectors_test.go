// SPDX-License-Identifier: Apache-2.0

// Package conformance is the Go side of THE gate: for every corpus fixture the
// SDK must reproduce the same canonicalSha256 + sealedSha256 the Rust SDK does,
// from the SAME vendor/contract/vectors.json. One vendored contract, three
// language harnesses, identical hashes — that is the proof of byte-compatibility.
package conformance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/promaka/ajar-connectors/go/ajarconnector"
	"github.com/promaka/ajar-connectors/go/eventpb"
)

// contractDir is the vendored contract, relative to this test package.
const contractDir = "../../vendor/contract"

type vectorsFile struct {
	SigningSeedHex  string `json:"signingSeedHex"`
	VerifyingKeyHex string `json:"verifyingKeyHex"`
	Vectors         map[string]struct {
		CanonicalSha256 string `json:"canonicalSha256"`
		SealedSha256    string `json:"sealedSha256"`
	} `json:"vectors"`
}

type fixtureEvent struct {
	SchemaVersion string `json:"schemaVersion"`
	ID            string `json:"id"`
	SourceID      string `json:"sourceId"`
	EntityType    string `json:"entityType"`
	Timestamp     string `json:"timestamp"`
	ReceivedAt    string `json:"receivedAt"`
	Location      *struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		AltitudeM float64 `json:"altitudeM"`
	} `json:"location"`
	Payload    string   `json:"payload"`
	PolicyTags []string `json:"policyTags"`
	Confidence float64  `json:"confidence"`
	Attributes []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"attributes"`
	Metadata []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"metadata"`
}

func loadVectors(t *testing.T) vectorsFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contractDir, "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	return v
}

// loadFixture reads corpus/<name>.json verbatim (including received_at, which a
// live connector would leave for Ajar to stamp) so the canonical bytes match
// what core hashed when it blessed these vectors.
func loadFixture(t *testing.T, name string) *eventpb.Event {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contractDir, "corpus", name+".json"))
	if err != nil {
		t.Fatalf("read %s.json: %v", name, err)
	}
	var f fixtureEvent
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s.json: %v", name, err)
	}

	var payload []byte
	if f.Payload != "" {
		payload, err = base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			t.Fatalf("base64 payload in %s.json: %v", name, err)
		}
	}

	var location *eventpb.GeoPoint
	if f.Location != nil {
		location = &eventpb.GeoPoint{
			Latitude:  f.Location.Latitude,
			Longitude: f.Location.Longitude,
			AltitudeM: f.Location.AltitudeM,
		}
	}

	attrs := make([]*eventpb.Attribute, len(f.Attributes))
	for i, a := range f.Attributes {
		attrs[i] = &eventpb.Attribute{Key: a.Key, Value: a.Value}
	}

	meta := make([]*eventpb.Attribute, len(f.Metadata))
	for i, m := range f.Metadata {
		meta[i] = &eventpb.Attribute{Key: m.Key, Value: m.Value}
	}

	return &eventpb.Event{
		SchemaVersion: f.SchemaVersion,
		Id:            f.ID,
		SourceId:      f.SourceID,
		EntityType:    f.EntityType,
		Timestamp:     f.Timestamp,
		ReceivedAt:    f.ReceivedAt,
		Location:      location,
		Payload:       payload,
		PolicyTags:    f.PolicyTags,
		Confidence:    f.Confidence,
		Attributes:    attrs,
		Metadata:      meta,
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func testSigningKey(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode signing seed hex: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("signing seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestVerifyingKeyDerivesFromTestSeed(t *testing.T) {
	v := loadVectors(t)
	key := testSigningKey(t, v.SigningSeedHex)
	got := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if got != v.VerifyingKeyHex {
		t.Fatalf("verifying key mismatch:\n got  %s\n want %s", got, v.VerifyingKeyHex)
	}
}

func TestGoldenVectorsAreReproduced(t *testing.T) {
	v := loadVectors(t)
	key := testSigningKey(t, v.SigningSeedHex)
	if len(v.Vectors) == 0 {
		t.Fatal("no vectors to check")
	}

	for name, expected := range v.Vectors {
		t.Run(name, func(t *testing.T) {
			event := loadFixture(t, name)

			canonical, err := ajarconnector.CanonicalBytes(event)
			if err != nil {
				t.Fatalf("canonical bytes: %v", err)
			}
			if got := sha256Hex(canonical); got != expected.CanonicalSha256 {
				t.Fatalf("canonical SHA-256 mismatch:\n got  %s\n want %s", got, expected.CanonicalSha256)
			}

			sealed := ajarconnector.Seal(canonical, key)
			if got := sha256Hex(sealed); got != expected.SealedSha256 {
				t.Fatalf("sealed SHA-256 mismatch:\n got  %s\n want %s", got, expected.SealedSha256)
			}
		})
	}
}
