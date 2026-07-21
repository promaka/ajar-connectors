// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestBuilderSortsAttributesAndSetsDefaults(t *testing.T) {
	event, err := NewEventBuilder("sensor-1", "mim:drone").
		NewID().Now().
		Attribute("speed", "110").
		Attribute("heading", "225").
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if event.GetSchemaVersion() != "v1" {
		t.Errorf("schema_version = %q", event.GetSchemaVersion())
	}
	if event.GetReceivedAt() != "" {
		t.Errorf("received_at should be empty, got %q", event.GetReceivedAt())
	}
	attrs := event.GetAttributes()
	if len(attrs) != 2 || attrs[0].GetKey() != "heading" || attrs[1].GetKey() != "speed" {
		t.Errorf("attributes not sorted: %+v", attrs)
	}
}

func TestBuilderSortsMetadataAndRejectsDuplicateKeys(t *testing.T) {
	event, err := NewEventBuilder("sensor-1", "mim:drone").
		NewID().Now().
		Metadata("mmsi", "227006760").
		Metadata("callsign", "F-ABCD").
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	meta := event.GetMetadata()
	if len(meta) != 2 || meta[0].GetKey() != "callsign" || meta[1].GetKey() != "mmsi" {
		t.Errorf("metadata not sorted: %+v", meta)
	}

	_, err = NewEventBuilder("sensor-1", "mim:drone").
		NewID().Now().
		Metadata("mmsi", "1").
		Metadata("mmsi", "2").
		Build()
	if err == nil || !strings.Contains(err.Error(), "duplicate metadata key") {
		t.Fatalf("want duplicate-metadata-key error, got %v", err)
	}
}

func TestBuilderRejectsDuplicateAttributeKeys(t *testing.T) {
	_, err := NewEventBuilder("sensor-1", "mim:drone").
		NewID().Now().
		Attribute("heading", "225").
		Attribute("heading", "226").
		Build()
	if err == nil || !strings.Contains(err.Error(), "duplicate attribute key") {
		t.Fatalf("want duplicate-key error, got %v", err)
	}
}

func TestBuilderRequiresIDAndTimestamp(t *testing.T) {
	_, err := NewEventBuilder("sensor-1", "mim:drone").Build()
	if err == nil || !strings.Contains(err.Error(), "missing required field: id") {
		t.Fatalf("want missing-id error, got %v", err)
	}
}

func TestBuilderRejectsOutOfRangeConfidence(t *testing.T) {
	_, err := NewEventBuilder("sensor-1", "mim:drone").
		NewID().Now().Confidence(1.5).Build()
	if err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("want confidence error, got %v", err)
	}
}

func TestBuilderEnforcesNamespacingWithOptOut(t *testing.T) {
	_, err := NewEventBuilder("sensor-1", "drone").NewID().Now().Build()
	if err == nil || !strings.Contains(err.Error(), "not namespaced") {
		t.Fatalf("want namespacing error, got %v", err)
	}
	if _, err := NewEventBuilder("sensor-1", "drone").
		NewID().Now().AllowUnnamespacedEntityType().Build(); err != nil {
		t.Fatalf("opt-out should build, got %v", err)
	}
}

func TestNamespaceRules(t *testing.T) {
	cases := map[string]bool{
		"mim:vessel":    true,
		"mim:":          false,
		"x:acme:widget": true,
		"x:acme":        false,
		"drone":         false,
	}
	for in, want := range cases {
		if got := isNamespaced(in); got != want {
			t.Errorf("isNamespaced(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSealLayout(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x47
	}
	key := ed25519.NewKeyFromSeed(seed)
	canonical := []byte("hello ajar")
	sealed := Seal(canonical, key)
	if len(sealed) != SealSignatureLen+len(canonical) {
		t.Fatalf("sealed length = %d", len(sealed))
	}
	sig, body := sealed[:SealSignatureLen], sealed[SealSignatureLen:]
	if string(body) != string(canonical) {
		t.Fatalf("body mismatch")
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), canonical, sig) {
		t.Fatalf("signature did not verify")
	}
}

func TestProfileSerializesVerifyingKeyAsHex(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x47
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	profile := NewConnectorProfile("sensor-123", pub).
		AllowEntityType("mim:drone").
		MaxPayload(4096).
		RateLimit(50, 5.0)
	js, err := profile.ToJSON()
	if err != nil {
		t.Fatalf("to json: %v", err)
	}
	for _, want := range []string{`"source_id":"sensor-123"`, "mim:drone", "verifying_key_hex"} {
		if !strings.Contains(js, want) {
			t.Errorf("profile JSON missing %q: %s", want, js)
		}
	}
}
