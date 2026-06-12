// SPDX-License-Identifier: Apache-2.0

package cot

import (
	"bytes"
	"testing"

	"github.com/promaka/ajar-connectors/go/ajarconnector"
)

// Compile-time proof the CoT connector satisfies both SDK interfaces.
var (
	_ ajarconnector.Connector       = (*Connector)(nil)
	_ ajarconnector.OutboundProfile = (*Connector)(nil)
)

const sample = `<event version="2.0" uid="0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d" type="a-f-A" time="2026-06-04T02:00:00Z" start="2026-06-04T02:00:00Z" stale="2026-06-04T02:00:30Z"><point lat="26.4" lon="50.9" hae="1200.0" ce="10.0" le="10.0"/></event>`

func TestNormalizesCotToCanonicalEvent(t *testing.T) {
	conn := New("ad-radar-7")
	event, err := conn.Normalize([]byte(sample))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.GetEntityType() != "mim:aircraft" {
		t.Errorf("entity_type = %q, want mim:aircraft", event.GetEntityType())
	}
	if event.GetId() != "0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d" {
		t.Errorf("id = %q", event.GetId())
	}
	loc := event.GetLocation()
	if loc == nil || loc.GetLatitude() != 26.4 || loc.GetAltitudeM() != 1200.0 {
		t.Errorf("location = %+v", loc)
	}
}

// Round-trip conformance: canonical -> CoT -> canonical is identity over the
// modeled fields (lossy fields left at defaults so full bytes match).
func TestRoundTripPreservesModeledFields(t *testing.T) {
	conn := New("ad-radar-7")
	original, err := ajarconnector.NewEventBuilder("ad-radar-7", "mim:aircraft").
		ID("0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d").
		Timestamp("2026-06-04T02:00:00Z").
		Location(26.4, 50.9, 1200.0).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	back, err := conn.Normalize(conn.Render(original))
	if err != nil {
		t.Fatalf("normalize rendered: %v", err)
	}

	origBytes, err := ajarconnector.CanonicalBytes(original)
	if err != nil {
		t.Fatalf("canonical original: %v", err)
	}
	backBytes, err := ajarconnector.CanonicalBytes(back)
	if err != nil {
		t.Fatalf("canonical back: %v", err)
	}
	if !bytes.Equal(origBytes, backBytes) {
		t.Fatalf("modeled fields did not survive the CoT round trip")
	}
}
