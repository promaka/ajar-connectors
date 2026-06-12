// SPDX-License-Identifier: Apache-2.0

// Command first_connector is the Go "first connector" demo: native CoT in,
// signed canonical event out.
//
// Run with: go run ./examples/cot/cmd/first_connector
package main

import (
	"crypto/ed25519"
	"fmt"

	"github.com/promaka/ajar-connectors/go/ajarconnector"
	"github.com/promaka/ajar-connectors/go/examples/cot"
)

// demoSeed is illustration only. Generate and persist a real per-connector key
// for anything that leaves your machine; never sign real events with this.
var demoSeed = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
}

func main() {
	native := []byte(`<event version="2.0" uid="0191e7b0-3c2d-7e3f-8a9b-0c1d2e3f4a5d"
		type="a-f-A" time="2026-06-04T02:00:00Z" start="2026-06-04T02:00:00Z"
		stale="2026-06-04T02:00:30Z">
		<point lat="26.4" lon="50.9" hae="1200.0" ce="10.0" le="10.0"/>
	</event>`)

	// 1. Normalize native -> canonical event.
	connector := cot.New("ad-radar-7")
	event, err := connector.Normalize(native)
	if err != nil {
		panic(err)
	}

	// 2. Canonicalize and sign with this connector's own key.
	key := ed25519.NewKeyFromSeed(demoSeed)
	canonical, err := ajarconnector.CanonicalBytes(event)
	if err != nil {
		panic(err)
	}
	sealed := ajarconnector.Seal(canonical, key)

	// 3. Declare the profile Ajar registers for this connector.
	profile := ajarconnector.NewConnectorProfile("ad-radar-7", key.Public().(ed25519.PublicKey)).
		AllowEntityType("mim:aircraft").
		RateLimit(200, 20.0)
	profileJSON, err := profile.ToJSONPretty()
	if err != nil {
		panic(err)
	}

	fmt.Printf("entity_type : %s\n", event.GetEntityType())
	fmt.Printf("canonical   : %d bytes\n", len(canonical))
	fmt.Printf("sealed      : %d bytes (64-byte sig + canonical)\n", len(sealed))
	fmt.Printf("profile     :\n%s\n", profileJSON)
}
