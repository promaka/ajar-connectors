// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import "github.com/promaka/ajar-connectors/go/eventpb"

// Connector is an inbound connector: it turns a source system's native bytes
// into a canonical Event. Implementations parse native (CoT XML, a CSV row, a
// vendor binary frame, ...) and return a fully-populated event — ideally via
// EventBuilder so the canonical invariants hold by construction.
type Connector interface {
	Normalize(native []byte) (*eventpb.Event, error)
}

// OutboundProfile renders a governed Event into a target system's format. Its
// honesty is the ModeledFields / LossyFields declaration: which canonical fields
// survive translation and which are dropped or approximated. Round-trip
// conformance (canonical -> target -> canonical over the modeled fields) checks
// that claim; see the example package.
type OutboundProfile interface {
	// Target is the human-readable name of the target system (e.g. "TAK").
	Target() string
	// Slug is the stable machine slug for this profile (e.g. "tak-cot").
	Slug() string
	// Version is the profile version (semver-ish string).
	Version() string
	// ModeledFields are the canonical fields this profile faithfully carries.
	ModeledFields() []string
	// LossyFields are the canonical fields this profile drops or approximates.
	LossyFields() []string
	// Render renders the event into the target format's bytes.
	Render(event *eventpb.Event) []byte
}
