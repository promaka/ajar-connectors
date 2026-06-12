// SPDX-License-Identifier: Apache-2.0

// Package ajarconnector is the Go SDK for building byte-compatible connectors to
// the Ajar integration plane. It mirrors the Rust crate: types are generated
// from the same vendored event.proto, and canonical bytes are the deterministic
// protobuf encoding that gets hashed and signed. The shared
// vendor/contract/vectors.json proves the Go output is byte-identical to Rust's.
package ajarconnector

import (
	"google.golang.org/protobuf/proto"

	"github.com/promaka/ajar-connectors/go/eventpb"
)

// CanonicalBytes returns the canonical protobuf encoding of event.
//
// Determinism comes from proto.MarshalOptions{Deterministic: true}, which emits
// fields in ascending tag order and omits proto3 defaults — the same shape prost
// produces in Rust. The contract has no map fields, so the encoding is fully
// determined by the field values.
//
// The caller owns the attribute invariant (sorted by key, unique). When the
// event came from EventBuilder, that holds by construction.
func CanonicalBytes(event *eventpb.Event) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(event)
}
