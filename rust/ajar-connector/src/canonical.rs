// SPDX-License-Identifier: Apache-2.0
//! Canonical byte encoding of an [`Event`].
//!
//! The canonical bytes are the protobuf encoding of the vendored contract's
//! `Event`, under the additional constraints this contract imposes (see below).
//! These are the bytes that get signed; they are what Ajar hashes for provenance.
//!
//! **What makes them canonical is the conformance gate, not the encoder.**
//! Protobuf serialization is not canonical in general — the specification does
//! not require a particular field order, and implementations are free to differ.
//! Each SDK here uses a *different* encoder (prost, Go protobuf, libprotobuf,
//! nanopb, Python protobuf), so byte-identity across them is an empirical
//! property that must be tested, not a guarantee inherited from protobuf. The
//! golden vectors in `vendor/contract/vectors.json` are what enforce it: every
//! SDK, in every release, must reproduce the exact `v1` bytes and their SHA-256,
//! or the release does not ship.
//!
//! An implementer writing a sixth encoder against this contract should therefore
//! treat the vectors as the specification and validate against them, rather than
//! assuming their protobuf library agrees with ours.
//!
//! The one rule a connector author can violate is the [`Attribute`] ordering:
//! attributes MUST be sorted by `key` with unique keys, or the encoding is
//! non-canonical and Ajar rejects the event. [`crate::EventBuilder`] enforces
//! this for you; [`canonical_bytes`] trusts that invariant and does not re-sort.

use crate::event::Event;
use prost::Message;

/// Returns the canonical protobuf encoding of `event`.
///
/// Canonicality rests on three things holding together: the contract declares no
/// map fields (the one proto construct with unspecified ordering), the caller
/// supplies attributes sorted by key with no duplicates, and the golden vectors
/// confirm this encoder still agrees with every other SDK. The first two are
/// properties of the input; the third is what the conformance gate checks.
///
/// The caller is responsible for the attribute invariant (sorted, unique keys).
/// When the event came from [`crate::EventBuilder`], that holds by construction.
pub fn canonical_bytes(event: &Event) -> Vec<u8> {
    event.encode_to_vec()
}
