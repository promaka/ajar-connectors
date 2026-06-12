// SPDX-License-Identifier: Apache-2.0
//! Canonical byte encoding of an [`Event`].
//!
//! The canonical bytes are the deterministic protobuf encoding produced by
//! `prost` from the vendored contract. Because every language SDK is generated
//! from the same `event.proto` and uses the same encoder, the bytes — and thus
//! the SHA-256 over them — are identical across Rust, Go, and Python. These are
//! the bytes that get signed; they are what Ajar hashes for provenance.
//!
//! The one rule a connector author can violate is the [`Attribute`] ordering:
//! attributes MUST be sorted by `key` with unique keys, or the encoding is
//! non-canonical and Ajar rejects the event. [`crate::EventBuilder`] enforces
//! this for you; [`canonical_bytes`] trusts that invariant and does not re-sort.

use crate::event::Event;
use prost::Message;

/// Returns the canonical protobuf encoding of `event`.
///
/// This is `prost`'s deterministic encoding (no map fields are present in the
/// contract, so encoding is fully determined by field values and order).
///
/// The caller is responsible for the attribute invariant (sorted, unique keys).
/// When the event came from [`crate::EventBuilder`], that holds by construction.
pub fn canonical_bytes(event: &Event) -> Vec<u8> {
    event.encode_to_vec()
}
