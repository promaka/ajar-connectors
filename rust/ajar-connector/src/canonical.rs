// SPDX-License-Identifier: Apache-2.0
//! Canonical byte encoding of an [`Event`]: the bytes that are signed and hashed.
//!
//! Protobuf encoding is not canonical in general, and each SDK uses a different
//! encoder. The golden vectors in `vendor/contract/vectors.json` are the
//! specification that keeps them byte-identical.

use crate::event::Event;
use prost::Message;

/// Returns the canonical protobuf encoding of `event`: the bytes that are signed,
/// and that Ajar hashes for provenance.
///
/// Attributes and metadata must be sorted by key with unique keys, or the encoding
/// is non-canonical and Ajar rejects the event. [`crate::EventBuilder`] guarantees
/// this; this function does not re-sort.
///
/// Protobuf serialization is not canonical in general, and each SDK uses a different
/// encoder. Writing another encoder, treat the golden vectors in
/// `vendor/contract/vectors.json` as the specification and validate against them.
pub fn canonical_bytes(event: &Event) -> Vec<u8> {
    event.encode_to_vec()
}
