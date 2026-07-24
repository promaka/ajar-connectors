// SPDX-License-Identifier: Apache-2.0
//! Error types for building and validating events.

use thiserror::Error;

/// Why an [`crate::EventBuilder`] refused to produce an [`crate::Event`].
///
/// The builder fails closed: it would rather reject than emit a non-canonical
/// or under-specified event that Ajar's boundary would discard anyway.
#[derive(Debug, Error, PartialEq)]
pub enum BuildError {
    /// A field required by the contract was not set.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Two attributes shared the same key. Canonical attributes are unique.
    #[error("duplicate attribute key: {0:?}")]
    DuplicateAttributeKey(String),

    /// More than the contract's per-event limit of attributes.
    #[error("too many attributes: {count} (max {max})")]
    TooManyAttributes { count: usize, max: usize },

    /// Two metadata entries shared the same key. Canonical metadata is unique.
    #[error("duplicate metadata key: {0:?}")]
    DuplicateMetadataKey(String),

    /// More than the contract's per-event limit of metadata entries.
    #[error("too many metadata entries: {count} (max {max})")]
    TooManyMetadata { count: usize, max: usize },

    /// More than the contract's per-event limit of policy tags.
    #[error("too many policy tags: {count} (max {max})")]
    TooManyPolicyTags { count: usize, max: usize },

    /// `entity_type` was not a namespaced controlled-vocab value
    /// (`mim:<type>` or `x:<vendor>:<type>`).
    #[error("entity_type {0:?} is not namespaced as mim:<type> or x:<vendor>:<type>")]
    UnnamespacedEntityType(String),

    /// `confidence` was outside the inclusive range `[0.0, 1.0]`.
    #[error("confidence {0} is outside [0.0, 1.0]")]
    ConfidenceOutOfRange(f64),

    /// `timestamp` was not an RFC 3339 date-time (e.g. `2026-06-10T08:00:00Z`).
    #[error("timestamp {0:?} is not RFC 3339")]
    InvalidTimestamp(String),

    /// A location was outside WGS-84 bounds (or not a finite number).
    #[error("location ({latitude}, {longitude}) is not a valid WGS-84 position")]
    InvalidLocation { latitude: f64, longitude: f64 },
}
