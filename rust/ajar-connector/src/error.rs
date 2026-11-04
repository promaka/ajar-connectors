// SPDX-License-Identifier: Apache-2.0
//! Error types for building and validating events.

use thiserror::Error;

/// Why an [`crate::EventBuilder`] refused to produce an [`crate::Event`].
#[derive(Debug, Error, PartialEq)]
pub enum BuildError {
    /// A required field is not set.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Two attributes share a key.
    #[error("duplicate attribute key: {0:?}")]
    DuplicateAttributeKey(String),

    /// More attributes than the per-event limit.
    #[error("too many attributes: {count} (max {max})")]
    TooManyAttributes { count: usize, max: usize },

    /// Two metadata entries share a key.
    #[error("duplicate metadata key: {0:?}")]
    DuplicateMetadataKey(String),

    /// More metadata entries than the per-event limit.
    #[error("too many metadata entries: {count} (max {max})")]
    TooManyMetadata { count: usize, max: usize },

    /// More policy tags than the per-event limit.
    #[error("too many policy tags: {count} (max {max})")]
    TooManyPolicyTags { count: usize, max: usize },

    /// `entity_type` is not `mim:<type>` or `x:<vendor>:<type>`.
    #[error("entity_type {0:?} is not namespaced as mim:<type> or x:<vendor>:<type>")]
    UnnamespacedEntityType(String),

    /// `confidence` is outside `[0.0, 1.0]`.
    #[error("confidence {0} is outside [0.0, 1.0]")]
    ConfidenceOutOfRange(f64),

    /// `timestamp` is not an RFC 3339 date-time.
    #[error("timestamp {0:?} is not RFC 3339")]
    InvalidTimestamp(String),

    /// A location is outside WGS-84 bounds or not finite.
    #[error("location ({latitude}, {longitude}) is not a valid WGS-84 position")]
    InvalidLocation { latitude: f64, longitude: f64 },
}
