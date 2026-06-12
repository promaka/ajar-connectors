// SPDX-License-Identifier: Apache-2.0
//! Connector traits: inbound normalization and outbound rendering.

use crate::event::Event;

/// An **inbound** connector: turns a source system's native bytes into a
/// canonical [`Event`].
///
/// Implementors parse `native` (CoT XML, a CSV row, a vendor binary frame, …)
/// and return a fully-populated event — ideally via [`crate::EventBuilder`] so
/// the canonical invariants hold by construction.
pub trait Connector {
    /// Error returned when native input cannot be normalized.
    type Error;

    /// Normalizes one native message into a canonical event.
    fn normalize(&self, native: &[u8]) -> Result<Event, Self::Error>;
}

/// An **outbound** connector profile: renders a governed [`Event`] into a
/// target system's format.
///
/// The honesty of an outbound connector is its `modeled_fields` /
/// `lossy_fields` declaration: it states which canonical fields survive the
/// translation and which are dropped or approximated. Round-trip conformance
/// (canonical → target → canonical over the modeled fields) is how that claim
/// is checked; see the example crate for a concrete round-trip test.
pub trait OutboundProfile {
    /// Human-readable name of the target system (e.g. `"TAK"`).
    fn target(&self) -> &str;

    /// Stable machine slug for this profile (e.g. `"tak-cot"`).
    fn slug(&self) -> &str;

    /// Profile version (semver-ish string).
    fn version(&self) -> &str;

    /// Canonical fields this profile faithfully carries into the target.
    fn modeled_fields(&self) -> &[&str];

    /// Canonical fields this profile drops or approximates.
    fn lossy_fields(&self) -> &[&str];

    /// Renders the event into the target format's bytes.
    fn render(&self, event: &Event) -> Vec<u8>;
}
