// SPDX-License-Identifier: Apache-2.0
//! ASTERIX ingress for Ajar — the radar picture, air and surface.
//!
//! The connector is [`AsterixParser`], a category-generic FSPEC/UAP engine that
//! decodes CAT010 (surface movement), CAT021 (ADS-B), CAT048 (monoradar) and
//! CAT062 (SDPS system tracks) into canonical tracks, and CAT034 (radar service
//! messages) into a signed heartbeat per antenna rotation, plugged into the
//! shared [`ajar_connector_common`] runtime.
//! See `src/main.rs` for the wiring and `AGENTS.md` for the pattern.

pub mod asterix;

pub use asterix::{AsterixError, AsterixParser, AsterixTarget, RadarStatus, Sensor, ServiceReport};
