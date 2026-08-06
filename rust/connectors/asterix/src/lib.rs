// SPDX-License-Identifier: Apache-2.0
//! ASTERIX ingress for Ajar — the air picture.
//!
//! The connector is [`AsterixParser`], a category-generic FSPEC/UAP engine that
//! decodes CAT021 (ADS-B), CAT048 (monoradar) and CAT062 (SDPS system tracks) into
//! canonical air tracks, plugged into the shared [`ajar_connector_common`] runtime.
//! See `src/main.rs` for the wiring and `AGENTS.md` for the pattern.

pub mod asterix;

pub use asterix::{AsterixError, AsterixParser, AsterixTarget, Sensor};
