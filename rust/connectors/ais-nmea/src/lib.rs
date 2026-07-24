// SPDX-License-Identifier: Apache-2.0
//! AIS / NMEA 0183 ingress for Ajar.
//!
//! The connector is [`AisParser`] — the AIS-specific decode — plugged into the
//! shared [`ajar_connector_common`] runtime. See `src/main.rs` for the wiring.

pub mod ais;

pub use ais::{AisError, AisParser, AisPosition};
