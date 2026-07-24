// SPDX-License-Identifier: Apache-2.0
//! ADS-B (SBS-1 / BaseStation) ingress for Ajar.
//!
//! The connector is [`AdsbParser`] — the SBS-1 decode — plugged into the shared
//! [`ajar_connector_common`] runtime. See `src/main.rs` for the wiring.

pub mod adsb;

pub use adsb::{AdsbError, AdsbParser, AdsbPosition, AircraftState};
