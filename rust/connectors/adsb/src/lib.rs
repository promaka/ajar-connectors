// SPDX-License-Identifier: Apache-2.0
//! ADS-B (SBS-1 / BaseStation) ingress for Ajar.

pub mod adsb;

pub use adsb::{AdsbError, AdsbParser, AdsbPosition, AircraftState};
