// SPDX-License-Identifier: Apache-2.0
//! AIS / NMEA 0183 ingress for Ajar.
//!
//! The connector is [`AisParser`] plugged into the shared
//! [`ajar_connector_common`] runtime: AIS transponder decode (`!--VDM`/`VDO`)
//! and ARPA radar tracked targets (`$--TTM`, geolocated against own-ship GPS
//! on the same bus) from one feed. See `src/main.rs` for the wiring.

pub mod ais;
pub mod ttm;

pub use ais::{AisError, AisParser, AisPosition};
pub use ttm::RadarTarget;
