// SPDX-License-Identifier: Apache-2.0
//! EUROCONTROL ASTERIX ingress for Ajar.

pub mod asterix;

pub use asterix::{AsterixError, AsterixParser, AsterixTarget, RadarStatus, Sensor, ServiceReport};
