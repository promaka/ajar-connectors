// SPDX-License-Identifier: Apache-2.0
//! ASTERIX CAT021 (ADS-B) ingress for Ajar.
//!
//! The connector is [`AsterixParser`] — the CAT021-specific decode — plugged into
//! the shared [`ajar_connector_common`] runtime. See `src/main.rs` for the wiring.

pub mod asterix;

pub use asterix::{AsterixError, AsterixParser, AsterixTarget};
