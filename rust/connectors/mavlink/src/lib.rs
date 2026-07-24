// SPDX-License-Identifier: Apache-2.0
//! MAVLink ingress for Ajar.
//!
//! The connector is [`MavParser`] — the MAVLink-specific decode — plugged into
//! the shared [`ajar_connector_common`] runtime. See `src/main.rs` for the wiring.

pub mod mavlink;

pub use mavlink::{MavError, MavParser, MavPosition};
