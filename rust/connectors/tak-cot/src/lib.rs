// SPDX-License-Identifier: Apache-2.0
//! TAK / Cursor-on-Target ingress for Ajar.
//!
//! The whole connector is [`CotParser`] — the CoT-specific normalization — plugged
//! into the shared [`ajar_connector_common`] runtime. See `src/main.rs` for the
//! wiring; it is a few lines.

pub mod cot;

pub use cot::{CotError, CotParser};
