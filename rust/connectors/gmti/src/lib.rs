// SPDX-License-Identifier: Apache-2.0
//! STANAG 4607 (NATO GMTI) ingress for Ajar.
//!
//! The connector is [`GmtiParser`] — the GMTI Dwell-segment decode — plugged into
//! the shared [`ajar_connector_common`] runtime. See `src/main.rs` for the wiring
//! and the repo `AGENTS.md` for the pattern this connector follows (a worked
//! example of a binary, existence-mask-driven STANAG format alongside `klv`).

pub mod gmti;

pub use gmti::{GmtiError, GmtiParser, GmtiTarget};
