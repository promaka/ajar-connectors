// SPDX-License-Identifier: Apache-2.0
//! STANAG 4609 / MISB ST 0601 (UAS Datalink Local Set) KLV ingress for Ajar.
//!
//! The connector is [`KlvParser`] — the ST 0601 decode — plugged into the shared
//! [`ajar_connector_common`] runtime. See `src/main.rs` for the wiring and the
//! repo `AGENTS.md` for how this connector was authored (the pattern to follow
//! for any new binary format).

pub mod klv;

pub use klv::{KlvError, KlvParser, UasMetadata};
