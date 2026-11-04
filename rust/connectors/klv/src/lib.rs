// SPDX-License-Identifier: Apache-2.0
//! STANAG 4609 / MISB ST 0601 (UAS Datalink Local Set) KLV ingress for Ajar.

pub mod klv;

pub use klv::{KlvError, KlvParser, UasMetadata};
