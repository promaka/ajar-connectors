// SPDX-License-Identifier: Apache-2.0
//! Config-driven ingress for Ajar — the no-code path.
//!
//! For the long tail of simple JSON/CSV sources, a [`mapping::Mapping`] in the
//! connector's TOML is enough: no Rust, just field names. The parser
//! ([`GenericParser`]) runs on the shared [`ajar_connector_common`] runtime and
//! any transport, exactly like the hand-written connectors. When a source needs
//! real logic (a binary wire format, reassembly), reach for the
//! `connector-template` code path instead.

pub mod generic;
pub mod mapping;

pub use generic::{GenericError, GenericParser};
pub use mapping::Mapping;
