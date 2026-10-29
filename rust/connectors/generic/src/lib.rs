// SPDX-License-Identifier: Apache-2.0
//! Config-driven ingress for Ajar: a [`Mapping`] in the connector's TOML turns
//! JSON or CSV records into events with no per-source code.

pub mod generic;
pub mod mapping;

pub use generic::{GenericError, GenericParser};
pub use mapping::Mapping;
