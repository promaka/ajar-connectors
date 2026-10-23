// SPDX-License-Identifier: Apache-2.0
//! SAPIENT (BSI Flex 335) ingress for Ajar: the fusion-node side of the UK MOD
//! counter-UAS sensor interface.
//!
//! The connector is [`SapientParser`], which turns each SAPIENT message into a
//! signed event, plugged into the shared [`ajar_connector_common`] runtime.
//! Acting as the fusion node means answering each sensor's registration, which
//! a plain transport cannot do; [`dmm::DmmSource`] is the TCP acceptor that
//! does, and hands every message on to the parser unchanged. See `src/main.rs`
//! for the wiring and the repository's `AGENTS.md` for the rules every parser
//! follows.

pub mod dmm;
pub mod sapient;

pub use sapient::{Options, Role, SapientError, SapientParser, Types};
