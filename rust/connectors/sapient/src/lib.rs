// SPDX-License-Identifier: Apache-2.0
//! SAPIENT (BSI Flex 335) ingress for Ajar, on the fusion-node side of the
//! counter-UAS sensor interface. [`SapientParser`] turns each message into an
//! event; [`dmm::DmmSource`] accepts edge nodes and answers their registrations.

pub mod dmm;
pub mod sapient;

pub use sapient::{Options, Role, SapientError, SapientParser, Types};
