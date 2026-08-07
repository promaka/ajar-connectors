// SPDX-License-Identifier: Apache-2.0
//! STANAG 4586 (NATO UAS Control) Data Link Interface ingress connector.
//!
//! Decodes the DLI message set — the fixed-field big-endian messages exchanged
//! between the Core UCS and a vehicle-specific module — into canonical Ajar events.
//! See [`s4586`] for the wire model and the decode.

mod s4586;

pub use s4586::{S4586Error, S4586Parser};
