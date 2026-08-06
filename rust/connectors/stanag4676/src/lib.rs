// SPDX-License-Identifier: Apache-2.0
//! STANAG 4676 (NATO ISR Tracking Standard, AEDP-12 Edition B) ingress connector.
//!
//! Decodes `nitsRoot` track messages into canonical Ajar events — one per track
//! point — the **fused track layer** that sits above raw GMTI/ISR detections. See
//! [`s4676`] for the wire model and the decode.

mod s4676;

pub use s4676::{S4676Error, S4676Parser};
