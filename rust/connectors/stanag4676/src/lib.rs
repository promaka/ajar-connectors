// SPDX-License-Identifier: Apache-2.0
//! STANAG 4676 (NATO ISR Tracking Standard, AEDP-12 Edition B) ingress connector.

mod s4676;

pub use s4676::{S4676Error, S4676Parser};
