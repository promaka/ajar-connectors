// SPDX-License-Identifier: Apache-2.0
//! STANAG 4607 (NATO GMTI) ingress for Ajar.

pub mod gmti;

pub use gmti::{GmtiError, GmtiParser, GmtiTarget};
