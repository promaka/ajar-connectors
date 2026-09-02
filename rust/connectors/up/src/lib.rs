// SPDX-License-Identifier: Apache-2.0
//! `ajar up <packet.tar>`: one command from the operator's vendor packet to
//! flowing events, in either direction.
//!
//! The packet carries every decision the operator made at onboarding; the
//! only human inputs left are the ones structurally unknowable there (a
//! vendor-held signing seed; a consumer's delivery target). Producer packets
//! end with the named connector running; consumer packets end with a
//! verified tap on governed egress, or a generated config for a real
//! delivery target.

pub mod consumer;
pub mod packet;
pub mod producer;
