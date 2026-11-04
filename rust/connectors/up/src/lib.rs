// SPDX-License-Identifier: Apache-2.0
//! `ajar up <packet.tar>`: from the operator's vendor packet to flowing
//! events. A producer packet ends with the named connector running; a consumer
//! packet ends with a verified tap on governed egress, or a generated config
//! for a real delivery target.

pub mod consumer;
pub mod packet;
pub mod producer;
