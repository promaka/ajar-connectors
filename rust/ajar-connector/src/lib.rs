// SPDX-License-Identifier: Apache-2.0
//! # ajar-connector
//!
//! The vendor-facing SDK for building connectors to **Ajar**, the sovereign
//! defence integration plane. A connector turns a vendor or legacy system's
//! native data into Ajar's canonical, signed [`Event`] (inbound), and/or
//! renders governed events into a target system's format (outbound).
//!
//! This crate is **standalone**: it never depends on the private Ajar core.
//! Its types are generated from the vendored `event.proto` and it reimplements
//! the small seal spec, so it earns trust the only way that matters —
//! reproducing the golden byte-vectors that core accepts.
//!
//! ## Write your first connector
//!
//! ```
//! use ajar_connector::{canonical_bytes, seal, EventBuilder};
//! use ed25519_dalek::SigningKey;
//!
//! # fn main() -> Result<(), ajar_connector::BuildError> {
//! let event = EventBuilder::new("sensor-123", "mim:drone")
//!     .new_id()                 // UUIDv7, time-ordered
//!     .now()                    // RFC 3339 observation timestamp
//!     .confidence(0.98)
//!     .policy_tag("class:secret")
//!     .attribute("heading", "225")
//!     .attribute("speed", "110") // auto-sorted; duplicate keys rejected
//!     .build()?;
//!
//! let canonical = canonical_bytes(&event);
//! let key = SigningKey::from_bytes(&[0x11; 32]); // your connector's own key
//! let sealed = seal(&canonical, &key);          // 64-byte sig ++ canonical
//! # let _ = sealed;
//! # Ok(())
//! # }
//! ```
//!
//! The acceptance test lives in the `conformance` crate: it must reproduce
//! every hash in `vendor/contract/vectors.json`.

mod builder;
mod canonical;
mod connector;
mod error;
mod profile;
mod seal;

/// Types generated from the vendored `vendor/contract/event.proto`
/// (`ajar.event.v1`). This is the source of truth for the wire format.
pub mod event {
    include!(concat!(env!("OUT_DIR"), "/ajar.event.v1.rs"));
}

pub use builder::EventBuilder;
pub use canonical::canonical_bytes;
pub use connector::{Connector, OutboundProfile};
pub use error::BuildError;
pub use event::{Attribute, Event, GeoPoint};
pub use profile::ConnectorProfile;
pub use seal::{seal, SEAL_SIGNATURE_LEN};

// Re-exported so connector authors don't have to match our exact dep versions.
pub use ed25519_dalek::{self, SigningKey, VerifyingKey};
