// SPDX-License-Identifier: Apache-2.0
//! SDK for building connectors to Ajar, the sovereign defence integration plane.
//! A connector turns a vendor or legacy system's native data into Ajar's canonical,
//! signed [`Event`] (inbound), and/or renders governed events into a target
//! system's format (outbound).
//!
//! The crate is standalone: it does not depend on the private Ajar core. Its types
//! are generated from the vendored `event.proto`, and the `conformance` crate checks
//! its output against the golden vectors in `vendor/contract/vectors.json`.
//!
//! # Write your first connector
//!
//! ```
//! use ajar_connector::EventBuilder;
//! use ed25519_dalek::SigningKey;
//!
//! # fn main() -> Result<(), ajar_connector::BuildError> {
//! let event = EventBuilder::new("sensor-123", "mim:aircraft")
//!     .new_id()                  // UUIDv7, time-ordered
//!     .now()                     // RFC 3339 observation timestamp
//!     .confidence(0.98)
//!     .policy_tag("class:secret")
//!     .attribute("heading", "225")
//!     .attribute("speed", "110") // auto-sorted; duplicate keys rejected
//!     .build()?;
//!
//! let canonical = ajar_connector::canonical_bytes(&event);
//! let key = SigningKey::from_bytes(&[0x11; 32]); // your connector's own key
//! let sealed = ajar_connector::seal(&canonical, &key); // 64-byte signature ++ canonical
//! # let _ = sealed;
//! # Ok(())
//! # }
//! ```

mod builder;
mod canonical;
mod connector;
#[cfg(feature = "consumer")]
pub mod consumer;
mod error;
mod profile;
mod seal;

/// Types generated from `event.proto` (`ajar.event.v1`).
pub mod event {
    include!(concat!(env!("OUT_DIR"), "/ajar.event.v1.rs"));
}

/// NATS header the ingest broker deduplicates on. Publish every sealed event with
/// this header set to the event's `id` (see [`ingest_headers`]): the broker keeps a
/// duplicate window keyed on it, so a retransmission or reconnect race is dropped
/// instead of stored twice. The SDK has no transport dependency, so your NATS client
/// sets the header.
pub const NATS_MSG_ID_HEADER: &str = "Nats-Msg-Id";

/// The headers an ingest publish of `event` must carry, as plain pairs your NATS
/// client can adopt: `[("Nats-Msg-Id", event.id)]`.
pub fn ingest_headers(event: &Event) -> [(&'static str, String); 1] {
    [(NATS_MSG_ID_HEADER, event.id.clone())]
}

pub use builder::EventBuilder;
pub use canonical::canonical_bytes;
pub use connector::{Connector, OutboundProfile};
pub use error::BuildError;
pub use event::{Attribute, Event, GeoPoint};
pub use profile::ConnectorProfile;
pub use seal::{seal, verify, SealError, SEAL_SIGNATURE_LEN};

// Re-exported so connectors need not pin the same ed25519-dalek version.
pub use ed25519_dalek::{self, SigningKey, VerifyingKey};

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn ingest_headers_carry_event_id() {
        let event = EventBuilder::new("t-1", "mim:drone")
            .new_id()
            .now()
            .build()
            .expect("build");
        let [(name, value)] = ingest_headers(&event);
        assert_eq!(name, "Nats-Msg-Id");
        assert_eq!(value, event.id);
    }
}
