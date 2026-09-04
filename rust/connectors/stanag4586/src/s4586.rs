// SPDX-License-Identifier: Apache-2.0
//! STANAG 4586 (NATO UAS Control) Data Link Interface -> canonical Ajar events.
//!
//! 4586 is the NATO coalition standard for military UAS interoperability, spanning
//! UCS control Levels of Interoperability 1–5. The wire surface is the **Data Link
//! Interface (DLI)**: fixed-field big-endian messages exchanged between the Core UCS
//! (CUCS) and the vehicle-specific module (VSM). This connector **ingests the
//! telemetry** — the DLI vehicle-state reports — as canonical Ajar tracks, sealed
//! with the connector's Ed25519 key. It is an ingest connector; it does not command
//! vehicles. MAVLink plays the same telemetry role for small/commercial UAS.
//!
//! The message layouts here are implemented from the public NATO UNCLASSIFIED
//! STANAG 4586 Edition 2 field tables; an open reference implementation was consulted
//! only to confirm the wrapper length, with no code copied.
//!
//! ## The wire, exactly
//!
//! Every message is wrapped in a fixed header + checksum footer (STANAG 4586
//! Edition 2, NATO UNCLASSIFIED, §B.3.3.1):
//!
//! ```text
//!   IDD version   10 bytes  null-terminated ASCII
//!   instance id    u32      message instance
//!   message type   u32      1..<2000 standard, >2000 vehicle-specific
//!   message length u32      number of bytes in the body
//!   stream id      u32
//!   packet seq     u32      (unused, = -1)
//!   <body>         length bytes
//!   checksum       u32      byte-wise unsigned sum of all preceding bytes
//! ```
//!
//! **Byte order is most-significant-byte-first (big-endian) throughout**, with IEEE
//! 754 singles/doubles — this is the one thing the open reference implementations
//! get wrong, so the published field tables (not any code) are ground truth. A
//! datagram may pack several messages back to back; each carries its own checksum.
//!
//! v1 decodes **Message #101 Inertial States** — the vehicle's full kinematic state
//! (position, velocity, attitude), sent regularly to the CUCS and exactly what
//! populates a track. Other message types are validated at the wrapper and skipped
//! (not yet mapped); the raw frame of every event we emit is sealed verbatim.
//!
//! This is an untrusted edge: the decoder walks attacker-influenced length and
//! checksum fields, bounds-checks every read, and never panics or fabricates a
//! field. Canonical invariants then hold by construction via [`EventBuilder`].

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The message wrapper header: IDD(10) + five u32 fields = 30 bytes.
const HEADER: usize = 30;
/// The checksum footer.
const CHECKSUM: usize = 4;
/// Message type of Inertial States (§B.4.1.2.11).
const MSG_INERTIAL_STATES: u32 = 101;
/// Body length of Message #101 (bytes), from its field table (Table B1-25).
const INERTIAL_BODY_LEN: usize = 89;

/// Why a 4586 datagram could not be normalized. Dropped frames are counted and
/// logged with the reason by the shared runtime — never silently swallowed.
#[derive(Debug, PartialEq, Eq)]
pub enum S4586Error {
    /// A message's checksum did not match its contents (corruption / not 4586).
    Checksum { message_type: u32 },
    /// A decoded field or body was shorter than its fixed layout requires.
    Truncated(&'static str),
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for S4586Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S4586Error::Checksum { message_type } => {
                write!(f, "STANAG 4586 checksum mismatch on message {message_type}")
            }
            S4586Error::Truncated(what) => write!(f, "STANAG 4586 truncated: {what}"),
            S4586Error::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for S4586Error {}

/// Normalizes STANAG 4586 DLI for one connector identity.
pub struct S4586Parser {
    source_id: String,
    /// 4586 carries no affiliation, so it comes from config (own-force UAS are
    /// typically `friendly`); `None` resolves to `unknown`.
    enrichment: Enrichment,
    /// Entity type for decoded vehicles; overridable via config. MIM 5.3 has no
    /// uncrewed class: the airframe is the thing, and crewing is a property of it.
    entity_type: String,
}

/// Message #101 Inertial States, decoded into canonical quantities.
struct Inertial {
    timestamp_s: f64,
    vehicle_id: i32,
    cucs_id: i32,
    lat_deg: f64,
    lon_deg: f64,
    altitude_m: f64,
    altitude_type: u8,
    /// North / East / Down velocity components, m/s.
    vn: f32,
    ve: f32,
    vd: f32,
    roll_deg: f64,
    pitch_deg: f64,
    yaw_deg: f64,
    magvar_deg: f64,
}

impl S4586Parser {
    /// Build a parser for one connector identity. `entity_type` defaults to
    /// `mim:aircraft`; `enrichment` supplies the operator-asserted affiliation.
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            entity_type: "mim:aircraft".to_string(),
        }
    }

    /// Override the entity type decoded vehicles are mapped to.
    pub fn with_entity_type(mut self, entity_type: Option<String>) -> Self {
        if let Some(t) = entity_type {
            self.entity_type = t;
        }
        self
    }

    /// Parse one datagram (which may pack several messages) into a canonical event
    /// per decoded message. A well-formed datagram carrying only message types we do
    /// not yet map yields an empty vec, which the runtime treats as nothing to
    /// publish — not an error.
    pub fn to_events(&self, frame: &[u8]) -> Result<Vec<Event>, S4586Error> {
        let mut events = Vec::new();
        let mut off = 0usize;

        while off + HEADER + CHECKSUM <= frame.len() {
            let body_len = be_u32(frame, off + 18) as usize;
            // header + body + checksum, guarded against length-field overflow.
            let Some(msg_end) = off
                .checked_add(HEADER)
                .and_then(|v| v.checked_add(body_len))
                .and_then(|v| v.checked_add(CHECKSUM))
            else {
                break;
            };
            if msg_end > frame.len() {
                // The declared length runs past the datagram: stop walking rather
                // than read out of bounds. Anything parsed so far still stands.
                break;
            }

            // Checksum: byte-wise unsigned sum of every byte except the 4-byte
            // checksum itself, truncated to u32.
            let checksum = be_u32(frame, msg_end - CHECKSUM);
            let sum = frame[off..msg_end - CHECKSUM]
                .iter()
                .fold(0u32, |a, &b| a.wrapping_add(b as u32));
            let message_type = be_u32(frame, off + 14);
            if sum != checksum {
                return Err(S4586Error::Checksum { message_type });
            }

            if message_type == MSG_INERTIAL_STATES {
                let body = &frame[off + HEADER..off + HEADER + body_len];
                let raw = &frame[off..msg_end];
                if let Some(ev) = self.decode_inertial(body, raw)? {
                    events.push(ev);
                }
            }

            off = msg_end;
        }

        Ok(events)
    }

    /// Decode Message #101 Inertial States and build a canonical event.
    fn decode_inertial(&self, body: &[u8], raw: &[u8]) -> Result<Option<Event>, S4586Error> {
        if body.len() < INERTIAL_BODY_LEN {
            return Err(S4586Error::Truncated("Inertial States body"));
        }
        let s = Inertial {
            timestamp_s: be_f64(body, 0),
            vehicle_id: be_u32(body, 8) as i32,
            cucs_id: be_u32(body, 12) as i32,
            lat_deg: be_f64(body, 16).to_degrees(),
            lon_deg: be_f64(body, 24).to_degrees(),
            altitude_m: be_f32(body, 32) as f64,
            altitude_type: body[36],
            vn: be_f32(body, 37),
            ve: be_f32(body, 41),
            vd: be_f32(body, 45),
            // 49..61 are the U/V/W accelerations — preserved in the raw payload,
            // not yet promoted to attributes.
            roll_deg: (be_f32(body, 61) as f64).to_degrees(),
            pitch_deg: (be_f32(body, 65) as f64).to_degrees(),
            yaw_deg: normalize_deg((be_f32(body, 69) as f64).to_degrees()),
            magvar_deg: (be_f32(body, 85) as f64).to_degrees(),
        };

        // Ground track from the horizontal velocity; heading is where the platform
        // points (yaw). course != heading — kept distinct per ADR-0019.
        let speed = (s.vn.hypot(s.ve)) as f64;
        let course = normalize_deg((s.ve as f64).atan2(s.vn as f64).to_degrees());
        // W is positive-down; vertical_rate is positive-up (climb).
        let vertical_rate = -(s.vd as f64);

        let mut b = EventBuilder::new(self.source_id.clone(), self.entity_type.clone())
            .new_id()
            .payload(raw.to_vec())
            .location(s.lat_deg, s.lon_deg, s.altitude_m)
            .metadata("source_uid", format!("s4586:vehicle:{}", s.vehicle_id))
            // The vehicle id is the stable track key — the governed correlation key a
            // consumer keys on (`track_id`), not just provenance metadata.
            .attribute("track_id", s.vehicle_id.to_string())
            .metadata("cucs_id", s.cucs_id.to_string())
            .metadata("altitude_type", altitude_type(s.altitude_type))
            .attribute("speed", format!("{speed:.2}"))
            .attribute("course", format!("{course:.1}"))
            .attribute("heading", format!("{:.1}", s.yaw_deg))
            .attribute("vertical_rate", format!("{vertical_rate:.2}"))
            .metadata("roll_deg", format!("{:.2}", s.roll_deg))
            .metadata("pitch_deg", format!("{:.2}", s.pitch_deg))
            .metadata("magnetic_variation_deg", format!("{:.3}", s.magvar_deg));

        match rfc3339_from_unix_secs(s.timestamp_s) {
            Some(ts) => b = b.timestamp(ts),
            None => b = b.now(),
        }
        b = b.metadata("timestamp_s", format!("{:.3}", s.timestamp_s));
        if let Some(aff) = &self.enrichment.hostility {
            b = b.attribute("hostility", aff.clone());
        }

        Ok(Some(
            b.build().map_err(|e| S4586Error::Build(e.to_string()))?,
        ))
    }
}

/// STANAG 4586 altitude-type enumeration (I0101.07).
fn altitude_type(v: u8) -> &'static str {
    match v {
        0 => "pressure",
        1 => "baro",
        2 => "agl",
        3 => "wgs84",
        _ => "unknown",
    }
}

/// Normalize degrees into `[0, 360)`.
fn normalize_deg(d: f64) -> f64 {
    let m = d % 360.0;
    if m < 0.0 {
        m + 360.0
    } else {
        m
    }
}

/// The 4586 Time Stamp is UTC seconds since 1 Jan 1970 (§B.1.7). Convert to RFC3339,
/// with the arithmetic checked so an out-of-range or non-finite value falls back to
/// receipt time rather than panicking.
fn rfc3339_from_unix_secs(secs: f64) -> Option<String> {
    if !secs.is_finite() {
        return None;
    }
    let nanos = (secs * 1_000_000_000.0).round();
    if nanos.abs() >= i128::MAX as f64 {
        return None;
    }
    OffsetDateTime::from_unix_timestamp_nanos(nanos as i128)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// Read a big-endian u32 at `off`, or 0 if out of range (callers bound the frame
/// before decoding fields, so this is a defensive floor, never a silent shift).
fn be_u32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off + 4) {
        Some(s) => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

/// Read a big-endian IEEE-754 single at `off`, or 0.0 if out of range.
fn be_f32(b: &[u8], off: usize) -> f32 {
    match b.get(off..off + 4) {
        Some(s) => f32::from_be_bytes([s[0], s[1], s[2], s[3]]),
        None => 0.0,
    }
}

/// Read a big-endian IEEE-754 double at `off`, or 0.0 if out of range.
fn be_f64(b: &[u8], off: usize) -> f64 {
    match b.get(off..off + 8) {
        Some(s) => f64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        None => 0.0,
    }
}

/// The glue into the shared runtime: one datagram maps to zero or more events.
impl FrameParser for S4586Parser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        self.to_events(frame).map_err(|e| Box::new(e) as ParseError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> S4586Parser {
        S4586Parser::new("uas-vsm-1", Enrichment::default().with_hostility("Friend"))
    }

    fn tactical<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .chain(ev.metadata.iter())
            .find(|a| a.key == key)
            .map(|a| a.value.as_str())
    }

    /// Assemble a valid message: 30-byte header + body + a correct checksum footer.
    fn wrap(message_type: u32, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"8\0\0\0\0\0\0\0\0\0"); // IDD version "8" (Edition 2), padded
        m.extend_from_slice(&1u32.to_be_bytes()); // instance id
        m.extend_from_slice(&message_type.to_be_bytes());
        m.extend_from_slice(&(body.len() as u32).to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes()); // stream id
        m.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // packet seq = -1
        m.extend_from_slice(body);
        let sum = m.iter().fold(0u32, |a, &b| a.wrapping_add(b as u32));
        m.extend_from_slice(&sum.to_be_bytes());
        m
    }

    /// A #101 body: a UAS over the Gulf, climbing, tracking north-east.
    fn inertial_body() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&1_754_000_000.0f64.to_be_bytes()); // time stamp (unix s)
        b.extend_from_slice(&7u32.to_be_bytes()); // vehicle id 7
        b.extend_from_slice(&3u32.to_be_bytes()); // cucs id 3
        b.extend_from_slice(&26.3f64.to_radians().to_be_bytes()); // latitude
        b.extend_from_slice(&50.6f64.to_radians().to_be_bytes()); // longitude
        b.extend_from_slice(&1500.0f32.to_be_bytes()); // altitude m
        b.push(3); // altitude type = WGS-84
        b.extend_from_slice(&30.0f32.to_be_bytes()); // U_Speed (north) m/s
        b.extend_from_slice(&40.0f32.to_be_bytes()); // V_Speed (east) m/s
        b.extend_from_slice(&(-5.0f32).to_be_bytes()); // W_Speed (down) -> climbing
        b.extend_from_slice(&0.0f32.to_be_bytes()); // U_Accel
        b.extend_from_slice(&0.0f32.to_be_bytes()); // V_Accel
        b.extend_from_slice(&0.0f32.to_be_bytes()); // W_Accel
        b.extend_from_slice(&0.1f32.to_be_bytes()); // Phi (roll)
        b.extend_from_slice(&0.05f32.to_be_bytes()); // Theta (pitch)
        b.extend_from_slice(&1.5707964f32.to_be_bytes()); // Psi (yaw) ~90 deg
        b.extend_from_slice(&0.0f32.to_be_bytes()); // Phi_dot
        b.extend_from_slice(&0.0f32.to_be_bytes()); // Theta_dot
        b.extend_from_slice(&0.0f32.to_be_bytes()); // Psi_dot
        b.extend_from_slice(&0.02f32.to_be_bytes()); // Magnetic Variation
        assert_eq!(b.len(), INERTIAL_BODY_LEN);
        b
    }

    #[test]
    fn decodes_inertial_states_into_a_track() {
        let frame = wrap(MSG_INERTIAL_STATES, &inertial_body());
        let evs = parser().to_events(&frame).unwrap();
        assert_eq!(evs.len(), 1);
        let ev = &evs[0];

        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(tactical(ev, "source_uid"), Some("s4586:vehicle:7"));
        assert_eq!(tactical(ev, "track_id"), Some("7")); // governed correlation key
        let loc = ev.location.as_ref().unwrap();
        assert!((loc.latitude - 26.3).abs() < 1e-6, "lat {}", loc.latitude);
        assert!((loc.longitude - 50.6).abs() < 1e-6, "lon {}", loc.longitude);
        assert!((loc.altitude_m - 1500.0).abs() < 1e-3);

        // speed = hypot(30,40) = 50 m/s; course = atan2(E=40, N=30) ~ 53.13 deg.
        let speed: f64 = tactical(ev, "speed").unwrap().parse().unwrap();
        assert!((speed - 50.0).abs() < 0.05, "speed {speed}");
        let course: f64 = tactical(ev, "course").unwrap().parse().unwrap();
        assert!((course - 53.13).abs() < 0.1, "course {course}");
        // heading from yaw ~ 90 deg (distinct from course).
        let heading: f64 = tactical(ev, "heading").unwrap().parse().unwrap();
        assert!((heading - 90.0).abs() < 0.1, "heading {heading}");
        // W=-5 down -> +5 climb.
        assert_eq!(tactical(ev, "vertical_rate"), Some("5.00"));
        assert_eq!(tactical(ev, "altitude_type"), Some("wgs84"));
        assert_eq!(tactical(ev, "hostility"), Some("Friend"));
    }

    #[test]
    fn timestamp_reconstructs_from_unix_seconds() {
        let ev = &parser().to_events(&wrap(101, &inertial_body())).unwrap()[0];
        // 1_754_000_000 s since 1970 -> 2025-07-31T22:13:20Z.
        assert_eq!(ev.timestamp, "2025-07-31T22:13:20Z");
    }

    #[test]
    fn raw_message_is_sealed_verbatim() {
        let frame = wrap(101, &inertial_body());
        let ev = &parser().to_events(&frame).unwrap()[0];
        assert_eq!(ev.payload.as_slice(), frame.as_slice());
    }

    #[test]
    fn two_messages_in_one_datagram() {
        let mut datagram = wrap(101, &inertial_body());
        datagram.extend(wrap(101, &inertial_body()));
        assert_eq!(parser().to_events(&datagram).unwrap().len(), 2);
    }

    #[test]
    fn unmapped_message_type_is_skipped_not_errored() {
        // A valid #20 (Vehicle ID) message we do not yet decode: no event, no error.
        let evs = parser().to_events(&wrap(20, &[0u8; 12])).unwrap();
        assert!(evs.is_empty());
    }

    #[test]
    fn corrupt_checksum_is_rejected() {
        let mut frame = wrap(101, &inertial_body());
        let n = frame.len();
        frame[n - 1] ^= 0xFF; // flip the checksum
        assert!(matches!(
            parser().to_events(&frame),
            Err(S4586Error::Checksum { message_type: 101 })
        ));
    }

    #[test]
    fn lying_length_does_not_read_out_of_bounds() {
        let mut frame = wrap(101, &inertial_body());
        frame[18..22].copy_from_slice(&0xFFFF_FF00u32.to_be_bytes()); // absurd length
                                                                      // Must not panic; walk stops rather than reading past the datagram.
        let _ = parser().to_events(&frame);
    }

    #[test]
    fn short_body_is_truncation_error_not_panic() {
        // Declares #101 but the body is too short for the fixed layout.
        let frame = wrap(101, &[0u8; 20]);
        assert!(matches!(
            parser().to_events(&frame),
            Err(S4586Error::Truncated(_))
        ));
    }
}
