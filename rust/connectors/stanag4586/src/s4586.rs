// SPDX-License-Identifier: Apache-2.0
//! STANAG 4586 Edition 2 Data Link Interface telemetry to canonical events.
//! Decodes Message #101 Inertial States into one track event per message;
//! other message types are checksum-validated and skipped. A datagram may pack
//! several messages. Layouts follow the NATO UNCLASSIFIED Edition 2 field tables.
//!
//! Message wrapper (§B.3.3.1), big-endian, IEEE 754 floats:
//!
//! ```text
//!   IDD version   10 bytes  null-terminated ASCII
//!   instance id    u32
//!   message type   u32      1..<2000 standard, >2000 vehicle-specific
//!   message length u32      body bytes
//!   stream id      u32
//!   packet seq     u32      unused, -1
//!   <body>
//!   checksum       u32      byte-wise unsigned sum of all preceding bytes
//! ```

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// IDD version and five u32 fields.
const HEADER: usize = 30;
const CHECKSUM: usize = 4;
/// STANAG 4586 §B.4.1.2.11.
const MSG_INERTIAL_STATES: u32 = 101;
/// Table B1-25.
const INERTIAL_BODY_LEN: usize = 89;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum S4586Error {
    #[error("STANAG 4586 checksum mismatch on message {message_type}")]
    Checksum { message_type: u32 },
    #[error("STANAG 4586 truncated: {0}")]
    Truncated(&'static str),
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

pub struct S4586Parser {
    source_id: String,
    enrichment: Enrichment,
    entity_type: String,
}

/// Message #101 Inertial States in canonical units.
struct Inertial {
    timestamp_s: f64,
    vehicle_id: i32,
    cucs_id: i32,
    lat: f64,
    lon: f64,
    altitude_m: f64,
    altitude_type: u8,
    north_mps: f32,
    east_mps: f32,
    down_mps: f32,
    roll_deg: f64,
    pitch_deg: f64,
    yaw_deg: f64,
    magvar_deg: f64,
}

impl S4586Parser {
    /// The entity type defaults to `mim:aircraft`.
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            entity_type: "mim:aircraft".to_string(),
        }
    }

    /// `None` keeps the current entity type.
    pub fn with_entity_type(mut self, entity_type: Option<String>) -> Self {
        if let Some(t) = entity_type {
            self.entity_type = t;
        }
        self
    }

    /// One event per decoded message in the datagram. A declared length past the
    /// end of the datagram stops the walk and keeps the events decoded so far.
    pub fn to_events(&self, frame: &[u8]) -> Result<Vec<Event>, S4586Error> {
        let mut events = Vec::new();
        let mut off = 0usize;

        while off + HEADER + CHECKSUM <= frame.len() {
            let body_len = be_u32(frame, off + 18) as usize;
            let Some(msg_end) = off
                .checked_add(HEADER)
                .and_then(|v| v.checked_add(body_len))
                .and_then(|v| v.checked_add(CHECKSUM))
            else {
                break;
            };
            if msg_end > frame.len() {
                break;
            }

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
                events.push(self.decode_inertial(body, raw)?);
            }

            off = msg_end;
        }

        Ok(events)
    }

    fn decode_inertial(&self, body: &[u8], raw: &[u8]) -> Result<Event, S4586Error> {
        if body.len() < INERTIAL_BODY_LEN {
            return Err(S4586Error::Truncated("Inertial States body"));
        }
        let s = Inertial {
            timestamp_s: be_f64(body, 0),
            vehicle_id: be_u32(body, 8) as i32,
            cucs_id: be_u32(body, 12) as i32,
            lat: be_f64(body, 16).to_degrees(),
            lon: be_f64(body, 24).to_degrees(),
            altitude_m: be_f32(body, 32) as f64,
            altitude_type: body[36],
            north_mps: be_f32(body, 37),
            east_mps: be_f32(body, 41),
            down_mps: be_f32(body, 45),
            // 49..61 are the U/V/W accelerations, left in the payload.
            roll_deg: (be_f32(body, 61) as f64).to_degrees(),
            pitch_deg: (be_f32(body, 65) as f64).to_degrees(),
            yaw_deg: (be_f32(body, 69) as f64).to_degrees().rem_euclid(360.0),
            magvar_deg: (be_f32(body, 85) as f64).to_degrees(),
        };

        let speed_mps = s.north_mps.hypot(s.east_mps) as f64;
        let course_deg = (s.east_mps as f64)
            .atan2(s.north_mps as f64)
            .to_degrees()
            .rem_euclid(360.0);
        let climb_mps = -(s.down_mps as f64);

        let mut b = EventBuilder::new(self.source_id.clone(), self.entity_type.clone())
            .new_id()
            .payload(raw.to_vec())
            .location(s.lat, s.lon, s.altitude_m)
            .metadata("source_uid", format!("s4586:vehicle:{}", s.vehicle_id))
            .metadata("cucs_id", s.cucs_id.to_string())
            .metadata("altitude_type", altitude_type(s.altitude_type))
            .attribute("speed", format!("{speed_mps:.2}"))
            .attribute("course", format!("{course_deg:.1}"))
            .attribute("heading", format!("{:.1}", s.yaw_deg))
            .attribute("vertical_rate", format!("{climb_mps:.2}"))
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

        Ok(b.build()?)
    }
}

impl FrameParser for S4586Parser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        Ok(self.to_events(frame)?)
    }
}

/// STANAG 4586 altitude type (I0101.07).
fn altitude_type(v: u8) -> &'static str {
    match v {
        0 => "pressure",
        1 => "baro",
        2 => "agl",
        3 => "wgs84",
        _ => "unknown",
    }
}

/// The 4586 Time Stamp (UTC seconds since 1970, §B.1.7) as RFC 3339;
/// `None` when it is not finite or out of range.
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

/// 0 when out of range; callers bound the frame first.
fn be_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_be_bytes)
}

/// 0.0 when out of range; callers bound the frame first.
fn be_f32(b: &[u8], off: usize) -> f32 {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0.0, f32::from_be_bytes)
}

/// 0.0 when out of range; callers bound the frame first.
fn be_f64(b: &[u8], off: usize) -> f64 {
    b.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0.0, f64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VEHICLE_7: &str = "s4586:vehicle:7";

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

    /// A message with a correct checksum.
    fn wrap(message_type: u32, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"8\0\0\0\0\0\0\0\0\0"); // IDD version, Edition 2
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

    /// A #101 body at 26.3 N 50.6 E, 1500 m, climbing, tracking north-east.
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
        b.extend_from_slice(&(-5.0f32).to_be_bytes()); // W_Speed (down)
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
    fn decodes_inertial_states() {
        let frame = wrap(MSG_INERTIAL_STATES, &inertial_body());
        let evs = parser().to_events(&frame).unwrap();
        assert_eq!(evs.len(), 1);
        let ev = &evs[0];

        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(tactical(ev, "source_uid"), Some(VEHICLE_7));
        let loc = ev.location.as_ref().unwrap();
        assert!((loc.latitude - 26.3).abs() < 1e-6, "lat {}", loc.latitude);
        assert!((loc.longitude - 50.6).abs() < 1e-6, "lon {}", loc.longitude);
        assert!((loc.altitude_m - 1500.0).abs() < 1e-3);

        let speed: f64 = tactical(ev, "speed").unwrap().parse().unwrap();
        assert!((speed - 50.0).abs() < 0.05, "speed {speed}");
        let course: f64 = tactical(ev, "course").unwrap().parse().unwrap();
        assert!((course - 53.13).abs() < 0.1, "course {course}");
        let heading: f64 = tactical(ev, "heading").unwrap().parse().unwrap();
        assert!((heading - 90.0).abs() < 0.1, "heading {heading}");
        assert_eq!(
            tactical(ev, "vertical_rate"),
            Some("5.00"),
            "down velocity is negated into climb"
        );
        assert_eq!(tactical(ev, "altitude_type"), Some("wgs84"));
        assert_eq!(tactical(ev, "hostility"), Some("Friend"));
    }

    #[test]
    fn timestamp_from_unix_seconds() {
        let ev = &parser().to_events(&wrap(101, &inertial_body())).unwrap()[0];
        assert_eq!(ev.timestamp, "2025-07-31T22:13:20Z");
    }

    #[test]
    fn raw_message_sealed_in_payload() {
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
    fn unmapped_message_type_is_skipped() {
        let evs = parser().to_events(&wrap(20, &[0u8; 12])).unwrap();
        assert!(evs.is_empty());
    }

    #[test]
    fn corrupt_checksum_is_rejected() {
        let mut frame = wrap(101, &inertial_body());
        let n = frame.len();
        frame[n - 1] ^= 0xFF;
        assert!(matches!(
            parser().to_events(&frame),
            Err(S4586Error::Checksum { message_type: 101 })
        ));
    }

    #[test]
    fn length_past_datagram_stops_walk() {
        let mut frame = wrap(101, &inertial_body());
        frame[18..22].copy_from_slice(&0xFFFF_FF00u32.to_be_bytes());
        let _ = parser().to_events(&frame);
    }

    #[test]
    fn short_body_is_truncated() {
        let frame = wrap(101, &[0u8; 20]);
        assert!(matches!(
            parser().to_events(&frame),
            Err(S4586Error::Truncated(_))
        ));
    }
}
