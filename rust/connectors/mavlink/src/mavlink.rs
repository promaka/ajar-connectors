// SPDX-License-Identifier: Apache-2.0
//! MAVLink vehicle telemetry -> canonical Ajar event.
//!
//! MAVLink is the framed binary protocol most UAS/drone autopilots and ground
//! stations speak (both v1, magic `0xFE`, and v2, magic `0xFD`). This is an
//! untrusted edge: frames can be truncated, mis-framed, or hostile, so the frame
//! is length-checked and its CRC verified before any field is read — it never
//! panics and never trusts an unverified frame.
//!
//! Scope (military operating picture):
//!  - **Position** — GLOBAL_POSITION_INT (33) and GPS_RAW_INT (24): WGS-84
//!    position, altitude, ground speed, heading/course.
//!  - **Identity/state** — HEARTBEAT (0): vehicle type, armed state, and system
//!    status (active/critical/emergency). HEARTBEAT arrives separately from
//!    position, so the connector caches it per system id and enriches each
//!    position report with the vehicle's latest known state.
//!
//! MAVLink orders a message's fields on the wire by decreasing type size; the
//! offsets below follow that layout and are verified against constructed frames.

use std::collections::HashMap;
use std::sync::Mutex;

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError, Tactical};

/// 1 metre/second in knots.
const MPS_TO_KNOTS: f64 = 1.943_844;

/// Why a MAVLink frame could not be turned into a position.
#[derive(Debug, PartialEq, Eq)]
pub enum MavError {
    /// No MAVLink start-of-frame byte.
    NotMavlink,
    /// The buffer was shorter than the framed length claims.
    Truncated,
    /// The frame's CRC did not match (corrupt, or wrong dialect CRC_EXTRA).
    BadCrc,
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for MavError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MavError::NotMavlink => write!(f, "not a MAVLink frame"),
            MavError::Truncated => write!(f, "MAVLink frame truncated"),
            MavError::BadCrc => write!(f, "MAVLink CRC mismatch"),
            MavError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for MavError {}

/// A decoded MAVLink position enriched with the vehicle's known state.
#[derive(Debug, Clone, PartialEq)]
pub struct MavPosition {
    pub sysid: u8,
    pub msg_id: u32,
    pub lat: f64,
    pub lon: f64,
    pub alt_m: f64,
    /// True heading, degrees (GLOBAL_POSITION_INT).
    pub heading: Option<f64>,
    /// Course over ground, degrees (GPS_RAW_INT).
    pub course: Option<f64>,
    /// Ground speed, knots.
    pub sog: Option<f64>,
    /// Vehicle type category (from HEARTBEAT): fixed-wing, multirotor, …
    pub vehicle_type: Option<&'static str>,
    /// System status (from HEARTBEAT): active, critical, emergency, …
    pub status: Option<&'static str>,
    /// Armed state (from HEARTBEAT).
    pub armed: Option<bool>,
}

/// A vehicle's last-known state from its HEARTBEAT, cached by system id.
#[derive(Debug, Clone, Default, PartialEq)]
struct VehicleState {
    vehicle_type: Option<&'static str>,
    status: Option<&'static str>,
    armed: Option<bool>,
}

/// Normalizes MAVLink for one connector identity, caching HEARTBEAT state per
/// system id.
pub struct MavParser {
    source_id: String,
    enrichment: Enrichment,
    vehicles: Mutex<HashMap<u8, VehicleState>>,
}

/// CRC_EXTRA and full (untruncated) payload length for the messages we decode.
fn spec(msg_id: u32) -> Option<(u8, usize)> {
    match msg_id {
        0 => Some((50, 9)),    // HEARTBEAT
        24 => Some((24, 30)),  // GPS_RAW_INT
        33 => Some((104, 28)), // GLOBAL_POSITION_INT
        _ => None,
    }
}

impl MavParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            vehicles: Mutex::new(HashMap::new()),
        }
    }

    /// Parse one MAVLink frame. Returns a position for a CRC-valid position
    /// message; `Ok(None)` for a HEARTBEAT (which updates the state cache) or a
    /// message we do not map.
    pub fn parse_frame(&self, frame: &[u8]) -> Result<Option<MavPosition>, MavError> {
        let &magic = frame.first().ok_or(MavError::Truncated)?;
        let (len, header_len, sysid, msg_id) = match magic {
            0xFE => {
                // v1: magic len seq sysid compid msgid | payload | crc16
                if frame.len() < 6 {
                    return Err(MavError::Truncated);
                }
                (frame[1] as usize, 6, frame[3], frame[5] as u32)
            }
            0xFD => {
                // v2: magic len incompat compat seq sysid compid msgid[3] | payload | crc16
                if frame.len() < 10 {
                    return Err(MavError::Truncated);
                }
                let msg_id = frame[7] as u32 | (frame[8] as u32) << 8 | (frame[9] as u32) << 16;
                (frame[1] as usize, 10, frame[5], msg_id)
            }
            _ => return Err(MavError::NotMavlink),
        };

        let crc_start = header_len + len;
        if frame.len() < crc_start + 2 {
            return Err(MavError::Truncated);
        }

        let Some((crc_extra, full_len)) = spec(msg_id) else {
            return Ok(None); // valid framing, message we do not map
        };

        // CRC covers everything from just after the magic through the payload,
        // plus the message's CRC_EXTRA. Verify before trusting any field.
        let given = frame[crc_start] as u16 | (frame[crc_start + 1] as u16) << 8;
        if crc(&frame[1..crc_start], crc_extra) != given {
            return Err(MavError::BadCrc);
        }

        // v2 truncates trailing zero bytes; zero-extend to the full payload.
        let mut payload = vec![0u8; full_len];
        let body = &frame[header_len..crc_start];
        let n = body.len().min(full_len);
        payload[..n].copy_from_slice(&body[..n]);

        match msg_id {
            0 => {
                self.heartbeat(sysid, &payload);
                Ok(None)
            }
            33 => Ok(Some(self.global_position(sysid, &payload))),
            24 => Ok(Some(self.gps_raw(sysid, &payload))),
            _ => Ok(None),
        }
    }

    /// HEARTBEAT (msg 0): cache vehicle type, armed state, system status by sysid.
    fn heartbeat(&self, sysid: u8, p: &[u8]) {
        let state = VehicleState {
            vehicle_type: vehicle_type(p[4]),
            status: mav_state(p[7]),
            armed: Some(p[6] & 0x80 != 0), // MAV_MODE_FLAG_SAFETY_ARMED
        };
        self.vehicles
            .lock()
            .expect("vehicle mutex")
            .insert(sysid, state);
    }

    /// GLOBAL_POSITION_INT (msg 33): position, altitude, ground speed from the
    /// velocity vector, true heading.
    fn global_position(&self, sysid: u8, p: &[u8]) -> MavPosition {
        let vx = i16le(p, 20) as f64;
        let vy = i16le(p, 22) as f64;
        let sog = Some((vx * vx + vy * vy).sqrt() / 100.0 * MPS_TO_KNOTS);
        let hdg = u16le(p, 26);
        self.position(
            sysid,
            33,
            i32le(p, 4),
            i32le(p, 8),
            i32le(p, 12),
            (hdg != u16::MAX).then_some(hdg as f64 / 100.0),
            None,
            sog,
        )
    }

    /// GPS_RAW_INT (msg 24): position, altitude, ground speed, course over ground.
    fn gps_raw(&self, sysid: u8, p: &[u8]) -> MavPosition {
        let vel = u16le(p, 24);
        let cog = u16le(p, 26);
        self.position(
            sysid,
            24,
            i32le(p, 8),
            i32le(p, 12),
            i32le(p, 16),
            None,
            (cog != u16::MAX).then_some(cog as f64 / 100.0),
            (vel != u16::MAX).then_some(vel as f64 / 100.0 * MPS_TO_KNOTS),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn position(
        &self,
        sysid: u8,
        msg_id: u32,
        lat_e7: i32,
        lon_e7: i32,
        alt_mm: i32,
        heading: Option<f64>,
        course: Option<f64>,
        sog: Option<f64>,
    ) -> MavPosition {
        let state = self
            .vehicles
            .lock()
            .expect("vehicle mutex")
            .get(&sysid)
            .cloned()
            .unwrap_or_default();
        MavPosition {
            sysid,
            msg_id,
            lat: lat_e7 as f64 / 1e7,
            lon: lon_e7 as f64 / 1e7,
            alt_m: alt_mm as f64 / 1000.0,
            heading,
            course,
            sog,
            vehicle_type: state.vehicle_type,
            status: state.status,
            armed: state.armed,
        }
    }

    fn base_builder(&self, p: &MavPosition) -> EventBuilder {
        let affiliation = self.enrichment.affiliation.as_deref().unwrap_or("unknown");

        // System id is an identifier -> always metadata; tactical fields follow mode.
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(p.lat, p.lon, p.alt_m)
            .metadata("mav_sysid", p.sysid.to_string())
            .tactical(&self.enrichment, "affiliation", affiliation);
        if let Some(sog) = p.sog {
            b = b.tactical(&self.enrichment, "speed", format!("{sog:.1}")); // knots
        }
        if let Some(h) = p.heading {
            b = b.tactical(&self.enrichment, "heading", format!("{h:.1}")); // degrees true
        }
        if let Some(c) = p.course {
            b = b.tactical(&self.enrichment, "course", format!("{c:.1}")); // degrees
        }
        if let Some(vt) = p.vehicle_type {
            b = b.tactical(&self.enrichment, "vehicle_type", vt);
        }
        if let Some(st) = p.status {
            b = b.tactical(&self.enrichment, "status", st);
        }
        if let Some(armed) = p.armed {
            b = b.tactical(
                &self.enrichment,
                "armed",
                if armed { "true" } else { "false" },
            );
        }
        b
    }

    /// Build with an explicit observation timestamp (tests pin this path).
    pub fn to_event_at(&self, p: &MavPosition, observed: &str) -> Result<Event, MavError> {
        self.base_builder(p)
            .timestamp(observed)
            .build()
            .map_err(|e| MavError::Build(e.to_string()))
    }

    /// Build stamped with receipt time — GLOBAL_POSITION_INT carries only a
    /// boot-relative clock, so observation time is when we saw it.
    fn to_event_now(&self, p: &MavPosition) -> Result<Event, MavError> {
        self.base_builder(p)
            .now()
            .build()
            .map_err(|e| MavError::Build(e.to_string()))
    }
}

impl FrameParser for MavParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        match self.parse_frame(frame).map_err(box_err)? {
            Some(pos) => Ok(vec![self.to_event_now(&pos).map_err(box_err)?]),
            None => Ok(Vec::new()),
        }
    }
}

fn box_err(e: MavError) -> ParseError {
    Box::new(e) as ParseError
}

/// MAV_TYPE (subset) → operational category.
fn vehicle_type(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "fixed-wing",
        2 | 3 | 13 | 14 | 15 => "multirotor",
        4 => "helicopter",
        7 | 8 => "airship",
        10 => "ground-vehicle",
        11 => "surface-vessel",
        12 => "submarine",
        19..=23 => "vtol",
        _ => return None,
    })
}

/// MAV_STATE → status string.
fn mav_state(s: u8) -> Option<&'static str> {
    Some(match s {
        0 => "uninitialised",
        1 => "booting",
        2 => "calibrating",
        3 => "standby",
        4 => "active",
        5 => "critical",
        6 => "emergency",
        7 => "powering-off",
        8 => "terminating",
        _ => return None,
    })
}

fn i32le(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn i16le(b: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([b[off], b[off + 1]])
}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// MAVLink's CRC-16/MCRF4XX over `data`, finished with the message CRC_EXTRA.
fn crc(data: &[u8], extra: u8) -> u16 {
    let mut crc: u16 = 0xFFFF;
    let accum = |b: u8, crc: &mut u16| {
        let mut tmp = b ^ (*crc & 0xFF) as u8;
        tmp ^= tmp << 4;
        *crc = (*crc >> 8) ^ ((tmp as u16) << 8) ^ ((tmp as u16) << 3) ^ ((tmp as u16) >> 4);
    };
    for &b in data {
        accum(b, &mut crc);
    }
    accum(extra, &mut crc);
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth GLOBAL_POSITION_INT (CRC-correct), sysid 1: 47.397742 N,
    // 8.545594 E, 500.0 m, heading 90.0, ground speed 10 m/s (= 19.44 kn).
    const GPI: &str = "fe1c00010121e80300004c52401c44f4170520a1070000000000e8030000000028232c77";
    // Ground-truth HEARTBEAT (CRC-correct), sysid 1: type 2 (multirotor), armed,
    // system status 4 (active).
    const HEARTBEAT: &str = "fe0900010100000000000203800403be39";

    fn parser() -> MavParser {
        MavParser::new("uav-flight-1", Enrichment::default())
    }

    fn governed() -> MavParser {
        MavParser::new(
            "uav-flight-1",
            Enrichment::governing([
                "affiliation",
                "speed",
                "heading",
                "course",
                "vehicle_type",
                "status",
                "armed",
            ])
            .with_affiliation("friendly"),
        )
    }

    fn bytes(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    #[test]
    fn decodes_position_altitude_speed_heading() {
        let p = parser().parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(p.sysid, 1);
        assert!((p.lat - 47.397742).abs() < 1e-6);
        assert!((p.alt_m - 500.0).abs() < 1e-6);
        assert!((p.heading.unwrap() - 90.0).abs() < 1e-6);
        assert!((p.sog.unwrap() - 19.44).abs() < 0.01); // 10 m/s in knots
    }

    #[test]
    fn heartbeat_state_correlates_into_positions() {
        let p = governed();
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None); // cached, no event
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.vehicle_type, Some("multirotor"));
        assert_eq!(pos.status, Some("active"));
        assert_eq!(pos.armed, Some(true));
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.as_str())
        };
        assert_eq!(attr("affiliation"), Some("friendly"));
        assert_eq!(attr("vehicle_type"), Some("multirotor"));
        assert_eq!(attr("armed"), Some("true"));
        assert!(ev
            .metadata
            .iter()
            .any(|m| m.key == "mav_sysid" && m.value == "1"));
    }

    #[test]
    fn default_mode_routes_tactical_to_metadata() {
        let pos = parser().parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = parser().to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert!(ev.metadata.iter().any(|m| m.key == "affiliation"));
        assert!(!ev.attributes.iter().any(|a| a.key == "affiliation"));
    }

    #[test]
    fn corrupt_crc_is_rejected() {
        let mut b = bytes(GPI);
        let last = b.len() - 1;
        b[last] ^= 0xFF;
        assert_eq!(parser().parse_frame(&b), Err(MavError::BadCrc));
    }

    #[test]
    fn unmapped_message_is_ignored_not_errored() {
        // ATTITUDE (msgid 30), zero-length body: valid framing, not mapped. We do
        // not validate its CRC (unmapped), we just decline to map it.
        let attitude = bytes("fe000001011e0000");
        assert_eq!(parser().parse_frame(&attitude).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parser().parse_frame(b"\x00\x01\x02\x03").is_err());
        assert!(parser().parse_frame(&[0xFEu8]).is_err());
        assert!(parser().parse_frame(&[]).is_err());
    }
}
