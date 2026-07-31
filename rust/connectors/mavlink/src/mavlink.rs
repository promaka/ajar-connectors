// SPDX-License-Identifier: Apache-2.0
//! MAVLink vehicle telemetry -> canonical Ajar event.
//!
//! MAVLink is the framed binary protocol most UAS/drone autopilots and ground
//! stations speak (both v1, magic `0xFE`, and v2, magic `0xFD`). This is an
//! untrusted edge: frames can be truncated, mis-framed, or hostile, so the frame
//! is length-checked and its CRC verified before any field is read — it never
//! panics and never trusts an unverified frame.
//!
//! Scope — full telemetry passthrough. A GPS fix anchors a track on the map, so
//! GLOBAL_POSITION_INT (33) and GPS_RAW_INT (24) are the two messages that emit
//! an event. Every other message the autopilot sends updates a per–system-id
//! telemetry snapshot, and each emitted track carries the vehicle's latest known
//! state. Whatever the drone reports is mapped; whatever it omits stays absent.
//!
//!  - **Position/kinematics** — GLOBAL_POSITION_INT (33): WGS-84 position,
//!    altitude (AMSL + relative), true heading, ground/vertical speed.
//!    GPS_RAW_INT (24): position, course, ground speed, and fix quality
//!    (fix type, satellites, HDOP).
//!  - **Attitude** — ATTITUDE (30): roll, pitch, yaw.
//!  - **Airdata** — VFR_HUD (74): airspeed, throttle, climb rate.
//!  - **Power/health** — SYS_STATUS (1) and BATTERY_STATUS (147): battery
//!    voltage, current, remaining, consumed charge, temperature, CPU load.
//!  - **Identity/state** — HEARTBEAT (0): vehicle type, armed state, system
//!    status, and flight mode.
//!
//! Each airframe is its own track: the MAVLink system id is emitted as the stable
//! `source_uid` (and `mav_sysid`), so Core derives a per-vehicle `track_id`
//! rather than collapsing every drone onto the connector's `source_id`.
//!
//! MAVLink orders a message's fields on the wire by decreasing type size; the
//! offsets below follow that layout and are verified against constructed frames.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

/// Per-vehicle cap on raw frames carried forward before the next emit, and their
/// total bytes. A vehicle streaming telemetry but never a position must cost
/// bounded memory: past the cap the oldest pending frame is dropped, never the event.
const MAX_PENDING_FRAMES: usize = 128;
const MAX_PENDING_BYTES: usize = 32 * 1024;

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

/// A vehicle's latest known non-positional telemetry, cached by system id and
/// attached to every emitted track. Every field is optional: absent until the
/// drone reports it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VehicleState {
    // HEARTBEAT (0)
    /// Vehicle category: fixed-wing, multirotor, …
    pub vehicle_type: Option<&'static str>,
    /// System status: active, critical, emergency, …
    pub status: Option<&'static str>,
    /// Armed state.
    pub armed: Option<bool>,
    /// Coarse flight mode derived from the base-mode flags.
    pub mode: Option<&'static str>,
    /// Autopilot-specific mode number (ArduPilot/PX4 differ); passthrough.
    pub custom_mode: Option<u32>,
    // ATTITUDE (30) — degrees
    pub roll: Option<f64>,
    pub pitch: Option<f64>,
    pub yaw: Option<f64>,
    // VFR_HUD (74)
    /// Airspeed, m/s (distinct from GPS ground speed).
    pub airspeed: Option<f64>,
    /// Throttle, percent.
    pub throttle: Option<u16>,
    /// Climb rate, m/s (positive up).
    pub climb: Option<f64>,
    // SYS_STATUS (1) / BATTERY_STATUS (147)
    pub battery_voltage: Option<f64>,  // volts
    pub battery_current: Option<f64>,  // amps
    pub battery_remaining: Option<i8>, // percent
    pub battery_consumed_mah: Option<i32>,
    pub battery_temp: Option<f64>, // degrees C
    pub cpu_load: Option<f64>,     // percent
    // GPS_RAW_INT (24) quality
    pub gps_fix: Option<&'static str>,
    pub gps_sats: Option<u8>,
    pub gps_hdop: Option<f64>,
}

/// A decoded MAVLink position, plus the vehicle's cached telemetry snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct MavPosition {
    pub sysid: u8,
    pub msg_id: u32,
    pub lat: f64,
    pub lon: f64,
    /// Altitude above mean sea level, metres.
    pub alt_m: f64,
    /// Altitude above home, metres (GLOBAL_POSITION_INT).
    pub relative_alt_m: Option<f64>,
    /// True heading, degrees (GLOBAL_POSITION_INT).
    pub heading: Option<f64>,
    /// Course over ground, degrees (GPS_RAW_INT).
    pub course: Option<f64>,
    /// Ground speed, m/s.
    pub sog: Option<f64>,
    /// Vertical speed, m/s positive up (GLOBAL_POSITION_INT).
    pub vertical_speed: Option<f64>,
    /// Latest known non-positional telemetry for this system id.
    pub state: VehicleState,
    /// Every raw MAVLink frame that contributed to this event since the last
    /// emit — the position frame plus cached telemetry frames (heartbeat,
    /// attitude, battery, …) — concatenated verbatim into the signed `payload`.
    pub raw: Vec<u8>,
    /// True if the per-vehicle buffer dropped frames over the cap before this emit.
    pub truncated: bool,
}

/// Normalizes MAVLink for one connector identity, caching per–system-id
/// telemetry across messages.
/// One vehicle: its latest parsed telemetry, plus the raw frames received since
/// its last emitted event (carried forward so non-position frames are not lost).
#[derive(Default)]
struct Vehicle {
    state: VehicleState,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    dropped_since_emit: bool,
}

impl Vehicle {
    /// Remember one raw frame, dropping the oldest past the cap; returns # dropped.
    fn push_raw(&mut self, raw: &[u8]) -> u64 {
        self.pending.push_back(raw.to_vec());
        self.pending_bytes += raw.len();
        let mut dropped = 0;
        while self.pending.len() > MAX_PENDING_FRAMES || self.pending_bytes > MAX_PENDING_BYTES {
            match self.pending.pop_front() {
                Some(old) => {
                    self.pending_bytes -= old.len();
                    self.dropped_since_emit = true;
                    dropped += 1;
                }
                None => break,
            }
        }
        dropped
    }

    /// Concatenate all pending frames (MAVLink frames self-delimit — a re-parser
    /// walks them by their length field), reporting whether any were dropped.
    fn drain_payload(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(self.pending_bytes);
        for f in self.pending.drain(..) {
            out.extend_from_slice(&f);
        }
        self.pending_bytes = 0;
        (out, std::mem::take(&mut self.dropped_since_emit))
    }
}

pub struct MavParser {
    source_id: String,
    enrichment: Enrichment,
    vehicles: Mutex<HashMap<u8, Vehicle>>,
    /// Carry-forward frames dropped over the per-vehicle cap, since start.
    dropped: Arc<AtomicU64>,
}

/// CRC_EXTRA and full (untruncated) payload length for the messages we decode.
fn spec(msg_id: u32) -> Option<(u8, usize)> {
    match msg_id {
        0 => Some((50, 9)),     // HEARTBEAT
        1 => Some((124, 31)),   // SYS_STATUS
        24 => Some((24, 30)),   // GPS_RAW_INT
        30 => Some((39, 28)),   // ATTITUDE
        33 => Some((104, 28)),  // GLOBAL_POSITION_INT
        74 => Some((20, 20)),   // VFR_HUD
        147 => Some((154, 36)), // BATTERY_STATUS
        _ => None,
    }
}

impl MavParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            vehicles: Mutex::new(HashMap::new()),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Parse one MAVLink frame. Returns a position for a CRC-valid position
    /// message (33/24); `Ok(None)` for a state message that updates the per-sysid
    /// telemetry cache, or a message we do not map.
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

        let msg_end = crc_start + 2;
        let Some((crc_extra, full_len)) = spec(msg_id) else {
            // Valid framing, a message we do not map: carry the raw frame forward
            // (a future parser may understand it), emit nothing.
            self.carry(sysid, &frame[..msg_end]);
            return Ok(None);
        };

        // CRC covers everything from just after the magic through the payload,
        // plus the message's CRC_EXTRA. Verify before trusting any field.
        let given = frame[crc_start] as u16 | (frame[crc_start + 1] as u16) << 8;
        if crc(&frame[1..crc_start], crc_extra) != given {
            return Err(MavError::BadCrc);
        }

        // CRC-valid: carry this raw frame forward for the vehicle.
        self.carry(sysid, &frame[..msg_end]);

        // v2 truncates trailing zero bytes; zero-extend to the full payload.
        let mut payload = vec![0u8; full_len];
        let body = &frame[header_len..crc_start];
        let n = body.len().min(full_len);
        payload[..n].copy_from_slice(&body[..n]);

        match msg_id {
            0 => {
                self.mutate(sysid, |s| heartbeat(s, &payload));
                Ok(None)
            }
            1 => {
                self.mutate(sysid, |s| sys_status(s, &payload));
                Ok(None)
            }
            30 => {
                self.mutate(sysid, |s| attitude(s, &payload));
                Ok(None)
            }
            74 => {
                self.mutate(sysid, |s| vfr_hud(s, &payload));
                Ok(None)
            }
            147 => {
                self.mutate(sysid, |s| battery_status(s, &payload));
                Ok(None)
            }
            33 => Ok(Some(self.global_position(sysid, &payload))),
            24 => Ok(Some(self.gps_raw(sysid, &payload))),
            _ => Ok(None),
        }
    }

    /// Apply `f` to this system id's cached state (creating it on first sight).
    fn mutate(&self, sysid: u8, f: impl FnOnce(&mut VehicleState)) {
        let mut vehicles = self.vehicles.lock().expect("vehicle mutex");
        f(&mut vehicles.entry(sysid).or_default().state);
    }

    fn snapshot(&self, sysid: u8) -> VehicleState {
        self.vehicles
            .lock()
            .expect("vehicle mutex")
            .get(&sysid)
            .map(|v| v.state.clone())
            .unwrap_or_default()
    }

    /// Carry one raw frame forward on `sysid`'s buffer, counting any drop.
    fn carry(&self, sysid: u8, raw: &[u8]) {
        let dropped = self
            .vehicles
            .lock()
            .expect("vehicle mutex")
            .entry(sysid)
            .or_default()
            .push_raw(raw);
        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
            tracing::warn!(dropped, sysid, "mavlink: carry-forward buffer over cap");
        }
    }

    /// Drain `sysid`'s carried frames into one payload, with the truncated flag.
    fn drain(&self, sysid: u8) -> (Vec<u8>, bool) {
        self.vehicles
            .lock()
            .expect("vehicle mutex")
            .entry(sysid)
            .or_default()
            .drain_payload()
    }

    /// GLOBAL_POSITION_INT (msg 33): position, altitudes, ground/vertical speed
    /// from the velocity vector, true heading.
    fn global_position(&self, sysid: u8, p: &[u8]) -> MavPosition {
        let vx = i16le(p, 20) as f64;
        let vy = i16le(p, 22) as f64;
        let vz = i16le(p, 24) as f64; // positive down, cm/s
        let sog = Some((vx * vx + vy * vy).sqrt() / 100.0);
        let climb = -vz / 100.0;
        let hdg = u16le(p, 26);
        let (raw, truncated) = self.drain(sysid);
        MavPosition {
            sysid,
            msg_id: 33,
            lat: i32le(p, 4) as f64 / 1e7,
            lon: i32le(p, 8) as f64 / 1e7,
            alt_m: i32le(p, 12) as f64 / 1000.0,
            relative_alt_m: Some(i32le(p, 16) as f64 / 1000.0),
            heading: (hdg != u16::MAX).then_some(hdg as f64 / 100.0),
            course: None,
            sog,
            // Normalize IEEE negative zero so a level aircraft reads "0.0".
            vertical_speed: Some(if climb == 0.0 { 0.0 } else { climb }),
            state: self.snapshot(sysid),
            raw,
            truncated,
        }
    }

    /// GPS_RAW_INT (msg 24): position, altitude, ground speed, course, and fix
    /// quality (which also updates the cache so later position reports carry it).
    fn gps_raw(&self, sysid: u8, p: &[u8]) -> MavPosition {
        let eph = u16le(p, 20);
        let vel = u16le(p, 24);
        let cog = u16le(p, 26);
        let fix = gps_fix(p[28]);
        let sats = p[29];
        self.mutate(sysid, |s| {
            s.gps_fix = fix;
            s.gps_sats = (sats != u8::MAX).then_some(sats);
            s.gps_hdop = (eph != u16::MAX).then_some(eph as f64 / 100.0);
        });
        let (raw, truncated) = self.drain(sysid);
        MavPosition {
            sysid,
            msg_id: 24,
            lat: i32le(p, 8) as f64 / 1e7,
            lon: i32le(p, 12) as f64 / 1e7,
            alt_m: i32le(p, 16) as f64 / 1000.0,
            relative_alt_m: None,
            heading: None,
            course: (cog != u16::MAX).then_some(cog as f64 / 100.0),
            sog: (vel != u16::MAX).then_some(vel as f64 / 100.0),
            vertical_speed: None,
            state: self.snapshot(sysid),
            raw,
            truncated,
        }
    }

    fn base_builder(&self, p: &MavPosition) -> EventBuilder {
        let s = &p.state;

        // The raw MAVLink frames are preserved verbatim in the signed payload;
        // system id is the stable identity (source_uid = track key; mav_sysid).
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(p.lat, p.lon, p.alt_m)
            .payload(p.raw.clone())
            .metadata("source_uid", p.sysid.to_string())
            .metadata("mav_sysid", p.sysid.to_string());
        if p.truncated {
            b = b.metadata("payload_truncated", "true");
        }
        // Operator-asserted affiliation only — never a connector-invented default.
        if let Some(aff) = self.enrichment.affiliation.as_deref() {
            b = b.attribute("affiliation", aff);
        }

        // Parse every field into attributes; Core demotes undeclared keys.
        macro_rules! attr {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    b = b.attribute($key, v);
                }
            };
        }
        attr!("speed", p.sog.map(|v| format!("{v:.1}"))); // m/s
        attr!("heading", p.heading.map(|v| format!("{v:.1}"))); // deg true
        attr!("course", p.course.map(|v| format!("{v:.1}"))); // deg
        attr!(
            "vertical_rate",
            p.vertical_speed.or(s.climb).map(|v| format!("{v:.1}"))
        ); // m/s
        attr!(
            "relative_altitude",
            p.relative_alt_m.map(|v| format!("{v:.1}"))
        ); // m
        attr!("vehicle_type", s.vehicle_type);
        attr!("status", s.status);
        attr!("armed", s.armed.map(|a| if a { "true" } else { "false" }));
        attr!("mode", s.mode);
        attr!("roll", s.roll.map(|v| format!("{v:.1}"))); // deg
        attr!("pitch", s.pitch.map(|v| format!("{v:.1}"))); // deg
        attr!("yaw", s.yaw.map(|v| format!("{v:.1}"))); // deg
        attr!("airspeed", s.airspeed.map(|v| format!("{v:.1}"))); // m/s (ungoverned)
        attr!("throttle", s.throttle.map(|v| v.to_string())); // %
        attr!(
            "battery_voltage",
            s.battery_voltage.map(|v| format!("{v:.2}"))
        ); // V
        attr!(
            "battery_current",
            s.battery_current.map(|v| format!("{v:.2}"))
        ); // A
        attr!(
            "battery",
            s.battery_remaining.map(|v| v.to_string())
        ); // %
        attr!(
            "battery_consumed",
            s.battery_consumed_mah.map(|v| v.to_string())
        ); // mAh
        attr!("battery_temp", s.battery_temp.map(|v| format!("{v:.1}"))); // °C
        attr!("cpu_load", s.cpu_load.map(|v| format!("{v:.0}"))); // %
        attr!("gps_fix", s.gps_fix);
        attr!("gps_satellites", s.gps_sats.map(|v| v.to_string()));
        attr!("gps_hdop", s.gps_hdop.map(|v| format!("{v:.2}")));

        // Autopilot-specific mode number: an opaque identifier -> metadata.
        if let Some(cm) = s.custom_mode {
            b = b.metadata("custom_mode", cm.to_string());
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

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        vec![("connector_dropped_carryforward_total", self.dropped.clone())]
    }
}

fn box_err(e: MavError) -> ParseError {
    Box::new(e) as ParseError
}

// --- per-message decoders (mutate the cached snapshot) ---

/// HEARTBEAT (msg 0): vehicle type, armed state, system status, flight mode.
fn heartbeat(s: &mut VehicleState, p: &[u8]) {
    let base_mode = p[6];
    s.vehicle_type = vehicle_type(p[4]);
    s.status = mav_state(p[7]);
    s.armed = Some(base_mode & 0x80 != 0); // MAV_MODE_FLAG_SAFETY_ARMED
    s.mode = base_flag_mode(base_mode);
    // custom_mode is only meaningful when the custom-mode flag is set.
    s.custom_mode = (base_mode & 0x01 != 0).then(|| u32le(p, 0));
}

/// SYS_STATUS (msg 1): battery voltage/current/remaining and CPU load. Sentinel
/// values (0xFFFF / -1) mean "unknown" and are dropped.
fn sys_status(s: &mut VehicleState, p: &[u8]) {
    let load = u16le(p, 12);
    let voltage = u16le(p, 14);
    let current = i16le(p, 16);
    let remaining = p[30] as i8;
    if load != u16::MAX {
        s.cpu_load = Some(load as f64 / 10.0);
    }
    if voltage != u16::MAX {
        s.battery_voltage = Some(voltage as f64 / 1000.0);
    }
    if current != -1 {
        s.battery_current = Some(current as f64 / 100.0);
    }
    if remaining != -1 {
        s.battery_remaining = Some(remaining);
    }
}

/// ATTITUDE (msg 30): roll, pitch, yaw (radians on the wire -> degrees).
fn attitude(s: &mut VehicleState, p: &[u8]) {
    s.roll = Some((f32le(p, 4) as f64).to_degrees());
    s.pitch = Some((f32le(p, 8) as f64).to_degrees());
    s.yaw = Some((f32le(p, 12) as f64).to_degrees().rem_euclid(360.0));
}

/// VFR_HUD (msg 74): airspeed, throttle, climb rate.
fn vfr_hud(s: &mut VehicleState, p: &[u8]) {
    s.airspeed = Some(f32le(p, 0) as f64);
    s.climb = Some(f32le(p, 12) as f64);
    s.throttle = Some(u16le(p, 18));
}

/// BATTERY_STATUS (msg 147): consumed charge, temperature, and a more precise
/// voltage/current/remaining than SYS_STATUS when both are sent.
fn battery_status(s: &mut VehicleState, p: &[u8]) {
    let consumed = i32le(p, 0);
    let temperature = i16le(p, 8);
    let cell0 = u16le(p, 10);
    let current = i16le(p, 30);
    let remaining = p[35] as i8;
    if consumed != -1 {
        s.battery_consumed_mah = Some(consumed);
    }
    if temperature != i16::MAX {
        s.battery_temp = Some(temperature as f64 / 100.0);
    }
    if cell0 != u16::MAX {
        s.battery_voltage = Some(cell0 as f64 / 1000.0);
    }
    if current != -1 {
        s.battery_current = Some(current as f64 / 100.0);
    }
    if remaining != -1 {
        s.battery_remaining = Some(remaining);
    }
}

// --- enumerations ---

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

/// Coarse flight mode from MAV_MODE_FLAG base-mode bits (most-specific first).
/// The autopilot-specific detail is the separate `custom_mode` passthrough.
fn base_flag_mode(base_mode: u8) -> Option<&'static str> {
    if base_mode & 0x04 != 0 {
        Some("auto") // MAV_MODE_FLAG_AUTO_ENABLED
    } else if base_mode & 0x08 != 0 {
        Some("guided") // MAV_MODE_FLAG_GUIDED_ENABLED
    } else if base_mode & 0x10 != 0 {
        Some("stabilize") // MAV_MODE_FLAG_STABILIZE_ENABLED
    } else if base_mode & 0x40 != 0 {
        Some("manual") // MAV_MODE_FLAG_MANUAL_INPUT_ENABLED
    } else {
        None
    }
}

/// GPS_FIX_TYPE → string.
fn gps_fix(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "no-gps",
        1 => "no-fix",
        2 => "2d",
        3 => "3d",
        4 => "dgps",
        5 => "rtk-float",
        6 => "rtk-fixed",
        7 => "static",
        8 => "ppp",
        _ => return None,
    })
}

// --- little-endian field readers ---

fn i32le(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn f32le(b: &[u8], off: usize) -> f32 {
    f32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
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

    const GOVERNED: [&str; 24] = [
        "affiliation",
        "speed",
        "heading",
        "course",
        "vertical_rate",
        "relative_altitude",
        "vehicle_type",
        "status",
        "armed",
        "mode",
        "roll",
        "pitch",
        "yaw",
        "airspeed",
        "throttle",
        "battery_voltage",
        "battery_current",
        "battery",
        "battery_consumed",
        "battery_temp",
        "cpu_load",
        "gps_fix",
        "gps_satellites",
        "gps_hdop",
    ];

    fn governed() -> MavParser {
        MavParser::new(
            "uav-flight-1",
            Enrichment::governing(GOVERNED).with_affiliation("friendly"),
        )
    }

    fn bytes(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    /// Assemble a CRC-correct v1 frame (sysid 1, compid 1, seq 0) for `msgid`
    /// with `payload` placed verbatim — the encode side of the offset check.
    fn frame(msgid: u32, payload: &[u8]) -> Vec<u8> {
        let (extra, _) = spec(msgid).expect("known msgid");
        let mut f = vec![0xFE, payload.len() as u8, 0, 1, 1, msgid as u8];
        f.extend_from_slice(payload);
        let c = crc(&f[1..], extra);
        f.push((c & 0xFF) as u8);
        f.push((c >> 8) as u8);
        f
    }

    fn put_i32(p: &mut [u8], off: usize, v: i32) {
        p[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(p: &mut [u8], off: usize, v: u32) {
        p[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_f32(p: &mut [u8], off: usize, v: f32) {
        p[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_i16(p: &mut [u8], off: usize, v: i16) {
        p[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u16(p: &mut [u8], off: usize, v: u16) {
        p[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn attr_of<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .find(|a| a.key == k)
            .map(|a| a.value.as_str())
    }
    fn meta_of<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
        ev.metadata
            .iter()
            .find(|m| m.key == k)
            .map(|m| m.value.as_str())
    }

    #[test]
    fn decodes_position_altitude_speed_heading() {
        let p = parser().parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(p.sysid, 1);
        assert!((p.lat - 47.397742).abs() < 1e-6);
        assert!((p.alt_m - 500.0).abs() < 1e-6);
        assert!((p.heading.unwrap() - 90.0).abs() < 1e-6);
        assert!((p.sog.unwrap() - 10.0).abs() < 0.01); // 10 m/s
    }

    #[test]
    fn sysid_becomes_stable_source_uid() {
        let pos = parser().parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = parser().to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        // Each airframe is its own track: sysid rides as source_uid (Core's track
        // key) and mav_sysid.
        assert_eq!(meta_of(&ev, "source_uid"), Some("1"));
        assert_eq!(meta_of(&ev, "mav_sysid"), Some("1"));
    }

    #[test]
    fn heartbeat_state_correlates_into_positions() {
        let p = governed();
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None); // cached, no event
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.vehicle_type, Some("multirotor"));
        assert_eq!(pos.state.status, Some("active"));
        assert_eq!(pos.state.armed, Some(true));
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "affiliation"), Some("friendly"));
        assert_eq!(attr_of(&ev, "vehicle_type"), Some("multirotor"));
        assert_eq!(attr_of(&ev, "armed"), Some("true"));
    }

    #[test]
    fn attitude_maps_roll_pitch_yaw_in_degrees() {
        let p = governed();
        let mut payload = vec![0u8; 28];
        put_f32(&mut payload, 4, 0.5); // roll rad
        put_f32(&mut payload, 8, -0.25); // pitch rad
        put_f32(&mut payload, 12, std::f32::consts::FRAC_PI_2); // yaw = 90°
        assert_eq!(p.parse_frame(&frame(30, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert!((pos.state.roll.unwrap() - 0.5_f64.to_degrees()).abs() < 1e-3);
        assert!((pos.state.pitch.unwrap() - (-0.25_f64).to_degrees()).abs() < 1e-3);
        assert!((pos.state.yaw.unwrap() - 90.0).abs() < 1e-3);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "yaw"), Some("90.0"));
    }

    #[test]
    fn sys_status_maps_battery_and_load() {
        let p = governed();
        let mut payload = vec![0u8; 31];
        put_u16(&mut payload, 12, 250); // load 25.0%
        put_u16(&mut payload, 14, 12600); // 12.6 V
        put_i16(&mut payload, 16, 1500); // 15.0 A
        payload[30] = 77i8 as u8; // remaining 77%
        assert_eq!(p.parse_frame(&frame(1, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.battery_remaining, Some(77));
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "battery_voltage"), Some("12.60"));
        assert_eq!(attr_of(&ev, "battery_current"), Some("15.00"));
        assert_eq!(attr_of(&ev, "cpu_load"), Some("25"));
    }

    #[test]
    fn sys_status_unknown_sentinels_stay_absent() {
        let p = governed();
        let mut payload = vec![0u8; 31];
        put_u16(&mut payload, 14, u16::MAX); // voltage unknown
        put_i16(&mut payload, 16, -1); // current unknown
        payload[30] = (-1i8) as u8; // remaining unknown
        assert_eq!(p.parse_frame(&frame(1, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.battery_voltage, None);
        assert_eq!(pos.state.battery_current, None);
        assert_eq!(pos.state.battery_remaining, None);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "battery_voltage"), None);
    }

    #[test]
    fn vfr_hud_maps_airspeed_throttle_climb() {
        let p = governed();
        let mut payload = vec![0u8; 20];
        put_f32(&mut payload, 0, 20.0); // airspeed 20 m/s
        put_f32(&mut payload, 12, 2.5); // climb 2.5 m/s
        put_u16(&mut payload, 18, 55); // throttle 55%
        assert_eq!(p.parse_frame(&frame(74, &payload)).unwrap(), None);

        // Trigger on GPS_RAW (which has no vertical velocity of its own) so the
        // cached VFR climb is what surfaces as vertical_speed.
        let mut gps = vec![0u8; 30];
        put_i32(&mut gps, 8, 474_000_000);
        put_i32(&mut gps, 12, 85_000_000);
        put_i32(&mut gps, 16, 500_000);
        gps[28] = 3;
        let pos = p.parse_frame(&frame(24, &gps)).unwrap().unwrap();
        assert!((pos.state.airspeed.unwrap() - 20.0).abs() < 0.1);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "throttle"), Some("55"));
        assert_eq!(attr_of(&ev, "vertical_rate"), Some("2.5")); // VFR climb fallback

        // A GLOBAL_POSITION_INT carries its own (level) vertical speed, clean of
        // negative zero, and it wins over the cached VFR value.
        let gpi = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev2 = p.to_event_at(&gpi, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev2, "vertical_rate"), Some("0.0"));
    }

    #[test]
    fn battery_status_maps_consumed_and_temperature() {
        let p = governed();
        let mut payload = vec![0u8; 36];
        put_i32(&mut payload, 0, 1234); // consumed 1234 mAh
        put_i16(&mut payload, 8, 2500); // 25.0 °C
        put_u16(&mut payload, 10, 12550); // cell0 12.55 V
        put_i16(&mut payload, 30, 1600); // 16.0 A
        payload[35] = 66i8 as u8; // remaining 66%
        assert_eq!(p.parse_frame(&frame(147, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.battery_consumed_mah, Some(1234));
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "battery_consumed"), Some("1234"));
        assert_eq!(attr_of(&ev, "battery_temp"), Some("25.0"));
        assert_eq!(attr_of(&ev, "battery_voltage"), Some("12.55"));
    }

    #[test]
    fn gps_raw_maps_fix_quality_and_caches_it() {
        let p = governed();
        let mut payload = vec![0u8; 30];
        put_i32(&mut payload, 8, 474_000_000); // 47.4 N
        put_i32(&mut payload, 12, 85_000_000); // 8.5 E
        put_i32(&mut payload, 16, 500_000); // 500 m
        put_u16(&mut payload, 20, 120); // eph -> hdop 1.2
        put_u16(&mut payload, 24, 1000); // vel 10 m/s
        put_u16(&mut payload, 26, 4500); // cog 45.0°
        payload[28] = 3; // fix 3d
        payload[29] = 12; // 12 sats

        let pos = p.parse_frame(&frame(24, &payload)).unwrap().unwrap();
        assert_eq!(pos.msg_id, 24);
        assert_eq!(pos.state.gps_fix, Some("3d"));
        assert_eq!(pos.state.gps_sats, Some(12));
        assert!((pos.state.gps_hdop.unwrap() - 1.2).abs() < 1e-9);
        assert!((pos.course.unwrap() - 45.0).abs() < 1e-6);
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "gps_fix"), Some("3d"));
        assert_eq!(attr_of(&ev, "gps_satellites"), Some("12"));

        // The fix quality is cached, so a later GLOBAL_POSITION_INT carries it too.
        let gpi = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(gpi.state.gps_fix, Some("3d"));
    }

    #[test]
    fn heartbeat_maps_flight_mode() {
        let p = governed();
        let mut payload = vec![0u8; 9];
        put_u32(&mut payload, 0, 4); // custom_mode = 4 (autopilot-specific)
        payload[4] = 1; // type fixed-wing
        payload[6] = 0x01 | 0x04 | 0x80; // custom-enabled | auto | armed
        payload[7] = 4; // active
        assert_eq!(p.parse_frame(&frame(0, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.mode, Some("auto"));
        assert_eq!(pos.state.custom_mode, Some(4));
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(attr_of(&ev, "mode"), Some("auto"));
        assert_eq!(meta_of(&ev, "custom_mode"), Some("4"));
    }

    #[test]
    fn distinct_sysids_keep_separate_state() {
        let p = governed();
        // sysid 1 heartbeat: multirotor. sysid 7 heartbeat: fixed-wing.
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None); // sysid 1
        let mut hb7 = vec![0u8; 9];
        hb7[4] = 1; // fixed-wing
        hb7[7] = 4;
        let mut f7 = frame(0, &hb7);
        f7[3] = 7; // override sysid -> 7 (recompute CRC)
        let (extra, _) = spec(0).unwrap();
        let c = crc(&f7[1..f7.len() - 2], extra);
        let n = f7.len();
        f7[n - 2] = (c & 0xFF) as u8;
        f7[n - 1] = (c >> 8) as u8;
        assert_eq!(p.parse_frame(&f7).unwrap(), None); // sysid 7 cached

        let pos1 = p.parse_frame(&bytes(GPI)).unwrap().unwrap(); // sysid 1
        assert_eq!(pos1.sysid, 1);
        assert_eq!(pos1.state.vehicle_type, Some("multirotor"));
    }

    #[test]
    fn absent_affiliation_not_invented_and_raw_carried() {
        // Default mode: no operator affiliation -> none invented; and the raw
        // frame is preserved verbatim in the signed payload.
        let p = parser();
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        assert!(!ev.attributes.iter().any(|a| a.key == "affiliation"));
        assert!(!ev.metadata.iter().any(|m| m.key == "affiliation"));
        assert_eq!(ev.payload, bytes(GPI));
    }

    #[test]
    fn carries_cache_only_frames_forward_into_payload() {
        // A HEARTBEAT emits nothing; its raw must ride into the next position
        // event's payload, concatenated with the position frame (self-delimiting).
        let p = governed();
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None);
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = p.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        let mut want = bytes(HEARTBEAT);
        want.extend_from_slice(&bytes(GPI));
        assert_eq!(ev.payload, want);
        // The correlated heartbeat state still surfaces as an attribute.
        assert_eq!(attr_of(&ev, "vehicle_type"), Some("multirotor"));
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
        // PARAM_VALUE (msgid 22), zero-length body: valid framing, not mapped.
        let param = bytes("fe00000101160000");
        assert_eq!(parser().parse_frame(&param).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parser().parse_frame(b"\x00\x01\x02\x03").is_err());
        assert!(parser().parse_frame(&[0xFEu8]).is_err());
        assert!(parser().parse_frame(&[]).is_err());
    }
}
