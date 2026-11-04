// SPDX-License-Identifier: Apache-2.0
//! MAVLink v1 (`0xFE`) and v2 (`0xFD`) telemetry to `mim:aircraft` events.
//! GLOBAL_POSITION_INT (33) and GPS_RAW_INT (24) emit an event; HEARTBEAT,
//! SYS_STATUS, ATTITUDE, VFR_HUD and BATTERY_STATUS update a per-system-id
//! snapshot that every later event of that vehicle carries.

mod messages;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::GovernedIdentity;
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

use messages::{crc, crc_extra_and_len, gps_fix, i16le, i32le, u16le, u32le};

const MAX_PENDING_FRAMES: usize = 128;
const MAX_PENDING_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum MavError {
    #[error("not a MAVLink frame")]
    NotMavlink,
    #[error("MAVLink frame truncated")]
    Truncated,
    /// Corrupt, or a dialect with a different CRC_EXTRA.
    #[error("MAVLink CRC mismatch")]
    BadCrc,
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

/// Latest non-positional telemetry of one vehicle; a field stays `None` until
/// a message carries it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VehicleState {
    pub vehicle_type: Option<&'static str>,
    pub status: Option<&'static str>,
    pub armed: Option<bool>,
    /// Coarse flight mode from the base-mode flags.
    pub mode: Option<&'static str>,
    /// Autopilot-specific mode number; ArduPilot and PX4 differ.
    pub custom_mode: Option<u32>,
    pub roll_deg: Option<f64>,
    pub pitch_deg: Option<f64>,
    pub yaw_deg: Option<f64>,
    pub airspeed_mps: Option<f64>,
    pub throttle_pct: Option<u16>,
    /// Positive up.
    pub climb_mps: Option<f64>,
    pub battery_voltage_v: Option<f64>,
    pub battery_current_a: Option<f64>,
    pub battery_remaining_pct: Option<i8>,
    pub battery_consumed_mah: Option<i32>,
    pub battery_temp_c: Option<f64>,
    pub cpu_load_pct: Option<f64>,
    pub gps_fix: Option<&'static str>,
    pub gps_sats: Option<u8>,
    pub gps_hdop: Option<f64>,
    /// MAVLink 2 GPS_RAW_INT uncertainty extensions; absent on MAVLink 1 or
    /// when zero.
    pub gps_h_acc_m: Option<f64>,
    pub gps_v_acc_m: Option<f64>,
    pub gps_vel_acc_mps: Option<f64>,
    pub gps_hdg_acc_deg: Option<f64>,
}

/// A position message with the vehicle's latest cached telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct MavPosition {
    pub sysid: u8,
    pub msg_id: u32,
    pub lat: f64,
    pub lon: f64,
    /// Above mean sea level.
    pub alt_m: f64,
    /// Above home; GLOBAL_POSITION_INT only.
    pub relative_alt_m: Option<f64>,
    /// True heading; GLOBAL_POSITION_INT only.
    pub heading_deg: Option<f64>,
    /// Course over ground; GPS_RAW_INT only.
    pub course_deg: Option<f64>,
    pub sog_mps: Option<f64>,
    /// Positive up; GLOBAL_POSITION_INT only.
    pub vertical_speed_mps: Option<f64>,
    pub state: VehicleState,
    /// Every frame received from this vehicle since its last event,
    /// concatenated; frames self-delimit by their length field.
    pub raw: Vec<u8>,
    /// Frames were dropped from `raw` over the per-vehicle cap.
    pub truncated: bool,
}

#[derive(Default)]
struct Vehicle {
    state: VehicleState,
    pending: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    dropped_since_emit: bool,
}

impl Vehicle {
    /// Returns how many of the oldest pending frames were dropped over the cap.
    fn push_raw(&mut self, raw: &[u8]) -> u64 {
        self.pending.push_back(raw.to_vec());
        self.pending_bytes += raw.len();
        let mut dropped = 0;
        while self.pending.len() > MAX_PENDING_FRAMES || self.pending_bytes > MAX_PENDING_BYTES {
            let Some(old) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes -= old.len();
            self.dropped_since_emit = true;
            dropped += 1;
        }
        dropped
    }

    /// The pending frames concatenated, and whether any were dropped.
    fn drain_payload(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(self.pending_bytes);
        for frame in self.pending.drain(..) {
            out.extend_from_slice(&frame);
        }
        self.pending_bytes = 0;
        (out, std::mem::take(&mut self.dropped_since_emit))
    }
}

pub struct MavParser {
    source_id: String,
    enrichment: Enrichment,
    vehicles: Mutex<HashMap<u8, Vehicle>>,
    dropped: Arc<AtomicU64>,
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

    /// `Some` for a CRC-valid position message (33 or 24); `None` for a
    /// message that only updates the snapshot or one that is not mapped.
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
        let Some((crc_extra, full_len)) = crc_extra_and_len(msg_id) else {
            self.carry(sysid, &frame[..msg_end]);
            return Ok(None);
        };

        // The CRC covers everything after the magic through the payload.
        let given = frame[crc_start] as u16 | (frame[crc_start + 1] as u16) << 8;
        if crc(&frame[1..crc_start], crc_extra) != given {
            return Err(MavError::BadCrc);
        }
        self.carry(sysid, &frame[..msg_end]);

        // v2 trims trailing zero bytes; zero-extend to the full payload. Every
        // `full_len` in the table fits MAVLink's one-byte length, so 255 holds it.
        let mut zero_extended = [0u8; 255];
        let body = &frame[header_len..crc_start];
        let n = body.len().min(full_len);
        zero_extended[..n].copy_from_slice(&body[..n]);
        let payload = &zero_extended[..full_len];

        let update: fn(&mut VehicleState, &[u8]) = match msg_id {
            0 => messages::heartbeat,
            1 => messages::sys_status,
            30 => messages::attitude,
            74 => messages::vfr_hud,
            147 => messages::battery_status,
            33 => return Ok(Some(self.global_position(sysid, payload))),
            24 => return Ok(Some(self.gps_raw(sysid, payload))),
            _ => return Ok(None),
        };
        self.mutate(sysid, |s| update(s, payload));
        Ok(None)
    }

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

    fn carry(&self, sysid: u8, raw: &[u8]) {
        let mut vehicles = self.vehicles.lock().expect("vehicle mutex");
        if !vehicles.contains_key(&sysid) {
            // Two vehicles that both kept the default SYSID_THISMAV=1 merge into
            // one track; logging each new id lets an operator count airframes.
            tracing::info!(sysid, "mavlink: first frame from a new system id");
        }
        let dropped = vehicles.entry(sysid).or_default().push_raw(raw);
        if dropped > 0 {
            self.dropped.fetch_add(dropped, Ordering::Relaxed);
            tracing::warn!(dropped, sysid, "mavlink: carry-forward buffer over cap");
        }
    }

    fn drain(&self, sysid: u8) -> (Vec<u8>, bool) {
        self.vehicles
            .lock()
            .expect("vehicle mutex")
            .entry(sysid)
            .or_default()
            .drain_payload()
    }

    /// GLOBAL_POSITION_INT (33).
    fn global_position(&self, sysid: u8, p: &[u8]) -> MavPosition {
        let vx_cms = i16le(p, 20) as f64;
        let vy_cms = i16le(p, 22) as f64;
        // Positive down.
        let vz_cms = i16le(p, 24) as f64;
        let climb_mps = -vz_cms / 100.0;
        let hdg_cdeg = u16le(p, 26);
        let (raw, truncated) = self.drain(sysid);
        MavPosition {
            sysid,
            msg_id: 33,
            lat: i32le(p, 4) as f64 / 1e7,
            lon: i32le(p, 8) as f64 / 1e7,
            alt_m: i32le(p, 12) as f64 / 1000.0,
            relative_alt_m: Some(i32le(p, 16) as f64 / 1000.0),
            heading_deg: (hdg_cdeg != u16::MAX).then_some(hdg_cdeg as f64 / 100.0),
            course_deg: None,
            sog_mps: Some((vx_cms * vx_cms + vy_cms * vy_cms).sqrt() / 100.0),
            // Normalise negative zero so a level aircraft reads "0.0".
            vertical_speed_mps: Some(if climb_mps == 0.0 { 0.0 } else { climb_mps }),
            state: self.snapshot(sysid),
            raw,
            truncated,
        }
    }

    /// GPS_RAW_INT (24). The fix quality is also cached for later events.
    fn gps_raw(&self, sysid: u8, p: &[u8]) -> MavPosition {
        let eph = u16le(p, 20);
        let vel_cms = u16le(p, 24);
        let cog_cdeg = u16le(p, 26);
        let fix = gps_fix(p[28]);
        let sats = p[29];
        // MAVLink 2 extensions after alt_ellipsoid: h_acc (mm) at 34, v_acc
        // (mm) at 38, vel_acc (mm/s) at 42, hdg_acc (degE5) at 46. Zero, as
        // from a trimmed payload, and the all-ones sentinel mean not known.
        let ext = |off: usize| -> Option<f64> {
            Some(u32le(p, off))
                .filter(|v| *v != 0 && *v != u32::MAX)
                .map(f64::from)
        };
        self.mutate(sysid, |s| {
            s.gps_fix = fix;
            s.gps_sats = (sats != u8::MAX).then_some(sats);
            s.gps_hdop = (eph != u16::MAX).then_some(eph as f64 / 100.0);
            s.gps_h_acc_m = ext(34).map(|mm| mm / 1000.0);
            s.gps_v_acc_m = ext(38).map(|mm| mm / 1000.0);
            s.gps_vel_acc_mps = ext(42).map(|mms| mms / 1000.0);
            // The contract bounds angle_accuracy to 360.
            s.gps_hdg_acc_deg = ext(46)
                .map(|de5| de5 / 100_000.0)
                .filter(|deg| *deg <= 360.0);
        });
        let (raw, truncated) = self.drain(sysid);
        MavPosition {
            sysid,
            msg_id: 24,
            lat: i32le(p, 8) as f64 / 1e7,
            lon: i32le(p, 12) as f64 / 1e7,
            alt_m: i32le(p, 16) as f64 / 1000.0,
            relative_alt_m: None,
            heading_deg: None,
            course_deg: (cog_cdeg != u16::MAX).then_some(cog_cdeg as f64 / 100.0),
            sog_mps: (vel_cms != u16::MAX).then_some(vel_cms as f64 / 100.0),
            vertical_speed_mps: None,
            state: self.snapshot(sysid),
            raw,
            truncated,
        }
    }

    fn base_builder(&self, p: MavPosition) -> EventBuilder {
        let s = &p.state;
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(p.lat, p.lon, p.alt_m)
            .payload(p.raw)
            .metadata("source_uid", p.sysid.to_string())
            .metadata("mav_sysid", p.sysid.to_string())
            .identity("MAVLink", p.sysid.to_string());
        if p.truncated {
            b = b.metadata("payload_truncated", "true");
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }

        macro_rules! attr {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    b = b.attribute($key, v);
                }
            };
        }
        let f1 = |v: f64| format!("{v:.1}");
        let f2 = |v: f64| format!("{v:.2}");
        attr!("speed", p.sog_mps.map(f1));
        attr!("heading", p.heading_deg.map(f1));
        attr!("course", p.course_deg.map(f1));
        attr!(
            "vertical_rate",
            p.vertical_speed_mps.or(s.climb_mps).map(f1)
        );
        attr!("relative_altitude", p.relative_alt_m.map(f1));
        attr!("vehicle_type", s.vehicle_type);
        attr!("status", s.status);
        attr!("armed", s.armed.map(|a| if a { "true" } else { "false" }));
        attr!("mode", s.mode);
        attr!("roll", s.roll_deg.map(f1));
        attr!("pitch", s.pitch_deg.map(f1));
        attr!("yaw", s.yaw_deg.map(f1));
        attr!("airspeed", s.airspeed_mps.map(f1));
        attr!("throttle", s.throttle_pct.map(|v| v.to_string()));
        attr!("battery_voltage", s.battery_voltage_v.map(f2));
        attr!("battery_current", s.battery_current_a.map(f2));
        attr!("battery", s.battery_remaining_pct.map(|v| v.to_string()));
        attr!(
            "battery_consumed",
            s.battery_consumed_mah.map(|v| v.to_string())
        );
        attr!("battery_temp", s.battery_temp_c.map(f1));
        attr!("cpu_load", s.cpu_load_pct.map(|v| format!("{v:.0}")));
        attr!("gps_fix", s.gps_fix);
        attr!("gps_satellites", s.gps_sats.map(|v| v.to_string()));
        attr!("gps_hdop", s.gps_hdop.map(f2));
        // A GLOBAL_POSITION_INT is the EKF's estimate, so the receiver's
        // uncertainty rides only on the GPS_RAW_INT that stated it.
        if p.msg_id == 24 {
            attr!("position_accuracy_h_m", s.gps_h_acc_m.map(f2));
            attr!("position_accuracy_v_m", s.gps_v_acc_m.map(f2));
            attr!("speed_accuracy", s.gps_vel_acc_mps.map(f2));
            attr!("angle_accuracy", s.gps_hdg_acc_deg.map(f2));
        }
        if let Some(cm) = s.custom_mode {
            b = b.metadata("custom_mode", cm.to_string());
        }
        b
    }

    pub fn to_event_at(&self, p: MavPosition, observed: &str) -> Result<Event, MavError> {
        Ok(self.base_builder(p).timestamp(observed).build()?)
    }
}

impl FrameParser for MavParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let Some(pos) = self.parse_frame(frame)? else {
            return Ok(Vec::new());
        };
        // MAVLink position messages carry a boot-relative clock, so stamp the
        // time of receipt.
        let event = self
            .base_builder(pos)
            .now()
            .build()
            .map_err(MavError::from)?;
        Ok(vec![event])
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
        vec![("connector_dropped_carryforward_total", self.dropped.clone())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GLOBAL_POSITION_INT, sysid 1: 47.397742 N 8.545594 E, 500.0 m, heading
    // 90.0, ground speed 10 m/s.
    const GPI: &str = "fe1c00010121e80300004c52401c44f4170520a1070000000000e8030000000028232c77";
    // HEARTBEAT, sysid 1: multirotor, armed, active. feed-synthetic pins the
    // same bytes, so the generator and this decoder cannot drift apart.
    const HEARTBEAT: &str = "fe0900010100000000000203800403be39";
    const OBSERVED: &str = "2026-06-10T08:00:00Z";

    fn parser() -> MavParser {
        MavParser::new("uav-flight-1", Enrichment::default())
    }

    fn governed() -> MavParser {
        MavParser::new(
            "uav-flight-1",
            Enrichment::default().with_hostility("Friend"),
        )
    }

    fn bytes(h: &str) -> Vec<u8> {
        hex::decode(h).unwrap()
    }

    /// A CRC-correct v1 frame (compid 1, seq 0) carrying `payload` verbatim.
    fn frame_from(sysid: u8, msgid: u32, payload: &[u8]) -> Vec<u8> {
        let (extra, _) = crc_extra_and_len(msgid).expect("known msgid");
        let mut f = vec![0xFE, payload.len() as u8, 0, sysid, 1, msgid as u8];
        f.extend_from_slice(payload);
        let c = crc(&f[1..], extra);
        f.extend_from_slice(&c.to_le_bytes());
        f
    }

    fn frame(msgid: u32, payload: &[u8]) -> Vec<u8> {
        frame_from(1, msgid, payload)
    }

    /// A GPS_RAW_INT payload of `len` bytes: 47.4 N 8.5 E, 500 m, 3D fix.
    fn gps_raw_payload(len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        put_i32(&mut p, 8, 474_000_000);
        put_i32(&mut p, 12, 85_000_000);
        put_i32(&mut p, 16, 500_000);
        p[28] = 3;
        p
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
        assert!((p.heading_deg.unwrap() - 90.0).abs() < 1e-6);
        assert!((p.sog_mps.unwrap() - 10.0).abs() < 0.01);
    }

    #[test]
    fn sysid_is_source_uid() {
        let pos = parser().parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = parser().to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(meta_of(&ev, "source_uid"), Some("1"));
        assert_eq!(meta_of(&ev, "mav_sysid"), Some("1"));
    }

    #[test]
    fn heartbeat_joins_next_position() {
        let p = governed();
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None);
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.vehicle_type, Some("multirotor"));
        assert_eq!(pos.state.status, Some("active"));
        assert_eq!(pos.state.armed, Some(true));
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "hostility"), Some("Friend"));
        assert_eq!(attr_of(&ev, "vehicle_type"), Some("multirotor"));
        assert_eq!(attr_of(&ev, "armed"), Some("true"));
    }

    #[test]
    fn attitude_maps_to_degrees() {
        let p = governed();
        let mut payload = vec![0u8; 28];
        put_f32(&mut payload, 4, 0.5);
        put_f32(&mut payload, 8, -0.25);
        put_f32(&mut payload, 12, std::f32::consts::FRAC_PI_2);
        assert_eq!(p.parse_frame(&frame(30, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert!((pos.state.roll_deg.unwrap() - 0.5_f64.to_degrees()).abs() < 1e-3);
        assert!((pos.state.pitch_deg.unwrap() - (-0.25_f64).to_degrees()).abs() < 1e-3);
        assert!((pos.state.yaw_deg.unwrap() - 90.0).abs() < 1e-3);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "yaw"), Some("90.0"));
    }

    #[test]
    fn sys_status_maps_battery_and_load() {
        let p = governed();
        let mut payload = vec![0u8; 31];
        put_u16(&mut payload, 12, 250);
        put_u16(&mut payload, 14, 12600);
        put_i16(&mut payload, 16, 1500);
        payload[30] = 77;
        assert_eq!(p.parse_frame(&frame(1, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.battery_remaining_pct, Some(77));
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "battery_voltage"), Some("12.60"));
        assert_eq!(attr_of(&ev, "battery_current"), Some("15.00"));
        assert_eq!(attr_of(&ev, "cpu_load"), Some("25"));
    }

    #[test]
    fn sys_status_unknown_sentinels_stay_absent() {
        let p = governed();
        let mut payload = vec![0u8; 31];
        put_u16(&mut payload, 14, u16::MAX);
        put_i16(&mut payload, 16, -1);
        payload[30] = (-1i8) as u8;
        assert_eq!(p.parse_frame(&frame(1, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.battery_voltage_v, None);
        assert_eq!(pos.state.battery_current_a, None);
        assert_eq!(pos.state.battery_remaining_pct, None);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "battery_voltage"), None);
    }

    #[test]
    fn vfr_hud_maps_airspeed_throttle_climb() {
        let p = governed();
        let mut payload = vec![0u8; 20];
        put_f32(&mut payload, 0, 20.0);
        put_f32(&mut payload, 12, 2.5);
        put_u16(&mut payload, 18, 55);
        assert_eq!(p.parse_frame(&frame(74, &payload)).unwrap(), None);

        let pos = p
            .parse_frame(&frame(24, &gps_raw_payload(30)))
            .unwrap()
            .unwrap();
        assert!((pos.state.airspeed_mps.unwrap() - 20.0).abs() < 0.1);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "throttle"), Some("55"));
        assert_eq!(
            attr_of(&ev, "vertical_rate"),
            Some("2.5"),
            "GPS_RAW_INT falls back to the VFR climb"
        );

        let gpi = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev2 = p.to_event_at(gpi, OBSERVED).unwrap();
        assert_eq!(
            attr_of(&ev2, "vertical_rate"),
            Some("0.0"),
            "GLOBAL_POSITION_INT's own level rate wins, without negative zero"
        );
    }

    #[test]
    fn battery_status_maps_consumed_and_temperature() {
        let p = governed();
        let mut payload = vec![0u8; 36];
        put_i32(&mut payload, 0, 1234);
        put_i16(&mut payload, 8, 2500);
        put_u16(&mut payload, 10, 12550);
        put_i16(&mut payload, 30, 1600);
        payload[35] = 66;
        assert_eq!(p.parse_frame(&frame(147, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.battery_consumed_mah, Some(1234));
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "battery_consumed"), Some("1234"));
        assert_eq!(attr_of(&ev, "battery_temp"), Some("25.0"));
        assert_eq!(attr_of(&ev, "battery_voltage"), Some("12.55"));
    }

    #[test]
    fn reference_heartbeat_decodes() {
        let p = governed();
        assert!(p.parse_frame(&bytes(HEARTBEAT)).unwrap().is_none());
        let mut payload = vec![0u8; 28];
        put_i32(&mut payload, 4, 507_950_000);
        put_i32(&mut payload, 8, -11_050_000);
        let pos = p.parse_frame(&frame(33, &payload)).unwrap().unwrap();
        assert_eq!(pos.state.vehicle_type, Some("multirotor"));
        assert_eq!(pos.state.armed, Some(true));
        assert_eq!(pos.state.status, Some("active"));
    }

    #[test]
    fn mavlink2_accuracy_becomes_contract_uncertainty() {
        let p = governed();
        let mut payload = gps_raw_payload(50);
        put_u16(&mut payload, 20, 120);
        payload[29] = 12;
        put_u32(&mut payload, 34, 2500);
        put_u32(&mut payload, 38, 4000);
        put_u32(&mut payload, 42, 300);
        put_u32(&mut payload, 46, 150_000);
        let pos = p.parse_frame(&frame(24, &payload)).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "position_accuracy_h_m"), Some("2.50"));
        assert_eq!(attr_of(&ev, "position_accuracy_v_m"), Some("4.00"));
        assert_eq!(attr_of(&ev, "speed_accuracy"), Some("0.30"));
        assert_eq!(attr_of(&ev, "angle_accuracy"), Some("1.50"));

        let mut zeros = payload.clone();
        put_u32(&mut zeros, 34, 0);
        let pos = p.parse_frame(&frame(24, &zeros)).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(
            attr_of(&ev, "position_accuracy_h_m"),
            None,
            "zero is not known"
        );
        assert_eq!(attr_of(&ev, "position_accuracy_v_m"), Some("4.00"));

        let mut bad = payload.clone();
        put_u32(&mut bad, 46, 40_000_000);
        put_u32(&mut bad, 38, u32::MAX);
        let pos = p.parse_frame(&frame(24, &bad)).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(
            attr_of(&ev, "angle_accuracy"),
            None,
            "400 deg is out of range"
        );
        assert_eq!(
            attr_of(&ev, "position_accuracy_v_m"),
            None,
            "all ones is not known"
        );

        let mut gpi = vec![0u8; 28];
        put_i32(&mut gpi, 4, 474_000_000);
        put_i32(&mut gpi, 8, 85_000_000);
        let pos = p.parse_frame(&frame(33, &gpi)).unwrap().unwrap();
        assert_eq!(pos.msg_id, 33);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(
            attr_of(&ev, "position_accuracy_h_m"),
            None,
            "the EKF position carries none of the receiver's uncertainty"
        );
        assert_eq!(attr_of(&ev, "speed_accuracy"), None);
    }

    #[test]
    fn gps_raw_maps_fix_quality_and_caches_it() {
        let p = governed();
        let mut payload = gps_raw_payload(30);
        put_u16(&mut payload, 20, 120);
        put_u16(&mut payload, 24, 1000);
        put_u16(&mut payload, 26, 4500);
        payload[29] = 12;

        let pos = p.parse_frame(&frame(24, &payload)).unwrap().unwrap();
        assert_eq!(pos.msg_id, 24);
        assert_eq!(pos.state.gps_fix, Some("3d"));
        assert_eq!(pos.state.gps_sats, Some(12));
        assert!((pos.state.gps_hdop.unwrap() - 1.2).abs() < 1e-9);
        assert!((pos.course_deg.unwrap() - 45.0).abs() < 1e-6);
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "gps_fix"), Some("3d"));
        assert_eq!(attr_of(&ev, "gps_satellites"), Some("12"));
        assert_eq!(attr_of(&ev, "alt_id"), Some("1"));
        assert_eq!(attr_of(&ev, "alt_id_standard"), Some("MAVLink"));
        assert_eq!(
            attr_of(&ev, "position_accuracy_h_m"),
            None,
            "a MAVLink 1 payload states no accuracy"
        );

        let gpi = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(gpi.state.gps_fix, Some("3d"), "fix quality is cached");
    }

    #[test]
    fn heartbeat_maps_flight_mode() {
        let p = governed();
        let mut payload = vec![0u8; 9];
        put_u32(&mut payload, 0, 4);
        payload[4] = 1;
        // custom mode enabled, auto, armed
        payload[6] = 0x01 | 0x04 | 0x80;
        payload[7] = 4;
        assert_eq!(p.parse_frame(&frame(0, &payload)).unwrap(), None);

        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos.state.mode, Some("auto"));
        assert_eq!(pos.state.custom_mode, Some(4));
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "mode"), Some("auto"));
        assert_eq!(meta_of(&ev, "custom_mode"), Some("4"));
    }

    #[test]
    fn vehicle_state_stays_per_sysid() {
        let p = governed();
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None);
        let mut fixed_wing = vec![0u8; 9];
        fixed_wing[4] = 1;
        fixed_wing[7] = 4;
        assert_eq!(p.parse_frame(&frame_from(7, 0, &fixed_wing)).unwrap(), None);

        let pos1 = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        assert_eq!(pos1.sysid, 1);
        assert_eq!(pos1.state.vehicle_type, Some("multirotor"));
    }

    #[test]
    fn hostility_absent_without_config() {
        let p = parser();
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(attr_of(&ev, "hostility"), None);
        assert_eq!(meta_of(&ev, "hostility"), None);
    }

    #[test]
    fn raw_frame_sealed_in_payload() {
        let p = parser();
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(ev.payload, bytes(GPI));
    }

    #[test]
    fn cache_only_frames_ride_into_payload() {
        let p = governed();
        assert_eq!(p.parse_frame(&bytes(HEARTBEAT)).unwrap(), None);
        let pos = p.parse_frame(&bytes(GPI)).unwrap().unwrap();
        let ev = p.to_event_at(pos, OBSERVED).unwrap();
        assert_eq!(ev.payload, [bytes(HEARTBEAT), bytes(GPI)].concat());
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
    fn unmapped_message_is_ignored() {
        // PARAM_VALUE (22) with an empty body.
        let param = bytes("fe00000101160000");
        assert_eq!(parser().parse_frame(&param).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics() {
        assert_eq!(
            parser().parse_frame(b"\x00\x01\x02\x03"),
            Err(MavError::NotMavlink)
        );
        assert_eq!(parser().parse_frame(&[0xFEu8]), Err(MavError::Truncated));
        assert_eq!(parser().parse_frame(&[]), Err(MavError::Truncated));
    }
}
