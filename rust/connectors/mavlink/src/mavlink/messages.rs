// SPDX-License-Identifier: Apache-2.0
//! Per-message payload decoders for the common dialect, CRC_EXTRA table and
//! the MAVLink CRC. Offsets follow the wire order: fields by decreasing size.

use super::VehicleState;

/// CRC_EXTRA and full (untruncated) payload length.
pub(super) fn crc_extra_and_len(msg_id: u32) -> Option<(u8, usize)> {
    match msg_id {
        0 => Some((50, 9)),     // HEARTBEAT
        1 => Some((124, 31)),   // SYS_STATUS
        24 => Some((24, 52)),   // GPS_RAW_INT, with the MAVLink 2 extensions
        30 => Some((39, 28)),   // ATTITUDE
        33 => Some((104, 28)),  // GLOBAL_POSITION_INT
        74 => Some((20, 20)),   // VFR_HUD
        147 => Some((154, 36)), // BATTERY_STATUS
        _ => None,
    }
}

/// CRC-16/MCRF4XX over `data`, finished with the message's CRC_EXTRA.
pub(super) fn crc(data: &[u8], extra: u8) -> u16 {
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

/// HEARTBEAT (0).
pub(super) fn heartbeat(s: &mut VehicleState, p: &[u8]) {
    let base_mode = p[6];
    s.vehicle_type = vehicle_type(p[4]);
    s.status = mav_state(p[7]);
    // MAV_MODE_FLAG_SAFETY_ARMED
    s.armed = Some(base_mode & 0x80 != 0);
    s.mode = base_flag_mode(base_mode);
    // MAV_MODE_FLAG_CUSTOM_MODE_ENABLED
    s.custom_mode = (base_mode & 0x01 != 0).then(|| u32le(p, 0));
}

/// SYS_STATUS (1). 0xFFFF and -1 mean unknown.
pub(super) fn sys_status(s: &mut VehicleState, p: &[u8]) {
    let load = u16le(p, 12);
    let voltage_mv = u16le(p, 14);
    let current_ca = i16le(p, 16);
    let remaining = p[30] as i8;
    if load != u16::MAX {
        s.cpu_load_pct = Some(load as f64 / 10.0);
    }
    if voltage_mv != u16::MAX {
        s.battery_voltage_v = Some(voltage_mv as f64 / 1000.0);
    }
    if current_ca != -1 {
        s.battery_current_a = Some(current_ca as f64 / 100.0);
    }
    if remaining != -1 {
        s.battery_remaining_pct = Some(remaining);
    }
}

/// ATTITUDE (30), radians on the wire.
pub(super) fn attitude(s: &mut VehicleState, p: &[u8]) {
    s.roll_deg = Some((f32le(p, 4) as f64).to_degrees());
    s.pitch_deg = Some((f32le(p, 8) as f64).to_degrees());
    s.yaw_deg = Some((f32le(p, 12) as f64).to_degrees().rem_euclid(360.0));
}

/// VFR_HUD (74).
pub(super) fn vfr_hud(s: &mut VehicleState, p: &[u8]) {
    s.airspeed_mps = Some(f32le(p, 0) as f64);
    s.climb_mps = Some(f32le(p, 12) as f64);
    s.throttle_pct = Some(u16le(p, 18));
}

/// BATTERY_STATUS (147). Overrides the SYS_STATUS battery figures when both
/// are sent.
pub(super) fn battery_status(s: &mut VehicleState, p: &[u8]) {
    let consumed_mah = i32le(p, 0);
    let temp_cdeg = i16le(p, 8);
    let cell0_mv = u16le(p, 10);
    let current_ca = i16le(p, 30);
    let remaining = p[35] as i8;
    if consumed_mah != -1 {
        s.battery_consumed_mah = Some(consumed_mah);
    }
    if temp_cdeg != i16::MAX {
        s.battery_temp_c = Some(temp_cdeg as f64 / 100.0);
    }
    if cell0_mv != u16::MAX {
        s.battery_voltage_v = Some(cell0_mv as f64 / 1000.0);
    }
    if current_ca != -1 {
        s.battery_current_a = Some(current_ca as f64 / 100.0);
    }
    if remaining != -1 {
        s.battery_remaining_pct = Some(remaining);
    }
}

/// MAV_TYPE subset to category.
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

/// MAV_STATE.
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

/// Coarse flight mode from the MAV_MODE_FLAG bits, most specific first.
fn base_flag_mode(base_mode: u8) -> Option<&'static str> {
    const MODES: [(u8, &str); 4] = [
        (0x04, "auto"),      // MAV_MODE_FLAG_AUTO_ENABLED
        (0x08, "guided"),    // MAV_MODE_FLAG_GUIDED_ENABLED
        (0x10, "stabilize"), // MAV_MODE_FLAG_STABILIZE_ENABLED
        (0x40, "manual"),    // MAV_MODE_FLAG_MANUAL_INPUT_ENABLED
    ];
    MODES
        .iter()
        .find(|(flag, _)| base_mode & flag != 0)
        .map(|&(_, mode)| mode)
}

/// GPS_FIX_TYPE.
pub(super) fn gps_fix(t: u8) -> Option<&'static str> {
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

pub(super) fn i32le(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub(super) fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn f32le(b: &[u8], off: usize) -> f32 {
    f32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

pub(super) fn i16le(b: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([b[off], b[off + 1]])
}

pub(super) fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
