// SPDX-License-Identifier: Apache-2.0
//! MAVLink: the uncrewed aircraft's telemetry as v1 frames, what the `mavlink`
//! connector reads.
//!
//! MAVLink is what autopilots and ground stations speak, and the connector
//! verifies the frame CRC before trusting a single field. Correctly: a corrupt
//! frame that parsed anyway would put a drone somewhere it is not. So this
//! builds real frames, CRC-16/MCRF4XX over everything after the magic byte
//! finished with the message's CRC_EXTRA. Get that wrong and nothing arrives,
//! which is the right failure, and why [`self_check`] runs before a single
//! packet leaves.
//!
//! Three messages, because that is what the connector maps and what a real
//! link carries: HEARTBEAT says the vehicle exists and what state it is in,
//! GLOBAL_POSITION_INT carries the fused position and heading, GPS_RAW_INT
//! carries the raw fix with its uncertainty. That last one is why this is the
//! only source here reporting every accuracy attribute: an autopilot knows its
//! own GPS error, and most sensors do not.
//!
//! v1 framing (magic 0xFE) rather than v2, because it is the simpler of the two
//! the connector accepts and nothing here needs v2's extensions or signing.

use crate::scenario::{Uav, UavState};

const HEARTBEAT: u8 = 0;
const GLOBAL_POSITION_INT: u8 = 33;
const GPS_RAW_INT: u8 = 24;

/// CRC_EXTRA and payload length per message, matching the connector's own table.
fn spec(msg_id: u8) -> (u8, usize) {
    match msg_id {
        HEARTBEAT => (50, 9),
        GLOBAL_POSITION_INT => (104, 28),
        GPS_RAW_INT => (24, 52),
        _ => unreachable!("only the three messages above are generated"),
    }
}

/// MAVLink's CRC-16/MCRF4XX, finished with the message CRC_EXTRA.
fn crc(data: &[u8], extra: u8) -> u16 {
    let mut c: u16 = 0xFFFF;
    for &b in data.iter().chain(std::iter::once(&extra)) {
        let mut tmp = b ^ (c & 0xFF) as u8;
        tmp ^= tmp << 4;
        c = (c >> 8) ^ ((tmp as u16) << 8) ^ ((tmp as u16) << 3) ^ ((tmp as u16) >> 4);
    }
    c
}

/// A frame builder holding the per-link sequence counter.
pub struct Link {
    seq: u8,
}

impl Link {
    pub fn new() -> Self {
        Link { seq: 0 }
    }

    /// One v1 frame: magic, length, sequence, system id, component id,
    /// message id, payload padded to the message's full length, CRC.
    fn frame(&mut self, msg_id: u8, payload: &[u8]) -> Vec<u8> {
        let (extra, len) = spec(msg_id);
        let mut body = vec![len as u8, self.seq, Uav::SYSID, 1, msg_id];
        self.seq = self.seq.wrapping_add(1);
        let mut p = payload.to_vec();
        p.resize(len, 0);
        body.extend_from_slice(&p);
        let c = crc(&body, extra);
        let mut out = vec![0xFE];
        out.extend_from_slice(&body);
        out.extend_from_slice(&c.to_le_bytes());
        out
    }

    /// HEARTBEAT: an armed multirotor on ArduPilot, actively flying.
    pub fn heartbeat(&mut self) -> Vec<u8> {
        let mut p = Vec::with_capacity(9);
        p.extend_from_slice(&0u32.to_le_bytes()); // custom_mode
        p.push(2); // type: MAV_TYPE_QUADROTOR, which the connector reports as multirotor
        p.push(3); // autopilot: ArduPilot
        p.push(0x80); // base_mode: armed
        p.push(4); // system_status: active
        p.push(3); // mavlink_version
        self.frame(HEARTBEAT, &p)
    }

    /// GLOBAL_POSITION_INT: the fused position and heading. Velocity is split
    /// into north and east components from the heading, as an autopilot reports
    /// it, rather than a scalar the connector would have to invent a direction for.
    pub fn global_position_int(&mut self, u: &UavState, boot_ms: u32) -> Vec<u8> {
        let (s, c) = u.heading_deg.to_radians().sin_cos();
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&boot_ms.to_le_bytes());
        p.extend_from_slice(&((u.fix.lat * 1e7) as i32).to_le_bytes());
        p.extend_from_slice(&((u.fix.lon * 1e7) as i32).to_le_bytes());
        p.extend_from_slice(&((u.alt_m * 1000.0) as i32).to_le_bytes()); // alt, mm
        p.extend_from_slice(&((u.alt_m * 1000.0) as i32).to_le_bytes()); // relative_alt
        p.extend_from_slice(&((u.speed_mps * c * 100.0) as i16).to_le_bytes()); // vx, cm/s
        p.extend_from_slice(&((u.speed_mps * s * 100.0) as i16).to_le_bytes()); // vy
        p.extend_from_slice(&0i16.to_le_bytes()); // vz
        p.extend_from_slice(&((u.heading_deg * 100.0) as u16).to_le_bytes()); // hdg, cdeg
        self.frame(GLOBAL_POSITION_INT, &p)
    }

    /// GPS_RAW_INT: the raw fix, then the v2 extension block carrying the
    /// accuracies in millimetres and the heading accuracy in 1e-5 degrees. The
    /// connector reads those extensions, which is where the accuracy attributes
    /// come from.
    pub fn gps_raw_int(&mut self, u: &UavState, boot_us: u64) -> Vec<u8> {
        let mut p = Vec::with_capacity(52);
        p.extend_from_slice(&boot_us.to_le_bytes());
        p.extend_from_slice(&((u.fix.lat * 1e7) as i32).to_le_bytes());
        p.extend_from_slice(&((u.fix.lon * 1e7) as i32).to_le_bytes());
        p.extend_from_slice(&((u.alt_m * 1000.0) as i32).to_le_bytes());
        p.extend_from_slice(&120u16.to_le_bytes()); // eph: HDOP x100
        p.extend_from_slice(&150u16.to_le_bytes()); // epv
        p.extend_from_slice(&((u.speed_mps * 100.0) as u16).to_le_bytes()); // vel, cm/s
        p.extend_from_slice(&((u.heading_deg * 100.0) as u16).to_le_bytes()); // cog, cdeg
        p.push(3); // fix_type: 3D
        p.push(14); // satellites_visible
        p.extend_from_slice(&0i32.to_le_bytes()); // alt_ellipsoid
        p.extend_from_slice(&((Uav::H_ACC_M * 1000.0) as u32).to_le_bytes());
        p.extend_from_slice(&((Uav::V_ACC_M * 1000.0) as u32).to_le_bytes());
        p.extend_from_slice(&((Uav::VEL_ACC_MPS * 1000.0) as u32).to_le_bytes());
        p.extend_from_slice(&((Uav::HDG_ACC_DEG * 1e5) as u32).to_le_bytes());
        self.frame(GPS_RAW_INT, &p)
    }
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

/// The connector's ground-truth HEARTBEAT, byte for byte. A silent CRC bug in
/// the encoder would look exactly like a dead link, so the encoder proves
/// itself against this before the feed starts.
pub const REFERENCE_HEARTBEAT: &str = "fe0900010100000000000203800403be39";

/// Verify the encoder against the reference frame. Panics on drift, which is
/// the right failure for a generator that would otherwise emit frames the
/// connector silently refuses.
pub fn self_check() {
    let got: String = Link::new()
        .heartbeat()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        got, REFERENCE_HEARTBEAT,
        "HEARTBEAT encoding drifted from the connector's reference frame"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ajar_connector_common::Enrichment;
    use ajar_mavlink::MavParser;

    #[test]
    fn the_heartbeat_matches_the_reference_frame_byte_for_byte() {
        self_check();
    }

    #[test]
    fn the_three_frames_decode_to_the_uav_with_every_accuracy() {
        let d = MavParser::new("uav-1", Enrichment::default().with_hostility("Friend"));
        let mut link = Link::new();
        let u = Uav::at(45.0);
        assert!(d.parse_frame(&link.heartbeat()).unwrap().is_none());
        let pos = d
            .parse_frame(&link.global_position_int(&u, 45_000))
            .unwrap()
            .expect("a position message yields a track");
        assert!((pos.lat - u.fix.lat).abs() < 2e-7);
        assert!((pos.lon - u.fix.lon).abs() < 2e-7);
        assert_eq!(pos.state.vehicle_type, Some("multirotor"));
        assert_eq!(pos.state.armed, Some(true));
        // The fused message is where the heading lives.
        let fused = d.to_event_at(&pos, "2026-06-10T08:00:00Z").unwrap();
        let hdg: f64 = fused
            .attributes
            .iter()
            .find(|a| a.key == "heading")
            .map(|a| a.value.parse().unwrap())
            .expect("GLOBAL_POSITION_INT carries the heading");
        assert!(
            (hdg - u.heading_deg).abs() < 0.02,
            "{hdg} vs {}",
            u.heading_deg
        );
        let raw = d
            .parse_frame(&link.gps_raw_int(&u, 45_000_000))
            .unwrap()
            .expect("a raw fix yields a track");
        let ev = d.to_event_at(&raw, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.parse::<f64>().unwrap())
        };
        assert!((attr("position_accuracy_h_m").unwrap() - Uav::H_ACC_M).abs() < 1e-3);
        assert!((attr("position_accuracy_v_m").unwrap() - Uav::V_ACC_M).abs() < 1e-3);
        assert!((attr("speed_accuracy").unwrap() - Uav::VEL_ACC_MPS).abs() < 1e-3);
        assert!((attr("angle_accuracy").unwrap() - Uav::HDG_ACC_DEG).abs() < 1e-3);
        // A raw fix carries course over ground, not the fused heading.
        assert!(attr("heading").is_none());
        let id = ev
            .attributes
            .iter()
            .find(|a| a.key == "alt_id")
            .map(|a| a.value.as_str());
        assert_eq!(id, Some("1"));
    }

    #[test]
    fn a_flipped_bit_fails_the_crc_and_the_frame_is_refused() {
        let d = MavParser::new("uav-1", Enrichment::default());
        let mut f = Link::new().global_position_int(&Uav::at(0.0), 1);
        f[10] ^= 0x01;
        assert!(d.parse_frame(&f).is_err());
    }
}
