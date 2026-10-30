// SPDX-License-Identifier: Apache-2.0
//! MAVLink: the uncrewed aircraft's telemetry as v1 frames, read by the
//! `mavlink` connector: HEARTBEAT, GLOBAL_POSITION_INT and GPS_RAW_INT. The CRC
//! and frame layout are written independently of the connector's decoder, so
//! the round-trip tests are not circular.

use crate::scenario::{Uav, UavState};

const HEARTBEAT: u8 = 0;
const GLOBAL_POSITION_INT: u8 = 33;
const GPS_RAW_INT: u8 = 24;

fn crc_extra_and_len(msg_id: u8) -> (u8, usize) {
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
#[derive(Default)]
pub struct Link {
    seq: u8,
}

impl Link {
    /// One v1 frame: magic, length, sequence, system id, component id,
    /// message id, payload padded to the message's full length, CRC.
    fn frame(&mut self, msg_id: u8, payload: &[u8]) -> Vec<u8> {
        let (extra, len) = crc_extra_and_len(msg_id);
        let mut out = Vec::with_capacity(6 + len + 2);
        // Magic 0xFE is v1: nothing here needs v2's extensions or signing.
        out.extend_from_slice(&[0xFE, len as u8, self.seq, Uav::SYSID, 1, msg_id]);
        self.seq = self.seq.wrapping_add(1);
        out.extend_from_slice(payload);
        out.resize(6 + len, 0);
        let c = crc(&out[1..], extra);
        out.extend_from_slice(&c.to_le_bytes());
        out
    }

    /// HEARTBEAT: an armed multirotor on ArduPilot, actively flying.
    pub fn heartbeat(&mut self) -> Vec<u8> {
        let mut p = Vec::with_capacity(9);
        p.extend_from_slice(&0u32.to_le_bytes()); // custom_mode
        p.push(2); // type: MAV_TYPE_QUADROTOR
        p.push(3); // autopilot: ArduPilot
        p.push(0x80); // base_mode: armed
        p.push(4); // system_status: active
        p.push(3); // mavlink_version
        self.frame(HEARTBEAT, &p)
    }

    /// GLOBAL_POSITION_INT: the fused position, north and east velocity, and
    /// heading.
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
    /// accuracies in millimetres and the heading accuracy in 1e-5 degrees.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{attr, num, EVENT_TIME};
    use ajar_connector_common::Enrichment;
    use ajar_mavlink::MavParser;

    #[test]
    fn heartbeat_matches_reference_frame() {
        // Produced outside this encoder and the decoder, so a CRC_EXTRA wrong in both fails.
        let hex: String = Link::default()
            .heartbeat()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex, "fe0900010100000000000203800403be39",
            "HEARTBEAT encoding drifted from the connector's reference frame"
        );
    }

    #[test]
    fn three_frames_decode_with_every_accuracy() {
        let d = MavParser::new("uav-1", Enrichment::default().with_hostility("Friend"));
        let mut link = Link::default();
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
        let fused = d.to_event_at(pos, EVENT_TIME).unwrap();
        let hdg = num(&fused, "heading");
        assert!(
            (hdg - u.heading_deg).abs() < 0.02,
            "{hdg} vs {}",
            u.heading_deg
        );
        let raw = d
            .parse_frame(&link.gps_raw_int(&u, 45_000_000))
            .unwrap()
            .expect("a raw fix yields a track");
        let ev = d.to_event_at(raw, EVENT_TIME).unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert!((num(&ev, "position_accuracy_h_m") - Uav::H_ACC_M).abs() < 1e-3);
        assert!((num(&ev, "position_accuracy_v_m") - Uav::V_ACC_M).abs() < 1e-3);
        assert!((num(&ev, "speed_accuracy") - Uav::VEL_ACC_MPS).abs() < 1e-3);
        assert!((num(&ev, "angle_accuracy") - Uav::HDG_ACC_DEG).abs() < 1e-3);
        assert!(
            attr(&ev, "heading").is_none(),
            "a raw fix carries course over ground, not heading"
        );
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("1"));
    }

    #[test]
    fn flipped_bit_fails_crc() {
        let d = MavParser::new("uav-1", Enrichment::default());
        let mut f = Link::default().global_position_int(&Uav::at(0.0), 1);
        f[10] ^= 0x01;
        assert!(d.parse_frame(&f).is_err());
    }
}
