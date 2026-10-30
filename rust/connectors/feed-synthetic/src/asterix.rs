// SPDX-License-Identifier: Apache-2.0
//! Radar: ASTERIX on the surveillance multicast group, read by the `asterix`
//! connector. A CAT062 system track for the airliner, a CAT010 surface plot
//! for the vessel with no identity, and a CAT034 north marker, which shares a
//! datagram with the plot as from a real radar head. The CAT010 record has no
//! time of day.

use std::time::SystemTime;

use crate::scenario::{
    bearing_range, seconds_since_midnight, Aircraft, AircraftState, VesselState, FT_PER_M, RADAR,
    RADAR_ALT_M, RADAR_SAC, RADAR_SCAN_PERIOD_S, RADAR_SIC, RADAR_WINDOW,
};

const LSB_105: f64 = 180.0 / (1u64 << 25) as f64;
const LSB_120: f64 = 180.0 / (1u64 << 23) as f64;
const ANGLE_16: f64 = 360.0 / 65_536.0;
/// CAT034 message type 1: north marker.
const NORTH_MARKER: u8 = 1;

/// The field specification: which data items follow, in UAP order, with the
/// extension bit on every octet but the last.
fn fspec(frns: &[u8]) -> Vec<u8> {
    let max = *frns.iter().max().expect("at least one item") as usize;
    let octets = max.div_ceil(7);
    let mut f = vec![0u8; octets];
    for &n in frns {
        let i = (n as usize - 1) / 7;
        f[i] |= 0x80 >> ((n as usize - 1) % 7);
    }
    for o in f.iter_mut().take(octets - 1) {
        *o |= 0x01;
    }
    f
}

/// One ASTERIX block: category, total length including the header, record.
fn block(cat: u8, record: &[u8]) -> Vec<u8> {
    let len = (3 + record.len()) as u16;
    let mut out = Vec::with_capacity(3 + record.len());
    out.push(cat);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(record);
    out
}

/// Time of day, three bytes, in 1/128 s since midnight UTC.
fn tod(t: SystemTime) -> [u8; 3] {
    let ticks = (seconds_since_midnight(t) * 128.0) as u32 & 0xFF_FFFF;
    [(ticks >> 16) as u8, (ticks >> 8) as u8, ticks as u8]
}

/// Callsign in the ICAO six-bit character set, eight characters into six bytes.
fn aircraft_id(s: &str) -> [u8; 6] {
    let mut v: u64 = 0;
    for k in 0..8 {
        let c = s.as_bytes().get(k).copied().unwrap_or(b' ');
        let six: u64 = match c {
            b'A'..=b'Z' => (c - b'A' + 1) as u64,
            b'0'..=b'9' => (c - b'0' + 48) as u64,
            _ => 32,
        };
        v |= six << (42 - 6 * k);
    }
    v.to_be_bytes()[2..8].try_into().expect("six bytes")
}

/// Three big-endian bytes of a signed value.
fn i24(v: i64) -> [u8; 3] {
    let u = (v as u32) & 0xFF_FFFF;
    [(u >> 16) as u8, (u >> 8) as u8, u as u8]
}

/// CAT062: a system track for the aircraft, with identity.
pub fn cat062_track(a: &AircraftState, observed: SystemTime) -> Vec<u8> {
    let mut r = fspec(&[1, 4, 5, 7, 9, 11, 12, 17, 20]);
    r.extend_from_slice(&[RADAR_SAC, RADAR_SIC]); // 010
    r.extend_from_slice(&tod(observed)); // 070 time of track information
    r.extend_from_slice(&((a.fix.lat / LSB_105) as i32).to_be_bytes()); // 105
    r.extend_from_slice(&((a.fix.lon / LSB_105) as i32).to_be_bytes());
    // 185 velocity, quarter-metres per second, x east then y north.
    let (s, c) = a.course_deg.to_radians().sin_cos();
    r.extend_from_slice(&((a.speed_mps * s * 4.0) as i16).to_be_bytes());
    r.extend_from_slice(&((a.speed_mps * c * 4.0) as i16).to_be_bytes());
    r.extend_from_slice(&0o1234u16.to_be_bytes()); // 060 Mode 3/A, octal
    r.push(0xC0); // 380 primary subfield: ADR and ID present
    r.extend_from_slice(&Aircraft::ICAO24); // 380 ADR
    r.extend_from_slice(&aircraft_id(Aircraft::CALLSIGN)); // 380 ID
    r.extend_from_slice(&Aircraft::TRACK_NUMBER.to_be_bytes()); // 040
    r.extend_from_slice(&((a.alt_m * FT_PER_M / 25.0) as i16).to_be_bytes()); // 136, 1/4 FL
    r.extend_from_slice(&((a.vertical_rate_mps * FT_PER_M * 60.0 / 6.25) as i16).to_be_bytes()); // 220
    block(62, &r)
}

/// CAT010: a surface plot for the vessel in polar coordinates from the radar
/// head, which the connector geolocates against its `[sensor]` block.
pub fn cat010_plot(v: &VesselState) -> Vec<u8> {
    let (bearing, range_m) = bearing_range(RADAR, v.fix);
    let mut r = fspec(&[1, 2, 6]);
    r.extend_from_slice(&[RADAR_SAC, RADAR_SIC]); // 010
    r.push(1); // 000 message type: target report
    r.extend_from_slice(&(range_m.round() as u16).to_be_bytes()); // 040 rho, m
    r.extend_from_slice(&((bearing / ANGLE_16).round() as u16).to_be_bytes()); // 040 theta
    block(10, &r)
}

/// CAT034: the radar's north marker, with rotation period, polar window and
/// site position.
pub fn cat034_heartbeat(observed: SystemTime) -> Vec<u8> {
    let mut r = fspec(&[1, 2, 3, 5, 9, 11]);
    r.extend_from_slice(&[RADAR_SAC, RADAR_SIC]); // 010
    r.push(NORTH_MARKER); // 000
    r.extend_from_slice(&tod(observed)); // 030
    r.extend_from_slice(&((RADAR_SCAN_PERIOD_S * 128.0) as u16).to_be_bytes()); // 041, 1/128 s
                                                                                // 100 generic polar window: range in 1/256 NM, azimuth in 360/65536 deg.
    let (r0, r1, a0, a1) = RADAR_WINDOW;
    r.extend_from_slice(&((r0 * 256.0) as u16).to_be_bytes());
    r.extend_from_slice(&((r1 * 256.0) as u16).to_be_bytes());
    r.extend_from_slice(&((a0 / ANGLE_16) as u16).to_be_bytes());
    r.extend_from_slice(&((a1 / ANGLE_16) as u16).to_be_bytes());
    // 120 3D position of the data source: height (m), latitude, longitude.
    r.extend_from_slice(&(RADAR_ALT_M as i16).to_be_bytes());
    r.extend_from_slice(&i24((RADAR.lat / LSB_120) as i64));
    r.extend_from_slice(&i24((RADAR.lon / LSB_120) as i64));
    block(34, &r)
}

/// One rotation: the service block leading the surface plot, then the system
/// track.
pub fn rotation(v: &VesselState, a: &AircraftState, observed: SystemTime) -> [Vec<u8>; 2] {
    let mut first = cat034_heartbeat(observed);
    first.extend_from_slice(&cat010_plot(v));
    [first, cat062_track(a, observed)]
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::fixtures::{attr, num, observed, EVENT_TIME};
    use crate::scenario::{Fix, Vessel};
    use ajar_asterix::{AsterixParser, Sensor};
    use ajar_connector_common::Enrichment;

    fn decoder() -> AsterixParser {
        let mut map = HashMap::new();
        map.insert("cat010_domain".to_string(), "SURFACE".to_string());
        AsterixParser::new("radar-1", Enrichment::default().with_hostility("Unknown"))
            .with_sensor(Some(Sensor {
                lat: RADAR.lat,
                lon: RADAR.lon,
                alt_m: RADAR_ALT_M,
            }))
            .with_entity_map(&map)
            .expect("SURFACE is in the ontology's vocabulary")
    }

    #[test]
    fn system_track_decodes_to_airliner() {
        let a = Aircraft::at(20.0);
        let d = decoder();
        let mut targets = d
            .parse_block(&cat062_track(&a, observed()))
            .expect("valid block");
        assert_eq!(targets.len(), 1);
        let t = targets.remove(0);
        assert_eq!(t.icao, Some(0x4CA2D6));
        assert_eq!(t.callsign.as_deref(), Some("BAW117"));
        assert_eq!(t.track, Some(4095));
        assert_eq!(t.squawk.as_deref(), Some("1234"));
        assert!(
            (t.time_of_day_s.unwrap() - 73_600.0).abs() < 0.01,
            "20:26:40 UTC as time of day"
        );
        let ev = d.to_event_at(t, EVENT_TIME).unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        let loc = ev.location.as_ref().unwrap();
        assert!((loc.latitude - a.fix.lat).abs() < 1e-5);
        assert!((loc.longitude - a.fix.lon).abs() < 1e-5);
        assert!(
            (loc.altitude_m - Aircraft::ALT_M).abs() < 8.0,
            "{}",
            loc.altitude_m
        );
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("4CA2D6"));
        assert_eq!(attr(&ev, "alt_id_standard").as_deref(), Some("ICAO24"));
        let speed = num(&ev, "speed");
        assert!((speed - Aircraft::SPEED_MPS).abs() < 0.3, "{speed}");
        let course = num(&ev, "course");
        assert!((course - Aircraft::COURSE_DEG).abs() < 0.2, "{course}");
        let vr = num(&ev, "vertical_rate");
        assert!((vr - Aircraft::VERTICAL_RATE_MPS).abs() < 0.06, "{vr}");
    }

    #[test]
    fn surface_plot_geolocates_onto_vessel() {
        let v = Vessel::at(20.0);
        let d = decoder();
        let mut targets = d.parse_block(&cat010_plot(&v)).unwrap();
        let ev = d.to_event_at(targets.remove(0), EVENT_TIME).unwrap();
        assert_eq!(
            ev.entity_type, "mim:object",
            "a plot is not an identification"
        );
        assert_eq!(attr(&ev, "environment").as_deref(), Some("SURFACE"));
        assert!(attr(&ev, "callsign").is_none());
        assert!(attr(&ev, "alt_id").is_none());
        let loc = ev.location.unwrap();
        let (_, err_m) = bearing_range(
            v.fix,
            Fix {
                lat: loc.latitude,
                lon: loc.longitude,
            },
        );
        assert!(err_m < 5.0, "plot is {err_m:.1} m off the vessel");
    }

    #[test]
    fn north_marker_becomes_sensor_event() {
        let d = decoder();
        let mut reports = d
            .parse_service_block(&cat034_heartbeat(observed()))
            .unwrap();
        assert_eq!(reports.len(), 1);
        let r = reports.remove(0);
        assert_eq!((r.sac, r.sic), (RADAR_SAC, RADAR_SIC));
        assert_eq!(r.message_type, NORTH_MARKER);
        assert!((r.rotation_period_s.unwrap() - RADAR_SCAN_PERIOD_S).abs() < 0.01);
        let (lat, lon, alt) = r.position.unwrap();
        assert!((lat - RADAR.lat).abs() < 1e-4);
        assert!((lon - RADAR.lon).abs() < 1e-4);
        assert!((alt - RADAR_ALT_M).abs() < 0.5);
        let ev = d.service_event_at(r, EVENT_TIME).unwrap();
        assert_eq!(ev.entity_type, "mim:sensor");
        assert_eq!(attr(&ev, "scan_period_s").as_deref(), Some("2.500"));
        assert_eq!(attr(&ev, "update_interval_s").as_deref(), Some("2.500"));
        let (_, r1, a0, a1) = RADAR_WINDOW;
        assert!((num(&ev, "coverage_bearing_start_deg") - a0).abs() < 0.01);
        assert!((num(&ev, "coverage_bearing_end_deg") - a1).abs() < 0.01);
        assert!((num(&ev, "detection_range_m") - r1 * 1852.0).abs() < 1.0);
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("25:10"));
        assert_eq!(attr(&ev, "alt_id_standard").as_deref(), Some("ASTERIX"));
    }

    #[test]
    fn service_block_does_not_hide_plot() {
        let [first, second] = rotation(&Vessel::at(0.0), &Aircraft::at(0.0), observed());
        let d = decoder();
        let (targets, reports) = d.parse_datagram(&first).unwrap();
        assert_eq!(reports.len(), 1, "the heartbeat");
        assert_eq!(targets.len(), 1, "the plot behind it");
        let (targets, reports) = d.parse_datagram(&second).unwrap();
        assert_eq!((targets.len(), reports.len()), (1, 0));
    }

    #[test]
    fn fspec_extension_bit_on_all_but_last() {
        assert_eq!(fspec(&[1, 2, 6]), vec![0xC4]);
        assert_eq!(
            fspec(&[1, 4, 5, 7, 9, 11, 12, 17, 20]),
            vec![0x9B, 0x59, 0x24]
        );
    }
}
