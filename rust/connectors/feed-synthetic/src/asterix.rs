// SPDX-License-Identifier: Apache-2.0
//! Radar: ASTERIX blocks on the surveillance multicast group, what the
//! `asterix` connector reads.
//!
//! Three categories, which is what a radar head actually puts on the wire:
//!
//! - CAT062, a system track, for the airliner. Identity (ICAO address and
//!   callsign), position, velocity, flight level and rate of climb: the
//!   processed picture, after the radar's own tracker has done its work.
//! - CAT010, a surface plot, for the vessel. Position and nothing else: a plot
//!   is a return, not an identification. This is the half of the pair that AIS
//!   completes, and the connector emits it as an untyped object in the domain
//!   the operator states, never as a vessel it cannot know it is.
//! - CAT034, the radar's own status and north marker: alive, turning this fast,
//!   from here, watching this window. The connector promotes the rotation
//!   period and the window into the contract's sensor attributes.
//!
//! Field encodings follow the record layouts in the connector's own decoder:
//! range in metres, angles in 360/65536 of a degree, WGS-84 in 180/2^25 of a
//! degree for tracks and 180/2^23 for the sensor position, velocity in
//! quarter-metres per second, flight level in quarter-hundreds of feet, time
//! of day in 1/128 s.
//!
//! CAT034 and CAT010 travel in one datagram, as they do from a real radar head:
//! a service block leading the target blocks is the standard shape, and a
//! decoder that only read the first block would silently drop the targets
//! behind it.
//!
//! One honest gap: this CAT010 record carries no time of day, so the connector
//! stamps the plot with its own clock. The CAT062 track does carry the radar's
//! observation time, so the aircraft demonstrates the two-clock behaviour and
//! the vessel plot does not.

use std::time::SystemTime;

use crate::scenario::{
    bearing_range, seconds_since_midnight, Aircraft, AircraftState, VesselState, RADAR,
    RADAR_ALT_M, RADAR_SAC, RADAR_SCAN_PERIOD_S, RADAR_SIC, RADAR_WINDOW,
};

const LSB_105: f64 = 180.0 / (1u64 << 25) as f64;
const LSB_120: f64 = 180.0 / (1u64 << 23) as f64;
const ANGLE_16: f64 = 360.0 / 65_536.0;
const FT_PER_M: f64 = 3.280_84;
/// CAT034 message type 1: north marker.
const NORTH_MARKER: u8 = 1;

/// The field specification bitmap: which data items follow, in UAP order.
/// Every octet but the last carries the extension bit, which is what lets a
/// record grow.
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

/// One ASTERIX block: category, total length including the three header bytes.
fn block(cat: u8, record: &[u8]) -> Vec<u8> {
    let len = (3 + record.len()) as u16;
    let mut out = vec![cat];
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

/// CAT062: a system track for the aircraft, the radar's processed answer,
/// with identity.
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

/// CAT010: a surface plot for the vessel, polar position from the radar head,
/// no identity. Range in metres and bearing in 360/65536 of a degree, which
/// the connector geolocates against the site in its `[sensor]` block. That is
/// the real division of labour: the radar reports what it measured, the
/// operator states where the radar is.
pub fn cat010_plot(v: &VesselState) -> Vec<u8> {
    let (bearing, range_m) = bearing_range(RADAR, v.fix);
    let mut r = fspec(&[1, 2, 6]);
    r.extend_from_slice(&[RADAR_SAC, RADAR_SIC]); // 010
    r.push(1); // 000 message type: target report
    r.extend_from_slice(&(range_m.round() as u16).to_be_bytes()); // 040 rho, m
    r.extend_from_slice(&((bearing / ANGLE_16).round() as u16).to_be_bytes()); // 040 theta
    block(10, &r)
}

/// CAT034: the radar's north marker. Alive, turning this fast, from here,
/// watching this window.
pub fn cat034_heartbeat(observed: SystemTime) -> Vec<u8> {
    let mut r = fspec(&[1, 2, 3, 5, 9, 11]);
    r.extend_from_slice(&[RADAR_SAC, RADAR_SIC]); // 010
    r.push(NORTH_MARKER); // 000
    r.extend_from_slice(&tod(observed)); // 030
    r.extend_from_slice(&((RADAR_SCAN_PERIOD_S * 128.0) as u16).to_be_bytes()); // 041, 1/128 s
                                                                                // 100 generic polar window: range start and end in 1/256 NM, azimuth start
                                                                                // and end in 360/65536 deg.
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

/// The two datagrams one rotation produces: the service block leading the
/// surface plot, then the system track.
pub fn rotation(v: &VesselState, a: &AircraftState, observed: SystemTime) -> [Vec<u8>; 2] {
    let mut first = cat034_heartbeat(observed);
    first.extend_from_slice(&cat010_plot(v));
    [first, cat062_track(a, observed)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{Vessel, RADAR_WINDOW};
    use ajar_asterix::{AsterixParser, Sensor};
    use ajar_connector_common::Enrichment;
    use std::collections::HashMap;

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
    }

    fn attr(ev: &ajar_connector::Event, k: &str) -> Option<String> {
        ev.attributes
            .iter()
            .find(|a| a.key == k)
            .map(|a| a.value.clone())
    }

    #[test]
    fn the_system_track_decodes_to_the_identified_airliner() {
        let a = Aircraft::at(20.0);
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let d = decoder();
        let targets = d.parse_block(&cat062_track(&a, now)).expect("valid block");
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        assert_eq!(t.icao, Some(0x4CA2D6));
        assert_eq!(t.callsign.as_deref(), Some("BAW117"));
        assert_eq!(t.track, Some(4095));
        assert_eq!(t.squawk.as_deref(), Some("1234"));
        // 20:26:40 UTC as the radar's time of day.
        assert!((t.time_of_day.unwrap() - 73_600.0).abs() < 0.01);
        let ev = d.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        let loc = ev.location.unwrap();
        assert!((loc.latitude - a.fix.lat).abs() < 1e-5);
        assert!((loc.longitude - a.fix.lon).abs() < 1e-5);
        assert!(
            (loc.altitude_m - Aircraft::ALT_M).abs() < 8.0,
            "{}",
            loc.altitude_m
        );
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("4CA2D6"));
        assert_eq!(attr(&ev, "alt_id_standard").as_deref(), Some("ICAO24"));
        let speed: f64 = attr(&ev, "speed").unwrap().parse().unwrap();
        assert!((speed - Aircraft::SPEED_MPS).abs() < 0.3, "{speed}");
        let course: f64 = attr(&ev, "course").unwrap().parse().unwrap();
        assert!((course - Aircraft::COURSE_DEG).abs() < 0.2, "{course}");
        let vr: f64 = attr(&ev, "vertical_rate").unwrap().parse().unwrap();
        assert!((vr - Aircraft::VERTICAL_RATE_MPS).abs() < 0.06, "{vr}");
    }

    #[test]
    fn the_surface_plot_geolocates_onto_the_vessel_and_claims_no_identity() {
        let v = Vessel::at(20.0);
        let d = decoder();
        let targets = d.parse_block(&cat010_plot(&v)).unwrap();
        let t = &targets[0];
        let ev = d.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        // A return is a domain, not an identification.
        assert_eq!(ev.entity_type, "mim:object");
        assert_eq!(attr(&ev, "environment").as_deref(), Some("SURFACE"));
        assert!(attr(&ev, "callsign").is_none());
        assert!(attr(&ev, "alt_id").is_none());
        // Within the metre the range field can carry, and within the angular
        // resolution at this range: the plot lands on the ship.
        let loc = ev.location.unwrap();
        let (_, err_m) = bearing_range(
            v.fix,
            crate::scenario::Fix {
                lat: loc.latitude,
                lon: loc.longitude,
            },
        );
        assert!(err_m < 5.0, "plot is {err_m:.1} m off the vessel");
    }

    #[test]
    fn the_north_marker_becomes_a_sensor_event_with_the_revision_4_footprint() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let d = decoder();
        let reports = d.parse_service_block(&cat034_heartbeat(now)).unwrap();
        assert_eq!(reports.len(), 1);
        let r = &reports[0];
        assert_eq!((r.sac, r.sic), (RADAR_SAC, RADAR_SIC));
        assert_eq!(r.message_type, NORTH_MARKER);
        assert!((r.rotation_period_s.unwrap() - RADAR_SCAN_PERIOD_S).abs() < 0.01);
        let (lat, lon, alt) = r.position.unwrap();
        assert!((lat - RADAR.lat).abs() < 1e-4);
        assert!((lon - RADAR.lon).abs() < 1e-4);
        assert!((alt - RADAR_ALT_M).abs() < 0.5);
        let ev = d.service_event_at(r, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:sensor");
        assert_eq!(attr(&ev, "scan_period_s").as_deref(), Some("2.500"));
        assert_eq!(attr(&ev, "update_interval_s").as_deref(), Some("2.500"));
        let (_, r1, a0, a1) = RADAR_WINDOW;
        let f = |k: &str| attr(&ev, k).unwrap().parse::<f64>().unwrap();
        assert!((f("coverage_bearing_start_deg") - a0).abs() < 0.01);
        assert!((f("coverage_bearing_end_deg") - a1).abs() < 0.01);
        assert!((f("detection_range_m") - r1 * 1852.0).abs() < 1.0);
        assert_eq!(attr(&ev, "alt_id").as_deref(), Some("25:10"));
        assert_eq!(attr(&ev, "alt_id_standard").as_deref(), Some("ASTERIX"));
    }

    #[test]
    fn a_rotation_is_two_datagrams_and_the_service_block_does_not_hide_the_plot() {
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000);
        let [first, second] = rotation(&Vessel::at(0.0), &Aircraft::at(0.0), now);
        let d = decoder();
        let (targets, reports) = d.parse_datagram(&first).unwrap();
        assert_eq!(reports.len(), 1, "the heartbeat");
        assert_eq!(targets.len(), 1, "the plot behind it");
        let (targets, reports) = d.parse_datagram(&second).unwrap();
        assert_eq!((targets.len(), reports.len()), (1, 0));
    }

    #[test]
    fn fspec_sets_the_extension_bit_on_every_octet_but_the_last() {
        assert_eq!(fspec(&[1, 2, 6]), vec![0xC4]);
        // FRN 9, 11 and 12 in the second octet plus its extension bit; FRN 17
        // and 20 in the third, which is last and so has none.
        assert_eq!(
            fspec(&[1, 4, 5, 7, 9, 11, 12, 17, 20]),
            vec![0x9B, 0x59, 0x24]
        );
    }
}
