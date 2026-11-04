// SPDX-License-Identifier: Apache-2.0
//! CAT010 monosensor surface movement reports, Edition 1.1: airport surface
//! and, from coastal and naval radars, sea surface. Position is WGS-84, or polar
//! or Cartesian from the sensor and geolocated against the configured site.

use super::field::{Field, Item};
use super::forward_geodetic;
use super::wire::{aircraft_id, be_uint, mode_3a, sign_extend, signed, time_of_day_s};
use super::{AsterixTarget, Sensor, ANGLE_16, CAT010, KNOTS_TO_MPS, NM_TO_M, SPEED_LSB_KN};

#[rustfmt::skip]
pub(super) const UAP: &[(Item, Field)] = &[
    (Item(10), Field::Fixed(2)),       // 1  Data Source Identifier
    (Item(0), Field::Fixed(1)),        // 2  Message Type
    (Item(20), Field::Extended(1)),    // 3  Target Report Descriptor
    (Item(140), Field::Fixed(3)),      // 4  Time of Day
    (Item(41), Field::Fixed(8)),       // 5  Position in WGS-84
    (Item(40), Field::Fixed(4)),       // 6  Measured Position (polar)
    (Item(42), Field::Fixed(4)),       // 7  Position (Cartesian)
    (Item(200), Field::Fixed(4)),      // 8  Calculated Track Velocity (polar)
    (Item(202), Field::Fixed(4)),      // 9  Calculated Track Velocity (Cartesian)
    (Item(161), Field::Fixed(2)),      // 10 Track Number
    (Item(170), Field::Extended(1)),   // 11 Track Status
    (Item(60), Field::Fixed(2)),       // 12 Mode-3/A Code
    (Item(220), Field::Fixed(3)),      // 13 Target Address
    (Item(245), Field::Fixed(7)),      // 14 Target Identification
    (Item(250), Field::Repetitive(8)), // 15 Mode S MB Data
    (Item(300), Field::Fixed(1)),      // 16 Vehicle Fleet Identification
    (Item(90), Field::Fixed(2)),       // 17 Flight Level (binary)
    (Item(91), Field::Fixed(2)),       // 18 Measured Height
    (Item(270), Field::Extended(1)),   // 19 Target Size and Orientation
    (Item(550), Field::Fixed(1)),      // 20 System Status
    (Item(310), Field::Fixed(1)),      // 21 Pre-programmed Message
    (Item(500), Field::Fixed(4)),      // 22 Standard Deviation of Position
    (Item(280), Field::Repetitive(2)), // 23 Presence
    (Item(131), Field::Fixed(1)),      // 24 Amplitude of Primary Plot
    (Item(210), Field::Fixed(2)),      // 25 Calculated Acceleration
    (Item::SPARE, Field::Spare),       // 26
    (Item::SP, Field::Explicit),       // 27 Special Purpose
    (Item::RE, Field::Explicit),       // 28 Reserved Expansion
];
/// I010/041 latitude and longitude LSB, degrees.
pub(super) const LSB_041: f64 = 180.0 / (1u64 << 31) as f64;
/// The I010/000 message type of a target report; the others are status.
pub(super) const TARGET_REPORT: u8 = 1;

pub(super) fn decode(items: &[(Item, &[u8])], sensor: Option<&Sensor>) -> AsterixTarget {
    let mut t = AsterixTarget {
        category: CAT010,
        ..Default::default()
    };
    for &(id, item) in items {
        match id {
            Item(10) => (t.sac, t.sic) = (item[0], item[1]),
            Item(0) => t.message_type = Some(item[0]),
            Item(20) => {
                // TYP in bits 8-6; SIM, TST and RAB in the first extension.
                t.report_type = Some(match item[0] >> 5 {
                    0 => "ssr-multilateration",
                    1 => "mode-s-multilateration",
                    2 => "ads-b",
                    3 => "psr",
                    4 => "magnetic-loop",
                    5 => "hf-multilateration",
                    _ => "other",
                });
                if item[0] & 0x01 != 0 {
                    if let Some(&ext) = item.get(1) {
                        t.simulated = ext & 0x80 != 0;
                        t.test_target = ext & 0x40 != 0;
                        t.field_monitor = ext & 0x20 != 0;
                    }
                }
            }
            Item(140) => t.time_of_day_s = Some(time_of_day_s(item)),
            Item(41) => t.set_pos(signed(item, 0, 4) * LSB_041, signed(item, 4, 4) * LSB_041),
            Item(40) => {
                // RHO in metres, stored in NM like CAT048. A surface target
                // needs no slant correction.
                let rho_m = u16::from_be_bytes([item[0], item[1]]) as f64;
                let theta = u16::from_be_bytes([item[2], item[3]]) as f64 * ANGLE_16;
                t.polar = Some((rho_m / NM_TO_M, theta));
            }
            Item(42) => t.cartesian_m = Some((signed(item, 0, 2), signed(item, 2, 2))),
            Item(200) => {
                let gs = u16::from_be_bytes([item[0], item[1]]);
                let hd = u16::from_be_bytes([item[2], item[3]]);
                t.ground_speed_kn = Some(gs as f64 * SPEED_LSB_KN);
                t.track_angle_deg = Some(hd as f64 * ANGLE_16);
            }
            Item(202) => {
                // Vx east and Vy north, LSB 0.25 m/s.
                let vx = signed(item, 0, 2) * 0.25;
                let vy = signed(item, 2, 2) * 0.25;
                let speed_mps = (vx * vx + vy * vy).sqrt();
                t.ground_speed_kn = Some(speed_mps / KNOTS_TO_MPS);
                if speed_mps > 0.0 {
                    t.track_angle_deg = Some(vx.atan2(vy).to_degrees().rem_euclid(360.0));
                }
            }
            Item(161) => t.track = Some((u16::from_be_bytes([item[0], item[1]]) & 0x0FFF) as u32),
            Item(60) => {
                let w = u16::from_be_bytes([item[0], item[1]]);
                if w & 0xC000 == 0 {
                    t.squawk = Some(mode_3a(w));
                }
            }
            Item(220) => t.icao = Some(be_uint(item, 0, 3) as u32),
            Item(245) => t.callsign = item.get(1..7).and_then(aircraft_id),
            Item(300) => t.vehicle_fleet = vehicle_fleet(item[0]),
            Item(90) => {
                if item[0] & 0xC0 == 0 {
                    let raw = u16::from_be_bytes([item[0], item[1]]) & 0x3FFF;
                    t.alt_ft = Some(sign_extend(raw as u64, 14) as f64 * 25.0);
                }
            }
            Item(91) => t.alt_ft = Some(signed(item, 0, 2) * 6.25),
            Item(270) => {
                // LENGTH in metres, then ORIENTATION (LSB 360/128 deg) and WIDTH
                // in metres in the extensions.
                let length = (item[0] >> 1) as f64;
                let orientation = item.get(1).map(|o| (o >> 1) as f64 * 360.0 / 128.0);
                let width = item.get(2).map(|o| (o >> 1) as f64);
                t.size = Some((length, width, orientation));
            }
            // LSB 0.25 m.
            Item(500) => t.position_sd_m = Some((item[0] as f64 * 0.25, item[1] as f64 * 0.25)),
            _ => {}
        }
    }
    let Some(s) = sensor else {
        return t;
    };
    if t.lat.is_some() {
        return t;
    }
    if let Some((rho_nm, theta)) = t.polar {
        let (lat, lon) = forward_geodetic(s.lat, s.lon, theta, rho_nm * NM_TO_M);
        t.set_pos(lat, lon);
    } else if let Some((x, y)) = t.cartesian_m {
        let dist = (x * x + y * y).sqrt();
        let bearing = x.atan2(y).to_degrees().rem_euclid(360.0);
        let (lat, lon) = forward_geodetic(s.lat, s.lon, bearing, dist);
        t.set_pos(lat, lon);
    }
    t
}

/// I010/300 Vehicle Fleet Identification.
fn vehicle_fleet(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "atc-equipment-maintenance",
        2 => "airport-maintenance",
        3 => "fire",
        4 => "bird-scarer",
        5 => "snow-plough",
        6 => "runway-sweeper",
        7 => "emergency",
        8 => "police",
        9 => "bus",
        10 => "tug",
        11 => "grass-cutter",
        12 => "fuel",
        13 => "baggage",
        14 => "catering",
        15 => "aircraft-maintenance",
        16 => "flyco",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asterix::testutil::{
        attr, block, cat010_record, fspec, meta, parser, u16b, OBSERVED, SITE,
    };
    use ajar_connector_common::FrameParser;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn entity_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// A target report with a WGS-84 fix at 0,0 followed by `extra` items.
    fn report_at_origin(items: &[Item], extra: &[u8]) -> Vec<u8> {
        let mut r = fspec(UAP, items);
        r.extend_from_slice(&[25, 10]);
        r.push(TARGET_REPORT);
        r.extend_from_slice(&[0u8; 8]);
        r.extend_from_slice(extra);
        r
    }

    #[test]
    fn wgs84_report_keeps_position_uncertainty() {
        let p = parser();
        let t = p
            .parse_block(&block(10, &cat010_record()))
            .unwrap()
            .remove(0);
        assert!((t.lat.unwrap() - 60.0).abs() < 1e-6);
        assert!((t.lon.unwrap() - 25.0).abs() < 1e-6);
        assert!((t.ground_speed_kn.unwrap() - 450.0).abs() < 0.1);
        assert_eq!(t.track, Some(77));
        assert_eq!(t.position_sd_m, Some((2.0, 3.0)));
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:object", "nothing identifies the plot");
        assert_eq!(meta(&ev, "source_uid"), Some("asterix:10:25:10:77"));
        assert_eq!(meta(&ev, "asterix_category"), Some("10"));
        assert_eq!(meta(&ev, "position_sd_x_m"), Some("2.00"));
        assert_eq!(meta(&ev, "position_sd_y_m"), Some("3.00"));
        assert_eq!(attr(&ev, "position_accuracy_h_m"), Some("3.61"), "DRMS");
        assert_eq!(attr(&ev, "alt_id"), Some("10:25:10:77"));
        assert_eq!(attr(&ev, "alt_id_standard"), Some("ASTERIX"));
        assert_eq!(attr(&ev, "course"), Some("90.0"));
        assert_eq!(attr(&ev, "environment"), None, "no domain without a choice");
    }

    #[test]
    fn entity_map_sets_vessel_type() {
        let map = entity_map(&[("cat010", "mim:vessel")]);
        let p = parser().with_entity_map(&map).unwrap();
        let t = p
            .parse_block(&block(10, &cat010_record()))
            .unwrap()
            .remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:vessel");
        assert_eq!(attr(&ev, "environment"), None);
    }

    #[test]
    fn vehicle_fleet_makes_land_vehicle() {
        let p = parser();
        // I010/300 fire vehicle.
        let r = report_at_origin(&[Item(10), Item(0), Item(41), Item(300)], &[3]);
        let t = p.parse_block(&block(10, &r)).unwrap().remove(0);
        assert_eq!(t.vehicle_fleet, Some("fire"));
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:land-vehicle");
        assert_eq!(attr(&ev, "environment"), None);
        assert_eq!(meta(&ev, "vehicle_fleet"), Some("fire"));
    }

    #[test]
    fn mode_s_address_makes_aircraft() {
        let p = parser();
        let r = report_at_origin(
            &[Item(10), Item(0), Item(41), Item(220)],
            &[0x4C, 0xA2, 0xD6],
        );
        let t = p.parse_block(&block(10, &r)).unwrap().remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(meta(&ev, "source_uid"), Some("icao:4CA2D6"));
        assert_eq!(attr(&ev, "alt_id"), Some("4CA2D6"));
        assert_eq!(attr(&ev, "alt_id_standard"), Some("ICAO24"));
    }

    #[test]
    fn typed_class_keeps_domain_in_metadata() {
        for ty in ["mim:vessel", "mim:surface-vessel", "mim:subsurface-vessel"] {
            let map = entity_map(&[("cat010", ty), ("cat010_domain", "SURFACE")]);
            let p = parser().with_entity_map(&map).unwrap();
            let t = p
                .parse_block(&block(10, &cat010_record()))
                .unwrap()
                .remove(0);
            let ev = p.to_event_at(t, OBSERVED).unwrap();
            assert_eq!(ev.entity_type, ty);
            assert_eq!(
                attr(&ev, "environment"),
                None,
                "{ty}: environment is governed on mim:object alone"
            );
            assert_eq!(meta(&ev, "environment"), Some("SURFACE"), "{ty}");
        }
    }

    #[test]
    fn object_carries_configured_domain() {
        let map = entity_map(&[("cat010_domain", "SURFACE")]);
        let p = parser().with_entity_map(&map).unwrap();
        let t = p
            .parse_block(&block(10, &cat010_record()))
            .unwrap()
            .remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:object");
        assert_eq!(attr(&ev, "environment"), Some("SURFACE"));
    }

    #[test]
    fn unknown_domain_refused_at_construction() {
        for bad_value in ["sea", "surface", "Surface"] {
            let map = entity_map(&[("cat010_domain", bad_value)]);
            let err = parser()
                .with_entity_map(&map)
                .err()
                .expect(bad_value)
                .to_string();
            assert!(err.contains("cat010_domain"), "{err}");
            assert!(err.contains("SURFACE"), "names the vocabulary: {err}");
        }
    }

    #[test]
    fn polar_geolocates_without_slant_correction() {
        let p = parser().with_sensor(Some(SITE));
        // 1852 m due north.
        let mut r = fspec(UAP, &[Item(10), Item(0), Item(40)]);
        r.extend_from_slice(&[25, 10]);
        r.push(TARGET_REPORT);
        r.extend_from_slice(&u16b(1852));
        r.extend_from_slice(&u16b(0));
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        let dlat = t.lat.unwrap() - 60.0;
        assert!((dlat - 0.01666).abs() < 0.0005, "one NM north = {dlat} deg");
        assert!((t.lon.unwrap() - 25.0).abs() < 1e-9);
    }

    /// A target report 1000 m due east of the sensor.
    fn cartesian_east() -> Vec<u8> {
        let mut r = fspec(UAP, &[Item(10), Item(0), Item(42)]);
        r.extend_from_slice(&[25, 10]);
        r.push(TARGET_REPORT);
        r.extend_from_slice(&1000i16.to_be_bytes());
        r.extend_from_slice(&0i16.to_be_bytes());
        r
    }

    #[test]
    fn cartesian_geolocates_against_site() {
        let p = parser().with_sensor(Some(SITE));
        let t = &p.parse_block(&block(10, &cartesian_east())).unwrap()[0];
        assert!(
            (t.lat.unwrap() - 60.0).abs() < 1e-4,
            "a great circle due east keeps latitude to within ~1e-6 deg"
        );
        let dlon = t.lon.unwrap() - 25.0;
        assert!(
            (0.0175..0.0185).contains(&dlon),
            "1 km east at 60N = {dlon} deg"
        );
    }

    #[test]
    fn cartesian_in_metadata_without_sensor() {
        let p = parser();
        let t = p
            .parse_block(&block(10, &cartesian_east()))
            .unwrap()
            .remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert!(ev.location.is_none());
        assert_eq!(meta(&ev, "x_m"), Some("1000"));
        assert_eq!(meta(&ev, "y_m"), Some("0"));
    }

    #[test]
    fn cartesian_velocity_becomes_speed_and_course() {
        // Vx 10 m/s east, Vy 0.
        let mut velocity = 40i16.to_be_bytes().to_vec();
        velocity.extend_from_slice(&0i16.to_be_bytes());
        let r = report_at_origin(&[Item(10), Item(0), Item(41), Item(202)], &velocity);
        let t = &parser().parse_block(&block(10, &r)).unwrap()[0];
        assert!((t.ground_speed_kn.unwrap() * KNOTS_TO_MPS - 10.0).abs() < 0.01);
        assert!((t.track_angle_deg.unwrap() - 90.0).abs() < 1e-6);
    }

    #[test]
    fn status_message_is_not_a_track() {
        let mut r = fspec(UAP, &[Item(10), Item(0), Item(41)]);
        r.extend_from_slice(&[25, 10]);
        // Periodic status message, carrying a position.
        r.push(3);
        r.extend_from_slice(&[0u8; 8]);
        assert!(parser().parse_block(&block(10, &r)).unwrap().is_empty());
    }

    #[test]
    fn simulated_report_counted_not_published() {
        let mut r = fspec(UAP, &[Item(10), Item(0), Item(20), Item(41)]);
        r.extend_from_slice(&[25, 10]);
        r.push(TARGET_REPORT);
        // I010/020 TYP=PSR with FX, then SIM in the first extension.
        r.extend_from_slice(&[0x60 | 0x01, 0x80]);
        r.extend_from_slice(&[0u8; 8]);
        let p = parser();
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        assert!(t.simulated);
        assert_eq!(t.report_type, Some("psr"));
        assert!(p.parse(&block(10, &r)).unwrap().is_empty());
        assert_eq!(p.test_targets.load(Ordering::Relaxed), 1);
    }
}
