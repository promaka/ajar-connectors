// SPDX-License-Identifier: Apache-2.0
//! CAT048 monoradar target reports. Position is slant range and azimuth from
//! the radar, geolocated against the configured sensor site.

use super::field::{Field, Item};
use super::forward_geodetic;
use super::wire::{aircraft_id, be_uint, mode_3a, sign_extend, time_of_day_s};
use super::{AsterixTarget, Sensor, ANGLE_16, CAT048, FT_TO_M, NM_TO_M, SPEED_LSB_KN};

#[rustfmt::skip]
pub(super) const UAP: &[(Item, Field)] = &[
    (Item(10), Field::Fixed(2)),            // 1  Data Source Identifier
    (Item(140), Field::Fixed(3)),           // 2  Time of Day
    (Item(20), Field::Extended(1)),         // 3  Target Report Descriptor
    (Item(40), Field::Fixed(4)),            // 4  Measured Position (polar)
    (Item(70), Field::Fixed(2)),            // 5  Mode-3/A Code
    (Item(90), Field::Fixed(2)),            // 6  Flight Level (binary)
    (Item(130), Field::Compound(&SUB_130)), // 7  Radar Plot Characteristics
    (Item(220), Field::Fixed(3)),           // 8  Aircraft Address
    (Item(240), Field::Fixed(6)),           // 9  Aircraft Identification
    (Item(250), Field::Repetitive(8)),      // 10 Mode S / BDS Register Data
    (Item(161), Field::Fixed(2)),           // 11 Track Number
    (Item(42), Field::Fixed(4)),            // 12 Calculated Position (Cartesian)
    (Item(200), Field::Fixed(4)),           // 13 Calculated Track Velocity (polar)
    (Item(170), Field::Extended(1)),        // 14 Track Status
    (Item(210), Field::Fixed(4)),           // 15 Track Quality
    (Item(30), Field::Extended(1)),         // 16 Warning/Error Conditions
    (Item(80), Field::Fixed(2)),            // 17 Mode-3/A Confidence
    (Item(100), Field::Fixed(4)),           // 18 Mode-C Code + Confidence
    (Item(110), Field::Fixed(2)),           // 19 Height Measured by 3D Radar
    (Item(120), Field::Compound(&SUB_120)), // 20 Radial Doppler Speed
    (Item(230), Field::Fixed(2)),           // 21 Comms/ACAS Capability & Status
    (Item(260), Field::Fixed(7)),           // 22 ACAS Resolution Advisory
    (Item(55), Field::Fixed(1)),            // 23 Mode-1 Code
    (Item(50), Field::Fixed(2)),            // 24 Mode-2 Code
    (Item(65), Field::Fixed(1)),            // 25 Mode-1 Confidence
    (Item(60), Field::Fixed(2)),            // 26 Mode-2 Confidence
    (Item::SP, Field::Explicit),            // 27 Special Purpose
    (Item::RE, Field::Explicit),            // 28 Reserved Expansion
];
/// I048/130 subfields SRL, SRR, SAM, PRL, PAM, RPD, APD.
const SUB_130: [Field; 7] = [Field::Fixed(1); 7];
/// I048/120 subfields CAL and RDS.
const SUB_120: [Field; 2] = [Field::Fixed(2), Field::Repetitive(6)];

pub(super) fn decode(items: &[(Item, &[u8])], sensor: Option<&Sensor>) -> AsterixTarget {
    let mut t = AsterixTarget {
        category: CAT048,
        ..Default::default()
    };
    for &(id, item) in items {
        match id {
            Item(10) => (t.sac, t.sic) = (item[0], item[1]),
            Item(140) => t.time_of_day_s = Some(time_of_day_s(item)),
            Item(20) => {
                // SIM and RAB in the first octet, TST in the first extension.
                let o1 = item[0];
                t.simulated = o1 & 0x10 != 0;
                t.field_monitor = o1 & 0x02 != 0;
                if o1 & 0x01 != 0 {
                    if let Some(&ext) = item.get(1) {
                        t.test_target = ext & 0x80 != 0;
                    }
                }
            }
            Item(40) => {
                // RHO LSB 1/256 NM. Geolocated after the loop, once the flight
                // level is known.
                let rho_nm = u16::from_be_bytes([item[0], item[1]]) as f64 / 256.0;
                let theta = u16::from_be_bytes([item[2], item[3]]) as f64 * ANGLE_16;
                t.polar = Some((rho_nm, theta));
            }
            Item(70) => {
                // A code with V (invalid) or G (garbled) set is omitted.
                let w = u16::from_be_bytes([item[0], item[1]]);
                if w & 0xC000 == 0 {
                    t.squawk = Some(mode_3a(w));
                }
            }
            Item(90) => {
                // V/G as for Mode-3/A, then 14-bit two's complement, LSB 25 ft.
                if item[0] & 0xC0 == 0 {
                    let raw = u16::from_be_bytes([item[0], item[1]]) & 0x3FFF;
                    t.alt_ft = Some(sign_extend(raw as u64, 14) as f64 * 25.0);
                }
            }
            Item(220) => t.icao = Some(be_uint(item, 0, 3) as u32),
            Item(240) => t.callsign = aircraft_id(item),
            Item(161) => t.track = Some((u16::from_be_bytes([item[0], item[1]]) & 0x0FFF) as u32),
            Item(200) => {
                let gs = u16::from_be_bytes([item[0], item[1]]);
                let hd = u16::from_be_bytes([item[2], item[3]]);
                t.ground_speed_kn = Some(gs as f64 * SPEED_LSB_KN);
                t.track_angle_deg = Some(hd as f64 * ANGLE_16);
            }
            _ => {}
        }
    }
    if let (Some((rho_nm, theta)), Some(s)) = (t.polar, sensor) {
        // RHO is slant range. Pressure altitude stands in for geometric height
        // to project it to ground range; a return steeper than vertical lands
        // on the site.
        let slant_m = rho_nm * NM_TO_M;
        let height_m = t.alt_ft.map(|ft| ft * FT_TO_M - s.alt_m).unwrap_or(0.0);
        let ground_m = if slant_m > height_m.abs() {
            (slant_m * slant_m - height_m * height_m).sqrt()
        } else {
            0.0
        };
        let (lat, lon) = forward_geodetic(s.lat, s.lon, theta, ground_m);
        t.set_pos(lat, lon);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::{Item, UAP};
    use crate::asterix::testutil::{
        attr, block, cat048_record, fspec, meta, parser, u16b, OBSERVED, SITE,
    };
    use ajar_connector_common::FrameParser;
    use std::sync::atomic::Ordering;

    #[test]
    fn decodes_polar_kinematics_and_identity() {
        let t = &parser().parse_block(&block(48, &cat048_record())).unwrap()[0];
        let (rho, theta) = t.polar.unwrap();
        assert!((rho - 100.0).abs() < 1e-6, "rho {rho}");
        assert!((theta - 45.0).abs() < 1e-3, "theta {theta}");
        assert_eq!(t.alt_ft, Some(35000.0));
        assert_eq!(t.icao, Some(0x4CA2D6), "items after I048/130 stay aligned");
        assert_eq!(t.track, Some(1234));
        assert!((t.ground_speed_kn.unwrap() - 450.0).abs() < 0.1);
        assert!((t.track_angle_deg.unwrap() - 90.0).abs() < 1e-3);
        assert_eq!(t.squawk.as_deref(), Some("1234"));
    }

    #[test]
    fn geolocates_against_sensor_site() {
        let p = parser().with_sensor(Some(SITE));
        let t = p
            .parse_block(&block(48, &cat048_record()))
            .unwrap()
            .remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        let loc = ev.location.as_ref().expect("geolocated");
        assert!(
            loc.latitude > 60.0 && loc.latitude < 62.0,
            "100 NM at 045 lands north-east: lat {}",
            loc.latitude
        );
        assert!(loc.longitude > 25.0, "lon {}", loc.longitude);
        assert_eq!(attr(&ev, "squawk"), Some("1234"));
    }

    #[test]
    fn polar_in_metadata_without_sensor() {
        let p = parser();
        let t = p
            .parse_block(&block(48, &cat048_record()))
            .unwrap()
            .remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert!(ev.location.is_none());
        assert_eq!(meta(&ev, "range_nm"), Some("100.000"));
        assert_eq!(meta(&ev, "azimuth_deg").map(|s| &s[..2]), Some("45"));
    }

    #[test]
    fn slant_range_projected_to_ground_range() {
        let p = parser().with_sensor(Some(SITE));
        let mut r = fspec(UAP, &[Item(10), Item(40), Item(90)]);
        r.extend_from_slice(&[25, 10]);
        // 10 NM due north at FL350.
        r.extend_from_slice(&u16b(2560));
        r.extend_from_slice(&u16b(0));
        r.extend_from_slice(&u16b(1400));
        let t = &p.parse_frame(&block(48, &r)).unwrap()[0];
        // Slant 18520 m and height 10668 m give ground ~15139 m, ~0.136 deg;
        // the uncorrected slant range would give ~0.166 deg.
        let dlat = t.lat.unwrap() - 60.0;
        assert!(
            (0.130..0.142).contains(&dlat),
            "expected ground-projected ~0.136 deg, got {dlat}"
        );
    }

    #[test]
    fn simulated_target_counted_not_published() {
        let mut r = fspec(UAP, &[Item(10), Item(20), Item(40)]);
        r.extend_from_slice(&[25, 10]);
        // I048/020 with SIM set.
        r.push(0x10);
        r.extend_from_slice(&u16b(25600));
        r.extend_from_slice(&u16b(8192));
        let p = parser();
        let events = p.parse(&block(48, &r)).unwrap();
        assert!(events.is_empty(), "a simulated target is not a track");
        assert_eq!(p.test_targets.load(Ordering::Relaxed), 1);
        let t = &p.parse_frame(&block(48, &r)).unwrap()[0];
        assert!(t.simulated && !t.test_target && !t.field_monitor);
    }

    #[test]
    fn garbled_or_invalid_codes_omitted() {
        let p = parser();
        let mut status_only = fspec(UAP, &[Item(10), Item(70), Item(90)]);
        status_only.extend_from_slice(&[25, 10]);
        status_only.extend_from_slice(&u16b(0x8000 | 0o1234));
        status_only.extend_from_slice(&[0x40 | 0x05, 0x78]);
        assert!(
            p.parse_frame(&block(48, &status_only)).unwrap().is_empty(),
            "no position, no track"
        );

        let mut r = fspec(UAP, &[Item(10), Item(40), Item(70), Item(90)]);
        r.extend_from_slice(&[25, 10]);
        r.extend_from_slice(&u16b(25600));
        r.extend_from_slice(&u16b(8192));
        // I048/070 with V set, I048/090 with G set.
        r.extend_from_slice(&u16b(0x8000 | 0o1234));
        r.extend_from_slice(&[0x45, 0x78]);
        let t = &p.parse_frame(&block(48, &r)).unwrap()[0];
        assert_eq!(t.squawk, None, "invalid squawk is no squawk");
        assert_eq!(t.alt_ft, None, "garbled flight level is no flight level");
    }
}
