// SPDX-License-Identifier: Apache-2.0
//! CAT062 SDPS system tracks, the fused air picture. Position is WGS-84.

use super::field::{walk_compound, Field, Item};
use super::wire::{aircraft_id, be_uint, mode_3a, signed, time_of_day_s};
use super::{AsterixTarget, CAT062, FT_TO_M, KNOTS_TO_MPS};

#[rustfmt::skip]
pub(super) const UAP: &[(Item, Field)] = &[
    (Item(10), Field::Fixed(2)),            // 1  Data Source Identifier
    (Item::SPARE, Field::Opaque),           // 2
    (Item(15), Field::Fixed(1)),            // 3  Service Identification
    (Item(70), Field::Fixed(3)),            // 4  Time Of Track Information
    (Item(105), Field::Fixed(8)),           // 5  Calculated Position WGS-84
    (Item(100), Field::Fixed(6)),           // 6  Calculated Track Position (Cartesian)
    (Item(185), Field::Fixed(4)),           // 7  Calculated Track Velocity (Cartesian)
    (Item(210), Field::Fixed(2)),           // 8  Calculated Acceleration
    (Item(60), Field::Fixed(2)),            // 9  Track Mode 3/A Code
    (Item(245), Field::Fixed(7)),           // 10 Target Identification
    (Item(380), Field::Compound(&SUB_380)), // 11 Aircraft Derived Data
    (Item(40), Field::Fixed(2)),            // 12 Track Number
    (Item(80), Field::Extended(1)),         // 13 Track Status
    (Item(290), Field::Compound(&SUB_290)), // 14 System Track Update Ages
    (Item(200), Field::Fixed(1)),           // 15 Mode of Movement
    (Item(295), Field::Compound(&SUB_295)), // 16 Track Data Ages
    (Item(136), Field::Fixed(2)),           // 17 Measured Flight Level
    (Item(130), Field::Fixed(2)),           // 18 Calculated Geometric Altitude
    (Item(135), Field::Fixed(2)),           // 19 Calculated Barometric Altitude
    (Item(220), Field::Fixed(2)),           // 20 Calculated Rate of Climb/Descent
    (Item(390), Field::Compound(&SUB_390)), // 21 Flight Plan Related Data
    (Item(270), Field::Extended(1)),        // 22 Target Size & Orientation
    (Item(300), Field::Fixed(1)),           // 23 Vehicle Fleet Identification
    (Item(110), Field::Compound(&SUB_110)), // 24 Mode 5 Data
    (Item(120), Field::Fixed(2)),           // 25 Track Mode 2 Code
    (Item(510), Field::Extended(3)),        // 26 Composed Track Number
    (Item(500), Field::Compound(&SUB_500)), // 27 Estimated Accuracies
    (Item(340), Field::Compound(&SUB_340)), // 28 Measured Information
    (Item::SPARE, Field::Opaque),           // 29
    (Item::SPARE, Field::Opaque),           // 30
    (Item::SPARE, Field::Opaque),           // 31
    (Item::SPARE, Field::Opaque),           // 32
    (Item::SPARE, Field::Opaque),           // 33
    (Item::RE, Field::Explicit),            // 34 Reserved Expansion
    (Item::SP, Field::Explicit),            // 35 Special Purpose
];

/// I062/105 latitude and longitude LSB, degrees.
pub(super) const LSB_105: f64 = 180.0 / (1u64 << 25) as f64;

/// I062/380 Aircraft Derived Data subfields.
#[rustfmt::skip]
const SUB_380: [Field; 28] = [
    Field::Fixed(3),       // ADR Target Address
    Field::Fixed(6),       // ID  Target Identification
    Field::Fixed(2),       // MHG Magnetic Heading
    Field::Fixed(2),       // IAS Indicated Airspeed / Mach
    Field::Fixed(2),       // TAS True Airspeed
    Field::Fixed(2),       // SAL Selected Altitude
    Field::Fixed(2),       // FSS Final State Selected Altitude
    Field::Extended(1),    // TIS Trajectory Intent Status
    Field::Repetitive(15), // TID Trajectory Intent Data
    Field::Fixed(2),       // COM Comms/ACAS Capability
    Field::Fixed(2),       // SAB Status reported by ADS-B
    Field::Fixed(7),       // ACS ACAS Resolution Advisory
    Field::Fixed(2),       // BVR Barometric Vertical Rate
    Field::Fixed(2),       // GVR Geometric Vertical Rate
    Field::Fixed(2),       // RAN Roll Angle
    Field::Fixed(2),       // TAR Track Angle Rate
    Field::Fixed(2),       // TAN Track Angle
    Field::Fixed(2),       // GSP Ground Speed
    Field::Fixed(1),       // VUN Velocity Uncertainty
    Field::Fixed(8),       // MET Meteorological Data
    Field::Fixed(1),       // EMC Emitter Category
    Field::Fixed(6),       // POS Position
    Field::Fixed(2),       // GAL Geometric Altitude
    Field::Fixed(1),       // PUN Position Uncertainty
    Field::Repetitive(8),  // MB  Mode-S MB Data
    Field::Fixed(2),       // IAR Indicated Airspeed
    Field::Fixed(2),       // MAC Mach Number
    Field::Fixed(2),       // BPS Barometric Pressure Setting
];

/// I062/290 System Track Update Ages subfields.
#[rustfmt::skip]
const SUB_290: [Field; 14] = [
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), // TRK PSR SSR MDS
    Field::Fixed(2), Field::Fixed(1), Field::Fixed(1),                  // ADS ES VDL
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),                  // UAT LOP MLT
    Field::Spare, Field::Spare, Field::Spare, Field::Spare,
];

/// I062/295 Track Data Ages subfields: 31 one-octet ages, then spares.
#[rustfmt::skip]
const SUB_295: [Field; 35] = [
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Spare, Field::Spare, Field::Spare, Field::Spare,
];

/// I062/500 Estimated Accuracies subfields.
#[rustfmt::skip]
const SUB_500: [Field; 14] = [
    Field::Fixed(4), Field::Fixed(2), Field::Fixed(4), Field::Fixed(1), // APC COV APW AGA
    Field::Fixed(1), Field::Fixed(2), Field::Fixed(2),                  // ABA ATV AA
    Field::Fixed(1),                                                    // ARC
    Field::Spare, Field::Spare, Field::Spare, Field::Spare, Field::Spare, Field::Spare,
];

/// I062/340 Measured Information subfields.
#[rustfmt::skip]
const SUB_340: [Field; 7] = [
    Field::Fixed(2), Field::Fixed(4), Field::Fixed(2), // SID POS HEI
    Field::Fixed(2), Field::Fixed(2), Field::Fixed(1), // MDC MDA TYP
    Field::Spare,
];

/// I062/110 Mode 5 Data subfields.
#[rustfmt::skip]
const SUB_110: [Field; 7] = [
    Field::Fixed(1), Field::Fixed(4), Field::Fixed(6),                  // SUM PMN POS
    Field::Fixed(2), Field::Fixed(2), Field::Fixed(1), Field::Fixed(1), // GA EM1 TOS XP
];

/// I062/390 Flight Plan Related Data subfields.
#[rustfmt::skip]
const SUB_390: [Field; 21] = [
    Field::Fixed(2),      // TAG
    Field::Fixed(7),      // CSN Callsign
    Field::Fixed(4),      // IFI
    Field::Fixed(1),      // FCT
    Field::Fixed(4),      // TAC
    Field::Fixed(1),      // WTC
    Field::Fixed(4),      // DEP
    Field::Fixed(4),      // DST
    Field::Fixed(3),      // RDS
    Field::Fixed(2),      // CFL
    Field::Fixed(2),      // CTL
    Field::Repetitive(4), // TOD
    Field::Fixed(6),      // AST
    Field::Fixed(1),      // STS
    Field::Fixed(7),      // STD
    Field::Fixed(7),      // STA
    Field::Fixed(2),      // PEM
    Field::Fixed(7),      // PEC
    Field::Spare, Field::Spare, Field::Spare,
];

pub(super) fn decode(items: &[(Item, &[u8])]) -> AsterixTarget {
    let mut t = AsterixTarget {
        category: CAT062,
        ..Default::default()
    };
    for &(id, item) in items {
        match id {
            Item(10) => (t.sac, t.sic) = (item[0], item[1]),
            Item(70) => t.time_of_day_s = Some(time_of_day_s(item)),
            Item(105) => t.set_pos(signed(item, 0, 4) * LSB_105, signed(item, 4, 4) * LSB_105),
            Item(185) => {
                // Vx east and Vy north, LSB 0.25 m/s.
                let vx = i16::from_be_bytes([item[0], item[1]]) as f64 * 0.25;
                let vy = i16::from_be_bytes([item[2], item[3]]) as f64 * 0.25;
                t.ground_speed_kn = Some((vx * vx + vy * vy).sqrt() / KNOTS_TO_MPS);
                t.track_angle_deg = Some(vx.atan2(vy).to_degrees().rem_euclid(360.0));
            }
            Item(60) => t.squawk = Some(mode_3a(u16::from_be_bytes([item[0], item[1]]))),
            Item(245) => t.callsign = aircraft_id(&item[1..7]),
            Item(380) => {
                for (sub, bytes) in walk_compound(&SUB_380, item) {
                    match sub {
                        0 => t.icao = Some(be_uint(bytes, 0, 3) as u32),
                        1 => t.callsign = aircraft_id(bytes),
                        _ => {}
                    }
                }
            }
            Item(40) => t.track = Some(u16::from_be_bytes([item[0], item[1]]) as u32),
            Item(136) => t.alt_ft = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 25.0),
            Item(220) => {
                t.vertical_rate_ftmin = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 6.25)
            }
            Item(500) => {
                // APC sigma x and y (LSB 0.5 m), ABA sigma of the barometric
                // altitude these events carry (LSB 25 ft), ATV sigma vx and vy
                // (LSB 0.25 m/s). AGA describes a geometric altitude that is
                // not emitted.
                for (sub, bytes) in walk_compound(&SUB_500, item) {
                    match sub {
                        0 => {
                            let sx = u16::from_be_bytes([bytes[0], bytes[1]]) as f64 * 0.5;
                            let sy = u16::from_be_bytes([bytes[2], bytes[3]]) as f64 * 0.5;
                            t.position_sd_m = Some((sx, sy));
                        }
                        4 => t.accuracy_v_m = Some(bytes[0] as f64 * 25.0 * FT_TO_M),
                        5 => {
                            t.velocity_sd_mps =
                                Some((bytes[0] as f64 * 0.25, bytes[1] as f64 * 0.25))
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asterix::testutil::{
        attr, block, cat062_record, fspec, meta, parser, u16b, OBSERVED,
    };

    #[test]
    fn decodes_position_velocity_and_derived_data() {
        let t = &parser().parse_block(&block(62, &cat062_record())).unwrap()[0];
        let (lat, lon) = (t.lat.unwrap(), t.lon.unwrap());
        assert!((lat - 60.0).abs() < 1e-4, "lat {lat}");
        assert!((lon - 25.0).abs() < 1e-4, "lon {lon}");
        let kn = t.ground_speed_kn.unwrap();
        assert!(
            (kn - 194.38).abs() < 0.1,
            "100 m/s east is 194.38 kn, got {kn}"
        );
        assert!((t.track_angle_deg.unwrap() - 90.0).abs() < 1e-3);
        assert_eq!(t.alt_ft, Some(35000.0));
        assert_eq!(t.vertical_rate_ftmin, Some(1000.0));
        assert_eq!(t.track, Some(4095), "items after I062/380 stay aligned");
        assert_eq!(t.icao, Some(0x406201));
        assert_eq!(t.callsign.as_deref(), Some("BAW123"));
    }

    #[test]
    fn event_carries_canonical_units() {
        let p = parser();
        let t = p
            .parse_block(&block(62, &cat062_record()))
            .unwrap()
            .remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(meta(&ev, "source_uid"), Some("icao:406201"));
        assert_eq!(meta(&ev, "asterix_category"), Some("62"));
        assert_eq!(attr(&ev, "speed"), Some("100.00"));
        assert_eq!(attr(&ev, "course"), Some("90.0"));
        assert_eq!(attr(&ev, "callsign"), Some("BAW123"));
        assert_eq!(
            ev.payload,
            cat062_record(),
            "the raw record is sealed verbatim"
        );
    }

    /// A track at 60N 25E with track number 4095, an I062/136 flight level
    /// when `fl` is set, and `accuracies` as I062/500.
    fn track_with_accuracies(fl: Option<i16>, accuracies: &[u8]) -> Vec<u8> {
        let mut items = vec![Item(10), Item(105), Item(40)];
        items.extend(fl.map(|_| Item(136)));
        items.push(Item(500));
        let mut r = fspec(UAP, &items);
        r.extend_from_slice(&[25, 10]);
        r.extend_from_slice(&((60.0 / LSB_105) as i32).to_be_bytes());
        r.extend_from_slice(&((25.0 / LSB_105) as i32).to_be_bytes());
        r.extend_from_slice(&u16b(4095));
        if let Some(fl) = fl {
            r.extend_from_slice(&fl.to_be_bytes());
        }
        r.extend_from_slice(accuracies);
        r
    }

    /// APC sigma x 10 m and y 0, ABA 50 ft, ATV sigma vx 1 m/s and vy 0.
    const ACCURACIES: [u8; 8] = [0x8C, 0, 20, 0, 0, 2, 4, 0];

    #[test]
    fn estimated_accuracies_become_uncertainty() {
        let p = parser();
        let t = p
            .parse_block(&block(62, &track_with_accuracies(None, &ACCURACIES)))
            .unwrap()
            .remove(0);
        assert_eq!(t.position_sd_m, Some((10.0, 0.0)));
        assert!(
            (t.accuracy_v_m.unwrap() - 15.24).abs() < 1e-6,
            "{:?}",
            t.accuracy_v_m
        );
        assert_eq!(t.velocity_sd_mps, Some((1.0, 0.0)));
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(attr(&ev, "position_accuracy_h_m"), Some("10.00"));
        assert_eq!(meta(&ev, "position_sd_x_m"), Some("10.00"));
        assert_eq!(
            attr(&ev, "position_accuracy_v_m"),
            None,
            "no altitude for the vertical sigma to describe"
        );
        assert_eq!(attr(&ev, "speed_accuracy"), Some("1.00"));
        assert_eq!(attr(&ev, "alt_id"), Some("62:25:10:4095"));
        assert_eq!(attr(&ev, "alt_id_standard"), Some("ASTERIX"));
    }

    #[test]
    fn vertical_accuracy_needs_flight_level() {
        let p = parser();
        let r = track_with_accuracies(Some(1400), &ACCURACIES);
        let t = p.parse_block(&block(62, &r)).unwrap().remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(attr(&ev, "position_accuracy_v_m"), Some("15.24"));
    }

    #[test]
    fn zero_sigma_is_not_published() {
        let p = parser();
        // APC only, all zero.
        let r = track_with_accuracies(None, &[0x80, 0, 0, 0, 0]);
        let t = p.parse_block(&block(62, &r)).unwrap().remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(attr(&ev, "position_accuracy_h_m"), None);
        assert_eq!(meta(&ev, "position_sd_x_m"), Some("0.00"));
    }
}
