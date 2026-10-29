// SPDX-License-Identifier: Apache-2.0
//! CAT021 ADS-B target reports, Edition 2.x. Position is WGS-84.

use super::field::{Field, Item};
use super::wire::{aircraft_id, be_uint, mode_3a, signed};
use super::{AsterixTarget, ANGLE_16, CAT021, SPEED_LSB_KN};

#[rustfmt::skip]
pub(super) const UAP: &[(Item, Field)] = &[
    (Item(10), Field::Fixed(2)),       // 1  Data Source Identification
    (Item(40), Field::Extended(1)),    // 2  Target Report Descriptor
    (Item(161), Field::Fixed(2)),      // 3  Track Number
    (Item(15), Field::Fixed(1)),       // 4  Service Identification
    (Item(71), Field::Fixed(3)),       // 5  Time of Applicability for Position
    (Item(130), Field::Fixed(6)),      // 6  Position WGS-84
    (Item(131), Field::Fixed(8)),      // 7  High-Resolution Position WGS-84
    (Item(72), Field::Fixed(3)),       // 8  Time of Applicability for Velocity
    (Item(150), Field::Fixed(2)),      // 9  Air Speed
    (Item(151), Field::Fixed(2)),      // 10 True Airspeed
    (Item(80), Field::Fixed(3)),       // 11 Target Address
    (Item(73), Field::Fixed(3)),       // 12 Time of Message Reception for Position
    (Item(74), Field::Fixed(4)),       // 13 Time of Message Reception for Position, High Precision
    (Item(75), Field::Fixed(3)),       // 14 Time of Message Reception for Velocity
    (Item(76), Field::Fixed(4)),       // 15 Time of Message Reception for Velocity, High Precision
    (Item(140), Field::Fixed(2)),      // 16 Geometric Height
    (Item(90), Field::Extended(1)),    // 17 Quality Indicators
    (Item(210), Field::Fixed(1)),      // 18 MOPS Version
    (Item(70), Field::Fixed(2)),       // 19 Mode 3/A Code
    (Item(230), Field::Fixed(2)),      // 20 Roll Angle
    (Item(145), Field::Fixed(2)),      // 21 Flight Level
    (Item(152), Field::Fixed(2)),      // 22 Magnetic Heading
    (Item(200), Field::Fixed(1)),      // 23 Target Status
    (Item(155), Field::Fixed(2)),      // 24 Barometric Vertical Rate
    (Item(157), Field::Fixed(2)),      // 25 Geometric Vertical Rate
    (Item(160), Field::Fixed(4)),      // 26 Airborne Ground Vector
    (Item(165), Field::Fixed(2)),      // 27 Track Angle Rate
    (Item(77), Field::Fixed(3)),       // 28 Time of Report Transmission
    (Item(170), Field::Fixed(6)),      // 29 Target Identification
    (Item(20), Field::Fixed(1)),       // 30 Emitter Category
    (Item(220), Field::Opaque),        // 31 Met Information
    (Item(146), Field::Fixed(2)),      // 32 Selected Altitude
    (Item(148), Field::Fixed(2)),      // 33 Final State Selected Altitude
    (Item(110), Field::Opaque),        // 34 Trajectory Intent
    (Item(16), Field::Fixed(1)),       // 35 Service Management
    (Item(8), Field::Fixed(1)),        // 36 Aircraft Operational Status
    (Item(271), Field::Extended(1)),   // 37 Surface Capabilities and Characteristics
    (Item(132), Field::Fixed(1)),      // 38 Message Amplitude
    (Item(250), Field::Repetitive(8)), // 39 Mode S MB Data
    (Item(260), Field::Fixed(7)),      // 40 ACAS Resolution Advisory
    (Item(400), Field::Fixed(1)),      // 41 Receiver ID
    (Item(295), Field::Opaque),        // 42 Data Ages
    (Item::RE, Field::Explicit),       // 43 Reserved Expansion Field
    (Item::SP, Field::Explicit),       // 44 Special Purpose Field
];

/// I021/130 latitude and longitude LSB, degrees.
const LSB_130: f64 = 180.0 / (1u32 << 23) as f64;
/// I021/131 latitude and longitude LSB, degrees.
const LSB_131: f64 = 180.0 / (1u64 << 30) as f64;

pub(super) fn decode(items: &[(Item, &[u8])]) -> AsterixTarget {
    let mut t = AsterixTarget {
        category: CAT021,
        ..Default::default()
    };
    for &(id, item) in items {
        match id {
            Item(10) => (t.sac, t.sic) = (item[0], item[1]),
            Item(161) => t.track = Some(u16::from_be_bytes([item[0], item[1]]) as u32),
            Item(130) => t.set_pos(signed(item, 0, 3) * LSB_130, signed(item, 3, 3) * LSB_130),
            Item(131) => t.set_pos(signed(item, 0, 4) * LSB_131, signed(item, 4, 4) * LSB_131),
            Item(80) => t.icao = Some(be_uint(item, 0, 3) as u32),
            Item(140) => t.alt_ft = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 6.25),
            Item(70) => t.squawk = Some(mode_3a(u16::from_be_bytes([item[0], item[1]]))),
            Item(145) => {
                t.alt_ft
                    .get_or_insert(i16::from_be_bytes([item[0], item[1]]) as f64 * 25.0);
            }
            Item(160) => {
                let gs = u16::from_be_bytes([item[0], item[1]]);
                let ta = u16::from_be_bytes([item[2], item[3]]);
                t.ground_speed_kn = Some(gs as f64 * SPEED_LSB_KN);
                t.track_angle_deg = Some(ta as f64 * ANGLE_16);
            }
            Item(170) => t.callsign = aircraft_id(item),
            Item(20) => t.emitter = emitter_category(item[0]),
            _ => {}
        }
    }
    t
}

/// I021/020 Emitter Category.
fn emitter_category(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "light",
        2 => "small",
        3 => "medium",
        4 => "high-vortex",
        5 => "heavy",
        6 => "high-performance",
        7 => "rotorcraft",
        10 => "glider",
        11 => "lighter-than-air",
        12 => "uav",
        13 => "space",
        20 => "emergency-vehicle",
        21 => "service-vehicle",
        _ => return None,
    })
}
