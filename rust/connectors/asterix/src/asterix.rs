// SPDX-License-Identifier: Apache-2.0
//! EUROCONTROL ASTERIX -> canonical Ajar events. Handles the surveillance
//! categories a radar head or its processing chain emits:
//!  - **CAT010** monosensor surface movement reports (airport surface and, for
//!    coastal and naval surveillance radars, sea-surface targets; WGS-84, polar
//!    or Cartesian position, the latter two geolocated against a sensor site).
//!  - **CAT021** ADS-B target reports (cooperative traffic, WGS-84 position).
//!  - **CAT034** monoradar service messages: the radar's own heartbeat. Its
//!    status is tracked per radar and emitted once per antenna rotation as a
//!    signed `mim:sensor` event (jamming strobes emit too); sector crossings are
//!    counted, not published.
//!  - **CAT048** monoradar target reports (primary + Mode S/SSR; position is
//!    radar-relative polar, geolocated against a configured sensor site).
//!  - **CAT062** SDPS system tracks (the fused, recognised air picture; WGS-84
//!    position).
//!
//! An ASTERIX data block is `CAT | LEN | record…`; one UDP datagram can carry
//! several records, so one frame maps to several events. Each record begins with a
//! variable-length FSPEC bitmap naming the data items present, in the fixed order
//! of the category's User Application Profile (UAP). The engine is category-generic:
//! a [`Field`] length model per UAP lets it walk past any item to the next record,
//! and each category supplies a UAP table plus a decoder. The whole raw record is
//! sealed verbatim into the signed `Event.payload`.
//!
//! This is an untrusted edge, so every length is bounds-checked before it is read;
//! the decoder never panics and never emits a misaligned position. Validate the
//! UAP against your feed's edition before operational use.

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

const CAT010: u8 = 10;
const CAT021: u8 = 21;
const CAT034: u8 = 34;
const CAT048: u8 = 48;
const CAT062: u8 = 62;

/// 1 knot in metres/second — the governed `speed` attribute is m/s (ADR-0019).
const KNOTS_TO_MPS: f64 = 0.514_444;
/// 1 nautical mile in metres.
const NM_TO_M: f64 = 1852.0;
/// LSB of an ASTERIX 16-bit binary angle: 360 / 2^16 degrees.
const ANGLE_16: f64 = 360.0 / 65_536.0;

/// Why an ASTERIX block or record could not be decoded.
#[derive(Debug, PartialEq, Eq)]
pub enum AsterixError {
    /// The block header (CAT + 2-byte length) was incomplete or inconsistent.
    BadBlock {
        /// The block's category byte, when one could be read.
        cat: Option<u8>,
        /// The block's declared length and the bytes actually available.
        declared: usize,
        have: usize,
    },
    /// A data item ran past the end of the buffer.
    Truncated,
    /// A record referenced a UAP item this decoder does not length-model; it stops
    /// rather than misalign. (See the module scope note.)
    UnsupportedItem { cat: u8, frn: u8 },
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for AsterixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsterixError::BadBlock {
                cat,
                declared,
                have,
            } => match cat {
                Some(c) => write!(
                    f,
                    "malformed ASTERIX data block: CAT{c:03} declares {declared} bytes, \
                     {have} available"
                ),
                None => write!(
                    f,
                    "malformed ASTERIX data block: {have} bytes is too short for a \
                     category and length"
                ),
            },
            AsterixError::Truncated => write!(f, "ASTERIX item runs past end of block"),
            AsterixError::UnsupportedItem { cat, frn } => {
                write!(
                    f,
                    "CAT{cat:03} FRN {frn} is not length-modelled by this decoder; the \
                     rest of this data block is dropped rather than misread"
                )
            }
            AsterixError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for AsterixError {}

/// The `(FRN, item-bytes)` pairs a record walk yields.
type Items<'a> = Vec<(u8, &'a [u8])>;

// ============================================================================
// Length engine — how to measure a UAP item so the record walk can skip it.
// ============================================================================

/// How to measure a UAP (or compound sub-) item's octet length.
#[derive(Clone, Copy)]
enum Field {
    /// A fixed number of octets.
    Fixed(usize),
    /// FX-chained: `unit`-octet extents continue while the low bit of each extent's
    /// last octet is set. (`unit` is 1 for almost everything; 3 for I062/510.)
    Extended(usize),
    /// A one-octet repetition count, then that many `N`-octet items.
    Repetitive(usize),
    /// A one-octet total-length prefix (value includes itself) — ASTERIX "Explicit"
    /// (the RE / SP items).
    Explicit,
    /// An FX-chained primary subfield bitmap, then the present subfields in bit
    /// order (bit 8 of octet 1 first, FX/low bit excluded). `Spare` marks a bit
    /// position with no subfield.
    Compound(&'static [Field]),
    /// A bit position inside a compound primary bitmap that carries no subfield.
    Spare,
    /// A complex item this decoder does not length-model; a record containing it
    /// stops with `UnsupportedItem` rather than risk a misaligned walk.
    Opaque,
}

/// The octet length of the `field` starting at `data[off]`, or `None` if it can't
/// be measured (truncated, or `Opaque`). Recurses for `Compound`.
fn field_len(field: Field, data: &[u8], off: usize) -> Option<usize> {
    match field {
        Field::Fixed(n) => Some(n),
        Field::Spare => Some(0),
        Field::Extended(unit) => {
            let mut n = 0;
            loop {
                let last = off.checked_add(n + unit)?.checked_sub(1)?;
                if last >= data.len() {
                    return None;
                }
                n += unit;
                if data[last] & 0x01 == 0 {
                    return Some(n);
                }
            }
        }
        Field::Repetitive(item) => {
            let rep = *data.get(off)? as usize;
            Some(1 + rep * item)
        }
        Field::Explicit => Some(*data.get(off)? as usize),
        Field::Compound(subs) => {
            // Primary bitmap: FX-chained octets; each contributes 7 presence bits.
            let bits = primary_bits(data, off)?;
            let mut total = bits.len().div_ceil(7); // octets consumed by the bitmap
            for (i, &present) in bits.iter().enumerate() {
                if present {
                    let sub = *subs.get(i)?;
                    total += field_len(sub, data, off + total)?;
                }
            }
            Some(total)
        }
        Field::Opaque => None,
    }
}

/// The presence bits of an FX-chained primary bitmap starting at `data[off]`,
/// bit 8 first, excluding the FX (low) bit of each octet. 7 bits per octet.
fn primary_bits(data: &[u8], mut off: usize) -> Option<Vec<bool>> {
    let mut bits = Vec::new();
    loop {
        let octet = *data.get(off)?;
        off += 1;
        for b in 0..7 {
            bits.push(octet & (0x80 >> b) != 0);
        }
        if octet & 0x01 == 0 {
            return Some(bits);
        }
    }
}

// ============================================================================
// CAT021 — ADS-B target reports (Edition 2.x). WGS-84 position.
// ============================================================================

#[rustfmt::skip]
const UAP021: &[Field] = &[
    Field::Fixed(2),      // 1  I021/010 Data Source Identification
    Field::Extended(1),   // 2  I021/040 Target Report Descriptor
    Field::Fixed(2),      // 3  I021/161 Track Number
    Field::Fixed(1),      // 4  I021/015 Service Identification
    Field::Fixed(3),      // 5  I021/071 Time of Applicability for Position
    Field::Fixed(6),      // 6  I021/130 Position WGS-84
    Field::Fixed(8),      // 7  I021/131 High-Resolution Position WGS-84
    Field::Fixed(3),      // 8  I021/072 Time of Applicability for Velocity
    Field::Fixed(2),      // 9  I021/150 Air Speed
    Field::Fixed(2),      // 10 I021/151 True Airspeed
    Field::Fixed(3),      // 11 I021/080 Target Address
    Field::Fixed(3),      // 12 I021/073 Time of Message Reception for Position
    Field::Fixed(4),      // 13 I021/074 …High Precision
    Field::Fixed(3),      // 14 I021/075 Time of Message Reception for Velocity
    Field::Fixed(4),      // 15 I021/076 …High Precision
    Field::Fixed(2),      // 16 I021/140 Geometric Height
    Field::Extended(1),   // 17 I021/090 Quality Indicators
    Field::Fixed(1),      // 18 I021/210 MOPS Version
    Field::Fixed(2),      // 19 I021/070 Mode 3/A Code
    Field::Fixed(2),      // 20 I021/230 Roll Angle
    Field::Fixed(2),      // 21 I021/145 Flight Level
    Field::Fixed(2),      // 22 I021/152 Magnetic Heading
    Field::Fixed(1),      // 23 I021/200 Target Status
    Field::Fixed(2),      // 24 I021/155 Barometric Vertical Rate
    Field::Fixed(2),      // 25 I021/157 Geometric Vertical Rate
    Field::Fixed(4),      // 26 I021/160 Airborne Ground Vector
    Field::Fixed(2),      // 27 I021/165 Track Angle Rate
    Field::Fixed(3),      // 28 I021/077 Time of Report Transmission
    Field::Fixed(6),      // 29 I021/170 Target Identification
    Field::Fixed(1),      // 30 I021/020 Emitter Category
    Field::Opaque,        // 31 I021/220 Met Information (compound, not modelled)
    Field::Fixed(2),      // 32 I021/146 Selected Altitude
    Field::Fixed(2),      // 33 I021/148 Final State Selected Altitude
    Field::Opaque,        // 34 I021/110 Trajectory Intent (compound, not modelled)
    Field::Fixed(1),      // 35 I021/016 Service Management
    Field::Fixed(1),      // 36 I021/008 Aircraft Operational Status
    Field::Extended(1),   // 37 I021/271 Surface Capabilities and Characteristics
    Field::Fixed(1),      // 38 I021/132 Message Amplitude
    Field::Repetitive(8), // 39 I021/250 Mode S MB Data
    Field::Fixed(7),      // 40 I021/260 ACAS Resolution Advisory
    Field::Fixed(1),      // 41 I021/400 Receiver ID
    Field::Opaque,        // 42 I021/295 Data Ages (compound, not modelled)
    Field::Explicit,      // 43 RE Reserved Expansion Field
    Field::Explicit,      // 44 SP Special Purpose Field
];

// I021/130 lat/lon: 24-bit signed, LSB 180/2^23; I021/131: 32-bit signed, 180/2^30.
const LSB_130: f64 = 180.0 / (1u32 << 23) as f64;
const LSB_131: f64 = 180.0 / (1u64 << 30) as f64;

fn decode_021(items: &[(u8, &[u8])]) -> AsterixTarget {
    let mut t = AsterixTarget::new(CAT021);
    for &(frn, item) in items {
        match frn {
            1 => (t.sac, t.sic) = (item[0], item[1]),
            3 => t.track = Some(u16::from_be_bytes([item[0], item[1]]) as u32),
            6 => t.set_pos(signed(item, 0, 3) * LSB_130, signed(item, 3, 3) * LSB_130),
            7 => t.set_pos(signed(item, 0, 4) * LSB_131, signed(item, 4, 4) * LSB_131),
            11 => t.icao = Some(be(item, 0, 3) as u32),
            16 => t.alt_ft = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 6.25),
            19 => t.squawk = Some(mode_3a(u16::from_be_bytes([item[0], item[1]]))),
            21 => {
                t.alt_ft
                    .get_or_insert(i16::from_be_bytes([item[0], item[1]]) as f64 * 25.0);
            }
            26 => {
                let gs = u16::from_be_bytes([item[0], item[1]]);
                let ta = u16::from_be_bytes([item[2], item[3]]);
                t.ground_speed = Some(gs as f64 * 2f64.powi(-14) * 3600.0); // NM/s -> kt
                t.track_angle = Some(ta as f64 * ANGLE_16);
            }
            29 => t.callsign = aircraft_id(item),
            30 => t.emitter = emitter_category(item[0]),
            _ => {}
        }
    }
    t
}

// ============================================================================
// CAT048 — monoradar target reports. Radar-relative polar position.
// ============================================================================

#[rustfmt::skip]
const UAP048: &[Field] = &[
    Field::Fixed(2),                                  // 1  I048/010 Data Source Identifier
    Field::Fixed(3),                                  // 2  I048/140 Time of Day
    Field::Extended(1),                               // 3  I048/020 Target Report Descriptor
    Field::Fixed(4),                                  // 4  I048/040 Measured Position (polar)
    Field::Fixed(2),                                  // 5  I048/070 Mode-3/A Code
    Field::Fixed(2),                                  // 6  I048/090 Flight Level (binary)
    Field::Compound(&SUB_048_130),                    // 7  I048/130 Radar Plot Characteristics
    Field::Fixed(3),                                  // 8  I048/220 Aircraft Address
    Field::Fixed(6),                                  // 9  I048/240 Aircraft Identification
    Field::Repetitive(8),                             // 10 I048/250 Mode S / BDS Register Data
    Field::Fixed(2),                                  // 11 I048/161 Track Number
    Field::Fixed(4),                                  // 12 I048/042 Calculated Position (Cartesian)
    Field::Fixed(4),                                  // 13 I048/200 Calculated Track Velocity (polar)
    Field::Extended(1),                               // 14 I048/170 Track Status
    Field::Fixed(4),                                  // 15 I048/210 Track Quality
    Field::Extended(1),                               // 16 I048/030 Warning/Error Conditions
    Field::Fixed(2),                                  // 17 I048/080 Mode-3/A Confidence
    Field::Fixed(4),                                  // 18 I048/100 Mode-C Code + Confidence
    Field::Fixed(2),                                  // 19 I048/110 Height Measured by 3D Radar
    Field::Compound(&SUB_048_120),                    // 20 I048/120 Radial Doppler Speed
    Field::Fixed(2),                                  // 21 I048/230 Comms/ACAS Capability & Status
    Field::Fixed(7),                                  // 22 I048/260 ACAS Resolution Advisory
    Field::Fixed(1),                                  // 23 I048/055 Mode-1 Code
    Field::Fixed(2),                                  // 24 I048/050 Mode-2 Code
    Field::Fixed(1),                                  // 25 I048/065 Mode-1 Confidence
    Field::Fixed(2),                                  // 26 I048/060 Mode-2 Confidence
    Field::Explicit,                                  // 27 I048/SP Special Purpose
    Field::Explicit,                                  // 28 I048/RE Reserved Expansion
];
/// I048/130 subfields (SRL, SRR, SAM, PRL, PAM, RPD, APD) — each 1 octet.
const SUB_048_130: [Field; 7] = [Field::Fixed(1); 7];
/// I048/120 subfields: CAL (fixed 2), RDS (repetitive, 6 octets/rep).
const SUB_048_120: [Field; 2] = [Field::Fixed(2), Field::Repetitive(6)];

fn decode_048(items: &[(u8, &[u8])], sensor: Option<&Sensor>) -> AsterixTarget {
    let mut t = AsterixTarget::new(CAT048);
    for &(frn, item) in items {
        match frn {
            1 => (t.sac, t.sic) = (item[0], item[1]),
            2 => t.time_of_day = Some(be(item, 0, 3) as f64 / 128.0),
            3 => {
                // I048/020 Target Report Descriptor: the truth bits. SIM
                // (simulated), RAB (field monitor) in the first part; TST
                // (test target) in the first extension when present.
                let o1 = item[0];
                t.simulated = o1 & 0x10 != 0;
                t.field_monitor = o1 & 0x02 != 0;
                if o1 & 0x01 != 0 {
                    if let Some(&ext) = item.get(1) {
                        t.test_target = ext & 0x80 != 0;
                    }
                }
            }
            4 => {
                // Measured position: RHO (LSB 1/256 NM), THETA (LSB 360/2^16 deg).
                // Geolocation happens after the loop: RHO is SLANT range, and
                // the flight level needed to correct it decodes later (FRN 6).
                let rho_nm = u16::from_be_bytes([item[0], item[1]]) as f64 / 256.0;
                let theta = u16::from_be_bytes([item[2], item[3]]) as f64 * ANGLE_16;
                t.polar = Some((rho_nm, theta));
            }
            5 => {
                // V (invalid) or G (garbled) means the code cannot be trusted.
                // An untrusted squawk is omitted, never published as clean.
                let w = u16::from_be_bytes([item[0], item[1]]);
                if w & 0xC000 == 0 {
                    t.squawk = Some(mode_3a(w));
                }
            }
            6 => {
                // Flight level: bits 14..1 signed two's-complement, LSB 25 ft.
                // Same V/G rule as the squawk: garbled altitude is no altitude.
                if item[0] & 0xC0 == 0 {
                    let raw = u16::from_be_bytes([item[0], item[1]]) & 0x3FFF;
                    t.alt_ft = Some(sign_extend(raw as u64, 14) as f64 * 25.0);
                }
            }
            8 => t.icao = Some(be(item, 0, 3) as u32),
            9 => t.callsign = aircraft_id(item),
            11 => t.track = Some((u16::from_be_bytes([item[0], item[1]]) & 0x0FFF) as u32),
            13 => {
                // Calculated velocity: ground speed (LSB 2^-14 NM/s), heading.
                let gs = u16::from_be_bytes([item[0], item[1]]);
                let hd = u16::from_be_bytes([item[2], item[3]]);
                t.ground_speed = Some(gs as f64 * 2f64.powi(-14) * 3600.0); // NM/s -> kt
                t.track_angle = Some(hd as f64 * ANGLE_16);
            }
            _ => {}
        }
    }
    if let (Some((rho_nm, theta)), Some(s)) = (t.polar, sensor) {
        // I048/040 RHO is SLANT range. Project it to ground range with the
        // decoded flight level before the forward solution (pressure altitude
        // as the geometric proxy; the residual is small against the radar's
        // own accuracy, and using the slant range raw overstates ground
        // distance by the whole altitude triangle). A return steeper than
        // vertical is clamped to the site.
        let slant_m = rho_nm * NM_TO_M;
        let height_m = t.alt_ft.map(|ft| ft * 0.3048 - s.alt_m).unwrap_or(0.0);
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

// ============================================================================
// CAT010 — Monosensor surface movement data (Edition 1.1). Airport surface
// (SMR, MLAT, ADS-B) and, for coastal and naval surveillance radars, sea
// surface. Position is WGS-84, polar (metres) or Cartesian offsets from the
// sensor reference point.
// ============================================================================

#[rustfmt::skip]
const UAP010: &[Field] = &[
    Field::Fixed(2),                                  // 1  I010/010 Data Source Identifier
    Field::Fixed(1),                                  // 2  I010/000 Message Type
    Field::Extended(1),                               // 3  I010/020 Target Report Descriptor
    Field::Fixed(3),                                  // 4  I010/140 Time of Day
    Field::Fixed(8),                                  // 5  I010/041 Position in WGS-84
    Field::Fixed(4),                                  // 6  I010/040 Measured Position (polar)
    Field::Fixed(4),                                  // 7  I010/042 Position (Cartesian)
    Field::Fixed(4),                                  // 8  I010/200 Calculated Track Velocity (polar)
    Field::Fixed(4),                                  // 9  I010/202 Calculated Track Velocity (Cartesian)
    Field::Fixed(2),                                  // 10 I010/161 Track Number
    Field::Extended(1),                               // 11 I010/170 Track Status
    Field::Fixed(2),                                  // 12 I010/060 Mode-3/A Code
    Field::Fixed(3),                                  // 13 I010/220 Target Address
    Field::Fixed(7),                                  // 14 I010/245 Target Identification
    Field::Repetitive(8),                             // 15 I010/250 Mode S MB Data
    Field::Fixed(1),                                  // 16 I010/300 Vehicle Fleet Identification
    Field::Fixed(2),                                  // 17 I010/090 Flight Level (binary)
    Field::Fixed(2),                                  // 18 I010/091 Measured Height
    Field::Extended(1),                               // 19 I010/270 Target Size and Orientation
    Field::Fixed(1),                                  // 20 I010/550 System Status
    Field::Fixed(1),                                  // 21 I010/310 Pre-programmed Message
    Field::Fixed(4),                                  // 22 I010/500 Standard Deviation of Position
    Field::Repetitive(2),                             // 23 I010/280 Presence
    Field::Fixed(1),                                  // 24 I010/131 Amplitude of Primary Plot
    Field::Fixed(2),                                  // 25 I010/210 Calculated Acceleration
    Field::Spare,                                     // 26 spare
    Field::Explicit,                                  // 27 I010/SP Special Purpose
    Field::Explicit,                                  // 28 I010/RE Reserved Expansion
];
/// LSB of I010/041 latitude and longitude: 180 / 2^31 degrees.
const LSB_041: f64 = 180.0 / (1u64 << 31) as f64;
/// I010/000 message type that carries a target; the rest are status messages.
const CAT010_TARGET_REPORT: u8 = 1;

fn decode_010(items: &[(u8, &[u8])], sensor: Option<&Sensor>) -> AsterixTarget {
    let mut t = AsterixTarget::new(CAT010);
    for &(frn, item) in items {
        match frn {
            1 => (t.sac, t.sic) = (item[0], item[1]),
            2 => t.message_type = Some(item[0]),
            3 => {
                // I010/020: TYP (bits 8-6) names the sensor technique; the
                // truth bits SIM/TST/RAB sit in the first extension.
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
            4 => t.time_of_day = Some(be(item, 0, 3) as f64 / 128.0),
            5 => {
                let lat = signed(item, 0, 4) * LSB_041;
                let lon = signed(item, 4, 4) * LSB_041;
                t.set_pos(lat, lon);
            }
            6 => {
                // Measured position: RHO in metres (LSB 1 m), THETA 360/2^16.
                // Kept in NM in `polar` so one field means one thing across
                // categories; a surface target needs no slant correction.
                let rho_m = u16::from_be_bytes([item[0], item[1]]) as f64;
                let theta = u16::from_be_bytes([item[2], item[3]]) as f64 * ANGLE_16;
                t.polar = Some((rho_m / NM_TO_M, theta));
            }
            7 => {
                // Cartesian offsets from the sensor reference point, metres:
                // X east, Y north.
                let x = signed(item, 0, 2);
                let y = signed(item, 2, 2);
                t.cartesian = Some((x, y));
            }
            8 => {
                let gs = u16::from_be_bytes([item[0], item[1]]);
                let hd = u16::from_be_bytes([item[2], item[3]]);
                t.ground_speed = Some(gs as f64 * 2f64.powi(-14) * 3600.0); // NM/s -> kt
                t.track_angle = Some(hd as f64 * ANGLE_16);
            }
            9 => {
                // Cartesian velocity, LSB 0.25 m/s: Vx east, Vy north.
                let vx = signed(item, 0, 2) * 0.25;
                let vy = signed(item, 2, 2) * 0.25;
                let speed_mps = (vx * vx + vy * vy).sqrt();
                t.ground_speed = Some(speed_mps / KNOTS_TO_MPS);
                if speed_mps > 0.0 {
                    t.track_angle = Some(vx.atan2(vy).to_degrees().rem_euclid(360.0));
                }
            }
            10 => t.track = Some((u16::from_be_bytes([item[0], item[1]]) & 0x0FFF) as u32),
            12 => {
                let w = u16::from_be_bytes([item[0], item[1]]);
                if w & 0xC000 == 0 {
                    t.squawk = Some(mode_3a(w));
                }
            }
            13 => t.icao = Some(be(item, 0, 3) as u32),
            14 => t.callsign = aircraft_id(&item[1..7]),
            16 => t.vehicle_fleet = vehicle_fleet(item[0]),
            17 => {
                if item[0] & 0xC0 == 0 {
                    let raw = u16::from_be_bytes([item[0], item[1]]) & 0x3FFF;
                    t.alt_ft = Some(sign_extend(raw as u64, 14) as f64 * 25.0);
                }
            }
            18 => t.alt_ft = Some(signed(item, 0, 2) * 6.25),
            19 => {
                // Target size and orientation: LENGTH (m), then ORIENTATION
                // (360/128 deg) and WIDTH (m) in the extensions.
                let length = (item[0] >> 1) as f64;
                let orientation = item.get(1).map(|o| (o >> 1) as f64 * 360.0 / 128.0);
                let width = item.get(2).map(|o| (o >> 1) as f64);
                t.size = Some((length, width, orientation));
            }
            22 => {
                // Standard deviation of position, LSB 0.25 m.
                t.position_sd = Some((item[0] as f64 * 0.25, item[1] as f64 * 0.25));
            }
            _ => {}
        }
    }
    if t.lat.is_none() {
        if let Some(s) = sensor {
            if let Some((rho_nm, theta)) = t.polar {
                // Surface targets: the measured range is the ground range.
                let (lat, lon) = forward_geodetic(s.lat, s.lon, theta, rho_nm * NM_TO_M);
                t.set_pos(lat, lon);
            } else if let Some((x, y)) = t.cartesian {
                let dist = (x * x + y * y).sqrt();
                let bearing = x.atan2(y).to_degrees().rem_euclid(360.0);
                let (lat, lon) = forward_geodetic(s.lat, s.lon, bearing, dist);
                t.set_pos(lat, lon);
            }
        }
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

// ============================================================================
// CAT034 — Monoradar service messages (Edition 1.27): the radar talking about
// itself. North marker once per antenna rotation, sector crossings between,
// system status when it changes, jamming strobes when it sees them.
// ============================================================================

#[rustfmt::skip]
const UAP034: &[Field] = &[
    Field::Fixed(2),                                  // 1  I034/010 Data Source Identifier
    Field::Fixed(1),                                  // 2  I034/000 Message Type
    Field::Fixed(3),                                  // 3  I034/030 Time of Day
    Field::Fixed(1),                                  // 4  I034/020 Sector Number
    Field::Fixed(2),                                  // 5  I034/041 Antenna Rotation Speed
    Field::Compound(&SUB_034_050),                    // 6  I034/050 System Configuration and Status
    Field::Compound(&SUB_034_060),                    // 7  I034/060 System Processing Mode
    Field::Repetitive(2),                             // 8  I034/070 Message Count Values
    Field::Fixed(8),                                  // 9  I034/100 Generic Polar Window
    Field::Fixed(1),                                  // 10 I034/110 Data Filter
    Field::Fixed(8),                                  // 11 I034/120 3D-Position of Data Source
    Field::Fixed(2),                                  // 12 I034/090 Collimation Error
    Field::Explicit,                                  // 13 I034/RE Reserved Expansion
    Field::Explicit,                                  // 14 I034/SP Special Purpose
];
/// I034/050 subfields: COM (1), spare, spare, PSR (1), SSR (1), MDS (2), spare.
const SUB_034_050: [Field; 7] = [
    Field::Fixed(1),
    Field::Spare,
    Field::Spare,
    Field::Fixed(1),
    Field::Fixed(1),
    Field::Fixed(2),
    Field::Spare,
];
/// I034/060 subfields: COM (1), spare, spare, PSR (1), SSR (1), MDS (1), spare.
const SUB_034_060: [Field; 7] = [
    Field::Fixed(1),
    Field::Spare,
    Field::Spare,
    Field::Fixed(1),
    Field::Fixed(1),
    Field::Fixed(1),
    Field::Spare,
];
/// LSB of I034/120 latitude and longitude: 180 / 2^23 degrees.
const LSB_120: f64 = 180.0 / (1u64 << 23) as f64;

/// I034/000 message types.
const NORTH_MARKER: u8 = 1;
const SECTOR_CROSSING: u8 = 2;
const JAMMING_STROBE: u8 = 4;
const SSR_JAMMING_STROBE: u8 = 6;
const MODE_S_JAMMING_STROBE: u8 = 7;

/// A radar's self-reported health, from I034/050 COM/PSR/SSR/MDS. Every field
/// is `None` until the radar has said so; a status message never carries all
/// of them, so the parser merges each new message into the last known state.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RadarStatus {
    /// NOGO: the radar declares itself not operational.
    pub nogo: Option<bool>,
    /// Radar data processor overload.
    pub rdp_overload: Option<bool>,
    /// Transmission subsystem overload.
    pub xmt_overload: Option<bool>,
    /// Monitoring system disconnected.
    pub monitoring_disconnected: Option<bool>,
    /// Time source invalid.
    pub time_source_invalid: Option<bool>,
    /// Primary radar overload.
    pub psr_overload: Option<bool>,
    /// Secondary radar overload.
    pub ssr_overload: Option<bool>,
    /// Mode S surveillance overload.
    pub mds_overload: Option<bool>,
}

impl RadarStatus {
    fn merge(&mut self, other: RadarStatus) {
        macro_rules! take {
            ($($f:ident),*) => { $( if other.$f.is_some() { self.$f = other.$f; } )* };
        }
        take!(
            nogo,
            rdp_overload,
            xmt_overload,
            monitoring_disconnected,
            time_source_invalid,
            psr_overload,
            ssr_overload,
            mds_overload
        );
    }
    /// Any overload or NOGO the radar has reported.
    fn degraded(&self) -> bool {
        [
            self.nogo,
            self.rdp_overload,
            self.xmt_overload,
            self.psr_overload,
            self.ssr_overload,
            self.mds_overload,
        ]
        .contains(&Some(true))
    }
}

/// One decoded CAT034 record.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceReport {
    pub sac: u8,
    pub sic: u8,
    /// I034/000 message type.
    pub message_type: u8,
    /// Time of day, seconds since UTC midnight.
    pub time_of_day: Option<f64>,
    /// I034/020 sector number (0..=255, 360/256 degrees each).
    pub sector: Option<u8>,
    /// Antenna rotation period in seconds (I034/041).
    pub rotation_period_s: Option<f64>,
    /// The radar's own position from I034/120: latitude, longitude, height (m).
    pub position: Option<(f64, f64, f64)>,
    /// Status carried by this record alone (merged into the parser's per-radar
    /// state; `is_none` fields mean "not in this message").
    pub status: RadarStatus,
    /// I034/100 polar window: range start/end (NM), azimuth start/end (deg).
    pub window: Option<(f64, f64, f64, f64)>,
    /// The raw bytes of this record, preserved verbatim in the signed payload.
    pub raw: Vec<u8>,
}

impl ServiceReport {
    /// The message types that become events: the once-per-rotation heartbeat
    /// and the strobes that say the radar is being jammed.
    fn is_published(&self) -> bool {
        matches!(
            self.message_type,
            NORTH_MARKER | JAMMING_STROBE | SSR_JAMMING_STROBE | MODE_S_JAMMING_STROBE
        )
    }
    fn message_name(&self) -> &'static str {
        match self.message_type {
            NORTH_MARKER => "north-marker",
            SECTOR_CROSSING => "sector-crossing",
            3 => "geographical-filtering",
            JAMMING_STROBE => "jamming-strobe",
            5 => "solar-storm",
            SSR_JAMMING_STROBE => "ssr-jamming-strobe",
            MODE_S_JAMMING_STROBE => "mode-s-jamming-strobe",
            _ => "unknown",
        }
    }
}

fn decode_034(items: &[(u8, &[u8])]) -> ServiceReport {
    let mut r = ServiceReport {
        sac: 0,
        sic: 0,
        message_type: 0,
        time_of_day: None,
        sector: None,
        rotation_period_s: None,
        position: None,
        status: RadarStatus::default(),
        window: None,
        raw: Vec::new(),
    };
    for &(frn, item) in items {
        match frn {
            1 => (r.sac, r.sic) = (item[0], item[1]),
            2 => r.message_type = item[0],
            3 => r.time_of_day = Some(be(item, 0, 3) as f64 / 128.0),
            4 => r.sector = Some(item[0]),
            5 => r.rotation_period_s = Some(u16::from_be_bytes([item[0], item[1]]) as f64 / 128.0),
            6 => {
                for (sub, bytes) in walk_compound(&SUB_034_050, item) {
                    match sub {
                        0 => {
                            let com = bytes[0];
                            r.status.nogo = Some(com & 0x80 != 0);
                            r.status.rdp_overload = Some(com & 0x10 != 0);
                            r.status.xmt_overload = Some(com & 0x08 != 0);
                            r.status.monitoring_disconnected = Some(com & 0x04 != 0);
                            r.status.time_source_invalid = Some(com & 0x02 != 0);
                        }
                        3 => r.status.psr_overload = Some(bytes[0] & 0x10 != 0),
                        4 => r.status.ssr_overload = Some(bytes[0] & 0x10 != 0),
                        5 => r.status.mds_overload = Some(bytes[0] & 0x10 != 0),
                        _ => {}
                    }
                }
            }
            9 => {
                let rho_start = u16::from_be_bytes([item[0], item[1]]) as f64 / 256.0;
                let rho_end = u16::from_be_bytes([item[2], item[3]]) as f64 / 256.0;
                let theta_start = u16::from_be_bytes([item[4], item[5]]) as f64 * ANGLE_16;
                let theta_end = u16::from_be_bytes([item[6], item[7]]) as f64 * ANGLE_16;
                r.window = Some((rho_start, rho_end, theta_start, theta_end));
            }
            11 => {
                let height = signed(item, 0, 2);
                let lat = signed(item, 2, 3) * LSB_120;
                let lon = signed(item, 5, 3) * LSB_120;
                r.position = Some((lat, lon, height));
            }
            _ => {}
        }
    }
    r
}

// ============================================================================
// CAT062 — SDPS system tracks (fused air picture). WGS-84 position.
// ============================================================================

#[rustfmt::skip]
const UAP062: &[Field] = &[
    Field::Fixed(2),                // 1  I062/010 Data Source Identifier
    Field::Opaque,                  // 2  (spare / unassigned)
    Field::Fixed(1),                // 3  I062/015 Service Identification
    Field::Fixed(3),                // 4  I062/070 Time Of Track Information
    Field::Fixed(8),                // 5  I062/105 Calculated Position WGS-84
    Field::Fixed(6),                // 6  I062/100 Calculated Track Position (Cartesian)
    Field::Fixed(4),                // 7  I062/185 Calculated Track Velocity (Cartesian)
    Field::Fixed(2),                // 8  I062/210 Calculated Acceleration
    Field::Fixed(2),                // 9  I062/060 Track Mode 3/A Code
    Field::Fixed(7),                // 10 I062/245 Target Identification
    Field::Compound(&SUB_062_380),  // 11 I062/380 Aircraft Derived Data
    Field::Fixed(2),                // 12 I062/040 Track Number
    Field::Extended(1),             // 13 I062/080 Track Status
    Field::Compound(&SUB_062_290),  // 14 I062/290 System Track Update Ages
    Field::Fixed(1),                // 15 I062/200 Mode of Movement
    Field::Compound(&SUB_062_295),  // 16 I062/295 Track Data Ages
    Field::Fixed(2),                // 17 I062/136 Measured Flight Level
    Field::Fixed(2),                // 18 I062/130 Calculated Geometric Altitude
    Field::Fixed(2),                // 19 I062/135 Calculated Barometric Altitude
    Field::Fixed(2),                // 20 I062/220 Calculated Rate of Climb/Descent
    Field::Compound(&SUB_062_390),  // 21 I062/390 Flight Plan Related Data
    Field::Extended(1),             // 22 I062/270 Target Size & Orientation
    Field::Fixed(1),                // 23 I062/300 Vehicle Fleet Identification
    Field::Compound(&SUB_062_110),  // 24 I062/110 Mode 5 Data
    Field::Fixed(2),                // 25 I062/120 Track Mode 2 Code
    Field::Extended(3),             // 26 I062/510 Composed Track Number (3-octet units)
    Field::Compound(&SUB_062_500),  // 27 I062/500 Estimated Accuracies
    Field::Compound(&SUB_062_340),  // 28 I062/340 Measured Information
    Field::Opaque,                  // 29 (spare)
    Field::Opaque,                  // 30 (spare)
    Field::Opaque,                  // 31 (spare)
    Field::Opaque,                  // 32 (spare)
    Field::Opaque,                  // 33 (spare)
    Field::Explicit,                // 34 I062/RE Reserved Expansion
    Field::Explicit,                // 35 I062/SP Special Purpose
];

// I062/105 lat/lon: 32-bit signed, LSB 180/2^25 degrees.
const LSB_105: f64 = 180.0 / (1u64 << 25) as f64;

/// I062/380 Aircraft Derived Data subfields (bit order; TIS/TID/MB are variable).
#[rustfmt::skip]
const SUB_062_380: [Field; 28] = [
    Field::Fixed(3),      // ADR Target Address (ICAO 24-bit)
    Field::Fixed(6),      // ID  Target Identification (callsign)
    Field::Fixed(2),      // MHG Magnetic Heading
    Field::Fixed(2),      // IAS Indicated Airspeed / Mach
    Field::Fixed(2),      // TAS True Airspeed
    Field::Fixed(2),      // SAL Selected Altitude
    Field::Fixed(2),      // FSS Final State Selected Altitude
    Field::Extended(1),   // TIS Trajectory Intent Status
    Field::Repetitive(15),// TID Trajectory Intent Data
    Field::Fixed(2),      // COM Comms/ACAS Capability
    Field::Fixed(2),      // SAB Status reported by ADS-B
    Field::Fixed(7),      // ACS ACAS Resolution Advisory
    Field::Fixed(2),      // BVR Barometric Vertical Rate
    Field::Fixed(2),      // GVR Geometric Vertical Rate
    Field::Fixed(2),      // RAN Roll Angle
    Field::Fixed(2),      // TAR Track Angle Rate
    Field::Fixed(2),      // TAN Track Angle
    Field::Fixed(2),      // GSP Ground Speed
    Field::Fixed(1),      // VUN Velocity Uncertainty
    Field::Fixed(8),      // MET Meteorological Data
    Field::Fixed(1),      // EMC Emitter Category
    Field::Fixed(6),      // POS Position (WGS-84)
    Field::Fixed(2),      // GAL Geometric Altitude
    Field::Fixed(1),      // PUN Position Uncertainty
    Field::Repetitive(8), // MB  Mode-S MB Data
    Field::Fixed(2),      // IAR Indicated Airspeed
    Field::Fixed(2),      // MAC Mach Number
    Field::Fixed(2),      // BPS Barometric Pressure Setting
];

/// I062/290 System Track Update Ages subfields (ADS is 2 bytes; the rest 1).
#[rustfmt::skip]
const SUB_062_290: [Field; 14] = [
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), // TRK PSR SSR MDS
    Field::Fixed(2), Field::Fixed(1), Field::Fixed(1),                  // ADS(2) ES VDL
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),                  // UAT LOP MLT
    Field::Spare, Field::Spare, Field::Spare, Field::Spare,
];

/// I062/295 Track Data Ages subfields — 31 one-octet ages, then spares.
#[rustfmt::skip]
const SUB_062_295: [Field; 35] = [
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1),
    Field::Spare, Field::Spare, Field::Spare, Field::Spare,
];

/// I062/500 Estimated Accuracies subfields.
#[rustfmt::skip]
const SUB_062_500: [Field; 14] = [
    Field::Fixed(4), Field::Fixed(2), Field::Fixed(4), Field::Fixed(1), // APC COV APW AGA
    Field::Fixed(1), Field::Fixed(2), Field::Fixed(2),                  // ABA ATV AA
    Field::Fixed(1),                                                    // ARC
    Field::Spare, Field::Spare, Field::Spare, Field::Spare, Field::Spare, Field::Spare,
];

/// I062/340 Measured Information subfields.
#[rustfmt::skip]
const SUB_062_340: [Field; 7] = [
    Field::Fixed(2), Field::Fixed(4), Field::Fixed(2), // SID POS HEI
    Field::Fixed(2), Field::Fixed(2), Field::Fixed(1), // MDC MDA TYP
    Field::Spare,
];

/// I062/110 Mode 5 Data subfields.
#[rustfmt::skip]
const SUB_062_110: [Field; 7] = [
    Field::Fixed(1), Field::Fixed(4), Field::Fixed(6), // SUM PMN POS
    Field::Fixed(2), Field::Fixed(2), Field::Fixed(1), Field::Fixed(1), // GA EM1 TOS XP
];

/// I062/390 Flight Plan Related Data subfields (TOD is the one repetitive one).
#[rustfmt::skip]
const SUB_062_390: [Field; 21] = [
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

fn decode_062(items: &[(u8, &[u8])]) -> AsterixTarget {
    let mut t = AsterixTarget::new(CAT062);
    for &(frn, item) in items {
        match frn {
            1 => (t.sac, t.sic) = (item[0], item[1]),
            4 => t.time_of_day = Some(be(item, 0, 3) as f64 / 128.0),
            5 => t.set_pos(signed(item, 0, 4) * LSB_105, signed(item, 4, 4) * LSB_105),
            7 => {
                // Cartesian velocity Vx (East), Vy (North), LSB 0.25 m/s.
                let vx = i16::from_be_bytes([item[0], item[1]]) as f64 * 0.25;
                let vy = i16::from_be_bytes([item[2], item[3]]) as f64 * 0.25;
                t.ground_speed = Some((vx * vx + vy * vy).sqrt() / KNOTS_TO_MPS); // knots
                let course = vx.atan2(vy).to_degrees();
                t.track_angle = Some(if course < 0.0 { course + 360.0 } else { course });
            }
            9 => t.squawk = Some(mode_3a(u16::from_be_bytes([item[0], item[1]]))),
            10 if item.len() >= 7 => t.callsign = aircraft_id(&item[1..7]),
            11 => {
                // Aircraft Derived Data: ADR (subfield 0) and ID (subfield 1).
                for (idx, sub) in walk_compound(&SUB_062_380, item) {
                    match idx {
                        0 => t.icao = Some(be(sub, 0, 3) as u32),
                        1 => t.callsign = aircraft_id(sub),
                        _ => {}
                    }
                }
            }
            12 => t.track = Some(u16::from_be_bytes([item[0], item[1]]) as u32),
            17 => t.alt_ft = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 25.0),
            20 => t.vertical_rate = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 6.25),
            _ => {}
        }
    }
    t
}

/// Slice the present subfields of a compound item's body into `(index, bytes)`.
fn walk_compound<'a>(subs: &[Field], data: &'a [u8]) -> Vec<(usize, &'a [u8])> {
    let mut out = Vec::new();
    let Some(bits) = primary_bits(data, 0) else {
        return out;
    };
    let mut off = bits.len().div_ceil(7);
    for (i, &present) in bits.iter().enumerate() {
        if !present {
            continue;
        }
        let Some(sub) = subs.get(i).copied() else {
            break;
        };
        let Some(len) = field_len(sub, data, off) else {
            break;
        };
        let end = off + len;
        if end > data.len() {
            break;
        }
        out.push((i, &data[off..end]));
        off = end;
    }
    out
}

// ============================================================================
// Decoded target — a superset across categories; the mapper reads what is set.
// ============================================================================

/// A decoded ASTERIX air track — the wire facts, no clock. Deterministic.
#[derive(Debug, Clone, PartialEq)]
pub struct AsterixTarget {
    /// ASTERIX category (10, 21, 48, 62) — drives `source_uid` and provenance.
    pub category: u8,
    pub sac: u8,
    pub sic: u8,
    /// Track number (12-bit for CAT048, 16-bit for CAT021/062).
    pub track: Option<u32>,
    /// 24-bit ICAO target address, if the report carried one.
    pub icao: Option<u32>,
    /// WGS-84 latitude/longitude in degrees, if the record carried (or was
    /// geolocated to) an absolute position.
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    /// Radar-relative polar measurement (range NM, azimuth deg) for CAT048 and
    /// CAT010 when no sensor site is configured to geolocate it.
    pub polar: Option<(f64, f64)>,
    /// Cartesian offset from the sensor reference point (x east, y north, metres)
    /// for CAT010 when no sensor site is configured to geolocate it.
    pub cartesian: Option<(f64, f64)>,
    /// I010/000 message type; only a target report (1) is a track.
    pub message_type: Option<u8>,
    /// I010/020 TYP: the sensor technique that produced the report.
    pub report_type: Option<&'static str>,
    /// I010/300 vehicle fleet, when the target is a known ground vehicle.
    pub vehicle_fleet: Option<&'static str>,
    /// I010/270 target length (m), width (m), orientation (deg).
    pub size: Option<(f64, Option<f64>, Option<f64>)>,
    /// I010/500 standard deviation of position, x and y (m).
    pub position_sd: Option<(f64, f64)>,
    /// Altitude in feet (geometric height / flight level).
    pub alt_ft: Option<f64>,
    /// Ground speed in knots.
    pub ground_speed: Option<f64>,
    /// Track angle / course over ground in degrees.
    pub track_angle: Option<f64>,
    /// Rate of climb/descent in feet/minute (CAT062).
    pub vertical_rate: Option<f64>,
    /// Mode 3/A squawk as four octal digits.
    pub squawk: Option<String>,
    /// Callsign / flight identity.
    pub callsign: Option<String>,
    /// Emitter category (CAT021).
    pub emitter: Option<&'static str>,
    /// Time of day / track, seconds since UTC midnight (native; kept in metadata).
    pub time_of_day: Option<f64>,
    /// I048/020 target report descriptor truth bits: simulated target, test
    /// target, field monitor. Any of them set means this is NOT a real track
    /// and must never reach the operational picture as one.
    pub simulated: bool,
    pub test_target: bool,
    pub field_monitor: bool,
    /// The raw bytes of this record, preserved verbatim in the signed payload.
    pub raw: Vec<u8>,
}

impl AsterixTarget {
    fn new(category: u8) -> Self {
        AsterixTarget {
            category,
            sac: 0,
            sic: 0,
            track: None,
            icao: None,
            lat: None,
            lon: None,
            polar: None,
            cartesian: None,
            message_type: None,
            report_type: None,
            vehicle_fleet: None,
            size: None,
            position_sd: None,
            alt_ft: None,
            ground_speed: None,
            track_angle: None,
            vertical_rate: None,
            squawk: None,
            callsign: None,
            emitter: None,
            time_of_day: None,
            simulated: false,
            test_target: false,
            field_monitor: false,
            raw: Vec::new(),
        }
    }
    fn set_pos(&mut self, lat: f64, lon: f64) {
        self.lat = Some(lat);
        self.lon = Some(lon);
    }
    /// A record contributes an event if it carries a position (absolute or, for
    /// CAT048 and CAT010, a sensor-relative measurement) — otherwise it is a
    /// status-only record. A CAT010 status message never is, whatever it carries.
    fn is_track(&self) -> bool {
        if self.category == CAT010 && self.message_type != Some(CAT010_TARGET_REPORT) {
            return false;
        }
        self.lat.is_some() || self.polar.is_some() || self.cartesian.is_some()
    }
    /// The entity type a CAT010 report implies when the operator has not chosen
    /// one: a known vehicle fleet is a land vehicle, a Mode S address or an
    /// identification is an aircraft, anything else is an object.
    fn implied_surface_type(&self) -> &'static str {
        if self.vehicle_fleet.is_some() {
            "mim:land-vehicle"
        } else if self.icao.is_some() || self.callsign.is_some() {
            "mim:aircraft"
        } else {
            "mim:object"
        }
    }
}

/// A radar site, for geolocating CAT048 polar measurements.
#[derive(Debug, Clone, Copy)]
pub struct Sensor {
    pub lat: f64,
    pub lon: f64,
    /// Site elevation in metres, used to convert slant range to ground range.
    pub alt_m: f64,
}

// ============================================================================
// Parser — block/record walk and event mapping.
// ============================================================================

/// Normalizes an ASTERIX stream for one connector identity.
pub struct AsterixParser {
    source_id: String,
    enrichment: Enrichment,
    sensor: Option<Sensor>,
    /// Entity type for CAT010 surface reports, from `[entity_map] cat010`. Unset
    /// means the report's own content decides (`implied_surface_type`).
    cat010_type: Option<String>,
    /// Entity type for CAT034 radar heartbeats, from `[entity_map] cat034`.
    cat034_type: Option<String>,
    /// Last known self-reported status per radar (SAC, SIC), merged from every
    /// CAT034 message so the heartbeat carries the whole picture.
    radar_status: std::sync::Mutex<std::collections::HashMap<(u8, u8), RadarStatus>>,
    /// Data blocks for categories this connector does not decode: skipped and
    /// counted, never an error.
    ignored_blocks: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// SIM/TST/RAB reports: decoded, counted, and kept OUT of the picture.
    test_targets: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// CAT034 North markers: one per antenna rotation.
    north_markers: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// CAT034 sector crossings: counted, never published.
    sector_crossings: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// CAT034 jamming strobes of any kind.
    jamming_strobes: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Heartbeats published while the radar reported NOGO or an overload.
    radar_degraded: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl AsterixParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            sensor: None,
            cat010_type: None,
            cat034_type: None,
            radar_status: Default::default(),
            ignored_blocks: Default::default(),
            test_targets: Default::default(),
            north_markers: Default::default(),
            sector_crossings: Default::default(),
            jamming_strobes: Default::default(),
            radar_degraded: Default::default(),
        }
    }

    /// Set the radar site used to geolocate CAT048 polar and CAT010 polar or
    /// Cartesian measurements.
    pub fn with_sensor(mut self, sensor: Option<Sensor>) -> Self {
        self.sensor = sensor;
        self
    }

    /// Apply the operator's `[entity_map]`: `cat010` chooses the entity type for
    /// surface reports (`"mim:vessel"` for a coastal or naval radar,
    /// `"mim:land-vehicle"` for an airport surface feed), `cat034` the type for
    /// radar heartbeats (default `mim:sensor`). Other keys are not this
    /// connector's and are ignored.
    pub fn with_entity_map(mut self, map: &std::collections::HashMap<String, String>) -> Self {
        self.cat010_type = map.get("cat010").cloned();
        self.cat034_type = map.get("cat034").cloned();
        self
    }

    /// Decode every track-bearing record in every data block of one datagram.
    /// Radar heads pack multiple blocks per datagram (CAT034 service messages
    /// interleaved with CAT048 targets is the standard shape); a category this
    /// connector does not decode is skipped and counted, never an error, and
    /// never takes the blocks after it down with it. Service messages are
    /// decoded and their status remembered; [`parse_datagram`](Self::parse_datagram)
    /// returns them too.
    pub fn parse_frame(&self, frame: &[u8]) -> Result<Vec<AsterixTarget>, AsterixError> {
        self.parse_datagram(frame).map(|(t, _)| t)
    }

    /// Every track and every service report in one datagram.
    pub fn parse_datagram(
        &self,
        frame: &[u8],
    ) -> Result<(Vec<AsterixTarget>, Vec<ServiceReport>), AsterixError> {
        let mut targets = Vec::new();
        let mut reports = Vec::new();
        let mut off = 0usize;
        while off < frame.len() {
            let rest = &frame[off..];
            if rest.len() < 3 {
                return Err(AsterixError::BadBlock {
                    cat: None,
                    declared: 0,
                    have: rest.len(),
                });
            }
            let cat = rest[0];
            let len = u16::from_be_bytes([rest[1], rest[2]]) as usize;
            if len < 3 || len > rest.len() {
                return Err(AsterixError::BadBlock {
                    cat: Some(cat),
                    declared: len,
                    have: rest.len(),
                });
            }
            match cat {
                CAT010 | CAT021 | CAT048 | CAT062 => {
                    targets.extend(self.parse_block(&rest[..len])?)
                }
                CAT034 => reports.extend(self.parse_service_block(&rest[..len])?),
                _ => {
                    self.ignored_blocks
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            off += len;
        }
        Ok((targets, reports))
    }

    /// Decode every CAT034 record in one data block, merging each into the
    /// radar's remembered status and counting what kind it was.
    pub fn parse_service_block(&self, frame: &[u8]) -> Result<Vec<ServiceReport>, AsterixError> {
        let (cat, len) = block_header(frame)?;
        if cat != CAT034 {
            return Ok(Vec::new());
        }
        let mut reports = Vec::new();
        let mut off = 3;
        while off < len {
            let (items, next) = walk_record_cat(cat, UAP034, &frame[..len], off)?;
            if next <= off {
                return Err(AsterixError::BadBlock {
                    cat: Some(cat),
                    declared: len,
                    have: off,
                });
            }
            let mut r = decode_034(&items);
            r.raw = frame[off..next.min(len)].to_vec();
            {
                let mut all = self.radar_status.lock().unwrap_or_else(|e| e.into_inner());
                let known = all.entry((r.sac, r.sic)).or_default();
                known.merge(r.status);
                r.status = *known;
            }
            let counter = match r.message_type {
                NORTH_MARKER => Some(&self.north_markers),
                SECTOR_CROSSING => Some(&self.sector_crossings),
                JAMMING_STROBE | SSR_JAMMING_STROBE | MODE_S_JAMMING_STROBE => {
                    Some(&self.jamming_strobes)
                }
                _ => None,
            };
            if let Some(c) = counter {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            if r.message_type == NORTH_MARKER && r.status.degraded() {
                self.radar_degraded
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            reports.push(r);
            off = next;
        }
        Ok(reports)
    }

    /// Decode every track-bearing record in one data block. A block for a category
    /// this connector does not handle is not an error, just not ours.
    pub fn parse_block(&self, frame: &[u8]) -> Result<Vec<AsterixTarget>, AsterixError> {
        if frame.len() < 3 {
            return Err(AsterixError::BadBlock {
                cat: None,
                declared: 0,
                have: frame.len(),
            });
        }
        let cat = frame[0];
        let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        if len < 3 || len > frame.len() {
            return Err(AsterixError::BadBlock {
                cat: Some(cat),
                declared: len,
                have: frame.len(),
            });
        }
        let uap: &[Field] = match cat {
            CAT010 => UAP010,
            CAT021 => UAP021,
            CAT048 => UAP048,
            CAT062 => UAP062,
            _ => return Ok(Vec::new()),
        };

        let mut targets = Vec::new();
        let mut off = 3;
        while off < len {
            let (items, next) = walk_record_cat(cat, uap, &frame[..len], off)?;
            let mut t = match cat {
                CAT010 => decode_010(&items, self.sensor.as_ref()),
                CAT021 => decode_021(&items),
                CAT048 => decode_048(&items, self.sensor.as_ref()),
                CAT062 => decode_062(&items),
                _ => unreachable!(),
            };
            if next <= off {
                // No progress would loop forever.
                return Err(AsterixError::BadBlock {
                    cat: Some(cat),
                    declared: len,
                    have: off,
                });
            }
            if t.is_track() {
                t.raw = frame[off..next.min(len)].to_vec();
                targets.push(t);
            }
            off = next;
        }
        Ok(targets)
    }

    fn to_event_with(
        &self,
        t: &AsterixTarget,
        stamp: impl FnOnce(EventBuilder) -> EventBuilder,
    ) -> Result<Event, AsterixError> {
        // Native identity: ICAO address if present, else category:SAC:SIC:track.
        let source_uid = match (t.icao, t.track) {
            (Some(icao), _) => format!("icao:{icao:06X}"),
            (None, Some(track)) => format!("asterix:{}:{}:{}:{}", t.category, t.sac, t.sic, track),
            (None, None) => format!("asterix:{}:{}:{}", t.category, t.sac, t.sic),
        };
        let entity_type = self.entity_type_for(t);
        let mut b = EventBuilder::new(self.source_id.clone(), entity_type.clone())
            .new_id()
            .payload(t.raw.clone())
            .metadata("source_uid", source_uid)
            .metadata("asterix_category", t.category.to_string());
        // A surface report names its domain when the operator chose one.
        match entity_type.as_str() {
            "mim:vessel" => b = b.attribute("environment", "SURFACE"),
            "mim:land-vehicle" => b = b.attribute("environment", "LAND"),
            _ => {}
        }
        // Absolute position -> structured location (metres); else the
        // sensor-relative measurement rides as metadata so nothing is lost.
        if let (Some(lat), Some(lon)) = (t.lat, t.lon) {
            b = b.location(lat, lon, t.alt_ft.map(|ft| ft * 0.3048).unwrap_or(0.0));
        } else if let Some((rho, theta)) = t.polar {
            b = b.metadata("range_nm", format!("{rho:.3}"));
            b = b.metadata("azimuth_deg", format!("{theta:.3}"));
        } else if let Some((x, y)) = t.cartesian {
            b = b.metadata("x_m", format!("{x:.0}"));
            b = b.metadata("y_m", format!("{y:.0}"));
        }
        if let Some((sx, sy)) = t.position_sd {
            b = b.metadata("position_sd_x_m", format!("{sx:.2}"));
            b = b.metadata("position_sd_y_m", format!("{sy:.2}"));
        }
        if let Some((length, width, orientation)) = t.size {
            b = b.metadata("target_length_m", format!("{length:.0}"));
            if let Some(w) = width {
                b = b.metadata("target_width_m", format!("{w:.0}"));
            }
            if let Some(o) = orientation {
                b = b.metadata("target_orientation_deg", format!("{o:.1}"));
            }
        }
        if let Some(rt) = t.report_type {
            b = b.metadata("report_type", rt);
        }
        if let Some(fleet) = t.vehicle_fleet {
            b = b.metadata("vehicle_fleet", fleet);
        }
        if let Some(ft) = t.alt_ft {
            b = b.metadata("altitude_ft", format!("{ft:.0}"));
        }
        if let Some(tod) = t.time_of_day {
            b = b.metadata("time_of_day_s", format!("{tod:.3}"));
        }
        // Affiliation only ever the operator's explicit assertion.
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(gs) = t.ground_speed {
            b = b.attribute("speed", format!("{:.2}", gs * KNOTS_TO_MPS)); // m/s
            b = b.metadata("speed_kn", format!("{gs:.1}"));
        }
        if let Some(ta) = t.track_angle {
            b = b.attribute("course", format!("{ta:.1}"));
        }
        if let Some(vr) = t.vertical_rate {
            b = b.attribute("vertical_rate", format!("{:.1}", vr * 0.3048 / 60.0)); // ft/min -> m/s
            b = b.metadata("vertical_rate_ftmin", format!("{vr:.0}"));
        }
        if let Some(sq) = &t.squawk {
            b = b.attribute("squawk", sq.clone());
        }
        if let Some(cs) = &t.callsign {
            b = b.attribute("callsign", cs.clone());
        }
        if let Some(cat) = t.emitter {
            // Not an ontology attribute: kept as metadata, never quarantined.
            b = b.metadata("emitter_category", cat);
        }
        stamp(b)
            .build()
            .map_err(|e| AsterixError::Build(e.to_string()))
    }

    /// Build with an explicit observation timestamp (tests pin this path).
    pub fn to_event_at(&self, t: &AsterixTarget, observed: &str) -> Result<Event, AsterixError> {
        self.to_event_with(t, |b| b.timestamp(observed))
    }

    fn to_event_now(&self, t: &AsterixTarget) -> Result<Event, AsterixError> {
        self.to_event_with(t, |b| b.now())
    }

    /// The entity type a track publishes as: CAT010 is the operator's choice or
    /// the report's implication; every air-picture category is an aircraft.
    fn entity_type_for(&self, t: &AsterixTarget) -> String {
        if t.category == CAT010 {
            self.cat010_type
                .clone()
                .unwrap_or_else(|| t.implied_surface_type().to_string())
        } else {
            "mim:aircraft".to_string()
        }
    }

    /// A radar heartbeat or jamming strobe as a signed event about the radar
    /// itself: its status as last reported, its rotation period, its own
    /// position (from the message, else the configured site).
    fn service_event_with(
        &self,
        r: &ServiceReport,
        stamp: impl FnOnce(EventBuilder) -> EventBuilder,
    ) -> Result<Event, AsterixError> {
        let entity_type = self
            .cat034_type
            .clone()
            .unwrap_or_else(|| "mim:sensor".to_string());
        let mut b = EventBuilder::new(self.source_id.clone(), entity_type)
            .new_id()
            .payload(r.raw.clone())
            .metadata("source_uid", format!("asterix:radar:{}:{}", r.sac, r.sic))
            .metadata("asterix_category", CAT034.to_string())
            .metadata("message_type", r.message_name());
        if let Some((lat, lon, h)) = r.position {
            b = b.location(lat, lon, h);
        } else if let Some(s) = self.sensor {
            b = b.location(s.lat, s.lon, s.alt_m);
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(tod) = r.time_of_day {
            b = b.metadata("time_of_day_s", format!("{tod:.3}"));
        }
        if let Some(p) = r.rotation_period_s {
            b = b.metadata("rotation_period_s", format!("{p:.3}"));
        }
        if let Some(sec) = r.sector {
            b = b.metadata("sector", sec.to_string());
        }
        if let Some((r0, r1, a0, a1)) = r.window {
            b = b.metadata("window_range_start_nm", format!("{r0:.3}"));
            b = b.metadata("window_range_end_nm", format!("{r1:.3}"));
            b = b.metadata("window_azimuth_start_deg", format!("{a0:.3}"));
            b = b.metadata("window_azimuth_end_deg", format!("{a1:.3}"));
        }
        let flags = [
            ("nogo", r.status.nogo),
            ("rdp_overload", r.status.rdp_overload),
            ("xmt_overload", r.status.xmt_overload),
            ("monitoring_disconnected", r.status.monitoring_disconnected),
            ("time_source_invalid", r.status.time_source_invalid),
            ("psr_overload", r.status.psr_overload),
            ("ssr_overload", r.status.ssr_overload),
            ("mds_overload", r.status.mds_overload),
        ];
        for (key, value) in flags {
            if let Some(v) = value {
                b = b.metadata(key, if v { "true" } else { "false" });
            }
        }
        stamp(b)
            .build()
            .map_err(|e| AsterixError::Build(e.to_string()))
    }

    /// Build a service event with an explicit timestamp (tests pin this path).
    pub fn service_event_at(
        &self,
        r: &ServiceReport,
        observed: &str,
    ) -> Result<Event, AsterixError> {
        self.service_event_with(r, |b| b.timestamp(observed))
    }
}

/// The category and declared length of a data block, checked against the bytes
/// actually present.
fn block_header(frame: &[u8]) -> Result<(u8, usize), AsterixError> {
    if frame.len() < 3 {
        return Err(AsterixError::BadBlock {
            cat: None,
            declared: 0,
            have: frame.len(),
        });
    }
    let cat = frame[0];
    let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    if len < 3 || len > frame.len() {
        return Err(AsterixError::BadBlock {
            cat: Some(cat),
            declared: len,
            have: frame.len(),
        });
    }
    Ok((cat, len))
}

/// Walk one record starting at `off`: decode the FSPEC, slice each present item by
/// its UAP length model, and return `(FRN, bytes)` pairs plus the next offset.
fn walk_record_cat<'a>(
    cat: u8,
    uap: &[Field],
    data: &'a [u8],
    mut off: usize,
) -> Result<(Items<'a>, usize), AsterixError> {
    // FSPEC: octets, MSB = FRN1; the low bit (FX) continues the bitmap.
    let mut present = Vec::new();
    let mut frn = 1u8;
    loop {
        let octet = *data.get(off).ok_or(AsterixError::Truncated)?;
        off += 1;
        for bit in 0..7 {
            if octet & (0x80 >> bit) != 0 {
                present.push(frn);
            }
            frn = frn.saturating_add(1);
        }
        if octet & 0x01 == 0 {
            break;
        }
    }

    let mut items = Vec::with_capacity(present.len());
    for &frn in &present {
        let field = *uap
            .get(frn as usize - 1)
            .ok_or(AsterixError::UnsupportedItem { cat, frn })?;
        let len = match field_len(field, data, off) {
            Some(len) => len,
            None => {
                return Err(match field {
                    Field::Opaque | Field::Compound(_) => {
                        AsterixError::UnsupportedItem { cat, frn }
                    }
                    _ => AsterixError::Truncated,
                });
            }
        };
        let end = off.checked_add(len).ok_or(AsterixError::Truncated)?;
        let item = data.get(off..end).ok_or(AsterixError::Truncated)?;
        items.push((frn, item));
        off = end;
    }
    Ok((items, off))
}

impl FrameParser for AsterixParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let (targets, reports) = self.parse_datagram(frame).map_err(box_err)?;
        let mut events = Vec::with_capacity(targets.len() + reports.len());
        for r in reports.iter().filter(|r| r.is_published()) {
            events.push(self.service_event_with(r, |b| b.now()).map_err(box_err)?);
        }
        for t in &targets {
            // A simulated, test or field-monitor report is real wire traffic
            // but not a real object: counted, never published as a track.
            if t.simulated || t.test_target || t.field_monitor {
                self.test_targets
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue;
            }
            events.push(self.to_event_now(t).map_err(box_err)?);
        }
        Ok(events)
    }

    fn counters(&self) -> Vec<(&'static str, std::sync::Arc<std::sync::atomic::AtomicU64>)> {
        vec![
            ("asterix_ignored_blocks_total", self.ignored_blocks.clone()),
            ("asterix_test_targets_total", self.test_targets.clone()),
            ("asterix_north_markers_total", self.north_markers.clone()),
            (
                "asterix_sector_crossings_total",
                self.sector_crossings.clone(),
            ),
            (
                "asterix_jamming_strobes_total",
                self.jamming_strobes.clone(),
            ),
            ("asterix_radar_degraded_total", self.radar_degraded.clone()),
        ]
    }
}

fn box_err(e: AsterixError) -> ParseError {
    Box::new(e) as ParseError
}

// ============================================================================
// Shared field decoders.
// ============================================================================

/// A big-endian unsigned integer from `data[start..start+n]` (n <= 8).
fn be(data: &[u8], start: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        v = (v << 8) | data[start + i] as u64;
    }
    v
}

/// A big-endian two's-complement signed integer from `data[start..start+n]`.
fn signed(data: &[u8], start: usize, n: usize) -> f64 {
    sign_extend(be(data, start, n), (n * 8) as u32) as f64
}

/// Sign-extend the low `bits` of `v` to an i64.
fn sign_extend(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

/// The four-octal-digit Mode 3/A squawk from a 16-bit item (low 12 bits are the
/// code, split into four 3-bit octal digits).
fn mode_3a(v: u16) -> String {
    let code = v & 0x0FFF;
    format!(
        "{:o}{:o}{:o}{:o}",
        (code >> 9) & 7,
        (code >> 6) & 7,
        (code >> 3) & 7,
        code & 7
    )
}

/// The ICAO 6-bit-encoded aircraft identification (8 characters, trailing pad
/// trimmed). Used by I021/170, I048/240 and CAT062 subfields.
fn aircraft_id(item: &[u8]) -> Option<String> {
    if item.len() < 6 {
        return None;
    }
    let v = be(item, 0, 6);
    let mut s = String::with_capacity(8);
    for k in 0..8 {
        let c = ((v >> (42 - 6 * k)) & 0x3F) as u8;
        s.push(sixbit(c));
    }
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// One ICAO 6-bit character: 1..=26 -> A..Z, 48..=57 -> 0..9, else space.
fn sixbit(c: u8) -> char {
    match c {
        1..=26 => (b'A' + c - 1) as char,
        48..=57 => (b'0' + c - 48) as char,
        _ => ' ',
    }
}

/// Forward geodetic: from `(lat, lon)` degrees, travel `dist_m` metres at true
/// `bearing_deg` (clockwise from North). Spherical earth — good to ~0.3% over
/// radar ranges, and never invents a position the record didn't measure.
fn forward_geodetic(lat: f64, lon: f64, bearing_deg: f64, dist_m: f64) -> (f64, f64) {
    const R: f64 = 6_371_000.0;
    let d = dist_m / R;
    let br = bearing_deg.to_radians();
    let (lat1, lon1) = (lat.to_radians(), lon.to_radians());
    let lat2 = (lat1.sin() * d.cos() + lat1.cos() * d.sin() * br.cos()).asin();
    let lon2 = lon1 + (br.sin() * d.sin() * lat1.cos()).atan2(d.cos() - lat1.sin() * lat2.sin());
    (lat2.to_degrees(), lon2.to_degrees())
}

/// I021/020 Emitter Category → operational category.
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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- record/block builders --------------------------------------------
    fn fspec(frns: &[u8]) -> Vec<u8> {
        let max = frns.iter().copied().max().unwrap_or(1) as usize;
        let octets = max.div_ceil(7).max(1);
        let mut f = vec![0u8; octets];
        for &n in frns {
            f[(n as usize - 1) / 7] |= 0x80 >> ((n as usize - 1) % 7);
        }
        for byte in f.iter_mut().take(octets - 1) {
            *byte |= 0x01; // FX on every octet but the last
        }
        f
    }
    fn block(cat: u8, record: &[u8]) -> Vec<u8> {
        let len = 3 + record.len();
        let mut b = vec![cat, (len >> 8) as u8, (len & 0xff) as u8];
        b.extend_from_slice(record);
        b
    }
    fn u16b(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    fn enc_id(s: &str) -> [u8; 6] {
        let mut v = 0u64;
        for k in 0..8 {
            let c = s.as_bytes().get(k).copied().unwrap_or(b' ');
            let six = match c {
                b'A'..=b'Z' => c - b'A' + 1,
                b'0'..=b'9' => c - b'0' + 48,
                _ => 32,
            } as u64;
            v |= six << (42 - 6 * k);
        }
        let mut out = [0u8; 6];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (v >> (40 - 8 * i)) as u8;
        }
        out
    }

    fn parser() -> AsterixParser {
        AsterixParser::new("radar-1", Enrichment::default())
    }
    fn attr<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
        ev.attributes
            .iter()
            .find(|a| a.key == k)
            .map(|a| a.value.as_str())
    }
    fn meta<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
        ev.metadata
            .iter()
            .find(|m| m.key == k)
            .map(|m| m.value.as_str())
    }

    // ---- CAT048 ------------------------------------------------------------

    #[test]
    fn every_block_in_a_datagram_is_decoded_not_just_the_first() {
        // The standard radar-head shape: a CAT034 service block leading the
        // CAT048 targets in one datagram. The old walk stopped at the first
        // block's declared length and silently dropped everything after it.
        let p = parser();
        let mut datagram = block(34, &cat034_north_marker()); // service block first
        datagram.extend(block(48, &cat048_record()));
        let (targets, reports) = p.parse_datagram(&datagram).unwrap();
        assert_eq!(
            targets.len(),
            1,
            "the CAT048 block behind CAT034 must decode"
        );
        assert_eq!(
            reports.len(),
            1,
            "the service block is decoded, not skipped"
        );
        assert_eq!(
            p.ignored_blocks.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "nothing in this datagram was ignored"
        );
        // A category nobody decodes is still counted, never an error.
        let mut datagram = vec![240, 0, 4, 0]; // CAT240 video: not ours
        datagram.extend(block(48, &cat048_record()));
        assert_eq!(p.parse_frame(&datagram).unwrap().len(), 1);
        assert_eq!(
            p.ignored_blocks.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn simulated_and_test_targets_never_reach_the_picture() {
        // I048/020 with SIM set: decoded, counted, filtered.
        let mut r = fspec(&[1, 3, 4]);
        r.extend_from_slice(&[25, 10]); // 010 SAC/SIC
        r.push(0x10); // 020: SIM, no extension
        r.extend_from_slice(&u16b(25600)); // 040 RHO
        r.extend_from_slice(&u16b(8192)); //  040 THETA
        let p = parser();
        let events = p.parse(&block(48, &r)).unwrap();
        assert!(events.is_empty(), "a simulated target is not a track");
        assert_eq!(p.test_targets.load(std::sync::atomic::Ordering::Relaxed), 1);
        // The decoder itself still sees it, truthfully flagged.
        let t = &p.parse_frame(&block(48, &r)).unwrap()[0];
        assert!(t.simulated && !t.test_target && !t.field_monitor);
    }

    #[test]
    fn garbled_or_invalid_codes_are_omitted_not_published_as_clean() {
        let mut r = fspec(&[1, 5, 6]);
        r.extend_from_slice(&[25, 10]);
        r.extend_from_slice(&u16b(0x8000 | 0o1234)); // 070 with V (invalid) set
        r.extend_from_slice(&[0x40 | 0x05, 0x78]); // 090 with G (garbled) set
        let p = parser();
        // No position: not a track, but decode_048 is still exercised.
        let items_only = p.parse_frame(&block(48, &r)).unwrap();
        assert!(items_only.is_empty(), "status-only record");
        let mut r2 = fspec(&[1, 4, 5, 6]);
        r2.extend_from_slice(&[25, 10]);
        r2.extend_from_slice(&u16b(25600));
        r2.extend_from_slice(&u16b(8192));
        r2.extend_from_slice(&u16b(0x8000 | 0o1234)); // V set
        r2.extend_from_slice(&[0x45, 0x78]); // 090 with G (0x40) set: garbled
        let t = &p.parse_frame(&block(48, &r2)).unwrap()[0];
        assert_eq!(t.squawk, None, "invalid squawk is no squawk");
        assert_eq!(t.alt_ft, None, "garbled flight level is no flight level");
    }

    #[test]
    fn slant_range_is_projected_to_ground_range_before_geolocation() {
        // Radar at sea level; target due north at 10 NM slant, FL350. The
        // ground range is sqrt(slant^2 - height^2), visibly shorter.
        let p = parser().with_sensor(Some(Sensor {
            lat: 60.0,
            lon: 25.0,
            alt_m: 0.0,
        }));
        let mut r = fspec(&[1, 4, 6]);
        r.extend_from_slice(&[25, 10]);
        r.extend_from_slice(&u16b(2560)); // RHO = 10.0 NM
        r.extend_from_slice(&u16b(0)); //    THETA = 0 (due north)
        r.extend_from_slice(&u16b(1400)); // FL: 35000 ft
        let t = &p.parse_frame(&block(48, &r)).unwrap()[0];
        let lat = t.lat.unwrap();
        // slant 18520 m, height 10668 m -> ground ~15139 m -> ~0.136 deg north.
        let dlat = lat - 60.0;
        assert!(
            (0.130..0.142).contains(&dlat),
            "expected ground-projected ~0.136 deg, got {dlat}"
        );
        // Using raw slant would land ~0.166 deg north: assert we did not.
        assert!(dlat < 0.15, "slant range was not corrected: {dlat}");
    }

    #[test]
    fn a_bad_block_error_names_the_category_and_lengths() {
        let p = parser();
        let err = p.parse_frame(&[48, 0xFF, 0xFF, 0, 0]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CAT048"), "{msg}");
        assert!(msg.contains("65535"), "{msg}");
        assert!(msg.contains("5 available"), "{msg}");
    }

    fn cat048_record() -> Vec<u8> {
        let mut r = fspec(&[1, 4, 5, 6, 7, 8, 11, 13]);
        r.extend_from_slice(&[25, 10]); // 010 SAC/SIC
        r.extend_from_slice(&u16b(25600)); // 040 RHO = 100.0 NM (100*256)
        r.extend_from_slice(&u16b(8192)); //  040 THETA = 45.0 deg (45/(360/65536))
        r.extend_from_slice(&u16b(0o1234)); // 070 Mode-3/A
        r.extend_from_slice(&u16b(1400)); // 090 FL: raw 1400 -> 35000 ft
        r.extend_from_slice(&[0x80, 0xAB]); // 130 compound: SRL present (1 subfield, 1 byte)
        r.extend_from_slice(&[0x4C, 0xA2, 0xD6]); // 220 ICAO
        r.extend_from_slice(&u16b(1234)); // 161 Track Number
        r.extend_from_slice(&u16b(2048)); // 200 groundspeed raw -> 450.0 kt
        r.extend_from_slice(&u16b(16384)); // 200 heading -> 90.0 deg
        r
    }

    #[test]
    fn cat048_decodes_polar_kinematics_and_identity() {
        let t = &parser().parse_block(&block(48, &cat048_record())).unwrap()[0];
        let (rho, theta) = t.polar.unwrap();
        assert!((rho - 100.0).abs() < 1e-6, "rho {rho}");
        assert!((theta - 45.0).abs() < 1e-3, "theta {theta}");
        assert_eq!(t.alt_ft, Some(35000.0));
        assert_eq!(t.icao, Some(0x4CA2D6));
        assert_eq!(t.track, Some(1234));
        assert!((t.ground_speed.unwrap() - 450.0).abs() < 0.1);
        assert!((t.track_angle.unwrap() - 90.0).abs() < 1e-3);
        assert_eq!(t.squawk.as_deref(), Some("1234"));
        // The compound I048/130 (present) did not misalign the items after it.
    }

    #[test]
    fn cat048_geolocates_against_a_sensor_site() {
        // Radar at 60N 25E; a target 100 NM to the north-east (azimuth 45) lands
        // north-east of it — both latitude and longitude increase.
        let p = parser().with_sensor(Some(Sensor {
            lat: 60.0,
            lon: 25.0,
            alt_m: 0.0,
        }));
        let t = &p.parse_block(&block(48, &cat048_record())).unwrap()[0];
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        let loc = ev.location.as_ref().expect("geolocated");
        assert!(
            loc.latitude > 60.0 && loc.latitude < 62.0,
            "lat {}",
            loc.latitude
        );
        assert!(loc.longitude > 25.0, "lon {}", loc.longitude);
        assert_eq!(attr(&ev, "squawk"), Some("1234"));
    }

    #[test]
    fn cat048_without_sensor_keeps_polar_in_metadata() {
        let p = parser();
        let t = &p.parse_block(&block(48, &cat048_record())).unwrap()[0];
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert!(ev.location.is_none());
        assert_eq!(meta(&ev, "range_nm"), Some("100.000"));
        assert_eq!(meta(&ev, "azimuth_deg").map(|s| &s[..2]), Some("45"));
    }

    // ---- CAT062 ------------------------------------------------------------
    fn cat062_record() -> Vec<u8> {
        let lat = (60.0 / LSB_105) as i32;
        let lon = (25.0 / LSB_105) as i32;
        let mut r = fspec(&[1, 4, 5, 7, 9, 11, 12, 17, 20]);
        r.extend_from_slice(&[25, 10]); // 010 SAC/SIC
        r.extend_from_slice(&300u32.to_be_bytes()[1..]); // 070 time (3 bytes)
        r.extend_from_slice(&lat.to_be_bytes()); // 105 lat
        r.extend_from_slice(&lon.to_be_bytes()); // 105 lon
        r.extend_from_slice(&(400i16).to_be_bytes()); // 185 Vx = 100 m/s East
        r.extend_from_slice(&(0i16).to_be_bytes()); //  185 Vy = 0
        r.extend_from_slice(&u16b(0o7000)); // 060 Mode-3/A
                                            // 380 compound: ADR + ID present.
        r.push(0xC0); // primary: ADR(bit8) ID(bit7), FX=0
        r.extend_from_slice(&[0x40, 0x62, 0x01]); // ADR ICAO
        r.extend_from_slice(&enc_id("BAW123")); // ID callsign
        r.extend_from_slice(&u16b(4095)); // 040 Track Number
        r.extend_from_slice(&(1400i16).to_be_bytes()); // 136 FL raw 1400 -> 35000 ft
        r.extend_from_slice(&(160i16).to_be_bytes()); // 220 rate: 160 -> 1000 ft/min
        r
    }

    #[test]
    fn cat062_decodes_wgs84_track_velocity_and_derived_data() {
        let t = &parser().parse_block(&block(62, &cat062_record())).unwrap()[0];
        assert!(
            (t.lat.unwrap() - 60.0).abs() < 1e-4,
            "lat {}",
            t.lat.unwrap()
        );
        assert!(
            (t.lon.unwrap() - 25.0).abs() < 1e-4,
            "lon {}",
            t.lon.unwrap()
        );
        // Vx=100 East, Vy=0 -> 100 m/s = 194.4 kt, course 90.
        assert!(
            (t.ground_speed.unwrap() - 194.38).abs() < 0.1,
            "gs {}",
            t.ground_speed.unwrap()
        );
        assert!((t.track_angle.unwrap() - 90.0).abs() < 1e-3);
        assert_eq!(t.alt_ft, Some(35000.0));
        assert_eq!(t.vertical_rate, Some(1000.0));
        assert_eq!(t.track, Some(4095));
        // I062/380 (a compound with variable subfields) decoded ADR + ID, and its
        // length was computed correctly (the Track Number after it aligned).
        assert_eq!(t.icao, Some(0x406201));
        assert_eq!(t.callsign.as_deref(), Some("BAW123"));
    }

    #[test]
    fn cat062_event_carries_canonical_units() {
        let p = parser();
        let t = &p.parse_block(&block(62, &cat062_record())).unwrap()[0];
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(meta(&ev, "source_uid"), Some("icao:406201"));
        assert_eq!(meta(&ev, "asterix_category"), Some("62"));
        assert_eq!(attr(&ev, "speed"), Some("100.00")); // 194.38 kn * 0.514444
        assert_eq!(attr(&ev, "course"), Some("90.0"));
        assert_eq!(attr(&ev, "callsign"), Some("BAW123"));
        assert!(ev.payload.len() > 20); // raw record sealed
    }

    // ---- cross-cutting -----------------------------------------------------
    #[test]
    fn other_category_is_ignored_not_errored() {
        // A CAT034 (service message) block is valid ASTERIX but not ours.
        assert_eq!(
            parser()
                .parse_block(&block(34, &[0x80, 0x00]))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn malformed_blocks_never_panic() {
        assert!(parser().parse_block(b"").is_err());
        assert!(parser().parse_block(&[62, 0, 200]).is_err()); // LEN past buffer
                                                               // A record whose FSPEC claims items running past the block: typed error.
        let _ = parser().parse_block(&block(62, &[0xFF, 0xFF, 0x00]));
        // Truncated compound must not panic.
        let mut r = fspec(&[1, 11]);
        r.extend_from_slice(&[25, 10]);
        r.push(0xC0); // 380 says ADR+ID present but no bytes follow
        let _ = parser().parse_block(&block(62, &r));
    }
    // ---- CAT010 ------------------------------------------------------------
    fn cat010_wgs84_record() -> Vec<u8> {
        let lat = (60.0 / LSB_041) as i32;
        let lon = (25.0 / LSB_041) as i32;
        let mut r = fspec(&[1, 2, 4, 5, 8, 10, 22]);
        r.extend_from_slice(&[25, 10]); // 010 SAC/SIC
        r.push(1); // 000 target report
        r.extend_from_slice(&300u32.to_be_bytes()[1..]); // 140 time of day
        r.extend_from_slice(&lat.to_be_bytes()); // 041 lat
        r.extend_from_slice(&lon.to_be_bytes()); // 041 lon
        r.extend_from_slice(&u16b(2048)); // 200 ground speed -> 450 kt
        r.extend_from_slice(&u16b(16384)); // 200 track angle -> 90 deg
        r.extend_from_slice(&u16b(77)); // 161 track number
        r.extend_from_slice(&[8, 12, 0, 0]); // 500 sd: 2.0 m, 3.0 m
        r
    }

    #[test]
    fn cat010_wgs84_report_is_a_surface_track_with_uncertainty_kept() {
        let p = parser();
        let t = &p.parse_block(&block(10, &cat010_wgs84_record())).unwrap()[0];
        assert!((t.lat.unwrap() - 60.0).abs() < 1e-6);
        assert!((t.lon.unwrap() - 25.0).abs() < 1e-6);
        assert!((t.ground_speed.unwrap() - 450.0).abs() < 0.1);
        assert_eq!(t.track, Some(77));
        assert_eq!(t.position_sd, Some((2.0, 3.0)));
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        // No operator choice, no vehicle fleet, no Mode S identity: an object.
        assert_eq!(ev.entity_type, "mim:object");
        assert_eq!(meta(&ev, "source_uid"), Some("asterix:10:25:10:77"));
        assert_eq!(meta(&ev, "asterix_category"), Some("10"));
        assert_eq!(meta(&ev, "position_sd_x_m"), Some("2.00"));
        assert_eq!(meta(&ev, "position_sd_y_m"), Some("3.00"));
        assert_eq!(attr(&ev, "course"), Some("90.0"));
        assert_eq!(attr(&ev, "environment"), None, "no domain without a choice");
    }

    #[test]
    fn cat010_entity_map_makes_a_coastal_radar_emit_vessels() {
        let mut map = std::collections::HashMap::new();
        map.insert("cat010".to_string(), "mim:vessel".to_string());
        let p = parser().with_entity_map(&map);
        let t = &p.parse_block(&block(10, &cat010_wgs84_record())).unwrap()[0];
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:vessel");
        assert_eq!(attr(&ev, "environment"), Some("SURFACE"));
    }

    #[test]
    fn cat010_implied_type_follows_the_report_content() {
        // A vehicle fleet id makes a land vehicle; a Mode S address an aircraft.
        let mut r = fspec(&[1, 2, 5, 16]);
        r.extend_from_slice(&[25, 10]);
        r.push(1);
        r.extend_from_slice(&[0u8; 8]); // 041 at 0,0
        r.push(3); // 300 fire vehicle
        let p = parser();
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        assert_eq!(t.vehicle_fleet, Some("fire"));
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:land-vehicle");
        assert_eq!(attr(&ev, "environment"), Some("LAND"));
        assert_eq!(meta(&ev, "vehicle_fleet"), Some("fire"));

        let mut r = fspec(&[1, 2, 5, 13]);
        r.extend_from_slice(&[25, 10]);
        r.push(1);
        r.extend_from_slice(&[0u8; 8]);
        r.extend_from_slice(&[0x4C, 0xA2, 0xD6]); // 220 target address
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:aircraft");
        assert_eq!(meta(&ev, "source_uid"), Some("icao:4CA2D6"));
    }

    #[test]
    fn cat010_polar_and_cartesian_geolocate_against_the_site_without_slant_correction() {
        let p = parser().with_sensor(Some(Sensor {
            lat: 60.0,
            lon: 25.0,
            alt_m: 0.0,
        }));
        // Polar: 1852 m (one NM) due north. RHO is metres in CAT010.
        let mut r = fspec(&[1, 2, 6]);
        r.extend_from_slice(&[25, 10]);
        r.push(1);
        r.extend_from_slice(&u16b(1852));
        r.extend_from_slice(&u16b(0));
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        let dlat = t.lat.unwrap() - 60.0;
        assert!((dlat - 0.01666).abs() < 0.0005, "one NM north = {dlat} deg");
        assert!((t.lon.unwrap() - 25.0).abs() < 1e-9);
        // Cartesian: 1000 m due east.
        let mut r = fspec(&[1, 2, 7]);
        r.extend_from_slice(&[25, 10]);
        r.push(1);
        r.extend_from_slice(&(1000i16).to_be_bytes());
        r.extend_from_slice(&(0i16).to_be_bytes());
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        // A great-circle step due east bends a hair toward the equator: ~1e-6
        // degrees over 1 km at 60N, which is the geometry, not an error.
        assert!((t.lat.unwrap() - 60.0).abs() < 1e-4, "east keeps latitude");
        let dlon = t.lon.unwrap() - 25.0;
        assert!(
            (0.0175..0.0185).contains(&dlon),
            "1 km east at 60N = {dlon} deg"
        );
        // Without a site the offsets ride as metadata, nothing lost.
        let t = &parser().parse_block(&block(10, &r)).unwrap()[0];
        let ev = parser().to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert!(ev.location.is_none());
        assert_eq!(meta(&ev, "x_m"), Some("1000"));
        assert_eq!(meta(&ev, "y_m"), Some("0"));
    }

    #[test]
    fn cat010_cartesian_velocity_becomes_speed_and_course() {
        let mut r = fspec(&[1, 2, 5, 9]);
        r.extend_from_slice(&[25, 10]);
        r.push(1);
        r.extend_from_slice(&[0u8; 8]);
        r.extend_from_slice(&(40i16).to_be_bytes()); // Vx = 10 m/s east
        r.extend_from_slice(&(0i16).to_be_bytes()); //  Vy = 0
        let t = &parser().parse_block(&block(10, &r)).unwrap()[0];
        assert!((t.ground_speed.unwrap() * KNOTS_TO_MPS - 10.0).abs() < 0.01);
        assert!((t.track_angle.unwrap() - 90.0).abs() < 1e-6);
    }

    #[test]
    fn cat010_status_messages_and_test_targets_never_become_tracks() {
        // A periodic status message carries a position field but is not a target.
        let mut r = fspec(&[1, 2, 5]);
        r.extend_from_slice(&[25, 10]);
        r.push(3); // 000 periodic status message
        r.extend_from_slice(&[0u8; 8]);
        let p = parser();
        assert!(p.parse_block(&block(10, &r)).unwrap().is_empty());
        // SIM lives in the first extension of I010/020 (not the first octet).
        let mut r = fspec(&[1, 2, 3, 5]);
        r.extend_from_slice(&[25, 10]);
        r.push(1);
        r.extend_from_slice(&[0x60 | 0x01, 0x80]); // TYP=PSR, FX; ext: SIM
        r.extend_from_slice(&[0u8; 8]);
        let t = &p.parse_block(&block(10, &r)).unwrap()[0];
        assert!(t.simulated);
        assert_eq!(t.report_type, Some("psr"));
        assert!(p.parse(&block(10, &r)).unwrap().is_empty());
        assert_eq!(p.test_targets.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    // ---- CAT034 ------------------------------------------------------------
    fn cat034_north_marker() -> Vec<u8> {
        let lat = (60.0 / LSB_120) as i64;
        let lon = (25.0 / LSB_120) as i64;
        let mut r = fspec(&[1, 2, 3, 5, 11]);
        r.extend_from_slice(&[25, 10]); // 010
        r.push(NORTH_MARKER); // 000
        r.extend_from_slice(&300u32.to_be_bytes()[1..]); // 030 time
        r.extend_from_slice(&u16b(512)); // 041: 4.000 s per rotation
        r.extend_from_slice(&(50i16).to_be_bytes()); // 120 height 50 m
        r.extend_from_slice(&lat.to_be_bytes()[5..]); // 120 lat (3 bytes)
        r.extend_from_slice(&lon.to_be_bytes()[5..]); // 120 lon (3 bytes)
        r
    }
    fn cat034_sector_crossing_with_status(com: u8) -> Vec<u8> {
        let mut r = fspec(&[1, 2, 4, 6]);
        r.extend_from_slice(&[25, 10]);
        r.push(SECTOR_CROSSING);
        r.push(96); // 020 sector 96 = 135 deg
        r.extend_from_slice(&[0x80, com]); // 050: COM present, FX=0
        r
    }

    #[test]
    fn cat034_status_is_remembered_across_messages_and_rides_the_heartbeat() {
        let p = parser();
        // A sector crossing reports NOGO + RDP overload; it is counted, not published.
        let r = p
            .parse_service_block(&block(34, &cat034_sector_crossing_with_status(0x90)))
            .unwrap();
        assert_eq!(r.len(), 1);
        assert!(!r[0].is_published());
        assert_eq!(r[0].status.nogo, Some(true));
        assert_eq!(r[0].status.rdp_overload, Some(true));
        assert_eq!(r[0].status.xmt_overload, Some(false));
        assert_eq!(r[0].sector, Some(96));
        // The next North marker carries no status item itself but the
        // heartbeat reports what the radar last said.
        let r = p
            .parse_service_block(&block(34, &cat034_north_marker()))
            .unwrap();
        let nm = &r[0];
        assert!(nm.is_published());
        assert_eq!(nm.rotation_period_s, Some(4.0));
        assert_eq!(nm.status.nogo, Some(true));
        let (lat, lon, h) = nm.position.unwrap();
        assert!((lat - 60.0).abs() < 1e-4 && (lon - 25.0).abs() < 1e-4 && h == 50.0);
        let ev = p.service_event_at(nm, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:sensor");
        assert_eq!(meta(&ev, "source_uid"), Some("asterix:radar:25:10"));
        assert_eq!(meta(&ev, "message_type"), Some("north-marker"));
        assert_eq!(meta(&ev, "rotation_period_s"), Some("4.000"));
        assert_eq!(meta(&ev, "nogo"), Some("true"));
        assert_eq!(meta(&ev, "rdp_overload"), Some("true"));
        assert_eq!(
            meta(&ev, "psr_overload"),
            None,
            "never claimed, never stated"
        );
        let loc = ev.location.as_ref().unwrap();
        assert!((loc.latitude - 60.0).abs() < 1e-4);
        assert_eq!(ev.payload, nm.raw, "the raw record is sealed verbatim");
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(p.north_markers.load(Relaxed), 1);
        assert_eq!(p.sector_crossings.load(Relaxed), 1);
        assert_eq!(p.radar_degraded.load(Relaxed), 1);
        // Recovery: a status message clears NOGO; the next heartbeat is clean.
        p.parse_service_block(&block(34, &cat034_sector_crossing_with_status(0x00)))
            .unwrap();
        let r = p
            .parse_service_block(&block(34, &cat034_north_marker()))
            .unwrap();
        assert_eq!(r[0].status.nogo, Some(false));
        assert_eq!(p.radar_degraded.load(Relaxed), 1);
    }

    #[test]
    fn cat034_jamming_strobe_is_published_with_its_window() {
        let mut r = fspec(&[1, 2, 9]);
        r.extend_from_slice(&[25, 10]);
        r.push(JAMMING_STROBE);
        r.extend_from_slice(&u16b(2560)); // 100 rho start 10 NM
        r.extend_from_slice(&u16b(5120)); //     rho end 20 NM
        r.extend_from_slice(&u16b(8192)); //     theta start 45
        r.extend_from_slice(&u16b(16384)); //    theta end 90
        let p = parser();
        let rep = &p.parse_service_block(&block(34, &r)).unwrap()[0];
        assert!(rep.is_published());
        let ev = p.service_event_at(rep, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(meta(&ev, "message_type"), Some("jamming-strobe"));
        assert_eq!(meta(&ev, "window_range_start_nm"), Some("10.000"));
        assert_eq!(meta(&ev, "window_range_end_nm"), Some("20.000"));
        assert_eq!(meta(&ev, "window_azimuth_start_deg"), Some("45.000"));
        assert_eq!(meta(&ev, "window_azimuth_end_deg"), Some("90.000"));
        assert_eq!(
            p.jamming_strobes.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn one_datagram_publishes_the_heartbeat_and_the_tracks_behind_it() {
        let p = parser().with_sensor(Some(Sensor {
            lat: 60.0,
            lon: 25.0,
            alt_m: 0.0,
        }));
        let mut datagram = block(34, &cat034_north_marker());
        datagram.extend(block(34, &cat034_sector_crossing_with_status(0x00)));
        datagram.extend(block(48, &cat048_record()));
        datagram.extend(block(10, &cat010_wgs84_record()));
        let events = p.parse(&datagram).unwrap();
        let types: Vec<&str> = events.iter().map(|e| e.entity_type.as_str()).collect();
        assert_eq!(types, ["mim:sensor", "mim:aircraft", "mim:object"]);
    }

    // ---- ontology gate -------------------------------------------------------
    #[test]
    fn every_attribute_and_type_the_connector_can_emit_is_declared() {
        // The same check the connector runs at boot, over everything this
        // decoder can produce: a name the ontology does not declare would be
        // quarantined silently in Core, so it fails here instead.
        let declared = ajar_connector_common::ontology::Declared {
            entity_types: [
                "mim:aircraft",
                "mim:object",
                "mim:vessel",
                "mim:land-vehicle",
                "mim:sensor",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            attributes: [
                "hostility",
                "speed",
                "course",
                "vertical_rate",
                "squawk",
                "callsign",
                "environment",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            fixed_values: [("environment", "SURFACE"), ("environment", "LAND")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        let faults = ajar_connector_common::ontology::check(&declared);
        assert!(faults.is_empty(), "undeclared: {faults:?}");
    }
}
