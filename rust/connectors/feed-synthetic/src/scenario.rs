// SPDX-License-Identifier: Apache-2.0
//! The fixture every feed renders: one set of objects, each seen by the sensors
//! that would see it, so association has a known answer. Every object runs a
//! racetrack and everything is a pure function of seconds since start.

use std::time::{Duration, SystemTime};

/// A WGS-84 position.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
}

/// The coastal radar site in the Solent approaches. The ESM receiver is
/// co-located with it.
pub const RADAR: Fix = Fix {
    lat: 50.7900,
    lon: -1.1000,
};
/// Above the ellipsoid.
pub const RADAR_ALT_M: f64 = 30.0;
/// ASTERIX data source identifier.
pub const RADAR_SAC: u8 = 25;
pub const RADAR_SIC: u8 = 10;
pub const RADAR_SCAN_PERIOD_S: f64 = 2.5;
/// Range start and end in nautical miles, azimuth start and end in degrees.
/// Seaward from the site, out to the radar horizon.
pub const RADAR_WINDOW: (f64, f64, f64, f64) = (0.5, 12.0, 90.0, 270.0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensor {
    Ais,
    Adsb,
    Asterix,
    Mavlink,
    Cot,
    Esm,
    Sapient,
}

impl Sensor {
    /// Delay from observation to arrival at the connector.
    pub fn latency_s(self) -> f64 {
        // An autopilot link is near-instant; AIS goes via a shore station, CoT via a TAK server.
        match self {
            Sensor::Mavlink => 0.2,
            Sensor::Sapient => 0.3,
            Sensor::Adsb => 0.5,
            Sensor::Asterix => 1.0,
            Sensor::Esm => 1.5,
            Sensor::Cot => 3.0,
            Sensor::Ais => 4.0,
        }
    }

    pub fn period_s(self) -> f64 {
        match self {
            Sensor::Mavlink => 1.0,
            Sensor::Sapient => 1.0,
            Sensor::Adsb => 1.0,
            Sensor::Asterix => RADAR_SCAN_PERIOD_S,
            Sensor::Esm => 2.0,
            Sensor::Cot => 5.0,
            Sensor::Ais => 2.0,
        }
    }

    /// The source's clock for a report emitted at `now`.
    pub fn observed(self, now: SystemTime) -> SystemTime {
        now - Duration::from_secs_f64(self.latency_s())
    }

    /// The subcommand and log name.
    pub fn name(self) -> &'static str {
        match self {
            Sensor::Ais => "ais",
            Sensor::Adsb => "adsb",
            Sensor::Asterix => "asterix",
            Sensor::Mavlink => "mavlink",
            Sensor::Cot => "cot",
            Sensor::Esm => "esm",
            Sensor::Sapient => "sapient",
        }
    }
}

/// Advance a position along a course on a flat earth.
fn step(from: Fix, course_deg: f64, speed_mps: f64, secs: f64) -> Fix {
    let d = speed_mps * secs;
    let (s, c) = course_deg.to_radians().sin_cos();
    Fix {
        lat: from.lat + (d * c) / M_PER_DEG_LAT,
        lon: from.lon + (d * s) / (M_PER_DEG_LAT * from.lat.to_radians().cos()),
    }
}

pub const M_PER_DEG_LAT: f64 = 111_320.0;

// Defined from the base units so they match the decoders' constants exactly.
pub const FT_PER_M: f64 = 1.0 / 0.3048;
pub const MPS_TO_KN: f64 = 1.0 / 0.514_444;
pub const FTMIN_PER_MPS: f64 = FT_PER_M * 60.0;

/// Out along `course_deg` for `leg_s`, back along the reciprocal for `leg_s`,
/// repeating.
fn racetrack(start: Fix, course_deg: f64, speed_mps: f64, leg_s: f64, secs: f64) -> (Fix, f64) {
    let t = secs.rem_euclid(2.0 * leg_s);
    let far = step(start, course_deg, speed_mps, leg_s);
    if t < leg_s {
        (step(start, course_deg, speed_mps, t), course_deg)
    } else {
        let back = (course_deg + 180.0) % 360.0;
        (step(far, back, speed_mps, t - leg_s), back)
    }
}

/// True bearing in degrees and range in metres from one fix to another, on the
/// same flat earth as `step`.
pub fn bearing_range(from: Fix, to: Fix) -> (f64, f64) {
    let dn = (to.lat - from.lat) * M_PER_DEG_LAT;
    let de = (to.lon - from.lon) * M_PER_DEG_LAT * from.lat.to_radians().cos();
    let bearing = (de.atan2(dn).to_degrees() + 360.0) % 360.0;
    (bearing, dn.hypot(de))
}

/// A container ship in the Solent approaches, seen by AIS with her identity
/// and by the coastal radar without it.
pub struct Vessel;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VesselState {
    pub fix: Fix,
    pub course_deg: f64,
    pub speed_mps: f64,
}

impl Vessel {
    pub const MMSI: u32 = 235_009_870;
    pub const CALLSIGN: &'static str = "MSCL";
    pub const NAME: &'static str = "MSC LEANNE";
    pub const COURSE_DEG: f64 = 118.0;
    pub const SPEED_MPS: f64 = 8.0;
    /// Under way using engine.
    pub const NAV_STATUS: u8 = 0;
    /// Cargo, all ships of this type.
    pub const SHIP_TYPE: u8 = 70;
    /// One racetrack leg; the whole track stays inside the radar's window.
    pub const LEG_S: f64 = 900.0;
    const START: Fix = Fix {
        lat: 50.7700,
        lon: -1.1300,
    };

    pub fn at(secs: f64) -> VesselState {
        let (fix, course_deg) = racetrack(
            Self::START,
            Self::COURSE_DEG,
            Self::SPEED_MPS,
            Self::LEG_S,
            secs,
        );
        VesselState {
            fix,
            course_deg,
            speed_mps: Self::SPEED_MPS,
        }
    }
}

/// An airliner in a hold, seen by ADS-B and by the radar's system track. Both
/// carry the ICAO 24-bit address, so the pair also associates on identity.
pub struct Aircraft;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AircraftState {
    pub fix: Fix,
    pub course_deg: f64,
    pub speed_mps: f64,
    pub alt_m: f64,
    pub vertical_rate_mps: f64,
}

impl Aircraft {
    pub const ICAO24: [u8; 3] = [0x4C, 0xA2, 0xD6];
    pub const ICAO24_HEX: &'static str = "4CA2D6";
    pub const CALLSIGN: &'static str = "BAW117";
    pub const SQUAWK: &'static str = "1234";
    pub const COURSE_DEG: f64 = 271.0;
    pub const SPEED_MPS: f64 = 231.5;
    /// FL350.
    pub const ALT_M: f64 = 10_668.0;
    pub const VERTICAL_RATE_MPS: f64 = -2.54;
    /// The radar's system track number.
    pub const TRACK_NUMBER: u16 = 4095;
    pub const LEG_S: f64 = 240.0;
    const START: Fix = Fix {
        lat: 50.9300,
        lon: -0.5000,
    };

    pub fn at(secs: f64) -> AircraftState {
        let (fix, course_deg) = racetrack(
            Self::START,
            Self::COURSE_DEG,
            Self::SPEED_MPS,
            Self::LEG_S,
            secs,
        );
        AircraftState {
            fix,
            course_deg,
            speed_mps: Self::SPEED_MPS,
            alt_m: Self::ALT_M,
            vertical_rate_mps: Self::VERTICAL_RATE_MPS,
        }
    }
}

/// A small uncrewed aircraft orbiting the harbour mouth on a MAVLink link, the
/// one source that reports its own GPS accuracy.
pub struct Uav;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UavState {
    pub fix: Fix,
    pub alt_m: f64,
    pub heading_deg: f64,
    pub speed_mps: f64,
}

impl Uav {
    pub const SYSID: u8 = 1;
    pub const RADIUS_M: f64 = 900.0;
    pub const PERIOD_S: f64 = 240.0;
    pub const ALT_M: f64 = 120.0;
    /// GPS accuracies the autopilot reports.
    pub const H_ACC_M: f64 = 1.8;
    pub const V_ACC_M: f64 = 2.5;
    pub const VEL_ACC_MPS: f64 = 0.4;
    pub const HDG_ACC_DEG: f64 = 2.5;
    const CENTRE: Fix = Fix {
        lat: 50.7950,
        lon: -1.1050,
    };

    pub fn at(secs: f64) -> UavState {
        let ang = std::f64::consts::TAU * (secs % Self::PERIOD_S) / Self::PERIOD_S;
        let fix = Fix {
            lat: Self::CENTRE.lat + (Self::RADIUS_M * ang.cos()) / M_PER_DEG_LAT,
            lon: Self::CENTRE.lon
                + (Self::RADIUS_M * ang.sin())
                    / (M_PER_DEG_LAT * Self::CENTRE.lat.to_radians().cos()),
        };
        UavState {
            fix,
            alt_m: Self::ALT_M,
            // Along the tangent.
            heading_deg: (ang.to_degrees() + 90.0) % 360.0,
            speed_mps: std::f64::consts::TAU * Self::RADIUS_M / Self::PERIOD_S,
        }
    }
}

/// A friendly shore party reporting itself over CoT: an identity and a
/// position, no kinematics.
pub struct Unit;

impl Unit {
    pub const UID: &'static str = "SHORE-PARTY-1";
    pub const CALLSIGN: &'static str = "BRAVO21";
    /// Friendly, ground, unit, combat.
    pub const COT_TYPE: &'static str = "a-f-G-U-C";
    pub const FIX: Fix = Fix {
        lat: 50.8020,
        lon: -1.1120,
    };
    pub const ALT_M: f64 = 12.0;
}

/// A navigation radar on the vessel, intercepted by the ESM receiver at the
/// coastal radar site.
pub struct Emitter;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmitterState {
    /// The vessel's position.
    pub fix: Fix,
    /// True, from the receiver.
    pub bearing_deg: f64,
    /// Received, varying with range and aspect.
    pub power_dbm: f64,
}

impl Emitter {
    pub const ID: &'static str = "EM-NAV-1";
    /// X-band navigation radar.
    pub const FREQUENCY_HZ: u64 = 9_410_000_000;
    pub const BANDWIDTH_HZ: u64 = 20_000_000;
    pub const POWER_DBM: f64 = -47.2;
    pub const ELNOT: &'static str = "G1234";
    pub const PRF_HZ: f64 = 2100.0;
    pub const PULSE_WIDTH_US: f64 = 0.08;
    /// `scan_type` is governed free text.
    pub const SCAN_TYPE: &'static str = "circular";
    pub const SCAN_PERIOD_S: f64 = 2.5;
    pub const BEARING_ACCURACY_DEG: f64 = 2.0;

    pub fn at(secs: f64) -> EmitterState {
        let v = Vessel::at(secs);
        let (bearing_deg, range_m) = bearing_range(RADAR, v.fix);
        // Free-space path loss with range, plus a slow aspect wobble.
        let power_dbm =
            Self::POWER_DBM - 20.0 * (range_m / 5_000.0).log10() + 1.5 * (secs / 7.0).sin();
        EmitterState {
            fix: v.fix,
            bearing_deg,
            power_dbm,
        }
    }
}

/// RFC 3339 UTC to the second.
pub fn rfc3339(t: SystemTime) -> String {
    let odt = time::OffsetDateTime::from(t)
        .replace_nanosecond(0)
        .expect("zero is valid");
    odt.format(&time::format_description::well_known::Rfc3339)
        .expect("RFC 3339 formatting of a valid time")
}

/// Seconds since midnight UTC, for the wire formats that carry time of day.
pub fn seconds_since_midnight(t: SystemTime) -> f64 {
    let odt = time::OffsetDateTime::from(t);
    let (h, m, s, ms) = (
        odt.hour() as f64,
        odt.minute() as f64,
        odt.second() as f64,
        odt.millisecond() as f64,
    );
    h * 3600.0 + m * 60.0 + s + ms / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vessel_racetrack_stays_in_radar_window() {
        let a = Vessel::at(0.0);
        let b = Vessel::at(60.0);
        let (bearing, range) = bearing_range(a.fix, b.fix);
        assert!((bearing - Vessel::COURSE_DEG).abs() < 0.5, "{bearing}");
        assert!((range - 60.0 * Vessel::SPEED_MPS).abs() < 1.0, "{range}");
        let far = Vessel::at(Vessel::LEG_S);
        let back = Vessel::at(Vessel::LEG_S + 60.0);
        assert!(
            (back.course_deg - (Vessel::COURSE_DEG + 180.0) % 360.0).abs() < 1e-9,
            "the far end turns back along the reciprocal"
        );
        let (_, r) = bearing_range(far.fix, back.fix);
        assert!((r - 60.0 * Vessel::SPEED_MPS).abs() < 1.0);
        let home = Vessel::at(2.0 * Vessel::LEG_S);
        assert!(
            (home.fix.lat - a.fix.lat).abs() < 1e-6 && (home.fix.lon - a.fix.lon).abs() < 1e-6,
            "a full lap returns to the start"
        );
        let (_, r_end, a0, a1) = RADAR_WINDOW;
        for secs in (0..(2.0 * Vessel::LEG_S) as u32).step_by(10) {
            let (b, r) = bearing_range(RADAR, Vessel::at(secs as f64).fix);
            assert!(
                r < r_end * 1852.0 && r < 65_535.0,
                "{secs}s: {r} m outside the window or the CAT010 range field"
            );
            assert!(b >= a0 && b <= a1, "{secs}s: bearing {b}");
        }
        let (_, r_air) = bearing_range(RADAR, Aircraft::at(Aircraft::LEG_S).fix);
        assert!(
            r_air < 100_000.0,
            "the hold stays within a radar's reach: {r_air} m"
        );
    }

    #[test]
    fn emitter_bearing_points_at_vessel() {
        for secs in [0.0, 30.0, 300.0] {
            let v = Vessel::at(secs);
            let e = Emitter::at(secs);
            assert_eq!(e.fix, v.fix);
            let (b, _) = bearing_range(RADAR, v.fix);
            assert_eq!(e.bearing_deg, b);
            assert!((0.0..360.0).contains(&e.bearing_deg));
        }
    }

    #[test]
    fn uav_orbits_centre_along_tangent() {
        let a = Uav::at(0.0);
        let b = Uav::at(Uav::PERIOD_S / 4.0);
        let (_, r) = bearing_range(Uav::CENTRE, a.fix);
        assert!((r - Uav::RADIUS_M).abs() < 1.0, "{r}");
        assert!(
            ((b.heading_deg - a.heading_deg + 360.0) % 360.0 - 90.0).abs() < 0.01,
            "a quarter orbit turns the heading a quarter"
        );
        let full = Uav::at(Uav::PERIOD_S);
        assert!((full.fix.lat - a.fix.lat).abs() < 1e-9);
    }

    #[test]
    fn each_sensor_lags_by_its_latency() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for s in [Sensor::Ais, Sensor::Mavlink, Sensor::Cot] {
            let lag = now.duration_since(s.observed(now)).unwrap().as_secs_f64();
            assert!((lag - s.latency_s()).abs() < 1e-6, "{s:?}");
        }
        assert!(Sensor::Ais.latency_s() > Sensor::Mavlink.latency_s());
    }

    #[test]
    fn rfc3339_is_whole_seconds_utc() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1_780_000_000_123);
        assert_eq!(rfc3339(t), "2026-05-28T20:26:40Z");
        assert!((seconds_since_midnight(t) - 73_600.123).abs() < 1e-6);
    }
}
