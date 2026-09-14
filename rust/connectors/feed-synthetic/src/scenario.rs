// SPDX-License-Identifier: Apache-2.0
//! The fixture every feed renders: one set of objects, seen by six sensors.
//!
//! One shared world rather than six independent feeds, because a fusion
//! consumer's task is deciding that two reports are the same object. The same
//! vessel is seen by the coastal radar and by AIS, the same aircraft by ADS-B
//! and by the radar's system track, and an emitter sits on the vessel, so
//! association has work to do and a known answer.
//!
//! Each sensor emits only what that sensor carries: AIS has an identity and no
//! accuracy, radar has accuracy and no identity, CoT has an identity and no
//! kinematics, the ESM intercept has a bearing and no position.
//!
//! Latency is per sensor. The event's `timestamp` is when the source observed
//! the object; Core stamps its own receipt time on arrival. The two diverge by
//! the sensor's latency, as they do in the field.
//!
//! Every object runs a racetrack, so the fixture is bounded: the objects stay
//! inside the radar's window and the association cases hold for as long as
//! the feed runs. Everything is a pure function of seconds since start, so a
//! generator and a decoder test see exactly the same world.

use std::time::{Duration, SystemTime};

/// A WGS-84 position.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
}

/// The coastal radar site in the Solent approaches. Real geography, so bearings
/// and ranges are sane and a consumer can sanity-check a plot on any chart. The
/// ESM receiver is co-located with it.
pub const RADAR: Fix = Fix {
    lat: 50.7900,
    lon: -1.1000,
};
/// Height of the radar site above the ellipsoid, metres.
pub const RADAR_ALT_M: f64 = 30.0;
/// The radar's ASTERIX data source identifier (SAC, SIC).
pub const RADAR_SAC: u8 = 25;
pub const RADAR_SIC: u8 = 10;
/// The radar's antenna rotation period, seconds.
pub const RADAR_SCAN_PERIOD_S: f64 = 2.5;
/// The radar's declared polar window: range in nautical miles, azimuth in
/// degrees. Seaward from the site, out to the horizon a 30 m mast sees.
pub const RADAR_WINDOW: (f64, f64, f64, f64) = (0.5, 12.0, 90.0, 270.0);

/// The sensors in the scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensor {
    Ais,
    Adsb,
    Asterix,
    Mavlink,
    Cot,
    Esm,
}

impl Sensor {
    /// How late this sensor's reports reach the connector, seconds. A direct
    /// radio link and an autopilot are near-instant; AIS goes via a shore
    /// station; CoT via a TAK server.
    pub fn latency(self) -> f64 {
        match self {
            Sensor::Mavlink => 0.2,
            Sensor::Adsb => 0.5,
            Sensor::Asterix => 1.0,
            Sensor::Esm => 1.5,
            Sensor::Cot => 3.0,
            Sensor::Ais => 4.0,
        }
    }

    /// How often this sensor reports, seconds. A radar reports once per
    /// rotation; a slow-moving shore party once every few seconds.
    pub fn period(self) -> f64 {
        match self {
            Sensor::Mavlink => 1.0,
            Sensor::Adsb => 1.0,
            Sensor::Asterix => RADAR_SCAN_PERIOD_S,
            Sensor::Esm => 2.0,
            Sensor::Cot => 5.0,
            Sensor::Ais => 2.0,
        }
    }

    /// The source's own clock for a report emitted at `now`: behind by the
    /// sensor's latency, which is what the event's timestamp carries.
    pub fn observed(self, now: SystemTime) -> SystemTime {
        now - Duration::from_secs_f64(self.latency())
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
        }
    }
}

/// Advance a position along a course. Flat earth, adequate over these
/// distances.
fn step(from: Fix, course_deg: f64, speed_mps: f64, secs: f64) -> Fix {
    let d = speed_mps * secs;
    let (s, c) = course_deg.to_radians().sin_cos();
    Fix {
        lat: from.lat + (d * c) / M_PER_DEG_LAT,
        lon: from.lon + (d * s) / (M_PER_DEG_LAT * from.lat.to_radians().cos()),
    }
}

/// Metres per degree of latitude.
pub const M_PER_DEG_LAT: f64 = 111_320.0;

/// Unit factors, defined from the contract's base units so the encoders and
/// the decoders' own constants agree to the last digit.
pub const FT_PER_M: f64 = 1.0 / 0.3048;
pub const MPS_TO_KN: f64 = 1.0 / 0.514_444;
pub const FTMIN_PER_MPS: f64 = FT_PER_M * 60.0;

/// A racetrack: out along `course` for `leg_s`, back along the reciprocal for
/// `leg_s`, repeating. Position is continuous; the course flips each leg.
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

/// True bearing and range from one fix to another, degrees and metres, on the
/// same flat earth the motion uses, so a bearing a sensor reports points at
/// exactly where the scenario put the target.
pub fn bearing_range(from: Fix, to: Fix) -> (f64, f64) {
    let dn = (to.lat - from.lat) * M_PER_DEG_LAT;
    let de = (to.lon - from.lon) * M_PER_DEG_LAT * from.lat.to_radians().cos();
    let bearing = (de.atan2(dn).to_degrees() + 360.0) % 360.0;
    (bearing, dn.hypot(de))
}

/// A container ship running a 15-minute racetrack in the Solent approaches.
///
/// Seen twice: by AIS, which states her identity, and by the coastal radar,
/// which does not. The pair associates on position and time alone.
pub struct Vessel;

/// Where the vessel is and how she is moving.
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
    /// About 15.5 knots.
    pub const SPEED_MPS: f64 = 8.0;
    /// AIS navigational status 0: under way using engine.
    pub const NAV_STATUS: u8 = 0;
    /// AIS ship type 70: cargo, all ships of this type.
    pub const SHIP_TYPE: u8 = 70;
    /// One leg of the racetrack, seconds. 7.2 km at this speed, inside the
    /// radar's window throughout.
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

/// An airliner holding at FL350 on a 4-minute racetrack.
///
/// Also seen twice: by ADS-B, cooperatively, and by the radar's system track.
/// Both carry the ICAO 24-bit address, so this pair associates on identity as
/// well as on position and time: the known-answer case.
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
    /// About 450 knots.
    pub const SPEED_MPS: f64 = 231.5;
    /// FL350.
    pub const ALT_M: f64 = 10_668.0;
    /// About 500 feet per minute down.
    pub const VERTICAL_RATE_MPS: f64 = -2.54;
    /// The radar's system track number for this aircraft.
    pub const TRACK_NUMBER: u16 = 4095;
    /// One leg of the hold, seconds: 55 km at this speed.
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

/// A small uncrewed aircraft orbiting the harbour mouth on a MAVLink link.
/// The only source that reports its own GPS uncertainty, so the only one
/// carrying every accuracy attribute.
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
    /// GPS accuracies the autopilot reports: horizontal and vertical metres,
    /// velocity metres per second, heading degrees.
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
            // Tangential heading, and the speed that carries it round the circle.
            heading_deg: (ang.to_degrees() + 90.0) % 360.0,
            speed_mps: std::f64::consts::TAU * Self::RADIUS_M / Self::PERIOD_S,
        }
    }
}

/// A friendly shore party reporting itself over CoT: an identity and a
/// position, no course, no speed, no accuracy.
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

/// A navigation radar mounted on the vessel, intercepted by an ESM receiver
/// ashore, co-located with the coastal radar: an emission with parameters and
/// no identity of its own. The contract's platform link names the vessel.
pub struct Emitter;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmitterState {
    /// Where the emitter really is: on the vessel. The bearing points here.
    pub fix: Fix,
    /// True bearing from the receiver to the emitter, degrees.
    pub bearing_deg: f64,
    /// Received power, dBm, varying with range and aspect.
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
    /// The receiver's own word for the scan; `scan_type` is governed free text.
    pub const SCAN_TYPE: &'static str = "circular";
    pub const SCAN_PERIOD_S: f64 = 2.5;
    pub const BEARING_ACCURACY_DEG: f64 = 2.0;

    pub fn at(secs: f64) -> EmitterState {
        let v = Vessel::at(secs);
        let (bearing_deg, range_m) = bearing_range(RADAR, v.fix);
        // Free-space path loss grows with range; a slow aspect wobble on top.
        let power_dbm =
            Self::POWER_DBM - 20.0 * (range_m / 5_000.0).log10() + 1.5 * (secs / 7.0).sin();
        EmitterState {
            fix: v.fix,
            bearing_deg,
            power_dbm,
        }
    }
}

/// RFC 3339 UTC to the second, the form every connector and the contract expect.
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
    fn the_vessel_runs_her_racetrack_inside_the_radars_window() {
        let a = Vessel::at(0.0);
        let b = Vessel::at(60.0);
        let (bearing, range) = bearing_range(a.fix, b.fix);
        assert!((bearing - Vessel::COURSE_DEG).abs() < 0.5, "{bearing}");
        assert!((range - 60.0 * Vessel::SPEED_MPS).abs() < 1.0, "{range}");
        // The far end turns back along the reciprocal and returns to the start.
        let far = Vessel::at(Vessel::LEG_S);
        let back = Vessel::at(Vessel::LEG_S + 60.0);
        assert!((back.course_deg - (Vessel::COURSE_DEG + 180.0) % 360.0).abs() < 1e-9);
        let (_, r) = bearing_range(far.fix, back.fix);
        assert!((r - 60.0 * Vessel::SPEED_MPS).abs() < 1.0);
        let home = Vessel::at(2.0 * Vessel::LEG_S);
        assert!((home.fix.lat - a.fix.lat).abs() < 1e-6 && (home.fix.lon - a.fix.lon).abs() < 1e-6);
        // Every point of the track is inside the radar's declared window, and
        // within the range a CAT010 plot can carry, for as long as it runs.
        let (_, r_end, a0, a1) = RADAR_WINDOW;
        for secs in (0..(2.0 * Vessel::LEG_S) as u32).step_by(10) {
            let (b, r) = bearing_range(RADAR, Vessel::at(secs as f64).fix);
            assert!(r < r_end * 1852.0 && r < 65_535.0, "{secs}s: {r} m");
            assert!(b >= a0 && b <= a1, "{secs}s: bearing {b}");
        }
        let (_, r_air) = bearing_range(RADAR, Aircraft::at(Aircraft::LEG_S).fix);
        assert!(
            r_air < 100_000.0,
            "the hold stays within a radar's reach: {r_air} m"
        );
    }

    #[test]
    fn the_emitter_is_on_the_vessel_and_its_bearing_points_there() {
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
    fn the_uav_orbits_its_centre_and_heads_along_the_tangent() {
        let a = Uav::at(0.0);
        let b = Uav::at(Uav::PERIOD_S / 4.0);
        let (_, r) = bearing_range(Uav::CENTRE, a.fix);
        assert!((r - Uav::RADIUS_M).abs() < 1.0, "{r}");
        // A quarter turn later the heading has turned a quarter.
        assert!(((b.heading_deg - a.heading_deg + 360.0) % 360.0 - 90.0).abs() < 0.01);
        let full = Uav::at(Uav::PERIOD_S);
        assert!((full.fix.lat - a.fix.lat).abs() < 1e-9);
    }

    #[test]
    fn every_sensor_lags_by_its_own_latency() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        for s in [Sensor::Ais, Sensor::Mavlink, Sensor::Cot] {
            let lag = now.duration_since(s.observed(now)).unwrap().as_secs_f64();
            assert!((lag - s.latency()).abs() < 1e-6, "{s:?}");
        }
        assert!(Sensor::Ais.latency() > Sensor::Mavlink.latency());
    }

    #[test]
    fn rfc3339_is_whole_seconds_utc() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_millis(1_780_000_000_123);
        assert_eq!(rfc3339(t), "2026-05-28T20:26:40Z");
        assert!((seconds_since_midnight(t) - 73_600.123).abs() < 1e-6);
    }
}
