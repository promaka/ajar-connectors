// SPDX-License-Identifier: Apache-2.0
//! One world, seen by several sensors: the shared scenario every feed renders.
//!
//! Why one scenario rather than six independent feeds: a fusion partner's whole
//! job is deciding that two reports are the same object. Independent random
//! feeds give them nothing to decide, so a demonstration built that way proves
//! the plumbing and none of the thing the plumbing exists for. Here the same
//! vessel is seen by a coastal radar and by AIS, the same aircraft by ADS-B and
//! by the radar's system track, and an emitter sits on the vessel, so there is
//! real association work to do and a real answer to check it against.
//!
//! The other half of the point is honest gaps. Each sensor emits only what that
//! sensor genuinely carries: AIS has an identity and no accuracy, radar has
//! accuracy and no identity, CoT has an identity and no kinematics. A feed where
//! every sensor reported every field would teach a consumer to expect something
//! no real deployment delivers.
//!
//! Latency is per sensor and deliberate. The event's `timestamp` is when the
//! source observed the thing; Core stamps its own receipt time on arrival. Those
//! diverge in the real world, which is why both are on the wire, and a consumer
//! correlating on arrival time rather than observation time concludes a target
//! teleported. A scenario where everything arrived instantly would hide the
//! mistake instead of exposing it.
//!
//! Everything here is a pure function of seconds since the scenario started, so
//! a generator and a test see exactly the same world.

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
}

/// Advance a position along a course. Flat-earth over these distances keeps
/// the scenario readable; the point is plausible motion, not navigation.
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

/// True bearing and range from one fix to another, degrees and metres, on the
/// same flat earth the motion uses, so a bearing a sensor reports points at
/// exactly where the scenario put the target.
pub fn bearing_range(from: Fix, to: Fix) -> (f64, f64) {
    let dn = (to.lat - from.lat) * M_PER_DEG_LAT;
    let de = (to.lon - from.lon) * M_PER_DEG_LAT * from.lat.to_radians().cos();
    let bearing = (de.atan2(dn).to_degrees() + 360.0) % 360.0;
    (bearing, dn.hypot(de))
}

/// A container ship outbound through the Solent.
///
/// Seen twice: by AIS, which says who she is, and by the coastal radar, which
/// does not. That pair is the cleanest association case there is: same
/// position, same time, one identity. It is what makes the radar plot useful.
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
    const START: Fix = Fix {
        lat: 50.8180,
        lon: -1.0870,
    };

    pub fn at(secs: f64) -> VesselState {
        VesselState {
            fix: step(Self::START, Self::COURSE_DEG, Self::SPEED_MPS, secs),
            course_deg: Self::COURSE_DEG,
            speed_mps: Self::SPEED_MPS,
        }
    }
}

/// An airliner westbound at FL350.
///
/// Also seen twice: by ADS-B, cooperatively, and by the radar's system track.
/// Both carry the ICAO 24-bit address, so this pair associates on identity as
/// well as on space and time. The easy case, included so a consumer can check
/// their harder space-time association against a known answer.
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
    const START: Fix = Fix {
        lat: 50.9300,
        lon: -0.8000,
    };

    pub fn at(secs: f64) -> AircraftState {
        AircraftState {
            fix: step(Self::START, Self::COURSE_DEG, Self::SPEED_MPS, secs),
            course_deg: Self::COURSE_DEG,
            speed_mps: Self::SPEED_MPS,
            alt_m: Self::ALT_M,
            vertical_rate_mps: Self::VERTICAL_RATE_MPS,
        }
    }
}

/// A small uncrewed aircraft orbiting the harbour mouth on a MAVLink link.
///
/// The only source here that reports its own attitude and GPS uncertainty,
/// which is why it is the one carrying every accuracy attribute at once.
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

/// A friendly shore party reporting itself over CoT.
///
/// Carries an identity and a position and nothing else, which is exactly what
/// a CoT self-report gives you: no course, no speed, no accuracy.
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
/// ashore, co-located with the coastal radar.
///
/// This is the case a fusion partner cares about most and can least often
/// resolve: an emission with parameters but no identity. Knowing which platform
/// it sits on is most of what an emitter library would tell them, which is why
/// the contract carries the link and this feed states it.
pub struct Emitter;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmitterState {
    /// Where the emitter really is: on the vessel. The bearing points here.
    pub fix: Fix,
    /// True bearing from the receiver to the emitter, degrees.
    pub bearing_deg: f64,
    /// Received power, dBm, varying with range and aspect so a consumer
    /// learns not to key on it.
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
    /// The receiver's own word for it; not in the contract's modulation set,
    /// which is the point: it rides in metadata, not in the governed attribute.
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
    fn the_vessel_moves_along_her_course_at_her_speed() {
        let a = Vessel::at(0.0);
        let b = Vessel::at(60.0);
        let (bearing, range) = bearing_range(a.fix, b.fix);
        assert!((bearing - Vessel::COURSE_DEG).abs() < 0.5, "{bearing}");
        assert!((range - 60.0 * Vessel::SPEED_MPS).abs() < 1.0, "{range}");
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
