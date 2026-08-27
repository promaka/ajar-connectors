// SPDX-License-Identifier: Apache-2.0
//! ARPA radar tracked targets (`$--TTM`) -> canonical Ajar events.
//!
//! Every bridge radar with target tracking emits its contacts as NMEA 0183
//! `TTM` sentences on the same bus that carries AIS, so one connector on one
//! serial or UDP feed yields both the cooperative picture (AIS transponders)
//! and the radar picture (what the radar actually sees, transponder or not).
//! That pairing is the naval unified-picture case in one config file.
//!
//! A TTM position is a range and bearing FROM OWN SHIP, so geolocating it
//! needs the observer's own position. Two sources, in priority order:
//!
//!  1. Own-ship GPS on the same bus: `$--GGA` / `$--RMC` sentences update a
//!     cached fix. A moving warship is the normal case.
//!  2. The `[sensor]` site from config, for a shore-mounted ARPA that never
//!     moves — the same convention the ASTERIX CAT048 connector uses.
//!
//! Without either (or when the cached fix has gone stale), the target's range
//! and bearing ride as metadata and the event carries no absolute location —
//! never a guessed one. Relative bearings (the `R` flag) are likewise not
//! geolocated: resolving them needs own heading, and a wrong assumption there
//! would place a contact on the wrong side of the ship. The raw sentence is
//! preserved verbatim in the payload either way, so nothing is lost.
//!
//! A domain is not a classification: a radar return says "something on the
//! surface", so targets are `mim:object` with `environment = SURFACE`, never a
//! guessed vessel type.

use std::sync::Mutex;

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::Enrichment;

use crate::ais::AisError;

/// 1 knot in metres/second (governed `speed` is m/s; ADR-0019).
const KNOTS_TO_MPS: f64 = 0.514_444;
/// 1 nautical mile in metres.
const NM_TO_M: f64 = 1_852.0;
/// Mean Earth radius in metres, for the spherical forward solution.
const EARTH_RADIUS_M: f64 = 6_371_000.0;
/// An own-ship fix older than this no longer geolocates targets: a minute-old
/// position on a ship at 20 knots is already ~600 m of error.
const FIX_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// The observer's latest known position.
#[derive(Debug, Clone, Copy)]
struct OwnFix {
    lat: f64,
    lon: f64,
    at: std::time::Instant,
}

/// Own-ship state plus a static fallback site, shared across sentences.
pub struct TtmState {
    fix: Mutex<Option<OwnFix>>,
    /// Shore installation: a fixed observer from config.
    site: Option<(f64, f64)>,
}

/// One tracked target, decoded and (when possible) geolocated.
#[derive(Debug, PartialEq)]
pub struct RadarTarget {
    /// Target number as the radar reports it (00-99).
    pub number: String,
    /// Absolute position, when an observer fix was available and bearing true.
    pub position: Option<(f64, f64)>,
    /// Range in metres and TRUE bearing in degrees, as measured.
    pub range_m: f64,
    pub bearing_deg: Option<f64>,
    /// Target speed in m/s and course in degrees, when reported as true.
    pub speed_mps: Option<f64>,
    pub course_deg: Option<f64>,
    /// Radar-assigned name, if the operator labelled the target.
    pub name: Option<String>,
    /// Closest point of approach: distance (m) and time (minutes).
    pub cpa_m: Option<f64>,
    pub tcpa_min: Option<f64>,
    /// The verbatim sentence, for the signed payload.
    pub raw: Vec<u8>,
}

impl TtmState {
    pub fn new(site: Option<(f64, f64)>) -> Self {
        Self {
            fix: Mutex::new(None),
            site,
        }
    }

    /// True if this sentence type belongs to the radar/own-ship family.
    pub fn wants(sentence: &str) -> bool {
        let star = sentence.find('*').unwrap_or(sentence.len());
        let talker = sentence[..star].split(',').next().unwrap_or("");
        talker.len() >= 3
            && (talker.ends_with("TTM") || talker.ends_with("GGA") || talker.ends_with("RMC"))
    }

    /// Handle one radar-family sentence: GGA/RMC update the own-ship fix and
    /// emit nothing; TTM yields a target when the radar reports it as tracked.
    pub fn handle(&self, fields: &[&str], raw: Vec<u8>) -> Result<Option<RadarTarget>, AisError> {
        let kind = fields[0];
        if kind.ends_with("GGA") {
            self.update_fix_gga(fields);
            return Ok(None);
        }
        if kind.ends_with("RMC") {
            self.update_fix_rmc(fields);
            return Ok(None);
        }
        self.decode_ttm(fields, raw)
    }

    /// `$--GGA,time,lat,N/S,lon,E/W,quality,...` — quality 0 means no fix.
    fn update_fix_gga(&self, f: &[&str]) {
        if f.len() < 7 || f[6] == "0" {
            return;
        }
        if let (Some(lat), Some(lon)) = (
            parse_coord(f.get(2), f.get(3)),
            parse_coord(f.get(4), f.get(5)),
        ) {
            *self.fix.lock().expect("fix mutex") = Some(OwnFix {
                lat,
                lon,
                at: std::time::Instant::now(),
            });
        }
    }

    /// `$--RMC,time,status,lat,N/S,lon,E/W,...` — status A means valid.
    fn update_fix_rmc(&self, f: &[&str]) {
        if f.len() < 7 || f[2] != "A" {
            return;
        }
        if let (Some(lat), Some(lon)) = (
            parse_coord(f.get(3), f.get(4)),
            parse_coord(f.get(5), f.get(6)),
        ) {
            *self.fix.lock().expect("fix mutex") = Some(OwnFix {
                lat,
                lon,
                at: std::time::Instant::now(),
            });
        }
    }

    /// The observer to geolocate against: a fresh GPS fix, else the static site.
    fn observer(&self) -> Option<(f64, f64)> {
        if let Some(fix) = *self.fix.lock().expect("fix mutex") {
            if fix.at.elapsed() <= FIX_MAX_AGE {
                return Some((fix.lat, fix.lon));
            }
        }
        self.site
    }

    /// `$--TTM,num,dist,brg,T|R,speed,course,T|R,cpa,tcpa,units,name,status,...`
    fn decode_ttm(&self, f: &[&str], raw: Vec<u8>) -> Result<Option<RadarTarget>, AisError> {
        if f.len() < 13 {
            return Err(AisError::Fields);
        }
        // Only a target the radar itself calls tracked becomes an event; a
        // lost target's last report is stale and an acquiring one is noise.
        if f[12] != "T" {
            return Ok(None);
        }
        let number = f[1].trim();
        if number.is_empty() {
            return Err(AisError::Fields);
        }

        // Units apply to distance AND speed: N = nm/knots (the fielded
        // default), K = km & km/h, S = statute miles & mph.
        let (dist_to_m, speed_to_mps) = match *f.get(10).unwrap_or(&"N") {
            "K" => (1_000.0, 1.0 / 3.6),
            "S" => (1_609.344, 0.447_04),
            _ => (NM_TO_M, KNOTS_TO_MPS),
        };

        let range_m = match f[2].parse::<f64>() {
            Ok(d) if d >= 0.0 => d * dist_to_m,
            _ => return Err(AisError::Fields),
        };
        let bearing_true = f[4] == "T";
        let bearing_deg = f[3]
            .parse::<f64>()
            .ok()
            .filter(|b| (0.0..=360.0).contains(b));
        let speed_mps = f[5].parse::<f64>().ok().map(|s| s * speed_to_mps);
        let course_deg = if f[7] == "T" {
            f[6].parse::<f64>()
                .ok()
                .filter(|c| (0.0..=360.0).contains(c))
        } else {
            None
        };
        let cpa_m = f[8].parse::<f64>().ok().map(|d| d * dist_to_m);
        let tcpa_min = f[9].parse::<f64>().ok();
        let name = f
            .get(11)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(String::from);

        // Geolocate only when the maths is honest: a true bearing and a live
        // observer. Anything else stays a relative measurement in metadata.
        let position = match (bearing_true, bearing_deg, self.observer()) {
            (true, Some(brg), Some((lat, lon))) => Some(forward(lat, lon, brg, range_m)),
            _ => None,
        };

        Ok(Some(RadarTarget {
            number: number.to_string(),
            position,
            range_m,
            bearing_deg,
            speed_mps,
            course_deg,
            name,
            cpa_m,
            tcpa_min,
            raw,
        }))
    }
}

/// Spherical forward solution: the point `distance_m` from (`lat`, `lon`) along
/// true bearing `bearing_deg`. Exact on the sphere; within centimetres of the
/// ellipsoid at radar ranges.
fn forward(lat: f64, lon: f64, bearing_deg: f64, distance_m: f64) -> (f64, f64) {
    let (phi1, lam1, theta) = (lat.to_radians(), lon.to_radians(), bearing_deg.to_radians());
    let delta = distance_m / EARTH_RADIUS_M;
    let phi2 = (phi1.sin() * delta.cos() + phi1.cos() * delta.sin() * theta.cos()).asin();
    let lam2 = lam1
        + (theta.sin() * delta.sin() * phi1.cos()).atan2(delta.cos() - phi1.sin() * phi2.sin());
    (phi2.to_degrees(), lam2.to_degrees())
}

/// NMEA ddmm.mmmm + hemisphere -> signed decimal degrees.
fn parse_coord(value: Option<&&str>, hemi: Option<&&str>) -> Option<f64> {
    let v = value?.trim();
    let h = hemi?.trim();
    if v.len() < 3 {
        return None;
    }
    let split = v.find('.').unwrap_or(v.len()).saturating_sub(2);
    let degrees: f64 = v[..split].parse().ok()?;
    let minutes: f64 = v[split..].parse().ok()?;
    let dd = degrees + minutes / 60.0;
    match h {
        "N" | "E" => Some(dd),
        "S" | "W" => Some(-dd),
        _ => None,
    }
}

/// Build the canonical event for one radar target.
pub fn to_event(
    source_id: &str,
    enrichment: &Enrichment,
    t: &RadarTarget,
) -> Result<Event, String> {
    let mut b = EventBuilder::new(source_id.to_string(), "mim:object")
        .new_id()
        .now()
        .payload(t.raw.clone())
        .metadata("source_uid", format!("arpa-{}", t.number))
        .metadata("target_number", t.number.clone())
        .metadata("range_m", format!("{:.0}", t.range_m))
        .attribute("environment", "SURFACE");

    if let Some((lat, lon)) = t.position {
        b = b.location(lat, lon, 0.0);
    }
    if let Some(brg) = t.bearing_deg {
        b = b.metadata("bearing_deg", format!("{brg:.1}"));
    }
    if let Some(v) = t.speed_mps {
        b = b.attribute("speed", format!("{v:.2}"));
    }
    if let Some(c) = t.course_deg {
        b = b.attribute("course", format!("{c:.1}"));
    }
    if let Some(n) = &t.name {
        b = b.attribute("callsign", n.clone());
    }
    if let Some(cpa) = t.cpa_m {
        b = b.metadata("cpa_m", format!("{cpa:.0}"));
    }
    if let Some(tcpa) = t.tcpa_min {
        b = b.metadata("tcpa_min", format!("{tcpa:.1}"));
    }
    if let Some(h) = enrichment.hostility.as_deref() {
        b = b.attribute("hostility", h);
    }
    b.build().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a body in NMEA framing with a computed checksum, so tests never
    /// carry hand-typed checksums that rot when a sentence changes.
    fn sentence(body: &str) -> String {
        let cs = body.bytes().fold(0u8, |a, b| a ^ b);
        format!("${body}*{cs:02X}")
    }

    fn fields(s: &str) -> Vec<String> {
        let star = s.find('*').unwrap();
        s[1..star].split(',').map(String::from).collect()
    }

    fn handle(state: &TtmState, s: &str) -> Result<Option<RadarTarget>, AisError> {
        let f = fields(s);
        let refs: Vec<&str> = f.iter().map(String::as_str).collect();
        state.handle(&refs, s.as_bytes().to_vec())
    }

    const OWN_GGA: &str = "GPGGA,120000,6000.000,N,00500.000,E,1,08,0.9,5.0,M,45.0,M,,";
    // Target 07: 1.0 nm at 090 true, 10 kn on course 180 true, tracked.
    const TARGET: &str = "RATTM,07,1.0,90.0,T,10.0,180.0,T,0.5,4.0,N,SKJOLD,T,,120010,A";

    #[test]
    fn a_tracked_target_geolocates_from_the_gps_fix() {
        let state = TtmState::new(None);
        assert!(handle(&state, &sentence(OWN_GGA)).unwrap().is_none());
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        let (lat, lon) = t.position.expect("true bearing + fresh fix geolocates");
        // 1 nm due east of 60N 5E: latitude unchanged, longitude +1/60 deg
        // divided by cos(60) = +0.0333 deg.
        assert!((lat - 60.0).abs() < 1e-3, "lat {lat}");
        assert!((lon - 5.0333).abs() < 2e-3, "lon {lon}");
        assert!((t.range_m - 1852.0).abs() < 0.5);
        assert!((t.speed_mps.unwrap() - 5.144_44).abs() < 1e-3);
        assert_eq!(t.name.as_deref(), Some("SKJOLD"));
        assert!((t.cpa_m.unwrap() - 926.0).abs() < 0.5);
    }

    #[test]
    fn without_any_observer_the_target_carries_no_position() {
        let state = TtmState::new(None);
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        assert!(
            t.position.is_none(),
            "no fix, no site: never a guessed position"
        );
        assert!(
            (t.range_m - 1852.0).abs() < 0.5,
            "the measurement itself survives"
        );
    }

    #[test]
    fn a_shore_site_geolocates_when_no_gps_is_on_the_bus() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        assert!(t.position.is_some());
    }

    #[test]
    fn a_relative_bearing_is_never_geolocated() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let rel = "RATTM,07,1.0,90.0,R,10.0,180.0,T,0.5,4.0,N,,T,,120010,A";
        let t = handle(&state, &sentence(rel)).unwrap().unwrap();
        assert!(
            t.position.is_none(),
            "resolving R needs heading; a guess flips sides"
        );
        assert!(
            t.bearing_deg.is_some(),
            "the relative measurement rides as data"
        );
    }

    #[test]
    fn lost_and_acquiring_targets_do_not_emit() {
        let state = TtmState::new(Some((60.0, 5.0)));
        for status in ["L", "Q"] {
            let s = format!("RATTM,07,1.0,90.0,T,10.0,180.0,T,0.5,4.0,N,,{status},,120010,A");
            assert!(handle(&state, &sentence(&s)).unwrap().is_none(), "{status}");
        }
    }

    #[test]
    fn kilometre_units_convert() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let s = "RATTM,08,1.852,90.0,T,3.6,180.0,T,0.5,4.0,K,,T,,120010,A";
        let t = handle(&state, &sentence(s)).unwrap().unwrap();
        assert!((t.range_m - 1852.0).abs() < 0.5);
        assert!((t.speed_mps.unwrap() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn a_stale_fix_stops_geolocating_but_a_site_does_not_expire() {
        // Directly: the observer preference logic, no sleeping in tests.
        let state = TtmState::new(Some((60.0, 5.0)));
        *state.fix.lock().unwrap() = Some(OwnFix {
            lat: 61.0,
            lon: 6.0,
            at: std::time::Instant::now() - (FIX_MAX_AGE + std::time::Duration::from_secs(1)),
        });
        assert_eq!(
            state.observer(),
            Some((60.0, 5.0)),
            "stale fix falls back to the site"
        );
    }

    #[test]
    fn the_event_is_an_object_on_the_surface_with_the_native_identity() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        let ev = to_event("hms-example", &Enrichment::default(), &t).unwrap();
        assert_eq!(ev.entity_type, "mim:object");
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.clone())
        };
        let meta = |k: &str| {
            ev.metadata
                .iter()
                .find(|m| m.key == k)
                .map(|m| m.value.clone())
        };
        assert_eq!(attr("environment").as_deref(), Some("SURFACE"));
        assert_eq!(attr("callsign").as_deref(), Some("SKJOLD"));
        assert_eq!(meta("source_uid").as_deref(), Some("arpa-07"));
        assert_eq!(meta("range_m").as_deref(), Some("1852"));
        assert!(ev.location.is_some());
        assert_eq!(ev.payload, sentence(TARGET).as_bytes());
    }

    #[test]
    fn rmc_also_provides_the_fix() {
        let state = TtmState::new(None);
        let rmc = "GPRMC,120000,A,6000.000,N,00500.000,E,12.0,90.0,270826,,,A";
        assert!(handle(&state, &sentence(rmc)).unwrap().is_none());
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        assert!(t.position.is_some());
    }
}
