// SPDX-License-Identifier: Apache-2.0
//! ARPA radar tracked targets (`$--TTM`) to `mim:object` events with
//! `environment = SURFACE`. A target is range and bearing from own ship, placed
//! against the latest `$--GGA`/`$--RMC` fix on the bus or the configured site;
//! without either, or with a relative bearing, the event carries no location.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::Enrichment;

use crate::ais::AisError;

const KNOTS_TO_MPS: f64 = 0.514_444;
const NM_TO_M: f64 = 1_852.0;
const EARTH_RADIUS_M: f64 = 6_371_000.0;
// A minute-old fix on a ship at 20 knots is about 600 m off.
const FIX_MAX_AGE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct OwnFix {
    lat: f64,
    lon: f64,
    at: Instant,
}

/// The own-ship fix, plus a fixed fallback site for a shore radar.
pub struct TtmState {
    fix: Mutex<Option<OwnFix>>,
    site: Option<(f64, f64)>,
    /// TTM reports with a status other than T (tracking); they emit no event.
    pub non_tracking: Arc<AtomicU64>,
}

#[derive(Debug, PartialEq)]
pub struct RadarTarget {
    /// Target number as the radar reports it (00-99).
    pub number: String,
    /// Set only for a true bearing with an observer available.
    pub position: Option<(f64, f64)>,
    pub range_m: f64,
    /// True or relative, as the sentence flags it.
    pub bearing_deg: Option<f64>,
    pub speed_mps: Option<f64>,
    /// Set only when the sentence flags the course as true.
    pub course_deg: Option<f64>,
    /// Label the radar operator gave the target.
    pub name: Option<String>,
    /// Closest point of approach.
    pub cpa_m: Option<f64>,
    pub tcpa_min: Option<f64>,
    pub raw: Vec<u8>,
}

impl TtmState {
    pub fn new(site: Option<(f64, f64)>) -> Self {
        Self {
            fix: Mutex::new(None),
            site,
            non_tracking: Default::default(),
        }
    }

    /// True for TTM, GGA and RMC sentences.
    pub fn wants(sentence: &str) -> bool {
        let star = sentence.find('*').unwrap_or(sentence.len());
        let talker = sentence[..star].split(',').next().unwrap_or("");
        talker.len() >= 3
            && (talker.ends_with("TTM") || talker.ends_with("GGA") || talker.ends_with("RMC"))
    }

    /// GGA and RMC update the own-ship fix and yield nothing; a TTM yields a
    /// target when the radar reports it as tracked.
    pub fn handle(&self, f: &[&str], raw: Vec<u8>) -> Result<Option<RadarTarget>, AisError> {
        // GGA: time,lat,N/S,lon,E/W,quality where quality 0 is no fix.
        // RMC: time,status,lat,N/S,lon,E/W where status A is valid.
        let (valid, lat_at) = if f[0].ends_with("GGA") {
            (f.len() >= 7 && f[6] != "0", 2)
        } else if f[0].ends_with("RMC") {
            (f.len() >= 7 && f[2] == "A", 3)
        } else {
            return self.decode_ttm(f, raw);
        };
        if valid {
            let lat = parse_coord(f.get(lat_at), f.get(lat_at + 1));
            let lon = parse_coord(f.get(lat_at + 2), f.get(lat_at + 3));
            if let (Some(lat), Some(lon)) = (lat, lon) {
                *self.fix.lock().expect("fix mutex") = Some(OwnFix {
                    lat,
                    lon,
                    at: Instant::now(),
                });
            }
        }
        Ok(None)
    }

    /// A fresh own-ship fix, else the configured site.
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
        // L (lost) is a stale last report and Q (acquiring) is not yet a track.
        if f[12] != "T" {
            self.non_tracking.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let number = f[1].trim();
        if number.is_empty() {
            return Err(AisError::Fields);
        }

        // N is nautical miles and knots, K kilometres and km/h, S statute
        // miles and mph.
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

        // A relative bearing needs own heading to resolve, which TTM does not carry.
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

/// The point `distance_m` from (`lat`, `lon`) along true bearing `bearing_deg`
/// on a sphere; within centimetres of the ellipsoid at radar ranges.
fn forward(lat: f64, lon: f64, bearing_deg: f64, distance_m: f64) -> (f64, f64) {
    let (phi1, lam1, theta) = (lat.to_radians(), lon.to_radians(), bearing_deg.to_radians());
    let delta = distance_m / EARTH_RADIUS_M;
    let phi2 = (phi1.sin() * delta.cos() + phi1.cos() * delta.sin() * theta.cos()).asin();
    let lam2 = lam1
        + (theta.sin() * delta.sin() * phi1.cos()).atan2(delta.cos() - phi1.sin() * phi2.sin());
    (phi2.to_degrees(), lam2.to_degrees())
}

/// NMEA `ddmm.mmmm` and hemisphere to signed decimal degrees.
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

pub fn to_event(
    source_id: &str,
    enrichment: &Enrichment,
    t: RadarTarget,
) -> Result<Event, BuildError> {
    let mut b = EventBuilder::new(source_id.to_string(), "mim:object")
        .new_id()
        .now()
        .payload(t.raw)
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
    b.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN_GGA: &str = "GPGGA,120000,6000.000,N,00500.000,E,1,08,0.9,5.0,M,45.0,M,,";
    // Target 07: 1.0 nm at 090 true, 10 kn on course 180 true, tracked.
    const TARGET: &str = "RATTM,07,1.0,90.0,T,10.0,180.0,T,0.5,4.0,N,SKJOLD,T,,120010,A";

    /// `body` framed as `$body*HH` with the computed checksum.
    fn sentence(body: &str) -> String {
        let cs = body.bytes().fold(0u8, |a, b| a ^ b);
        format!("${body}*{cs:02X}")
    }

    fn handle(state: &TtmState, s: &str) -> Result<Option<RadarTarget>, AisError> {
        let star = s.find('*').unwrap();
        let fields: Vec<&str> = s[1..star].split(',').collect();
        state.handle(&fields, s.as_bytes().to_vec())
    }

    #[test]
    fn non_tracking_targets_are_counted() {
        let state = TtmState::new(Some((60.0, 25.0)));
        for status in ["L", "Q"] {
            let s = format!("RATTM,03,2.5,45.0,T,10.0,90.0,T,1.0,5.0,N,TGT03,{status},");
            let out = handle(&state, &sentence(&s)).unwrap();
            assert!(out.is_none(), "{status}: not an event");
        }
        assert_eq!(state.non_tracking.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn tracked_target_placed_from_gps_fix() {
        let state = TtmState::new(None);
        assert!(handle(&state, &sentence(OWN_GGA)).unwrap().is_none());
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        let (lat, lon) = t.position.expect("true bearing + fresh fix geolocates");
        // 1 nm due east of 60N 5E is +1/60 deg / cos(60) of longitude.
        assert!((lat - 60.0).abs() < 1e-3, "lat {lat}");
        assert!((lon - 5.0333).abs() < 2e-3, "lon {lon}");
        assert!((t.range_m - 1852.0).abs() < 0.5);
        assert!((t.speed_mps.unwrap() - 5.144_44).abs() < 1e-3);
        assert_eq!(t.name.as_deref(), Some("SKJOLD"));
        assert!((t.cpa_m.unwrap() - 926.0).abs() < 0.5);
    }

    #[test]
    fn no_observer_means_no_position() {
        let state = TtmState::new(None);
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        assert!(t.position.is_none(), "no fix, no site: no position");
        assert!(
            (t.range_m - 1852.0).abs() < 0.5,
            "the measurement itself survives"
        );
    }

    #[test]
    fn shore_site_places_target_without_gps() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        assert!(t.position.is_some());
    }

    #[test]
    fn relative_bearing_is_never_placed() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let rel = "RATTM,07,1.0,90.0,R,10.0,180.0,T,0.5,4.0,N,,T,,120010,A";
        let t = handle(&state, &sentence(rel)).unwrap().unwrap();
        assert!(t.position.is_none(), "resolving R needs heading");
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
    fn stale_fix_falls_back_to_site() {
        let state = TtmState::new(Some((60.0, 5.0)));
        *state.fix.lock().unwrap() = Some(OwnFix {
            lat: 61.0,
            lon: 6.0,
            at: Instant::now() - (FIX_MAX_AGE + Duration::from_secs(1)),
        });
        assert_eq!(state.observer(), Some((60.0, 5.0)));
    }

    #[test]
    fn event_is_surface_object_with_native_id() {
        let state = TtmState::new(Some((60.0, 5.0)));
        let t = handle(&state, &sentence(TARGET)).unwrap().unwrap();
        let ev = to_event("hms-example", &Enrichment::default(), t).unwrap();
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
