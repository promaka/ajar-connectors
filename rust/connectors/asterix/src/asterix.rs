// SPDX-License-Identifier: Apache-2.0
//! EUROCONTROL ASTERIX to Ajar events. CAT010, CAT021, CAT048 and CAT062 records
//! become tracks; CAT034 records update a per-radar status that is published on
//! each north marker and jamming strobe. A data block is `CAT | LEN | record...`,
//! a record an FSPEC bitmap and then the items it names in UAP order. Blocks of
//! other categories are skipped and counted.

mod cat010;
mod cat021;
mod cat034;
mod cat048;
mod cat062;
mod field;
#[cfg(test)]
mod testutil;
mod wire;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::ontology::{self, Declared};
use ajar_connector_common::{
    Enrichment, FrameParser, GovernedAttribute, GovernedIdentity, ParseError,
};

pub use cat034::{RadarStatus, ServiceReport};
use cat034::{
    JAMMING_STROBE, MODE_S_JAMMING_STROBE, NORTH_MARKER, SECTOR_CROSSING, SSR_JAMMING_STROBE,
};
use field::{block_header, walk_record, Field, Item};

const CAT010: u8 = 10;
const CAT021: u8 = 21;
const CAT034: u8 = 34;
const CAT048: u8 = 48;
const CAT062: u8 = 62;

const KNOTS_TO_MPS: f64 = 0.514_444;
const NM_TO_M: f64 = 1852.0;
const FT_TO_M: f64 = 0.3048;
/// LSB of a 16-bit binary angle, degrees.
const ANGLE_16: f64 = 360.0 / 65_536.0;
/// LSB of a 2^-14 NM/s ground speed, knots.
const SPEED_LSB_KN: f64 = 3600.0 / 16_384.0;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum AsterixError {
    /// `cat` is `None` when the block is too short to hold a header.
    #[error("malformed ASTERIX data block: {}", bad_block(cat, declared, have))]
    BadBlock {
        cat: Option<u8>,
        declared: usize,
        have: usize,
    },
    #[error("ASTERIX item runs past end of block")]
    Truncated,
    /// The record walk stops rather than misalign on an item it cannot measure.
    #[error("CAT{cat:03} FRN {frn} not length-modelled")]
    UnsupportedItem { cat: u8, frn: u8 },
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

fn bad_block(cat: &Option<u8>, declared: &usize, have: &usize) -> String {
    match cat {
        Some(c) => format!("CAT{c:03} declares {declared} bytes, {have} available"),
        None => format!("{have} bytes is too short for a category and length"),
    }
}

/// One decoded track report; items the category does not carry stay unset.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AsterixTarget {
    pub category: u8,
    pub sac: u8,
    pub sic: u8,
    /// 12 bits for CAT010 and CAT048, 16 bits for CAT021 and CAT062.
    pub track: Option<u32>,
    /// 24-bit ICAO address.
    pub icao: Option<u32>,
    /// From the record, or geolocated against the sensor site.
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    /// Range (NM) and azimuth (deg) from the sensor.
    pub polar: Option<(f64, f64)>,
    /// Offset east and north of the sensor.
    pub cartesian_m: Option<(f64, f64)>,
    /// I010/000; only a target report is a track.
    pub message_type: Option<u8>,
    /// I010/020 TYP, the sensor technique.
    pub report_type: Option<&'static str>,
    /// I010/300.
    pub vehicle_fleet: Option<&'static str>,
    /// I010/270 length (m), width (m) and orientation (deg).
    pub size: Option<(f64, Option<f64>, Option<f64>)>,
    /// Standard deviation of x and y position, from I010/500 or I062/500 APC.
    pub position_sd_m: Option<(f64, f64)>,
    /// I062/500 ABA, standard deviation of the barometric altitude.
    pub accuracy_v_m: Option<f64>,
    /// I062/500 ATV, standard deviation of x and y velocity.
    pub velocity_sd_mps: Option<(f64, f64)>,
    pub alt_ft: Option<f64>,
    pub ground_speed_kn: Option<f64>,
    /// Course over ground.
    pub track_angle_deg: Option<f64>,
    pub vertical_rate_ftmin: Option<f64>,
    /// Mode 3/A code as four octal digits.
    pub squawk: Option<String>,
    pub callsign: Option<String>,
    /// I021/020.
    pub emitter: Option<&'static str>,
    /// Seconds since UTC midnight.
    pub time_of_day_s: Option<f64>,
    /// Target report descriptor bits; a report with any of them set is
    /// counted and not published.
    pub simulated: bool,
    pub test_target: bool,
    pub field_monitor: bool,
    /// The record's bytes, sealed into the payload.
    pub raw: Vec<u8>,
}

impl AsterixTarget {
    fn set_pos(&mut self, lat: f64, lon: f64) {
        self.lat = Some(lat);
        self.lon = Some(lon);
    }
}

/// The radar site CAT048 and CAT010 sensor-relative positions are geolocated
/// against.
#[derive(Debug, Clone, Copy)]
pub struct Sensor {
    pub lat: f64,
    pub lon: f64,
    pub alt_m: f64,
}

const EARTH_RADIUS_M: f64 = 6_371_000.0;

/// The point `dist_m` from `(lat, lon)` along true bearing `bearing_deg`.
fn forward_geodetic(lat: f64, lon: f64, bearing_deg: f64, dist_m: f64) -> (f64, f64) {
    let d = dist_m / EARTH_RADIUS_M;
    let br = bearing_deg.to_radians();
    let (lat1, lon1) = (lat.to_radians(), lon.to_radians());
    let lat2 = (lat1.sin() * d.cos() + lat1.cos() * d.sin() * br.cos()).asin();
    let lon2 = lon1 + (br.sin() * d.sin() * lat1.cos()).atan2(d.cos() - lat1.sin() * lat2.sin());
    (lat2.to_degrees(), lon2.to_degrees())
}

pub struct AsterixParser {
    source_id: String,
    enrichment: Enrichment,
    sensor: Option<Sensor>,
    cat010_type: Option<String>,
    /// The `environment` of an unidentified CAT010 plot.
    surface_domain: Option<String>,
    cat034_type: Option<String>,
    /// Merged status per radar (SAC, SIC).
    radar_status: Mutex<HashMap<(u8, u8), RadarStatus>>,
    ignored_blocks: Arc<AtomicU64>,
    test_targets: Arc<AtomicU64>,
    north_markers: Arc<AtomicU64>,
    sector_crossings: Arc<AtomicU64>,
    jamming_strobes: Arc<AtomicU64>,
    /// North markers published while the radar reported NOGO or an overload.
    radar_degraded: Arc<AtomicU64>,
}

impl AsterixParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
            sensor: None,
            cat010_type: None,
            cat034_type: None,
            surface_domain: None,
            radar_status: Default::default(),
            ignored_blocks: Default::default(),
            test_targets: Default::default(),
            north_markers: Default::default(),
            sector_crossings: Default::default(),
            jamming_strobes: Default::default(),
            radar_degraded: Default::default(),
        }
    }

    pub fn with_sensor(mut self, sensor: Option<Sensor>) -> Self {
        self.sensor = sensor;
        self
    }

    /// Reads `cat010`, `cat034` and `cat010_domain` from `[entity_map]`; other
    /// keys are ignored. Fails if `cat010_domain` is not in the ontology's
    /// vocabulary.
    pub fn with_entity_map(mut self, map: &HashMap<String, String>) -> anyhow::Result<Self> {
        self.cat010_type = map.get("cat010").cloned();
        self.cat034_type = map.get("cat034").cloned();
        self.surface_domain = map.get("cat010_domain").cloned();
        if let Some(v) = &self.surface_domain {
            let declared = Declared {
                entity_type: "mim:object".to_string(),
                attributes: vec!["environment".to_string()],
                fixed_values: vec![("environment".to_string(), v.clone())],
            };
            if let Some(f) = ontology::check(&declared).first() {
                anyhow::bail!("[entity_map] cat010_domain: {f}");
            }
        }
        Ok(self)
    }

    /// The tracks in one datagram. Service reports still update radar status.
    pub fn parse_frame(&self, frame: &[u8]) -> Result<Vec<AsterixTarget>, AsterixError> {
        self.parse_datagram(frame).map(|(t, _)| t)
    }

    /// The tracks and service reports in every data block of one datagram.
    pub fn parse_datagram(
        &self,
        frame: &[u8],
    ) -> Result<(Vec<AsterixTarget>, Vec<ServiceReport>), AsterixError> {
        let mut targets = Vec::new();
        let mut reports = Vec::new();
        let mut rest = frame;
        while !rest.is_empty() {
            let (cat, len) = block_header(rest)?;
            let block = &rest[..len];
            match cat {
                CAT010 | CAT021 | CAT048 | CAT062 => targets.extend(self.parse_block(block)?),
                CAT034 => reports.extend(self.parse_service_block(block)?),
                _ => {
                    self.ignored_blocks.fetch_add(1, Ordering::Relaxed);
                }
            }
            rest = &rest[len..];
        }
        Ok((targets, reports))
    }

    /// Every CAT034 record in one data block, each merged into its radar's
    /// status; empty for any other category.
    pub fn parse_service_block(&self, frame: &[u8]) -> Result<Vec<ServiceReport>, AsterixError> {
        let (cat, len) = block_header(frame)?;
        if cat != CAT034 {
            return Ok(Vec::new());
        }
        let block = &frame[..len];
        let mut reports = Vec::new();
        let mut off = 3;
        while off < len {
            let (items, next) = walk_record(cat, cat034::UAP, block, off)?;
            let mut r = cat034::decode(&items);
            r.raw = block[off..next].to_vec();
            {
                let mut all = self
                    .radar_status
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
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
                c.fetch_add(1, Ordering::Relaxed);
            }
            if r.message_type == NORTH_MARKER && r.status.degraded() {
                self.radar_degraded.fetch_add(1, Ordering::Relaxed);
            }
            reports.push(r);
            off = next;
        }
        Ok(reports)
    }

    /// Every track in one CAT010, CAT021, CAT048 or CAT062 data block; empty
    /// for any other category.
    pub fn parse_block(&self, frame: &[u8]) -> Result<Vec<AsterixTarget>, AsterixError> {
        type Decode = fn(&[(Item, &[u8])], Option<&Sensor>) -> AsterixTarget;
        let (cat, len) = block_header(frame)?;
        let (uap, decode): (&[(Item, Field)], Decode) = match cat {
            CAT010 => (cat010::UAP, cat010::decode),
            CAT021 => (cat021::UAP, |items, _| cat021::decode(items)),
            CAT048 => (cat048::UAP, cat048::decode),
            CAT062 => (cat062::UAP, |items, _| cat062::decode(items)),
            _ => return Ok(Vec::new()),
        };
        let block = &frame[..len];
        let mut targets = Vec::new();
        let mut off = 3;
        while off < len {
            let (items, next) = walk_record(cat, uap, block, off)?;
            let mut t = decode(&items, self.sensor.as_ref());
            let target_report = cat != CAT010 || t.message_type == Some(cat010::TARGET_REPORT);
            let positioned = t.lat.is_some() || t.polar.is_some() || t.cartesian_m.is_some();
            if target_report && positioned {
                t.raw = block[off..next].to_vec();
                targets.push(t);
            }
            off = next;
        }
        Ok(targets)
    }

    pub fn to_event_at(&self, t: AsterixTarget, observed: &str) -> Result<Event, AsterixError> {
        Ok(self.target_builder(t).timestamp(observed).build()?)
    }

    pub fn service_event_at(
        &self,
        r: ServiceReport,
        observed: &str,
    ) -> Result<Event, AsterixError> {
        Ok(self.service_builder(r).timestamp(observed).build()?)
    }

    fn target_builder(&self, t: AsterixTarget) -> EventBuilder {
        // The track number is scoped by category and SAC/SIC so that two
        // radars' track 7, or one site's CAT010 and CAT062 track 7, differ.
        let (source_uid, identity) = match (t.icao, t.track) {
            (Some(icao), _) => (
                format!("icao:{icao:06X}"),
                Some(("ICAO24", format!("{icao:06X}"))),
            ),
            (None, Some(track)) => {
                let scoped = format!("{}:{}:{}:{}", t.category, t.sac, t.sic, track);
                (format!("asterix:{scoped}"), Some(("ASTERIX", scoped)))
            }
            (None, None) => (format!("asterix:{}:{}:{}", t.category, t.sac, t.sic), None),
        };
        let entity_type: &str = if t.category != CAT010 {
            "mim:aircraft"
        } else if let Some(ty) = &self.cat010_type {
            ty
        } else if t.vehicle_fleet.is_some() {
            "mim:land-vehicle"
        } else if t.icao.is_some() || t.callsign.is_some() {
            "mim:aircraft"
        } else {
            "mim:object"
        };
        let mut b = EventBuilder::new(self.source_id.clone(), entity_type)
            .new_id()
            .payload(t.raw)
            .metadata("source_uid", source_uid)
            .metadata("asterix_category", t.category.to_string());
        if let Some((standard, id)) = identity {
            b = b.identity(standard, id);
        }
        // A per-axis sigma pair is published as its root sum square (DRMS). A
        // zero sigma is a field the sender left blank.
        if let Some((sx, sy)) = t.position_sd_m {
            b = b
                .metadata("position_sd_x_m", format!("{sx:.2}"))
                .metadata("position_sd_y_m", format!("{sy:.2}"));
            let h = sx.hypot(sy);
            if h > 0.0 {
                b = b.attribute("position_accuracy_h_m", format!("{h:.2}"));
            }
        }
        // The vertical sigma describes the altitude, so it needs one.
        if let (Some(v), Some(_)) = (t.accuracy_v_m, t.alt_ft) {
            if v > 0.0 {
                b = b.attribute("position_accuracy_v_m", format!("{v:.2}"));
            }
        }
        if let Some((vx, vy)) = t.velocity_sd_mps {
            let s = vx.hypot(vy);
            if s > 0.0 {
                b = b.attribute("speed_accuracy", format!("{s:.2}"));
            }
        }
        // `environment` is governed on the untyped class alone; a typed class
        // keeps it in metadata.
        if let Some(env) = &self.surface_domain {
            b = b.governed(entity_type, "environment", env.clone());
        }
        if let (Some(lat), Some(lon)) = (t.lat, t.lon) {
            b = b.location(lat, lon, t.alt_ft.map(|ft| ft * FT_TO_M).unwrap_or(0.0));
        } else if let Some((rho, theta)) = t.polar {
            b = b.metadata("range_nm", format!("{rho:.3}"));
            b = b.metadata("azimuth_deg", format!("{theta:.3}"));
        } else if let Some((x, y)) = t.cartesian_m {
            b = b.metadata("x_m", format!("{x:.0}"));
            b = b.metadata("y_m", format!("{y:.0}"));
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
        if let Some(tod) = t.time_of_day_s {
            b = b.metadata("time_of_day_s", format!("{tod:.3}"));
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(kn) = t.ground_speed_kn {
            b = b.attribute("speed", format!("{:.2}", kn * KNOTS_TO_MPS));
            b = b.metadata("speed_kn", format!("{kn:.1}"));
        }
        if let Some(deg) = t.track_angle_deg {
            b = b.attribute("course", format!("{deg:.1}"));
        }
        if let Some(ftmin) = t.vertical_rate_ftmin {
            b = b.attribute("vertical_rate", format!("{:.1}", ftmin * FT_TO_M / 60.0));
            b = b.metadata("vertical_rate_ftmin", format!("{ftmin:.0}"));
        }
        // Governed on aircraft; a surface plot keeps it in metadata.
        if let Some(sq) = t.squawk {
            b = b.governed(entity_type, "squawk", sq);
        }
        if let Some(cs) = t.callsign {
            b = b.attribute("callsign", cs);
        }
        if let Some(cat) = t.emitter {
            b = b.metadata("emitter_category", cat);
        }
        b
    }

    /// An event about the radar itself, located at the position it reports,
    /// else at the configured site.
    fn service_builder(&self, r: ServiceReport) -> EventBuilder {
        let message_type = r.message_name();
        let entity_type = self
            .cat034_type
            .clone()
            .unwrap_or_else(|| "mim:sensor".to_string());
        let mut b = EventBuilder::new(self.source_id.clone(), entity_type.clone())
            .new_id()
            .payload(r.raw)
            .metadata("source_uid", format!("asterix:radar:{}:{}", r.sac, r.sic))
            .metadata("asterix_category", CAT034.to_string())
            .metadata("message_type", message_type)
            .identity("ASTERIX", format!("{}:{}", r.sac, r.sic));
        if let Some((lat, lon, h)) = r.position {
            b = b.location(lat, lon, h);
        } else if let Some(s) = self.sensor {
            b = b.location(s.lat, s.lon, s.alt_m);
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(tod) = r.time_of_day_s {
            b = b.metadata("time_of_day_s", format!("{tod:.3}"));
        }
        if let Some(p) = r.rotation_period_s {
            // The rotation period is the scan period, and on a north marker
            // also the heartbeat interval; strobes are not periodic.
            b = b
                .governed(&entity_type, "scan_period_s", format!("{p:.3}"))
                .metadata("rotation_period_s", format!("{p:.3}"));
            if r.message_type == NORTH_MARKER {
                b = b.governed(&entity_type, "update_interval_s", format!("{p:.3}"));
            }
        }
        if let Some(sec) = r.sector {
            b = b.metadata("sector", sec.to_string());
        }
        if let Some((r0, r1, a0, a1)) = r.window {
            // On a north marker the window is the radar's coverage; on a
            // jamming strobe it is the jammed sector and stays in metadata.
            if r.message_type == NORTH_MARKER {
                b = b
                    .governed(
                        &entity_type,
                        "coverage_bearing_start_deg",
                        format!("{a0:.3}"),
                    )
                    .governed(&entity_type, "coverage_bearing_end_deg", format!("{a1:.3}"))
                    .governed(
                        &entity_type,
                        "detection_range_m",
                        format!("{:.0}", r1 * NM_TO_M),
                    );
            }
            b = b
                .metadata("window_range_start_nm", format!("{r0:.3}"))
                .metadata("window_range_end_nm", format!("{r1:.3}"))
                .metadata("window_azimuth_start_deg", format!("{a0:.3}"))
                .metadata("window_azimuth_end_deg", format!("{a1:.3}"));
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
        b
    }
}

impl FrameParser for AsterixParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let (targets, reports) = self.parse_datagram(frame)?;
        let mut events = Vec::with_capacity(targets.len() + reports.len());
        for r in reports.into_iter().filter(|r| r.is_published()) {
            let event = self
                .service_builder(r)
                .now()
                .build()
                .map_err(AsterixError::from)?;
            events.push(event);
        }
        for t in targets {
            if t.simulated || t.test_target || t.field_monitor {
                self.test_targets.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let event = self
                .target_builder(t)
                .now()
                .build()
                .map_err(AsterixError::from)?;
            events.push(event);
        }
        Ok(events)
    }

    fn counters(&self) -> Vec<(&'static str, Arc<AtomicU64>)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use testutil::{
        block, cat010_record, cat034_north_marker, cat034_sector_crossing, cat048_record, fspec,
        parser, SITE,
    };

    #[test]
    fn every_block_in_datagram_decoded() {
        let p = parser();
        let mut datagram = block(34, &cat034_north_marker());
        datagram.extend(block(48, &cat048_record()));
        let (targets, reports) = p.parse_datagram(&datagram).unwrap();
        assert_eq!(targets.len(), 1, "the CAT048 block behind CAT034 decodes");
        assert_eq!(reports.len(), 1, "the service block decodes");
        assert_eq!(p.ignored_blocks.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unknown_category_block_counted_and_skipped() {
        let p = parser();
        // An empty CAT240 block, then a CAT048 one.
        let mut datagram = vec![240, 0, 4, 0];
        datagram.extend(block(48, &cat048_record()));
        assert_eq!(p.parse_frame(&datagram).unwrap().len(), 1);
        assert_eq!(p.ignored_blocks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn datagram_publishes_heartbeat_and_tracks() {
        let p = parser().with_sensor(Some(SITE));
        let mut datagram = block(34, &cat034_north_marker());
        datagram.extend(block(34, &cat034_sector_crossing(0x00)));
        datagram.extend(block(48, &cat048_record()));
        datagram.extend(block(10, &cat010_record()));
        let events = p.parse(&datagram).unwrap();
        let types: Vec<&str> = events.iter().map(|e| e.entity_type.as_str()).collect();
        assert_eq!(types, ["mim:sensor", "mim:aircraft", "mim:object"]);
    }

    #[test]
    fn bad_block_error_names_category_and_lengths() {
        let msg = parser()
            .parse_frame(&[48, 0xFF, 0xFF, 0, 0])
            .unwrap_err()
            .to_string();
        assert!(msg.contains("CAT048"), "{msg}");
        assert!(msg.contains("65535"), "{msg}");
        assert!(msg.contains("5 available"), "{msg}");
    }

    #[test]
    fn other_category_block_yields_no_tracks() {
        let targets = parser().parse_block(&block(34, &[0x80, 0x00])).unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn malformed_blocks_never_panic() {
        assert!(parser().parse_block(b"").is_err());
        assert!(
            parser().parse_block(&[62, 0, 200]).is_err(),
            "LEN past the buffer"
        );
        let _ = parser().parse_block(&block(62, &[0xFF, 0xFF, 0x00]));
        // I062/380 names ADR and ID but no bytes follow.
        let mut r = fspec(cat062::UAP, &[Item(10), Item(380)]);
        r.extend_from_slice(&[25, 10]);
        r.push(0xC0);
        let _ = parser().parse_block(&block(62, &r));
    }

    #[test]
    fn every_emitted_attribute_is_declared() {
        // Checked per entity type, as the ontology governs attributes.
        struct Emission<'a> {
            entity_type: &'a str,
            attributes: &'a [&'a str],
            fixed_values: &'a [(&'a str, &'a str)],
        }
        const SURFACE_TRACK: &[&str] =
            &["hostility", "speed", "course", "alt_id", "alt_id_standard"];
        let emissions = [
            Emission {
                entity_type: "mim:aircraft",
                attributes: &[
                    "hostility",
                    "speed",
                    "course",
                    "vertical_rate",
                    "squawk",
                    "callsign",
                    "alt_id",
                    "alt_id_standard",
                    "position_accuracy_h_m",
                    "position_accuracy_v_m",
                    "speed_accuracy",
                ],
                fixed_values: &[
                    ("alt_id_standard", "ICAO24"),
                    ("alt_id_standard", "ASTERIX"),
                ],
            },
            Emission {
                entity_type: "mim:object",
                attributes: &[
                    "hostility",
                    "speed",
                    "course",
                    "environment",
                    "alt_id",
                    "alt_id_standard",
                    "position_accuracy_h_m",
                ],
                fixed_values: &[
                    ("environment", "SURFACE"),
                    ("environment", "LAND"),
                    ("environment", "SUBSURFACE"),
                    ("environment", "AIR"),
                    ("alt_id_standard", "ASTERIX"),
                ],
            },
            Emission {
                entity_type: "mim:vessel",
                attributes: SURFACE_TRACK,
                fixed_values: &[],
            },
            Emission {
                entity_type: "mim:surface-vessel",
                attributes: SURFACE_TRACK,
                fixed_values: &[],
            },
            Emission {
                entity_type: "mim:subsurface-vessel",
                attributes: SURFACE_TRACK,
                fixed_values: &[],
            },
            Emission {
                entity_type: "mim:land-vehicle",
                attributes: SURFACE_TRACK,
                fixed_values: &[],
            },
            Emission {
                entity_type: "mim:sensor",
                attributes: &[
                    "hostility",
                    "alt_id",
                    "alt_id_standard",
                    "scan_period_s",
                    "update_interval_s",
                    "coverage_bearing_start_deg",
                    "coverage_bearing_end_deg",
                    "detection_range_m",
                ],
                fixed_values: &[("alt_id_standard", "ASTERIX")],
            },
        ];
        for e in emissions {
            let declared = Declared {
                entity_type: e.entity_type.to_string(),
                attributes: e.attributes.iter().map(|s| s.to_string()).collect(),
                fixed_values: e
                    .fixed_values
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            };
            let faults = ontology::check(&declared);
            assert!(
                faults.is_empty(),
                "{}: undeclared: {faults:?}",
                e.entity_type
            );
        }
    }
}
