// SPDX-License-Identifier: Apache-2.0
//! STANAG 4607 (NATO GMTI) Dwell segments to `mim:object` events, one per
//! located target report. Reports are untracked detections, so `source_uid` is
//! `platform:job:dwell:report` and unique per detection. The whole dwell segment
//! is the payload of each of its events. Field layout and scale factors follow
//! STANAG 4607, cross-checked against Wireshark and pentlandedge `s4607`.

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

const PACKET_HEADER_LEN: usize = 32;
/// Segment type (1 byte) and size (4 bytes).
const SEGMENT_HEADER_LEN: usize = 5;
const SEG_DWELL: u8 = 2;

/// Existence-mask bit and byte size of the dwell fields this parser skips
/// between the sensor position and the dwell area.
const SENSOR_FIELDS: [(u32, usize); 12] = [
    (10, 4), // D12 sensor position uncertainty, along track
    (11, 4), // D13 sensor position uncertainty, cross track
    (12, 2), // D14 sensor position uncertainty, altitude
    (13, 2), // D15 sensor track
    (14, 4), // D16 sensor speed
    (15, 1), // D17 sensor vertical velocity
    (16, 1), // D18 sensor track uncertainty
    (17, 2), // D19 sensor speed uncertainty
    (18, 2), // D20 sensor vertical velocity uncertainty
    (19, 2), // D21 platform orientation heading
    (20, 2), // D22 platform orientation pitch
    (21, 2), // D23 platform orientation roll
];

/// Dwell fields skipped after the dwell area.
const ORIENTATION_FIELDS: [(u32, usize); 4] = [
    (26, 2), // D28 sensor orientation heading
    (27, 2), // D29 sensor orientation pitch
    (28, 2), // D30 sensor orientation roll
    (29, 1), // D31 minimum detectable velocity
];

/// Target report fields skipped between classification and RCS.
const TARGET_UNCERTAINTY_FIELDS: [(u32, usize); 7] = [
    (40, 1), // D32.11 target classification probability
    (41, 2), // D32.12 target slant range uncertainty
    (42, 2), // D32.13 target cross range uncertainty
    (43, 1), // D32.14 target height uncertainty
    (44, 2), // D32.15 target radial velocity uncertainty
    (45, 1), // D32.16 truth tag application
    (46, 4), // D32.17 truth tag entity
];

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum GmtiError {
    #[error("not a STANAG 4607 GMTI packet")]
    NotGmti,
    #[error("GMTI packet truncated")]
    Truncated,
    #[error("GMTI segment declared an invalid size")]
    BadSegment,
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

/// One located target report with its dwell context.
#[derive(Debug, Clone, PartialEq)]
pub struct GmtiTarget {
    pub platform: String,
    pub job_id: u32,
    pub dwell_index: u16,
    pub mti_index: Option<u16>,
    /// Relative to the Mission Segment reference time.
    pub dwell_time_ms: i32,
    pub sensor_lat: f64,
    pub sensor_lon: f64,
    pub lat: f64,
    pub lon: f64,
    /// Geodetic height.
    pub height_m: Option<f64>,
    /// Line-of-sight velocity.
    pub radial_velocity_mps: Option<f64>,
    pub snr_db: Option<i8>,
    /// STANAG 4607 target classification code.
    pub classification: Option<u8>,
    pub rcs_db: Option<i8>,
    /// The whole dwell segment.
    pub raw: Vec<u8>,
}

pub struct GmtiParser {
    source_id: String,
    enrichment: Enrichment,
}

impl GmtiParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
        }
    }

    /// One target per located report across all Dwell segments; other segment
    /// types are skipped by size.
    pub fn parse_packet(&self, frame: &[u8]) -> Result<Vec<GmtiTarget>, GmtiError> {
        if frame.len() < PACKET_HEADER_LEN {
            return Err(GmtiError::Truncated);
        }
        // GMTI has no magic number; the edition byte and a sane packet size are
        // the only format check.
        let edition = frame[0];
        if edition != 0x02 && edition != 0x03 {
            return Err(GmtiError::NotGmti);
        }
        let packet_size = u32_be(&frame[2..6]) as usize;
        if packet_size < PACKET_HEADER_LEN || packet_size > frame.len() {
            return Err(GmtiError::Truncated);
        }
        let platform = String::from_utf8_lossy(&frame[14..24]).trim().to_string();
        let job_id = u32_be(&frame[28..32]);

        let mut targets = Vec::new();
        let mut off = PACKET_HEADER_LEN;
        while off + SEGMENT_HEADER_LEN <= packet_size {
            let seg_type = frame[off];
            let seg_size = u32_be(&frame[off + 1..off + 5]) as usize;
            if seg_size < SEGMENT_HEADER_LEN || off + seg_size > packet_size {
                return Err(GmtiError::BadSegment);
            }
            if seg_type == SEG_DWELL {
                let seg = &frame[off..off + seg_size];
                self.parse_dwell(seg, &platform, job_id, &mut targets)?;
            }
            off += seg_size;
        }
        Ok(targets)
    }

    fn parse_dwell(
        &self,
        seg: &[u8],
        platform: &str,
        job_id: u32,
        out: &mut Vec<GmtiTarget>,
    ) -> Result<(), GmtiError> {
        let mut r = Reader::new(seg);
        r.skip(SEGMENT_HEADER_LEN)?;
        let mask = u64::from_be_bytes(r.array()?);
        let bit = |n: u32| (mask >> (63 - n)) & 1 == 1;
        let skip_present = |r: &mut Reader, fields: &[(u32, usize)]| {
            for &(n, len) in fields {
                if bit(n) {
                    r.skip(len)?;
                }
            }
            Ok::<(), GmtiError>(())
        };

        let _revisit = r.u16()?;
        let dwell_index = r.u16()?;
        let _last_dwell = r.u8()?;
        let target_count = r.u16()?;
        let dwell_time_ms = r.i32()?;
        let sensor_lat = sa32(r.i32()?);
        let sensor_lon = norm_lon(ba32(r.u32()?));
        let _sensor_alt_cm = r.i32()?;

        let lat_scale = if bit(8) { Some(sa32(r.i32()?)) } else { None };
        let lon_scale = if bit(9) { Some(ba32(r.u32()?)) } else { None };
        skip_present(&mut r, &SENSOR_FIELDS)?;

        let dwell_center_lat = sa32(r.i32()?);
        // Kept in 0..360 so delta-coded longitudes add to it before wrapping.
        let dwell_center_lon_0_360 = ba32(r.u32()?);
        // D26 dwell range half extent, D27 dwell angle half extent.
        r.skip(4)?;
        skip_present(&mut r, &ORIENTATION_FIELDS)?;

        for _ in 0..target_count {
            let mti_index = if bit(30) { Some(r.u16()?) } else { None };
            let hr_lat = if bit(31) { Some(sa32(r.i32()?)) } else { None };
            let hr_lon = if bit(32) { Some(ba32(r.u32()?)) } else { None };
            let delta_lat = if bit(33) { Some(r.i16()?) } else { None };
            let delta_lon = if bit(34) { Some(r.i16()?) } else { None };
            let height_m = if bit(35) { Some(r.i16()? as f64) } else { None };
            // D32.7 is in cm/s.
            let radial_velocity_mps = if bit(36) {
                Some(r.i16()? as f64 / 100.0)
            } else {
                None
            };
            // D32.8 wrap velocity.
            if bit(37) {
                r.skip(2)?;
            }
            let snr_db = if bit(38) { Some(r.i8()?) } else { None };
            let classification = if bit(39) { Some(r.u8()?) } else { None };
            skip_present(&mut r, &TARGET_UNCERTAINTY_FIELDS)?;
            let rcs_db = if bit(47) { Some(r.i8()?) } else { None };

            // Absolute hi-res position, else the delta from the dwell centre
            // times the scale factors. A report with neither is dropped.
            let pos = match (hr_lat, hr_lon) {
                (Some(la), Some(lo)) => Some((la, norm_lon(lo))),
                _ => match (delta_lat, delta_lon, lat_scale, lon_scale) {
                    (Some(dla), Some(dlo), Some(ls), Some(los)) => Some((
                        dwell_center_lat + dla as f64 * ls,
                        norm_lon(dwell_center_lon_0_360 + dlo as f64 * los),
                    )),
                    _ => None,
                },
            };
            let Some((lat, lon)) = pos else {
                continue;
            };
            out.push(GmtiTarget {
                platform: platform.to_string(),
                job_id,
                dwell_index,
                mti_index,
                dwell_time_ms,
                sensor_lat,
                sensor_lon,
                lat,
                lon,
                height_m,
                radial_velocity_mps,
                snr_db,
                classification,
                rcs_db,
                raw: seg.to_vec(),
            });
        }
        Ok(())
    }

    fn base_builder(&self, t: GmtiTarget) -> EventBuilder {
        let report = t
            .mti_index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "na".to_string());
        let source_uid = format!("{}:{}:{}:{}", t.platform, t.job_id, t.dwell_index, report);
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:object")
            .new_id()
            .location(t.lat, t.lon, t.height_m.unwrap_or(0.0))
            .payload(t.raw)
            .metadata("source_uid", source_uid)
            .metadata("platform", t.platform)
            .metadata("job_id", t.job_id.to_string())
            .metadata("dwell_index", t.dwell_index.to_string())
            .metadata("dwell_time_ms", t.dwell_time_ms.to_string())
            .metadata("sensor_lat", format!("{:.6}", t.sensor_lat))
            .metadata("sensor_lon", format!("{:.6}", t.sensor_lon));
        if let Some(i) = t.mti_index {
            b = b.metadata("mti_report_index", i.to_string());
        }

        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(v) = t.radial_velocity_mps {
            b = b.attribute("radial_velocity", format!("{v:.2}"));
        }
        if let Some(s) = t.snr_db {
            b = b.attribute("snr_db", s.to_string());
        }
        if let Some(c) = t.classification {
            b = b.attribute("classification_code", c.to_string());
        }
        if let Some(rcs) = t.rcs_db {
            b = b.attribute("rcs_db", rcs.to_string());
        }
        b
    }

    pub fn to_event_at(&self, t: GmtiTarget, observed: &str) -> Result<Event, GmtiError> {
        Ok(self.base_builder(t).timestamp(observed).build()?)
    }
}

impl FrameParser for GmtiParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        // Dwell time is relative to a Mission Segment that may be in another
        // packet, so stamp the time of receipt.
        let targets = self.parse_packet(frame)?;
        let mut events = Vec::with_capacity(targets.len());
        for t in targets {
            let event = self
                .base_builder(t)
                .now()
                .build()
                .map_err(GmtiError::from)?;
            events.push(event);
        }
        Ok(events)
    }
}

/// A bounds-checked big-endian reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], GmtiError> {
        let end = self.pos.checked_add(n).ok_or(GmtiError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(GmtiError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], GmtiError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn skip(&mut self, n: usize) -> Result<(), GmtiError> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, GmtiError> {
        Ok(self.take(1)?[0])
    }

    fn i8(&mut self) -> Result<i8, GmtiError> {
        Ok(self.take(1)?[0] as i8)
    }

    fn u16(&mut self) -> Result<u16, GmtiError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn i16(&mut self) -> Result<i16, GmtiError> {
        Ok(i16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, GmtiError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, GmtiError> {
        Ok(i32::from_be_bytes(self.array()?))
    }
}

fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// STANAG 4607 SA32 signed binary angle to degrees.
fn sa32(v: i32) -> f64 {
    v as f64 * 1.406_25 / 33_554_432.0
}

/// STANAG 4607 BA32 binary angle to degrees in 0..360.
fn ba32(v: u32) -> f64 {
    v as f64 * 1.406_25 / 16_777_216.0
}

/// A 0..360 longitude to -180..180.
fn norm_lon(deg: f64) -> f64 {
    if deg > 180.0 {
        deg - 360.0
    } else {
        deg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T_LAT: f64 = 60.1;
    const T_LON: f64 = 24.9;
    const OBSERVED: &str = "2026-06-10T08:00:00Z";

    fn sa32_enc(deg: f64) -> i32 {
        (deg * 33_554_432.0 / 1.406_25) as i32
    }

    fn ba32_enc(deg: f64) -> u32 {
        (deg * 16_777_216.0 / 1.406_25) as u32
    }

    /// A packet with one Dwell segment holding one target report with hi-res
    /// position, height and radial velocity.
    fn sample_packet() -> Vec<u8> {
        // Mandatory fields, D24..D27, and D32.1, D32.2, D32.3, D32.6, D32.7.
        let mask: [u8; 8] = [0xFF, 0x00, 0x03, 0xC3, 0x98, 0x00, 0x00, 0x00];

        let mut dwell_body = Vec::new();
        dwell_body.extend_from_slice(&mask);
        dwell_body.extend_from_slice(&7u16.to_be_bytes()); // D2 revisit index
        dwell_body.extend_from_slice(&3u16.to_be_bytes()); // D3 dwell index
        dwell_body.push(1); // D4 last dwell of revisit
        dwell_body.extend_from_slice(&1u16.to_be_bytes()); // D5 target report count
        dwell_body.extend_from_slice(&123_456i32.to_be_bytes()); // D6 dwell time ms
        dwell_body.extend_from_slice(&sa32_enc(60.0).to_be_bytes()); // D7 sensor lat
        dwell_body.extend_from_slice(&ba32_enc(25.0).to_be_bytes()); // D8 sensor lon
        dwell_body.extend_from_slice(&150_000i32.to_be_bytes()); // D9 sensor alt cm
        dwell_body.extend_from_slice(&sa32_enc(60.05).to_be_bytes()); // D24 centre lat
        dwell_body.extend_from_slice(&ba32_enc(24.95).to_be_bytes()); // D25 centre lon
        dwell_body.extend_from_slice(&0u16.to_be_bytes()); // D26 range half extent
        dwell_body.extend_from_slice(&0u16.to_be_bytes()); // D27 angle half extent
        dwell_body.extend_from_slice(&42u16.to_be_bytes()); // D32.1 mti index
        dwell_body.extend_from_slice(&sa32_enc(T_LAT).to_be_bytes()); // D32.2 lat
        dwell_body.extend_from_slice(&ba32_enc(T_LON).to_be_bytes()); // D32.3 lon
        dwell_body.extend_from_slice(&120i16.to_be_bytes()); // D32.6 height m
        dwell_body.extend_from_slice(&(-450i16).to_be_bytes()); // D32.7 radial cm/s

        let seg_size = (SEGMENT_HEADER_LEN + dwell_body.len()) as u32;
        let mut segment = vec![SEG_DWELL];
        segment.extend_from_slice(&seg_size.to_be_bytes());
        segment.extend_from_slice(&dwell_body);

        let packet_size = (PACKET_HEADER_LEN + segment.len()) as u32;
        let mut pkt = vec![0x03, 0x01]; // edition 3, version 1
        pkt.extend_from_slice(&packet_size.to_be_bytes());
        pkt.extend_from_slice(b"XN"); // nationality
        pkt.push(1); // classification: unclassified
        pkt.extend_from_slice(b"  "); // classification system
        pkt.extend_from_slice(&0u16.to_be_bytes()); // packet security
        pkt.push(0); // exercise indicator
        pkt.extend_from_slice(b"REAPER-01 "); // platform id
        pkt.extend_from_slice(&77u32.to_be_bytes()); // mission id
        pkt.extend_from_slice(&9001u32.to_be_bytes()); // job id
        assert_eq!(pkt.len(), PACKET_HEADER_LEN);
        pkt.extend_from_slice(&segment);
        pkt
    }

    fn parser() -> GmtiParser {
        GmtiParser::new("gmti-radar-1", Enrichment::default())
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

    #[test]
    fn decodes_target_position_and_kinematics() {
        let targets = parser().parse_packet(&sample_packet()).unwrap();
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        assert!((t.lat - T_LAT).abs() < 1e-3, "lat {}", t.lat);
        assert!((t.lon - T_LON).abs() < 1e-3, "lon {}", t.lon);
        assert!((t.height_m.unwrap() - 120.0).abs() < 1.0);
        assert!((t.radial_velocity_mps.unwrap() - (-4.5)).abs() < 1e-6);
        assert_eq!(t.mti_index, Some(42));
        assert_eq!(t.dwell_index, 3);
        assert_eq!(t.platform, "REAPER-01");
        assert_eq!(t.job_id, 9001);
    }

    #[test]
    fn event_carries_identity_and_units() {
        let p = GmtiParser::new(
            "gmti-radar-1",
            Enrichment::default().with_hostility("Hostile"),
        );
        let t = p.parse_packet(&sample_packet()).unwrap().remove(0);
        let ev = p.to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:object");
        assert_eq!(meta(&ev, "source_uid"), Some("REAPER-01:9001:3:42"));
        assert_eq!(meta(&ev, "platform"), Some("REAPER-01"));
        assert_eq!(attr(&ev, "radial_velocity"), Some("-4.50"));
        assert_eq!(attr(&ev, "hostility"), Some("Hostile"));
    }

    #[test]
    fn dwell_segment_sealed_in_payload() {
        let pkt = sample_packet();
        let t = parser().parse_packet(&pkt).unwrap().remove(0);
        let ev = parser().to_event_at(t, OBSERVED).unwrap();
        assert_eq!(ev.payload.as_slice(), &pkt[PACKET_HEADER_LEN..]);
    }

    #[test]
    fn non_gmti_is_rejected() {
        assert_eq!(
            parser().parse_packet(b"this is definitely not a gmti packet at all!!"),
            Err(GmtiError::NotGmti)
        );
    }

    #[test]
    fn truncated_packet_is_rejected() {
        let pkt = sample_packet();
        assert_eq!(parser().parse_packet(&pkt[..40]), Err(GmtiError::Truncated));
    }

    #[test]
    fn oversized_segment_is_rejected() {
        let mut pkt = sample_packet();
        pkt[PACKET_HEADER_LEN + 1] = 0xFF;
        assert_eq!(parser().parse_packet(&pkt), Err(GmtiError::BadSegment));
    }

    #[test]
    fn non_dwell_segments_are_skipped() {
        let dwell_pkt = sample_packet();
        let dwell_seg = &dwell_pkt[PACKET_HEADER_LEN..];
        let body = b"mission-plan-bytes";
        let mut mission = vec![1u8];
        mission.extend_from_slice(&((SEGMENT_HEADER_LEN + body.len()) as u32).to_be_bytes());
        mission.extend_from_slice(body);

        let total = (PACKET_HEADER_LEN + mission.len() + dwell_seg.len()) as u32;
        let mut pkt = dwell_pkt[..PACKET_HEADER_LEN].to_vec();
        pkt[2..6].copy_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&mission);
        pkt.extend_from_slice(dwell_seg);
        let targets = parser().parse_packet(&pkt).unwrap();
        assert_eq!(targets.len(), 1);
        assert!((targets[0].lat - T_LAT).abs() < 1e-3);
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parser().parse_packet(b"").is_err());
        assert!(parser().parse_packet(&[0x03; 8]).is_err());
        let mut huge = vec![0x03, 0x01];
        huge.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        huge.extend_from_slice(&[0u8; 26]);
        assert_eq!(
            parser().parse_packet(&huge),
            Err(GmtiError::Truncated),
            "a declared size past the frame is refused"
        );
    }
}
