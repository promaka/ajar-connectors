// SPDX-License-Identifier: Apache-2.0
//! STANAG 4607 (NATO GMTI Format) Dwell Segment -> canonical Ajar events.
//!
//! Ground Moving Target Indicator radar emits **GMTI** packets: a 32-byte packet
//! header, then a run of segments (Mission, Dwell, Job Definition, ...). The
//! **Dwell Segment** carries the actual moving-target reports — the dots on the
//! map. Each dwell opens with an 8-byte **existence mask** that says which
//! optional fields are present; the target reports follow, each gated by the same
//! mask. This connector decodes the Dwell path completely (sensor geometry, dwell
//! area, and per-target position / velocity) and emits one event per target.
//!
//! The **entire raw dwell segment** is sealed into every target event's payload,
//! so any field this connector does not map — and any other segment type — is
//! never lost. GMTI target reports are un-associated detections (the format
//! carries no persistent track id), so `source_uid` is unique per detection, not
//! a track; downstream fusion associates them.
//!
//! Untrusted edge: GMTI has no checksum, so the only structural guard is strict
//! size-bounding. Every read is bounds-checked and every failure is a typed error
//! — it never panics and never fabricates a field. Field order, sizes, existence-
//! mask bit assignments, and scale factors are taken from the STANAG 4607 spec and
//! cross-checked against the Wireshark dissector and the pentlandedge `s4607`
//! reference implementation.

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

/// The fixed GMTI packet header length.
const PACKET_HEADER_LEN: usize = 32;
/// The segment header length (1-byte type + 4-byte size).
const SEGMENT_HEADER_LEN: usize = 5;
/// Dwell segment type number.
const SEG_DWELL: u8 = 2;

/// Why a GMTI packet could not be decoded. Counted and logged with the reason.
#[derive(Debug, PartialEq, Eq)]
pub enum GmtiError {
    /// Not a GMTI packet (unrecognised edition, or declared size out of range).
    NotGmti,
    /// A field, segment, or report ran past its declared bound.
    Truncated,
    /// A segment declared an impossible size.
    BadSegment,
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for GmtiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GmtiError::NotGmti => write!(f, "not a STANAG 4607 GMTI packet"),
            GmtiError::Truncated => write!(f, "GMTI packet truncated"),
            GmtiError::BadSegment => write!(f, "GMTI segment declared an invalid size"),
            GmtiError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for GmtiError {}

/// One decoded GMTI moving-target detection, with its dwell context and the raw
/// dwell segment that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct GmtiTarget {
    /// Platform id from the packet header (trimmed ASCII).
    pub platform: String,
    /// Job id from the packet header — ties detections to a sensor tasking.
    pub job_id: u32,
    /// Dwell index within the revisit.
    pub dwell_index: u16,
    /// MTI report index within the dwell, if present.
    pub mti_index: Option<u16>,
    /// Dwell time, milliseconds relative to the mission reference time (the
    /// absolute reference lives in the Mission Segment; kept native here).
    pub dwell_time_ms: i32,
    /// Sensor (platform) latitude at the dwell, degrees.
    pub sensor_lat: f64,
    /// Sensor (platform) longitude at the dwell, degrees (-180..180).
    pub sensor_lon: f64,
    /// Target latitude, degrees.
    pub lat: f64,
    /// Target longitude, degrees (-180..180).
    pub lon: f64,
    /// Target geodetic height, metres, if reported.
    pub height_m: Option<f64>,
    /// Target line-of-sight (radial) velocity, m/s, if reported.
    pub radial_velocity_mps: Option<f64>,
    /// Target signal-to-noise ratio, dB, if reported.
    pub snr_db: Option<i8>,
    /// Target classification code (STANAG 4607 target-classification table).
    pub classification: Option<u8>,
    /// Target radar cross section, dB, if reported.
    pub rcs_db: Option<i8>,
    /// The entire raw dwell segment, verbatim — sealed into the payload so nothing
    /// (including unmapped fields and reports) is lost.
    pub raw: Vec<u8>,
}

/// Normalizes a STANAG 4607 GMTI stream for one connector identity. Stateless:
/// each packet is self-contained.
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

    /// Parse one GMTI packet, returning a detection per located target report
    /// across all Dwell segments. Non-dwell segments (Mission, Job Definition, ...)
    /// are skipped by size — they carry no target data.
    pub fn parse_packet(&self, frame: &[u8]) -> Result<Vec<GmtiTarget>, GmtiError> {
        if frame.len() < PACKET_HEADER_LEN {
            return Err(GmtiError::Truncated);
        }
        // Version ID byte 0 = edition. GMTI has no magic key, so this plus a
        // sane packet size is the best available "is this GMTI" guard.
        let edition = frame[0];
        if edition != 0x02 && edition != 0x03 {
            return Err(GmtiError::NotGmti);
        }
        let packet_size = u32_be(&frame[2..6]) as usize;
        if packet_size < PACKET_HEADER_LEN || packet_size > frame.len() {
            return Err(GmtiError::Truncated);
        }
        let platform = ascii(&frame[14..24]);
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

    /// Decode one Dwell segment: existence mask, dwell-level fields (mandatory +
    /// conditional per the mask, in wire order), then each target report.
    fn parse_dwell(
        &self,
        seg: &[u8],
        platform: &str,
        job_id: u32,
        out: &mut Vec<GmtiTarget>,
    ) -> Result<(), GmtiError> {
        let mut r = Reader::new(seg);
        r.skip(SEGMENT_HEADER_LEN)?; // segment type + size
        let mask = u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes"));
        let bit = |n: u32| (mask >> (63 - n)) & 1 == 1;

        // Mandatory dwell fields (D2..D9), always present.
        let _revisit = r.u16()?;
        let dwell_index = r.u16()?;
        let _last_dwell = r.u8()?;
        let target_count = r.u16()?;
        let dwell_time_ms = r.i32()?;
        let sensor_lat = sa32(r.i32()?);
        let sensor_lon = norm_lon(ba32(r.u32()?));
        let _sensor_alt_cm = r.i32()?;

        // Conditional dwell fields D10..D23 (bits 8..21), in wire order. Only the
        // lat/lon scale factors are used (to place delta-coded targets); the rest
        // are correctly skipped by size so the target reports stay byte-aligned.
        let lat_scale = if bit(8) { Some(sa32(r.i32()?)) } else { None };
        let lon_scale = if bit(9) { Some(ba32(r.u32()?)) } else { None };
        if bit(10) {
            r.skip(4)?;
        } // sensor pos. uncertainty, along track
        if bit(11) {
            r.skip(4)?;
        } // sensor pos. uncertainty, cross track
        if bit(12) {
            r.skip(2)?;
        } // sensor pos. uncertainty, altitude
        if bit(13) {
            r.skip(2)?;
        } // sensor track
        if bit(14) {
            r.skip(4)?;
        } // sensor speed
        if bit(15) {
            r.skip(1)?;
        } // sensor vertical velocity
        if bit(16) {
            r.skip(1)?;
        } // sensor track uncertainty
        if bit(17) {
            r.skip(2)?;
        } // sensor speed uncertainty
        if bit(18) {
            r.skip(2)?;
        } // sensor vertical velocity uncertainty
        if bit(19) {
            r.skip(2)?;
        } // platform heading
        if bit(20) {
            r.skip(2)?;
        } // platform pitch
        if bit(21) {
            r.skip(2)?;
        } // platform roll

        // Mandatory dwell-area fields (D24..D27), always present.
        let dwell_center_lat = sa32(r.i32()?);
        let dwell_center_lon_raw = ba32(r.u32()?); // kept 0..360 for delta math
        r.skip(2)?; // dwell range half-extent (b16, km)
        r.skip(2)?; // dwell angle half-extent (ba16)

        // Conditional dwell fields D28..D31 (bits 26..29).
        if bit(26) {
            r.skip(2)?;
        } // sensor orientation heading
        if bit(27) {
            r.skip(2)?;
        } // sensor orientation pitch
        if bit(28) {
            r.skip(2)?;
        } // sensor orientation roll
        if bit(29) {
            r.skip(1)?;
        } // minimum detectable velocity

        // Target reports, each gated by the D32.x bits (30..47).
        for _ in 0..target_count {
            let mti_index = if bit(30) { Some(r.u16()?) } else { None };
            let hr_lat = if bit(31) { Some(sa32(r.i32()?)) } else { None };
            let hr_lon = if bit(32) { Some(ba32(r.u32()?)) } else { None };
            let delta_lat = if bit(33) { Some(r.i16()?) } else { None };
            let delta_lon = if bit(34) { Some(r.i16()?) } else { None };
            let height_m = if bit(35) { Some(r.i16()? as f64) } else { None };
            let radial = if bit(36) {
                Some(r.i16()? as f64 / 100.0)
            } else {
                None
            };
            if bit(37) {
                r.skip(2)?;
            } // wrap velocity
            let snr_db = if bit(38) { Some(r.i8()?) } else { None };
            let classification = if bit(39) { Some(r.u8()?) } else { None };
            if bit(40) {
                r.skip(1)?;
            } // classification probability
            if bit(41) {
                r.skip(2)?;
            } // slant-range uncertainty
            if bit(42) {
                r.skip(2)?;
            } // cross-range uncertainty
            if bit(43) {
                r.skip(1)?;
            } // height uncertainty
            if bit(44) {
                r.skip(2)?;
            } // radial-velocity uncertainty
            if bit(45) {
                r.skip(1)?;
            } // truth tag: application
            if bit(46) {
                r.skip(4)?;
            } // truth tag: entity
            let rcs_db = if bit(47) { Some(r.i8()?) } else { None };

            // Position: absolute hi-res, else delta from dwell centre × scale.
            let pos = match (hr_lat, hr_lon) {
                (Some(la), Some(lo)) => Some((la, norm_lon(lo))),
                _ => match (delta_lat, delta_lon, lat_scale, lon_scale) {
                    (Some(dla), Some(dlo), Some(ls), Some(los)) => Some((
                        dwell_center_lat + dla as f64 * ls,
                        norm_lon(dwell_center_lon_raw + dlo as f64 * los),
                    )),
                    _ => None,
                },
            };
            // A report with no position updates nothing on the map; skip it.
            if let Some((lat, lon)) = pos {
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
                    radial_velocity_mps: radial,
                    snr_db,
                    classification,
                    rcs_db,
                    raw: seg.to_vec(),
                });
            }
        }
        Ok(())
    }

    fn base_builder(&self, t: &GmtiTarget) -> EventBuilder {
        // The whole raw dwell segment is preserved verbatim in the signed payload.
        // GMTI detections carry no persistent identity, so source_uid is unique per
        // detection (platform:job:dwell:report), not a track — downstream fusion
        // associates them. Height defaults to 0 when the report omits it.
        let report = self.mti_ordinal(t);
        let source_uid = format!("{}:{}:{}:{}", t.platform, t.job_id, t.dwell_index, report);
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:ground-track")
            .new_id()
            .location(t.lat, t.lon, t.height_m.unwrap_or(0.0))
            .payload(t.raw.clone())
            .metadata("source_uid", source_uid)
            .metadata("platform", t.platform.clone())
            .metadata("job_id", t.job_id.to_string())
            .metadata("dwell_index", t.dwell_index.to_string())
            .metadata("dwell_time_ms", t.dwell_time_ms.to_string())
            .metadata("sensor_lat", format!("{:.6}", t.sensor_lat))
            .metadata("sensor_lon", format!("{:.6}", t.sensor_lon));
        if let Some(i) = t.mti_index {
            b = b.metadata("mti_report_index", i.to_string());
        }

        // Affiliation is only ever the operator's explicit assertion — GMTI carries
        // none of its own. Every decoded field rides as an attribute; Core demotes
        // undeclared keys.
        if let Some(aff) = self.enrichment.affiliation.as_deref() {
            b = b.attribute("affiliation", aff);
        }
        // Radial velocity is line-of-sight (governed m/s), distinct from ground
        // speed; kept under its own key.
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

    /// A stable-within-dwell ordinal for the detection (the MTI index if present).
    fn mti_ordinal(&self, t: &GmtiTarget) -> String {
        t.mti_index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "na".to_string())
    }

    /// Build with an explicit observation timestamp (tests pin this path).
    pub fn to_event_at(&self, t: &GmtiTarget, observed: &str) -> Result<Event, GmtiError> {
        self.base_builder(t)
            .timestamp(observed)
            .build()
            .map_err(|e| GmtiError::Build(e.to_string()))
    }

    /// Build stamped with receipt time — GMTI dwell time is relative to the
    /// Mission Segment reference, so observation time is when we saw it.
    fn to_event_now(&self, t: &GmtiTarget) -> Result<Event, GmtiError> {
        self.base_builder(t)
            .now()
            .build()
            .map_err(|e| GmtiError::Build(e.to_string()))
    }
}

impl FrameParser for GmtiParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let targets = self.parse_packet(frame).map_err(box_err)?;
        let mut events = Vec::with_capacity(targets.len());
        for t in &targets {
            events.push(self.to_event_now(t).map_err(box_err)?);
        }
        Ok(events)
    }
}

fn box_err(e: GmtiError) -> ParseError {
    Box::new(e) as ParseError
}

/// A bounds-checked big-endian reader over a byte slice.
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
        if end > self.buf.len() {
            return Err(GmtiError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
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
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn i16(&mut self) -> Result<i16, GmtiError> {
        Ok(i16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }
    fn u32(&mut self) -> Result<u32, GmtiError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn i32(&mut self) -> Result<i32, GmtiError> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
}

fn u32_be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// STANAG 4607 32-bit signed binary angle -> degrees (±90 for lat, ±180 for lon).
fn sa32(v: i32) -> f64 {
    v as f64 * 1.406_25 / 33_554_432.0
}
/// STANAG 4607 32-bit binary angle -> degrees (0..360).
fn ba32(v: u32) -> f64 {
    v as f64 * 1.406_25 / 16_777_216.0
}
/// Normalise a 0..360 longitude to -180..180.
fn norm_lon(d: f64) -> f64 {
    if d > 180.0 {
        d - 360.0
    } else {
        d
    }
}

fn ascii(v: &[u8]) -> String {
    String::from_utf8_lossy(v).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal-but-valid GMTI packet: 32-byte header + one Dwell segment
    // with the mandatory dwell fields and a single target carrying absolute
    // hi-res lat/lon, geodetic height, and radial velocity.
    const T_LAT: f64 = 60.1;
    const T_LON: f64 = 24.9;

    fn sa32_enc(deg: f64) -> i32 {
        (deg * 33_554_432.0 / 1.406_25) as i32
    }
    fn ba32_enc(deg: f64) -> u32 {
        (deg * 16_777_216.0 / 1.406_25) as u32
    }

    fn sample_packet() -> Vec<u8> {
        // Existence mask: mandatory (0xFF) + D24/D25 (dwell centre) + D26/D27
        // (range/angle) + target D32.1 (index), D32.2/.3 (hi-res lat/lon),
        // D32.6 (height), D32.7 (radial). All other conditionals absent.
        let mask: [u8; 8] = [0xFF, 0x00, 0x03, 0xC3, 0x98, 0x00, 0x00, 0x00];

        let mut dwell_body = Vec::new();
        dwell_body.extend_from_slice(&mask);
        dwell_body.extend_from_slice(&7u16.to_be_bytes()); // revisit index
        dwell_body.extend_from_slice(&3u16.to_be_bytes()); // dwell index
        dwell_body.push(1); // last dwell of revisit
        dwell_body.extend_from_slice(&1u16.to_be_bytes()); // target report count
        dwell_body.extend_from_slice(&123_456i32.to_be_bytes()); // dwell time ms
        dwell_body.extend_from_slice(&sa32_enc(60.0).to_be_bytes()); // sensor lat
        dwell_body.extend_from_slice(&ba32_enc(25.0).to_be_bytes()); // sensor lon
        dwell_body.extend_from_slice(&150_000i32.to_be_bytes()); // sensor alt cm
                                                                 // dwell-area (mandatory)
        dwell_body.extend_from_slice(&sa32_enc(60.05).to_be_bytes()); // centre lat
        dwell_body.extend_from_slice(&ba32_enc(24.95).to_be_bytes()); // centre lon
        dwell_body.extend_from_slice(&0u16.to_be_bytes()); // range half-extent
        dwell_body.extend_from_slice(&0u16.to_be_bytes()); // angle half-extent
                                                           // one target report
        dwell_body.extend_from_slice(&42u16.to_be_bytes()); // mti index
        dwell_body.extend_from_slice(&sa32_enc(T_LAT).to_be_bytes()); // hi-res lat
        dwell_body.extend_from_slice(&ba32_enc(T_LON).to_be_bytes()); // hi-res lon
        dwell_body.extend_from_slice(&120i16.to_be_bytes()); // geodetic height m
        dwell_body.extend_from_slice(&(-450i16).to_be_bytes()); // radial cm/s

        let seg_size = (SEGMENT_HEADER_LEN + dwell_body.len()) as u32;
        let mut segment = Vec::new();
        segment.push(SEG_DWELL);
        segment.extend_from_slice(&seg_size.to_be_bytes());
        segment.extend_from_slice(&dwell_body);

        let packet_size = (PACKET_HEADER_LEN + segment.len()) as u32;
        let mut pkt = Vec::new();
        pkt.push(0x03); // edition 3
        pkt.push(0x01); // version 1
        pkt.extend_from_slice(&packet_size.to_be_bytes());
        pkt.extend_from_slice(b"XN"); // nationality
        pkt.push(1); // classification: unclassified
        pkt.extend_from_slice(b"  "); // classification system
        pkt.extend_from_slice(&0u16.to_be_bytes()); // packet security
        pkt.push(0); // exercise indicator
        pkt.extend_from_slice(b"REAPER-01 "); // platform id (10 ascii)
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
    fn decodes_a_target_position_and_kinematics() {
        let targets = parser().parse_packet(&sample_packet()).unwrap();
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        assert!((t.lat - T_LAT).abs() < 1e-3, "lat {}", t.lat);
        assert!((t.lon - T_LON).abs() < 1e-3, "lon {}", t.lon);
        assert!((t.height_m.unwrap() - 120.0).abs() < 1.0);
        assert!((t.radial_velocity_mps.unwrap() - (-4.5)).abs() < 1e-6); // -450 cm/s
        assert_eq!(t.mti_index, Some(42));
        assert_eq!(t.dwell_index, 3);
        assert_eq!(t.platform, "REAPER-01");
        assert_eq!(t.job_id, 9001);
    }

    #[test]
    fn event_carries_identity_units_and_seals_raw() {
        let pkt = sample_packet();
        let p = GmtiParser::new(
            "gmti-radar-1",
            Enrichment::default().with_affiliation("hostile"),
        );
        let t = &p.parse_packet(&pkt).unwrap()[0];
        let ev = p.to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(ev.entity_type, "mim:ground-track");
        // Unique-per-detection source_uid: platform:job:dwell:report.
        assert_eq!(meta(&ev, "source_uid"), Some("REAPER-01:9001:3:42"));
        assert_eq!(meta(&ev, "platform"), Some("REAPER-01"));
        assert_eq!(attr(&ev, "radial_velocity"), Some("-4.50")); // m/s
        assert_eq!(attr(&ev, "affiliation"), Some("hostile"));
        // Losslessness: the whole raw dwell segment is sealed in the payload.
        assert!(ev.payload.starts_with(&[SEG_DWELL]));
        assert!(ev.payload.len() > 40);
    }

    #[test]
    fn non_gmti_is_rejected() {
        assert_eq!(
            parser()
                .parse_packet(b"this is definitely not a gmti packet at all!!")
                .unwrap_err(),
            GmtiError::NotGmti
        );
    }

    #[test]
    fn truncated_packet_is_rejected_not_panicked() {
        let pkt = sample_packet();
        assert_eq!(
            parser().parse_packet(&pkt[..40]).unwrap_err(),
            GmtiError::Truncated
        );
    }

    #[test]
    fn oversized_segment_is_rejected() {
        let mut pkt = sample_packet();
        // Corrupt the dwell segment size to claim it runs past the packet.
        pkt[PACKET_HEADER_LEN + 1] = 0xFF;
        assert_eq!(
            parser().parse_packet(&pkt).unwrap_err(),
            GmtiError::BadSegment
        );
    }

    #[test]
    fn non_dwell_segments_are_skipped() {
        // Prepend a Mission segment (type 1) the connector doesn't decode; the
        // dwell after it must still parse to one target.
        let dwell_pkt = sample_packet();
        let dwell_seg = &dwell_pkt[PACKET_HEADER_LEN..];
        let mission = {
            let body = b"mission-plan-bytes";
            let size = (SEGMENT_HEADER_LEN + body.len()) as u32;
            let mut s = vec![1u8];
            s.extend_from_slice(&size.to_be_bytes());
            s.extend_from_slice(body);
            s
        };
        let total = (PACKET_HEADER_LEN + mission.len() + dwell_seg.len()) as u32;
        let mut pkt = dwell_pkt[..PACKET_HEADER_LEN].to_vec();
        pkt[2..6].copy_from_slice(&total.to_be_bytes()); // fix packet size
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
        // Edition 3 header claiming a huge packet size must be rejected, not read.
        let mut bad = vec![0x03, 0x01];
        bad.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        bad.extend_from_slice(&[0u8; 26]);
        assert_eq!(
            parser().parse_packet(&bad).unwrap_err(),
            GmtiError::Truncated
        );
    }
}
