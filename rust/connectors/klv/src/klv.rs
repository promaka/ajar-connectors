// SPDX-License-Identifier: Apache-2.0
//! STANAG 4609 / MISB ST 0601 "UAS Datalink Local Set" (KLV) -> canonical Ajar
//! event.
//!
//! Full-motion-imagery platforms (UAS, gimbals, ISR pods) emit their telemetry as
//! **KLV** (Key-Length-Value, SMPTE 336M) carrying the MISB ST 0601 UAS Local Set:
//! a 16-byte Universal Label, a BER length, then a run of BER-OID-tagged
//! Tag-Length-Value items, closed by a mandatory 16-bit checksum (tag 1).
//!
//! This is a REFERENCE binary-STANAG connector: it decodes the common platform
//! tags (time, identity, attitude, sensor position) and — crucially — seals the
//! **entire raw KLV set** into `Event.payload`, so the ~100 ST 0601 tags this
//! connector does not yet map are never lost. A later ontology (or a generated
//! extension) can re-extract them from the stored raw. It is a worked example of
//! the pattern an operator (or an agent, see the repo `AGENTS.md`) follows to add
//! a connector for any binary format.
//!
//! This is an untrusted edge: a set can be truncated, non-KLV, or hostile, so
//! every step is checked and every failure is a typed error — it never panics and
//! never fabricates a field. Scaling factors are per MISB ST 0601.

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The 16-byte Universal Label that opens a MISB ST 0601 UAS Datalink Local Set.
const UAS_LS_KEY: [u8; 16] = [
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

/// Why a KLV set could not be turned into a platform event. Counted and logged
/// with the reason; never silently swallowed.
#[derive(Debug, PartialEq, Eq)]
pub enum KlvError {
    /// The set did not open with the ST 0601 UAS Local Set Universal Label.
    NotUasLs,
    /// A length or value ran past the end of the buffer.
    Truncated,
    /// A BER length field was malformed (indefinite form, or too many bytes).
    BadLength,
    /// The mandatory ST 0601 checksum (tag 1) was missing or did not match.
    BadChecksum,
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for KlvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KlvError::NotUasLs => write!(f, "not a MISB ST 0601 UAS Local Set (bad key)"),
            KlvError::Truncated => write!(f, "KLV set truncated"),
            KlvError::BadLength => write!(f, "malformed BER length"),
            KlvError::BadChecksum => write!(f, "ST 0601 checksum missing or mismatched"),
            KlvError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for KlvError {}

/// A decoded ST 0601 platform report — the subset of tags this connector maps,
/// plus the verbatim raw set. Deterministic given the same input.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UasMetadata {
    /// Precision Time Stamp (tag 2) as RFC 3339, if present and valid.
    pub timestamp: Option<String>,
    /// Platform Tail Number (tag 4).
    pub tail_number: Option<String>,
    /// Platform Designation (tag 10).
    pub designation: Option<String>,
    /// Mission ID (tag 3).
    pub mission_id: Option<String>,
    /// Platform Heading Angle, degrees (tag 5).
    pub heading: Option<f64>,
    /// Platform Pitch Angle, degrees (tag 6).
    pub pitch: Option<f64>,
    /// Platform Roll Angle, degrees (tag 7).
    pub roll: Option<f64>,
    /// Sensor Latitude, degrees (tag 13).
    pub lat: Option<f64>,
    /// Sensor Longitude, degrees (tag 14).
    pub lon: Option<f64>,
    /// Sensor True Altitude, metres (tag 15).
    pub alt_m: Option<f64>,
    /// UAS LS version number (tag 65).
    pub ls_version: Option<u8>,
    /// The entire raw KLV set, verbatim — carried into the signed payload so the
    /// tags this connector does not map are never lost.
    pub raw: Vec<u8>,
}

/// Normalizes a MISB ST 0601 KLV stream for one connector identity. Stateless:
/// each set is self-contained, so there is no per-entity cache.
pub struct KlvParser {
    source_id: String,
    enrichment: Enrichment,
}

impl KlvParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
        }
    }

    /// Parse one KLV set. Returns a platform report for a set carrying sensor
    /// lat+lon; `Ok(None)` for a valid set with no position (nothing to track).
    pub fn parse_set(&self, frame: &[u8]) -> Result<Option<UasMetadata>, KlvError> {
        if frame.len() < 17 || frame[..16] != UAS_LS_KEY {
            return Err(KlvError::NotUasLs);
        }
        let mut pos = 16;
        let set_len = read_ber_len(frame, &mut pos)?;
        let total = pos.checked_add(set_len).ok_or(KlvError::BadLength)?;
        if total > frame.len() || total < pos + 2 {
            return Err(KlvError::Truncated);
        }
        let pkt = &frame[..total];

        // The mandatory ST 0601 checksum (tag 1) is the final item; its 2-byte
        // value is a 16-bit running sum over every prior byte of the set.
        let given = u16::from_be_bytes([pkt[total - 2], pkt[total - 1]]);
        if bcc_16(&pkt[..total - 2]) != given {
            return Err(KlvError::BadChecksum);
        }

        let mut m = UasMetadata::default();
        let end = total;
        let mut p = pos; // start of the first TLV
        while p < end {
            let tag = read_ber_oid_tag(frame, &mut p)?;
            let len = read_ber_len(frame, &mut p)?;
            let vend = p.checked_add(len).ok_or(KlvError::BadLength)?;
            if vend > end {
                return Err(KlvError::Truncated);
            }
            let val = &frame[p..vend];
            p = vend;
            match tag {
                1 => {} // checksum — already validated above
                2 => m.timestamp = be_u64(val).and_then(micros_to_rfc3339),
                3 => m.mission_id = ascii(val),
                4 => m.tail_number = ascii(val),
                5 => m.heading = be_u16(val).map(|v| v as f64 * 360.0 / 65535.0),
                6 => m.pitch = be_i16(val).and_then(|v| i16_scaled(v, 20.0)),
                7 => m.roll = be_i16(val).and_then(|v| i16_scaled(v, 50.0)),
                10 => m.designation = ascii(val),
                13 => m.lat = be_i32(val).and_then(|v| i32_angle(v, 90.0)),
                14 => m.lon = be_i32(val).and_then(|v| i32_angle(v, 180.0)),
                15 => m.alt_m = be_u16(val).map(|v| -900.0 + v as f64 * 19_900.0 / 65_535.0),
                65 => m.ls_version = val.first().copied(),
                // Every other ST 0601 tag rides untouched in the raw payload
                // (losslessness) — a later ontology can extract it.
                _ => {}
            }
        }
        m.raw = pkt.to_vec();

        // A platform track needs a position; a set without sensor lat+lon updates
        // nothing on the map, so it emits no event (its raw is not retained —
        // consistent with the other connectors' no-fix behaviour).
        if m.lat.is_some() && m.lon.is_some() {
            Ok(Some(m))
        } else {
            Ok(None)
        }
    }

    fn base_builder(&self, m: &UasMetadata) -> EventBuilder {
        // The entire raw KLV set is preserved verbatim in the signed payload, so
        // the ~100 ST 0601 tags not mapped here are never lost. Tail number is the
        // stable identity (source_uid); every decoded field rides as an attribute
        // (Core demotes undeclared keys), platform ids as metadata.
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(
                m.lat.expect("emit requires lat"),
                m.lon.expect("emit requires lon"),
                m.alt_m.unwrap_or(0.0),
            )
            .payload(m.raw.clone());

        if let Some(id) = m.tail_number.clone().or_else(|| m.designation.clone()) {
            b = b.metadata("source_uid", id);
        }
        if let Some(t) = &m.tail_number {
            b = b.metadata("tail_number", t.clone());
        }
        if let Some(mi) = &m.mission_id {
            b = b.metadata("mission_id", mi.clone());
        }
        if let Some(v) = m.ls_version {
            b = b.metadata("uas_ls_version", v.to_string());
        }
        // Affiliation is only ever the operator's explicit assertion — never a
        // connector-invented default (KLV carries none of its own).
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(d) = &m.designation {
            b = b.attribute("platform_designation", d.clone());
        }
        // heading is the governed degrees attribute; pitch/roll ride ungoverned.
        if let Some(h) = m.heading {
            b = b.attribute("heading", format!("{h:.1}"));
        }
        if let Some(p) = m.pitch {
            b = b.attribute("pitch", format!("{p:.1}"));
        }
        if let Some(r) = m.roll {
            b = b.attribute("roll", format!("{r:.1}"));
        }
        b
    }

    /// Build with an explicit observation timestamp (tests pin this path).
    pub fn to_event_at(&self, m: &UasMetadata, observed: &str) -> Result<Event, KlvError> {
        self.base_builder(m)
            .timestamp(observed)
            .build()
            .map_err(|e| KlvError::Build(e.to_string()))
    }

    /// Build using the set's own Precision Time Stamp (tag 2) when present, else
    /// receipt time.
    fn to_event(&self, m: &UasMetadata) -> Result<Event, KlvError> {
        let b = self.base_builder(m);
        let b = match &m.timestamp {
            Some(ts) => b.timestamp(ts.clone()),
            None => b.now(),
        };
        b.build().map_err(|e| KlvError::Build(e.to_string()))
    }
}

impl FrameParser for KlvParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        match self.parse_set(frame).map_err(box_err)? {
            Some(m) => Ok(vec![self.to_event(&m).map_err(box_err)?]),
            None => Ok(Vec::new()),
        }
    }
}

fn box_err(e: KlvError) -> ParseError {
    Box::new(e) as ParseError
}

/// The ST 0601 16-bit checksum: a running sum where even-indexed bytes land in
/// the high byte and odd-indexed bytes in the low byte.
fn bcc_16(bytes: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in bytes.iter().enumerate() {
        sum = sum.wrapping_add((b as u16) << (8 * ((i + 1) % 2)));
    }
    sum
}

/// Read a BER length at `*pos`, advancing it. Rejects the indefinite form and
/// lengths wider than 4 bytes.
fn read_ber_len(buf: &[u8], pos: &mut usize) -> Result<usize, KlvError> {
    let b0 = *buf.get(*pos).ok_or(KlvError::Truncated)?;
    *pos += 1;
    if b0 & 0x80 == 0 {
        return Ok(b0 as usize);
    }
    let n = (b0 & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(KlvError::BadLength);
    }
    let mut len = 0usize;
    for _ in 0..n {
        let b = *buf.get(*pos).ok_or(KlvError::Truncated)?;
        *pos += 1;
        len = (len << 8) | b as usize;
    }
    Ok(len)
}

/// Read a BER-OID tag at `*pos`, advancing it (single byte for tags < 128).
fn read_ber_oid_tag(buf: &[u8], pos: &mut usize) -> Result<u32, KlvError> {
    let mut tag = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(KlvError::Truncated)?;
        *pos += 1;
        tag = (tag << 7) | (b & 0x7f) as u32;
        if b & 0x80 == 0 {
            return Ok(tag);
        }
    }
}

fn be_u16(v: &[u8]) -> Option<u16> {
    (v.len() == 2).then(|| u16::from_be_bytes([v[0], v[1]]))
}
fn be_i16(v: &[u8]) -> Option<i16> {
    (v.len() == 2).then(|| i16::from_be_bytes([v[0], v[1]]))
}
fn be_i32(v: &[u8]) -> Option<i32> {
    (v.len() == 4).then(|| i32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}
fn be_u64(v: &[u8]) -> Option<u64> {
    (v.len() == 8).then(|| u64::from_be_bytes(v.try_into().expect("len checked")))
}

/// ST 0601 signed angle: full int range maps to ±`half`; `i32::MIN` is the
/// "error" indicator.
fn i32_angle(v: i32, half: f64) -> Option<f64> {
    (v != i32::MIN).then(|| v as f64 * half / (i32::MAX as f64))
}
/// ST 0601 signed attitude: full int range maps to ±`half` degrees; `i16::MIN`
/// is the "out of range" indicator.
fn i16_scaled(v: i16, half: f64) -> Option<f64> {
    (v != i16::MIN).then(|| v as f64 * half / (i16::MAX as f64))
}

fn ascii(v: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(v).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn micros_to_rfc3339(micros: u64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos((micros as i128) * 1_000)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ber_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else if n <= 0xff {
            vec![0x81, n as u8]
        } else {
            vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
        }
    }

    fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(ber_len(val.len()));
        v.extend_from_slice(val);
        v
    }

    /// Assemble a valid ST 0601 set from body items, appending a correct checksum.
    fn build_set(items: &[Vec<u8>]) -> Vec<u8> {
        let mut inner = Vec::new();
        for it in items {
            inner.extend_from_slice(it);
        }
        inner.extend_from_slice(&[0x01, 0x02]); // checksum tag + length
        let set_len = inner.len() + 2; // + the 2 checksum value bytes
        let mut pkt = UAS_LS_KEY.to_vec();
        pkt.extend(ber_len(set_len));
        pkt.extend_from_slice(&inner);
        let bcc = bcc_16(&pkt); // over everything up to the checksum value
        pkt.extend_from_slice(&bcc.to_be_bytes());
        pkt
    }

    // Helsinki-ish platform: 60.176822 N, 24.935508 E, 500 m, heading 270.
    const LAT: f64 = 60.176822;
    const LON: f64 = 24.935508;

    fn sample() -> Vec<u8> {
        let lat = (LAT * (i32::MAX as f64) / 90.0) as i32;
        let lon = (LON * (i32::MAX as f64) / 180.0) as i32;
        let hdg = (270.0 / 360.0 * 65_535.0) as u16;
        let alt = ((500.0 + 900.0) / 19_900.0 * 65_535.0) as u16;
        build_set(&[
            tlv(2, &1_700_000_000_000_000u64.to_be_bytes()), // 2023-11-14T22:13:20Z
            tlv(4, b"AB123"),
            tlv(5, &hdg.to_be_bytes()),
            tlv(10, b"PREDATOR"),
            tlv(13, &lat.to_be_bytes()),
            tlv(14, &lon.to_be_bytes()),
            tlv(15, &alt.to_be_bytes()),
            tlv(65, &[15]),
            // An unmapped tag (Platform True Airspeed) — must survive in payload.
            tlv(56, &[42]),
        ])
    }

    fn parser() -> KlvParser {
        KlvParser::new("uas-klv-1", Enrichment::default())
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
    fn decodes_position_attitude_and_identity() {
        let m = parser().parse_set(&sample()).unwrap().unwrap();
        assert!((m.lat.unwrap() - LAT).abs() < 1e-4);
        assert!((m.lon.unwrap() - LON).abs() < 1e-4);
        assert!((m.alt_m.unwrap() - 500.0).abs() < 1.0);
        assert!((m.heading.unwrap() - 270.0).abs() < 0.05);
        assert_eq!(m.tail_number.as_deref(), Some("AB123"));
        assert_eq!(m.designation.as_deref(), Some("PREDATOR"));
        assert_eq!(m.ls_version, Some(15));
        assert!(m
            .timestamp
            .as_deref()
            .unwrap()
            .starts_with("2023-11-14T22:13:20"));
    }

    #[test]
    fn event_carries_canonical_fields_and_seals_raw() {
        let set = sample();
        let p = KlvParser::new("uas-klv-1", Enrichment::default().with_hostility("Friend"));
        let m = p.parse_set(&set).unwrap().unwrap();
        let ev = p.to_event_at(&m, "2026-06-10T08:00:00Z").unwrap();
        assert_eq!(meta(&ev, "source_uid"), Some("AB123"));
        assert_eq!(meta(&ev, "tail_number"), Some("AB123"));
        assert_eq!(attr(&ev, "heading"), Some("270.0"));
        assert_eq!(attr(&ev, "platform_designation"), Some("PREDATOR"));
        assert_eq!(attr(&ev, "hostility"), Some("Friend"));
        // Losslessness: the entire raw set (incl. the unmapped airspeed tag 56) is
        // sealed verbatim in the payload.
        assert_eq!(ev.payload.as_slice(), set.as_slice());
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let mut set = sample();
        let n = set.len();
        set[n / 2] ^= 0xff; // corrupt a value byte; the stored checksum no longer matches
        assert_eq!(parser().parse_set(&set), Err(KlvError::BadChecksum));
    }

    #[test]
    fn non_klv_is_rejected() {
        assert_eq!(
            parser().parse_set(b"this is not a KLV set at all"),
            Err(KlvError::NotUasLs)
        );
    }

    #[test]
    fn truncated_set_is_rejected_not_panicked() {
        let set = sample();
        assert_eq!(parser().parse_set(&set[..20]), Err(KlvError::Truncated));
    }

    #[test]
    fn set_without_position_emits_nothing() {
        // A valid set carrying only identity (no sensor lat/lon) is not a track.
        let set = build_set(&[tlv(4, b"AB123"), tlv(65, &[15])]);
        assert_eq!(parser().parse_set(&set).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parser().parse_set(b"").is_err());
        assert!(parser().parse_set(&[0u8; 16]).is_err()); // key only, no length
    }
}
