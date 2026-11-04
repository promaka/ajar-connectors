// SPDX-License-Identifier: Apache-2.0
//! STANAG 4609 / MISB ST 0601 UAS Datalink Local Set (KLV) to `mim:aircraft`
//! events, one per set that carries a sensor position. The tail number, else the
//! platform designation, is the `source_uid`. Scaling follows MISB ST 0601.

use ajar_connector::{BuildError, Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// The Universal Label that opens a MISB ST 0601 UAS Datalink Local Set.
const UAS_LS_KEY: [u8; 16] = [
    0x06, 0x0e, 0x2b, 0x34, 0x02, 0x0b, 0x01, 0x01, 0x0e, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
];

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum KlvError {
    #[error("not a MISB ST 0601 UAS Local Set (bad key)")]
    NotUasLs,
    #[error("KLV set truncated")]
    Truncated,
    /// Indefinite form, or wider than 4 bytes.
    #[error("malformed BER length")]
    BadLength,
    #[error("ST 0601 checksum missing or mismatched")]
    BadChecksum,
    #[error("event build failed: {0}")]
    Build(#[from] BuildError),
}

/// The ST 0601 tags this connector maps, and the raw set.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UasMetadata {
    /// RFC 3339.
    pub timestamp: Option<String>,
    pub tail_number: Option<String>,
    pub designation: Option<String>,
    pub mission_id: Option<String>,
    pub heading_deg: Option<f64>,
    pub pitch_deg: Option<f64>,
    pub roll_deg: Option<f64>,
    // The sensor's position, not the frame centre.
    pub lat: f64,
    pub lon: f64,
    pub alt_m: Option<f64>,
    /// UAS Local Set version.
    pub ls_version: Option<u8>,
    pub raw: Vec<u8>,
}

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

    /// `None` for a valid set without sensor latitude and longitude.
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

        // The checksum (tag 1) is the last item; its value covers every byte
        // before it.
        let given = u16::from_be_bytes([pkt[total - 2], pkt[total - 1]]);
        if bcc_16(&pkt[..total - 2]) != given {
            return Err(KlvError::BadChecksum);
        }

        let mut m = UasMetadata::default();
        let (mut lat, mut lon) = (None, None);
        let mut p = pos;
        while p < total {
            let tag = read_ber_oid_tag(frame, &mut p)?;
            let len = read_ber_len(frame, &mut p)?;
            let vend = p.checked_add(len).ok_or(KlvError::BadLength)?;
            if vend > total {
                return Err(KlvError::Truncated);
            }
            let val = &frame[p..vend];
            p = vend;
            match tag {
                2 => {
                    m.timestamp = be_u64(val).and_then(|us| {
                        OffsetDateTime::from_unix_timestamp_nanos(us as i128 * 1_000)
                            .ok()?
                            .format(&Rfc3339)
                            .ok()
                    })
                }
                3 => m.mission_id = ascii(val),
                4 => m.tail_number = ascii(val),
                5 => m.heading_deg = be_u16(val).map(|v| v as f64 * 360.0 / 65535.0),
                6 => m.pitch_deg = be_i16(val).and_then(|v| i16_scaled(v, 20.0)),
                7 => m.roll_deg = be_i16(val).and_then(|v| i16_scaled(v, 50.0)),
                10 => m.designation = ascii(val),
                13 => lat = be_i32(val).and_then(|v| i32_angle(v, 90.0)),
                14 => lon = be_i32(val).and_then(|v| i32_angle(v, 180.0)),
                15 => m.alt_m = be_u16(val).map(|v| -900.0 + v as f64 * 19_900.0 / 65_535.0),
                65 => m.ls_version = val.first().copied(),
                _ => {}
            }
        }
        let (Some(lat), Some(lon)) = (lat, lon) else {
            return Ok(None);
        };
        m.lat = lat;
        m.lon = lon;
        m.raw = pkt.to_vec();
        Ok(Some(m))
    }

    fn base_builder(&self, m: UasMetadata) -> EventBuilder {
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(m.lat, m.lon, m.alt_m.unwrap_or(0.0))
            .payload(m.raw);

        if let Some(id) = m.tail_number.as_ref().or(m.designation.as_ref()) {
            b = b.metadata("source_uid", id.as_str());
        }
        if let Some(t) = m.tail_number {
            b = b.metadata("tail_number", t);
        }
        if let Some(mi) = m.mission_id {
            b = b.metadata("mission_id", mi);
        }
        if let Some(v) = m.ls_version {
            b = b.metadata("uas_ls_version", v.to_string());
        }
        if let Some(aff) = self.enrichment.hostility.as_deref() {
            b = b.attribute("hostility", aff);
        }
        if let Some(d) = m.designation {
            b = b.attribute("platform_designation", d);
        }
        if let Some(deg) = m.heading_deg {
            b = b.attribute("heading", format!("{deg:.1}"));
        }
        if let Some(deg) = m.pitch_deg {
            b = b.attribute("pitch", format!("{deg:.1}"));
        }
        if let Some(deg) = m.roll_deg {
            b = b.attribute("roll", format!("{deg:.1}"));
        }
        b
    }

    pub fn to_event_at(&self, m: UasMetadata, observed: &str) -> Result<Event, KlvError> {
        Ok(self.base_builder(m).timestamp(observed).build()?)
    }
}

impl FrameParser for KlvParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let Some(mut m) = self.parse_set(frame)? else {
            return Ok(Vec::new());
        };
        let timestamp = m.timestamp.take();
        let b = self.base_builder(m);
        let b = match timestamp {
            Some(ts) => b.timestamp(ts),
            None => b.now(),
        };
        Ok(vec![b.build().map_err(KlvError::from)?])
    }
}

/// The ST 0601 checksum: a 16-bit running sum with even-indexed bytes in the
/// high byte and odd-indexed bytes in the low byte.
fn bcc_16(bytes: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in bytes.iter().enumerate() {
        sum = sum.wrapping_add((b as u16) << (8 * ((i + 1) % 2)));
    }
    sum
}

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
    v.try_into().ok().map(u16::from_be_bytes)
}

fn be_i16(v: &[u8]) -> Option<i16> {
    v.try_into().ok().map(i16::from_be_bytes)
}

fn be_i32(v: &[u8]) -> Option<i32> {
    v.try_into().ok().map(i32::from_be_bytes)
}

fn be_u64(v: &[u8]) -> Option<u64> {
    v.try_into().ok().map(u64::from_be_bytes)
}

/// ST 0601 signed angle: the full range maps to +-`half_deg`; `i32::MIN` is
/// the error indicator.
fn i32_angle(v: i32, half_deg: f64) -> Option<f64> {
    (v != i32::MIN).then(|| v as f64 * half_deg / (i32::MAX as f64))
}

/// ST 0601 signed attitude: the full range maps to +-`half_deg`; `i16::MIN`
/// is the out-of-range indicator.
fn i16_scaled(v: i16, half_deg: f64) -> Option<f64> {
    (v != i16::MIN).then(|| v as f64 * half_deg / (i16::MAX as f64))
}

fn ascii(v: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(v).trim().to_string();
    (!s.is_empty()).then_some(s)
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
        // Checksum tag and length; the 2-byte value follows the set length.
        inner.extend_from_slice(&[0x01, 0x02]);
        let set_len = inner.len() + 2;
        let mut pkt = UAS_LS_KEY.to_vec();
        pkt.extend(ber_len(set_len));
        pkt.extend_from_slice(&inner);
        let bcc = bcc_16(&pkt);
        pkt.extend_from_slice(&bcc.to_be_bytes());
        pkt
    }

    const LAT: f64 = 60.176822;
    const LON: f64 = 24.935508;
    const OBSERVED: &str = "2026-06-10T08:00:00Z";

    /// 500 m, heading 270, and an unmapped tag 56 (true airspeed).
    fn sample() -> Vec<u8> {
        let lat = (LAT * (i32::MAX as f64) / 90.0) as i32;
        let lon = (LON * (i32::MAX as f64) / 180.0) as i32;
        let hdg = (270.0 / 360.0 * 65_535.0) as u16;
        let alt = ((500.0 + 900.0) / 19_900.0 * 65_535.0) as u16;
        build_set(&[
            tlv(2, &1_700_000_000_000_000u64.to_be_bytes()),
            tlv(4, b"AB123"),
            tlv(5, &hdg.to_be_bytes()),
            tlv(10, b"PREDATOR"),
            tlv(13, &lat.to_be_bytes()),
            tlv(14, &lon.to_be_bytes()),
            tlv(15, &alt.to_be_bytes()),
            tlv(65, &[15]),
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
        assert!((m.lat - LAT).abs() < 1e-4);
        assert!((m.lon - LON).abs() < 1e-4);
        assert!((m.alt_m.unwrap() - 500.0).abs() < 1.0);
        assert!((m.heading_deg.unwrap() - 270.0).abs() < 0.05);
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
    fn event_carries_identity_and_attributes() {
        let p = KlvParser::new("uas-klv-1", Enrichment::default().with_hostility("Friend"));
        let m = p.parse_set(&sample()).unwrap().unwrap();
        let ev = p.to_event_at(m, OBSERVED).unwrap();
        assert_eq!(meta(&ev, "source_uid"), Some("AB123"));
        assert_eq!(meta(&ev, "tail_number"), Some("AB123"));
        assert_eq!(attr(&ev, "heading"), Some("270.0"));
        assert_eq!(attr(&ev, "platform_designation"), Some("PREDATOR"));
        assert_eq!(attr(&ev, "hostility"), Some("Friend"));
    }

    #[test]
    fn raw_set_sealed_in_payload() {
        let set = sample();
        let m = parser().parse_set(&set).unwrap().unwrap();
        let ev = parser().to_event_at(m, OBSERVED).unwrap();
        assert_eq!(ev.payload.as_slice(), set.as_slice());
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let mut set = sample();
        let n = set.len();
        set[n / 2] ^= 0xff;
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
    fn truncated_set_is_rejected() {
        let set = sample();
        assert_eq!(parser().parse_set(&set[..20]), Err(KlvError::Truncated));
    }

    #[test]
    fn set_without_position_emits_nothing() {
        let set = build_set(&[tlv(4, b"AB123"), tlv(65, &[15])]);
        assert_eq!(parser().parse_set(&set).unwrap(), None);
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parser().parse_set(b"").is_err());
        assert!(parser().parse_set(&[0u8; 16]).is_err());
    }
}
