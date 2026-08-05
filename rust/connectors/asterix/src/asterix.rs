// SPDX-License-Identifier: Apache-2.0
//! EUROCONTROL ASTERIX CAT021 (ADS-B target reports) -> canonical Ajar events.
//!
//! An ASTERIX data block is `CAT | LEN | record…`; a single UDP datagram can
//! carry several target records, so one frame maps to several events. Each record
//! begins with a variable-length FSPEC bitmap that says which data items follow,
//! in the fixed order of the category's User Application Profile (UAP).
//!
//! This is an untrusted edge, so every length is bounds-checked before it is read;
//! the decoder never panics and never emits a misaligned position. The UAP length
//! table below lets it walk past any standard item to reach the next record. The
//! few compound items it does not length-model (Met, Trajectory Intent, Data Ages)
//! cause it to stop at that record and report — it fails closed rather than risk
//! decoding garbage.
//!
//! Scope: CAT021 Edition 2.x, the ADS-B position report — item I021/130 (and the
//! high-resolution I021/131) WGS-84 position, keyed by target address (I021/080)
//! or track number (I021/161). Validate the UAP against your feed's edition before
//! operational use.

use ajar_connector::{Event, EventBuilder};
use ajar_connector_common::{Enrichment, FrameParser, ParseError};

const CAT021: u8 = 21;
/// 1 knot in metres/second — the governed `speed` attribute is m/s (ADR-0019).
const KNOTS_TO_MPS: f64 = 0.514_444;

/// Why an ASTERIX block or record could not be decoded.
#[derive(Debug, PartialEq, Eq)]
pub enum AsterixError {
    /// The block header (CAT + 2-byte length) was incomplete or inconsistent.
    BadBlock,
    /// A data item ran past the end of the buffer.
    Truncated,
    /// A record referenced a UAP item this decoder does not length-model; it stops
    /// rather than misalign. (See the module scope note.)
    UnsupportedItem(u8),
    /// The canonical event failed to build (a propagated invariant violation).
    Build(String),
}

impl std::fmt::Display for AsterixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsterixError::BadBlock => write!(f, "malformed ASTERIX data block"),
            AsterixError::Truncated => write!(f, "ASTERIX item runs past end of block"),
            AsterixError::UnsupportedItem(frn) => {
                write!(f, "unsupported CAT021 UAP item (FRN {frn})")
            }
            AsterixError::Build(e) => write!(f, "event build failed: {e}"),
        }
    }
}
impl std::error::Error for AsterixError {}

/// A decoded CAT021 target — the wire facts, no clock. Deterministic.
#[derive(Debug, Clone, PartialEq)]
pub struct AsterixTarget {
    pub sac: u8,
    pub sic: u8,
    pub track: Option<u16>,
    /// 24-bit ICAO target address, if the report carried one.
    pub icao: Option<u32>,
    pub lat: f64,
    pub lon: f64,
    /// Altitude in feet — geometric height (I021/140) preferred, else flight level
    /// (I021/145).
    pub alt_ft: Option<f64>,
    /// Ground speed in knots (I021/160).
    pub ground_speed: Option<f64>,
    /// Track angle / course over ground in degrees (I021/160).
    pub track_angle: Option<f64>,
    /// Mode 3/A squawk as four octal digits (I021/070).
    pub squawk: Option<String>,
    /// Callsign / flight identity (I021/170).
    pub callsign: Option<String>,
    /// Emitter category — light, heavy, rotorcraft, uav, … (I021/020).
    pub emitter: Option<&'static str>,
    /// The raw bytes of this record within the data block, preserved verbatim in
    /// the signed payload (a re-parser reads it as one CAT021 record).
    pub raw: Vec<u8>,
}

/// How to measure a UAP item's length so the record walk can skip it.
#[derive(Clone, Copy)]
enum Field {
    /// A fixed number of octets.
    Fixed(usize),
    /// FX-chained: octets continue while the low bit of each is set.
    Extended,
    /// A one-octet repetition count, then that many fixed-size items.
    Repetitive(usize),
    /// A one-octet total-length prefix (RE / SP items).
    LenPrefixed,
    /// A compound item this decoder does not length-model.
    Compound,
}

/// CAT021 Edition 2.x UAP, indexed by Field Reference Number (1-based). Only the
/// lengths matter for the record walk; the position items (FRN 6/7), track (3),
/// address (11), and source id (1) are the ones actually decoded.
const UAP: &[Field] = &[
    Field::Fixed(2),      // 1  I021/010 Data Source Identification
    Field::Extended,      // 2  I021/040 Target Report Descriptor
    Field::Fixed(2),      // 3  I021/161 Track Number
    Field::Fixed(1),      // 4  I021/015 Service Identification
    Field::Fixed(3),      // 5  I021/071 Time of Applicability for Position
    Field::Fixed(6),      // 6  I021/130 Position WGS-84
    Field::Fixed(8),      // 7  I021/131 High-Resolution Position WGS-84
    Field::Fixed(3),      // 8  I021/072 Time of Applicability for Velocity
    Field::Fixed(2),      // 9  I021/150 Air Speed
    Field::Fixed(2),      // 10 I021/151 True Airspeed
    Field::Fixed(3),      // 11 I021/080 Target Address
    Field::Fixed(3),      // 12 I021/073 Time of Message Reception for Position
    Field::Fixed(4),      // 13 I021/074 …High Precision
    Field::Fixed(3),      // 14 I021/075 Time of Message Reception for Velocity
    Field::Fixed(4),      // 15 I021/076 …High Precision
    Field::Fixed(2),      // 16 I021/140 Geometric Height
    Field::Extended,      // 17 I021/090 Quality Indicators
    Field::Fixed(1),      // 18 I021/210 MOPS Version
    Field::Fixed(2),      // 19 I021/070 Mode 3/A Code
    Field::Fixed(2),      // 20 I021/230 Roll Angle
    Field::Fixed(2),      // 21 I021/145 Flight Level
    Field::Fixed(2),      // 22 I021/152 Magnetic Heading
    Field::Fixed(1),      // 23 I021/200 Target Status
    Field::Fixed(2),      // 24 I021/155 Barometric Vertical Rate
    Field::Fixed(2),      // 25 I021/157 Geometric Vertical Rate
    Field::Fixed(4),      // 26 I021/160 Airborne Ground Vector
    Field::Fixed(2),      // 27 I021/165 Track Angle Rate
    Field::Fixed(3),      // 28 I021/077 Time of Report Transmission
    Field::Fixed(6),      // 29 I021/170 Target Identification
    Field::Fixed(1),      // 30 I021/020 Emitter Category
    Field::Compound,      // 31 I021/220 Met Information
    Field::Fixed(2),      // 32 I021/146 Selected Altitude
    Field::Fixed(2),      // 33 I021/148 Final State Selected Altitude
    Field::Compound,      // 34 I021/110 Trajectory Intent
    Field::Fixed(1),      // 35 I021/016 Service Management
    Field::Fixed(1),      // 36 I021/008 Aircraft Operational Status
    Field::Extended,      // 37 I021/271 Surface Capabilities and Characteristics
    Field::Fixed(1),      // 38 I021/132 Message Amplitude
    Field::Repetitive(8), // 39 I021/250 Mode S MB Data
    Field::Fixed(7),      // 40 I021/260 ACAS Resolution Advisory
    Field::Fixed(1),      // 41 I021/400 Receiver ID
    Field::Compound,      // 42 I021/295 Data Ages
    Field::LenPrefixed,   // 43 RE Reserved Expansion Field
    Field::LenPrefixed,   // 44 SP Special Purpose Field
];

// Position scaling (WGS-84), independent of the UAP: I021/130 stores lat and lon
// as 24-bit signed with LSB 180/2^23 degrees; I021/131 as 32-bit signed with LSB
// 180/2^30.
const LSB_130: f64 = 180.0 / (1u32 << 23) as f64;
const LSB_131: f64 = 180.0 / (1u64 << 30) as f64;

/// Normalizes ASTERIX CAT021 for one connector identity.
pub struct AsterixParser {
    source_id: String,
    enrichment: Enrichment,
}

impl AsterixParser {
    pub fn new(source_id: impl Into<String>, enrichment: Enrichment) -> Self {
        Self {
            source_id: source_id.into(),
            enrichment,
        }
    }

    /// Decode every position-bearing target record in one data block. A block for
    /// another category, or a record without a position, contributes no target.
    pub fn parse_block(&self, frame: &[u8]) -> Result<Vec<AsterixTarget>, AsterixError> {
        if frame.len() < 3 {
            return Err(AsterixError::BadBlock);
        }
        let cat = frame[0];
        let len = u16::from_be_bytes([frame[1], frame[2]]) as usize;
        if len < 3 || len > frame.len() {
            return Err(AsterixError::BadBlock);
        }
        // A block for a category we do not handle is not an error, just not ours.
        if cat != CAT021 {
            return Ok(Vec::new());
        }

        let mut targets = Vec::new();
        let mut off = 3;
        while off < len {
            let (target, next) = self.parse_record(&frame[..len], off)?;
            if let Some(mut t) = target {
                // Preserve this record's raw bytes for the signed payload.
                t.raw = frame[off..next.min(len)].to_vec();
                targets.push(t);
            }
            if next <= off {
                // No forward progress would loop forever; treat as malformed.
                return Err(AsterixError::BadBlock);
            }
            off = next;
        }
        Ok(targets)
    }

    /// Parse one record starting at `off`, returning the target (if it had a
    /// position) and the offset of the next record.
    fn parse_record(
        &self,
        data: &[u8],
        mut off: usize,
    ) -> Result<(Option<AsterixTarget>, usize), AsterixError> {
        // FSPEC: octets, MSB = FRN1; the low bit (FX) continues the bitmap.
        let mut present = Vec::new();
        let mut frn = 1;
        loop {
            let octet = *data.get(off).ok_or(AsterixError::Truncated)?;
            off += 1;
            for bit in 0..7 {
                if octet & (0x80 >> bit) != 0 {
                    present.push(frn);
                }
                frn += 1;
            }
            if octet & 0x01 == 0 {
                break;
            }
        }

        let mut sac = 0u8;
        let mut sic = 0u8;
        let mut track = None;
        let mut icao = None;
        let mut pos: Option<(f64, f64)> = None;
        let mut alt_ft = None;
        let mut ground_speed = None;
        let mut track_angle = None;
        let mut squawk = None;
        let mut callsign = None;
        let mut emitter = None;

        for &frn in &present {
            let kind = UAP
                .get(frn as usize - 1)
                .ok_or(AsterixError::UnsupportedItem(frn))?;
            let len = match field_len(*kind, data, off) {
                Some(len) => len,
                None => match kind {
                    Field::Compound => return Err(AsterixError::UnsupportedItem(frn)),
                    _ => return Err(AsterixError::Truncated),
                },
            };
            let end = off.checked_add(len).ok_or(AsterixError::Truncated)?;
            let item = data.get(off..end).ok_or(AsterixError::Truncated)?;

            match frn {
                1 => {
                    sac = item[0];
                    sic = item[1];
                }
                3 => track = Some(u16::from_be_bytes([item[0], item[1]])),
                6 => pos = Some((signed(item, 0, 3) * LSB_130, signed(item, 3, 3) * LSB_130)),
                // High-resolution position overrides the coarse one if both present.
                7 => pos = Some((signed(item, 0, 4) * LSB_131, signed(item, 4, 4) * LSB_131)),
                11 => icao = Some((item[0] as u32) << 16 | (item[1] as u32) << 8 | item[2] as u32),
                // I021/140 Geometric Height: signed, LSB 6.25 ft (WGS-84).
                16 => alt_ft = Some(i16::from_be_bytes([item[0], item[1]]) as f64 * 6.25),
                // I021/070 Mode 3/A Code: low 12 bits are the octal squawk.
                19 => squawk = Some(mode_3a(u16::from_be_bytes([item[0], item[1]]))),
                // I021/145 Flight Level: signed, LSB 1/4 FL (25 ft). Fallback altitude.
                21 => {
                    alt_ft.get_or_insert(i16::from_be_bytes([item[0], item[1]]) as f64 * 25.0);
                }
                // I021/160 Airborne Ground Vector: ground speed + track angle.
                26 => {
                    let gs = u16::from_be_bytes([item[0], item[1]]);
                    let ta = u16::from_be_bytes([item[2], item[3]]);
                    // LSB: 2^-14 NM/s -> knots (x3600); 360/2^16 degrees.
                    ground_speed = Some(gs as f64 * 2f64.powi(-14) * 3600.0);
                    track_angle = Some(ta as f64 * 360.0 / 65536.0);
                }
                // I021/170 Target Identification: 8-character ICAO callsign.
                29 => callsign = target_id(item),
                // I021/020 Emitter Category.
                30 => emitter = emitter_category(item[0]),
                _ => {}
            }
            off = end;
        }

        let target = pos.map(|(lat, lon)| AsterixTarget {
            sac,
            sic,
            track,
            icao,
            lat,
            lon,
            alt_ft,
            ground_speed,
            track_angle,
            squawk,
            callsign,
            emitter,
            raw: Vec::new(), // filled by parse_block, which knows the record extent
        });
        Ok((target, off))
    }

    fn to_event_with(
        &self,
        t: &AsterixTarget,
        stamp: impl FnOnce(EventBuilder) -> EventBuilder,
    ) -> Result<Event, AsterixError> {
        // The native target identity (ICAO address, or SAC/SIC + track number).
        let track = match (t.icao, t.track) {
            (Some(icao), _) => format!("icao:{icao:06X}"),
            (None, Some(track)) => format!("asterix:{}:{}:{}", t.sac, t.sic, track),
            (None, None) => format!("asterix:{}:{}", t.sac, t.sic),
        };
        // Core requires the event id to be a fresh UUIDv7. The native identity is
        // an identifier -> metadata; the raw record rides verbatim in the payload;
        // decoded fields ride as attributes (Core demotes undeclared keys).
        // Altitude is the structured location field, in metres.
        let altitude_m = t.alt_ft.map(|ft| ft * 0.3048).unwrap_or(0.0);
        let mut b = EventBuilder::new(self.source_id.clone(), "mim:aircraft")
            .new_id()
            .location(t.lat, t.lon, altitude_m)
            .payload(t.raw.clone())
            .metadata("track", track);
        if let Some(ft) = t.alt_ft {
            b = b.metadata("altitude_ft", format!("{ft:.0}")); // native feet (GeoPoint is metres)
        }
        // Operator-asserted affiliation only — never a connector-invented default.
        if let Some(aff) = self.enrichment.affiliation.as_deref() {
            b = b.attribute("affiliation", aff);
        }
        if let Some(gs) = t.ground_speed {
            // Governed `speed` is m/s; keep the native knots in metadata (ADR-0019).
            b = b.attribute("speed", format!("{:.2}", gs * KNOTS_TO_MPS));
            b = b.metadata("speed_kn", format!("{gs:.1}"));
        }
        if let Some(ta) = t.track_angle {
            b = b.attribute("course", format!("{ta:.1}")); // degrees
        }
        if let Some(sq) = &t.squawk {
            b = b.attribute("squawk", sq.clone());
        }
        if let Some(cs) = &t.callsign {
            b = b.attribute("callsign", cs.clone());
        }
        if let Some(cat) = t.emitter {
            b = b.attribute("aircraft_type", cat);
        }
        stamp(b)
            .build()
            .map_err(|e| AsterixError::Build(e.to_string()))
    }

    /// Build with an explicit observation timestamp (tests pin this path).
    pub fn to_event_at(&self, t: &AsterixTarget, observed: &str) -> Result<Event, AsterixError> {
        self.to_event_with(t, |b| b.timestamp(observed))
    }

    fn to_event_now(&self, t: &AsterixTarget) -> Result<Event, AsterixError> {
        self.to_event_with(t, |b| b.now())
    }
}

impl FrameParser for AsterixParser {
    fn parse(&self, frame: &[u8]) -> Result<Vec<Event>, ParseError> {
        let targets = self.parse_block(frame).map_err(box_err)?;
        let mut events = Vec::with_capacity(targets.len());
        for t in &targets {
            events.push(self.to_event_now(t).map_err(box_err)?);
        }
        Ok(events)
    }
}

fn box_err(e: AsterixError) -> ParseError {
    Box::new(e) as ParseError
}

/// Length in octets of the item at `off`, or `None` if it runs past the buffer or
/// is a compound item we do not model.
fn field_len(kind: Field, data: &[u8], off: usize) -> Option<usize> {
    match kind {
        Field::Fixed(n) => (off + n <= data.len()).then_some(n),
        Field::Extended => {
            let mut n = 0;
            loop {
                let octet = *data.get(off + n)?;
                n += 1;
                if octet & 0x01 == 0 {
                    return Some(n);
                }
            }
        }
        Field::Repetitive(item) => {
            let rep = *data.get(off)? as usize;
            let total = 1 + rep * item;
            (off + total <= data.len()).then_some(total)
        }
        Field::LenPrefixed => {
            let total = *data.get(off)? as usize;
            (total >= 1 && off + total <= data.len()).then_some(total)
        }
        Field::Compound => None,
    }
}

/// Read `n` big-endian octets at `item[start..]` as a two's-complement signed int.
fn signed(item: &[u8], start: usize, n: usize) -> f64 {
    let mut v: i64 = 0;
    for i in 0..n {
        v = (v << 8) | item[start + i] as i64;
    }
    let bits = n * 8;
    if v & (1 << (bits - 1)) != 0 {
        v -= 1 << bits;
    }
    v as f64
}

/// The Mode 3/A code (low 12 bits) as four octal digits, e.g. `7700`.
fn mode_3a(field: u16) -> String {
    let c = field & 0x0FFF;
    format!("{}{}{}{}", (c >> 9) & 7, (c >> 6) & 7, (c >> 3) & 7, c & 7)
}

/// Decode I021/170 Target Identification: eight 6-bit ICAO characters (1–26 = A–Z,
/// 48–57 = 0–9, 32 = space) packed into 6 octets. Trailing spaces trimmed.
fn target_id(item: &[u8]) -> Option<String> {
    if item.len() < 6 {
        return None;
    }
    let mut bits: u64 = 0;
    for &b in &item[..6] {
        bits = (bits << 8) | b as u64;
    }
    let mut s = String::with_capacity(8);
    for i in 0..8 {
        let v = ((bits >> (42 - i * 6)) & 0x3F) as u8;
        let c = match v {
            1..=26 => (b'A' + v - 1) as char,
            48..=57 => (b'0' + v - 48) as char,
            32 => ' ',
            _ => continue,
        };
        s.push(c);
    }
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// I021/020 Emitter Category → operational category.
fn emitter_category(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "light",
        2 => "small",
        3 => "medium",
        4 => "high-vortex-large",
        5 => "heavy",
        6 => "highly-manoeuvrable",
        10 => "rotorcraft",
        11 => "glider",
        12 => "lighter-than-air",
        13 => "uav",
        14 => "space",
        15 => "ultralight",
        16 => "parachutist",
        20 => "emergency-vehicle",
        21 => "service-vehicle",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth CAT021 blocks. Single record: SAC 25 SIC 10, track 1234,
    // 47.397745 N, 8.545604 E. Two-record adds track 5678 at Cape Town.
    const ONE: &str = "150013fc190a0004d20100000021b47f0613ae";
    const TWO: &str = "150023fc190a0004d20100000021b47f0613aefc190a00162e01000000e7e0290d1a01";
    // Rich record: SAC 25 SIC 10, position, geometric height 10000 ft, squawk 7700,
    // ground speed 480.1 kn, track 90 deg, callsign TEST1234, emitter UAV.
    const RICH: &str = "15001f85014909c0190a21b47f0613ae06400fc0088940005054d4c72cf40d";

    fn parser() -> AsterixParser {
        AsterixParser::new("radar-adsb-1", Enrichment::default())
    }

    fn governed() -> AsterixParser {
        AsterixParser::new(
            "radar-adsb-1",
            Enrichment::default().with_affiliation("neutral"),
        )
    }

    #[test]
    fn decodes_a_single_target() {
        let t = &parser().parse_block(&hex::decode(ONE).unwrap()).unwrap()[0];
        assert_eq!((t.sac, t.sic), (25, 10));
        assert_eq!(t.track, Some(1234));
        assert!((t.lat - 47.397745).abs() < 1e-5);
        assert!((t.lon - 8.545604).abs() < 1e-5);
    }

    #[test]
    fn decodes_tactical_items_a_cop_needs() {
        let t = &governed().parse_block(&hex::decode(RICH).unwrap()).unwrap()[0];
        assert!((t.alt_ft.unwrap() - 10000.0).abs() < 1e-6);
        assert_eq!(t.squawk.as_deref(), Some("7700"));
        assert!((t.ground_speed.unwrap() - 480.1).abs() < 0.2);
        assert!((t.track_angle.unwrap() - 90.0).abs() < 0.1);
        assert_eq!(t.callsign.as_deref(), Some("TEST1234"));
        assert_eq!(t.emitter, Some("uav"));

        // In governed mode the tactical items ride as governed attributes, and
        // altitude is in the structured location (feet -> metres).
        let ev = governed().to_event_at(t, "2026-06-10T08:00:00Z").unwrap();
        let attr = |k: &str| {
            ev.attributes
                .iter()
                .find(|a| a.key == k)
                .map(|a| a.value.as_str())
        };
        assert_eq!(attr("squawk"), Some("7700"));
        assert_eq!(attr("callsign"), Some("TEST1234"));
        assert_eq!(attr("aircraft_type"), Some("uav"));
        assert_eq!(attr("affiliation"), Some("neutral"));
        assert!((ev.location.unwrap().altitude_m - 3048.0).abs() < 0.1);
    }

    #[test]
    fn decodes_every_record_in_a_block() {
        let ts = parser().parse_block(&hex::decode(TWO).unwrap()).unwrap();
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[0].track, Some(1234));
        assert_eq!(ts[1].track, Some(5678));
        assert!((ts[1].lat - -33.924901).abs() < 1e-5);
        assert!((ts[1].lon - 18.424094).abs() < 1e-5);
    }

    #[test]
    fn other_category_is_ignored_not_errored() {
        // CAT062 block: a category we do not handle.
        let cat062 = hex::decode("3e0004ff").unwrap();
        assert_eq!(parser().parse_block(&cat062).unwrap(), Vec::new());
    }

    #[test]
    fn block_longer_than_buffer_is_rejected() {
        // Claims length 0x13 but only a few bytes present.
        let bad = hex::decode("150013fc19").unwrap();
        assert_eq!(parser().parse_block(&bad), Err(AsterixError::BadBlock));
    }

    #[test]
    fn record_item_past_block_end_is_truncated() {
        // Well-formed block length, but the FSPEC promises I021/130 (6 bytes) with
        // only a couple present — the item runs past the block end.
        let bad = hex::decode("150008fc190a0000").unwrap();
        assert_eq!(parser().parse_block(&bad), Err(AsterixError::Truncated));
    }

    #[test]
    fn garbage_never_panics() {
        assert!(parser().parse_block(b"\x15\x00").is_err());
        assert!(parser().parse_block(&[]).is_err());
        assert!(
            parser().parse_block(b"\xff\xff\xff\xff\xff").is_ok()
                || parser().parse_block(b"\xff\xff\xff\xff\xff").is_err()
        );
    }
}
