// SPDX-License-Identifier: Apache-2.0
//! CAT034 monoradar service messages, Edition 1.27: north markers, sector
//! crossings, system status and jamming strobes from the radar itself.

use super::field::{walk_compound, Field, Item};
use super::wire::{signed, time_of_day_s};
use super::ANGLE_16;

#[rustfmt::skip]
pub(super) const UAP: &[(Item, Field)] = &[
    (Item(10), Field::Fixed(2)),           // 1  Data Source Identifier
    (Item(0), Field::Fixed(1)),            // 2  Message Type
    (Item(30), Field::Fixed(3)),           // 3  Time of Day
    (Item(20), Field::Fixed(1)),           // 4  Sector Number
    (Item(41), Field::Fixed(2)),           // 5  Antenna Rotation Speed
    (Item(50), Field::Compound(&SUB_050)), // 6  System Configuration and Status
    (Item(60), Field::Compound(&SUB_060)), // 7  System Processing Mode
    (Item(70), Field::Repetitive(2)),      // 8  Message Count Values
    (Item(100), Field::Fixed(8)),          // 9  Generic Polar Window
    (Item(110), Field::Fixed(1)),          // 10 Data Filter
    (Item(120), Field::Fixed(8)),          // 11 3D-Position of Data Source
    (Item(90), Field::Fixed(2)),           // 12 Collimation Error
    (Item::RE, Field::Explicit),           // 13 Reserved Expansion
    (Item::SP, Field::Explicit),           // 14 Special Purpose
];
/// I034/050 subfields COM, spare, spare, PSR, SSR, MDS, spare.
#[rustfmt::skip]
const SUB_050: [Field; 7] = [
    Field::Fixed(1), Field::Spare, Field::Spare,
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(2), Field::Spare,
];
/// I034/060 subfields COM, spare, spare, PSR, SSR, MDS, spare.
#[rustfmt::skip]
const SUB_060: [Field; 7] = [
    Field::Fixed(1), Field::Spare, Field::Spare,
    Field::Fixed(1), Field::Fixed(1), Field::Fixed(1), Field::Spare,
];
/// I034/120 latitude and longitude LSB, degrees.
pub(super) const LSB_120: f64 = 180.0 / (1u64 << 23) as f64;

// I034/000 message types.
pub(super) const NORTH_MARKER: u8 = 1;
pub(super) const SECTOR_CROSSING: u8 = 2;
pub(super) const JAMMING_STROBE: u8 = 4;
pub(super) const SSR_JAMMING_STROBE: u8 = 6;
pub(super) const MODE_S_JAMMING_STROBE: u8 = 7;

/// A radar's self-reported health from I034/050. A field is `None` until the
/// radar has reported it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RadarStatus {
    /// The radar declares itself not operational.
    pub nogo: Option<bool>,
    /// Radar data processor overload.
    pub rdp_overload: Option<bool>,
    /// Transmission subsystem overload.
    pub xmt_overload: Option<bool>,
    pub monitoring_disconnected: Option<bool>,
    pub time_source_invalid: Option<bool>,
    pub psr_overload: Option<bool>,
    pub ssr_overload: Option<bool>,
    /// Mode S surveillance overload.
    pub mds_overload: Option<bool>,
}

impl RadarStatus {
    /// Overwrites each field `other` reports.
    pub(super) fn merge(&mut self, other: RadarStatus) {
        macro_rules! take {
            ($($f:ident),*) => { $( if other.$f.is_some() { self.$f = other.$f; } )* };
        }
        take!(
            nogo,
            rdp_overload,
            xmt_overload,
            monitoring_disconnected,
            time_source_invalid,
            psr_overload,
            ssr_overload,
            mds_overload
        );
    }

    /// NOGO or any overload reported.
    pub(super) fn degraded(&self) -> bool {
        [
            self.nogo,
            self.rdp_overload,
            self.xmt_overload,
            self.psr_overload,
            self.ssr_overload,
            self.mds_overload,
        ]
        .contains(&Some(true))
    }
}

/// One decoded CAT034 record.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServiceReport {
    pub sac: u8,
    pub sic: u8,
    /// I034/000.
    pub message_type: u8,
    /// Seconds since UTC midnight.
    pub time_of_day_s: Option<f64>,
    /// I034/020, 360/256 degrees per sector.
    pub sector: Option<u8>,
    /// I034/041 antenna rotation period.
    pub rotation_period_s: Option<f64>,
    /// I034/120 latitude, longitude and height (m) of the radar.
    pub position: Option<(f64, f64, f64)>,
    /// The parser's merged status for this radar, after this record.
    pub status: RadarStatus,
    /// I034/100 range start and end (NM), azimuth start and end (deg).
    pub window: Option<(f64, f64, f64, f64)>,
    /// The record's bytes, sealed into the payload.
    pub raw: Vec<u8>,
}

impl ServiceReport {
    /// A north marker (the once-per-rotation heartbeat) or a jamming strobe.
    pub(super) fn is_published(&self) -> bool {
        matches!(
            self.message_type,
            NORTH_MARKER | JAMMING_STROBE | SSR_JAMMING_STROBE | MODE_S_JAMMING_STROBE
        )
    }

    pub(super) fn message_name(&self) -> &'static str {
        match self.message_type {
            NORTH_MARKER => "north-marker",
            SECTOR_CROSSING => "sector-crossing",
            3 => "geographical-filtering",
            JAMMING_STROBE => "jamming-strobe",
            5 => "solar-storm",
            SSR_JAMMING_STROBE => "ssr-jamming-strobe",
            MODE_S_JAMMING_STROBE => "mode-s-jamming-strobe",
            _ => "unknown",
        }
    }
}

pub(super) fn decode(items: &[(Item, &[u8])]) -> ServiceReport {
    let mut r = ServiceReport::default();
    for &(id, item) in items {
        match id {
            Item(10) => (r.sac, r.sic) = (item[0], item[1]),
            Item(0) => r.message_type = item[0],
            Item(30) => r.time_of_day_s = Some(time_of_day_s(item)),
            Item(20) => r.sector = Some(item[0]),
            Item(41) => {
                r.rotation_period_s = Some(u16::from_be_bytes([item[0], item[1]]) as f64 / 128.0)
            }
            Item(50) => {
                for (sub, bytes) in walk_compound(&SUB_050, item) {
                    match sub {
                        0 => {
                            let com = bytes[0];
                            r.status.nogo = Some(com & 0x80 != 0);
                            r.status.rdp_overload = Some(com & 0x10 != 0);
                            r.status.xmt_overload = Some(com & 0x08 != 0);
                            r.status.monitoring_disconnected = Some(com & 0x04 != 0);
                            r.status.time_source_invalid = Some(com & 0x02 != 0);
                        }
                        3 => r.status.psr_overload = Some(bytes[0] & 0x10 != 0),
                        4 => r.status.ssr_overload = Some(bytes[0] & 0x10 != 0),
                        5 => r.status.mds_overload = Some(bytes[0] & 0x10 != 0),
                        _ => {}
                    }
                }
            }
            Item(100) => {
                let rho_start = u16::from_be_bytes([item[0], item[1]]) as f64 / 256.0;
                let rho_end = u16::from_be_bytes([item[2], item[3]]) as f64 / 256.0;
                let theta_start = u16::from_be_bytes([item[4], item[5]]) as f64 * ANGLE_16;
                let theta_end = u16::from_be_bytes([item[6], item[7]]) as f64 * ANGLE_16;
                r.window = Some((rho_start, rho_end, theta_start, theta_end));
            }
            Item(120) => {
                let height_m = signed(item, 0, 2);
                let lat = signed(item, 2, 3) * LSB_120;
                let lon = signed(item, 5, 3) * LSB_120;
                r.position = Some((lat, lon, height_m));
            }
            _ => {}
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asterix::testutil::{
        attr, block, cat034_north_marker, cat034_sector_crossing, fspec, meta, parser, u16b,
        OBSERVED,
    };
    use std::sync::atomic::Ordering;

    /// A `message_type` record with `items`: `before_window`
    /// holds those between I034/000 and I034/100, and the window is 10-20 NM,
    /// 045-090 deg.
    fn with_window(items: &[Item], message_type: u8, before_window: &[u8]) -> Vec<u8> {
        let mut r = fspec(UAP, items);
        r.extend_from_slice(&[25, 10]);
        r.push(message_type);
        r.extend_from_slice(before_window);
        r.extend_from_slice(&u16b(2560));
        r.extend_from_slice(&u16b(5120));
        r.extend_from_slice(&u16b(8192));
        r.extend_from_slice(&u16b(16384));
        r
    }

    #[test]
    fn status_carries_over_to_next_heartbeat() {
        let p = parser();
        // NOGO and RDP overload.
        let r = p
            .parse_service_block(&block(34, &cat034_sector_crossing(0x90)))
            .unwrap();
        assert_eq!(r.len(), 1);
        assert!(!r[0].is_published());
        assert_eq!(r[0].status.nogo, Some(true));
        assert_eq!(r[0].status.rdp_overload, Some(true));
        assert_eq!(r[0].status.xmt_overload, Some(false));
        assert_eq!(r[0].sector, Some(96));

        let mut r = p
            .parse_service_block(&block(34, &cat034_north_marker()))
            .unwrap();
        let nm = r.remove(0);
        assert!(nm.is_published());
        assert_eq!(nm.rotation_period_s, Some(4.0));
        assert_eq!(nm.status.nogo, Some(true), "remembered from the crossing");
        let (lat, lon, h) = nm.position.unwrap();
        assert!((lat - 60.0).abs() < 1e-4 && (lon - 25.0).abs() < 1e-4 && h == 50.0);

        let ev = p.service_event_at(nm, OBSERVED).unwrap();
        assert_eq!(ev.entity_type, "mim:sensor");
        assert_eq!(meta(&ev, "source_uid"), Some("asterix:radar:25:10"));
        assert_eq!(meta(&ev, "message_type"), Some("north-marker"));
        assert_eq!(meta(&ev, "rotation_period_s"), Some("4.000"));
        assert_eq!(attr(&ev, "scan_period_s"), Some("4.000"));
        assert_eq!(attr(&ev, "update_interval_s"), Some("4.000"));
        assert_eq!(meta(&ev, "nogo"), Some("true"));
        assert_eq!(meta(&ev, "rdp_overload"), Some("true"));
        assert_eq!(
            meta(&ev, "psr_overload"),
            None,
            "never claimed, never stated"
        );
        let loc = ev.location.as_ref().unwrap();
        assert!((loc.latitude - 60.0).abs() < 1e-4);
        assert_eq!(
            ev.payload,
            cat034_north_marker(),
            "the raw record is sealed verbatim"
        );
        assert_eq!(p.north_markers.load(Ordering::Relaxed), 1);
        assert_eq!(p.sector_crossings.load(Ordering::Relaxed), 1);
        assert_eq!(p.radar_degraded.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cleared_nogo_stops_degraded_count() {
        let p = parser();
        let service = |record: Vec<u8>| p.parse_service_block(&block(34, &record)).unwrap();
        service(cat034_sector_crossing(0x90));
        service(cat034_north_marker());
        service(cat034_sector_crossing(0x00));
        let r = service(cat034_north_marker());
        assert_eq!(r[0].status.nogo, Some(false));
        assert_eq!(p.radar_degraded.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn north_marker_window_is_coverage() {
        // I034/030 time of day and I034/041 rotation speed precede the window.
        let mut before = 300u32.to_be_bytes()[1..].to_vec();
        before.extend_from_slice(&u16b(512));
        let r = with_window(
            &[Item(10), Item(0), Item(30), Item(41), Item(100)],
            NORTH_MARKER,
            &before,
        );
        let p = parser();
        let rep = p.parse_service_block(&block(34, &r)).unwrap().remove(0);
        let ev = p.service_event_at(rep, OBSERVED).unwrap();
        assert_eq!(attr(&ev, "coverage_bearing_start_deg"), Some("45.000"));
        assert_eq!(attr(&ev, "coverage_bearing_end_deg"), Some("90.000"));
        assert_eq!(attr(&ev, "detection_range_m"), Some("37040"));
        assert_eq!(attr(&ev, "update_interval_s"), Some("4.000"));
        assert_eq!(meta(&ev, "window_range_end_nm"), Some("20.000"));
    }

    #[test]
    fn jamming_strobe_window_stays_metadata() {
        let r = with_window(&[Item(10), Item(0), Item(100)], JAMMING_STROBE, &[]);
        let p = parser();
        let rep = p.parse_service_block(&block(34, &r)).unwrap().remove(0);
        assert!(rep.is_published());
        let ev = p.service_event_at(rep, OBSERVED).unwrap();
        assert_eq!(meta(&ev, "message_type"), Some("jamming-strobe"));
        assert_eq!(meta(&ev, "window_range_start_nm"), Some("10.000"));
        assert_eq!(meta(&ev, "window_range_end_nm"), Some("20.000"));
        assert_eq!(meta(&ev, "window_azimuth_start_deg"), Some("45.000"));
        assert_eq!(meta(&ev, "window_azimuth_end_deg"), Some("90.000"));
        for key in [
            "coverage_bearing_start_deg",
            "coverage_bearing_end_deg",
            "detection_range_m",
            "update_interval_s",
        ] {
            assert_eq!(attr(&ev, key), None, "a jammed sector is not coverage");
        }
        assert_eq!(p.jamming_strobes.load(Ordering::Relaxed), 1);
    }
}
