// SPDX-License-Identifier: Apache-2.0
//! Record builders, fixtures and event accessors shared by the decoder tests.

use ajar_connector::Event;
use ajar_connector_common::Enrichment;

use super::field::{Field, Item};
use super::{cat010, cat034, cat048, cat062, AsterixParser, Sensor};

pub(super) const OBSERVED: &str = "2026-06-10T08:00:00Z";
pub(super) const SITE: Sensor = Sensor {
    lat: 60.0,
    lon: 25.0,
    alt_m: 0.0,
};

pub(super) fn parser() -> AsterixParser {
    AsterixParser::new("radar-1", Enrichment::default())
}

pub(super) fn attr<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
    ev.attributes
        .iter()
        .find(|a| a.key == k)
        .map(|a| a.value.as_str())
}

pub(super) fn meta<'a>(ev: &'a Event, k: &str) -> Option<&'a str> {
    ev.metadata
        .iter()
        .find(|m| m.key == k)
        .map(|m| m.value.as_str())
}

/// The FSPEC naming `items` of `uap`, with FX set on every octet but the last.
pub(super) fn fspec(uap: &[(Item, Field)], items: &[Item]) -> Vec<u8> {
    let frns: Vec<usize> = items
        .iter()
        .map(|item| {
            1 + uap
                .iter()
                .position(|(i, _)| i == item)
                .expect("item in the UAP")
        })
        .collect();
    let max = frns.iter().copied().max().unwrap_or(1);
    let octets = max.div_ceil(7).max(1);
    let mut f = vec![0u8; octets];
    for n in frns {
        f[(n - 1) / 7] |= 0x80 >> ((n - 1) % 7);
    }
    for byte in f.iter_mut().take(octets - 1) {
        *byte |= 0x01;
    }
    f
}

pub(super) fn block(cat: u8, record: &[u8]) -> Vec<u8> {
    let len = 3 + record.len();
    let mut b = vec![cat, (len >> 8) as u8, (len & 0xff) as u8];
    b.extend_from_slice(record);
    b
}

pub(super) fn u16b(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// `s` as eight ICAO 6-bit characters, space padded.
pub(super) fn enc_id(s: &str) -> [u8; 6] {
    let mut v = 0u64;
    for k in 0..8 {
        let c = s.as_bytes().get(k).copied().unwrap_or(b' ');
        let six = match c {
            b'A'..=b'Z' => c - b'A' + 1,
            b'0'..=b'9' => c - b'0' + 48,
            _ => 32,
        } as u64;
        v |= six << (42 - 6 * k);
    }
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (v >> (40 - 8 * i)) as u8;
    }
    out
}

/// 100 NM at 045, squawk 1234, FL350, ICAO 4CA2D6, track 1234, 450 kn on 090,
/// with a one-subfield I048/130 between them.
pub(super) fn cat048_record() -> Vec<u8> {
    let mut r = fspec(
        cat048::UAP,
        &[
            Item(10),
            Item(40),
            Item(70),
            Item(90),
            Item(130),
            Item(220),
            Item(161),
            Item(200),
        ],
    );
    r.extend_from_slice(&[25, 10]);
    r.extend_from_slice(&u16b(25600));
    r.extend_from_slice(&u16b(8192));
    r.extend_from_slice(&u16b(0o1234));
    r.extend_from_slice(&u16b(1400));
    r.extend_from_slice(&[0x80, 0xAB]);
    r.extend_from_slice(&[0x4C, 0xA2, 0xD6]);
    r.extend_from_slice(&u16b(1234));
    r.extend_from_slice(&u16b(2048));
    r.extend_from_slice(&u16b(16384));
    r
}

/// 60N 25E, 100 m/s east, squawk 7000, ICAO 406201 "BAW123" in I062/380,
/// track 4095, FL350, climbing 1000 ft/min.
pub(super) fn cat062_record() -> Vec<u8> {
    let lat = (60.0 / cat062::LSB_105) as i32;
    let lon = (25.0 / cat062::LSB_105) as i32;
    let mut r = fspec(
        cat062::UAP,
        &[
            Item(10),
            Item(70),
            Item(105),
            Item(185),
            Item(60),
            Item(380),
            Item(40),
            Item(136),
            Item(220),
        ],
    );
    r.extend_from_slice(&[25, 10]);
    r.extend_from_slice(&300u32.to_be_bytes()[1..]);
    r.extend_from_slice(&lat.to_be_bytes());
    r.extend_from_slice(&lon.to_be_bytes());
    r.extend_from_slice(&400i16.to_be_bytes());
    r.extend_from_slice(&0i16.to_be_bytes());
    r.extend_from_slice(&u16b(0o7000));
    // I062/380 with ADR and ID present.
    r.push(0xC0);
    r.extend_from_slice(&[0x40, 0x62, 0x01]);
    r.extend_from_slice(&enc_id("BAW123"));
    r.extend_from_slice(&u16b(4095));
    r.extend_from_slice(&1400i16.to_be_bytes());
    r.extend_from_slice(&160i16.to_be_bytes());
    r
}

/// A target report at 60N 25E, 450 kn on 090, track 77, position sigma 2 m
/// and 3 m.
pub(super) fn cat010_record() -> Vec<u8> {
    let lat = (60.0 / cat010::LSB_041) as i32;
    let lon = (25.0 / cat010::LSB_041) as i32;
    let mut r = fspec(
        cat010::UAP,
        &[
            Item(10),
            Item(0),
            Item(140),
            Item(41),
            Item(200),
            Item(161),
            Item(500),
        ],
    );
    r.extend_from_slice(&[25, 10]);
    r.push(cat010::TARGET_REPORT);
    r.extend_from_slice(&300u32.to_be_bytes()[1..]);
    r.extend_from_slice(&lat.to_be_bytes());
    r.extend_from_slice(&lon.to_be_bytes());
    r.extend_from_slice(&u16b(2048));
    r.extend_from_slice(&u16b(16384));
    r.extend_from_slice(&u16b(77));
    r.extend_from_slice(&[8, 12, 0, 0]);
    r
}

/// A north marker from 25/10: 4 s rotation, radar at 60N 25E and 50 m.
pub(super) fn cat034_north_marker() -> Vec<u8> {
    let lat = (60.0 / cat034::LSB_120) as i64;
    let lon = (25.0 / cat034::LSB_120) as i64;
    let mut r = fspec(
        cat034::UAP,
        &[Item(10), Item(0), Item(30), Item(41), Item(120)],
    );
    r.extend_from_slice(&[25, 10]);
    r.push(cat034::NORTH_MARKER);
    r.extend_from_slice(&300u32.to_be_bytes()[1..]);
    r.extend_from_slice(&u16b(512));
    r.extend_from_slice(&50i16.to_be_bytes());
    r.extend_from_slice(&lat.to_be_bytes()[5..]);
    r.extend_from_slice(&lon.to_be_bytes()[5..]);
    r
}

/// A crossing into sector 96 with `com` as the I034/050 COM subfield.
pub(super) fn cat034_sector_crossing(com: u8) -> Vec<u8> {
    let mut r = fspec(cat034::UAP, &[Item(10), Item(0), Item(20), Item(50)]);
    r.extend_from_slice(&[25, 10]);
    r.push(cat034::SECTOR_CROSSING);
    r.push(96);
    r.extend_from_slice(&[0x80, com]);
    r
}
