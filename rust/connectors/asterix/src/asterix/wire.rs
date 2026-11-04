// SPDX-License-Identifier: Apache-2.0
//! Value decoders shared by the categories.

/// A big-endian unsigned integer from `data[start..start + n]`, `n <= 8`.
pub(super) fn be_uint(data: &[u8], start: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        v = (v << 8) | data[start + i] as u64;
    }
    v
}

/// A big-endian two's-complement integer from `data[start..start + n]`.
pub(super) fn signed(data: &[u8], start: usize, n: usize) -> f64 {
    sign_extend(be_uint(data, start, n), (n * 8) as u32) as f64
}

/// The low `bits` of `v` as a signed integer.
pub(super) fn sign_extend(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

/// A three-octet time of day, LSB 1/128 s, in seconds since UTC midnight.
pub(super) fn time_of_day_s(item: &[u8]) -> f64 {
    be_uint(item, 0, 3) as f64 / 128.0
}

/// The Mode 3/A code in the low 12 bits, as four octal digits.
pub(super) fn mode_3a(v: u16) -> String {
    let code = v & 0x0FFF;
    format!(
        "{:o}{:o}{:o}{:o}",
        (code >> 9) & 7,
        (code >> 6) & 7,
        (code >> 3) & 7,
        code & 7
    )
}

/// Eight ICAO 6-bit characters from six octets, trailing padding trimmed.
pub(super) fn aircraft_id(item: &[u8]) -> Option<String> {
    if item.len() < 6 {
        return None;
    }
    let v = be_uint(item, 0, 6);
    let mut s = String::with_capacity(8);
    for k in 0..8 {
        let c = ((v >> (42 - 6 * k)) & 0x3F) as u8;
        s.push(match c {
            1..=26 => (b'A' + c - 1) as char,
            48..=57 => (b'0' + c - 48) as char,
            _ => ' ',
        });
    }
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}
