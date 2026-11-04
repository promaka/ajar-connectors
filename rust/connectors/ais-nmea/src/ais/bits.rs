// SPDX-License-Identifier: Apache-2.0
//! The 6-bit armored AIS payload, read by absolute bit position, MSB first.

use super::AisError;

/// The AIS 6-bit character set, used for names and call signs.
const SIXBIT_ASCII: &[u8; 64] =
    b"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?";

pub(super) struct Bits {
    six: Vec<u8>,
    pub(super) valid_bits: usize,
}

impl Bits {
    pub(super) fn from_payload(payload: &str, fill: u8) -> Result<Bits, AisError> {
        let mut six = Vec::with_capacity(payload.len());
        for c in payload.bytes() {
            let mut v = c as i16 - 48;
            if v > 40 {
                v -= 8;
            }
            if !(0..=63).contains(&v) {
                return Err(AisError::Armor(c));
            }
            six.push(v as u8);
        }
        let valid_bits = (six.len() * 6).saturating_sub(fill as usize);
        Ok(Bits { six, valid_bits })
    }

    pub(super) fn u(&self, start: usize, n: usize) -> u64 {
        let mut val = 0u64;
        for i in 0..n {
            let bit = start + i;
            let b = (self.six[bit / 6] >> (5 - (bit % 6))) & 1;
            val = (val << 1) | b as u64;
        }
        val
    }

    /// `None` if the `n` bits run past the valid payload.
    pub(super) fn opt_u(&self, start: usize, n: usize) -> Option<u64> {
        (start + n <= self.valid_bits).then(|| self.u(start, n))
    }

    /// Two's complement; `None` if the `n` bits run past the valid payload.
    pub(super) fn opt_i(&self, start: usize, n: usize) -> Option<i64> {
        let u = self.opt_u(start, n)?;
        Some(if u & (1 << (n - 1)) != 0 {
            u as i64 - (1i64 << n)
        } else {
            u as i64
        })
    }

    /// A 6-bit text field trimmed of `@` padding and whitespace; `None` if it
    /// runs past the payload or is empty.
    pub(super) fn opt_text(&self, start: usize, bits: usize) -> Option<String> {
        if start + bits > self.valid_bits {
            return None;
        }
        let mut s = String::with_capacity(bits / 6);
        for i in 0..(bits / 6) {
            let v = self.u(start + i * 6, 6) as usize;
            s.push(SIXBIT_ASCII[v] as char);
        }
        let s = s.trim_end_matches('@').trim().to_string();
        (!s.is_empty()).then_some(s)
    }
}
