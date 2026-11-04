// SPDX-License-Identifier: Apache-2.0
//! The category-generic length engine: block header, FSPEC walk, and the octet
//! length of each UAP item, so a record walk can step past items it does not
//! decode.

use super::AsterixError;

/// A data item by its number in the category: I048/140 is `Item(140)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Item(pub(super) u16);

impl Item {
    pub(super) const SP: Item = Item(1000);
    pub(super) const RE: Item = Item(1001);
    pub(super) const SPARE: Item = Item(1002);
}

/// The `(item, bytes)` pairs of one record.
pub(super) type Items<'a> = Vec<(Item, &'a [u8])>;

/// How to measure the octet length of a UAP item or compound subfield.
#[derive(Clone, Copy)]
pub(super) enum Field {
    Fixed(usize),
    /// Extents of `unit` octets that continue while the low (FX) bit of each
    /// extent's last octet is set; `unit` is 3 for I062/510, else 1.
    Extended(usize),
    /// A one-octet repetition count, then that many items of `N` octets.
    Repetitive(usize),
    /// A one-octet length that counts itself (RE and SP items).
    Explicit,
    /// An FX-chained presence bitmap, then the present subfields in bit order.
    Compound(&'static [Field]),
    /// A compound bitmap position with no subfield.
    Spare,
    /// Not length-modelled; a record containing it fails with `UnsupportedItem`.
    Opaque,
}

/// The octet length of `field` at `data[off]`, or `None` if it is truncated or
/// `Opaque`.
fn field_len(field: Field, data: &[u8], off: usize) -> Option<usize> {
    match field {
        Field::Fixed(n) => Some(n),
        Field::Spare => Some(0),
        Field::Extended(unit) => {
            let mut n = 0;
            loop {
                let last = off.checked_add(n + unit)?.checked_sub(1)?;
                if last >= data.len() {
                    return None;
                }
                n += unit;
                if data[last] & 0x01 == 0 {
                    return Some(n);
                }
            }
        }
        Field::Repetitive(item) => {
            let rep = *data.get(off)? as usize;
            Some(1 + rep * item)
        }
        Field::Explicit => Some(*data.get(off)? as usize),
        Field::Compound(subs) => {
            let bits = primary_bits(data, off)?;
            let mut total = bits.len().div_ceil(7);
            for (i, &present) in bits.iter().enumerate() {
                if present {
                    let sub = *subs.get(i)?;
                    total += field_len(sub, data, off + total)?;
                }
            }
            Some(total)
        }
        Field::Opaque => None,
    }
}

/// The presence bits of an FX-chained bitmap at `data[off]`, seven per octet,
/// bit 8 first.
fn primary_bits(data: &[u8], mut off: usize) -> Option<Vec<bool>> {
    let mut bits = Vec::new();
    loop {
        let octet = *data.get(off)?;
        off += 1;
        for b in 0..7 {
            bits.push(octet & (0x80 >> b) != 0);
        }
        if octet & 0x01 == 0 {
            return Some(bits);
        }
    }
}

/// The present subfields of a compound item as `(subfield index, bytes)`,
/// stopping at the first one that cannot be measured.
pub(super) fn walk_compound<'a>(subs: &[Field], data: &'a [u8]) -> Vec<(usize, &'a [u8])> {
    let mut out = Vec::new();
    let Some(bits) = primary_bits(data, 0) else {
        return out;
    };
    let mut off = bits.len().div_ceil(7);
    for (i, &present) in bits.iter().enumerate() {
        if !present {
            continue;
        }
        let Some(sub) = subs.get(i).copied() else {
            break;
        };
        let Some(len) = field_len(sub, data, off) else {
            break;
        };
        let end = off + len;
        if end > data.len() {
            break;
        }
        out.push((i, &data[off..end]));
        off = end;
    }
    out
}

/// The category and declared length of the data block at the start of `frame`.
pub(super) fn block_header(frame: &[u8]) -> Result<(u8, usize), AsterixError> {
    let [cat, hi, lo, ..] = *frame else {
        return Err(AsterixError::BadBlock {
            cat: None,
            declared: 0,
            have: frame.len(),
        });
    };
    let len = u16::from_be_bytes([hi, lo]) as usize;
    if len < 3 || len > frame.len() {
        return Err(AsterixError::BadBlock {
            cat: Some(cat),
            declared: len,
            have: frame.len(),
        });
    }
    Ok((cat, len))
}

/// The items of the record at `data[off]`, and the offset of the next record.
pub(super) fn walk_record<'a>(
    cat: u8,
    uap: &[(Item, Field)],
    data: &'a [u8],
    mut off: usize,
) -> Result<(Items<'a>, usize), AsterixError> {
    let mut present = Vec::new();
    let mut frn = 1u8;
    loop {
        let octet = *data.get(off).ok_or(AsterixError::Truncated)?;
        off += 1;
        for bit in 0..7 {
            if octet & (0x80 >> bit) != 0 {
                present.push(frn);
            }
            frn = frn.saturating_add(1);
        }
        if octet & 0x01 == 0 {
            break;
        }
    }

    let mut items = Vec::with_capacity(present.len());
    for frn in present {
        let (item, field) = *uap
            .get(frn as usize - 1)
            .ok_or(AsterixError::UnsupportedItem { cat, frn })?;
        let Some(len) = field_len(field, data, off) else {
            return Err(match field {
                Field::Opaque | Field::Compound(_) => AsterixError::UnsupportedItem { cat, frn },
                _ => AsterixError::Truncated,
            });
        };
        let end = off.checked_add(len).ok_or(AsterixError::Truncated)?;
        let bytes = data.get(off..end).ok_or(AsterixError::Truncated)?;
        items.push((item, bytes));
        off = end;
    }
    Ok((items, off))
}
