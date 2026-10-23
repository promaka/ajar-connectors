// SPDX-License-Identifier: Apache-2.0
//! ULIDs, which BSI Flex 335 requires for every report, object, task and
//! alert identifier: 48 bits of millisecond time and 80 random bits, as 26
//! Crockford base32 characters. Small enough to own rather than depend on.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A fresh ULID for now.
pub fn new() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let random = uuid::Uuid::new_v4().as_u128() & ((1u128 << 80) - 1);
    encode(millis, random)
}

/// The ULID for a given time and randomness: 128 bits, the top 48 the time.
pub fn encode(millis: u64, random80: u128) -> String {
    let value = (u128::from(millis & 0xFFFF_FFFF_FFFF) << 80) | (random80 & ((1u128 << 80) - 1));
    let mut out = [b'0'; 26];
    let mut v = value;
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(v & 31) as usize];
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("the alphabet is ASCII")
}

/// Whether `s` has a ULID's shape: 26 Crockford base32 characters with a
/// first character that keeps the value inside 128 bits.
pub fn is_valid(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| ALPHABET.contains(&b.to_ascii_uppercase()))
        && s.as_bytes()[0] <= b'7'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_ulid_has_the_shape_the_standard_wants() {
        let id = new();
        assert!(is_valid(&id), "{id}");
        assert_ne!(new(), id);
    }

    #[test]
    fn the_encoding_matches_the_specification_example() {
        // The spec's canonical example: time 1469918176385 ms, random 0 gives
        // the first ten characters 01ARYZ6S41 and sixteen zeros.
        assert_eq!(encode(1_469_918_176_385, 0), "01ARYZ6S410000000000000000");
        assert_eq!(encode(0, 1), "00000000000000000000000001");
        assert_eq!(encode(u64::MAX, u128::MAX), "7ZZZZZZZZZZZZZZZZZZZZZZZZZ");
    }

    #[test]
    fn validation_refuses_the_wrong_shape() {
        assert!(!is_valid(""));
        assert!(!is_valid("01ARYZ6S41000000000000000")); // 25 chars
        assert!(!is_valid("01ARYZ6S4100000000000000IL")); // I and L are not in the alphabet
        assert!(!is_valid("8ZZZZZZZZZZZZZZZZZZZZZZZZZ")); // overflows 128 bits
        assert!(is_valid("01j9a0b1c2d3e4f5g6h7j8k9m0")); // lower case is accepted
    }
}
