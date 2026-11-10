// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/gdb-rsp/src/hex.rs

//! Hex digits as the protocol writes them: numbers most significant digit
//! first, data as two digits per byte in memory order.

use crate::Error;

/// The protocol's hex digits, lower case, as GDB writes them.
pub(crate) const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The value of one hex digit, either case; `None` for any other byte.
#[must_use]
pub fn nibble(digit: u8) -> Option<u8>
{
    match digit
    {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// The number `digits` writes, most significant digit first.
///
/// # Errors
/// - `Malformed`: `digits` is empty, holds a byte that is not a hex digit, or
///   writes a number above `u64::MAX`.
pub fn parse_u64(digits: &[u8]) -> Result<u64, Error>
{
    if digits.is_empty()
    {
        return Err(Error::Malformed);
    }
    digits.iter().try_fold(0u64, |acc, &d| {
        let n = nibble(d).ok_or(Error::Malformed)?;
        acc.checked_mul(16)
            .map(|v| v | u64::from(n))
            .ok_or(Error::Malformed)
    })
}

/// Decode `hex`, two digits per byte, into the front of `out`; returns the
/// byte count, `hex.len() / 2`.
///
/// # Errors
/// - `Malformed`: `hex` has an odd length or a byte that is not a hex digit.
/// - `Overflow`: `out` is shorter than the decoded bytes.
pub fn decode(hex: &[u8], out: &mut [u8]) -> Result<usize, Error>
{
    if hex.len() % 2 != 0
    {
        return Err(Error::Malformed);
    }
    let n = hex.len() / 2;
    let out = out.get_mut(..n).ok_or(Error::Overflow)?;
    for (byte, pair) in out.iter_mut().zip(hex.chunks_exact(2))
    {
        let hi = nibble(pair[0]).ok_or(Error::Malformed)?;
        let lo = nibble(pair[1]).ok_or(Error::Malformed)?;
        *byte = hi << 4 | lo;
    }
    Ok(n)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_number_reads_most_significant_digit_first_in_either_case()
    {
        assert_eq!(parse_u64(b"7fFF0010"), Ok(0x7fff_0010));
        assert_eq!(parse_u64(b"ffffffffffffffff"), Ok(u64::MAX));
        assert_eq!(parse_u64(b"0000000000000000001"), Ok(1));
    }

    #[test]
    fn a_number_that_is_empty_not_hex_or_past_64_bits_is_malformed()
    {
        assert_eq!(parse_u64(b""), Err(Error::Malformed));
        assert_eq!(parse_u64(b"12g4"), Err(Error::Malformed));
        assert_eq!(parse_u64(b"10000000000000000"), Err(Error::Malformed));
    }

    #[test]
    fn data_decodes_two_digits_per_byte_in_order()
    {
        let mut out = [0u8; 4];
        assert_eq!(decode(b"00fFa5", &mut out), Ok(3));
        assert_eq!(out, [0x00, 0xff, 0xa5, 0x00]);
        assert_eq!(decode(b"", &mut out), Ok(0));
    }

    #[test]
    fn data_of_odd_length_or_with_a_non_digit_is_malformed()
    {
        let mut out = [0u8; 4];
        assert_eq!(decode(b"abc", &mut out), Err(Error::Malformed));
        assert_eq!(decode(b"a-", &mut out), Err(Error::Malformed));
    }

    #[test]
    fn data_longer_than_the_output_overflows()
    {
        let mut out = [0u8; 1];
        assert_eq!(decode(b"0102", &mut out), Err(Error::Overflow));
    }
}
