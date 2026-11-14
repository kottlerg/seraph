// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/hex.rs

//! Hexadecimal encoding and decoding, as test files and failure reports
//! carry byte strings.

use std::fmt::Write as _;

/// Why a hex string did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError
{
    /// The string has an odd number of digits.
    OddLength,
    /// The character at this byte offset is not a hex digit.
    BadDigit(usize),
}

/// Decode `text` (upper or lower case digits, no separators) into bytes.
///
/// # Errors
///
/// [`HexError::OddLength`] for an odd digit count, [`HexError::BadDigit`] for
/// a character that is not a hex digit.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError>
{
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2)
    {
        return Err(HexError::OddLength);
    }
    let (pairs, _) = digits.as_chunks::<2>();
    let mut out = Vec::with_capacity(pairs.len());
    for (index, &[hi, lo]) in pairs.iter().enumerate()
    {
        let at = index.wrapping_mul(2);
        let hi = nibble(hi).ok_or(HexError::BadDigit(at))?;
        let lo = nibble(lo).ok_or(HexError::BadDigit(at.wrapping_add(1)))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Encode `bytes` as lower-case hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String
{
    let mut out = String::with_capacity(bytes.len().wrapping_mul(2));
    for byte in bytes
    {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn nibble(digit: u8) -> Option<u8>
{
    match digit
    {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit.checked_sub(b'a')?.checked_add(10),
        b'A'..=b'F' => digit.checked_sub(b'A')?.checked_add(10),
        _ => None,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn decode_reads_both_cases_and_round_trips_through_encode()
    {
        let bytes = decode("00ff7Fa0").unwrap();
        assert_eq!(bytes, [0x00, 0xff, 0x7f, 0xa0]);
        assert_eq!(encode(&bytes), "00ff7fa0");
    }

    #[test]
    fn decode_refuses_an_odd_length_and_names_the_offset_of_a_bad_digit()
    {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("00g0"), Err(HexError::BadDigit(2)));
        assert_eq!(decode("000g"), Err(HexError::BadDigit(3)));
    }
}
