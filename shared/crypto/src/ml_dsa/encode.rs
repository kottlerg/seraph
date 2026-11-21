// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/encode.rs

//! The bit packing and the codecs of FIPS 204 § 7.1 and § 7.2: public keys,
//! signatures, w1 and the hint section.
//!
//! Coefficients are packed least-significant bit first into a little-endian
//! bit stream (`SimpleBitPack` and `BitPack`, Algorithms 16 and 17, with
//! `BitsToBytes`). Packing and unpacking branch on the bit width and the
//! lengths only, so the signer packs its secret mask through them. The checks
//! a signature's decoding owes are here: [`hints_valid`] is every check of
//! `HintBitUnpack` (Algorithm 21), and [`z_in_range`] the norm bound
//! `Verify_internal` (Algorithm 8) puts on z.

use super::params::{BETA, GAMMA1, HINT_LEN, OMEGA, Z_BITS};

/// The coefficients packed in `bytes`, `bits` bits each (at most 32), as
/// unsigned values: the inverse of [`pack`], before the caller maps them to
/// the coefficients they encode.
pub(crate) fn unpack(bytes: &[u8], bits: u32) -> Unpack<'_>
{
    Unpack {
        bytes: bytes.iter(),
        held: 0,
        bits_held: 0,
        bits,
    }
}

/// The iterator [`unpack`] returns.
pub(crate) struct Unpack<'a>
{
    bytes: core::slice::Iter<'a, u8>,
    /// Bits read but not yet returned, least significant first.
    held: u64,
    bits_held: u32,
    bits: u32,
}

impl Iterator for Unpack<'_>
{
    type Item = i32;

    fn next(&mut self) -> Option<i32>
    {
        while self.bits_held < self.bits
        {
            let byte = *self.bytes.next()?;
            self.held |= u64::from(byte).wrapping_shl(self.bits_held);
            self.bits_held = self.bits_held.wrapping_add(8);
        }
        let value = self.held & 1u64.wrapping_shl(self.bits).wrapping_sub(1);
        self.held = self.held.wrapping_shr(self.bits);
        self.bits_held = self.bits_held.wrapping_sub(self.bits);
        let [b0, b1, b2, b3, ..] = value.to_le_bytes();
        Some(i32::from_le_bytes([b0, b1, b2, b3]))
    }
}

/// Pack `values`, each in [0, 2^bits), `bits` bits each, into `out`, which
/// holds exactly as many bits as the values (FIPS 204 Algorithms 16 and 17;
/// the callers map their coefficients to these values).
pub(crate) fn pack(values: impl IntoIterator<Item = i32>, bits: u32, out: &mut [u8])
{
    let mut held: u64 = 0;
    let mut bits_held: u32 = 0;
    let mut slots = out.iter_mut();
    for value in values
    {
        held |= u64::from(value.cast_unsigned()).wrapping_shl(bits_held);
        bits_held = bits_held.wrapping_add(bits);
        while bits_held >= 8
        {
            let [low, ..] = held.to_le_bytes();
            if let Some(slot) = slots.next()
            {
                *slot = low;
            }
            held = held.wrapping_shr(8);
            bits_held = bits_held.wrapping_sub(8);
        }
    }
}

/// Every check `HintBitUnpack` (FIPS 204 Algorithm 21) makes of the hint
/// section: each row's end index is at least the previous row's and at most
/// OMEGA, the positions of each row strictly increase, and every position slot
/// past the last row's end is zero. A section that passes encodes exactly one
/// hint vector, so a signature has one encoding.
pub(crate) fn hints_valid(hints: &[u8; HINT_LEN]) -> bool
{
    let (positions, ends) = hints.split_at(OMEGA);
    let mut start = 0;
    for &end in ends
    {
        let end = usize::from(end);
        if end < start || end > OMEGA
        {
            return false;
        }
        let Some(row) = positions.get(start..end)
        else
        {
            return false;
        };
        if row.windows(2).any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return false;
        }
        start = end;
    }
    positions
        .get(start..)
        .is_some_and(|rest| rest.iter().all(|&b| b == 0))
}

/// The hint positions of each row of a section [`hints_valid`] accepted, in
/// increasing order.
pub(crate) fn hint_rows(hints: &[u8; HINT_LEN]) -> impl Iterator<Item = &[u8]>
{
    let (positions, ends) = hints.split_at(OMEGA);
    ends.iter().scan(0, move |start, &end| {
        let end = usize::from(end);
        let row = positions.get(*start..end).unwrap_or(&[]);
        *start = end;
        Some(row)
    })
}

/// Whether every coefficient of the packed z lies in
/// (-(GAMMA1 - BETA), GAMMA1 - BETA), the bound `Verify_internal` (FIPS 204
/// Algorithm 8) puts on it. A packed value v encodes GAMMA1 - v, so a decoded
/// coefficient lies in (-GAMMA1, GAMMA1] before this check.
pub(crate) fn z_in_range(z: &[u8]) -> bool
{
    unpack(z, Z_BITS)
        .all(|v| GAMMA1.wrapping_sub(v).unsigned_abs() < (GAMMA1 - BETA).unsigned_abs())
}

/// `HintBitPack` (FIPS 204 Algorithm 20): the hint section of 0/1 hint rows
/// that hold at most OMEGA ones together.
#[cfg(any(test, feature = "sign"))]
pub(crate) fn pack_hints(rows: &[[u8; super::params::N]; super::params::K]) -> [u8; HINT_LEN]
{
    let mut out = [0u8; HINT_LEN];
    let (positions, ends) = out.split_at_mut(OMEGA);
    let mut slots = positions.iter_mut();
    let mut count: u8 = 0;
    for (row, end) in rows.iter().zip(ends.iter_mut())
    {
        for (position, _) in (0u8..=u8::MAX).zip(row).filter(|(_, hint)| **hint != 0)
        {
            if let Some(slot) = slots.next()
            {
                *slot = position;
                count = count.wrapping_add(1);
            }
        }
        *end = count;
    }
    out
}

#[cfg(test)]
mod tests
{
    use std::vec;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn unpacking_inverts_packing_at_every_width_the_codecs_use()
    {
        for bits in [4u32, 6, 10, 13, 18, 20]
        {
            let values: Vec<i32> = (0..256i64)
                .map(|i| i32::try_from(i * 2_654_435_761 % (1i64 << bits)).unwrap())
                .collect();
            let mut packed = vec![0u8; 256 * usize::try_from(bits).unwrap() / 8];
            pack(values.iter().copied(), bits, &mut packed);
            assert_eq!(
                unpack(&packed, bits).collect::<Vec<_>>(),
                values,
                "{bits} bits"
            );
        }
    }

    fn section(rows: &[&[u8]]) -> [u8; HINT_LEN]
    {
        let mut out = [0u8; HINT_LEN];
        let mut index = 0;
        for (i, row) in rows.iter().enumerate()
        {
            for &p in *row
            {
                out[index] = p;
                index += 1;
            }
            out[OMEGA + i] = u8::try_from(index).unwrap();
        }
        for i in rows.len()..super::super::params::K
        {
            out[OMEGA + i] = u8::try_from(index).unwrap();
        }
        out
    }

    #[test]
    fn a_canonical_hint_section_is_accepted_and_read_back()
    {
        let full: Vec<u8> = (0..55).collect();
        for rows in [vec![], vec![&[0u8, 7, 255][..], &[], &[3]], vec![&full[..]]]
        {
            let hints = section(&rows);
            assert!(hints_valid(&hints));
            let read: Vec<&[u8]> = hint_rows(&hints).collect();
            assert_eq!(&read[..rows.len()], &rows[..]);
        }
    }

    #[test]
    fn every_non_canonical_hint_section_is_refused()
    {
        let valid = section(&[&[1, 2], &[5]]);
        // Positions within a row not strictly increasing: equal, then decreasing.
        let mut equal = valid;
        equal[1] = 1;
        let mut decreasing = valid;
        decreasing[0] = 3;
        // A row's end before the previous row's.
        let mut backwards = valid;
        backwards[OMEGA + 1] = 1;
        // An end past OMEGA.
        let mut past_omega = valid;
        past_omega[OMEGA + 5] = u8::try_from(OMEGA + 1).unwrap();
        // A non-zero slot past the last end.
        let mut trailing = valid;
        trailing[OMEGA - 1] = 9;
        for (name, hints) in [
            ("equal", equal),
            ("decreasing", decreasing),
            ("backwards", backwards),
            ("past omega", past_omega),
            ("trailing", trailing),
        ]
        {
            assert!(!hints_valid(&hints), "{name}");
        }
        // Positions that decrease across a row boundary are canonical.
        assert!(hints_valid(&section(&[&[9], &[2]])));
    }

    #[test]
    fn hint_packing_round_trips()
    {
        let mut rows = [[0u8; super::super::params::N]; super::super::params::K];
        rows[0][3] = 1;
        rows[0][200] = 1;
        rows[4][0] = 1;
        rows[5][255] = 1;
        let hints = pack_hints(&rows);
        assert!(hints_valid(&hints));
        let read: Vec<&[u8]> = hint_rows(&hints).collect();
        assert_eq!(read, [&[3u8, 200][..], &[], &[], &[], &[0], &[255]]);
    }

    #[test]
    fn z_is_refused_at_the_norm_bound_and_accepted_inside_it()
    {
        let bound = GAMMA1 - BETA;
        for (z, inside) in [
            (bound - 1, true),
            (bound, false),
            (-(bound - 1), true),
            (-bound, false),
        ]
        {
            let mut values = [GAMMA1; 256];
            values[17] = GAMMA1 - z;
            let mut packed = [0u8; 640];
            pack(values, Z_BITS, &mut packed);
            assert_eq!(z_in_range(&packed), inside, "z = {z}");
        }
    }
}
