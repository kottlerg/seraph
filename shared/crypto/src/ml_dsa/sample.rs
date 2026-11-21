// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/sample.rs

//! The pseudorandom sampling of FIPS 204 § 7.3: the entries of A
//! (`RejNTTPoly`), the secret vectors (`RejBoundedPoly`), the mask (`ExpandMask`)
//! and the challenge (`SampleInBall`).
//!
//! A matrix entry is never stored: [`mul_acc_matrix_entry`] multiplies each
//! coefficient into an accumulator as it is sampled, so the verifier holds one
//! SHAKE128 block for A, never A's k * l polynomials.
//!
//! Timing. `RejNTTPoly` samples from the public rho, so its rejection loop
//! branches on the samples. `SampleInBall` samples from c-tilde, which an
//! accepted signature publishes but a rejected attempt's does not (it is a
//! function of w = A y, and y is secret): it branches only on whether a
//! position byte is rejected, and places the positions and signs it draws under
//! masks. `RejBoundedPoly` samples the secret vectors from the secret rho': it
//! branches on whether a half-byte is rejected, which reveals the positions of
//! the rejected half-bytes in the SHAKE256 stream and nothing else, since each
//! half-byte is independent and a rejected one is discarded; the value of an
//! accepted one is mapped without a branch. `ExpandMask` takes every sample, so
//! it has no rejection.

#[cfg(any(test, feature = "sign"))]
use super::params::POLY_Z_LEN;
use super::params::{ETA, GAMMA1, N, Q, RHO_LEN, TAU, Z_BITS};
use super::poly::{Poly, ZERO, montgomery_reduce};
use crate::shake::{SHAKE128_RATE, SHAKE256_RATE, Shake128, Shake256};

/// `acc[i] += A[row][col][i] * rhs[i] * 2^-32` (Montgomery), with
/// `A[row][col]` = RejNTTPoly(rho || col || row) of `ExpandA` (FIPS 204
/// Algorithms 30 and 32), sampled as it is used. The entry's coefficients lie
/// in [0, q) and each product's contribution below q in magnitude, so an
/// accumulator of l contributions stays below l * q.
pub(crate) fn mul_acc_matrix_entry(
    rho: &[u8; RHO_LEN],
    row: u8,
    col: u8,
    rhs: &Poly,
    acc: &mut Poly,
)
{
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[col, row]);
    let mut reader = xof.finalize();
    let mut block = [0u8; SHAKE128_RATE];
    // Triples of the current block, all used: 168 is a multiple of 3.
    let mut triples: core::slice::Iter<'_, [u8; 3]> = [].iter();
    for (a, r) in acc.iter_mut().zip(rhs)
    {
        let coefficient = loop
        {
            if let Some([b0, b1, b2]) = triples.next()
            {
                // `CoeffFromThreeBytes` (Algorithm 14): the low 23 bits, if
                // below q.
                let value = u32::from_le_bytes([*b0, *b1, *b2 & 0x7f, 0]).cast_signed();
                if value < Q
                {
                    break value;
                }
            }
            else
            {
                reader.read(&mut block);
                triples = block.as_chunks::<3>().0.iter();
            }
        };
        let product = montgomery_reduce(i64::from(coefficient).wrapping_mul(i64::from(*r)));
        *a = a.wrapping_add(product);
    }
}

/// The largest half-byte `RejBoundedPoly` takes, plus one: the largest multiple
/// of 2 * ETA + 1 that is at most 16, so the accepted half-bytes cover each
/// residue mod 2 * ETA + 1 equally (15 for ETA = 2, 9 for ETA = 4).
#[cfg(any(test, feature = "sign"))]
const HALF_BYTE_BOUND: u32 = 16 - 16 % RESIDUES;

/// 2 * ETA + 1, the number of values a secret coefficient takes.
#[cfg(any(test, feature = "sign"))]
const RESIDUES: u32 = 2 * ETA.unsigned_abs() + 1;

/// ceil(2^10 / (2 * ETA + 1)): for b below 16, b * this >> 10 is
/// b / (2 * ETA + 1), without a division instruction.
#[cfg(any(test, feature = "sign"))]
const HALF_BYTE_RECIPROCAL: u32 = 1024u32.div_ceil(RESIDUES);

/// `CoeffFromHalfByte` (FIPS 204 Algorithm 15) for a half-byte below
/// [`HALF_BYTE_BOUND`]: ETA - (b mod (2 * ETA + 1)), without a branch.
#[cfg(any(test, feature = "sign"))]
fn coefficient_from_half_byte(b: u32) -> i32
{
    let quotient = b.wrapping_mul(HALF_BYTE_RECIPROCAL).wrapping_shr(10);
    let remainder = b.wrapping_sub(quotient.wrapping_mul(RESIDUES));
    ETA.wrapping_sub(remainder.cast_signed())
}

/// `RejBoundedPoly` (FIPS 204 Algorithm 31) of rho' || nonce, nonce as two
/// little-endian bytes: a polynomial with coefficients in [-ETA, ETA].
#[cfg(any(test, feature = "sign"))]
pub(crate) fn rej_bounded_poly(seed: &[u8; 64], nonce: u16) -> Poly
{
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut reader = xof.finalize();
    let mut block = [0u8; SHAKE256_RATE];
    let mut bytes: core::slice::Iter<'_, u8> = [].iter();
    let mut out = ZERO;
    let mut slots = out.iter_mut();
    let mut slot = slots.next();
    while let Some(target) = slot.take()
    {
        if let Some(&byte) = bytes.next()
        {
            // The low half-byte first, then the high one; each fills the next
            // free slot when it is accepted.
            let mut target = Some(target);
            for half in [u32::from(byte & 0x0f), u32::from(byte >> 4)]
            {
                if half < HALF_BYTE_BOUND
                    && let Some(t) = target.take()
                {
                    *t = coefficient_from_half_byte(half);
                    target = slots.next();
                }
            }
            slot = target;
        }
        else
        {
            reader.read(&mut block);
            bytes = block.iter();
            slot = Some(target);
        }
    }
    out
}

/// One polynomial of `ExpandMask` (FIPS 204 Algorithm 34): `BitUnpack` of
/// SHAKE256(rho'' || nonce) with coefficients GAMMA1 - v, in
/// (-GAMMA1, GAMMA1].
#[cfg(any(test, feature = "sign"))]
pub(crate) fn expand_mask(seed: &[u8; 64], nonce: u16) -> Poly
{
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut packed = [0u8; POLY_Z_LEN];
    xof.finalize().read(&mut packed);
    let mut out = ZERO;
    for (c, v) in out.iter_mut().zip(super::encode::unpack(&packed, Z_BITS))
    {
        *c = GAMMA1.wrapping_sub(v);
    }
    out
}

/// The index of the first coefficient `SampleInBall` places, N - TAU, as the
/// byte its position draws are compared with.
const FIRST_PLACED: u8 = (N - TAU).to_le_bytes()[0];

/// `SampleInBall` (FIPS 204 Algorithm 29): the challenge polynomial of
/// c-tilde, with TAU coefficients +-1 and the rest 0.
///
/// The signer calls it on the c-tilde of every attempt, rejected ones
/// included, whose challenge stays secret, so no branch and no memory index
/// depends on a drawn position or sign: each swap reads and writes every
/// coefficient up to the one placed, under a mask. What the draws reveal is
/// how many position bytes each placement rejects.
pub(crate) fn sample_in_ball(ctilde: &[u8]) -> Poly
{
    let mut xof = Shake256::new();
    xof.update(ctilde);
    let mut reader = xof.finalize();
    let mut signs = [0u8; 8];
    reader.read(&mut signs);
    let mut signs = u64::from_le_bytes(signs);
    let mut c = ZERO;
    let mut byte = [0u8; 1];
    for placed in FIRST_PLACED..=u8::MAX
    {
        let j = loop
        {
            reader.read(&mut byte);
            let [j] = byte;
            if j <= placed
            {
                break j;
            }
        };
        // +1 or -1 from the next sign bit.
        let [bit, ..] = (signs & 1).to_le_bytes();
        let sign = 1i32.wrapping_sub(i32::from(bit).wrapping_mul(2));
        signs = signs.wrapping_shr(1);
        // c[placed] = c[j], then c[j] = sign, as masked passes over c[..=placed].
        let mut moved = 0;
        for (k, ck) in (0u8..=placed).zip(c.iter_mut())
        {
            let at_j = core::hint::black_box(equal_mask(k, j));
            moved |= *ck & at_j;
            *ck = (*ck & !at_j) | (sign & at_j);
        }
        let at_placed = equal_mask(placed, j);
        if let Some(c_placed) = c.get_mut(usize::from(placed))
        {
            *c_placed = (moved & !at_placed) | (sign & at_placed);
        }
    }
    c
}

/// -1 when `a` equals `b`, 0 otherwise, without a branch.
fn equal_mask(a: u8, b: u8) -> i32
{
    let is_equal = u32::from(a ^ b).wrapping_sub(1).wrapping_shr(31);
    0i32.wrapping_sub(is_equal.cast_signed())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn half_bytes_map_to_their_residues_without_division()
    {
        for b in 0..HALF_BYTE_BOUND
        {
            let expected = ETA - i32::try_from(b).unwrap() % (2 * ETA + 1);
            assert_eq!(coefficient_from_half_byte(b), expected, "{b}");
        }
    }

    /// `SampleInBall` as FIPS 204 Algorithm 29 writes it, with indexed swaps.
    fn sample_in_ball_by_the_text(ctilde: &[u8]) -> Poly
    {
        let mut xof = Shake256::new();
        xof.update(ctilde);
        let mut reader = xof.finalize();
        let mut signs = [0u8; 8];
        reader.read(&mut signs);
        let signs = u64::from_le_bytes(signs);
        let mut c = ZERO;
        let mut byte = [0u8; 1];
        for i in N - TAU..N
        {
            let j = loop
            {
                reader.read(&mut byte);
                if usize::from(byte[0]) <= i
                {
                    break usize::from(byte[0]);
                }
            };
            c[i] = c[j];
            c[j] = if (signs >> (i + TAU - N)) & 1 == 1
            {
                -1
            }
            else
            {
                1
            };
        }
        c
    }

    #[test]
    fn the_masked_challenge_equals_the_indexed_one()
    {
        for seed in 0..=255u8
        {
            let ctilde = [seed, seed.wrapping_mul(7), 3, seed ^ 0x5a];
            assert_eq!(
                sample_in_ball(&ctilde),
                sample_in_ball_by_the_text(&ctilde),
                "{seed}"
            );
        }
    }

    #[test]
    fn equal_mask_is_minus_one_exactly_on_equality()
    {
        for a in 0..=255u8
        {
            for b in [0, 1, a, a.wrapping_add(1), 255]
            {
                assert_eq!(equal_mask(a, b), if a == b { -1 } else { 0 });
            }
        }
    }

    #[test]
    fn the_challenge_has_tau_signed_ones()
    {
        for seed in 0..64u8
        {
            let c = sample_in_ball(&[seed; 48]);
            assert_eq!(c.iter().filter(|&&x| x != 0).count(), TAU);
            assert!(c.iter().all(|&x| (-1..=1).contains(&x)));
        }
    }

    #[test]
    fn secret_coefficients_lie_within_eta()
    {
        for nonce in 0..16
        {
            let s = rej_bounded_poly(&[0xa5; 64], nonce);
            assert!(s.iter().all(|&x| (-ETA..=ETA).contains(&x)));
        }
    }
}
