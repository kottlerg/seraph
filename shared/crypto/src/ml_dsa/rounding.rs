// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/rounding.rs

//! The rounding of FIPS 204 § 7.4: `Power2Round`, Decompose and the
//! `HighBits`, `LowBits`, `MakeHint` and `UseHint` built on it.
//!
//! Each function takes a coefficient in [0, q). `Power2Round`, Decompose and
//! `MakeHint` take secret values in the signer, so they compute without a branch
//! and without a division instruction: the division by 2 * GAMMA2 is a
//! multiplication by a reciprocal and a shift, exact over the inputs they take
//! (tested over all of [0, q)), and the one special case of Decompose is a
//! mask. `UseHint` takes public values only (the verifier's) and branches.

#[cfg(any(test, feature = "sign"))]
use super::params::D;
use super::params::{GAMMA2, W1_MAX};

/// The shift of the reciprocal multiplication in [`decompose`].
const RECIPROCAL_SHIFT: u32 = 48;

/// ceil(2^48 / (2 * GAMMA2)). For every n below 2^24, n * this / 2^48 rounds
/// down to n / (2 * GAMMA2): the error of the reciprocal is below 1, so the
/// product's error is below n / 2^48 < 2^-24, less than the distance from
/// n / (2 * GAMMA2) to the next integer above it, which is at least
/// 1 / (2 * GAMMA2) > 2^-20.
const RECIPROCAL: i64 = ((1i64 << RECIPROCAL_SHIFT) + 2 * GAMMA2 as i64 - 1) / (2 * GAMMA2 as i64);

/// -1 when `a` is not zero, 0 when it is, without a branch, for |a| < 2^31.
fn nonzero_mask(a: i32) -> i32
{
    (a | a.wrapping_neg()).wrapping_shr(31)
}

/// `Power2Round` (FIPS 204 Algorithm 35): r = r1 * 2^D + r0 with r0 in
/// (-2^(D-1), 2^(D-1)].
#[cfg(any(test, feature = "sign"))]
pub(crate) fn power2round(r: i32) -> (i32, i32)
{
    let r1 = r.wrapping_add((1 << (D - 1)) - 1).wrapping_shr(D);
    (r1, r.wrapping_sub(r1.wrapping_shl(D)))
}

/// Decompose (FIPS 204 Algorithm 36): r = r1 * 2 * GAMMA2 + r0 mod q with r0 in
/// (-GAMMA2, GAMMA2], except that the top value of r1 folds to 0 with r0 one
/// lower, so that r1 lies in [0, `W1_MAX`].
#[expect(
    clippy::cast_possible_truncation,
    reason = "the quotient is below q / (2 * GAMMA2), which fits an i32"
)]
pub(crate) fn decompose(r: i32) -> (i32, i32)
{
    // r1 = ceil((r - GAMMA2) / (2 * GAMMA2)) = floor((r + GAMMA2 - 1) / (2 * GAMMA2)),
    // the r1 whose r0 = r - r1 * 2 * GAMMA2 lies in (-GAMMA2, GAMMA2].
    let n = i64::from(r.wrapping_add(GAMMA2 - 1));
    let r1 = n.wrapping_mul(RECIPROCAL).wrapping_shr(RECIPROCAL_SHIFT) as i32;
    let r0 = r.wrapping_sub(r1.wrapping_mul(2 * GAMMA2));
    // r - r0 = q - 1 exactly when r1 = W1_MAX + 1: then r1 = 0 and r0 = r0 - 1.
    let other = nonzero_mask(r1 ^ (W1_MAX + 1));
    (r1 & other, r0.wrapping_add(!other))
}

/// `HighBits` (FIPS 204 Algorithm 37).
pub(crate) fn high_bits(r: i32) -> i32
{
    decompose(r).0
}

/// `LowBits` (FIPS 204 Algorithm 38).
#[cfg(any(test, feature = "sign"))]
pub(crate) fn low_bits(r: i32) -> i32
{
    decompose(r).1
}

/// `MakeHint` (FIPS 204 Algorithm 39), with z + r passed reduced: 1 when adding
/// z to r changes its high bits, 0 otherwise.
#[cfg(any(test, feature = "sign"))]
pub(crate) fn make_hint(r_plus_z: i32, r: i32) -> i32
{
    nonzero_mask(high_bits(r) ^ high_bits(r_plus_z)) & 1
}

/// `UseHint` (FIPS 204 Algorithm 40) with the hint set: the high bits of r,
/// moved one step in the direction of its low bits. With the hint clear,
/// `UseHint` is [`high_bits`].
pub(crate) fn use_hint(r: i32) -> i32
{
    let (r1, r0) = decompose(r);
    if r0 > 0
    {
        if r1 == W1_MAX { 0 } else { r1.wrapping_add(1) }
    }
    else if r1 == 0
    {
        W1_MAX
    }
    else
    {
        r1.wrapping_sub(1)
    }
}

#[cfg(test)]
mod tests
{
    use super::super::params::Q;
    use super::*;

    /// Decompose as FIPS 204 Algorithm 36 states it, with division and
    /// remainder.
    fn decompose_by_definition(r: i32) -> (i32, i32)
    {
        let alpha = 2 * GAMMA2;
        let mut r0 = r % alpha;
        if r0 > GAMMA2
        {
            r0 -= alpha;
        }
        if r - r0 == Q - 1
        {
            (0, r0 - 1)
        }
        else
        {
            ((r - r0) / alpha, r0)
        }
    }

    #[test]
    fn decompose_matches_its_definition_over_every_residue()
    {
        for r in 0..Q
        {
            assert_eq!(decompose(r), decompose_by_definition(r), "r = {r}");
        }
    }

    #[test]
    fn power2round_splits_every_residue_into_its_rounded_parts()
    {
        for r in 0..Q
        {
            let (r1, r0) = power2round(r);
            assert_eq!(r1 * (1 << D) + r0, r);
            assert!(-(1 << (D - 1)) < r0 && r0 <= 1 << (D - 1), "r = {r}");
        }
    }

    #[test]
    fn a_hint_recovers_the_high_bits_of_the_unrounded_sum()
    {
        // FIPS 204 Lemma 1: UseHint(MakeHint(z, r), r) = HighBits(r + z) for
        // |z| <= GAMMA2, here across the wrap at q and every rounding boundary.
        for r in (0..Q).step_by(997).chain(Q - 3 * GAMMA2..Q)
        {
            for z in [-GAMMA2, -GAMMA2 + 1, -1, 0, 1, GAMMA2 - 1, GAMMA2]
            {
                let sum = (r + z).rem_euclid(Q);
                let used = if make_hint(sum, r) == 1
                {
                    use_hint(r)
                }
                else
                {
                    high_bits(r)
                };
                assert_eq!(used, high_bits(sum), "r = {r}, z = {z}");
            }
        }
    }
}
