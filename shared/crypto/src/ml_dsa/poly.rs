// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/poly.rs

//! Arithmetic in `R_q = Z_q[X]/(X^256 + 1)` and the number-theoretic transform
//! (FIPS 204 § 7.5 and Appendix A).
//!
//! A [`Poly`] holds 256 coefficients as `i32`, each a representative of its
//! residue mod q that is not necessarily reduced; every function states the
//! range it takes and the range it returns. Multiplication is Montgomery
//! multiplication with R = 2^32 (FIPS 204 Algorithm 49): the transform's
//! twiddle factors are stored times R, so [`ntt`] needs no correction, a
//! pointwise product carries a factor R^-1, and [`inv_ntt`] multiplies it back
//! by R as it scales by 1/256. So `inv_ntt(pointwise(ntt(a), ntt(b)))` is the
//! plain product a * b.
//!
//! Every operation is additions, multiplications and arithmetic shifts in
//! loops of fixed bounds: no branch and no index depends on a coefficient, so
//! the signer passes secret polynomials through them. The operations wrap
//! (`wrapping_*`) where the stated ranges keep every intermediate inside its
//! type, so wrapping and exact results agree.

use super::params::{N, Q};

/// A polynomial: coefficient i multiplies X^i.
pub(crate) type Poly = [i32; N];

/// The zero polynomial.
pub(crate) const ZERO: Poly = [0; N];

/// q^-1 mod 2^32, for Montgomery reduction.
const QINV: i32 = q_inverse();

/// The twiddle factors of the transform: `ZETAS[m]` is zeta^brv8(m) * 2^32
/// mod q, centred in (-q/2, q/2], with zeta = 1753 the 512th root of unity of
/// FIPS 204 and brv8 the bit reversal of an 8-bit index (FIPS 204 Appendix B
/// lists the same powers without the factor 2^32).
const ZETAS: [i32; N] = zetas();

/// 2^64 / 256 mod q: the scale [`inv_ntt`] applies, which divides by 256 and
/// undoes the R^-1 of a pointwise product and of its own reduction.
const INV_NTT_SCALE: i64 = pow2_mod_q(56);

/// q^-1 mod 2^32 by Newton's iteration: q is 1 mod 2^13, so 1 is its inverse
/// to 13 bits, and each step doubles the bits that are right.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "evaluated at compile time only, where an overflow is a compile error"
)]
const fn q_inverse() -> i32
{
    let q = Q.cast_unsigned();
    let mut inverse: u32 = 1;
    let mut step = 0;
    while step < 5
    {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(q.wrapping_mul(inverse)));
        step += 1;
    }
    // Reinterpreted as the signed value Montgomery reduction multiplies by.
    inverse.cast_signed()
}

/// 2^`exponent` mod q.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "evaluated at compile time only, where an overflow is a compile error"
)]
const fn pow2_mod_q(exponent: u32) -> i64
{
    let mut value: i64 = 1;
    let mut step = 0;
    while step < exponent
    {
        value = value * 2 % Q as i64;
        step += 1;
    }
    value
}

/// The table [`ZETAS`] describes.
#[expect(
    clippy::cast_possible_truncation,
    reason = "every value is reduced mod q, which fits an i32"
)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "evaluated at compile time only, where an overflow or an index out of range is a \
              compile error"
)]
const fn zetas() -> [i32; N]
{
    const ZETA: i64 = 1753;
    let q = Q as i64;
    let montgomery = pow2_mod_q(32);
    let mut table = [0i32; N];
    let mut m = 0;
    while m < N
    {
        // zeta^brv8(m), by square-and-multiply over the reversed bits.
        let exponent = (m as u8).reverse_bits();
        let mut power: i64 = 1;
        let mut bit = 8;
        while bit > 0
        {
            bit -= 1;
            power = power * power % q;
            if (exponent >> bit) & 1 == 1
            {
                power = power * ZETA % q;
            }
        }
        let mut value = power * montgomery % q;
        if value > q / 2
        {
            value -= q;
        }
        table[m] = value as i32;
        m += 1;
    }
    table
}

/// Montgomery reduction (FIPS 204 Algorithm 49): for |a| < 2^31 * q, a value
/// congruent to a * 2^-32 mod q in (-q, q).
#[expect(
    clippy::cast_possible_truncation,
    reason = "the low 32 bits of a are the operand of the reduction, and the result, below q \
              in magnitude, fits an i32"
)]
pub(crate) fn montgomery_reduce(a: i64) -> i32
{
    let t = (a as i32).wrapping_mul(QINV);
    (a.wrapping_sub(i64::from(t).wrapping_mul(i64::from(Q)))
        .wrapping_shr(32)) as i32
}

/// For a below 2^31 - 2^22 in magnitude, a value congruent to it mod q in
/// [-6283009, 6283008]: inside (-q, q), as [`inv_ntt`] needs.
pub(crate) fn reduce32(a: i32) -> i32
{
    let t = a.wrapping_add(1 << 22).wrapping_shr(23);
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// For a in (-q, q), a + q when a is negative: the representative in [0, q).
pub(crate) fn caddq(a: i32) -> i32
{
    a.wrapping_add(a.wrapping_shr(31) & Q)
}

/// For a below 2^31 - 2^22 in magnitude, the representative in [0, q).
#[cfg(any(test, feature = "sign"))]
pub(crate) fn freeze(a: i32) -> i32
{
    caddq(reduce32(a))
}

/// For a below 2^31 - 2^22 in magnitude, the centred representative in
/// [-(q - 1) / 2, (q - 1) / 2].
#[cfg(any(test, feature = "sign"))]
pub(crate) fn centre(a: i32) -> i32
{
    let f = freeze(a);
    f.wrapping_sub(((Q - 1) / 2).wrapping_sub(f).wrapping_shr(31) & Q)
}

/// The forward transform in place (FIPS 204 Algorithm 41). Takes coefficients
/// below B in magnitude, with B + 8q < 2^31; returns them below B + 8q, in
/// bit-reversed order.
pub(crate) fn ntt(a: &mut Poly)
{
    let mut zetas = ZETAS.iter().skip(1);
    let mut len = N / 2;
    while len > 0
    {
        for block in a.chunks_exact_mut(len.wrapping_mul(2))
        {
            let zeta = i64::from(zetas.next().copied().unwrap_or(0));
            let (low, high) = block.split_at_mut(len);
            for (x, y) in low.iter_mut().zip(high.iter_mut())
            {
                let t = montgomery_reduce(zeta.wrapping_mul(i64::from(*y)));
                *y = x.wrapping_sub(t);
                *x = x.wrapping_add(t);
            }
        }
        len /= 2;
    }
}

/// The inverse transform in place, times 2^32 (FIPS 204 Algorithm 42 with
/// Montgomery reduction). Takes coefficients below q in magnitude, which grow
/// at most 256-fold inside it; returns them below q in magnitude.
pub(crate) fn inv_ntt(a: &mut Poly)
{
    let mut zetas = ZETAS.iter().rev();
    let mut len = 1;
    while len < N
    {
        for block in a.chunks_exact_mut(len.wrapping_mul(2))
        {
            let zeta = i64::from(zetas.next().copied().unwrap_or(0)).wrapping_neg();
            let (low, high) = block.split_at_mut(len);
            for (x, y) in low.iter_mut().zip(high.iter_mut())
            {
                let t = *x;
                *x = t.wrapping_add(*y);
                *y = montgomery_reduce(zeta.wrapping_mul(i64::from(t.wrapping_sub(*y))));
            }
        }
        len = len.wrapping_mul(2);
    }
    for c in a.iter_mut()
    {
        *c = montgomery_reduce(INV_NTT_SCALE.wrapping_mul(i64::from(*c)));
    }
}

/// a[i] * b[i] * 2^-32 mod q, below q in magnitude, for transformed a and b
/// whose products are below 2^31 * q in magnitude.
#[cfg(any(test, feature = "sign"))]
pub(crate) fn pointwise(a: &Poly, b: &Poly) -> Poly
{
    let mut out = ZERO;
    for (o, (x, y)) in out.iter_mut().zip(a.iter().zip(b))
    {
        *o = montgomery_reduce(i64::from(*x).wrapping_mul(i64::from(*y)));
    }
    out
}

/// `f` applied to every coefficient in place.
pub(crate) fn map(a: &mut Poly, f: impl Fn(i32) -> i32)
{
    for c in a.iter_mut()
    {
        *c = f(*c);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The negacyclic product of a and b mod q, by the schoolbook method.
    fn schoolbook(a: &Poly, b: &Poly) -> Poly
    {
        let q = i64::from(Q);
        let mut wide = [0i64; N];
        for (i, &x) in a.iter().enumerate()
        {
            for (j, &y) in b.iter().enumerate()
            {
                let product = i64::from(x) * i64::from(y) % q;
                if i + j < N
                {
                    wide[i + j] = (wide[i + j] + product) % q;
                }
                else
                {
                    wide[i + j - N] = (wide[i + j - N] - product) % q;
                }
            }
        }
        wide.map(|v| i32::try_from(v.rem_euclid(q)).unwrap())
    }

    fn sample(seed: u32, bound: i32) -> Poly
    {
        let mut state = seed;
        core::array::from_fn(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            i32::try_from(state >> 8).unwrap() % bound
        })
    }

    #[test]
    fn transform_multiplication_matches_the_negacyclic_product()
    {
        // Operands at the ranges the verifier and signer pass: a full-range
        // value mod q against a short one, and two values of the mask's size.
        for (a, b) in [
            (sample(1, Q), sample(2, 5)),
            (sample(3, 1 << 19), sample(4, 1 << 19)),
            (sample(5, Q).map(|c| -c), sample(6, Q)),
        ]
        {
            let (mut a_hat, mut b_hat) = (a, b);
            ntt(&mut a_hat);
            ntt(&mut b_hat);
            let mut product = pointwise(&a_hat, &b_hat);
            map(&mut product, reduce32);
            inv_ntt(&mut product);
            map(&mut product, freeze);
            assert_eq!(product, schoolbook(&a, &b));
        }
    }

    #[test]
    fn reductions_return_their_stated_ranges()
    {
        let limit = i32::MAX - (1 << 22);
        for a in [-limit, -Q, -1, 0, 1, Q - 1, Q, 2 * Q + 5, limit]
        {
            let r = reduce32(a);
            assert!((-6_283_009..=6_283_008).contains(&r), "{a}");
            assert_eq!((i64::from(r) - i64::from(a)) % i64::from(Q), 0);
            let f = freeze(a);
            assert!((0..Q).contains(&f) && (i64::from(f) - i64::from(a)) % i64::from(Q) == 0);
            let c = centre(a);
            assert!(c.abs() <= (Q - 1) / 2 && (i64::from(c) - i64::from(a)) % i64::from(Q) == 0);
        }
    }
}
