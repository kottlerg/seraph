// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/edwards.rs

//! The edwards25519 group: points in extended coordinates, addition, scalar
//! multiplication, decompression, and encoding.
//!
//! A [`Point`] is `[X, Y, Z, T]` with affine `x = X/Z`, `y = Y/Z`, and
//! `T = XY/Z` (Hisil–Wong–Carter–Dawson extended coordinates). Scalar
//! multiplication is a constant-shape conditional-swap ladder; constant time
//! is not required for verification, but the swap form is simple and correct.

// many_single_char_names: the addition formula uses the standard a..h
// extended-coordinate working names; renaming would obscure the published math.
#![allow(clippy::many_single_char_names)]

use crate::field::{self, Fe, GF0, GF1};

/// A curve point in extended coordinates `[X, Y, Z, T]`.
pub(crate) type Point = [Fe; 4];

/// The group identity `(0, 1, 1, 0)`.
const IDENTITY: Point = [GF0, GF1, GF1, GF0];

/// In-place point addition: `p ← p + q` (extended-coordinate unified formula).
pub(crate) fn add(p: &mut Point, q: &Point)
{
    let mut a = GF0;
    let mut b = GF0;
    let mut c = GF0;
    let mut d = GF0;
    let mut t = GF0;
    let mut e = GF0;
    let mut f = GF0;
    let mut g = GF0;
    let mut h = GF0;

    field::sub(&mut a, &p[1], &p[0]);
    field::sub(&mut t, &q[1], &q[0]);
    let tmp = a;
    field::mul(&mut a, &tmp, &t);

    field::add(&mut b, &p[0], &p[1]);
    field::add(&mut t, &q[0], &q[1]);
    let tmp = b;
    field::mul(&mut b, &tmp, &t);

    field::mul(&mut c, &p[3], &q[3]);
    let tmp = c;
    field::mul(&mut c, &tmp, &field::D2);

    field::mul(&mut d, &p[2], &q[2]);
    let tmp = d;
    field::add(&mut d, &tmp, &tmp);

    field::sub(&mut e, &b, &a);
    field::sub(&mut f, &d, &c);
    field::add(&mut g, &d, &c);
    field::add(&mut h, &b, &a);

    field::mul(&mut p[0], &e, &f);
    field::mul(&mut p[1], &h, &g);
    field::mul(&mut p[2], &g, &f);
    field::mul(&mut p[3], &e, &h);
}

/// Conditional swap of two points when `swap == 1`.
fn cswap(p: &mut Point, q: &mut Point, swap: u8)
{
    let mut i = 0;
    while i < 4
    {
        field::cswap(&mut p[i], &mut q[i], swap);
        i += 1;
    }
}

/// `[s] q` for a little-endian scalar `s`.
pub(crate) fn scalar_mul(q: &Point, s: &[u8; 32]) -> Point
{
    let mut p = IDENTITY;
    let mut q = *q;
    let mut i = 256usize;
    while i > 0
    {
        i -= 1;
        let bit = (s[i >> 3] >> (i & 7)) & 1;
        cswap(&mut p, &mut q, bit);
        let pc = p;
        add(&mut q, &pc);
        add(&mut p, &pc);
        cswap(&mut p, &mut q, bit);
    }
    p
}

/// `[s] B` for a little-endian scalar `s`, where `B` is the base point.
pub(crate) fn scalar_mul_base(s: &[u8; 32]) -> Point
{
    let mut bt = GF0;
    field::mul(&mut bt, &field::BX, &field::BY);
    let base: Point = [field::BX, field::BY, GF1, bt];
    scalar_mul(&base, s)
}

/// Decompress a 32-byte public key into the **negated** point `-A`.
///
/// Returns `None` if the bytes do not decode to a curve point. Returning the
/// negation directly lets the verifier compute `[S]B + [k](-A)` in one
/// addition. Follows RFC 8032 §5.1.3 for the square-root recovery, with the
/// sign condition inverted to select `-A`.
pub(crate) fn decompress_neg(pk: &[u8; 32]) -> Option<Point>
{
    let mut r: Point = [GF0, GF0, GF1, GF0];
    field::unpack(&mut r[1], pk);

    let mut num = GF0;
    field::sqr(&mut num, &r[1]); // y^2
    let mut den = GF0;
    field::mul(&mut den, &num, &field::D); // d*y^2
    let tmp = num;
    field::sub(&mut num, &tmp, &r[2]); // y^2 - 1
    let tmp = den;
    field::add(&mut den, &r[2], &tmp); // 1 + d*y^2

    // x = (num/den) recovered as num * den^3 * (num * den^7)^((p-5)/8).
    let mut den2 = GF0;
    field::sqr(&mut den2, &den);
    let mut den4 = GF0;
    field::sqr(&mut den4, &den2);
    let mut den6 = GF0;
    field::mul(&mut den6, &den4, &den2);

    let mut t = GF0;
    field::mul(&mut t, &den6, &num);
    let tmp = t;
    field::mul(&mut t, &tmp, &den); // num * den^7

    let tmp = t;
    field::pow2523(&mut t, &tmp); // (num*den^7)^((p-5)/8)
    let tmp = t;
    field::mul(&mut t, &tmp, &num);
    let tmp = t;
    field::mul(&mut t, &tmp, &den);
    let tmp = t;
    field::mul(&mut t, &tmp, &den);
    field::mul(&mut r[0], &t, &den); // candidate x

    // Verify x^2 * den == num, else multiply by sqrt(-1) and retry.
    let mut chk = GF0;
    field::sqr(&mut chk, &r[0]);
    let tmp = chk;
    field::mul(&mut chk, &tmp, &den);
    if !field::eq(&chk, &num)
    {
        let tmp = r[0];
        field::mul(&mut r[0], &tmp, &field::SQRTM1);
    }

    field::sqr(&mut chk, &r[0]);
    let tmp = chk;
    field::mul(&mut chk, &tmp, &den);
    if !field::eq(&chk, &num)
    {
        // No square root: not a valid curve point.
        return None;
    }

    // Select the sign giving -A: negate when the parity already matches the
    // encoded sign bit (the inverse of the standard decompression rule).
    if field::parity(&r[0]) == (pk[31] >> 7)
    {
        let tmp = r[0];
        field::sub(&mut r[0], &GF0, &tmp);
    }

    let mut tt = GF0;
    field::mul(&mut tt, &r[0], &r[1]);
    r[3] = tt;
    Some(r)
}

/// Encode a point as its 32-byte little-endian compressed form.
pub(crate) fn pack(p: &Point) -> [u8; 32]
{
    let mut zi = GF0;
    field::invert(&mut zi, &p[2]);
    let mut tx = GF0;
    field::mul(&mut tx, &p[0], &zi); // x = X/Z
    let mut ty = GF0;
    field::mul(&mut ty, &p[1], &zi); // y = Y/Z
    let mut out = [0u8; 32];
    field::pack(&mut out, &ty);
    out[31] ^= field::parity(&tx) << 7;
    out
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::scalar::L;

    /// Compressed encoding of the base point B (RFC 8032).
    const BASE_ENCODED: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    /// Encoding of the identity point (y = 1, x = 0).
    const IDENTITY_ENCODED: [u8; 32] = [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    fn scalar_one() -> [u8; 32]
    {
        let mut s = [0u8; 32];
        s[0] = 1;
        s
    }

    #[test]
    fn base_times_one_is_base()
    {
        assert_eq!(pack(&scalar_mul_base(&scalar_one())), BASE_ENCODED);
    }

    #[test]
    fn order_times_base_is_identity()
    {
        assert_eq!(pack(&scalar_mul_base(&L)), IDENTITY_ENCODED);
    }

    #[test]
    fn decompress_rejects_non_curve_point()
    {
        // y = 2 is not the y-coordinate of any curve point; decompression
        // must fail rather than return a bogus point.
        let mut pk = [0u8; 32];
        pk[0] = 2;
        assert!(decompress_neg(&pk).is_none());
    }
}
