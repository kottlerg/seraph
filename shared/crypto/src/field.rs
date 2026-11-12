// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/field.rs

//! Arithmetic in the prime field GF(2^255 - 19) for Ed25519.
//!
//! Elements are 16 signed limbs of radix 2^16 ([`Fe`]). This compact
//! representation (the `TweetNaCl` `gf` model) keeps every intermediate product
//! comfortably inside `i64` and makes carry handling uniform, which is the
//! safest basis for a from-scratch verifier. Verification touches only public
//! data, so the arithmetic is variable-time by design.
//!
//! Limbs are kept loosely bounded between explicit carry passes; multiply and
//! pack run enough carry rounds to renormalise. All public-facing encodings
//! (`pack`/`unpack`) are little-endian per RFC 8032 §5.1.2.

// Field code casts between i64 and byte/limb widths after masking; the masks
// bound every value, so truncation and sign-loss are intentional here.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
// many_single_char_names: limb/loop variables (a, b, c, t, i, j, …) follow the
// reference field-arithmetic naming; descriptive names would only add noise.
#![allow(clippy::many_single_char_names)]

// Limb arithmetic uses wrapping operations: the radix-2^16 representation bounds every
// intermediate inside i64, so wrapping and exact results agree.

/// A field element: 16 limbs, value = Σ limb[i] · 2^(16·i).
pub(crate) type Fe = [i64; 16];

/// Field constant 0.
pub(crate) const GF0: Fe = [0; 16];

/// Field constant 1.
pub(crate) const GF1: Fe = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Curve constant d = -121665/121666.
pub(crate) const D: Fe = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];

/// 2·d, used by the extended-coordinate addition formula.
pub(crate) const D2: Fe = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];

/// Base-point x-coordinate.
pub(crate) const BX: Fe = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
];

/// Base-point y-coordinate (= 4/5).
pub(crate) const BY: Fe = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
];

/// sqrt(-1) = 2^((p-1)/4), the alternate root used in point decompression.
pub(crate) const SQRTM1: Fe = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];

/// One carry/reduce pass (radix-2^16 with the 2^256 ≡ 38 (mod p) fold).
pub(crate) fn carry(o: &mut Fe)
{
    // Each limb absorbs the previous limb's carry (`prev`); the top limb's carry
    // folds into limb 0 afterwards.
    let mut prev = 0i64;
    for limb in o.iter_mut()
    {
        let v = limb.wrapping_add(1 << 16).wrapping_add(prev);
        let c = v >> 16;
        *limb = v.wrapping_sub(c << 16);
        prev = c.wrapping_sub(1);
    }
    if let Some(first) = o.first_mut()
    {
        *first = first.wrapping_add(prev.wrapping_mul(38));
    }
}

/// Field addition (limb-wise; result left un-normalised).
pub(crate) fn add(o: &mut Fe, a: &Fe, b: &Fe)
{
    for ((o, a), b) in o.iter_mut().zip(a).zip(b)
    {
        *o = a.wrapping_add(*b);
    }
}

/// Field subtraction (limb-wise; result left un-normalised, may be negative).
pub(crate) fn sub(o: &mut Fe, a: &Fe, b: &Fe)
{
    for ((o, a), b) in o.iter_mut().zip(a).zip(b)
    {
        *o = a.wrapping_sub(*b);
    }
}

/// Field multiplication; limbs carried back to radix 2^16 (not canonical; `pack`
/// canonicalises).
pub(crate) fn mul(o: &mut Fe, a: &Fe, b: &Fe)
{
    let mut t = [0i64; 31];
    for (i, ai) in a.iter().enumerate()
    {
        for (tj, bj) in t.iter_mut().skip(i).zip(b)
        {
            *tj = tj.wrapping_add(ai.wrapping_mul(*bj));
        }
    }
    o[15] = t[15];
    for (oi, (lo, hi)) in o.iter_mut().zip(t.iter().zip(t.iter().skip(16)))
    {
        *oi = lo.wrapping_add(hi.wrapping_mul(38));
    }
    carry(o);
    carry(o);
}

/// Field squaring.
pub(crate) fn sqr(o: &mut Fe, a: &Fe)
{
    mul(o, a, a);
}

/// Multiplicative inverse via Fermat: a^(p-2). Returns 0 for input 0.
pub(crate) fn invert(o: &mut Fe, a: &Fe)
{
    let mut c = *a;
    for i in (0..=253).rev()
    {
        let t = c;
        sqr(&mut c, &t);
        if i != 2 && i != 4
        {
            let t = c;
            mul(&mut c, &t, a);
        }
    }
    *o = c;
}

/// Raise to (p-5)/8 — the square-root candidate exponent (RFC 8032 §5.1.3).
pub(crate) fn pow2523(o: &mut Fe, a: &Fe)
{
    let mut c = *a;
    for i in (0..=250).rev()
    {
        let t = c;
        sqr(&mut c, &t);
        if i != 1
        {
            let t = c;
            mul(&mut c, &t, a);
        }
    }
    *o = c;
}

/// Constant-shape conditional swap of `p` and `q` when `swap == 1`.
pub(crate) fn cswap(p: &mut Fe, q: &mut Fe, swap: u8)
{
    let mask = !(i64::from(swap).wrapping_sub(1));
    for (p, q) in p.iter_mut().zip(q.iter_mut())
    {
        let t = mask & (*p ^ *q);
        *p ^= t;
        *q ^= t;
    }
}

/// Encode a field element as 32 little-endian bytes (fully reduced).
pub(crate) fn pack(out: &mut [u8; 32], n: &Fe)
{
    let mut t = *n;
    carry(&mut t);
    carry(&mut t);
    carry(&mut t);
    // Two conditional subtractions of p bring t into the canonical range.
    for _ in 0..2
    {
        let mut m: Fe = [0; 16];
        // `prev` is the unmasked previous limb; its bit 16 is the borrow.
        let mut prev = t[0].wrapping_sub(0xffed);
        m[0] = prev & 0xffff;
        for (mi, ti) in m.iter_mut().zip(t.iter()).take(15).skip(1)
        {
            let cur = ti.wrapping_sub(0xffff).wrapping_sub((prev >> 16) & 1);
            *mi = cur & 0xffff;
            prev = cur;
        }
        m[15] = t[15].wrapping_sub(0x7fff).wrapping_sub((prev >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        cswap(&mut t, &mut m, 1u8.wrapping_sub(b as u8));
    }
    for (pair, ti) in out.as_chunks_mut::<2>().0.iter_mut().zip(t.iter())
    {
        *pair = [(ti & 0xff) as u8, ((ti >> 8) & 0xff) as u8];
    }
}

/// Decode 32 little-endian bytes into a field element, masking the top bit
/// (the sign bit, not field data).
pub(crate) fn unpack(o: &mut Fe, n: &[u8; 32])
{
    for (oi, pair) in o.iter_mut().zip(n.as_chunks::<2>().0)
    {
        *oi = i64::from(pair[0]).wrapping_add(i64::from(pair[1]) << 8);
    }
    o[15] &= 0x7fff;
}

/// Low bit of the canonical encoding (the `x_0` sign bit).
pub(crate) fn parity(a: &Fe) -> u8
{
    let mut d = [0u8; 32];
    pack(&mut d, a);
    d[0] & 1
}

/// Equality after canonical reduction.
pub(crate) fn eq(a: &Fe, b: &Fe) -> bool
{
    let mut da = [0u8; 32];
    let mut db = [0u8; 32];
    pack(&mut da, a);
    pack(&mut db, b);
    da == db
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn from_u64(v: u64) -> Fe
    {
        let mut f = GF0;
        f[0] = (v & 0xffff) as i64;
        f[1] = ((v >> 16) & 0xffff) as i64;
        f[2] = ((v >> 32) & 0xffff) as i64;
        f[3] = ((v >> 48) & 0xffff) as i64;
        f
    }

    #[test]
    fn inverse_roundtrip()
    {
        let a = from_u64(0x0123_4567_89ab_cdef);
        let mut inv = GF0;
        invert(&mut inv, &a);
        let mut prod = GF0;
        mul(&mut prod, &a, &inv);
        assert!(eq(&prod, &GF1));
    }

    #[test]
    fn mul_is_associative()
    {
        let a = from_u64(0xdead_beef);
        let b = from_u64(0x1234_5678_9abc);
        let c = from_u64(0xfeed_face_cafe);
        let (mut ab, mut bc, mut left, mut right) = (GF0, GF0, GF0, GF0);
        mul(&mut ab, &a, &b);
        mul(&mut left, &ab, &c);
        mul(&mut bc, &b, &c);
        mul(&mut right, &a, &bc);
        assert!(eq(&left, &right));
    }

    #[test]
    fn pack_unpack_roundtrip()
    {
        let a = from_u64(0x9e37_79b9_7f4a_7c15);
        let mut bytes = [0u8; 32];
        pack(&mut bytes, &a);
        let mut b = GF0;
        unpack(&mut b, &bytes);
        assert!(eq(&a, &b));
    }

    #[test]
    fn sqrt_minus_one_squares_to_minus_one()
    {
        let mut sq = GF0;
        sqr(&mut sq, &SQRTM1);
        let mut neg_one = GF0;
        sub(&mut neg_one, &GF0, &GF1);
        assert!(eq(&sq, &neg_one));
    }
}
