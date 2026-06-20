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
    let mut i = 0;
    while i < 16
    {
        o[i] += 1 << 16;
        let c = o[i] >> 16;
        if i < 15
        {
            o[i + 1] += c - 1;
        }
        else
        {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
        i += 1;
    }
}

/// Field addition (limb-wise; result left un-normalised).
pub(crate) fn add(o: &mut Fe, a: &Fe, b: &Fe)
{
    let mut i = 0;
    while i < 16
    {
        o[i] = a[i] + b[i];
        i += 1;
    }
}

/// Field subtraction (limb-wise; result left un-normalised, may be negative).
pub(crate) fn sub(o: &mut Fe, a: &Fe, b: &Fe)
{
    let mut i = 0;
    while i < 16
    {
        o[i] = a[i] - b[i];
        i += 1;
    }
}

/// Field multiplication, fully reduced.
pub(crate) fn mul(o: &mut Fe, a: &Fe, b: &Fe)
{
    let mut t = [0i64; 31];
    let mut i = 0;
    while i < 16
    {
        let mut j = 0;
        while j < 16
        {
            t[i + j] += a[i] * b[j];
            j += 1;
        }
        i += 1;
    }
    let mut i = 0;
    while i < 15
    {
        t[i] += 38 * t[i + 16];
        i += 1;
    }
    o.copy_from_slice(&t[..16]);
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
    let mut i = 253i32;
    while i >= 0
    {
        let t = c;
        sqr(&mut c, &t);
        if i != 2 && i != 4
        {
            let t = c;
            mul(&mut c, &t, a);
        }
        i -= 1;
    }
    *o = c;
}

/// Raise to (p-5)/8 — the square-root candidate exponent (RFC 8032 §5.1.3).
pub(crate) fn pow2523(o: &mut Fe, a: &Fe)
{
    let mut c = *a;
    let mut i = 250i32;
    while i >= 0
    {
        let t = c;
        sqr(&mut c, &t);
        if i != 1
        {
            let t = c;
            mul(&mut c, &t, a);
        }
        i -= 1;
    }
    *o = c;
}

/// Constant-shape conditional swap of `p` and `q` when `swap == 1`.
pub(crate) fn cswap(p: &mut Fe, q: &mut Fe, swap: u8)
{
    let mask = !(i64::from(swap) - 1);
    let mut i = 0;
    while i < 16
    {
        let t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
        i += 1;
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
    let mut round = 0;
    while round < 2
    {
        let mut m: Fe = [0; 16];
        m[0] = t[0] - 0xffed;
        let mut i = 1;
        while i < 15
        {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
            i += 1;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        cswap(&mut t, &mut m, (1 - b) as u8);
        round += 1;
    }
    let mut i = 0;
    while i < 16
    {
        out[2 * i] = (t[i] & 0xff) as u8;
        out[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
        i += 1;
    }
}

/// Decode 32 little-endian bytes into a field element, masking the top bit
/// (the sign bit, not field data).
pub(crate) fn unpack(o: &mut Fe, n: &[u8; 32])
{
    let mut i = 0;
    while i < 16
    {
        o[i] = i64::from(n[2 * i]) + (i64::from(n[2 * i + 1]) << 8);
        i += 1;
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
