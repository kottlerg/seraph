// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/generate/edwards.rs

//! The edwards25519 group (RFC 8032 § 5.1): points in extended coordinates,
//! their sum and scalar multiples, and their encodings; and the scalars
//! modulo the group order L.
//!
//! The generator builds the Ed25519 edge cases with it (torsion points,
//! mixed-order keys, crafted signatures) and names a rejection reason with
//! [`decode`]. It is independent of `shared/crypto` and is not the reference:
//! OpenSSL judges every signature.

use super::nat::{Modulus, U256};

/// p = 2^255 - 19, little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The group order L = 2^252 + 27742317777372353535851937790883648493,
/// little-endian.
pub const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// 2d, d = -121665 / 121666 mod p the curve constant, little-endian.
const D2: [u8; 32] = [
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24,
];

/// d, little-endian.
const D: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// A square root of -1 mod p, 2^((p - 1) / 4), little-endian.
const SQRT_M1: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// (p + 3) / 8, the exponent of a square root candidate, little-endian.
const SQRT_EXPONENT: [u8; 32] = [
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

/// The base point B's x, little-endian.
const BASE_X: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

/// The base point B's y = 4/5, little-endian.
const BASE_Y: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The canonical encoding of a point of order 8; its multiples are the
/// whole torsion subgroup.
pub const ORDER_8: [u8; 32] = [
    0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
    0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
];

/// Arithmetic modulo p.
fn fp() -> Modulus
{
    Modulus::new(U256::from_le_bytes(&P))
}

/// Arithmetic modulo L.
#[must_use]
pub fn scalars() -> Modulus
{
    Modulus::new(U256::from_le_bytes(&L))
}

/// A point of edwards25519 in extended coordinates (X : Y : Z : T), x = X/Z,
/// y = Y/Z, xy = T/Z.
#[derive(Debug, Clone, Copy)]
pub struct Point
{
    x: U256,
    y: U256,
    z: U256,
    t: U256,
}

impl PartialEq for Point
{
    /// Equal when they are the same point, whatever their Z.
    fn eq(&self, other: &Self) -> bool
    {
        let fe = fp();
        fe.mul(self.x, other.z) == fe.mul(other.x, self.z)
            && fe.mul(self.y, other.z) == fe.mul(other.y, self.z)
    }
}

impl Eq for Point {}

impl Point
{
    /// The neutral element O, (0, 1).
    #[must_use]
    pub const fn identity() -> Self
    {
        Self {
            x: U256::ZERO,
            y: U256::ONE,
            z: U256::ONE,
            t: U256::ZERO,
        }
    }

    /// The point (x, y), which the caller has checked is on the curve.
    fn affine(x: U256, y: U256) -> Self
    {
        Self {
            x,
            y,
            z: U256::ONE,
            t: fp().mul(x, y),
        }
    }

    /// The base point B.
    #[must_use]
    pub fn base() -> Self
    {
        Self::affine(U256::from_le_bytes(&BASE_X), U256::from_le_bytes(&BASE_Y))
    }

    /// `self + other`, by the unified formula for a = -1 (Hisil, Wong,
    /// Carter and Dawson, 2008), complete on edwards25519 since d is not a
    /// square: it doubles a point too.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self
    {
        // The formula's A, B, C, D, E, F, G and H.
        let fe = fp();
        let aa = fe.mul(fe.sub(self.y, self.x), fe.sub(other.y, other.x));
        let bb = fe.mul(fe.add(self.y, self.x), fe.add(other.y, other.x));
        let cc = fe.mul(fe.mul(self.t, U256::from_le_bytes(&D2)), other.t);
        let zz = fe.mul(self.z, other.z);
        let dd = fe.add(zz, zz);
        let (ee, ff, gg, hh) = (
            fe.sub(bb, aa),
            fe.sub(dd, cc),
            fe.add(dd, cc),
            fe.add(bb, aa),
        );
        Self {
            x: fe.mul(ee, ff),
            y: fe.mul(gg, hh),
            z: fe.mul(ff, gg),
            t: fe.mul(ee, hh),
        }
    }

    /// `[k]self`.
    #[must_use]
    pub fn mul(&self, k: U256) -> Self
    {
        let mut result = Self::identity();
        for bit in (0..256).rev()
        {
            result = result.add(&result);
            if k.bit(bit)
            {
                result = result.add(self);
            }
        }
        result
    }

    /// The canonical encoding: y, with the low bit of x in bit 255.
    #[must_use]
    pub fn encode(&self) -> [u8; 32]
    {
        let fe = fp();
        let z_inv = fe.inv(self.z);
        let x = fe.mul(self.x, z_inv).to_le_bytes();
        let mut out = fe.mul(self.y, z_inv).to_le_bytes();
        out[31] |= (x[0] & 1) << 7;
        out
    }
}

/// The point a canonical encoding names; `None` for every other encoding: a
/// y at or above p, a y with no x on the curve, or x = 0 with the sign bit
/// set (RFC 8032 § 5.1.3).
#[must_use]
pub fn decode(encoding: &[u8; 32]) -> Option<Point>
{
    let fe = fp();
    let sign = encoding[31] >> 7;
    let mut y_bytes = *encoding;
    y_bytes[31] &= 0x7f;
    let y = U256::from_le_bytes(&y_bytes);
    if y >= fe.value()
    {
        return None;
    }
    // x^2 = (y^2 - 1) / (d y^2 + 1).
    let yy = fe.mul(y, y);
    let numerator = fe.sub(yy, U256::ONE);
    let denominator = fe.add(fe.mul(U256::from_le_bytes(&D), yy), U256::ONE);
    let xx = fe.mul(numerator, fe.inv(denominator));
    let mut x = fe.pow(xx, U256::from_le_bytes(&SQRT_EXPONENT));
    if fe.mul(x, x) != xx
    {
        x = fe.mul(x, U256::from_le_bytes(&SQRT_M1));
    }
    if fe.mul(x, x) != xx || (x == U256::ZERO && sign == 1)
    {
        return None;
    }
    if (x.to_le_bytes()[0] & 1) != sign
    {
        x = fe.sub(U256::ZERO, x);
    }
    Some(Point::affine(x, y))
}

/// The eight points of the torsion subgroup, the identity first: the
/// multiples of the point [`ORDER_8`] encodes.
#[must_use]
pub fn torsion() -> Vec<Point>
{
    let Some(generator) = decode(&ORDER_8)
    else
    {
        return Vec::new();
    };
    let mut points = vec![Point::identity()];
    for _ in 1..8
    {
        let next = points[points.len() - 1].add(&generator);
        points.push(next);
    }
    points
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_base_point_has_order_l_and_encodes_to_its_standard_encoding()
    {
        let base = Point::base();
        assert_eq!(base.mul(U256::from_le_bytes(&L)), Point::identity());
        assert_ne!(base.mul(U256::from_u64(8)), Point::identity());
        assert_eq!(base.encode(), BASE_Y);
        assert_eq!(decode(&base.encode()), Some(base));
        assert_eq!(base.add(&base), base.mul(U256::from_u64(2)));
    }

    #[test]
    fn a_secret_scalar_multiplies_the_base_to_its_rfc_8032_public_key()
    {
        // RFC 8032 § 7.1, TEST 1: the clamped scalar of the secret key
        // 9d61...7f60, and the public key d75a...511a.
        let scalar =
            crate::hex::decode("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f")
                .unwrap();
        let public = Point::base().mul(U256::from_le_bytes(&scalar.try_into().unwrap()));
        assert_eq!(
            crate::hex::encode(&public.encode()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    #[test]
    fn torsion_is_eight_distinct_points_of_order_dividing_eight()
    {
        let points = torsion();
        assert_eq!(points.len(), 8);
        for (i, p) in points.iter().enumerate()
        {
            assert_eq!(p.mul(U256::from_u64(8)), Point::identity());
            assert!(points[..i].iter().all(|q| q != p), "torsion {i} repeats");
        }
        assert_ne!(points[1].mul(U256::from_u64(4)), Point::identity());
    }

    #[test]
    fn decode_refuses_every_non_canonical_encoding()
    {
        // y = p, y = p + 1 (the identity's y plus p), y = 2 (no x), and the
        // identity with the sign bit set.
        let mut p = P;
        assert_eq!(decode(&p), None);
        p[0] += 1;
        assert_eq!(decode(&p), None);
        let mut no_x = [0u8; 32];
        no_x[0] = 2;
        assert_eq!(decode(&no_x), None);
        let mut identity = Point::identity().encode();
        assert_eq!(decode(&identity), Some(Point::identity()));
        identity[31] |= 0x80;
        assert_eq!(decode(&identity), None);
    }
}
