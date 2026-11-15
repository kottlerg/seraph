// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/generate/nat.rs

//! 256-bit unsigned integers and arithmetic modulo an odd prime, for the
//! curve arithmetic that builds the Ed25519 edge cases.
//!
//! Plain schoolbook code, chosen for being easy to check rather than fast: a
//! product is reduced by binary long division. Nothing here is constant
//! time, and nothing needs to be: it builds test inputs from public values.

use std::cmp::Ordering;

/// A 256-bit unsigned integer, as four 64-bit limbs, least significant
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256([u64; 4]);

impl U256
{
    /// 0.
    pub const ZERO: Self = Self([0; 4]);
    /// 1.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// The integer of 32 little-endian bytes.
    #[must_use]
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Self
    {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0)
        {
            *limb = u64::from_le_bytes(*chunk);
        }
        Self(limbs)
    }

    /// The integer as 32 little-endian bytes.
    #[must_use]
    pub fn to_le_bytes(self) -> [u8; 32]
    {
        let mut out = [0u8; 32];
        for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.0)
        {
            *chunk = limb.to_le_bytes();
        }
        out
    }

    /// The integer `value`.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self
    {
        Self([value, 0, 0, 0])
    }

    /// Bit `index`, 0 the least significant; false past bit 255.
    #[must_use]
    pub fn bit(self, index: usize) -> bool
    {
        self.0
            .get(index / 64)
            .is_some_and(|limb| (limb >> (index % 64)) & 1 == 1)
    }

    /// `self + other` modulo 2^256, and whether it carried out of bit 255.
    #[must_use]
    pub fn overflowing_add(self, other: Self) -> (Self, bool)
    {
        let mut out = [0u64; 4];
        let mut carry = false;
        for ((o, a), b) in out.iter_mut().zip(self.0).zip(other.0)
        {
            let (sum, c1) = a.overflowing_add(b);
            let (sum, c2) = sum.overflowing_add(u64::from(carry));
            *o = sum;
            carry = c1 || c2;
        }
        (Self(out), carry)
    }

    /// `self + other`, or `None` when it does not fit 256 bits.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self>
    {
        let (sum, carry) = self.overflowing_add(other);
        (!carry).then_some(sum)
    }

    /// `self - other` modulo 2^256.
    #[must_use]
    pub fn wrapping_sub(self, other: Self) -> Self
    {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for ((o, a), b) in out.iter_mut().zip(self.0).zip(other.0)
        {
            let (diff, b1) = a.overflowing_sub(b);
            let (diff, b2) = diff.overflowing_sub(u64::from(borrow));
            *o = diff;
            borrow = b1 || b2;
        }
        Self(out)
    }

    /// The 512-bit product, as eight limbs, least significant first.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "each limb keeps the low 64 bits of its column; the high 64 carry on"
    )]
    pub fn widening_mul(self, other: Self) -> [u64; 8]
    {
        let mut out = [0u64; 8];
        for (i, a) in self.0.iter().enumerate()
        {
            let mut carry = 0u128;
            for (j, b) in other.0.iter().enumerate()
            {
                // At most (2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1: no overflow.
                let t = u128::from(*a) * u128::from(*b) + u128::from(out[i + j]) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }
}

impl Ord for U256
{
    fn cmp(&self, other: &Self) -> Ordering
    {
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl PartialOrd for U256
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}

/// Arithmetic modulo an odd prime `m`: every operand is below `m`, and so is
/// every result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modulus(U256);

impl Modulus
{
    /// Arithmetic modulo `m`, an odd prime.
    #[must_use]
    pub const fn new(m: U256) -> Self
    {
        Self(m)
    }

    /// The modulus.
    #[must_use]
    pub const fn value(self) -> U256
    {
        self.0
    }

    /// The 512-bit integer `limbs` (least significant first) modulo `m`, by
    /// binary long division.
    #[must_use]
    pub fn reduce_wide(self, limbs: &[u64; 8]) -> U256
    {
        let mut r = U256::ZERO;
        for bit in (0..512).rev()
        {
            // r < m, so 2r + 1 < 2m and one subtraction brings it below m;
            // a carry out of bit 255 stands for the 2^256 the subtraction
            // wraps away.
            let (doubled, carry) = r.overflowing_add(r);
            let next = (limbs[bit / 64] >> (bit % 64)) & 1;
            let (shifted, _) = doubled.overflowing_add(U256::from_u64(next));
            r = if carry || shifted >= self.0
            {
                shifted.wrapping_sub(self.0)
            }
            else
            {
                shifted
            };
        }
        r
    }

    /// The integer of 64 little-endian bytes, modulo `m`.
    #[must_use]
    pub fn reduce_le_bytes(self, bytes: &[u8; 64]) -> U256
    {
        let mut limbs = [0u64; 8];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0)
        {
            *limb = u64::from_le_bytes(*chunk);
        }
        self.reduce_wide(&limbs)
    }

    /// `value` modulo `m`, for any 256-bit `value`.
    #[must_use]
    pub fn reduce(self, value: U256) -> U256
    {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&value.to_le_bytes());
        self.reduce_le_bytes(&bytes)
    }

    /// `a + b mod m`.
    #[must_use]
    pub fn add(self, a: U256, b: U256) -> U256
    {
        let (sum, carry) = a.overflowing_add(b);
        if carry || sum >= self.0
        {
            sum.wrapping_sub(self.0)
        }
        else
        {
            sum
        }
    }

    /// `a - b mod m`.
    #[must_use]
    pub fn sub(self, a: U256, b: U256) -> U256
    {
        let diff = a.wrapping_sub(b);
        if a >= b
        {
            diff
        }
        else
        {
            diff.overflowing_add(self.0).0
        }
    }

    /// `a * b mod m`.
    #[must_use]
    pub fn mul(self, a: U256, b: U256) -> U256
    {
        self.reduce_wide(&a.widening_mul(b))
    }

    /// `base ^ exponent mod m`.
    #[must_use]
    pub fn pow(self, base: U256, exponent: U256) -> U256
    {
        let mut result = U256::ONE;
        for bit in (0..256).rev()
        {
            result = self.mul(result, result);
            if exponent.bit(bit)
            {
                result = self.mul(result, base);
            }
        }
        result
    }

    /// `1 / a mod m`, by Fermat's little theorem; 0 for `a` = 0.
    #[must_use]
    pub fn inv(self, a: U256) -> U256
    {
        self.pow(a, self.0.wrapping_sub(U256::from_u64(2)))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::rng::Rng;

    /// The prime 2^61 - 1, small enough that u128 arithmetic checks every
    /// result.
    const M61: u64 = (1 << 61) - 1;

    #[test]
    fn modular_arithmetic_agrees_with_u128_arithmetic()
    {
        let modulus = Modulus::new(U256::from_u64(M61));
        let wide = u128::from(M61);
        let residue = |v: u128| U256::from_u64(u64::try_from(v % wide).unwrap());
        let mut rng = Rng::new(61);
        for _ in 0..200
        {
            let (left, right) = (rng.next_u64() % M61, rng.next_u64() % M61);
            let (big_left, big_right) = (U256::from_u64(left), U256::from_u64(right));
            let (left, right) = (u128::from(left), u128::from(right));
            assert_eq!(modulus.add(big_left, big_right), residue(left + right));
            assert_eq!(
                modulus.sub(big_left, big_right),
                residue(left + wide - right)
            );
            assert_eq!(modulus.mul(big_left, big_right), residue(left * right));
            assert_eq!(
                modulus.pow(big_left, U256::from_u64(3)),
                residue(left * left % wide * left)
            );
            if left != 0
            {
                assert_eq!(modulus.mul(big_left, modulus.inv(big_left)), U256::ONE);
            }
        }
    }

    #[test]
    fn full_width_values_reduce_to_their_residues()
    {
        // p = 2^255 - 19: (p - 1)^2 = 1, 2^256 = 38 and 2^256 - 1 = 37 mod p.
        let mut bytes = [0xffu8; 32];
        bytes[0] = 0xed;
        bytes[31] = 0x7f;
        let p = Modulus::new(U256::from_le_bytes(&bytes));
        let minus_one = p.value().wrapping_sub(U256::ONE);
        assert_eq!(p.mul(minus_one, minus_one), U256::ONE);
        let mut two_256 = [0u8; 64];
        two_256[32] = 1;
        assert_eq!(p.reduce_le_bytes(&two_256), U256::from_u64(38));
        assert_eq!(
            p.reduce(U256::from_le_bytes(&[0xff; 32])),
            U256::from_u64(37)
        );
        assert_eq!(p.sub(U256::ZERO, U256::ONE), minus_one);
        assert_eq!(p.add(minus_one, U256::from_u64(2)), U256::ONE);
    }

    #[test]
    fn integers_round_trip_through_bytes_and_compare_by_magnitude()
    {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate()
        {
            *b = u8::try_from(i).unwrap();
        }
        let n = U256::from_le_bytes(&bytes);
        assert_eq!(n.to_le_bytes(), bytes);
        let mut high = [0u8; 32];
        high[31] = 1;
        assert!(U256::from_le_bytes(&high) > U256::from_u64(u64::MAX));
        assert!(U256::from_le_bytes(&high).bit(248));
        assert_eq!(
            U256::from_le_bytes(&[0xff; 32]).checked_add(U256::ONE),
            None
        );
        assert_eq!(
            U256::ONE.wrapping_sub(U256::from_u64(2)),
            U256::from_le_bytes(&[0xff; 32])
        );
    }
}
