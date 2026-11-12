// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/scalar.rs

//! Arithmetic modulo the Ed25519 group order
//! L = 2^252 + 27742317777372353535851937790883648493.
//!
//! Two operations suffice for verification: the canonical range check on the
//! signature scalar S (RFC 8032 §5.1.7) and reduction of the 64-byte hash
//! `SHA512(R‖A‖M)` to a scalar mod L. Both treat scalars as little-endian.

// Reduction works in signed limbs and casts back to bytes after masking.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]

/// L in little-endian bytes (32 bytes; the top limb is 0x10).
pub(crate) const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// True iff the little-endian scalar `s` is strictly less than L.
///
/// Mandatory before verification (RFC 8032 §5.1.7): S must lie in `{0, …,
/// L-1}`. `s == L` and anything larger is rejected, blocking signature
/// malleability.
pub(crate) fn is_canonical(s: &[u8; 32]) -> bool
{
    for (sb, lb) in s.iter().zip(L.iter()).rev()
    {
        if sb < lb
        {
            return true;
        }
        if sb > lb
        {
            return false;
        }
    }
    // s == L exactly: not canonical.
    false
}

/// Reduce a 64-byte little-endian value mod L into a 32-byte scalar.
pub(crate) fn reduce_512(h: &[u8; 64]) -> [u8; 32]
{
    let mut x = [0i64; 64];
    for (xi, hi) in x.iter_mut().zip(h)
    {
        *xi = i64::from(*hi);
    }
    let mut r = [0u8; 32];
    mod_l(&mut r, &mut x);
    r
}

/// Reduce mod L the `TweetNaCl` `modL` way: fold each high byte down by
/// subtracting the matching multiple of L, then subtract the residual quotient
/// multiples of L twice. Operates in signed radix-2^8 limbs.
fn mod_l(r: &mut [u8; 32], x: &mut [i64; 64])
{
    for base in (0..32usize).rev()
    {
        let hi = base.wrapping_add(32);
        let mut carry = 0i64;
        let xi = x.get(hi).copied().unwrap_or(0);
        // Limbs `base` .. `hi` - 12 absorb x[hi] times L; the next limb takes the final carry.
        let mut limbs = x.iter_mut().skip(base);
        for (xj, lj) in limbs.by_ref().take(20).zip(L.iter())
        {
            let prod = 16i64.wrapping_mul(xi).wrapping_mul(i64::from(*lj));
            *xj = xj.wrapping_add(carry.wrapping_sub(prod));
            carry = xj.wrapping_add(128) >> 8;
            *xj = xj.wrapping_sub(carry << 8);
        }
        if let Some(xj) = limbs.next()
        {
            *xj = xj.wrapping_add(carry);
        }
        if let Some(xi) = x.get_mut(hi)
        {
            *xi = 0;
        }
    }

    let top = x[31];
    let mut carry = 0i64;
    for (xj, lj) in x.iter_mut().zip(L.iter()).take(32)
    {
        *xj = xj.wrapping_add(carry.wrapping_sub((top >> 4).wrapping_mul(i64::from(*lj))));
        carry = *xj >> 8;
        *xj &= 255;
    }
    for (xj, lj) in x.iter_mut().zip(L.iter())
    {
        *xj = xj.wrapping_sub(carry.wrapping_mul(i64::from(*lj)));
    }
    let mut carry_in = 0i64;
    for (xi, ri) in x.iter_mut().zip(r.iter_mut())
    {
        let v = xi.wrapping_add(carry_in);
        carry_in = v >> 8;
        *ri = (v & 255) as u8;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn canonical_boundaries()
    {
        assert!(is_canonical(&[0u8; 32]));

        let mut l_minus_1 = L;
        l_minus_1[0] -= 1;
        assert!(is_canonical(&l_minus_1));

        // S == L must be rejected.
        assert!(!is_canonical(&L));

        // S > L must be rejected.
        let mut too_big = L;
        too_big[31] += 1;
        assert!(!is_canonical(&too_big));
    }

    #[test]
    fn reduce_passes_through_small_scalar()
    {
        // A value below L (top byte 0) reduces to itself.
        let mut v = [0u8; 32];
        let mut i = 0;
        while i < 31
        {
            v[i] = (i as u8).wrapping_mul(7).wrapping_add(3);
            i += 1;
        }
        v[31] = 0x00;
        let mut h = [0u8; 64];
        h[..32].copy_from_slice(&v);
        assert_eq!(reduce_512(&h), v);
    }

    #[test]
    fn reduce_of_l_is_zero()
    {
        let mut h = [0u8; 64];
        h[..32].copy_from_slice(&L);
        assert_eq!(reduce_512(&h), [0u8; 32]);
    }
}
