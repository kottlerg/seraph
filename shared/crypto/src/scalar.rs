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
    let mut i = 31i32;
    while i >= 0
    {
        let idx = i as usize;
        if s[idx] < L[idx]
        {
            return true;
        }
        if s[idx] > L[idx]
        {
            return false;
        }
        i -= 1;
    }
    // s == L exactly: not canonical.
    false
}

/// Reduce a 64-byte little-endian value mod L into a 32-byte scalar.
pub(crate) fn reduce_512(h: &[u8; 64]) -> [u8; 32]
{
    let mut x = [0i64; 64];
    let mut i = 0;
    while i < 64
    {
        x[i] = i64::from(h[i]);
        i += 1;
    }
    let mut r = [0u8; 32];
    mod_l(&mut r, &mut x);
    r
}

/// Barrett-style folding of the high half into the low half, then two
/// conditional subtractions of L. Operates in signed radix-2^8 limbs.
fn mod_l(r: &mut [u8; 32], x: &mut [i64; 64])
{
    let mut i = 63usize;
    while i >= 32
    {
        let mut carry = 0i64;
        let base = i - 32;
        let mut j = base;
        while j < i - 12
        {
            x[j] += carry - 16 * x[i] * i64::from(L[j - base]);
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        // j == i - 12 here.
        x[j] += carry;
        x[i] = 0;
        i -= 1;
    }

    let mut carry = 0i64;
    let mut j = 0;
    while j < 32
    {
        x[j] += carry - (x[31] >> 4) * i64::from(L[j]);
        carry = x[j] >> 8;
        x[j] &= 255;
        j += 1;
    }
    let mut j = 0;
    while j < 32
    {
        x[j] -= carry * i64::from(L[j]);
        j += 1;
    }
    let mut i = 0;
    while i < 32
    {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
        i += 1;
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
