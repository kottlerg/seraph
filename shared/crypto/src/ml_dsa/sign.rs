// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/sign.rs

//! ML-DSA key generation and signing from a 32-byte seed (FIPS 204
//! Algorithms 1, 2, 6 and 7), deterministic (rnd = 0^32, FIPS 204 § 3.4).
//!
//! Compiled only with the crate's `sign` feature and in its own tests, like
//! the Ed25519 signer: no component built for the target compiles it. A key is
//! the seed xi; [`public_key`] and [`sign`] expand it on every call
//! (`KeyGen_internal`), so nothing is kept between calls.
//!
//! Timing. No branch and no memory index depends on the seed or on a value
//! derived from it, apart from the rejection sampling of the secret vectors
//! ([`super::sample`] states what that reveals). The transform, the
//! reductions, `Power2Round`, Decompose, `MakeHint` and the mask's unpacking are
//! branch-free arithmetic ([`super::poly`], [`super::rounding`]). Each attempt
//! of the rejection loop computes all four of its bounds (on z, on the low
//! bits of w - c s2, on c t0 and on the number of hints) as masks and branches
//! once on the combined verdict, so a rejected attempt reveals that it was
//! rejected and nothing of which bound failed or where; its hints are counted,
//! never packed. The commitment w1, c-tilde and the challenge c are functions
//! of the mask's image A y, which the secret does not enter, and the signature
//! publishes them for the accepted attempt. No secret is wiped after use: the
//! caller holds the seed.

use super::encode::{pack, pack_hints};
use super::params::{
    BETA, CTILDE_LEN, GAMMA1, GAMMA2, HINT_LEN, K, L, MAX_CONTEXT_LEN, N, OMEGA, POLY_T1_LEN,
    POLY_W1_LEN, POLY_Z_LEN, PUBLIC_KEY_LEN, RHO_LEN, SEED_LEN, SIGNATURE_LEN, T1_BITS, TR_LEN,
    W1_BITS, Z_BITS,
};
use super::poly::{Poly, ZERO, caddq, centre, freeze, inv_ntt, map, ntt, pointwise, reduce32};
use super::rounding::{high_bits, low_bits, make_hint, power2round};
use super::sample::{expand_mask, mul_acc_matrix_entry, rej_bounded_poly, sample_in_ball};
use crate::shake::Shake256;

/// Why [`sign`] refused to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError
{
    /// The context string is longer than [`MAX_CONTEXT_LEN`] bytes (FIPS 204
    /// Algorithm 2).
    ContextTooLong,
}

/// The expanded secret key: what skDecode (FIPS 204 Algorithm 25) returns,
/// with s1, s2 and t0 transformed once for the signing loop.
pub(crate) struct ExpandedKey
{
    pub(crate) rho: [u8; RHO_LEN],
    pub(crate) key: [u8; 32],
    pub(crate) tr: [u8; TR_LEN],
    pub(crate) s1_hat: [Poly; L],
    pub(crate) s2_hat: [Poly; K],
    pub(crate) t0_hat: [Poly; K],
}

/// The public key of a 32-byte secret seed (ML-DSA.KeyGen_internal, FIPS 204
/// Algorithm 6).
#[expect(
    clippy::large_stack_frames,
    reason = "the expanded key (17 KiB) that the public key is derived with is on the stack of the host thread that signs: \
              the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
#[must_use]
pub fn public_key(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN]
{
    let mut public_key = [0u8; PUBLIC_KEY_LEN];
    expand_key(seed, &mut public_key);
    public_key
}

/// The deterministic signature of `message` with context string `context`
/// under the key of a 32-byte secret seed (ML-DSA.Sign, FIPS 204
/// Algorithm 2, with rnd = 0^32: the pure form, message representative over
/// 0 || |ctx| || ctx || M).
///
/// # Errors
///
/// [`SignError::ContextTooLong`]: `context` is longer than
/// [`MAX_CONTEXT_LEN`] bytes.
#[expect(
    clippy::large_stack_frames,
    reason = "the expanded key (17 KiB) and the public key are on the stack of the host thread that signs: \
              the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
pub fn sign(
    seed: &[u8; SEED_LEN],
    message: &[u8],
    context: &[u8],
) -> Result<[u8; SIGNATURE_LEN], SignError>
{
    if context.len() > MAX_CONTEXT_LEN
    {
        return Err(SignError::ContextTooLong);
    }
    let [context_len, ..] = context.len().to_le_bytes();
    let mut public_key = [0u8; PUBLIC_KEY_LEN];
    let key = expand_key(seed, &mut public_key);
    let mu =
        super::verify::message_representative(&public_key, &[&[0, context_len], context, message]);
    Ok(sign_mu(&key, &mu, &[0; 32]))
}

/// `KeyGen_internal` (FIPS 204 Algorithm 6): writes the public key and returns
/// the expanded secret key.
#[expect(
    clippy::large_stack_frames,
    reason = "the expanded key (17 polynomials, 17 KiB) and t's working row are on the stack \
              of the host thread that signs: the signer is compiled for the build host only \
              (the sign feature), whose threads have 2 MiB"
)]
pub(crate) fn expand_key(
    seed: &[u8; SEED_LEN],
    public_key: &mut [u8; PUBLIC_KEY_LEN],
) -> ExpandedKey
{
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&[K.to_le_bytes()[0], L.to_le_bytes()[0]]);
    let mut reader = xof.finalize();
    let mut rho = [0u8; RHO_LEN];
    let mut rho_prime = [0u8; 64];
    let mut key = [0u8; 32];
    reader.read(&mut rho);
    reader.read(&mut rho_prime);
    reader.read(&mut key);

    let mut expanded = ExpandedKey {
        rho,
        key,
        tr: [0; TR_LEN],
        s1_hat: [ZERO; L],
        s2_hat: [ZERO; K],
        t0_hat: [ZERO; K],
    };
    for (s1, nonce) in expanded.s1_hat.iter_mut().zip(0u16..)
    {
        *s1 = rej_bounded_poly(&rho_prime, nonce);
        ntt(s1);
    }

    let (rho_out, t1_out) = public_key.split_at_mut(RHO_LEN);
    rho_out.copy_from_slice(&rho);
    let t1_rows = t1_out.as_chunks_mut::<POLY_T1_LEN>().0;
    let rows = expanded
        .s2_hat
        .iter_mut()
        .zip(expanded.t0_hat.iter_mut())
        .zip(t1_rows);
    for (((s2_hat, t0_hat), t1_row), (row, nonce)) in rows.zip((0u8..).zip(0u16..))
    {
        // t = NTT^-1(A NTT(s1)) + s2, row by row.
        let s2 = rej_bounded_poly(&rho_prime, nonce.wrapping_add(L.to_le_bytes()[0].into()));
        let mut t = ZERO;
        for (col, s1_hat) in (0u8..).zip(&expanded.s1_hat)
        {
            mul_acc_matrix_entry(&rho, row, col, s1_hat, &mut t);
        }
        map(&mut t, reduce32);
        inv_ntt(&mut t);
        for (c, s) in t.iter_mut().zip(&s2)
        {
            *c = freeze(c.wrapping_add(*s));
        }
        // (t1, t0) = Power2Round(t).
        let mut t1 = ZERO;
        for ((c, high), low) in t.iter().zip(t1.iter_mut()).zip(t0_hat.iter_mut())
        {
            (*high, *low) = power2round(*c);
        }
        pack(t1, T1_BITS, t1_row);
        ntt(t0_hat);
        *s2_hat = s2;
        ntt(s2_hat);
    }
    crate::shake::shake256(public_key, &mut expanded.tr);
    expanded
}

/// `Sign_internal` (FIPS 204 Algorithm 7) from the message representative mu
/// and the 32 bytes rnd (zero for deterministic signing).
#[expect(
    clippy::large_stack_frames,
    reason = "the signature each attempt returns (3.3 KiB) is on the stack of the host thread that signs: \
              the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
pub(crate) fn sign_mu(key: &ExpandedKey, mu: &[u8; TR_LEN], rnd: &[u8; 32]) -> [u8; SIGNATURE_LEN]
{
    let mut xof = Shake256::new();
    xof.update(&key.key);
    xof.update(rnd);
    xof.update(mu);
    let mut rho_second = [0u8; 64];
    xof.finalize().read(&mut rho_second);

    let mut kappa: u16 = 0;
    loop
    {
        if let Some(signature) = attempt(key, mu, &rho_second, kappa)
        {
            return signature;
        }
        kappa = kappa.wrapping_add(L.to_le_bytes()[0].into());
    }
}

/// 1 when |a| >= bound, 0 otherwise, without a branch, for a centred a and a
/// positive bound below 2^30.
fn exceeds(a: i32, bound: i32) -> i32
{
    let sign = a.wrapping_shr(31);
    let magnitude = a.wrapping_sub(sign & a.wrapping_mul(2));
    bound
        .wrapping_sub(1)
        .wrapping_sub(magnitude)
        .wrapping_shr(31)
        & 1
}

/// The working vectors of one attempt.
struct Attempt
{
    y_hat: [Poly; L],
    w: [Poly; K],
    z: [Poly; L],
    hints: [[u8; N]; K],
}

/// One iteration of `Sign_internal`'s loop (FIPS 204 Algorithm 7, lines 11 to
/// 31) with counter kappa: the signature, or `None` when a bound rejects it.
#[expect(
    clippy::large_stack_frames,
    reason = "an attempt's vectors y, w, z and the hints (17.5 KiB) are on the stack of the host \
              thread that signs: the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
fn attempt(
    key: &ExpandedKey,
    mu: &[u8; TR_LEN],
    rho_second: &[u8; 64],
    kappa: u16,
) -> Option<[u8; SIGNATURE_LEN]>
{
    let mut work = Attempt {
        y_hat: [ZERO; L],
        w: [ZERO; K],
        z: [ZERO; L],
        hints: [[0; N]; K],
    };
    for (y_hat, nonce) in work.y_hat.iter_mut().zip(kappa..)
    {
        *y_hat = expand_mask(rho_second, nonce);
        ntt(y_hat);
    }

    // w = NTT^-1(A NTT(y)), and c-tilde = H(mu || w1Encode(HighBits(w))).
    let mut xof = Shake256::new();
    xof.update(mu);
    let mut w1_packed = [0u8; POLY_W1_LEN];
    for (w, row) in work.w.iter_mut().zip(0u8..)
    {
        for (col, y_hat) in (0u8..).zip(&work.y_hat)
        {
            mul_acc_matrix_entry(&key.rho, row, col, y_hat, w);
        }
        map(w, reduce32);
        inv_ntt(w);
        map(w, caddq);
        pack(w.iter().map(|&c| high_bits(c)), W1_BITS, &mut w1_packed);
        xof.update(&w1_packed);
    }
    let mut ctilde = [0u8; CTILDE_LEN];
    xof.finalize().read(&mut ctilde);
    let mut c_hat = sample_in_ball(&ctilde);
    ntt(&mut c_hat);

    // z = y + c s1, bounded by GAMMA1 - BETA.
    let mut rejected = 0;
    for ((z, s1_hat), nonce) in work.z.iter_mut().zip(&key.s1_hat).zip(kappa..)
    {
        let mut cs1 = pointwise(&c_hat, s1_hat);
        inv_ntt(&mut cs1);
        let y = expand_mask(rho_second, nonce);
        for ((c, y), cs1) in z.iter_mut().zip(&y).zip(&cs1)
        {
            *c = y.wrapping_add(centre(*cs1));
            rejected |= exceeds(*c, GAMMA1 - BETA);
        }
    }

    // The low bits of w - c s2, c t0, and the hints MakeHint(-c t0, w - c s2 + c t0).
    let mut hint_count: i32 = 0;
    let rows = work
        .w
        .iter()
        .zip(&key.s2_hat)
        .zip(&key.t0_hat)
        .zip(work.hints.iter_mut());
    for (((w, s2_hat), t0_hat), hints) in rows
    {
        let mut cs2 = pointwise(&c_hat, s2_hat);
        inv_ntt(&mut cs2);
        let mut ct0 = pointwise(&c_hat, t0_hat);
        inv_ntt(&mut ct0);
        for (((w, cs2), ct0), hint) in w.iter().zip(&cs2).zip(&ct0).zip(hints.iter_mut())
        {
            let r = freeze(w.wrapping_sub(*cs2));
            let ct0 = centre(*ct0);
            rejected |= exceeds(low_bits(r), GAMMA2 - BETA);
            rejected |= exceeds(ct0, GAMMA2);
            let bit = make_hint(r, freeze(r.wrapping_add(ct0)));
            hint_count = hint_count.wrapping_add(bit);
            let [low, ..] = bit.to_le_bytes();
            *hint = low;
        }
    }
    rejected |= exceeds(
        hint_count,
        i32::from(OMEGA.to_le_bytes()[0]).wrapping_add(1),
    );

    if rejected != 0
    {
        return None;
    }
    Some(encode_signature(&ctilde, &work.z, &work.hints))
}

/// `sigEncode` (FIPS 204 Algorithm 26) of an accepted attempt.
#[expect(
    clippy::large_stack_frames,
    reason = "the signature (3.3 KiB) is on the stack of the host thread that signs: \
              the signer is compiled for the build host only (the sign \
              feature), whose threads have 2 MiB"
)]
fn encode_signature(
    ctilde: &[u8; CTILDE_LEN],
    z: &[Poly; L],
    hints: &[[u8; N]; K],
) -> [u8; SIGNATURE_LEN]
{
    let mut out = [0u8; SIGNATURE_LEN];
    let (ctilde_out, rest) = out.split_at_mut(CTILDE_LEN);
    ctilde_out.copy_from_slice(ctilde);
    let (z_out, hint_out) = rest.split_at_mut(L * POLY_Z_LEN);
    for (z, packed) in z.iter().zip(z_out.as_chunks_mut::<POLY_Z_LEN>().0)
    {
        pack(z.iter().map(|&c| GAMMA1.wrapping_sub(c)), Z_BITS, packed);
    }
    let hints: [u8; HINT_LEN] = pack_hints(hints);
    hint_out.copy_from_slice(&hints);
    out
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn exceeds_is_the_magnitude_comparison()
    {
        for bound in [1, 196, 261_888, (1 << 19) - 196]
        {
            for a in [
                0,
                1,
                -1,
                bound - 1,
                1 - bound,
                bound,
                -bound,
                bound + 1,
                -bound - 1,
                4_190_208,
                -4_190_208,
            ]
            {
                assert_eq!(
                    exceeds(a, bound),
                    i32::from(a.abs() >= bound),
                    "a {a}, bound {bound}"
                );
            }
        }
    }
}
