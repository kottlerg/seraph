// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/verify.rs

//! ML-DSA verification (FIPS 204 Algorithms 3 and 8).
//!
//! The verifier holds no matrix and no vector: it checks the encoding of the
//! hints and the range of z on the signature's bytes, then computes
//! w'_approx = A z - c t1 2^D one row at a time, sampling each entry of A as
//! it multiplies it and transforming each `z_j` and `t1_i` from their packed bytes
//! again for every row, and absorbs each row's w1' into the hash that
//! recomputes c-tilde. Its largest frames hold three polynomials (1 KiB each),
//! two SHAKE states and a SHAKE128 block, whatever the message length; the
//! message is absorbed into SHAKE256 as it is read.
//!
//! It touches only public data, so it branches on the hints, the range check
//! and the comparison, and stops at the first check that fails.

use super::encode::{hint_rows, hints_valid, unpack, z_in_range};
use super::params::{
    CTILDE_LEN, D, GAMMA1, HINT_LEN, MAX_CONTEXT_LEN, POLY_T1_LEN, POLY_W1_LEN, POLY_Z_LEN,
    PUBLIC_KEY_LEN, RHO_LEN, SIGNATURE_LEN, T1_BITS, TR_LEN, W1_BITS, Z_BITS,
};
use super::poly::{Poly, ZERO, caddq, inv_ntt, map, montgomery_reduce, ntt, reduce32};
use super::rounding::{high_bits, use_hint};
use super::sample::{mul_acc_matrix_entry, sample_in_ball};
use crate::shake::Shake256;

/// Why a signature failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError
{
    /// The context string is longer than [`MAX_CONTEXT_LEN`] bytes (FIPS 204
    /// Algorithm 3).
    ContextTooLong,
    /// The hint section is not a canonical encoding of a hint vector
    /// (`HintBitUnpack`, FIPS 204 Algorithm 21).
    MalformedHint,
    /// A coefficient of z is at or beyond GAMMA1 - BETA in magnitude.
    ZOutOfRange,
    /// The recomputed commitment hash differs from the signature's: the
    /// signature is not one of this message under this key.
    Mismatch,
}

/// Verify an ML-DSA signature over `message` with context string `context`
/// (ML-DSA.Verify, FIPS 204 Algorithm 3: the pure form, message
/// representative over 0 || |ctx| || ctx || M).
///
/// # Errors
///
/// Returns the first failing check, in this order:
/// - [`VerifyError::ContextTooLong`]: `context` is longer than
///   [`MAX_CONTEXT_LEN`] bytes.
/// - [`VerifyError::MalformedHint`]: the signature's hint section is not
///   canonical.
/// - [`VerifyError::ZOutOfRange`]: z exceeds its norm bound.
/// - [`VerifyError::Mismatch`]: the commitment hash does not match.
///
/// A returned `Ok(())` means the signature is valid for `public_key`,
/// `message` and `context`.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    context: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), VerifyError>
{
    if context.len() > MAX_CONTEXT_LEN
    {
        return Err(VerifyError::ContextTooLong);
    }
    let [context_len, ..] = context.len().to_le_bytes();
    let mu = message_representative(public_key, &[&[0, context_len], context, message]);
    verify_mu(public_key, &mu, signature)
}

/// mu = H(H(pk, 64) || M', 64), with M' given in pieces (FIPS 204 Algorithm 8,
/// lines 6 and 7).
pub(crate) fn message_representative(
    public_key: &[u8; PUBLIC_KEY_LEN],
    m_prime: &[&[u8]],
) -> [u8; TR_LEN]
{
    let mut tr = [0u8; TR_LEN];
    crate::shake::shake256(public_key, &mut tr);
    let mut xof = Shake256::new();
    xof.update(&tr);
    for piece in m_prime
    {
        xof.update(piece);
    }
    let mut mu = [0u8; TR_LEN];
    xof.finalize().read(&mut mu);
    mu
}

/// `Verify_internal` (FIPS 204 Algorithm 8) from the message representative mu.
#[expect(
    clippy::large_stack_frames,
    reason = "the challenge `c_hat` and the row and scratch polynomials `work` (`Poly`, 1 KiB \
              each), with the SHAKE states of the commitment hash and of the challenge and matrix \
              sampling inlined into it; on its caller's stack, 16 KiB at the smallest (init's, in \
              the ktest run)"
)]
pub(crate) fn verify_mu(
    public_key: &[u8; PUBLIC_KEY_LEN],
    mu: &[u8; TR_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), VerifyError>
{
    let (rho, t1) = public_key
        .split_first_chunk::<RHO_LEN>()
        .unwrap_or((&[0; RHO_LEN], &[]));
    let (ctilde, rest) = signature
        .split_first_chunk::<CTILDE_LEN>()
        .unwrap_or((&[0; CTILDE_LEN], &[]));
    let (z, hints) = rest
        .split_last_chunk::<HINT_LEN>()
        .unwrap_or((&[], &[0; HINT_LEN]));

    if !hints_valid(hints)
    {
        return Err(VerifyError::MalformedHint);
    }
    if !z_in_range(z)
    {
        return Err(VerifyError::ZOutOfRange);
    }

    let mut c_hat = sample_in_ball(ctilde);
    ntt(&mut c_hat);

    let mut xof = Shake256::new();
    xof.update(mu);
    let mut w1_packed = [0u8; POLY_W1_LEN];
    let mut work = [ZERO; 2];
    for ((row, t1_row), hint_row) in (0u8..)
        .zip(t1.as_chunks::<POLY_T1_LEN>().0)
        .zip(hint_rows(hints))
    {
        w_approx_row(rho, row, z, t1_row, &c_hat, &mut work);
        let [w, _] = &work;
        let mut hinted = hint_row.iter().map(|&p| usize::from(p)).peekable();
        let w1 = w.iter().enumerate().map(|(i, &coefficient)| {
            if hinted.next_if_eq(&i).is_some()
            {
                use_hint(coefficient)
            }
            else
            {
                high_bits(coefficient)
            }
        });
        super::encode::pack(w1, W1_BITS, &mut w1_packed);
        xof.update(&w1_packed);
    }
    let mut recomputed = [0u8; CTILDE_LEN];
    xof.finalize().read(&mut recomputed);

    if &recomputed == ctilde
    {
        Ok(())
    }
    else
    {
        Err(VerifyError::Mismatch)
    }
}

/// Row `row` of w'_approx = NTT^-1(A NTT(z) - NTT(c) NTT(t1 2^D)) (FIPS 204
/// Algorithm 8, line 9), with coefficients in [0, q), into `work[0]`;
/// `work[1]` is scratch. The caller holds both, so that no polynomial is
/// returned by value through the frames of the verifier.
fn w_approx_row(
    rho: &[u8; RHO_LEN],
    row: u8,
    z: &[u8],
    t1_row: &[u8; POLY_T1_LEN],
    c_hat: &Poly,
    work: &mut [Poly; 2],
)
{
    let [acc, operand] = work;
    *acc = ZERO;
    for (col, z_col) in (0u8..).zip(z.as_chunks::<POLY_Z_LEN>().0)
    {
        for (c, v) in operand.iter_mut().zip(unpack(z_col, Z_BITS))
        {
            *c = GAMMA1.wrapping_sub(v);
        }
        ntt(operand);
        mul_acc_matrix_entry(rho, row, col, operand, acc);
    }
    for (c, v) in operand.iter_mut().zip(unpack(t1_row, T1_BITS))
    {
        *c = v.wrapping_shl(D);
    }
    ntt(operand);
    for (a, (c, t)) in acc.iter_mut().zip(c_hat.iter().zip(operand.iter()))
    {
        *a = a.wrapping_sub(montgomery_reduce(i64::from(*c).wrapping_mul(i64::from(*t))));
    }
    map(acc, reduce32);
    inv_ntt(acc);
    map(acc, caddq);
}
