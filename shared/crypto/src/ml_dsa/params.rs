// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/params.rs

//! The ML-DSA parameter set: ML-DSA-65 (FIPS 204 § 4, Tables 1 and 2).
//!
//! Every value that differs between ML-DSA-44, ML-DSA-65 and ML-DSA-87 is a
//! constant of the first block below, and the rest of the module is written
//! against these names: the second block derives the bit widths and byte
//! lengths from them, and the arithmetic, sampling and encoding read only
//! those. Another parameter set is this first block with that set's values
//! (Table 1); the module builds and tests ML-DSA-65 only.

/// The parameter set's name, for messages.
pub const NAME: &str = "ML-DSA-65";

// ── The parameter set (FIPS 204 Table 1) ─────────────────────────────────────

/// Rows of the matrix A: the length of t, w and the hint vector.
pub(crate) const K: usize = 6;
/// Columns of the matrix A: the length of s1, y and z.
pub(crate) const L: usize = 5;
/// The bound of the secret coefficients: s1 and s2 lie in [-ETA, ETA].
pub(crate) const ETA: i32 = 4;
/// The number of +-1 coefficients of the challenge polynomial c.
pub(crate) const TAU: usize = 49;
/// The bound of the mask y: its coefficients lie in (-GAMMA1, GAMMA1].
pub(crate) const GAMMA1: i32 = 1 << 19;
/// The low-order rounding range: Decompose splits by 2 * GAMMA2.
pub(crate) const GAMMA2: i32 = (Q - 1) / 32;
/// The most hint bits a signature carries.
pub(crate) const OMEGA: usize = 55;
/// The collision strength of c-tilde in bits.
pub(crate) const LAMBDA: usize = 192;

// ── Fixed by FIPS 204 for every parameter set ────────────────────────────────

/// The ring degree: polynomials have N coefficients.
pub(crate) const N: usize = 256;
/// The modulus q = 2^23 - 2^13 + 1.
pub(crate) const Q: i32 = 8_380_417;
/// The bits `Power2Round` drops from t.
pub(crate) const D: u32 = 13;

// ── Derived (FIPS 204 § 4 and § 7.2) ─────────────────────────────────────────

/// BETA = TAU * ETA: the largest coefficient c * s1 or c * s2 can have.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "TAU is at most 60 in every parameter set, so it fits an i32 exactly"
)]
pub(crate) const BETA: i32 = TAU as i32 * ETA;

/// Bytes of c-tilde, the signature's commitment hash: LAMBDA / 4.
pub(crate) const CTILDE_LEN: usize = LAMBDA / 4;

/// Bits of one packed coefficient of t1: bitlen(q - 1) - D.
pub(crate) const T1_BITS: u32 = (Q - 1).ilog2() + 1 - D;
/// Bits of one packed coefficient of z (and of y): 1 + bitlen(GAMMA1 - 1).
pub(crate) const Z_BITS: u32 = (GAMMA1 - 1).ilog2() + 2;
/// The largest coefficient of w1, `HighBits` of a value below q:
/// (q - 1) / (2 * GAMMA2) - 1.
pub(crate) const W1_MAX: i32 = (Q - 1) / (2 * GAMMA2) - 1;
/// Bits of one packed coefficient of w1: the bit length of `W1_MAX`.
pub(crate) const W1_BITS: u32 = W1_MAX.ilog2() + 1;

/// Bytes of one packed polynomial of t1.
pub(crate) const POLY_T1_LEN: usize = N * T1_BITS as usize / 8;
/// Bytes of one packed polynomial of z.
pub(crate) const POLY_Z_LEN: usize = N * Z_BITS as usize / 8;
/// Bytes of one packed polynomial of w1.
pub(crate) const POLY_W1_LEN: usize = N * W1_BITS as usize / 8;

/// Bytes of the seed rho, from which the matrix A is expanded.
pub(crate) const RHO_LEN: usize = 32;
/// Bytes of tr, the hash of the public key, and of the message
/// representative mu.
pub(crate) const TR_LEN: usize = 64;
/// Bytes of the hint section: OMEGA positions, then one end index per row.
pub(crate) const HINT_LEN: usize = OMEGA + K;

/// Bytes of a public key: rho, then t1 (FIPS 204 Algorithm 22).
pub const PUBLIC_KEY_LEN: usize = RHO_LEN + K * POLY_T1_LEN;
/// Bytes of a signature: c-tilde, then z, then the hints (FIPS 204
/// Algorithm 26).
pub const SIGNATURE_LEN: usize = CTILDE_LEN + L * POLY_Z_LEN + HINT_LEN;
/// Bytes of the secret seed xi a key is derived from.
pub const SEED_LEN: usize = 32;
/// The longest context string a signature may bind: its length is one byte.
pub const MAX_CONTEXT_LEN: usize = 255;
