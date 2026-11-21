// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/crypto.rs

//! Tier 1 tests for the shared `crypto` crate (SHA-512, Ed25519 verify,
//! ChaCha20-Poly1305, Keccak-f[1600] and SHAKE, ML-DSA-65 verify).
//!
//! These run the crate's own known-answer vectors on the live target so the
//! primitives are validated under QEMU on both `x86_64` and `riscv64`, not only
//! by the host-side `cargo xtask test` run. The vector tables and assertions
//! live in `shared/crypto` (`run_sha512_kats`, `run_ed25519_kats`,
//! `run_chacha20_poly1305_kats`, `run_shake_kats`, `run_ml_dsa_kats`); this
//! module is a thin on-target entry point so host and on-target runs exercise
//! identical logic.

use crate::{TestContext, TestResult};

/// SHA-512 known-answer tests: FIPS 180-4 vectors plus incremental and
/// padding-boundary self-consistency.
pub fn sha512_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_sha512_kats()
}

/// Ed25519 verification known-answer tests: RFC 8032 §7.1 positive vectors
/// plus tamper negatives (flipped signature/message, wrong key, non-canonical
/// S, invalid public key, and the two non-canonical public-key encodings).
pub fn ed25519_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_ed25519_kats()
}

/// ChaCha20-Poly1305 known-answer tests: every RFC 8439 vector of the block
/// function, the cipher, Poly1305, the Poly1305 key derivation and the AEAD,
/// plus tamper negatives (a flipped bit of the tag, ciphertext, nonce or AAD,
/// and another key, each refused with the buffer unchanged).
pub fn chacha20_poly1305_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_chacha20_poly1305_kats()
}

/// Keccak-f[1600] and SHAKE known-answer tests: the FIPS 202 zero-state
/// permutation vector, SHAKE128 and SHAKE256 of the empty message, NIST ACVP
/// cases across the rate, and incremental absorbing and squeezing against
/// one-shot output.
pub fn shake_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_shake_kats()
}

/// ML-DSA-65 verification known-answer tests: NIST ACVP cases (a valid
/// signature with a context string; valid and modified signatures through the
/// message representative), and refusals of the valid signature with each
/// FIPS 204 check broken: an over-long context, a changed context or
/// message, a changed commitment hash, hint sections out of range, out of
/// order or with a non-zero trailing slot, and z at its norm bound.
pub fn ml_dsa_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_ml_dsa_kats()
}
