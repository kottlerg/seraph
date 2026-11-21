// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/ml_dsa/mod.rs

//! ML-DSA (FIPS 204), parameter set ML-DSA-65: signature verification and,
//! for the host signer, key generation and deterministic signing.
//!
//! [`verify`] is ML-DSA.Verify, the pure form with a context string. It
//! allocates nothing and its stack is bounded whatever the message length
//! ([`verify`'s module][self] states the frames); every check FIPS 204 makes
//! of a signature's encoding and range is made, and each failure is a single
//! terminal `Err` naming the check. [`public_key`] and [`sign`] derive the
//! key from a 32-byte seed and sign deterministically, compiled only with the
//! `sign` feature, which only a host tool may enable (the crate's README,
//! § Design notes).
//!
//! The parameter set is the first block of constants in `params.rs`; the rest
//! of the module reads only those names, so ML-DSA-44 and ML-DSA-87 differ
//! from it only there.

mod encode;
mod kat;
mod params;
mod poly;
mod rounding;
mod sample;
#[cfg(any(test, feature = "sign"))]
mod sign;
#[cfg(test)]
mod tests;
mod verify;

pub use kat::run_ml_dsa_kats;
pub use params::{MAX_CONTEXT_LEN, NAME, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN};
#[cfg(any(test, feature = "sign"))]
pub use sign::{SignError, public_key, sign};
pub use verify::{VerifyError, verify};
