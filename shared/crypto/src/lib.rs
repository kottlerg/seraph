// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/lib.rs

//! In-OS cryptographic primitives: SHA-512 hashing, Keccak-f[1600] and SHAKE,
//! Ed25519 and ML-DSA-65 signature verification and, for the host signer, key
//! generation and signing, and ChaCha20-Poly1305 authenticated encryption.
//!
//! `no_std`, no allocation, no external dependencies. The primitives:
//!
//! - [`sha512`] / [`Sha512`] — FIPS 180-4 SHA-512, one-shot and incremental.
//!   The incremental form hashes large inputs (e.g. boot-module bodies)
//!   without buffering them.
//! - [`ed25519_verify`] — RFC 8032 Ed25519 signature verification. It
//!   operates only on public data (public key, signature, message), so its
//!   range check and point decompression are variable-time. Failure is
//!   terminal: a single `Err` exit, no fallback, no warn-and-continue.
//! - `ed25519_public_key` and `ed25519_sign` — RFC 8032 Ed25519 key
//!   derivation from a secret seed the caller passes, and deterministic
//!   signing, compiled only with the `sign` feature, which only a host tool
//!   may enable and no component built for the target may (the crate's README,
//!   § Design notes). No branch and no memory index depends on a secret value.
//! - [`chacha20poly1305`] — the RFC 8439 AEAD, sealing and opening a buffer
//!   in place with a detached tag. It handles secret data, so no branch and
//!   no memory index depends on the key, the plaintext or a tag, and a tag is
//!   compared in a time that does not depend on where it differs.
//! - [`keccak`] — the FIPS 202 Keccak-f[1600] permutation, in constant time.
//!   The kernel's entropy sponge runs it (the kernel depends on this crate
//!   with no feature and calls nothing else), and so does [`shake`].
//! - [`shake`] — FIPS 202 SHAKE128 and SHAKE256, one-shot and incremental
//!   (absorb in pieces, then squeeze in pieces).
//! - [`ml_dsa`] — FIPS 204 ML-DSA-65 signature verification, the pure form
//!   with a context string. It allocates nothing and its stack does not grow
//!   with the message; it operates only on public data, so it is
//!   variable-time. Key derivation from a seed and deterministic signing
//!   (`ml_dsa::public_key`, `ml_dsa::sign`) are compiled only with the `sign`
//!   feature, as Ed25519's are.
//!
//! Each hash serves a signature scheme and is public too: SHA-512 the one
//! Ed25519 mandates (RFC 8032 §5.1), SHAKE the ones ML-DSA does (FIPS 204).

#![no_std]

#[cfg(test)]
extern crate std;

pub mod chacha20poly1305;
pub mod keccak;
pub mod ml_dsa;
pub mod sha512;
pub mod shake;

mod chacha20;
mod ed25519;
#[cfg(any(test, feature = "sign"))]
mod ed25519_sign;
mod edwards;
mod field;
mod kat_hex;
mod poly1305;
mod scalar;

pub use chacha20poly1305::run_chacha20_poly1305_kats;
pub use ed25519::{VerifyError, ed25519_verify, run_ed25519_kats};
#[cfg(any(test, feature = "sign"))]
pub use ed25519_sign::{ed25519_public_key, ed25519_sign};
pub use ml_dsa::run_ml_dsa_kats;
pub use sha512::{Sha512, run_sha512_kats, sha512};
pub use shake::run_shake_kats;
