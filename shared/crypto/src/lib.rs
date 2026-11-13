// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/lib.rs

//! In-OS cryptographic primitives: SHA-512 hashing and Ed25519 signature
//! verification.
//!
//! `no_std`, no allocation, no external dependencies. Two primitives:
//!
//! - [`sha512`] / [`Sha512`] — FIPS 180-4 SHA-512, one-shot and incremental.
//!   The incremental form hashes large inputs (e.g. boot-module bodies)
//!   without buffering them.
//! - [`ed25519_verify`] — RFC 8032 Ed25519 signature *verification*. There is
//!   no signing or key generation here; verification operates only on public
//!   data (public key, signature, message), so the field arithmetic is
//!   variable-time by design and carries no side-channel obligation. Failure
//!   is terminal: a single `Err` exit, no fallback, no warn-and-continue.
//!
//! SHA-512 is the only hash provided because Ed25519 mandates it internally
//! (RFC 8032 §5.1); one core serves both the public hash and the signature's
//! internal hashing.
//!
//! Non-goal: the kernel's `entropy` subsystem carries its own Keccak/SHAKE256
//! sponge for the CSPRNG. That primitive is kernel-internal and is not shared
//! with or consumed by this crate; consolidating hash primitives is out of
//! scope here.

#![no_std]

pub mod sha512;

mod ed25519;
mod edwards;
mod field;
mod scalar;

pub use ed25519::{VerifyError, ed25519_verify, run_ed25519_kats};
pub use sha512::{Sha512, run_sha512_kats, sha512};
