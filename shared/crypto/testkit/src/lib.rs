// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/lib.rs

//! Reusable test infrastructure for cryptographic primitives: a Wycheproof
//! loader, a differential harness, and host-only references.
//!
//! Test-only and `std`: a crate reaches it as a dev-dependency. It does not
//! depend on the crates it tests, so each maps its own results to the
//! outcomes here (a verdict, a digest).
//!
//! - [`wycheproof`] loads the vendored Wycheproof test files into typed cases
//!   and runs every case against an implementation.
//! - [`differential`] runs inputs through an implementation and a reference
//!   and reports every disagreement.
//! - [`ed25519`] and [`sha512`] hold the references (`ed25519-dalek`,
//!   `RustCrypto` `sha2`) and the generated and edge-case inputs for each
//!   primitive.
//! - [`rng`] is the seeded generator the inputs come from, so every run is
//!   deterministic.

pub mod differential;
pub mod ed25519;
pub mod hex;
pub mod rng;
pub mod sha512;
pub mod wycheproof;
