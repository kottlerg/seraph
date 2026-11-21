// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/lib.rs

//! Reusable test infrastructure for cryptographic primitives: a Wycheproof
//! loader, a differential harness, reference vectors computed with OpenSSL,
//! and their generator.
//!
//! Test-only and `std`: a crate reaches it as a dev-dependency. It does not
//! depend on the crates it tests, so each maps its own results to the
//! outcomes here (a verdict, a digest).
//!
//! - [`wycheproof`] loads the vendored Wycheproof test files into typed cases
//!   and runs every case against an implementation.
//! - [`differential`] runs inputs through an implementation and a reference
//!   and reports every disagreement.
//! - [`ed25519`], [`sha512`], [`shake`] and [`ml_dsa`] load the reference
//!   vectors: generated and edge-case inputs for each primitive, each with
//!   OpenSSL's outcome, and Ed25519 and ML-DSA-65 signing inputs with
//!   OpenSSL's key and signature.
//! - [`generate`] writes those vectors, driving the `openssl` command; the
//!   `crypto-reference-vectors` binary runs it.
//! - [`rng`] is the seeded generator the generated inputs come from, so every
//!   run is deterministic.
//! - [`vectors`] holds the JSON field readers the loaders share.

pub mod differential;
pub mod ed25519;
pub mod generate;
pub mod hex;
pub mod ml_dsa;
pub mod rng;
pub mod sha512;
pub mod shake;
pub mod vectors;
pub mod wycheproof;
