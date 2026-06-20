// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/crypto.rs

//! Tier 1 tests for the shared `crypto` crate (SHA-512, Ed25519 verify).
//!
//! These run the crate's own known-answer vectors on the live target so the
//! primitives are validated under QEMU on both `x86_64` and `riscv64`, not only
//! by host `cargo test`. The vector tables and assertions live in `shared/crypto`
//! (`run_sha512_kats` / `run_ed25519_kats`); this module is a thin on-target
//! entry point so host and on-target runs exercise identical logic.

use crate::{TestContext, TestResult};

/// SHA-512 known-answer tests: FIPS 180-4 vectors plus incremental and
/// padding-boundary self-consistency.
pub fn sha512_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_sha512_kats()
}

/// Ed25519 verification known-answer tests: RFC 8032 §7.1 positive vectors
/// plus tamper negatives (flipped signature/message, wrong key, non-canonical
/// S, invalid public key).
pub fn ed25519_kats(_ctx: &TestContext) -> TestResult
{
    crypto::run_ed25519_kats()
}
