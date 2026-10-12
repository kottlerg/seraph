// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/mod.rs

//! RISC-V ktest code.
//!
//! The RISC-V-specific `integration::sbi_gating` scenario still sits in
//! `integration/` behind its own `target_arch` gates; moving it here is #460.

use crate::TestContext;

/// Run every RISC-V-specific Tier 2 scenario that lives behind this module
/// (none yet; see the module doc).
pub fn run_integration(_ctx: &TestContext) {}
