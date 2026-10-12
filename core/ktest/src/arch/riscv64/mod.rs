// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/mod.rs

//! RISC-V ktest code.
//!
//! Tier 1 tests:
//! - `sbi_call.rs` — `SYS_SBI_CALL` reaches the SBI firmware
//!
//! TODO: move the RISC-V-specific `integration::sbi_gating` scenario, which still
//! sits in `integration/` behind its own `target_arch` gates, behind this module.
//! Deferred because the move is a ktest code-quality cleanup that changes no test
//! coverage; it is tracked, with the other arch-gated ktest items outside
//! `crate::arch`, on #460.

mod sbi_call;

use crate::TestContext;

/// Run every RISC-V-specific Tier 1 test. x86-64's wrapped-stack probe has no
/// RISC-V counterpart: the RISC-V entry alignment, `sp & !0xF`, rounds down
/// without wrapping, so the raw stack check covers it.
pub fn run_unit(ctx: &TestContext)
{
    crate::run_test!(
        "hw::sbi_call_get_spec_version",
        sbi_call::get_spec_version(ctx)
    );
}

/// Run every RISC-V-specific Tier 2 scenario that lives behind this module
/// (none yet; see the module doc).
pub fn run_integration(_ctx: &TestContext) {}
