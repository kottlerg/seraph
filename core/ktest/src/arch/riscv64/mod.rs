// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/mod.rs

//! RISC-V ktest code.
//!
//! Tier 1 tests:
//! - `sbi_call.rs` — `SYS_SBI_CALL` reaches the SBI firmware
//!
//! Tier 2 scenarios:
//! - `sbi_gating.rs` — `SYS_SBI_CALL` refuses kernel-reserved extensions and
//!   sanctioned ones the cap lacks the right for

mod sbi_call;
mod sbi_gating;

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

/// Run every RISC-V-specific Tier 2 integration scenario.
pub fn run_integration(ctx: &TestContext)
{
    crate::run_integration_test!("integration::sbi_gating", sbi_gating::run(ctx));
}
