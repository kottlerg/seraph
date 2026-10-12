// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/arch/x86_64/mod.rs

//! x86-64 Tier 2 scenarios.
//!
//! Files:
//! - `syscall_rflags_hardening.rs` — user-set DF and TF and a reloaded user GS
//!   base do not reach the kernel across a SYSCALL

mod syscall_rflags_hardening;

use crate::TestContext;

/// Run every x86-64-specific integration scenario.
pub fn run_all(ctx: &TestContext)
{
    crate::run_integration_test!(
        "integration::arch::syscall_rflags_hardening",
        syscall_rflags_hardening::run(ctx)
    );
}
