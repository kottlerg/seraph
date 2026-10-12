// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/mod.rs

//! x86-64 ktest code.
//!
//! Tier 1 tests:
//! - `configure_wrapped_stack.rs` — `thread_configure` refuses a stack top the
//!   entry alignment wraps below zero
//! - `sbi_call.rs` — `SYS_SBI_CALL` returns `NotSupported`
//!
//! Tier 2 scenarios:
//! - `syscall_rflags_hardening.rs` — user-set DF and TF and a reloaded user GS
//!   base do not reach the kernel across a SYSCALL

mod configure_wrapped_stack;
mod sbi_call;
mod syscall_rflags_hardening;

use crate::TestContext;

/// Run every x86-64-specific Tier 1 test.
pub fn run_unit(ctx: &TestContext)
{
    crate::run_test!(
        "thread::configure_wrapped_stack_err",
        configure_wrapped_stack::run(ctx)
    );
    crate::run_test!(
        "hw::sbi_call_not_supported_x86_64",
        sbi_call::not_supported(ctx)
    );
}

/// Run every x86-64-specific Tier 2 integration scenario.
pub fn run_integration(ctx: &TestContext)
{
    crate::run_integration_test!(
        "integration::syscall_rflags_hardening",
        syscall_rflags_hardening::run(ctx)
    );
}
