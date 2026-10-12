// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/mod.rs

//! x86-64 ktest code.
//!
//! Tier 2 scenarios:
//! - `syscall_rflags_hardening.rs` — user-set DF and TF and a reloaded user GS
//!   base do not reach the kernel across a SYSCALL
//! - `configure_wrapped_stack.rs` — `thread_configure` refuses a stack top the
//!   entry alignment wraps below zero

mod configure_wrapped_stack;
mod syscall_rflags_hardening;

use crate::TestContext;

/// Run every x86-64-specific Tier 2 integration scenario.
pub fn run_integration(ctx: &TestContext)
{
    crate::run_integration_test!(
        "integration::syscall_rflags_hardening",
        syscall_rflags_hardening::run(ctx)
    );
    crate::run_integration_test!(
        "integration::configure_wrapped_stack",
        configure_wrapped_stack::run(ctx)
    );
}
