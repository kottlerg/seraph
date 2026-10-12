// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/configure_wrapped_stack.rs

//! Integration (x86-64): `thread_configure` refuses a stack pointer that leaves
//! the user half only after the entry ABI's alignment.
//!
//! The kernel rounds the initial stack pointer to the x86-64 `extern "C"` entry
//! alignment (`(sp & !0xF) - 8`, `core/kernel/src/arch/x86_64/context.rs`
//! `align_initial_stack`), which wraps for any `stack_top` below 16. A raw value
//! in the user half can therefore start the thread outside it, and the kernel
//! checks the aligned value too (`core/kernel/docs/syscalls.md`
//! § `SYS_THREAD_CONFIGURE`).

use syscall::{cap_delete, thread_configure};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// A user-half stack top that the entry alignment wraps below zero.
const WRAPPING_STACK_TOP: u64 = 8;

pub fn run(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "configure_wrapped_stack: spawn::new_child failed")?;
    let entry = run as *const () as u64;
    let result = thread_configure(child.th, entry, WRAPPING_STACK_TOP, 0);
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    if result != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("configure_wrapped_stack: a stack that wraps on alignment was accepted");
    }
    Ok(())
}
