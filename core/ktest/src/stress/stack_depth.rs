// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stack_depth.rs

//! Report: the deepest use of each kernel stack class, read after the rest of
//! Tier S has run.
//!
//! Reads `SYS_SYSTEM_INFO(StackHighWater)` for the idle stacks, the thread
//! kernel stacks, and the bootloader's handoff stack, and logs each against
//! its size (core/kernel/docs/memory-internals.md § Kernel Stack Depth). It
//! is a report: it fails only on an overflow, when a class reads full (every
//! word overwritten) or the handoff stack's base mark, which an overflow
//! overwrites, is gone. The measured bounds are stated at
//! `KERNEL_STACK_PAGES` and `HANDOFF_STACK_BYTES`.

use boot_protocol::layout::HANDOFF_STACK_BYTES;
use syscall::stack_high_water;
use syscall_abi::{
    PAGE_SIZE, STACK_CLASS_HANDOFF, STACK_CLASS_IDLE, STACK_CLASS_THREAD, SyscallError,
};

use crate::TestResult;

/// Size of an idle or thread kernel stack: a mirror of the kernel-private
/// `KERNEL_STACK_PAGES` (4) pages, listed under docs/limits.md § Unpinned
/// couplings.
pub const KERNEL_STACK_BYTES: u64 = 4 * PAGE_SIZE;

/// Size of the handoff stack's painted span: `HANDOFF_STACK_BYTES` less the
/// base-mark word below it.
const HANDOFF_SPAN_BYTES: u64 = HANDOFF_STACK_BYTES as u64 - 8;

pub fn run(_ctx: &crate::TestContext) -> TestResult
{
    let idle = stack_high_water(STACK_CLASS_IDLE)
        .map_err(|_| "stack_depth: StackHighWater(idle) failed")?;
    let thread = stack_high_water(STACK_CLASS_THREAD)
        .map_err(|_| "stack_depth: StackHighWater(thread) failed")?;
    let handoff = match stack_high_water(STACK_CLASS_HANDOFF)
    {
        Ok(h) => h,
        Err(e) if e == SyscallError::NotSupported as i64 =>
        {
            return Err(
                "stack_depth: handoff stack base mark not found (overflow, or a misderived top)",
            );
        }
        Err(_) => return Err("stack_depth: StackHighWater(handoff) failed"),
    };
    crate::log_u64("ktest: stress::stack_depth idle_bytes=", idle);
    crate::log_u64("ktest: stress::stack_depth thread_bytes=", thread);
    crate::log_u64(
        "ktest: stress::stack_depth kernel_stack_bytes=",
        KERNEL_STACK_BYTES,
    );
    crate::log_u64("ktest: stress::stack_depth handoff_bytes=", handoff);
    crate::log_u64(
        "ktest: stress::stack_depth handoff_span_bytes=",
        HANDOFF_SPAN_BYTES,
    );
    if idle >= KERNEL_STACK_BYTES
    {
        return Err("stack_depth: an idle stack reads full (overflow)");
    }
    if thread >= KERNEL_STACK_BYTES
    {
        return Err("stack_depth: a thread kernel stack reads full (overflow)");
    }
    if handoff >= HANDOFF_SPAN_BYTES
    {
        return Err("stack_depth: the handoff stack reads full (overflow)");
    }
    Ok(())
}
