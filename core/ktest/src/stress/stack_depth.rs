// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/stack_depth.rs

//! Report: the deepest use of each kernel stack class, read after the rest of
//! Tier S has run.
//!
//! Reads `SYS_SYSTEM_INFO(StackHighWater)` for the idle stacks, the thread
//! kernel stacks, and the bootloader's handoff stack, and logs each against
//! its size (core/kernel/docs/memory-internals.md § Kernel Stack Depth). It
//! is a report: it fails only when a class reads full (every word overwritten,
//! an overflow) or the handoff stack could not be located, whose base mark an
//! overflow overwrites. The measured bounds are stated at
//! `KERNEL_STACK_PAGES` and `HANDOFF_STACK_BYTES`.

use syscall::stack_high_water;
use syscall_abi::{PAGE_SIZE, STACK_CLASS_HANDOFF, STACK_CLASS_IDLE, STACK_CLASS_THREAD};

use crate::TestResult;

/// Size of an idle or thread kernel stack: the kernel's `KERNEL_STACK_PAGES`
/// (4) pages.
const KERNEL_STACK_BYTES: u64 = 4 * PAGE_SIZE;

/// Size of the handoff stack (`boot_protocol::layout::HANDOFF_STACK_BYTES`),
/// less the base-mark word below its painted span.
const HANDOFF_SPAN_BYTES: u64 = 64 * 1024 - 8;

pub fn run(_ctx: &crate::TestContext) -> TestResult
{
    let idle = stack_high_water(STACK_CLASS_IDLE)
        .map_err(|_| "stack_depth: StackHighWater(idle) failed")?;
    let thread = stack_high_water(STACK_CLASS_THREAD)
        .map_err(|_| "stack_depth: StackHighWater(thread) failed")?;
    let handoff = stack_high_water(STACK_CLASS_HANDOFF)
        .map_err(|_| "stack_depth: StackHighWater(handoff) failed")?;
    crate::log_u64("ktest: stress::stack_depth idle_bytes=", idle);
    crate::log_u64("ktest: stress::stack_depth thread_bytes=", thread);
    crate::log_u64(
        "ktest: stress::stack_depth kernel_stack_bytes=",
        KERNEL_STACK_BYTES,
    );
    if handoff == u64::MAX
    {
        return Err(
            "stack_depth: handoff stack base mark not found (overflow, or a misderived top)",
        );
    }
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
    if thread == 0 || idle == 0 || handoff == 0
    {
        return Err("stack_depth: a class reads zero use (its stack was not painted)");
    }
    Ok(())
}
