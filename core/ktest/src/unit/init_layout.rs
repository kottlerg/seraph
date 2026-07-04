// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/init_layout.rs

//! Tier 1 tests for the kernel's randomized init bootstrap layout (ASLR, #39).
//!
//! ktest is loaded as the init process, so its own `InitInfo` VA (delivered in
//! the entry register) and its own stack are the kernel's `choose_init_layout`
//! draw — asserting on them exercises the Phase 9 draw, the mapping, and the
//! `sched::enter` trap-frame build end-to-end.

use init_protocol::INIT_STACK_PAGES;
use process_layout::{INIT_INFO_WINDOW, INIT_STACK_GUARD_WINDOW};

use crate::{TestContext, TestResult};

/// The `InitInfo` page VA delivered in the entry register is a page-aligned
/// draw from the kernel's `InitInfo` window. ktest has been reading its
/// `InitInfo` through this address since `_start`, so membership also proves
/// the mapping and the register delivery agree.
pub fn init_info_va_in_window(ctx: &TestContext) -> TestResult
{
    if !ctx.init_info_va.is_multiple_of(4096)
    {
        return Err("InitInfo VA is not page-aligned");
    }
    if !INIT_INFO_WINDOW.contains(ctx.init_info_va)
    {
        return Err("InitInfo VA outside the kernel's InitInfo window");
    }
    Ok(())
}

/// The stack pointer of a live stack frame lies inside the span reachable
/// from the init-stack-guard window: above the lowest possible mapped stack
/// byte and below the highest possible stack top. Proves `sched::enter`'s
/// cached stack top matches the Phase 9 stack mapping.
pub fn sp_in_init_stack_window(_ctx: &TestContext) -> TestResult
{
    let probe = 0u64;
    let sp = core::ptr::addr_of!(probe) as u64;
    let lowest = INIT_STACK_GUARD_WINDOW.base + 4096;
    let highest = INIT_STACK_GUARD_WINDOW.base
        + INIT_STACK_GUARD_WINDOW.span()
        + (1 + INIT_STACK_PAGES as u64) * 4096;
    if sp < lowest || sp >= highest
    {
        return Err("SP outside the init-stack window span");
    }
    Ok(())
}
