// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/init_layout.rs

//! Tier 1 tests for the kernel's randomized init bootstrap layout (ASLR, #39).
//!
//! ktest is loaded as the init process, so its own `InitInfo` VA (delivered in
//! the entry register), its own stack, and its own image base are the
//! kernel's Phase 9 draws — asserting on them exercises the layout draw, the
//! PIE bias + relocation path, the mapping, and the `sched::enter`
//! trap-frame build end-to-end.

use init_protocol::INIT_STACK_PAGES;
use process_layout::{IMAGE_WINDOW, INIT_INFO_WINDOW, INIT_STACK_GUARD_WINDOW};
use syscall_abi::PAGE_SIZE;

use crate::{TestContext, TestResult};

// lld-synthesized symbol at the ELF header — the image load base.
unsafe extern "C" {
    static __ehdr_start: u8;
}

/// The `InitInfo` page VA delivered in the entry register is a page-aligned
/// draw from the kernel's `InitInfo` window. ktest has been reading its
/// `InitInfo` through this address since `_start`, so membership also proves
/// the mapping and the register delivery agree.
pub fn init_info_va_in_window(ctx: &TestContext) -> TestResult
{
    if !ctx.init_info_va.is_multiple_of(PAGE_SIZE)
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
/// byte and below the highest possible stack top (the maximum guard draw
/// plus `INIT_STACK_PAGES` mapped pages). Proves `sched::enter`'s cached
/// stack top matches the Phase 9 stack mapping.
pub fn sp_in_init_stack_window(_ctx: &TestContext) -> TestResult
{
    let probe = 0u64;
    let sp = core::ptr::addr_of!(probe) as u64;
    let lowest = INIT_STACK_GUARD_WINDOW.base + PAGE_SIZE;
    let highest = INIT_STACK_GUARD_WINDOW.base
        + INIT_STACK_GUARD_WINDOW.span()
        + INIT_STACK_PAGES as u64 * PAGE_SIZE;
    if sp < lowest || sp >= highest
    {
        return Err("SP outside the init-stack window span");
    }
    Ok(())
}

/// The image load base (`__ehdr_start`) is a draw from the image window —
/// not the legacy fixed `ET_EXEC` base. Proves the whole PIE chain:
/// bootloader kind detection, kernel bias draw, relocation application
/// (this test's own code runs relocated), and biased segment mapping.
pub fn image_base_randomized(_ctx: &TestContext) -> TestResult
{
    // Only the linker-synthesized symbol's address is taken, never its value.
    let base = core::ptr::addr_of!(__ehdr_start) as u64;
    if base == 0x20_0000
    {
        return Err("image base is the legacy fixed ET_EXEC base");
    }
    if !IMAGE_WINDOW.contains(base)
    {
        return Err("image base outside the image window");
    }
    Ok(())
}
