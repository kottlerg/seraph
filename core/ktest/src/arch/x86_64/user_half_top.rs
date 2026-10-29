// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/user_half_top.rs

//! Tier 1 (x86-64): the top page of the user half is never mappable.
//!
//! The kernel keeps `[0x7FFF_FFFF_F000, 1 << 47)` out of every user mapping
//! (`paging::user_va_top` is `(1 << 47) - 4096`; docs/memory-model.md § x86-64):
//! with that page unmappable no user instruction ends at the canonical
//! boundary, so the address after a ring-3 `syscall` (the RIP `sysretq`
//! returns to) is always canonical. A mappable top page would let a `syscall`
//! in its last two bytes hand the kernel the non-canonical return RIP
//! `1 << 47`, which only `syscall_entry`'s defensive divert keeps from faulting
//! in ring 0 (core/kernel/docs/syscalls.md § Syscall Entry and Exit).

use syscall::{mem_map, mem_unmap};
use syscall_abi::{MAP_WRITABLE, SyscallError};

use crate::{TestContext, TestResult};

/// The last page of the user half: `(1 << 47) - 4096`.
const TOP_USER_PAGE: u64 = 0x7FFF_FFFF_F000;

/// The page just below it, the highest one a process may map.
const HIGHEST_MAPPABLE_PAGE: u64 = TOP_USER_PAGE - 0x1000;

/// `mem_map` refuses the top user page with `InvalidAddress` and maps the page
/// below it, so the boundary sits exactly one page under `1 << 47`.
pub fn top_page_unmappable(ctx: &TestContext) -> TestResult
{
    let frame = crate::frame_pool::alloc().ok_or("user_half_top: frame pool exhausted")?;

    let top = mem_map(frame, ctx.aspace_cap, TOP_USER_PAGE, 0, 1, MAP_WRITABLE);
    if top.is_ok()
    {
        // The frame is now mapped at the top page: unmap before returning it
        // to the pool, and keep it if the unmap fails.
        if mem_unmap(ctx.aspace_cap, TOP_USER_PAGE, 1).is_ok()
        {
            // SAFETY: `frame` came from the pool and its only mapping was just
            // removed.
            unsafe { crate::frame_pool::free(frame) };
        }
        return Err("user_half_top: mem_map of the top user page succeeded");
    }

    let below = mem_map(
        frame,
        ctx.aspace_cap,
        HIGHEST_MAPPABLE_PAGE,
        0,
        1,
        MAP_WRITABLE,
    );
    let unmapped = below.is_err() || mem_unmap(ctx.aspace_cap, HIGHEST_MAPPABLE_PAGE, 1).is_ok();
    if unmapped
    {
        // SAFETY: `frame` came from the pool and is mapped nowhere: the top-page
        // map failed, and the lower map either failed or was just undone.
        unsafe { crate::frame_pool::free(frame) };
    }

    if top != Err(SyscallError::InvalidAddress as i64)
    {
        return Err("user_half_top: top-page mem_map not refused with InvalidAddress");
    }
    if below.is_err()
    {
        return Err("user_half_top: mem_map of the page below the top failed");
    }
    if !unmapped
    {
        return Err("user_half_top: mem_unmap of the page below the top failed");
    }
    Ok(())
}
