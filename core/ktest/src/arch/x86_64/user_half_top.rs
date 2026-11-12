// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/user_half_top.rs

//! Tier 1 (x86-64): the top page of the user half is never mappable.
//!
//! The kernel keeps the last page of the lower canonical half out of every
//! user mapping: `paging::user_va_top` is that half's limit less 4 KiB, the
//! limit being `1 << 47` at 4-level paging and `1 << 56` at 5-level
//! (docs/memory-model.md § x86-64). With that page unmappable no user
//! instruction ends at the canonical boundary, so the address after a ring-3
//! `syscall` (the RIP `sysretq` returns to) is always canonical. A mappable top
//! page would let a `syscall` in its last two bytes hand the kernel the
//! non-canonical return RIP at the limit, which only `syscall_entry`'s
//! defensive divert keeps from faulting in ring 0
//! (core/kernel/docs/syscalls.md § Syscall Entry and Exit).

use syscall::{mem_map, mem_unmap, system_info};
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE, SyscallError, SystemInfoType};

use crate::{TestContext, TestResult};

/// `mem_map` refuses the top page of the lower canonical half with
/// `InvalidAddress` and maps the page below it, so the boundary sits exactly
/// one page under the half's limit (`1 << 47` or `1 << 56`, by paging depth).
pub fn top_page_unmappable(ctx: &TestContext) -> TestResult
{
    // The top user page is the first unmappable one: `UserVaTop` itself.
    let top_user_page = system_info(SystemInfoType::UserVaTop as u64)
        .map_err(|_| "user_half_top: system_info(UserVaTop) failed")?;
    let limit = top_user_page
        .checked_add(PAGE_SIZE)
        .ok_or("user_half_top: UserVaTop plus a page overflows")?;
    if limit != 1 << 47 && limit != 1 << 56
    {
        return Err("user_half_top: UserVaTop is not one page under a canonical-half limit");
    }
    // The page just below it, the highest one a process may map.
    let highest_mappable_page = top_user_page
        .checked_sub(PAGE_SIZE)
        .ok_or("user_half_top: UserVaTop is below one page")?;

    let frame = crate::frame_pool::alloc().ok_or("user_half_top: frame pool exhausted")?;

    // SAFETY: `top_user_page` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let top = unsafe { mem_map(frame, ctx.aspace_cap, top_user_page, 0, 1, MAP_WRITABLE) };
    if top.is_ok()
    {
        // The frame is now mapped at the top page: unmap before returning it
        // to the pool, and keep it if the unmap fails.
        // SAFETY: `top_user_page` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { mem_unmap(ctx.aspace_cap, top_user_page, 1) }.is_ok()
        {
            // SAFETY: `frame` came from the pool and its only mapping was just
            // removed.
            unsafe { crate::frame_pool::free(frame) };
        }
        return Err("user_half_top: mem_map of the top user page succeeded");
    }

    // SAFETY: `highest_mappable_page` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let below = unsafe {
        mem_map(
            frame,
            ctx.aspace_cap,
            highest_mappable_page,
            0,
            1,
            MAP_WRITABLE,
        )
    };
    // SAFETY: `highest_mappable_page` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let unmapped =
        below.is_err() || unsafe { mem_unmap(ctx.aspace_cap, highest_mappable_page, 1) }.is_ok();
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
