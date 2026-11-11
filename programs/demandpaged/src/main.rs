// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/demandpaged/src/main.rs

//! Demand-paging fixture for the svctest pager phase.
//!
//! Demand paging is the system-wide default, so when spawned normally procmgr
//! binds this process's fault handler to memmgr (the pager). The pager phase
//! also spawns it `pinned(true)` to prove the opt-out leaves it with no pager.
//! Two modes, selected by argv:
//!
//!   * default — reserve an unbacked region, register it as demand-paged, and
//!     write a per-page pattern across it. Each first touch faults to memmgr,
//!     which backs the page and resumes. A second read-back pass verifies the
//!     data persisted (no re-fault, no zero-fill), proving the round-trip.
//!     Exits `SUCCESS` on success; a register failure or mismatch exits
//!     non-zero.
//!   * `oor` — touch a reserved but *unregistered* page. The pager finds no
//!     region and declines, so the kernel kills this process. If the touch
//!     somehow survives (a pager bug), exit `SUCCESS` so the harness's "must
//!     be killed" assertion fails loudly rather than hanging.
//!   * `ptdrain` — register a demand region holding a 2 MiB block whose leaf
//!     page table does not exist yet, then empty this address space's
//!     page-table pool with mappings of its own, as any other mapping of the
//!     process may after a region's funding, and only then touch the block.
//!     The pager finds the pool empty when it maps the block's chunk, and
//!     must fund the pool itself rather than decline. Exits `SUCCESS` when
//!     the touch is backed and reads back.
//!
//! Driven by `services/svctest`'s pager phase.

use std::os::seraph::{register_demand_paged, reserve_pages, startup_info};
use std::process::ExitCode;

use syscall_abi::{CAP_INFO_ASPACE_PT_BUDGET, MAP_READ, PAGE_SIZE, SyscallError};

const PAGES: usize = 4;
const PAGE: usize = 4096;

/// Pages one last-level page table spans: 512 entries of 4 KiB, 2 MiB, under
/// every paging mode of both architectures.
const TABLE_SPAN_PAGES: u64 = 512;

/// Mappings the `ptdrain` drain makes past the pool's reported page count
/// before it gives up on emptying the pool: each needs at least one fresh
/// table page, so the pool's pages plus this slack are always enough.
const DRAIN_SLACK: u64 = 16;

fn main() -> ExitCode
{
    if std::env::args().any(|a| a == "oor")
    {
        out_of_region()
    }
    else if std::env::args().any(|a| a == "ptdrain")
    {
        page_table_drain()
    }
    else
    {
        in_region()
    }
}

// cast_possible_truncation: the pattern byte is intentionally the low 8 bits of
// a per-(page, byte) mix; truncation is the point.
#[allow(clippy::cast_possible_truncation)]
fn pattern(page: usize, byte: usize) -> u8
{
    (page as u8).wrapping_mul(31).wrapping_add(byte as u8)
}

fn in_region() -> ExitCode
{
    let Ok(range) = register_demand_paged(PAGES as u64)
    else
    {
        return ExitCode::from(2);
    };
    let base = range.va_start() as *mut u8;

    // First pass: write. The first store into each page faults; memmgr backs it
    // and the store retries against the now-mapped page.
    for p in 0..PAGES
    {
        let off = p * PAGE;
        for i in 0..PAGE
        {
            // SAFETY: [base, base + PAGES*PAGE) is a registered demand-paged
            // region; touches are backed by the pager on fault.
            unsafe {
                *base.add(off + i) = pattern(p, i);
            }
        }
    }

    // Second pass: read back. Proves the pages stayed mapped (no re-fault, no
    // zero-fill) and were mapped writable.
    for p in 0..PAGES
    {
        let off = p * PAGE;
        for i in 0..PAGE
        {
            // SAFETY: same region, now fully backed.
            let got = unsafe { *base.add(off + i) };
            if got != pattern(p, i)
            {
                return ExitCode::from(3);
            }
        }
    }
    ExitCode::SUCCESS
}

fn out_of_region() -> ExitCode
{
    let Ok(range) = reserve_pages(1)
    else
    {
        return ExitCode::from(2);
    };
    let p = range.va_start() as *mut u8;
    // SAFETY: deliberate fault on an unregistered VA. The pager replies KILL
    // and control should not return.
    unsafe {
        core::ptr::write_volatile(p, 0xAB);
    }
    // Reached only if the pager wrongly backed an unregistered fault; exit
    // success so the harness's "must be killed" assertion fails loudly.
    ExitCode::SUCCESS
}

/// One page of RAM from memmgr (`REQUEST_MEMORY_CAPS`), as a Memory cap this
/// process may map. `None` when the request fails.
fn request_frame(memmgr_ep: u64) -> Option<u64>
{
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) }.ok()?;
    if reply.label != ipc::memmgr_errors::SUCCESS
    {
        return None;
    }
    reply.caps().first().copied()
}

/// The `ptdrain` mode: a demand fault that finds the address space's
/// page-table pool empty is still backed. Exit codes: `0` when the touch is
/// backed and reads back; `2` if a reservation or the registration fails; `3`
/// on a mismatch; `4` if the frame request or a drain mapping fails for a
/// reason other than an empty pool; `5` if the drain does not empty the pool.
fn page_table_drain() -> ExitCode
{
    let info = startup_info();
    let aspace = info.self_aspace;
    let span = TABLE_SPAN_PAGES * PAGE_SIZE;

    // Two spans hold one whole 2 MiB-aligned block. The reservation is this
    // process's alone and nothing has touched it, so no leaf table covers the
    // block: its first touch needs a fresh table page from the pool. The
    // registration funds the pool for the region.
    let Ok(region) = register_demand_paged(2 * TABLE_SPAN_PAGES)
    else
    {
        return ExitCode::from(2);
    };
    let target = region.va_start().next_multiple_of(span);

    let Some(frame) = request_frame(info.memmgr_endpoint)
    else
    {
        return ExitCode::from(4);
    };
    let pool_pages = |aspace| {
        syscall::cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET).map_or(u64::MAX, |b| b / PAGE_SIZE)
    };
    let blocks = pool_pages(aspace).saturating_add(DRAIN_SLACK);
    let Some(drain_pages) = blocks
        .checked_add(1)
        .and_then(|b| b.checked_mul(TABLE_SPAN_PAGES))
    else
    {
        return ExitCode::from(5);
    };
    let Ok(drain) = reserve_pages(drain_pages)
    else
    {
        return ExitCode::from(2);
    };

    // Map the frame once in each 2 MiB block of the second reservation: each
    // map takes at least a fresh leaf table from the pool, until the kernel
    // reports the pool empty.
    let first = drain.va_start().next_multiple_of(span);
    let mut emptied = false;
    for b in 0..blocks
    {
        // SAFETY: the page lies in this process's own reservation `drain`,
        // which nothing else maps and where no Rust object or IPC page lies.
        match unsafe { syscall::mem_map(frame, aspace, first + b * span, 0, 1, MAP_READ) }
        {
            Ok(()) =>
            {}
            Err(e) if e == SyscallError::OutOfMemory as i64 =>
            {
                emptied = true;
                break;
            }
            Err(_) => return ExitCode::from(4),
        }
    }
    if !emptied || pool_pages(aspace) != 0
    {
        return ExitCode::from(5);
    }

    // The first touch of the block faults to the pager with the pool empty.
    let base = target as *mut u8;
    for i in 0..PAGE
    {
        // SAFETY: `target` starts a page of the registered demand region;
        // the store is backed by the pager on fault.
        unsafe { core::ptr::write_volatile(base.add(i), pattern(0, i)) };
    }
    for i in 0..PAGE
    {
        // SAFETY: the same page, now backed.
        if unsafe { core::ptr::read_volatile(base.add(i)) } != pattern(0, i)
        {
            return ExitCode::from(3);
        }
    }
    ExitCode::SUCCESS
}
