// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/freed_object_bytes_zeroed.rs

//! Integration: a dead kernel object's bytes read zero through the Memory cap
//! it was retyped from.
//!
//! Splits a grant off the tail of `memory_base` of one page and one Thread
//! slot, and retypes a `CSpace` from its first page and a Thread (guard page,
//! kernel stack, wrapper and TCB page, extended-state area) from the slot
//! above it. Each object's death returns its bytes, and the retype cursor
//! then moves back below them, so `mem_map` lets the grant map them; every
//! byte must read zero. Without the clear, the Thread's TCB and kernel stack
//! (kernel pointers, return addresses into the slid image) and the `CSpace`'s
//! wrapper page would be readable, defeating KASLR
//! (`core/kernel/docs/cross-boundary-disclosure.md` § Kernel state in donated
//! memory).
//!
//! Two orders cover the cursor's moves:
//! - the Thread dies first, at the bump frontier: the cursor rolls back over
//!   it while the `CSpace` below lives; the `CSpace`'s death (its pool's
//!   create-time slab, returned as a run) then rolls the cursor to 0;
//! - the `CSpace` dies first, below a live Thread: its page goes onto the
//!   allocator's page free list; the Thread's death then drains the grant and
//!   resets the cursor to 0, leaving that free-list page above it. The page
//!   keeps the allocator's 16-byte run header (its page count and the
//!   end-of-list sentinel, region offsets and counts, no address;
//!   `core/kernel/docs/memory-internals.md` § Kernel Object Memory), and nothing
//!   else.
//!
//! The grant is restored with `memory_merge`, never `cap_delete`: a deleted
//! RAM tail would free its pages back to the sealed buddy allocator.

use syscall::{
    MAP_READ, cap_create_cspace, cap_create_thread, cap_delete, cap_info, mem_map, mem_unmap,
    memory_merge, memory_split, system_info,
};
use syscall_abi::{CAP_INFO_MEMORY_SIZE, PAGE_SIZE, SystemInfoType};

use crate::{TestContext, TestResult};

/// Probe VA, distinct from the other integration tests' mapping windows.
const PROBE_VA: u64 = 0x1_5700_0000;

/// The retype allocator's end-of-list sentinel, the `next` word of the last
/// run on its page free list.
const FREE_LIST_END: u64 = u64::MAX;

pub fn run(ctx: &TestContext) -> TestResult
{
    let slot_bytes = system_info(SystemInfoType::ThreadRetypeBytes as u64)
        .map_err(|_| "integration::freed_object_bytes_zeroed: system_info(ThreadRetypeBytes)")?;
    let slot_pages = slot_bytes / PAGE_SIZE;
    // A Thread slot is a handful of pages (`unit::sysinfo`), so neither
    // product below saturates.
    let grant_pages = slot_pages.saturating_add(1);
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "integration::freed_object_bytes_zeroed: cap_info(MEMORY_SIZE) failed")?;
    let split_at = size
        .checked_sub(grant_pages.saturating_mul(PAGE_SIZE))
        .ok_or("integration::freed_object_bytes_zeroed: memory_base too small")?;
    let grant = memory_split(ctx.memory_base, split_at)
        .map_err(|_| "integration::freed_object_bytes_zeroed: memory_split failed")?;

    let result = thread_dies_first(ctx, grant, slot_pages)
        .and_then(|()| cspace_dies_first(ctx, grant, slot_pages));

    memory_merge(ctx.memory_base, grant)
        .map_err(|_| "integration::freed_object_bytes_zeroed: memory_merge of the grant failed")?;
    result
}

/// Retype the `CSpace` at the grant's page 0 and the Thread at page 1.
fn create(ctx: &TestContext, grant: u64) -> Result<(u64, u64), &'static str>
{
    let cs = cap_create_cspace(grant, 0, 1)
        .map_err(|_| "integration::freed_object_bytes_zeroed: cap_create_cspace failed")?;
    let Ok(th) = cap_create_thread(grant, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
    else
    {
        cap_delete(cs).ok();
        return Err("integration::freed_object_bytes_zeroed: cap_create_thread failed");
    };
    Ok((cs, th))
}

/// The Thread dies at the bump frontier, then the `CSpace` below it.
fn thread_dies_first(ctx: &TestContext, grant: u64, slot_pages: u64) -> TestResult
{
    let (cs, th) = create(ctx, grant)?;
    cap_delete(th).map_err(|_| "integration::freed_object_bytes_zeroed: cap_delete(thread)")?;
    let result = expect_zero(ctx, grant, 1, slot_pages, None);
    cap_delete(cs).map_err(|_| "integration::freed_object_bytes_zeroed: cap_delete(cspace)")?;
    result?;
    expect_zero(ctx, grant, 0, 1, None)
}

/// The `CSpace` dies below the live Thread, then the Thread drains the grant.
fn cspace_dies_first(ctx: &TestContext, grant: u64, slot_pages: u64) -> TestResult
{
    let (cs, th) = create(ctx, grant)?;
    cap_delete(cs).map_err(|_| "integration::freed_object_bytes_zeroed: cap_delete(cspace)")?;
    cap_delete(th).map_err(|_| "integration::freed_object_bytes_zeroed: cap_delete(thread)")?;
    // Page 0 is a one-page run on the free list: its header is `(1, end)`.
    expect_zero(
        ctx,
        grant,
        0,
        slot_pages.saturating_add(1),
        Some([1, FREE_LIST_END]),
    )
}

/// Map `pages` pages of `grant` from page `first` read-only and require every
/// word to read zero, but for the first two words of page `first` when
/// `header` names them.
fn expect_zero(
    ctx: &TestContext,
    grant: u64,
    first: u64,
    pages: u64,
    header: Option<[u64; 2]>,
) -> TestResult
{
    // SAFETY: `PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_map(grant, ctx.aspace_cap, PROBE_VA, first, pages, MAP_READ) }
        .map_err(|_| "integration::freed_object_bytes_zeroed: freed pages were not mappable")?;
    let words = pages.saturating_mul(PAGE_SIZE / 8);
    let mut result = Ok(());
    for i in 0..words
    {
        // SAFETY: the word lies in the read-only mapping made above, which
        // nothing else writes or references.
        let word = unsafe {
            core::ptr::read_volatile(PROBE_VA.wrapping_add(i.wrapping_mul(8)) as *const u64)
        };
        let expected = match (header, i)
        {
            (Some(h), 0) => h[0],
            (Some(h), 1) => h[1],
            _ => 0,
        };
        if word != expected
        {
            crate::log_u64(
                "ktest: freed byte offset=",
                first
                    .wrapping_mul(PAGE_SIZE)
                    .wrapping_add(i.wrapping_mul(8)),
            );
            crate::log_u64("ktest: freed word=", word);
            result = Err("integration::freed_object_bytes_zeroed: a dead object's bytes survive");
            break;
        }
    }
    // SAFETY: as for the map above; no reference into the span is live.
    unsafe { mem_unmap(ctx.aspace_cap, PROBE_VA, pages) }
        .map_err(|_| "integration::freed_object_bytes_zeroed: mem_unmap failed")?;
    result
}
