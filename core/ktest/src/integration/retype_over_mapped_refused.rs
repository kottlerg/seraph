// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/retype_over_mapped_refused.rs

//! Integration: a retype never carves kernel objects out of a page some
//! address space maps.
//!
//! Splits two four-page grants off the tail of `memory_base` and checks the
//! converse order of the retype/map boundary
//! ([docs/capability-model.md § Typed Memory](../../../../docs/capability-model.md#typed-memory)):
//!
//! - With the grant's first page mapped writable, `cap_create_cspace` from the
//!   grant returns `OutOfMemory` and leaves the grant's ledger as it was: its
//!   available bytes are unchanged, its retype cursor has not moved (the next
//!   page still maps), and an equal-size retype from the other grant succeeds.
//!   Once the page is unmapped the same retype succeeds.
//! - A page mapped through the grant stays protected after the grant is split
//!   and the tail merged back and split again: the refusal follows the frame,
//!   not the capability object.
//! - A page mapped only into another address space is protected until that
//!   address space is destroyed, and retypable after.
//! - A span unmap with `MEM_UNMAP_RECLAIM_PTS` releases every frame it clears,
//!   including frames past the kernel's release batch: a span of physically
//!   discontiguous pages, one more than the batch holds runs, is unretypable
//!   while mapped and retypable in full after the unmap.
//!
//! Without the refusal a process holding `WRITE | RETYPE` on a grant could map
//! it, retype a `CSpace` into the mapped page, and forge capability slots
//! through its mapping.
//!
//! The grants are restored with `memory_merge`, never `cap_delete`: a deleted
//! RAM tail would free its pages back to the sealed buddy allocator.

use syscall::{
    MAP_WRITABLE, cap_create_aspace, cap_create_cspace, cap_delete, cap_info, mem_map, mem_unmap,
    mem_unmap_reclaim, memory_merge, memory_split,
};
use syscall_abi::{CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_SIZE, SyscallError};

use crate::{TestContext, TestResult};

const PAGE: u64 = 0x1000;

/// Pages split off `memory_base` for each grant.
const GRANT_PAGES: u64 = 4;

/// Probe VA in ktest's own address space, distinct from the other integration
/// tests' mapping windows.
const OWN_VA: u64 = 0x1_5A00_0000;

/// Probe VA in the address space the teardown phase creates.
const OTHER_AS_VA: u64 = 0x1_5B00_0000;

/// Pages mapped by the span phase: one more than the kernel's frame-map
/// release batch holds runs (`mm::frame_map::ReleaseBatch`, 16), each its own
/// run, so the span unmap must drain a full batch mid-walk.
const SPAN_PAGES: u64 = 17;

/// Pages of the span phase's grant: the span maps every other page of it.
const SPAN_GRANT_PAGES: u64 = 2 * SPAN_PAGES;

/// Base VA of the span phase's mappings in ktest's own address space.
const SPAN_VA: u64 = 0x1_5C00_0000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "integration::retype_over_mapped_refused: cap_info(MEMORY_SIZE) failed")?;
    if size < 2 * GRANT_PAGES * PAGE
    {
        return Err("integration::retype_over_mapped_refused: memory_base too small");
    }
    let grant_at = size - GRANT_PAGES * PAGE;
    let grant = memory_split(ctx.memory_base, grant_at)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_split (grant) failed")?;
    let result = match memory_split(ctx.memory_base, grant_at - GRANT_PAGES * PAGE)
    {
        Ok(other) =>
        {
            let result = phases(ctx, grant, other);
            memory_merge(ctx.memory_base, other).map_err(|_| {
                "integration::retype_over_mapped_refused: memory_merge of the other grant failed"
            })?;
            result
        }
        Err(_) => Err("integration::retype_over_mapped_refused: memory_split (other) failed"),
    };
    memory_merge(ctx.memory_base, grant)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_merge of the grant failed")?;
    result
}

fn phases(ctx: &TestContext, grant: u32, other: u32) -> TestResult
{
    refusal_leaves_ledger(ctx, grant, other)?;
    refusal_survives_split_and_merge(ctx, grant)?;
    teardown_releases_frames(ctx, grant)?;
    span_unmap_releases_every_frame(ctx)
}

/// Map `page` of `memory` writable at `va` in `aspace`.
///
/// # Safety
/// `va` is a scratch VA of ktest's own address space (crate docs § Scratch
/// VAs), or `aspace` is an address space ktest runs nothing in.
unsafe fn map_one(memory: u32, aspace: u32, va: u64, page: u64) -> TestResult
{
    // SAFETY: caller contract.
    unsafe { mem_map(memory, aspace, va, page, 1, MAP_WRITABLE) }
        .map_err(|_| "integration::retype_over_mapped_refused: mem_map failed")
}

/// Unmap the scratch page at `OWN_VA`.
fn unmap_own(ctx: &TestContext) -> TestResult
{
    // SAFETY: `OWN_VA` is a scratch VA (crate docs § Scratch VAs), so the span
    // holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap(ctx.aspace_cap, OWN_VA, 1) }
        .map_err(|_| "integration::retype_over_mapped_refused: mem_unmap failed")
}

/// Assert a one-page `CSpace` retype from `memory` is refused with
/// `OutOfMemory`, deleting the `CSpace` if it was not.
fn expect_refused(memory: u32) -> TestResult
{
    match cap_create_cspace(memory, 0, 1)
    {
        Err(e) if e == SyscallError::OutOfMemory as i64 => Ok(()),
        Ok(cs) =>
        {
            cap_delete(cs).ok();
            Err("integration::retype_over_mapped_refused: a retype carved a mapped page")
        }
        Err(_) => Err("integration::retype_over_mapped_refused: wrong error from the retype"),
    }
}

/// Assert a one-page `CSpace` retype from `memory` succeeds, and delete it.
fn expect_retype(memory: u32) -> TestResult
{
    expect_retype_pages(memory, 1)
}

/// Assert a `pages`-page `CSpace` retype from `memory` succeeds, and delete it.
fn expect_retype_pages(memory: u32, pages: u64) -> TestResult
{
    let cs = cap_create_cspace(memory, 0, pages)
        .map_err(|_| "integration::retype_over_mapped_refused: a retype of free pages failed")?;
    cap_delete(cs).map_err(|_| "integration::retype_over_mapped_refused: cap_delete failed")
}

/// The refused retype changes nothing: the ledger, the cursor, and the other
/// grant's capacity are as before, and unmapping the page lifts the refusal.
fn refusal_leaves_ledger(ctx: &TestContext, grant: u32, other: u32) -> TestResult
{
    // SAFETY: `OWN_VA` is a scratch VA (crate docs § Scratch VAs).
    unsafe { map_one(grant, ctx.aspace_cap, OWN_VA, 0) }?;
    let before = cap_info(grant, CAP_INFO_MEMORY_AVAILABLE);
    let refused = expect_refused(grant);
    let after = cap_info(grant, CAP_INFO_MEMORY_AVAILABLE);
    // A cursor the refusal left advanced would refuse this map of page 1.
    // SAFETY: `OWN_VA + PAGE` is a scratch VA (crate docs § Scratch VAs).
    let cursor = unsafe { map_one(grant, ctx.aspace_cap, OWN_VA + PAGE, 1) }.and_then(|()| {
        // SAFETY: as for the map above.
        unsafe { mem_unmap(ctx.aspace_cap, OWN_VA + PAGE, 1) }
            .map_err(|_| "integration::retype_over_mapped_refused: mem_unmap failed")
    });
    unmap_own(ctx)?;
    refused?;
    if before.is_err() || before != after
    {
        return Err("integration::retype_over_mapped_refused: the refusal changed the ledger");
    }
    cursor.map_err(|_| "integration::retype_over_mapped_refused: the refusal moved the cursor")?;
    expect_retype(other)?;
    expect_retype(grant)
}

/// A frame mapped through the grant stays unretypable through a split of the
/// grant and a merge and re-split of its tail.
fn refusal_survives_split_and_merge(ctx: &TestContext, grant: u32) -> TestResult
{
    // SAFETY: `OWN_VA` is a scratch VA (crate docs § Scratch VAs).
    unsafe { map_one(grant, ctx.aspace_cap, OWN_VA, 2) }?;
    let result = split_tail_refuses(grant).and_then(|()| split_tail_refuses(grant));
    unmap_own(ctx)?;
    result?;
    let tail = memory_split(grant, 2 * PAGE)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_split of the grant failed")?;
    let retyped = expect_retype(tail);
    memory_merge(grant, tail)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_merge of the tail failed")?;
    retyped
}

/// Split the grant's last two pages off, assert a retype from the tail (whose
/// first page the caller has mapped through the grant) is refused, and merge
/// the tail back.
fn split_tail_refuses(grant: u32) -> TestResult
{
    let tail = memory_split(grant, 2 * PAGE)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_split of the grant failed")?;
    let refused = expect_refused(tail);
    memory_merge(grant, tail)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_merge of the tail failed")?;
    refused
}

/// A frame mapped only into another address space is unretypable until that
/// address space is destroyed.
fn teardown_releases_frames(ctx: &TestContext, grant: u32) -> TestResult
{
    let aspace = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "integration::retype_over_mapped_refused: cap_create_aspace failed")?;
    // SAFETY: `aspace` is an address space this test created, which runs
    // nothing of ktest's.
    let refused =
        unsafe { map_one(grant, aspace, OTHER_AS_VA, 0) }.and_then(|()| expect_refused(grant));
    // Destroying the address space drops its leaves without an unmap.
    cap_delete(aspace)
        .map_err(|_| "integration::retype_over_mapped_refused: cap_delete(aspace) failed")?;
    refused?;
    expect_retype(grant)
}

/// A span unmap releases every frame it clears, past the release batch.
fn span_unmap_releases_every_frame(ctx: &TestContext) -> TestResult
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "integration::retype_over_mapped_refused: cap_info(MEMORY_SIZE) failed")?;
    let at = size
        .checked_sub(SPAN_GRANT_PAGES * PAGE)
        .ok_or("integration::retype_over_mapped_refused: memory_base too small for the span")?;
    let wide = memory_split(ctx.memory_base, at)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_split (span) failed")?;
    let result = span_phase(ctx, wide);
    memory_merge(ctx.memory_base, wide)
        .map_err(|_| "integration::retype_over_mapped_refused: memory_merge (span) failed")?;
    result
}

/// Map page `2 * i` of `wide` at `SPAN_VA + i` pages, so no two adjacent
/// leaves name adjacent frames, then check the retype refusal before and after
/// one reclaiming unmap of the span.
fn span_phase(ctx: &TestContext, wide: u32) -> TestResult
{
    let mut mapped = Ok(());
    for i in 0..SPAN_PAGES
    {
        // SAFETY: the span lies in ktest's scratch band (crate docs § Scratch
        // VAs), so it holds no Rust object or IPC page of ktest.
        mapped = unsafe { map_one(wide, ctx.aspace_cap, SPAN_VA + i * PAGE, 2 * i) };
        if mapped.is_err()
        {
            break;
        }
    }
    let refused = mapped.and_then(|()| expect_refused(wide));
    // SAFETY: as for the maps above; a page the loop did not map is skipped.
    unsafe { mem_unmap_reclaim(ctx.aspace_cap, SPAN_VA, SPAN_PAGES) }
        .map_err(|_| "integration::retype_over_mapped_refused: mem_unmap_reclaim failed")?;
    refused?;
    // The retype covers every page of the grant up to the last one mapped.
    expect_retype_pages(wide, SPAN_GRANT_PAGES - 1)
}
