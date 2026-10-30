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
//!
//! Without the refusal a process holding `WRITE | RETYPE` on a grant could map
//! it, retype a `CSpace` into the mapped page, and forge capability slots
//! through its mapping.
//!
//! The grants are restored with `memory_merge`, never `cap_delete`: a deleted
//! RAM tail would free its pages back to the sealed buddy allocator.

use syscall::{
    MAP_WRITABLE, cap_create_aspace, cap_create_cspace, cap_delete, cap_info, mem_map, mem_unmap,
    memory_merge, memory_split,
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
    teardown_releases_frames(ctx, grant)
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
    let cs = cap_create_cspace(memory, 0, 1)
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
