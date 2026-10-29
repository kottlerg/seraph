// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/mem_map_retyped_refused.rs

//! Integration: a Memory cap cannot map the bytes it has retyped away.
//!
//! Splits a four-page grant off the tail of `memory_base`, creates a `CSpace`
//! from its first page and augments that `CSpace` with its second, then
//! asserts that `mem_map` refuses both retyped pages (writable or read-only)
//! with `InvalidArgument` and still maps the first page past the retype
//! cursor. Without the refusal the caller could write the `CSpace`'s wrapper
//! and slot pages directly, forging capability slots
//! ([docs/capability-model.md § Typed Memory](../../../../docs/capability-model.md#typed-memory)).
//!
//! The grant is restored with `memory_merge`, never `cap_delete`: a deleted
//! RAM tail would free its pages back to the sealed buddy allocator.

use syscall::{
    MAP_READ, MAP_WRITABLE, cap_create_cspace, cap_delete, cap_info, mem_map, mem_unmap,
    memory_merge, memory_split,
};
use syscall_abi::{CAP_INFO_MEMORY_SIZE, SyscallError};

use crate::{TestContext, TestResult};

const PAGE: u64 = 0x1000;

/// Pages split off `memory_base` for the grant.
const GRANT_PAGES: u64 = 4;

/// Probe VA, distinct from the other integration tests' mapping windows.
const PROBE_VA: u64 = 0x1_5800_0000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "integration::mem_map_retyped_refused: cap_info(MEMORY_SIZE) failed")?;
    let split_at = size
        .checked_sub(GRANT_PAGES * PAGE)
        .ok_or("integration::mem_map_retyped_refused: memory_base too small")?;
    let grant = memory_split(ctx.memory_base, split_at)
        .map_err(|_| "integration::mem_map_retyped_refused: memory_split failed")?;

    let result = check_boundary(ctx, grant);

    memory_merge(ctx.memory_base, grant)
        .map_err(|_| "integration::mem_map_retyped_refused: memory_merge of the grant failed")?;
    result
}

/// Retype the grant's first two pages into a `CSpace` and probe `mem_map`
/// against them and the page after. Leaves the grant virgin again.
fn check_boundary(ctx: &TestContext, grant: u32) -> TestResult
{
    let cs = cap_create_cspace(grant, 0, 1)
        .map_err(|_| "integration::mem_map_retyped_refused: cap_create_cspace failed")?;
    let result = probe(ctx, grant, cs);
    // Returns both retyped pages to the grant; the cursor drains back to 0.
    cap_delete(cs)
        .map_err(|_| "integration::mem_map_retyped_refused: cap_delete(cspace) failed")?;
    result
}

fn probe(ctx: &TestContext, grant: u32, cs: u32) -> TestResult
{
    cap_create_cspace(grant, cs, 1)
        .map_err(|_| "integration::mem_map_retyped_refused: augment cap_create_cspace failed")?;

    let refused = SyscallError::InvalidArgument as i64;
    for page in 0..2
    {
        for prot in [MAP_WRITABLE, MAP_READ]
        {
            match mem_map(grant, ctx.aspace_cap, PROBE_VA, page, 1, prot)
            {
                Err(e) if e == refused =>
                {}
                Ok(()) =>
                {
                    mem_unmap(ctx.aspace_cap, PROBE_VA, 1).ok();
                    return Err("integration::mem_map_retyped_refused: a retyped page was mapped");
                }
                Err(_) =>
                {
                    return Err(
                        "integration::mem_map_retyped_refused: wrong error mapping a retyped page",
                    );
                }
            }
        }
    }

    mem_map(grant, ctx.aspace_cap, PROBE_VA, 2, 1, MAP_WRITABLE).map_err(
        |_| "integration::mem_map_retyped_refused: the page past the retype cursor was refused",
    )?;
    mem_unmap(ctx.aspace_cap, PROBE_VA, 1)
        .map_err(|_| "integration::mem_map_retyped_refused: mem_unmap failed")?;
    Ok(())
}
