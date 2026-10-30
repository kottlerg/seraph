// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/cspace_recycle.rs

//! Stress test: repeated `CSpace` create + delete past the registry's
//! capacity.
//!
//! `CSpaceId`s are recycled via the registry's free list, so the registry is
//! bounded by *live* count, not by *cumulative* creates. The registry arena
//! holds one id per page of DRAM, rounded up to whole chunks
//! (core/kernel/docs/capability-internals.md § Representation). This test
//! creates and immediately destroys one more `CSpace` than that capacity, in
//! a tight loop; if destruction did not return its id, `cap_create_cspace`
//! would surface `SyscallError::OutOfMemory` once the arena ran dry and the
//! loop would fail.

use init_protocol::InitInfo;
use syscall::{cap_create_cspace, cap_delete};

use crate::{TestContext, TestResult};

/// Ids per registry chunk (`cap::registry::ENTRIES_PER_CHUNK`). An
/// underestimate would let a leak hide in the chunk's tail, so the count
/// below rounds up to whole chunks of this size.
const IDS_PER_CHUNK: u64 = 65_536;

const PAGE: u64 = 4096;

/// Create/delete cycles: the registry capacity the kernel sized from
/// `system_ram_bytes`, plus one.
fn iterations(ctx: &TestContext) -> u64
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // the life of the harness.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let pages = info.system_ram_bytes.div_ceil(PAGE);
    pages.div_ceil(IDS_PER_CHUNK).max(1) * IDS_PER_CHUNK + 1
}

pub fn run(ctx: &TestContext) -> TestResult
{
    for _ in 0..iterations(ctx)
    {
        // One page: the wrapper alone, the cheapest CSpace.
        let cs = cap_create_cspace(ctx.memory_base, 0, 1)
            .map_err(|_| "cspace_recycle: cap_create_cspace failed (ids not recycled?)")?;
        cap_delete(cs).map_err(|_| "cspace_recycle: cap_delete failed")?;
    }
    Ok(())
}
