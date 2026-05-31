// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: repeated `CSpace` create + delete past the live-count bound.
//!
//! `CSpaceId`s are recycled via a free list, so the `CSpace` namespace is
//! bounded by *live* count, not by *cumulative* creates. To prove recycling
//! holds, this test creates and immediately destroys 10000 `CSpace`s in a
//! tight loop. With `MAX_CSPACES = 4096`, this iteration count is 2.4× the
//! ceiling; if recycling were broken, `cap_create_cspace` would surface
//! `SyscallError::OutOfMemory` at iteration ~4096 and the loop would fail
//! its first negative return.

use syscall::{cap_create_cspace, cap_delete};

use crate::{TestContext, TestResult};

/// Number of create/delete cycles. Chosen well above `MAX_CSPACES = 4096`
/// so a recycling regression aborts the loop before the test completes.
const ITERATIONS: usize = 10_000;

pub fn run(ctx: &TestContext) -> TestResult
{
    for _ in 0..ITERATIONS
    {
        // Smallest viable CSpace: 4 init_pages (wrapper page + 3 pool pages,
        // matching `unit/cap.rs::insert_out_of_bounds_err`'s sizing) and
        // 64 max_slots (well below L1_SIZE * L2_SIZE = 14336).
        let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 64)
            .map_err(|_| "cspace_recycle: cap_create_cspace failed (namespace exhausted?)")?;
        cap_delete(cs).map_err(|_| "cspace_recycle: cap_delete failed")?;
    }
    Ok(())
}
