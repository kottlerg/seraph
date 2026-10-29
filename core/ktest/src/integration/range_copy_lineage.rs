// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/range_copy_lineage.rs

//! Integration: the copy limit of a range-capability lineage, and the root's
//! lifetime under live copies.
//!
//! Takes a fresh lineage root (`crate::arch::fresh_range_root`: an `IoPort`
//! split on x86-64, an `Mmio` split on riscv64), then derives [`COPY_LIMIT`]
//! copies of it and checks that one more is refused with `QuotaExceeded`,
//! whether derived from the root or from a copy
//! ([core/kernel/docs/capability-internals.md § Copies and
//! Lineages](../../../kernel/docs/capability-internals.md#copies-and-lineages)).
//! Deleting the root while its copies live keeps the limit counting the copies
//! alone, and deleting one copy frees a place for a new one. Every object is
//! then deleted; a root body freed twice or never would surface as a kernel
//! fault or as a later SEED exhaustion rather than here, so the test keeps the
//! lineage's whole life inside one run.

use syscall::{cap_delete, cap_derive};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// The kernel's `RANGE_COPY_LIMIT`: live copies one lineage admits.
const COPY_LIMIT: usize = 64;

pub fn run(ctx: &TestContext) -> TestResult
{
    let Some(root) = crate::arch::fresh_range_root(ctx)
    else
    {
        crate::log("ktest: integration::range_copy_lineage SKIP (no fresh range root)");
        return Ok(());
    };

    let mut copies = [0u32; COPY_LIMIT];
    let mut made = 0;
    let result = check(root, &mut copies, &mut made);
    for &c in &copies[..made]
    {
        cap_delete(c).ok();
    }
    cap_delete(root).ok();
    result
}

fn check(root: u32, copies: &mut [u32; COPY_LIMIT], made: &mut usize) -> TestResult
{
    let refused = SyscallError::QuotaExceeded as i64;
    while *made < COPY_LIMIT
    {
        copies[*made] = cap_derive(root, syscall::RIGHTS_ALL)
            .map_err(|_| "integration::range_copy_lineage: a copy under the limit was refused")?;
        *made += 1;
    }
    if cap_derive(root, syscall::RIGHTS_ALL) != Err(refused)
        || cap_derive(copies[0], syscall::RIGHTS_ALL) != Err(refused)
    {
        return Err("integration::range_copy_lineage: a copy past the limit was not refused");
    }

    // The root goes; its copies, and the lineage count, stay.
    cap_delete(root).map_err(|_| "integration::range_copy_lineage: cap_delete(root) failed")?;
    if cap_derive(copies[1], syscall::RIGHTS_ALL) != Err(refused)
    {
        return Err("integration::range_copy_lineage: the root's delete freed a copy's place");
    }

    // A copy goes; its place is free again.
    cap_delete(copies[0])
        .map_err(|_| "integration::range_copy_lineage: cap_delete(copy) failed")?;
    copies[0] = cap_derive(copies[1], syscall::RIGHTS_ALL)
        .map_err(|_| "integration::range_copy_lineage: a freed copy place was not reusable")?;
    Ok(())
}
