// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/range_copy_lineage.rs

//! Integration: the copy limit of a range-capability lineage, and the root's
//! lifetime under live copies.
//!
//! Splits a fresh lineage root off a copy of an `Mmio` aperture capability,
//! then derives [`COPY_LIMIT`] copies of it and checks that one more is
//! refused with `QuotaExceeded`, whether derived from the root or from a copy
//! ([core/kernel/docs/capability-internals.md § Copies and
//! Lineages](../../../kernel/docs/capability-internals.md#copies-and-lineages)).
//! Deleting the root while its copies live keeps the limit counting the copies
//! alone, and deleting one copy frees a place for a new one. Every object is
//! then deleted; a root body freed twice or never would surface as a kernel
//! fault or as a later SEED exhaustion rather than here, so the test keeps the
//! lineage's whole life inside one run.

use init_protocol::{CapType, InitInfo};
use syscall::{cap_delete, cap_derive, mmio_split};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

/// The kernel's `RANGE_COPY_LIMIT`: live copies one lineage admits.
const COPY_LIMIT: usize = 64;

const PAGE: u64 = 0x1000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let Some(root) = fresh_root(ctx)
    else
    {
        crate::log("ktest: integration::range_copy_lineage SKIP (no splittable Mmio cap)");
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

/// A lineage root of its own: the low page split off a copy of an `Mmio`
/// capability of at least two pages, the high part deleted.
fn fresh_root(ctx: &TestContext) -> Option<u32>
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    for d in crate::init_info::descriptors(info)
    {
        if d.cap_type != CapType::Mmio || d.aux1 < 2 * PAGE
        {
            continue;
        }
        // A slot an earlier test consumed refuses the derive.
        let Ok(copy) = cap_derive(d.slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        if let Ok((low, high)) = mmio_split(copy, PAGE)
        {
            cap_delete(high).ok();
            return Some(low);
        }
        cap_delete(copy).ok();
    }
    None
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
