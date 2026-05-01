// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/retype.rs

//! Unit tests for the retype primitive itself.
//!
//! `cap.rs` and `cap_info.rs` cover the user-visible cap-create syscalls;
//! this file exercises the lower-mechanism behaviours that aren't visible
//! from any single create call:
//!
//! - **Augment-mode** on `cap_create_aspace` / `cap_create_cspace` —
//!   topping up an existing AS/CS growth budget by passing a non-zero
//!   target. Functional coverage of the syscall path that is otherwise
//!   only reached when an explicit refill is requested.
//! - **PT-budget exhaustion** — repeated `mem_map` against a freshly
//!   created `AddressSpace` whose initial growth budget covers only its
//!   root PT and one pool page eventually returns `OutOfMemory` from the
//!   intermediate-PT allocation. Exercises the
//!   `pt_growth_budget_bytes`-zero failure path on both arches.
//! - **Deep PT walk** — mapping into a wide VA range forces the per-AS
//!   pool to allocate multiple intermediate PT pages. Verifies the
//!   per-arch `map_user_page_pooled` walker handles intermediate-page
//!   allocation correctly.
//! - **`CSpace` slot-page growth** — populating slots beyond the first
//!   `CSpace` slot page demonstrates `CSpace::grow` consuming pool pages.
//!
//! All retype sources come from `ctx.memory_frame_base` directly; the
//! source cap is never deleted (the parent frame is shared across the
//! suite). Each test cleans up only its own derived caps.

use syscall::{
    cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_delete, cap_info,
    mem_map, mem_unmap,
};
use syscall_abi::{
    CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_USED, MAP_WRITABLE,
};

use crate::{TestContext, TestResult};

const TEST_VA_BASE: u64 = 0x0000_0000_4000_0000;
const SYS_OUT_OF_MEMORY: i64 = -8;

/// Augment-mode on `cap_create_aspace` increases the target AS's PT
/// growth budget without creating a new AS.
pub fn aspace_augment_grows_budget(ctx: &TestContext) -> TestResult
{
    let frame = ctx.memory_frame_base;

    // Create an AS with the minimum useful slab: page 0 = wrapper page,
    // page 1 = root PT, no pool pages.
    let aspace = cap_create_aspace(frame, 0, 2)
        .map_err(|_| "retype::aspace_augment: cap_create_aspace failed")?;
    let initial_budget = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::aspace_augment: cap_info(initial budget) failed")?;

    // Augment by 4 pages.
    if cap_create_aspace(frame, aspace, 4).is_err()
    {
        cap_delete(aspace).ok();
        return Err("retype::aspace_augment: augment cap_create_aspace failed");
    }
    let augmented_budget = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::aspace_augment: cap_info(augmented budget) failed")?;

    cap_delete(aspace).ok();

    if augmented_budget <= initial_budget
    {
        return Err("retype::aspace_augment: budget did not grow");
    }
    Ok(())
}

/// Augment-mode on `cap_create_cspace` increases the target CS's slot-
/// page growth budget without creating a new CS.
pub fn cspace_augment_grows_budget(ctx: &TestContext) -> TestResult
{
    let frame = ctx.memory_frame_base;

    let cspace = cap_create_cspace(frame, 0, 1, 256)
        .map_err(|_| "retype::cspace_augment: cap_create_cspace failed")?;
    let initial_budget = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::cspace_augment: cap_info(initial budget) failed")?;

    if cap_create_cspace(frame, cspace, 2, 0).is_err()
    {
        cap_delete(cspace).ok();
        return Err("retype::cspace_augment: augment cap_create_cspace failed");
    }
    let augmented_budget = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::cspace_augment: cap_info(augmented budget) failed")?;

    cap_delete(cspace).ok();

    if augmented_budget <= initial_budget
    {
        return Err("retype::cspace_augment: budget did not grow");
    }
    Ok(())
}

/// `mem_map` against a freshly minted AS whose budget is small must
/// return `OutOfMemory` once the pool is drained. Maps page-after-page
/// across a VA range wide enough to force intermediate PT page
/// allocation.
pub fn pt_budget_exhaustion_returns_oom(ctx: &TestContext) -> TestResult
{
    let frame = ctx.memory_frame_base;

    // Slab layout: page 0 = wrapper, page 1 = root PT, pages 2..4 = 2
    // pool pages — enough to allocate a few intermediate PT pages but
    // not unbounded. The map loop below is sized to exhaust this.
    let aspace = cap_create_aspace(frame, 0, 4)
        .map_err(|_| "retype::pt_budget: cap_create_aspace failed")?;

    // Map further pages spaced by 1 GiB so each new mapping forces a
    // fresh intermediate PT page (PML2 / sv48 intermediate). After ≤ 3
    // mappings the pool is exhausted.
    let mut got_oom = false;
    for i in 0..16u64
    {
        let va = TEST_VA_BASE + i * 0x4000_0000; // 1 GiB stride
        match mem_map(frame, aspace, va, 0, 1, MAP_WRITABLE)
        {
            Ok(()) =>
            {}
            Err(SYS_OUT_OF_MEMORY) =>
            {
                got_oom = true;
                break;
            }
            Err(_) => break,
        }
    }

    cap_delete(aspace).ok();

    if !got_oom
    {
        return Err("retype::pt_budget: exhaustion did not return OutOfMemory");
    }
    Ok(())
}

/// Mapping into a wide VA range forces multiple distinct intermediate-PT
/// pages to be allocated from the per-AS pool. With a generously sized
/// pool, every map must succeed.
pub fn deep_pt_walk_consumes_pool(ctx: &TestContext) -> TestResult
{
    let frame = ctx.memory_frame_base;

    // 32 pool pages covers ≥ 4 mappings spread across distinct PML2 /
    // intermediate PT regions on x86-64 / sv48 (each fresh region needs
    // 2-3 intermediate PT pages depending on arch + sharing).
    let aspace =
        cap_create_aspace(frame, 0, 32).map_err(|_| "retype::deep_pt: cap_create_aspace failed")?;

    let mappings = 4usize;
    let stride: u64 = 0x4000_0000; // 1 GiB stride forces fresh PML2 entries.
    for i in 0..mappings
    {
        let va = TEST_VA_BASE + i as u64 * stride;
        if mem_map(frame, aspace, va, 0, 1, MAP_WRITABLE).is_err()
        {
            cap_delete(aspace).ok();
            return Err("retype::deep_pt: mem_map failed despite ample budget");
        }
    }

    // Unmap each page so the AS is clean before deletion.
    for i in 0..mappings
    {
        let va = TEST_VA_BASE + i as u64 * stride;
        mem_unmap(aspace, va, 1).ok();
    }

    cap_delete(aspace).ok();
    Ok(())
}

/// `CSpace::grow` consumes pool pages as slots are inserted past the
/// first slot page's capacity. `slots_used` advances and `growth_budget`
/// drops in step.
pub fn cspace_grow_consumes_pool(ctx: &TestContext) -> TestResult
{
    let frame = ctx.memory_frame_base;

    // 3 slot pages = ~192 slots (depending on slot size). max_slots set
    // generously so insertion isn't capped by max_slots.
    let cspace = cap_create_cspace(frame, 0, 3, 4096)
        .map_err(|_| "retype::cspace_grow: cap_create_cspace failed")?;
    let used_before = cap_info(cspace, CAP_INFO_CSPACE_USED)
        .map_err(|_| "retype::cspace_grow: cap_info(used before) failed")?;
    let budget_before = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::cspace_grow: cap_info(budget before) failed")?;

    let probe = cap_create_endpoint(frame)
        .map_err(|_| "retype::cspace_grow: cap_create_endpoint failed")?;

    // Copy enough times to spill past the first slot page. ~70 copies
    // forces at least one grow on a typical 64-slot page.
    let copies = 70usize;
    for _ in 0..copies
    {
        if cap_copy(probe, cspace, 1).is_err()
        {
            break;
        }
    }

    let used_after = cap_info(cspace, CAP_INFO_CSPACE_USED).unwrap_or(used_before);
    let budget_after = cap_info(cspace, CAP_INFO_CSPACE_BUDGET).unwrap_or(budget_before);

    cap_delete(probe).ok();
    cap_delete(cspace).ok();

    if used_after <= used_before
    {
        return Err("retype::cspace_grow: slots_used did not advance");
    }
    if budget_after >= budget_before
    {
        return Err("retype::cspace_grow: budget did not decrease as pool was consumed");
    }
    Ok(())
}
