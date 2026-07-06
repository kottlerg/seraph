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
//! All retype sources come from `ctx.memory_base` directly; the
//! source cap is never deleted (the parent Memory cap is shared across
//! the suite). Each test cleans up only its own derived caps.

use syscall::{
    cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_delete, cap_info,
    mem_map, mem_unmap, mem_unmap_reclaim,
};
use syscall_abi::{
    CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_USED, MAP_WRITABLE,
};

use crate::{TestContext, TestResult};

const TEST_VA_BASE: u64 = 0x0000_0001_4000_0000;
const SYS_OUT_OF_MEMORY: i64 = -8;
const SYS_QUOTA_EXCEEDED: i64 = -17;

/// Augment-mode on `cap_create_aspace` increases the target AS's PT
/// growth budget without creating a new AS.
pub fn aspace_augment_grows_budget(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;

    // Create an AS with the minimum useful slab: page 0 = wrapper page,
    // page 1 = root PT, no pool pages.
    let aspace = cap_create_aspace(memory, 0, 2)
        .map_err(|_| "retype::aspace_augment: cap_create_aspace failed")?;
    let initial_budget = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::aspace_augment: cap_info(initial budget) failed")?;

    // Augment by 4 pages.
    if cap_create_aspace(memory, aspace, 4).is_err()
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
    let memory = ctx.memory_base;

    let cspace = cap_create_cspace(memory, 0, 1, 256)
        .map_err(|_| "retype::cspace_augment: cap_create_cspace failed")?;
    let initial_budget = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::cspace_augment: cap_info(initial budget) failed")?;

    if cap_create_cspace(memory, cspace, 2, 0).is_err()
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
    let memory = ctx.memory_base;

    // Slab layout: page 0 = wrapper, page 1 = root PT, pages 2..4 = 2
    // pool pages — enough to allocate a few intermediate PT pages but
    // not unbounded. The map loop below is sized to exhaust this.
    let aspace = cap_create_aspace(memory, 0, 4)
        .map_err(|_| "retype::pt_budget: cap_create_aspace failed")?;

    // Map further pages spaced by 1 GiB so each new mapping forces a
    // fresh intermediate PT page (a distinct level-2 slot on x86-64 and in
    // every riscv64 paging mode). After ≤ 3 mappings the pool is exhausted.
    let mut got_oom = false;
    for i in 0..16u64
    {
        let va = TEST_VA_BASE + i * 0x4000_0000; // 1 GiB stride
        match mem_map(memory, aspace, va, 0, 1, MAP_WRITABLE)
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
    let memory = ctx.memory_base;

    // 32 pool pages covers ≥ 4 mappings spread across distinct
    // intermediate PT regions (each fresh region needs 2-4 intermediate PT
    // pages depending on arch, paging mode, and sharing).
    let aspace = cap_create_aspace(memory, 0, 32)
        .map_err(|_| "retype::deep_pt: cap_create_aspace failed")?;

    let mappings = 4usize;
    let stride: u64 = 0x4000_0000; // 1 GiB stride forces fresh level-2 entries.
    for i in 0..mappings
    {
        let va = TEST_VA_BASE + i as u64 * stride;
        if mem_map(memory, aspace, va, 0, 1, MAP_WRITABLE).is_err()
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

/// `mem_unmap_reclaim` (the `MEM_UNMAP_RECLAIM_PTS` path) returns the
/// intermediate page tables a freed span empties back to the per-AS pool,
/// crediting `pt_growth_budget_bytes`. A fresh single-page mapping at a clean
/// VA allocates one intermediate table per non-root level (three on x86-64
/// and riscv64 Sv48; the count varies with the riscv64 paging mode); tearing
/// the region down reclaims them all (the budget round-trips to its pre-map
/// value), and the same VA then remaps from the returned pool pages.
pub fn region_unmap_reclaims_pt_budget(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;

    // Slab: page 0 = wrapper, page 1 = root PT, pages 2..8 = 6 pool pages —
    // ample for the 3 intermediate PTs a single fresh mapping needs.
    let aspace = cap_create_aspace(memory, 0, 8)
        .map_err(|_| "retype::region_reclaim: cap_create_aspace failed")?;

    let budget0 = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::region_reclaim: cap_info(budget0) failed")?;

    // Map one page at a fresh 2 MiB-aligned VA: allocates the full intermediate
    // chain (3 pages) from the pool.
    if mem_map(memory, aspace, TEST_VA_BASE, 0, 1, MAP_WRITABLE).is_err()
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: initial mem_map failed");
    }
    let budget1 = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::region_reclaim: cap_info(budget1) failed")?;
    if budget1 >= budget0
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: mapping did not consume PT budget");
    }

    // Reclaiming unmap: clears the leaf, empties PT→PD→PDPT, returns all three
    // to the pool and credits the budget.
    if mem_unmap_reclaim(aspace, TEST_VA_BASE, 1).is_err()
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: mem_unmap_reclaim failed");
    }
    let budget2 = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::region_reclaim: cap_info(budget2) failed")?;
    if budget2 <= budget1
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: unmap did not credit PT budget");
    }
    if budget2 != budget0
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: reclaimed budget != pre-map budget");
    }

    // The returned pages are reusable: remap the same VA (re-allocates the
    // chain from the pool), then tear it down again.
    if mem_map(memory, aspace, TEST_VA_BASE, 0, 1, MAP_WRITABLE).is_err()
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: remap after reclaim failed");
    }
    mem_unmap_reclaim(aspace, TEST_VA_BASE, 1).ok();

    cap_delete(aspace).ok();
    Ok(())
}

/// A burst of concurrent distinct-VA regions holds peak PT-pool RAM while all
/// are mapped; reclaiming-unmap of each returns its intermediate tables, so the
/// budget recovers to its pre-burst value instead of staying depressed until
/// address-space death. This is the #273 peak-concurrency retention case: the
/// 1 GiB stride gives every region its own PD+PT under a shared PDPT, and the
/// final unmap empties and frees the PDPT too — a full round-trip to baseline.
pub fn concurrent_regions_release_pt_budget_on_unmap(ctx: &TestContext) -> TestResult
{
    const N: u64 = 6;
    const STRIDE: u64 = 0x4000_0000; // 1 GiB — distinct level-2 slot per region.

    let memory = ctx.memory_base;

    // Generous pool: 1 PDPT + N*(PD+PT) intermediate pages plus slack.
    let aspace = cap_create_aspace(memory, 0, 64)
        .map_err(|_| "retype::concurrent_regions: cap_create_aspace failed")?;

    let baseline = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::concurrent_regions: cap_info(baseline) failed")?;

    // Map the whole burst (peak concurrency): budget drops as PTs allocate.
    for i in 0..N
    {
        let va = TEST_VA_BASE + i * STRIDE;
        if mem_map(memory, aspace, va, 0, 1, MAP_WRITABLE).is_err()
        {
            cap_delete(aspace).ok();
            return Err("retype::concurrent_regions: mem_map failed");
        }
    }
    let peak = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::concurrent_regions: cap_info(peak) failed")?;
    if peak >= baseline
    {
        cap_delete(aspace).ok();
        return Err("retype::concurrent_regions: burst did not consume PT budget");
    }

    // Reclaiming-unmap each region; the budget must climb back to baseline.
    for i in 0..N
    {
        let va = TEST_VA_BASE + i * STRIDE;
        if mem_unmap_reclaim(aspace, va, 1).is_err()
        {
            cap_delete(aspace).ok();
            return Err("retype::concurrent_regions: mem_unmap_reclaim failed");
        }
    }
    let after = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::concurrent_regions: cap_info(after) failed")?;

    cap_delete(aspace).ok();

    if after != baseline
    {
        return Err("retype::concurrent_regions: PT budget not fully released on unmap");
    }
    Ok(())
}

/// `CSpace::grow` consumes pool pages as slots are inserted past the
/// first slot page's capacity. `slots_used` advances and `growth_budget`
/// drops in step.
pub fn cspace_grow_consumes_pool(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;

    // init_pages = 3 → wrapper page + 2 pool pages = 111 usable slots.
    // max_slots set generously so insertion isn't capped by max_slots.
    let cspace = cap_create_cspace(memory, 0, 3, 4096)
        .map_err(|_| "retype::cspace_grow: cap_create_cspace failed")?;
    let used_before = cap_info(cspace, CAP_INFO_CSPACE_USED)
        .map_err(|_| "retype::cspace_grow: cap_info(used before) failed")?;
    let budget_before = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::cspace_grow: cap_info(budget before) failed")?;

    let probe = cap_create_endpoint(memory)
        .map_err(|_| "retype::cspace_grow: cap_create_endpoint failed")?;

    // Copy enough times to spill past the first slot page. ~70 copies
    // forces at least one grow on an `L2_SIZE`-slot page (currently 56).
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

/// Pool exhaustion and the `max_slots` quota are distinct failures (#366):
/// an under-seeded pool fails the insert with the refillable `OutOfMemory`
/// (augment-mode then allows further inserts), while reaching `max_slots`
/// fails with the hard `QuotaExceeded`.
pub fn cspace_pool_exhaust_augment_then_quota(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;

    // init_pages = 2 → 1 pool page → 55 usable slots; max_slots = 120
    // deliberately exceeds the seeded capacity to expose both bounds.
    let cspace = cap_create_cspace(memory, 0, 2, 120)
        .map_err(|_| "retype::pool_vs_quota: cap_create_cspace failed")?;
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::pool_vs_quota: cap_create_endpoint failed");
    };

    // Copy until the first failure: the seeded pool backs 55 slots, so 55
    // copies succeed and the 56th hits pool exhaustion.
    let mut ok_before = 0u32;
    let mut err_at_pool = 0i64;
    for _ in 0..=55
    {
        match cap_copy(probe, cspace, 1)
        {
            Ok(_) => ok_before += 1,
            Err(e) =>
            {
                err_at_pool = e;
                break;
            }
        }
    }

    // Refill the pool (2 more slot pages = 112 slots, ample for the
    // remaining quota), then copy up to `max_slots`.
    let augment_ok = cap_create_cspace(memory, cspace, 2, 0).is_ok();
    let mut ok_after = 0u32;
    let mut err_at_quota = 0i64;
    for _ in 0..=65
    {
        match cap_copy(probe, cspace, 1)
        {
            Ok(_) => ok_after += 1,
            Err(e) =>
            {
                err_at_quota = e;
                break;
            }
        }
    }

    // Deleting the CSpace cap reclaims the copies wholesale.
    cap_delete(probe).ok();
    cap_delete(cspace).ok();

    if ok_before != 55 || err_at_pool != SYS_OUT_OF_MEMORY
    {
        return Err(
            "retype::pool_vs_quota: pool exhaustion did not surface OutOfMemory after 55 slots",
        );
    }
    if !augment_ok
    {
        return Err("retype::pool_vs_quota: augment-mode refill failed");
    }
    if ok_after != 65 || err_at_quota != SYS_QUOTA_EXCEEDED
    {
        return Err("retype::pool_vs_quota: quota did not surface QuotaExceeded at max_slots");
    }
    Ok(())
}
