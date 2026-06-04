// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/mm.rs

//! Tier 1 tests for memory management syscalls.
//!
//! Covers: `SYS_MEMORY_SPLIT`, `SYS_MEM_MAP`, `SYS_MEM_UNMAP`,
//! `SYS_MEM_PROTECT`, `SYS_ASPACE_QUERY`.
//!
//! Memory cap layout after `aspace_cap` (as provided by the kernel/bootloader):
//!   `aspace_cap + 1` — TEXT segment Memory cap
//!   `aspace_cap + 2` — RODATA segment Memory cap
//!   `aspace_cap + 3` — BSS/DATA segment Memory cap
//!
//! Every segment cap carries full rights (`MAP|READ|WRITE|EXECUTE|RETYPE`): the
//! kernel mints all RAM frames uniformly so they flow into memmgr's pool as
//! general RAM at init reap. Page-table protection (R/RW/RX) is applied at map
//! time by `map_segment`, independent of cap rights.
//!
//! Segment Memory caps own their physical memory (the kernel mints them with
//! `owns_memory=true` so the init-reap donation cascade can return them to
//! memmgr). Tests therefore MUST NOT `cap_delete` or otherwise dec-ref a
//! segment cap (or a tail derived from one) while the segment is still
//! mapped in ktest's own address space — the dealloc would buddy-free phys
//! pages still referenced by live PTEs and silently alias future allocations.
//! Split/merge/delete exercises operate on pool-allocated frames; segments
//! are read-only test surfaces for `mem_map` / `mem_protect`.

use syscall::{MAP_READ, MAP_WRITABLE, aspace_query, mem_map, mem_unmap};

use crate::{TestContext, TestResult};

/// Safe test virtual address: 1 GiB. Well above ktest's load address and stack.
/// Used consistently across mm tests to avoid mapping conflicts.
const TEST_VA: u64 = 0x4000_0000;

// ── SYS_MEMORY_SPLIT / SYS_MEMORY_MERGE ─────────────────────────────────────────

/// Split-merge round-trip on the RODATA segment cap (Option D semantics).
///
/// Validates the full inverse relationship between `memory_split` and
/// `memory_merge`:
///
/// 1. Splitting RODATA at one page shrinks the parent slot in place to a
///    single page and returns a new tail slot covering the remainder.
/// 2. Merging in the wrong order (tail, parent) is rejected — the
///    contiguity check requires `parent.base + parent.size == tail.base`.
/// 3. Merging in the correct order absorbs the tail back into the parent;
///    the parent slot survives.
/// 4. The merged cap can be re-split at the same offset, proving the
///    merge correctly restored the parent's size and base.
///
/// The test exclusively uses `memory_split` / `memory_merge` and never
/// `cap_delete` on a segment-derived tail. Segment caps own their
/// physical memory (kernel mint sets `owns_memory=true` for the
/// init-reap donation cascade), so a `cap_delete` of a tail whose phys
/// range is still mapped in ktest's own address space would buddy-free
/// pages while live PTEs alias them. `memory_merge` clears `owns_memory`
/// on the consumed tail before `dec_ref`, so the matching round-trip
/// leaves no dangling deletes and preserves the original mapping.
pub fn memory_split_merge(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = 0x1000;

    let rodata_cap = ctx.aspace_cap + 2;
    let tail =
        syscall::memory_split(rodata_cap, PAGE).map_err(|_| "memory_split on RODATA failed")?;
    if tail == rodata_cap
    {
        return Err("memory_split returned the parent's slot for the tail");
    }

    if syscall::memory_merge(tail, rodata_cap).is_ok()
    {
        return Err("memory_merge(tail, parent) should fail (contiguity reversed)");
    }

    syscall::memory_merge(rodata_cap, tail).map_err(|_| "memory_merge halves failed")?;

    let tail2 =
        syscall::memory_split(rodata_cap, PAGE).map_err(|_| "re-split of merged cap failed")?;
    if tail2 == rodata_cap
    {
        return Err("re-split returned parent slot for tail");
    }

    // Restore RODATA to its original size via merge. Using `cap_delete`
    // here would dec-ref a Memory cap whose phys range is still mapped at
    // RODATA's segment VA; the dealloc path would buddy-free pages live
    // in ktest's own page tables.
    syscall::memory_merge(rodata_cap, tail2).map_err(|_| "final memory_merge failed")?;
    Ok(())
}

// ── SYS_MEM_MAP / SYS_MEM_UNMAP ──────────────────────────────────────────────

/// `mem_map` maps a frame page into the address space; `mem_unmap` removes it.
///
/// Allocates a frame from the pool, maps it, verifies via `aspace_query`,
/// then unmaps and returns the frame to the pool.
pub fn mem_map_unmap(ctx: &TestContext) -> TestResult
{
    let mut memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_map_unmap: frame pool exhausted")?;

    // Map one page at TEST_VA, offset 0 within the cap region.
    memory_cap.map(TEST_VA).map_err(|_| "mem_map failed")?;

    // Verify the mapping appears in the address space.
    let phys =
        aspace_query(ctx.aspace_cap, TEST_VA).map_err(|_| "aspace_query after mem_map failed")?;
    if phys == 0 || phys & 0xFFF != 0
    {
        return Err("aspace_query returned invalid physical address after mem_map");
    }

    // FrameGuard drop unmaps and returns frame to pool.
    Ok(())
}

// ── SYS_MEM_PROTECT ───────────────────────────────────────────────────────────

/// `mem_protect` changes permission flags on an existing mapping.
///
/// Maps a frame page, sets it to read-only (prot = 0: no WRITE, no EXECUTE),
/// then unmaps. Verifying that a write actually faults requires a userspace
/// fault handler (deferred).
pub fn mem_protect(ctx: &TestContext) -> TestResult
{
    let mut memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_protect: frame pool exhausted")?;

    memory_cap
        .map(TEST_VA)
        .map_err(|_| "mem_map for protect test failed")?;

    // prot = 0: read-only. Always valid regardless of Memory cap rights.
    syscall::mem_protect(memory_cap.cap(), ctx.aspace_cap, TEST_VA, 1, 0)
        .map_err(|_| "mem_protect (read-only) failed")?;

    // FrameGuard drop unmaps and returns frame to pool.
    Ok(())
}

// ── SYS_MEM_PROTECT negative ──────────────────────────────────────────────────

/// `mem_protect` on an unmapped virtual address must return an error.
pub fn mem_protect_unmapped_err(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("mem_protect_unmapped_err: frame pool exhausted")?;
    // 0x1000_0000 is not mapped by ktest.
    let unmapped_va = 0x1000_0000u64;
    let err = syscall::mem_protect(memory_cap, ctx.aspace_cap, unmapped_va, 1, 0);

    // SAFETY: memory_cap was allocated from pool and never mapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("mem_protect on unmapped VA should fail");
    }
    Ok(())
}

// ── SYS_MEM_UNMAP idempotent ──────────────────────────────────────────────────

/// Unmapping an already-unmapped VA is a no-op, not an error.
pub fn mem_unmap_idempotent(ctx: &TestContext) -> TestResult
{
    let mut memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_unmap_idempotent: frame pool exhausted")?;

    memory_cap
        .map(TEST_VA)
        .map_err(|_| "mem_map for idempotent-unmap test failed")?;
    mem_unmap(ctx.aspace_cap, TEST_VA, 1).map_err(|_| "first mem_unmap failed")?;
    // Second unmap of the same range must succeed (no-op).
    mem_unmap(ctx.aspace_cap, TEST_VA, 1).map_err(|_| "second mem_unmap (idempotent) failed")?;

    // FrameGuard drop will try to unmap again (third time) — also idempotent.
    Ok(())
}

// ── SYS_ASPACE_QUERY ─────────────────────────────────────────────────────────

/// `aspace_query` returns the physical address for a mapped page.
///
/// ktest's own `_start` page is always mapped R-X; use it as a stable target.
pub fn aspace_query_mapped(ctx: &TestContext) -> TestResult
{
    unsafe extern "C" {
        fn _start();
    }
    let code_va = (_start as *const () as u64) & !0xFFF;
    let phys =
        aspace_query(ctx.aspace_cap, code_va).map_err(|_| "aspace_query on _start page failed")?;
    if phys == 0 || phys & 0xFFF != 0
    {
        return Err("aspace_query returned non-page-aligned or zero physical address");
    }
    Ok(())
}

/// `aspace_query` on an unmapped virtual address must return an error.
pub fn aspace_query_unmapped_err(ctx: &TestContext) -> TestResult
{
    // 0x7000_0000_0000 is never mapped in ktest's address space.
    let err = aspace_query(ctx.aspace_cap, 0x7000_0000_0000u64);
    if err.is_ok()
    {
        return Err("aspace_query on unmapped VA should fail");
    }
    Ok(())
}

// ── SYS_MEM_MAP negative ──────────────────────────────────────────────────────

/// `mem_map` with a non-page-aligned virtual address must return an error.
pub fn mem_map_unaligned_vaddr_err(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("mem_map_unaligned_vaddr_err: frame pool exhausted")?;
    let err = mem_map(memory_cap, ctx.aspace_cap, TEST_VA + 1, 0, 1, MAP_WRITABLE);

    // SAFETY: memory_cap was allocated from pool and never successfully mapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("mem_map with unaligned vaddr should fail");
    }
    Ok(())
}

/// `mem_map` targeting the kernel virtual address half must return an error.
///
/// On both x86-64 and RISC-V Sv48, `0xFFFF_8000_0000_0000` is in the kernel half.
pub fn mem_map_kernel_half_err(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("mem_map_kernel_half_err: frame pool exhausted")?;
    let kernel_va: u64 = 0xFFFF_8000_0000_0000;
    let err = mem_map(memory_cap, ctx.aspace_cap, kernel_va, 0, 1, MAP_WRITABLE);

    // SAFETY: memory_cap was allocated from pool and never successfully mapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("mem_map into kernel address space should fail");
    }
    Ok(())
}

// ── SYS_MEMORY_SPLIT negative ──────────────────────────────────────────────────

/// `memory_split` at offset 0 must return an error (left half would be empty).
pub fn memory_split_at_zero_err(_ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("memory_split_at_zero_err: frame pool exhausted")?;
    let err = syscall::memory_split(memory_cap, 0);

    // If split fails (expected), the Memory cap is still valid, so return it to pool.
    // SAFETY: memory_cap was allocated from pool; split failed so it's still intact.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("memory_split at offset 0 should fail (zero-size left half)");
    }
    Ok(())
}

// ── SYS_MEM_PROTECT negative ──────────────────────────────────────────────────

/// `mem_protect` requesting permissions beyond the Memory cap's rights must fail.
///
/// Maps a full-rights pool frame, then derives a no-WRITE cap over the same
/// frame and requests WRITE through it via `mem_protect` — which must be rejected
/// with `InsufficientRights`. Attenuation supplies the no-WRITE cap: every RAM
/// frame the kernel mints (init segments included) carries full rights, so a
/// segment cap can no longer serve as the no-WRITE surface.
pub fn mem_protect_exceeds_cap_rights_err(ctx: &TestContext) -> TestResult
{
    // Use a VA distinct from TEST_VA=0x4000_0000 to avoid conflicts.
    const PROTECT_TEST_VA: u64 = 0x4100_0000;

    let mut frame = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_protect_exceeds_cap_rights_err: frame pool exhausted")?;
    frame
        .map(PROTECT_TEST_VA)
        .map_err(|_| "mem_map for protect-rights test failed")?;

    // Attenuate to a no-WRITE cap (MAP only) over the same frame; mem_protect
    // checks the requested perms against this cap's rights, not the mapping cap.
    let ro_cap = syscall::cap_derive(frame.cap(), syscall::RIGHTS_MAP_READ)
        .map_err(|_| "mem_protect_exceeds_cap_rights_err: cap_derive failed")?;

    // Read-only cap has no WRITE — requesting WRITE must fail.
    let err = syscall::mem_protect(ro_cap, ctx.aspace_cap, PROTECT_TEST_VA, 1, MAP_WRITABLE);

    // The parent frame keeps the object alive, so deleting the derived slot is
    // safe; FrameGuard's drop unmaps PROTECT_TEST_VA and returns the frame.
    syscall::cap_delete(ro_cap).ok();
    drop(frame);

    if err.is_ok()
    {
        return Err("mem_protect with WRITE on a read-only cap should fail (InsufficientRights)");
    }
    Ok(())
}

// ── SYS_MEM_MAP (multi-page) ─────────────────────────────────────────────────

/// `mem_map` with `page_count`=2 maps two consecutive pages.
///
/// Allocates two frames, maps them at consecutive VAs, verifies both are
/// accessible via `aspace_query`.
pub fn mem_map_multi_page(ctx: &TestContext) -> TestResult
{
    const MULTI_VA: u64 = 0x4200_0000;

    let memory_a = crate::frame_pool::alloc().ok_or("mem_map_multi_page: memory_a exhausted")?;
    let memory_b = crate::frame_pool::alloc().ok_or("mem_map_multi_page: memory_b exhausted")?;

    // Map each cap at consecutive pages.
    mem_map(memory_a, ctx.aspace_cap, MULTI_VA, 0, 1, MAP_WRITABLE)
        .map_err(|_| "mem_map memory_a failed")?;
    mem_map(
        memory_b,
        ctx.aspace_cap,
        MULTI_VA + 0x1000,
        0,
        1,
        MAP_WRITABLE,
    )
    .map_err(|_| "mem_map memory_b failed")?;

    // Both pages must be queryable.
    let phys_a =
        aspace_query(ctx.aspace_cap, MULTI_VA).map_err(|_| "aspace_query page_a failed")?;
    let phys_b = aspace_query(ctx.aspace_cap, MULTI_VA + 0x1000)
        .map_err(|_| "aspace_query page_b failed")?;

    if phys_a == 0 || phys_b == 0
    {
        return Err("aspace_query returned zero phys for multi-page mapping");
    }
    if phys_a == phys_b
    {
        return Err("both pages mapped to same physical address");
    }

    mem_unmap(ctx.aspace_cap, MULTI_VA, 1).ok();
    mem_unmap(ctx.aspace_cap, MULTI_VA + 0x1000, 1).ok();
    // SAFETY: caps allocated from pool and now unmapped.
    unsafe {
        crate::frame_pool::free(memory_a);
        crate::frame_pool::free(memory_b);
    }
    Ok(())
}

// ── SYS_MEM_MAP (zero pages) ─────────────────────────────────────────────────

/// `mem_map` with `page_count`=0 must return `InvalidArgument`.
pub fn mem_map_zero_pages_err(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("mem_map_zero_pages_err: frame pool exhausted")?;
    let err = mem_map(memory_cap, ctx.aspace_cap, TEST_VA, 0, 0, MAP_WRITABLE);

    // SAFETY: memory_cap allocated from pool and never mapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("mem_map with page_count=0 should fail");
    }
    Ok(())
}

// ── SYS_MEM_MAP (offset beyond Memory cap) ───────────────────────────────────

/// `mem_map` with `offset_pages` that exceeds the Memory cap size must fail.
pub fn mem_map_offset_beyond_memory_err(ctx: &TestContext) -> TestResult
{
    let memory_cap = crate::frame_pool::alloc()
        .ok_or("mem_map_offset_beyond_memory_err: frame pool exhausted")?;
    // Pool frames are single-page (4 KiB). offset_pages=1 means byte offset 0x1000,
    // which is at the end of the cap region — mapping 1 page from there overflows.
    let err = mem_map(memory_cap, ctx.aspace_cap, TEST_VA, 1, 1, MAP_WRITABLE);

    // SAFETY: memory_cap allocated from pool and never mapped.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("mem_map with offset beyond Memory cap size should fail");
    }
    Ok(())
}

// ── SYS_MEM_UNMAP (unaligned VA) ─────────────────────────────────────────────

/// `mem_unmap` with a non-page-aligned virtual address must return an error.
pub fn mem_unmap_unaligned_err(ctx: &TestContext) -> TestResult
{
    let err = mem_unmap(ctx.aspace_cap, TEST_VA + 1, 1);
    if err.is_ok()
    {
        return Err("mem_unmap with unaligned VA should fail");
    }
    Ok(())
}

// ── SYS_MEM_PROTECT (W^X) ───────────────────────────────────────────────────

/// `mem_protect` with both WRITE (bit 1) and EXECUTE (bit 2) set must fail.
pub fn mem_protect_wx_err(ctx: &TestContext) -> TestResult
{
    const WX_TEST_VA: u64 = 0x4300_0000;

    let mut memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_protect_wx_err: frame pool exhausted")?;
    memory_cap
        .map(WX_TEST_VA)
        .map_err(|_| "mem_map for wx test failed")?;

    let err = syscall::mem_protect(
        memory_cap.cap(),
        ctx.aspace_cap,
        WX_TEST_VA,
        1,
        MAP_WRITABLE | syscall::MAP_EXECUTABLE,
    );
    if err.is_ok()
    {
        return Err("mem_protect with WRITE|EXECUTE should fail (W^X violation)");
    }
    Ok(())
}

// ── SYS_MEM_MAP (W^X via prot_bits) ─────────────────────────────────────────

/// `mem_map` with `prot_bits` specifying both WRITE and EXECUTE must fail.
pub fn mem_map_wx_prot_err(ctx: &TestContext) -> TestResult
{
    let memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_map_wx_prot_err: frame pool exhausted")?;

    let err = mem_map(
        memory_cap.cap(),
        ctx.aspace_cap,
        0x4400_0000,
        0,
        1,
        MAP_WRITABLE | syscall::MAP_EXECUTABLE,
    );

    if err.is_ok()
    {
        return Err("mem_map with WRITE|EXECUTE prot_bits should fail (W^X violation)");
    }
    // FrameGuard drop returns the cap to pool (no unmap needed since map failed).
    drop(memory_cap);
    Ok(())
}

// ── SYS_MEMORY_SPLIT (offset at end) ─────────────────────────────────────────

/// `memory_split` with offset >= `memory_size` must return an error (right half empty).
pub fn memory_split_at_end_err(_ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("memory_split_at_end_err: frame pool exhausted")?;
    // Pool frames are 4 KiB (1 page). Splitting at offset 0x1000 = entire cap
    // leaves right half empty.
    let err = syscall::memory_split(memory_cap, 0x1000);

    // SAFETY: memory_cap allocated from pool; split failed so it's still intact.
    unsafe { crate::frame_pool::free(memory_cap) };

    if err.is_ok()
    {
        return Err("memory_split at offset >= memory_size should fail");
    }
    Ok(())
}

// ── Init segment Memory cap alignment (issue #56) ────────────────────────────

/// Every init segment Memory cap exposes a page-aligned `base` and whole-page
/// `size` to userspace, even when the underlying ELF segment has a sub-page
/// `p_vaddr` (i.e. the ktest binary contains a non-empty `.data` section).
///
/// Maps each segment cap's first page read-only at `SEG_PROBE_VA` and queries
/// the resulting physical address. The kernel `debug_assert!`s page alignment
/// inside `PageTableEntry::new_page`, so a misaligned cap would panic before
/// the query returns. `aspace_query` returning a page-aligned PA confirms the
/// mapping landed cleanly.
///
/// Regression for issue #56: with the Phase 9 cap-mint masking off, the
/// non-zero `fpu::SUB_PAGE_SENTINEL` static would push the RW segment's VA
/// off a page boundary and trigger
/// `core/kernel/src/arch/riscv64/paging.rs:80`'s
/// `page PA not 4 KiB-aligned` panic during the first mapping below.
pub fn init_segment_caps_aligned(ctx: &TestContext) -> TestResult
{
    const SEG_PROBE_VA: u64 = 0x4300_0000;
    // Phase 9 mints exactly three segments per init binary: TEXT, RODATA,
    // BSS/DATA. The cap slots sit contiguously starting at `aspace_cap + 1`.
    const SEG_COUNT: u32 = 3;

    for i in 0..SEG_COUNT
    {
        let seg_cap = ctx.aspace_cap + 1 + i;
        // Map read-only via explicit prot (not prot=0): segment caps are now
        // full-rights, so deriving perms from cap rights would request W+X and
        // trip W^X. Explicit MAP_READ maps read-only regardless of cap rights;
        // the probe only needs the page's phys base.
        mem_map(seg_cap, ctx.aspace_cap, SEG_PROBE_VA, 0, 1, MAP_READ)
            .map_err(|_| "init_segment_caps_aligned: mem_map failed")?;

        let phys = aspace_query(ctx.aspace_cap, SEG_PROBE_VA)
            .map_err(|_| "init_segment_caps_aligned: aspace_query failed")?;
        if phys == 0 || phys & 0xFFF != 0
        {
            mem_unmap(ctx.aspace_cap, SEG_PROBE_VA, 1).ok();
            return Err("init_segment_caps_aligned: segment cap mapped to non-page-aligned PA");
        }

        mem_unmap(ctx.aspace_cap, SEG_PROBE_VA, 1)
            .map_err(|_| "init_segment_caps_aligned: mem_unmap failed")?;
    }

    // Touch the sentinel static so the optimiser keeps `.data` populated.
    let _ = crate::unit::fpu::SUB_PAGE_SENTINEL.load(core::sync::atomic::Ordering::Relaxed);
    Ok(())
}
