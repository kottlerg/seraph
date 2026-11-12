// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/mm.rs

//! Tier 1 tests for memory management syscalls.
//!
//! Covers: `SYS_MEMORY_SPLIT`, `SYS_MEMORY_MERGE`, `SYS_MEM_MAP`, `SYS_MEM_UNMAP`,
//! `SYS_MEM_PROTECT`, `SYS_ASPACE_QUERY`.
//!
//! Memory cap layout after `aspace_cap`: the kernel mints one segment Memory
//! cap per init LOAD segment at Phase 9, in program-header order
//! (`core/kernel/docs/initialization.md` § Phase 9: Init Creation and Scheduler
//! Entry). For ktest's image:
//!   `aspace_cap + 1` — RODATA segment (R) Memory cap
//!   `aspace_cap + 2` — TEXT segment (RX) Memory cap
//!   `aspace_cap + 3` — RELRO segment (`.data.rel.ro`, `.dynamic`, `.got`) Memory cap
//!   `aspace_cap + 4` — DATA/BSS segment (RW) Memory cap
//!
//! Every segment cap carries full Memory rights (`MAP|WRITE|EXECUTE|RETYPE`);
//! the page-table protection of ktest's own segments is independent of cap
//! rights (see `core/kernel/docs/initialization.md` § Phase 9: Init Creation and
//! Scheduler Entry).
//!
//! Segment Memory caps own their physical memory (`owns_memory = true`; see
//! `core/kernel/docs/initialization.md` § Phase 9: Init Creation and Scheduler
//! Entry). Tests therefore MUST NOT `cap_delete` or otherwise dec-ref a
//! segment cap (or a tail derived from one) while the segment is still
//! mapped in ktest's own address space — the dealloc would buddy-free phys
//! pages still referenced by live PTEs and silently alias future allocations.
//! Split-boundary and delete exercises operate on pool-allocated frames.
//! `memory_split_merge` splits a segment cap and restores it through
//! `memory_merge` only (never `cap_delete`), and `init_segment_caps_aligned`
//! maps segment caps read-only through `mem_map`.

use syscall::{
    MAP_READ, MAP_WRITABLE, RIGHTS_ALL, aspace_query, cap_copy, cap_create_cspace, cap_delete,
    cap_derive, cap_info, mem_map, mem_unmap,
};
use syscall_abi::{CAP_INFO_MEMORY_SIZE, PAGE_SIZE};

use crate::{TestContext, TestResult};

/// Test virtual address: 5 GiB. Below ktest's PIE image, `InitInfo`, and stack
/// windows (`IMAGE_WINDOW`, `INIT_INFO_WINDOW`, `INIT_STACK_GUARD_WINDOW` in
/// `shared/process-layout`), so it overlaps no ktest mapping. Used consistently
/// across mm tests to avoid mapping conflicts.
const TEST_VA: u64 = 0x1_4000_0000;

// ── SYS_MEMORY_SPLIT / SYS_MEMORY_MERGE ─────────────────────────────────────────

/// Split-merge round-trip on the TEXT segment cap (`aspace_cap + 2`; the
/// local is named `rodata_cap`), using the in-place-shrink split semantics of
/// `sys_memory_split`.
///
/// Validates the full inverse relationship between `memory_split` and
/// `memory_merge`:
///
/// 1. Splitting the TEXT segment cap at one page shrinks the parent slot in place to a
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

    let rodata_cap = ctx
        .aspace_cap
        .checked_add(2)
        .ok_or("memory_split_merge: RODATA slot out of range")?;
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

    // Restore the TEXT segment cap to its original size via merge. Using `cap_delete`
    // here would dec-ref a Memory cap whose phys range is still mapped at
    // the TEXT segment's VA; the dealloc path would buddy-free pages live
    // in ktest's own page tables.
    syscall::memory_merge(rodata_cap, tail2).map_err(|_| "final memory_merge failed")?;
    Ok(())
}

/// Pages of the piece the shared-object cases split off `memory_base`.
const SHARED_PIECE_PAGES: u64 = 4;

/// Split [`SHARED_PIECE_PAGES`] pages off the top of `memory_base`; the piece is
/// a derivation root, as `memory_base` is.
fn split_shared_piece(ctx: &TestContext, case: &'static str) -> Result<u64, &'static str>
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE).map_err(|_| case)?;
    let keep = size
        .checked_sub(SHARED_PIECE_PAGES * PAGE_SIZE)
        .ok_or(case)?;
    syscall::memory_split(ctx.memory_base, keep).map_err(|_| case)
}

/// The size of the Memory object `cap` names, or 0 when the query fails.
fn memory_size(cap: u64) -> u64
{
    cap_info(cap, CAP_INFO_MEMORY_SIZE).unwrap_or(0)
}

/// `SYS_MEMORY_SPLIT` refuses a Memory cap whose object another slot also
/// names, and leaves the object's size unchanged (core/kernel/docs/syscalls.md
/// § `SYS_MEMORY_SPLIT`).
///
/// Three holders of a shared object are refused: a derivation of the piece,
/// the piece itself while that derivation lives, and a derivation that a
/// delete of its parent left an unlinked root beside a sibling of the same
/// object. Once the last other slot goes, the split succeeds, and the halves
/// merge back into `memory_base`.
pub fn memory_split_shared_object_refused(ctx: &TestContext) -> TestResult
{
    const CASE: &str = "mm::memory_split_shared_object_refused: setup failed";
    let piece = split_shared_piece(ctx, CASE)?;
    let full = SHARED_PIECE_PAGES * PAGE_SIZE;

    let derived = cap_derive(piece, RIGHTS_ALL).map_err(|_| CASE)?;
    let by_child = syscall::memory_split(derived, PAGE_SIZE);
    let by_parent = syscall::memory_split(piece, PAGE_SIZE);
    let size_after = memory_size(piece);

    // A second derivation, then the piece's delete: both derivations become
    // roots that share the object with no derivation edge between them.
    let sibling = cap_derive(piece, RIGHTS_ALL).map_err(|_| CASE)?;
    cap_delete(piece).map_err(|_| CASE)?;
    let by_unlinked = syscall::memory_split(derived, PAGE_SIZE);
    let unlinked_size = memory_size(derived);
    cap_delete(sibling).map_err(|_| CASE)?;

    let tail = syscall::memory_split(derived, PAGE_SIZE)
        .map_err(|_| "mm::memory_split_shared_object_refused: split of the sole slot failed")?;
    syscall::memory_merge(derived, tail).map_err(|_| CASE)?;
    syscall::memory_merge(ctx.memory_base, derived).map_err(|_| CASE)?;

    if by_child.is_ok() || by_parent.is_ok() || by_unlinked.is_ok()
    {
        return Err("mm::memory_split_shared_object_refused: a shared Memory object was split");
    }
    if size_after != full || unlinked_size != full
    {
        return Err("mm::memory_split_shared_object_refused: a refused split changed the size");
    }
    Ok(())
}

/// 1 ms polls, about 2 s, that wait for a dead `CSpace`'s deferred teardown to
/// release its slots; stretched past [`crate::UNSCALED_CPUS`] CPUs through
/// [`crate::scaled_polls`].
const CSPACE_RELEASE_POLLS: u32 = 2000;

/// A `CSpace`'s teardown stops counting the slots it held: a piece copied into
/// a fresh `CSpace` is refused a split while the copy lives, and splits again
/// once the last capability to that `CSpace` is deleted and its teardown has
/// released the copy (core/kernel/docs/syscalls.md § `SYS_MEMORY_SPLIT`). The
/// teardown is deferred, so the split is retried, a 1 ms sleep apart, within
/// [`CSPACE_RELEASE_POLLS`].
pub fn memory_split_after_cspace_teardown(ctx: &TestContext) -> TestResult
{
    const CASE: &str = "mm::memory_split_after_cspace_teardown: setup failed";
    let piece = split_shared_piece(ctx, CASE)?;
    let cs = cap_create_cspace(ctx.memory_base, 0, 4).map_err(|_| CASE)?;
    let shared_split =
        cap_copy(piece, cs, RIGHTS_ALL).map(|_| syscall::memory_split(piece, PAGE_SIZE));
    cap_delete(cs).map_err(|_| CASE)?;
    match shared_split
    {
        // No copy was made: the piece is still sole, so it merges back.
        Err(_) =>
        {
            syscall::memory_merge(ctx.memory_base, piece).ok();
            return Err(CASE);
        }
        // A split while the copy lived is the defect itself; the halves are
        // merged back as far as the kernel lets them.
        Ok(Ok(probe_tail)) =>
        {
            if syscall::memory_merge(piece, probe_tail).is_ok()
            {
                syscall::memory_merge(ctx.memory_base, piece).ok();
            }
            return Err(
                "mm::memory_split_after_cspace_teardown: a piece with a live copy was split",
            );
        }
        Ok(Err(_)) =>
        {}
    }

    let mut tail = None;
    for _ in 0..crate::scaled_polls(CSPACE_RELEASE_POLLS)
    {
        if let Ok(t) = syscall::memory_split(piece, PAGE_SIZE)
        {
            tail = Some(t);
            break;
        }
        let _ = syscall::thread_sleep(1);
    }
    // A slot the teardown left counted also refuses the merges below, so the
    // stuck split is reported before them, and the piece is left unmerged.
    let Some(tail) = tail
    else
    {
        return Err(
            "mm::memory_split_after_cspace_teardown: the split stayed refused after the copy's \
             CSpace was torn down",
        );
    };
    syscall::memory_merge(piece, tail).map_err(|_| CASE)?;
    syscall::memory_merge(ctx.memory_base, piece).map_err(|_| CASE)
}

/// `SYS_MEMORY_MERGE` refuses a parent or a tail whose object another slot also
/// names, and leaves both sizes unchanged (core/kernel/docs/syscalls.md
/// § `SYS_MEMORY_MERGE`).
///
/// The other slot is an unlinked root: each case derives two caps from one
/// half and deletes that half, so the derivations are roots, siblings of the
/// other half, that share one object. A merge through either half fails until
/// the extra root is deleted; the halves then merge and return to
/// `memory_base`.
pub fn memory_merge_shared_object_refused(ctx: &TestContext) -> TestResult
{
    const CASE: &str = "mm::memory_merge_shared_object_refused: setup failed";
    let piece = split_shared_piece(ctx, CASE)?;
    let tail = syscall::memory_split(piece, PAGE_SIZE).map_err(|_| CASE)?;

    // Parent shared: `head` and `head_extra` both name the parent's object.
    let head = cap_derive(piece, RIGHTS_ALL).map_err(|_| CASE)?;
    let head_extra = cap_derive(piece, RIGHTS_ALL).map_err(|_| CASE)?;
    cap_delete(piece).map_err(|_| CASE)?;
    let parent_shared = syscall::memory_merge(head, tail);
    let sizes_parent_case = (memory_size(head), memory_size(tail));
    cap_delete(head_extra).map_err(|_| CASE)?;

    // Tail shared: `rest` and `rest_extra` both name the tail's object.
    let rest = cap_derive(tail, RIGHTS_ALL).map_err(|_| CASE)?;
    let rest_extra = cap_derive(tail, RIGHTS_ALL).map_err(|_| CASE)?;
    cap_delete(tail).map_err(|_| CASE)?;
    let tail_shared = syscall::memory_merge(head, rest);
    let sizes_tail_case = (memory_size(head), memory_size(rest));
    cap_delete(rest_extra).map_err(|_| CASE)?;

    syscall::memory_merge(head, rest)
        .map_err(|_| "mm::memory_merge_shared_object_refused: merge of sole slots failed")?;
    syscall::memory_merge(ctx.memory_base, head).map_err(|_| CASE)?;

    if parent_shared.is_ok() || tail_shared.is_ok()
    {
        return Err("mm::memory_merge_shared_object_refused: a shared Memory object was merged");
    }
    let halves = (PAGE_SIZE, (SHARED_PIECE_PAGES - 1) * PAGE_SIZE);
    if sizes_parent_case != halves || sizes_tail_case != halves
    {
        return Err("mm::memory_merge_shared_object_refused: a refused merge changed a size");
    }
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
    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { memory_cap.map(TEST_VA) }.map_err(|_| "mem_map failed")?;

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
/// Maps a frame page and sets it read-only (prot = 0: no WRITE, no EXECUTE);
/// `FrameGuard`'s drop unmaps it. The test checks only that `mem_protect`
/// succeeds; it does not write to the page to observe the resulting fault.
pub fn mem_protect(ctx: &TestContext) -> TestResult
{
    let mut memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_protect: frame pool exhausted")?;

    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { memory_cap.map(TEST_VA) }.map_err(|_| "mem_map for protect test failed")?;

    // prot = 0: read-only. Always valid regardless of Memory cap rights.
    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { syscall::mem_protect(memory_cap.cap(), ctx.aspace_cap, TEST_VA, 1, 0) }
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
    // SAFETY: nothing is mapped at `unmapped_va` (the test's premise), so the
    // kernel refuses the reprotect and changes nothing.
    let err = unsafe { syscall::mem_protect(memory_cap, ctx.aspace_cap, unmapped_va, 1, 0) };

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

    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { memory_cap.map(TEST_VA) }.map_err(|_| "mem_map for idempotent-unmap test failed")?;
    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap(ctx.aspace_cap, TEST_VA, 1) }.map_err(|_| "first mem_unmap failed")?;
    // Second unmap of the same range must succeed (no-op).
    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap(ctx.aspace_cap, TEST_VA, 1) }
        .map_err(|_| "second mem_unmap (idempotent) failed")?;

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
    // Never mapped by ktest, and a canonical user VA in every paging mode
    // (below the 2^38 Sv39 user half), above every layout zone.
    let err = aspace_query(ctx.aspace_cap, 0x3F_0000_0000u64);
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
    // SAFETY: `TEST_VA + 1` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err = unsafe { mem_map(memory_cap, ctx.aspace_cap, TEST_VA + 1, 0, 1, MAP_WRITABLE) };

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
/// The kernel image's top-2-GiB base is in the kernel half and canonical in
/// every paging mode on both architectures.
pub fn mem_map_kernel_half_err(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("mem_map_kernel_half_err: frame pool exhausted")?;
    let kernel_va: u64 = 0xFFFF_FFFF_8000_0000;
    // SAFETY: `kernel_va` lies in the kernel half, which the kernel refuses
    // (the test's premise), so the call maps nothing.
    let err = unsafe { mem_map(memory_cap, ctx.aspace_cap, kernel_va, 0, 1, MAP_WRITABLE) };

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
    // Use a VA distinct from TEST_VA to avoid conflicts.
    const PROTECT_TEST_VA: u64 = 0x1_4100_0000;

    let mut frame = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_protect_exceeds_cap_rights_err: frame pool exhausted")?;
    // SAFETY: `PROTECT_TEST_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { frame.map(PROTECT_TEST_VA) }.map_err(|_| "mem_map for protect-rights test failed")?;

    // Attenuate to a no-WRITE cap (MAP only) over the same frame; mem_protect
    // checks the requested perms against this cap's rights, not the mapping cap.
    let ro_cap = syscall::cap_derive(frame.cap(), syscall::RIGHTS_MEM_MAP)
        .map_err(|_| "mem_protect_exceeds_cap_rights_err: cap_derive failed")?;

    // Read-only cap has no WRITE — requesting WRITE must fail.
    // SAFETY: `PROTECT_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err =
        unsafe { syscall::mem_protect(ro_cap, ctx.aspace_cap, PROTECT_TEST_VA, 1, MAP_WRITABLE) };

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
    const MULTI_VA: u64 = 0x1_4200_0000;

    // The guards unmap and return both frames on every exit path.
    let mut frame_a = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_map_multi_page: memory_a exhausted")?;
    let mut frame_b = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_map_multi_page: memory_b exhausted")?;

    // Map each cap at consecutive pages.
    // SAFETY: `MULTI_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { frame_a.map(MULTI_VA) }.map_err(|_| "mem_map memory_a failed")?;
    // SAFETY: `MULTI_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { frame_b.map(MULTI_VA + 0x1000) }.map_err(|_| "mem_map memory_b failed")?;

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
    Ok(())
}

// ── SYS_MEM_MAP (zero pages) ─────────────────────────────────────────────────

/// `mem_map` with `page_count`=0 must return `InvalidArgument`.
pub fn mem_map_zero_pages_err(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("mem_map_zero_pages_err: frame pool exhausted")?;
    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err = unsafe { mem_map(memory_cap, ctx.aspace_cap, TEST_VA, 0, 0, MAP_WRITABLE) };

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
    // SAFETY: `TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err = unsafe { mem_map(memory_cap, ctx.aspace_cap, TEST_VA, 1, 1, MAP_WRITABLE) };

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
    // SAFETY: `TEST_VA + 1` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err = unsafe { mem_unmap(ctx.aspace_cap, TEST_VA + 1, 1) };
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
    const WX_TEST_VA: u64 = 0x1_4300_0000;

    let mut memory_cap = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
        .ok_or("mem_protect_wx_err: frame pool exhausted")?;
    // SAFETY: `WX_TEST_VA` is a scratch VA (crate docs § Scratch VAs), off every
    // Rust object and IPC page of ktest.
    unsafe { memory_cap.map(WX_TEST_VA) }.map_err(|_| "mem_map for wx test failed")?;

    // SAFETY: `WX_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err = unsafe {
        syscall::mem_protect(
            memory_cap.cap(),
            ctx.aspace_cap,
            WX_TEST_VA,
            1,
            MAP_WRITABLE | syscall::MAP_EXECUTABLE,
        )
    };
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

    // SAFETY: `0x1_4400_0000` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let err = unsafe {
        mem_map(
            memory_cap.cap(),
            ctx.aspace_cap,
            0x1_4400_0000,
            0,
            1,
            MAP_WRITABLE | syscall::MAP_EXECUTABLE,
        )
    };

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
/// Maps the first page of each of the first three segment caps (RODATA,
/// TEXT, RELRO) read-only at `SEG_PROBE_VA` and queries
/// the resulting physical address. The kernel `debug_assert!`s page alignment
/// inside `PageTableEntry::new_page`, so a misaligned cap would panic before
/// the query returns. `aspace_query` returning a page-aligned PA confirms the
/// mapping landed cleanly.
///
/// Regression for issue #56: with the Phase 9 cap-mint masking off, the
/// non-zero `fpu::SUB_PAGE_SENTINEL` static would push the RW segment's VA
/// off a page boundary and trigger `PageTableEntry::new_page`'s
/// `page PA not 4 KiB-aligned` panic during the first mapping below.
pub fn init_segment_caps_aligned(ctx: &TestContext) -> TestResult
{
    // Its own VA, distinct from `mem_protect_wx_err`'s `WX_TEST_VA`, so a
    // probe page this test leaves mapped cannot collide with that test's map.
    const SEG_PROBE_VA: u64 = 0x1_4400_0000;
    // Phase 9 mints one Memory cap per init LOAD segment, in contiguous slots
    // from `aspace_cap + 1`. ktest's image has four (RODATA, TEXT, RELRO,
    // DATA/BSS); this loop probes only the first three, so the DATA/BSS cap
    // at `aspace_cap + 4` is not probed.
    const SEG_COUNT: u64 = 3;

    for i in 0..SEG_COUNT
    {
        let seg_cap = ctx
            .aspace_cap
            .checked_add(1)
            .and_then(|first| first.checked_add(i))
            .ok_or("segment cap slot out of range")?;
        // Map read-only via explicit prot (not prot=0): segment caps are now
        // full-rights, so deriving perms from cap rights would request W+X and
        // trip W^X. Explicit MAP_READ maps read-only regardless of cap rights;
        // the probe only needs the page's phys base.
        // SAFETY: `SEG_PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        unsafe { mem_map(seg_cap, ctx.aspace_cap, SEG_PROBE_VA, 0, 1, MAP_READ) }
            .map_err(|_| "init_segment_caps_aligned: mem_map failed")?;

        // Unmap before judging the query, so no exit path leaves ktest's own
        // segment page mapped at the probe VA.
        let phys = aspace_query(ctx.aspace_cap, SEG_PROBE_VA);
        // SAFETY: `SEG_PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        let unmapped = unsafe { mem_unmap(ctx.aspace_cap, SEG_PROBE_VA, 1) };
        let phys = phys.map_err(|_| "init_segment_caps_aligned: aspace_query failed")?;
        if phys == 0 || phys & 0xFFF != 0
        {
            return Err("init_segment_caps_aligned: segment cap mapped to non-page-aligned PA");
        }
        unmapped.map_err(|_| "init_segment_caps_aligned: mem_unmap failed")?;
    }

    // Touch the sentinel static so the optimiser keeps `.data` populated.
    let _ = crate::unit::fpu::SUB_PAGE_SENTINEL.load(core::sync::atomic::Ordering::Relaxed);
    Ok(())
}
