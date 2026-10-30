// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/retype.rs

//! Unit tests for the retype primitive itself.
//!
//! `cap.rs` and `cap_info.rs` cover the user-visible cap-create syscalls;
//! this file exercises the lower-mechanism behaviours that aren't visible
//! from any single create call:
//!
//! - **Augment-mode** on `cap_create_aspace` / `cap_create_cspace` —
//!   topping up an existing AS/CS growth budget by passing a non-zero
//!   target. Functional coverage of the syscall path that is otherwise
//!   only reached when an explicit refill is requested, including
//!   donation counts past the wrapper's inline records (the record pages
//!   the kernel carves from the donations themselves).
//! - **PT-budget exhaustion** — repeated `mem_map` against a freshly
//!   created `AddressSpace` whose initial growth budget covers only two
//!   pool pages eventually returns `OutOfMemory` from the
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

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_create_notification,
    cap_create_thread, cap_delete, cap_info, cap_insert, mem_map, mem_unmap, mem_unmap_reclaim,
    thread_configure, thread_sleep, thread_start,
};
use syscall_abi::{
    CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_USED,
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_THREAD_STATE, EXIT_KILLED, FAULT_LABEL, MAP_EXECUTABLE,
    MAP_WRITABLE, RIGHTS_ALL, RIGHTS_NTF_NOTIFY, THREAD_STATE_EXITED,
};

use crate::{TestContext, TestResult};

const TEST_VA_BASE: u64 = 0x0000_0001_4000_0000;

/// VA of the machine-code stub inside each dedicated child address space.
/// Canonical in every paging mode (below the 2^38 Sv39 user half) and
/// distinct from other tests' VAs.
const STUB_VA: u64 = 0x3E_6000_0000;
/// Scratch VA in ktest's own address space through which the stub is written.
const STUB_SCRATCH_VA: u64 = 0x3E_6100_0000;
/// Unmapped entry PC for the fault-blocked child.
const STUB_UNMAPPED_VA: u64 = 0x3E_6200_0000;
/// Badge bound with the fault handler of the fault-blocked child.
const FAULT_BADGE: u64 = 0xA5_7A5E;
/// Poll bound: ~2 s at 1 ms per poll. Applied through [`crate::scaled_polls`],
/// which stretches it past [`crate::UNSCALED_CPUS`] CPUs, where the child's
/// CPU waits for a host core.
const MAX_POLLS: u32 = 2000;

/// Write a machine-code stub into a fresh frame-pool page and map it
/// executable at [`STUB_VA`] in `aspace`. Returns the frame's Memory cap.
///
/// The page is written through a temporary writable mapping in ktest's own
/// address space and unmapped before the executable mapping is made (W^X).
/// No instruction-cache maintenance follows the write: the kernel performs
/// none for executable mappings, and the harness runs under QEMU, whose
/// translation cache is coherent with stores.
fn install_stub(
    ctx: &TestContext,
    aspace: u32,
    emit: impl FnOnce(&mut [u8]) -> usize,
) -> Result<u32, &'static str>
{
    let frame =
        crate::frame_pool::alloc().ok_or("retype::stub: frame_pool::alloc returned None")?;
    // SAFETY: `STUB_SCRATCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(frame, ctx.aspace_cap, STUB_SCRATCH_VA, 0, 1, MAP_WRITABLE) }.is_err()
    {
        // SAFETY: `frame` came from `alloc` above and the failed map left it
        // mapped nowhere.
        unsafe { crate::frame_pool::free(frame) };
        return Err("retype::stub: scratch mem_map failed");
    }
    let mut bytes = [0u8; 32];
    let len = emit(&mut bytes);
    for (i, b) in bytes[..len].iter().enumerate()
    {
        // SAFETY: STUB_SCRATCH_VA..+PAGE is mapped writable just above; i < 32.
        unsafe { (STUB_SCRATCH_VA as *mut u8).add(i).write_volatile(*b) };
    }
    // SAFETY: `STUB_SCRATCH_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_unmap(ctx.aspace_cap, STUB_SCRATCH_VA, 1) }.is_err()
    {
        // The frame is still mapped at STUB_SCRATCH_VA, and `free` requires
        // it unmapped, so it stays allocated rather than re-enter the pool.
        return Err("retype::stub: scratch mem_unmap failed");
    }
    // SAFETY: `STUB_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(frame, aspace, STUB_VA, 0, 1, MAP_EXECUTABLE) }.is_err()
    {
        // SAFETY: `frame` came from `alloc` above; the scratch mapping is
        // gone and the failed map left it mapped nowhere.
        unsafe { crate::frame_pool::free(frame) };
        return Err("retype::stub: executable mem_map failed");
    }
    Ok(frame)
}

/// Exit reason of an already-`Exited` thread, or an error naming `what`.
fn exited_reason(thread: u32, what: &'static str) -> Result<u64, &'static str>
{
    let state = cap_info(thread, CAP_INFO_THREAD_STATE)
        .map_err(|_| "retype::aspace_stop: cap_info(thread state) failed")?;
    if (state >> 32) as u32 != THREAD_STATE_EXITED
    {
        return Err(what);
    }
    Ok(state & 0xFFFF_FFFF)
}

/// A frame-pool cap a test maps in place of its retyped Memory cap. The test
/// returns it with [`ScratchFrame::release`] once the address space it mapped
/// the frame into is destroyed; a failure path that returns before that
/// release leaks the frame.
struct ScratchFrame(u32);

impl ScratchFrame
{
    fn alloc() -> Result<Self, &'static str>
    {
        crate::frame_pool::alloc()
            .map(Self)
            .ok_or("retype: frame pool exhausted")
    }

    /// Return the frame to the pool.
    ///
    /// # Safety
    /// No address space may still map the frame.
    unsafe fn release(self)
    {
        // SAFETY: the cap came from frame_pool::alloc; the caller guarantees
        // nothing maps it.
        unsafe { crate::frame_pool::free(self.0) };
    }
}

/// Deleting the last capability to an `AddressSpace` stops every thread
/// bound to it with `EXIT_KILLED` (see
/// [thread-lifecycle-and-sleep.md](../../../kernel/docs/thread-lifecycle-and-sleep.md)
/// § Lifecycle State Machine). Three bound threads, each in a
/// dedicated address space and deleted from under it:
///
/// - a thread created there and never started (`Created`);
/// - a thread running a `loop {}` stub mapped into the space — on a
///   multi-CPU guest it is `current` on another CPU, with the space loaded
///   in that CPU's satp/CR3, when the delete lands;
/// - a thread parked `BlockedOnFault` on ktest's endpoint (unmapped entry
///   PC, fault handler bound, the fault message received and never
///   answered).
///
/// Everything reclaims to baseline through the thread and `CSpace` caps.
pub fn aspace_delete_stops_bound_thread(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::aspace_stop: cap_info(baseline) failed")?;

    // ── Created, never started ──
    let aspace = cap_create_aspace(memory, 0, 8)
        .map_err(|_| "retype::aspace_stop: cap_create_aspace failed")?;
    let cspace = cap_create_cspace(memory, 0, 4)
        .map_err(|_| "retype::aspace_stop: cap_create_cspace failed")?;
    let thread = cap_create_thread(memory, aspace, cspace, 0, 0)
        .map_err(|_| "retype::aspace_stop: cap_create_thread failed")?;
    cap_delete(aspace).map_err(|_| "retype::aspace_stop: cap_delete(aspace) failed")?;
    let reason = exited_reason(
        thread,
        "retype::aspace_stop: Created thread not Exited after its AddressSpace was deleted",
    );
    cap_delete(thread).map_err(|_| "retype::aspace_stop: cap_delete(thread) failed")?;
    cap_delete(cspace).map_err(|_| "retype::aspace_stop: cap_delete(cspace) failed")?;
    if reason? != EXIT_KILLED
    {
        return Err("retype::aspace_stop: Created thread's exit reason is not EXIT_KILLED");
    }

    // ── Running a stub in its own address space ──
    let aspace = cap_create_aspace(memory, 0, 8)
        .map_err(|_| "retype::aspace_stop: cap_create_aspace (spin) failed")?;
    let cspace = cap_create_cspace(memory, 0, 4)
        .map_err(|_| "retype::aspace_stop: cap_create_cspace (spin) failed")?;
    let frame = install_stub(ctx, aspace, crate::arch::code_stub::emit_spin)?;
    let thread = cap_create_thread(memory, aspace, cspace, 0, 0)
        .map_err(|_| "retype::aspace_stop: cap_create_thread (spin) failed")?;
    // The stub never touches its stack; any VA will do.
    // SAFETY: the thread is bound to the `aspace` this test created, not
    // ktest's own, so its entry state touches nothing ktest runs on.
    unsafe { thread_configure(thread, STUB_VA, STUB_VA + 0x800, 0) }
        .map_err(|_| "retype::aspace_stop: thread_configure (spin) failed")?;
    thread_start(thread).map_err(|_| "retype::aspace_stop: thread_start (spin) failed")?;
    // Give the child a chance to be dispatched (on a single-CPU guest this
    // sleep is what lets it run at all).
    thread_sleep(5).ok();
    cap_delete(aspace).map_err(|_| "retype::aspace_stop: cap_delete(aspace, spin) failed")?;
    let reason = exited_reason(
        thread,
        "retype::aspace_stop: running thread not Exited after its AddressSpace was deleted",
    );
    cap_delete(thread).map_err(|_| "retype::aspace_stop: cap_delete(thread, spin) failed")?;
    cap_delete(cspace).map_err(|_| "retype::aspace_stop: cap_delete(cspace, spin) failed")?;
    // SAFETY: the only mapping of `frame` went with the address space.
    unsafe { crate::frame_pool::free(frame) };
    if reason? != EXIT_KILLED
    {
        return Err("retype::aspace_stop: running thread's exit reason is not EXIT_KILLED");
    }

    // ── Blocked on a fault in its own address space ──
    let ep = cap_create_endpoint(memory)
        .map_err(|_| "retype::aspace_stop: cap_create_endpoint failed")?;
    let aspace = cap_create_aspace(memory, 0, 8)
        .map_err(|_| "retype::aspace_stop: cap_create_aspace (fault) failed")?;
    let cspace = cap_create_cspace(memory, 0, 4)
        .map_err(|_| "retype::aspace_stop: cap_create_cspace (fault) failed")?;
    let thread = cap_create_thread(memory, aspace, cspace, 0, 0)
        .map_err(|_| "retype::aspace_stop: cap_create_thread (fault) failed")?;
    crate::bind_fault_handler(thread, ep, FAULT_BADGE)
        .map_err(|_| "retype::aspace_stop: thread_set_fault_handler failed")?;
    // SAFETY: the thread is bound to the `aspace` this test created, not
    // ktest's own, so its entry state touches nothing ktest runs on.
    unsafe { thread_configure(thread, STUB_UNMAPPED_VA, STUB_UNMAPPED_VA + 0x800, 0) }
        .map_err(|_| "retype::aspace_stop: thread_configure (fault) failed")?;
    thread_start(thread).map_err(|_| "retype::aspace_stop: thread_start (fault) failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg: IpcMessage = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "retype::aspace_stop: ipc_recv(fault) failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE
    {
        return Err("retype::aspace_stop: received message is not the child's fault");
    }
    // The child is now BlockedOnFault awaiting a reply that never comes.
    cap_delete(aspace).map_err(|_| "retype::aspace_stop: cap_delete(aspace, fault) failed")?;
    let reason = exited_reason(
        thread,
        "retype::aspace_stop: fault-blocked thread not Exited after its AddressSpace was deleted",
    );
    cap_delete(thread).map_err(|_| "retype::aspace_stop: cap_delete(thread, fault) failed")?;
    cap_delete(cspace).map_err(|_| "retype::aspace_stop: cap_delete(cspace, fault) failed")?;
    cap_delete(ep).map_err(|_| "retype::aspace_stop: cap_delete(ep) failed")?;
    if reason? != EXIT_KILLED
    {
        return Err("retype::aspace_stop: fault-blocked thread's exit reason is not EXIT_KILLED");
    }

    let after = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::aspace_stop: cap_info(after) failed")?;
    if after != baseline
    {
        return Err("retype::aspace_stop: memory did not return to baseline");
    }
    Ok(())
}

/// A thread deleting the last capability to its **own** `AddressSpace` is
/// stopped by that delete and never returns from it; the space is reclaimed
/// off-CPU once the thread has been scheduled away.
///
/// The child runs a stub in a dedicated address space whose only remaining
/// capability sits in the child's own `CSpace` (ktest's copy is deleted
/// before the child starts). The stub issues `SYS_CAP_DELETE` on it. ktest
/// observes the child `Exited` with `EXIT_KILLED`, then reclaims the thread
/// and `CSpace` and waits for memory to return to baseline — the address
/// space's own reclaim completes on the child's CPU after it is off it.
pub fn aspace_self_delete_stops_caller(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::aspace_self_delete: cap_info(baseline) failed")?;
    let aspace = cap_create_aspace(memory, 0, 8)
        .map_err(|_| "retype::aspace_self_delete: cap_create_aspace failed")?;
    let cspace = cap_create_cspace(memory, 0, 4)
        .map_err(|_| "retype::aspace_self_delete: cap_create_cspace failed")?;
    let child_as = cap_copy(aspace, cspace, RIGHTS_ALL)
        .map_err(|_| "retype::aspace_self_delete: cap_copy(aspace) failed")?;
    let frame = install_stub(ctx, aspace, |buf| {
        crate::arch::code_stub::emit_self_delete(buf, child_as)
    })?;
    let thread = cap_create_thread(memory, aspace, cspace, 0, 0)
        .map_err(|_| "retype::aspace_self_delete: cap_create_thread failed")?;
    // SAFETY: the thread is bound to the `aspace` this test created, not
    // ktest's own, so its entry state touches nothing ktest runs on.
    unsafe { thread_configure(thread, STUB_VA, STUB_VA + 0x800, 0) }
        .map_err(|_| "retype::aspace_self_delete: thread_configure failed")?;
    // Drop ktest's capability first, so the child's delete is the last one.
    cap_delete(aspace).map_err(|_| "retype::aspace_self_delete: cap_delete(aspace) failed")?;
    thread_start(thread).map_err(|_| "retype::aspace_self_delete: thread_start failed")?;

    let reason = crate::spawn::wait_until_exited(thread, crate::scaled_polls(MAX_POLLS));
    cap_delete(thread).map_err(|_| "retype::aspace_self_delete: cap_delete(thread) failed")?;
    cap_delete(cspace).map_err(|_| "retype::aspace_self_delete: cap_delete(cspace) failed")?;
    // SAFETY: the only mapping of `frame` went with the address space.
    unsafe { crate::frame_pool::free(frame) };
    if reason? != EXIT_KILLED
    {
        return Err("retype::aspace_self_delete: child's exit reason is not EXIT_KILLED");
    }
    crate::spawn::wait_memory_baseline(memory, baseline, crate::scaled_polls(MAX_POLLS))
        .map_err(|_| "retype::aspace_self_delete: memory did not return to baseline")
}

const SYS_OUT_OF_MEMORY: i64 = syscall_abi::SyscallError::OutOfMemory as i64;

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

    let cspace = cap_create_cspace(memory, 0, 1)
        .map_err(|_| "retype::cspace_augment: cap_create_cspace failed")?;
    let initial_budget = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::cspace_augment: cap_info(initial budget) failed")?;

    if cap_create_cspace(memory, cspace, 2).is_err()
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
    // The mapped pages come from a frame-pool cap: `mem_map` refuses the
    // region of `memory` that the retypes below consume.
    let scratch = ScratchFrame::alloc()?;
    let frame = scratch.0;

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
        // SAFETY: `aspace` is a fresh AddressSpace no ktest code runs in, so a
        // mapping at `va` there (past the scratch band once the stride leaves
        // it) holds no Rust object or IPC page of ktest.
        match unsafe { mem_map(frame, aspace, va, 0, 1, MAP_WRITABLE) }
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
    // SAFETY: the address space the frame was mapped into is destroyed.
    unsafe { scratch.release() };

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
    // The mapped pages come from a frame-pool cap: `mem_map` refuses the
    // region of `memory` that the retypes below consume.
    let scratch = ScratchFrame::alloc()?;
    let frame = scratch.0;

    // A 32-page slab (30 pool pages after the wrapper and root PT) covers
    // ≥ 4 mappings spread across distinct intermediate PT regions (each fresh
    // region needs 2-4 intermediate PT pages depending on arch, paging mode,
    // and sharing).
    let aspace = cap_create_aspace(memory, 0, 32)
        .map_err(|_| "retype::deep_pt: cap_create_aspace failed")?;

    let mappings = 4usize;
    let stride: u64 = 0x4000_0000; // 1 GiB stride forces fresh level-2 entries.
    for i in 0..mappings
    {
        let va = TEST_VA_BASE + i as u64 * stride;
        // SAFETY: `aspace` is a fresh AddressSpace no ktest code runs in, so a
        // mapping change at `va` there (past the scratch band once the stride
        // leaves it) touches no Rust object or IPC page of ktest.
        if unsafe { mem_map(frame, aspace, va, 0, 1, MAP_WRITABLE) }.is_err()
        {
            cap_delete(aspace).ok();
            return Err("retype::deep_pt: mem_map failed despite ample budget");
        }
    }

    // Unmap each page so the AS is clean before deletion.
    for i in 0..mappings
    {
        let va = TEST_VA_BASE + i as u64 * stride;
        // SAFETY: `aspace` is a fresh AddressSpace no ktest code runs in, so a
        // mapping change at `va` there (past the scratch band once the stride
        // leaves it) touches no Rust object or IPC page of ktest.
        unsafe { mem_unmap(aspace, va, 1) }.ok();
    }

    cap_delete(aspace).ok();
    // SAFETY: the address space the frame was mapped into is destroyed.
    unsafe { scratch.release() };
    Ok(())
}

/// `mem_unmap_reclaim` (the `MEM_UNMAP_RECLAIM_PTS` path) returns the
/// intermediate page tables a freed span empties back to the per-AS pool,
/// crediting `pt_growth_budget_bytes`. A fresh single-page mapping at a clean
/// VA allocates one intermediate table per non-root level (three on x86-64;
/// two to four on riscv64 depending on the negotiated paging mode); tearing
/// the region down reclaims them all (the budget round-trips to its pre-map
/// value), and the same VA then remaps from the returned pool pages.
pub fn region_unmap_reclaims_pt_budget(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    // The mapped pages come from a frame-pool cap: `mem_map` refuses the
    // region of `memory` that the retypes below consume.
    let scratch = ScratchFrame::alloc()?;
    let frame = scratch.0;

    // Slab: page 0 = wrapper, page 1 = root PT, pages 2..8 = 6 pool pages —
    // ample for the two to four intermediate tables a single fresh mapping needs.
    let aspace = cap_create_aspace(memory, 0, 8)
        .map_err(|_| "retype::region_reclaim: cap_create_aspace failed")?;

    let budget0 = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::region_reclaim: cap_info(budget0) failed")?;

    // Map one page at a fresh 2 MiB-aligned VA: allocates the full intermediate
    // chain (one table per non-root level) from the pool.
    // SAFETY: `TEST_VA_BASE` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(frame, aspace, TEST_VA_BASE, 0, 1, MAP_WRITABLE) }.is_err()
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

    // Reclaiming unmap: clears the leaf, empties every intermediate table on the
    // chain, returns them all to the pool and credits the budget.
    // SAFETY: `TEST_VA_BASE` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_unmap_reclaim(aspace, TEST_VA_BASE, 1) }.is_err()
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
    // SAFETY: `TEST_VA_BASE` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(frame, aspace, TEST_VA_BASE, 0, 1, MAP_WRITABLE) }.is_err()
    {
        cap_delete(aspace).ok();
        return Err("retype::region_reclaim: remap after reclaim failed");
    }
    // SAFETY: `TEST_VA_BASE` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    unsafe { mem_unmap_reclaim(aspace, TEST_VA_BASE, 1) }.ok();

    cap_delete(aspace).ok();
    // SAFETY: the address space the frame was mapped into is destroyed.
    unsafe { scratch.release() };
    Ok(())
}

/// A burst of concurrent distinct-VA regions holds peak PT-pool RAM while all
/// are mapped; reclaiming-unmap of each returns its intermediate tables, so the
/// budget recovers to its pre-burst value instead of staying depressed until
/// address-space death. This is the #273 peak-concurrency retention case: the
/// 1 GiB stride gives every region its own tables below the level-2 slot, under
/// whatever upper-level tables the paging mode shares, and the final unmap empties
/// and frees those shared tables too — a full round-trip to baseline.
pub fn concurrent_regions_release_pt_budget_on_unmap(ctx: &TestContext) -> TestResult
{
    const N: u64 = 6;
    const STRIDE: u64 = 0x4000_0000; // 1 GiB — distinct level-2 slot per region.

    let memory = ctx.memory_base;
    // The mapped pages come from a frame-pool cap: `mem_map` refuses the
    // region of `memory` that the retypes below consume.
    let scratch = ScratchFrame::alloc()?;
    let frame = scratch.0;

    // Generous pool: N regions' per-region intermediate tables plus any shared
    // upper-level tables, with slack.
    let aspace = cap_create_aspace(memory, 0, 64)
        .map_err(|_| "retype::concurrent_regions: cap_create_aspace failed")?;

    let baseline = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::concurrent_regions: cap_info(baseline) failed")?;

    // Map the whole burst (peak concurrency): budget drops as PTs allocate.
    for i in 0..N
    {
        let va = TEST_VA_BASE + i * STRIDE;
        // SAFETY: `aspace` is a fresh AddressSpace no ktest code runs in, so a
        // mapping change at `va` there (past the scratch band once the stride
        // leaves it) touches no Rust object or IPC page of ktest.
        if unsafe { mem_map(frame, aspace, va, 0, 1, MAP_WRITABLE) }.is_err()
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
        // SAFETY: `aspace` is a fresh AddressSpace no ktest code runs in, so a
        // mapping change at `va` there (past the scratch band once the stride
        // leaves it) touches no Rust object or IPC page of ktest.
        if unsafe { mem_unmap_reclaim(aspace, va, 1) }.is_err()
        {
            cap_delete(aspace).ok();
            return Err("retype::concurrent_regions: mem_unmap_reclaim failed");
        }
    }
    let after = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
        .map_err(|_| "retype::concurrent_regions: cap_info(after) failed")?;

    cap_delete(aspace).ok();
    // SAFETY: the address space the frame was mapped into is destroyed.
    unsafe { scratch.release() };

    if after != baseline
    {
        return Err("retype::concurrent_regions: PT budget not fully released on unmap");
    }
    Ok(())
}

/// `CSpace::grow` consumes pool pages as slots are inserted past the
/// first slot page's capacity. `CAP_INFO_CSPACE_USED` advances and
/// `CAP_INFO_CSPACE_BUDGET` drops in step.
pub fn cspace_grow_consumes_pool(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;

    // init_pages = 3 → wrapper page + 2 pool pages = 111 usable slots.
    let cspace = cap_create_cspace(memory, 0, 3)
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
        match cap_copy(probe, cspace, 1)
        {
            Ok(_) =>
            {}
            Err(SYS_OUT_OF_MEMORY) => break,
            Err(_) =>
            {
                cap_delete(probe).ok();
                cap_delete(cspace).ok();
                return Err(
                    "retype::cspace_grow: cap_copy failed for a reason other than the pool",
                );
            }
        }
    }

    let used_after = cap_info(cspace, CAP_INFO_CSPACE_USED);
    let budget_after = cap_info(cspace, CAP_INFO_CSPACE_BUDGET);

    cap_delete(probe).ok();
    cap_delete(cspace).ok();

    let used_after = used_after.map_err(|_| "retype::cspace_grow: cap_info(used after) failed")?;
    let budget_after =
        budget_after.map_err(|_| "retype::cspace_grow: cap_info(budget after) failed")?;

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

/// Pool exhaustion is refillable: an exhausted slot-page pool fails the
/// insert with `OutOfMemory` (-8) once only the IPC receive reserve
/// (`CSPACE_IPC_RECV_RESERVE` slots) is free, and an augment-mode donation
/// lifts the bound — every donated page's worth of inserts then succeeds.
/// Capacity is whatever the paid pool backs; no quota error exists below
/// the directory's structural ceiling.
pub fn cspace_pool_exhaust_then_augment(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;

    // init_pages = 2 → 1 pool page → 55 usable slots.
    let cspace = cap_create_cspace(memory, 0, 2)
        .map_err(|_| "retype::pool_exhaust: cap_create_cspace failed")?;
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::pool_exhaust: cap_create_endpoint failed");
    };

    // Copy until the first failure: the seeded pool backs 55 slots, of which
    // the IPC receive reserve keeps 4 free, so 51 copies succeed and the
    // 52nd hits pool exhaustion.
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

    // Refill the pool (2 more slot pages = 112 slots); every backed slot
    // must then accept an insert with no error in between.
    let augment_ok = cap_create_cspace(memory, cspace, 2).is_ok();
    let mut ok_after = 0u32;
    let mut err_after = 0i64;
    for _ in 0..=112
    {
        match cap_copy(probe, cspace, 1)
        {
            Ok(_) => ok_after += 1,
            Err(e) =>
            {
                err_after = e;
                break;
            }
        }
    }

    // Deleting the CSpace cap reclaims the copies wholesale.
    cap_delete(probe).ok();
    cap_delete(cspace).ok();

    if u64::from(ok_before) != 55 - syscall_abi::CSPACE_IPC_RECV_RESERVE
        || err_at_pool != SYS_OUT_OF_MEMORY
    {
        return Err(
            "retype::pool_exhaust: pool exhaustion did not surface OutOfMemory at the reserve",
        );
    }
    if !augment_ok
    {
        return Err("retype::pool_exhaust: augment-mode refill failed");
    }
    if ok_after != 112 || err_after != SYS_OUT_OF_MEMORY
    {
        return Err(
            "retype::pool_exhaust: augmented pool did not back exactly 112 further inserts",
        );
    }
    Ok(())
}

/// The indirect directory region works end to end: explicit-destination
/// placement past the direct region (slot 7300, leaf 130) and — memory
/// permitting — at index 1,000,000 (leaf 17,857), growing every
/// intermediate leaf and the covering pool-paid directory pages. The
/// wholesale delete reclaims the entire slab.
pub fn cspace_indirect_region(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = 4096;
    const SMALL_SLOT: u32 = 7300;
    const DEEP_SLOT: u32 = 1_000_000;
    // Pages to back DEEP_SLOT: leaves 0..=17,857 plus 35 directory pages.
    const DEEP_POOL_PAGES: u64 = 17_893;

    let memory = ctx.memory_base;
    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::indirect: cap_info(baseline) failed")?;
    let probe = cap_create_notification(memory)
        .map_err(|_| "retype::indirect: cap_create_notification failed")?;

    let cspace = cap_create_cspace(memory, 0, 4)
        .map_err(|_| "retype::indirect: cap_create_cspace failed")?;

    // Deep placement first (while the pool is coldest): fund it only if the
    // source cap has comfortable headroom, otherwise skip-pass the deep
    // half — CI guests with small RAM still exercise the small crossing.
    let deep = baseline > (DEEP_POOL_PAGES + 4096) * PAGE;
    if deep
    {
        if cap_create_cspace(memory, cspace, DEEP_POOL_PAGES).is_err()
        {
            cap_delete(cspace).ok();
            cap_delete(probe).ok();
            return Err("retype::indirect: deep augment failed");
        }
        if cap_insert(probe, cspace, DEEP_SLOT, RIGHTS_NTF_NOTIFY).is_err()
        {
            cap_delete(cspace).ok();
            cap_delete(probe).ok();
            return Err("retype::indirect: cap_insert(1_000_000) failed");
        }
    }
    else
    {
        crate::log("ktest: retype::cspace_indirect_region deep half SKIP (low memory)");
        // Small augment instead: enough pool for 131 leaves + 1 dir page.
        if cap_create_cspace(memory, cspace, 132).is_err()
        {
            cap_delete(cspace).ok();
            cap_delete(probe).ok();
            return Err("retype::indirect: small augment failed");
        }
    }

    // Small crossing: leaf 130, three-level lookup path.
    if cap_insert(probe, cspace, SMALL_SLOT, RIGHTS_NTF_NOTIFY).is_err()
    {
        cap_delete(cspace).ok();
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_insert(7300) failed");
    }

    // Explicit high-slot MOVE: same growth contract on the path that also
    // holds the derivation lock. The moved cap is consumed from this
    // CSpace and lands in the target.
    let mover = cap_create_notification(memory)
        .map_err(|_| "retype::indirect: cap_create_notification(mover) failed")?;
    if syscall::cap_move(mover, cspace, SMALL_SLOT + 56).is_err()
    {
        cap_delete(mover).ok();
        cap_delete(cspace).ok();
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_move to a high explicit slot failed");
    }

    let used = cap_info(cspace, CAP_INFO_CSPACE_USED)
        .map_err(|_| "retype::indirect: cap_info(used) failed")?;
    let expected_used = if deep { 3 } else { 2 };
    // An occupied high slot must also reject a second explicit placement.
    let occupied = cap_insert(probe, cspace, SMALL_SLOT, RIGHTS_NTF_NOTIFY).is_err();

    // Wholesale reclaim.
    cap_delete(cspace).map_err(|_| "retype::indirect: cap_delete(cspace) failed")?;
    cap_delete(probe).map_err(|_| "retype::indirect: cap_delete(probe) failed")?;

    if used != expected_used
    {
        return Err("retype::indirect: CSPACE_USED mismatch after explicit placements");
    }
    if !occupied
    {
        return Err("retype::indirect: re-placement at an occupied high slot succeeded");
    }
    let after = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::indirect: cap_info(after) failed")?;
    if after != baseline
    {
        return Err("retype::indirect: slab not fully reclaimed on delete");
    }
    Ok(())
}

/// A doomed explicit placement fails fast without consuming any pool
/// page: covering slot 7300 needs 132 pages (131 leaves plus the first
/// directory page) against a 1-page pool, and the budget is untouched
/// after the rejection.
pub fn cspace_explicit_placement_fast_fail(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = 4096;
    let memory = ctx.memory_base;
    let cspace = cap_create_cspace(memory, 0, 2)
        .map_err(|_| "retype::fast_fail: cap_create_cspace failed")?;
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::fast_fail: cap_create_endpoint failed");
    };

    let before = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::fast_fail: cap_info(budget) failed")?;
    let doomed = cap_insert(probe, cspace, 7300, syscall::RIGHTS_ALL);
    let after = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "retype::fast_fail: cap_info(budget after) failed")?;
    cap_delete(probe).ok();
    cap_delete(cspace).ok();
    if doomed != Err(SYS_OUT_OF_MEMORY) || before != after || before != PAGE
    {
        return Err("retype::fast_fail: doomed placement consumed budget");
    }
    Ok(())
}

/// A directory page that outlives a failed leaf allocation stays
/// published and is not re-charged: with exactly one pool page at the
/// direct/indirect boundary, the auto-allocating grow spends it on the
/// directory page and fails the leaf with `OutOfMemory`; after a one-page
/// refill the next insert succeeds without buying the directory page
/// again.
pub fn cspace_dir_page_survives_failed_grow(ctx: &TestContext) -> TestResult
{
    // 128 direct leaves x 56 slots, minus reserved slot 0.
    const DIRECT_SLOTS: u32 = 128 * 56 - 1;

    let memory = ctx.memory_base;
    let cspace = cap_create_cspace(memory, 0, 2)
        .map_err(|_| "retype::dir_survives: cap_create_cspace failed")?;
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: cap_create_endpoint failed");
    };

    // Fill the whole direct region, all but the IPC receive reserve, so
    // general allocations stop exactly at the direct/indirect boundary. 128
    // leaf pages total; 127 more than seeded.
    if cap_create_cspace(memory, cspace, 127).is_err()
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: boundary augment failed");
    }
    for _ in 0..u64::from(DIRECT_SLOTS) - syscall_abi::CSPACE_IPC_RECV_RESERVE
    {
        if cap_copy(probe, cspace, 1).is_err()
        {
            cap_delete(probe).ok();
            cap_delete(cspace).ok();
            return Err("retype::dir_survives: direct-region fill failed early");
        }
    }

    // One page in the pool at the boundary: the grow buys the directory
    // page, then fails the leaf.
    if cap_create_cspace(memory, cspace, 1).is_err()
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: one-page refill failed");
    }
    let at_boundary = cap_copy(probe, cspace, 1);
    let Ok(budget_after_fail) = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
    else
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: cap_info(budget after boundary) failed");
    };
    if at_boundary != Err(SYS_OUT_OF_MEMORY) || budget_after_fail != 0
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: boundary grow did not fail after buying the dir page");
    }

    // One more page: the surviving directory page is not re-charged, so a
    // single page now buys leaf 128. Its 56 slots join the 4 the IPC receive
    // reserve kept free, so exactly 56 more general inserts succeed before
    // the reserve is reached again.
    if cap_create_cspace(memory, cspace, 1).is_err()
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: second refill failed");
    }
    let mut landed = 0u32;
    for _ in 0..=56
    {
        if cap_copy(probe, cspace, 1).is_err()
        {
            break;
        }
        landed += 1;
    }
    cap_delete(probe).ok();
    cap_delete(cspace).ok();
    match landed
    {
        56 => Ok(()),
        0 => Err("retype::dir_survives: insert after refill failed — dir page re-charged?"),
        _ => Err("retype::dir_survives: the refill page did not back exactly one leaf"),
    }
}

/// Donations are unbounded in count: past the wrapper's inline records they
/// spill into record pages carved from the donations themselves (see
/// [capability-internals.md](../../../kernel/docs/capability-internals.md)
/// § Donation Records). Two hundred
/// donations of one page each cross the inline limit and one full record page,
/// so exactly two donations supply a record page and seed nothing; every
/// other page is usable, and the wholesale delete returns all of them to
/// the source Memory cap.
pub fn cspace_augment_many(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = 4096;
    const DONATIONS: u64 = 200;
    // Donations 16 and 186 open the two record pages: the inline records
    // hold the create-time slab plus fifteen donations, and a record page
    // holds 170 records — the kernel's RECORDS_PER_PAGE: a page's 4096
    // bytes less a 16-byte header, over 24-byte records — the first being its
    // own donation.
    const RECORD_PAGES: u64 = 2;
    const SEEDED: u64 = DONATIONS - RECORD_PAGES;
    // Mirrors the kernel's `L1_DIRECT`: leaves the inline root addresses
    // directly.
    const DIRECT_LEAVES: u64 = 128;
    // Mirrors the kernel's `DIR_FANOUT`: leaves per pool-paid directory page.
    const DIR_FANOUT: u64 = 512;
    // Directory pages the pool pays for leaves past the direct region; each
    // costs a page that would otherwise be a leaf. For the 198 seeded pages
    // here: one directory page, leaving 197 leaves.
    const fn directory_pages(pool_pages: u64) -> u64
    {
        let mut dirs = 0;
        while pool_pages
            .saturating_sub(dirs)
            .saturating_sub(DIRECT_LEAVES)
            > dirs * DIR_FANOUT
        {
            dirs += 1;
        }
        dirs
    }
    const DIRECTORY_PAGES: u64 = directory_pages(SEEDED);
    // Slots per leaf page: the kernel's `L2_SIZE`, published in the ABI.
    const SLOTS_PER_LEAF: u64 = syscall_abi::CSPACE_SLOTS_PER_PAGE;
    let memory = ctx.memory_base;

    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::cspace_augment_many: cap_info(baseline) failed")?;

    // init_pages = 1 → wrapper only: empty pool, zero budget.
    let cspace = cap_create_cspace(memory, 0, 1)
        .map_err(|_| "retype::cspace_augment_many: cap_create_cspace failed")?;
    let mut augment_failures = 0u32;
    for _ in 0..DONATIONS
    {
        if cap_create_cspace(memory, cspace, 1).is_err()
        {
            augment_failures += 1;
        }
    }
    let Ok(budget) = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::cspace_augment_many: cap_info(budget) failed");
    };

    // Every seeded page except the directory page backs a leaf; slot 0 of
    // the first leaf is the null slot, and the IPC receive reserve stays
    // free behind the general inserts.
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::cspace_augment_many: cap_create_endpoint failed");
    };
    let expected_copies =
        (SEEDED - DIRECTORY_PAGES) * SLOTS_PER_LEAF - 1 - syscall_abi::CSPACE_IPC_RECV_RESERVE;
    let mut copies = 0u64;
    let mut terminal = 0i64;
    for _ in 0..=expected_copies
    {
        match cap_copy(probe, cspace, 1)
        {
            Ok(_) => copies += 1,
            Err(e) =>
            {
                terminal = e;
                break;
            }
        }
    }

    // Deleting the CSpace reclaims the copies and every donation wholesale.
    cap_delete(cspace).ok();
    cap_delete(probe).ok();
    let after = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::cspace_augment_many: cap_info(after) failed")?;

    if augment_failures != 0
    {
        return Err("retype::cspace_augment_many: a donation past the inline records failed");
    }
    if budget != SEEDED * PAGE
    {
        return Err(
            "retype::cspace_augment_many: budget != SEEDED pages (mirrors RECORDS_PER_PAGE)",
        );
    }
    if copies != expected_copies || terminal != SYS_OUT_OF_MEMORY
    {
        return Err("retype::cspace_augment_many: seeded pages did not back exactly their slots");
    }
    if after != baseline
    {
        return Err(
            "retype::cspace_augment_many: delete did not return every donation to the Memory cap",
        );
    }
    Ok(())
}

/// The address-space pool spills its donation records the same way. Pages
/// described by spilled records serve as page tables: the free list is
/// LIFO, so fresh mappings draw first on the newest donations (described by
/// the second record page) and, once the pages it describes are used up, on
/// donations the first record page describes. Every table a reclaiming
/// unmap frees must be credited back, so the budget returns exactly to its
/// post-donation value, and the delete returns every donation.
pub fn aspace_augment_many(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = 4096;
    const DONATIONS: u64 = 200;
    const RECORD_PAGES: u64 = 2;
    const SEEDED: u64 = DONATIONS - RECORD_PAGES;
    // Each region at a 1 GiB stride costs at least two fresh intermediate
    // tables in every paging mode, so twelve regions consume more than the
    // fourteen pages the newest record page describes.
    const REGIONS: u64 = 12;
    const REGION_STRIDE: u64 = 0x4000_0000;
    let memory = ctx.memory_base;
    // The mapped pages come from a frame-pool cap: `mem_map` refuses the
    // region of `memory` that the retypes below consume.
    let scratch = ScratchFrame::alloc()?;
    let frame = scratch.0;

    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::aspace_augment_many: cap_info(baseline) failed")?;

    // init_pages = 2 → wrapper + root PT: empty pool, zero budget.
    let aspace = cap_create_aspace(memory, 0, 2)
        .map_err(|_| "retype::aspace_augment_many: cap_create_aspace failed")?;
    let mut augment_failures = 0u32;
    for _ in 0..DONATIONS
    {
        if cap_create_aspace(memory, aspace, 1).is_err()
        {
            augment_failures += 1;
        }
    }
    let Ok(budget) = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
    else
    {
        cap_delete(aspace).ok();
        return Err("retype::aspace_augment_many: cap_info(budget) failed");
    };

    let mut map_failures = 0u32;
    for i in 0..REGIONS
    {
        // SAFETY: `TEST_VA_BASE + i * REGION_STRIDE` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe {
            mem_map(
                frame,
                aspace,
                TEST_VA_BASE + i * REGION_STRIDE,
                0,
                1,
                MAP_WRITABLE,
            )
        }
        .is_err()
        {
            map_failures += 1;
        }
    }
    let Ok(after_map) = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET)
    else
    {
        cap_delete(aspace).ok();
        return Err("retype::aspace_augment_many: cap_info(after map) failed");
    };
    let mut reclaim_failures = 0u32;
    for i in 0..REGIONS
    {
        // SAFETY: `TEST_VA_BASE + i * REGION_STRIDE` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        if unsafe { mem_unmap_reclaim(aspace, TEST_VA_BASE + i * REGION_STRIDE, 1) }.is_err()
        {
            reclaim_failures += 1;
        }
    }
    let after_reclaim = cap_info(aspace, CAP_INFO_ASPACE_PT_BUDGET);

    cap_delete(aspace).ok();
    // SAFETY: the address space the frame was mapped into is destroyed.
    unsafe { scratch.release() };
    let after_reclaim =
        after_reclaim.map_err(|_| "retype::aspace_augment_many: cap_info(after reclaim) failed")?;
    let after = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::aspace_augment_many: cap_info(after) failed")?;

    if augment_failures != 0
    {
        return Err("retype::aspace_augment_many: a donation past the inline records failed");
    }
    if budget != SEEDED * PAGE
    {
        return Err(
            "retype::aspace_augment_many: budget != SEEDED pages (mirrors RECORDS_PER_PAGE)",
        );
    }
    if map_failures != 0 || after_map > budget.saturating_sub(2 * REGIONS * PAGE)
    {
        return Err("retype::aspace_augment_many: mappings did not draw two tables per region");
    }
    if reclaim_failures != 0 || after_reclaim != budget
    {
        return Err(
            "retype::aspace_augment_many: reclaiming unmaps did not credit every table back",
        );
    }
    if after != baseline
    {
        return Err(
            "retype::aspace_augment_many: delete did not return every donation to the Memory cap",
        );
    }
    Ok(())
}
