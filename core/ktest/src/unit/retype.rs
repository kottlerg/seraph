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
//! - **Page-pool latency** — the teardown of a pool of ten thousand
//!   donations, and the seeding of one large donation, take interrupts
//!   between batches: a TLB shootdown of the CPU making the call is
//!   acknowledged within a bound while the call runs.
//!
//! All retype sources come from `ctx.memory_base` directly, but for the
//! page-pool latency cases, which split a piece off its top and merge it
//! back; the source cap is never deleted (the parent Memory cap is shared
//! across the suite). Each test cleans up only its own derived caps.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_aspace, cap_create_cspace, cap_create_endpoint, cap_create_notification,
    cap_create_thread, cap_delete, cap_info, cap_insert, mem_map, mem_unmap, mem_unmap_reclaim,
    memory_merge, memory_split, system_info, thread_configure, thread_set_affinity, thread_sleep,
    thread_start, thread_yield,
};
use syscall_abi::{
    CAP_INFO_ASPACE_PT_BUDGET, CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_USED,
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_SIZE, CAP_INFO_THREAD_STATE, EXIT_KILLED,
    FAULT_LABEL, MAP_EXECUTABLE, MAP_WRITABLE, RIGHTS_ALL, RIGHTS_NTF_NOTIFY, SystemInfoType,
    THREAD_STATE_EXITED,
};

use crate::{TestContext, TestResult};

const TEST_VA_BASE: u64 = 0x0000_0001_4000_0000;

/// Leaf pages the `CSpace` root addresses directly: mirrors the kernel's
/// `L1_DIRECT` (core/kernel/src/cap/cspace.rs).
const DIRECT_LEAVES: u64 = 128;
/// Leaves per pool-paid directory page: mirrors the kernel's `DIR_FANOUT`,
/// one page of leaf pointers.
const DIR_FANOUT: u64 = syscall_abi::PAGE_SIZE / core::mem::size_of::<*const ()>() as u64;
/// The slot index of [`INDIRECT_SLOT`] as a `u64`, before its narrowing to `u32`.
const INDIRECT_SLOT_INDEX: u64 = (DIRECT_LEAVES + 2) * syscall_abi::CSPACE_SLOTS_PER_PAGE + 20;
const _: () = assert!(INDIRECT_SLOT_INDEX >> 32 == 0);
/// A slot past the direct region's `DIRECT_LEAVES` × `CSPACE_SLOTS_PER_PAGE`
/// slots, under the first directory page: 20 slots into the third leaf past
/// the direct region.
// cast_possible_truncation: the assert above keeps INDIRECT_SLOT_INDEX
// within u32.
#[allow(clippy::cast_possible_truncation)]
const INDIRECT_SLOT: u32 = INDIRECT_SLOT_INDEX as u32;

/// Pool pages a `CSpace` with no grown leaf spends to cover slot `index`:
/// every leaf through the covering one (`CSPACE_SLOTS_PER_PAGE` slots each,
/// the kernel's `L2_SIZE`), plus the directory pages above the direct
/// region. Mirrors the kernel's `CSpace::pages_to_cover` from leaf 0.
fn pages_to_cover(index: u32) -> u64
{
    let leaf = u64::from(index) / syscall_abi::CSPACE_SLOTS_PER_PAGE;
    let dirs = if leaf >= DIRECT_LEAVES
    {
        (leaf - DIRECT_LEAVES) / DIR_FANOUT + 1
    }
    else
    {
        0
    };
    leaf + 1 + dirs
}

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
    aspace: u64,
    emit: impl FnOnce(&mut [u8]) -> usize,
) -> Result<u64, &'static str>
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
fn exited_reason(thread: u64, what: &'static str) -> Result<u64, &'static str>
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
struct ScratchFrame(u64);

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

    // init_pages = 3 → wrapper page + 2 pool pages: two leaves of
    // `CSPACE_SLOTS_PER_PAGE` slots, less reserved slot 0.
    let cspace = cap_create_cspace(memory, 0, 3)
        .map_err(|_| "retype::cspace_grow: cap_create_cspace failed")?;
    let Ok(used_before) = cap_info(cspace, CAP_INFO_CSPACE_USED)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::cspace_grow: cap_info(used before) failed");
    };
    let Ok(budget_before) = cap_info(cspace, CAP_INFO_CSPACE_BUDGET)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::cspace_grow: cap_info(budget before) failed");
    };

    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::cspace_grow: cap_create_endpoint failed");
    };

    // Copy a quarter page past the first slot page's
    // `CSPACE_SLOTS_PER_PAGE` slots (the kernel's `L2_SIZE`), forcing at
    // least one grow.
    let copies = syscall_abi::CSPACE_SLOTS_PER_PAGE + syscall_abi::CSPACE_SLOTS_PER_PAGE / 4;
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
    // Slots one pool page backs (the kernel's `L2_SIZE`).
    const PAGE_SLOTS: u64 = syscall_abi::CSPACE_SLOTS_PER_PAGE;

    let memory = ctx.memory_base;

    // init_pages = 2 → 1 pool page → PAGE_SLOTS - 1 usable slots (slot 0 is
    // the null slot).
    let cspace = cap_create_cspace(memory, 0, 2)
        .map_err(|_| "retype::pool_exhaust: cap_create_cspace failed")?;
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::pool_exhaust: cap_create_endpoint failed");
    };

    // Copy until the first failure: the seeded pool backs PAGE_SLOTS - 1
    // slots, of which the IPC receive reserve keeps CSPACE_IPC_RECV_RESERVE
    // free, so that many fewer copies succeed before pool exhaustion.
    let mut ok_before = 0u64;
    let mut err_at_pool = 0i64;
    for _ in 0..PAGE_SLOTS
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

    // Refill the pool (2 more slot pages); every backed slot must then accept
    // an insert with no error in between.
    let augment_ok = cap_create_cspace(memory, cspace, 2).is_ok();
    let mut ok_after = 0u64;
    let mut err_after = 0i64;
    for _ in 0..=2 * PAGE_SLOTS
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

    if ok_before != PAGE_SLOTS - 1 - syscall_abi::CSPACE_IPC_RECV_RESERVE
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
    if ok_after != 2 * PAGE_SLOTS || err_after != SYS_OUT_OF_MEMORY
    {
        return Err(
            "retype::pool_exhaust: augmented pool did not back exactly two pages of inserts",
        );
    }
    Ok(())
}

/// The indirect directory region works end to end: explicit-destination
/// placement past the direct region (`INDIRECT_SLOT`) and — memory
/// permitting — at index 1,000,000, growing every intermediate leaf and the
/// covering pool-paid directory pages. The wholesale delete reclaims the
/// entire slab.
pub fn cspace_indirect_region(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = syscall_abi::PAGE_SIZE;
    const DEEP_SLOT: u32 = 1_000_000;
    let deep_pool_pages = pages_to_cover(DEEP_SLOT);
    // INDIRECT_SLOT one leaf on: slots per leaf page are the kernel's
    // `L2_SIZE`, published in the ABI. Taken before any capability exists,
    // so the refusal needs no cleanup.
    let next_leaf_slot = u32::try_from(syscall_abi::CSPACE_SLOTS_PER_PAGE)
        .map(|leaf| INDIRECT_SLOT + leaf)
        .map_err(|_| "retype::indirect: CSPACE_SLOTS_PER_PAGE exceeds a slot index")?;

    let memory = ctx.memory_base;
    let baseline = cap_info(memory, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::indirect: cap_info(baseline) failed")?;
    let probe = cap_create_notification(memory)
        .map_err(|_| "retype::indirect: cap_create_notification failed")?;

    let Ok(cspace) = cap_create_cspace(memory, 0, 4)
    else
    {
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_create_cspace failed");
    };

    // Deep placement first (while the pool is coldest): fund it only if the
    // source cap has comfortable headroom, otherwise skip-pass the deep
    // half — CI guests with small RAM still exercise the small crossing.
    let deep = baseline > (deep_pool_pages + 4096) * PAGE;
    if deep
    {
        if cap_create_cspace(memory, cspace, deep_pool_pages).is_err()
        {
            cap_delete(cspace).ok();
            cap_delete(probe).ok();
            return Err("retype::indirect: deep augment failed");
        }
        if cap_insert(probe, cspace, DEEP_SLOT, RIGHTS_NTF_NOTIFY).is_err()
        {
            cap_delete(cspace).ok();
            cap_delete(probe).ok();
            return Err("retype::indirect: cap_insert(DEEP_SLOT) failed");
        }
    }
    else
    {
        crate::log("ktest: retype::cspace_indirect_region deep half SKIP (low memory)");
        // Small augment instead: enough pool to cover INDIRECT_SLOT.
        if cap_create_cspace(memory, cspace, pages_to_cover(INDIRECT_SLOT)).is_err()
        {
            cap_delete(cspace).ok();
            cap_delete(probe).ok();
            return Err("retype::indirect: small augment failed");
        }
    }

    // Small crossing: the first indirect leaves, three-level lookup path.
    if cap_insert(probe, cspace, INDIRECT_SLOT, RIGHTS_NTF_NOTIFY).is_err()
    {
        cap_delete(cspace).ok();
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_insert(INDIRECT_SLOT) failed");
    }

    // Explicit high-slot MOVE: same growth contract on the path that also
    // holds the derivation lock. The moved cap is consumed from this
    // CSpace and lands in the target.
    let Ok(mover) = cap_create_notification(memory)
    else
    {
        cap_delete(cspace).ok();
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_create_notification(mover) failed");
    };
    if syscall::cap_move(mover, cspace, next_leaf_slot).is_err()
    {
        cap_delete(mover).ok();
        cap_delete(cspace).ok();
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_move to a high explicit slot failed");
    }

    let Ok(used) = cap_info(cspace, CAP_INFO_CSPACE_USED)
    else
    {
        cap_delete(cspace).ok();
        cap_delete(probe).ok();
        return Err("retype::indirect: cap_info(used) failed");
    };
    let expected_used = if deep { 3 } else { 2 };
    // An occupied high slot must also reject a second explicit placement.
    let occupied = cap_insert(probe, cspace, INDIRECT_SLOT, RIGHTS_NTF_NOTIFY).is_err();

    // Wholesale reclaim.
    let cspace_deleted = cap_delete(cspace);
    let probe_deleted = cap_delete(probe);
    cspace_deleted.map_err(|_| "retype::indirect: cap_delete(cspace) failed")?;
    probe_deleted.map_err(|_| "retype::indirect: cap_delete(probe) failed")?;

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
/// page: covering `INDIRECT_SLOT` needs `pages_to_cover(INDIRECT_SLOT)` pages
/// (every leaf through its own plus the first directory page) against a
/// 1-page pool, and the budget is untouched after the rejection.
pub fn cspace_explicit_placement_fast_fail(ctx: &TestContext) -> TestResult
{
    const PAGE: u64 = syscall_abi::PAGE_SIZE;
    let memory = ctx.memory_base;
    let cspace = cap_create_cspace(memory, 0, 2)
        .map_err(|_| "retype::fast_fail: cap_create_cspace failed")?;
    let Ok(probe) = cap_create_endpoint(memory)
    else
    {
        cap_delete(cspace).ok();
        return Err("retype::fast_fail: cap_create_endpoint failed");
    };

    let before = cap_info(cspace, CAP_INFO_CSPACE_BUDGET);
    let doomed = cap_insert(probe, cspace, INDIRECT_SLOT, syscall::RIGHTS_ALL);
    let after = cap_info(cspace, CAP_INFO_CSPACE_BUDGET);
    cap_delete(probe).ok();
    cap_delete(cspace).ok();
    let before = before.map_err(|_| "retype::fast_fail: cap_info(budget) failed")?;
    let after = after.map_err(|_| "retype::fast_fail: cap_info(budget after) failed")?;
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
    // The direct leaves of `CSPACE_SLOTS_PER_PAGE` slots (the kernel's
    // `L2_SIZE`), minus reserved slot 0.
    const DIRECT_SLOTS: u64 = DIRECT_LEAVES * syscall_abi::CSPACE_SLOTS_PER_PAGE - 1;

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
    // general allocations stop exactly at the direct/indirect boundary: the
    // direct leaves less the one seeded.
    if cap_create_cspace(memory, cspace, DIRECT_LEAVES - 1).is_err()
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: boundary augment failed");
    }
    for _ in 0..DIRECT_SLOTS - syscall_abi::CSPACE_IPC_RECV_RESERVE
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
    // single page now buys the first indirect leaf. Its
    // `CSPACE_SLOTS_PER_PAGE` slots join the `CSPACE_IPC_RECV_RESERVE` slots
    // the reserve kept free, so exactly that many more general inserts
    // succeed before the reserve is reached again.
    if cap_create_cspace(memory, cspace, 1).is_err()
    {
        cap_delete(probe).ok();
        cap_delete(cspace).ok();
        return Err("retype::dir_survives: second refill failed");
    }
    let mut landed = 0u64;
    for _ in 0..=syscall_abi::CSPACE_SLOTS_PER_PAGE
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
        syscall_abi::CSPACE_SLOTS_PER_PAGE => Ok(()),
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
    const PAGE: u64 = syscall_abi::PAGE_SIZE;
    const DONATIONS: u64 = 200;
    // Donations 16 and 143 open the two record pages: the inline records
    // hold the create-time slab plus fifteen donations, and a record page
    // holds 127 records — the kernel's RECORDS_PER_PAGE: a page's 4096
    // bytes less a 16-byte header, over 32-byte records — the first being its
    // own donation.
    const RECORD_PAGES: u64 = 2;
    const SEEDED: u64 = DONATIONS - RECORD_PAGES;
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
    const PAGE: u64 = syscall_abi::PAGE_SIZE;
    // Donations 16 and 143 open the two record pages (127 records each, as
    // above), so the newest describes the last fourteen donations.
    const DONATIONS: u64 = 157;
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

// ── Page-pool latency ───────────────────────────────────────────────────────
//
// A pool's teardown returns every donation, and its seeding pushes every
// donated page, inside one syscall whose length the caller chooses; the
// kernel takes interrupts between the batches of either
// (core/kernel/docs/capability-internals.md § Donation Records and
// § Teardown). A probe pinned to `PROBE_CPU` unmaps a page of ktest's address
// space in a loop, each unmap a synchronous TLB shootdown of `WORKER_CPU`,
// where a worker makes the call. Every probe the call overlaps must be
// acknowledged within `LATENCY_BOUND_US`, and a probe issued once the call
// was under way must be acknowledged before the call returned. A kernel that
// masks interrupts for the whole call fails both on the teardown, whose
// returns each walk the source's page free list, and the second on the
// seeding.

/// One-page holes the teardown cases leave on the source's page free list
/// below every donation of the target: a teardown that returns each donation
/// through its own walk of the list from its head passes all of them per
/// donation.
const LAT_HOLES: u64 = 20_000;
/// One-page donations of the teardown cases' target.
const LAT_DONATIONS: u64 = 10_000;
/// Pages the latency cases split off `memory_base`: a hole and a kept
/// neighbour per hole, the donations, and a guard page above them that keeps
/// their returns off the source's bump frontier.
const LAT_SOURCE_PAGES: u64 = 2 * LAT_HOLES + LAT_DONATIONS + 1;
/// Longest a probe that the measured call overlaps may wait for its
/// acknowledgement, in microseconds (stretched by `scaled_bound`). A window
/// between batches here costs at most one walk of `LAT_HOLES` nodes.
const LATENCY_BOUND_US: u64 = 250_000;
/// Bound on the whole measured call and on the worker's readiness, in
/// microseconds (stretched by `scaled_bound`).
const LAT_CALL_DEADLINE_US: u64 = 60_000_000;
/// The probe's page (crate docs § Scratch VAs).
const PROBE_VA: u64 = 0x1_6600_0000;
const PROBE_CPU: u32 = 0;
const WORKER_CPU: u32 = 1;

/// The calls the worker makes: delete `LAT_ARG0`, or create a `CSpace` or an
/// address space from Memory cap `LAT_ARG0` with `LAT_ARG1` pages.
const LAT_OP_DELETE: u64 = 1;
const LAT_OP_CREATE_CSPACE: u64 = 2;
const LAT_OP_CREATE_ASPACE: u64 = 3;

static LAT_OP: AtomicU64 = AtomicU64::new(0);
static LAT_ARG0: AtomicU64 = AtomicU64::new(0);
static LAT_ARG1: AtomicU64 = AtomicU64::new(0);
/// The worker's shortest syscall round trip, in microseconds: how long its
/// CPU runs with interrupts enabled between two syscalls.
static LAT_GAP_US: AtomicU64 = AtomicU64::new(0);
static LAT_READY: AtomicBool = AtomicBool::new(false);
static LAT_GO: AtomicBool = AtomicBool::new(false);
/// `ElapsedUs` just before and just after the measured call; 0 until set.
static LAT_START: AtomicU64 = AtomicU64::new(0);
static LAT_END: AtomicU64 = AtomicU64::new(0);
/// The call's result: its return value, or `u64::MAX` on an error.
static LAT_RESULT: AtomicU64 = AtomicU64::new(0);
static mut LAT_STACK: crate::ChildStack = crate::ChildStack::ZERO;

/// Worker entry: measure this CPU's syscall round trip, report ready, wait for
/// the probe, then make the call `LAT_OP` names between two clock reads.
extern "C" fn latency_worker(_arg: u64) -> !
{
    let mut gap = u64::MAX;
    let mut prev = crate::elapsed_us();
    for _ in 0..16
    {
        let now = crate::elapsed_us();
        gap = gap.min(now.saturating_sub(prev));
        prev = now;
    }
    LAT_GAP_US.store(gap, Ordering::Relaxed);
    LAT_READY.store(true, Ordering::Release);
    while !LAT_GO.load(Ordering::Acquire)
    {
        core::hint::spin_loop();
    }
    let (op, a0, a1) = (
        LAT_OP.load(Ordering::Relaxed),
        LAT_ARG0.load(Ordering::Relaxed),
        LAT_ARG1.load(Ordering::Relaxed),
    );
    LAT_START.store(crate::elapsed_us(), Ordering::Release);
    let result = match op
    {
        LAT_OP_DELETE => cap_delete(a0).map(|()| 0),
        LAT_OP_CREATE_CSPACE => cap_create_cspace(a0, 0, a1),
        LAT_OP_CREATE_ASPACE => cap_create_aspace(a0, 0, a1),
        _ => Err(0),
    };
    let end = crate::elapsed_us();
    LAT_RESULT.store(result.unwrap_or(u64::MAX), Ordering::Relaxed);
    LAT_END.store(end, Ordering::Release);
    syscall::thread_exit()
}

/// What the probe saw of one measured call.
struct Measured
{
    /// The call's duration.
    span_us: u64,
    /// The longest acknowledgement of a probe the call overlapped.
    max_wait_us: u64,
    /// Whether a probe issued once the call was under way was acknowledged
    /// before it returned.
    acked_inside: bool,
    /// The call's result (`LAT_RESULT`).
    result: u64,
}

/// Run the call `op` on a worker pinned to `WORKER_CPU`, probing it from
/// `PROBE_CPU` with unmaps of `frame` at `PROBE_VA`. The harness thread is
/// pinned to `PROBE_CPU` for the call and unpinned afterwards.
fn measure_call(
    ctx: &TestContext,
    frame: u64,
    op: u64,
    a0: u64,
    a1: u64,
) -> Result<Measured, &'static str>
{
    for word in [&LAT_GAP_US, &LAT_START, &LAT_END, &LAT_RESULT]
    {
        word.store(0, Ordering::Relaxed);
    }
    LAT_READY.store(false, Ordering::Relaxed);
    LAT_GO.store(false, Ordering::Relaxed);
    LAT_OP.store(op, Ordering::Relaxed);
    LAT_ARG0.store(a0, Ordering::Relaxed);
    LAT_ARG1.store(a1, Ordering::Release);

    thread_set_affinity(ctx.thread_cap, PROBE_CPU)
        .map_err(|_| "retype::pool_latency: pin the probe failed")?;
    let measured = thread_yield()
        .map_err(|_| "retype::pool_latency: yield failed")
        .and_then(|()| probe_worker(ctx, frame));
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "retype::pool_latency: restore the probe's affinity failed");
    let measured = measured?;
    restore?;
    Ok(measured)
}

/// Start the worker in ktest's own `CSpace`, so the handles in `LAT_ARG0`
/// are its own, probe it until its call returns, and reap it.
fn probe_worker(ctx: &TestContext, frame: u64) -> Result<Measured, &'static str>
{
    let mut worker = crate::spawn::SpawnedChild {
        th: cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
            .map_err(|_| "retype::pool_latency: create the worker failed")?,
        cs: 0,
    };
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and
    // `LAT_STACK` is this test's own stack, on which no other live thread runs
    // (the cases run one at a time and reap the worker before returning).
    unsafe {
        thread_configure(
            worker.th,
            latency_worker as *const () as u64,
            crate::ChildStack::top(core::ptr::addr_of!(LAT_STACK)),
            0,
        )
    }
    .map_err(|_| "retype::pool_latency: configure the worker failed")?;
    thread_set_affinity(worker.th, WORKER_CPU)
        .map_err(|_| "retype::pool_latency: pin the worker failed")?;
    thread_start(worker.th).map_err(|_| "retype::pool_latency: start the worker failed")?;

    let deadline = crate::scaled_bound(LAT_CALL_DEADLINE_US);
    let begun = crate::elapsed_us();
    while !LAT_READY.load(Ordering::Acquire)
    {
        if crate::elapsed_us().saturating_sub(begun) > deadline
        {
            return Err("retype::pool_latency: the worker never reported ready");
        }
        thread_yield().ok();
    }
    // A probe the worker's CPU could acknowledge between two of its syscalls,
    // just before or just after the call, is not counted against the call.
    let margin = 8 * LAT_GAP_US.load(Ordering::Relaxed) + 10;

    let mut max_wait = 0u64;
    let mut first_after_start = u64::MAX;
    let mut probe = || -> TestResult {
        // SAFETY: `PROBE_VA` is a scratch VA (crate docs § Scratch VAs), so
        // the page holds no Rust object or IPC page of ktest.
        unsafe { mem_map(frame, ctx.aspace_cap, PROBE_VA, 0, 1, MAP_WRITABLE) }
            .map_err(|_| "retype::pool_latency: probe map failed")?;
        let t0 = crate::elapsed_us();
        // SAFETY: as for the map.
        let unmapped = unsafe { mem_unmap(ctx.aspace_cap, PROBE_VA, 1) };
        let t1 = crate::elapsed_us();
        unmapped.map_err(|_| "retype::pool_latency: probe unmap failed")?;
        let start = LAT_START.load(Ordering::Acquire);
        if start != 0 && t1 >= start
        {
            max_wait = max_wait.max(t1 - t0);
        }
        if start != 0 && t0 >= start + margin
        {
            first_after_start = first_after_start.min(t1);
        }
        Ok(())
    };
    LAT_GO.store(true, Ordering::Release);
    let probed = loop
    {
        if LAT_END.load(Ordering::Acquire) != 0
        {
            break Ok(());
        }
        if let Err(e) = probe()
        {
            break Err(e);
        }
        if crate::elapsed_us().saturating_sub(begun) > deadline
        {
            break Err("retype::pool_latency: the measured call outlived its deadline");
        }
    };
    let exited = crate::spawn::wait_until_exited(worker.th, crate::scaled_polls(60_000));
    worker.delete_thread().ok();
    probed?;
    exited?;

    let (start, end) = (
        LAT_START.load(Ordering::Acquire),
        LAT_END.load(Ordering::Acquire),
    );
    Ok(Measured {
        span_us: end.saturating_sub(start),
        max_wait_us: max_wait,
        acked_inside: first_after_start.saturating_add(margin) <= end,
        result: LAT_RESULT.load(Ordering::Relaxed),
    })
}

/// Log `m`, the measure of `call` (a log line naming it), and check it against
/// the bounds.
fn check_measured(call: &'static str, m: &Measured) -> TestResult
{
    crate::log(call);
    crate::log_u64("ktest: pool_latency span_us=", m.span_us);
    crate::log_u64("ktest: pool_latency max_probe_wait_us=", m.max_wait_us);
    crate::log_u64(
        "ktest: pool_latency acked_inside=",
        u64::from(m.acked_inside),
    );
    if m.max_wait_us > crate::scaled_bound(LATENCY_BOUND_US)
    {
        return Err("retype::pool_latency: a probe waited past LATENCY_BOUND_US for the call");
    }
    if !m.acked_inside
    {
        return Err("retype::pool_latency: no probe was acknowledged while the call ran");
    }
    Ok(())
}

/// Whether the guest has the two CPUs the cases pin to; logs the skip.
fn latency_cpus_present() -> bool
{
    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    if cpus <= u64::from(WORKER_CPU)
    {
        crate::log("ktest: pool_latency SKIP (need 2+ CPUs)");
        return false;
    }
    true
}

/// Split `LAT_SOURCE_PAGES` pages off the top of `memory_base`, after checking
/// that it has them available.
fn split_latency_source(ctx: &TestContext) -> Result<u64, &'static str>
{
    const PAGE: u64 = syscall_abi::PAGE_SIZE;
    let need = LAT_SOURCE_PAGES * PAGE;
    let available = cap_info(ctx.memory_base, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::pool_latency: cap_info(memory_base available) failed")?;
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "retype::pool_latency: cap_info(memory_base size) failed")?;
    crate::log_u64(
        "ktest: pool_latency memory_base_available_pages=",
        available / PAGE,
    );
    crate::log_u64("ktest: pool_latency source_pages=", LAT_SOURCE_PAGES);
    if available < need
    {
        return Err("retype::pool_latency: memory_base has fewer pages available than the source");
    }
    memory_split(ctx.memory_base, size - need)
        .map_err(|_| "retype::pool_latency: memory_split(memory_base) failed")
}

/// Merge `source` back into `memory_base` once every page has returned to it.
fn merge_latency_source(ctx: &TestContext, source: u64) -> TestResult
{
    let available = cap_info(source, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "retype::pool_latency: cap_info(source) failed")?;
    if available != LAT_SOURCE_PAGES * syscall_abi::PAGE_SIZE
    {
        return Err("retype::pool_latency: a page did not return to the source");
    }
    memory_merge(ctx.memory_base, source)
        .map_err(|_| "retype::pool_latency: memory_merge(memory_base, source) failed")
}

/// The caps a teardown case holds, deleted on drop if still held.
struct TeardownFixture
{
    holes: u64,
    kept: u64,
    target: u64,
}

impl Drop for TeardownFixture
{
    fn drop(&mut self)
    {
        for cap in [self.target, self.holes, self.kept]
        {
            if cap != 0
            {
                cap_delete(cap).ok();
            }
        }
    }
}

/// Build the teardown fixture on `source`: `LAT_HOLES` pairs of one-page
/// donations, one to `holes` and one to `kept`, then `LAT_DONATIONS` one-page
/// donations to the target, a `CSpace` or (`aspace`) an address space created
/// from `memory_base`, and a guard donation to `kept`; then delete `holes`,
/// which leaves its pages free below the target's.
fn build_teardown_fixture(
    ctx: &TestContext,
    source: u64,
    aspace: bool,
    fixture: &mut TeardownFixture,
) -> TestResult
{
    let memory = ctx.memory_base;
    fixture.holes =
        cap_create_cspace(memory, 0, 1).map_err(|_| "retype::pool_latency: create holes failed")?;
    fixture.kept =
        cap_create_cspace(memory, 0, 1).map_err(|_| "retype::pool_latency: create kept failed")?;
    for _ in 0..LAT_HOLES
    {
        cap_create_cspace(source, fixture.holes, 1)
            .and_then(|_| cap_create_cspace(source, fixture.kept, 1))
            .map_err(|_| "retype::pool_latency: a hole or neighbour donation failed")?;
    }
    fixture.target = if aspace
    {
        cap_create_aspace(memory, 0, 2)
    }
    else
    {
        cap_create_cspace(memory, 0, 1)
    }
    .map_err(|_| "retype::pool_latency: create the target failed")?;
    for _ in 0..LAT_DONATIONS
    {
        if aspace
        {
            cap_create_aspace(source, fixture.target, 1)
        }
        else
        {
            cap_create_cspace(source, fixture.target, 1)
        }
        .map_err(|_| "retype::pool_latency: a donation to the target failed")?;
    }
    cap_create_cspace(source, fixture.kept, 1)
        .map_err(|_| "retype::pool_latency: the guard donation failed")?;
    let holes = core::mem::take(&mut fixture.holes);
    cap_delete(holes).map_err(|_| "retype::pool_latency: delete holes failed")
}

/// Delete a target carrying `LAT_DONATIONS` one-page donations above
/// `LAT_HOLES` free one-page holes of their Memory object, on a worker CPU,
/// while probing that CPU with TLB shootdowns.
fn teardown_case(ctx: &TestContext, aspace: bool, call: &'static str) -> TestResult
{
    if !latency_cpus_present()
    {
        return Ok(());
    }
    let source = split_latency_source(ctx)?;
    let scratch = ScratchFrame::alloc();
    let measured = scratch.as_ref().map_err(|e| *e).and_then(|frame| {
        let mut fixture = TeardownFixture {
            holes: 0,
            kept: 0,
            target: 0,
        };
        build_teardown_fixture(ctx, source, aspace, &mut fixture)?;
        let target = core::mem::take(&mut fixture.target);
        let measured = measure_call(ctx, frame.0, LAT_OP_DELETE, target, 0);
        if measured.as_ref().is_ok_and(|m| m.result != 0)
        {
            fixture.target = target;
            return Err("retype::pool_latency: the worker's delete of the target failed");
        }
        measured
    });
    if let Ok(frame) = scratch
    {
        // SAFETY: every probe map was undone by its unmap, or failed.
        unsafe { frame.release() };
    }
    let merged = merge_latency_source(ctx, source);
    check_measured(call, &measured?)?;
    merged
}

/// Deleting a `CSpace` that carries ten thousand one-page donations, above a
/// free list of `LAT_HOLES` holes in their Memory object, takes interrupts
/// throughout.
pub fn cspace_teardown_takes_interrupts(ctx: &TestContext) -> TestResult
{
    teardown_case(ctx, false, "ktest: pool_latency call=cspace_delete")
}

/// As [`cspace_teardown_takes_interrupts`], for an address space.
pub fn aspace_teardown_takes_interrupts(ctx: &TestContext) -> TestResult
{
    teardown_case(ctx, true, "ktest: pool_latency call=aspace_delete")
}

/// Creating a `CSpace`, then an address space, whose one donation seeds the
/// whole latency source takes interrupts throughout.
pub fn pool_seeding_takes_interrupts(ctx: &TestContext) -> TestResult
{
    const CALLS: [(u64, &str); 2] = [
        (
            LAT_OP_CREATE_CSPACE,
            "ktest: pool_latency call=cspace_create",
        ),
        (
            LAT_OP_CREATE_ASPACE,
            "ktest: pool_latency call=aspace_create",
        ),
    ];
    if !latency_cpus_present()
    {
        return Ok(());
    }
    let source = split_latency_source(ctx)?;
    let scratch = ScratchFrame::alloc();
    let measured = scratch.as_ref().map_err(|e| *e).and_then(|frame| {
        let mut all = [const { None }; CALLS.len()];
        for (slot, &(op, _)) in all.iter_mut().zip(&CALLS)
        {
            let m = measure_call(ctx, frame.0, op, source, LAT_SOURCE_PAGES)?;
            if m.result == u64::MAX
            {
                return Err("retype::pool_latency: the worker's create failed");
            }
            cap_delete(m.result)
                .map_err(|_| "retype::pool_latency: delete the seeded pool failed")?;
            *slot = Some(m);
        }
        Ok(all)
    });
    if let Ok(frame) = scratch
    {
        // SAFETY: every probe map was undone by its unmap, or failed.
        unsafe { frame.release() };
    }
    let merged = merge_latency_source(ctx, source);
    for (m, &(_, call)) in measured?.iter().zip(&CALLS)
    {
        if let Some(m) = m
        {
            check_measured(call, m)?;
        }
    }
    merged
}
