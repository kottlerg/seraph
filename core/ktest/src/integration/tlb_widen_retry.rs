// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/tlb_widen_retry.rs

//! Integration: a permission-widen that elides its TLB shootdown still lets a
//! remote CPU's stale-TLB write complete via the spurious-fault retry path.
//!
//! Operation-class elision skips the cross-CPU shootdown when a `mem_protect`
//! only *widens* permissions — a stale, narrower remote TLB entry can at worst
//! raise a re-walkable spurious fault. This test drives exactly that window:
//!
//!   1. Parent maps a page read-only at `WIDEN_VA`.
//!   2. A child pinned to CPU 1 reads the page, caching a read-only TLB entry,
//!      then busy-spins — never yielding, so a context switch cannot flush the
//!      entry (the scheduler re-selects the same thread without reloading the
//!      page-table root).
//!   3. Parent widens the page to read-write via `mem_protect`. The widen elides
//!      the remote shootdown, so CPU 1 keeps its stale read-only entry.
//!   4. Child writes the page. On a hardware TLB (KVM / real CPU) the stale
//!      read-only entry raises a store page fault; the kernel re-walks the live
//!      PTE, sees the write is now permitted, flushes locally, and retries — the
//!      store completes and the child is *not* killed.
//!
//! The assertion is on the observable outcome (the store lands, the child stays
//! alive), not that a fault occurred: under QEMU TCG the softmmu re-walks the
//! live page table on the permission-class miss and never raises the fault, so
//! the same assertion holds without exercising the retry. The retry path is
//! physically exercised only under a hardware-TLB backend (x86-64 KVM, real
//! hardware), where a broken spurious-fault classifier kills the child and fails
//! the test. The companion `fault_kills_thread` test covers the genuine-fault
//! kill side.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use syscall::{
    MAP_READ, MAP_WRITABLE, cap_delete, cap_info, mem_map, mem_protect, mem_unmap, system_info,
    thread_sleep,
};
use syscall_abi::{CAP_INFO_THREAD_STATE, SystemInfoType, THREAD_STATE_EXITED};

use crate::{ChildStack, TestContext, TestResult};

/// User-half VA used only by this test (1.375 GiB), clear of other tests.
const WIDEN_VA: u64 = 0x5800_0000;

/// Sentinel the child stores through the widened mapping.
const SENTINEL: u64 = 0xCAFE_F00D;

// Handshake phases. Parent and child advance this in lockstep through shared
// memory; both busy-spin (the child must not yield, or its remote TLB entry is
// flushed by the context switch).
const PHASE_MAPPED: u32 = 1; // parent: page mapped read-only
const PHASE_CACHED: u32 = 2; // child: read the page, TLB entry now cached
const PHASE_WIDENED: u32 = 3; // parent: widened to read-write (shootdown elided)
const PHASE_WROTE: u32 = 4; // child: store completed (retry succeeded)

static PHASE: AtomicU32 = AtomicU32::new(0);
static RESULT: AtomicU64 = AtomicU64::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child busy-spin bound per wait (~1e9 iterations): seconds of headroom over
/// the parent's sub-millisecond handshake, but finite so a dead parent cannot
/// hang the child past harness teardown.
const SPIN_BOUND: u64 = 1_000_000_000;

/// Parent poll bound: at ~1 ms per `thread_sleep(1)`, ~2 s before declaring the
/// child stuck. Comfortably above any scheduling latency on a busy SMP run.
const MAX_POLLS: u32 = 2000;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::tlb_widen_retry: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: integration::tlb_widen_retry SKIP (need 2+ CPUs)");
        return Ok(());
    }

    PHASE.store(0, Ordering::Release);
    RESULT.store(0, Ordering::Release);

    let frame =
        crate::frame_pool::alloc().ok_or("integration::tlb_widen_retry: frame pool exhausted")?;

    // Map the page read-only. MAP_READ forces R-- regardless of the frame cap's
    // rights, so the child caches a narrow entry the widen can later broaden.
    if mem_map(frame, ctx.aspace_cap, WIDEN_VA, 0, 1, MAP_READ).is_err()
    {
        // SAFETY: frame is from the pool and was never mapped.
        unsafe { crate::frame_pool::free(frame) };
        return Err("integration::tlb_widen_retry: mem_map read-only failed");
    }

    let Ok(child) = crate::spawn::new_child(ctx)
    else
    {
        cleanup(ctx, None, frame);
        return Err("integration::tlb_widen_retry: spawn::new_child failed");
    };

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    if crate::spawn::configure_and_start_pinned(&child, widen_child, stack_top, 0, 1).is_err()
    {
        cleanup(ctx, Some(&child), frame);
        return Err("integration::tlb_widen_retry: configure_and_start_pinned failed");
    }

    PHASE.store(PHASE_MAPPED, Ordering::Release);

    // Wait for the child to cache the read-only entry on CPU 1.
    if !parent_wait_phase(PHASE_CACHED, &child)
    {
        cleanup(ctx, Some(&child), frame);
        return Err("integration::tlb_widen_retry: child never cached the mapping");
    }

    // Widen R-- → RW-. Same frame, strictly broader rights ⇒ MapOutcome::Widen ⇒
    // the kernel elides the remote shootdown, leaving CPU 1's stale entry live.
    if mem_protect(frame, ctx.aspace_cap, WIDEN_VA, 1, MAP_READ | MAP_WRITABLE).is_err()
    {
        cleanup(ctx, Some(&child), frame);
        return Err("integration::tlb_widen_retry: mem_protect widen failed");
    }
    PHASE.store(PHASE_WIDENED, Ordering::Release);

    // Wait for the child's store to complete via the retry path — or catch a
    // kill (the child exiting before PHASE_WROTE means the widened write faulted
    // and was mis-classified as genuine).
    let mut polls = 0;
    loop
    {
        if PHASE.load(Ordering::Acquire) >= PHASE_WROTE
        {
            break;
        }
        if child_exited(&child)? && PHASE.load(Ordering::Acquire) < PHASE_WROTE
        {
            cleanup(ctx, Some(&child), frame);
            return Err("integration::tlb_widen_retry: child killed writing widened mapping");
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            cleanup(ctx, Some(&child), frame);
            return Err("integration::tlb_widen_retry: child never completed the write");
        }
        thread_sleep(1).ok();
    }

    if RESULT.load(Ordering::Acquire) != SENTINEL
    {
        cleanup(ctx, Some(&child), frame);
        return Err("integration::tlb_widen_retry: widened write produced the wrong value");
    }

    cleanup(ctx, Some(&child), frame);
    Ok(())
}

/// Spin (no yield) until `PHASE` reaches `target`, polling the child's liveness
/// so a child that died before notifying does not spin to the bound. Returns
/// `false` on timeout or an early child exit.
fn parent_wait_phase(target: u32, child: &crate::spawn::SpawnedChild) -> bool
{
    let mut polls = 0;
    while PHASE.load(Ordering::Acquire) < target
    {
        if child_exited(child).unwrap_or(true) && PHASE.load(Ordering::Acquire) < target
        {
            return false;
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return false;
        }
        thread_sleep(1).ok();
    }
    true
}

/// Whether the child thread has reached the `Exited` state.
fn child_exited(child: &crate::spawn::SpawnedChild) -> Result<bool, &'static str>
{
    let packed = cap_info(child.th, CAP_INFO_THREAD_STATE)
        .map_err(|_| "integration::tlb_widen_retry: cap_info(THREAD_STATE) failed")?;
    // cast_possible_truncation: the kernel packs an 8-bit state code in the high
    // word and a 32-bit exit reason in the low word.
    #[allow(clippy::cast_possible_truncation)]
    let state = (packed >> 32) as u32;
    Ok(state == THREAD_STATE_EXITED)
}

/// Wait for the child to exit cooperatively, then delete its caps, unmap the
/// page, and return the frame to the pool. Safe to call on any error path.
fn cleanup(ctx: &TestContext, child: Option<&crate::spawn::SpawnedChild>, frame: u32)
{
    if let Some(child) = child
    {
        // The child sets PHASE_WROTE then thread_exit()s; wait for Exited so
        // cap_delete never races a still-running pinned thread (which can hang
        // the harness on a CPU with no other ready thread).
        let mut polls = 0;
        while !child_exited(child).unwrap_or(true)
        {
            polls += 1;
            if polls >= MAX_POLLS
            {
                break;
            }
            thread_sleep(1).ok();
        }
        cap_delete(child.th).ok();
        cap_delete(child.cs).ok();
    }
    mem_unmap(ctx.aspace_cap, WIDEN_VA, 1).ok();
    // SAFETY: the page is now unmapped, so the frame is free to return.
    unsafe { crate::frame_pool::free(frame) };
}

/// Child entry: cache a read-only TLB entry, wait for the parent's widen, then
/// store through it. The store completes via the kernel's spurious-fault retry
/// when a hardware TLB faults on the stale read-only entry.
fn widen_child(_arg: u64) -> !
{
    let p = WIDEN_VA as *mut u64;

    if !child_spin_until(PHASE_MAPPED)
    {
        syscall::thread_exit();
    }
    // Read to cache a read-only TLB entry for WIDEN_VA on this CPU.
    // SAFETY: the parent mapped WIDEN_VA read-only before notifying.
    let _ = unsafe { p.read_volatile() };
    PHASE.store(PHASE_CACHED, Ordering::Release);

    if !child_spin_until(PHASE_WIDENED)
    {
        syscall::thread_exit();
    }
    // Store through the now-widened mapping. A stale read-only TLB entry faults;
    // the kernel re-walks the live RW PTE and retries, so the store completes.
    // SAFETY: WIDEN_VA is mapped read-write; any fault is resolved by the kernel.
    unsafe {
        p.write_volatile(SENTINEL);
    }
    // SAFETY: read back the value just written through the same mapping.
    let got = unsafe { p.read_volatile() };
    RESULT.store(got, Ordering::Release);
    PHASE.store(PHASE_WROTE, Ordering::Release);

    syscall::thread_exit()
}

/// Busy-wait (no syscall, so no context switch) until `PHASE` reaches `target`.
/// Returns `false` if the bound is hit first.
fn child_spin_until(target: u32) -> bool
{
    let mut spins = 0u64;
    while PHASE.load(Ordering::Acquire) < target
    {
        core::hint::spin_loop();
        spins += 1;
        if spins >= SPIN_BOUND
        {
            return false;
        }
    }
    true
}
