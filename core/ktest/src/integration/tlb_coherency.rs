// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Gregory Kottler <me@gregorykottler.com>

// ktest/src/integration/tlb_coherency.rs

//! Integration: TLB coherency across CPUs (Phase E).
//!
//! Exercises the TLB shootdown protocol by creating threads pinned to different
//! CPUs and performing map/unmap operations that trigger inter-processor
//! interrupts (IPIs) for TLB invalidation.
//!
//! Since ktest runs without page fault handlers, we cannot directly test that
//! a stale TLB entry causes a fault. Instead, this test verifies that:
//!
//! 1. Repeated map/unmap cycles across CPUs complete without deadlock
//! 2. Threads on different CPUs can safely access newly mapped memory
//! 3. The shootdown protocol doesn't panic or corrupt kernel state
//!
//! This validates Phase E.4's TLB shootdown IPI mechanism indirectly by
//! confirming the protocol operates correctly under concurrent access.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, mem_map,
    mem_unmap, signal_send, signal_wait, system_info, thread_configure, thread_exit, thread_start,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

const TEST_VA: u64 = 0x5000_0000; // 1.25 GiB — distinct from other integration tests.
const RIGHTS_SIGNAL_WAIT: u64 = (1 << 7) | (1 << 8);
const CYCLES: usize = 20;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child's c2p (child-to-parent) signal slot, written by parent before `thread_start`.
static mut CHILD_C2P_SLOT: u32 = 0;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::tlb_coherency: system_info(CpuCount) failed")?;

    if cpus < 2
    {
        crate::log("ktest: integration::tlb_coherency SKIP (need 2+ CPUs)");
        return Ok(());
    }

    // ── 1. Allocate a frame from the pool. ───────────────────────────────────
    let frame_cap =
        crate::frame_pool::alloc().ok_or("integration::tlb_coherency: frame pool exhausted")?;

    // ── 2. Set up two signals for parent-child coordination. ─────────────────
    //
    // Fix B1: use separate signals for each direction to prevent bit
    // accumulation across directions (parent→child vs child→parent).
    let p2c = cap_create_signal()
        .map_err(|_| "integration::tlb_coherency: cap_create_signal (p2c) failed")?;
    let c2p = cap_create_signal()
        .map_err(|_| "integration::tlb_coherency: cap_create_signal (c2p) failed")?;

    let cs = cap_create_cspace(16)
        .map_err(|_| "integration::tlb_coherency: cap_create_cspace failed")?;

    // Copy both signals into child's cspace.
    let child_p2c = cap_copy(p2c, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "integration::tlb_coherency: cap_copy (p2c) failed")?;
    let child_c2p = cap_copy(c2p, cs, RIGHTS_SIGNAL_WAIT)
        .map_err(|_| "integration::tlb_coherency: cap_copy (c2p) failed")?;

    // Pass child's c2p slot via static (thread_configure only has one arg).
    // SAFETY: single-threaded at this point; child not started yet.
    unsafe { CHILD_C2P_SLOT = child_c2p };

    // ── 3. Create a child thread pinned to CPU 1. ────────────────────────────
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "integration::tlb_coherency: cap_create_thread failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(
        th,
        tlb_worker_thread as *const () as u64,
        stack_top,
        u64::from(child_p2c), // arg = p2c slot; c2p slot read from static
    )
    .map_err(|_| "integration::tlb_coherency: thread_configure failed")?;

    // Pin child to CPU 1 (parent runs on CPU 0 by default).
    syscall::thread_set_affinity(th, 1)
        .map_err(|_| "integration::tlb_coherency: thread_set_affinity failed")?;

    thread_start(th).map_err(|_| "integration::tlb_coherency: thread_start failed")?;

    // Wait for child to signal readiness on c2p.
    let ready = signal_wait(c2p)
        .map_err(|_| "integration::tlb_coherency: signal_wait (readiness) failed")?;
    if ready != 0x1
    {
        return Err("integration::tlb_coherency: child sent wrong readiness bits");
    }

    // ── 4. Perform multiple map/unmap cycles to exercise TLB shootdown. ──────
    //
    // Each cycle:
    //   a. Map page at TEST_VA
    //   b. Signal child on p2c that page is mapped (0x2)
    //   c. Wait for child to confirm access on c2p (0x4)
    //   d. Unmap page (triggers TLB shootdown IPI to CPU 1)
    //
    // If TLB shootdown is broken, the kernel would panic or deadlock.

    for cycle in 0..CYCLES
    {
        // Map the page.
        mem_map(
            frame_cap,
            ctx.aspace_cap,
            TEST_VA,
            0,
            1,
            syscall::MAP_WRITABLE,
        )
        .map_err(|_| "integration::tlb_coherency: mem_map failed")?;

        // Signal child on p2c: page is mapped, you may access it.
        signal_send(p2c, 0x2)
            .map_err(|_| "integration::tlb_coherency: signal_send (map) failed")?;

        // Wait for child to confirm access on c2p.
        let ack =
            signal_wait(c2p).map_err(|_| "integration::tlb_coherency: signal_wait (ack) failed")?;
        if ack != 0x4
        {
            return Err("integration::tlb_coherency: child sent wrong ack bits");
        }

        // Unmap the page. This triggers TLB shootdown IPI to CPU 1.
        mem_unmap(ctx.aspace_cap, TEST_VA, 1)
            .map_err(|_| "integration::tlb_coherency: mem_unmap failed")?;

        // Log progress every 5 cycles.
        if cycle % 5 == 0
        {
            crate::log_u64("ktest: integration::tlb_coherency: cycle ", cycle as u64);
        }
    }

    // ── 5. Signal child to exit on p2c. ──────────────────────────────────────
    signal_send(p2c, 0x80).map_err(|_| "integration::tlb_coherency: signal_send (exit) failed")?;

    // ── 6. Clean up. ─────────────────────────────────────────────────────────
    cap_delete(th).map_err(|_| "integration::tlb_coherency: cap_delete (th) failed")?;
    cap_delete(cs).map_err(|_| "integration::tlb_coherency: cap_delete (cs) failed")?;
    cap_delete(p2c).map_err(|_| "integration::tlb_coherency: cap_delete (p2c) failed")?;
    cap_delete(c2p).map_err(|_| "integration::tlb_coherency: cap_delete (c2p) failed")?;

    // Return frame to pool.
    // SAFETY: We've unmapped all pages using this frame in the loop above.
    unsafe { crate::frame_pool::free(frame_cap) };

    Ok(())
}

/// Child thread entry point.
///
/// Runs on CPU 1. Waits for parent to map pages, accesses them to cache TLB
/// entries, then waits for parent to unmap (which triggers TLB shootdown).
///
/// # Arguments
///
/// * `p2c_slot` — parent-to-child Signal capability slot.
// cast_possible_truncation: p2c_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn tlb_worker_thread(p2c_slot: u64) -> !
{
    let p2c = p2c_slot as u32;
    // SAFETY: parent wrote CHILD_C2P_SLOT before thread_start; no concurrent writes.
    let c2p = unsafe { CHILD_C2P_SLOT };

    // Signal parent on c2p: we're ready.
    signal_send(c2p, 0x1).ok();

    while let Ok(bits) = signal_wait(p2c)
    {
        if bits & 0x80 != 0
        {
            // Exit signal received.
            break;
        }

        if bits & 0x2 != 0
        {
            // Page is mapped. Access it (read) to load TLB entry.
            //
            // SAFETY: Parent maps TEST_VA before signaling 0x2. If TLB
            // shootdown is broken, we'd read stale data or fault after
            // unmap, but since ktest has no fault handler, we just trust
            // the kernel correctly invalidated our cached entry.
            let ptr = TEST_VA as *const u64;
            // SAFETY: TEST_VA is mapped by parent; see comment above.
            let _value = unsafe { ptr.read_volatile() };

            // Acknowledge to parent on c2p: we've accessed the page.
            signal_send(c2p, 0x4).ok();
        }
    }

    thread_exit()
}
