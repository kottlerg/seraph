// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Gregory Kottler <me@gregorykottler.com>

// ktest/src/integration/tlb_coherency.rs

//! Integration: TLB coherency across CPUs (Phase E).
//!
//! Exercises the TLB shootdown protocol by creating threads pinned to different
//! CPUs and performing map/unmap operations that trigger inter-processor
//! interrupts (IPIs) for TLB invalidation. A second phase repeats the cycles
//! with `mem_unmap_reclaim` (the `MEM_UNMAP_RECLAIM_PTS` path), which frees the
//! now-empty intermediate page table back to the AS pool and issues one coarse
//! full-flush shootdown *while holding `pt_lock`* — a distinct path from the
//! per-VA shootdown above.
//!
//! ktest threads run in user mode, so a stale-TLB access the shootdown failed
//! to flush would surface as a page fault. The kernel retries only faults the
//! live tables already satisfy; an access to an entry that should have been
//! invalidated terminates the thread (the kill path is covered by
//! `integration::fault_kills_thread`). This test does not construct such a
//! window — it verifies that:
//!
//! 1. Repeated map/unmap cycles across CPUs complete without deadlock — for
//!    both the per-VA and the coarse pool-reclaiming shootdown paths.
//! 2. Threads on different CPUs read back the sentinel from newly mapped
//!    memory, including after a same-VA remap whose intermediate page table was
//!    reclaimed and re-allocated from the pool.
//! 3. The shootdown protocol doesn't panic or corrupt kernel state.
//!
//! This validates Phase E.4's TLB shootdown IPI mechanism indirectly by
//! confirming the protocol operates correctly under concurrent access.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, mem_map, mem_unmap, mem_unmap_reclaim,
    notification_send, notification_wait, system_info, thread_exit,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult};

const TEST_VA: u64 = 0x5000_0000; // 1.25 GiB — distinct from other integration tests.
const RIGHTS_NOTIFY_WAIT: u64 = (1 << 7) | (1 << 8);
const CYCLES: usize = 100;
/// Value the parent writes into the mapped frame each cycle; the child reads it
/// back to confirm the translation resolves to the right frame.
const SENTINEL: u64 = 0xA5A5_5A5A_DEAD_BEEF;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child's c2p (child-to-parent) notification slot, written by parent before `thread_start`.
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
    let memory_cap =
        crate::frame_pool::alloc().ok_or("integration::tlb_coherency: frame pool exhausted")?;

    // ── 2. Set up two notifications for parent-child coordination. ─────────────────
    //
    // Fix B1: use separate notifications for each direction to prevent bit
    // accumulation across directions (parent→child vs child→parent).
    let p2c = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::tlb_coherency: cap_create_notification (p2c) failed")?;
    let c2p = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::tlb_coherency: cap_create_notification (c2p) failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::tlb_coherency: spawn::new_child failed")?;

    // Copy both notifications into child's cspace.
    let child_p2c = cap_copy(p2c, child.cs, RIGHTS_NOTIFY_WAIT)
        .map_err(|_| "integration::tlb_coherency: cap_copy (p2c) failed")?;
    let child_c2p = cap_copy(c2p, child.cs, RIGHTS_NOTIFY_WAIT)
        .map_err(|_| "integration::tlb_coherency: cap_copy (c2p) failed")?;

    // Pass child's c2p slot via static (thread_configure only has one arg).
    // SAFETY: single-threaded at this point; child not started yet.
    unsafe { CHILD_C2P_SLOT = child_c2p };

    // ── 3. Configure + pin child to CPU 1, then start. ──────────────────────
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start_pinned(
        &child,
        tlb_worker_thread,
        stack_top,
        u64::from(child_p2c), // arg = p2c slot; c2p slot read from static
        1,
    )
    .map_err(|_| "integration::tlb_coherency: configure_and_start_pinned failed")?;

    // Wait for child to signal readiness on c2p.
    let ready = notification_wait(c2p)
        .map_err(|_| "integration::tlb_coherency: notification_wait (readiness) failed")?;
    if ready != 0x1
    {
        return Err("integration::tlb_coherency: child sent wrong readiness bits");
    }

    // ── 4. Map/access/unmap cycles to exercise TLB shootdown. ────────────────
    //
    // Each cycle:
    //   a. Map page at TEST_VA and write SENTINEL into it.
    //   b. Notify child on p2c that the page is mapped (0x2).
    //   c. Wait for child to confirm it read SENTINEL back on c2p (0x4); a
    //      stale translation resolving to the wrong frame acks 0x10.
    //   d. Unmap the page (triggers a TLB shootdown IPI to CPU 1).
    //
    // Phase 0 uses per-page `mem_unmap` (single-VA shootdown). Phase 1 uses
    // `mem_unmap_reclaim` (the MEM_UNMAP_RECLAIM_PTS path): it frees the
    // now-empty intermediate page table back to the AS pool and issues one
    // coarse full-flush shootdown *while holding pt_lock*. The next cycle
    // remaps the same VA, re-allocating an intermediate table (often the same
    // frame) from the pool. A broken shootdown would panic, deadlock, fault the
    // child, or read the wrong frame.
    for phase in 0..2u32
    {
        let reclaim = phase == 1;
        for cycle in 0..CYCLES
        {
            mem_map(
                memory_cap,
                ctx.aspace_cap,
                TEST_VA,
                0,
                1,
                syscall::MAP_WRITABLE,
            )
            .map_err(|_| "integration::tlb_coherency: mem_map failed")?;

            // Stamp the freshly mapped frame so the child can validate the
            // translation by value.
            // SAFETY: TEST_VA is mapped writable on this CPU by the map above.
            unsafe { (TEST_VA as *mut u64).write_volatile(SENTINEL) };

            notification_send(p2c, 0x2)
                .map_err(|_| "integration::tlb_coherency: notification_send (map) failed")?;

            let ack = notification_wait(c2p)
                .map_err(|_| "integration::tlb_coherency: notification_wait (ack) failed")?;
            if ack == 0x10
            {
                return Err(
                    "integration::tlb_coherency: child read wrong frame (stale translation)",
                );
            }
            if ack != 0x4
            {
                return Err("integration::tlb_coherency: child sent wrong ack bits");
            }

            // Unmap. Phase 1 also reclaims the now-empty intermediate PT.
            if reclaim
            {
                mem_unmap_reclaim(ctx.aspace_cap, TEST_VA, 1)
                    .map_err(|_| "integration::tlb_coherency: mem_unmap_reclaim failed")?;
            }
            else
            {
                mem_unmap(ctx.aspace_cap, TEST_VA, 1)
                    .map_err(|_| "integration::tlb_coherency: mem_unmap failed")?;
            }

            if cycle % 25 == 0
            {
                crate::log_u64("ktest: integration::tlb_coherency: cycle ", cycle as u64);
            }
        }
    }

    // ── 5. Notification child to exit on p2c. ──────────────────────────────────────
    notification_send(p2c, 0x80)
        .map_err(|_| "integration::tlb_coherency: notification_send (exit) failed")?;

    // ── 6. Clean up. ─────────────────────────────────────────────────────────
    cap_delete(child.th).map_err(|_| "integration::tlb_coherency: cap_delete (th) failed")?;
    cap_delete(child.cs).map_err(|_| "integration::tlb_coherency: cap_delete (cs) failed")?;
    cap_delete(p2c).map_err(|_| "integration::tlb_coherency: cap_delete (p2c) failed")?;
    cap_delete(c2p).map_err(|_| "integration::tlb_coherency: cap_delete (c2p) failed")?;

    // Return frame to pool.
    // SAFETY: We've unmapped all pages using this frame in the loop above.
    unsafe { crate::frame_pool::free(memory_cap) };

    Ok(())
}

/// Child thread entry point.
///
/// Runs on CPU 1. Waits for parent to map pages, accesses them to cache TLB
/// entries, then waits for parent to unmap (which triggers TLB shootdown).
///
/// # Arguments
///
/// * `p2c_slot` — parent-to-child Notification capability slot.
// cast_possible_truncation: p2c_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn tlb_worker_thread(p2c_slot: u64) -> !
{
    let p2c = p2c_slot as u32;
    // SAFETY: parent wrote CHILD_C2P_SLOT before thread_start; no concurrent writes.
    let c2p = unsafe { CHILD_C2P_SLOT };

    // Notification parent on c2p: we're ready.
    notification_send(c2p, 0x1).ok();

    while let Ok(bits) = notification_wait(p2c)
    {
        if bits & 0x80 != 0
        {
            // Exit notification received.
            break;
        }

        if bits & 0x2 != 0
        {
            // Page is mapped and stamped with SENTINEL. Read it back to load
            // the TLB entry and validate the translation by value.
            //
            // SAFETY: Parent maps + writes TEST_VA before notifying 0x2. The
            // parent's prior-cycle unmap (or reclaiming unmap) shot down this
            // hart's entry, so the read sees the fresh mapping; a broken
            // shootdown would instead fault here (terminating this thread) or,
            // if it resolved to a stale frame, read a non-SENTINEL value.
            let value = unsafe { (TEST_VA as *const u64).read_volatile() };

            // Ack match (0x4) or wrong-frame (0x10).
            let ack = if value == SENTINEL { 0x4 } else { 0x10 };
            notification_send(c2p, ack).ok();
        }
    }

    thread_exit()
}
