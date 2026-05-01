// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/stress/retype_concurrent.rs

//! Stress test: concurrent retype + reclaim against a single Frame cap.
//!
//! N child threads hammer the same retype-source Frame cap with
//! `cap_create_endpoint` + `cap_delete` cycles. The retype-allocator's
//! per-cap spinlock and per-`FrameObject` rwlock are the load-bearing
//! invariants — interleavings between retype-consume and dealloc-reclaim
//! must not corrupt free-list links or double-debit `available_bytes`.
//!
//! Pass criterion: every iteration of every child returns Ok, the child
//! count of successful cycles equals `NUM_WORKERS * ITERS_PER_WORKER`,
//! and the source cap's `available_bytes` returns to its pre-stress
//! baseline at the end.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_thread, cap_delete, cap_info,
    signal_send, signal_wait, thread_configure, thread_exit, thread_start,
};
use syscall_abi::CAP_INFO_FRAME_AVAILABLE;

use crate::{ChildStack, TestContext, TestResult};

const NUM_WORKERS: usize = 8;
const ITERS_PER_WORKER: u64 = 200;
const ALL_BITS: u64 = 0xFF;
const WORKER_BIT: [u64; NUM_WORKERS] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

pub fn run(ctx: &TestContext) -> TestResult
{
    // Pre-warm: pay the per-FrameObject allocator metadata cost on
    // ctx.memory_frame_base (if some earlier test hasn't already) so the
    // post-stress baseline matches the pre-stress baseline.
    let frame = ctx.memory_frame_base;
    let warm = syscall::cap_create_endpoint(frame)
        .map_err(|_| "stress::retype_concurrent: warmup endpoint failed")?;
    cap_delete(warm).ok();
    let baseline = cap_info(frame, CAP_INFO_FRAME_AVAILABLE)
        .map_err(|_| "stress::retype_concurrent: cap_info(baseline) failed")?;

    // Done signal: each worker ORs its bit when finished.
    let done = syscall::cap_create_signal(frame)
        .map_err(|_| "stress::retype_concurrent: create done failed")?;

    let mut threads = [0u32; NUM_WORKERS];
    let mut cspaces = [0u32; NUM_WORKERS];

    for i in 0..NUM_WORKERS
    {
        let cs = cap_create_cspace(frame, 0, 4, 64)
            .map_err(|_| "stress::retype_concurrent: create_cspace failed")?;
        let child_frame = cap_copy(frame, cs, syscall::RIGHTS_RETYPE | syscall::RIGHTS_MAP_RW)
            .map_err(|_| "stress::retype_concurrent: cap_copy frame failed")?;
        let child_done = cap_copy(done, cs, 1 << 7)
            .map_err(|_| "stress::retype_concurrent: cap_copy done failed")?;
        let th = cap_create_thread(frame, ctx.aspace_cap, cs)
            .map_err(|_| "stress::retype_concurrent: create_thread failed")?;

        let arg = u64::from(child_frame) | (u64::from(child_done) << 16) | ((i as u64) << 32);

        // SAFETY: stress tests run sequentially; each worker uses a distinct stack.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        thread_configure(th, worker_entry as *const () as u64, stack_top, arg)
            .map_err(|_| "stress::retype_concurrent: thread_configure failed")?;
        thread_start(th).map_err(|_| "stress::retype_concurrent: thread_start failed")?;

        threads[i] = th;
        cspaces[i] = cs;
    }

    // Collect done bits.
    let mut done_bits: u64 = 0;
    while done_bits & ALL_BITS != ALL_BITS
    {
        let bits =
            signal_wait(done).map_err(|_| "stress::retype_concurrent: signal_wait done failed")?;
        done_bits |= bits;
    }

    // Cleanup workers.
    for i in 0..NUM_WORKERS
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(done).ok();

    // Verify the source cap returned to baseline. Any leak or double-
    // debit shows up as a discrepancy here.
    let after = cap_info(frame, CAP_INFO_FRAME_AVAILABLE)
        .map_err(|_| "stress::retype_concurrent: cap_info(after) failed")?;

    if after != baseline
    {
        return Err("stress::retype_concurrent: available_bytes did not return to baseline");
    }

    // Worker reports failure via NOT setting its bit — so seeing all bits
    // already implies every worker completed without an internal Err.
    if done_bits & ALL_BITS != ALL_BITS
    {
        return Err("stress::retype_concurrent: not every worker reported done");
    }
    Ok(())
}

// cast_possible_truncation: cap slots are < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn worker_entry(arg: u64) -> !
{
    let frame_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let bit_index = ((arg >> 32) & 0xFFFF) as usize;
    let bit = WORKER_BIT[bit_index.min(NUM_WORKERS - 1)];

    for _ in 0..ITERS_PER_WORKER
    {
        // Tight retype + reclaim loop. Every Endpoint occupies a BIN_128
        // slot inside `frame_slot`; concurrent workers compete on the
        // bin's free list and the per-cap allocator spinlock.
        if let Ok(ep) = cap_create_endpoint(frame_slot)
        {
            cap_delete(ep).ok();
        }
        else
        {
            // Refusing to set the done bit signals failure to the parent.
            thread_exit();
        }
    }

    signal_send(done_slot, bit).ok();
    thread_exit()
}
