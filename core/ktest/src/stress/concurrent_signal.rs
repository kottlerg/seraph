// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: concurrent signal send/wait races.
//!
//! 4 child threads simultaneously send distinct bit patterns to the same signal.
//! The parent waits for all children to finish, then verifies all bit patterns
//! arrived in the accumulated signal state.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, thread_configure, thread_exit, thread_start,
};

use crate::{ChildStack, TestContext, TestResult};

const NUM_SENDERS: usize = 16;
const SEND_ITERATIONS: u64 = 2000;

/// Each sender ORs its unique bit once per iteration.
const SENDER_BITS: [u64; NUM_SENDERS] = [
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000,
    0x8000,
];
const ALL_BITS: u64 = 0xFFFF;

pub fn run(ctx: &TestContext) -> TestResult
{
    let target = cap_create_signal().map_err(|_| "concurrent_signal: create target failed")?;
    let done = cap_create_signal().map_err(|_| "concurrent_signal: create done failed")?;

    // Spawn 4 sender threads.
    let mut threads = [0u32; NUM_SENDERS];
    let mut cspaces = [0u32; NUM_SENDERS];

    for i in 0..NUM_SENDERS
    {
        let cs = cap_create_cspace(16).map_err(|_| "concurrent_signal: create_cspace failed")?;
        // Child needs SIGNAL right on target and done.
        let child_target = cap_copy(target, cs, 1 << 7)
            .map_err(|_| "concurrent_signal: cap_copy target failed")?;
        let child_done =
            cap_copy(done, cs, 1 << 7).map_err(|_| "concurrent_signal: cap_copy done failed")?;

        let th = cap_create_thread(ctx.aspace_cap, cs)
            .map_err(|_| "concurrent_signal: create_thread failed")?;

        // Pack: bits[15:0]=target_slot, bits[31:16]=done_slot, bits[47:32]=bit_index
        let arg = u64::from(child_target) | (u64::from(child_done) << 16) | ((i as u64) << 32);

        // SAFETY: Sequential setup; each child gets a unique stack index.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        thread_configure(th, sender_entry as *const () as u64, stack_top, arg)
            .map_err(|_| "concurrent_signal: thread_configure failed")?;
        thread_start(th).map_err(|_| "concurrent_signal: thread_start failed")?;

        threads[i] = th;
        cspaces[i] = cs;
    }

    // Wait for all senders to report done. Each child ORs a unique bit into
    // `done`, so we wait until all 4 bits are set (one blocking wait suffices
    // since the last child to finish will set the final bit).
    let mut done_bits: u64 = 0;
    while done_bits != ALL_BITS
    {
        let bits = signal_wait(done).map_err(|_| "concurrent_signal: signal_wait done failed")?;
        done_bits |= bits;
    }

    // All children have finished. Collect accumulated bits from target.
    // Children sent non-blocking (signal_send), so bits have been ORed into
    // the target signal. One wait collects everything.
    let accumulated =
        signal_wait(target).map_err(|_| "concurrent_signal: signal_wait target failed")?;

    // Clean up.
    for i in 0..NUM_SENDERS
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(target).ok();
    cap_delete(done).ok();

    if accumulated & ALL_BITS != ALL_BITS
    {
        return Err("concurrent_signal: not all bit patterns received");
    }
    Ok(())
}

// cast_possible_truncation: slot indices are kernel cap slots < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(arg: u64) -> !
{
    let target_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let bit_index = ((arg >> 32) & 0xFFFF) as usize;

    let bits = SENDER_BITS[bit_index.min(NUM_SENDERS - 1)];

    for _ in 0..SEND_ITERATIONS
    {
        signal_send(target_slot, bits).ok();
    }

    // Signal done with this child's unique bit so the parent can track
    // completion of each sender individually.
    signal_send(done_slot, bits).ok();
    thread_exit()
}
