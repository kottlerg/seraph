// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: concurrent notification send/wait races.
//!
//! `NUM_SENDERS` child threads simultaneously send distinct bit patterns
//! to the same notification. The parent waits for all children to finish, then
//! verifies every bit pattern arrived in the accumulated notification state.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    thread_exit,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_SENDERS: usize = 64;
const SEND_ITERATIONS: u64 = 5000;

/// Each sender ORs its unique bit (`1 << i`) once per iteration. The
/// notification's bit width is 64; one sender per bit saturates the bitmask.
const fn sender_bits() -> [u64; NUM_SENDERS]
{
    let mut bits = [0u64; NUM_SENDERS];
    let mut i = 0;
    while i < NUM_SENDERS
    {
        bits[i] = 1u64 << i;
        i += 1;
    }
    bits
}
const SENDER_BITS: [u64; NUM_SENDERS] = sender_bits();
const ALL_BITS: u64 = u64::MAX;

pub fn run(ctx: &TestContext) -> TestResult
{
    let target = cap_create_notification(ctx.memory_frame_base)
        .map_err(|_| "concurrent_notification: create target failed")?;
    let done = cap_create_notification(ctx.memory_frame_base)
        .map_err(|_| "concurrent_notification: create done failed")?;

    // Spawn `NUM_SENDERS` sender threads.
    let mut threads = [0u32; NUM_SENDERS];
    let mut cspaces = [0u32; NUM_SENDERS];

    for i in 0..NUM_SENDERS
    {
        let child = spawn::new_child(ctx)
            .map_err(|_| "concurrent_notification: spawn::new_child failed")?;
        // Child needs NOTIFY right on target and done.
        let child_target = cap_copy(target, child.cs, 1 << 7)
            .map_err(|_| "concurrent_notification: cap_copy target failed")?;
        let child_done = cap_copy(done, child.cs, 1 << 7)
            .map_err(|_| "concurrent_notification: cap_copy done failed")?;

        // Pack: bits[15:0]=target_slot, bits[31:16]=done_slot, bits[47:32]=bit_index
        let arg = u64::from(child_target) | (u64::from(child_done) << 16) | ((i as u64) << 32);

        // SAFETY: Sequential setup; each child gets a unique stack index.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, sender_entry, stack_top, arg)
            .map_err(|_| "concurrent_notification: configure_and_start failed")?;

        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Wait for all senders to report done. Each child ORs a unique bit into
    // `done`, so we wait until every `NUM_SENDERS` bit is set (one blocking
    // wait suffices since the last child to finish will set the final bit).
    let mut done_bits: u64 = 0;
    while done_bits != ALL_BITS
    {
        let bits = notification_wait(done)
            .map_err(|_| "concurrent_notification: notification_wait done failed")?;
        done_bits |= bits;
    }

    // All children have finished. Collect accumulated bits from target.
    // Children sent non-blocking (notification_send), so bits have been ORed into
    // the target notification. One wait collects everything.
    let accumulated = notification_wait(target)
        .map_err(|_| "concurrent_notification: notification_wait target failed")?;

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
        return Err("concurrent_notification: not all bit patterns received");
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
        notification_send(target_slot, bits).ok();
    }

    // Notification done with this child's unique bit so the parent can track
    // completion of each sender individually.
    notification_send(done_slot, bits).ok();
    thread_exit()
}
