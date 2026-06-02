// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress: many concurrent producers on one event queue.
//!
//! Existing `stress/event_queue_fill_drain.rs` is single-threaded
//! (one fill, one drain). This test runs multiple producer threads
//! posting concurrently to one queue; the parent (single consumer)
//! drains all messages and verifies every producer's full sequence
//! arrived exactly once. Exercises the event-queue post-side spinlock
//! under contention.
//!
//! Payload encoding: each producer claims a distinct 4-bit "producer id"
//! and posts an 8-bit sequence number. The parent reconstructs the per-
//! producer set and asserts each set is `0..MESSAGES_PER_PRODUCER`.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, event_post, event_queue_create, event_recv,
    notification_send, notification_wait, thread_exit,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// One producer per stress stack — capped at `MAX_STRESS_THREADS`.
const NUM_PRODUCERS: usize = 4;
/// Messages per producer.
const MESSAGES_PER_PRODUCER: u32 = 64;
/// Total messages across all producers.
#[allow(clippy::cast_possible_truncation)]
const TOTAL_MESSAGES: u32 = NUM_PRODUCERS as u32 * MESSAGES_PER_PRODUCER;

/// NOTIFY right (send) only.
const RIGHTS_NOTIFY: u64 = 1 << 7;
/// `EventQueue` POST right (bit 9 per the kernel).
const RIGHTS_POST: u64 = 1 << 9;

/// Producer: post `MESSAGES_PER_PRODUCER` messages each tagged with its
/// producer id, then post done bit.
///
/// `arg`: bits[15:0] = queue slot, bits[31:16] = done slot,
///        bits[47:32] = producer id.
// cast_possible_truncation: slot indices are < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn producer_entry(arg: u64) -> !
{
    let queue_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let producer_id = (arg >> 32) & 0xFFFF;

    for seq in 0..u64::from(MESSAGES_PER_PRODUCER)
    {
        // Pack: bits[3:0] = producer_id, bits[11:4] = seq.
        let payload = producer_id | (seq << 4);
        if event_post(queue_slot, payload).is_err()
        {
            break;
        }
    }
    notification_send(done_slot, 1u64 << producer_id).ok();
    thread_exit()
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_base, TOTAL_MESSAGES)
        .map_err(|_| "concurrent_event_producers: event_queue_create failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "concurrent_event_producers: cap_create_notification failed")?;

    let mut threads = [0u32; NUM_PRODUCERS];
    let mut cspaces = [0u32; NUM_PRODUCERS];

    for i in 0..NUM_PRODUCERS
    {
        let child = spawn::new_child(ctx)
            .map_err(|_| "concurrent_event_producers: spawn::new_child failed")?;
        let child_eq = cap_copy(eq, child.cs, RIGHTS_POST)
            .map_err(|_| "concurrent_event_producers: cap_copy queue failed")?;
        let child_done = cap_copy(done, child.cs, RIGHTS_NOTIFY)
            .map_err(|_| "concurrent_event_producers: cap_copy done failed")?;
        let arg = u64::from(child_eq) | (u64::from(child_done) << 16) | ((i as u64) << 32);

        // SAFETY: stress tests run sequentially; each producer gets its own stack.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, producer_entry, stack_top, arg)
            .map_err(|_| "concurrent_event_producers: configure_and_start failed")?;

        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Consumer: drain TOTAL_MESSAGES messages and bucket by producer id.
    let mut per_producer = [[false; MESSAGES_PER_PRODUCER as usize]; NUM_PRODUCERS];
    for _ in 0..TOTAL_MESSAGES
    {
        let payload =
            event_recv(eq).map_err(|_| "concurrent_event_producers: event_recv failed")?;
        // cast_possible_truncation: low nibbles are bounded by NUM_PRODUCERS
        // and MESSAGES_PER_PRODUCER which both fit in usize easily.
        #[allow(clippy::cast_possible_truncation)]
        let producer_id = (payload & 0xF) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let seq = ((payload >> 4) & 0xFF) as usize;
        if producer_id >= NUM_PRODUCERS
        {
            return Err("concurrent_event_producers: producer id out of range");
        }
        if seq >= MESSAGES_PER_PRODUCER as usize
        {
            return Err("concurrent_event_producers: seq out of range");
        }
        if per_producer[producer_id][seq]
        {
            return Err("concurrent_event_producers: duplicate (producer, seq)");
        }
        per_producer[producer_id][seq] = true;
    }

    // Wait for all producers to signal done.
    let all_done = (1u64 << NUM_PRODUCERS) - 1;
    let mut done_bits: u64 = 0;
    while done_bits & all_done != all_done
    {
        done_bits |= notification_wait(done).unwrap_or(0);
    }

    // Verify every producer's full sequence arrived.
    for (p_id, seen) in per_producer.iter().enumerate()
    {
        for (seq, &present) in seen.iter().enumerate()
        {
            if !present
            {
                crate::log_u64("concurrent_event_producers: missing producer=", p_id as u64);
                crate::log_u64("concurrent_event_producers: missing seq=", seq as u64);
                return Err("concurrent_event_producers: missing message");
            }
        }
    }

    for i in 0..NUM_PRODUCERS
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(eq).ok();
    cap_delete(done).ok();
    Ok(())
}
