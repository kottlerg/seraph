// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/death_observer_outlives_queue_caps.rs

//! Integration: a death-observer binding keeps its `EventQueue` live after
//! the queue's last capability is deleted, until the observed owner's
//! teardown releases it.
//!
//! Each binding (`SYS_THREAD_BIND_NOTIFICATION`, `SYS_ASPACE_BIND_NOTIFICATION`)
//! holds a reference on its queue (core/kernel/docs/syscalls.md, the two
//! sections' Lifetime paragraphs). Without it, deleting the queue's last cap
//! freed it while the binding still named it, and the death post wrote into
//! freed (possibly retyped) memory.
//!
//! The test retypes each queue from its own single-page frame, so the
//! frame's available bytes show whether the queue is still allocated. It binds
//! queue A as a thread's death observer and queue B as the thread's address
//! space's terminal-fault observer, deletes both queues' caps, and requires
//! both frames still occupied. The thread, in a dedicated address space with
//! an unmapped entry PC, then terminal-faults, which posts to both bindings:
//! the frames must stay occupied (the posts landed in live queues, which the
//! bindings still hold). Deleting the thread and the address space releases
//! the bindings, and both frames must come back whole.

use syscall::{
    aspace_bind_notification, cap_create_aspace, cap_create_cspace, cap_create_thread, cap_delete,
    cap_info, event_queue_create_observed, thread_bind_notification, thread_configure,
    thread_start,
};
use syscall_abi::{CAP_INFO_MEMORY_AVAILABLE, EXIT_FAULT_BASE};

use crate::{TestContext, TestResult};

/// Unmapped user VA used as the doomed thread's entry PC; the first
/// instruction fetch faults. Canonical in every paging mode and distinct
/// from the other fault tests' VAs.
const UNMAPPED_ENTRY: u64 = 0x3E_A000_0000;
/// Unmapped stack pointer, never reached (the entry fetch faults first).
const UNMAPPED_STACK: u64 = 0x3E_A000_8000;

/// Event-queue capacity; small so each queue fits its one-page frame.
const CAPACITY: u32 = 4;

/// Poll bound for the thread's death: about 2 s at 1 ms per poll, applied
/// through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// The objects this test creates; [`Parts::release`] deletes what exists.
#[derive(Default)]
struct Parts
{
    frames: [Option<u64>; 2],
    queues: [Option<u64>; 2],
    aspace: Option<u64>,
    cspace: Option<u64>,
    thread: Option<u64>,
}

impl Parts
{
    fn release(&mut self)
    {
        for cap in [self.thread.take(), self.cspace.take(), self.aspace.take()]
            .into_iter()
            .chain(self.queues.iter_mut().map(Option::take))
            .flatten()
        {
            cap_delete(cap).ok();
        }
        for frame in self.frames.iter_mut().filter_map(Option::take)
        {
            // SAFETY: the frame came from frame_pool::alloc and was never
            // mapped; its only object, an event queue, is deleted above.
            unsafe { crate::frame_pool::free(frame) };
        }
    }
}

/// Available bytes of the Memory cap `frame`.
fn available(frame: u64) -> Result<u64, &'static str>
{
    cap_info(frame, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "death_observer_outlives_queue_caps: cap_info(MEMORY_AVAILABLE) failed")
}

/// Whether every frame in `frames` reports exactly the matching `expected`
/// available byte count.
fn frames_at(frames: [u64; 2], expected: [u64; 2]) -> Result<bool, &'static str>
{
    Ok(available(frames[0])? == expected[0] && available(frames[1])? == expected[1])
}

/// Take a frame from the pool into `frame_slot`, create an observed event
/// queue in it into `queue_slot`, and return the frame, its available bytes
/// before the queue, the queue, and the frame's available bytes after it.
fn create_queue(
    frame_slot: &mut Option<u64>,
    queue_slot: &mut Option<u64>,
) -> Result<(u64, u64, u64, u64), &'static str>
{
    let frame = crate::frame_pool::alloc()
        .ok_or("death_observer_outlives_queue_caps: frame pool exhausted")?;
    *frame_slot = Some(frame);
    let empty = available(frame)?;
    let queue = event_queue_create_observed(frame, CAPACITY, 1)
        .map_err(|_| "death_observer_outlives_queue_caps: event_queue_create failed")?;
    *queue_slot = Some(queue);
    let occupied = available(frame)?;
    if occupied >= empty
    {
        return Err("death_observer_outlives_queue_caps: queue took no frame bytes");
    }
    Ok((frame, empty, queue, occupied))
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = run_with(ctx, &mut parts);
    parts.release();
    result
}

fn run_with(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let [frame_slot0, frame_slot1] = &mut parts.frames;
    let [queue_slot0, queue_slot1] = &mut parts.queues;
    let made = [
        create_queue(frame_slot0, queue_slot0)?,
        create_queue(frame_slot1, queue_slot1)?,
    ];
    let frames = made.map(|m| m.0);
    let empty = made.map(|m| m.1);
    let queues = made.map(|m| m.2);
    let occupied = made.map(|m| m.3);

    let aspace = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "death_observer_outlives_queue_caps: cap_create_aspace failed")?;
    parts.aspace = Some(aspace);
    let cspace = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "death_observer_outlives_queue_caps: cap_create_cspace failed")?;
    parts.cspace = Some(cspace);
    let thread = cap_create_thread(ctx.memory_base, aspace, cspace, 0, 0)
        .map_err(|_| "death_observer_outlives_queue_caps: cap_create_thread failed")?;
    parts.thread = Some(thread);

    thread_bind_notification(thread, queues[0], 0x5390)
        .map_err(|_| "death_observer_outlives_queue_caps: thread_bind_notification failed")?;
    aspace_bind_notification(aspace, queues[1], 0x5391)
        .map_err(|_| "death_observer_outlives_queue_caps: aspace_bind_notification failed")?;

    // Delete the last capability to each queue: the bindings must keep both.
    for slot in &mut parts.queues
    {
        if let Some(cap) = slot.take()
        {
            cap_delete(cap)
                .map_err(|_| "death_observer_outlives_queue_caps: cap_delete(queue) failed")?;
        }
    }
    if !frames_at(frames, occupied)?
    {
        return Err("death_observer_outlives_queue_caps: queue freed while still bound");
    }

    // SAFETY: the thread is bound to the dedicated `aspace` created above, not
    // ktest's own, so its entry state touches nothing ktest runs on.
    unsafe { thread_configure(thread, UNMAPPED_ENTRY, UNMAPPED_STACK, 0) }
        .map_err(|_| "death_observer_outlives_queue_caps: thread_configure failed")?;
    thread_start(thread).map_err(|_| "death_observer_outlives_queue_caps: thread_start failed")?;
    let reason = crate::spawn::wait_until_exited(thread, crate::scaled_polls(MAX_POLLS))?;
    if reason < EXIT_FAULT_BASE
    {
        return Err("death_observer_outlives_queue_caps: thread did not terminal-fault");
    }
    if !frames_at(frames, occupied)?
    {
        return Err("death_observer_outlives_queue_caps: queue freed before its owner's teardown");
    }

    // The owners' teardowns release the bindings, freeing both queues.
    for cap in [
        parts.thread.take(),
        parts.cspace.take(),
        parts.aspace.take(),
    ]
    .into_iter()
    .flatten()
    {
        cap_delete(cap).map_err(|_| "death_observer_outlives_queue_caps: owner delete failed")?;
    }
    if !frames_at(frames, empty)?
    {
        return Err("death_observer_outlives_queue_caps: owner teardown left a queue allocated");
    }
    Ok(())
}
