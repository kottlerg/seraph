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
    frames: [Option<u32>; 2],
    queues: [Option<u32>; 2],
    aspace: Option<u32>,
    cspace: Option<u32>,
    thread: Option<u32>,
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
fn available(frame: u32) -> Result<u64, &'static str>
{
    cap_info(frame, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "death_observer_outlives_queue_caps: cap_info(MEMORY_AVAILABLE) failed")
}

/// Whether every frame in `frames` reports exactly the matching `expected`
/// available byte count.
fn frames_at(frames: [u32; 2], expected: [u64; 2]) -> Result<bool, &'static str>
{
    Ok(available(frames[0])? == expected[0] && available(frames[1])? == expected[1])
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
    let mut frames = [0u32; 2];
    let mut empty = [0u64; 2];
    let mut occupied = [0u64; 2];
    let mut queues = [0u32; 2];
    for i in 0..2
    {
        frames[i] = crate::frame_pool::alloc()
            .ok_or("death_observer_outlives_queue_caps: frame pool exhausted")?;
        parts.frames[i] = Some(frames[i]);
        empty[i] = available(frames[i])?;
        queues[i] = event_queue_create_observed(frames[i], CAPACITY, 1)
            .map_err(|_| "death_observer_outlives_queue_caps: event_queue_create failed")?;
        parts.queues[i] = Some(queues[i]);
        occupied[i] = available(frames[i])?;
        if occupied[i] >= empty[i]
        {
            return Err("death_observer_outlives_queue_caps: queue took no frame bytes");
        }
    }

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
