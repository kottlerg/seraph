// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/thread.rs

//! Thread lifecycle benchmark: create → start → exit → cleanup.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    thread_exit,
};

use super::Harness;
use crate::{ChildStack, spawn};

static mut BENCH_LIFECYCLE_STACK: ChildStack = ChildStack::ZERO;

extern "C" fn lifecycle_entry(done_slot: u64) -> !
{
    notification_send(done_slot, 0x1).ok();
    thread_exit()
}

/// Benchmark: one child thread's whole life, timed from its creation to the
/// deletion of its caps after it exits.
pub(super) fn bench_thread_lifecycle(ctx: &crate::TestContext, h: &mut Harness)
{
    // Use fewer iterations for this heavier benchmark.
    let n = h.iters().min(100);

    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    // SAFETY: `BENCH_LIFECYCLE_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(BENCH_LIFECYCLE_STACK)) };

    let (mut samples, counters) = h.recorder();
    for _ in 0..n
    {
        let t0 = counters.read();

        let Ok(mut child) = spawn::new_child(ctx)
        else
        {
            break;
        };
        let Ok(child_done) = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        else
        {
            break;
        };
        // SAFETY: the stack is `BENCH_LIFECYCLE_STACK`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        if unsafe { spawn::configure_and_start(&child, lifecycle_entry, stack_top, child_done) }
            .is_err()
        {
            break;
        }
        notification_wait(done).ok();
        child.delete_thread().ok();
        child.delete_cspace().ok();

        samples.record(counters.read().since(&t0).cycles);
    }
    let summary = samples.summary();

    cap_delete(done).ok();

    h.report("thread_lifecycle", &[], summary, &[]);
}

// ── Context-switch latency ────────────────────────────────────────────────────

static mut BENCH_CTXSWITCH_STACK: ChildStack = ChildStack::ZERO;
/// Iterations counter for the ping-pong loop, set by the parent before
/// starting the child. Read by the child to drive its yield count.
static BENCH_CTXSWITCH_ITERS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Child entry: ping-pong via `thread_yield` for `BENCH_CTXSWITCH_ITERS`
/// iterations, then send on the `done_slot` notification and exit.
extern "C" fn ctxswitch_child_entry(done_slot: u64) -> !
{
    let n = BENCH_CTXSWITCH_ITERS.load(core::sync::atomic::Ordering::Acquire);
    for _ in 0..n
    {
        let _ = syscall::thread_yield();
    }
    notification_send(done_slot, 0x1).ok();
    thread_exit()
}

/// Benchmark: context-switch latency via parent/child `thread_yield`
/// ping-pong on CPU 0, where the child is pinned and `run_all` pins the
/// parent (ktest's harness thread).
///
/// The yield ping-pong requires the child at the parent's own level
/// (`INIT_PRIORITY`; see `core/kernel/docs/scheduler.md` § Time Slice Policy),
/// so the child is created at that level via the root `SchedControl` band.
/// Skipped when the initial cap set has no `SchedControl` cap.
///
/// Each sample is one parent `thread_yield` call: two switches, parent →
/// child and child → parent, so the benchmark is `context_switch_pair`.
///
/// The extras `tlb_elided` and `tlb_performed` are the tagged-TLB flush
/// counters, the cumulative system-wide elided and performed context-switch
/// activations since boot (see docs/memory-model.md § TLB Management; both are
/// 0 without hardware tagging). The ping-pong shares one address space, so it
/// adds no tagged activation of its own; the totals count every cross-space
/// and post-block re-activation since boot. QEMU TCG does not model
/// TLB-refill timing, so its cycles are no measure of that cost.
pub(super) fn bench_context_switch(ctx: &crate::TestContext, h: &mut Harness)
{
    use crate::spawn;

    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: bench context_switch_pair SKIP (no SchedControl cap)");
        return;
    }

    let n = h.iters();
    BENCH_CTXSWITCH_ITERS.store(u64::from(n), core::sync::atomic::Ordering::Release);

    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        return;
    };
    // PRIORITY_MAX == INIT_PRIORITY: the level this (init-loaded) thread runs at.
    let Ok(mut child) = spawn::new_child_at(ctx, ctx.sched_control_cap, syscall_abi::PRIORITY_MAX)
    else
    {
        return;
    };
    let Ok(child_done) = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
    else
    {
        return;
    };
    // SAFETY: `BENCH_CTXSWITCH_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(BENCH_CTXSWITCH_STACK)) };
    // SAFETY: the stack is `BENCH_CTXSWITCH_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    if unsafe {
        spawn::configure_and_start_pinned(&child, ctxswitch_child_entry, stack_top, child_done, 0)
    }
    .is_err()
    {
        child.delete_thread().ok();
        child.delete_cspace().ok();
        cap_delete(done).ok();
        return;
    }

    let (mut samples, counters) = h.recorder();
    for _ in 0..n
    {
        let t0 = counters.read();
        let _ = syscall::thread_yield();
        samples.record(counters.read().since(&t0).cycles);
    }
    let summary = samples.summary();

    notification_wait(done).ok();
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(done).ok();

    let elided = syscall::cap_info(ctx.memory_base, syscall_abi::CAP_INFO_TLB_ELIDED).unwrap_or(0);
    let performed =
        syscall::cap_info(ctx.memory_base, syscall_abi::CAP_INFO_TLB_PERFORMED).unwrap_or(0);
    h.report(
        "context_switch_pair",
        &[],
        summary,
        &[("tlb_elided", elided), ("tlb_performed", performed)],
    );
}

// ── SYS_THREAD_READ_MEM throughput ────────────────────────────────────────────

/// Pages [`bench_thread_read_mem`] reads, cycled through in order.
const READ_MEM_PAGES: usize = 16;

/// The page-aligned buffer [`bench_thread_read_mem`] reads through a thread
/// of ktest's own address space.
#[repr(C, align(4096))]
struct ReadMemSource([u8; READ_MEM_PAGES * 4096]);

static BENCH_READ_MEM_SOURCE: ReadMemSource = ReadMemSource([0x5A; READ_MEM_PAGES * 4096]);

/// The page-aligned buffer each read copies into.
#[repr(C, align(4096))]
struct ReadMemSink([u8; 4096]);

static mut BENCH_READ_MEM_SINK: ReadMemSink = ReadMemSink([0; 4096]);

/// Benchmark: `SYS_THREAD_READ_MEM` of one whole page (`MAX_THREAD_MEM_COPY`)
/// through a never-started thread of ktest's own address space, cycling over
/// [`READ_MEM_PAGES`] resident pages: the per-page cost a debugger pays to
/// copy a process's memory (docs/fault-handling.md § Debugging).
pub(super) fn bench_thread_read_mem(ctx: &crate::TestContext, h: &mut Harness)
{
    use crate::spawn;

    let Ok(mut child) = spawn::new_child(ctx)
    else
    {
        return;
    };
    let base = core::ptr::addr_of!(BENCH_READ_MEM_SOURCE) as u64;
    // SAFETY: `BENCH_READ_MEM_SINK` is reached only here, on ktest's one
    // thread, and the reference is the only one alive while the loop runs.
    let sink = unsafe { &mut (*core::ptr::addr_of_mut!(BENCH_READ_MEM_SINK)).0 };

    let iters = h.iters();
    let (mut samples, counters) = h.recorder();
    for i in 0..iters
    {
        let page = (i as usize) % READ_MEM_PAGES;
        let va = base.wrapping_add((page as u64).wrapping_mul(4096));
        let t0 = counters.read();
        let read = syscall::thread_read_mem(child.th, va, sink);
        let t1 = counters.read();
        if read != Ok(4096)
        {
            break;
        }
        samples.record(t1.since(&t0).cycles);
    }
    let summary = samples.summary();
    child.delete_thread().ok();
    child.delete_cspace().ok();

    h.report("thread_read_mem_page", &[], summary, &[]);
}
