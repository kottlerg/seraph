// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/bench/thread.rs

//! Thread benchmarks: the lifecycle (create → start → exit → cleanup), the
//! context-switch pair, and `SYS_THREAD_READ_MEM`.

use core::sync::atomic::{AtomicU64, Ordering};

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
        return h.skip("thread_lifecycle", "cap_create_notification failed");
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
static BENCH_CTXSWITCH_ITERS: AtomicU64 = AtomicU64::new(0);

/// Child entry: ping-pong via `thread_yield` for `BENCH_CTXSWITCH_ITERS`
/// iterations, then send on the `done_slot` notification and exit.
extern "C" fn ctxswitch_child_entry(done_slot: u64) -> !
{
    let n = BENCH_CTXSWITCH_ITERS.load(Ordering::Acquire);
    for _ in 0..n
    {
        let _ = syscall::thread_yield();
    }
    notification_send(done_slot, PARTNER_BIT).ok();
    thread_exit()
}

/// The notification bit the yielding child signals.
const PARTNER_BIT: u64 = 0x1;
/// The notification bit an `iopb=` case's timing child signals.
const TIMER_BIT: u64 = 0x2;

/// Timing-child entry of an `iopb=` case: `BENCH_CTXSWITCH_ITERS` yields to
/// its partner, each timed into [`super::CHILD_SAMPLES`] and counted in
/// [`super::CHILD_COMPLETED`], then a send on the `done_slot` notification
/// and exit.
extern "C" fn ctxswitch_timer_entry(done_slot: u64) -> !
{
    let n = BENCH_CTXSWITCH_ITERS.load(Ordering::Acquire);
    let counters = ::bench::Counters::open();
    let iters = usize::try_from(n).unwrap_or(usize::MAX);
    for (i, sample) in super::CHILD_SAMPLES.iter().take(iters).enumerate()
    {
        let t0 = counters.read();
        let _ = syscall::thread_yield();
        let t1 = counters.read();
        sample.store(t1.since(&t0).cycles, Ordering::Relaxed);
        super::CHILD_COMPLETED.store(i.saturating_add(1) as u64, Ordering::Relaxed);
    }
    notification_send(done_slot, TIMER_BIT).ok();
    thread_exit()
}

/// The `schedule()` stages, `syscall_abi::SCHED_STAGE_COUNT`.
const STAGES: usize = 9;
const _: () = assert!(syscall_abi::SCHED_STAGE_COUNT == STAGES as u64);

/// The `stage_<name>` extras, in `syscall_abi::SCHED_STAGE_*` order.
const STAGE_EXTRAS: [&str; STAGES] = [
    "stage_lock",
    "stage_pick",
    "stage_release",
    "stage_flip",
    "stage_iopb",
    "stage_guard",
    "stage_aspace",
    "stage_fpu",
    "stage_switch",
];

/// Zero the kernel's `schedule()` stage sums and collect them on this
/// thread's CPU, CPU 0 (`SystemInfoType::SchedStages`); nothing from a
/// kernel built without the `sched-stages` feature.
fn arm_stages()
{
    let _ = syscall::sched_stages(syscall_abi::SCHED_STAGES_ARM);
}

/// Each stage's mean cycles per switch since [`arm_stages`], as the
/// [`STAGE_EXTRAS`]: the register switch's over the switches whose incoming
/// thread resumed in `schedule()`, every other stage's over the switches made.
/// `None` from a kernel built without the `sched-stages` feature, which
/// answers no query.
#[inline(never)]
fn stage_means() -> Option<StageMeans>
{
    let switches = syscall::sched_stages(syscall_abi::SCHED_STAGES_SWITCHES).ok()?;
    let resumes = syscall::sched_stages(syscall_abi::SCHED_STAGES_RESUMES).ok()?;
    let mut means = [("", 0u64); STAGES];
    for ((word, mean), name) in (0u64..).zip(means.iter_mut()).zip(STAGE_EXTRAS)
    {
        let sum = syscall::sched_stages(word).ok()?;
        let count = if word == syscall_abi::SCHED_STAGE_SWITCH
        {
            resumes
        }
        else
        {
            switches
        };
        *mean = (name, sum.checked_div(count).unwrap_or(0));
    }
    Some(means)
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
///
/// A kernel built with the `sched-stages` feature adds the [`STAGE_EXTRAS`],
/// each stage's mean cycles over the switches CPU 0 made in the measured loop
/// (core/kernel/docs/scheduler.md § Stage Breakdown).
///
/// Two more lines, variant `iopb=` (x86-64 alone; riscv64 has no I/O ports),
/// run the ping-pong between two children with the harness waiting, so no
/// switch is into ktest's harness thread and its I/O port bindings: neither
/// child holds a binding (`none`), or the timing child holds ktest's widest
/// `IoPort` cap (`bound`).
pub(super) fn bench_context_switch(ctx: &crate::TestContext, h: &mut Harness)
{
    if ctx.sched_control_cap == 0
    {
        h.skip(CTXSWITCH, "no SchedControl cap");
        if crate::arch::HAS_IO_PORTS
        {
            h.skip(CTXSWITCH, "iopb=none: no SchedControl cap");
            h.skip(CTXSWITCH, "iopb=bound: no SchedControl cap");
        }
        return;
    }
    bench_context_switch_harness(ctx, h);
    bench_context_switch_iopb(ctx, h, Iopb::None);
    bench_context_switch_iopb(ctx, h, Iopb::Bound);
}

/// The context-switch benchmark's name.
const CTXSWITCH: &str = "context_switch_pair";

/// The `context_switch_pair` line without variant: the harness thread's
/// ping-pong with one child.
fn bench_context_switch_harness(ctx: &crate::TestContext, h: &mut Harness)
{
    use crate::spawn;

    const NAME: &str = CTXSWITCH;

    let n = h.iters();
    BENCH_CTXSWITCH_ITERS.store(u64::from(n), Ordering::Release);

    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip(NAME, "cap_create_notification failed");
    };
    // PRIORITY_MAX == INIT_PRIORITY: the level this (init-loaded) thread runs at.
    let Ok(mut child) = spawn::new_child_at(ctx, ctx.sched_control_cap, syscall_abi::PRIORITY_MAX)
    else
    {
        cap_delete(done).ok();
        return h.skip(NAME, "the child could not be created");
    };
    let Ok(child_done) = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
    else
    {
        child.delete_thread().ok();
        child.delete_cspace().ok();
        cap_delete(done).ok();
        return h.skip(NAME, "cap_copy into the child failed");
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
        return h.skip(NAME, "the child did not start");
    }

    arm_stages();
    let (mut samples, counters) = h.recorder();
    for _ in 0..n
    {
        let t0 = counters.read();
        let _ = syscall::thread_yield();
        samples.record(counters.read().since(&t0).cycles);
    }
    let summary = samples.summary();
    let stages = stage_means();

    notification_wait(done).ok();
    child.delete_thread().ok();
    child.delete_cspace().ok();
    cap_delete(done).ok();

    let elided = syscall::cap_info(ctx.memory_base, syscall_abi::CAP_INFO_TLB_ELIDED).unwrap_or(0);
    let performed =
        syscall::cap_info(ctx.memory_base, syscall_abi::CAP_INFO_TLB_PERFORMED).unwrap_or(0);
    report_harness_pair(
        h,
        summary,
        [("tlb_elided", elided), ("tlb_performed", performed)],
        stages,
    );
}

/// Report the line without variant: its TLB counts, then each stage's mean
/// when the kernel answered them.
fn report_harness_pair(
    h: &Harness,
    summary: super::Measured,
    tlb: [(&'static str, u64); 2],
    stages: Option<StageMeans>,
)
{
    match stages
    {
        Some([s0, s1, s2, s3, s4, s5, s6, s7, s8]) =>
        {
            let [t0, t1] = tlb;
            let extras = [t0, t1, s0, s1, s2, s3, s4, s5, s6, s7, s8];
            h.report(CTXSWITCH, &[], summary, &extras);
        }
        None => h.report(CTXSWITCH, &[], summary, &tlb),
    }
}

/// Stacks of the `iopb=` cases' children: the partner, then the timer, of
/// `none` and then of `bound`, so no case's child shares a stack with the
/// previous case's.
static mut BENCH_IOPB_STACKS: [ChildStack; 4] = [ChildStack::ZERO; 4];

/// Each stage's mean, as its extra.
type StageMeans = [(&'static str, u64); STAGES];

/// Whether the timing child of an `iopb=` case holds a port binding; its
/// `iopb=` word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Iopb
{
    /// It holds none: `none`.
    None,
    /// It holds ktest's widest `IoPort` cap: `bound`.
    Bound,
}

/// The `context_switch_pair iopb=` line of `iopb`: a yielding partner
/// child and a timing child, both pinned to CPU 0 at the harness's level, the
/// timer holding ktest's widest `IoPort` cap for `bound`, while the harness
/// waits for both.
fn bench_context_switch_iopb(ctx: &crate::TestContext, h: &mut Harness, iopb: Iopb)
{
    let bound = iopb == Iopb::Bound;
    let word = if bound { "bound" } else { "none" };
    // An architecture without I/O ports has no such case, and what an
    // architecture decides is no SKIP (core/ktest/README.md).
    if !crate::arch::HAS_IO_PORTS
    {
        return;
    }
    let port_cap = match (bound, crate::arch::io_port_cap())
    {
        (false, _) => None,
        (true, Some(cap)) => Some(cap),
        (true, None) => return h.skip(CTXSWITCH, "iopb=bound: no IoPort cap"),
    };
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        return h.skip(
            CTXSWITCH,
            format_args!("iopb={word}: cap_create_notification failed"),
        );
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; 2];
    let first = if bound { 2 } else { 0 };
    let outcome = iopb_pair(ctx, h, (done, port_cap), first, &mut children);
    for child in &mut children
    {
        child.delete_thread().ok();
        child.delete_cspace().ok();
    }
    cap_delete(done).ok();
    match outcome
    {
        Ok((measured, stages)) =>
        {
            let stages = stages.as_ref().map_or(&[][..], |s| &s[..]);
            h.report(
                CTXSWITCH,
                &[("iopb", ::bench::Value::Word(word))],
                measured,
                stages,
            );
        }
        Err(e) => h.skip(CTXSWITCH, format_args!("iopb={word}: {e}")),
    }
}

/// Start the partner and the timer of an `iopb=` case into `children`, on
/// stacks `first` and `first + 1` of [`BENCH_IOPB_STACKS`], binding
/// `port_cap` to the timer when it is `Some`; wait for both, and return the
/// timer's measurement, with CPU 0's idle halts over the pair's run, and the
/// stage means.
fn iopb_pair(
    ctx: &crate::TestContext,
    h: &mut Harness,
    (done, port_cap): (u64, Option<u64>),
    first: usize,
    children: &mut [spawn::SpawnedChild; 2],
) -> Result<(super::Measured, Option<StageMeans>), &'static str>
{
    BENCH_CTXSWITCH_ITERS.store(u64::from(h.iters()), Ordering::Release);
    super::CHILD_COMPLETED.store(0, Ordering::Relaxed);
    let entries: [extern "C" fn(u64) -> !; 2] = [ctxswitch_child_entry, ctxswitch_timer_entry];
    let mut handles = [0u64; 2];
    for (child, handle) in children.iter_mut().zip(&mut handles)
    {
        // PRIORITY_MAX == INIT_PRIORITY: the level of the harness, which
        // waits, and of each other.
        *child = spawn::new_child_at(ctx, ctx.sched_control_cap, syscall_abi::PRIORITY_MAX)
            .map_err(|_| "a child could not be created")?;
        *handle = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "cap_copy into a child failed")?;
    }
    if let (Some(cap), [_, timer]) = (port_cap, &*children)
    {
        // The bind takes the timer's port-binding table from its `CSpace`'s
        // growth budget, which `new_child_at` sizes for a few caps alone.
        syscall::cap_create_cspace(
            ctx.memory_base,
            timer.cs,
            syscall_abi::IOPORT_BINDING_TABLE_PAGES,
        )
        .map_err(|_| "the CSpace augment for the binding table failed")?;
        syscall::ioport_bind(timer.th, cap).map_err(|_| "ioport_bind failed")?;
    }
    let (mut samples, _) = h.recorder();
    arm_stages();
    for (offset, ((child, entry), handle)) in children.iter().zip(entries).zip(handles).enumerate()
    {
        // SAFETY: `BENCH_IOPB_STACKS` is a static array of stacks, reached only through `addr_of!`.
        let stack_top = unsafe {
            ChildStack::top_at(
                core::ptr::addr_of!(BENCH_IOPB_STACKS),
                first.saturating_add(offset),
            )
        }
        .map_err(|_| "no child stack")?;
        // SAFETY: the stack is this child's own entry of `BENCH_IOPB_STACKS`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(child, entry, stack_top, handle, 0) }
            .map_err(|_| "a child did not start")?;
    }
    let mut signalled = 0u64;
    crate::tally::await_all(
        done,
        &mut signalled,
        PARTNER_BIT | TIMER_BIT,
        "a child never signalled",
    )?;
    let stages = stage_means();
    samples.record_children();
    Ok((samples.summary(), stages))
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
        return h.skip("thread_read_mem_page", "new_child failed");
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
