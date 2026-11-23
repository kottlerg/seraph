// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/rt_wake_preempt.rs

//! Integration: the wake of a thread that outranks the running thread of its
//! CPU preempts that thread at the CPU's next return to user mode
//! (core/kernel/docs/scheduler.md § Wake Preemption).
//!
//! ## Same-CPU case
//!
//! A waiter at [`WAITER_PRIORITY`] and a waker at [`LOW_PRIORITY`] are pinned
//! to CPU 1. The waiter, started first, runs ahead of the waker and blocks on
//! `wake`; the waker then signals `wake`, a self-wake on CPU 1 that sends no
//! IPI, and reads the waiter's [`RAN`] flag as its `notification_send`
//! returns. The syscall's exit preempts the waker for the waiter, so the flag
//! is set; a kernel that leaves the waker running until it blocks, yields or
//! expires has it read the flag clear.
//!
//! ## Cross-CPU case
//!
//! A spinner at [`LOW_PRIORITY`] and a waiter at [`WAITER_PRIORITY`] are
//! pinned to CPU 1, a waker at [`WAITER_PRIORITY`] to CPU 0. For each of
//! [`SAMPLES`] rounds the waker sleeps a tick, so the waiter has blocked and
//! the spinner runs, reads `ElapsedUs` and signals the waiter, which reads it
//! again as it runs and acknowledges. The wake-to-run latencies are logged as
//! their median, 99th percentile and worst. The median must stay within
//! [`MEDIAN_BOUND_US`] at every width: the wake preempts the spinner through
//! its IPI, where a wake left to the spinner's slice expiry waits half an RT
//! slice at the median, whatever the width.
//!
//! Needs 2 CPUs and the `SchedControl` cap (skips otherwise).

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, notification_send, notification_wait,
    notification_wait_timeout, system_info, thread_exit, thread_sleep,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Level of the woken threads and of the cross-CPU waker: an RT level above
/// [`LOW_PRIORITY`] and below the harness's `INIT_PRIORITY` (30).
const WAITER_PRIORITY: u8 = 26;

/// Level of the thread the wake preempts: the same-CPU waker, and the
/// cross-CPU spinner. An RT level, so only a higher RT level outranks it.
const LOW_PRIORITY: u8 = 22;

/// The CPU the woken threads run on.
const TARGET_CPU: u32 = 1;

/// The CPU of the cross-CPU waker.
const WAKER_CPU: u32 = 0;

/// Wake-to-run samples the cross-CPU case takes.
const SAMPLES: usize = 200;

/// Bound on the median wake-to-run latency (µs): two 1 ms ticks, below the
/// 5 ms median a wait for the spinner's 10 ms slice gives, with room for an
/// emulated CPU's IPI delivery. It applies as written past
/// [`crate::UNSCALED_CPUS`]: the slice wait it tells the wake apart from does
/// not grow with the width, so a bound stretched by [`crate::scaled_bound`]
/// would pass that wait at 128 CPUs, where an emulated boot's median still
/// stays under a quarter of it.
const MEDIAN_BOUND_US: u64 = 2_000;

/// Wait for one acknowledgement in the cross-CPU case (ms), applied through
/// [`crate::scaled_bound`]: past a whole slice, so only a lost wake reaches it.
const ACK_TIMEOUT_MS: u64 = 1_000;

/// 5 s windows the harness waits, at most, for a case's children to report.
const REPORT_WINDOWS: u32 = 12;

/// `done` bits.
const WAITER_DONE: u64 = 1 << 0;
const WAKER_SAW_RAN: u64 = 1 << 1;
const WAKER_SAW_CLEAR: u64 = 1 << 2;
const SPINNER_DONE: u64 = 1 << 3;
const MEASURED: u64 = 1 << 4;
const MEASURE_FAILED: u64 = 1 << 5;

/// Set by the same-CPU waiter when it runs.
static RAN: AtomicU32 = AtomicU32::new(0);

/// Tells the cross-CPU spinner to finish.
static STOP: AtomicBool = AtomicBool::new(false);

/// `ElapsedUs` as the cross-CPU waiter last ran.
static WOKE_AT_US: AtomicU64 = AtomicU64::new(0);

/// The cross-CPU latencies (µs), one per round.
static LATENCY_US: [AtomicU64; SAMPLES] = [const { AtomicU64::new(0) }; SAMPLES];

/// The caps a child holds, in its own `CSpace`; a zero slot is unused.
#[derive(Clone, Copy)]
struct Args
{
    /// `wake` (wait for a waiter, notify for a waker).
    wake: u64,
    /// `ack` (notify for a waiter, wait for a waker).
    ack: u64,
    /// `done` (notify).
    done: u64,
    /// The cross-CPU waker's acknowledgement timeout (ms).
    ack_timeout_ms: u64,
}

const NO_ARGS: Args = Args {
    wake: 0,
    ack: 0,
    done: 0,
    ack_timeout_ms: 0,
};

/// One entry per child: the same-CPU waiter and waker, then the cross-CPU
/// spinner, waiter and waker.
static ARGS: spawn::ArgBlock<Args, 5> = spawn::ArgBlock::new(NO_ARGS);

/// Stacks, indexed as [`ARGS`].
static mut STACKS: [ChildStack; 5] = [const { ChildStack::ZERO }; 5];

/// Same-CPU waiter: block on `wake`, set [`RAN`], report, exit.
extern "C" fn same_cpu_waiter(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    if notification_wait(a.wake).is_ok()
    {
        RAN.store(1, Ordering::Release);
    }
    notification_send(a.done, WAITER_DONE).ok();
    thread_exit();
}

/// Same-CPU waker: signal `wake`, read [`RAN`] as the send returns, report.
extern "C" fn same_cpu_waker(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    notification_send(a.wake, 1).ok();
    let seen = if RAN.load(Ordering::Acquire) == 1
    {
        WAKER_SAW_RAN
    }
    else
    {
        WAKER_SAW_CLEAR
    };
    notification_send(a.done, seen).ok();
    thread_exit();
}

/// Cross-CPU spinner: run until [`STOP`], report, exit.
extern "C" fn spinner(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    while !STOP.load(Ordering::Relaxed)
    {
        core::hint::spin_loop();
    }
    notification_send(a.done, SPINNER_DONE).ok();
    thread_exit();
}

/// Cross-CPU waiter: for each wake, record `ElapsedUs` and acknowledge.
extern "C" fn cross_cpu_waiter(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    for _ in 0..SAMPLES
    {
        if notification_wait(a.wake).is_err()
        {
            break;
        }
        let Ok(now) = system_info(SystemInfoType::ElapsedUs as u64)
        else
        {
            break;
        };
        WOKE_AT_US.store(now, Ordering::Release);
        notification_send(a.ack, 1).ok();
    }
    notification_send(a.done, WAITER_DONE).ok();
    thread_exit();
}

/// Cross-CPU waker: take [`SAMPLES`] wake-to-run latencies into
/// [`LATENCY_US`], then report [`MEASURED`] or [`MEASURE_FAILED`].
extern "C" fn cross_cpu_waker(arg: u64) -> !
{
    // SAFETY: arg is this child's ARGS entry, published before its start.
    let a: Args = unsafe { spawn::child_args(arg) };
    let mut outcome = MEASURED;
    for slot in &LATENCY_US
    {
        // A tick's sleep: the waiter has blocked again and the spinner runs.
        let sent_at = thread_sleep(1)
            .ok()
            .and_then(|()| system_info(SystemInfoType::ElapsedUs as u64).ok());
        let acked = sent_at.is_some()
            && notification_send(a.wake, 1).is_ok()
            && notification_wait_timeout(a.ack, a.ack_timeout_ms).is_ok_and(|bits| bits != 0);
        let Some(sent_at) = sent_at.filter(|_| acked)
        else
        {
            outcome = MEASURE_FAILED;
            break;
        };
        slot.store(
            WOKE_AT_US.load(Ordering::Acquire).saturating_sub(sent_at),
            Ordering::Relaxed,
        );
    }
    notification_send(a.done, outcome).ok();
    thread_exit();
}

/// Spawn a child at `priority` holding `wake`, `ack` and `done` with the
/// given rights (a zero right skips the cap), publish its arguments in entry
/// `index`, and start it on `cpu`.
fn start_child(
    ctx: &TestContext,
    index: usize,
    priority: u8,
    entry: extern "C" fn(u64) -> !,
    caps: [(u64, u64); 3],
    ack_timeout_ms: u64,
    cpu: u32,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child_at(ctx, ctx.sched_control_cap, priority)
        .map_err(|_| "rt_wake_preempt: spawn::new_child_at failed")?;
    let mut slots = [0u64; 3];
    for (slot, (cap, rights)) in slots.iter_mut().zip(caps)
    {
        if rights != 0
        {
            *slot =
                cap_copy(cap, child.cs, rights).map_err(|_| "rt_wake_preempt: cap_copy failed")?;
        }
    }
    let [wake, ack, done] = slots;
    // SAFETY: index < 5, and no child reads the entry: each runs once, after
    // its publish, and exits before the next case.
    let arg = unsafe {
        ARGS.publish(
            index,
            Args {
                wake,
                ack,
                done,
                ack_timeout_ms,
            },
        )
    };
    // SAFETY: `STACKS` is a static array of stacks, reached only through
    // `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), index) }?;
    // SAFETY: the stack is this child's own `ChildStack`, on which no other
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child, entry, stack, arg, cpu) }
        .map_err(|_| "rt_wake_preempt: configure_and_start_pinned failed")?;
    Ok(child)
}

/// Wait on `done` until every bit of one of `any_of`'s masks has arrived, at
/// most [`REPORT_WINDOWS`] 5 s windows; the bits seen.
fn await_bits(done: u64, seen: u64, any_of: &[u64]) -> u64
{
    let mut seen = seen;
    for _ in 0..REPORT_WINDOWS
    {
        if any_of.iter().any(|&mask| seen & mask == mask)
        {
            break;
        }
        seen |= notification_wait_timeout(done, 5_000).unwrap_or(0);
    }
    seen
}

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("rt_wake_preempt: starting");
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: rt_wake_preempt SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "rt_wake_preempt: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: rt_wake_preempt SKIP (needs 2 CPUs)");
        return Ok(());
    }
    same_cpu(ctx)?;
    cross_cpu(ctx)
}

/// The same-CPU case.
fn same_cpu(ctx: &TestContext) -> TestResult
{
    let wake = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_wake_preempt: cap_create_notification (wake) failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_wake_preempt: cap_create_notification (done) failed")?;
    RAN.store(0, Ordering::Relaxed);
    let notify = syscall_abi::RIGHTS_NTF_NOTIFY;
    let wait = syscall_abi::RIGHTS_NTF_WAIT;

    let outcome = (|| {
        let waiter = start_child(
            ctx,
            0,
            WAITER_PRIORITY,
            same_cpu_waiter,
            [(wake, wait), (0, 0), (done, notify)],
            0,
            TARGET_CPU,
        )?;
        // Started second on the same CPU and outranked by the waiter, the
        // waker runs only once the waiter has blocked on `wake`.
        let waker = start_child(
            ctx,
            1,
            LOW_PRIORITY,
            same_cpu_waker,
            [(wake, notify), (0, 0), (done, notify)],
            0,
            TARGET_CPU,
        )?;
        let bits = await_bits(
            done,
            0,
            &[WAITER_DONE | WAKER_SAW_RAN, WAITER_DONE | WAKER_SAW_CLEAR],
        );
        drop(waker);
        drop(waiter);
        if bits & WAKER_SAW_CLEAR != 0
        {
            return Err(
                "rt_wake_preempt: the waker returned from its send before the outranking waiter ran",
            );
        }
        if bits & (WAITER_DONE | WAKER_SAW_RAN) != WAITER_DONE | WAKER_SAW_RAN
        {
            crate::log_u64("rt_wake_preempt: same-CPU bits=", bits);
            return Err("rt_wake_preempt: the same-CPU children did not report");
        }
        Ok(())
    })();
    cap_delete(wake).ok();
    cap_delete(done).ok();
    outcome
}

/// The cross-CPU case.
fn cross_cpu(ctx: &TestContext) -> TestResult
{
    let wake = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_wake_preempt: cap_create_notification (wake) failed")?;
    let ack = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_wake_preempt: cap_create_notification (ack) failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "rt_wake_preempt: cap_create_notification (done) failed")?;
    STOP.store(false, Ordering::Relaxed);
    let notify = syscall_abi::RIGHTS_NTF_NOTIFY;
    let wait = syscall_abi::RIGHTS_NTF_WAIT;

    let outcome = (|| {
        let spinner = start_child(
            ctx,
            2,
            LOW_PRIORITY,
            spinner,
            [(0, 0), (0, 0), (done, notify)],
            0,
            TARGET_CPU,
        )?;
        let result = (|| {
            let waiter = start_child(
                ctx,
                3,
                WAITER_PRIORITY,
                cross_cpu_waiter,
                [(wake, wait), (ack, notify), (done, notify)],
                0,
                TARGET_CPU,
            )?;
            let waker = start_child(
                ctx,
                4,
                WAITER_PRIORITY,
                cross_cpu_waker,
                [(wake, notify), (ack, wait), (done, notify)],
                crate::scaled_bound(ACK_TIMEOUT_MS),
                WAKER_CPU,
            )?;
            let bits = await_bits(done, 0, &[MEASURED | WAITER_DONE, MEASURE_FAILED]);
            drop(waker);
            drop(waiter);
            Ok(bits)
        })();
        STOP.store(true, Ordering::Relaxed);
        let bits = result?;
        let bits = await_bits(done, bits, &[SPINNER_DONE]);
        drop(spinner);
        if bits & MEASURED == 0
        {
            crate::log_u64("rt_wake_preempt: cross-CPU bits=", bits);
            return Err("rt_wake_preempt: the cross-CPU waker did not complete its samples");
        }
        check_latencies()
    })();
    cap_delete(wake).ok();
    cap_delete(ack).ok();
    cap_delete(done).ok();
    outcome
}

/// Log the median, 99th percentile and worst of [`LATENCY_US`], and hold the
/// median to [`MEDIAN_BOUND_US`].
fn check_latencies() -> TestResult
{
    let mut sorted = [0u64; SAMPLES];
    for (out, sample) in sorted.iter_mut().zip(&LATENCY_US)
    {
        *out = sample.load(Ordering::Relaxed);
    }
    sorted.sort_unstable();
    let at = |rank: usize| sorted.get(rank).copied().unwrap_or(u64::MAX);
    let median = at(SAMPLES / 2);
    crate::log_u64("rt_wake_preempt: wake-to-run median_us=", median);
    crate::log_u64(
        "rt_wake_preempt: wake-to-run p99_us=",
        at(SAMPLES * 99 / 100),
    );
    crate::log_u64("rt_wake_preempt: wake-to-run worst_us=", at(SAMPLES - 1));
    if median > MEDIAN_BOUND_US
    {
        return Err("rt_wake_preempt: the median wake-to-run latency exceeds its bound");
    }
    Ok(())
}
