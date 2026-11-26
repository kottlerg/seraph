// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/ipc_receiver_order.rs

//! Integration: a call takes the receiver parked on the caller's CPU when that
//! CPU queues no thread but its idle thread, and the longest-waiting receiver
//! otherwise (core/kernel/docs/ipc-internals.md § Wait Queues).
//!
//! ## The hazard
//!
//! Each CPU keeps a four-slot table of the receivers parked from it. A table
//! that outlives a receiver hands a call a removed or freed thread; one that
//! answers for the wrong endpoint or CPU serves a call out of order; one that
//! refuses when it is full or has no record fails a call the queue could
//! serve. The queue behind it must stay first come, first served.
//!
//! ## How this exercises it
//!
//! Needs 4 CPUs and the `SchedControl` cap (skips otherwise). The harness pins
//! itself to CPU 0 and never polls while a phase's calls run: it waits for the
//! caller's report in one notification wait. Each phase has its own endpoints,
//! children and `done` notification, all torn down before the next. A caller
//! pins itself to the CPU of each step, waits for the receivers' parks, lets
//! their switch-outs finish, calls, and records the receiver's id and CPU from
//! the reply.
//!
//!   1. **`pinned_pool`** — one receiver pinned to each of CPUs 0 to 3 on one
//!      endpoint, parked in the order CPU 0 to 3. Four calls from each of CPUs
//!      3, 2, 1 and 0 reach the receiver of that CPU, which replies on it, and
//!      no receiver counts a remote wake.
//!   2. **`unpinned_pool`** — three unpinned receivers park from CPUs 2, 1
//!      and 2, in the queue order U2, U1, U3. Calls from CPUs 1, 2 and 3 reach
//!      U1, U3 (the later park from CPU 2) and U2 (no record, the queue head).
//!   3. **`fifo_fallback`** — receivers on CPUs 1 and 2 park in that order.
//!      Four calls from CPU 2 reach CPU 2's receiver; one from CPU 3 reaches
//!      the other, the queue head. A call from CPU 2 then holds CPU 2's
//!      receiver, and a second call from CPU 2, whose record went with the
//!      held receiver, reaches the head.
//!   4. **`full_table`** — a receiver on CPU 1 and one on CPU 3 park on one
//!      endpoint, then four receivers on CPU 3 park on four other endpoints,
//!      which evicts the CPU 3 record of the first endpoint. A call from CPU 3
//!      reaches the CPU 1 receiver (the head, not a refusal), the next the CPU
//!      3 one.
//!   5. **`stress`** — a receiver on CPU 1 is removed while parked, by
//!      deleting its thread, by destroying its endpoint (a fresh endpoint
//!      follows at once) or by its timed receive expiring, [`STRESS_ROUNDS`]
//!      times each. A receiver on CPU 2 then parks, and a call from CPU 1 must
//!      reach it.
//!
//! ## Pass criterion
//!
//! Every call's reply names the receiver the phase expects, and, in phase 1,
//! the CPU the call came from. No child's syscall fails, and every report
//! arrives within its bound.

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_revoke,
    notification_send, notification_wait, notification_wait_timeout, system_info, thread_exit,
    thread_set_affinity, thread_sleep, thread_yield,
};
use syscall_abi::{
    RIGHTS_EP_RECEIVE, RIGHTS_EP_SEND, RIGHTS_NTF_NOTIFY, RIGHTS_NTF_WAIT, RIGHTS_THREAD_CONTROL,
    SyscallError, SystemInfoType,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// The CPUs the cell uses, 0 to 3.
const CPUS: u32 = 4;

/// The harness's CPU.
const HARNESS_CPU: u32 = 0;

/// The fair level of every child.
const FAIR: u8 = 10;

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Yields a thread takes to reach its pinned CPU.
const MAX_YIELDS: u32 = 64;

/// Bound on each wait for a receiver's park or exit, and on each wait for a
/// report, in 1 ms units before [`crate::scaled_polls`] and
/// [`crate::scaled_bound`].
const PARK_POLLS: u32 = 2_000;
const REPORT_MS: u64 = 4_000;

/// Milliseconds a thread waits after a receiver announced its park, for the
/// receiver's entry into the queue and its switch-out to complete before the
/// call: the receiver announces just before its receive, so the park itself
/// is not yet done at the announcement.
const SETTLE_MS: u64 = 5;

/// Calls from each CPU in phase 1.
const CALLS_PER_CPU: u32 = 4;

/// Rounds of each removal kind in phase 5.
const STRESS_ROUNDS: u32 = 3;

/// The timed receive of an expiring receiver, in milliseconds.
const EXPIRE_MS: u64 = 5;

/// A receiver serving calls until its receive fails.
const FOREVER: u32 = u32::MAX;

/// The request word asking a receiver to hold its reply.
const HOLD_FLAG: u64 = 1;

/// `done` bits: the first and second caller, and a receiver holding.
const BIT_A: u64 = 1 << 0;
const BIT_B: u64 = 1 << 1;
const BIT_HELD: u64 = 1 << 2;

/// A step's `expect_cpu` that checks no CPU.
const NO_CPU: u32 = u32::MAX;

/// Children of a phase: receivers on indices 0 to 5 (their id less 1), the
/// callers on [`CALLER_A`] and [`CALLER_B`].
const MAX_CHILDREN: usize = 8;
const CALLER_A: usize = 6;
const CALLER_B: usize = 7;

/// Endpoints of a phase.
const MAX_EPS: usize = 5;

/// Recorded calls: the most any phase makes, with the second caller's at
/// [`B_BASE`].
const MAX_RESULTS: usize = 16;
const B_BASE: u32 = 8;

/// Receiver ids are indices into the progress arrays, from 1.
const MAX_IDS: usize = 8;

/// Times each receiver (by id) announced a park, set before its receive.
static PARKED: [AtomicU32; MAX_IDS] = [const { AtomicU32::new(0) }; MAX_IDS];

/// Set by a receiver (by id) whose timed receive expired, and by one that holds.
static EXPIRED: [AtomicU32; MAX_IDS] = [const { AtomicU32::new(0) }; MAX_IDS];
static HOLDING: [AtomicU32; MAX_IDS] = [const { AtomicU32::new(0) }; MAX_IDS];

/// The receiver id and CPU each call's reply named, by step.
static RESULT_ID: [AtomicU32; MAX_RESULTS] = [const { AtomicU32::new(u32::MAX) }; MAX_RESULTS];
static RESULT_CPU: [AtomicU32; MAX_RESULTS] = [const { AtomicU32::new(u32::MAX) }; MAX_RESULTS];

/// Syscall failures in the children.
static CHILD_ERRORS: AtomicU32 = AtomicU32::new(0);

/// The scripts a caller runs.
#[derive(Clone, Copy)]
enum Script
{
    Pinned,
    Unpinned,
    FifoA,
    FifoB,
    Full,
    Stress,
}

/// One call of a script.
#[derive(Clone, Copy)]
struct Step
{
    /// The CPU the caller calls from.
    cpu: u32,
    /// The receiver id and park count the caller waits for first; id 0 waits
    /// for none.
    wait: (u32, u32),
    /// The request's word 0.
    flag: u64,
    /// The receiver id the reply must name, and the CPU it must name, or
    /// [`NO_CPU`].
    expect_id: u32,
    expect_cpu: u32,
}

impl Step
{
    const fn to(cpu: u32, expect_id: u32) -> Self
    {
        Self {
            cpu,
            wait: (0, 0),
            flag: 0,
            expect_id,
            expect_cpu: NO_CPU,
        }
    }

    const fn after(self, id: u32, parks: u32) -> Self
    {
        Self {
            wait: (id, parks),
            ..self
        }
    }
}

/// Call `i` of `script`, `None` past its end.
fn step(script: Script, i: u32) -> Option<Step>
{
    match (script, i)
    {
        (Script::Pinned, 0..=15) =>
        {
            let cpu = (CPUS - 1).saturating_sub(i / CALLS_PER_CPU);
            let id = cpu.saturating_add(1);
            // The receiver of `cpu` parked once at the start and once after each reply.
            let parks = (i % CALLS_PER_CPU).saturating_add(1);
            Some(Step {
                expect_cpu: cpu,
                ..Step::to(cpu, id).after(id, parks)
            })
        }
        (Script::Unpinned, 0) => Some(Step::to(1, 1)),
        (Script::Unpinned, 1) => Some(Step::to(2, 3)),
        (Script::Unpinned, 2) | (Script::Full, 1) => Some(Step::to(3, 2)),
        (Script::FifoA, 0..=3) => Some(Step::to(2, 2).after(2, i.saturating_add(1))),
        (Script::FifoA, 4) => Some(Step::to(3, 1).after(1, 1)),
        (Script::FifoA, 5) => Some(Step {
            flag: HOLD_FLAG,
            ..Step::to(2, 2).after(2, 5)
        }),
        (Script::FifoB, 0) => Some(Step::to(2, 1).after(1, 2)),
        (Script::Full, 0) => Some(Step::to(3, 1)),
        (Script::Stress, 0) => Some(Step::to(1, 2)),
        _ => None,
    }
}

/// A child's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct ChildArgs
{
    /// Its copy of the endpoint.
    ep: u64,
    /// Its stack and IPC page.
    slot: usize,
    /// A receiver's id, from 1.
    id: u32,
    /// Calls a receiver serves before it exits, or [`FOREVER`].
    serve: u32,
    /// Whether a receiver clears its affinity before it parks.
    unpin: bool,
    /// A receiver's copy of the notification it waits on to release a held
    /// reply (0 for none), and of `done` it signals on holding.
    release: u64,
    held: u64,
    /// A receiver's receive timeout in milliseconds, 0 for none.
    timeout_ms: u64,
    /// The child's own Thread cap (control rights), when it changes affinity.
    me: u64,
    /// A caller's copy of `done`, the bit it signals, its script and the index
    /// of its first result.
    done: u64,
    bit: u64,
    script: Script,
    base: u32,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, MAX_CHILDREN> = spawn::ArgBlock::new(ChildArgs {
    ep: 0,
    slot: 0,
    id: 0,
    serve: 0,
    unpin: false,
    release: 0,
    held: 0,
    timeout_ms: 0,
    me: 0,
    done: 0,
    bit: 0,
    script: Script::Pinned,
    base: 0,
});

/// One stack per child.
static mut STACKS: [ChildStack; MAX_CHILDREN] = [const { ChildStack::ZERO }; MAX_CHILDREN];

/// One IPC page per child.
static mut IPC_PAGES: [crate::IpcPage; MAX_CHILDREN] =
    [const { crate::IpcPage::ZERO }; MAX_CHILDREN];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "ipc_receiver_order: system_info(CpuCount) failed")?;
    if cpus < u64::from(CPUS)
    {
        crate::log("ktest: ipc_receiver_order SKIP (needs 4 CPUs)");
        return Ok(());
    }
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: ipc_receiver_order SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let result = pin_self(ctx)
        .and_then(|()| with_fixture(ctx, |fx| pinned_pool(ctx, fx)))
        .and_then(|()| with_fixture(ctx, |fx| unpinned_pool(ctx, fx)))
        .and_then(|()| with_fixture(ctx, |fx| fifo_fallback(ctx, fx)))
        .and_then(|()| with_fixture(ctx, |fx| full_table(ctx, fx)))
        .and_then(|()| stress(ctx));
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    result?;
    restored.map_err(|_| "ipc_receiver_order: restore affinity failed")
}

/// The CPU this thread runs on.
#[expect(clippy::cast_possible_truncation, reason = "a CPU index fits u32")]
fn current_cpu() -> u32
{
    system_info(SystemInfoType::CurrentCpu as u64).map_or(u32::MAX, |cpu| cpu as u32)
}

/// Yield until this thread, just pinned to `cpu`, runs there.
fn reach(cpu: u32) -> bool
{
    for _ in 0..MAX_YIELDS
    {
        if current_cpu() == cpu
        {
            return true;
        }
        let _ = thread_yield();
    }
    current_cpu() == cpu
}

/// Pin the harness to [`HARNESS_CPU`] and run there.
fn pin_self(ctx: &TestContext) -> TestResult
{
    thread_set_affinity(ctx.thread_cap, HARNESS_CPU)
        .map_err(|_| "ipc_receiver_order: pin failed")?;
    if !reach(HARNESS_CPU)
    {
        return Err("ipc_receiver_order: the harness never ran on its CPU");
    }
    Ok(())
}

/// The value of entry `index` of `counts`, 0 past its end.
fn load(counts: &[AtomicU32], index: u32) -> u32
{
    usize::try_from(index)
        .ok()
        .and_then(|i| counts.get(i))
        .map_or(0, |count| count.load(Ordering::Acquire))
}

/// Store `value` in entry `index` of `counts`; past its end nothing.
fn store(counts: &[AtomicU32], index: u32, value: u32)
{
    if let Some(count) = usize::try_from(index).ok().and_then(|i| counts.get(i))
    {
        count.store(value, Ordering::Release);
    }
}

/// Count one more park of receiver `id`.
fn note_park(id: u32)
{
    if let Some(count) = usize::try_from(id).ok().and_then(|i| PARKED.get(i))
    {
        count.fetch_add(1, Ordering::Release);
    }
}

/// Clear every progress array for a new phase.
fn reset_state()
{
    CHILD_ERRORS.store(0, Ordering::Release);
    for count in PARKED.iter().chain(&EXPIRED).chain(&HOLDING)
    {
        count.store(0, Ordering::Release);
    }
    for result in RESULT_ID.iter().chain(&RESULT_CPU)
    {
        result.store(u32::MAX, Ordering::Release);
    }
}

/// Start `child` on stack `slot`, pinned to `cpu`.
fn start(
    child: &spawn::SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    slot: usize,
    arg: u64,
    cpu: u32,
) -> TestResult
{
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), slot) }?;
    // SAFETY: the stack is this test's own `STACKS` slot, on which no other
    // live thread runs (`ChildStack`'s rule): a phase's children are deleted before
    // the next phase starts.
    unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, cpu) }
        .map_err(|_| "ipc_receiver_order: start child failed")
}

/// What a phase owns: its notifications, endpoints and children.
struct Fixture
{
    /// Children's reports, and the notification a held receiver waits on.
    done: u64,
    release: u64,
    /// Endpoints, 0 for none.
    eps: [u64; MAX_EPS],
    children: [spawn::SpawnedChild; MAX_CHILDREN],
}

/// Run `body` on a fresh [`Fixture`], then release everything whatever the result.
fn with_fixture(ctx: &TestContext, body: impl FnOnce(&mut Fixture) -> TestResult) -> TestResult
{
    reset_state();
    let mut fx = Fixture {
        done: 0,
        release: 0,
        eps: [0; MAX_EPS],
        children: [const { spawn::SpawnedChild::EMPTY }; MAX_CHILDREN],
    };
    let result = create_notifications(ctx, &mut fx).and_then(|()| body(&mut fx));
    let released = teardown(&mut fx);
    result?;
    released
}

fn create_notifications(ctx: &TestContext, fx: &mut Fixture) -> TestResult
{
    fx.done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc_receiver_order: cap_create_notification failed")?;
    fx.release = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc_receiver_order: cap_create_notification failed")?;
    Ok(())
}

/// Destroy the endpoints (revoking the children's copies first, so the last
/// Receive cap goes and the parked receivers wake with an error), then delete
/// every child thread and cspace, then the notifications.
fn teardown(fx: &mut Fixture) -> TestResult
{
    let mut released = true;
    for ep in &mut fx.eps
    {
        if *ep != 0
        {
            let _ = cap_revoke(*ep);
            released &= cap_delete(*ep).is_ok();
            *ep = 0;
        }
    }
    for child in &mut fx.children
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    for cap in [&mut fx.done, &mut fx.release]
    {
        if *cap != 0
        {
            released &= cap_delete(*cap).is_ok();
            *cap = 0;
        }
    }
    if released
    {
        Ok(())
    }
    else
    {
        Err("ipc_receiver_order: teardown failed")
    }
}

/// Create endpoint `index` of the fixture.
fn new_ep(ctx: &TestContext, fx: &mut Fixture, index: usize) -> Result<u64, &'static str>
{
    let slot = fx
        .eps
        .get_mut(index)
        .ok_or("ipc_receiver_order: endpoint index out of range")?;
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc_receiver_order: cap_create_endpoint failed")?;
    *slot = ep;
    Ok(ep)
}

/// A receiver's behaviour.
#[derive(Clone, Copy)]
struct Recv
{
    id: u32,
    serve: u32,
    unpin: bool,
    timeout_ms: u64,
}

impl Recv
{
    const fn serving(id: u32, serve: u32) -> Self
    {
        Self {
            id,
            serve,
            unpin: false,
            timeout_ms: 0,
        }
    }
}

/// Start receiver `cfg` on `ep`, pinned to `cpu`.
fn spawn_receiver(ctx: &TestContext, fx: &mut Fixture, ep: u64, cfg: Recv, cpu: u32) -> TestResult
{
    let (done, release) = (fx.done, fx.release);
    let index = usize::try_from(cfg.id.saturating_sub(1)).unwrap_or(usize::MAX);
    let child = fx
        .children
        .get_mut(index)
        .ok_or("ipc_receiver_order: receiver index out of range")?;
    *child = spawn::new_child_at(ctx, ctx.sched_control_cap, FAIR)
        .map_err(|_| "ipc_receiver_order: spawn receiver failed")?;
    let me = if cfg.unpin
    {
        cap_copy(child.th, child.cs, RIGHTS_THREAD_CONTROL)
            .map_err(|_| "ipc_receiver_order: cap_copy thread failed")?
    }
    else
    {
        0
    };
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_RECEIVE)
        .map_err(|_| "ipc_receiver_order: cap_copy endpoint failed")?;
    let child_release = cap_copy(release, child.cs, RIGHTS_NTF_WAIT)
        .map_err(|_| "ipc_receiver_order: cap_copy release failed")?;
    let child_held = cap_copy(done, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "ipc_receiver_order: cap_copy done failed")?;
    // SAFETY: entry `index` is this receiver's alone; it has not started, and
    // the previous phase's child of the index has been deleted.
    let arg = unsafe {
        CHILD_ARGS.publish(
            index,
            ChildArgs {
                ep: child_ep,
                slot: index,
                id: cfg.id,
                serve: cfg.serve,
                unpin: cfg.unpin,
                release: child_release,
                held: child_held,
                timeout_ms: cfg.timeout_ms,
                me,
                ..ChildArgs::NONE
            },
        )
    };
    start(child, receiver_entry, index, arg, cpu)
}

impl ChildArgs
{
    /// The arguments of no child.
    const NONE: Self = Self {
        ep: 0,
        slot: 0,
        id: 0,
        serve: 0,
        unpin: false,
        release: 0,
        held: 0,
        timeout_ms: 0,
        me: 0,
        done: 0,
        bit: 0,
        script: Script::Pinned,
        base: 0,
    };
}

/// Start the caller at child `index` running `script` against `ep`, recording
/// its calls from result `base` and reporting `bit` on `done` when it ends.
fn spawn_caller(
    ctx: &TestContext,
    fx: &mut Fixture,
    index: usize,
    ep: u64,
    (script, base, bit): (Script, u32, u64),
) -> TestResult
{
    let done = fx.done;
    let child = fx
        .children
        .get_mut(index)
        .ok_or("ipc_receiver_order: caller index out of range")?;
    *child = spawn::new_child_at(ctx, ctx.sched_control_cap, FAIR)
        .map_err(|_| "ipc_receiver_order: spawn caller failed")?;
    let me = cap_copy(child.th, child.cs, RIGHTS_THREAD_CONTROL)
        .map_err(|_| "ipc_receiver_order: cap_copy thread failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND)
        .map_err(|_| "ipc_receiver_order: cap_copy endpoint failed")?;
    let child_done = cap_copy(done, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "ipc_receiver_order: cap_copy done failed")?;
    let first = step(script, 0).map_or(HARNESS_CPU, |first| first.cpu);
    // SAFETY: entry `index` is this caller's alone; it has not started, and the
    // previous phase's child of the index has been deleted.
    let arg = unsafe {
        CHILD_ARGS.publish(
            index,
            ChildArgs {
                ep: child_ep,
                slot: index,
                me,
                done: child_done,
                bit,
                script,
                base,
                ..ChildArgs::NONE
            },
        )
    };
    start(child, caller_entry, index, arg, first)
}

/// Wait, 1 ms at a time, until receiver `id` has announced `count` parks, then
/// [`SETTLE_MS`] for the park itself. For the harness before any call runs.
fn wait_parked(id: u32, count: u32) -> TestResult
{
    for _ in 0..crate::scaled_polls(PARK_POLLS)
    {
        if load(&PARKED, id) >= count
        {
            let _ = thread_sleep(SETTLE_MS);
            return Ok(());
        }
        let _ = thread_sleep(1);
    }
    Err("ipc_receiver_order: a receiver never parked")
}

/// Wait once for the `bits` on `done`, within [`REPORT_MS`], and fail on a child's
/// syscall failure.
fn wait_done(fx: &Fixture, bits: u64) -> TestResult
{
    let got = notification_wait_timeout(fx.done, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "ipc_receiver_order: wait for a report failed")?;
    if CHILD_ERRORS.load(Ordering::Acquire) != 0
    {
        return Err("ipc_receiver_order: a child syscall failed");
    }
    if got == 0
    {
        return Err("ipc_receiver_order: a child never reported");
    }
    if got & bits != bits
    {
        return Err("ipc_receiver_order: a child reported out of turn");
    }
    Ok(())
}

/// Check the calls `script` recorded from result `base` against its steps.
fn check_results(script: Script, base: u32) -> TestResult
{
    let mut i = 0u32;
    while let Some(expected) = step(script, i)
    {
        let at = base.saturating_add(i);
        let id = load(&RESULT_ID, at);
        let cpu = load(&RESULT_CPU, at);
        if id != expected.expect_id || (expected.expect_cpu != NO_CPU && cpu != expected.expect_cpu)
        {
            crate::log_args(format_args!(
                "ktest: ipc_receiver_order mismatch: step={at} from_cpu={} expected={} got={id} on_cpu={cpu}",
                expected.cpu, expected.expect_id
            ));
            return Err("ipc_receiver_order: a call reached the wrong receiver");
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Phase 1: one pinned receiver per CPU on one endpoint.
fn pinned_pool(ctx: &TestContext, fx: &mut Fixture) -> TestResult
{
    let ep = new_ep(ctx, fx, 0)?;
    for cpu in 0..CPUS
    {
        let id = cpu.saturating_add(1);
        spawn_receiver(ctx, fx, ep, Recv::serving(id, FOREVER), cpu)?;
        wait_parked(id, 1)?;
    }
    let baseline = remote_wakes(fx)?;
    spawn_caller(ctx, fx, CALLER_A, ep, (Script::Pinned, 0, BIT_A))?;
    wait_done(fx, BIT_A)?;
    check_results(Script::Pinned, 0)?;
    if remote_wakes(fx)? != baseline
    {
        return Err("ipc_receiver_order: a receiver was woken across CPUs");
    }
    crate::log("ktest: ipc_receiver_order pinned_pool: calls=16");
    Ok(())
}

/// The `THREAD_PLACEMENT_REMOTE_WAKES` of the four receivers.
fn remote_wakes(fx: &Fixture) -> Result<[u64; 4], &'static str>
{
    let mut out = [0u64; 4];
    for (count, child) in out.iter_mut().zip(&fx.children)
    {
        *count = syscall::cap_info_thread_placement(
            child.th,
            syscall_abi::THREAD_PLACEMENT_REMOTE_WAKES,
        )
        .map_err(|_| "ipc_receiver_order: cap_info(THREAD_PLACEMENT) failed")?;
    }
    Ok(out)
}

/// Phase 2: unpinned receivers parking from CPUs 2, 1 and 2.
fn unpinned_pool(ctx: &TestContext, fx: &mut Fixture) -> TestResult
{
    let ep = new_ep(ctx, fx, 0)?;
    for (id, cpu) in [(2, 2), (1, 1), (3, 2)]
    {
        let cfg = Recv {
            unpin: true,
            ..Recv::serving(id, 1)
        };
        spawn_receiver(ctx, fx, ep, cfg, cpu)?;
        wait_parked(id, 1)?;
    }
    spawn_caller(ctx, fx, CALLER_A, ep, (Script::Unpinned, 0, BIT_A))?;
    wait_done(fx, BIT_A)?;
    check_results(Script::Unpinned, 0)?;
    crate::log("ktest: ipc_receiver_order unpinned_pool: calls=3");
    Ok(())
}

/// Phase 3: a call from a CPU with no record, and one whose record's receiver
/// is held, take the queue head.
fn fifo_fallback(ctx: &TestContext, fx: &mut Fixture) -> TestResult
{
    let ep = new_ep(ctx, fx, 0)?;
    for (id, cpu) in [(1, 1), (2, 2)]
    {
        spawn_receiver(ctx, fx, ep, Recv::serving(id, FOREVER), cpu)?;
        wait_parked(id, 1)?;
    }
    spawn_caller(ctx, fx, CALLER_A, ep, (Script::FifoA, 0, BIT_A))?;
    // Caller A's sixth call parks in the held receiver after five replies.
    wait_done(fx, BIT_HELD)?;
    if load(&HOLDING, 2) == 0
    {
        return Err("ipc_receiver_order: the held receiver did not hold");
    }
    spawn_caller(ctx, fx, CALLER_B, ep, (Script::FifoB, B_BASE, BIT_B))?;
    wait_done(fx, BIT_B)?;
    notification_send(fx.release, 1).map_err(|_| "ipc_receiver_order: notification_send failed")?;
    wait_done(fx, BIT_A)?;
    check_results(Script::FifoA, 0)?;
    check_results(Script::FifoB, B_BASE)?;
    crate::log("ktest: ipc_receiver_order fifo_fallback: calls=7");
    Ok(())
}

/// Phase 4: CPU 3's table holds four other endpoints when a call from it
/// reaches the first.
fn full_table(ctx: &TestContext, fx: &mut Fixture) -> TestResult
{
    for index in 0..MAX_EPS
    {
        new_ep(ctx, fx, index)?;
    }
    let first = fx.eps.first().copied().unwrap_or(0);
    spawn_receiver(ctx, fx, first, Recv::serving(1, 1), 1)?;
    wait_parked(1, 1)?;
    spawn_receiver(ctx, fx, first, Recv::serving(2, 1), 3)?;
    wait_parked(2, 1)?;
    for (id, index) in (3..=6).zip(1..MAX_EPS)
    {
        let ep = fx.eps.get(index).copied().unwrap_or(0);
        spawn_receiver(ctx, fx, ep, Recv::serving(id, FOREVER), 3)?;
        wait_parked(id, 1)?;
    }
    spawn_caller(ctx, fx, CALLER_A, first, (Script::Full, 0, BIT_A))?;
    wait_done(fx, BIT_A)?;
    check_results(Script::Full, 0)?;
    crate::log("ktest: ipc_receiver_order full_table: calls=2");
    Ok(())
}

/// How a phase 5 victim leaves the queue.
#[derive(Clone, Copy)]
enum Removal
{
    Kill,
    Destroy,
    Expire,
}

/// Phase 5: each removal kind, [`STRESS_ROUNDS`] rounds, each on fresh objects.
fn stress(ctx: &TestContext) -> TestResult
{
    for (removal, name) in [
        (Removal::Kill, "kill"),
        (Removal::Destroy, "destroy"),
        (Removal::Expire, "expire"),
    ]
    {
        for _ in 0..STRESS_ROUNDS
        {
            with_fixture(ctx, |fx| stress_round(ctx, fx, removal))?;
        }
        crate::log_args(format_args!(
            "ktest: ipc_receiver_order stress {name}: rounds={STRESS_ROUNDS}"
        ));
    }
    Ok(())
}

/// One round: park a victim on CPU 1, remove it, park a receiver on CPU 2 on
/// the round's endpoint, and call it from CPU 1.
fn stress_round(ctx: &TestContext, fx: &mut Fixture, removal: Removal) -> TestResult
{
    let mut ep = new_ep(ctx, fx, 0)?;
    let victim = Recv {
        timeout_ms: if matches!(removal, Removal::Expire)
        {
            EXPIRE_MS
        }
        else
        {
            0
        },
        ..Recv::serving(1, 1)
    };
    spawn_receiver(ctx, fx, ep, victim, 1)?;
    wait_parked(1, 1)?;
    match removal
    {
        Removal::Kill =>
        {
            if let Some(child) = fx.children.first_mut()
            {
                child
                    .delete_thread()
                    .and_then(|()| child.delete_cspace())
                    .map_err(|_| "ipc_receiver_order: deleting the victim failed")?;
            }
        }
        Removal::Destroy =>
        {
            cap_revoke(ep).map_err(|_| "ipc_receiver_order: cap_revoke endpoint failed")?;
            cap_delete(ep).map_err(|_| "ipc_receiver_order: cap_delete endpoint failed")?;
            if let Some(slot) = fx.eps.first_mut()
            {
                *slot = 0;
            }
            wait_victim_exit(fx)?;
            ep = new_ep(ctx, fx, 0)?;
        }
        Removal::Expire =>
        {
            let mut expired = false;
            for _ in 0..crate::scaled_polls(PARK_POLLS)
            {
                if load(&EXPIRED, 1) != 0
                {
                    expired = true;
                    break;
                }
                let _ = thread_sleep(1);
            }
            if !expired
            {
                return Err("ipc_receiver_order: the timed receive never expired");
            }
            wait_victim_exit(fx)?;
        }
    }
    spawn_receiver(ctx, fx, ep, Recv::serving(2, 1), 2)?;
    wait_parked(2, 1)?;
    spawn_caller(ctx, fx, CALLER_A, ep, (Script::Stress, 0, BIT_A))?;
    wait_done(fx, BIT_A)?;
    check_results(Script::Stress, 0)
}

/// Wait for the victim (child 0) to exit.
fn wait_victim_exit(fx: &Fixture) -> TestResult
{
    let victim = fx.children.first().map_or(0, |child| child.th);
    spawn::wait_until_exited(victim, crate::scaled_polls(PARK_POLLS)).map(|_| ())
}

/// Register IPC page `slot` as this thread's IPC buffer.
fn ipc_buffer(slot: usize) -> Option<*mut u64>
{
    let addr = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(IPC_PAGES), slot).ok()?;
    // SAFETY: entry `slot` of `IPC_PAGES` is this child's own IPC page, used by
    // one thread at a time (`IpcPage`'s rule); no Rust object lives in it, and
    // the child reaches it only through the raw pointer returned.
    unsafe { syscall::ipc_buffer_set(addr) }.ok()?;
    Some(addr as *mut u64)
}

/// Park, serve and reply until the serve count is spent or a receive fails;
/// a failed receive (the endpoint destroyed, or the timeout) ends it quietly.
/// A request carrying [`HOLD_FLAG`] makes it announce on `done` and wait for the
/// release before it replies. A reply carries its id and its CPU.
extern "C" fn receiver_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the phase published for this receiver.
    let args: ChildArgs = unsafe { spawn::child_args(arg) };
    let Some(buf) = ipc_buffer(args.slot)
    else
    {
        CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
        thread_exit()
    };
    if args.unpin && thread_set_affinity(args.me, AFFINITY_ANY).is_err()
    {
        CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
    }
    let mut left = args.serve;
    while serve_once(&args, buf)
    {
        if args.serve != FOREVER
        {
            left = left.saturating_sub(1);
            if left == 0
            {
                break;
            }
        }
    }
    thread_exit()
}

/// Park and serve one call: announce the park, receive, hold the reply when
/// asked, and reply. `false` when the receive failed.
#[inline(never)]
fn serve_once(args: &ChildArgs, buf: *mut u64) -> bool
{
    note_park(args.id);
    // SAFETY: buf is this thread's registered IPC buffer.
    let request = match unsafe { ipc::ipc_recv_timeout(args.ep, buf, args.timeout_ms) }
    {
        Ok(request) => request,
        Err(code) =>
        {
            if args.timeout_ms != 0 && code == SyscallError::WouldBlock as i64
            {
                store(&EXPIRED, args.id, 1);
            }
            return false;
        }
    };
    if request.word(0) == HOLD_FLAG
    {
        store(&HOLDING, args.id, 1);
        if notification_send(args.held, BIT_HELD).is_err()
            || notification_wait(args.release).is_err()
        {
            CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
        }
    }
    send_reply(args, buf);
    true
}

/// Reply with the receiver's id and CPU.
#[inline(never)]
fn send_reply(args: &ChildArgs, buf: *mut u64)
{
    let reply = IpcMessage::builder(0)
        .word(0, u64::from(args.id))
        .word(1, u64::from(current_cpu()))
        .build();
    // SAFETY: buf is this thread's registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, buf) }.is_err()
    {
        CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
    }
}

/// Run the script, then report on `done`; a failure counts and ends it.
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the phase published for this caller.
    let args: ChildArgs = unsafe { spawn::child_args(arg) };
    if !run_script(&args)
    {
        CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
    }
    let _ = notification_send(args.done, args.bit);
    thread_exit()
}

/// Each step: pin to its CPU, wait for the parks it names, give the receivers'
/// switch-outs [`SETTLE_MS`], call, and record the reply; stop after a reply
/// from a receiver the step does not expect. `false` on any failure.
fn run_script(args: &ChildArgs) -> bool
{
    let Some(buf) = ipc_buffer(args.slot)
    else
    {
        return false;
    };
    let mut i = 0u32;
    while let Some(next) = step(args.script, i)
    {
        if thread_set_affinity(args.me, next.cpu).is_err() || !reach(next.cpu)
        {
            return false;
        }
        let (id, parks) = next.wait;
        if id != 0 && !parked_at_least(id, parks)
        {
            return false;
        }
        let _ = thread_sleep(SETTLE_MS);
        let request = IpcMessage::builder(0).word(0, next.flag).build();
        // SAFETY: buf is this thread's registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(args.ep, &request, buf) })
        else
        {
            return false;
        };
        let at = args.base.saturating_add(i);
        store(
            &RESULT_ID,
            at,
            u32::try_from(reply.word(0)).unwrap_or(u32::MAX),
        );
        store(
            &RESULT_CPU,
            at,
            u32::try_from(reply.word(1)).unwrap_or(u32::MAX),
        );
        if reply.word(0) != u64::from(next.expect_id)
        {
            // The wrong receiver served: its own next park, which a later
            // step may wait for, may never come. The harness reports the
            // mismatch from the recorded results.
            return true;
        }
        i = i.saturating_add(1);
    }
    true
}

/// Poll, 1 ms at a time, until receiver `id` has announced `count` parks.
fn parked_at_least(id: u32, count: u32) -> bool
{
    for _ in 0..crate::scaled_polls(PARK_POLLS)
    {
        if load(&PARKED, id) >= count
        {
            return true;
        }
        let _ = thread_sleep(1);
    }
    false
}
