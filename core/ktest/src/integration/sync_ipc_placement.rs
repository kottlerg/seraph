// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/sync_ipc_placement.rs

//! Integration: a call runs its receiver on the caller's CPU when that CPU
//! queues no other thread and the receiver does not outrank the caller, and
//! leaves it to the other placement rules otherwise
//! (core/kernel/docs/scheduling-internals.md § Wake Protocol Invariants,
//! "Target CPU selection").
//!
//! ## The hazard
//!
//! Without the synchronous wake rule, a server parked on one CPU is woken on
//! that CPU by every call from another, so a pair that starts apart stays
//! apart and each round trip pays a wake IPI to a halted CPU. With the rule
//! too wide, the server runs ahead of a thread queued on the caller's CPU
//! while its own CPU idles, or ahead of a caller it outranks, whose reply wake
//! then waits behind it.
//!
//! ## How this exercises it
//!
//! Needs 3 CPUs and the `SchedControl` cap (skips otherwise). The harness
//! pins itself to CPU 0. For each [`Case`], a caller is pinned to K (CPU 2),
//! with a fair spinner pinned beside it when the case asks, and an unpinned
//! server runs on P (CPU 1), clears its affinity there, and parks in its
//! receive. The caller waits for the park, lets the server's switch-out
//! finish, and calls. Around each receive the server reads its own placement
//! counts (`CAP_INFO_THREAD_PLACEMENT`): the wakes that reached the rule, those
//! the rule placed on the waker's CPU, and the load balancer's pulls. It
//! records them with the CPU the receive returned on. [`ROUNDS`] rounds per
//! case.
//!
//! ## Pass criterion
//!
//! The rule's own counts say which rounds it decided, so every such round is
//! judged. A round whose wake did not reach the rule is excluded, and the log
//! gives the count of those rounds. Such a round is one whose call found the
//! server not yet parked, or its context save on P still in flight.
//!
//! - In a case that allows the rule, every counted round is placed on K and
//!   runs there, unless a pull moved the server off K's queue first.
//! - In a case that does not, no counted round is placed on K.
//! - No round of a case that does not allow the rule runs on K, unless a pull
//!   moved the server there: an idle K may pull it off P's queue.
//! - A case that allows the rule fails when no round is counted.
//! - A round whose counts moved by more than its one wake fails.

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait_timeout, system_info, thread_exit, thread_set_affinity, thread_sleep,
    thread_yield,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Calls per case.
const ROUNDS: u32 = 8;

/// The caller's CPU.
const K: u32 = 2;

/// The CPU the server parks on.
const P: u32 = 1;

/// The harness's CPU, away from K and P.
const HARNESS_CPU: u32 = 0;

/// A fair level and an RT level for the threads of a case.
const FAIR: u8 = 10;
const RT: u8 = 24;

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Yields a thread takes to reach its pinned CPU.
const MAX_YIELDS: u32 = 64;

/// 1 ms waits the caller gives the server to reach its park, and the harness
/// gives the caller to finish; applied through [`crate::scaled_polls`].
const PARK_POLLS: u32 = 2_000;
const DONE_POLLS: u32 = 4_000;

/// Milliseconds the caller waits after the server announced its park, for the
/// server's switch-out on P to complete before the call.
const SETTLE_MS: u64 = 2;

/// One case: the levels of the server and the caller, whether a fair spinner
/// is queued on K, and whether the rule runs the server on K.
#[derive(Clone, Copy)]
struct Case
{
    name: &'static str,
    server: u8,
    caller: u8,
    spinner: bool,
    on_k: bool,
}

const CASES: [Case; 5] = [
    Case {
        name: "fair",
        server: FAIR,
        caller: FAIR,
        spinner: false,
        on_k: true,
    },
    Case {
        name: "fair, thread queued on K",
        server: FAIR,
        caller: FAIR,
        spinner: true,
        on_k: false,
    },
    Case {
        name: "RT",
        server: RT,
        caller: RT,
        spinner: false,
        on_k: true,
    },
    Case {
        name: "RT, fair thread queued on K",
        server: RT,
        caller: RT,
        spinner: true,
        on_k: false,
    },
    Case {
        name: "RT server, fair caller",
        server: RT,
        caller: FAIR,
        spinner: false,
        on_k: false,
    },
];

/// The round the server is about to park for (1-based; 0 before the first).
static PARKING: AtomicU32 = AtomicU32::new(0);

/// The CPU the server ran each round on, as its receive returned there.
static RAN_ON: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(u32::MAX) }; ROUNDS as usize];

/// The server's placement counts across each round's receive, as differences:
/// the wakes that reached the synchronous wake rule, those it placed on the
/// waker's CPU, and the load balancer's pulls.
static REACHED: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];
static LOCAL: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];
static PULLED: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];

/// The `CAP_INFO_THREAD_PLACEMENT` views the server reads around a receive,
/// in the order of [`REACHED`], [`LOCAL`] and [`PULLED`].
const COUNTED_VIEWS: [u64; 3] = [
    syscall_abi::THREAD_PLACEMENT_SYNC_WAKES,
    syscall_abi::THREAD_PLACEMENT_SYNC_LOCAL,
    syscall_abi::THREAD_PLACEMENT_PULLS,
];

/// Syscall failures in the children.
static CHILD_ERRORS: AtomicU32 = AtomicU32::new(0);

/// A child's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct ChildArgs
{
    /// The child's copy of its own Thread cap (the server's), or of `done`
    /// (the caller's, notify).
    cap: u64,
    /// Its copy of the endpoint.
    ep: u64,
    /// Its slot: its IPC page.
    slot: usize,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 2> = spawn::ArgBlock::new(ChildArgs {
    cap: 0,
    ep: 0,
    slot: 0,
});

/// Stacks: the server on 0, the caller on 1, the spinner on 2.
static mut STACKS: [ChildStack; 3] = [const { ChildStack::ZERO }; 3];

/// IPC pages of the server (0) and the caller (1).
static mut IPC_PAGES: [crate::IpcPage; 2] = [const { crate::IpcPage::ZERO }; 2];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "sync_ipc_placement: system_info(CpuCount) failed")?;
    if cpus < 3
    {
        crate::log("ktest: sync_ipc_placement SKIP (needs 3 CPUs)");
        return Ok(());
    }
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: sync_ipc_placement SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let result =
        pin_self(ctx).and_then(|()| CASES.iter().try_for_each(|&case| run_case(ctx, case)));
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    result?;
    restored.map_err(|_| "sync_ipc_placement: restore affinity failed")
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
        .map_err(|_| "sync_ipc_placement: pin failed")?;
    if !reach(HARNESS_CPU)
    {
        return Err("sync_ipc_placement: the harness never ran on its CPU");
    }
    Ok(())
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
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, cpu) }
        .map_err(|_| "sync_ipc_placement: start child failed")
}

/// Run one case with its own endpoint, children and `done` notification.
fn run_case(ctx: &TestContext, case: Case) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "sync_ipc_placement: cap_create_endpoint failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(ep);
        return Err("sync_ipc_placement: cap_create_notification failed");
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; 3];
    let result = rounds(ctx, case, ep, done, &mut children);
    for child in &mut children
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    let deleted_done = cap_delete(done);
    let deleted_ep = cap_delete(ep);
    result?;
    deleted_done.map_err(|_| "sync_ipc_placement: cap_delete done failed")?;
    deleted_ep.map_err(|_| "sync_ipc_placement: cap_delete endpoint failed")
}

/// Start the case's threads, wait for the caller's rounds, and check where
/// the server ran.
fn rounds(
    ctx: &TestContext,
    case: Case,
    ep: u64,
    done: u64,
    children: &mut [spawn::SpawnedChild; 3],
) -> TestResult
{
    PARKING.store(0, Ordering::Release);
    CHILD_ERRORS.store(0, Ordering::Release);
    for ran_on in &RAN_ON
    {
        ran_on.store(u32::MAX, Ordering::Release);
    }
    for count in REACHED.iter().chain(&LOCAL).chain(&PULLED)
    {
        count.store(0, Ordering::Release);
    }
    let [server, caller, spinner] = children;

    *server = spawn::new_child_at(ctx, ctx.sched_control_cap, case.server)
        .map_err(|_| "sync_ipc_placement: spawn server failed")?;
    let me = cap_copy(server.th, server.cs, syscall_abi::RIGHTS_THREAD_CONTROL)
        .map_err(|_| "sync_ipc_placement: cap_copy thread failed")?;
    let server_ep = cap_copy(ep, server.cs, syscall_abi::RIGHTS_EP_RECEIVE)
        .map_err(|_| "sync_ipc_placement: cap_copy endpoint failed")?;
    // SAFETY: entry 0 is the server's alone; it has not started, and the
    // previous case's server has been deleted.
    let arg = unsafe {
        CHILD_ARGS.publish(
            0,
            ChildArgs {
                cap: me,
                ep: server_ep,
                slot: 0,
            },
        )
    };
    start(server, server_entry, 0, arg, P)?;

    if case.spinner
    {
        *spinner = spawn::new_child_at(ctx, ctx.sched_control_cap, FAIR)
            .map_err(|_| "sync_ipc_placement: spawn spinner failed")?;
        start(spinner, spinner_entry, 2, 0, K)?;
    }

    *caller = spawn::new_child_at(ctx, ctx.sched_control_cap, case.caller)
        .map_err(|_| "sync_ipc_placement: spawn caller failed")?;
    let caller_done = cap_copy(done, caller.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "sync_ipc_placement: cap_copy done failed")?;
    let caller_ep = cap_copy(ep, caller.cs, syscall_abi::RIGHTS_EP_SEND)
        .map_err(|_| "sync_ipc_placement: cap_copy endpoint failed")?;
    // SAFETY: entry 1 is the caller's alone; it has not started, and the
    // previous case's caller has been deleted.
    let arg = unsafe {
        CHILD_ARGS.publish(
            1,
            ChildArgs {
                cap: caller_done,
                ep: caller_ep,
                slot: 1,
            },
        )
    };
    start(caller, caller_entry, 1, arg, K)?;

    let mut finished = false;
    for _ in 0..crate::scaled_polls(DONE_POLLS)
    {
        if notification_wait_timeout(done, 1).is_ok_and(|bits| bits != 0)
        {
            finished = true;
            break;
        }
    }
    if !finished
    {
        return Err("sync_ipc_placement: the caller never finished its rounds");
    }
    if CHILD_ERRORS.load(Ordering::Acquire) != 0
    {
        return Err("sync_ipc_placement: a child syscall failed");
    }
    check(case)
}

/// Check each round of `case` against the counts its server recorded.
fn check(case: Case) -> TestResult
{
    let mut on_k = 0u32;
    let mut counted = 0u32;
    for (((ran_on, reached), local), pulled) in RAN_ON.iter().zip(&REACHED).zip(&LOCAL).zip(&PULLED)
    {
        let cpu = ran_on.load(Ordering::Acquire);
        let reached = reached.load(Ordering::Acquire);
        let local = local.load(Ordering::Acquire);
        let pulled = pulled.load(Ordering::Acquire);
        if cpu == K
        {
            on_k = on_k.saturating_add(1);
        }
        if reached > 1 || local > reached
        {
            return Err(
                "sync_ipc_placement: the rule's counts moved by more than a round's one wake",
            );
        }
        if !case.on_k && cpu == K && pulled == 0
        {
            return Err(
                "sync_ipc_placement: a call ran its server on the caller's CPU past the guard",
            );
        }
        if reached == 0
        {
            continue;
        }
        counted = counted.saturating_add(1);
        if case.on_k && local == 0
        {
            return Err(
                "sync_ipc_placement: a call the rule allows was not placed on the caller's CPU",
            );
        }
        if !case.on_k && local != 0
        {
            return Err("sync_ipc_placement: the rule placed a guarded call on the caller's CPU");
        }
        if case.on_k && cpu != K && pulled == 0
        {
            crate::log_args(format_args!(
                "ktest: sync_ipc_placement {}: a server placed on the caller's CPU ran on CPU {cpu}",
                case.name
            ));
            return Err(
                "sync_ipc_placement: a wake placed on the caller's CPU ran elsewhere unpulled",
            );
        }
    }
    crate::log_args(format_args!(
        "ktest: sync_ipc_placement {}: rounds counted={counted} excluded={} on_caller_cpu={on_k}",
        case.name,
        ROUNDS.saturating_sub(counted)
    ));
    if case.on_k && counted == 0
    {
        return Err("sync_ipc_placement: no round of a case the rule allows reached the rule");
    }
    Ok(())
}

/// The server's [`COUNTED_VIEWS`] of its own placement, `None` when a read
/// fails.
#[expect(
    clippy::cast_possible_truncation,
    reason = "each count is a 32-bit counter"
)]
fn counts(me: u64) -> Option<[u32; 3]>
{
    let mut out = [0u32; 3];
    for (slot, &view) in out.iter_mut().zip(&COUNTED_VIEWS)
    {
        *slot = syscall::cap_info_thread_placement(me, view).ok()? as u32;
    }
    Some(out)
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

/// Each round: pin to P and run there, clear the affinity (the server stays on
/// P until it parks), read its placement counts, publish the round, receive,
/// record the counts' differences across the receive, and reply with the CPU
/// the receive returned on. Runs until a receive fails; its case deletes it,
/// parked.
extern "C" fn server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for the server.
    let ChildArgs { cap: me, ep, slot } = unsafe { spawn::child_args(arg) };
    let fail = || {
        CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
    };
    let Some(buf) = ipc_buffer(slot)
    else
    {
        fail();
        thread_exit()
    };
    let mut round = 0u32;
    loop
    {
        round = round.saturating_add(1);
        if thread_set_affinity(me, P).is_err() || !reach(P)
        {
            fail();
        }
        if thread_set_affinity(me, AFFINITY_ANY).is_err()
        {
            fail();
        }
        let before = counts(me);
        PARKING.store(round, Ordering::Release);
        // SAFETY: buf is this thread's registered IPC buffer.
        if unsafe { ipc::ipc_recv(ep, buf) }.is_err()
        {
            break;
        }
        let cpu = current_cpu();
        match (before, counts(me))
        {
            (Some(before), Some(after)) =>
            {
                record(round, before, after);
            }
            _ => fail(),
        }
        let reply = IpcMessage::new(u64::from(cpu));
        // SAFETY: as for the receive.
        if unsafe { ipc::ipc_reply(&reply, buf) }.is_err()
        {
            fail();
        }
    }
    thread_exit()
}

/// Record round `round`'s count differences, `before` and `after` its
/// receive, in [`REACHED`], [`LOCAL`] and [`PULLED`]; a round past
/// [`ROUNDS`] records nothing.
fn record(round: u32, before: [u32; 3], after: [u32; 3])
{
    let Some(index) = round.checked_sub(1).and_then(|i| usize::try_from(i).ok())
    else
    {
        return;
    };
    for (counts, (b, a)) in [&REACHED, &LOCAL, &PULLED]
        .into_iter()
        .zip(before.into_iter().zip(after))
    {
        if let Some(count) = counts.get(index)
        {
            count.store(a.wrapping_sub(b), Ordering::Release);
        }
    }
}

/// Each round: wait for the server to announce its park, give its switch-out
/// [`SETTLE_MS`], call, and record the CPU the reply names; then report on
/// `done`.
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for the caller.
    let ChildArgs {
        cap: done,
        ep,
        slot,
    } = unsafe { spawn::child_args(arg) };
    let fail = || {
        CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
    };
    let Some(buf) = ipc_buffer(slot)
    else
    {
        fail();
        let _ = notification_send(done, 1);
        thread_exit()
    };
    let request = IpcMessage::new(0);
    for (round, ran_on) in (1..=ROUNDS).zip(&RAN_ON)
    {
        let mut parking = false;
        for _ in 0..crate::scaled_polls(PARK_POLLS)
        {
            if PARKING.load(Ordering::Acquire) == round
            {
                parking = true;
                break;
            }
            let _ = thread_sleep(1);
        }
        if !parking
        {
            fail();
            break;
        }
        let _ = thread_sleep(SETTLE_MS);
        // SAFETY: buf is this thread's registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(ep, &request, buf) })
        else
        {
            fail();
            break;
        };
        ran_on.store(
            u32::try_from(reply.label).unwrap_or(u32::MAX),
            Ordering::Release,
        );
    }
    let _ = notification_send(done, 1);
    thread_exit()
}

/// Yield in a loop on the pinned CPU, so a thread is queued there whenever
/// another runs.
extern "C" fn spinner_entry(_arg: u64) -> !
{
    loop
    {
        let _ = thread_yield();
    }
}
