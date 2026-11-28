// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/reply_recv_placement.rs

//! Integration: `SYS_IPC_REPLY_RECV` wakes its fair caller after its receive
//! has decided: onto the server's CPU, where it runs at once, when the
//! receive parks; and into the front of the fair queue of that CPU, where it
//! runs when the server blocks and the server runs on first, when the receive
//! binds a queued caller (core/kernel/docs/scheduler.md § Service Call
//! Latency).
//!
//! ## The hazard
//!
//! A reply wake placed without knowing what the server does next sends the
//! caller away from a CPU the server is about to leave idle. A reply wake
//! that links the caller at the tail of a queue, the server's or another
//! CPU's, makes it wait a slice of each fair thread queued there; one that
//! yields the server's CPU to it leaves the queued callers waiting on it.
//!
//! ## How this exercises it
//!
//! Needs 3 CPUs and the `SchedControl` cap (skips otherwise). The harness
//! pins itself to CPU 0. A server pinned to P (CPU 1) serves a caller C of
//! its own fair level with `ipc_reply_recv`, [`ROUNDS`] calls per [`Case`]:
//!
//! - parks: C, last run on K (CPU 2), calls; the server's reply-and-receive
//!   finds no other caller and parks.
//! - binds: C, last run on P, calls; a second caller pinned to K calls while
//!   the server holds C's request, so the reply-and-receive binds it.
//! - runs on: as binds, with C pinned to P.
//!
//! Around each call C reads its own placement counts
//! (`CAP_INFO_THREAD_PLACEMENT`): the wakes that reached the synchronous wake
//! rule, those it placed on the waker's CPU, and the load balancer's pulls.
//! It records them with the CPU its call returned on. In the runs-on case, C
//! and the server each mark the round as they return from it, and the first
//! mark stands.
//!
//! ## Pass criterion
//!
//! - parks: every round whose wake reached the rule is placed on P and runs
//!   there unless pulled, and some round reaches the rule.
//! - binds: every round runs on P unless pulled, no round reaches the rule
//!   (a round that did found the second caller not yet queued and is
//!   excluded), and some round is counted.
//! - runs on: the server returns first in every round, and C returns on P.
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

/// The server's CPU.
const P: u32 = 1;

/// The second caller's CPU, and the parks case's caller's before each call.
const K: u32 = 2;

/// The harness's CPU, away from K and P.
const HARNESS_CPU: u32 = 0;

/// The fair level of every thread of a case.
const FAIR: u8 = 10;

/// `SYS_THREAD_SET_AFFINITY`'s value clearing a hard affinity.
const AFFINITY_ANY: u32 = u32::MAX;

/// Yields a thread takes to reach its pinned CPU.
const MAX_YIELDS: u32 = 64;

/// 1 ms waits a thread gives another to reach a step, and the harness gives
/// the caller to finish; applied through [`crate::scaled_polls`].
const STEP_POLLS: u32 = 2_000;
const DONE_POLLS: u32 = 4_000;

/// Milliseconds the server holds a request before its reply-and-receive: for
/// the caller's switch-out to complete, and for the second caller's call to
/// queue.
const SETTLE_MS: u64 = 2;

/// Who marked a round first in the runs-on case.
const FIRST_CALLER: u32 = 1;
const FIRST_SERVER: u32 = 2;

/// One case: where C runs before each call, and whether a second caller
/// queues while the server holds C's request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case
{
    Parks,
    Binds,
    RunsOn,
}

impl Case
{
    fn name(self) -> &'static str
    {
        match self
        {
            Self::Parks => "parks",
            Self::Binds => "binds",
            Self::RunsOn => "runs on",
        }
    }

    /// Whether a second caller queues during each round.
    fn second_caller(self) -> bool
    {
        self != Self::Parks
    }
}

const CASES: [Case; 3] = [Case::Parks, Case::Binds, Case::RunsOn];

/// The case running, as its index in [`CASES`].
static CASE: AtomicU32 = AtomicU32::new(0);

/// The round whose request the server holds, and the round the second
/// caller has called for (1-based; 0 before the first).
static HOLDING: AtomicU32 = AtomicU32::new(0);
static SECOND_CALLED: AtomicU32 = AtomicU32::new(0);

/// The CPU C's call returned on, each round.
static RAN_ON: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(u32::MAX) }; ROUNDS as usize];

/// C's placement counts across each round's call, as differences: the wakes
/// that reached the synchronous wake rule, those it placed on the waker's CPU,
/// and the load balancer's pulls.
static REACHED: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];
static LOCAL: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];
static PULLED: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];

/// The first mark of each round of the runs-on case.
static FIRST: [AtomicU32; ROUNDS as usize] = [const { AtomicU32::new(0) }; ROUNDS as usize];

/// The `CAP_INFO_THREAD_PLACEMENT` views C reads around a call, in the order
/// of [`REACHED`], [`LOCAL`] and [`PULLED`].
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
    /// C's copy of its own Thread cap and of `done`; unused otherwise.
    me: u64,
    done: u64,
    /// Its copy of the endpoint.
    ep: u64,
    /// Its slot: its stack and IPC page.
    slot: usize,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 3> = spawn::ArgBlock::new(ChildArgs {
    me: 0,
    done: 0,
    ep: 0,
    slot: 0,
});

/// Stacks and IPC pages: the server on 0, C on 1, the second caller on 2.
static mut STACKS: [ChildStack; 3] = [const { ChildStack::ZERO }; 3];
static mut IPC_PAGES: [crate::IpcPage; 3] = [const { crate::IpcPage::ZERO }; 3];

/// The slots of the three children.
const SERVER: usize = 0;
const CALLER: usize = 1;
const SECOND: usize = 2;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "reply_recv_placement: system_info(CpuCount) failed")?;
    if cpus < 3
    {
        crate::log("ktest: reply_recv_placement SKIP (needs 3 CPUs)");
        return Ok(());
    }
    if ctx.sched_control_cap == 0
    {
        crate::log("ktest: reply_recv_placement SKIP (no SchedControl cap in initial cap set)");
        return Ok(());
    }
    let result = thread_set_affinity(ctx.thread_cap, HARNESS_CPU)
        .map_err(|_| "reply_recv_placement: pin failed")
        .and_then(|()| {
            if reach(HARNESS_CPU)
            {
                Ok(())
            }
            else
            {
                Err("reply_recv_placement: the harness never ran on its CPU")
            }
        })
        .and_then(|()| {
            CASES
                .iter()
                .enumerate()
                .try_for_each(|(index, &case)| run_case(ctx, index, case))
        });
    let restored = thread_set_affinity(ctx.thread_cap, AFFINITY_ANY);
    result?;
    restored.map_err(|_| "reply_recv_placement: restore affinity failed")
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

/// Wait in 1 ms sleeps, up to [`STEP_POLLS`] scaled, until `value` reads
/// `round`.
fn wait_for(value: &AtomicU32, round: u32) -> bool
{
    for _ in 0..crate::scaled_polls(STEP_POLLS)
    {
        if value.load(Ordering::Acquire) == round
        {
            return true;
        }
        let _ = thread_sleep(1);
    }
    false
}

/// Run one case with its own endpoint, children and `done` notification.
fn run_case(ctx: &TestContext, index: usize, case: Case) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "reply_recv_placement: cap_create_endpoint failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(ep);
        return Err("reply_recv_placement: cap_create_notification failed");
    };
    let mut children = [const { spawn::SpawnedChild::EMPTY }; 3];
    let result = rounds(ctx, index, case, ep, done, &mut children);
    for child in &mut children
    {
        let _ = child.delete_thread();
        let _ = child.delete_cspace();
    }
    let deleted_done = cap_delete(done);
    let deleted_ep = cap_delete(ep);
    result?;
    deleted_done.map_err(|_| "reply_recv_placement: cap_delete done failed")?;
    deleted_ep.map_err(|_| "reply_recv_placement: cap_delete endpoint failed")
}

/// Spawn the child of `slot` at the fair level, give it `ep` with
/// `ep_rights`, and start it on `entry`, pinned to `cpu`; `me` and `done`
/// give it a copy of its own Thread cap and of `done` when set.
#[expect(
    clippy::too_many_arguments,
    reason = "one child's whole set-up; a struct would only restate the arguments"
)]
fn start_child(
    ctx: &TestContext,
    child: &mut spawn::SpawnedChild,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
    ep: u64,
    ep_rights: u64,
    done: Option<u64>,
    cpu: u32,
) -> TestResult
{
    *child = spawn::new_child_at(ctx, ctx.sched_control_cap, FAIR)
        .map_err(|_| "reply_recv_placement: spawn child failed")?;
    let me = if done.is_some()
    {
        cap_copy(child.th, child.cs, syscall_abi::RIGHTS_THREAD_CONTROL)
            .map_err(|_| "reply_recv_placement: cap_copy thread failed")?
    }
    else
    {
        0
    };
    let done = match done
    {
        Some(done) => cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "reply_recv_placement: cap_copy done failed")?,
        None => 0,
    };
    let ep = cap_copy(ep, child.cs, ep_rights)
        .map_err(|_| "reply_recv_placement: cap_copy endpoint failed")?;
    // SAFETY: entry `slot` is this child's alone; it has not started, and the
    // previous case's child of the slot has been deleted.
    let arg = unsafe { CHILD_ARGS.publish(slot, ChildArgs { me, done, ep, slot }) };
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), slot) }?;
    // SAFETY: the stack is this test's own `STACKS` slot, on which no other
    // live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(child, entry, stack, arg, cpu) }
        .map_err(|_| "reply_recv_placement: start child failed")
}

/// Start the case's threads, wait for C's rounds, and check them.
fn rounds(
    ctx: &TestContext,
    index: usize,
    case: Case,
    ep: u64,
    done: u64,
    children: &mut [spawn::SpawnedChild; 3],
) -> TestResult
{
    CASE.store(u32::try_from(index).unwrap_or(0), Ordering::Release);
    HOLDING.store(0, Ordering::Release);
    SECOND_CALLED.store(0, Ordering::Release);
    CHILD_ERRORS.store(0, Ordering::Release);
    for ran_on in &RAN_ON
    {
        ran_on.store(u32::MAX, Ordering::Release);
    }
    for count in REACHED.iter().chain(&LOCAL).chain(&PULLED).chain(&FIRST)
    {
        count.store(0, Ordering::Release);
    }
    let [server, caller, second] = children;
    start_child(
        ctx,
        server,
        SERVER,
        server_entry,
        ep,
        syscall_abi::RIGHTS_EP_RECEIVE,
        None,
        P,
    )?;
    if case.second_caller()
    {
        start_child(
            ctx,
            second,
            SECOND,
            second_entry,
            ep,
            syscall_abi::RIGHTS_EP_SEND,
            None,
            K,
        )?;
    }
    let first_cpu = if case == Case::Parks { K } else { P };
    start_child(
        ctx,
        caller,
        CALLER,
        caller_entry,
        ep,
        syscall_abi::RIGHTS_EP_SEND,
        Some(done),
        first_cpu,
    )?;

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
        return Err("reply_recv_placement: the caller never finished its rounds");
    }
    if CHILD_ERRORS.load(Ordering::Acquire) != 0
    {
        return Err("reply_recv_placement: a child syscall failed");
    }
    check(case)
}

/// Check each round of `case` against the counts C recorded.
fn check(case: Case) -> TestResult
{
    let mut counted = 0u32;
    for (((ran_on, reached), local), (pulled, first)) in RAN_ON
        .iter()
        .zip(&REACHED)
        .zip(&LOCAL)
        .zip(PULLED.iter().zip(&FIRST))
    {
        let cpu = ran_on.load(Ordering::Acquire);
        let reached = reached.load(Ordering::Acquire);
        let local = local.load(Ordering::Acquire);
        let pulled = pulled.load(Ordering::Acquire);
        if reached > 1 || local > reached
        {
            return Err(
                "reply_recv_placement: the rule's counts moved by more than a round's one wake",
            );
        }
        match case
        {
            Case::Parks =>
            {
                if reached == 0
                {
                    continue;
                }
                if local == 0
                {
                    return Err(
                        "reply_recv_placement: a reply whose receive parked was not placed on \
                         the server's CPU",
                    );
                }
                if cpu != P && pulled == 0
                {
                    return Err(
                        "reply_recv_placement: a caller placed on the server's CPU ran elsewhere \
                         unpulled",
                    );
                }
            }
            Case::Binds =>
            {
                if reached != 0
                {
                    continue;
                }
                if cpu != P && pulled == 0
                {
                    return Err(
                        "reply_recv_placement: a reply whose receive bound a caller ran its \
                         caller off the server's CPU unpulled",
                    );
                }
            }
            Case::RunsOn =>
            {
                if first.load(Ordering::Acquire) != FIRST_SERVER
                {
                    return Err(
                        "reply_recv_placement: a server whose receive bound a caller did not \
                         run on ahead of the caller it replied to",
                    );
                }
                if cpu != P
                {
                    return Err(
                        "reply_recv_placement: a caller pinned to the server's CPU returned \
                         elsewhere",
                    );
                }
            }
        }
        counted = counted.saturating_add(1);
    }
    crate::log_args(format_args!(
        "ktest: reply_recv_placement {}: rounds counted={counted} excluded={}",
        case.name(),
        ROUNDS.saturating_sub(counted)
    ));
    if counted == 0
    {
        return Err("reply_recv_placement: no round of a case was counted");
    }
    Ok(())
}

/// C's [`COUNTED_VIEWS`] of its own placement, `None` when a read fails.
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

/// Count a child syscall failure.
fn fail()
{
    CHILD_ERRORS.fetch_add(1, Ordering::AcqRel);
}

/// The 0-based index of round `round`, `None` past [`ROUNDS`].
fn index_of(round: u64) -> Option<usize>
{
    let index = usize::try_from(round.checked_sub(1)?).ok()?;
    (index < ROUNDS as usize).then_some(index)
}

/// The server: receive once, then serve every request with a
/// reply-and-receive. C's request names its round; the server holds it
/// [`SETTLE_MS`] after the second caller (when the case has one) has called,
/// then marks the round in the runs-on case once its reply-and-receive
/// returns. The second caller's request (round 0) is answered at once. Runs
/// until a receive fails; its case deletes it, parked.
extern "C" fn server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for the server.
    let ChildArgs { ep, slot, .. } = unsafe { spawn::child_args(arg) };
    let Some(buf) = ipc_buffer(slot)
    else
    {
        fail();
        thread_exit()
    };
    let case = CASES
        .get(CASE.load(Ordering::Acquire) as usize)
        .copied()
        .unwrap_or(Case::Parks);
    // SAFETY: buf is this thread's registered IPC buffer.
    let Ok(mut request) = (unsafe { ipc::ipc_recv(ep, buf) })
    else
    {
        thread_exit()
    };
    loop
    {
        let round = request.label;
        if round != 0
        {
            HOLDING.store(u32::try_from(round).unwrap_or(0), Ordering::Release);
            if case.second_caller() && !wait_for(&SECOND_CALLED, u32::try_from(round).unwrap_or(0))
            {
                fail();
            }
            let _ = thread_sleep(SETTLE_MS);
        }
        let reply = IpcMessage::new(0);
        // SAFETY: as for the receive.
        let Ok(next) = (unsafe { ipc::ipc_reply_recv(ep, &reply, buf, 0) })
        else
        {
            break;
        };
        if round != 0
            && case == Case::RunsOn
            && let Some(first) = index_of(round).and_then(|i| FIRST.get(i))
        {
            let _ = first.compare_exchange(0, FIRST_SERVER, Ordering::AcqRel, Ordering::Acquire);
        }
        request = next;
    }
    thread_exit()
}

/// C: each round, run on its case's CPU (pinned there for the runs-on case,
/// left unpinned after reaching it otherwise), read its placement counts,
/// call with the round as label, record the CPU the call returned on and the
/// counts' differences, and mark the round; then report on `done`.
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for C.
    let ChildArgs { me, done, ep, slot } = unsafe { spawn::child_args(arg) };
    let Some(buf) = ipc_buffer(slot)
    else
    {
        fail();
        let _ = notification_send(done, 1);
        thread_exit()
    };
    let case = CASES
        .get(CASE.load(Ordering::Acquire) as usize)
        .copied()
        .unwrap_or(Case::Parks);
    let home = if case == Case::Parks { K } else { P };
    for round in 1..=ROUNDS
    {
        if thread_set_affinity(me, home).is_err() || !reach(home)
        {
            fail();
        }
        if case != Case::RunsOn && thread_set_affinity(me, AFFINITY_ANY).is_err()
        {
            fail();
        }
        let before = counts(me);
        // SAFETY: buf is this thread's registered IPC buffer.
        if unsafe { ipc::ipc_call(ep, &IpcMessage::new(u64::from(round)), buf) }.is_err()
        {
            fail();
            break;
        }
        let cpu = current_cpu();
        let Some(index) = index_of(u64::from(round))
        else
        {
            break;
        };
        if let Some(first) = FIRST.get(index)
        {
            let _ = first.compare_exchange(0, FIRST_CALLER, Ordering::AcqRel, Ordering::Acquire);
        }
        if let Some(ran_on) = RAN_ON.get(index)
        {
            ran_on.store(cpu, Ordering::Release);
        }
        match (before, counts(me))
        {
            (Some(before), Some(after)) =>
            {
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
            _ => fail(),
        }
    }
    let _ = notification_send(done, 1);
    thread_exit()
}

/// The second caller: each round, once the server holds C's request, call.
extern "C" fn second_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `rounds` published for the second caller.
    let ChildArgs { ep, slot, .. } = unsafe { spawn::child_args(arg) };
    let Some(buf) = ipc_buffer(slot)
    else
    {
        fail();
        thread_exit()
    };
    for round in 1..=ROUNDS
    {
        if !wait_for(&HOLDING, round)
        {
            fail();
            break;
        }
        SECOND_CALLED.store(round, Ordering::Release);
        // SAFETY: buf is this thread's registered IPC buffer.
        if unsafe { ipc::ipc_call(ep, &IpcMessage::new(0), buf) }.is_err()
        {
            fail();
            break;
        }
    }
    thread_exit()
}
