// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/reply_caller_delete.rs

//! Stress: a server replies to its bound caller while another CPU deletes
//! that caller's last Thread capability, so the reply's claim of the caller
//! races the caller's `dealloc_object(Thread)`.
//!
//! ## The hazard
//!
//! `SYS_IPC_REPLY` reaches its caller only through the server's reply
//! binding, `reply_tcb`, which holds no reference on the caller's TCB. A
//! concurrent `dealloc_object(Thread)` of the caller claims the same binding
//! (its `BlockedOnReply` / `BlockedOnFault` arm CASes `reply_tcb` to null) and
//! then frees the TCB. The reply's claim (the `reply_tcb` CAS in
//! `endpoint_reply`) is what keeps the caller live: once the reply wins it,
//! the caller's `wake_in_flight` pin holds the dealloc off until the reply's
//! wake. Before the fix `sys_ipc_reply` read the caller ahead of that claim
//! at two sites: the fault-reply peek (`(*caller).ipc_state`) and the cap
//! pre-allocation peek (`magic`, `cspace_id`, `cspace_epoch`), so a dealloc
//! that won the binding in between let the reply read a freed, possibly
//! reused TCB (#513). The reply now claims first and reads the caller only
//! under its claim (core/kernel/src/syscall/ipc.rs `sys_ipc_reply`;
//! core/kernel/docs/ipc-internals.md § Reply Path).
//!
//! ## How this exercises it
//!
//! Each round binds a fresh caller to a fresh server through a fresh
//! endpoint, in one of three kinds that rotate by round: a call answered with
//! a reply carrying one capability (the pre-allocation path), a call answered
//! with a reply carrying one data word, and a fault (the caller stores to an
//! unmapped VA, with the endpoint bound as its fault handler) answered with a
//! `FAULT_REPLY_RESUME` fault reply (the fault-reply path; a resumed faulter
//! faults again and queues on the endpoint, which no one receives on any
//! more, until its delete, so no fault is ever terminal and none is logged
//! as a userspace fault kill). The controller,
//! pinned to CPU 0, spawns the caller on CPU 2 and, once the caller reports
//! it is about to call or fault, the server on CPU 1. The server receives,
//! reports the binding armed, spins a varying delay (up to about 2^16 spins),
//! and replies. The controller, on the armed report, spins its own varying
//! delay (up to about 2^12 spins) and deletes the caller's Thread capability,
//! its last: the caller runs in its own `CSpace`, which the controller keeps
//! alive until the round ends, but only the controller holds a capability to
//! its thread. The two delays sweep the delete from before the reply's claim
//! to after the caller has resumed with the reply.
//!
//! Every round also takes one of three orders, rotating independently of the
//! kind. A race round runs the sweep above. A reply-first round has the
//! controller wait for the server's reply result before it deletes. A
//! delete-first round has the server wait, once armed, for the controller's
//! `go` signal, which the controller sends after its delete has returned. The
//! two steered orders reach both sides of the claim on every run, whatever
//! the timing; the race rounds land the delete inside the claim's window as
//! often as the host's timing allows.
//!
//! The server classifies its reply: `Ok` (it claimed the caller first) or
//! `InvalidCapability` (the delete's dealloc claimed the binding first, so no
//! caller was bound); anything else is bad. For the capability kind it then
//! checks that the transferred capability left its `CSpace` exactly when the
//! reply returned `Ok`. A caller whose call returns (the delete landed after
//! its resume) checks the reply it received. Required: every reply returned
//! `Ok` or `InvalidCapability`; the capability moved exactly on `Ok`; every
//! call that returned carried the server's reply, and only in a round whose
//! reply returned `Ok`; every reply-first round's reply returned `Ok` (the
//! caller was still bound); and every delete-first round's reply returned
//! `InvalidCapability` (the dealloc claimed the binding before the reply
//! ran). The race rounds' split between the two outcomes is logged, not
//! required: under TCG on a 4-vCPU runner the vCPUs' relative progress can
//! land every race round's delete on one side of the claim, so a one-sided
//! sweep is the host's timing rather than a kernel defect, and the steered
//! rounds already reach both sides. Such a sweep is logged as a note.
//!
//! A reply that read a freed caller before its claim has no userspace
//! signature of its own; the kernel's tripwires (the `TCB_MAGIC` debug
//! assertions on the claimed caller, a freed object's lock) catch it
//! whenever a race round lands the delete inside the claim's window.
//!
//! Needs **≥ 3 CPUs** (the controller's delete, the server's reply, and the
//! caller each on their own CPU).

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_info, ipc_buffer_set,
    notification_send, notification_wait, notification_wait_timeout, system_info, thread_exit,
    thread_set_affinity,
};
use syscall_abi::{
    CAP_INFO_TAG_RIGHTS, FAULT_LABEL, FAULT_REPLY_RESUME, RIGHTS_ALL, RIGHTS_EP_RECEIVE,
    RIGHTS_EP_SEND_GRANT, SyscallError, SystemInfoType,
};

use crate::tally::{BadTally, await_report};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::reply_caller_delete";

/// Rounds to run, rotating over the three kinds and the four order slots
/// ([`ORDERS`]); half are race rounds, so a full-width run races the reply
/// against the delete 600 times.
const CYCLES: u32 = 1200;

/// Fewest rounds at any width ([`super::scaled_attempts`]): 96 rounds give
/// each kind 8 reply-first, 8 delete-first and 16 race rounds, so every
/// (kind, steered order) check runs several times.
const MIN_CYCLES: u32 = 96;

/// The controller's, the server's, and the caller's CPUs.
const CONTROLLER_CPU: u32 = 0;
const SERVER_CPU: u32 = 1;
const CALLER_CPU: u32 = 2;

/// CPUs needed: one each for the controller, the server, and the caller.
const MIN_CPUS: u64 = 3;

/// Unmapped user VA the faulting caller stores to; canonical in every paging
/// mode (below the 2^38 Sv39 user half). Distinct from other tests' VAs.
const RESERVED_VA: u64 = 0x3E_9000_0000;

/// Badge bound with the fault handler.
const FAULT_BADGE: u64 = 0xC0FF_EE0D;

/// Label of the caller's call, and of the server's reply to it.
const CALL_LABEL: u64 = 0x5EC5;
const REPLY_LABEL: u64 = 0x5EC6;
/// The data word the data-kind reply carries.
const REPLY_WORD: u64 = 0xD00D_F00D_0000_0513;

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;
/// Notification WAIT right — what the server needs to wait on `go`.
const RIGHTS_WAIT: u64 = syscall_abi::RIGHTS_NTF_WAIT;

/// The caller is about to call (or fault).
const BIT_CALLING: u64 = 1 << 0;
/// The server has received the caller: its reply binding is armed.
const BIT_ARMED: u64 = 1 << 1;
/// The server's reply returned `Ok`.
const BIT_REPLY_OK: u64 = 1 << 2;
/// The server's reply returned `InvalidCapability`: no caller was bound.
const BIT_REPLY_GONE: u64 = 1 << 3;
/// The server saw something else (tallied with its result word).
const BIT_SERVER_BAD: u64 = 1 << 4;
/// The caller's call returned the server's reply.
const BIT_CALLER_REPLIED: u64 = 1 << 5;
/// The caller's call returned anything else (tallied with its result word).
const BIT_CALLER_BAD: u64 = 1 << 6;
const SERVER_VERDICT: u64 = BIT_REPLY_OK | BIT_REPLY_GONE | BIT_SERVER_BAD;

/// The round kinds, rotating by round.
const KIND_CAP: u32 = 0;
const KIND_DATA: u32 = 1;
const KIND_FAULT: u32 = 2;
const KINDS: u32 = 3;

/// The orders a round takes, rotating by `cycle / KINDS` so every kind
/// meets every order: two race slots, one reply-first, one delete-first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Order
{
    /// The controller's and the server's delays sweep the delete across the
    /// reply.
    Race,
    /// The controller deletes only after the server reported its reply's
    /// result: the reply must return `Ok`.
    ReplyFirst,
    /// The server replies only after the controller's delete returned: the
    /// reply must return `InvalidCapability`.
    DeleteFirst,
}

/// The order rotation, indexed by `(cycle / KINDS) % ORDERS.len()`.
const ORDERS: [Order; 4] = [
    Order::Race,
    Order::ReplyFirst,
    Order::Race,
    Order::DeleteFirst,
];

/// Stress stack indices of the server and the caller.
const SERVER_STACK: usize = 0;
const CALLER_STACK: usize = 1;

/// The server's results outside the accepted set: a reply that returned
/// neither `Ok` nor `InvalidCapability`, a capability that did not move
/// exactly on `Ok`, or a receive that failed or returned the wrong message.
static BAD_SERVER: BadTally = BadTally::new();
/// The caller's calls that returned anything but the server's reply.
static BAD_CALLER: BadTally = BadTally::new();

/// A child's IPC buffer page (one live user each).
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);
// SAFETY: used only by the round's server, of which one runs at a time.
static mut SERVER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);
// SAFETY: used only by the round's caller, of which one runs at a time.
static mut CALLER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

/// The server's arguments, handed to its entry by address.
#[derive(Clone, Copy)]
struct ServerArgs
{
    ep: u32,
    done: u32,
    /// The controller's signal that its delete returned (delete-first
    /// rounds only; 0 for the other orders).
    go: u32,
    /// The capability the cap-kind reply transfers (0 for the other kinds).
    gift: u32,
    kind: u32,
    /// Spins between the armed report and the reply.
    delay: u32,
}

static SERVER_ARGS: spawn::ArgBlock<ServerArgs, 1> = spawn::ArgBlock::new(ServerArgs {
    ep: 0,
    done: 0,
    go: 0,
    gift: 0,
    kind: 0,
    delay: 0,
});

/// Per-run outcome counts of the race rounds (a steered round's outcome is
/// fixed by its order and checked in that round).
#[derive(Default)]
struct Outcomes
{
    replied: u32,
    gone: u32,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::reply_caller_delete: system_info(CpuCount) failed")?;
    if cpus < MIN_CPUS
    {
        crate::log("ktest: stress::reply_caller_delete SKIP (need 3+ CPUs)");
        return Ok(());
    }
    BAD_SERVER.reset();
    BAD_CALLER.reset();
    thread_set_affinity(ctx.thread_cap, CONTROLLER_CPU)
        .map_err(|_| "stress::reply_caller_delete: pin controller failed")?;
    // Each round's spawns, deletes and cross-CPU wakes grow with the width;
    // the count shrinks with it.
    let count = super::scaled_attempts(CYCLES, MIN_CYCLES, cpus);
    let mut outcomes = Outcomes::default();
    let mut result = Ok(());
    for cycle in 0..count
    {
        if let Err(e) = one_round(ctx, cycle, &mut outcomes)
        {
            result = Err(e);
            break;
        }
    }
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "stress::reply_caller_delete: restore controller affinity failed");
    result?;
    restore?;

    BAD_SERVER.check(
        CELL,
        "stress::reply_caller_delete: a reply racing its caller's delete returned neither Ok \
         nor InvalidCapability, or its capability did not move exactly on Ok",
    )?;
    BAD_CALLER.check(
        CELL,
        "stress::reply_caller_delete: a call returned something other than the server's reply",
    )?;
    crate::tally::log_cell_u64(CELL, " race replied=", u64::from(outcomes.replied));
    crate::tally::log_cell_u64(CELL, " race gone=", u64::from(outcomes.gone));
    if outcomes.replied == 0 || outcomes.gone == 0
    {
        // A one-sided sweep is the host's timing (see the module doc); the
        // steered rounds already reached both sides of the claim.
        crate::log(
            "ktest: stress::reply_caller_delete note: every race round fell on one side of the \
             claim",
        );
    }
    Ok(())
}

/// The round's capabilities, reaped in [`reap`] whatever the round's result.
struct Round
{
    ep: u32,
    done: u32,
    /// The delete-first rounds' `go` notification (0 for the other orders).
    go: u32,
    gift: u32,
    caller: Option<spawn::SpawnedChild>,
    server: Option<spawn::SpawnedChild>,
}

/// One round: arm a reply binding, order the reply and the caller's delete
/// per the round's order (a race round races them), and check the outcome.
fn one_round(ctx: &TestContext, cycle: u32, outcomes: &mut Outcomes) -> TestResult
{
    let kind = cycle % KINDS;
    let order = ORDERS[(cycle / KINDS) as usize % ORDERS.len()];
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "stress::reply_caller_delete: create endpoint failed")?;
    let Ok(done) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(ep);
        return Err("stress::reply_caller_delete: create done failed");
    };
    let mut round = Round {
        ep,
        done,
        go: 0,
        gift: 0,
        caller: None,
        server: None,
    };
    let verdict = run_round(ctx, &mut round, kind, order, cycle);
    let reaped = reap(&mut round);
    let acc = verdict?;
    reaped?;
    classify(acc, order, outcomes)
}

/// Spawn the caller and the server, order the reply and the caller's delete
/// per `order` (a race round races them), and return every report bit the
/// round produced.
fn run_round(
    ctx: &TestContext,
    round: &mut Round,
    kind: u32,
    order: Order,
    cycle: u32,
) -> Result<u64, &'static str>
{
    let caller =
        spawn::new_child(ctx).map_err(|_| "stress::reply_caller_delete: spawn caller failed")?;
    let c_ep = cap_copy(round.ep, caller.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "stress::reply_caller_delete: cap_copy caller ep failed");
    let c_done = cap_copy(round.done, caller.cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::reply_caller_delete: cap_copy caller done failed");
    let th = caller.th;
    round.caller = Some(caller);
    let (c_ep, c_done) = (c_ep?, c_done?);
    let entry: extern "C" fn(u64) -> ! = if kind == KIND_FAULT
    {
        crate::bind_fault_handler(th, round.ep, FAULT_BADGE)
            .map_err(|_| "stress::reply_caller_delete: thread_set_fault_handler failed")?;
        faulter_entry
    }
    else
    {
        caller_entry
    };
    // SAFETY: the caller's stack index is this round's only user of it; the
    // previous round's caller was deleted before this one was spawned.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[CALLER_STACK]) });
    if let Some(caller) = round.caller.as_ref()
    {
        // SAFETY: the stack is `super::STRESS_STACKS[CALLER_STACK]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe {
            spawn::configure_and_start_pinned(
                caller,
                entry,
                stack,
                u64::from(c_ep) | (u64::from(c_done) << 32),
                CALLER_CPU,
            )
        }
        .map_err(|_| "stress::reply_caller_delete: start caller failed")?;
    }
    let mut acc = 0u64;
    await_report(
        round.done,
        &mut acc,
        BIT_CALLING,
        "stress::reply_caller_delete: the caller never reached its call",
    )?;

    if order == Order::DeleteFirst
    {
        round.go = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::reply_caller_delete: create go failed")?;
    }
    start_server(ctx, round, kind, cycle)?;
    await_report(
        round.done,
        &mut acc,
        BIT_ARMED,
        "stress::reply_caller_delete: the server never received the caller",
    )?;

    match order
    {
        Order::Race =>
        {
            // Sweep the delete across the server's reply: the server spins up
            // to about 2^16 iterations before replying, this up to about 2^12
            // before deleting, with independent per-round draws.
            for _ in 0..(cycle.wrapping_mul(2_654_435_761) >> 20)
            {
                core::hint::spin_loop();
            }
        }
        Order::ReplyFirst => await_report(
            round.done,
            &mut acc,
            SERVER_VERDICT,
            "stress::reply_caller_delete: reply-first: the server never reported its reply's \
             result",
        )?,
        Order::DeleteFirst =>
        {}
    }
    round
        .caller
        .as_mut()
        .map_or(Ok(()), spawn::SpawnedChild::delete_thread)
        .map_err(|_| "stress::reply_caller_delete: delete caller thread failed")?;
    if order == Order::DeleteFirst
    {
        // The delete returned, so the caller's dealloc has claimed the reply
        // binding: release the server to reply with no caller bound.
        notification_send(round.go, 1)
            .map_err(|_| "stress::reply_caller_delete: delete-first: signal go failed")?;
    }

    await_report(
        round.done,
        &mut acc,
        SERVER_VERDICT,
        "stress::reply_caller_delete: the server never reported its reply's result",
    )?;
    // The caller is off every CPU once its delete returned, so any report it
    // made is already pending: collect it without blocking (a 1 ms wait
    // returns at once when bits are pending).
    acc |= notification_wait_timeout(round.done, 1)
        .map_err(|_| "stress::reply_caller_delete: final report poll failed")?;
    Ok(acc)
}

/// Spawn and start the round's server, with the capability the cap-kind
/// reply transfers copied into its `CSpace`.
fn start_server(ctx: &TestContext, round: &mut Round, kind: u32, cycle: u32) -> TestResult
{
    let server =
        spawn::new_child(ctx).map_err(|_| "stress::reply_caller_delete: spawn server failed")?;
    let cs = server.cs;
    round.server = Some(server);
    let s_ep = cap_copy(round.ep, cs, RIGHTS_EP_RECEIVE)
        .map_err(|_| "stress::reply_caller_delete: cap_copy server ep failed")?;
    let s_done = cap_copy(round.done, cs, RIGHTS_SIGNAL)
        .map_err(|_| "stress::reply_caller_delete: cap_copy server done failed")?;
    let mut s_go = 0;
    if round.go != 0
    {
        s_go = cap_copy(round.go, cs, RIGHTS_WAIT)
            .map_err(|_| "stress::reply_caller_delete: cap_copy server go failed")?;
    }
    let mut s_gift = 0;
    if kind == KIND_CAP
    {
        round.gift = cap_create_notification(ctx.memory_base)
            .map_err(|_| "stress::reply_caller_delete: create gift failed")?;
        s_gift = cap_copy(round.gift, cs, RIGHTS_ALL)
            .map_err(|_| "stress::reply_caller_delete: cap_copy gift failed")?;
    }
    let args = ServerArgs {
        ep: s_ep,
        done: s_done,
        go: s_go,
        gift: s_gift,
        kind,
        delay: cycle.wrapping_mul(0x9E37_79B1) >> 16,
    };
    // SAFETY: entry 0 is the round's server's alone; the previous round's
    // server was deleted before this one starts.
    let arg = unsafe { SERVER_ARGS.publish(0, args) };
    // SAFETY: the server's stack index is this round's only user of it.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[SERVER_STACK]) });
    if let Some(server) = round.server.as_ref()
    {
        // SAFETY: the stack is `super::STRESS_STACKS[SERVER_STACK]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start_pinned(server, server_entry, stack, arg, SERVER_CPU) }
            .map_err(|_| "stress::reply_caller_delete: start server failed")?;
    }
    Ok(())
}

/// Delete every capability the round created. Deleting a Thread stops it
/// wherever it is, so the next round can reuse the stacks and buffers even
/// after a failed round.
fn reap(round: &mut Round) -> TestResult
{
    let mut deleted: [Result<(), i64>; 8] = [Ok(()); 8];
    if let Some(server) = round.server.as_mut()
    {
        deleted[0] = server.delete_thread();
        deleted[1] = server.delete_cspace();
    }
    if let Some(caller) = round.caller.as_mut()
    {
        deleted[2] = caller.delete_thread();
        deleted[3] = caller.delete_cspace();
    }
    if round.gift != 0
    {
        deleted[4] = cap_delete(round.gift);
    }
    deleted[5] = cap_delete(round.ep);
    deleted[6] = cap_delete(round.done);
    if round.go != 0
    {
        deleted[7] = cap_delete(round.go);
    }
    deleted
        .into_iter()
        .collect::<Result<(), i64>>()
        .map_err(|_| "stress::reply_caller_delete: reap failed")
}

/// Check the round's report bits against the accepted outcomes and, for a
/// steered `order`, against the outcome it fixes; count a race round's
/// outcome.
fn classify(acc: u64, order: Order, outcomes: &mut Outcomes) -> TestResult
{
    if acc & BIT_SERVER_BAD != 0
    {
        // The tally, checked at the end, carries the result word.
        return Ok(());
    }
    if acc & BIT_CALLER_REPLIED != 0 && acc & BIT_REPLY_OK == 0
    {
        return Err(
            "stress::reply_caller_delete: a caller received a reply its server's reply did not \
             deliver",
        );
    }
    match order
    {
        Order::Race =>
        {
            if acc & BIT_REPLY_OK != 0
            {
                outcomes.replied += 1;
            }
            if acc & BIT_REPLY_GONE != 0
            {
                outcomes.gone += 1;
            }
            Ok(())
        }
        Order::ReplyFirst if acc & BIT_REPLY_OK == 0 => Err(
            "stress::reply_caller_delete: reply-first: a reply made before its caller's delete \
             did not return Ok",
        ),
        Order::DeleteFirst if acc & BIT_REPLY_GONE == 0 => Err(
            "stress::reply_caller_delete: delete-first: a reply made after its caller's delete \
             returned did not return InvalidCapability",
        ),
        Order::ReplyFirst | Order::DeleteFirst => Ok(()),
    }
}

// cast_possible_truncation: packed fields are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn unpack(arg: u64) -> (u32, u32)
{
    ((arg & 0xFFFF_FFFF) as u32, (arg >> 32) as u32)
}

/// Server: receive the round's caller (arming the reply binding), report the
/// binding armed, wait for `go` in a delete-first round, spin the round's
/// delay, reply per the round's kind, and report the reply's result.
extern "C" fn server_entry(arg: u64) -> !
{
    // SAFETY: arg is SERVER_ARGS entry 0's address, published before the start.
    let args: ServerArgs = unsafe { spawn::child_args(arg) };
    let buf = core::ptr::addr_of_mut!(SERVER_IPC_BUF).cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        BAD_SERVER.record(0);
        notification_send(args.done, BIT_SERVER_BAD).ok();
        thread_exit()
    }
    // SAFETY: buf is this thread's registered IPC buffer.
    let msg = match unsafe { ipc::ipc_recv(args.ep, buf) }
    {
        Ok(msg) => msg,
        Err(e) =>
        {
            BAD_SERVER.record_error(e);
            notification_send(args.done, BIT_SERVER_BAD).ok();
            thread_exit()
        }
    };
    let expected = if args.kind == KIND_FAULT
    {
        FAULT_LABEL
    }
    else
    {
        CALL_LABEL
    };
    if msg.label != expected
    {
        BAD_SERVER.record(msg.label);
        notification_send(args.done, BIT_SERVER_BAD).ok();
        thread_exit()
    }
    // A child has no other channel to report on; a failed send fails the
    // controller's bounded wait for the bit.
    notification_send(args.done, BIT_ARMED).ok();
    if args.go != 0
        && let Err(e) = notification_wait(args.go)
    {
        BAD_SERVER.record_error(e);
        notification_send(args.done, BIT_SERVER_BAD).ok();
        thread_exit()
    }
    for _ in 0..args.delay
    {
        core::hint::spin_loop();
    }
    let reply = match args.kind
    {
        KIND_CAP => IpcMessage::builder(REPLY_LABEL).cap(args.gift).build(),
        KIND_DATA => IpcMessage::builder(REPLY_LABEL).word(0, REPLY_WORD).build(),
        _ => IpcMessage::new(FAULT_REPLY_RESUME),
    };
    // SAFETY: buf is this thread's registered IPC buffer.
    let bit = match unsafe { ipc::ipc_reply(&reply, buf) }
    {
        Ok(()) => BIT_REPLY_OK,
        Err(e) if e == SyscallError::InvalidCapability as i64 => BIT_REPLY_GONE,
        Err(e) =>
        {
            BAD_SERVER.record_error(e);
            BIT_SERVER_BAD
        }
    };
    let bit = if args.kind == KIND_CAP
    {
        check_gift(args.gift, bit)
    }
    else
    {
        bit
    };
    notification_send(args.done, bit).ok();
    thread_exit()
}

/// For the cap kind: the reply moves `gift` out of the server's `CSpace`
/// exactly when it returns `Ok`; a refused reply leaves it in place.
/// Returns `bit`, or [`BIT_SERVER_BAD`] (tallied) on a mismatch.
fn check_gift(gift: u32, bit: u64) -> u64
{
    let present = cap_info(gift, CAP_INFO_TAG_RIGHTS).is_ok();
    if present == (bit == BIT_REPLY_OK) && bit != BIT_SERVER_BAD
    {
        BAD_SERVER.record(bit);
        return BIT_SERVER_BAD;
    }
    bit
}

/// Caller: report the call, call the endpoint, and check that a returning
/// call carries the server's reply (one capability, or the data word).
extern "C" fn caller_entry(arg: u64) -> !
{
    let (ep, done) = unpack(arg);
    let buf = core::ptr::addr_of_mut!(CALLER_IPC_BUF).cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static above),
    // registered by one thread at a time; no Rust object lives in it, and the
    // thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        BAD_CALLER.record(0);
        notification_send(done, BIT_CALLER_BAD).ok();
        thread_exit()
    }
    // A failed send fails the controller's bounded wait for the bit.
    notification_send(done, BIT_CALLING).ok();
    // SAFETY: buf is this thread's registered IPC buffer.
    let bit = match unsafe { ipc::ipc_call(ep, &IpcMessage::new(CALL_LABEL), buf) }
    {
        Ok(reply)
            if reply.label == REPLY_LABEL
                && (reply.caps().len() == 1
                    || (reply.word_count() == 1 && reply.word(0) == REPLY_WORD)) =>
        {
            BIT_CALLER_REPLIED
        }
        Ok(reply) =>
        {
            BAD_CALLER.record(reply.label);
            BIT_CALLER_BAD
        }
        Err(e) =>
        {
            BAD_CALLER.record_error(e);
            BIT_CALLER_BAD
        }
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Faulting caller: report the fault, then store to the reserved VA. The
/// store faults and is delivered to the bound endpoint; after the server's
/// `FAULT_REPLY_RESUME` it re-executes, faults again, and stays queued on the
/// endpoint until the controller's delete ends the thread, so the store never
/// completes.
extern "C" fn faulter_entry(arg: u64) -> !
{
    let (_ep, done) = unpack(arg);
    // A failed send fails the controller's bounded wait for the bit.
    notification_send(done, BIT_CALLING).ok();
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — every fault is delivered to the bound
    // handler, and the thread's delete ends it while a fault is pending, so
    // the store never completes.
    unsafe {
        p.write_volatile(0x0513);
    }
    loop
    {
        core::hint::spin_loop();
    }
}
