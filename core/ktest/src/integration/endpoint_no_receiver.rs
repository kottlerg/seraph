// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/endpoint_no_receiver.rs

//! Integration: once no capability with the Receive right on an endpoint is
//! left, nothing waits on it for a receiver that can never come.
//!
//!   1. **`delete`** — a client's call is queued on an endpoint whose only
//!      Receive-right capability is the controller's. The controller deletes
//!      it (the client's Send copy keeps the endpoint alive): the queued call
//!      returns `NoReceiver`, and the client's next call fails at once with
//!      it.
//!   2. **`teardown`** — the only Receive-right capability sits in another
//!      `CSpace` (a holder with no thread). The client's call stays queued
//!      while it does; the teardown of the holder's `CSpace` then releases the
//!      call with `NoReceiver`, and the next call fails at once.
//!   3. **`parked_receivers`** — two receivers park on copies of the
//!      endpoint. The controller revokes the copies, which leaves its own
//!      Receive-right capability, so both stay parked; deleting that one
//!      releases both with `NoReceiver`.
//!   4. **`fault_queued`** and **`fault_immediate`** — a child bound to the
//!      endpoint faults while the fault is queued on it, or after its last
//!      Receive-right capability went: either way the fault is unhandled and
//!      the child exits with the standard fault exit reason.
//!
//! A queued call or fault is seen through a wait set holding the endpoint,
//! whose readiness a queued call raises. Runs on a single CPU (the children
//! are timer-preempted peers).

use syscall::{
    MsgRegs, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_revoke,
    notification_send, notification_wait_timeout, raw_ipc_call, raw_ipc_recv, thread_exit,
    thread_sleep, wait_set_add, wait_set_create, wait_set_wait_timeout,
};
use syscall_abi::{
    EXIT_FAULT_BASE, RIGHTS_EP_RECEIVE, RIGHTS_EP_SEND, RIGHTS_NTF_NOTIFY, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Per-child `done` bits; child `i`'s are shifted by `i * CHILD_SHIFT`.
/// Raised just before the child parks.
const BIT_READY: u64 = 1 << 0;
/// Raised when every wait returned `NoReceiver`.
const BIT_OK: u64 = 1 << 1;
/// Raised on any other result.
const BIT_BAD: u64 = 1 << 2;
const CHILD_SHIFT: u32 = 3;
const MAX_CHILDREN: usize = 2;

/// The wait-set badge of the endpoint.
const EP_BADGE: u64 = 0xE9;

/// Badge bound with the fault handler.
const FAULT_BADGE: u64 = 0xC0FF_EE1B;

/// Unmapped user VA the fault children touch; canonical in every paging mode
/// (below the 2^38 Sv39 user half). Distinct from other tests.
const RESERVED_VA: u64 = 0x3E_6000_0000;

/// Wall-clock settle after READY so a receiver has, in practice, reached its
/// park before the revoke, before `crate::scaled_bound`. A receiver that has
/// not meets its revoked handle (`InvalidCapability`) and reports BAD.
const SETTLE_SLEEP_MS: u64 = 20;

/// How long a call or receive that must still be waiting is watched for a
/// report it must not make, before `crate::scaled_bound`.
const STILL_WAITING_MS: u64 = 100;

/// Bound on each controller wait for a report, before `crate::scaled_bound`.
const REPORT_MS: u64 = 1000;

/// Poll bound for a fault child's exit, before `crate::scaled_polls`.
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACKS: [ChildStack; MAX_CHILDREN] = [ChildStack::ZERO; MAX_CHILDREN];

/// A child's argument: its copy of the endpoint, its `done` copy, and the
/// shift of its `done` bits.
#[derive(Clone, Copy)]
struct ChildArgs
{
    ep: u64,
    done: u64,
    shift: u32,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, MAX_CHILDREN> = spawn::ArgBlock::new(ChildArgs {
    ep: 0,
    done: 0,
    shift: 0,
});

/// What a phase does with the endpoint's last Receive-right capability.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase
{
    Delete,
    Teardown,
    ParkedReceivers,
    FaultQueued,
    FaultImmediate,
}

/// The objects a phase creates, each `None` once released.
struct Objects
{
    ep: Option<u64>,
    done: Option<u64>,
    ws: Option<u64>,
    holder: Option<spawn::SpawnedChild>,
    children: [Option<spawn::SpawnedChild>; MAX_CHILDREN],
}

pub fn run(ctx: &TestContext) -> TestResult
{
    for (phase, name) in [
        (Phase::Delete, "delete"),
        (Phase::Teardown, "teardown"),
        (Phase::ParkedReceivers, "parked_receivers"),
        (Phase::FaultQueued, "fault_queued"),
        (Phase::FaultImmediate, "fault_immediate"),
    ]
    {
        run_phase(ctx, phase).inspect_err(|_| {
            crate::log("ktest: integration::endpoint_no_receiver failing phase:");
            crate::log(name);
        })?;
    }
    Ok(())
}

/// Run `phase` on fresh objects, then reap everything whatever the outcome.
fn run_phase(ctx: &TestContext, phase: Phase) -> TestResult
{
    let mut objs = Objects {
        ep: None,
        done: None,
        ws: None,
        holder: None,
        children: [None, None],
    };
    let result = phase_body(ctx, phase, &mut objs);
    // Deleting a thread tears the child down wherever it is, so a failed
    // phase leaves no child parked on a stack the next phase reuses.
    let mut reaped = true;
    for child in objs.children.iter_mut().flatten()
    {
        reaped &= child.delete_thread().is_ok();
        reaped &= child.delete_cspace().is_ok();
    }
    if let Some(holder) = objs.holder.as_mut()
    {
        reaped &= holder.delete_thread().is_ok();
        reaped &= holder.delete_cspace().is_ok();
    }
    for cap in [objs.ws, objs.ep, objs.done].into_iter().flatten()
    {
        reaped &= cap_delete(cap).is_ok();
    }
    result?;
    if reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::endpoint_no_receiver: teardown failed")
    }
}

fn phase_body(ctx: &TestContext, phase: Phase, objs: &mut Objects) -> TestResult
{
    let ep = *objs.ep.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::endpoint_no_receiver: create ep failed")?,
    );
    let done = *objs.done.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "integration::endpoint_no_receiver: create done failed")?,
    );
    // The probe of a queued call: the endpoint turns the set ready.
    let ws = *objs.ws.insert(
        wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
            .map_err(|_| "integration::endpoint_no_receiver: create wait set failed")?,
    );
    wait_set_add(ws, ep, EP_BADGE)
        .map_err(|_| "integration::endpoint_no_receiver: wait_set_add failed")?;
    match phase
    {
        Phase::Delete | Phase::Teardown => calls(ctx, phase, objs, ep, done),
        Phase::ParkedReceivers => receivers(ctx, objs, ep, done),
        Phase::FaultQueued | Phase::FaultImmediate => faults(ctx, phase, objs, ep),
    }
}

/// Phases 1 and 2: a client's queued call and its next one.
fn calls(ctx: &TestContext, phase: Phase, objs: &mut Objects, ep: u64, done: u64) -> TestResult
{
    if phase == Phase::Teardown
    {
        let holder = objs.holder.insert(
            spawn::new_child(ctx)
                .map_err(|_| "integration::endpoint_no_receiver: spawn holder failed")?,
        );
        cap_copy(ep, holder.cs, RIGHTS_EP_RECEIVE)
            .map_err(|_| "integration::endpoint_no_receiver: cap_copy to holder failed")?;
    }
    start_child(ctx, objs, ep, RIGHTS_EP_SEND, done, 0, client_entry)?;
    if phase == Phase::Teardown
    {
        // The holder's copy is now the endpoint's only Receive right.
        release_ep(objs)?;
    }
    let acc = wait_for(done, 0, BIT_READY)?;
    if wait_set_wait_timeout(ws_of(objs)?, crate::scaled_bound(REPORT_MS)) != Ok(EP_BADGE)
    {
        return Err("integration::endpoint_no_receiver: the client's call never queued");
    }
    let acc = if phase == Phase::Teardown
    {
        let acc = still_waiting(done, acc, BIT_OK | BIT_BAD)?;
        let mut holder = objs
            .holder
            .take()
            .ok_or("integration::endpoint_no_receiver: no holder")?;
        holder
            .delete_thread()
            .and(holder.delete_cspace())
            .map_err(|_| "integration::endpoint_no_receiver: holder teardown failed")?;
        acc
    }
    else
    {
        release_ep(objs)?;
        acc
    };
    let acc = wait_for(done, acc, BIT_OK | BIT_BAD)?;
    if acc & BIT_BAD != 0
    {
        return Err(
            "integration::endpoint_no_receiver: a call on an endpoint with no receiver left \
             returned a non-NoReceiver result",
        );
    }
    Ok(())
}

/// Phase 3: two parked receivers, released only by the last Receive right's
/// delete.
fn receivers(ctx: &TestContext, objs: &mut Objects, ep: u64, done: u64) -> TestResult
{
    let mut acc = 0;
    for index in 0..MAX_CHILDREN
    {
        start_child(
            ctx,
            objs,
            ep,
            RIGHTS_EP_RECEIVE,
            done,
            index,
            receiver_entry,
        )?;
        acc = wait_for(done, acc, BIT_READY << shift(index))?;
        thread_sleep(crate::scaled_bound(SETTLE_SLEEP_MS))
            .map_err(|_| "integration::endpoint_no_receiver: settle sleep failed")?;
    }
    // The revoke frees the receivers' copies, but the controller's own cap
    // still carries the Receive right.
    cap_revoke(ep).map_err(|_| "integration::endpoint_no_receiver: revoke failed")?;
    let reports = (0..MAX_CHILDREN).fold(0, |m, index| m | ((BIT_OK | BIT_BAD) << shift(index)));
    acc = still_waiting(done, acc, reports)?;
    release_ep(objs)?;
    for index in 0..MAX_CHILDREN
    {
        acc = wait_for(done, acc, (BIT_OK | BIT_BAD) << shift(index))?;
    }
    if (0..MAX_CHILDREN).any(|index| acc & (BIT_BAD << shift(index)) != 0)
    {
        return Err(
            "integration::endpoint_no_receiver: a receive parked when the last Receive right \
             went returned a non-NoReceiver result",
        );
    }
    Ok(())
}

/// Phases 4 and 5: a fault delivered to an endpoint with no receiver left,
/// queued when it goes or after.
fn faults(ctx: &TestContext, phase: Phase, objs: &mut Objects, ep: u64) -> TestResult
{
    let child = objs.children[0].insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::endpoint_no_receiver: spawn fault child failed")?,
    );
    // The binding holds a reference, not a capability: it counts no receiver.
    crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
        .map_err(|_| "integration::endpoint_no_receiver: bind_fault_handler failed")?;
    if phase == Phase::FaultImmediate
    {
        release_ep(objs)?;
    }
    let child = objs.children[0]
        .as_ref()
        .ok_or("integration::endpoint_no_receiver: no fault child")?;
    // SAFETY: `CHILD_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(CHILD_STACKS), 0) }?;
    // SAFETY: the stack is `CHILD_STACKS[0]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, fault_entry, stack, 0) }
        .map_err(|_| "integration::endpoint_no_receiver: start fault child failed")?;
    let th = child.th;
    if phase == Phase::FaultQueued
    {
        if wait_set_wait_timeout(ws_of(objs)?, crate::scaled_bound(REPORT_MS)) != Ok(EP_BADGE)
        {
            return Err("integration::endpoint_no_receiver: the fault was never queued");
        }
        release_ep(objs)?;
    }
    let reason = spawn::wait_until_exited(th, crate::scaled_polls(MAX_POLLS))?;
    if reason != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
    {
        return Err("integration::endpoint_no_receiver: wrong exit reason for the fault");
    }
    Ok(())
}

/// Delete the controller's endpoint cap.
fn release_ep(objs: &mut Objects) -> TestResult
{
    let ep = objs
        .ep
        .take()
        .ok_or("integration::endpoint_no_receiver: no endpoint cap")?;
    cap_delete(ep).map_err(|_| "integration::endpoint_no_receiver: delete ep failed")
}

fn ws_of(objs: &Objects) -> Result<u64, &'static str>
{
    objs.ws
        .ok_or("integration::endpoint_no_receiver: no wait set")
}

/// The shift of child `index`'s `done` bits.
fn shift(index: usize) -> u32
{
    #[expect(clippy::cast_possible_truncation, reason = "index < MAX_CHILDREN")]
    let index = index as u32;
    index.saturating_mul(CHILD_SHIFT)
}

/// Start child `index` running `entry` with a copy of `ep` carrying
/// `rights`, storing it in `objs` before anything can fail so the phase's
/// teardown reaps it.
fn start_child(
    ctx: &TestContext,
    objs: &mut Objects,
    ep: u64,
    rights: u64,
    done: u64,
    index: usize,
    entry: extern "C" fn(u64) -> !,
) -> TestResult
{
    let slot = objs
        .children
        .get_mut(index)
        .ok_or("integration::endpoint_no_receiver: child index out of range")?;
    let child = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::endpoint_no_receiver: spawn child failed")?,
    );
    let c_ep = cap_copy(ep, child.cs, rights)
        .map_err(|_| "integration::endpoint_no_receiver: cap_copy ep failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::endpoint_no_receiver: cap_copy done failed")?;
    // SAFETY: entry `index` belongs to this child alone; phases run
    // sequentially and each phase's children are reaped before the next
    // phase publishes.
    let arg = unsafe {
        CHILD_ARGS.publish(
            index,
            ChildArgs {
                ep: c_ep,
                done: c_done,
                shift: shift(index),
            },
        )
    };
    // SAFETY: `CHILD_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(CHILD_STACKS), index) }?;
    // SAFETY: the stack is `CHILD_STACKS[index]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, entry, stack, arg) }
        .map_err(|_| "integration::endpoint_no_receiver: start child failed")
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present,
/// failing once a scaled [`REPORT_MS`] wait passes with nothing new.
fn wait_for(done: u64, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, crate::scaled_bound(REPORT_MS))
            .map_err(|_| "integration::endpoint_no_receiver: notification_wait_timeout failed")?;
        if bits == 0
        {
            return Err("integration::endpoint_no_receiver: a child never reported");
        }
        acc |= bits;
    }
    Ok(acc)
}

/// Watch `done` for a scaled [`STILL_WAITING_MS`] and fail if any bit of
/// `mask` arrives: a wait that must not have ended yet.
fn still_waiting(done: u64, acc: u64, mask: u64) -> Result<u64, &'static str>
{
    let bits = notification_wait_timeout(done, crate::scaled_bound(STILL_WAITING_MS))
        .map_err(|_| "integration::endpoint_no_receiver: notification_wait_timeout failed")?;
    if bits & mask != 0
    {
        return Err(
            "integration::endpoint_no_receiver: a wait ended while a Receive right was left",
        );
    }
    Ok(acc | bits)
}

/// Whether `result` is `NoReceiver`.
fn no_receiver<T>(result: &Result<T, i64>) -> bool
{
    matches!(result, Err(e) if *e == SyscallError::NoReceiver as i64)
}

/// Client: raise READY, call (queued until the last Receive right goes), call
/// again (refused at once); raise OK iff both returned `NoReceiver`.
extern "C" fn client_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for this child.
    let ChildArgs { ep, done, shift } = unsafe { spawn::child_args(arg) };
    notification_send(done, BIT_READY << shift).ok();
    let queued = raw_ipc_call(ep, 0x7185, 0, 0, &MsgRegs::default());
    let later = raw_ipc_call(ep, 0x7185, 0, 0, &MsgRegs::default());
    let bit = if no_receiver(&queued) && no_receiver(&later)
    {
        BIT_OK
    }
    else
    {
        BIT_BAD
    };
    notification_send(done, bit << shift).ok();
    thread_exit()
}

/// Receiver: raise READY, receive; raise OK iff it returned `NoReceiver`.
extern "C" fn receiver_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for this child.
    let ChildArgs { ep, done, shift } = unsafe { spawn::child_args(arg) };
    notification_send(done, BIT_READY << shift).ok();
    let bit = if no_receiver(&raw_ipc_recv(ep))
    {
        BIT_OK
    }
    else
    {
        BIT_BAD
    };
    notification_send(done, bit << shift).ok();
    thread_exit()
}

/// Fault child: store to the reserved VA. The fault is unhandled, so the
/// kernel terminates this thread before the store returns; the loop only
/// satisfies `-> !`.
extern "C" fn fault_entry(_arg: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — no handler can receive the fault, so
    // the kernel terminates this thread instead of resuming the store.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}
