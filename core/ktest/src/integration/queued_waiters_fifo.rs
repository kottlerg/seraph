// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/queued_waiters_fifo.rs

//! Integration: threads waiting on one notification, event queue, or wait set
//! queue in arrival order, and each delivery wakes the longest-waiting one.
//!
//! A source kept a single waiter slot that a second wait overwrote, leaving
//! the first thread parked, bound to the source and (if timed) on the sleep
//! list, with nothing left to wake it; ruststd's lock primitives, which block
//! every contender on one notification, depend on all of them waking. One
//! phase per object: child A parks, then child B parks on the same object;
//! the controller delivers once and A (the head) must receive it while B
//! stays parked, then delivers again and B must receive it.
//!
//! Runs on a single CPU (the children are timer-preempted peers).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, event_post, event_queue_create,
    event_recv, notification_send, notification_wait, notification_wait_timeout, thread_exit,
    thread_sleep, wait_set_add, wait_set_create, wait_set_wait,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Per-child `done` bits; child B's are child A's shifted by [`B_SHIFT`].
/// Raised just before the child parks.
const BIT_READY: u64 = 1 << 0;
/// Raised when the wait returned the delivery meant for the child.
const BIT_OK: u64 = 1 << 1;
/// Raised on any other result.
const BIT_BAD: u64 = 1 << 2;
const B_SHIFT: u32 = 3;

/// The two deliveries, in order; each child expects its own (the wait set
/// fires one member whose badge is [`BADGE`] for both).
const FIRST: u64 = 0x0A;
const SECOND: u64 = 0x0B;
const BADGE: u64 = 0x005E_C00D;

/// Wall-clock settle after READY so a child provably reaches its park, and
/// how long B is given to (wrongly) wake on A's delivery.
const SETTLE_SLEEP_MS: u64 = 20;

static mut CHILD_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];

/// Which object a phase's children wait on.
#[derive(Clone, Copy)]
enum Object
{
    Notification,
    EventQueue,
    WaitSet,
}

/// A child's argument: the object, the `done` notification, the object kind,
/// and the delivery it expects (A the first, B the second).
#[derive(Clone, Copy)]
struct ChildArgs
{
    obj: u32,
    done: u32,
    object: Object,
    is_b: bool,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 2> = spawn::ArgBlock::new(ChildArgs {
    obj: 0,
    done: 0,
    object: Object::Notification,
    is_b: false,
});

pub fn run(ctx: &TestContext) -> TestResult
{
    for (object, name) in [
        (Object::Notification, "notification"),
        (Object::EventQueue, "event queue"),
        (Object::WaitSet, "wait set"),
    ]
    {
        run_phase(ctx, object).inspect_err(|_| {
            crate::log("ktest: integration::queued_waiters_fifo failing phase:");
            crate::log(name);
        })?;
    }
    Ok(())
}

fn run_phase(ctx: &TestContext, object: Object) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::queued_waiters_fifo: create done failed")?;
    let (obj, member) = create_object(ctx, object)?;

    let a = start_child(ctx, object, obj, done, false)?;
    let mut acc = wait_for(done, 0, BIT_READY)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    let b = start_child(ctx, object, obj, done, true)?;
    acc = wait_for(done, acc, BIT_READY << B_SHIFT)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);

    deliver(object, obj, member, FIRST)?;
    acc = wait_for(done, acc, BIT_OK | BIT_BAD)?;
    // B must still be parked: give it time to (wrongly) report.
    if let Ok(bits) = notification_wait_timeout(done, SETTLE_SLEEP_MS)
    {
        acc |= bits;
    }
    let b_woke_early = acc & ((BIT_OK | BIT_BAD) << B_SHIFT) != 0;
    deliver(object, obj, member, SECOND)?;
    acc = wait_for(done, acc, (BIT_OK | BIT_BAD) << B_SHIFT)?;

    for child in [&a, &b]
    {
        cap_delete(child.th)
            .map_err(|_| "integration::queued_waiters_fifo: reap child thread failed")?;
        cap_delete(child.cs)
            .map_err(|_| "integration::queued_waiters_fifo: reap child cspace failed")?;
    }
    cap_delete(obj).map_err(|_| "integration::queued_waiters_fifo: del object failed")?;
    if let Some(m) = member
    {
        cap_delete(m).map_err(|_| "integration::queued_waiters_fifo: del member failed")?;
    }
    cap_delete(done).map_err(|_| "integration::queued_waiters_fifo: del done failed")?;

    if acc & BIT_BAD != 0
    {
        return Err(
            "integration::queued_waiters_fifo: the first waiter did not receive the \
                    first delivery",
        );
    }
    if b_woke_early
    {
        return Err(
            "integration::queued_waiters_fifo: the second waiter woke on the first \
                    delivery",
        );
    }
    if acc & (BIT_BAD << B_SHIFT) != 0
    {
        return Err(
            "integration::queued_waiters_fifo: the second waiter did not receive the \
                    second delivery",
        );
    }
    Ok(())
}

/// Deliver once: notification bits, an event payload, or a member fire.
fn deliver(object: Object, obj: u32, member: Option<u32>, value: u64) -> TestResult
{
    match object
    {
        Object::Notification => notification_send(obj, value),
        Object::EventQueue => event_post(obj, value),
        Object::WaitSet => notification_send(member.unwrap_or(0), value),
    }
    .map_err(|_| "integration::queued_waiters_fifo: delivery failed")
}

/// Create the phase's object; a wait set gets one member whose badge is
/// [`BADGE`], returned so the controller can fire and later delete it.
fn create_object(ctx: &TestContext, object: Object) -> Result<(u32, Option<u32>), &'static str>
{
    let obj = match object
    {
        Object::Notification => cap_create_notification(ctx.memory_base),
        Object::EventQueue => event_queue_create(ctx.memory_base, 4),
        Object::WaitSet => wait_set_create(ctx.memory_base),
    }
    .map_err(|_| "integration::queued_waiters_fifo: create object failed")?;
    if !matches!(object, Object::WaitSet)
    {
        return Ok((obj, None));
    }
    let member = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::queued_waiters_fifo: create member failed")?;
    wait_set_add(obj, member, BADGE)
        .map_err(|_| "integration::queued_waiters_fifo: wait_set_add failed")?;
    Ok((obj, Some(member)))
}

/// Start child A (`is_b == false`) or B waiting (untimed) on a copy of `obj`.
fn start_child(
    ctx: &TestContext,
    object: Object,
    obj: u32,
    done: u32,
    is_b: bool,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::queued_waiters_fifo: spawn child failed")?;
    let c_obj = cap_copy(obj, child.cs, RIGHTS_ALL)
        .map_err(|_| "integration::queued_waiters_fifo: cap_copy object failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::queued_waiters_fifo: cap_copy done failed")?;
    let index = usize::from(is_b);
    // SAFETY: entry `index` belongs to this child alone; phases run
    // sequentially and each phase's children are reaped before the next
    // phase publishes.
    let arg = unsafe {
        CHILD_ARGS.publish(
            index,
            ChildArgs {
                obj: c_obj,
                done: c_done,
                object,
                is_b,
            },
        )
    };
    // SAFETY: stack `index` is this child's; reaped before the next phase.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(CHILD_STACKS[index]) });
    spawn::configure_and_start(&child, child_entry, stack, arg)
        .map_err(|_| "integration::queued_waiters_fifo: start child failed")?;
    Ok(child)
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present.
fn wait_for(done: u32, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        acc |= notification_wait(done)
            .map_err(|_| "integration::queued_waiters_fifo: notification_wait failed")?;
    }
    Ok(acc)
}

/// Wait once on the object and check the result is this child's delivery.
fn child_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for this child.
    let ChildArgs {
        obj,
        done,
        object,
        is_b,
    } = unsafe { spawn::child_args(arg) };
    let shift = if is_b { B_SHIFT } else { 0 };
    notification_send(done, BIT_READY << shift).ok();
    let expected = match object
    {
        Object::WaitSet => BADGE,
        _ if is_b => SECOND,
        _ => FIRST,
    };
    let result = match object
    {
        Object::Notification => notification_wait(obj),
        Object::EventQueue => event_recv(obj),
        Object::WaitSet => wait_set_wait(obj),
    };
    let bit = if result == Ok(expected)
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
