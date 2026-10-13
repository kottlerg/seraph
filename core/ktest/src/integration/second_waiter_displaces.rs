// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/second_waiter_displaces.rs

//! Integration: a notification, event queue, or wait set takes one waiter.
//! A second thread's wait displaces the parked one, whose wait returns
//! `Interrupted`, and the new waiter receives the next delivery.
//!
//! Before displacement woke the displaced thread, it stayed parked on a slot
//! that no longer named it — still bound to the object and, for a timed
//! wait, on the sleep list — with nothing left to wake it. One phase per
//! object: child A parks, child B waits on the same object, then the
//! controller delivers once. A must report `Interrupted` and B the delivery.
//!
//! Runs on a single CPU (the children are timer-preempted peers).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, event_post, event_queue_create,
    event_recv, notification_send, notification_wait, thread_exit, thread_sleep, wait_set_add,
    wait_set_create, wait_set_wait,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Per-child `done` bits; child B's are child A's shifted by [`B_SHIFT`].
/// Raised just before the child parks.
const BIT_READY: u64 = 1 << 0;
/// Raised when the wait returned the result the child's role expects.
const BIT_OK: u64 = 1 << 1;
/// Raised on any other result.
const BIT_BAD: u64 = 1 << 2;
const B_SHIFT: u32 = 3;

/// What the controller delivers once both children wait: the notification
/// bits, the event payload, the member badge.
const DELIVERY: u64 = 0x005E_C00D;

/// Wall-clock settle after READY so a child provably reaches its park.
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
/// and its role (A is displaced; B is the displacing waiter).
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
            crate::log("ktest: integration::second_waiter_displaces failing phase:");
            crate::log(name);
        })?;
    }
    Ok(())
}

fn run_phase(ctx: &TestContext, object: Object) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::second_waiter_displaces: create done failed")?;
    let (obj, member) = create_object(ctx, object)?;

    let a = start_child(ctx, object, obj, done, false)?;
    let mut acc = wait_for(done, 0, BIT_READY)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    let b = start_child(ctx, object, obj, done, true)?;
    acc = wait_for(done, acc, BIT_READY << B_SHIFT)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    // A's verdict arrives once B's wait displaced it.
    acc = wait_for(done, acc, BIT_OK | BIT_BAD)?;

    match object
    {
        Object::Notification => notification_send(obj, DELIVERY),
        Object::EventQueue => event_post(obj, DELIVERY),
        Object::WaitSet => notification_send(member.unwrap_or(0), 1),
    }
    .map_err(|_| "integration::second_waiter_displaces: delivery failed")?;
    acc = wait_for(done, acc, (BIT_OK | BIT_BAD) << B_SHIFT)?;

    for child in [&a, &b]
    {
        cap_delete(child.th)
            .map_err(|_| "integration::second_waiter_displaces: reap child thread failed")?;
        cap_delete(child.cs)
            .map_err(|_| "integration::second_waiter_displaces: reap child cspace failed")?;
    }
    cap_delete(obj).map_err(|_| "integration::second_waiter_displaces: del object failed")?;
    if let Some(m) = member
    {
        cap_delete(m).map_err(|_| "integration::second_waiter_displaces: del member failed")?;
    }
    cap_delete(done).map_err(|_| "integration::second_waiter_displaces: del done failed")?;

    if acc & BIT_BAD != 0
    {
        return Err(
            "integration::second_waiter_displaces: the displaced wait did not return \
                    Interrupted",
        );
    }
    if acc & (BIT_BAD << B_SHIFT) != 0
    {
        return Err(
            "integration::second_waiter_displaces: the displacing waiter did not \
                    receive the delivery",
        );
    }
    Ok(())
}

/// Create the phase's object; a wait set gets one member whose badge is
/// [`DELIVERY`], returned so the controller can fire and later delete it.
fn create_object(ctx: &TestContext, object: Object) -> Result<(u32, Option<u32>), &'static str>
{
    let obj = match object
    {
        Object::Notification => cap_create_notification(ctx.memory_base),
        Object::EventQueue => event_queue_create(ctx.memory_base, 4),
        Object::WaitSet => wait_set_create(ctx.memory_base),
    }
    .map_err(|_| "integration::second_waiter_displaces: create object failed")?;
    if !matches!(object, Object::WaitSet)
    {
        return Ok((obj, None));
    }
    let member = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::second_waiter_displaces: create member failed")?;
    wait_set_add(obj, member, DELIVERY)
        .map_err(|_| "integration::second_waiter_displaces: wait_set_add failed")?;
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
        .map_err(|_| "integration::second_waiter_displaces: spawn child failed")?;
    let c_obj = cap_copy(obj, child.cs, RIGHTS_ALL)
        .map_err(|_| "integration::second_waiter_displaces: cap_copy object failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::second_waiter_displaces: cap_copy done failed")?;
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
        .map_err(|_| "integration::second_waiter_displaces: start child failed")?;
    Ok(child)
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present.
fn wait_for(done: u32, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        acc |= notification_wait(done)
            .map_err(|_| "integration::second_waiter_displaces: notification_wait failed")?;
    }
    Ok(acc)
}

/// Wait once on the object; A expects `Interrupted` (displaced), B expects
/// [`DELIVERY`].
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
    let result = match object
    {
        Object::Notification => notification_wait(obj),
        Object::EventQueue => event_recv(obj),
        Object::WaitSet => wait_set_wait(obj),
    };
    let ok = if is_b
    {
        result == Ok(DELIVERY)
    }
    else
    {
        result == Err(SyscallError::Interrupted as i64)
    };
    notification_send(done, (if ok { BIT_OK } else { BIT_BAD }) << shift).ok();
    thread_exit()
}
