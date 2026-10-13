// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/destroyed_source_interrupts.rs

//! Integration: a thread parked on a notification, event queue, or wait set
//! returns `Interrupted` when that object is destroyed under it — never a
//! success carrying a payload nobody sent.
//!
//! The source's dealloc wake claims the parked waiter under the source lock
//! and stamps its park episode `INTERRUPTED`; the waiter's resume consumes
//! the stamp before reading `wakeup_value`. One phase per source:
//!
//!   1. **`notification_wait`** (untimed).
//!   2. **`notification_wait_timeout`** — a timed waiter is also on the sleep
//!      list; the dealloc removes that entry with the waiter slot.
//!   3. **`event_recv`** (untimed).
//!   4. **`wait_set_wait`** — the wait set itself is destroyed, not a member.
//!
//! The child waits on a copy of the source. The controller frees the object
//! by revoking its own capability (the copy is its derivation child) and
//! then deleting it; the child, raising an OK bit on `Interrupted` or a BAD
//! bit on any other result, is the verdict.
//!
//! Runs on a single CPU (the child is a timer-preempted peer).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, cap_revoke, event_queue_create,
    event_recv, notification_send, notification_wait, notification_wait_timeout, thread_exit,
    thread_sleep, wait_set_add, wait_set_create, wait_set_wait,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Child raises this just before it parks.
const BIT_READY: u64 = 1 << 0;
/// Child raises this when its wait returned `Interrupted`.
const BIT_OK: u64 = 1 << 1;
/// Child raises this on any other result.
const BIT_BAD: u64 = 1 << 2;

/// A timed wait that never elapses on its own within the test.
const PARK_FOREVER_MS: u64 = 600_000;

/// Wall-clock settle after READY so the child provably reaches its park
/// before the source is destroyed (see `park_interrupted_stop_start`).
const SETTLE_SLEEP_MS: u64 = 20;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Which source a phase's child waits on, and how.
#[derive(Clone, Copy)]
enum Source
{
    Notification,
    NotificationTimed,
    EventQueue,
    WaitSet,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    for (source, name) in [
        (Source::Notification, "notification_wait"),
        (Source::NotificationTimed, "notification_wait_timeout"),
        (Source::EventQueue, "event_recv"),
        (Source::WaitSet, "wait_set_wait"),
    ]
    {
        run_phase(ctx, source).inspect_err(|_| {
            crate::log("ktest: integration::destroyed_source_interrupts failing phase:");
            crate::log(name);
        })?;
    }
    Ok(())
}

/// Park a child on a copy of a fresh `source`, destroy the source, and take
/// the child's verdict.
fn run_phase(ctx: &TestContext, source: Source) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::destroyed_source_interrupts: create done failed")?;
    let (object, member) = create_source(ctx, source)?;
    let child = start_child(ctx, source, object, done)?;

    let mut acc = wait_for(done, 0, BIT_READY)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    // Revoke deletes the child's copy (a derivation child of `object`); the
    // delete then drops the last reference and runs the dealloc wake.
    cap_revoke(object).map_err(|_| "integration::destroyed_source_interrupts: revoke failed")?;
    cap_delete(object).map_err(|_| "integration::destroyed_source_interrupts: delete failed")?;
    acc = wait_for(done, acc, BIT_OK | BIT_BAD)?;

    cap_delete(child.th)
        .map_err(|_| "integration::destroyed_source_interrupts: reap child thread failed")?;
    cap_delete(child.cs)
        .map_err(|_| "integration::destroyed_source_interrupts: reap child cspace failed")?;
    if let Some(m) = member
    {
        cap_delete(m).map_err(|_| "integration::destroyed_source_interrupts: del member failed")?;
    }
    cap_delete(done).map_err(|_| "integration::destroyed_source_interrupts: del done failed")?;

    if acc & BIT_BAD != 0
    {
        return Err(
            "integration::destroyed_source_interrupts: a wait on a destroyed source returned \
             a non-Interrupted result",
        );
    }
    Ok(())
}

/// Create the phase's object; a wait set gets one member that never fires,
/// returned so it can be deleted after the set.
fn create_source(ctx: &TestContext, source: Source) -> Result<(u32, Option<u32>), &'static str>
{
    let object = match source
    {
        Source::Notification | Source::NotificationTimed =>
        {
            cap_create_notification(ctx.memory_base)
        }
        Source::EventQueue => event_queue_create(ctx.memory_base, 4),
        Source::WaitSet => wait_set_create(ctx.memory_base),
    }
    .map_err(|_| "integration::destroyed_source_interrupts: create source failed")?;
    if !matches!(source, Source::WaitSet)
    {
        return Ok((object, None));
    }
    let member = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::destroyed_source_interrupts: create member failed")?;
    wait_set_add(object, member, 0x5E7)
        .map_err(|_| "integration::destroyed_source_interrupts: wait_set_add failed")?;
    Ok((object, Some(member)))
}

/// Start the phase's child waiting on a copy of `object`.
fn start_child(
    ctx: &TestContext,
    source: Source,
    object: u32,
    done: u32,
) -> Result<spawn::SpawnedChild, &'static str>
{
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::destroyed_source_interrupts: spawn child failed")?;
    let c_object = cap_copy(object, child.cs, RIGHTS_ALL)
        .map_err(|_| "integration::destroyed_source_interrupts: cap_copy source failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::destroyed_source_interrupts: cap_copy done failed")?;
    let entry: fn(u64) -> ! = match source
    {
        Source::Notification => notif_entry,
        Source::NotificationTimed => notif_timed_entry,
        Source::EventQueue => event_entry,
        Source::WaitSet => waitset_entry,
    };
    // Phases run sequentially and each child is reaped (its thread deleted)
    // before the next spawn, so the shared stack has one live user.
    let stack = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    spawn::configure_and_start(
        &child,
        entry,
        stack,
        u64::from(c_object) | (u64::from(c_done) << 32),
    )
    .map_err(|_| "integration::destroyed_source_interrupts: start child failed")?;
    Ok(child)
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present.
fn wait_for(done: u32, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        acc |= notification_wait(done)
            .map_err(|_| "integration::destroyed_source_interrupts: notification_wait failed")?;
    }
    Ok(acc)
}

// cast_possible_truncation: packed fields are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn unpack(arg: u64) -> (u32, u32)
{
    ((arg & 0xFFFF_FFFF) as u32, (arg >> 32) as u32)
}

/// Report the wait's verdict on `done` and exit.
fn finish(done: u32, result: Result<u64, i64>) -> !
{
    let bit = match result
    {
        Err(e) if e == SyscallError::Interrupted as i64 => BIT_OK,
        _ => BIT_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

fn notif_entry(arg: u64) -> !
{
    let (sig, done) = unpack(arg);
    notification_send(done, BIT_READY).ok();
    finish(done, notification_wait(sig))
}

fn notif_timed_entry(arg: u64) -> !
{
    let (sig, done) = unpack(arg);
    notification_send(done, BIT_READY).ok();
    finish(done, notification_wait_timeout(sig, PARK_FOREVER_MS))
}

fn event_entry(arg: u64) -> !
{
    let (eq, done) = unpack(arg);
    notification_send(done, BIT_READY).ok();
    finish(done, event_recv(eq))
}

fn waitset_entry(arg: u64) -> !
{
    let (ws, done) = unpack(arg);
    notification_send(done, BIT_READY).ok();
    finish(done, wait_set_wait(ws))
}
