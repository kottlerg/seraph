// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/destroyed_source_interrupts.rs

//! Integration: a thread parked on a notification, event queue, or wait set
//! returns `Interrupted` when that object is destroyed under it — never a
//! success carrying a payload nobody sent.
//!
//! The source's dealloc wake claims every queued waiter under the source lock
//! and stamps its park episode `INTERRUPTED`; each waiter's resume consumes
//! the stamp before reading `wakeup_value`. One phase per source, with two
//! queued waiters on a notification or event queue and one on a wait set
//! (which refuses a second):
//!
//!   1. **`notification_wait`** (untimed).
//!   2. **`notification_wait_timeout`** — a timed waiter is also on the sleep
//!      list; the dealloc removes those entries with the queue.
//!   3. **`event_recv`** (untimed).
//!   4. **`wait_set_wait`** — the wait set itself is destroyed, not a member.
//!
//! Each child waits on a copy of the source. The controller frees the object
//! by revoking its own capability (the copies are its derivation children)
//! and then deleting it; each child, raising an OK bit on `Interrupted` or a
//! BAD bit on any other result, is the verdict.
//!
//! Runs on a single CPU (the children are timer-preempted peers).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, cap_revoke, event_queue_create,
    event_recv, notification_send, notification_wait, notification_wait_timeout, thread_exit,
    thread_sleep, wait_set_add, wait_set_create, wait_set_wait,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Per-child `done` bits; child `i`'s are shifted by `i * CHILD_SHIFT`.
/// Raised just before the child parks.
const BIT_READY: u64 = 1 << 0;
/// Raised when the wait returned `Interrupted`.
const BIT_OK: u64 = 1 << 1;
/// Raised on any other result.
const BIT_BAD: u64 = 1 << 2;
const CHILD_SHIFT: u32 = 3;
const MAX_CHILDREN: usize = 2;

/// A timed wait that never elapses on its own within the test.
const PARK_FOREVER_MS: u64 = 600_000;

/// Wall-clock settle after READY so the child has, in practice, reached its
/// park before the source is destroyed (see `park_interrupted_stop_start`).
const SETTLE_SLEEP_MS: u64 = 20;

/// Bound on each controller wait for a child's report.
const REPORT_MS: u64 = 1000;

static mut CHILD_STACKS: [ChildStack; MAX_CHILDREN] = [ChildStack::ZERO; MAX_CHILDREN];

/// A child's argument: its copy of the source, its `done` copy, and the
/// shift of its `done` bits.
#[derive(Clone, Copy)]
struct ChildArgs
{
    source_cap: u32,
    done: u32,
    shift: u32,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, MAX_CHILDREN> = spawn::ArgBlock::new(ChildArgs {
    source_cap: 0,
    done: 0,
    shift: 0,
});

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

/// Park the phase's children on copies of a fresh `source`, destroy the
/// source, and take every child's verdict; reap everything whatever the
/// outcome.
fn run_phase(ctx: &TestContext, source: Source) -> TestResult
{
    let count = match source
    {
        Source::WaitSet => 1,
        _ => MAX_CHILDREN,
    };
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::destroyed_source_interrupts: create done failed")?;
    let (object, member) = match create_source(ctx, source)
    {
        Ok(created) => created,
        Err(e) =>
        {
            let _ = cap_delete(done);
            return Err(e);
        }
    };
    let mut object = Some(object);
    let mut children: [Option<spawn::SpawnedChild>; MAX_CHILDREN] = [None, None];
    let result = park_and_destroy(ctx, source, count, &mut object, done, &mut children);

    // Deleting a thread tears the child down wherever it is, so a failed
    // phase leaves no child parked on a stack the next phase reuses.
    let mut reaped = true;
    if let Some(obj) = object
    {
        reaped &= cap_revoke(obj).is_ok();
        reaped &= cap_delete(obj).is_ok();
    }
    for child in children.iter().flatten()
    {
        reaped &= cap_delete(child.th).is_ok();
        reaped &= cap_delete(child.cs).is_ok();
    }
    if let Some(m) = member
    {
        reaped &= cap_delete(m).is_ok();
    }
    reaped &= cap_delete(done).is_ok();
    result?;
    if reaped
    {
        Ok(())
    }
    else
    {
        Err("integration::destroyed_source_interrupts: teardown failed")
    }
}

/// Start `count` children parked on `object`, destroy it (taking it out of
/// `object`), and check every child's verdict.
fn park_and_destroy(
    ctx: &TestContext,
    source: Source,
    count: usize,
    object: &mut Option<u32>,
    done: u32,
    children: &mut [Option<spawn::SpawnedChild>; MAX_CHILDREN],
) -> TestResult
{
    let obj = object.ok_or("integration::destroyed_source_interrupts: no source")?;
    let mut acc = 0;
    for (index, slot) in children.iter_mut().enumerate().take(count)
    {
        start_child(ctx, source, obj, done, index, slot)?;
        acc = wait_for(done, acc, BIT_READY << shift(index))?;
        thread_sleep(SETTLE_SLEEP_MS)
            .map_err(|_| "integration::destroyed_source_interrupts: settle sleep failed")?;
    }
    // Revoke deletes the children's copies (derivation children of the
    // source); the delete then drops the last reference and runs the dealloc
    // wake. `object` keeps the cap until the delete succeeds, so a failure
    // leaves it to the phase's teardown.
    cap_revoke(obj).map_err(|_| "integration::destroyed_source_interrupts: revoke failed")?;
    cap_delete(obj).map_err(|_| "integration::destroyed_source_interrupts: delete failed")?;
    *object = None;
    for index in 0..count
    {
        acc = wait_for(done, acc, (BIT_OK | BIT_BAD) << shift(index))?;
    }
    if (0..count).any(|index| acc & (BIT_BAD << shift(index)) != 0)
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
    let Ok(member) = cap_create_notification(ctx.memory_base)
    else
    {
        let _ = cap_delete(object);
        return Err("integration::destroyed_source_interrupts: create member failed");
    };
    if wait_set_add(object, member, 0x5E7).is_err()
    {
        let _ = cap_delete(object);
        let _ = cap_delete(member);
        return Err("integration::destroyed_source_interrupts: wait_set_add failed");
    }
    Ok((object, Some(member)))
}

/// The shift of child `index`'s `done` bits.
fn shift(index: usize) -> u32
{
    // cast_possible_truncation: index < MAX_CHILDREN.
    #[allow(clippy::cast_possible_truncation)]
    let index = index as u32;
    index * CHILD_SHIFT
}

/// Start child `index` waiting on a copy of `object`, storing it in `slot`
/// before anything can fail so the phase's teardown reaps it.
fn start_child(
    ctx: &TestContext,
    source: Source,
    object: u32,
    done: u32,
    index: usize,
    slot: &mut Option<spawn::SpawnedChild>,
) -> TestResult
{
    let child = slot.insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::destroyed_source_interrupts: spawn child failed")?,
    );
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
    // SAFETY: entry `index` belongs to this child alone; phases run
    // sequentially and each phase's children are reaped before the next
    // phase publishes.
    let arg = unsafe {
        CHILD_ARGS.publish(
            index,
            ChildArgs {
                source_cap: c_object,
                done: c_done,
                shift: shift(index),
            },
        )
    };
    // SAFETY: stack `index` is this child's; reaped before the next phase.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(CHILD_STACKS[index]) });
    spawn::configure_and_start(child, entry, stack, arg)
        .map_err(|_| "integration::destroyed_source_interrupts: start child failed")
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present,
/// failing once a [`REPORT_MS`] wait passes with nothing new (a child that
/// never parked, or a waiter the destroy never woke).
fn wait_for(done: u32, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, REPORT_MS).map_err(
            |_| "integration::destroyed_source_interrupts: notification_wait_timeout failed",
        )?;
        if bits == 0
        {
            return Err("integration::destroyed_source_interrupts: a child never reported");
        }
        acc |= bits;
    }
    Ok(acc)
}

/// Raise READY, wait once, report the verdict on `done`, and exit.
fn park_and_report(arg: u64, wait: fn(u32) -> Result<u64, i64>) -> !
{
    // SAFETY: `arg` is the entry `start_child` published for this child.
    let ChildArgs {
        source_cap,
        done,
        shift,
    } = unsafe { spawn::child_args(arg) };
    notification_send(done, BIT_READY << shift).ok();
    let bit = match wait(source_cap)
    {
        Err(e) if e == SyscallError::Interrupted as i64 => BIT_OK,
        _ => BIT_BAD,
    };
    notification_send(done, bit << shift).ok();
    thread_exit()
}

fn notif_entry(arg: u64) -> !
{
    park_and_report(arg, notification_wait)
}

fn notif_timed_entry(arg: u64) -> !
{
    park_and_report(arg, |sig| notification_wait_timeout(sig, PARK_FOREVER_MS))
}

fn event_entry(arg: u64) -> !
{
    park_and_report(arg, event_recv)
}

fn waitset_entry(arg: u64) -> !
{
    park_and_report(arg, wait_set_wait)
}
