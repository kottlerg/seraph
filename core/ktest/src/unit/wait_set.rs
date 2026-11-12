// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/wait_set.rs

//! Tier 1 tests for wait set syscalls.
//!
//! Covers: `SYS_CAP_CREATE_WAIT_SET`, `SYS_WAIT_SET_ADD`,
//! `SYS_WAIT_SET_REMOVE`, `SYS_WAIT_SET_WAIT`.
//!
//! Tests cover immediate return (source signalled before the wait),
//! cross-thread return (a child thread signals the source; the parent blocks
//! unless the unpinned child signals first), two threads waiting on one set
//! at once, each arrival waking one, a member that takes several arrivals
//! holding one ready-ring entry, ready members returned in turn, and work a
//! woken waiter leaves returned by a later wait. The remove test verifies
//! that only the remaining member can wake the wait set after removal, and
//! the stale-entry test that a member whose source stopped being ready after
//! it was queued is not returned.

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, event_post,
    event_queue_create, event_recv, ipc_buffer_set, notification_send, notification_wait,
    notification_wait_timeout, thread_exit, thread_sleep, thread_start, thread_stop, wait_set_add,
    wait_set_create, wait_set_remove, wait_set_try_wait, wait_set_wait, wait_set_wait_timeout,
};
use syscall_abi::{RIGHTS_EP_SEND_GRANT, SyscallError};

use crate::{ChildStack, TestContext, TestResult};

// Notification right only (no WAIT). Children only send on notifications.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

// Child stack for the blocking_wait test.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

// Child stacks for the waiters of shared_set_waiters (two) and
// woken_member_stays_queued (one, on the first). Each test deletes its
// children on every path, so a failed run leaves no thread on either stack.
static mut SHARED_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];

/// `(ws, done)` for each waiter on [`SHARED_STACKS`], indexed like
/// [`SHARED_STACKS`]: each handle fills a word, so the pair goes by address.
static SHARED_ARGS: crate::spawn::ArgBlock<(u64, u64), 2> = crate::spawn::ArgBlock::new((0, 0));

/// `shared_set_waiters`' `done` bits for waiter 0; waiter 1 reports the same
/// bits shifted by [`WAITER_SHIFT`]. Each waiter announces that it is about
/// to wait, waits once on the set, and reports one verdict: returned with the
/// member's badge, or returned otherwise.
const BIT_READY: u64 = 1 << 0;
const BIT_OK: u64 = 1 << 1;
const BIT_BAD: u64 = 1 << 2;
const WAITER_SHIFT: u32 = 3;
const SHARED_BADGE: u64 = 9;
/// Wall-clock settle: after both waiters announce themselves, so that each has,
/// in practice, parked before the first arrival; and after a wake, to look for
/// a second wake the same arrival wrongly caused.
const SETTLE_SLEEP_MS: u64 = 20;
/// Bound on each report. Applied through [`crate::scaled_bound`], which
/// stretches it past [`crate::UNSCALED_CPUS`] CPUs, where a waiter's CPU
/// waits for a host core.
const REPORT_MS: u64 = 1000;

/// Waiter `k`'s verdict bits.
const fn waiter_bits(k: u32, bits: u64) -> u64
{
    match bits.checked_shl(k.saturating_mul(WAITER_SHIFT))
    {
        Some(shifted) => shifted,
        None => 0,
    }
}

// ── SYS_CAP_CREATE_WAIT_SET capacity ─────────────────────────────────────────

/// Members past the former fixed ceiling of 16, in the set sized for them.
const WIDE_MEMBERS: usize = 40;

/// A wait set holds exactly the member capacity its creator chose: a set of
/// [`WIDE_MEMBERS`] takes that many members and wakes for the last one, an add
/// past the capacity is refused, and a capacity of 0 or past
/// `WAIT_SET_MAX_MEMBERS` is refused at create. Fails if the kernel still caps
/// members at a fixed width, over-fills a set, or misindexes a member past 16.
pub fn capacity_is_caller_sized(ctx: &TestContext) -> TestResult
{
    let max = syscall_abi::WAIT_SET_MAX_MEMBERS;
    if wait_set_create(ctx.memory_base, 0) != Err(SyscallError::InvalidArgument as i64)
        || wait_set_create(ctx.memory_base, max + 1) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("wait_set::capacity: an out-of-range capacity was not refused");
    }
    // cast_possible_truncation: WIDE_MEMBERS is a small literal.
    #[allow(clippy::cast_possible_truncation)]
    let ws = wait_set_create(ctx.memory_base, WIDE_MEMBERS as u32)
        .map_err(|_| "wait_set::capacity: wait_set_create(wide) failed")?;
    let mut sigs = [0u64; WIDE_MEMBERS + 1];
    let result = fill_and_wake(ctx, ws, &mut sigs);
    for &sig in sigs.iter().filter(|&&s| s != 0)
    {
        cap_delete(sig).ok();
    }
    cap_delete(ws).ok();
    result
}

/// Body of [`capacity_is_caller_sized`]: fill `ws` with `sigs.len() - 1`
/// notifications, refuse one more, and wake on the last member.
fn fill_and_wake(ctx: &TestContext, ws: u64, sigs: &mut [u64]) -> TestResult
{
    let last = sigs
        .len()
        .checked_sub(1)
        .ok_or("wait_set::capacity: no notifications to add")?;
    let woken = last
        .checked_sub(1)
        .ok_or("wait_set::capacity: too few notifications to add")?;
    for (i, sig) in sigs.iter_mut().enumerate()
    {
        *sig = cap_create_notification(ctx.memory_base)
            .map_err(|_| "wait_set::capacity: cap_create_notification failed")?;
        let added = wait_set_add(ws, *sig, 0x1000u64.saturating_add(i as u64));
        if i < last && added.is_err()
        {
            return Err("wait_set::capacity: an add within the capacity was refused");
        }
        if i == last && added.is_ok()
        {
            return Err("wait_set::capacity: an add past the capacity was accepted");
        }
    }
    let woken_sig = sigs
        .get(woken)
        .copied()
        .ok_or("wait_set::capacity: member index out of range")?;
    notification_send(woken_sig, 0x1)
        .map_err(|_| "wait_set::capacity: notification_send failed")?;
    let badge = wait_set_wait(ws).map_err(|_| "wait_set::capacity: wait_set_wait failed")?;
    notification_wait(woken_sig).ok();
    if badge != 0x1000u64.saturating_add(woken as u64)
    {
        return Err("wait_set::capacity: the wait returned the wrong member's badge");
    }
    Ok(())
}

// ── wait_set_add (notification, immediate wake) ────────────────────────────────────

/// Signalling a notification already registered in a wait set causes
/// `wait_set_wait` to return immediately with the member's badge (the send
/// queues the member on the wait set's ready ring).
pub fn add_notification_immediate(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for ws-notification test failed")?;

    wait_set_add(ws, sig, 42).map_err(|_| "wait_set_add(notification) failed")?;

    // Pre-set bits so the notification is immediately ready.
    notification_send(sig, 0x1).map_err(|_| "notification_send before wait_set_wait failed")?;

    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait(notification, immediate) failed")?;
    if tok != 42
    {
        return Err("wait_set_wait returned wrong badge for notification source");
    }

    // Drain the notification bits.
    notification_wait(sig).map_err(|_| "notification_wait to drain after wait_set_wait failed")?;

    cap_delete(sig).map_err(|_| "cap_delete sig after ws-notification test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after ws-notification test failed")?;
    Ok(())
}

// ── wait_set_add (event queue, immediate wake) ────────────────────────────────

/// Posting to an event queue already registered in a wait set causes
/// `wait_set_wait` to return immediately with the member's badge (the post
/// queues the member on the wait set's ready ring).
pub fn add_queue_immediate(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for ws-queue test failed")?;
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "event_queue_create for ws-queue test failed")?;

    wait_set_add(ws, eq, 99).map_err(|_| "wait_set_add(queue) failed")?;

    // Pre-post an entry so the queue is immediately ready.
    event_post(eq, 0xEE).map_err(|_| "event_post before wait_set_wait failed")?;

    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait(queue, immediate) failed")?;
    if tok != 99
    {
        return Err("wait_set_wait returned wrong badge for queue source");
    }

    // Drain the queue.
    let payload = event_recv(eq).map_err(|_| "event_recv to drain after wait_set_wait failed")?;
    if payload != 0xEE
    {
        return Err("event_recv returned wrong payload after wait_set_wait");
    }

    cap_delete(eq).map_err(|_| "cap_delete eq after ws-queue test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after ws-queue test failed")?;
    Ok(())
}

// ── Ready ring: one entry per member ──────────────────────────────────────────

const BUSY_BADGE: u64 = 0xB0;
const QUIET_BADGE: u64 = 0xB1;

/// A member that takes several arrivals while no thread waits does not crowd
/// another member out of the ready ring: in a two-member set, three posts to
/// an event queue and then one send to a notification leave both members
/// queued, so two waits, neither of which consumes anything, return both
/// badges in that order. Fails if each post queued its own entry, which
/// filled the two-entry ring, dropped the notification's, and returned the
/// still-ready queue to both waits.
pub fn busy_member_does_not_crowd_out(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, 2)
        .map_err(|_| "wait_set::busy_member: wait_set_create failed")?;
    let eq = event_queue_create(ctx.memory_base, 4);
    let sig = cap_create_notification(ctx.memory_base);
    let result = match (eq, sig)
    {
        (Ok(eq), Ok(sig)) => busy_run(ws, eq, sig),
        _ => Err("wait_set::busy_member: creating a member failed"),
    };
    for cap in [eq.ok(), sig.ok(), Some(ws)].into_iter().flatten()
    {
        cap_delete(cap).ok();
    }
    result
}

/// Body of [`busy_member_does_not_crowd_out`].
fn busy_run(ws: u64, eq: u64, sig: u64) -> TestResult
{
    wait_set_add(ws, eq, BUSY_BADGE)
        .map_err(|_| "wait_set::busy_member: wait_set_add(eq) failed")?;
    wait_set_add(ws, sig, QUIET_BADGE)
        .map_err(|_| "wait_set::busy_member: wait_set_add(sig) failed")?;
    for n in 0..3
    {
        event_post(eq, n).map_err(|_| "wait_set::busy_member: event_post failed")?;
    }
    notification_send(sig, 0x1).map_err(|_| "wait_set::busy_member: notification_send failed")?;
    let first = wait_set_wait(ws).map_err(|_| "wait_set::busy_member: first wait failed")?;
    let second = wait_set_wait(ws).map_err(|_| "wait_set::busy_member: second wait failed")?;
    if (first, second) != (BUSY_BADGE, QUIET_BADGE)
    {
        return Err("wait_set::busy_member: the busy member crowded the other out of the ring");
    }
    Ok(())
}

/// A member's backlog is served while a lower-indexed member keeps taking
/// arrivals: in a two-member set of event queues, three posts to the second
/// and one to the first, then four rounds of wait, receive one entry from the
/// queue returned, and post one more entry to the first queue, return the two
/// members in turn. Fails if a returned member lost its ring entry, which left
/// the second queue's backlog to the level walk, which runs only when the ring
/// holds no ready entry: the first queue, queued again by every round's post,
/// was then returned every round after the first.
pub fn backlog_served_beside_arrivals(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, 2)
        .map_err(|_| "wait_set::backlog_served: wait_set_create failed")?;
    let low = event_queue_create(ctx.memory_base, 4);
    let high = event_queue_create(ctx.memory_base, 4);
    let result = match (low, high)
    {
        (Ok(low), Ok(high)) => backlog_run(ws, low, high),
        _ => Err("wait_set::backlog_served: event_queue_create failed"),
    };
    for cap in [low.ok(), high.ok(), Some(ws)].into_iter().flatten()
    {
        cap_delete(cap).ok();
    }
    result
}

/// Body of [`backlog_served_beside_arrivals`].
fn backlog_run(ws: u64, low: u64, high: u64) -> TestResult
{
    wait_set_add(ws, low, BUSY_BADGE)
        .map_err(|_| "wait_set::backlog_served: wait_set_add(low) failed")?;
    wait_set_add(ws, high, QUIET_BADGE)
        .map_err(|_| "wait_set::backlog_served: wait_set_add(high) failed")?;
    for n in 0..3
    {
        event_post(high, n).map_err(|_| "wait_set::backlog_served: event_post(high) failed")?;
    }
    event_post(low, 0).map_err(|_| "wait_set::backlog_served: event_post(low) failed")?;
    let mut returned = [0u64; 4];
    for badge in &mut returned
    {
        *badge = wait_set_wait(ws).map_err(|_| "wait_set::backlog_served: wait failed")?;
        let queue = if *badge == BUSY_BADGE { low } else { high };
        event_recv(queue).map_err(|_| "wait_set::backlog_served: event_recv failed")?;
        event_post(low, 0).map_err(|_| "wait_set::backlog_served: event_post(low) failed")?;
    }
    if returned != [QUIET_BADGE, BUSY_BADGE, QUIET_BADGE, BUSY_BADGE]
    {
        return Err(
            "wait_set::backlog_served: a member's backlog waited behind arrivals elsewhere",
        );
    }
    Ok(())
}

/// The caps and child `woken_member_stays_queued` creates; each is deleted on
/// every path.
#[derive(Default)]
struct Woken
{
    ws: Option<u64>,
    busy: Option<u64>,
    member: Option<u64>,
    done: Option<u64>,
    waiter: Option<crate::spawn::SpawnedChild>,
}

/// An arrival that wakes a parked thread queues its member too, so work the
/// woken thread leaves is returned by a later wait while another member stays
/// busy: a child parks on a two-member set, a post to the higher-indexed queue
/// wakes it, and it exits without receiving; the parent then posts a backlog
/// to the lower-indexed queue, reposting after each entry it takes, and
/// requires the left entry's member within two waits. Fails if the waking
/// arrival queued no entry, which left that member to the level walk, which
/// runs only when the ring holds no ready member (ipc-internals.md § Wait Set
/// Readiness Model, I2).
pub fn woken_member_stays_queued(ctx: &TestContext) -> TestResult
{
    let mut w = Woken::default();
    let result = woken_run(ctx, &mut w);
    let mut ok = true;
    if let Some(mut child) = w.waiter.take()
    {
        ok &= child.delete_thread().is_ok();
        ok &= child.delete_cspace().is_ok();
    }
    for cap in [w.ws, w.busy, w.member, w.done].into_iter().flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    result?;
    if ok
    {
        Ok(())
    }
    else
    {
        Err("wait_set::woken_member_stays_queued: cap_delete in cleanup failed")
    }
}

/// Body of [`woken_member_stays_queued`].
fn woken_run(ctx: &TestContext, w: &mut Woken) -> TestResult
{
    let err = "wait_set::woken_member_stays_queued: setup failed";
    let ws = *w
        .ws
        .insert(wait_set_create(ctx.memory_base, 2).map_err(|_| err)?);
    let busy = *w
        .busy
        .insert(event_queue_create(ctx.memory_base, 4).map_err(|_| err)?);
    let member = *w
        .member
        .insert(event_queue_create(ctx.memory_base, 4).map_err(|_| err)?);
    let done = *w
        .done
        .insert(cap_create_notification(ctx.memory_base).map_err(|_| err)?);
    wait_set_add(ws, busy, BUSY_BADGE).map_err(|_| err)?;
    wait_set_add(ws, member, SHARED_BADGE).map_err(|_| err)?;

    let child = w
        .waiter
        .insert(crate::spawn::new_child(ctx).map_err(|_| err)?);
    start_shared_child(child, 0, shared_waiter_0, ws, done)?;
    let acc = collect(done, 0, waiter_bits(0, BIT_READY))
        .map_err(|_| "wait_set::woken_member_stays_queued: the waiter did not start")?;
    // In practice the waiter has parked by now; if it has not, the post below
    // queues the member and its wait returns it, which leaves the member
    // queued too, so the check below cannot fail on that interleaving.
    let _ = thread_sleep(crate::scaled_bound(SETTLE_SLEEP_MS));

    event_post(member, 0).map_err(|_| err)?;
    let acc = collect(done, acc, waiter_bits(0, BIT_OK | BIT_BAD))
        .map_err(|_| "wait_set::woken_member_stays_queued: the post woke no waiter")?;
    if acc & waiter_bits(0, BIT_BAD) != 0
    {
        return Err("wait_set::woken_member_stays_queued: the waiter got another badge");
    }

    for n in 0..3
    {
        event_post(busy, n).map_err(|_| err)?;
    }
    for _ in 0..2
    {
        let badge =
            wait_set_wait(ws).map_err(|_| "wait_set::woken_member_stays_queued: wait failed")?;
        if badge == SHARED_BADGE
        {
            return Ok(());
        }
        event_recv(busy).map_err(|_| err)?;
        event_post(busy, 0).map_err(|_| err)?;
    }
    Err("wait_set::woken_member_stays_queued: work a woken waiter left was not returned")
}

// ── wait_set_wait (blocking) ──────────────────────────────────────────────────

/// A child thread signals a registered notification and `wait_set_wait` returns
/// its badge: the parent blocks if it waits first, or, if the unpinned child runs
/// first on another CPU, returns the badge already queued on the ready ring.
pub fn blocking_wait(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for blocking test failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for blocking test failed")?;

    wait_set_add(ws, sig, 7).map_err(|_| "wait_set_add for blocking test failed")?;

    // Set up a child thread that sends on the notification.
    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "spawn::new_child for blocking test failed")?;
    let child_sig =
        cap_copy(sig, child.cs, RIGHTS_NOTIFY).map_err(|_| "cap_copy for blocking test failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, sender_entry, stack_top, child_sig) }
        .map_err(|_| "configure_and_start for blocking test failed")?;

    // Block until the child fires the notification.
    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait (blocking) failed")?;
    if tok != 7
    {
        return Err("wait_set_wait (blocking) returned wrong badge");
    }

    // Drain the notification bits.
    let bits = notification_wait(sig)
        .map_err(|_| "notification_wait to drain after blocking wait failed")?;
    if bits != 0xBEEF
    {
        return Err("notification bits after blocking wait_set_wait are wrong (expected 0xBEEF)");
    }

    child
        .delete_thread()
        .map_err(|_| "cap_delete th after blocking test failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after blocking test failed")?;
    child
        .delete_cspace()
        .map_err(|_| "cap_delete cs after blocking test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after blocking test failed")?;
    Ok(())
}

// ── wait_set_wait (try-once and timed) ────────────────────────────────────────

// Child stack for the delayed signaller of wait_timeout_woken_before_expiry.
static mut DELAYED_STACK: ChildStack = ChildStack::ZERO;

/// Microseconds since boot.
fn now_us() -> Result<u64, &'static str>
{
    syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "wait_set: system_info(ElapsedUs) failed")
}

/// `wait_set_try_wait` on a set whose member has nothing pending returns
/// `WouldBlock` at once.
pub fn try_wait_empty_would_block(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for try_wait_empty_would_block failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for try_wait_empty_would_block failed")?;
    wait_set_add(ws, sig, 5).map_err(|_| "wait_set_add for try_wait_empty_would_block failed")?;

    let r = wait_set_try_wait(ws);
    cap_delete(sig).map_err(|_| "cap_delete sig after try_wait_empty_would_block failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after try_wait_empty_would_block failed")?;
    if r != Err(SyscallError::WouldBlock as i64)
    {
        return Err("wait_set_try_wait on an idle set did not return WouldBlock");
    }
    Ok(())
}

/// `wait_set_try_wait` returns the badge of a member signalled beforehand.
pub fn try_wait_returns_ready_badge(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for try_wait_returns_ready_badge failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for try_wait_returns_ready_badge failed")?;
    wait_set_add(ws, sig, 77)
        .map_err(|_| "wait_set_add for try_wait_returns_ready_badge failed")?;
    notification_send(sig, 0x1)
        .map_err(|_| "notification_send for try_wait_returns_ready_badge failed")?;

    let r = wait_set_try_wait(ws);
    notification_wait(sig).ok();
    cap_delete(sig).map_err(|_| "cap_delete sig after try_wait_returns_ready_badge failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after try_wait_returns_ready_badge failed")?;
    if r != Ok(77)
    {
        return Err("wait_set_try_wait did not return the ready member's badge (expected 77)");
    }
    Ok(())
}

/// `wait_set_wait_timeout` with nothing ready returns `WouldBlock` once the
/// timeout has elapsed.
pub fn wait_timeout_expires(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for wait_timeout_expires failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for wait_timeout_expires failed")?;
    wait_set_add(ws, sig, 5).map_err(|_| "wait_set_add for wait_timeout_expires failed")?;

    let t0 = now_us()?;
    let r = wait_set_wait_timeout(ws, 50);
    let t1 = now_us()?;
    cap_delete(sig).map_err(|_| "cap_delete sig after wait_timeout_expires failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after wait_timeout_expires failed")?;
    if r != Err(SyscallError::WouldBlock as i64)
    {
        return Err("wait_set_wait_timeout on an idle set did not return WouldBlock");
    }
    // Allow ~10 ms slack for timer granularity on slow VMs.
    if t1.wrapping_sub(t0) < 40_000
    {
        return Err("wait_set_wait_timeout returned earlier than the requested timeout");
    }
    Ok(())
}

/// A member signalled while the main thread waits with a long timeout wakes
/// the wait well before the timeout, and the woken wait leaves nothing behind
/// that ends a later timed wait early.
pub fn wait_timeout_woken_before_expiry(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for wait_timeout_woken_before_expiry failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for wait_timeout_woken_before_expiry failed")?;
    wait_set_add(ws, sig, 31)
        .map_err(|_| "wait_set_add for wait_timeout_woken_before_expiry failed")?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "spawn::new_child for wait_timeout_woken_before_expiry failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_NOTIFY)
        .map_err(|_| "cap_copy sig for wait_timeout_woken_before_expiry failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(DELAYED_STACK));
    // SAFETY: the stack is `DELAYED_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(&child, delayed_sender_entry, stack_top, child_sig)
    }
    .map_err(|_| "configure_and_start for wait_timeout_woken_before_expiry failed")?;

    let t0 = now_us()?;
    let woken = wait_set_wait_timeout(ws, 5000);
    let t1 = now_us()?;
    if woken != Ok(31)
    {
        return Err("wait_set_wait_timeout was not woken with the member's badge (expected 31)");
    }
    if t1.wrapping_sub(t0) >= 2_000_000
    {
        return Err("wait_set_wait_timeout woken by a signal returned only near its timeout");
    }

    // Drain the member, then a second timed wait must run its full timeout.
    notification_wait(sig).map_err(|_| "notification_wait to drain failed")?;
    let t2 = now_us()?;
    let again = wait_set_wait_timeout(ws, 50);
    let t3 = now_us()?;
    if again != Err(SyscallError::WouldBlock as i64)
    {
        return Err("second wait_set_wait_timeout on an idle set did not return WouldBlock");
    }
    if t3.wrapping_sub(t2) < 40_000
    {
        return Err("second wait_set_wait_timeout ended early (stale entry from the first wait)");
    }

    child
        .delete_thread()
        .map_err(|_| "cap_delete th after wait_timeout_woken_before_expiry failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after wait_timeout_woken_before_expiry failed")?;
    child
        .delete_cspace()
        .map_err(|_| "cap_delete cs after wait_timeout_woken_before_expiry failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after wait_timeout_woken_before_expiry failed")?;
    Ok(())
}

// ── wait_set_wait (several waiters) ───────────────────────────────────────────

/// The kind of member `shared_set_waiters` makes ready, and how it arrives.
#[derive(Clone, Copy)]
enum SharedMember
{
    /// A notification; each arrival is a `notification_send`.
    Notification,
    /// An event queue; each arrival is an `event_post`.
    EventQueue,
    /// An endpoint; each arrival is a caller's `ipc_call`, which stays queued
    /// (nothing receives on the endpoint).
    Endpoint,
}

/// The caps and children one `shared_set_waiters` phase creates; each is
/// deleted on every path.
#[derive(Default)]
struct Shared
{
    ws: Option<u64>,
    member: Option<u64>,
    done: Option<u64>,
    waiters: [Option<crate::spawn::SpawnedChild>; 2],
    callers: [Option<crate::spawn::SpawnedChild>; 2],
}

// Child stacks and IPC pages for the endpoint phase's two callers, which the
// phase deletes on every path.
static mut SHARED_CALLER_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];
static mut SHARED_CALLER_PAGES: [crate::IpcPage; 2] = [crate::IpcPage::ZERO; 2];

/// Two threads wait on one wait set at once, and each arrival of work on its
/// member wakes one of them: the first arrival wakes exactly one waiter with
/// the member's badge and leaves the other parked, and the second arrival
/// wakes the other. One phase per member kind: a notification, an event queue
/// (two posts), and an endpoint (two queued calls). Fails if the set refuses
/// or fails the second wait, if one arrival wakes both waiters, or if an
/// arrival while the member is still ready wakes no one (a source that
/// notifies the set only on its empty-to-non-empty transition).
pub fn shared_set_waiters(ctx: &TestContext) -> TestResult
{
    for member in [
        SharedMember::Notification,
        SharedMember::EventQueue,
        SharedMember::Endpoint,
    ]
    {
        let mut sh = Shared::default();
        let result = shared_run(ctx, member, &mut sh);
        // Deleting a thread tears the child down wherever it is, so the
        // stacks are free even when the phase failed with a child parked.
        let mut ok = true;
        for child in sh.waiters.iter_mut().chain(sh.callers.iter_mut()).flatten()
        {
            ok &= child.delete_thread().is_ok();
            ok &= child.delete_cspace().is_ok();
        }
        for cap in [sh.ws, sh.member, sh.done].into_iter().flatten()
        {
            ok &= cap_delete(cap).is_ok();
        }
        result?;
        if !ok
        {
            return Err("wait_set::shared_set_waiters: cap_delete in cleanup failed");
        }
    }
    Ok(())
}

/// Create the set, its `member`, and `done`; park both waiters; then make two
/// arrivals on the member, requiring one wake for each.
fn shared_run(ctx: &TestContext, member: SharedMember, sh: &mut Shared) -> TestResult
{
    let ws = *sh.ws.insert(
        wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
            .map_err(|_| "wait_set::shared_set_waiters: wait_set_create failed")?,
    );
    let source = *sh.member.insert(
        match member
        {
            SharedMember::Notification => cap_create_notification(ctx.memory_base),
            SharedMember::EventQueue => event_queue_create(ctx.memory_base, 4),
            SharedMember::Endpoint => cap_create_endpoint(ctx.memory_base),
        }
        .map_err(|_| "wait_set::shared_set_waiters: creating the member failed")?,
    );
    let done = *sh.done.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "wait_set::shared_set_waiters: cap_create_notification (done) failed")?,
    );
    wait_set_add(ws, source, SHARED_BADGE)
        .map_err(|_| "wait_set::shared_set_waiters: wait_set_add failed")?;

    let entries: [extern "C" fn(u64) -> !; 2] = [shared_waiter_0, shared_waiter_1];
    let mut acc = 0;
    for (k, entry) in entries.into_iter().enumerate()
    {
        let spawned = crate::spawn::new_child(ctx)
            .map_err(|_| "wait_set::shared_set_waiters: spawn::new_child failed")?;
        let child = sh
            .waiters
            .get_mut(k)
            .ok_or("wait_set::shared_set_waiters: waiter index out of range")?
            .insert(spawned);
        start_shared_child(child, k, entry, ws, done)?;
        // cast_possible_truncation: k < 2.
        #[allow(clippy::cast_possible_truncation)]
        let mask = waiter_bits(k as u32, BIT_READY);
        acc = collect(done, acc, mask)?;
    }
    let _ = thread_sleep(crate::scaled_bound(SETTLE_SLEEP_MS));

    let returned = |k: u32| waiter_bits(k, BIT_OK | BIT_BAD);
    let returned_any = returned(0) | returned(1);
    acc |= notification_wait_timeout(done, SETTLE_SLEEP_MS)
        .map_err(|_| "wait_set::shared_set_waiters: waiting on done failed")?;
    if acc & returned_any != 0
    {
        return Err("wait_set::shared_set_waiters: a waiter returned before any arrival");
    }

    arrive(ctx, member, source, 0, sh)?;
    acc = collect(done, acc, returned_any)?;
    acc |= notification_wait_timeout(done, SETTLE_SLEEP_MS)
        .map_err(|_| "wait_set::shared_set_waiters: waiting on done failed")?;
    let parked: u32 = match (acc & returned(0) != 0, acc & returned(1) != 0)
    {
        (true, false) => 1,
        (false, true) => 0,
        _ => return Err("wait_set::shared_set_waiters: one arrival woke both waiters"),
    };

    arrive(ctx, member, source, 1, sh)?;
    acc = collect(done, acc, returned(parked)).map_err(|_| {
        "wait_set::shared_set_waiters: a second arrival on a still-ready member did not wake \
         the second waiter"
    })?;
    if acc & (waiter_bits(0, BIT_BAD) | waiter_bits(1, BIT_BAD)) != 0
    {
        return Err("wait_set::shared_set_waiters: a waiter returned without the member's badge");
    }
    Ok(())
}

/// Make arrival `n` (0 or 1) of work on `source`, a `member` kind of source.
/// An endpoint's arrival is caller `n`'s call, the caller kept in `sh`.
fn arrive(
    ctx: &TestContext,
    member: SharedMember,
    source: u64,
    n: usize,
    sh: &mut Shared,
) -> TestResult
{
    let err = "wait_set::shared_set_waiters: an arrival on the member failed";
    match member
    {
        SharedMember::Notification => notification_send(source, 0x1).map_err(|_| err),
        SharedMember::EventQueue =>
        {
            event_post(source, 0xA0u64.saturating_add(n as u64)).map_err(|_| err)
        }
        SharedMember::Endpoint =>
        {
            let entries: [extern "C" fn(u64) -> !; 2] = [shared_caller_0, shared_caller_1];
            let caller = sh
                .callers
                .get_mut(n)
                .ok_or(err)?
                .insert(crate::spawn::new_child(ctx).map_err(|_| err)?);
            let c_ep = cap_copy(source, caller.cs, RIGHTS_EP_SEND_GRANT).map_err(|_| err)?;
            let stack_top = ChildStack::top_at(core::ptr::addr_of!(SHARED_CALLER_STACKS), n)?;
            let entry = *entries.get(n).ok_or(err)?;
            // SAFETY: the stack is `SHARED_CALLER_STACKS[n]`, this test's own
            // `ChildStack`, on which no other live thread runs (`ChildStack`'s
            // rule).
            unsafe { crate::spawn::configure_and_start(caller, entry, stack_top, c_ep) }
                .map_err(|_| err)
        }
    }
}

/// Start `child` at `entry` on shared stack `stack`, passing it copies of
/// `ws` and `done` through entry `stack` of [`SHARED_ARGS`].
fn start_shared_child(
    child: &crate::spawn::SpawnedChild,
    stack: usize,
    entry: extern "C" fn(u64) -> !,
    ws: u64,
    done: u64,
) -> TestResult
{
    let c_ws = cap_copy(ws, child.cs, RIGHTS_ALL)
        .map_err(|_| "wait_set: cap_copy(ws) for a waiter failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_NOTIFY)
        .map_err(|_| "wait_set: cap_copy(done) for a waiter failed")?;
    let stack_top = ChildStack::top_at(core::ptr::addr_of!(SHARED_STACKS), stack)?;
    // SAFETY: `stack` < 2; the entry's previous child (a waiter of an earlier
    // test, phase, or run, deleted before it returned) has exited, and this
    // one has not started.
    let arg = unsafe { SHARED_ARGS.publish(stack, (c_ws, c_done)) };
    // SAFETY: the stack is `SHARED_STACKS[stack]`, a `ChildStack` of this
    // module's waiters, on which no other live thread runs (`ChildStack`'s
    // rule).
    unsafe { crate::spawn::configure_and_start(child, entry, stack_top, arg) }
        .map_err(|_| "wait_set: configure_and_start of a waiter failed")
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present,
/// failing when a scaled [`REPORT_MS`] wait passes with nothing new.
fn collect(done: u64, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, crate::scaled_bound(REPORT_MS))
            .map_err(|_| "wait_set::shared_set_waiters: waiting on done failed")?;
        if bits == 0
        {
            return Err("wait_set::shared_set_waiters: a waiter did not report in time");
        }
        acc |= bits;
    }
    Ok(acc)
}

// ── wait_set_wait (stale ready-ring entry) ────────────────────────────────────

/// Badges of `stale_endpoint_entry_skipped`'s endpoint and notification.
const STALE_EP_BADGE: u64 = 21;
const STALE_SIG_BADGE: u64 = 22;
/// `stale_endpoint_entry_skipped`'s `done` bits: the caller is about to call,
/// its call returned `Interrupted`, or it returned otherwise.
const STALE_READY: u64 = 1 << 0;
const STALE_OK: u64 = 1 << 1;
const STALE_BAD: u64 = 1 << 2;

// Child stack and IPC page for `stale_endpoint_entry_skipped`'s caller, which
// the test deletes on every path.
static mut STALE_STACK: ChildStack = ChildStack::ZERO;
static mut STALE_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// `(ep, done)` for the caller, by address.
static STALE_ARGS: crate::spawn::ArgBlock<(u64, u64), 1> = crate::spawn::ArgBlock::new((0, 0));

/// The caps and child `stale_endpoint_entry_skipped` creates; each is deleted
/// on every path.
#[derive(Default)]
struct Stale
{
    ws: Option<u64>,
    ep: Option<u64>,
    sig: Option<u64>,
    done: Option<u64>,
    caller: Option<crate::spawn::SpawnedChild>,
}

/// A ready-ring entry whose source stopped being ready is skipped: a caller
/// queued on a member endpoint while no thread waits pushes the endpoint's
/// entry, a stop of the caller cancels its call and empties the send queue,
/// and a later wait, with a member notification signalled since, returns the
/// notification's badge. Fails if the wait returns the endpoint's badge for
/// a send queue nothing is left on, which sends the waiter to a receive that
/// blocks (core/kernel/docs/ipc-internals.md § Wait Path).
pub fn stale_endpoint_entry_skipped(ctx: &TestContext) -> TestResult
{
    let mut s = Stale::default();
    let result = stale_run(ctx, &mut s);
    // Deleting the caller's thread tears it down wherever it is, so its stack
    // and IPC page are free even when the test failed with it parked.
    let mut ok = true;
    if let Some(mut caller) = s.caller.take()
    {
        ok &= caller.delete_thread().is_ok();
        ok &= caller.delete_cspace().is_ok();
    }
    for cap in [s.ws, s.ep, s.sig, s.done].into_iter().flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    result?;
    if ok
    {
        Ok(())
    }
    else
    {
        Err("wait_set::stale_endpoint_entry_skipped: cap_delete in cleanup failed")
    }
}

/// Build the set of an endpoint and a notification, queue the caller on the
/// endpoint, stop it, signal the notification, and wait once; then restart the
/// caller and require that its call was the cancelled one.
fn stale_run(ctx: &TestContext, s: &mut Stale) -> TestResult
{
    let ws = *s.ws.insert(
        wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
            .map_err(|_| "wait_set::stale_endpoint_entry_skipped: wait_set_create failed")?,
    );
    let ep = *s.ep.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "wait_set::stale_endpoint_entry_skipped: cap_create_endpoint failed")?,
    );
    let sig = *s
        .sig
        .insert(cap_create_notification(ctx.memory_base).map_err(
            |_| "wait_set::stale_endpoint_entry_skipped: cap_create_notification (member) failed",
        )?);
    let done = *s
        .done
        .insert(cap_create_notification(ctx.memory_base).map_err(
            |_| "wait_set::stale_endpoint_entry_skipped: cap_create_notification (done) failed",
        )?);
    wait_set_add(ws, ep, STALE_EP_BADGE)
        .and_then(|()| wait_set_add(ws, sig, STALE_SIG_BADGE))
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: wait_set_add failed")?;

    let caller = s.caller.insert(
        crate::spawn::new_child(ctx)
            .map_err(|_| "wait_set::stale_endpoint_entry_skipped: spawn::new_child failed")?,
    );
    let c_ep = cap_copy(ep, caller.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: cap_copy(ep) failed")?;
    let c_done = cap_copy(done, caller.cs, RIGHTS_NOTIFY)
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: cap_copy(done) failed")?;
    // SAFETY: the caller has not been started, and no other thread reads the
    // entry.
    let arg = unsafe { STALE_ARGS.publish(0, (c_ep, c_done)) };
    let stack_top = ChildStack::top(core::ptr::addr_of!(STALE_STACK));
    // SAFETY: the stack is `STALE_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(caller, stale_caller, stack_top, arg) }
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: configure_and_start failed")?;

    let mut acc = stale_collect(done, 0, STALE_READY)?;
    // Let the caller reach its park on the send queue; whether it did is
    // checked after the wait, from its call's result.
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    thread_stop(caller.th)
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: thread_stop failed")?;
    notification_send(sig, 0x1)
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: notification_send failed")?;
    let badge = wait_set_wait(ws)
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: wait_set_wait failed")?;
    thread_start(caller.th)
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: thread_start failed")?;
    acc = stale_collect(done, acc, STALE_OK | STALE_BAD)?;
    if acc & STALE_OK == 0
    {
        return Err("wait_set::stale_endpoint_entry_skipped: the caller's call was not cancelled");
    }
    if badge != STALE_SIG_BADGE
    {
        return Err(
            "wait_set::stale_endpoint_entry_skipped: wait_set_wait returned the endpoint whose \
             only sender was stopped, not the signalled notification",
        );
    }
    notification_wait(sig)
        .map(|_| ())
        .map_err(|_| "wait_set::stale_endpoint_entry_skipped: draining the notification failed")
}

/// Accumulate `done` bits into `acc` until any bit of `mask` is present. A
/// caller stopped before it parked parks once restarted, with no canceller,
/// and so never reports: that run fails here rather than hanging.
fn stale_collect(done: u64, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, crate::scaled_bound(REPORT_MS))
            .map_err(|_| "wait_set::stale_endpoint_entry_skipped: waiting on done failed")?;
        if bits == 0
        {
            return Err(
                "wait_set::stale_endpoint_entry_skipped: the caller did not report (stopped \
                 before it parked in ipc_call)",
            );
        }
        acc |= bits;
    }
    Ok(acc)
}

/// `stale_endpoint_entry_skipped`'s caller: register its IPC page, announce
/// the call, then call the endpoint, which no thread receives on; report
/// whether the call returned `Interrupted`.
extern "C" fn stale_caller(arg: u64) -> !
{
    // SAFETY: `arg` is the `STALE_ARGS` entry `stale_run` published.
    let (ep, done): (u64, u64) = unsafe { crate::spawn::child_args(arg) };
    let buf = core::ptr::addr_of_mut!(STALE_IPC_PAGE).cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page (the static
    // above), registered by one thread at a time; no Rust object lives in it,
    // and the thread reaches it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }
    notification_send(done, STALE_READY).ok();
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let bit = match unsafe { ipc::ipc_call(ep, &ipc::IpcMessage::new(0), buf) }
    {
        Err(e) if e == SyscallError::Interrupted as i64 => STALE_OK,
        _ => STALE_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

// ── SYS_WAIT_SET_REMOVE ───────────────────────────────────────────────────────

/// After `wait_set_remove`, the removed source no longer wakes the wait set.
///
/// Registers a notification (badge 1) and an event queue (badge 2). Removes the
/// notification. Posts to the event queue and verifies only badge 2 fires.
pub fn remove(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create for remove test failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for remove test failed")?;
    let eq = event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "event_queue_create for remove test failed")?;

    wait_set_add(ws, sig, 1).map_err(|_| "wait_set_add(sig) for remove test failed")?;
    wait_set_add(ws, eq, 2).map_err(|_| "wait_set_add(eq) for remove test failed")?;

    // Remove the notification — only the queue remains.
    wait_set_remove(ws, sig).map_err(|_| "wait_set_remove(sig) failed")?;

    // Post to the queue; wait_set_wait must return badge 2.
    event_post(eq, 0xFF).map_err(|_| "event_post after remove failed")?;
    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait after remove failed")?;
    if tok != 2
    {
        return Err("wait_set_wait returned wrong badge after notification removed (expected 2)");
    }

    // Drain the queue.
    event_recv(eq).map_err(|_| "event_recv to drain after remove test failed")?;

    cap_delete(eq).map_err(|_| "cap_delete eq after remove test failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after remove test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after remove test failed")?;
    Ok(())
}

// ── Source pin via wait-set membership (refcount invariant) ──────────────────

/// Dropping the only user-held cap to a notification that is a wait-set member
/// leaves it live: a later `wait_set_wait` returns the member's badge, and
/// dropping the wait-set cap then reclaims the notification. The membership
/// reference rule is in core/kernel/docs/ipc-internals.md § Wait Set Add/Remove.
pub fn source_notification_pinned_by_member(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create failed")?;
    let sig =
        cap_create_notification(ctx.memory_base).map_err(|_| "cap_create_notification failed")?;

    wait_set_add(ws, sig, 31).map_err(|_| "wait_set_add(sig) failed")?;
    notification_send(sig, 0xCAFE).map_err(|_| "notification_send before drop failed")?;

    // Drop the only user-held cap to the notification while it is a wait-set
    // member (membership reference: core/kernel/docs/ipc-internals.md § Wait Set
    // Add/Remove).
    cap_delete(sig).map_err(|_| "cap_delete(sig) while member-bound failed")?;

    // `wait_set_wait` returns the member's badge, which the `notification_send`
    // above queued on the wait set's ready ring.
    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait after sig cap drop failed")?;
    if tok != 31
    {
        return Err("wait_set_wait returned wrong badge after sig cap drop");
    }

    // Cascade-reclaims the notification state through wait_set_drop's dec_ref.
    cap_delete(ws).map_err(|_| "cap_delete(ws) cascade-drop failed")?;
    Ok(())
}

/// Symmetric to `source_notification_pinned_by_member` for `EventQueue`: the
/// `event_post` before the cap drop queues the member on the wait set's ready
/// ring, so the post-drop `wait_set_wait` returns its badge.
pub fn source_eventqueue_pinned_by_member(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create failed")?;
    let eq = event_queue_create(ctx.memory_base, 4).map_err(|_| "event_queue_create failed")?;

    wait_set_add(ws, eq, 73).map_err(|_| "wait_set_add(eq) failed")?;
    event_post(eq, 0xABCD_EF01).map_err(|_| "event_post before drop failed")?;

    cap_delete(eq).map_err(|_| "cap_delete(eq) while member-bound failed")?;

    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait after eq cap drop failed")?;
    if tok != 73
    {
        return Err("wait_set_wait returned wrong badge after eq cap drop");
    }

    cap_delete(ws).map_err(|_| "cap_delete(ws) cascade-drop failed")?;
    Ok(())
}

/// Endpoint smoke variant. We can't easily make an endpoint "ready" without
/// pre-queueing a sender, so this test only verifies that dropping the cap to
/// a member-bound endpoint and then dropping the wait-set cap completes
/// without UAF — the source is reclaimed via `wait_set_drop`'s cascade.
pub fn source_endpoint_pinned_by_member(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "wait_set_create failed")?;
    let ep = cap_create_endpoint(ctx.memory_base).map_err(|_| "cap_create_endpoint failed")?;

    wait_set_add(ws, ep, 19).map_err(|_| "wait_set_add(ep) failed")?;

    // Drop the only user-held cap to the endpoint while it is a wait-set member
    // (membership reference: core/kernel/docs/ipc-internals.md § Wait Set Add/Remove).
    cap_delete(ep).map_err(|_| "cap_delete(ep) while member-bound failed")?;

    // Cascade-reclaims the endpoint state through wait_set_drop's dec_ref.
    cap_delete(ws).map_err(|_| "cap_delete(ws) cascade-drop failed")?;
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

extern "C" fn sender_entry(sig_slot: u64) -> !
{
    notification_send(sig_slot, 0xBEEF).ok();
    thread_exit()
}

/// Sleep 20 ms, then signal `sig_slot` and exit.
extern "C" fn delayed_sender_entry(sig_slot: u64) -> !
{
    thread_sleep(20).ok();
    notification_send(sig_slot, 0x1).ok();
    thread_exit()
}

/// Announce, wait once on the shared set, and report waiter `k`'s verdict;
/// `arg` is the waiter's [`SHARED_ARGS`] entry. The waiter does not receive on
/// the member, so the member stays ready after its wake.
fn shared_waiter(arg: u64, k: u32) -> !
{
    // SAFETY: `arg` is the `SHARED_ARGS` entry `start_shared_child` published
    // for this waiter.
    let (ws, done): (u64, u64) = unsafe { crate::spawn::child_args(arg) };
    notification_send(done, waiter_bits(k, BIT_READY)).ok();
    let bit = match wait_set_wait(ws)
    {
        Ok(SHARED_BADGE) => BIT_OK,
        _ => BIT_BAD,
    };
    notification_send(done, waiter_bits(k, bit)).ok();
    thread_exit()
}

/// Waiter 0's entry.
extern "C" fn shared_waiter_0(arg: u64) -> !
{
    shared_waiter(arg, 0)
}

/// Waiter 1's entry.
extern "C" fn shared_waiter_1(arg: u64) -> !
{
    shared_waiter(arg, 1)
}

/// Register caller `n`'s IPC page and call the endpoint `ep`, which nothing
/// receives on: the call stays queued until the phase deletes the caller.
fn shared_caller(ep: u64, n: usize) -> !
{
    let Some(page) = crate::elem_ptr_mut(core::ptr::addr_of_mut!(SHARED_CALLER_PAGES), n)
    else
    {
        thread_exit()
    };
    let buf = page.cast::<u64>();
    // SAFETY: the page is caller `n`'s own, registered by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the thread reaches
    // it only through the raw `buf` pointer.
    if unsafe { ipc_buffer_set(buf as u64) }.is_err()
    {
        thread_exit()
    }
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep, &ipc::IpcMessage::new(0), buf) };
    thread_exit()
}

/// Caller 0's entry.
extern "C" fn shared_caller_0(ep: u64) -> !
{
    shared_caller(ep, 0)
}

/// Caller 1's entry.
extern "C" fn shared_caller_1(ep: u64) -> !
{
    shared_caller(ep, 1)
}
