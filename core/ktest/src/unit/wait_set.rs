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
//! unless the unpinned child signals first), and the refusal of a second
//! concurrent waiter. The remove test verifies that only the remaining member
//! can wake the wait set after removal.

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, event_post,
    event_queue_create, event_recv, notification_send, notification_wait,
    notification_wait_timeout, thread_exit, thread_sleep, wait_set_add, wait_set_create,
    wait_set_remove, wait_set_wait,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult};

// Notification right only (no WAIT). Children only send on notifications.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

// Child stack for the blocking_wait test.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

// Child stacks for occupied_wait_refused's parked waiter (0) and refused
// waiter (1). The test deletes both children on every path, so a failed run
// leaves no thread on either stack.
static mut OCCUPIED_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];

/// `occupied_wait_refused`'s `done` bits: the parked waiter is about to park,
/// and its wait's verdict; the refused waiter's verdict.
const BIT_READY: u64 = 1 << 0;
const BIT_OK: u64 = 1 << 1;
const BIT_BAD: u64 = 1 << 2;
const BIT_REFUSED: u64 = 1 << 3;
const BIT_NOT_REFUSED: u64 = 1 << 4;
const OCCUPIED_BADGE: u64 = 9;
/// Settle after READY so the parked waiter provably parks, and after the
/// refusal so a wake it caused is seen; bound on each report.
const SETTLE_SLEEP_MS: u64 = 20;
const REPORT_MS: u64 = 1000;

// ── wait_set_add (notification, immediate wake) ────────────────────────────────────

/// Signalling a notification already registered in a wait set causes
/// `wait_set_wait` to return immediately with the member's badge (the send
/// queues the member on the wait set's ready ring).
pub fn add_notification_immediate(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create failed")?;
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
    let ws =
        wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create for ws-queue test failed")?;
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

// ── wait_set_wait (blocking) ──────────────────────────────────────────────────

/// A child thread signals a registered notification and `wait_set_wait` returns
/// its badge: the parent blocks if it waits first, or, if the unpinned child runs
/// first on another CPU, returns the badge already queued on the ready ring.
pub fn blocking_wait(ctx: &TestContext) -> TestResult
{
    let ws =
        wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create for blocking test failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for blocking test failed")?;

    wait_set_add(ws, sig, 7).map_err(|_| "wait_set_add for blocking test failed")?;

    // Set up a child thread that sends on the notification.
    let child =
        crate::spawn::new_child(ctx).map_err(|_| "spawn::new_child for blocking test failed")?;
    let child_sig =
        cap_copy(sig, child.cs, RIGHTS_NOTIFY).map_err(|_| "cap_copy for blocking test failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, sender_entry, stack_top, u64::from(child_sig))
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

    cap_delete(child.th).map_err(|_| "cap_delete th after blocking test failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after blocking test failed")?;
    cap_delete(child.cs).map_err(|_| "cap_delete cs after blocking test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after blocking test failed")?;
    Ok(())
}

// ── wait_set_wait (occupied set) ──────────────────────────────────────────────

/// The caps and children `occupied_wait_refused` creates; each is deleted on
/// every path.
#[derive(Default)]
struct Occupied
{
    ws: Option<u32>,
    sig: Option<u32>,
    done: Option<u32>,
    parked: Option<crate::spawn::SpawnedChild>,
    refused: Option<crate::spawn::SpawnedChild>,
}

/// While a child waits on a wait set, a second child's `wait_set_wait`
/// returns `InvalidState` at once and the first child's wait is unaffected:
/// it does not return, and a member fire still reaches it.
pub fn occupied_wait_refused(ctx: &TestContext) -> TestResult
{
    let mut o = Occupied::default();
    let result = occupied_run(ctx, &mut o);
    // Deleting a thread tears the child down wherever it is, so the stacks
    // are free even when the test failed with a child still parked.
    let mut ok = true;
    for child in [o.parked, o.refused].iter().flatten()
    {
        ok &= cap_delete(child.th).is_ok();
        ok &= cap_delete(child.cs).is_ok();
    }
    for cap in [o.ws, o.sig, o.done].into_iter().flatten()
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
        Err("cap_delete after occupied test failed")
    }
}

/// Create the set, its member, and `done`; park the first child on the set;
/// have the second child's wait refused; then release the first child.
fn occupied_run(ctx: &TestContext, o: &mut Occupied) -> TestResult
{
    let ws = *o.ws.insert(
        wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create for occupied failed")?,
    );
    let sig = *o.sig.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "cap_create_notification (member) for occupied failed")?,
    );
    let done = *o.done.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "cap_create_notification (done) for occupied failed")?,
    );
    wait_set_add(ws, sig, OCCUPIED_BADGE).map_err(|_| "wait_set_add for occupied failed")?;

    let parked = o
        .parked
        .insert(crate::spawn::new_child(ctx).map_err(|_| "spawn::new_child for occupied failed")?);
    start_occupied_child(parked, 0, occupied_waiter_entry, ws, done)?;
    let mut acc = collect(done, 0, BIT_READY)?;
    thread_sleep(SETTLE_SLEEP_MS).map_err(|_| "settle sleep for occupied failed")?;

    let refused = o
        .refused
        .insert(crate::spawn::new_child(ctx).map_err(|_| "spawn::new_child for occupied failed")?);
    start_occupied_child(refused, 1, refused_waiter_entry, ws, done)?;
    acc = collect(done, acc, BIT_REFUSED | BIT_NOT_REFUSED)?;
    if acc & BIT_NOT_REFUSED != 0
    {
        return Err("a second wait_set_wait on an occupied set was not refused with InvalidState");
    }
    acc |= notification_wait_timeout(done, SETTLE_SLEEP_MS)
        .map_err(|_| "notification_wait_timeout on done for occupied failed")?;
    if acc & (BIT_OK | BIT_BAD) != 0
    {
        return Err("the parked wait set waiter returned before any member fired");
    }

    notification_send(sig, 0x1).map_err(|_| "notification_send for occupied failed")?;
    acc = collect(done, acc, BIT_OK | BIT_BAD)?;
    if acc & BIT_BAD != 0
    {
        return Err("the parked wait set waiter did not receive the member's badge");
    }
    Ok(())
}

/// Start `child` at `entry` on occupied stack `stack`, passing it copies of
/// `ws` and `done`.
fn start_occupied_child(
    child: &crate::spawn::SpawnedChild,
    stack: usize,
    entry: fn(u64) -> !,
    ws: u32,
    done: u32,
) -> TestResult
{
    let c_ws = cap_copy(ws, child.cs, RIGHTS_ALL).map_err(|_| "cap_copy ws for occupied failed")?;
    let c_done =
        cap_copy(done, child.cs, RIGHTS_NOTIFY).map_err(|_| "cap_copy done for occupied failed")?;
    // SAFETY: each occupied stack belongs to one of this test's two children,
    // which the test deletes before returning; unit tests run sequentially.
    let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(OCCUPIED_STACKS[stack]) });
    crate::spawn::configure_and_start(
        child,
        entry,
        stack_top,
        u64::from(c_ws) | (u64::from(c_done) << 32),
    )
    .map_err(|_| "configure_and_start for occupied failed")
}

/// Accumulate `done` bits onto `acc` until any bit of `mask` is present,
/// failing when a [`REPORT_MS`] wait passes with nothing new.
fn collect(done: u32, mut acc: u64, mask: u64) -> Result<u64, &'static str>
{
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, REPORT_MS)
            .map_err(|_| "notification_wait_timeout on done for occupied failed")?;
        if bits == 0
        {
            return Err("the wait set waiter did not report in time");
        }
        acc |= bits;
    }
    Ok(acc)
}

// ── SYS_WAIT_SET_REMOVE ───────────────────────────────────────────────────────

/// After `wait_set_remove`, the removed source no longer wakes the wait set.
///
/// Registers a notification (badge 1) and an event queue (badge 2). Removes the
/// notification. Posts to the event queue and verifies only badge 2 fires.
pub fn remove(ctx: &TestContext) -> TestResult
{
    let ws =
        wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create for remove test failed")?;
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
    let ws = wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create failed")?;
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
    let ws = wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create failed")?;
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
    let ws = wait_set_create(ctx.memory_base).map_err(|_| "wait_set_create failed")?;
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

// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(sig_slot: u64) -> !
{
    notification_send(sig_slot as u32, 0xBEEF).ok();
    thread_exit()
}

/// Raise READY, wait once on the set, and report whether it returned the
/// member's badge.
// cast_possible_truncation: packed fields are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn occupied_waiter_entry(arg: u64) -> !
{
    let (ws, done) = ((arg & 0xFFFF_FFFF) as u32, (arg >> 32) as u32);
    notification_send(done, BIT_READY).ok();
    let bit = if wait_set_wait(ws) == Ok(OCCUPIED_BADGE)
    {
        BIT_OK
    }
    else
    {
        BIT_BAD
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Wait once on the occupied set and report whether the wait was refused
/// with `InvalidState`.
// cast_possible_truncation: packed fields are 32-bit cap handles.
#[allow(clippy::cast_possible_truncation)]
fn refused_waiter_entry(arg: u64) -> !
{
    let (ws, done) = ((arg & 0xFFFF_FFFF) as u32, (arg >> 32) as u32);
    let bit = if wait_set_wait(ws) == Err(SyscallError::InvalidState as i64)
    {
        BIT_REFUSED
    }
    else
    {
        BIT_NOT_REFUSED
    };
    notification_send(done, bit).ok();
    thread_exit()
}
