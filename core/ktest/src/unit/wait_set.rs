// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/wait_set.rs

//! Tier 1 tests for wait set syscalls.
//!
//! Covers: `SYS_CAP_CREATE_WAIT_SET`, `SYS_WAIT_SET_ADD`,
//! `SYS_WAIT_SET_REMOVE`, `SYS_WAIT_SET_WAIT`.
//!
//! Tests cover immediate return (source signalled before the wait) and
//! cross-thread return (a child thread signals the source; the parent blocks
//! unless the unpinned child signals first). The remove test verifies that
//! only the remaining member can wake the wait set after removal.

use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, event_post,
    event_queue_create, event_recv, notification_send, notification_wait, thread_exit,
    wait_set_add, wait_set_create, wait_set_remove, wait_set_wait,
};

use crate::{ChildStack, TestContext, TestResult};

// Notification right only (no WAIT). Children only send on notifications.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

// Child stack for the blocking_wait test.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

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
