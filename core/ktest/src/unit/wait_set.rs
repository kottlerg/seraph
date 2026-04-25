// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/wait_set.rs

//! Tier 1 tests for wait set syscalls.
//!
//! Covers: `SYS_CAP_CREATE_WAIT_SET`, `SYS_WAIT_SET_ADD`,
//! `SYS_WAIT_SET_REMOVE`, `SYS_WAIT_SET_WAIT`.
//!
//! Tests cover immediate return (source already ready) and blocking return
//! (child thread fires source while we wait). The remove test verifies that
//! only the remaining member can wake the wait set after removal.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, event_post,
    event_queue_create, event_recv, signal_send, signal_wait, thread_configure, thread_exit,
    thread_start, wait_set_add, wait_set_create, wait_set_remove, wait_set_wait,
};

use crate::{ChildStack, TestContext, TestResult};

// Signal right only (no WAIT). Children only send on signals.
const RIGHTS_SIGNAL: u64 = 1 << 7;

// Child stack for the blocking_wait test.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

// ── wait_set_add (signal, immediate wake) ────────────────────────────────────

/// Adding a signal with pre-set bits to a wait set causes `wait_set_wait`
/// to return immediately with the correct token.
pub fn add_signal_immediate(_ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create().map_err(|_| "wait_set_create failed")?;
    let sig = cap_create_signal().map_err(|_| "cap_create_signal for ws-signal test failed")?;

    wait_set_add(ws, sig, 42).map_err(|_| "wait_set_add(signal) failed")?;

    // Pre-set bits so the signal is immediately ready.
    signal_send(sig, 0x1).map_err(|_| "signal_send before wait_set_wait failed")?;

    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait(signal, immediate) failed")?;
    if tok != 42
    {
        return Err("wait_set_wait returned wrong token for signal source");
    }

    // Drain the signal bits.
    signal_wait(sig).map_err(|_| "signal_wait to drain after wait_set_wait failed")?;

    cap_delete(sig).map_err(|_| "cap_delete sig after ws-signal test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after ws-signal test failed")?;
    Ok(())
}

// ── wait_set_add (event queue, immediate wake) ────────────────────────────────

/// Adding an event queue with a pre-posted entry causes `wait_set_wait`
/// to return immediately with the correct token.
pub fn add_queue_immediate(_ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create().map_err(|_| "wait_set_create for ws-queue test failed")?;
    let eq = event_queue_create(4).map_err(|_| "event_queue_create for ws-queue test failed")?;

    wait_set_add(ws, eq, 99).map_err(|_| "wait_set_add(queue) failed")?;

    // Pre-post an entry so the queue is immediately ready.
    event_post(eq, 0xEE).map_err(|_| "event_post before wait_set_wait failed")?;

    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait(queue, immediate) failed")?;
    if tok != 99
    {
        return Err("wait_set_wait returned wrong token for queue source");
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

/// `wait_set_wait` blocks until a child thread fires a registered signal.
pub fn blocking_wait(ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create().map_err(|_| "wait_set_create for blocking test failed")?;
    let sig = cap_create_signal().map_err(|_| "cap_create_signal for blocking test failed")?;

    wait_set_add(ws, sig, 7).map_err(|_| "wait_set_add for blocking test failed")?;

    // Set up a child thread that sends on the signal.
    let cs = cap_create_cspace(16).map_err(|_| "cap_create_cspace for blocking test failed")?;
    let child_sig =
        cap_copy(sig, cs, RIGHTS_SIGNAL).map_err(|_| "cap_copy for blocking test failed")?;
    let th = cap_create_thread(ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread for blocking test failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(
        th,
        sender_entry as *const () as u64,
        stack_top,
        u64::from(child_sig),
    )
    .map_err(|_| "thread_configure for blocking test failed")?;
    thread_start(th).map_err(|_| "thread_start for blocking test failed")?;

    // Block until the child fires the signal.
    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait (blocking) failed")?;
    if tok != 7
    {
        return Err("wait_set_wait (blocking) returned wrong token");
    }

    // Drain the signal bits.
    let bits = signal_wait(sig).map_err(|_| "signal_wait to drain after blocking wait failed")?;
    if bits != 0xBEEF
    {
        return Err("signal bits after blocking wait_set_wait are wrong (expected 0xBEEF)");
    }

    cap_delete(th).map_err(|_| "cap_delete th after blocking test failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after blocking test failed")?;
    cap_delete(cs).map_err(|_| "cap_delete cs after blocking test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after blocking test failed")?;
    Ok(())
}

// ── SYS_WAIT_SET_REMOVE ───────────────────────────────────────────────────────

/// After `wait_set_remove`, the removed source no longer wakes the wait set.
///
/// Registers a signal (token 1) and an event queue (token 2). Removes the
/// signal. Posts to the event queue and verifies only token 2 fires.
pub fn remove(_ctx: &TestContext) -> TestResult
{
    let ws = wait_set_create().map_err(|_| "wait_set_create for remove test failed")?;
    let sig = cap_create_signal().map_err(|_| "cap_create_signal for remove test failed")?;
    let eq = event_queue_create(4).map_err(|_| "event_queue_create for remove test failed")?;

    wait_set_add(ws, sig, 1).map_err(|_| "wait_set_add(sig) for remove test failed")?;
    wait_set_add(ws, eq, 2).map_err(|_| "wait_set_add(eq) for remove test failed")?;

    // Remove the signal — only the queue remains.
    wait_set_remove(ws, sig).map_err(|_| "wait_set_remove(sig) failed")?;

    // Post to the queue; wait_set_wait must return token 2.
    event_post(eq, 0xFF).map_err(|_| "event_post after remove failed")?;
    let tok = wait_set_wait(ws).map_err(|_| "wait_set_wait after remove failed")?;
    if tok != 2
    {
        return Err("wait_set_wait returned wrong token after signal removed (expected 2)");
    }

    // Drain the queue.
    event_recv(eq).map_err(|_| "event_recv to drain after remove test failed")?;

    cap_delete(eq).map_err(|_| "cap_delete eq after remove test failed")?;
    cap_delete(sig).map_err(|_| "cap_delete sig after remove test failed")?;
    cap_delete(ws).map_err(|_| "cap_delete ws after remove test failed")?;
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

// cast_possible_truncation: sig_slot is a kernel cap slot index, guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_entry(sig_slot: u64) -> !
{
    signal_send(sig_slot as u32, 0xBEEF).ok();
    thread_exit()
}
