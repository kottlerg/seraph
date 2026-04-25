// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/event.rs

//! Tier 1 tests for event queue syscalls.
//!
//! Covers: `SYS_CAP_CREATE_EVENT_Q`, `SYS_EVENT_POST`, `SYS_EVENT_RECV`.
//!
//! All tests are single-threaded — `event_post` is non-blocking and `event_recv`
//! blocks only when the queue is empty. We pre-fill queues before receiving.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, event_post,
    event_queue_create, event_recv, signal_send, signal_wait, thread_configure, thread_exit,
    thread_start, thread_yield,
};
use syscall_abi::SyscallError;

use crate::{ChildStack, TestContext, TestResult};

// Child stack for the recv_blocks_until_post test.
static mut RECV_BLOCKS_STACK: ChildStack = ChildStack::ZERO;

// ── SYS_CAP_CREATE_EVENT_Q ───────────────────────────────────────────────────

/// `event_queue_create` returns a valid slot for a queue of the given capacity.
pub fn create(_ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(4).map_err(|_| "event_queue_create(4) failed")?;
    cap_delete(eq).map_err(|_| "cap_delete after event queue create failed")?;
    Ok(())
}

// ── SYS_EVENT_POST / SYS_EVENT_RECV ──────────────────────────────────────────

/// `event_post` enqueues payloads and `event_recv` dequeues them in FIFO order.
pub fn post_recv_fifo(_ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(4).map_err(|_| "event_queue_create for FIFO test failed")?;

    event_post(eq, 0x100).map_err(|_| "event_post(0x100) failed")?;
    event_post(eq, 0x200).map_err(|_| "event_post(0x200) failed")?;
    event_post(eq, 0x300).map_err(|_| "event_post(0x300) failed")?;

    let p0 = event_recv(eq).map_err(|_| "event_recv[0] failed")?;
    let p1 = event_recv(eq).map_err(|_| "event_recv[1] failed")?;
    let p2 = event_recv(eq).map_err(|_| "event_recv[2] failed")?;

    if p0 != 0x100
    {
        return Err("event_recv[0] returned wrong payload (expected 0x100)");
    }
    if p1 != 0x200
    {
        return Err("event_recv[1] returned wrong payload (expected 0x200)");
    }
    if p2 != 0x300
    {
        return Err("event_recv[2] returned wrong payload (expected 0x300)");
    }

    cap_delete(eq).map_err(|_| "cap_delete after FIFO test failed")?;
    Ok(())
}

// ── SYS_EVENT_POST negative ───────────────────────────────────────────────────

/// `event_post` on a full queue returns `QueueFull`.
///
/// A capacity-1 queue accepts exactly one post; the second returns an error.
pub fn queue_full_err(_ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(1).map_err(|_| "event_queue_create(1) failed")?;

    event_post(eq, 0xAA).map_err(|_| "first event_post to capacity-1 queue failed")?;

    let err = event_post(eq, 0xBB);
    if err != Err(SyscallError::QueueFull as i64)
    {
        return Err("second event_post to full queue did not return QueueFull");
    }

    // Drain so queue cap can be cleanly deleted.
    event_recv(eq).map_err(|_| "event_recv after full-queue test failed")?;
    cap_delete(eq).map_err(|_| "cap_delete after full-queue test failed")?;
    Ok(())
}

// ── SYS_EVENT_RECV (blocking path) ────────────────────────────────────────────

/// `event_recv` on an empty queue blocks; a subsequent `event_post` wakes it.
///
/// A child thread calls `event_recv` on an initially empty queue. The main
/// thread yields once to let the child block, then posts 0x42. The child
/// verifies the received payload and reports it back via a signal.
pub fn recv_blocks_until_post(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(4).map_err(|_| "event_queue_create failed")?;
    let sync = cap_create_signal().map_err(|_| "cap_create_signal for sync failed")?;

    let cs = cap_create_cspace(16).map_err(|_| "cap_create_cspace failed")?;
    // Pass all rights for the queue; SIGNAL right for the sync signal.
    let child_eq = cap_copy(eq, cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy eq failed")?;
    let child_sync = cap_copy(sync, cs, 1 << 7).map_err(|_| "cap_copy sync failed")?;
    let child_arg = u64::from(child_eq) | (u64::from(child_sync) << 16);

    let th = cap_create_thread(ctx.aspace_cap, cs).map_err(|_| "cap_create_thread failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(RECV_BLOCKS_STACK));
    thread_configure(
        th,
        recv_and_report_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure failed")?;
    thread_start(th).map_err(|_| "thread_start failed")?;

    // Yield to let the child run and block on event_recv (queue is empty).
    thread_yield().map_err(|_| "thread_yield failed")?;

    // Post a value — the blocked child wakes and receives it.
    event_post(eq, 0x42).map_err(|_| "event_post failed")?;

    // Child sends the received value back via the sync signal.
    let bits = signal_wait(sync).map_err(|_| "signal_wait for result failed")?;
    if bits != 0x42
    {
        return Err("child received wrong event payload (expected 0x42)");
    }

    cap_delete(th).ok();
    cap_delete(eq).ok();
    cap_delete(sync).ok();
    cap_delete(cs).ok();
    Ok(())
}

// ── SYS_EVENT_POST (insufficient rights) ─────────────────────────────────────

/// `event_post` on a cap without POST right must fail.
pub fn post_insufficient_rights(_ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(4).map_err(|_| "event_queue_create for post_rights test failed")?;

    // Derive with RECV right only (bit 10), no POST (bit 9).
    let recv_only =
        syscall::cap_derive(eq, 1 << 10).map_err(|_| "cap_derive for post_rights test failed")?;

    let err = event_post(recv_only, 0x42);
    if err != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("event_post on RECV-only cap did not return InsufficientRights");
    }

    cap_delete(recv_only).map_err(|_| "cap_delete recv_only failed")?;
    cap_delete(eq).map_err(|_| "cap_delete eq after post_rights test failed")?;
    Ok(())
}

// ── SYS_EVENT_RECV (insufficient rights) ─────────────────────────────────────

/// `event_recv` on a cap without RECV right must fail.
///
/// Pre-posts a value so we test rights, not blocking.
pub fn recv_insufficient_rights(_ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(4).map_err(|_| "event_queue_create for recv_rights test failed")?;

    // Post a value first so the queue is non-empty.
    event_post(eq, 0x42).map_err(|_| "event_post for recv_rights test failed")?;

    // Derive with POST right only (bit 9), no RECV (bit 10).
    let post_only =
        syscall::cap_derive(eq, 1 << 9).map_err(|_| "cap_derive for recv_rights test failed")?;

    let err = event_recv(post_only);
    if err != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("event_recv on POST-only cap did not return InsufficientRights");
    }

    // Drain via full-rights cap.
    event_recv(eq).ok();
    cap_delete(post_only).map_err(|_| "cap_delete post_only failed")?;
    cap_delete(eq).map_err(|_| "cap_delete eq after recv_rights test failed")?;
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

/// Child: blocks on `event_recv` then signals the received payload back.
///
/// `arg`: bits[15:0] = `eq_slot`, bits[31:16] = `sync_slot` (in child's `CSpace`).
fn recv_and_report_entry(arg: u64) -> !
{
    let eq_slot = (arg & 0xFFFF) as u32;
    let sync_slot = ((arg >> 16) & 0xFFFF) as u32;

    match event_recv(eq_slot)
    {
        Ok(val) =>
        {
            signal_send(sync_slot, val).ok();
        }
        Err(_) =>
        {
            signal_send(sync_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}
