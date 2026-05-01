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
    event_queue_create, event_recv, event_recv_timeout, event_try_recv, signal_send, signal_wait,
    system_info, thread_configure, thread_exit, thread_sleep, thread_start, thread_yield,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

// Child stack for the recv_blocks_until_post test.
static mut RECV_BLOCKS_STACK: ChildStack = ChildStack::ZERO;
// Child stacks for the timeout tests (each test owns its own stack).
static mut TIMEOUT_ZERO_PAYLOAD_STACK: ChildStack = ChildStack::ZERO;
static mut TIMEOUT_NONZERO_PAYLOAD_STACK: ChildStack = ChildStack::ZERO;
static mut TIMEOUT_FOREVER_STACK: ChildStack = ChildStack::ZERO;

// ── SYS_CAP_CREATE_EVENT_Q ───────────────────────────────────────────────────

/// `event_queue_create` returns a valid slot for a queue of the given capacity.
pub fn create(ctx: &TestContext) -> TestResult
{
    let eq =
        event_queue_create(ctx.memory_frame_base, 4).map_err(|_| "event_queue_create(4) failed")?;
    cap_delete(eq).map_err(|_| "cap_delete after event queue create failed")?;
    Ok(())
}

// ── SYS_EVENT_POST / SYS_EVENT_RECV ──────────────────────────────────────────

/// `event_post` enqueues payloads and `event_recv` dequeues them in FIFO order.
pub fn post_recv_fifo(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for FIFO test failed")?;

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
pub fn queue_full_err(ctx: &TestContext) -> TestResult
{
    let eq =
        event_queue_create(ctx.memory_frame_base, 1).map_err(|_| "event_queue_create(1) failed")?;

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
    let eq =
        event_queue_create(ctx.memory_frame_base, 4).map_err(|_| "event_queue_create failed")?;
    let sync = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for sync failed")?;

    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace failed")?;
    // Pass all rights for the queue; SIGNAL right for the sync signal.
    let child_eq = cap_copy(eq, cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy eq failed")?;
    let child_sync = cap_copy(sync, cs, 1 << 7).map_err(|_| "cap_copy sync failed")?;
    let child_arg = u64::from(child_eq) | (u64::from(child_sync) << 16);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread failed")?;
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
pub fn post_insufficient_rights(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for post_rights test failed")?;

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
pub fn recv_insufficient_rights(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for recv_rights test failed")?;

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

// ── SYS_EVENT_RECV (timeout sentinels) ───────────────────────────────────────

/// `event_try_recv` (`arg1 = u64::MAX`) on an empty queue returns `WouldBlock`.
///
/// Positive control: pre-post then `event_try_recv` returns the payload.
pub fn try_recv_empty_returns_wouldblock(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for try_recv test failed")?;

    let err = event_try_recv(eq);
    if err != Err(SyscallError::WouldBlock as i64)
    {
        return Err("event_try_recv on empty queue did not return WouldBlock");
    }

    event_post(eq, 0xABCD).map_err(|_| "event_post for try_recv positive control failed")?;
    let payload = event_try_recv(eq).map_err(|_| "event_try_recv after post failed")?;
    if payload != 0xABCD
    {
        return Err("event_try_recv returned wrong payload (expected 0xABCD)");
    }

    cap_delete(eq).map_err(|_| "cap_delete after try_recv test failed")?;
    Ok(())
}

/// `event_recv_timeout` fires the timer when no post arrives within the bound.
///
/// Asserts the call returns `WouldBlock` and that elapsed wall-clock time is
/// at least most of the requested 50 ms (generous lower bound to absorb QEMU
/// timer jitter; no upper bound enforced — only correctness, not latency).
pub fn recv_timeout_fires_on_empty_queue(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for timeout test failed")?;

    let t0 = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "system_info(ElapsedUs) before recv failed")?;
    let err = event_recv_timeout(eq, 50);
    let t1 = system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "system_info(ElapsedUs) after recv failed")?;

    if err != Err(SyscallError::WouldBlock as i64)
    {
        return Err("event_recv_timeout on empty queue did not return WouldBlock");
    }
    let elapsed_us = t1.saturating_sub(t0);
    // Allow some slack below 50 ms for tick boundary alignment.
    if elapsed_us < 30_000
    {
        return Err("event_recv_timeout returned too quickly — timer did not bound the wait");
    }

    cap_delete(eq).map_err(|_| "cap_delete after timeout test failed")?;
    Ok(())
}

/// Critical disambiguation test: a legitimate-zero payload must NOT be
/// confused with the timer-fired outcome. Without `tcb.timed_out`, this
/// regresses to `WouldBlock` even though a real post arrived.
pub fn recv_timeout_payload_zero_wins(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for zero-payload test failed")?;
    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace failed")?;
    let child_eq = cap_copy(eq, cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy eq failed")?;
    // Encode the post payload as 0; the child will sleep ~10 ms, then post 0.
    let child_arg = u64::from(child_eq);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(TIMEOUT_ZERO_PAYLOAD_STACK));
    thread_configure(
        th,
        post_zero_after_sleep_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure failed")?;
    thread_start(th).map_err(|_| "thread_start failed")?;

    // Wait up to 1 s for the child's post; 0 is the legitimate payload.
    let payload = event_recv_timeout(eq, 1000)
        .map_err(|_| "event_recv_timeout with pending post returned an error (timeout misread?)")?;
    if payload != 0
    {
        return Err("event_recv_timeout returned wrong payload (expected legitimate 0)");
    }

    cap_delete(th).ok();
    cap_delete(eq).ok();
    cap_delete(cs).ok();
    Ok(())
}

/// Same as the zero-payload disambiguation test but with a non-zero payload,
/// guarding the data path itself.
pub fn recv_timeout_payload_nonzero_wins(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for nonzero-payload test failed")?;
    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace failed")?;
    let child_eq = cap_copy(eq, cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy eq failed")?;
    let child_arg = u64::from(child_eq);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(TIMEOUT_NONZERO_PAYLOAD_STACK));
    thread_configure(
        th,
        post_cafe_after_sleep_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure failed")?;
    thread_start(th).map_err(|_| "thread_start failed")?;

    let payload = event_recv_timeout(eq, 1000).map_err(|_| "event_recv_timeout failed")?;
    if payload != 0xCAFE
    {
        return Err("event_recv_timeout returned wrong payload (expected 0xCAFE)");
    }

    cap_delete(th).ok();
    cap_delete(eq).ok();
    cap_delete(cs).ok();
    Ok(())
}

/// `event_recv_timeout(eq, 0)` blocks indefinitely (sentinel preserves the
/// `arg1 = 0` semantics of `event_recv`).
pub fn recv_timeout_zero_blocks_forever(ctx: &TestContext) -> TestResult
{
    let eq = event_queue_create(ctx.memory_frame_base, 4)
        .map_err(|_| "event_queue_create for forever-block test failed")?;
    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace failed")?;
    let child_eq = cap_copy(eq, cs, syscall::RIGHTS_ALL).map_err(|_| "cap_copy eq failed")?;
    let child_arg = u64::from(child_eq);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "cap_create_thread failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(TIMEOUT_FOREVER_STACK));
    thread_configure(
        th,
        post_beef_after_sleep_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure failed")?;
    thread_start(th).map_err(|_| "thread_start failed")?;

    let payload = event_recv_timeout(eq, 0)
        .map_err(|_| "event_recv_timeout(eq, 0) returned error (forever-block sentinel broken)")?;
    if payload != 0xBEEF
    {
        return Err("event_recv_timeout(eq, 0) returned wrong payload (expected 0xBEEF)");
    }

    cap_delete(th).ok();
    cap_delete(eq).ok();
    cap_delete(cs).ok();
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

/// Child: sleeps ~10 ms then posts payload `0` (the legitimate-zero
/// disambiguation case).
fn post_zero_after_sleep_entry(arg: u64) -> !
{
    let eq_slot = (arg & 0xFFFF_FFFF) as u32;
    let _ = thread_sleep(10);
    let _ = event_post(eq_slot, 0);
    thread_exit()
}

/// Child: sleeps ~10 ms then posts payload `0xCAFE`.
fn post_cafe_after_sleep_entry(arg: u64) -> !
{
    let eq_slot = (arg & 0xFFFF_FFFF) as u32;
    let _ = thread_sleep(10);
    let _ = event_post(eq_slot, 0xCAFE);
    thread_exit()
}

/// Child: sleeps ~10 ms then posts payload `0xBEEF` (used by the
/// `arg1=0` "block forever" sentinel test).
fn post_beef_after_sleep_entry(arg: u64) -> !
{
    let eq_slot = (arg & 0xFFFF_FFFF) as u32;
    let _ = thread_sleep(10);
    let _ = event_post(eq_slot, 0xBEEF);
    thread_exit()
}
