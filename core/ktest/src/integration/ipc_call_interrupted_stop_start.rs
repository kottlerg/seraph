// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/ipc_call_interrupted_stop_start.rs

//! Integration: a client stopped while parked in `ipc_call` and then
//! restarted returns `Interrupted` — never a stale-`ipc_msg` "reply" (#361).
//!
//! `cancel_ipc_block` deposits the cancelled disposition when a stop lands on
//! a parked caller; the caller's resume consumes it instead of reading
//! `ipc_msg` unconditionally. Both park states a `sys_ipc_call` episode can
//! be cancelled in are exercised:
//!
//!   1. **`BlockedOnSend`** — the client calls an endpoint with no receiver and
//!      parks on the send queue; the stop's claim is the send-queue unlink
//!      under `ep.lock`.
//!   2. **`BlockedOnReply`** — a server `ipc_recv`s the client (rebinding it to
//!      awaiting-reply), announces the armed window, and never replies; the
//!      stop's claim is the `reply_tcb` CAS on the server.
//!
//! In each phase the controller stops the parked client, restarts it, and the
//! client itself asserts `ipc_call == Err(Interrupted)` — raising an OK bit
//! on the contract or a BAD bit on any other result (the pre-#361 behavior
//! was a rax=0 "success" carrying stale `ipc_msg` bytes).
//!
//! Runs on a single CPU (the children are timer-preempted peers).

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, thread_exit, thread_start, thread_stop, thread_yield,
};
use syscall_abi::{RIGHTS_RECEIVE, RIGHTS_SEND_GRANT, SyscallError};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification signal right (bit 7) and wait right (bit 8).
const RIGHTS_SIGNAL: u64 = 1 << 7;
const RIGHTS_WAIT: u64 = 1 << 8;

/// Phase 1 (`BlockedOnSend`) bits: client about to call / contract held / broken.
const BIT_P1_READY: u64 = 1 << 0;
const BIT_P1_OK: u64 = 1 << 1;
const BIT_P1_BAD: u64 = 1 << 2;

/// Phase 2 (`BlockedOnReply`) bits: server armed the reply binding / contract
/// held / broken.
const BIT_P2_ARMED: u64 = 1 << 3;
const BIT_P2_OK: u64 = 1 << 4;
const BIT_P2_BAD: u64 = 1 << 5;

/// Bounded yields after a client's READY signal so it provably reaches its
/// park before the stop lands. A stop that lands pre-park stops a Running
/// thread instead — the restart would then park with no canceller and hang to
/// the watchdog, so generous slack is cheap insurance.
const SETTLE_YIELDS: usize = 32;

static mut CLIENT_STACK: ChildStack = ChildStack::ZERO;
static mut SERVER_STACK: ChildStack = ChildStack::ZERO;

/// A page-aligned 4 KiB IPC buffer page per concurrently-live child.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

// SAFETY: used by at most one live client child at a time (phase 1's client
// is reaped before phase 2's is spawned).
static mut CLIENT_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

// SAFETY: used only by phase 2's single server child.
static mut SERVER_IPC_BUF: IpcBufPage = IpcBufPage([0u64; 512]);

pub fn run(ctx: &TestContext) -> TestResult
{
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: create done failed")?;
    let mut acc = 0u64;

    // ── Phase 1: stop while BlockedOnSend (no receiver on the endpoint). ────
    let ep1 = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: create ep1 failed")?;
    let client = spawn::new_child(ctx)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: spawn p1 client failed")?;
    let c_ep = cap_copy(ep1, client.cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy p1 ep failed")?;
    let c_done = cap_copy(done, client.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy p1 done failed")?;
    let arg = pack(c_ep, c_done, BIT_P1_READY, BIT_P1_OK, BIT_P1_BAD);
    // Phase 1's client is the sole user of CLIENT_STACK until reaped.
    let stack = ChildStack::top(core::ptr::addr_of!(CLIENT_STACK));
    spawn::configure_and_start(&client, client_entry, stack, arg)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: start p1 client failed")?;

    wait_for(done, &mut acc, BIT_P1_READY)?;
    for _ in 0..SETTLE_YIELDS
    {
        let _ = thread_yield();
    }
    thread_stop(client.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: p1 thread_stop failed")?;
    thread_start(client.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: p1 thread_start failed")?;
    wait_for(done, &mut acc, BIT_P1_OK | BIT_P1_BAD)?;
    if acc & BIT_P1_BAD != 0
    {
        return Err(
            "integration::ipc_call_interrupted_stop_start: BlockedOnSend stop returned a \
             non-Interrupted result (stale reply surfaced — #361)",
        );
    }
    cap_delete(client.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: reap p1 client failed")?;
    cap_delete(client.cs)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: reap p1 cs failed")?;
    cap_delete(ep1).map_err(|_| "integration::ipc_call_interrupted_stop_start: del ep1 failed")?;

    // ── Phase 2: stop while BlockedOnReply (server recvs, never replies). ───
    let ep2 = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: create ep2 failed")?;
    let block = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: create block failed")?;

    let server = spawn::new_child(ctx)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: spawn server failed")?;
    let s_ep = cap_copy(ep2, server.cs, RIGHTS_RECEIVE)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy s ep failed")?;
    let s_done = cap_copy(done, server.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy s done failed")?;
    let s_block = cap_copy(block, server.cs, RIGHTS_WAIT)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy s block failed")?;
    let s_arg = u64::from(s_ep) | (u64::from(s_done) << 16) | (u64::from(s_block) << 32);
    // Phase 2's server is the sole user of SERVER_STACK.
    let s_stack = ChildStack::top(core::ptr::addr_of!(SERVER_STACK));
    spawn::configure_and_start(&server, server_entry, s_stack, s_arg)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: start server failed")?;

    let client2 = spawn::new_child(ctx)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: spawn p2 client failed")?;
    let p2c_ep = cap_copy(ep2, client2.cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy p2 ep failed")?;
    let p2c_done = cap_copy(done, client2.cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: cap_copy p2 done failed")?;
    let c2_arg = pack(p2c_ep, p2c_done, 0, BIT_P2_OK, BIT_P2_BAD);
    // Phase 1's client was reaped above; CLIENT_STACK is free again.
    let c2_stack = ChildStack::top(core::ptr::addr_of!(CLIENT_STACK));
    spawn::configure_and_start(&client2, client_entry, c2_stack, c2_arg)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: start p2 client failed")?;

    // The armed bit is raised only after the server's `ipc_recv` returns, so
    // its arrival proves the client is BlockedOnReply on the server.
    wait_for(done, &mut acc, BIT_P2_ARMED)?;
    thread_stop(client2.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: p2 thread_stop failed")?;
    thread_start(client2.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: p2 thread_start failed")?;
    wait_for(done, &mut acc, BIT_P2_OK | BIT_P2_BAD)?;
    if acc & BIT_P2_BAD != 0
    {
        return Err(
            "integration::ipc_call_interrupted_stop_start: BlockedOnReply stop returned a \
             non-Interrupted result (stale reply surfaced — #361)",
        );
    }

    // ── Cleanup. The server is parked on `block`; deleting its TCB reaps it. ─
    cap_delete(client2.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: reap p2 client failed")?;
    cap_delete(client2.cs)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: reap p2 cs failed")?;
    cap_delete(server.th)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: reap server failed")?;
    cap_delete(server.cs)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: reap server cs failed")?;
    cap_delete(ep2).map_err(|_| "integration::ipc_call_interrupted_stop_start: del ep2 failed")?;
    cap_delete(block)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: del block failed")?;
    cap_delete(done)
        .map_err(|_| "integration::ipc_call_interrupted_stop_start: del done failed")?;
    Ok(())
}

/// Accumulate `done` bits into `acc` until any bit of `mask` is present.
fn wait_for(done: u32, acc: &mut u64, mask: u64) -> Result<(), &'static str>
{
    while *acc & mask == 0
    {
        let bits = notification_wait(done).map_err(
            |_| "integration::ipc_call_interrupted_stop_start: notification_wait failed",
        )?;
        *acc |= bits;
    }
    Ok(())
}

/// Pack the client arg: ep[15:0] | done[31:16] | ready-bit[39:32] |
/// ok-bit[47:40] | bad-bit[55:48] (the bits are < 64, stored as their log2
/// positions' raw mask truncated to 8 bits each).
fn pack(ep: u32, done: u32, ready: u64, ok: u64, bad: u64) -> u64
{
    u64::from(ep) | (u64::from(done) << 16) | (ready << 32) | (ok << 40) | (bad << 48)
}

/// Client: optionally announce readiness, then `ipc_call`; raise the OK bit
/// iff the call returns `Interrupted`, the BAD bit otherwise.
// cast_possible_truncation: packed fields are cap slots < 2^16 and 8-bit masks.
#[allow(clippy::cast_possible_truncation)]
fn client_entry(arg: u64) -> !
{
    let ep = (arg & 0xFFFF) as u32;
    let done = ((arg >> 16) & 0xFFFF) as u32;
    let ready = (arg >> 32) & 0xFF;
    let ok = (arg >> 40) & 0xFF;
    let bad = (arg >> 48) & 0xFF;

    // SAFETY: sole live user of CLIENT_IPC_BUF (phases run sequentially).
    let buf = core::ptr::addr_of_mut!(CLIENT_IPC_BUF).cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }
    if ready != 0
    {
        notification_send(done, ready).ok();
    }
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let bit = match unsafe { ipc::ipc_call(ep, &IpcMessage::new(0), buf) }
    {
        Err(e) if e == SyscallError::Interrupted as i64 => ok,
        _ => bad,
    };
    notification_send(done, bit).ok();
    thread_exit()
}

/// Server: receive one caller (rebinding it to `BlockedOnReply`), announce the
/// armed window, then park on `block` without ever replying.
// cast_possible_truncation: packed fields are cap slot indices < 2^16.
#[allow(clippy::cast_possible_truncation)]
fn server_entry(arg: u64) -> !
{
    let ep = (arg & 0xFFFF) as u32;
    let done = ((arg >> 16) & 0xFFFF) as u32;
    let block = ((arg >> 32) & 0xFFFF) as u32;

    // SAFETY: sole user of SERVER_IPC_BUF.
    let buf = core::ptr::addr_of_mut!(SERVER_IPC_BUF).cast::<u64>();
    if ipc_buffer_set(buf as u64).is_err()
    {
        thread_exit()
    }
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_recv(ep, buf) }.is_ok()
    {
        notification_send(done, BIT_P2_ARMED).ok();
    }
    // Never reply; hold the armed binding until the controller reaps us.
    notification_wait(block).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
