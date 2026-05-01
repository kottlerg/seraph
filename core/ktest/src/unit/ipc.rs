// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/ipc.rs

//! Tier 1 tests for IPC syscalls.
//!
//! Covers: `SYS_IPC_CALL`, `SYS_IPC_REPLY`, `SYS_IPC_RECV`,
//! `SYS_IPC_BUFFER_SET`.
//!
//! `SYS_IPC_BUFFER_SET` is tested implicitly — it is called once in `run()`
//! before any tests execute, and any IPC test failure would surface a missing
//! or broken buffer. A dedicated unit test would interfere with the global
//! registration, so it is not tested in isolation here.
//!
//! The round-trip test spawns a child thread as the "caller" and uses the main
//! ktest thread as the "server". The child calls the endpoint, the server
//! receives, verifies the label, and replies.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_signal, cap_create_thread,
    cap_delete, cap_derive, ipc_buffer_set, signal_send, signal_wait, thread_configure,
    thread_exit, thread_start, thread_yield,
};

use crate::{ChildStack, TestContext, TestResult};

// SEND + GRANT rights (bits 4 and 6).
const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);
// RECV right only (bit 4 for SEND is not set).
const RIGHTS_RECV_ONLY: u64 = 1 << 10;

// Child stacks — one per test that spawns a child.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;
static mut RECV_BLOCKS_STACK: ChildStack = ChildStack::ZERO;
static mut DATA_WORDS_STACK: ChildStack = ChildStack::ZERO;
static mut CAP_XFER_STACK: ChildStack = ChildStack::ZERO;
static mut TOKEN_STACK: ChildStack = ChildStack::ZERO;
static mut SNAPSHOT_STACK: ChildStack = ChildStack::ZERO;
static mut REPLY_OOM_STACK: ChildStack = ChildStack::ZERO;
static mut RECV_OOM_STACK: ChildStack = ChildStack::ZERO;

// ── SYS_IPC_CALL / SYS_IPC_RECV / SYS_IPC_REPLY ─────────────────────────────

/// Full synchronous IPC round-trip: child calls, server receives and replies.
///
/// The child sends label 0xCAFE. The server verifies the label and replies
/// with label 0xBEEF. The child verifies the reply label and signals done.
///
/// A separate sync signal (`done_sig`) lets the server wait for the child to
/// complete its post-reply verification before the test returns.
pub fn call_reply_recv(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for IPC test failed")?;

    // Notification signal: child sends 0xDEAD (success) or 0xBAD (failure).
    let notify = syscall::cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for IPC notify failed")?;

    // Build child CSpace: endpoint (SEND | GRANT) + notify signal (SIGNAL only).
    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "child CSpace create failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep into child CSpace failed")?;
    let child_notify = cap_copy(notify, child_cs, 1 << 7)
        .map_err(|_| "cap_copy notify into child CSpace failed")?;

    // Pack child ep and notify slots into the arg u64.
    let child_arg = u64::from(child_ep) | (u64::from(child_notify) << 16);

    let child_th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for IPC test failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(
        child_th,
        caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for IPC test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for IPC test failed")?;

    // Server: wait for the child's IPC call.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }.map_err(|_| "ipc_recv failed")?;
    if msg.label != 0xCAFE
    {
        return Err("ipc_recv returned wrong label (expected 0xCAFE)");
    }

    // Reply with label 0xBEEF and no data or caps.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0xBEEF), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply failed")?;

    // Wait for child confirmation.
    let result_bits = signal_wait(notify).map_err(|_| "signal_wait for IPC done failed")?;
    if result_bits != 0xDEAD
    {
        return Err("child IPC post-reply verification failed (expected 0xDEAD)");
    }

    cap_delete(child_th).map_err(|_| "cap_delete child_th after IPC test failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after IPC test failed")?;
    cap_delete(notify).map_err(|_| "cap_delete notify after IPC test failed")?;
    cap_delete(child_cs).map_err(|_| "cap_delete child_cs after IPC test failed")?;
    Ok(())
}

// ── SYS_IPC_RECV (send-queue path) ───────────────────────────────────────────

/// Tests the send-queue path: caller blocks on the endpoint BEFORE the server
/// calls `ipc_recv`.
///
/// The server yields once after starting the child. This lets the child run,
/// call `ipc_call`, and block on the send queue before the server calls
/// `ipc_recv`.  (Contrast with `call_reply_recv`, where the server blocks first
/// and tests the recv-queue path.)
pub fn recv_finds_queued_caller(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for recv_finds_queued_caller failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for recv_finds_queued_caller failed")?;

    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace for recv_finds_queued_caller failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep for recv_finds_queued_caller failed")?;
    let child_done = cap_copy(done, child_cs, 1 << 7)
        .map_err(|_| "cap_copy done for recv_finds_queued_caller failed")?;
    let child_arg = u64::from(child_ep) | (u64::from(child_done) << 16);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for recv_finds_queued_caller failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(RECV_BLOCKS_STACK));
    thread_configure(
        th,
        queued_caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for recv_finds_queued_caller failed")?;
    thread_start(th).map_err(|_| "thread_start for recv_finds_queued_caller failed")?;

    // Yield CPU once so the child runs and blocks on ipc_call (no server yet).
    thread_yield().map_err(|_| "thread_yield for recv_finds_queued_caller failed")?;

    // Now call ipc_recv — the child should be on the send queue.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for recv_finds_queued_caller failed")?;
    if msg.label != 0xFACE
    {
        return Err("ipc_recv returned wrong label (expected 0xFACE)");
    }

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0xC0DE), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for recv_finds_queued_caller failed")?;

    let result =
        signal_wait(done).map_err(|_| "signal_wait done for recv_finds_queued_caller failed")?;
    if result != 0xDEAD
    {
        return Err("child post-reply check failed (expected 0xDEAD)");
    }

    cap_delete(th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

// ── SYS_IPC_BUFFER_SET negative ──────────────────────────────────────────────

/// `ipc_buffer_set` with a non-page-aligned address must return an error.
///
/// Address 1 is obviously not page-aligned; the kernel must reject it before
/// modifying any state, so the currently registered buffer remains valid.
pub fn ipc_buffer_misaligned_err(_ctx: &TestContext) -> TestResult
{
    let err = ipc_buffer_set(1);
    if err.is_ok()
    {
        return Err("ipc_buffer_set with non-page-aligned address should fail");
    }
    Ok(())
}

// ── SYS_IPC_CALL (insufficient rights) ───────────────────────────────────────

/// `ipc_call` on an endpoint cap with only RECV right (no SEND) must fail.
pub fn send_insufficient_rights_err(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for send_rights test failed")?;

    // Derive with RECV right only (bit 10), no SEND (bit 4).
    let recv_only =
        cap_derive(ep, RIGHTS_RECV_ONLY).map_err(|_| "cap_derive for send_rights test failed")?;

    // ipc_call requires SEND right.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let err = unsafe { ipc::ipc_call(recv_only, &IpcMessage::new(0xABCD), ctx.ipc_buf) };
    if err.is_ok()
    {
        return Err("ipc_call on RECV-only cap should fail (InsufficientRights)");
    }

    cap_delete(recv_only).map_err(|_| "cap_delete recv_only failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after send_rights test failed")?;
    Ok(())
}

// ── SYS_IPC_CALL with data words ─────────────────────────────────────────────

/// IPC call with `data_count`=2 transfers data words via the IPC buffer.
///
/// The child writes two data words into its IPC buffer before calling.
/// The server receives them and verifies the values.
pub fn call_with_data_words(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for data_words test failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for data_words test failed")?;

    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace for data_words test failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep for data_words test failed")?;
    let child_done =
        cap_copy(done, child_cs, 1 << 7).map_err(|_| "cap_copy done for data_words test failed")?;
    let child_arg = u64::from(child_ep) | (u64::from(child_done) << 16);

    let child_th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for data_words test failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(DATA_WORDS_STACK));
    thread_configure(
        child_th,
        data_caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for data_words test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for data_words test failed")?;

    // Server: receive the call.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for data_words test failed")?;
    if msg.label != 0xDA7A
    {
        return Err("ipc_recv returned wrong label for data_words test");
    }
    if msg.word_count() < 2
    {
        return Err("ipc_recv for data_words test delivered fewer than 2 words");
    }

    // Data words are snapshotted onto the returned message.
    let word0 = msg.word(0);
    let word1 = msg.word(1);

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for data_words test failed")?;

    signal_wait(done).map_err(|_| "signal_wait for data_words test failed")?;

    if word0 != 0xAAAA_BBBB
    {
        return Err("data word[0] mismatch (expected 0xAAAABBBB)");
    }
    if word1 != 0xCCCC_DDDD
    {
        return Err("data word[1] mismatch (expected 0xCCCCDDDD)");
    }

    cap_delete(child_th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

// ── SYS_IPC_CALL with cap transfer ───────────────────────────────────────────

/// IPC call transferring one capability from caller to server.
///
/// The child creates a signal, passes it via the IPC cap transfer mechanism.
/// The server receives it and verifies it can use the transferred cap.
pub fn call_with_cap_transfer(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for cap_xfer test failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for cap_xfer test failed")?;

    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace for cap_xfer test failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep for cap_xfer test failed")?;
    let child_done =
        cap_copy(done, child_cs, 1 << 7).map_err(|_| "cap_copy done for cap_xfer test failed")?;
    let child_frame = cap_copy(ctx.memory_frame_base, child_cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy frame for cap_xfer test failed")?;
    let child_arg =
        u64::from(child_ep) | (u64::from(child_done) << 16) | (u64::from(child_frame) << 32);

    let child_th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for cap_xfer test failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(CAP_XFER_STACK));
    thread_configure(
        child_th,
        cap_xfer_caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for cap_xfer test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for cap_xfer test failed")?;

    // Server: receive the call with cap transfer.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for cap_xfer test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("ipc_recv returned wrong label for cap_xfer test");
    }

    // Transferred cap slot indices are snapshotted onto the returned message.
    if msg.caps().len() != 1
    {
        return Err("expected 1 transferred cap, got different count");
    }

    // The transferred cap should be a valid signal — try sending on it.
    let transferred_sig = msg.caps()[0];
    let send_result = syscall::signal_send(transferred_sig, 0x1);

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for cap_xfer test failed")?;

    signal_wait(done).map_err(|_| "signal_wait for cap_xfer test failed")?;

    if send_result.is_err()
    {
        return Err("transferred cap is not usable as a signal");
    }

    // Clean up the transferred cap.
    cap_delete(transferred_sig).ok();
    cap_delete(child_th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

// ── Token delivery via IPC ───────────────────────────────────────────────────

/// `ipc_recv` delivers the token from the sender's endpoint cap.
///
/// The child calls via a tokened endpoint cap (token=0x1234). The server
/// receives and verifies the token value in the third return register.
pub fn recv_delivers_token(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for recv_delivers_token failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for recv_delivers_token failed")?;

    // Derive a tokened send+grant cap.
    let tokened_ep = syscall::cap_derive_token(ep, RIGHTS_SEND_GRANT, 0x1234)
        .map_err(|_| "cap_derive_token for recv_delivers_token failed")?;

    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace for recv_delivers_token failed")?;
    let child_ep = cap_copy(tokened_ep, child_cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy tokened ep for recv_delivers_token failed")?;
    let child_done = cap_copy(done, child_cs, 1 << 7)
        .map_err(|_| "cap_copy done for recv_delivers_token failed")?;
    let child_arg = u64::from(child_ep) | (u64::from(child_done) << 16);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for recv_delivers_token failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(TOKEN_STACK));
    thread_configure(
        th,
        token_caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for recv_delivers_token failed")?;
    thread_start(th).map_err(|_| "thread_start for recv_delivers_token failed")?;

    // Server: receive and check token.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for recv_delivers_token failed")?;

    if msg.label != 0xD00D
    {
        return Err("recv_delivers_token: wrong label (expected 0xD00D)");
    }
    if msg.token != 0x1234
    {
        return Err("recv_delivers_token: wrong token (expected 0x1234)");
    }

    // Reply so child can finish.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for recv_delivers_token failed")?;

    signal_wait(done).map_err(|_| "signal_wait for recv_delivers_token failed")?;

    cap_delete(th).ok();
    cap_delete(tokened_ep).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

/// `ipc_recv` returns token=0 when the sender uses an untokened cap.
pub fn recv_untokened_returns_zero(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for recv_untokened failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for recv_untokened failed")?;

    // Give child an untokened send+grant cap (regular derive, no token).
    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace for recv_untokened failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep for recv_untokened failed")?;
    let child_done =
        cap_copy(done, child_cs, 1 << 7).map_err(|_| "cap_copy done for recv_untokened failed")?;
    let child_arg = u64::from(child_ep) | (u64::from(child_done) << 16);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for recv_untokened failed")?;

    // Reuse the caller_entry (sends 0xCAFE, expects reply 0xBEEF).
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(th, caller_entry as *const () as u64, stack_top, child_arg)
        .map_err(|_| "thread_configure for recv_untokened failed")?;
    thread_start(th).map_err(|_| "thread_start for recv_untokened failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for recv_untokened failed")?;

    if msg.label != 0xCAFE
    {
        return Err("recv_untokened: wrong label");
    }
    if msg.token != 0
    {
        return Err("recv_untokened: token should be 0 for untokened cap");
    }

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0xBEEF), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for recv_untokened failed")?;

    signal_wait(done).map_err(|_| "signal_wait for recv_untokened failed")?;

    cap_delete(th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

/// Child: calls the endpoint with label 0xCAFE, waits for reply, then signals.
///
/// `arg`: bits[15:0] = `ep_slot`, bits[31:16] = `notify_slot` (in child's `CSpace`).
fn caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let notify_slot = ((arg >> 16) & 0xFFFF) as u32;

    // Register the shared IPC buffer for this child thread. Each thread has its
    // own IPC buffer pointer in its TCB; the child must register before calling.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(notify_slot, 0xBAD).ok();
        thread_exit()
    }

    // Call the server. Blocks until server calls ipc_reply.
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let reply = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xCAFE), buf_addr as *mut u64) };
    match reply
    {
        Ok(msg) =>
        {
            if msg.label == 0xBEEF
            {
                signal_send(notify_slot, 0xDEAD).ok();
            }
            else
            {
                signal_send(notify_slot, 0xBAD).ok();
            }
        }
        Err(_) =>
        {
            signal_send(notify_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}

/// Child for `recv_finds_queued_caller`: calls endpoint immediately (no server
/// yet), then signals the result after the server replies.
///
/// `arg`: bits[15:0] = `ep_slot`, bits[31:16] = `done_slot` (in child's `CSpace`).
fn queued_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // ipc_call with no server yet — blocks on the endpoint's send queue.
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let reply = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xFACE), buf_addr as *mut u64) };
    match reply
    {
        Ok(msg) =>
        {
            let result = if msg.label == 0xC0DE { 0xDEAD } else { 0xBAD };
            signal_send(done_slot, result).ok();
        }
        Err(_) =>
        {
            signal_send(done_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}

/// Child for `call_with_data_words`: registers its IPC buffer, builds a two-word
/// message, then calls.
///
/// `arg`: bits[15:0] = `ep_slot`, bits[31:16] = `done_slot`.
fn data_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;

    // Register the shared IPC buffer for this child thread. Each thread has its
    // own IPC buffer pointer in its TCB; the child must register before calling.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    let msg = IpcMessage::builder(0xDA7A)
        .word(0, 0xAAAA_BBBB)
        .word(1, 0xCCCC_DDDD)
        .build();

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(_) => signal_send(done_slot, 0xDEAD).ok(),
        Err(_) => signal_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

/// Child for `call_with_cap_transfer`: creates a signal and transfers it via IPC.
///
/// `arg`: bits[15:0] = `ep_slot`, bits[31:16] = `done_slot`,
/// bits[47:32] = `frame_slot` (Frame cap with RETYPE for `cap_create_signal`).
fn cap_xfer_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let frame_slot = ((arg >> 32) & 0xFFFF) as u32;

    // Register IPC buffer for cap transfer.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // Create a signal in the child's CSpace.
    let Ok(sig) = syscall::cap_create_signal(frame_slot)
    else
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    };

    // Call with 1 cap to transfer.
    let msg = IpcMessage::builder(0xCAFE).cap(sig).build();
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(_) => signal_send(done_slot, 0xDEAD).ok(),
        Err(_) => signal_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

/// Child for `recv_delivers_token`: calls endpoint with label 0xD00D.
///
/// `arg`: bits[15:0] = `ep_slot`, bits[31:16] = `done_slot`.
fn token_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xD00D), buf_addr as *mut u64) }
    {
        Ok(_) => signal_send(done_slot, 0xDEAD).ok(),
        Err(_) => signal_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

// ── SYS_IPC_RECV snapshot independence ───────────────────────────────────────

/// Regression guard: the `IpcMessage` returned by `ipc_recv` must own its
/// payload, so subsequent buffer writes (e.g. a nested `ipc_call` inside a
/// logging helper, or any other IPC issued before the caller consumes the
/// received data) cannot clobber it.
///
/// Historically the IPC buffer was caller-visible state across the
/// post-recv / pre-read window; a `println!` between recv and the word
/// read would scribble `STREAM_BYTES` over the received payload. The
/// snapshot wrapper eliminates that window at the type level. This test
/// locks the invariant in: receive a message with known words, scribble
/// garbage directly over the IPC buffer (the worst case of any nested IPC
/// activity), then verify the message's view is unchanged.
pub fn recv_snapshot_survives_buffer_clobber(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for snapshot test failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal for snapshot test failed")?;

    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "cap_create_cspace for snapshot test failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep for snapshot test failed")?;
    let child_done =
        cap_copy(done, child_cs, 1 << 7).map_err(|_| "cap_copy done for snapshot test failed")?;
    let child_arg = u64::from(child_ep) | (u64::from(child_done) << 16);

    let child_th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for snapshot test failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(SNAPSHOT_STACK));
    thread_configure(
        child_th,
        snapshot_caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for snapshot test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for snapshot test failed")?;

    // Server: receive the call with two known data words.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for snapshot test failed")?;
    if msg.label != 0x5A15
    {
        return Err("snapshot test: ipc_recv returned wrong label");
    }
    if msg.word_count() < 2
    {
        return Err("snapshot test: received fewer than 2 data words");
    }

    // Simulate any nested IPC activity between recv and read. A real
    // `println!` here would issue a `SYS_IPC_CALL` that the kernel serves
    // by overwriting the same buffer page. We skip the orchestration and
    // directly scribble garbage over every data slot — a strictly worse
    // case than any real IPC would produce.
    for i in 0..syscall_abi::MSG_DATA_WORDS_MAX
    {
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer; i is
        // bounded by MSG_DATA_WORDS_MAX, well within the 4 KiB page.
        unsafe { core::ptr::write_volatile(ctx.ipc_buf.add(i), 0xDEAD_BEEF_DEAD_BEEF) };
    }

    // Now consume the message. Must still see the sender's original words.
    let word0 = msg.word(0);
    let word1 = msg.word(1);

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for snapshot test failed")?;

    signal_wait(done).map_err(|_| "signal_wait for snapshot test failed")?;

    if word0 != 0x1234_5678_9ABC_DEF0
    {
        return Err("snapshot test: word[0] clobbered by buffer write");
    }
    if word1 != 0x0FED_CBA9_8765_4321
    {
        return Err("snapshot test: word[1] clobbered by buffer write");
    }

    cap_delete(child_th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

/// Child for `recv_snapshot_survives_buffer_clobber`: calls with two known
/// data words and exits.
fn snapshot_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;

    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    let msg = IpcMessage::builder(0x5A15)
        .word(0, 0x1234_5678_9ABC_DEF0)
        .word(1, 0x0FED_CBA9_8765_4321)
        .build();

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(_) => signal_send(done_slot, 0xDEAD).ok(),
        Err(_) => signal_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

// ── sys_ipc_reply cap-transfer OOM regression ────────────────────────────────

/// Server's cap-bearing `ipc_reply` to a caller whose `CSpace` is full
/// must return `OutOfMemory` *and* leave the caller still `BlockedOnReply`,
/// so that a subsequent no-cap `ipc_reply` from the same server still
/// resolves the call cleanly.
///
/// Without the kernel fix, the first reply runs `endpoint_reply` (which
/// flips the caller to `Ready` and clears `(*server).reply_tcb`) before
/// the cap-transfer OOM is caught — wedging the caller in `Ready`/off-
/// runqueue and leaving the server with no reply target. The second
/// reply would then see a null `reply_tcb` and return `InvalidCapability`,
/// and the child's `done` signal would never arrive. With the fix the
/// caller's `CSpace` is pre-allocated before `endpoint_reply`, so the
/// first reply fails atomically with no IPC state mutated, and the retry
/// succeeds.
pub fn reply_oom_keeps_caller_blocked(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for reply_oom test failed")?;
    let ready = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal(ready) for reply_oom test failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal(done) for reply_oom test failed")?;
    // Extra signal we will try to transfer in the cap-bearing reply. Created
    // in the server's CSpace; the failing reply must leave it untouched.
    let xfer = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal(xfer) for reply_oom test failed")?;

    // Small child CSpace: the child consumes its remaining headroom by
    // creating signals until full so that pre_allocate(1) on the reply path
    // returns OutOfMemory.
    let child_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 8)
        .map_err(|_| "cap_create_cspace for reply_oom test failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "cap_copy ep for reply_oom test failed")?;
    let child_ready = cap_copy(ready, child_cs, 1 << 7)
        .map_err(|_| "cap_copy ready for reply_oom test failed")?;
    let child_done =
        cap_copy(done, child_cs, 1 << 7).map_err(|_| "cap_copy done for reply_oom test failed")?;
    let child_frame = cap_copy(ctx.memory_frame_base, child_cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy frame for reply_oom test failed")?;

    let child_arg = u64::from(child_ep)
        | (u64::from(child_ready) << 16)
        | (u64::from(child_done) << 32)
        | (u64::from(child_frame) << 48);

    let child_th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, child_cs)
        .map_err(|_| "cap_create_thread for reply_oom test failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(REPLY_OOM_STACK));
    thread_configure(
        child_th,
        reply_oom_caller_entry as *const () as u64,
        stack_top,
        child_arg,
    )
    .map_err(|_| "thread_configure for reply_oom test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for reply_oom test failed")?;

    // Wait until the child has filled its CSpace and is about to ipc_call.
    let ready_bits = signal_wait(ready).map_err(|_| "signal_wait(ready) for reply_oom failed")?;
    if ready_bits != 0x1
    {
        return Err("reply_oom: child reported failure filling its CSpace");
    }

    // Receive the child's call. No caps in the incoming message, so the
    // server-side `pre_allocate(MSG_CAP_SLOTS_MAX)` succeeds.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for reply_oom test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("reply_oom: ipc_recv returned wrong label");
    }

    // Try a cap-bearing reply. Child's CSpace is full, so the kernel's
    // pre_allocate on the caller side must fail before any IPC state
    // mutates, returning OutOfMemory.
    let cap_reply = IpcMessage::builder(0xBEEF).cap(xfer).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let first_attempt = unsafe { ipc::ipc_reply(&cap_reply, ctx.ipc_buf) };
    match first_attempt
    {
        Err(code) if code == syscall_abi::SyscallError::OutOfMemory as i64 =>
        {}
        Err(_) => return Err("reply_oom: cap-bearing reply returned wrong error code"),
        Ok(()) => return Err("reply_oom: cap-bearing reply succeeded unexpectedly"),
    }

    // Retry without caps. The fix guarantees `(*server).reply_tcb` was not
    // cleared by the failed first attempt, so the child is still
    // BlockedOnReply and this reply must succeed.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0xBEEF), ctx.ipc_buf) }
        .map_err(|_| "reply_oom: no-cap retry reply failed")?;

    let done_bits = signal_wait(done).map_err(|_| "signal_wait(done) for reply_oom failed")?;
    if done_bits != 0xDEAD
    {
        return Err("reply_oom: child did not see the retry reply");
    }

    cap_delete(child_th).ok();
    cap_delete(ep).ok();
    cap_delete(ready).ok();
    cap_delete(done).ok();
    cap_delete(xfer).ok();
    cap_delete(child_cs).ok();
    Ok(())
}

/// Child for `reply_oom_keeps_caller_blocked`: registers IPC buffer, fills
/// its own `CSpace`, signals readiness, then issues an `ipc_call`. Reports
/// success when the server's eventual no-cap reply arrives.
fn reply_oom_caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let ready_slot = ((arg >> 16) & 0xFFFF) as u32;
    let done_slot = ((arg >> 32) & 0xFFFF) as u32;
    let frame_slot = ((arg >> 48) & 0xFFFF) as u32;

    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(ready_slot, 0xBAD).ok();
        thread_exit()
    }

    // Saturate the child's CSpace so the server-side reply's caller-CSpace
    // pre_allocate must fail. Bounded loop guards against an unbounded
    // CSpace if the test setup ever changes.
    for _ in 0..1024
    {
        if cap_create_signal(frame_slot).is_err()
        {
            break;
        }
    }
    if cap_create_signal(frame_slot).is_ok()
    {
        // Still has free slots — test setup did not actually fill the CSpace.
        signal_send(ready_slot, 0xBAD).ok();
        thread_exit()
    }

    signal_send(ready_slot, 0x1).ok();

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let reply = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xCAFE), buf_addr as *mut u64) };
    match reply
    {
        Ok(msg) =>
        {
            let bits = if msg.label == 0xBEEF { 0xDEAD } else { 0xBAD };
            signal_send(done_slot, bits).ok();
        }
        Err(_) =>
        {
            signal_send(done_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}

// ── sys_ipc_recv cap-transfer OOM regression ─────────────────────────────────

/// `sys_ipc_recv` on a thread whose `CSpace` cannot absorb
/// `MSG_CAP_SLOTS_MAX` more caps must return `OutOfMemory` cleanly without
/// blocking on the recv queue, so the recv-side cap-transfer OOM cannot
/// wedge any IPC participant.
///
/// Verifies the symmetric pre-allocation hoisted to the top of
/// `sys_ipc_recv`. The victim thread fills its own `CSpace`, then issues
/// `ipc_recv`. With the fix the syscall returns `OutOfMemory` immediately;
/// without the fix the victim would either block on the recv queue or hit
/// the bug only when caps actually arrive.
pub fn recv_oom_returns_cleanly(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "cap_create_endpoint for recv_oom test failed")?;
    let done = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "cap_create_signal(done) for recv_oom test failed")?;

    let victim_cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 8)
        .map_err(|_| "cap_create_cspace for recv_oom test failed")?;
    let victim_ep = cap_copy(ep, victim_cs, syscall_abi::RIGHTS_RECEIVE)
        .map_err(|_| "cap_copy ep for recv_oom test failed")?;
    let victim_done =
        cap_copy(done, victim_cs, 1 << 7).map_err(|_| "cap_copy done for recv_oom test failed")?;
    let victim_frame = cap_copy(ctx.memory_frame_base, victim_cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy frame for recv_oom test failed")?;
    let victim_arg =
        u64::from(victim_ep) | (u64::from(victim_done) << 16) | (u64::from(victim_frame) << 32);

    let victim_th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, victim_cs)
        .map_err(|_| "cap_create_thread for recv_oom test failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(RECV_OOM_STACK));
    thread_configure(
        victim_th,
        recv_oom_victim_entry as *const () as u64,
        stack_top,
        victim_arg,
    )
    .map_err(|_| "thread_configure for recv_oom test failed")?;
    thread_start(victim_th).map_err(|_| "thread_start for recv_oom test failed")?;

    let bits = signal_wait(done).map_err(|_| "signal_wait(done) for recv_oom failed")?;
    if bits != 0xDEAD
    {
        return Err("recv_oom: victim did not see OutOfMemory from ipc_recv");
    }

    cap_delete(victim_th).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(victim_cs).ok();
    Ok(())
}

/// Victim for `recv_oom_returns_cleanly`: fills its `CSpace` then issues
/// `ipc_recv`. Reports `0xDEAD` if the syscall returns `OutOfMemory`
/// (post-fix behavior), `0xBAD` otherwise.
fn recv_oom_victim_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let frame_slot = ((arg >> 32) & 0xFFFF) as u32;

    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    for _ in 0..1024
    {
        if cap_create_signal(frame_slot).is_err()
        {
            break;
        }
    }
    if cap_create_signal(frame_slot).is_ok()
    {
        signal_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let result = unsafe { ipc::ipc_recv(ep_slot, buf_addr as *mut u64) };
    let bits = match result
    {
        Err(code) if code == syscall_abi::SyscallError::OutOfMemory as i64 => 0xDEAD,
        _ => 0xBAD,
    };
    signal_send(done_slot, bits).ok();
    thread_exit()
}
