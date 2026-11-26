// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/ipc.rs

//! Tier 1 tests for IPC syscalls.
//!
//! Covers: `SYS_IPC_CALL`, `SYS_IPC_REPLY`, `SYS_IPC_RECV`,
//! `SYS_IPC_REPLY_RECV`, `SYS_IPC_BUFFER_SET`.
//!
//! `SYS_IPC_BUFFER_SET`'s success path is tested implicitly: `run()` registers
//! the harness thread's buffer before any test executes and each child entry
//! registers its own, so any IPC test failure would surface a missing or broken
//! registration. Only the rejection path is tested directly
//! (`ipc_buffer_misaligned_err`); re-registering the harness thread's buffer
//! would disturb the global registration.
//!
//! The round-trip test spawns a child thread as the "caller" and uses the main
//! ktest thread as the "server". The child calls the endpoint, the server
//! receives, verifies the label, and replies.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_notification, cap_create_thread,
    cap_delete, cap_derive, ipc_buffer_set, notification_send, notification_wait, thread_configure,
    thread_exit, thread_sleep, thread_start,
};
use syscall_abi::RIGHTS_EP_SEND_GRANT;

use crate::spawn::{ArgBlock, child_args};
use crate::{ChildStack, TestContext, TestResult};

// Endpoint RECEIVE right only (no SEND).
const RIGHTS_RECV_ONLY: u64 = syscall_abi::RIGHTS_EP_RECEIVE;

// Child stacks — one per test that spawns a child.
static mut CHILD_STACK: ChildStack = ChildStack::ZERO;
static mut UNBADGED_STACK: ChildStack = ChildStack::ZERO;
static mut RECV_BLOCKS_STACK: ChildStack = ChildStack::ZERO;
static mut DATA_WORDS_STACK: ChildStack = ChildStack::ZERO;
static mut CAP_XFER_STACK: ChildStack = ChildStack::ZERO;
static mut BADGE_STACK: ChildStack = ChildStack::ZERO;
static mut SNAPSHOT_STACK: ChildStack = ChildStack::ZERO;
static mut REPLY_OOM_STACK: ChildStack = ChildStack::ZERO;
static mut DUP_REPLY_STACK: ChildStack = ChildStack::ZERO;
static mut RECV_RESERVE_VICTIM_STACK: ChildStack = ChildStack::ZERO;
static mut RECV_RESERVE_CALLER_STACK: ChildStack = ChildStack::ZERO;
static mut STALE_REPLY_STACK: ChildStack = ChildStack::ZERO;
static mut FOUR_CAPS_STACK: ChildStack = ChildStack::ZERO;

/// Arguments of the cap-transfer children (`cap_xfer`, `four_caps`, the
/// receive-reserve victim and caller), handed to their entries by address; `memory` carries RETYPE
/// so the child can mint notifications: the transferred objects, or for
/// the receive-reserve victim the fillers that exhaust its `CSpace`.
#[derive(Clone, Copy)]
struct XferArgs
{
    ep: u64,
    done: u64,
    memory: u64,
}

static CAP_XFER_ARGS: ArgBlock<XferArgs, 1> = ArgBlock::new(XferArgs {
    ep: 0,
    done: 0,
    memory: 0,
});
static FOUR_CAPS_ARGS: ArgBlock<XferArgs, 1> = ArgBlock::new(XferArgs {
    ep: 0,
    done: 0,
    memory: 0,
});
static RECV_RESERVE_ARGS: ArgBlock<XferArgs, 2> = ArgBlock::new(XferArgs {
    ep: 0,
    done: 0,
    memory: 0,
});

/// Arguments of the reply-OOM child, handed to its entry by address.
#[derive(Clone, Copy)]
struct ReplyOomArgs
{
    ep: u64,
    ready: u64,
    done: u64,
    memory: u64,
}

static REPLY_OOM_ARGS: ArgBlock<ReplyOomArgs, 1> = ArgBlock::new(ReplyOomArgs {
    ep: 0,
    ready: 0,
    done: 0,
    memory: 0,
});

/// Arguments of the children that take an endpoint and a report
/// notification, handed to their entries by address: each handle fills a
/// whole `u64`, so the pair does not fit the one argument word.
#[derive(Clone, Copy)]
struct EpDoneArgs
{
    ep: u64,
    done: u64,
}

/// An [`EpDoneArgs`] block holding no caps.
const fn ep_done_block() -> ArgBlock<EpDoneArgs, 1>
{
    ArgBlock::new(EpDoneArgs { ep: 0, done: 0 })
}

/// Label of `call_with_cap_transfer`'s second, capless call.
const CAPLESS_LABEL: u64 = 0xCA9E;

static CALL_REPLY_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static QUEUED_CALLER_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static DATA_WORDS_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static BADGE_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static UNBADGED_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static SNAPSHOT_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static DUP_REPLY_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();
static STALE_REPLY_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();

// ── SYS_IPC_CALL / SYS_IPC_RECV / SYS_IPC_REPLY ─────────────────────────────

/// Full synchronous IPC round-trip: child calls, server receives and replies.
///
/// The child sends label 0xCAFE. The server verifies the label and replies
/// with label 0xBEEF. The child verifies the reply label and signals done.
///
/// A separate sync notification (`notify`) lets the server wait for the child to
/// complete its post-reply verification before the test returns.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn call_reply_recv(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for IPC test failed")?;

    // Notification round-trip: child sends 0xDEAD (success) or 0xBAD (failure).
    let notify = syscall::cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for IPC notify failed")?;

    // Build child CSpace: endpoint (SEND | GRANT) + notify notification (NOTIFY only).
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::call_reply_recv: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep into child CSpace failed")?;
    let child_notify = cap_copy(notify, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy notify into child CSpace failed")?;

    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        CALL_REPLY_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_notify,
            },
        )
    };

    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, caller_entry, stack_top, child_arg) }
        .map_err(|_| "ipc::call_reply_recv: configure_and_start failed")?;

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
    let result_bits =
        notification_wait(notify).map_err(|_| "notification_wait for IPC done failed")?;
    if result_bits != 0xDEAD
    {
        return Err("child IPC post-reply verification failed (expected 0xDEAD)");
    }

    child
        .delete_thread()
        .map_err(|_| "cap_delete child_th after IPC test failed")?;
    cap_delete(ep).map_err(|_| "cap_delete ep after IPC test failed")?;
    cap_delete(notify).map_err(|_| "cap_delete notify after IPC test failed")?;
    child
        .delete_cspace()
        .map_err(|_| "cap_delete child_cs after IPC test failed")?;
    Ok(())
}

// ── SYS_IPC_RECV (send-queue path) ───────────────────────────────────────────

/// Tests the send-queue path: caller blocks on the endpoint BEFORE the server
/// calls `ipc_recv`.
///
/// The server sleeps for one tick after starting the child. This lets the child run,
/// call `ipc_call`, and block on the send queue before the server calls
/// `ipc_recv`.  (Contrast with `call_reply_recv`, where the server blocks first
/// and tests the recv-queue path.)
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn recv_finds_queued_caller(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for recv_finds_queued_caller failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for recv_finds_queued_caller failed")?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::recv_finds_queued_caller: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for recv_finds_queued_caller failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for recv_finds_queued_caller failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        QUEUED_CALLER_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };

    // SAFETY: `RECV_BLOCKS_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(RECV_BLOCKS_STACK)) };
    // SAFETY: the stack is `RECV_BLOCKS_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, queued_caller_entry, stack_top, child_arg) }
        .map_err(|_| "ipc::recv_finds_queued_caller: configure_and_start failed")?;

    // Sleep so the child (created at the floor priority, strictly below
    // this thread's INIT_PRIORITY) runs and blocks on ipc_call (no server
    // yet).
    thread_sleep(1).map_err(|_| "thread_sleep for recv_finds_queued_caller failed")?;

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

    let result = notification_wait(done)
        .map_err(|_| "notification_wait done for recv_finds_queued_caller failed")?;
    if result != 0xDEAD
    {
        return Err("child post-reply check failed (expected 0xDEAD)");
    }

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

// ── SYS_IPC_BUFFER_SET negative ──────────────────────────────────────────────

/// `ipc_buffer_set` with a non-page-aligned address must return an error.
///
/// Address 1 is obviously not page-aligned; the kernel must reject it before
/// modifying any state, so the currently registered buffer remains valid.
pub fn ipc_buffer_misaligned_err(_ctx: &TestContext) -> TestResult
{
    // SAFETY: address 1 is not page-aligned, so the kernel registers nothing (the
    // test's premise) and ktest's registered buffer stays as it was.
    let err = unsafe { ipc_buffer_set(1) };
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
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for send_rights test failed")?;

    // Derive with RECEIVE right only, no SEND.
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
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn call_with_data_words(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for data_words test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for data_words test failed")?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::call_with_data_words: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for data_words test failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for data_words test failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        DATA_WORDS_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };

    // SAFETY: `DATA_WORDS_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(DATA_WORDS_STACK)) };
    // SAFETY: the stack is `DATA_WORDS_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, data_caller_entry, stack_top, child_arg) }
        .map_err(|_| "ipc::call_with_data_words: configure_and_start failed")?;

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

    notification_wait(done).map_err(|_| "notification_wait for data_words test failed")?;

    if word0 != 0xAAAA_BBBB
    {
        return Err("data word[0] mismatch (expected 0xAAAABBBB)");
    }
    if word1 != 0xCCCC_DDDD
    {
        return Err("data word[1] mismatch (expected 0xCCCCDDDD)");
    }

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

// ── SYS_IPC_CALL with cap transfer ───────────────────────────────────────────

/// IPC call transferring one capability from caller to server.
///
/// The child creates a notification, passes it via the IPC cap transfer mechanism.
/// The server receives it and verifies it can use the transferred cap. The
/// child then calls once more with no cap, and that message carries none,
/// although the kernel leaves the server's cap result block as the first
/// delivery wrote it (core/kernel/docs/syscalls.md § `SYS_IPC_RECV`).
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and `capless` and the reply `IpcMessage`s (568 B each) and \
              the `Result` temporaries of their `ipc_recv(..)?` (about 576 B each); on init's \
              16 KiB stack"
)]
pub fn call_with_cap_transfer(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for cap_xfer test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for cap_xfer test failed")?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::call_with_cap_transfer: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for cap_xfer test failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for cap_xfer test failed")?;
    let child_memory = cap_copy(ctx.memory_base, child.cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy memory for cap_xfer test failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        CAP_XFER_ARGS.publish(
            0,
            XferArgs {
                ep: child_ep,
                done: child_done,
                memory: child_memory,
            },
        )
    };

    // SAFETY: `CAP_XFER_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CAP_XFER_STACK)) };
    // SAFETY: the stack is `CAP_XFER_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(&child, cap_xfer_caller_entry, stack_top, child_arg)
    }
    .map_err(|_| "ipc::call_with_cap_transfer: configure_and_start failed")?;

    // Server: receive the call with cap transfer.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for cap_xfer test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("ipc_recv returned wrong label for cap_xfer test");
    }

    // Delivered destination cap handles are snapshotted onto the returned message.
    if msg.caps().len() != 1
    {
        return Err("expected 1 transferred cap, got different count");
    }

    // The transferred cap should be a valid notification — try sending on it.
    let transferred_sig = msg
        .caps()
        .first()
        .copied()
        .ok_or("expected 1 transferred cap, got different count")?;
    let send_result = syscall::notification_send(transferred_sig, 0x1);

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for cap_xfer test failed")?;

    // The capless call that follows delivers no cap, so the kernel leaves the
    // cap result block holding the first delivery's handle; the message must
    // carry no cap all the same.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let capless = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv of the capless call for cap_xfer test failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply to the capless call for cap_xfer test failed")?;

    notification_wait(done).map_err(|_| "notification_wait for cap_xfer test failed")?;

    if capless.label != CAPLESS_LABEL || !capless.caps().is_empty()
    {
        cap_delete(transferred_sig).ok();
        return Err("a capless call after a cap-carrying one delivered a cap");
    }

    if send_result.is_err()
    {
        return Err("transferred cap is not usable as a notification");
    }

    // Clean up the transferred cap.
    cap_delete(transferred_sig).ok();
    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

// ── Badge delivery via IPC ───────────────────────────────────────────────────

/// `ipc_recv` delivers the badge from the sender's endpoint cap.
///
/// The child calls via a badged endpoint cap (badge=0x1234). The server
/// receives and verifies the badge value in the third return register.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn recv_delivers_badge(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for recv_delivers_badge failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for recv_delivers_badge failed")?;

    // Derive a badged send+grant cap.
    let badged_ep = syscall::cap_derive_badge(ep, RIGHTS_EP_SEND_GRANT, 0x1234)
        .map_err(|_| "cap_derive_badge for recv_delivers_badge failed")?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::recv_delivers_badge: spawn::new_child failed")?;
    let child_ep = cap_copy(badged_ep, child.cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy badged ep for recv_delivers_badge failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for recv_delivers_badge failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        BADGE_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };

    // SAFETY: `BADGE_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(BADGE_STACK)) };
    // SAFETY: the stack is `BADGE_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, badge_caller_entry, stack_top, child_arg) }
        .map_err(|_| "ipc::recv_delivers_badge: configure_and_start failed")?;

    // Server: receive and check badge.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for recv_delivers_badge failed")?;

    if msg.label != 0xD00D
    {
        return Err("recv_delivers_badge: wrong label (expected 0xD00D)");
    }
    if msg.badge != 0x1234
    {
        return Err("recv_delivers_badge: wrong badge (expected 0x1234)");
    }

    // Reply so child can finish.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for recv_delivers_badge failed")?;

    notification_wait(done).map_err(|_| "notification_wait for recv_delivers_badge failed")?;

    child.delete_thread().ok();
    cap_delete(badged_ep).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// `ipc_recv` returns badge=0 when the sender uses an unbadged cap.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn recv_unbadged_returns_zero(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for recv_unbadged failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for recv_unbadged failed")?;

    // Give child an unbadged send+grant cap (regular derive, no badge).
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::recv_unbadged_returns_zero: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for recv_unbadged failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for recv_unbadged failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        UNBADGED_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };

    // Reuse the caller_entry (sends 0xCAFE, expects reply 0xBEEF).
    // SAFETY: `UNBADGED_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(UNBADGED_STACK)) };
    // SAFETY: the stack is `UNBADGED_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, caller_entry, stack_top, child_arg) }
        .map_err(|_| "ipc::recv_unbadged_returns_zero: configure_and_start failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for recv_unbadged failed")?;

    if msg.label != 0xCAFE
    {
        return Err("recv_unbadged: wrong label");
    }
    if msg.badge != 0
    {
        return Err("recv_unbadged: badge should be 0 for unbadged cap");
    }

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0xBEEF), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for recv_unbadged failed")?;

    notification_wait(done).map_err(|_| "notification_wait for recv_unbadged failed")?;

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

/// IPC page of the [`caller_entry`] child.
static mut CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`queued_caller_entry`] child.
static mut QUEUED_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`data_caller_entry`] child.
static mut DATA_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`cap_xfer_caller_entry`] child.
static mut CAP_XFER_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`badge_caller_entry`] child.
static mut BADGE_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`snapshot_caller_entry`] child.
static mut SNAPSHOT_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`reply_oom_caller_entry`] child.
static mut REPLY_OOM_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`dup_reply_caller_entry`] child.
static mut DUP_REPLY_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`four_caps_caller_entry`] child.
static mut FOUR_CAPS_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`recv_reserve_victim_entry`] child.
static mut RECV_RESERVE_VICTIM_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// IPC page of the [`recv_reserve_caller_entry`] thread.
static mut RECV_RESERVE_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// Child: calls the endpoint with label 0xCAFE, waits for reply, then signals.
///
/// `arg`: address of the child's [`EpDoneArgs`] (slots in the child's `CSpace`).
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs {
        ep: ep_slot,
        done: notify_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(CALLER_IPC_PAGE));
    // SAFETY: `CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(notify_slot, 0xBAD).ok();
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
                notification_send(notify_slot, 0xDEAD).ok();
            }
            else
            {
                notification_send(notify_slot, 0xBAD).ok();
            }
        }
        Err(_) =>
        {
            notification_send(notify_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}

/// Child for `recv_finds_queued_caller`: calls endpoint immediately (no server
/// yet), then signals the result after the server replies.
///
/// `arg`: address of the child's [`EpDoneArgs`] (slots in the child's `CSpace`).
extern "C" fn queued_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs {
        ep: ep_slot,
        done: done_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(QUEUED_CALLER_IPC_PAGE));
    // SAFETY: `QUEUED_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
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
            notification_send(done_slot, result).ok();
        }
        Err(_) =>
        {
            notification_send(done_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}

/// Child for `call_with_data_words`: registers its IPC buffer, builds a two-word
/// message, then calls.
///
/// `arg`: address of the child's [`EpDoneArgs`].
extern "C" fn data_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs {
        ep: ep_slot,
        done: done_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(DATA_CALLER_IPC_PAGE));
    // SAFETY: `DATA_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    let msg = IpcMessage::builder(0xDA7A)
        .word(0, 0xAAAA_BBBB)
        .word(1, 0xCCCC_DDDD)
        .build();

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(_) => notification_send(done_slot, 0xDEAD).ok(),
        Err(_) => notification_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

/// Child for `call_with_cap_transfer`: creates a notification and transfers it via IPC.
///
/// `arg`: address of the child's [`XferArgs`].
extern "C" fn cap_xfer_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let XferArgs {
        ep: ep_slot,
        done: done_slot,
        memory: memory_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(CAP_XFER_CALLER_IPC_PAGE));
    // SAFETY: `CAP_XFER_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // Create a notification in the child's CSpace.
    let Ok(sig) = syscall::cap_create_notification(memory_slot)
    else
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    };

    // Call with 1 cap to transfer, then once with none.
    let msg = IpcMessage::builder(0xCAFE).cap(sig).build();
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let with_cap = unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) };
    let capless = with_cap.and_then(|_| {
        // SAFETY: buf_addr was registered as this thread's IPC buffer above.
        unsafe {
            ipc::ipc_call(
                ep_slot,
                &IpcMessage::new(CAPLESS_LABEL),
                buf_addr as *mut u64,
            )
        }
    });
    match capless
    {
        Ok(_) => notification_send(done_slot, 0xDEAD).ok(),
        Err(_) => notification_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

/// Child for `recv_delivers_badge`: calls endpoint with label 0xD00D.
///
/// `arg`: address of the child's [`EpDoneArgs`].
extern "C" fn badge_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs {
        ep: ep_slot,
        done: done_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(BADGE_CALLER_IPC_PAGE));
    // SAFETY: `BADGE_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xD00D), buf_addr as *mut u64) }
    {
        Ok(_) => notification_send(done_slot, 0xDEAD).ok(),
        Err(_) => notification_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

// ── SYS_IPC_RECV snapshot independence ───────────────────────────────────────

/// Regression guard: the `IpcMessage` returned by `ipc_recv` must own its
/// payload, so subsequent buffer writes (e.g. a nested `ipc_call` inside a
/// logging helper, or any other IPC issued before the caller consumes the
/// received data) cannot clobber it.
///
/// Without the snapshot, the IPC buffer would be caller-visible state across
/// the post-recv / pre-read window: any IPC issued in that window (in a
/// ruststd process, a `println!` sending `STREAM_BYTES` on its log stream)
/// would overwrite the received payload. This test locks the snapshot
/// contract (`ipc::IpcMessage`) in: receive a message with known words, one
/// longer than `MSG_REGS_DATA_MAX` so that it arrives in the buffer, scribble
/// garbage directly over the IPC buffer (the worst case of any
/// nested IPC activity), then verify the message's view is unchanged.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn recv_snapshot_survives_buffer_clobber(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for snapshot test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for snapshot test failed")?;

    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::recv_snapshot_survives_buffer_clobber: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for snapshot test failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for snapshot test failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        SNAPSHOT_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };

    // SAFETY: `SNAPSHOT_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(SNAPSHOT_STACK)) };
    // SAFETY: the stack is `SNAPSHOT_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(&child, snapshot_caller_entry, stack_top, child_arg)
    }
    .map_err(|_| "ipc::recv_snapshot_survives_buffer_clobber: configure_and_start failed")?;

    // Server: receive the call with two known data words.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for snapshot test failed")?;
    if msg.label != 0x5A15
    {
        return Err("snapshot test: ipc_recv returned wrong label");
    }
    if msg.word_count() != syscall_abi::MSG_REGS_DATA_MAX + 1
    {
        return Err("snapshot test: received a wrong data word count");
    }

    // Simulate any nested IPC activity between recv and read: an IPC issued
    // here (e.g. a ruststd `println!` in a userspace process) would rewrite
    // the same buffer page. We skip the orchestration and directly scribble
    // garbage over every data slot — a strictly worse case than any real IPC
    // would produce.
    for i in 0..syscall_abi::MSG_DATA_WORDS_MAX
    {
        // SAFETY: i is bounded by MSG_DATA_WORDS_MAX, well within the 4 KiB
        // IPC buffer page.
        let slot = unsafe { ctx.ipc_buf.add(i) };
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer, and
        // `slot` is a word inside it.
        unsafe { core::ptr::write_volatile(slot, 0xDEAD_BEEF_DEAD_BEEF) };
    }

    // Now consume the message. Must still see the sender's original words.
    let word0 = msg.word(0);
    let word1 = msg.word(1);

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for snapshot test failed")?;

    notification_wait(done).map_err(|_| "notification_wait for snapshot test failed")?;

    if word0 != 0x1234_5678_9ABC_DEF0
    {
        return Err("snapshot test: word[0] clobbered by buffer write");
    }
    if word1 != 0x0FED_CBA9_8765_4321
    {
        return Err("snapshot test: word[1] clobbered by buffer write");
    }

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Child for `recv_snapshot_survives_buffer_clobber`: calls with two known
/// data words in a message of `MSG_REGS_DATA_MAX + 1` words and exits.
extern "C" fn snapshot_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs {
        ep: ep_slot,
        done: done_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(SNAPSHOT_CALLER_IPC_PAGE));
    // SAFETY: `SNAPSHOT_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // One word more than the message registers carry, so the message
    // travels in the server's IPC buffer, which the test then clobbers.
    let msg = IpcMessage::builder(0x5A15)
        .word(0, 0x1234_5678_9ABC_DEF0)
        .word(1, 0x0FED_CBA9_8765_4321)
        .word_count(syscall_abi::MSG_REGS_DATA_MAX + 1)
        .build();

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(_) => notification_send(done_slot, 0xDEAD).ok(),
        Err(_) => notification_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

// ── sys_ipc_reply cap-transfer OOM regression ────────────────────────────────

/// A caller whose `CSpace` has no general slot left still receives a
/// cap-bearing reply into its IPC receive reserve
/// (core/kernel/docs/capability-internals.md § IPC Receive Reserve). Once
/// that reserve is spent, the server's cap-bearing `ipc_reply` must return
/// `OutOfMemory` *and* wake the caller with the synthetic
/// [`syscall_abi::IPC_REPLY_TRANSFER_FAILED`] label so it un-parks
/// gracefully instead of dead-locking.
///
/// The caller fills its general slots and calls twice. The first reply
/// carries `MSG_CAP_SLOTS_MAX` (4) caps, which take the reserve; the second
/// carries one cap and must fail.
///
/// The reply-failure wake this test pins is specified in
/// core/kernel/docs/syscalls.md § `SYS_IPC_REPLY` and docs/ipc-design.md
/// § Message Format.
#[expect(
    clippy::large_stack_frames,
    reason = "the two received `msg`s, the replies `four_cap_message` returns and `cap_reply` \
              builds and the builder values behind them (568 B each), and the `Result` temporaries \
              of its `ipc_recv(..)?` calls (about 576 B each); on init's 16 KiB stack"
)]
pub fn reply_oom_wakes_caller_with_transfer_failed(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for reply_oom test failed")?;
    let ready = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(ready) for reply_oom test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(done) for reply_oom test failed")?;
    // Notifications the replies transfer, created in the server's CSpace:
    // four for the reply that takes the caller's reserve, and `xfer` for the
    // failing reply, which must leave it untouched.
    let xfer = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(xfer) for reply_oom test failed")?;
    let reserve_caps = mint_notifications(ctx.memory_base)?;

    // Small child CSpace: a single seeded pool page (55 usable slots)
    // whose general slots the child consumes by creating notifications
    // until one fails, leaving only the IPC receive reserve. With no quota,
    // the exhausted pool surfaces as the refillable OutOfMemory. The tiny
    // pool shape is part of the test contract, so this site bypasses
    // `spawn::new_child` per the convention documented in
    // `crate::spawn::new_child_at`.
    let child_cs = cap_create_cspace(ctx.memory_base, 0, 2)
        .map_err(|_| "cap_create_cspace for reply_oom test failed")?;
    let child_ep = cap_copy(ep, child_cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for reply_oom test failed")?;
    let child_ready = cap_copy(ready, child_cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy ready for reply_oom test failed")?;
    let child_done = cap_copy(done, child_cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for reply_oom test failed")?;
    let child_memory = cap_copy(ctx.memory_base, child_cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy memory for reply_oom test failed")?;

    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        REPLY_OOM_ARGS.publish(
            0,
            ReplyOomArgs {
                ep: child_ep,
                ready: child_ready,
                done: child_done,
                memory: child_memory,
            },
        )
    };

    let child_th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, child_cs, 0, 0)
        .map_err(|_| "cap_create_thread for reply_oom test failed")?;
    let mut child = crate::spawn::SpawnedChild {
        th: child_th,
        cs: child_cs,
    };
    // SAFETY: `REPLY_OOM_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(REPLY_OOM_STACK)) };
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and the
    // stack is this child's own, on which no other live thread runs (`ChildStack`'s
    // rule, as noted where the stack is chosen).
    unsafe {
        thread_configure(
            child_th,
            reply_oom_caller_entry as *const () as u64,
            stack_top,
            child_arg,
        )
    }
    .map_err(|_| "thread_configure for reply_oom test failed")?;
    thread_start(child_th).map_err(|_| "thread_start for reply_oom test failed")?;

    // Wait until the child has filled its CSpace and is about to ipc_call.
    let ready_bits =
        notification_wait(ready).map_err(|_| "notification_wait(ready) for reply_oom failed")?;
    if ready_bits != 0x1
    {
        return Err("reply_oom: child reported failure filling its CSpace");
    }

    // Receive the child's first call. The server's own `CSpace` has
    // headroom, so `sys_ipc_recv`'s worst-case
    // `pre_allocate(MSG_CAP_SLOTS_MAX)` succeeds; only the child's general
    // slots are exhausted. Reply with four caps: they take the child's
    // reserve.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for reply_oom test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("reply_oom: ipc_recv returned wrong label");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&four_cap_message(0xBEEF, reserve_caps), ctx.ipc_buf) }
        .map_err(|_| "reply_oom: the reply into the caller's reserve failed")?;

    // The second call: the reserve is spent.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "second ipc_recv for reply_oom test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("reply_oom: second ipc_recv returned wrong label");
    }

    // Cap-bearing reply: the child's reserve is spent and its pool
    // exhausted, so the kernel's pre_allocate on the caller side fails. The kernel returns
    // OutOfMemory to the server *and* wakes the caller with the
    // synthetic IPC_REPLY_TRANSFER_FAILED label.
    let cap_reply = IpcMessage::builder(0xBEEF).cap(xfer).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let attempt = unsafe { ipc::ipc_reply(&cap_reply, ctx.ipc_buf) };
    match attempt
    {
        Err(code) if code == syscall_abi::SyscallError::OutOfMemory as i64 =>
        {}
        Err(_) => return Err("reply_oom: cap-bearing reply returned wrong error code"),
        Ok(()) => return Err("reply_oom: cap-bearing reply succeeded unexpectedly"),
    }

    // The child must have un-parked observing the synthetic transfer-failed
    // label. It signals 0xFA11 in that case (see reply_oom_caller_entry).
    let done_bits =
        notification_wait(done).map_err(|_| "notification_wait(done) for reply_oom failed")?;
    if done_bits != 0xFA11
    {
        return Err("reply_oom: child did not get 4 caps and then IPC_REPLY_TRANSFER_FAILED");
    }

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(ready).ok();
    cap_delete(done).ok();
    cap_delete(xfer).ok();
    for c in reserve_caps
    {
        cap_delete(c).ok();
    }
    child.delete_cspace().ok();
    Ok(())
}

/// Mint `MSG_CAP_SLOTS_MAX` (4) notifications from `memory` for a
/// cap-bearing message.
fn mint_notifications(memory: u64) -> Result<[u64; 4], &'static str>
{
    let mut caps = [0u64; 4];
    for c in &mut caps
    {
        *c = cap_create_notification(memory)
            .map_err(|_| "cap_create_notification for a four-cap message failed")?;
    }
    Ok(caps)
}

/// A message labelled `label` carrying the four `caps`.
fn four_cap_message(label: u64, caps: [u64; 4]) -> IpcMessage
{
    IpcMessage::builder(label)
        .cap(caps[0])
        .cap(caps[1])
        .cap(caps[2])
        .cap(caps[3])
        .build()
}

/// Child for `reply_oom_wakes_caller_with_transfer_failed`: registers IPC
/// buffer, fills its own `CSpace`'s general slots, signals readiness, then
/// issues two `ipc_call`s. Reports `0xFA11` if the first reply delivers four
/// caps and the second is the kernel-synthesised `IPC_REPLY_TRANSFER_FAILED`
/// label, `0xBAD` otherwise.
extern "C" fn reply_oom_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let ReplyOomArgs {
        ep: ep_slot,
        ready: ready_slot,
        done: done_slot,
        memory: memory_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(REPLY_OOM_CALLER_IPC_PAGE));
    // SAFETY: `REPLY_OOM_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(ready_slot, 0xBAD).ok();
        thread_exit()
    }

    // Saturate the child's general slots, leaving only the IPC receive
    // reserve. Bounded loop guards against an unbounded CSpace if the test
    // setup ever changes.
    for _ in 0..1024
    {
        if cap_create_notification(memory_slot).is_err()
        {
            break;
        }
    }
    if cap_create_notification(memory_slot).is_ok()
    {
        // Still has free slots — test setup did not actually fill the CSpace.
        notification_send(ready_slot, 0xBAD).ok();
        thread_exit()
    }

    notification_send(ready_slot, 0x1).ok();

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let first = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xCAFE), buf_addr as *mut u64) };
    let reserve_filled = first.is_ok_and(|msg| msg.label == 0xBEEF && msg.caps().len() == 4);

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let reply = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xCAFE), buf_addr as *mut u64) };
    match reply
    {
        Ok(msg) =>
        {
            let bits = if reserve_filled && msg.label == syscall_abi::IPC_REPLY_TRANSFER_FAILED
            {
                0xFA11
            }
            else
            {
                0xBAD
            };
            notification_send(done_slot, bits).ok();
        }
        Err(_) =>
        {
            notification_send(done_slot, 0xBAD).ok();
        }
    }
    thread_exit()
}

// ── cap-transfer slot rejection (stale and duplicate) ───────────────────────

/// `sys_ipc_call` rejects a message naming a stale cap handle, before the
/// caller blocks.
///
/// Pins the stale-handle rejection of core/kernel/docs/syscalls.md
/// § `SYS_IPC_CALL` (handle format: docs/capability-model.md § Capability
/// Handle Format): the call fails with `InvalidCapability` and the recycled
/// slot's occupant is untouched.
pub fn call_stale_cap_handle_rejected(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for stale_cap test failed")?;
    let victim = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(victim) for stale_cap test failed")?;
    cap_delete(victim).map_err(|_| "cap_delete(victim) for stale_cap test failed")?;
    // The next create recycles the freed slot with a bumped generation
    // (core/kernel/docs/capability-internals.md § Free Slot Tracking and
    // § Per-Slot Generation); `victim` is now a stale handle to the
    // occupant's slot.
    let occupant = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(occupant) for stale_cap test failed")?;
    if syscall_abi::cap_handle_index(occupant) != syscall_abi::cap_handle_index(victim)
    {
        cap_delete(occupant).ok();
        cap_delete(ep).ok();
        return Err("stale_cap: freed slot was not recycled by the next create");
    }

    let msg = IpcMessage::builder(0x57A1).cap(victim).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let attempt = unsafe { ipc::ipc_call(ep, &msg, ctx.ipc_buf) };
    let outcome = match attempt
    {
        Err(code) if code == syscall_abi::SyscallError::InvalidCapability as i64 => Ok(()),
        Err(_) => Err("stale_cap: wrong error code for stale handle"),
        Ok(_) => Err("stale_cap: call with a stale cap handle succeeded"),
    };

    // The occupant must be untouched by the refused transfer.
    let occupant_intact = notification_send(occupant, 0x1).is_ok();
    cap_delete(occupant).ok();
    cap_delete(ep).ok();
    if !occupant_intact
    {
        return Err("stale_cap: occupant cap was disturbed by the refused transfer");
    }
    outcome
}

/// `sys_ipc_call` rejects a message that names the same cap slot twice,
/// before the caller blocks.
///
/// A repeated index would make the transfer's second move observe the Null
/// slot the first move freed; the kernel refuses the message up front with
/// `InvalidArgument` and the caller keeps its capabilities.
pub fn call_duplicate_cap_slot_rejected(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for call_dup test failed")?;
    let xfer = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for call_dup test failed")?;

    let msg = IpcMessage::builder(0xD0D0).cap(xfer).cap(xfer).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let attempt = unsafe { ipc::ipc_call(ep, &msg, ctx.ipc_buf) };
    match attempt
    {
        Err(code) if code == syscall_abi::SyscallError::InvalidArgument as i64 =>
        {}
        Err(_) => return Err("call_dup: wrong error code for duplicate cap slot"),
        Ok(_) => return Err("call_dup: duplicate-cap call succeeded unexpectedly"),
    }
    // The refused transfer left the cap untouched.
    notification_send(xfer, 0x1).map_err(|_| "call_dup: cap lost after refused call")?;

    cap_delete(xfer).ok();
    cap_delete(ep).ok();
    Ok(())
}

/// A reply that names the same cap slot twice is refused with
/// `InvalidArgument` at the server, and the waiting caller un-parks with
/// the synthetic `IPC_REPLY_TRANSFER_FAILED` label instead of being
/// stranded.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg`, the `cap_reply` `IpcMessage` and the builder values of its \
              `.cap()` chain (568 B each), and the `Result` temporaries of its `ipc_recv(..)?` \
              (about 576 B each); on init's 16 KiB stack"
)]
pub fn reply_duplicate_cap_slot_rejected(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for reply_dup test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for reply_dup test failed")?;
    let xfer = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(xfer) for reply_dup test failed")?;

    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "reply_dup: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for reply_dup test failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for reply_dup test failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        DUP_REPLY_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };
    // SAFETY: `DUP_REPLY_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(DUP_REPLY_STACK)) };
    // SAFETY: the stack is `DUP_REPLY_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(&child, dup_reply_caller_entry, stack_top, child_arg)
    }
    .map_err(|_| "reply_dup: configure_and_start failed")?;

    // Receive the child's call, then reply with one slot repeated.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for reply_dup test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("reply_dup: ipc_recv returned wrong label");
    }
    let cap_reply = IpcMessage::builder(0xBEEF).cap(xfer).cap(xfer).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let attempt = unsafe { ipc::ipc_reply(&cap_reply, ctx.ipc_buf) };
    match attempt
    {
        Err(code) if code == syscall_abi::SyscallError::InvalidArgument as i64 =>
        {}
        Err(_) => return Err("reply_dup: wrong error code for duplicate cap slot"),
        Ok(()) => return Err("reply_dup: duplicate-cap reply succeeded unexpectedly"),
    }

    // The child must have un-parked observing the synthetic label.
    let done_bits =
        notification_wait(done).map_err(|_| "notification_wait(done) for reply_dup failed")?;
    if done_bits != 0xFA11
    {
        return Err("reply_dup: child did not observe IPC_REPLY_TRANSFER_FAILED");
    }
    // The refused transfer left the server's cap untouched.
    notification_send(xfer, 0x1).map_err(|_| "reply_dup: cap lost after refused reply")?;

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(xfer).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Child for `reply_duplicate_cap_slot_rejected` and
/// `reply_stale_cap_handle_rejected`: registers its IPC buffer and issues
/// an `ipc_call`; reports `0xFA11` if the kernel-synthesised
/// `IPC_REPLY_TRANSFER_FAILED` label arrives, `0xBAD` otherwise.
extern "C" fn dup_reply_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs {
        ep: ep_slot,
        done: done_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(DUP_REPLY_CALLER_IPC_PAGE));
    // SAFETY: `DUP_REPLY_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let reply = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(0xCAFE), buf_addr as *mut u64) };
    let bits = match reply
    {
        Ok(msg) if msg.label == syscall_abi::IPC_REPLY_TRANSFER_FAILED => 0xFA11,
        _ => 0xBAD,
    };
    notification_send(done_slot, bits).ok();
    thread_exit()
}

// ── reply-direction stale cap-handle rejection ───────────────────────────────

/// A reply naming a stale cap handle is refused with `InvalidCapability`;
/// the waiting caller is still woken with the synthetic
/// `IPC_REPLY_TRANSFER_FAILED` label and the recycled slot's current
/// occupant is untouched. The handle is 256 recycles stale, so the
/// occupant's generation is past 255 and differs from the handle's only
/// above the low byte: the reply's cap block must carry the full handle.
///
/// Exercises the generation-mismatch branch of the reply direction's
/// pre-validation — a distinct rejection cause from the duplicate-index
/// branch `reply_duplicate_cap_slot_rejected` covers, routed through the
/// same post-claim `deposit_transfer_failed_reply` wake.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg`, the `cap_reply` `IpcMessage` and the builder values of its \
              `.cap()` chain (568 B each), and the `Result` temporaries of its `ipc_recv(..)?` \
              (about 576 B each); on init's 16 KiB stack"
)]
pub fn reply_stale_cap_handle_rejected(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for reply_stale test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for reply_stale test failed")?;
    let victim = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(victim) for reply_stale test failed")?;
    cap_delete(victim).map_err(|_| "cap_delete(victim) for reply_stale test failed")?;
    // Recycle the freed slot 256 times (the LIFO free list hands the same
    // index back each time) so `victim` is a stale handle to the occupant's
    // slot whose generation matches the occupant's in its low byte.
    for _ in 0..255
    {
        let filler = cap_create_notification(ctx.memory_base)
            .map_err(|_| "cap_create_notification(filler) for reply_stale test failed")?;
        cap_delete(filler).map_err(|_| "cap_delete(filler) for reply_stale test failed")?;
    }
    let occupant = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification(occupant) for reply_stale test failed")?;
    if syscall_abi::cap_handle_index(occupant) != syscall_abi::cap_handle_index(victim)
        || Some(syscall_abi::cap_handle_gen(occupant))
            != syscall_abi::cap_handle_gen(victim).checked_add(256)
    {
        cap_delete(occupant).ok();
        cap_delete(done).ok();
        cap_delete(ep).ok();
        return Err("reply_stale: freed slot was not recycled once per create");
    }

    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "reply_stale: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for reply_stale test failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for reply_stale test failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        STALE_REPLY_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };
    // SAFETY: `STALE_REPLY_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(STALE_REPLY_STACK)) };
    // SAFETY: the stack is `STALE_REPLY_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(&child, dup_reply_caller_entry, stack_top, child_arg)
    }
    .map_err(|_| "reply_stale: configure_and_start failed")?;

    // Receive the child's call, then reply naming the stale handle.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for reply_stale test failed")?;
    if msg.label != 0xCAFE
    {
        return Err("reply_stale: ipc_recv returned wrong label");
    }
    let cap_reply = IpcMessage::builder(0xBEEF).cap(victim).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let attempt = unsafe { ipc::ipc_reply(&cap_reply, ctx.ipc_buf) };
    match attempt
    {
        Err(code) if code == syscall_abi::SyscallError::InvalidCapability as i64 =>
        {}
        Err(_) => return Err("reply_stale: wrong error code for stale reply handle"),
        Ok(()) => return Err("reply_stale: stale-handle reply succeeded unexpectedly"),
    }

    // The child must have un-parked observing the synthetic label.
    let done_bits =
        notification_wait(done).map_err(|_| "notification_wait(done) for reply_stale failed")?;
    if done_bits != 0xFA11
    {
        return Err("reply_stale: child did not observe IPC_REPLY_TRANSFER_FAILED");
    }
    // The occupant must be untouched by the refused transfer.
    notification_send(occupant, 0x1)
        .map_err(|_| "reply_stale: occupant cap disturbed by refused reply")?;

    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(occupant).ok();
    child.delete_cspace().ok();
    Ok(())
}

// ── full-width cap transfer (every handle word) ──────────────────────────────

/// An IPC call transferring `MSG_CAP_SLOTS_MAX` (4) capabilities delivers
/// all four intact.
///
/// Exercises every cap-handle word of the sender's IPC buffer, the
/// `MSG_CAP_SLOTS_MAX` words from `MSG_CAP_HANDLES_WORD` on (layout:
/// core/kernel/docs/syscalls.md § `SYS_IPC_CALL`), so a sender and kernel
/// that disagreed on where a handle word sits would fail it.
#[expect(
    clippy::large_stack_frames,
    reason = "the received `msg` and the reply `IpcMessage` (568 B each) and the `Result` \
              temporaries of its `ipc_recv(..)?` (about 576 B each); on init's 16 KiB stack"
)]
pub fn call_four_caps_transfer(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "cap_create_endpoint for four_caps test failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for four_caps test failed")?;

    let mut child =
        crate::spawn::new_child(ctx).map_err(|_| "four_caps: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "cap_copy ep for four_caps test failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "cap_copy done for four_caps test failed")?;
    let child_memory = cap_copy(ctx.memory_base, child.cs, syscall::RIGHTS_ALL)
        .map_err(|_| "cap_copy memory for four_caps test failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        FOUR_CAPS_ARGS.publish(
            0,
            XferArgs {
                ep: child_ep,
                done: child_done,
                memory: child_memory,
            },
        )
    };

    // SAFETY: `FOUR_CAPS_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(FOUR_CAPS_STACK)) };
    // SAFETY: the stack is `FOUR_CAPS_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(&child, four_caps_caller_entry, stack_top, child_arg)
    }
    .map_err(|_| "four_caps: configure_and_start failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "ipc_recv for four_caps test failed")?;
    if msg.label != 0x4CA5
    {
        return Err("four_caps: ipc_recv returned wrong label");
    }
    if msg.caps().len() != 4
    {
        return Err("four_caps: expected 4 transferred caps");
    }
    // Each delivered handle must name a distinct, usable notification.
    for (i, &h) in msg.caps().iter().enumerate()
    {
        if msg
            .caps()
            .iter()
            .take(i)
            .any(|&o| syscall_abi::cap_handle_index(o) == syscall_abi::cap_handle_index(h))
        {
            return Err("four_caps: duplicate destination slot delivered");
        }
        if notification_send(h, 1 << i).is_err()
        {
            return Err("four_caps: a transferred cap is not a usable notification");
        }
    }

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "ipc_reply for four_caps test failed")?;
    notification_wait(done).map_err(|_| "notification_wait for four_caps test failed")?;

    for &h in msg.caps()
    {
        cap_delete(h).ok();
    }
    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Child for `call_four_caps_transfer`: creates four notifications and
/// sends all of them in one cap-bearing call, then signals completion.
#[expect(
    clippy::large_stack_frames,
    reason = "the request `msg` and the five builder values of its `.cap()` chain (568 B each) and \
              the `Result` holding the reply (about 576 B); on its 16 KiB `ChildStack`"
)]
extern "C" fn four_caps_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let XferArgs {
        ep: ep_slot,
        done: done_slot,
        memory: memory_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(FOUR_CAPS_CALLER_IPC_PAGE));
    // SAFETY: `FOUR_CAPS_CALLER_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    let mut caps = [0u64; 4];
    for c in &mut caps
    {
        let Ok(h) = cap_create_notification(memory_slot)
        else
        {
            notification_send(done_slot, 0xBAD).ok();
            thread_exit()
        };
        *c = h;
    }

    let msg = IpcMessage::builder(0x4CA5)
        .cap(caps[0])
        .cap(caps[1])
        .cap(caps[2])
        .cap(caps[3])
        .build();
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(_) => notification_send(done_slot, 0xD00D).ok(),
        Err(_) => notification_send(done_slot, 0xBAD).ok(),
    };
    thread_exit()
}

// ── sys_ipc_recv on a CSpace whose general slots are exhausted ──────────────

/// Bound on each of the test's waits for a child report, in milliseconds: a
/// receive that blocked or a transfer that was never delivered surfaces as a
/// test failure, not a wedged harness.
const RECV_RESERVE_WAIT_MS: u64 = 10_000;

/// `sys_ipc_recv` succeeds on a `CSpace` whose general slots are exhausted,
/// and the received caps land in the IPC receive reserve; once they have
/// taken it, the next `ipc_recv` fails before blocking with `OutOfMemory`
/// (core/kernel/docs/capability-internals.md § IPC Receive Reserve,
/// docs/ipc-design.md § Receive-Failure Policy).
///
/// The victim fills its single-page `CSpace` with general allocations until
/// one fails with `OutOfMemory`, then serves receives: it replies to each
/// call with the number of caps it received. A caller thread in ktest's own
/// `CSpace` sends one call carrying `MSG_CAP_SLOTS_MAX` (4) caps. The caller
/// must see the reply count 4, and the victim's next receive must fail with
/// `OutOfMemory` after exactly one served round.
pub fn recv_succeeds_on_exhausted_general_slots(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "recv_reserve: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "recv_reserve: cap_create_notification(done) failed")?;
    let result = cap_create_notification(ctx.memory_base)
        .map_err(|_| "recv_reserve: cap_create_notification(result) failed")?;

    // A single-pool-page cspace (55 usable slots) is part of the test
    // contract: the victim fills its general slots. Bypasses
    // `spawn::new_child` per the convention documented in
    // `crate::spawn::new_child_at`.
    let victim_cs = cap_create_cspace(ctx.memory_base, 0, 2)
        .map_err(|_| "recv_reserve: cap_create_cspace failed")?;
    let victim_ep = cap_copy(ep, victim_cs, syscall_abi::RIGHTS_EP_RECEIVE)
        .map_err(|_| "recv_reserve: cap_copy ep failed")?;
    let victim_done = cap_copy(done, victim_cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "recv_reserve: cap_copy done failed")?;
    let victim_memory = cap_copy(ctx.memory_base, victim_cs, syscall::RIGHTS_ALL)
        .map_err(|_| "recv_reserve: cap_copy memory failed")?;
    // SAFETY: the victim has not been started yet.
    let victim_arg = unsafe {
        RECV_RESERVE_ARGS.publish(
            0,
            XferArgs {
                ep: victim_ep,
                done: victim_done,
                memory: victim_memory,
            },
        )
    };
    // SAFETY: the caller has not been started yet.
    let caller_arg = unsafe {
        RECV_RESERVE_ARGS.publish(
            1,
            XferArgs {
                ep,
                done: result,
                memory: ctx.memory_base,
            },
        )
    };

    let victim_th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, victim_cs, 0, 0)
        .map_err(|_| "recv_reserve: cap_create_thread(victim) failed")?;
    let mut victim = crate::spawn::SpawnedChild {
        th: victim_th,
        cs: victim_cs,
    };
    let caller_th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, ctx.cspace_cap, 0, 0)
        .map_err(|_| "recv_reserve: cap_create_thread(caller) failed")?;

    let outcome = recv_reserve_drive(
        [victim_th, caller_th],
        [victim_arg, caller_arg],
        [result, done],
    );

    // Deleting the threads ends a receive or call a failure left blocked.
    cap_delete(caller_th).ok();
    victim.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(result).ok();
    victim.delete_cspace().ok();
    outcome
}

/// Start the victim and the caller of `recv_succeeds_on_exhausted_general_slots`
/// (`threads` and their published `args`, in that order) and check their
/// reports on `reports`: the caller's result, then the victim's done.
fn recv_reserve_drive(threads: [u64; 2], args: [u64; 2], reports: [u64; 2]) -> TestResult
{
    let [victim_th, caller_th] = threads;
    let [victim_arg, caller_arg] = args;
    let [result, done] = reports;
    // SAFETY: `RECV_RESERVE_VICTIM_STACK` is a static stack, reached only through `addr_of!`.
    let victim_stack = unsafe { ChildStack::top(core::ptr::addr_of!(RECV_RESERVE_VICTIM_STACK)) };
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and
    // the stack is `RECV_RESERVE_VICTIM_STACK`, the victim's own, on which no
    // other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start_thread(
            victim_th,
            recv_reserve_victim_entry,
            victim_stack,
            victim_arg,
        )?;
    }
    // SAFETY: `RECV_RESERVE_CALLER_STACK` is a static stack, reached only through `addr_of!`.
    let caller_stack = unsafe { ChildStack::top(core::ptr::addr_of!(RECV_RESERVE_CALLER_STACK)) };
    // SAFETY: the entry is an `extern "C" fn(u64) -> !` of the entry ABI, and
    // the stack is `RECV_RESERVE_CALLER_STACK`, the caller's own, on which no
    // other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start_thread(
            caller_th,
            recv_reserve_caller_entry,
            caller_stack,
            caller_arg,
        )?;
    }
    let caller_bits = syscall::notification_wait_timeout(result, RECV_RESERVE_WAIT_MS)
        .map_err(|_| "recv_reserve: notification_wait(result) failed")?;
    if caller_bits != 0x1000 | 4
    {
        return Err("recv_reserve: the exhausted CSpace did not receive all 4 caps");
    }
    let victim_bits = syscall::notification_wait_timeout(done, RECV_RESERVE_WAIT_MS)
        .map_err(|_| "recv_reserve: notification_wait(done) failed")?;
    if victim_bits != 0xDE01
    {
        return Err("recv_reserve: the receive after the reserve was spent did not fail once");
    }
    Ok(())
}

/// Victim for `recv_succeeds_on_exhausted_general_slots`: fills its `CSpace`'s
/// general slots, then serves receives, replying to each with the number of
/// caps it carried. Reports `0xDE00 | rounds` once a receive fails with
/// `OutOfMemory`, `0xBAD` on any other outcome.
extern "C" fn recv_reserve_victim_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this victim.
    let XferArgs {
        ep: ep_slot,
        done: done_slot,
        memory: memory_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(RECV_RESERVE_VICTIM_IPC_PAGE));
    // SAFETY: `RECV_RESERVE_VICTIM_IPC_PAGE` is this child's own IPC page, used by one thread at
    // a time (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    // General allocations fail first, with a caller-visible OutOfMemory.
    let mut filled = false;
    for _ in 0..1024
    {
        match cap_create_notification(memory_slot)
        {
            Ok(_) =>
            {}
            Err(code) if code == syscall_abi::SyscallError::OutOfMemory as i64 =>
            {
                filled = true;
                break;
            }
            Err(_) => break,
        }
    }
    if !filled
    {
        notification_send(done_slot, 0xBAD).ok();
        thread_exit()
    }

    let mut rounds: u64 = 0;
    loop
    {
        // SAFETY: buf_addr was registered as this thread's IPC buffer above.
        match unsafe { ipc::ipc_recv(ep_slot, buf_addr as *mut u64) }
        {
            Ok(msg) if rounds < 8 =>
            {
                rounds = rounds.saturating_add(1);
                let reply = IpcMessage::new(msg.caps().len() as u64);
                // SAFETY: buf_addr was registered as this thread's IPC buffer above.
                if unsafe { ipc::ipc_reply(&reply, buf_addr as *mut u64) }.is_err()
                {
                    notification_send(done_slot, 0xBAD).ok();
                    thread_exit()
                }
            }
            Err(code) if code == syscall_abi::SyscallError::OutOfMemory as i64 =>
            {
                notification_send(done_slot, 0xDE00 | rounds).ok();
                thread_exit()
            }
            _ =>
            {
                notification_send(done_slot, 0xBAD).ok();
                thread_exit()
            }
        }
    }
}

/// Caller for `recv_succeeds_on_exhausted_general_slots`, in ktest's own
/// `CSpace`: mints `MSG_CAP_SLOTS_MAX` notifications, sends them in one call,
/// and reports `0x1000 | <reply label>`, or `0xBAD` on failure.
#[expect(
    clippy::large_stack_frames,
    reason = "the request `msg` and the five builder values of its `.cap()` chain (568 B each) and \
              the `Result` holding the reply (about 576 B); on its 16 KiB `ChildStack`"
)]
extern "C" fn recv_reserve_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this caller.
    let XferArgs {
        ep: ep_slot,
        done: result_slot,
        memory: memory_slot,
    } = unsafe { child_args(arg) };

    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(RECV_RESERVE_CALLER_IPC_PAGE));
    // SAFETY: `RECV_RESERVE_CALLER_IPC_PAGE` is this thread's own IPC page, used by one thread at
    // a time (`IpcPage`'s rule); no Rust object lives in it, and the thread
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(result_slot, 0xBAD).ok();
        thread_exit()
    }

    let mut caps = [0u64; 4];
    for c in &mut caps
    {
        let Ok(h) = cap_create_notification(memory_slot)
        else
        {
            notification_send(result_slot, 0xBAD).ok();
            thread_exit()
        };
        *c = h;
    }
    let msg = IpcMessage::builder(0x5E5E)
        .cap(caps[0])
        .cap(caps[1])
        .cap(caps[2])
        .cap(caps[3])
        .build();
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let bits = match unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }
    {
        Ok(reply) => 0x1000 | (reply.label & 0xFFF),
        Err(_) => 0xBAD,
    };
    notification_send(result_slot, bits).ok();
    thread_exit()
}

// ── SYS_IPC_RECV / SYS_IPC_CALL (timed and try-once waits) ───────────────────

/// `WaitArgs` slot of `recv_try_once_takes_queued_caller`.
const WAIT_SLOT_TAKE: usize = 0;
/// `WaitArgs` slot of `recv_try_once_keeps_reply_binding`.
const WAIT_SLOT_KEEP: usize = 1;
/// `WaitArgs` slot of `call_timeout_late_reply_refused`.
const WAIT_SLOT_LATE: usize = 2;
/// `WaitArgs` slot of `regs_round_trip_no_buffer`'s server.
const WAIT_SLOT_REGS_SERVER: usize = 3;
/// `WaitArgs` slot of `regs_and_buffer_delivery`'s caller.
const WAIT_SLOT_REGS_CALLER: usize = 4;

/// Bound on each wait for a child's report, before `crate::scaled_bound`.
const WAIT_REPORT_MS: u64 = 5000;
/// Report bits of a child whose setup or call failed.
const WAIT_BAD: u64 = 0xBAD;
/// Report bit of `wait_late_server_entry`: it has received a call.
const WAIT_RECEIVED: u64 = 1 << 40;
/// Report bits of `wait_late_server_entry`: its late reply was refused with
/// `InvalidCapability`.
const WAIT_REFUSED: u64 = 0xD00D;
/// Bound of each call `call_timeout_late_reply_refused` makes.
const LATE_CALL_TIMEOUT_MS: u32 = 50;
/// Calls `call_timeout_late_reply_refused` makes, before `crate::scaled_bound`,
/// until the server has received one.
const LATE_CALL_ATTEMPTS: u64 = 50;

/// Label the timed-wait callers send.
const WAIT_CALL_LABEL: u64 = 0x7001;

/// Arguments of the timed-wait children, handed to their entries by address;
/// `page` is the address of the child's own IPC page, and `go` a notification
/// the child waits on (0 for a child that waits on none).
#[derive(Clone, Copy)]
struct WaitArgs
{
    ep: u64,
    done: u64,
    go: u64,
    page: u64,
}

static WAIT_ARGS: ArgBlock<WaitArgs, 5> = ArgBlock::new(WaitArgs {
    ep: 0,
    done: 0,
    go: 0,
    page: 0,
});
static mut WAIT_STACKS: [ChildStack; 5] = [ChildStack::ZERO; 5];
static mut WAIT_PAGES: [crate::IpcPage; 5] = [crate::IpcPage::ZERO; 5];

/// Microseconds since boot.
fn now_us() -> Result<u64, &'static str>
{
    syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "system_info(ElapsedUs) failed")
}

/// Create a child holding `ep` with `ep_rights`, `done` (NOTIFY), and, when
/// non-zero, `go` (WAIT), and start it at `entry` on slot `slot` of the
/// timed-wait stacks and pages.
fn start_wait_child(
    ctx: &TestContext,
    ep: u64,
    ep_rights: u64,
    done: u64,
    go: u64,
    slot: usize,
    entry: extern "C" fn(u64) -> !,
) -> Result<crate::spawn::SpawnedChild, &'static str>
{
    let child = crate::spawn::new_child(ctx).map_err(|_| "ipc wait child: new_child failed")?;
    let child_ep =
        cap_copy(ep, child.cs, ep_rights).map_err(|_| "ipc wait child: cap_copy ep failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "ipc wait child: cap_copy done failed")?;
    let child_go = if go == 0
    {
        0
    }
    else
    {
        cap_copy(go, child.cs, syscall_abi::RIGHTS_NTF_WAIT)
            .map_err(|_| "ipc wait child: cap_copy go failed")?
    };
    let page = crate::IpcPage::addr_at(core::ptr::addr_of_mut!(WAIT_PAGES), slot)?;
    // SAFETY: the slot's child has not been started yet.
    let arg = unsafe {
        WAIT_ARGS.publish(
            slot,
            WaitArgs {
                ep: child_ep,
                done: child_done,
                go: child_go,
                page,
            },
        )
    };
    // SAFETY: `WAIT_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top_at(core::ptr::addr_of!(WAIT_STACKS), slot) }?;
    // SAFETY: the stack is `WAIT_STACKS[slot]`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, entry, stack_top, arg) }
        .map_err(|_| "ipc wait child: configure_and_start failed")?;
    Ok(child)
}

/// Wait up to [`WAIT_REPORT_MS`], scaled, for a child's report bits on `done`.
fn wait_report(done: u64) -> Result<u64, &'static str>
{
    let bits = syscall::notification_wait_timeout(done, crate::scaled_bound(WAIT_REPORT_MS))
        .map_err(|_| "ipc wait child: notification_wait_timeout failed")?;
    if bits == 0
    {
        return Err("ipc wait child: no report within the bound");
    }
    Ok(bits)
}

/// `raw_ipc_recv_timeout` with `WAIT_TRY_ONCE` on an endpoint with no caller
/// returns `WouldBlock` at once.
pub fn recv_try_once_empty(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::recv_try_once_empty: cap_create_endpoint failed")?;
    let r = syscall::raw_ipc_recv_timeout(ep, syscall_abi::WAIT_TRY_ONCE);
    cap_delete(ep).map_err(|_| "ipc::recv_try_once_empty: cap_delete ep failed")?;
    if r != Err(syscall_abi::SyscallError::WouldBlock as i64)
    {
        return Err("ipc::recv_try_once_empty: try-once on an empty endpoint did not WouldBlock");
    }
    Ok(())
}

/// `raw_ipc_recv_timeout` with a 50 ms bound and no caller returns
/// `WouldBlock` once the bound has elapsed.
pub fn recv_timeout_expires(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::recv_timeout_expires: cap_create_endpoint failed")?;
    let t0 = now_us()?;
    let r = syscall::raw_ipc_recv_timeout(ep, 50);
    let t1 = now_us()?;
    cap_delete(ep).map_err(|_| "ipc::recv_timeout_expires: cap_delete ep failed")?;
    if r != Err(syscall_abi::SyscallError::WouldBlock as i64)
    {
        return Err("ipc::recv_timeout_expires: expired receive did not return WouldBlock");
    }
    // Allow ~10 ms slack for timer granularity on slow VMs.
    if t1.wrapping_sub(t0) < 40_000
    {
        return Err("ipc::recv_timeout_expires: receive returned earlier than its timeout");
    }
    Ok(())
}

/// A try-once receive takes a caller already queued on the endpoint, and the
/// reply it then sends reaches that caller.
pub fn recv_try_once_takes_queued_caller(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::recv_try_once_takes_queued_caller: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::recv_try_once_takes_queued_caller: create done failed")?;
    let mut child = start_wait_child(
        ctx,
        ep,
        RIGHTS_EP_SEND_GRANT,
        done,
        0,
        WAIT_SLOT_TAKE,
        wait_caller_entry,
    )?;

    // Give the child time to queue, then retry the try-once a bounded number
    // of times, scaled.
    let mut got = None;
    for _ in 0..crate::scaled_bound(50)
    {
        thread_sleep(20).map_err(|_| "ipc::recv_try_once_takes_queued_caller: sleep failed")?;
        match syscall::raw_ipc_recv_timeout(ep, syscall_abi::WAIT_TRY_ONCE)
        {
            Ok(m) =>
            {
                got = Some(m);
                break;
            }
            Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 =>
            {}
            Err(_) => return Err("ipc::recv_try_once_takes_queued_caller: try-once failed"),
        }
    }
    let got = got.ok_or("ipc::recv_try_once_takes_queued_caller: no caller was ever taken")?;
    if got.label != WAIT_CALL_LABEL
    {
        return Err("ipc::recv_try_once_takes_queued_caller: wrong label received");
    }
    syscall::raw_ipc_reply(0xC0DE, 0, 0, &syscall::MsgRegs::default())
        .map_err(|_| "ipc::recv_try_once_takes_queued_caller: reply failed")?;
    let report = wait_report(done)?;
    if report != 0xC0DE
    {
        return Err("ipc::recv_try_once_takes_queued_caller: caller got the wrong reply");
    }

    child
        .delete_thread()
        .map_err(|_| "ipc::recv_try_once_takes_queued_caller: delete child failed")?;
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// A try-once receive that finds no caller returns `WouldBlock` and leaves the
/// reply the thread still owes bound: the later reply reaches the first caller.
pub fn recv_try_once_keeps_reply_binding(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::recv_try_once_keeps_reply_binding: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::recv_try_once_keeps_reply_binding: create done failed")?;
    let mut child = start_wait_child(
        ctx,
        ep,
        RIGHTS_EP_SEND_GRANT,
        done,
        0,
        WAIT_SLOT_KEEP,
        wait_caller_entry,
    )?;

    let received = syscall::raw_ipc_recv(ep)
        .map_err(|_| "ipc::recv_try_once_keeps_reply_binding: recv failed")?;
    if received.label != WAIT_CALL_LABEL
    {
        return Err("ipc::recv_try_once_keeps_reply_binding: wrong label received");
    }
    if syscall::raw_ipc_recv_timeout(ep, syscall_abi::WAIT_TRY_ONCE)
        != Err(syscall_abi::SyscallError::WouldBlock as i64)
    {
        return Err("ipc::recv_try_once_keeps_reply_binding: try-once did not WouldBlock");
    }
    syscall::raw_ipc_reply(0xB10B, 0, 0, &syscall::MsgRegs::default())
        .map_err(|_| "ipc::recv_try_once_keeps_reply_binding: reply after the try-once failed")?;
    let report = wait_report(done)?;
    if report != 0xB10B
    {
        return Err("ipc::recv_try_once_keeps_reply_binding: caller got the wrong reply");
    }

    child
        .delete_thread()
        .map_err(|_| "ipc::recv_try_once_keeps_reply_binding: delete child failed")?;
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// `raw_ipc_call_timeout` with no server returns `WouldBlock` after its
/// bound, and the timed-out caller is not left on the send queue.
pub fn call_timeout_no_receiver(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::call_timeout_no_receiver: cap_create_endpoint failed")?;
    let t0 = now_us()?;
    let r =
        syscall::raw_ipc_call_timeout(ep, WAIT_CALL_LABEL, 0, 0, 50, &syscall::MsgRegs::default());
    let t1 = now_us()?;
    if r != Err(syscall_abi::SyscallError::WouldBlock as i64)
    {
        return Err("ipc::call_timeout_no_receiver: timed-out call did not return WouldBlock");
    }
    // Allow ~10 ms slack for timer granularity on slow VMs.
    if t1.wrapping_sub(t0) < 40_000
    {
        return Err("ipc::call_timeout_no_receiver: call returned earlier than its timeout");
    }
    if syscall::raw_ipc_recv_timeout(ep, syscall_abi::WAIT_TRY_ONCE)
        != Err(syscall_abi::SyscallError::WouldBlock as i64)
    {
        return Err("ipc::call_timeout_no_receiver: timed-out caller was left queued");
    }
    cap_delete(ep).map_err(|_| "ipc::call_timeout_no_receiver: cap_delete ep failed")?;
    Ok(())
}

/// A caller whose timeout expired in the reply phase is unbound: the server's
/// later reply returns `InvalidCapability`.
///
/// The server replies only once the test tells it to, after the call has
/// returned, so no timing window decides the outcome. A call that expires
/// before the server receives it is retried; the server reports
/// [`WAIT_RECEIVED`] once it has received one, whose reply phase that call's
/// expiry then ended.
pub fn call_timeout_late_reply_refused(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::call_timeout_late_reply_refused: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::call_timeout_late_reply_refused: create done failed")?;
    let go = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::call_timeout_late_reply_refused: create go failed")?;
    let mut child = start_wait_child(
        ctx,
        ep,
        syscall_abi::RIGHTS_EP_RECEIVE,
        done,
        go,
        WAIT_SLOT_LATE,
        wait_late_server_entry,
    )?;

    let mut received = false;
    for _ in 0..crate::scaled_bound(LATE_CALL_ATTEMPTS)
    {
        let r = syscall::raw_ipc_call_timeout(
            ep,
            WAIT_CALL_LABEL,
            0,
            0,
            LATE_CALL_TIMEOUT_MS,
            &syscall::MsgRegs::default(),
        );
        if r != Err(syscall_abi::SyscallError::WouldBlock as i64)
        {
            return Err("ipc::call_timeout_late_reply_refused: call did not time out");
        }
        match syscall::notification_try_wait(done)
        {
            Ok(bits) if bits & WAIT_RECEIVED != 0 =>
            {
                received = true;
                break;
            }
            Ok(_) => return Err("ipc::call_timeout_late_reply_refused: server failed"),
            Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 =>
            {}
            Err(_) => return Err("ipc::call_timeout_late_reply_refused: try-wait failed"),
        }
    }
    if !received
    {
        return Err("ipc::call_timeout_late_reply_refused: server never received a call");
    }
    notification_send(go, 1)
        .map_err(|_| "ipc::call_timeout_late_reply_refused: notify go failed")?;
    let report = wait_report(done)?;
    if report != WAIT_REFUSED
    {
        return Err("ipc::call_timeout_late_reply_refused: late reply was not refused");
    }

    child
        .delete_thread()
        .map_err(|_| "ipc::call_timeout_late_reply_refused: delete child failed")?;
    cap_delete(ep).ok();
    cap_delete(done).ok();
    cap_delete(go).ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Report [`WAIT_BAD`] on the child's `done` and exit.
fn wait_child_fail(args: WaitArgs) -> !
{
    notification_send(args.done, WAIT_BAD).ok();
    thread_exit()
}

/// Child: calls the endpoint once, unbounded, with [`WAIT_CALL_LABEL`] and
/// reports the reply label on `done` ([`WAIT_BAD`] on an error).
extern "C" fn wait_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let args: WaitArgs = unsafe { child_args(arg) };
    // SAFETY: `args.page` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child reaches it
    // only through the raw address.
    if unsafe { syscall::ipc_buffer_set(args.page) }.is_err()
    {
        wait_child_fail(args)
    }
    let bits =
        match syscall::raw_ipc_call(args.ep, WAIT_CALL_LABEL, 0, 0, &syscall::MsgRegs::default())
        {
            Ok(reply) => reply.label,
            Err(_) => WAIT_BAD,
        };
    notification_send(args.done, bits).ok();
    thread_exit()
}

/// Child server: receives one call (within [`WAIT_REPORT_MS`], scaled),
/// reports [`WAIT_RECEIVED`], waits on `go` (as long), replies, and reports
/// [`WAIT_REFUSED`] if the reply returned `InvalidCapability`, [`WAIT_BAD`]
/// otherwise.
extern "C" fn wait_late_server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let args: WaitArgs = unsafe { child_args(arg) };
    // SAFETY: `args.page` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child reaches it
    // only through the raw address.
    if unsafe { syscall::ipc_buffer_set(args.page) }.is_err()
    {
        wait_child_fail(args)
    }
    let bound = crate::scaled_bound(WAIT_REPORT_MS);
    if syscall::raw_ipc_recv_timeout(args.ep, bound).is_err()
    {
        wait_child_fail(args)
    }
    notification_send(args.done, WAIT_RECEIVED).ok();
    if !matches!(syscall::notification_wait_timeout(args.go, bound), Ok(bits) if bits != 0)
    {
        wait_child_fail(args)
    }
    let bits = match syscall::raw_ipc_reply(1, 0, 0, &syscall::MsgRegs::default())
    {
        Err(e) if e == syscall_abi::SyscallError::InvalidCapability as i64 => WAIT_REFUSED,
        _ => WAIT_BAD,
    };
    notification_send(args.done, bits).ok();
    thread_exit()
}

// ── Register transport (MSG_REGS_DATA_MAX) ───────────────────────────────────

/// Label of the register-transport calls.
const REGS_CALL_LABEL: u64 = 0x7E61;
/// Label of the register-transport replies.
const REGS_REPLY_LABEL: u64 = 0x7E62;
/// Report bits of a register-transport child whose every check passed.
const REGS_OK: u64 = 0x600D;
/// Data words of a message that fills the message registers.
const REGS_WORDS: syscall::MsgRegs = [
    0x0101_0101_0101_0101,
    0x0202_0202_0202_0202,
    0x0303_0303_0303_0303,
    0x0404_0404_0404_0404,
    0x0505_0505_0505_0505,
    0x0606_0606_0606_0606,
];
/// Data words of a message one word longer than the message registers carry.
const BUF_WORDS: [u64; syscall_abi::MSG_REGS_DATA_MAX + 1] = [
    0x7101_0000_0000_0001,
    0x7102_0000_0000_0002,
    0x7103_0000_0000_0003,
    0x7104_0000_0000_0004,
    0x7105_0000_0000_0005,
    0x7106_0000_0000_0006,
    0x7107_0000_0000_0007,
];
/// Marks a buffer data word the kernel must leave alone.
const BUF_SENTINEL: u64 = 0x5E57_1E57_5E57_1E57;

/// The data words of the reply to a message that carried `words`.
fn reply_words<const N: usize>(words: &[u64; N]) -> [u64; N]
{
    words.map(|w| !w)
}

/// Write `words` over the first data words of the IPC buffer at `buf`.
///
/// # Safety
///
/// `buf` is the calling thread's registered IPC buffer, and `words` is no
/// longer than `MSG_DATA_WORDS_MAX`.
unsafe fn buf_write(buf: *mut u64, words: &[u64])
{
    for (i, &word) in words.iter().enumerate()
    {
        // SAFETY: i < words.len() <= MSG_DATA_WORDS_MAX, a word inside the
        // buffer page (this fn's contract).
        let slot = unsafe { buf.add(i) };
        // SAFETY: slot is a data word of the caller's own IPC buffer.
        unsafe { slot.write_volatile(word) };
    }
}

/// Whether the first data words of the IPC buffer at `buf` equal `words`.
///
/// # Safety
///
/// As [`buf_write`].
unsafe fn buf_holds(buf: *const u64, words: &[u64]) -> bool
{
    words.iter().enumerate().all(|(i, &word)| {
        // SAFETY: i < words.len() <= MSG_DATA_WORDS_MAX, a word inside the
        // buffer page (this fn's contract).
        let slot = unsafe { buf.add(i) };
        // SAFETY: slot is a data word of the caller's own IPC buffer.
        let value = unsafe { slot.read_volatile() };
        value == word
    })
}

/// A message of `MSG_REGS_DATA_MAX` data words travels with no IPC buffer
/// registered on either side, as a call and as its reply, and one of a word
/// more is refused `InvalidArgument` there, as a call and as a reply.
///
/// The harness thread deregisters its buffer for the test, and the child
/// server never registers one.
pub fn regs_round_trip_no_buffer(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::regs_round_trip_no_buffer: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::regs_round_trip_no_buffer: cap_create_notification failed")?;
    let result = regs_round_trip_no_buffer_on(ctx, ep, done);
    cap_delete(ep).ok();
    cap_delete(done).ok();
    result
}

/// The results of [`regs_unbuffered_calls`]: the over-long call and reply,
/// the round trip's reply, and the server child.
type UnbufferedCalls = (
    Result<syscall::IpcDelivery, i64>,
    Result<(), i64>,
    Result<syscall::IpcDelivery, i64>,
    crate::spawn::SpawnedChild,
);

fn regs_round_trip_no_buffer_on(ctx: &TestContext, ep: u64, done: u64) -> TestResult
{
    // SAFETY: deregistering (0) dedicates no page.
    unsafe { ipc_buffer_set(0) }
        .map_err(|_| "ipc::regs_round_trip_no_buffer: ipc_buffer_set(0) failed")?;
    let calls = regs_unbuffered_calls(ctx, ep, done);
    // SAFETY: ctx.ipc_buf is the page ktest registered at startup, dedicated
    // to the kernel's IPC access under the contract it was first registered
    // with; re-registering it restores that state.
    unsafe { ipc_buffer_set(ctx.ipc_buf as u64) }
        .map_err(|_| "ipc::regs_round_trip_no_buffer: re-registering the IPC buffer failed")?;
    let (long_call, long_reply, reply, mut child) = calls?;

    let invalid = Err(syscall_abi::SyscallError::InvalidArgument as i64);
    if long_call.map(|_| ()) != invalid
    {
        return Err("ipc::regs_round_trip_no_buffer: a 7-word call with no buffer was not refused");
    }
    if long_reply != invalid
    {
        return Err(
            "ipc::regs_round_trip_no_buffer: a 7-word reply with no buffer was not refused",
        );
    }
    let reply = reply.map_err(|_| "ipc::regs_round_trip_no_buffer: the 6-word call failed")?;
    if reply.label != REGS_REPLY_LABEL
        || reply.data_count != syscall_abi::MSG_REGS_DATA_MAX
        || reply.cap_count != 0
        || reply.regs != reply_words(&REGS_WORDS)
    {
        return Err("ipc::regs_round_trip_no_buffer: the 6-word reply arrived altered");
    }
    if wait_report(done)? != REGS_OK
    {
        return Err("ipc::regs_round_trip_no_buffer: the server saw the 6-word call altered");
    }
    child.delete_thread().ok();
    child.delete_cspace().ok();
    Ok(())
}

/// With the harness thread's buffer deregistered: an over-long call and
/// reply, then a round trip of `MSG_REGS_DATA_MAX` words with a server child.
fn regs_unbuffered_calls(
    ctx: &TestContext,
    ep: u64,
    done: u64,
) -> Result<UnbufferedCalls, &'static str>
{
    // Nothing receives yet: a long call that passed its checks would wait
    // out its bound, and a long reply that did would find no caller.
    let long_call = syscall::raw_ipc_call_timeout(
        ep,
        REGS_CALL_LABEL,
        syscall_abi::MSG_REGS_DATA_MAX + 1,
        0,
        LATE_CALL_TIMEOUT_MS,
        &REGS_WORDS,
    );
    let long_reply = syscall::raw_ipc_reply(
        REGS_REPLY_LABEL,
        syscall_abi::MSG_REGS_DATA_MAX + 1,
        0,
        &REGS_WORDS,
    );
    let child = start_wait_child(
        ctx,
        ep,
        syscall_abi::RIGHTS_EP_RECEIVE,
        done,
        0,
        WAIT_SLOT_REGS_SERVER,
        regs_server_entry,
    )?;
    let bound = u32::try_from(crate::scaled_bound(WAIT_REPORT_MS)).unwrap_or(u32::MAX);
    let reply = syscall::raw_ipc_call_timeout(
        ep,
        REGS_CALL_LABEL,
        syscall_abi::MSG_REGS_DATA_MAX,
        0,
        bound,
        &REGS_WORDS,
    );
    Ok((long_call, long_reply, reply, child))
}

/// Child server with no IPC buffer: receives one call, replies with its
/// words inverted, and reports [`REGS_OK`] if the call carried
/// [`REGS_WORDS`] in registers, [`WAIT_BAD`] otherwise.
extern "C" fn regs_server_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let args: WaitArgs = unsafe { child_args(arg) };
    let Ok(call) = syscall::raw_ipc_recv_timeout(args.ep, crate::scaled_bound(WAIT_REPORT_MS))
    else
    {
        wait_child_fail(args)
    };
    let intact = call.label == REGS_CALL_LABEL
        && call.data_count == syscall_abi::MSG_REGS_DATA_MAX
        && call.cap_count == 0
        && call.regs == REGS_WORDS;
    let replied = syscall::raw_ipc_reply(
        REGS_REPLY_LABEL,
        syscall_abi::MSG_REGS_DATA_MAX,
        0,
        &reply_words(&REGS_WORDS),
    );
    let bits = if intact && replied.is_ok()
    {
        REGS_OK
    }
    else
    {
        WAIT_BAD
    };
    notification_send(args.done, bits).ok();
    thread_exit()
}

/// The data words arrive intact at `MSG_REGS_DATA_MAX` words, in registers,
/// and at one word more, in the buffer, as a call and as a reply; a message
/// in registers leaves the receiver's buffer data words as they were.
///
/// The child calls with 6 words and the harness replies with 7, then the
/// child calls with 7 and the harness replies with 6.
pub fn regs_and_buffer_delivery(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::regs_and_buffer_delivery: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::regs_and_buffer_delivery: cap_create_notification failed")?;
    let result = regs_and_buffer_delivery_on(ctx, ep, done);
    cap_delete(ep).ok();
    cap_delete(done).ok();
    result
}

fn regs_and_buffer_delivery_on(ctx: &TestContext, ep: u64, done: u64) -> TestResult
{
    let sentinels = [BUF_SENTINEL; syscall_abi::MSG_REGS_DATA_MAX + 1];
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer, and
    // `sentinels` is 7 words long.
    unsafe { buf_write(ctx.ipc_buf, &sentinels) };
    let mut child = start_wait_child(
        ctx,
        ep,
        RIGHTS_EP_SEND_GRANT,
        done,
        0,
        WAIT_SLOT_REGS_CALLER,
        regs_caller_entry,
    )?;
    let bound = crate::scaled_bound(WAIT_REPORT_MS);

    // Round 1: a 6-word call, answered with 7 words through the buffer.
    let first = syscall::raw_ipc_recv_timeout(ep, bound)
        .map_err(|_| "ipc::regs_and_buffer_delivery: no 6-word call arrived")?;
    // SAFETY: as above.
    let untouched = unsafe { buf_holds(ctx.ipc_buf, &sentinels) };
    let long_reply = reply_words(&BUF_WORDS);
    // SAFETY: as above; `long_reply` is 7 words long.
    unsafe { buf_write(ctx.ipc_buf, &long_reply) };
    syscall::raw_ipc_reply(
        REGS_REPLY_LABEL,
        long_reply.len(),
        0,
        &syscall::MsgRegs::default(),
    )
    .map_err(|_| "ipc::regs_and_buffer_delivery: the 7-word reply failed")?;
    if first.label != REGS_CALL_LABEL
        || first.data_count != syscall_abi::MSG_REGS_DATA_MAX
        || first.regs != REGS_WORDS
    {
        return Err("ipc::regs_and_buffer_delivery: the 6-word call arrived altered");
    }
    if !untouched
    {
        return Err("ipc::regs_and_buffer_delivery: a 6-word call wrote the receiver's buffer");
    }

    // Round 2: a 7-word call through the buffer, answered with 6 words.
    let second = syscall::raw_ipc_recv_timeout(ep, bound)
        .map_err(|_| "ipc::regs_and_buffer_delivery: no 7-word call arrived")?;
    // SAFETY: as above.
    let delivered = unsafe { buf_holds(ctx.ipc_buf, &BUF_WORDS) };
    syscall::raw_ipc_reply(
        REGS_REPLY_LABEL,
        syscall_abi::MSG_REGS_DATA_MAX,
        0,
        &reply_words(&REGS_WORDS),
    )
    .map_err(|_| "ipc::regs_and_buffer_delivery: the 6-word reply failed")?;
    if second.label != REGS_CALL_LABEL || second.data_count != BUF_WORDS.len() || !delivered
    {
        return Err("ipc::regs_and_buffer_delivery: the 7-word call arrived altered");
    }

    match wait_report(done)?
    {
        REGS_OK => (),
        WAIT_BAD => return Err("ipc::regs_and_buffer_delivery: a reply arrived altered"),
        _ => return Err("ipc::regs_and_buffer_delivery: a 6-word reply wrote the caller's buffer"),
    }
    child.delete_thread().ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Report bits of [`regs_caller_entry`] when the 6-word reply wrote its
/// buffer's data words.
const REGS_BUF_WRITTEN: u64 = 0xB0F;

/// Child for [`regs_and_buffer_delivery`]: calls with [`REGS_WORDS`] in
/// registers, expects [`BUF_WORDS`] inverted in its buffer, calls with
/// [`BUF_WORDS`] in its buffer, expects [`REGS_WORDS`] inverted in registers
/// and its buffer unchanged, and reports [`REGS_OK`], [`REGS_BUF_WRITTEN`] or
/// [`WAIT_BAD`].
extern "C" fn regs_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let args: WaitArgs = unsafe { child_args(arg) };
    // SAFETY: `args.page` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child reaches it
    // only through the raw address.
    if unsafe { syscall::ipc_buffer_set(args.page) }.is_err()
    {
        wait_child_fail(args)
    }
    let buf = args.page as *mut u64;

    let Ok(first) = syscall::raw_ipc_call(
        args.ep,
        REGS_CALL_LABEL,
        syscall_abi::MSG_REGS_DATA_MAX,
        0,
        &REGS_WORDS,
    )
    else
    {
        wait_child_fail(args)
    };
    // SAFETY: buf is this thread's registered IPC buffer; the slices are 7
    // words long.
    let first_ok = first.label == REGS_REPLY_LABEL
        && first.data_count == BUF_WORDS.len()
        && unsafe { buf_holds(buf, &reply_words(&BUF_WORDS)) };

    // SAFETY: as above.
    unsafe { buf_write(buf, &BUF_WORDS) };
    let Ok(second) = syscall::raw_ipc_call(
        args.ep,
        REGS_CALL_LABEL,
        BUF_WORDS.len(),
        0,
        &syscall::MsgRegs::default(),
    )
    else
    {
        wait_child_fail(args)
    };
    let second_ok = second.label == REGS_REPLY_LABEL
        && second.data_count == syscall_abi::MSG_REGS_DATA_MAX
        && second.regs == reply_words(&REGS_WORDS);
    // SAFETY: as above.
    let untouched = unsafe { buf_holds(buf, &BUF_WORDS) };

    let bits = match (first_ok && second_ok, untouched)
    {
        (true, true) => REGS_OK,
        (true, false) => REGS_BUF_WRITTEN,
        (false, _) => WAIT_BAD,
    };
    notification_send(args.done, bits).ok();
    thread_exit()
}

/// Unmapped VA the fault-message child stores to; no test maps it.
const FAULT_MSG_VA: u64 = 0x3E_A100_0000;
/// Badge of the endpoint cap bound as the fault-message child's handler.
const FAULT_MSG_BADGE: u64 = 0xFA17_0040;
static mut FAULT_MSG_STACK: ChildStack = ChildStack::ZERO;

/// A kernel-made fault message (4 data words) reaches a handler intact in
/// the message registers, with no IPC buffer registered on the handler.
pub fn fault_message_in_registers(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::fault_message_in_registers: cap_create_endpoint failed")?;
    let result = fault_message_in_registers_on(ctx, ep);
    cap_delete(ep).ok();
    result
}

fn fault_message_in_registers_on(ctx: &TestContext, ep: u64) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::fault_message_in_registers: spawn::new_child failed")?;
    crate::bind_fault_handler(child.th, ep, FAULT_MSG_BADGE)
        .map_err(|_| "ipc::fault_message_in_registers: bind_fault_handler failed")?;
    // SAFETY: `FAULT_MSG_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(FAULT_MSG_STACK)) };
    // SAFETY: the stack is `FAULT_MSG_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, fault_msg_entry, stack_top, 0) }
        .map_err(|_| "ipc::fault_message_in_registers: configure_and_start failed")?;

    // SAFETY: deregistering (0) dedicates no page.
    unsafe { ipc_buffer_set(0) }
        .map_err(|_| "ipc::fault_message_in_registers: ipc_buffer_set(0) failed")?;
    let fault = syscall::raw_ipc_recv_timeout(ep, crate::scaled_bound(WAIT_REPORT_MS));
    let killed = fault.as_ref().map_or(Ok(()), |_| {
        syscall::raw_ipc_reply(
            syscall_abi::FAULT_REPLY_KILL,
            0,
            0,
            &syscall::MsgRegs::default(),
        )
    });
    // SAFETY: ctx.ipc_buf is the page ktest registered at startup, dedicated
    // to the kernel's IPC access under the contract it was first registered
    // with; re-registering it restores that state.
    unsafe { ipc_buffer_set(ctx.ipc_buf as u64) }
        .map_err(|_| "ipc::fault_message_in_registers: re-registering the IPC buffer failed")?;

    let fault =
        fault.map_err(|_| "ipc::fault_message_in_registers: no fault message within the bound")?;
    killed.map_err(|_| "ipc::fault_message_in_registers: the KILL reply failed")?;
    if fault.label != syscall_abi::FAULT_LABEL || fault.badge != FAULT_MSG_BADGE
    {
        return Err("ipc::fault_message_in_registers: the message is not the child's fault");
    }
    if fault.data_count != 4 || fault.cap_count != 0
    {
        return Err("ipc::fault_message_in_registers: the fault message has the wrong counts");
    }
    let [kind, va, access, ip, ..] = fault.regs;
    if kind != syscall_abi::FAULT_KIND_VM
        || va != FAULT_MSG_VA
        || access & syscall_abi::FAULT_ACCESS_WRITE == 0
        || ip == 0
    {
        return Err("ipc::fault_message_in_registers: the fault message's words arrived altered");
    }
    child.delete_thread().ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Child for [`fault_message_in_registers`]: stores to [`FAULT_MSG_VA`],
/// which faults; the handler's reply kills it.
extern "C" fn fault_msg_entry(_arg: u64) -> !
{
    // SAFETY: FAULT_MSG_VA is unmapped, so the store faults to the bound
    // handler, which kills this thread; it never completes.
    unsafe { (FAULT_MSG_VA as *mut u64).write_volatile(1) };
    loop
    {
        core::hint::spin_loop();
    }
}

// ── SYS_IPC_REPLY_RECV and the words past a message's count ─────────────────

/// Stack, IPC page and arguments of [`words_past_count_caller_entry`].
static mut PAST_COUNT_STACK: ChildStack = ChildStack::ZERO;
static mut PAST_COUNT_CALLER_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;
static PAST_COUNT_ARGS: ArgBlock<EpDoneArgs, 1> = ep_done_block();

/// Label of each call of [`words_past_count_caller_entry`], and of the reply
/// to it.
const PAST_CALL_REGS: u64 = 0x9A51;
const PAST_CALL_BUF: u64 = 0x9A52;
const PAST_CALL_PLAIN_REGS: u64 = 0x9A53;
const PAST_CALL_PLAIN_BUF: u64 = 0x9A54;

/// Fillers that tell a word's writer: the caller's and the server's words
/// past a message's count, and each side's own sentinel, which only its own
/// thread writes.
const CALLER_JUNK: u64 = 0xC0DE_0000_0000_0000;
const SERVER_JUNK: u64 = 0x5E7E_0000_0000_0000;
const CALLER_SENTINEL: u64 = 0xCA11_5E47_0000_0000;
const SERVER_SENTINEL: u64 = 0x5E4F_5E47_0000_0000;

/// Data words of a message that travels in the IPC buffer: one past what the
/// message registers carry.
const PAST_BUF_WORDS: usize = syscall_abi::MSG_REGS_DATA_MAX + 1;

/// `base` tagged with its word index `i`, so a word moved to another index
/// is caught too.
const fn tagged(base: u64, i: usize) -> u64
{
    base | i as u64
}

/// Write `value(i)` to data words `range` of the IPC buffer at `buf`.
fn fill_words(buf: *mut u64, range: core::ops::Range<usize>, value: impl Fn(usize) -> u64)
{
    for i in range.filter(|&i| i < syscall_abi::MSG_DATA_WORDS_MAX)
    {
        // SAFETY: i < MSG_DATA_WORDS_MAX, within the 4 KiB page at `buf`.
        let slot = unsafe { buf.add(i) };
        // SAFETY: `slot` is a word of this thread's registered IPC buffer,
        // which no Rust reference covers.
        unsafe { core::ptr::write_volatile(slot, value(i)) };
    }
}

/// Whether data words `range` of the IPC buffer at `buf` hold `value(i)`.
fn words_hold(buf: *mut u64, range: core::ops::Range<usize>, value: impl Fn(usize) -> u64) -> bool
{
    range
        .filter(|&i| i < syscall_abi::MSG_DATA_WORDS_MAX)
        .all(|i| {
            // SAFETY: as for `fill_words`.
            let slot = unsafe { buf.add(i) };
            // SAFETY: as for `fill_words`.
            unsafe { core::ptr::read_volatile(slot) == value(i) }
        })
}

/// The message registers `words` followed by `filler`'s tagged words.
fn regs_of(words: &[u64], filler: u64) -> syscall::MsgRegs
{
    core::array::from_fn(|i| words.get(i).copied().unwrap_or(tagged(filler, i)))
}

/// Words past a message's data count never reach its recipient, in either
/// direction, on the `SYS_IPC_REPLY_RECV` path as on `SYS_IPC_CALL`,
/// `SYS_IPC_RECV` and `SYS_IPC_REPLY` (core/kernel/docs/syscalls.md § Calling
/// Convention): a message of at most `MSG_REGS_DATA_MAX` words leaves the
/// recipient's registers past its count as they were and its IPC buffer
/// untouched, and a longer one leaves the buffer's words past its count as
/// they were.
///
/// Each side fills the words past its message's count with its own junk and
/// its receiving buffer with its own sentinel. The harness serves: a plain
/// receive takes a two-word call, a reply-and-receive answers it with two
/// words and takes a buffer call of seven, a second answers that with seven
/// buffer words and takes a three-word call, a plain reply answers that with
/// one word, and a plain receive and reply serve a last buffer call. Every
/// delivery is checked on both sides: the delivered count, its words, the
/// registers past them, and the buffer words past them. A last try-once
/// reply-and-receive finds no caller and reports `WouldBlock` after its reply,
/// which the caller's report confirms.
pub fn words_past_count_never_reach_recipient(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::words_past_count: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "ipc::words_past_count: cap_create_notification failed")?;
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "ipc::words_past_count: spawn::new_child failed")?;
    let result = past_count_rounds(ctx, ep, done, &child);
    child.delete_thread().ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();
    child.delete_cspace().ok();
    result
}

/// The harness's side of [`words_past_count_never_reach_recipient`].
fn past_count_rounds(
    ctx: &TestContext,
    ep: u64,
    done: u64,
    child: &crate::spawn::SpawnedChild,
) -> TestResult
{
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "ipc::words_past_count: cap_copy ep failed")?;
    let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
        .map_err(|_| "ipc::words_past_count: cap_copy done failed")?;
    // SAFETY: the single child has not been started yet.
    let child_arg = unsafe {
        PAST_COUNT_ARGS.publish(
            0,
            EpDoneArgs {
                ep: child_ep,
                done: child_done,
            },
        )
    };
    // SAFETY: `PAST_COUNT_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(PAST_COUNT_STACK)) };
    // SAFETY: the stack is `PAST_COUNT_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe {
        crate::spawn::configure_and_start(
            child,
            words_past_count_caller_entry,
            stack_top,
            child_arg,
        )
    }
    .map_err(|_| "ipc::words_past_count: configure_and_start failed")?;

    serve_by_reply_recv(ctx.ipc_buf, ep)?;
    serve_plainly(ctx.ipc_buf, ep)?;
    match notification_wait(done)
    {
        Ok(0xDEAD) => Ok(()),
        Ok(_) => Err("ipc::words_past_count: the caller saw words past a reply's count"),
        Err(_) => Err("ipc::words_past_count: notification_wait failed"),
    }
}

/// The first three deliveries of [`past_count_rounds`], through the IPC
/// buffer `buf`: a plain receive of a two-word call, then two
/// reply-and-receives.
fn serve_by_reply_recv(buf: *mut u64, ep: u64) -> TestResult
{
    let all = 0..syscall_abi::MSG_DATA_WORDS_MAX;
    let sentinel = |i| tagged(SERVER_SENTINEL, i);

    // A two-word call by a plain receive: the buffer stays the server's.
    fill_words(buf, all.clone(), sentinel);
    let got = syscall::raw_ipc_recv(ep).map_err(|_| "ipc::words_past_count: recv failed")?;
    if got.label != PAST_CALL_REGS || got.data_count != 2 || got.regs[..2] != [1, 2]
    {
        return Err("ipc::words_past_count: plain recv delivered a wrong two-word message");
    }
    if !words_hold(buf, all.clone(), sentinel)
    {
        return Err("ipc::words_past_count: a two-word receive wrote the IPC buffer");
    }

    // Reply with two words and receive a seven-word buffer call: the
    // registers stay as they went in, and the buffer past the count stays.
    let reply_regs = regs_of(&[0x11, 0x12], SERVER_JUNK);
    let got = syscall::raw_ipc_reply_recv(ep, PAST_CALL_REGS, 2, 0, 0, &reply_regs)
        .map_err(|_| "ipc::words_past_count: first reply_recv failed")?;
    if got.label != PAST_CALL_BUF || got.data_count != PAST_BUF_WORDS
    {
        return Err("ipc::words_past_count: reply_recv delivered a wrong buffer message");
    }
    if !words_hold(buf, 0..PAST_BUF_WORDS, |i| tagged(0x20, i))
    {
        return Err("ipc::words_past_count: reply_recv delivered wrong buffer words");
    }
    if !words_hold(
        buf,
        PAST_BUF_WORDS..syscall_abi::MSG_DATA_WORDS_MAX,
        sentinel,
    )
    {
        return Err("ipc::words_past_count: reply_recv wrote buffer words past the count");
    }
    if got.regs != reply_regs
    {
        return Err("ipc::words_past_count: a buffer delivery rewrote the message registers");
    }

    // Reply with seven buffer words, junk past them, and receive a
    // three-word call: its registers past the count stay the reply's, and
    // the buffer stays as the reply left it.
    fill_words(buf, 0..PAST_BUF_WORDS, |i| tagged(0x30, i));
    fill_words(buf, PAST_BUF_WORDS..syscall_abi::MSG_DATA_WORDS_MAX, |i| {
        tagged(SERVER_JUNK, i)
    });
    let junk_regs = regs_of(&[], SERVER_JUNK);
    let got = syscall::raw_ipc_reply_recv(ep, PAST_CALL_BUF, PAST_BUF_WORDS, 0, 0, &junk_regs)
        .map_err(|_| "ipc::words_past_count: second reply_recv failed")?;
    if got.label != PAST_CALL_PLAIN_REGS
        || got.data_count != 3
        || got.regs[..3] != [0x41, 0x42, 0x43]
    {
        return Err("ipc::words_past_count: reply_recv delivered a wrong register message");
    }
    if got.regs[3..] != junk_regs[3..]
    {
        return Err("ipc::words_past_count: reply_recv delivered registers past the count");
    }
    if !words_hold(buf, 0..PAST_BUF_WORDS, |i| tagged(0x30, i))
        || !words_hold(buf, PAST_BUF_WORDS..syscall_abi::MSG_DATA_WORDS_MAX, |i| {
            tagged(SERVER_JUNK, i)
        })
    {
        return Err("ipc::words_past_count: a register delivery wrote the IPC buffer");
    }
    Ok(())
}

/// The last delivery of [`past_count_rounds`], through the IPC buffer
/// `buf`: a plain reply, a plain receive of a buffer call, and the try-once
/// reply-and-receive that answers it.
fn serve_plainly(buf: *mut u64, ep: u64) -> TestResult
{
    let sentinel = |i| tagged(SERVER_SENTINEL, i);

    // A plain one-word reply, then a buffer call by a plain receive.
    syscall::raw_ipc_reply(PAST_CALL_PLAIN_REGS, 1, 0, &regs_of(&[0x51], SERVER_JUNK))
        .map_err(|_| "ipc::words_past_count: plain reply failed")?;
    fill_words(buf, 0..syscall_abi::MSG_DATA_WORDS_MAX, sentinel);
    let got = syscall::raw_ipc_recv(ep).map_err(|_| "ipc::words_past_count: last recv failed")?;
    if got.label != PAST_CALL_PLAIN_BUF
        || got.data_count != PAST_BUF_WORDS
        || !words_hold(buf, 0..PAST_BUF_WORDS, |i| tagged(0x60, i))
    {
        return Err("ipc::words_past_count: plain recv delivered a wrong buffer message");
    }
    if !words_hold(
        buf,
        PAST_BUF_WORDS..syscall_abi::MSG_DATA_WORDS_MAX,
        sentinel,
    )
    {
        return Err("ipc::words_past_count: plain recv wrote buffer words past the count");
    }

    // The last reply, by a try-once reply-and-receive that finds no caller:
    // the reply is made, then the receive reports WouldBlock.
    let try_once = syscall::raw_ipc_reply_recv(
        ep,
        PAST_CALL_PLAIN_BUF,
        0,
        0,
        syscall::WAIT_TRY_ONCE,
        &regs_of(&[], SERVER_JUNK),
    );
    if try_once.err() != Some(syscall_abi::SyscallError::WouldBlock as i64)
    {
        return Err(
            "ipc::words_past_count: an empty try-once reply_recv did not report WouldBlock",
        );
    }
    Ok(())
}

/// The caller of [`words_past_count_never_reach_recipient`]: four calls, each
/// with its own junk past the count, checking each reply's words, the
/// registers past them and its buffer; reports `0xDEAD` when every check
/// holds and `0xBAD` otherwise.
extern "C" fn words_past_count_caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the test published for this child.
    let EpDoneArgs { ep, done } = unsafe { child_args(arg) };
    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(PAST_COUNT_CALLER_IPC_PAGE));
    // SAFETY: `PAST_COUNT_CALLER_IPC_PAGE` is this child's own IPC page, used by
    // one thread at a time (`IpcPage`'s rule); no Rust object lives in it, and
    // the child reaches it only through the raw `buf` pointer.
    let ok = unsafe { syscall::ipc_buffer_set(buf_addr) }.is_ok()
        && past_count_calls(ep, buf_addr as *mut u64);
    notification_send(done, if ok { 0xDEAD } else { 0xBAD }).ok();
    thread_exit()
}

/// The calls of [`words_past_count_caller_entry`] through its IPC buffer
/// `buf`; whether every check held.
fn past_count_calls(ep: u64, buf: *mut u64) -> bool
{
    let all = 0..syscall_abi::MSG_DATA_WORDS_MAX;
    let past = PAST_BUF_WORDS..syscall_abi::MSG_DATA_WORDS_MAX;
    let sentinel = |i| tagged(CALLER_SENTINEL, i);
    let junk = |i| tagged(CALLER_JUNK, i);

    // Two register words out, two back by reply_recv.
    fill_words(buf, all.clone(), sentinel);
    let regs = regs_of(&[1, 2], CALLER_JUNK);
    let Ok(got) = syscall::raw_ipc_call(ep, PAST_CALL_REGS, 2, 0, &regs)
    else
    {
        return false;
    };
    if got.data_count != 2
        || got.regs[..2] != [0x11, 0x12]
        || got.regs[2..] != regs[2..]
        || !words_hold(buf, all.clone(), sentinel)
    {
        return false;
    }

    // Seven buffer words out, seven back by reply_recv.
    fill_words(buf, 0..PAST_BUF_WORDS, |i| tagged(0x20, i));
    fill_words(buf, past.clone(), junk);
    let Ok(got) = syscall::raw_ipc_call(
        ep,
        PAST_CALL_BUF,
        PAST_BUF_WORDS,
        0,
        &regs_of(&[], CALLER_JUNK),
    )
    else
    {
        return false;
    };
    if got.data_count != PAST_BUF_WORDS
        || !words_hold(buf, 0..PAST_BUF_WORDS, |i| tagged(0x30, i))
        || !words_hold(buf, past.clone(), junk)
    {
        return false;
    }

    // Three register words out, one back by a plain reply.
    fill_words(buf, all.clone(), sentinel);
    let regs = regs_of(&[0x41, 0x42, 0x43], CALLER_JUNK);
    let Ok(got) = syscall::raw_ipc_call(ep, PAST_CALL_PLAIN_REGS, 3, 0, &regs)
    else
    {
        return false;
    };
    if got.data_count != 1
        || got.regs[0] != 0x51
        || got.regs[1..] != regs[1..]
        || !words_hold(buf, all, sentinel)
    {
        return false;
    }

    // Seven buffer words out to a plain receive, none back by the try-once
    // reply_recv.
    fill_words(buf, 0..PAST_BUF_WORDS, |i| tagged(0x60, i));
    fill_words(buf, past.clone(), junk);
    let regs = regs_of(&[], CALLER_JUNK);
    let Ok(got) = syscall::raw_ipc_call(ep, PAST_CALL_PLAIN_BUF, PAST_BUF_WORDS, 0, &regs)
    else
    {
        return false;
    };
    got.label == PAST_CALL_PLAIN_BUF
        && got.data_count == 0
        && got.regs == regs
        && words_hold(buf, 0..PAST_BUF_WORDS, |i| tagged(0x60, i))
        && words_hold(buf, past, junk)
}

/// A reply-and-receive on an endpoint cap without the Receive right is
/// refused with `InsufficientRights`, and one with no pending reply with
/// `InvalidCapability` before it receives: a try-once receive that ran would
/// report `WouldBlock` instead (core/kernel/docs/syscalls.md
/// § `SYS_IPC_REPLY_RECV`).
pub fn reply_recv_without_pending_reply_refused(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "ipc::reply_recv_refused: cap_create_endpoint failed")?;
    let result = reply_recv_refusals(ep);
    cap_delete(ep).ok();
    result
}

/// The checks of [`reply_recv_without_pending_reply_refused`] on `ep`.
fn reply_recv_refusals(ep: u64) -> TestResult
{
    let regs = regs_of(&[], SERVER_JUNK);
    let send_only = cap_derive(ep, syscall_abi::RIGHTS_EP_SEND)
        .map_err(|_| "ipc::reply_recv_refused: cap_derive failed")?;
    let rights = syscall::raw_ipc_reply_recv(send_only, 0, 0, 0, syscall::WAIT_TRY_ONCE, &regs);
    cap_delete(send_only).ok();
    if rights.err() != Some(syscall_abi::SyscallError::InsufficientRights as i64)
    {
        return Err("ipc::reply_recv_refused: a send-only endpoint cap was not refused");
    }
    let unbound = syscall::raw_ipc_reply_recv(ep, 0, 0, 0, syscall::WAIT_TRY_ONCE, &regs);
    if unbound.err() != Some(syscall_abi::SyscallError::InvalidCapability as i64)
    {
        return Err("ipc::reply_recv_refused: a reply_recv with no pending reply was not refused");
    }
    Ok(())
}
