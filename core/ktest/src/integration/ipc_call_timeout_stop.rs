// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/ipc_call_timeout_stop.rs

//! Integration: a client stopped while parked in a timed `ipc_call` and
//! restarted after its deadline returns `Interrupted`, and leaves no entry
//! behind.
//!
//! The client calls an endpoint with no receiver and a 200 ms timeout, and
//! parks on the send queue. The controller stops it, waits past the
//! deadline (an entry left on the sleep list would fire on a stopped thread),
//! and restarts it. The client itself asserts `Interrupted`, as the
//! unbounded call does in `ipc_call_interrupted_stop_start`. Afterwards a
//! try-once receive on the endpoint finds no queued caller.
//!
//! Needs no SMP: the child is unpinned, and on a single CPU it runs as a
//! timer-preempted peer. The call timeout, the sleep past it, and the report
//! bound go through `crate::scaled_bound`, so at a wide CPU count the stop
//! still lands inside the call's bound.

use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait_timeout, raw_ipc_call_timeout, raw_ipc_recv_timeout,
    thread_exit, thread_sleep, thread_start, thread_stop,
};
use syscall_abi::{RIGHTS_EP_SEND_GRANT, RIGHTS_NTF_NOTIFY, SyscallError, WAIT_TRY_ONCE};

use crate::{ChildStack, IpcPage, TestContext, TestResult, spawn};

/// `done` bits: client about to call / call returned `Interrupted` / any other result.
const BIT_READY: u64 = 1 << 0;
const BIT_OK: u64 = 1 << 1;
const BIT_BAD: u64 = 1 << 2;

/// The client's call timeout, before `crate::scaled_bound`.
const CALL_TIMEOUT_MS: u64 = 200;
/// Wall-clock settle after the READY signal so the client has, in practice,
/// reached its park before the stop lands.
const SETTLE_SLEEP_MS: u64 = 20;
/// Sleep while the client is stopped, past its call deadline, before
/// `crate::scaled_bound`.
const PAST_DEADLINE_MS: u64 = 400;
/// Bound on each wait for the client's report, before `crate::scaled_bound`.
const REPORT_MS: u64 = 5000;

static mut CLIENT_STACK: ChildStack = ChildStack::ZERO;
static mut CLIENT_IPC_PAGE: IpcPage = IpcPage::ZERO;

/// The client's arguments, handed to `client_entry` by address.
#[derive(Clone, Copy)]
struct ClientArgs
{
    ep: u64,
    done: u64,
    /// The call timeout, scaled.
    timeout_ms: u32,
}

static CLIENT_ARGS: spawn::ArgBlock<ClientArgs, 1> = spawn::ArgBlock::new(ClientArgs {
    ep: 0,
    done: 0,
    timeout_ms: 0,
});

pub fn run(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::ipc_call_timeout_stop: create ep failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::ipc_call_timeout_stop: create done failed")?;
    let mut client = spawn::new_child(ctx)
        .map_err(|_| "integration::ipc_call_timeout_stop: spawn client failed")?;
    let c_ep = cap_copy(ep, client.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "integration::ipc_call_timeout_stop: cap_copy ep failed")?;
    let c_done = cap_copy(done, client.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::ipc_call_timeout_stop: cap_copy done failed")?;
    // SAFETY: the single client has not been started yet.
    let arg = unsafe {
        CLIENT_ARGS.publish(
            0,
            ClientArgs {
                ep: c_ep,
                done: c_done,
                timeout_ms: u32::try_from(crate::scaled_bound(CALL_TIMEOUT_MS)).unwrap_or(u32::MAX),
            },
        )
    };
    let stack = ChildStack::top(core::ptr::addr_of!(CLIENT_STACK));
    // SAFETY: the stack is `CLIENT_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(&client, client_entry, stack, arg) }
        .map_err(|_| "integration::ipc_call_timeout_stop: start client failed")?;

    wait_for(done, BIT_READY)?;
    let _ = thread_sleep(SETTLE_SLEEP_MS);
    thread_stop(client.th).map_err(|_| "integration::ipc_call_timeout_stop: thread_stop failed")?;
    let _ = thread_sleep(crate::scaled_bound(PAST_DEADLINE_MS));
    thread_start(client.th)
        .map_err(|_| "integration::ipc_call_timeout_stop: thread_start failed")?;
    let acc = wait_for(done, BIT_OK | BIT_BAD)?;
    if acc & BIT_BAD != 0
    {
        return Err(
            "integration::ipc_call_timeout_stop: stopped timed call returned a \
             non-Interrupted result",
        );
    }

    if raw_ipc_recv_timeout(ep, WAIT_TRY_ONCE) != Err(SyscallError::WouldBlock as i64)
    {
        return Err("integration::ipc_call_timeout_stop: the cancelled caller is still queued");
    }

    client
        .delete_thread()
        .and(client.delete_cspace())
        .map_err(|_| "integration::ipc_call_timeout_stop: reap client failed")?;
    cap_delete(ep).map_err(|_| "integration::ipc_call_timeout_stop: del ep failed")?;
    cap_delete(done).map_err(|_| "integration::ipc_call_timeout_stop: del done failed")?;
    Ok(())
}

/// Collect `done` bits until any bit of `mask` is present; return all bits seen
/// by this call (earlier calls' bits are consumed).
fn wait_for(done: u64, mask: u64) -> Result<u64, &'static str>
{
    let mut acc = 0u64;
    while acc & mask == 0
    {
        let bits = notification_wait_timeout(done, crate::scaled_bound(REPORT_MS))
            .map_err(|_| "integration::ipc_call_timeout_stop: notification_wait failed")?;
        if bits == 0
        {
            return Err("integration::ipc_call_timeout_stop: no report within the bound");
        }
        acc |= bits;
    }
    Ok(acc)
}

/// Client: announce readiness, then `ipc_call` with a timeout and no
/// receiver; raise the OK bit iff the call returns `Interrupted`, the BAD
/// bit otherwise.
extern "C" fn client_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this client.
    let ClientArgs {
        ep,
        done,
        timeout_ms,
    } = unsafe { spawn::child_args(arg) };

    let buf = IpcPage::addr(core::ptr::addr_of_mut!(CLIENT_IPC_PAGE));
    // SAFETY: `CLIENT_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the thread reaches it
    // only through the raw `buf` address.
    if unsafe { ipc_buffer_set(buf) }.is_err()
    {
        thread_exit()
    }
    notification_send(done, BIT_READY).ok();
    let bit = match raw_ipc_call_timeout(ep, 0x7002, 0, 0, timeout_ms)
    {
        Err(e) if e == SyscallError::Interrupted as i64 => BIT_OK,
        _ => BIT_BAD,
    };
    notification_send(done, bit).ok();
    thread_exit()
}
