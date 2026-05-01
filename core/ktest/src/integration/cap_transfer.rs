// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/cap_transfer.rs

//! Integration: capability rights through an IPC endpoint round-trip.
//!
//! Verifies that the capability transfer machinery works end-to-end across a
//! synchronous IPC call. A child thread:
//!   1. Calls an endpoint, passing a signal cap in `cap_slots[0]`.
//!   2. Waits for the server (ktest) to reply.
//!   3. After the reply, verifies its original cap slot is now null (the kernel
//!      moved the cap to the server's `CSpace` on transfer).
//!   4. Signals the result back to the server via a separate sync signal.
//!
//! The server:
//!   1. Receives the call.
//!   2. Reads the transferred cap from the IPC buffer via `read_recv_caps`.
//!   3. Verifies the transferred cap is usable (`signal_send` works).
//!   4. Replies to the child.
//!   5. Waits for the child's post-transfer verification result.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_signal, cap_create_thread,
    cap_delete, signal_send, signal_wait, thread_configure, thread_exit, thread_start,
};

use crate::{ChildStack, TestContext, TestResult};

// SEND | GRANT rights (bits 4 and 6) for the endpoint copy in child's CSpace.
const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);
// SIGNAL right only (bit 7) for the test signal copy in child's CSpace.
const RIGHTS_SIGNAL: u64 = 1 << 7;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("cap_transfer: entering run");
    // Create the endpoint for the IPC call.
    let ep = cap_create_endpoint(ctx.memory_frame_base)
        .map_err(|_| "integration::cap_transfer: cap_create_endpoint failed")?;
    crate::log("cap_transfer: ep created");

    // test_sig is the cap the child will transfer to the server via IPC.
    let test_sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "integration::cap_transfer: cap_create_signal (test_sig) failed")?;
    crate::log("cap_transfer: test_sig created");

    // sync_sig is used by the child to report its post-reply verification result.
    let sync_sig = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "integration::cap_transfer: cap_create_signal (sync_sig) failed")?;
    crate::log("cap_transfer: sync_sig created");

    // Build the child's CSpace with three caps:
    //   child_ep       — SEND | GRANT copy of ep (needed to call and transfer caps)
    //   child_test_sig — SIGNAL-only copy of test_sig (the cap to transfer)
    //   child_sync_sig — SIGNAL-only copy of sync_sig (for reporting back)
    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 32)
        .map_err(|_| "integration::cap_transfer: cap_create_cspace failed")?;
    crate::log("cap_transfer: cspace created");

    let child_ep = cap_copy(ep, cs, RIGHTS_SEND_GRANT)
        .map_err(|_| "integration::cap_transfer: cap_copy ep failed")?;
    crate::log("cap_transfer: child_ep copied");
    let child_test_sig = cap_copy(test_sig, cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::cap_transfer: cap_copy test_sig failed")?;
    crate::log("cap_transfer: child_test_sig copied");
    let child_sync_sig = cap_copy(sync_sig, cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::cap_transfer: cap_copy sync_sig failed")?;
    crate::log("cap_transfer: child_sync_sig copied");

    // Pack three 16-bit slot indices into a single u64 argument.
    let child_arg =
        u64::from(child_ep) | (u64::from(child_test_sig) << 16) | (u64::from(child_sync_sig) << 32);

    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "integration::cap_transfer: cap_create_thread failed")?;
    crate::log("cap_transfer: child thread created");

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    thread_configure(th, child_entry as *const () as u64, stack_top, child_arg)
        .map_err(|_| "integration::cap_transfer: thread_configure failed")?;
    crate::log("cap_transfer: thread configured");
    thread_start(th).map_err(|_| "integration::cap_transfer: thread_start failed")?;
    crate::log("cap_transfer: thread started");

    // ── Server: receive the child's IPC call. ─────────────────────────────────
    crate::log("cap_transfer: server blocking on ipc_recv");
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::cap_transfer: ipc_recv failed")?;
    crate::log("cap_transfer: server ipc_recv returned");

    // Transferred cap slot indices live on the returned IpcMessage.
    let caps = msg.caps();
    crate::log_u64("cap_transfer: cap_count=", caps.len() as u64);
    if caps.len() != 1
    {
        return Err("integration::cap_transfer: expected exactly 1 transferred cap");
    }
    let recv_sig = caps[0];
    crate::log_u64("cap_transfer: recv_sig slot=", u64::from(recv_sig));

    // Verify the transferred cap is usable.
    crate::log("cap_transfer: calling signal_send on transferred cap");
    signal_send(recv_sig, 0x1)
        .map_err(|_| "integration::cap_transfer: signal_send on transferred cap failed")?;
    crate::log("cap_transfer: signal_send OK, calling ipc_reply");

    // Reply to the child (no caps, no data).
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }
        .map_err(|_| "integration::cap_transfer: ipc_reply failed")?;
    crate::log("cap_transfer: ipc_reply done, waiting for child sync");

    // Wait for the child to confirm its original cap slot is now null.
    let result = signal_wait(sync_sig)
        .map_err(|_| "integration::cap_transfer: signal_wait for sync failed")?;
    crate::log_u64("cap_transfer: child sync result=", result);
    if result != 0xDEAD
    {
        return Err(
            "integration::cap_transfer: child verification failed (original slot not null after transfer)",
        );
    }

    cap_delete(recv_sig).ok();
    cap_delete(th).ok();
    cap_delete(ep).ok();
    cap_delete(test_sig).ok();
    cap_delete(sync_sig).ok();
    cap_delete(cs).ok();
    Ok(())
}

// ── Child thread ──────────────────────────────────────────────────────────────

/// `arg` packs: bits[15:0] = `ep_slot`, bits[31:16] = `test_sig_slot`,
/// bits[47:32] = `sync_sig_slot` (all in the child's own `CSpace`).
fn child_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let test_sig_slot = ((arg >> 16) & 0xFFFF) as u32;
    let sync_sig_slot = ((arg >> 32) & 0xFFFF) as u32;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(sync_sig_slot, 0xBAD).ok();
        thread_exit()
    }

    // Call the endpoint, passing test_sig in cap_slots[0].
    // The kernel moves test_sig to the server's CSpace on transfer.
    let msg = IpcMessage::builder(0).cap(test_sig_slot).build();
    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_call(ep_slot, &msg, buf_addr as *mut u64) }.is_err()
    {
        signal_send(sync_sig_slot, 0xBAD).ok();
        thread_exit()
    }

    // After the reply, test_sig_slot must be null — the kernel moved it.
    let null_check = signal_send(test_sig_slot, 0x1);
    if null_check.is_err()
    {
        // Correct: original slot is null after the transfer.
        signal_send(sync_sig_slot, 0xDEAD).ok();
    }
    else
    {
        // Incorrect: original slot is still live (kernel did not clear it).
        signal_send(sync_sig_slot, 0xBAD).ok();
    }
    thread_exit()
}
