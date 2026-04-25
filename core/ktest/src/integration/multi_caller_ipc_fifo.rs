// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/multi_caller_ipc_fifo.rs

//! Integration: endpoint send-queue FIFO ordering with three concurrent callers.
//!
//! Verifies that `ipc_recv` dequeues blocked callers in the order they arrived
//! on the send queue (FIFO), not priority order or any other order.
//!
//! ## Approach
//!
//! Start callers A (label=1), B (label=2), C (label=3) one at a time, yielding
//! the CPU between each start. Each caller's entry point immediately calls
//! `ipc_call`, so after one yield it is blocked on the send queue.  The server
//! then calls `ipc_recv` three times and verifies the label sequence 1 → 2 → 3.
//!
//! Each caller ORs a distinct bit into the shared `done` signal after receiving
//! its reply; the server waits for all three bits before returning.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_signal, cap_create_thread,
    cap_delete, signal_send, signal_wait, thread_configure, thread_exit, thread_set_affinity,
    thread_start, thread_yield,
};

use crate::{ChildStack, TestContext, TestResult};

// SEND | GRANT rights (bits 4 and 6).
const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);

// One stack per caller to avoid aliasing.
static mut STACK_A: ChildStack = ChildStack::ZERO;
static mut STACK_B: ChildStack = ChildStack::ZERO;
static mut STACK_C: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("multi_caller_ipc_fifo: starting");

    let ep =
        cap_create_endpoint().map_err(|_| "multi_caller_ipc_fifo: cap_create_endpoint failed")?;
    let done =
        cap_create_signal().map_err(|_| "multi_caller_ipc_fifo: cap_create_signal failed")?;

    // ── Build and start caller A ──────────────────────────────────────────────
    let cs_a = cap_create_cspace(16).map_err(|_| "multi_caller_ipc_fifo: cs_a failed")?;
    let ep_a =
        cap_copy(ep, cs_a, RIGHTS_SEND_GRANT).map_err(|_| "multi_caller_ipc_fifo: ep_a failed")?;
    let done_a =
        cap_copy(done, cs_a, 1 << 7).map_err(|_| "multi_caller_ipc_fifo: done_a failed")?;
    // arg: ep_slot | (done_slot << 16) | (label << 32)
    let arg_a = u64::from(ep_a) | (u64::from(done_a) << 16) | (1u64 << 32);
    let th_a = cap_create_thread(ctx.aspace_cap, cs_a)
        .map_err(|_| "multi_caller_ipc_fifo: th_a failed")?;
    let stack_a = ChildStack::top(core::ptr::addr_of!(STACK_A));
    thread_configure(th_a, caller_entry as *const () as u64, stack_a, arg_a)
        .map_err(|_| "multi_caller_ipc_fifo: configure th_a failed")?;
    // Pin to CPU 0 so yield-based FIFO ordering is reliable under SMP.
    thread_set_affinity(th_a, 0).map_err(|_| "multi_caller_ipc_fifo: set_affinity th_a failed")?;
    thread_start(th_a).map_err(|_| "multi_caller_ipc_fifo: start th_a failed")?;
    // Yield so A runs and blocks on ipc_call before B is started.
    thread_yield().map_err(|_| "multi_caller_ipc_fifo: yield after A failed")?;

    // ── Build and start caller B ──────────────────────────────────────────────
    let cs_b = cap_create_cspace(16).map_err(|_| "multi_caller_ipc_fifo: cs_b failed")?;
    let ep_b =
        cap_copy(ep, cs_b, RIGHTS_SEND_GRANT).map_err(|_| "multi_caller_ipc_fifo: ep_b failed")?;
    let done_b =
        cap_copy(done, cs_b, 1 << 7).map_err(|_| "multi_caller_ipc_fifo: done_b failed")?;
    let arg_b = u64::from(ep_b) | (u64::from(done_b) << 16) | (2u64 << 32);
    let th_b = cap_create_thread(ctx.aspace_cap, cs_b)
        .map_err(|_| "multi_caller_ipc_fifo: th_b failed")?;
    let stack_b = ChildStack::top(core::ptr::addr_of!(STACK_B));
    thread_configure(th_b, caller_entry as *const () as u64, stack_b, arg_b)
        .map_err(|_| "multi_caller_ipc_fifo: configure th_b failed")?;
    // Pin to CPU 0 so yield-based FIFO ordering is reliable under SMP.
    thread_set_affinity(th_b, 0).map_err(|_| "multi_caller_ipc_fifo: set_affinity th_b failed")?;
    thread_start(th_b).map_err(|_| "multi_caller_ipc_fifo: start th_b failed")?;
    thread_yield().map_err(|_| "multi_caller_ipc_fifo: yield after B failed")?;

    // ── Build and start caller C ──────────────────────────────────────────────
    let cs_c = cap_create_cspace(16).map_err(|_| "multi_caller_ipc_fifo: cs_c failed")?;
    let ep_c =
        cap_copy(ep, cs_c, RIGHTS_SEND_GRANT).map_err(|_| "multi_caller_ipc_fifo: ep_c failed")?;
    let done_c =
        cap_copy(done, cs_c, 1 << 7).map_err(|_| "multi_caller_ipc_fifo: done_c failed")?;
    let arg_c = u64::from(ep_c) | (u64::from(done_c) << 16) | (3u64 << 32);
    let th_c = cap_create_thread(ctx.aspace_cap, cs_c)
        .map_err(|_| "multi_caller_ipc_fifo: th_c failed")?;
    let stack_c = ChildStack::top(core::ptr::addr_of!(STACK_C));
    thread_configure(th_c, caller_entry as *const () as u64, stack_c, arg_c)
        .map_err(|_| "multi_caller_ipc_fifo: configure th_c failed")?;
    // Pin to CPU 0 so yield-based FIFO ordering is reliable under SMP.
    thread_set_affinity(th_c, 0).map_err(|_| "multi_caller_ipc_fifo: set_affinity th_c failed")?;
    thread_start(th_c).map_err(|_| "multi_caller_ipc_fifo: start th_c failed")?;
    thread_yield().map_err(|_| "multi_caller_ipc_fifo: yield after C failed")?;

    // ── Drain send queue in FIFO order ────────────────────────────────────────
    let reply = IpcMessage::new(0);
    crate::log("multi_caller_ipc_fifo: recv 1 (expect label=1)");
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg_a = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "multi_caller_ipc_fifo: ipc_recv[0] failed")?;
    if msg_a.label != 1
    {
        return Err("FIFO violated: expected label 1 first");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
        .map_err(|_| "multi_caller_ipc_fifo: ipc_reply[0] failed")?;

    crate::log("multi_caller_ipc_fifo: recv 2 (expect label=2)");
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg_b = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "multi_caller_ipc_fifo: ipc_recv[1] failed")?;
    if msg_b.label != 2
    {
        return Err("FIFO violated: expected label 2 second");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
        .map_err(|_| "multi_caller_ipc_fifo: ipc_reply[1] failed")?;

    crate::log("multi_caller_ipc_fifo: recv 3 (expect label=3)");
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg_c = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "multi_caller_ipc_fifo: ipc_recv[2] failed")?;
    if msg_c.label != 3
    {
        return Err("FIFO violated: expected label 3 third");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
        .map_err(|_| "multi_caller_ipc_fifo: ipc_reply[2] failed")?;

    // Wait for all three callers to confirm they received their reply.
    //
    // signal_wait returns as soon as ANY bits are set, not necessarily all three.
    // Accumulate via repeated waits until all three bits (0x7) arrive.
    let mut all_done = 0u64;
    while all_done != 0x7
    {
        let bits =
            signal_wait(done).map_err(|_| "multi_caller_ipc_fifo: signal_wait done failed")?;
        all_done |= bits;
    }

    cap_delete(th_a).ok();
    cap_delete(cs_a).ok();
    cap_delete(th_b).ok();
    cap_delete(cs_b).ok();
    cap_delete(th_c).ok();
    cap_delete(cs_c).ok();
    cap_delete(ep).ok();
    cap_delete(done).ok();

    crate::log("multi_caller_ipc_fifo: PASS");
    Ok(())
}

// ── Child thread entry ────────────────────────────────────────────────────────

/// Caller entry: calls the endpoint immediately with its label, then ORs its
/// bit into the `done` signal when the reply arrives.
///
/// `arg`: bits[15:0] = `ep_slot`, bits[31:16] = `done_slot`, bits[47:32] = label
/// (all in the child's own `CSpace`).
fn caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let label = (arg >> 32) & 0xFFFF;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    if unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(label), buf_addr as *mut u64) }.is_ok()
    {
        // OR the bit for this caller's label (label 1→bit0, 2→bit1, 3→bit2).
        let bit = 1u64 << (label - 1);
        signal_send(done_slot, bit).ok();
    }
    /* else: no bit set — server detects the missing bit */
    thread_exit()
}
