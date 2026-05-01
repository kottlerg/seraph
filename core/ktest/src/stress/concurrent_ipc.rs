// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: concurrent IPC endpoint races.
//!
//! 4 callers simultaneously block on one endpoint. The server drains all 4,
//! verifying no callers are lost. Repeats for 10 cycles.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_cspace, cap_create_endpoint, cap_create_signal, cap_create_thread,
    cap_delete, signal_send, signal_wait, thread_configure, thread_exit, thread_start,
};

use crate::{ChildStack, TestContext, TestResult};

const NUM_CALLERS: usize = 16;
const CYCLES: usize = 50;

// SEND + GRANT rights.
const RIGHTS_SEND_GRANT: u64 = (1 << 4) | (1 << 6);

pub fn run(ctx: &TestContext) -> TestResult
{
    for _cycle in 0..CYCLES
    {
        let ep = cap_create_endpoint(ctx.memory_frame_base)
            .map_err(|_| "concurrent_ipc: create_endpoint failed")?;
        let done = cap_create_signal(ctx.memory_frame_base)
            .map_err(|_| "concurrent_ipc: create_signal failed")?;

        let mut threads = [0u32; NUM_CALLERS];
        let mut cspaces = [0u32; NUM_CALLERS];

        // Start all callers simultaneously (no yields between starts).
        for i in 0..NUM_CALLERS
        {
            let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
                .map_err(|_| "concurrent_ipc: create_cspace failed")?;
            let child_ep = cap_copy(ep, cs, RIGHTS_SEND_GRANT)
                .map_err(|_| "concurrent_ipc: cap_copy ep failed")?;
            let child_done =
                cap_copy(done, cs, 1 << 7).map_err(|_| "concurrent_ipc: cap_copy done failed")?;

            let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
                .map_err(|_| "concurrent_ipc: create_thread failed")?;

            // Pack: label = i+1 (1-based), done_bit = 1<<i (unique per child).
            let arg = u64::from(child_ep)
                | (u64::from(child_done) << 16)
                | (((i + 1) as u64) << 32)
                | ((1u64 << i) << 48);

            // SAFETY: Each caller uses a distinct stack index.
            let stack_top =
                ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
            thread_configure(th, caller_entry as *const () as u64, stack_top, arg)
                .map_err(|_| "concurrent_ipc: thread_configure failed")?;
            thread_start(th).map_err(|_| "concurrent_ipc: thread_start failed")?;

            threads[i] = th;
            cspaces[i] = cs;
        }

        // Server: receive and reply to all callers.
        let mut received_bitmap: u32 = 0;
        let reply = IpcMessage::new(0);
        for _ in 0..NUM_CALLERS
        {
            // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
            let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
                .map_err(|_| "concurrent_ipc: ipc_recv failed")?;
            // Label values are 1..=NUM_CALLERS; fits in u32. Truncation is safe
            // because we validate idx is in [1, NUM_CALLERS] immediately below.
            #[allow(clippy::cast_possible_truncation)]
            let idx = msg.label as u32;
            if idx == 0 || idx as usize > NUM_CALLERS
            {
                return Err("concurrent_ipc: received out-of-range label");
            }
            let bit = 1u32 << (idx - 1);
            if received_bitmap & bit != 0
            {
                return Err("concurrent_ipc: duplicate label received");
            }
            received_bitmap |= bit;
            // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
            unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
                .map_err(|_| "concurrent_ipc: ipc_reply failed")?;
        }

        // Verify all callers received.
        let expected = (1u32 << NUM_CALLERS) - 1;
        if received_bitmap != expected
        {
            return Err("concurrent_ipc: not all callers received");
        }

        // Wait for all children to signal done. Each child sends a unique
        // bit (1<<i), so we wait until all 4 bits are set.
        let all_done = (1u64 << NUM_CALLERS) - 1;
        let mut done_bits: u64 = 0;
        while done_bits != all_done
        {
            let bits = signal_wait(done).map_err(|_| "concurrent_ipc: signal_wait done failed")?;
            done_bits |= bits;
        }

        // Clean up.
        for i in 0..NUM_CALLERS
        {
            cap_delete(threads[i]).ok();
            cap_delete(cspaces[i]).ok();
        }
        cap_delete(ep).ok();
        cap_delete(done).ok();
    }

    Ok(())
}

// cast_possible_truncation: slot indices are kernel cap slots < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn caller_entry(arg: u64) -> !
{
    let ep_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let label = (arg >> 32) & 0xFFFF;
    let done_bit = arg >> 48;

    // Register the shared IPC buffer for this child thread.
    let buf_addr = core::ptr::addr_of_mut!(crate::IPC_BUF) as u64;
    if syscall::ipc_buffer_set(buf_addr).is_err()
    {
        signal_send(done_slot, done_bit).ok();
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(label), buf_addr as *mut u64) };
    signal_send(done_slot, done_bit).ok();
    thread_exit()
}
