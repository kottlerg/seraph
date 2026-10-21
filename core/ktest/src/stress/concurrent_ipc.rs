// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/concurrent_ipc.rs

//! Stress test: concurrent IPC endpoint races.
//!
//! `NUM_CALLERS` callers simultaneously block on one endpoint. The server
//! drains all of them, verifying no caller is lost. Repeats for `CYCLES`
//! cycles. Exercises the endpoint send-queue spinlock under contention.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, thread_exit,
};
use syscall_abi::RIGHTS_EP_SEND_GRANT;

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CALLERS: usize = 64;
const CYCLES: usize = 200;

/// Per-caller arguments, handed to `caller_entry` by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u32,
    done: u32,
    /// 1-based caller label carried in the call.
    label: u64,
    /// The caller's index: its done bit and its IPC buffer page.
    bit_index: usize,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, NUM_CALLERS> = spawn::ArgBlock::new(CallerArgs {
    ep: 0,
    done: 0,
    label: 0,
    bit_index: 0,
});

/// An IPC buffer page for one child thread, apart from ktest's own `IPC_BUF`: a child's IPC
/// and its parent's run on different threads, each through its own registered page.
#[repr(C, align(4096))]
struct IpcBufPage([u64; 512]);

impl IpcBufPage
{
    const ZERO: Self = Self([0u64; 512]);
}

// SAFETY: page `i` is registered only by caller `i` of the running cycle, and each cycle reaps its
// callers before the next starts.
static mut CALLER_IPC_BUFS: [IpcBufPage; NUM_CALLERS] = [IpcBufPage::ZERO; NUM_CALLERS];

pub fn run(ctx: &TestContext) -> TestResult
{
    for _cycle in 0..CYCLES
    {
        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "concurrent_ipc: create_endpoint failed")?;
        let done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "concurrent_ipc: create_notification failed")?;

        let mut threads = [0u32; NUM_CALLERS];
        let mut cspaces = [0u32; NUM_CALLERS];

        // Start all callers simultaneously (no yields between starts).
        for i in 0..NUM_CALLERS
        {
            let child =
                spawn::new_child(ctx).map_err(|_| "concurrent_ipc: spawn::new_child failed")?;
            let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
                .map_err(|_| "concurrent_ipc: cap_copy ep failed")?;
            let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
                .map_err(|_| "concurrent_ipc: cap_copy done failed")?;

            // SAFETY: caller `i` of this cycle has not been started yet, and
            // the previous cycle's callers were all reaped before this cycle.
            let arg = unsafe {
                CALLER_ARGS.publish(
                    i,
                    CallerArgs {
                        ep: child_ep,
                        done: child_done,
                        label: (i + 1) as u64,
                        bit_index: i,
                    },
                )
            };

            // SAFETY: Each caller uses a distinct stack index.
            let stack_top =
                ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
            spawn::configure_and_start(&child, caller_entry, stack_top, arg)
                .map_err(|_| "concurrent_ipc: configure_and_start failed")?;

            threads[i] = child.th;
            cspaces[i] = child.cs;
        }

        // Server: receive and reply to all callers.
        let mut received_bitmap: u64 = 0;
        let reply = IpcMessage::new(0);
        for _ in 0..NUM_CALLERS
        {
            // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
            let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
                .map_err(|_| "concurrent_ipc: ipc_recv failed")?;
            let idx = msg.label;
            // cast_possible_truncation: idx is bounded by NUM_CALLERS which
            // fits in usize on every target ktest supports.
            #[allow(clippy::cast_possible_truncation)]
            let idx_us = idx as usize;
            if idx == 0 || idx_us > NUM_CALLERS
            {
                return Err("concurrent_ipc: received out-of-range label");
            }
            let bit = 1u64 << (idx - 1);
            if received_bitmap & bit != 0
            {
                return Err("concurrent_ipc: duplicate label received");
            }
            received_bitmap |= bit;
            // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
            unsafe { ipc::ipc_reply(&reply, ctx.ipc_buf) }
                .map_err(|_| "concurrent_ipc: ipc_reply failed")?;
        }

        // Verify all callers received. At NUM_CALLERS=64, this is the
        // full u64 (`u64::MAX`); for smaller values, mask appropriately.
        let expected: u64 = if NUM_CALLERS >= 64
        {
            u64::MAX
        }
        else
        {
            (1u64 << NUM_CALLERS) - 1
        };
        if received_bitmap != expected
        {
            return Err("concurrent_ipc: not all callers received");
        }

        // Wait for all children to signal done. Each child sends a unique
        // bit (1<<i), so we wait until every bit is set.
        let all_done = expected;
        let mut done_bits: u64 = 0;
        while done_bits != all_done
        {
            let bits = notification_wait(done)
                .map_err(|_| "concurrent_ipc: notification_wait done failed")?;
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

fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this caller.
    let CallerArgs {
        ep: ep_slot,
        done: done_slot,
        label,
        bit_index,
    } = unsafe { spawn::child_args(arg) };
    let done_bit = 1u64 << bit_index;

    // Register this child's own IPC buffer page.
    // SAFETY: only the address of page `bit_index` is taken; no reference into `CALLER_IPC_BUFS` is
    // formed.
    let buf_addr = unsafe { core::ptr::addr_of_mut!(CALLER_IPC_BUFS[bit_index]) } as u64;
    // SAFETY: page `bit_index` of `CALLER_IPC_BUFS` is page-aligned and registered only by this
    // caller (one per concurrent caller), so the page is dedicated to the kernel as this thread's
    // IPC buffer; no Rust reference into it is ever taken, the page being reached only through raw
    // pointers and the `ipc` wrappers.
    if unsafe { syscall::ipc_buffer_set(buf_addr) }.is_err()
    {
        notification_send(done_slot, done_bit).ok();
        thread_exit()
    }

    // SAFETY: buf_addr was registered as this thread's IPC buffer above.
    let _ = unsafe { ipc::ipc_call(ep_slot, &IpcMessage::new(label), buf_addr as *mut u64) };
    notification_send(done_slot, done_bit).ok();
    thread_exit()
}
