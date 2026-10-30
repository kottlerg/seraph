// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/stress/concurrent_ipc.rs

//! Stress test: concurrent IPC endpoint races.
//!
//! `NUM_CALLERS` callers simultaneously block on one endpoint. The server
//! drains all of them, verifying no caller is lost. Repeats for `CYCLES`
//! cycles (fewer past 16 CPUs, see [`super::scaled_attempts`]), logging the
//! cycles done at most every [`PROGRESS_INTERVAL_US`]. Exercises the endpoint
//! send-queue spinlock under contention.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, system_info, thread_exit,
};
use syscall_abi::{RIGHTS_EP_SEND_GRANT, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// This cell's log name.
const CELL: &str = "stress::concurrent_ipc";

const NUM_CALLERS: usize = 64;
const CYCLES: u32 = 200;

/// Fewest cycles at any width: every cycle queues all `NUM_CALLERS` callers
/// on the endpoint at once, so a handful of cycles still contends its
/// send-queue lock from every caller.
const MIN_CYCLES: u32 = 8;

/// Least time between two progress lines, in microseconds: at wide CPU
/// counts a cycle takes long enough that the cell would otherwise run
/// silently for minutes, and that silence reads as a wedge.
const PROGRESS_INTERVAL_US: u64 = 10_000_000;

/// Per-caller arguments, handed to `caller_entry` by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    ep: u32,
    done: u32,
    /// 1-based caller label carried in the call.
    label: u64,
    bit_index: u64,
}

static CALLER_ARGS: spawn::ArgBlock<CallerArgs, NUM_CALLERS> = spawn::ArgBlock::new(CallerArgs {
    ep: 0,
    done: 0,
    label: 0,
    bit_index: 0,
});

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "concurrent_ipc: system_info(CpuCount) failed")?;
    // Each cycle's starts, replies and exits wake callers across CPUs, whose
    // cost grows with the width; the count shrinks with it.
    let cycles = super::scaled_attempts(CYCLES, MIN_CYCLES, cpus);
    let mut logged_at = crate::elapsed_us();
    for cycle in 0..cycles
    {
        let now = crate::elapsed_us();
        if now.saturating_sub(logged_at) >= PROGRESS_INTERVAL_US
        {
            crate::tally::log_cell_u64(CELL, " cycles done=", u64::from(cycle));
            logged_at = now;
        }
        let ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "concurrent_ipc: create_endpoint failed")?;
        let done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "concurrent_ipc: create_notification failed")?;

        let mut children = [const { spawn::SpawnedChild::EMPTY }; NUM_CALLERS];

        // Start all callers simultaneously (no yields between starts).
        for (i, slot) in children.iter_mut().enumerate()
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
                        bit_index: i as u64,
                    },
                )
            };

            // SAFETY: Each caller uses a distinct stack index.
            let stack_top =
                ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
            // SAFETY: the stack is `super::STRESS_STACKS[i]`, this test's own `ChildStack`,
            // on which no other live thread runs (`ChildStack`'s rule).
            unsafe { spawn::configure_and_start(&child, caller_entry, stack_top, arg) }
                .map_err(|_| "concurrent_ipc: configure_and_start failed")?;

            *slot = child;
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
            // cast_possible_truncation: usize is 64 bits on every ktest target
            // (x86_64, riscv64), so the u64 label widens losslessly; the range
            // check follows.
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
        for child in &mut children
        {
            child.delete_thread().ok();
            child.delete_cspace().ok();
        }
        cap_delete(ep).ok();
        cap_delete(done).ok();
    }

    Ok(())
}

/// IPC pages of the [`caller_entry`] children, one per `bit_index`.
static mut CALLER_IPC_PAGES: [crate::IpcPage; NUM_CALLERS] = [crate::IpcPage::ZERO; NUM_CALLERS];

extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this caller.
    let CallerArgs {
        ep: ep_slot,
        done: done_slot,
        label,
        bit_index,
    } = unsafe { spawn::child_args(arg) };
    let done_bit = 1u64 << bit_index;

    // cast_possible_truncation: `bit_index` is below `NUM_CALLERS`.
    #[allow(clippy::cast_possible_truncation)]
    let page = bit_index as usize;
    // SAFETY: takes the element's raw address without forming a reference to
    // the `static mut`.
    let buf_addr = crate::IpcPage::addr(unsafe { core::ptr::addr_of_mut!(CALLER_IPC_PAGES[page]) });
    // SAFETY: `CALLER_IPC_PAGES[page]` is this caller's own IPC page, used by one
    // thread at a time (`IpcPage`'s rule); no Rust object lives in it, and the
    // child reaches it only through the raw `buf_addr` pointer.
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
