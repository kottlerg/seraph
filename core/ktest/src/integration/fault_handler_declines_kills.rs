// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fault_handler_declines_kills.rs

//! Integration: a fault handler that replies `FAULT_REPLY_KILL` terminates the
//! faulting thread as an unhandled fault.
//!
//!   1. A child bound to an endpoint stores to an unmapped reserved VA, faulting.
//!   2. The harness thread receives the fault and replies `FAULT_REPLY_KILL`
//!      (declining to resolve it) instead of resuming.
//!   3. The child must reach `Exited` with exit reason `EXIT_FAULT_BASE +
//!      <fault vector>` — identical to the no-handler-bound terminal behavior.
//!
//! This exercises the kill disposition of the reply path and the
//! `BlockedOnFault → kill` transition. A bug that resumed the thread on a KILL
//! reply would loop on the fault (never reaching `Exited`) and trip the poll
//! bound rather than hanging.

use ipc::IpcMessage;
use syscall::{cap_create_endpoint, cap_delete, cap_info, thread_set_fault_handler, thread_sleep};
use syscall_abi::{
    CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, FAULT_CLASS_ALL, FAULT_LABEL, FAULT_REPLY_KILL,
    THREAD_STATE_EXITED,
};

use crate::{ChildStack, TestContext, TestResult};

/// Unmapped, canonical user-half VA the child touches. Distinct from other tests.
const RESERVED_VA: u64 = 0x6300_0000_0000;

/// Badge bound with the handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE03;

/// Fault vector recorded in `exit_reason` for a not-present store.
#[cfg(target_arch = "x86_64")]
const FAULT_VECTOR: u64 = 14; // #PF
#[cfg(target_arch = "riscv64")]
const FAULT_VECTOR: u64 = 15; // store/AMO page fault

/// Poll bound: ~2 s at ~1 ms per `thread_sleep(1)` before declaring failure.
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "fault_handler_declines_kills: cap_create_endpoint failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "fault_handler_declines_kills: spawn::new_child failed")?;
    thread_set_fault_handler(child.th, ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "fault_handler_declines_kills: thread_set_fault_handler failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, fault_child, stack_top, 0)
        .map_err(|_| "fault_handler_declines_kills: configure_and_start failed")?;

    // Receive the fault and decline it.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fault_handler_declines_kills: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE
    {
        return Err("fault_handler_declines_kills: unexpected fault message");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ctx.ipc_buf) }
        .map_err(|_| "fault_handler_declines_kills: ipc_reply(KILL) failed")?;

    // The declined fault is terminal: the child must reach Exited with the
    // standard fault exit reason.
    let expected = EXIT_FAULT_BASE + FAULT_VECTOR;
    let mut polls = 0;
    loop
    {
        let packed = cap_info(child.th, CAP_INFO_THREAD_STATE)
            .map_err(|_| "fault_handler_declines_kills: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: state code is the packed high word.
        #[allow(clippy::cast_possible_truncation)]
        let state = (packed >> 32) as u32;
        if state == THREAD_STATE_EXITED
        {
            if packed & 0xFFFF_FFFF != expected
            {
                return Err("fault_handler_declines_kills: wrong exit reason after KILL");
            }
            break;
        }
        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("fault_handler_declines_kills: child never died after KILL reply");
        }
        thread_sleep(1).ok();
    }

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(ep).ok();
    Ok(())
}

/// Child entry: store to the reserved VA. The store faults; the handler declines
/// (KILL), so the kernel terminates this thread before the store returns. The
/// loop only satisfies `-> !` and is never reached.
fn fault_child(_arg: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — the bound handler replies KILL, so the
    // kernel terminates this thread instead of resuming the store.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}
