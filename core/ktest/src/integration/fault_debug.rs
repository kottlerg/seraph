// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_debug.rs

//! Integration: a debugger's breakpoint reaches the thread's exception
//! handler (docs/fault-handling.md § Debugging). Each architecture's
//! single-step is its `arch/<arch>/single_step.rs`.
//!
//! A child bound to an endpoint for the exception class executes a software
//! breakpoint (`int3` on x86-64, `ebreak` on riscv64). The handler receives
//! `FAULT_KIND_EXCEPTION` with `FAULT_EXC_BREAKPOINT` and the architecture's
//! reported instruction pointer (past `int3`, at `ebreak`), which the thread's
//! registers match; it advances the pointer past the breakpoint where the
//! architecture needs it and resumes the thread, which returns from the
//! breakpoint and reports the breakpoint's address.
//!
//! On x86-64 the breakpoint gate is DPL 3, so a user `int3` raises `#BP`; a
//! DPL-0 gate would raise `#GP` instead and the message would carry
//! `FAULT_EXC_PROTECTION`.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait_timeout,
    thread_read_regs, thread_write_regs,
};
use syscall_abi::{
    FAULT_CLASS_EXCEPTION, FAULT_EXC_BREAKPOINT, FAULT_KIND_EXCEPTION, FAULT_LABEL,
    FAULT_REPLY_RESUME, RIGHTS_NTF_NOTIFY,
};

use crate::arch::{BREAKPOINT_RESUME_ADVANCE, IP_OFFSET, breakpoint_reported_ip};
use crate::{ChildStack, TestContext, TestResult, spawn};

/// Badge bound with the exception class and delivered in the fault message.
const BADGE: u64 = 0x0DEB_0001;

/// Bound, in milliseconds, on the wait for the child's report. Applied
/// through [`crate::scaled_bound`].
const REPORT_MS: u64 = 1000;

/// Register-file buffer size; holds the arch `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child cap slot of the report notification.
static REPORT_SIG: AtomicU64 = AtomicU64::new(0);

/// The breakpoint's address, published by the child once resumed past it.
static BREAKPOINT_AT: AtomicU64 = AtomicU64::new(0);

pub fn run(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::fault_debug: cap_create_endpoint failed")?;
    let Ok(sig) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        return Err("integration::fault_debug: cap_create_notification failed");
    };
    let mut child = spawn::new_child(ctx).inspect_err(|_| {
        cap_delete(ep).ok();
        cap_delete(sig).ok();
    })?;
    let result = breakpoint(ctx, &child, ep, sig);
    let ok = child.delete_thread().is_ok()
        & child.delete_cspace().is_ok()
        & cap_delete(ep).is_ok()
        & cap_delete(sig).is_ok();
    result?;
    if ok
    {
        Ok(())
    }
    else
    {
        Err("integration::fault_debug: teardown failed")
    }
}

/// A software breakpoint is delivered as `FAULT_EXC_BREAKPOINT` and
/// resumed past.
fn breakpoint(ctx: &TestContext, child: &spawn::SpawnedChild, ep: u64, sig: u64) -> TestResult
{
    let child_sig = cap_copy(sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::fault_debug: cap_copy notification failed")?;
    REPORT_SIG.store(child_sig, Ordering::Release);
    crate::bind_fault_handler_classes(child.th, ep, BADGE, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_debug: bind (exception) failed")?;
    let stack = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, breakpoint_entry, stack, 0) }
        .map_err(|_| "integration::fault_debug: start failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::fault_debug: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != BADGE || msg.word(0) != FAULT_KIND_EXCEPTION
    {
        return Err("integration::fault_debug: unexpected fault message");
    }
    if msg.word(1) != FAULT_EXC_BREAKPOINT
    {
        return Err("integration::fault_debug: a software breakpoint is not FAULT_EXC_BREAKPOINT");
    }
    let reported = msg.word(3);

    let mut regs = [0u8; BUF];
    thread_read_regs(child.th, &mut regs[..BUF])
        .map_err(|_| "integration::fault_debug: thread_read_regs failed")?;
    let mut word = [0u8; 8];
    word.copy_from_slice(&regs[IP_OFFSET..IP_OFFSET + 8]);
    if u64::from_le_bytes(word) != reported
    {
        return Err("integration::fault_debug: register IP does not match the message's");
    }
    regs[IP_OFFSET..IP_OFFSET + 8]
        .copy_from_slice(&(reported + BREAKPOINT_RESUME_ADVANCE).to_le_bytes());
    // SAFETY: the frame was read from this child, fault-blocked at its
    // breakpoint; only its instruction pointer changes, to the instruction
    // after the breakpoint in the same function, which it resumes as if the
    // breakpoint had returned.
    unsafe { thread_write_regs(child.th, &regs[..BUF]) }
        .map_err(|_| "integration::fault_debug: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::fault_debug: reply failed")?;

    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::fault_debug: report wait failed")?;
    if bits == 0
    {
        return Err("integration::fault_debug: the child never resumed past its breakpoint");
    }
    if breakpoint_reported_ip(BREAKPOINT_AT.load(Ordering::Acquire)) != reported
    {
        return Err("integration::fault_debug: the reported IP is not the architecture's");
    }
    Ok(())
}

/// Child entry: hit a software breakpoint, then report its address.
extern "C" fn breakpoint_entry(_arg: u64) -> !
{
    let at = crate::arch::software_breakpoint();
    BREAKPOINT_AT.store(at, Ordering::Release);
    syscall::notification_send(REPORT_SIG.load(Ordering::Acquire), 1).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
