// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fault_resume_modifies_pc.rs

//! Integration: a fault handler edits the faulting thread's registers, then
//! resumes it at a new instruction pointer.
//!
//! Proves two protocol guarantees beyond the plain pager round-trip:
//!   1. `SYS_THREAD_READ_REGS` / `SYS_THREAD_WRITE_REGS` operate on a thread
//!      that is fault-blocked (`Blocked` + `BlockedOnFault`), not only `Stopped`.
//!   2. A `FAULT_REPLY_RESUME` after a register edit resumes the thread from the
//!      handler-modified PC rather than re-executing the faulting instruction.
//!
//! The handler never maps the faulting page; instead it reads the faulting
//! thread's registers (confirming the captured IP is the faulting store), points
//! the instruction pointer at a recovery routine, writes the registers back, and
//! replies RESUME. The child abandons the faulting store and lands in the
//! recovery routine, which signals success — so a working test never touches the
//! reserved VA again.

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait,
    thread_read_regs, thread_set_fault_handler, thread_write_regs,
};
use syscall_abi::{FAULT_CLASS_ALL, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_RESUME, RIGHTS_ALL};

use crate::{ChildStack, TestContext, TestResult};

/// Unmapped, canonical user-half VA the child touches. Distinct from other tests.
const RESERVED_VA: u64 = 0x6200_0000_0000;

/// Badge bound with the handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE02;

/// Instruction-pointer field offset in the architecture `TrapFrame` (matches the
/// kernel layout: x86-64 `rip` at 120, RISC-V `sepc` at 248).
#[cfg(target_arch = "x86_64")]
const IP_OFFSET: usize = 120;
#[cfg(target_arch = "riscv64")]
const IP_OFFSET: usize = 248;

/// Register-file buffer size; the arch `TrapFrame` is 168 B (x86-64) / 280 B
/// (RISC-V), both within this bound.
const BUF: usize = 512;

/// Child cap slot for the success notification, stashed so the recovery routine
/// can read it without depending on register state across the PC redirect.
static RECOVERY_SIG: AtomicU32 = AtomicU32::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "fault_resume_modifies_pc: cap_create_endpoint failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fault_resume_modifies_pc: cap_create_notification failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "fault_resume_modifies_pc: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_ALL)
        .map_err(|_| "fault_resume_modifies_pc: cap_copy(sig) failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);

    thread_set_fault_handler(child.th, ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "fault_resume_modifies_pc: thread_set_fault_handler failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, fault_child, stack_top, 0)
        .map_err(|_| "fault_resume_modifies_pc: configure_and_start failed")?;

    // Receive the fault and verify it is the expected VM fault.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fault_resume_modifies_pc: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE || msg.word(0) != FAULT_KIND_VM
    {
        return Err("fault_resume_modifies_pc: unexpected fault message");
    }
    let fault_ip = msg.word(3);

    // Read the fault-blocked thread's registers (permitted in BlockedOnFault).
    let mut reg_buf = [0u8; BUF];
    thread_read_regs(child.th, reg_buf.as_mut_ptr(), BUF)
        .map_err(|_| "fault_resume_modifies_pc: thread_read_regs failed")?;
    let ip = u64::from_le_bytes(
        reg_buf[IP_OFFSET..IP_OFFSET + 8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    if ip == 0 || ip != fault_ip
    {
        return Err("fault_resume_modifies_pc: register IP does not match fault message IP");
    }

    // Redirect the instruction pointer to the recovery routine and resume.
    let recovery_ptr = recovery_child as *const () as u64;
    reg_buf[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&recovery_ptr.to_le_bytes());
    thread_write_regs(child.th, reg_buf.as_ptr(), BUF)
        .map_err(|_| "fault_resume_modifies_pc: thread_write_regs failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "fault_resume_modifies_pc: ipc_reply(RESUME) failed")?;

    notification_wait(sig).map_err(|_| "fault_resume_modifies_pc: notification_wait failed")?;

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(ep).ok();
    cap_delete(sig).ok();
    Ok(())
}

/// Child entry: store to the reserved VA. The store faults; the handler
/// redirects this thread to [`recovery_child`] instead of mapping, so the store
/// never completes. The loop only satisfies `-> !`.
fn fault_child(_arg: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — the handler resumes the thread at
    // recovery_child rather than backing this page, so the store is abandoned.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}

/// Recovery routine the handler redirects the faulting thread into. Signals
/// success through the stashed notification cap.
fn recovery_child() -> !
{
    syscall::notification_send(RECOVERY_SIG.load(Ordering::Acquire), 1).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
