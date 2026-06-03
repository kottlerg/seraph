// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fault_exception_redirect.rs

//! Integration: a non-page-fault CPU exception is redirected to a bound fault
//! handler, which resumes the thread at a new instruction pointer.
//!
//! Page faults already prove the `FAULT_KIND_VM` path (`fault_pager_roundtrip`,
//! `fault_resume_modifies_pc`). This exercises the `FAULT_KIND_EXCEPTION` path on
//! the real trap surface:
//!
//!   1. A child bound to an endpoint executes an illegal instruction (`ud2` on
//!      x86-64, `unimp` on RISC-V), trapping.
//!   2. The harness thread receives the kernel-synthesized fault, verifies its
//!      shape (`FAULT_LABEL`, badge, `FAULT_KIND_EXCEPTION`, normalized
//!      `FAULT_EXC_ILLEGAL_INSTRUCTION`, captured faulting IP), reads the
//!      fault-blocked thread's registers, points the instruction pointer at a
//!      recovery routine, writes the registers back, and replies
//!      `FAULT_REPLY_RESUME`.
//!   3. The child resumes in the recovery routine — never re-executing the
//!      illegal instruction — and signals success.
//!
//! A mechanism that only routed page faults would leave the child killed before
//! any fault message arrived, tripping the bounded `notification_wait`.

use core::sync::atomic::{AtomicU32, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait,
    thread_read_regs, thread_set_fault_handler, thread_write_regs,
};
use syscall_abi::{
    FAULT_CLASS_ALL, FAULT_EXC_ILLEGAL_INSTRUCTION, FAULT_KIND_EXCEPTION, FAULT_LABEL,
    FAULT_REPLY_RESUME, RIGHTS_ALL,
};

use crate::{ChildStack, TestContext, TestResult};

/// Badge bound with the handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE04;

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
        .map_err(|_| "fault_exception_redirect: cap_create_endpoint failed")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fault_exception_redirect: cap_create_notification failed")?;

    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "fault_exception_redirect: spawn::new_child failed")?;
    let child_sig = cap_copy(sig, child.cs, RIGHTS_ALL)
        .map_err(|_| "fault_exception_redirect: cap_copy(sig) failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);

    thread_set_fault_handler(child.th, ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "fault_exception_redirect: thread_set_fault_handler failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, fault_child, stack_top, 0)
        .map_err(|_| "fault_exception_redirect: configure_and_start failed")?;

    // Receive the fault and verify it is the expected illegal-instruction
    // exception (not a VM fault).
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fault_exception_redirect: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE
    {
        return Err("fault_exception_redirect: unexpected fault message");
    }
    if msg.word(0) != FAULT_KIND_EXCEPTION
    {
        return Err("fault_exception_redirect: fault kind is not EXCEPTION");
    }
    if msg.word(1) != FAULT_EXC_ILLEGAL_INSTRUCTION
    {
        return Err("fault_exception_redirect: normalized code is not ILLEGAL_INSTRUCTION");
    }
    let fault_ip = msg.word(3);

    // Read the fault-blocked thread's registers and confirm the captured IP in
    // the message matches the register frame.
    let mut reg_buf = [0u8; BUF];
    thread_read_regs(child.th, reg_buf.as_mut_ptr(), BUF)
        .map_err(|_| "fault_exception_redirect: thread_read_regs failed")?;
    let ip = u64::from_le_bytes(
        reg_buf[IP_OFFSET..IP_OFFSET + 8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    if ip == 0 || ip != fault_ip
    {
        return Err("fault_exception_redirect: register IP does not match fault message IP");
    }

    // Redirect the instruction pointer to the recovery routine and resume, so the
    // child never re-executes the illegal instruction.
    let recovery_ptr = recovery_child as *const () as u64;
    reg_buf[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&recovery_ptr.to_le_bytes());
    thread_write_regs(child.th, reg_buf.as_ptr(), BUF)
        .map_err(|_| "fault_exception_redirect: thread_write_regs failed")?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "fault_exception_redirect: ipc_reply(RESUME) failed")?;

    notification_wait(sig).map_err(|_| "fault_exception_redirect: notification_wait failed")?;

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(ep).ok();
    cap_delete(sig).ok();
    Ok(())
}

/// Child entry: execute an illegal instruction. The trap is redirected to the
/// bound handler, which points this thread at [`recovery_child`] rather than
/// resuming the faulting instruction. The loop only satisfies `-> !` and is
/// never reached.
fn fault_child(_arg: u64) -> !
{
    // SAFETY: a deliberately illegal instruction. The bound handler resumes this
    // thread at recovery_child, so control never returns here.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("ud2");
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("unimp");
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
