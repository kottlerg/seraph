// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/single_step.rs

//! Integration (x86-64): a debugger single-steps a thread with the trap flag
//! (docs/fault-handling.md § Debugging).
//!
//! A child bound to an endpoint for the exception class hits `int3` before a
//! block of a `mov`, a `syscall` (`SYS_THREAD_YIELD`), and a `nop`. The handler
//! resumes it from the breakpoint with the trap flag (`X86_64_RFLAGS_TF` at
//! `REGS_X86_64_FLAGS_OFFSET`) set through `SYS_THREAD_WRITE_REGS`. It then
//! receives one `FAULT_EXC_DEBUG` per instruction, each reporting the next
//! instruction: after the `mov`, after the `syscall` (the stepped syscall runs
//! with TF clear in the kernel and steps past as one instruction), and after
//! the `nop`. At the last one the handler clears the flag and resumes the
//! child, which reports.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait_timeout,
    thread_read_regs, thread_write_regs,
};
use syscall_abi::{
    FAULT_CLASS_EXCEPTION, FAULT_EXC_BREAKPOINT, FAULT_EXC_DEBUG, FAULT_KIND_EXCEPTION,
    FAULT_LABEL, FAULT_REPLY_RESUME, RIGHTS_NTF_NOTIFY, SYS_THREAD_YIELD, X86_64_RFLAGS_TF,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Badge bound with the exception class and delivered in the fault message.
const BADGE: u64 = 0x0DEB_0002;

/// Bound, in milliseconds, on the wait for the child's report. Applied
/// through [`crate::scaled_bound`].
const REPORT_MS: u64 = 1000;

/// Register-file buffer size; holds the arch `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child cap slot of the report notification.
static REPORT_SIG: AtomicU64 = AtomicU64::new(0);

/// The addresses after the breakpoint, published by the child once it has
/// run the stepped block: the `mov`, the `syscall`, the `nop`, and the end.
static STEPPED: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

pub fn run(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::single_step: cap_create_endpoint failed")?;
    let Ok(sig) = cap_create_notification(ctx.memory_base)
    else
    {
        cap_delete(ep).ok();
        return Err("integration::single_step: cap_create_notification failed");
    };
    let mut child = spawn::new_child(ctx).inspect_err(|_| {
        cap_delete(ep).ok();
        cap_delete(sig).ok();
    })?;
    let result = steps(ctx, &child, ep, sig);
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
        Err("integration::single_step: teardown failed")
    }
}

/// Resume the child from its breakpoint with the trap flag set, and take one
/// step per instruction of its block.
fn steps(ctx: &TestContext, child: &spawn::SpawnedChild, ep: u64, sig: u64) -> TestResult
{
    let child_sig = cap_copy(sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::single_step: cap_copy notification failed")?;
    REPORT_SIG.store(child_sig, Ordering::Release);
    crate::bind_fault_handler_classes(child.th, ep, BADGE, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::single_step: bind (exception) failed")?;
    let stack = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, step_entry, stack, 0) }
        .map_err(|_| "integration::single_step: start failed")?;

    let first = expect_exception(ctx, ep, FAULT_EXC_BREAKPOINT)?;
    edit_flags(child.th, |flags| flags | X86_64_RFLAGS_TF)?;
    reply_resume(ctx)?;
    let mut reported = [0u64; 3];
    for (k, slot) in reported.iter_mut().enumerate()
    {
        *slot = expect_exception(ctx, ep, FAULT_EXC_DEBUG)?;
        if k == 2
        {
            edit_flags(child.th, |flags| flags & !X86_64_RFLAGS_TF)?;
        }
        reply_resume(ctx)?;
    }
    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::single_step: report wait failed")?;
    if bits == 0
    {
        return Err("integration::single_step: the stepped child never finished its block");
    }
    let addrs = STEPPED.each_ref().map(|a| a.load(Ordering::Acquire));
    if first != addrs[0]
    {
        return Err("integration::single_step: the breakpoint reported the wrong instruction");
    }
    if reported != [addrs[1], addrs[2], addrs[3]]
    {
        return Err("integration::single_step: a step reported the wrong instruction");
    }
    Ok(())
}

/// Receive an exception fault on `ep` with normalized code `code`; returns its
/// reported instruction pointer.
fn expect_exception(ctx: &TestContext, ep: u64, code: u64) -> Result<u64, &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::single_step: ipc_recv failed")?;
    if msg.label != FAULT_LABEL
        || msg.badge != BADGE
        || msg.word(0) != FAULT_KIND_EXCEPTION
        || msg.word(1) != code
    {
        return Err("integration::single_step: unexpected fault message");
    }
    Ok(msg.word(3))
}

/// Rewrite the fault-blocked `th`'s `rflags` through `edit`.
fn edit_flags(th: u64, edit: impl FnOnce(u64) -> u64) -> TestResult
{
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF])
        .map_err(|_| "integration::single_step: thread_read_regs failed")?;
    super::edit_rflags(&mut regs, edit);
    // SAFETY: the frame was read from this child, fault-blocked; only the
    // trap flag changes, which decides whether the next instruction traps,
    // and nothing of the thread's memory or control flow.
    unsafe { thread_write_regs(th, &regs[..BUF]) }
        .map_err(|_| "integration::single_step: thread_write_regs failed")
}

/// Reply RESUME to the fault the controller holds.
fn reply_resume(ctx: &TestContext) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::single_step: reply failed")
}

/// Child entry: hit `int3` before the stepped block, then publish the
/// block's instruction boundaries and report.
extern "C" fn step_entry(_arg: u64) -> !
{
    let (after_bp, after_mov, after_syscall, after_nop): (u64, u64, u64, u64);
    // SAFETY: the `lea`s write only their outputs. `int3` raises #BP; the
    // `mov` loads the yield number; `syscall` yields, which changes nothing
    // the block depends on and clobbers `rcx`, `r11`, and `rax` (declared);
    // the `nop` does nothing. The handler clears the trap flag it set before
    // its last resume, so flags are restored, and touches no other register.
    unsafe {
        core::arch::asm!(
            "lea {a}, [rip + 2f]",
            "lea {b}, [rip + 3f]",
            "lea {c}, [rip + 4f]",
            "lea {d}, [rip + 5f]",
            "int3",
            "2: mov eax, {nr}",
            "3: syscall",
            "4: nop",
            "5:",
            a = out(reg) after_bp,
            b = out(reg) after_mov,
            c = out(reg) after_syscall,
            d = out(reg) after_nop,
            nr = const SYS_THREAD_YIELD,
            out("rax") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    for (slot, addr) in STEPPED
        .iter()
        .zip([after_bp, after_mov, after_syscall, after_nop])
    {
        slot.store(addr, Ordering::Release);
    }
    syscall::notification_send(REPORT_SIG.load(Ordering::Acquire), 1).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
