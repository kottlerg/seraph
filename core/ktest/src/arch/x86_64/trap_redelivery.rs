// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/trap_redelivery.rs

//! Integration (x86-64): a fault-handler rebind redelivers a trap-type
//! exception from the kernel, not by resuming the thread.
//!
//! A single-step `#DB` is a trap: the saved instruction pointer is already past
//! the instruction that trapped, and RFLAGS.TF stays set in the frame. The child
//! sets TF and steps one `nop`. The controller receives the `#DB` through the
//! first endpoint without replying, then rebinds the child to a second endpoint
//! with another badge. The fault must arrive there with the same instruction
//! pointer: a redelivery made by resuming the thread would run the next
//! instruction and trap again one instruction later. The controller then clears
//! TF, redirects the child to a recovery routine, and resumes it, which must
//! report (docs/fault-handling.md § Delivery, Resume, and Kill, Rebind).

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait_timeout,
    thread_read_regs, thread_write_regs,
};
use syscall_abi::{
    FAULT_EXC_DEBUG, FAULT_KIND_EXCEPTION, FAULT_LABEL, FAULT_REPLY_RESUME, RIGHTS_NTF_NOTIFY,
    X86_64_RFLAGS_TF,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Badges bound with the first and the second endpoint.
const BADGE_FIRST: u64 = 0xC0FF_EE0A;
const BADGE_SECOND: u64 = 0xC0FF_EE0B;

/// Bound, in milliseconds, on the wait for the recovery routine's report.
/// Applied through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs, where the child's CPU waits for a host core.
const REPORT_MS: u64 = 1000;

/// Register-file buffer size; holds the x86-64 `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Child cap slot of the report notification, read by [`recovery_entry`].
static RECOVERY_SIG: AtomicU64 = AtomicU64::new(0);

/// The caps and the child the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    first: Option<u64>,
    second: Option<u64>,
    sig: Option<u64>,
    child: Option<spawn::SpawnedChild>,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = body(ctx, &mut parts);
    let mut ok = true;
    if let Some(child) = parts.child.as_mut()
    {
        ok &= child.delete_thread().is_ok();
        ok &= child.delete_cspace().is_ok();
    }
    for cap in [parts.first, parts.second, parts.sig].into_iter().flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    result?;
    if ok
    {
        Ok(())
    }
    else
    {
        Err("integration::trap_redelivery: teardown failed")
    }
}

fn body(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let first = *parts.first.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::trap_redelivery: create first endpoint failed")?,
    );
    let second = *parts.second.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::trap_redelivery: create second endpoint failed")?,
    );
    let sig = *parts.sig.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "integration::trap_redelivery: create notification failed")?,
    );
    let child = parts
        .child
        .insert(spawn::new_child(ctx).map_err(|_| "integration::trap_redelivery: spawn failed")?);
    let child_sig = cap_copy(sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::trap_redelivery: cap_copy notification failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);
    crate::bind_fault_handler(child.th, first, BADGE_FIRST)
        .map_err(|_| "integration::trap_redelivery: bind failed")?;
    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, step_child, stack, 0) }
        .map_err(|_| "integration::trap_redelivery: start failed")?;
    let th = child.th;

    let ip = receive_step(ctx, first, BADGE_FIRST)?;
    crate::bind_fault_handler(th, second, BADGE_SECOND)
        .map_err(|_| "integration::trap_redelivery: rebind failed")?;
    if receive_step(ctx, second, BADGE_SECOND)? != ip
    {
        return Err(
            "integration::trap_redelivery: the redelivered #DB names another instruction pointer",
        );
    }
    resume_into_recovery(ctx, th, sig)
}

/// Receive a single-step `#DB` on `ep`, delivered with `badge`; return its
/// instruction pointer.
fn receive_step(ctx: &TestContext, ep: u64, badge: u64) -> Result<u64, &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::trap_redelivery: ipc_recv failed")?;
    if msg.label != FAULT_LABEL
        || msg.badge != badge
        || msg.word(0) != FAULT_KIND_EXCEPTION
        || msg.word(1) != FAULT_EXC_DEBUG
    {
        return Err("integration::trap_redelivery: unexpected fault message");
    }
    Ok(msg.word(3))
}

/// Clear TF in the fault-blocked `th`'s frame, redirect it into
/// [`recovery_entry`], reply RESUME, and wait for its report on `sig`.
fn resume_into_recovery(ctx: &TestContext, th: u64, sig: u64) -> TestResult
{
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF])
        .map_err(|_| "integration::trap_redelivery: thread_read_regs failed")?;
    super::edit_rflags(&mut regs, |rflags| rflags & !X86_64_RFLAGS_TF)?;
    spawn::redirect_to_entry(&mut regs[..], recovery_entry as *const () as u64)?;
    // SAFETY: the frame was read from this child, so its stack pointer lies on
    // the child's own `ChildStack`; `redirect_to_entry` pointed it at
    // `recovery_entry`, an `extern "C"` entry that never returns, with the
    // stack pointer moved down to the entry ABI's alignment on that stack, and
    // TF is clear so the routine runs without stepping.
    unsafe { thread_write_regs(th, &regs[..BUF]) }
        .map_err(|_| "integration::trap_redelivery: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::trap_redelivery: reply (RESUME) failed")?;
    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::trap_redelivery: recovery wait failed")?;
    if bits == 0
    {
        return Err("integration::trap_redelivery: resumed child never recovered");
    }
    Ok(())
}

/// Child: set TF and step the instructions after it. The first `#DB` traps
/// after the `nop` that follows `popfq`; the controller redirects the thread
/// before it runs on, so the loop only satisfies `-> !`.
extern "C" fn step_child(_arg: u64) -> !
{
    // SAFETY: TF is set deliberately; the single-step trap it raises is
    // delivered to the bound handler, which clears TF and redirects this
    // thread before control leaves the block. Registers: none besides RFLAGS;
    // pushfq/popfq use the stack.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "or qword ptr [rsp], {tf}",
            "popfq",
            "nop",
            "nop",
            "nop",
            tf = const X86_64_RFLAGS_TF,
        );
    }
    loop
    {
        core::hint::spin_loop();
    }
}

/// Recovery routine the controller redirects the child into: report through
/// the published notification cap.
extern "C" fn recovery_entry(_arg: u64) -> !
{
    syscall::notification_send(RECOVERY_SIG.load(Ordering::Acquire), 1).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
