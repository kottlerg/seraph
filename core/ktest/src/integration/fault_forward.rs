// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_forward.rs

//! Integration: a virtual-memory fault handler that replies
//! `FAULT_REPLY_FORWARD` hands the fault to the thread's exception handler
//! (docs/fault-handling.md § Reply).
//!
//!   1. **Forward to a bound handler.** With the VM and exception classes
//!      bound to two endpoints, a page fault reaches the VM endpoint; its
//!      forward with a reason word delivers the same fault message to the
//!      exception endpoint, with the exception binding's badge and the reason
//!      as data word 4. The thread stays fault-blocked there: its registers
//!      read, and the exception handler's resume runs it on, redirected into a
//!      recovery routine.
//!   2. **Forward with none bound.** With the exception class unbound, the
//!      forward is a decline: the thread exits with the page fault's reason.
//!   3. **Forward from the exception class.** A forward of an exception
//!      delivery is a decline too: the thread exits with the illegal
//!      instruction's reason, and nothing reaches the VM endpoint.
//!   4. **Forward of a kernel copy.** A forward of the fault of a
//!      `SYS_GETRANDOM` copy into an unmapped buffer is a decline: the
//!      syscall fails with `InvalidAddress` and the thread runs on, reporting
//!      it, without the exception handler receiving anything.
//!   5. **Rebind after a forward.** A change of the exception class's binding
//!      while the forwarded delivery waits there delivers the fault again
//!      under the new binding, with its badge and the forwarder's word still
//!      data word 4.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait_timeout,
    thread_read_regs, thread_write_regs, wait_set_add, wait_set_create, wait_set_wait,
};
use syscall_abi::{
    EXIT_FAULT_BASE, FAULT_CLASS_EXCEPTION, FAULT_CLASS_VM, FAULT_FORWARD_REASON_WORD,
    FAULT_KIND_EXCEPTION, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_FORWARD, FAULT_REPLY_KILL,
    FAULT_REPLY_RESUME, RIGHTS_NTF_NOTIFY,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Unmapped user VA the page-faulting children store to; canonical in every
/// paging mode (below the 2^38 Sv39 user half). Distinct from other tests.
const RESERVED_VA: u64 = 0x3E_E000_0000;

/// Badges bound with the VM and the exception endpoint, and with the
/// endpoint the exception class is rebound to.
const BADGE_VM: u64 = 0xC0FF_EE1A;
const BADGE_EXC: u64 = 0xC0FF_EE1B;
const BADGE_OTHER: u64 = 0xC0FF_EE1C;

/// Bytes the copy-fault child's `SYS_GETRANDOM` asks for.
const COPY_LEN: usize = 16;

/// The reason word the VM handler forwards.
const REASON: u64 = 0x5EED_0003;

/// Wait-set badges naming the endpoint a fault reached.
const WS_VM: u64 = 0x01;
const WS_EXC: u64 = 0x02;

/// Bound on the wait for a child to exit, in 1 ms polls. Applied through
/// [`crate::scaled_polls`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where a child's CPU waits for a host core.
const EXIT_POLLS: u32 = 2000;

/// Bound, in milliseconds, on the wait for the recovery routine's report.
/// Applied through [`crate::scaled_bound`], which stretches it the same way.
const REPORT_MS: u64 = 1000;

/// Register-file buffer size; holds the arch `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// One child per phase.
const CHILDREN: usize = 5;

static mut STACKS: [ChildStack; CHILDREN] = [ChildStack::ZERO; CHILDREN];

/// Child cap slot of the report notification, read by [`recovery_entry`].
static RECOVERY_SIG: AtomicU64 = AtomicU64::new(0);

/// The caps and children the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    ep_vm: Option<u64>,
    ep_exc: Option<u64>,
    ep_other: Option<u64>,
    sig: Option<u64>,
    ws: Option<u64>,
    children: [Option<spawn::SpawnedChild>; CHILDREN],
}

/// The objects the phases share.
struct Objects
{
    ep_vm: u64,
    ep_exc: u64,
    ep_other: u64,
    sig: u64,
    ws: u64,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = phases(ctx, &mut parts);
    let mut ok = true;
    for child in parts.children.iter_mut().flatten()
    {
        ok &= child.delete_thread().is_ok();
        ok &= child.delete_cspace().is_ok();
    }
    for cap in [
        parts.ws,
        parts.ep_vm,
        parts.ep_exc,
        parts.ep_other,
        parts.sig,
    ]
    .into_iter()
    .flatten()
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
        Err("integration::fault_forward: teardown failed")
    }
}

fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let fail = |_| "integration::fault_forward: object creation failed";
    let objects = Objects {
        ep_vm: *parts
            .ep_vm
            .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?),
        ep_exc: *parts
            .ep_exc
            .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?),
        ep_other: *parts
            .ep_other
            .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?),
        sig: *parts
            .sig
            .insert(cap_create_notification(ctx.memory_base).map_err(fail)?),
        ws: *parts
            .ws
            .insert(wait_set_create(ctx.memory_base, crate::WS_CAPACITY).map_err(fail)?),
    };
    wait_set_add(objects.ws, objects.ep_vm, WS_VM)
        .map_err(|_| "integration::fault_forward: wait_set_add (VM) failed")?;
    wait_set_add(objects.ws, objects.ep_exc, WS_EXC)
        .map_err(|_| "integration::fault_forward: wait_set_add (exception) failed")?;
    forward_to_bound(ctx, parts, &objects)?;
    forward_to_none(ctx, parts, &objects)?;
    forward_from_exception(ctx, parts, &objects)?;
    forward_of_kernel_copy(ctx, parts, &objects)?;
    rebind_after_forward(ctx, parts, &objects)
}

/// Phase 4: a forward of a kernel copy's fault fails the syscall, and the
/// thread reports it; the exception endpoint receives nothing.
fn forward_of_kernel_copy(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 3, objects)?;
    bind_vm(th, objects)?;
    bind_exception(th, objects)?;
    start_child(parts, 3, copy_entry)?;
    let msg = expect_fault_at(ctx, objects, WS_VM)?;
    if msg.word(0) != FAULT_KIND_VM || msg.word(1) != RESERVED_VA
    {
        return Err("integration::fault_forward: unexpected copy fault message");
    }
    reply_with_reason(ctx, FAULT_REPLY_FORWARD)?;
    let bits = notification_wait_timeout(objects.sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::fault_forward: copy report wait failed")?;
    if bits != COPY_REFUSED
    {
        return Err("integration::fault_forward: a forwarded copy fault did not fail the syscall");
    }
    Ok(())
}

/// Phase 5: a rebind of the exception class while the forwarded delivery is
/// queued there delivers it again under the new binding.
fn rebind_after_forward(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 4, objects)?;
    bind_vm(th, objects)?;
    bind_exception(th, objects)?;
    start_child(parts, 4, store_entry)?;
    expect_fault_at(ctx, objects, WS_VM)?;
    reply_with_reason(ctx, FAULT_REPLY_FORWARD)?;
    crate::bind_fault_handler_classes(th, objects.ep_other, BADGE_OTHER, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_forward: rebind (exception) failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(objects.ep_other, ctx.ipc_buf) }
        .map_err(|_| "integration::fault_forward: ipc_recv on the rebound endpoint failed")?;
    if msg.label != FAULT_LABEL
        || msg.badge != BADGE_OTHER
        || msg.word(0) != FAULT_KIND_VM
        || msg.word(FAULT_FORWARD_REASON_WORD) != REASON
    {
        return Err("integration::fault_forward: the rebound delivery is not the forwarded fault");
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ctx.ipc_buf) }
        .map_err(|_| "integration::fault_forward: reply (kill) failed")?;
    expect_exit(th, crate::arch::PAGE_FAULT_STORE_VECTOR)
}

/// Phase 1: the forward delivers the fault to the exception endpoint, where
/// the thread stays fault-blocked until that handler resumes it.
fn forward_to_bound(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 0, objects)?;
    bind_vm(th, objects)?;
    bind_exception(th, objects)?;
    start_child(parts, 0, store_entry)?;
    let first = expect_fault_at(ctx, objects, WS_VM)?;
    if first.badge != BADGE_VM || first.word(0) != FAULT_KIND_VM || first.word(1) != RESERVED_VA
    {
        return Err("integration::fault_forward: unexpected VM fault message");
    }
    reply_with_reason(ctx, FAULT_REPLY_FORWARD)?;

    let forwarded = expect_fault_at(ctx, objects, WS_EXC)?;
    let same_fault = (0..FAULT_FORWARD_REASON_WORD).all(|i| forwarded.word(i) == first.word(i));
    if forwarded.badge != BADGE_EXC
        || !same_fault
        || forwarded.word_count() != FAULT_FORWARD_REASON_WORD + 1
        || forwarded.word(FAULT_FORWARD_REASON_WORD) != REASON
    {
        return Err("integration::fault_forward: the forwarded message is not the fault's");
    }
    resume_into_recovery(ctx, th, objects.sig)
}

/// Phase 2: with no exception handler bound, the forward is a decline.
fn forward_to_none(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 1, objects)?;
    bind_vm(th, objects)?;
    start_child(parts, 1, store_entry)?;
    expect_fault_at(ctx, objects, WS_VM)?;
    reply_with_reason(ctx, FAULT_REPLY_FORWARD)?;
    expect_exit(th, crate::arch::PAGE_FAULT_STORE_VECTOR)
}

/// Phase 3: a forward of an exception-class delivery is a decline; the fault
/// does not reach the VM endpoint.
fn forward_from_exception(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 2, objects)?;
    bind_vm(th, objects)?;
    bind_exception(th, objects)?;
    start_child(parts, 2, illegal_entry)?;
    let msg = expect_fault_at(ctx, objects, WS_EXC)?;
    if msg.word(0) != FAULT_KIND_EXCEPTION
    {
        return Err("integration::fault_forward: unexpected exception message");
    }
    reply_with_reason(ctx, FAULT_REPLY_FORWARD)?;
    expect_exit(th, crate::arch::ILLEGAL_INSTRUCTION_VECTOR)
}

/// Spawn child `index` with a copy of the report notification. Returns its
/// Thread cap; the child is configured and started by [`start_child`].
fn spawn_child(
    ctx: &TestContext,
    parts: &mut Parts,
    index: usize,
    objects: &Objects,
) -> Result<u64, &'static str>
{
    let child = parts.children[index]
        .insert(spawn::new_child(ctx).map_err(|_| "integration::fault_forward: spawn failed")?);
    let child_sig = cap_copy(objects.sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::fault_forward: cap_copy notification failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);
    Ok(child.th)
}

/// Configure and start child `index` at `entry`.
fn start_child(parts: &Parts, index: usize, entry: extern "C" fn(u64) -> !) -> TestResult
{
    let child = parts.children[index]
        .as_ref()
        .ok_or("integration::fault_forward: no child")?;
    // SAFETY: stack `index` belongs to this child, deleted before this test
    // returns.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(STACKS[index]) });
    // SAFETY: the stack is `STACKS[index]`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, entry, stack, 0) }
        .map_err(|_| "integration::fault_forward: start failed")
}

fn bind_vm(th: u64, objects: &Objects) -> TestResult
{
    crate::bind_fault_handler_classes(th, objects.ep_vm, BADGE_VM, FAULT_CLASS_VM)
        .map_err(|_| "integration::fault_forward: bind (VM) failed")
}

fn bind_exception(th: u64, objects: &Objects) -> TestResult
{
    crate::bind_fault_handler_classes(th, objects.ep_exc, BADGE_EXC, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_forward: bind (exception) failed")
}

/// Wait for a fault to reach an endpoint, check through the wait set that it
/// is the one `ws_badge` names, and receive it there.
fn expect_fault_at(
    ctx: &TestContext,
    objects: &Objects,
    ws_badge: u64,
) -> Result<IpcMessage, &'static str>
{
    let ready = wait_set_wait(objects.ws)
        .map_err(|_| "integration::fault_forward: wait_set_wait failed")?;
    if ready != ws_badge
    {
        return Err("integration::fault_forward: a fault reached the other class's endpoint");
    }
    let ep = if ws_badge == WS_VM
    {
        objects.ep_vm
    }
    else
    {
        objects.ep_exc
    };
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::fault_forward: ipc_recv failed")?;
    if msg.label != FAULT_LABEL
    {
        return Err("integration::fault_forward: not a fault message");
    }
    Ok(msg)
}

/// Reply `label` with [`REASON`] as data word 0 to the fault the controller
/// holds.
fn reply_with_reason(ctx: &TestContext, label: u64) -> TestResult
{
    let msg = IpcMessage::builder(label).word(0, REASON).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&msg, ctx.ipc_buf) }
        .map_err(|_| "integration::fault_forward: reply failed")
}

/// Check that `th` exits with the fault reason of `vector`.
fn expect_exit(th: u64, vector: u64) -> TestResult
{
    let reason = spawn::wait_until_exited(th, crate::scaled_polls(EXIT_POLLS))
        .map_err(|_| "integration::fault_forward: child never exited")?;
    if reason != EXIT_FAULT_BASE + vector
    {
        return Err("integration::fault_forward: child exited with the wrong reason");
    }
    Ok(())
}

/// Read the fault-blocked `th`'s registers, redirect it into
/// [`recovery_entry`], reply RESUME, and wait for its report on `sig`.
fn resume_into_recovery(ctx: &TestContext, th: u64, sig: u64) -> TestResult
{
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF]).map_err(
        |_| "integration::fault_forward: thread_read_regs of the forwarded fault failed",
    )?;
    spawn::redirect_to_entry(&mut regs[..], recovery_entry as *const () as u64);
    // SAFETY: the frame was read from this child, so its stack pointer lies
    // on the child's own `ChildStack`; `redirect_to_entry` pointed it at
    // `recovery_entry`, an `extern "C"` entry that never returns, with the
    // stack pointer moved down to the entry ABI's alignment on that stack.
    unsafe { thread_write_regs(th, &regs[..BUF]) }
        .map_err(|_| "integration::fault_forward: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::fault_forward: reply (resume) failed")?;
    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::fault_forward: recovery wait failed")?;
    if bits == 0
    {
        return Err("integration::fault_forward: resumed child never recovered");
    }
    Ok(())
}

/// Child entry: store to the reserved VA, which faults. The loop only
/// satisfies `-> !`.
extern "C" fn store_entry(_arg: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — the fault is never resolved by backing
    // this page.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}

/// The copy-fault child's report: its `SYS_GETRANDOM` failed with
/// `InvalidAddress`.
const COPY_REFUSED: u64 = 0x2;

/// Child entry: `SYS_GETRANDOM` into the unmapped reserved VA, whose copy
/// faults; report through the published notification cap when the syscall
/// fails with `InvalidAddress`. The loop only satisfies `-> !`.
extern "C" fn copy_entry(_arg: u64) -> !
{
    // SAFETY: the span is unmapped, and no Rust object occupies it; the kernel
    // refuses the copy, or writes it once a handler backs it, which none does.
    let r = unsafe { syscall::getrandom_raw(RESERVED_VA as *mut u8, COPY_LEN) };
    if r == Err(syscall_abi::SyscallError::InvalidAddress as i64)
    {
        syscall::notification_send(RECOVERY_SIG.load(Ordering::Acquire), COPY_REFUSED).ok();
    }
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: execute an illegal instruction.
extern "C" fn illegal_entry(_arg: u64) -> !
{
    crate::arch::illegal_instruction()
}

/// Recovery routine a resumed child is redirected into: report through the
/// published notification cap.
extern "C" fn recovery_entry(_arg: u64) -> !
{
    syscall::notification_send(RECOVERY_SIG.load(Ordering::Acquire), 1).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
