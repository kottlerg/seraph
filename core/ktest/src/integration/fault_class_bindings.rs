// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_class_bindings.rs

//! Integration: a thread's fault handler is bound per fault class, read back
//! per class, and copied per class onto another thread
//! (docs/fault-handling.md § Fault-Handler Binding).
//!
//! The VM and exception classes are bound to two endpoints, each watched by a
//! wait set that names which endpoint a fault reached.
//!
//!   1. **Routing.** A page fault reaches the VM endpoint with the VM badge,
//!      and an illegal instruction the exception endpoint with the exception
//!      badge.
//!   2. **Partial unbind.** With both classes bound to the VM endpoint, an
//!      unbind of the exception class alone leaves the VM class bound (read
//!      back by `SYS_THREAD_GET_FAULT_HANDLER`), and an illegal instruction is
//!      then unhandled: the thread exits with the exception's fault reason.
//!   3. **Per-class rebind.** A rebind of the exception class while a page
//!      fault is held unreplied cancels nothing: the held fault's reply
//!      resumes the thread.
//!   4. **Inheritance.** `SYS_THREAD_INHERIT_FAULT_HANDLER` copies the VM
//!      class from a source thread and leaves the destination's exception
//!      class as it was; a copy of every class then unbinds the exception
//!      class, which the source has unbound. A page fault of the destination
//!      reaches the source's endpoint with the source's badge.
//!   5. **Argument and rights checks.** A mask of zero or with an undefined
//!      bit is refused by both binders, and a class argument that is not one
//!      class bit by the query. A Thread cap without `CONTROL` is refused
//!      (`InsufficientRights`) by the query and as either thread of the copy,
//!      and a handle that names no capability (`InvalidCapability`) likewise.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_derive,
    notification_wait_timeout, thread_get_fault_handler, thread_inherit_fault_handler,
    thread_read_regs, thread_set_fault_handler, thread_write_regs, wait_set_add, wait_set_create,
    wait_set_wait,
};
use syscall_abi::{
    EXIT_FAULT_BASE, FAULT_CLASS_ALL, FAULT_CLASS_EXCEPTION, FAULT_CLASS_VM, FAULT_KIND_EXCEPTION,
    FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL, FAULT_REPLY_RESUME, RIGHTS_NTF_NOTIFY,
    RIGHTS_THREAD_OBSERVE, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Unmapped user VA the page-faulting children store to; canonical in every
/// paging mode (below the 2^38 Sv39 user half). Distinct from other tests.
const RESERVED_VA: u64 = 0x3E_D000_0000;

/// Badges bound with the VM and the exception endpoint.
const BADGE_VM: u64 = 0xC0FF_EE0C;
const BADGE_EXC: u64 = 0xC0FF_EE0D;

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

/// Children: 0 and 1 for routing, 2 for the partial unbind, 3 for the
/// per-class rebind, and 4 and 5 for the inheritance source and destination.
const CHILDREN: usize = 6;

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
        Err("integration::fault_class_bindings: teardown failed")
    }
}

fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let fail = |_| "integration::fault_class_bindings: object creation failed";
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
        .map_err(|_| "integration::fault_class_bindings: wait_set_add (VM) failed")?;
    wait_set_add(objects.ws, objects.ep_exc, WS_EXC)
        .map_err(|_| "integration::fault_class_bindings: wait_set_add (exception) failed")?;
    routing(ctx, parts, &objects)?;
    partial_unbind(ctx, parts, &objects)?;
    per_class_rebind(ctx, parts, &objects)?;
    inheritance(ctx, parts, &objects)?;
    argument_checks(parts)?;
    rights_checks(parts)
}

/// Phase 1: a page fault and an illegal instruction reach their own classes'
/// endpoints.
fn routing(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let vm = spawn_child(ctx, parts, 0, objects)?;
    bind_split(vm, objects)?;
    start_child(parts, 0, store_entry)?;
    expect_fault_at(ctx, objects, WS_VM, BADGE_VM, FAULT_KIND_VM)?;
    reply(ctx, FAULT_REPLY_KILL)?;
    expect_exit(vm, crate::arch::PAGE_FAULT_STORE_VECTOR)?;

    let exc = spawn_child(ctx, parts, 1, objects)?;
    bind_split(exc, objects)?;
    start_child(parts, 1, illegal_entry)?;
    expect_fault_at(ctx, objects, WS_EXC, BADGE_EXC, FAULT_KIND_EXCEPTION)?;
    reply(ctx, FAULT_REPLY_KILL)?;
    expect_exit(exc, crate::arch::ILLEGAL_INSTRUCTION_VECTOR)
}

/// Phase 2: unbinding the exception class alone leaves the VM class bound
/// and makes an illegal instruction unhandled.
fn partial_unbind(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 2, objects)?;
    crate::bind_fault_handler(th, objects.ep_vm, BADGE_VM)
        .map_err(|_| "integration::fault_class_bindings: bind (all classes) failed")?;
    thread_set_fault_handler(th, 0, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_class_bindings: unbind (exception) failed")?;
    expect_binding(th, FAULT_CLASS_VM, Some(BADGE_VM))?;
    expect_binding(th, FAULT_CLASS_EXCEPTION, None)?;
    start_child(parts, 2, illegal_entry)?;
    expect_exit(th, crate::arch::ILLEGAL_INSTRUCTION_VECTOR)?;
    expect_binding(th, FAULT_CLASS_VM, Some(BADGE_VM))
}

/// Phase 3: rebinding the exception class leaves a held page fault to its
/// reply.
fn per_class_rebind(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 3, objects)?;
    bind_split(th, objects)?;
    start_child(parts, 3, store_entry)?;
    expect_fault_at(ctx, objects, WS_VM, BADGE_VM, FAULT_KIND_VM)?;
    crate::bind_fault_handler_classes(th, objects.ep_other, BADGE_EXC, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_class_bindings: rebind (exception) failed")?;
    resume_into_recovery(ctx, th, objects.sig)
}

/// Phase 4: a per-class copy, then a copy of every class, from a source
/// thread; the copied VM binding delivers the destination's fault.
fn inheritance(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let src = spawn_child(ctx, parts, 4, objects)?;
    crate::bind_fault_handler_classes(src, objects.ep_vm, BADGE_VM, FAULT_CLASS_VM)
        .map_err(|_| "integration::fault_class_bindings: bind source (VM) failed")?;
    let dst = spawn_child(ctx, parts, 5, objects)?;
    crate::bind_fault_handler_classes(dst, objects.ep_exc, BADGE_EXC, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_class_bindings: bind destination (exception) failed")?;

    thread_inherit_fault_handler(dst, src, FAULT_CLASS_VM)
        .map_err(|_| "integration::fault_class_bindings: inherit (VM) failed")?;
    expect_binding(dst, FAULT_CLASS_VM, Some(BADGE_VM))?;
    expect_binding(dst, FAULT_CLASS_EXCEPTION, Some(BADGE_EXC))?;

    thread_inherit_fault_handler(dst, src, FAULT_CLASS_ALL)
        .map_err(|_| "integration::fault_class_bindings: inherit (all classes) failed")?;
    expect_binding(dst, FAULT_CLASS_VM, Some(BADGE_VM))?;
    expect_binding(dst, FAULT_CLASS_EXCEPTION, None)?;

    start_child(parts, 5, store_entry)?;
    expect_fault_at(ctx, objects, WS_VM, BADGE_VM, FAULT_KIND_VM)?;
    reply(ctx, FAULT_REPLY_KILL)?;
    expect_exit(dst, crate::arch::PAGE_FAULT_STORE_VECTOR)
}

/// Phase 5: refused masks and class arguments.
fn argument_checks(parts: &Parts) -> TestResult
{
    let th = parts.children[4]
        .as_ref()
        .ok_or("integration::fault_class_bindings: no source thread")?
        .th;
    let invalid = Err(SyscallError::InvalidArgument as i64);
    for mask in [0, 1 << 3, FAULT_CLASS_VM | (1 << 63)]
    {
        if thread_set_fault_handler(th, 0, mask) != invalid
            || thread_inherit_fault_handler(th, th, mask) != invalid
        {
            return Err("integration::fault_class_bindings: a refused mask was accepted");
        }
    }
    for class in [0, FAULT_CLASS_VM | FAULT_CLASS_EXCEPTION, FAULT_CLASS_ALL]
    {
        if thread_get_fault_handler(th, class) != Err(SyscallError::InvalidArgument as i64)
        {
            return Err("integration::fault_class_bindings: a refused class was accepted");
        }
    }
    Ok(())
}

/// Phase 5, rights: a Thread cap without `CONTROL`, and a handle naming no
/// capability, are refused by the query and as either thread of the copy.
fn rights_checks(parts: &Parts) -> TestResult
{
    let th = parts.children[4]
        .as_ref()
        .ok_or("integration::fault_class_bindings: no source thread")?
        .th;
    let observe = cap_derive(th, RIGHTS_THREAD_OBSERVE)
        .map_err(|_| "integration::fault_class_bindings: cap_derive (observe) failed")?;
    let rights = check_refusals(th, observe, SyscallError::InsufficientRights);
    let deleted = cap_delete(observe)
        .map_err(|_| "integration::fault_class_bindings: cap_delete (observe) failed");
    rights?;
    deleted?;
    // A handle whose slot is empty: the observe cap just deleted.
    check_refusals(th, observe, SyscallError::InvalidCapability)
}

/// Check that `bad`, used with the `CONTROL` cap `th`, is refused with
/// `error` by the query, as the copy's destination, and as its source.
fn check_refusals(th: u64, bad: u64, error: SyscallError) -> TestResult
{
    let refused = Err(error as i64);
    if thread_get_fault_handler(bad, FAULT_CLASS_VM).map(|_| ()) != refused
        || thread_inherit_fault_handler(bad, th, FAULT_CLASS_ALL) != refused
        || thread_inherit_fault_handler(th, bad, FAULT_CLASS_ALL) != refused
    {
        return Err("integration::fault_class_bindings: a refused thread cap was accepted");
    }
    Ok(())
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
    let child = parts
        .children
        .get_mut(index)
        .ok_or("integration::fault_class_bindings: child index out of range")?
        .insert(
            spawn::new_child(ctx).map_err(|_| "integration::fault_class_bindings: spawn failed")?,
        );
    let child_sig = cap_copy(objects.sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::fault_class_bindings: cap_copy notification failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);
    Ok(child.th)
}

/// Configure and start child `index` at `entry`.
fn start_child(parts: &Parts, index: usize, entry: extern "C" fn(u64) -> !) -> TestResult
{
    let child = parts
        .children
        .get(index)
        .and_then(Option::as_ref)
        .ok_or("integration::fault_class_bindings: no child")?;
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), index) }?;
    // SAFETY: the stack is `STACKS[index]`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, entry, stack, 0) }
        .map_err(|_| "integration::fault_class_bindings: start failed")
}

/// Bind `th`'s VM class to the VM endpoint and its exception class to the
/// exception endpoint, each with its own badge.
fn bind_split(th: u64, objects: &Objects) -> TestResult
{
    crate::bind_fault_handler_classes(th, objects.ep_vm, BADGE_VM, FAULT_CLASS_VM)
        .map_err(|_| "integration::fault_class_bindings: bind (VM) failed")?;
    crate::bind_fault_handler_classes(th, objects.ep_exc, BADGE_EXC, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_class_bindings: bind (exception) failed")
}

/// Wait for a fault to reach an endpoint; check through the wait set that it
/// is the one `ws_badge` names, then receive it there and check its badge and
/// kind.
fn expect_fault_at(
    ctx: &TestContext,
    objects: &Objects,
    ws_badge: u64,
    badge: u64,
    kind: u64,
) -> TestResult
{
    let ready = wait_set_wait(objects.ws)
        .map_err(|_| "integration::fault_class_bindings: wait_set_wait failed")?;
    if ready != ws_badge
    {
        return Err(
            "integration::fault_class_bindings: a fault reached the other class's endpoint",
        );
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
        .map_err(|_| "integration::fault_class_bindings: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != badge || msg.word(0) != kind
    {
        return Err("integration::fault_class_bindings: unexpected fault message");
    }
    Ok(())
}

/// Reply `label` to the fault the controller holds.
fn reply(ctx: &TestContext, label: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(label), ctx.ipc_buf) }
        .map_err(|_| "integration::fault_class_bindings: reply failed")
}

/// Check that `th` exits with the fault reason of `vector`.
fn expect_exit(th: u64, vector: u64) -> TestResult
{
    let reason = spawn::wait_until_exited(th, crate::scaled_polls(EXIT_POLLS))
        .map_err(|_| "integration::fault_class_bindings: child never exited")?;
    if Some(reason) != EXIT_FAULT_BASE.checked_add(vector)
    {
        return Err("integration::fault_class_bindings: child exited with the wrong reason");
    }
    Ok(())
}

/// Check `th`'s binding for `class`: bound with `badge`, or unbound.
fn expect_binding(th: u64, class: u64, badge: Option<u64>) -> TestResult
{
    let got = thread_get_fault_handler(th, class)
        .map_err(|_| "integration::fault_class_bindings: thread_get_fault_handler failed")?;
    if got != badge
    {
        return Err("integration::fault_class_bindings: a class reads back the wrong binding");
    }
    Ok(())
}

/// Redirect the fault-blocked `th` into [`recovery_entry`], reply RESUME, and
/// wait for its report on `sig`.
fn resume_into_recovery(ctx: &TestContext, th: u64, sig: u64) -> TestResult
{
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF])
        .map_err(|_| "integration::fault_class_bindings: thread_read_regs failed")?;
    spawn::redirect_to_entry(&mut regs[..], recovery_entry as *const () as u64)?;
    // SAFETY: the frame was read from this child, so its stack pointer lies
    // on the child's own `ChildStack`; `redirect_to_entry` pointed it at
    // `recovery_entry`, an `extern "C"` entry that never returns, with the
    // stack pointer moved down to the entry ABI's alignment on that stack.
    unsafe { thread_write_regs(th, &regs[..BUF]) }
        .map_err(|_| "integration::fault_class_bindings: thread_write_regs failed")?;
    reply(ctx, FAULT_REPLY_RESUME)?;
    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::fault_class_bindings: recovery wait failed")?;
    if bits == 0
    {
        return Err("integration::fault_class_bindings: resumed child never recovered");
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
