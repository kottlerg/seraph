// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/thread_upcall.rs

//! Integration: asynchronous upcalls (docs/fault-handling.md § Asynchronous
//! Upcalls), posted with `SYS_THREAD_POST_UPCALL` and delivered through the
//! upcall class's binding.
//!
//!   1. **No handler.** A post to a thread not yet started, or to one with no
//!      upcall handler bound, is refused with `InvalidState`.
//!   2. **Syscall delivery.** A thread that yields in a loop takes the upcall
//!      at a syscall's return: the handler receives `FAULT_KIND_UPCALL` with
//!      the binding's badge, the poster's cookie, and the syscall point, and
//!      its reply resumes the thread, which yields on.
//!   3. **Nesting and stop.** A post during a delivery is accepted and
//!      delivered after the reply, at the same syscall return; a post to a
//!      stopped thread is kept (a second is `QueueFull`) and delivered once
//!      the thread is started.
//!   4. **Pending.** A thread that makes no syscall keeps a syscall-point
//!      upcall pending, so a second post is refused with `QueueFull`.
//!   5. **Any-instruction delivery.** A thread spinning with no syscall takes
//!      an `UPCALL_ANY_INSTRUCTION` upcall at an interrupt's return; the
//!      handler redirects it into a recovery routine, which reports.
//!   6. **Mask.** A thread that masks upcalls sleeps through a post
//!      uninterrupted and takes the upcall at its unmask's return.
//!   7. **Cancel during block.** A thread blocked in a notification wait, and
//!      one in a sleep, has the wait return `Interrupted` and takes the upcall
//!      at that return.
//!   8. **Recursion.** An upcall posted while the thread's page fault is held
//!      waits for the fault: it is delivered after the fault's reply, at the
//!      thread's next syscall. A stop of the thread during an upcall delivery
//!      drops the upcall: the handler's late reply finds no pending reply, and
//!      after a restart the thread takes a new post.
//!   9. **IPC arms.** A call queued on an endpoint no one receives on returns
//!      `Interrupted` and takes the upcall. So does a call whose message the
//!      controller received and has not replied to: the post claims the
//!      pending reply, so the controller's reply then fails.
//!  10. **Refused park.** A thread that a post reaches while it spins with no
//!      syscall has its next blocking syscall, a notification wait, refused:
//!      the wait returns `Interrupted` at once, and the upcall is delivered at
//!      its return.
//!  11. **Rights.** A Thread cap without `UPCALL` is refused
//!      (`InsufficientRights`), an `UPCALL`-only cap posts at the syscall point
//!      but not with `UPCALL_ANY_INSTRUCTION`, and an undefined flag bit is
//!      refused (`InvalidArgument`), as is a mask argument other than 0 or 1,
//!      which leaves the mask unchanged.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_derive,
    notification_send, notification_wait, notification_wait_timeout, thread_post_upcall,
    thread_read_regs, thread_set_upcall_mask, thread_sleep, thread_start, thread_stop,
    thread_write_regs, thread_yield,
};
use syscall_abi::{
    FAULT_CLASS_UPCALL, FAULT_CLASS_VM, FAULT_KIND_UPCALL, FAULT_KIND_VM, FAULT_LABEL,
    FAULT_REPLY_RESUME, RIGHTS_EP_SEND, RIGHTS_NTF_NOTIFY, RIGHTS_NTF_WAIT, RIGHTS_THREAD_CONTROL,
    RIGHTS_THREAD_OBSERVE, RIGHTS_THREAD_UPCALL, SYS_THREAD_SET_UPCALL_MASK, SyscallError,
    UPCALL_ANY_INSTRUCTION, UPCALL_POINT_INTERRUPT, UPCALL_POINT_SYSCALL,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Unmapped user VA the recursion child stores to; canonical in every paging
/// mode (below the 2^38 Sv39 user half). Distinct from other tests.
const RESERVED_VA: u64 = 0x3E_E000_0000;

/// Badges bound with the upcall and the VM endpoint.
const BADGE_UP: u64 = 0x0B5E_CA11;
const BADGE_VM: u64 = 0x0B5E_CA12;

/// Bound on a wait for a child's progress, in 1 ms polls. Applied through
/// [`crate::scaled_polls`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where a child's CPU waits for a host core.
const PROGRESS_POLLS: u32 = 2000;

/// Bound, in milliseconds, on the wait for the recovery routine's report.
/// Applied through [`crate::scaled_bound`].
const REPORT_MS: u64 = 1000;

/// The masked child's sleep, in milliseconds: long enough that a post lands
/// inside it.
const MASKED_SLEEP_MS: u64 = 100;

/// The sleeping child's sleep, in milliseconds: far past the test's run, so
/// only the upcall's cancel ends it.
const LONG_SLEEP_MS: u64 = 600_000;

/// Register-file buffer size; holds the arch `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Children: 0 yields (syscall delivery, nesting, stop, rights), 1 spins with
/// a pending syscall-point upcall, 2 spins for the any-instruction delivery,
/// 3 masks, 4 waits on a notification, 5 sleeps, 6 faults (recursion), 7 is
/// never started, 8 and 9 call (queued, and awaiting a reply), and 10 spins
/// and then waits (refused park).
const CHILDREN: usize = 11;

static mut STACKS: [ChildStack; CHILDREN] = [ChildStack::ZERO; CHILDREN];

/// The IPC buffer pages of the calling children 8 and 9.
static mut CALL_PAGES: [crate::IpcPage; 2] = [crate::IpcPage::ZERO, crate::IpcPage::ZERO];

/// How long, in milliseconds, the controller lets a calling child reach its
/// park before posting. A child slower than this has its park refused
/// instead, with the same outcome.
const SETTLE_MS: u64 = 20;

/// Child-side progress words, one per child that reports through memory.
static YIELDS: AtomicU64 = AtomicU64::new(0);
static MASK_STAGE: AtomicU64 = AtomicU64::new(0);
static MASK_SLEEP: AtomicU64 = AtomicU64::new(0);
static WAIT_STAGE: AtomicU64 = AtomicU64::new(0);
static WAIT_RESULT: AtomicU64 = AtomicU64::new(0);
static SLEEP_STAGE: AtomicU64 = AtomicU64::new(0);
static SLEEP_RESULT: AtomicU64 = AtomicU64::new(0);
static FAULT_YIELDS: AtomicU64 = AtomicU64::new(0);
static CALL_STAGE: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static CALL_RESULT: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static REFUSE_STAGE: AtomicU64 = AtomicU64::new(0);
static REFUSE_GO: AtomicU64 = AtomicU64::new(0);
static REFUSE_RESULT: AtomicU64 = AtomicU64::new(0);

/// Child cap slots of the endpoints the calling children call, and of the
/// notification the refused-park child waits on.
static CALL_EP: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static REFUSE_NEVER: AtomicU64 = AtomicU64::new(0);

/// Child cap slot of the report notification, read by [`recovery_entry`].
static RECOVERY_SIG: AtomicU64 = AtomicU64::new(0);

/// A blocking call's result as a progress word reads it.
const RESULT_OK: u64 = 1;
const RESULT_INTERRUPTED: u64 = 2;
const RESULT_OTHER: u64 = 3;

/// The caps and children the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    ep_up: Option<u64>,
    ep_vm: Option<u64>,
    ep_queued: Option<u64>,
    ep_held: Option<u64>,
    sig: Option<u64>,
    never: Option<u64>,
    children: [Option<spawn::SpawnedChild>; CHILDREN],
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
        parts.ep_up,
        parts.ep_vm,
        parts.ep_queued,
        parts.ep_held,
        parts.sig,
        parts.never,
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
        Err("integration::thread_upcall: teardown failed")
    }
}

fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let fail = |_| "integration::thread_upcall: object creation failed";
    let ep_up = *parts
        .ep_up
        .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?);
    let ep_vm = *parts
        .ep_vm
        .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?);
    let sig = *parts
        .sig
        .insert(cap_create_notification(ctx.memory_base).map_err(fail)?);
    let never = *parts
        .never
        .insert(cap_create_notification(ctx.memory_base).map_err(fail)?);

    no_handler(ctx, parts, ep_up)?;
    let yielder = parts.children[0]
        .as_ref()
        .ok_or("integration::thread_upcall: no yielding child")?
        .th;
    syscall_delivery(ctx, yielder, ep_up)?;
    nesting_and_stop(ctx, yielder, ep_up)?;
    pending(ctx, parts, ep_up)?;
    any_instruction(ctx, parts, ep_up, sig)?;
    mask(ctx, parts, ep_up)?;
    cancel_during_block(ctx, parts, ep_up, never)?;
    recursion(ctx, parts, ep_up, ep_vm)?;
    let ep_queued = *parts
        .ep_queued
        .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?);
    let ep_held = *parts
        .ep_held
        .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?);
    ipc_arms(ctx, parts, ep_up, [ep_queued, ep_held])?;
    refused_park(ctx, parts, ep_up, never)?;
    rights(ctx, yielder, ep_up)
}

/// Phase 1: no handler bound, or a thread not yet started.
fn no_handler(ctx: &TestContext, parts: &mut Parts, ep_up: u64) -> TestResult
{
    let refused = Err(SyscallError::InvalidState as i64);
    let unstarted = spawn_child(ctx, parts, 7)?;
    bind_upcall(unstarted, ep_up)?;
    if thread_post_upcall(unstarted, 1, 0) != refused
    {
        return Err("integration::thread_upcall: a post to an unstarted thread was accepted");
    }
    let th = spawn_child(ctx, parts, 0)?;
    start_child(parts, 0, yield_entry, 0)?;
    wait_for(&YIELDS, 1)?;
    if thread_post_upcall(th, 1, 0) != refused
    {
        return Err("integration::thread_upcall: a post with no handler bound was accepted");
    }
    bind_upcall(th, ep_up)
}

/// Phase 2: delivery at a syscall's return, then resume.
fn syscall_delivery(ctx: &TestContext, th: u64, ep_up: u64) -> TestResult
{
    thread_post_upcall(th, 0x5150_0001, 0)
        .map_err(|_| "integration::thread_upcall: post (syscall point) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0001, UPCALL_POINT_SYSCALL)?;
    let before = YIELDS.load(Ordering::Acquire);
    reply_resume(ctx)?;
    wait_for(
        &YIELDS,
        before
            .checked_add(1)
            .ok_or("integration::thread_upcall: yield count overflows")?,
    )
}

/// Phase 3: a post during a delivery, and a post to a stopped thread.
fn nesting_and_stop(ctx: &TestContext, th: u64, ep_up: u64) -> TestResult
{
    thread_post_upcall(th, 0x5150_0011, 0)
        .map_err(|_| "integration::thread_upcall: post (first) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0011, UPCALL_POINT_SYSCALL)?;
    thread_post_upcall(th, 0x5150_0012, 0)
        .map_err(|_| "integration::thread_upcall: a post during a delivery was refused")?;
    reply_resume(ctx)?;
    expect_upcall(ctx, ep_up, 0x5150_0012, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)?;

    thread_stop(th).map_err(|_| "integration::thread_upcall: thread_stop (yielder) failed")?;
    let posted = thread_post_upcall(th, 0x5150_0013, 0);
    let second = thread_post_upcall(th, 0x5150_0014, 0);
    thread_start(th).map_err(|_| "integration::thread_upcall: thread_start (yielder) failed")?;
    if posted.is_err() || second != Err(SyscallError::QueueFull as i64)
    {
        return Err("integration::thread_upcall: a stopped thread did not keep its upcall");
    }
    expect_upcall(ctx, ep_up, 0x5150_0013, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)
}

/// Phase 4: a syscall-point upcall stays pending on a thread that makes no
/// syscall, and a second post is refused.
fn pending(ctx: &TestContext, parts: &mut Parts, ep_up: u64) -> TestResult
{
    let th = spawn_child(ctx, parts, 1)?;
    bind_upcall(th, ep_up)?;
    start_child(parts, 1, spin_entry, 0)?;
    thread_post_upcall(th, 0x5150_0002, 0)
        .map_err(|_| "integration::thread_upcall: post (pending) failed")?;
    if thread_post_upcall(th, 0x5150_0003, 0) != Err(SyscallError::QueueFull as i64)
    {
        return Err("integration::thread_upcall: a second pending post was accepted");
    }
    Ok(())
}

/// Phase 5: delivery at an interrupt's return to a thread that spins, and a
/// redirect into the recovery routine.
fn any_instruction(ctx: &TestContext, parts: &mut Parts, ep_up: u64, sig: u64) -> TestResult
{
    let th = spawn_child(ctx, parts, 2)?;
    bind_upcall(th, ep_up)?;
    let child_sig = cap_copy(sig, child_cs(parts, 2)?, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::thread_upcall: cap_copy notification failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);
    start_child(parts, 2, spin_entry, 0)?;
    thread_post_upcall(th, 0x5150_0004, UPCALL_ANY_INSTRUCTION)
        .map_err(|_| "integration::thread_upcall: post (any instruction) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0004, UPCALL_POINT_INTERRUPT)?;
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF])
        .map_err(|_| "integration::thread_upcall: thread_read_regs failed")?;
    spawn::redirect_to_entry(&mut regs[..], recovery_entry as *const () as u64)?;
    // SAFETY: the frame was read from this child, so its stack pointer lies on
    // the child's own `ChildStack`; `redirect_to_entry` pointed it at
    // `recovery_entry`, an `extern "C"` entry that never returns, with the
    // stack pointer moved down to the entry ABI's alignment on that stack.
    unsafe { thread_write_regs(th, &regs[..BUF]) }
        .map_err(|_| "integration::thread_upcall: thread_write_regs failed")?;
    reply_resume(ctx)?;
    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::thread_upcall: recovery wait failed")?;
    if bits == 0
    {
        return Err("integration::thread_upcall: redirected child never recovered");
    }
    Ok(())
}

/// Phase 6: a masked thread's sleep is not interrupted, and the upcall is
/// delivered at the unmask's return.
fn mask(ctx: &TestContext, parts: &mut Parts, ep_up: u64) -> TestResult
{
    let th = spawn_child(ctx, parts, 3)?;
    bind_upcall(th, ep_up)?;
    start_child(parts, 3, masked_entry, 0)?;
    wait_for(&MASK_STAGE, 1)?;
    thread_post_upcall(th, 0x5150_0005, 0)
        .map_err(|_| "integration::thread_upcall: post (masked) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0005, UPCALL_POINT_SYSCALL)?;
    if MASK_STAGE.load(Ordering::Acquire) != 2 || MASK_SLEEP.load(Ordering::Acquire) != RESULT_OK
    {
        return Err("integration::thread_upcall: a masked thread took the upcall early");
    }
    reply_resume(ctx)?;
    wait_for(&MASK_STAGE, 3)
}

/// Phase 7: a notification wait and a sleep return `Interrupted`, and the
/// upcall is delivered at that return.
fn cancel_during_block(ctx: &TestContext, parts: &mut Parts, ep_up: u64, never: u64) -> TestResult
{
    let waiter = spawn_child(ctx, parts, 4)?;
    bind_upcall(waiter, ep_up)?;
    let child_never = cap_copy(never, child_cs(parts, 4)?, RIGHTS_NTF_WAIT)
        .map_err(|_| "integration::thread_upcall: cap_copy notification failed")?;
    start_child(parts, 4, wait_entry, child_never)?;
    wait_for(&WAIT_STAGE, 1)?;
    thread_post_upcall(waiter, 0x5150_0006, 0)
        .map_err(|_| "integration::thread_upcall: post (waiter) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0006, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)?;
    wait_for(&WAIT_STAGE, 2)?;
    if WAIT_RESULT.load(Ordering::Acquire) != RESULT_INTERRUPTED
    {
        return Err("integration::thread_upcall: an interrupted wait did not fail Interrupted");
    }

    let sleeper = spawn_child(ctx, parts, 5)?;
    bind_upcall(sleeper, ep_up)?;
    start_child(parts, 5, sleep_entry, 0)?;
    wait_for(&SLEEP_STAGE, 1)?;
    thread_post_upcall(sleeper, 0x5150_0007, 0)
        .map_err(|_| "integration::thread_upcall: post (sleeper) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0007, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)?;
    wait_for(&SLEEP_STAGE, 2)?;
    if SLEEP_RESULT.load(Ordering::Acquire) != RESULT_INTERRUPTED
    {
        return Err("integration::thread_upcall: an interrupted sleep did not fail Interrupted");
    }
    Ok(())
}

/// Phase 8: an upcall waits for a held fault, and a stop during an upcall
/// delivery drops the upcall.
fn recursion(ctx: &TestContext, parts: &mut Parts, ep_up: u64, ep_vm: u64) -> TestResult
{
    let th = spawn_child(ctx, parts, 6)?;
    bind_upcall(th, ep_up)?;
    crate::bind_fault_handler_classes(th, ep_vm, BADGE_VM, FAULT_CLASS_VM)
        .map_err(|_| "integration::thread_upcall: bind (VM) failed")?;
    start_child(parts, 6, store_entry, 0)?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let fault = unsafe { ipc::ipc_recv(ep_vm, ctx.ipc_buf) }
        .map_err(|_| "integration::thread_upcall: ipc_recv (fault) failed")?;
    if fault.label != FAULT_LABEL || fault.badge != BADGE_VM || fault.word(0) != FAULT_KIND_VM
    {
        return Err("integration::thread_upcall: unexpected fault message");
    }
    // The upcall stays pending while the fault is held.
    thread_post_upcall(th, 0x5150_0008, 0)
        .map_err(|_| "integration::thread_upcall: post (held fault) failed")?;
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF])
        .map_err(|_| "integration::thread_upcall: thread_read_regs (fault) failed")?;
    spawn::redirect_to_entry(&mut regs[..], fault_yield_entry as *const () as u64)?;
    // SAFETY: as in phase 5; `fault_yield_entry` never returns.
    unsafe { thread_write_regs(th, &regs[..BUF]) }
        .map_err(|_| "integration::thread_upcall: thread_write_regs (fault) failed")?;
    reply_resume(ctx)?;
    expect_upcall(ctx, ep_up, 0x5150_0008, UPCALL_POINT_SYSCALL)?;
    if FAULT_YIELDS.load(Ordering::Acquire) == 0
    {
        return Err("integration::thread_upcall: the upcall did not wait for the fault");
    }

    // A stop during the delivery drops the upcall.
    thread_stop(th).map_err(|_| "integration::thread_upcall: thread_stop failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    if unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }.is_ok()
    {
        return Err("integration::thread_upcall: a stopped delivery took its reply");
    }
    thread_start(th).map_err(|_| "integration::thread_upcall: thread_start failed")?;
    let before = FAULT_YIELDS.load(Ordering::Acquire);
    wait_for(
        &FAULT_YIELDS,
        before
            .checked_add(1)
            .ok_or("integration::thread_upcall: fault-yield count overflows")?,
    )?;
    thread_post_upcall(th, 0x5150_0009, 0)
        .map_err(|_| "integration::thread_upcall: post after a dropped upcall failed")?;
    expect_upcall(ctx, ep_up, 0x5150_0009, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)
}

/// Phase 9: a call queued on an endpoint (`eps[0]`), and a call awaiting its
/// reply (`eps[1]`, whose message the controller receives).
fn ipc_arms(ctx: &TestContext, parts: &mut Parts, ep_up: u64, eps: [u64; 2]) -> TestResult
{
    for (k, ep) in eps.into_iter().enumerate()
    {
        let (Some(index), Some(cookie), Some(call_ep), Some(stage), Some(result)) = (
            k.checked_add(8),
            0x5150_0020u64.checked_add(k as u64),
            CALL_EP.get(k),
            CALL_STAGE.get(k),
            CALL_RESULT.get(k),
        )
        else
        {
            return Err("integration::thread_upcall: call arm index out of range");
        };
        let th = spawn_child(ctx, parts, index)?;
        bind_upcall(th, ep_up)?;
        let slot = cap_copy(ep, child_cs(parts, index)?, RIGHTS_EP_SEND)
            .map_err(|_| "integration::thread_upcall: cap_copy endpoint failed")?;
        call_ep.store(slot, Ordering::Release);
        start_child(parts, index, call_entry, k as u64)?;
        wait_for(stage, 1)?;
        if k == 1
        {
            // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
            unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
                .map_err(|_| "integration::thread_upcall: ipc_recv (call) failed")?;
        }
        else
        {
            let _ = thread_sleep(SETTLE_MS);
        }
        thread_post_upcall(th, cookie, 0)
            .map_err(|_| "integration::thread_upcall: post (caller) failed")?;
        // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
        if k == 1 && unsafe { ipc::ipc_reply(&IpcMessage::new(0), ctx.ipc_buf) }.is_ok()
        {
            return Err("integration::thread_upcall: the post left the call's reply pending");
        }
        expect_upcall(ctx, ep_up, cookie, UPCALL_POINT_SYSCALL)?;
        reply_resume(ctx)?;
        wait_for(stage, 2)?;
        if result.load(Ordering::Acquire) != RESULT_INTERRUPTED
        {
            return Err("integration::thread_upcall: an interrupted call did not fail Interrupted");
        }
    }
    Ok(())
}

/// Phase 10: a post that finds the thread running refuses its next park.
fn refused_park(ctx: &TestContext, parts: &mut Parts, ep_up: u64, never: u64) -> TestResult
{
    let th = spawn_child(ctx, parts, 10)?;
    bind_upcall(th, ep_up)?;
    let slot = cap_copy(never, child_cs(parts, 10)?, RIGHTS_NTF_WAIT)
        .map_err(|_| "integration::thread_upcall: cap_copy notification failed")?;
    REFUSE_NEVER.store(slot, Ordering::Release);
    start_child(parts, 10, refuse_entry, 0)?;
    wait_for(&REFUSE_STAGE, 1)?;
    thread_post_upcall(th, 0x5150_0030, 0)
        .map_err(|_| "integration::thread_upcall: post (spinning) failed")?;
    REFUSE_GO.store(1, Ordering::Release);
    expect_upcall(ctx, ep_up, 0x5150_0030, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)?;
    wait_for(&REFUSE_STAGE, 2)?;
    if REFUSE_RESULT.load(Ordering::Acquire) != RESULT_INTERRUPTED
    {
        return Err("integration::thread_upcall: a refused park did not fail Interrupted");
    }
    Ok(())
}

/// Phase 11: the rights a post needs, its flag check, and the mask's argument
/// check.
fn rights(ctx: &TestContext, th: u64, ep_up: u64) -> TestResult
{
    let observe = cap_derive(th, RIGHTS_THREAD_OBSERVE | RIGHTS_THREAD_CONTROL)
        .map_err(|_| "integration::thread_upcall: cap_derive (no upcall) failed")?;
    let without = thread_post_upcall(observe, 1, 0);
    let deleted = cap_delete(observe);
    if without != Err(SyscallError::InsufficientRights as i64) || deleted.is_err()
    {
        return Err("integration::thread_upcall: a post without UPCALL was accepted");
    }
    if thread_post_upcall(th, 1, 1 << 1) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("integration::thread_upcall: an undefined flag was accepted");
    }
    // SAFETY: raw_syscall3's four conditions hold: SYS_THREAD_SET_UPCALL_MASK
    // takes no pointer and uses no IPC buffer, changes no mapping and no
    // CSpace slot, and acts only on the calling thread, whose mask a refused
    // argument leaves unchanged.
    let refused = unsafe { syscall::raw_syscall3(SYS_THREAD_SET_UPCALL_MASK, 2, 0, 0) };
    let unchanged = thread_set_upcall_mask(false);
    if refused != SyscallError::InvalidArgument as i64 || unchanged != Ok(false)
    {
        return Err("integration::thread_upcall: a mask argument other than 0 or 1 was accepted");
    }
    let upcall_only = cap_derive(th, RIGHTS_THREAD_UPCALL)
        .map_err(|_| "integration::thread_upcall: cap_derive (upcall) failed")?;
    let result = upcall_only_posts(ctx, upcall_only, ep_up);
    let deleted = cap_delete(upcall_only)
        .map_err(|_| "integration::thread_upcall: cap_delete (upcall) failed");
    result?;
    deleted
}

/// With an `UPCALL`-only cap: no `UPCALL_ANY_INSTRUCTION` post, and a
/// syscall-point post that is delivered.
fn upcall_only_posts(ctx: &TestContext, cap: u64, ep_up: u64) -> TestResult
{
    if thread_post_upcall(cap, 1, UPCALL_ANY_INSTRUCTION)
        != Err(SyscallError::InsufficientRights as i64)
    {
        return Err(
            "integration::thread_upcall: an any-instruction post without CONTROL was accepted",
        );
    }
    thread_post_upcall(cap, 0x5150_000A, 0)
        .map_err(|_| "integration::thread_upcall: post (upcall-only cap) failed")?;
    expect_upcall(ctx, ep_up, 0x5150_000A, UPCALL_POINT_SYSCALL)?;
    reply_resume(ctx)
}

/// Spawn child `index`; returns its Thread cap. The child is configured and
/// started by [`start_child`].
fn spawn_child(ctx: &TestContext, parts: &mut Parts, index: usize) -> Result<u64, &'static str>
{
    let child = parts
        .children
        .get_mut(index)
        .ok_or("integration::thread_upcall: child index out of range")?
        .insert(spawn::new_child(ctx).map_err(|_| "integration::thread_upcall: spawn failed")?);
    Ok(child.th)
}

/// The `CSpace` of child `index`.
fn child_cs(parts: &Parts, index: usize) -> Result<u64, &'static str>
{
    Ok(parts
        .children
        .get(index)
        .and_then(Option::as_ref)
        .ok_or("integration::thread_upcall: no child")?
        .cs)
}

/// Configure and start child `index` at `entry(arg)`.
fn start_child(parts: &Parts, index: usize, entry: extern "C" fn(u64) -> !, arg: u64)
-> TestResult
{
    let child = parts
        .children
        .get(index)
        .and_then(Option::as_ref)
        .ok_or("integration::thread_upcall: no child")?;
    let stack = ChildStack::top_at(core::ptr::addr_of!(STACKS), index)?;
    // SAFETY: the stack is `STACKS[index]`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, entry, stack, arg) }
        .map_err(|_| "integration::thread_upcall: start failed")
}

/// Bind `th`'s upcall class to `ep_up` with [`BADGE_UP`].
fn bind_upcall(th: u64, ep_up: u64) -> TestResult
{
    crate::bind_fault_handler_classes(th, ep_up, BADGE_UP, FAULT_CLASS_UPCALL)
        .map_err(|_| "integration::thread_upcall: bind (upcall) failed")
}

/// Receive an upcall on `ep_up` and check its badge, kind, cookie, and
/// delivery point.
fn expect_upcall(ctx: &TestContext, ep_up: u64, cookie: u64, point: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep_up, ctx.ipc_buf) }
        .map_err(|_| "integration::thread_upcall: ipc_recv (upcall) failed")?;
    if msg.label != FAULT_LABEL || msg.badge != BADGE_UP || msg.word(0) != FAULT_KIND_UPCALL
    {
        return Err("integration::thread_upcall: unexpected upcall message");
    }
    if msg.word(1) != cookie
    {
        return Err("integration::thread_upcall: an upcall carried the wrong cookie");
    }
    if msg.word(2) != point
    {
        return Err("integration::thread_upcall: an upcall arrived at the wrong point");
    }
    Ok(())
}

/// Reply RESUME to the upcall or fault the controller holds.
fn reply_resume(ctx: &TestContext) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::thread_upcall: reply failed")
}

/// Wait, in 1 ms sleeps, until `word` reaches at least `value`.
fn wait_for(word: &AtomicU64, value: u64) -> TestResult
{
    for _ in 0..crate::scaled_polls(PROGRESS_POLLS)
    {
        if word.load(Ordering::Acquire) >= value
        {
            return Ok(());
        }
        let _ = thread_sleep(1);
    }
    Err("integration::thread_upcall: a child made no progress")
}

/// The progress word of a blocking call's result.
fn result_word(result: Result<u64, i64>) -> u64
{
    match result
    {
        Ok(_) => RESULT_OK,
        Err(e) if e == SyscallError::Interrupted as i64 => RESULT_INTERRUPTED,
        Err(_) => RESULT_OTHER,
    }
}

/// Child entry: yield in a loop, counting.
extern "C" fn yield_entry(_arg: u64) -> !
{
    loop
    {
        YIELDS.fetch_add(1, Ordering::Release);
        let _ = thread_yield();
    }
}

/// Child entry: register IPC page `k` and call the endpoint published for
/// child `8 + k`, recording the result.
extern "C" fn call_entry(k: u64) -> !
{
    #[expect(
        clippy::cast_possible_truncation,
        reason = "k is 0 or 1, the index start_child passed"
    )]
    let k = k as usize;
    let (Some(page), Some(stage), Some(result), Some(call_ep)) = (
        crate::elem_ptr_mut(core::ptr::addr_of_mut!(CALL_PAGES), k),
        CALL_STAGE.get(k),
        CALL_RESULT.get(k),
        CALL_EP.get(k),
    )
    else
    {
        syscall::thread_exit()
    };
    // Page `k` belongs to this child alone (one calling child per page, each
    // run once), and no reference to it is formed.
    let buf = page.cast::<u64>();
    // SAFETY: `buf` is this thread's own page-aligned IPC page, registered by
    // one thread at a time; no Rust object lives in it, and the thread
    // reaches it only through the raw `buf` pointer.
    if unsafe { syscall::ipc_buffer_set(buf as u64) }.is_err()
    {
        syscall::thread_exit()
    }
    stage.store(1, Ordering::Release);
    let ep = call_ep.load(Ordering::Acquire);
    // SAFETY: `buf` was registered as this thread's IPC buffer above.
    let called = unsafe { ipc::ipc_call(ep, &IpcMessage::new(0), buf) };
    result.store(result_word(called.map(|_| 0)), Ordering::Release);
    stage.store(2, Ordering::Release);
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: spin with no syscall until released, then wait on the
/// notification that nothing signals.
extern "C" fn refuse_entry(_arg: u64) -> !
{
    REFUSE_STAGE.store(1, Ordering::Release);
    while REFUSE_GO.load(Ordering::Acquire) == 0
    {
        core::hint::spin_loop();
    }
    let waited = result_word(notification_wait(REFUSE_NEVER.load(Ordering::Acquire)));
    REFUSE_RESULT.store(waited, Ordering::Release);
    REFUSE_STAGE.store(2, Ordering::Release);
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: spin with no syscall.
extern "C" fn spin_entry(_arg: u64) -> !
{
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: mask upcalls, sleep, then unmask.
extern "C" fn masked_entry(_arg: u64) -> !
{
    let _ = thread_set_upcall_mask(true);
    MASK_STAGE.store(1, Ordering::Release);
    let slept = result_word(thread_sleep(MASKED_SLEEP_MS).map(|()| 0));
    MASK_SLEEP.store(slept, Ordering::Release);
    MASK_STAGE.store(2, Ordering::Release);
    let _ = thread_set_upcall_mask(false);
    MASK_STAGE.store(3, Ordering::Release);
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: wait on the notification in slot `never`, which nothing
/// signals.
extern "C" fn wait_entry(never: u64) -> !
{
    WAIT_STAGE.store(1, Ordering::Release);
    let waited = result_word(notification_wait(never));
    WAIT_RESULT.store(waited, Ordering::Release);
    WAIT_STAGE.store(2, Ordering::Release);
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: sleep far past the test's run.
extern "C" fn sleep_entry(_arg: u64) -> !
{
    SLEEP_STAGE.store(1, Ordering::Release);
    let slept = result_word(thread_sleep(LONG_SLEEP_MS).map(|()| 0));
    SLEEP_RESULT.store(slept, Ordering::Release);
    SLEEP_STAGE.store(2, Ordering::Release);
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: store to the reserved VA, which faults; the fault's handler
/// redirects the thread into [`fault_yield_entry`].
extern "C" fn store_entry(_arg: u64) -> !
{
    let p = RESERVED_VA as *mut u64;
    // SAFETY: deliberately faulting — the page is never backed.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry a resumed fault is redirected into: yield in a loop, counting.
extern "C" fn fault_yield_entry(_arg: u64) -> !
{
    loop
    {
        FAULT_YIELDS.fetch_add(1, Ordering::Release);
        let _ = thread_yield();
    }
}

/// Recovery routine the any-instruction upcall's handler redirects into:
/// report through the published notification cap.
extern "C" fn recovery_entry(_arg: u64) -> !
{
    let _ = notification_send(RECOVERY_SIG.load(Ordering::Acquire), 1);
    loop
    {
        core::hint::spin_loop();
    }
}
