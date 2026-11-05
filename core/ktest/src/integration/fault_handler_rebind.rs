// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_handler_rebind.rs

//! Integration: a change of a thread's fault-handler binding while a fault is
//! in flight cancels that delivery, and the fault is delivered again under the
//! binding current then; with none bound, the fault is unhandled
//! (docs/fault-handling.md § Delivery, Resume, and Kill).
//!
//! Four phases, each with its own faulter, which stores to an unmapped VA:
//!
//!   1. **Clear, received.** The controller receives the fault and does not
//!      reply, then clears the binding. The faulter must reach `Exited` with
//!      the fault exit reason, and the controller's late reply must find no
//!      pending reply (`InvalidCapability`).
//!   2. **Clear, queued.** Nobody receives; the faulter, still alive with its
//!      fault queued on the endpoint, must reach `Exited` with the fault exit
//!      reason once the binding is cleared.
//!   3. **Rebind, received.** The controller receives the fault through the
//!      first endpoint and rebinds the faulter to a second endpoint with
//!      another badge. The late reply through the first binding must find no
//!      pending reply; the fault must arrive again on the second endpoint with
//!      its badge and the same faulting address; a resume there, after the
//!      controller redirects the faulter's instruction pointer, must run the
//!      recovery routine.
//!   4. **Rebind, identical.** The controller receives the fault and rebinds
//!      the faulter to the same endpoint and badge, which cancels nothing: its
//!      reply must claim the fault and resume the faulter at the redirected
//!      instruction pointer.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait_timeout,
    thread_read_regs, thread_set_fault_handler, thread_sleep, thread_write_regs,
};
use syscall_abi::{
    EXIT_FAULT_BASE, FAULT_CLASS_ALL, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_RESUME,
    RIGHTS_NTF_NOTIFY, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Unmapped user VA every faulter stores to; canonical in every paging mode
/// (below the 2^38 Sv39 user half). Distinct from other tests.
const RESERVED_VA: u64 = 0x3E_C000_0000;

/// Badges bound with the first and the second endpoint.
const BADGE_FIRST: u64 = 0xC0FF_EE08;
const BADGE_SECOND: u64 = 0xC0FF_EE09;

/// Wait for the queued faulter to fault before the clear. The phase does not
/// depend on it for its verdict, only for exercising the queued delivery: a
/// fault taken after the clear finds no handler and is killed with the same
/// reason.
const SETTLE_SLEEP_MS: u64 = 20;

/// Bound on the wait for a faulter to exit, in 1 ms polls. Applied through
/// [`crate::scaled_polls`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where a child's CPU waits for a host core.
const EXIT_POLLS: u32 = 2000;

/// Bound, in milliseconds, on the wait for the recovery routine's report.
/// Applied through [`crate::scaled_bound`], which stretches it the same way.
const RECOVERY_MS: u64 = 1000;

/// Register-file buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Phase count; each phase's faulter has its own stack.
const PHASES: usize = 4;

static mut FAULTER_STACKS: [ChildStack; PHASES] = [ChildStack::ZERO; PHASES];

/// Child cap slot of the recovery notification, read by [`recovery_entry`]
/// after the controller redirects a faulter into it.
static RECOVERY_SIG: AtomicU64 = AtomicU64::new(0);

/// The caps and faulters the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    first: Option<u64>,
    second: Option<u64>,
    sig: Option<u64>,
    faulters: [Option<spawn::SpawnedChild>; PHASES],
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = phases(ctx, &mut parts);
    // Deleting a thread tears the child down wherever it is, so the stacks
    // are free for the next test even when a step failed.
    let mut ok = true;
    for child in parts.faulters.iter_mut().flatten()
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
        Err("integration::fault_handler_rebind: teardown failed")
    }
}

/// Create the shared objects and run the four phases.
fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let first = *parts.first.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::fault_handler_rebind: create first endpoint failed")?,
    );
    let second = *parts.second.insert(
        cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "integration::fault_handler_rebind: create second endpoint failed")?,
    );
    let sig = *parts.sig.insert(
        cap_create_notification(ctx.memory_base)
            .map_err(|_| "integration::fault_handler_rebind: create notification failed")?,
    );
    clear_received(ctx, parts, first)?;
    clear_queued(ctx, parts, first)?;
    rebind_received(ctx, parts, first, second, sig)?;
    rebind_identical(ctx, parts, first, sig)
}

/// Phase 1: clear the binding of a faulter whose fault the controller holds.
fn clear_received(ctx: &TestContext, parts: &mut Parts, ep: u64) -> TestResult
{
    let th = start_faulter(ctx, parts, 0, ep, None)?;
    receive_fault(ctx, ep, BADGE_FIRST)?;
    if spawn::is_exited(th).map_err(|_| "integration::fault_handler_rebind: cap_info failed")?
    {
        return Err("integration::fault_handler_rebind: faulter exited before the clear");
    }
    thread_set_fault_handler(th, 0, FAULT_CLASS_ALL)
        .map_err(|_| "integration::fault_handler_rebind: clear (received) failed")?;
    expect_fault_exit(th)?;
    expect_no_pending_reply(ctx)
}

/// Phase 2: clear the binding of a faulter whose fault is queued unreceived.
fn clear_queued(ctx: &TestContext, parts: &mut Parts, ep: u64) -> TestResult
{
    let th = start_faulter(ctx, parts, 1, ep, None)?;
    thread_sleep(SETTLE_SLEEP_MS)
        .map_err(|_| "integration::fault_handler_rebind: settle sleep failed")?;
    if spawn::is_exited(th).map_err(|_| "integration::fault_handler_rebind: cap_info failed")?
    {
        return Err("integration::fault_handler_rebind: queued faulter exited before the clear");
    }
    thread_set_fault_handler(th, 0, FAULT_CLASS_ALL)
        .map_err(|_| "integration::fault_handler_rebind: clear (queued) failed")?;
    expect_fault_exit(th)
}

/// Phase 3: rebind a faulter whose fault the controller holds to a second
/// endpoint, and resolve the redelivered fault there.
fn rebind_received(
    ctx: &TestContext,
    parts: &mut Parts,
    first: u64,
    second: u64,
    sig: u64,
) -> TestResult
{
    let th = start_faulter(ctx, parts, 2, first, Some(sig))?;
    receive_fault(ctx, first, BADGE_FIRST)?;
    crate::bind_fault_handler(th, second, BADGE_SECOND)
        .map_err(|_| "integration::fault_handler_rebind: rebind to the second endpoint failed")?;
    expect_no_pending_reply(ctx)?;
    receive_fault(ctx, second, BADGE_SECOND)?;
    resume_into_recovery(ctx, th, sig)
}

/// Phase 4: rebind a faulter whose fault the controller holds to the same
/// endpoint and badge, and resolve the fault with the original reply.
fn rebind_identical(ctx: &TestContext, parts: &mut Parts, ep: u64, sig: u64) -> TestResult
{
    let th = start_faulter(ctx, parts, 3, ep, Some(sig))?;
    receive_fault(ctx, ep, BADGE_FIRST)?;
    crate::bind_fault_handler(th, ep, BADGE_FIRST)
        .map_err(|_| "integration::fault_handler_rebind: identical rebind failed")?;
    resume_into_recovery(ctx, th, sig)
}

/// Spawn phase `index`'s faulter, bind it to `ep` with [`BADGE_FIRST`], and
/// start it; with `sig`, publish a copy of `sig` for its recovery routine.
/// Returns its Thread cap.
fn start_faulter(
    ctx: &TestContext,
    parts: &mut Parts,
    index: usize,
    ep: u64,
    sig: Option<u64>,
) -> Result<u64, &'static str>
{
    let child = parts.faulters[index].insert(
        spawn::new_child(ctx)
            .map_err(|_| "integration::fault_handler_rebind: spawn faulter failed")?,
    );
    if let Some(sig) = sig
    {
        let child_sig = cap_copy(sig, child.cs, RIGHTS_NTF_NOTIFY)
            .map_err(|_| "integration::fault_handler_rebind: cap_copy notification failed")?;
        RECOVERY_SIG.store(child_sig, Ordering::Release);
    }
    crate::bind_fault_handler(child.th, ep, BADGE_FIRST)
        .map_err(|_| "integration::fault_handler_rebind: bind failed")?;
    // SAFETY: stack `index` belongs to this phase's faulter, deleted before
    // this test returns.
    let stack = ChildStack::top(unsafe { core::ptr::addr_of!(FAULTER_STACKS[index]) });
    // SAFETY: the stack is `FAULTER_STACKS[index]`, this test's own
    // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, faulter_entry, stack, 0) }
        .map_err(|_| "integration::fault_handler_rebind: start faulter failed")?;
    Ok(child.th)
}

/// Receive a fault on `ep` and check that it is the faulters' store fault,
/// delivered with `badge`.
fn receive_fault(ctx: &TestContext, ep: u64, badge: u64) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::fault_handler_rebind: fault ipc_recv failed")?;
    if msg.label != FAULT_LABEL
        || msg.badge != badge
        || msg.word(0) != FAULT_KIND_VM
        || msg.word(1) != RESERVED_VA
    {
        return Err("integration::fault_handler_rebind: unexpected fault message");
    }
    Ok(())
}

/// Check that `th` exits with the store fault's exit reason.
fn expect_fault_exit(th: u64) -> TestResult
{
    let reason = spawn::wait_until_exited(th, crate::scaled_polls(EXIT_POLLS))
        .map_err(|_| "integration::fault_handler_rebind: unbound faulter never exited")?;
    if reason != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
    {
        return Err("integration::fault_handler_rebind: unbound faulter exited with wrong reason");
    }
    Ok(())
}

/// Check that a reply now finds no pending reply: the binding change claimed
/// the fault the controller received.
fn expect_no_pending_reply(ctx: &TestContext) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let late = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) };
    if late != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("integration::fault_handler_rebind: late reply found a pending fault");
    }
    Ok(())
}

/// Redirect the fault-blocked `th` into [`recovery_entry`], reply RESUME, and
/// wait for the recovery routine's report on `sig`.
fn resume_into_recovery(ctx: &TestContext, th: u64, sig: u64) -> TestResult
{
    let mut reg_buf = [0u8; BUF];
    thread_read_regs(th, &mut reg_buf[..BUF])
        .map_err(|_| "integration::fault_handler_rebind: thread_read_regs failed")?;
    spawn::redirect_to_entry(&mut reg_buf[..], recovery_entry as *const () as u64);
    // SAFETY: the frame was read from this faulter, so its stack pointer lies
    // on the faulter's own `ChildStack`; `redirect_to_entry` pointed it at
    // `recovery_entry`, an `extern "C"` entry that never returns and needs
    // nothing of the abandoned frame, with the stack pointer moved down to the
    // entry ABI's alignment on that same stack.
    unsafe { thread_write_regs(th, &reg_buf[..BUF]) }
        .map_err(|_| "integration::fault_handler_rebind: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::fault_handler_rebind: reply (RESUME) failed")?;
    let bits = notification_wait_timeout(sig, crate::scaled_bound(RECOVERY_MS))
        .map_err(|_| "integration::fault_handler_rebind: recovery wait failed")?;
    if bits == 0
    {
        return Err("integration::fault_handler_rebind: resumed faulter never recovered");
    }
    Ok(())
}

/// Faulter entry: store to the reserved VA. The store faults; the controller
/// either lets the fault be unhandled or redirects the thread to
/// [`recovery_entry`], so the store never completes. The loop only satisfies
/// `-> !`.
extern "C" fn faulter_entry(_arg: u64) -> !
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

/// Recovery routine a resumed faulter is redirected into: report through the
/// published notification cap.
extern "C" fn recovery_entry(_arg: u64) -> !
{
    syscall::notification_send(RECOVERY_SIG.load(Ordering::Acquire), 1).ok();
    loop
    {
        core::hint::spin_loop();
    }
}
