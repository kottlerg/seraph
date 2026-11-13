// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_handler_rebind.rs

//! Integration: a change of a thread's fault-handler binding while a fault is
//! in flight cancels that delivery, and the fault is delivered again under the
//! binding current then; with none bound, the fault is unhandled
//! (docs/fault-handling.md § Delivery, Resume, and Kill).
//!
//! Six phases, each with its own faulter, which stores to an unmapped VA (the
//! copy phase's faulter instead hands it to `SYS_GETRANDOM`). A queued phase
//! waits, through a wait set holding the first endpoint, until the fault
//! message is queued on that endpoint unreceived, so it exercises the queued
//! delivery rather than a fault taken after the change.
//!
//!   1. **Clear, received.** The controller receives the fault and does not
//!      reply, then clears the binding. The faulter must reach `Exited` with
//!      the fault exit reason, and the controller's late reply must find no
//!      pending reply (`InvalidCapability`).
//!   2. **Clear, queued.** With the fault queued, a clear must make the
//!      faulter reach `Exited` with the fault exit reason.
//!   3. **Rebind, queued.** With the fault queued on the first endpoint, a
//!      rebind to a second endpoint with another badge must deliver the fault
//!      there with that badge; a resume, after the controller redirects the
//!      faulter's instruction pointer, must run the recovery routine.
//!   4. **Clear, kernel copy.** A `SYS_GETRANDOM` into an unmapped buffer
//!      faults to the handler; with that fault queued, a clear must fail the
//!      call with `InvalidAddress`, the faulter living on to report it.
//!   5. **Rebind, received.** The controller receives the fault through the
//!      first endpoint and rebinds the faulter to the second. The late reply
//!      through the first binding must find no pending reply; the fault must
//!      arrive again on the second endpoint with its badge and the same
//!      faulting address, and a resume there must run the recovery routine.
//!   6. **Rebind, identical.** The controller receives the fault and rebinds
//!      the faulter to the same endpoint and badge, which cancels nothing: its
//!      reply must claim the fault and resume the faulter at the redirected
//!      instruction pointer.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_wait_timeout,
    thread_read_regs, thread_set_fault_handler, thread_write_regs, wait_set_add, wait_set_create,
    wait_set_remove, wait_set_wait,
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

/// Wait-set badge of the first endpoint while a queued phase watches it.
const WS_FIRST: u64 = 0xF1;

/// Bytes the copy phase's `SYS_GETRANDOM` asks for.
const COPY_LEN: usize = 16;

/// Bits the copy phase's faulter reports: its call failed with
/// `InvalidAddress`, or returned anything else.
const COPY_REFUSED: u64 = 1 << 0;
const COPY_OTHER: u64 = 1 << 1;

/// Bound on the wait for a faulter to exit, in 1 ms polls. Applied through
/// [`crate::scaled_polls`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where a child's CPU waits for a host core.
const EXIT_POLLS: u32 = 2000;

/// Bound, in milliseconds, on the wait for a faulter's report (the recovery
/// routine's, or the copy phase's call result). Applied through
/// [`crate::scaled_bound`], which stretches it the same way.
const REPORT_MS: u64 = 1000;

/// Register-file buffer size; holds the arch `TrapFrame`
/// (`crate::arch::TRAP_FRAME_BYTES`) on every architecture, as the guard
/// below checks.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Phase count; each phase's faulter has its own stack.
const PHASES: usize = 6;

static mut FAULTER_STACKS: [ChildStack; PHASES] = [ChildStack::ZERO; PHASES];

/// Child cap slot of the report notification, read by [`recovery_entry`]
/// after the controller redirects a faulter into it.
static RECOVERY_SIG: AtomicU64 = AtomicU64::new(0);

/// The caps and faulters the test creates; each is deleted on every path.
#[derive(Default)]
struct Parts
{
    first: Option<u64>,
    second: Option<u64>,
    sig: Option<u64>,
    ws: Option<u64>,
    faulters: [Option<spawn::SpawnedChild>; PHASES],
}

/// The objects the phases share.
struct Objects
{
    first: u64,
    second: u64,
    sig: u64,
    ws: u64,
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
    for cap in [parts.ws, parts.first, parts.second, parts.sig]
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
        Err("integration::fault_handler_rebind: teardown failed")
    }
}

/// Create the shared objects and run the six phases.
fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let objects = Objects {
        first: *parts.first.insert(
            cap_create_endpoint(ctx.memory_base)
                .map_err(|_| "integration::fault_handler_rebind: create first endpoint failed")?,
        ),
        second: *parts.second.insert(
            cap_create_endpoint(ctx.memory_base)
                .map_err(|_| "integration::fault_handler_rebind: create second endpoint failed")?,
        ),
        sig: *parts.sig.insert(
            cap_create_notification(ctx.memory_base)
                .map_err(|_| "integration::fault_handler_rebind: create notification failed")?,
        ),
        ws: *parts.ws.insert(
            wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
                .map_err(|_| "integration::fault_handler_rebind: create wait set failed")?,
        ),
    };
    clear_received(ctx, parts, &objects)?;
    clear_queued(ctx, parts, &objects)?;
    rebind_queued(ctx, parts, &objects)?;
    clear_copy_queued(ctx, parts, &objects)?;
    rebind_received(ctx, parts, &objects)?;
    rebind_identical(ctx, parts, &objects)
}

/// Phase 1: clear the binding of a faulter whose fault the controller holds.
fn clear_received(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = start_faulter(ctx, parts, 0, objects, faulter_entry)?;
    receive_fault(ctx, objects.first, BADGE_FIRST)?;
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
fn clear_queued(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = start_queued(ctx, parts, 1, objects, faulter_entry)?;
    thread_set_fault_handler(th, 0, FAULT_CLASS_ALL)
        .map_err(|_| "integration::fault_handler_rebind: clear (queued) failed")?;
    expect_fault_exit(th)
}

/// Phase 3: rebind a faulter whose fault is queued unreceived to the second
/// endpoint, and resolve the redelivered fault there.
fn rebind_queued(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = start_queued(ctx, parts, 2, objects, faulter_entry)?;
    crate::bind_fault_handler(th, objects.second, BADGE_SECOND)
        .map_err(|_| "integration::fault_handler_rebind: rebind (queued) failed")?;
    receive_fault(ctx, objects.second, BADGE_SECOND)?;
    resume_into_recovery(ctx, th, objects.sig)
}

/// Phase 4: clear the binding of a thread whose `SYS_GETRANDOM` copy fault is
/// queued unreceived; the call must fail with `InvalidAddress`.
fn clear_copy_queued(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = start_queued(ctx, parts, 3, objects, copy_faulter_entry)?;
    thread_set_fault_handler(th, 0, FAULT_CLASS_ALL)
        .map_err(|_| "integration::fault_handler_rebind: clear (copy) failed")?;
    let bits = notification_wait_timeout(objects.sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::fault_handler_rebind: copy report wait failed")?;
    if bits != COPY_REFUSED
    {
        return Err(
            "integration::fault_handler_rebind: unbound copy fault did not fail its syscall with \
             InvalidAddress",
        );
    }
    Ok(())
}

/// Phase 5: rebind a faulter whose fault the controller holds to the second
/// endpoint, and resolve the redelivered fault there.
fn rebind_received(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = start_faulter(ctx, parts, 4, objects, faulter_entry)?;
    receive_fault(ctx, objects.first, BADGE_FIRST)?;
    crate::bind_fault_handler(th, objects.second, BADGE_SECOND)
        .map_err(|_| "integration::fault_handler_rebind: rebind to the second endpoint failed")?;
    expect_no_pending_reply(ctx)?;
    receive_fault(ctx, objects.second, BADGE_SECOND)?;
    resume_into_recovery(ctx, th, objects.sig)
}

/// Phase 6: rebind a faulter whose fault the controller holds to the same
/// endpoint and badge, and resolve the fault with the original reply.
fn rebind_identical(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = start_faulter(ctx, parts, 5, objects, faulter_entry)?;
    receive_fault(ctx, objects.first, BADGE_FIRST)?;
    crate::bind_fault_handler(th, objects.first, BADGE_FIRST)
        .map_err(|_| "integration::fault_handler_rebind: identical rebind failed")?;
    resume_into_recovery(ctx, th, objects.sig)
}

/// Spawn phase `index`'s faulter with a copy of the report notification,
/// bind it to the first endpoint with [`BADGE_FIRST`], and start it at
/// `entry`, whose argument is that copy. Returns its Thread cap.
fn start_faulter(
    ctx: &TestContext,
    parts: &mut Parts,
    index: usize,
    objects: &Objects,
    entry: extern "C" fn(u64) -> !,
) -> Result<u64, &'static str>
{
    let child = parts
        .faulters
        .get_mut(index)
        .ok_or("integration::fault_handler_rebind: faulter index out of range")?
        .insert(
            spawn::new_child(ctx)
                .map_err(|_| "integration::fault_handler_rebind: spawn faulter failed")?,
        );
    let child_sig = cap_copy(objects.sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::fault_handler_rebind: cap_copy notification failed")?;
    RECOVERY_SIG.store(child_sig, Ordering::Release);
    crate::bind_fault_handler(child.th, objects.first, BADGE_FIRST)
        .map_err(|_| "integration::fault_handler_rebind: bind failed")?;
    // SAFETY: `FAULTER_STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(FAULTER_STACKS), index) }?;
    // SAFETY: the stack is `FAULTER_STACKS[index]`, this test's own
    // `ChildStack`, on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, entry, stack, child_sig) }
        .map_err(|_| "integration::fault_handler_rebind: start faulter failed")?;
    Ok(child.th)
}

/// [`start_faulter`], then wait until the faulter's fault message is queued
/// on the first endpoint, unreceived: the wait set holding that endpoint
/// reports it ready only with a sender queued, and nothing else sends there.
fn start_queued(
    ctx: &TestContext,
    parts: &mut Parts,
    index: usize,
    objects: &Objects,
    entry: extern "C" fn(u64) -> !,
) -> Result<u64, &'static str>
{
    wait_set_add(objects.ws, objects.first, WS_FIRST)
        .map_err(|_| "integration::fault_handler_rebind: wait_set_add failed")?;
    let started = start_faulter(ctx, parts, index, objects, entry);
    let ready = started.and_then(|_| {
        wait_set_wait(objects.ws)
            .map_err(|_| "integration::fault_handler_rebind: wait_set_wait failed")
    });
    let removed = wait_set_remove(objects.ws, objects.first)
        .map_err(|_| "integration::fault_handler_rebind: wait_set_remove failed");
    if ready? != WS_FIRST
    {
        return Err("integration::fault_handler_rebind: wait set reported an unknown source");
    }
    removed?;
    started
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
    spawn::redirect_to_entry(&mut reg_buf[..], recovery_entry as *const () as u64)?;
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
    let bits = notification_wait_timeout(sig, crate::scaled_bound(REPORT_MS))
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
extern "C" fn faulter_entry(_sig_slot: u64) -> !
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

/// Copy-phase faulter entry: hand the reserved VA to `SYS_GETRANDOM`, whose
/// copy faults to the handler, and report through `sig_slot` whether the call
/// failed with `InvalidAddress`.
extern "C" fn copy_faulter_entry(sig_slot: u64) -> !
{
    // SAFETY: the span lies on the reserved VA, which nothing maps and no Rust
    // object occupies; the kernel writes it only once a handler backs it, or
    // refuses.
    let r = unsafe { syscall::getrandom_raw(RESERVED_VA as *mut u8, COPY_LEN) };
    let bits = if r == Err(SyscallError::InvalidAddress as i64)
    {
        COPY_REFUSED
    }
    else
    {
        COPY_OTHER
    };
    syscall::notification_send(sig_slot, bits).ok();
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
