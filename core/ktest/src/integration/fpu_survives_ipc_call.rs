// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fpu_survives_ipc_call.rs

//! Tier 2 integration: FPU register file survives a raw `SYS_IPC_CALL`
//! round-trip across CPU migration.
//!
//! Mirrors `core/ktest/src/unit/fpu.rs::preempt_isolation_cross_cpu` but
//! substitutes an IPC call/reply for the notification rendezvous. The
//! child issues `SYS_IPC_CALL` directly via inline asm
//! (`crate::arch::fpu::ipc_call_capture`) so no Rust function
//! boundary clobbers the live FP register file between "load pattern" and
//! "capture pattern post-migration"; this is the only ktest call site that
//! exercises the `SYS_IPC_CALL` register ABI without going through
//! `shared/ipc`'s wrappers.
//!
//! Coverage: the kernel's eager-save / lazy-restore path is already
//! exercised by `core/ktest/src/unit/fpu.rs::preempt_isolation_cross_cpu`
//! via the notification rendezvous. This file adds the IPC-dispatch path —
//! `sys_ipc_call`'s endpoint-block branch into the scheduler, and
//! `sys_ipc_reply`'s wake — so a future IPC fast-path optimisation that
//! skipped `switch_out_save` would surface here. Requires SMP; skips on UP.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, ipc_buffer_set,
    notification_send, notification_wait, system_info, thread_exit, thread_set_affinity,
};
use syscall_abi::SystemInfoType;

use crate::{ChildStack, TestContext, TestResult, spawn};
use syscall_abi::RIGHTS_EP_SEND_GRANT;

/// Notification NOTIFY right — the child only signals `done` via `notification_send`.
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// 64-bit pattern loaded into every FP register before the call.
const PATTERN: u64 = 0xA5A5_A5A5_A5A5_A5A5;

/// Sentinel labels for the request/reply pair.
const REQ_LABEL: u64 = 0xCAFE;
const REPLY_LABEL: u64 = 0xBEEF;

/// Spin between FP load and `SYS_IPC_CALL` so timer ticks fire while the
/// child is `fpu_owner` on the source CPU. Same sizing rationale as the
/// cross-CPU notification test in `core/ktest/src/unit/fpu.rs`.
const SPIN_ITERS: u64 = 50_000;

static mut STACK: ChildStack = ChildStack::ZERO;

// Resources are published to the child via statics rather than the entry
// argument so the inline-asm block can load them without depending on any
// register the kernel-side entry-frame setup may not preserve. Matches the
// publishing scheme in `core/ktest/src/unit/fpu.rs::preempt_isolation_cross_cpu`.
static CHILD_EP: AtomicU32 = AtomicU32::new(0);
static CHILD_DONE: AtomicU32 = AtomicU32::new(0);
static MISMATCHES: AtomicU64 = AtomicU64::new(0);
static OBSERVED_CPU: AtomicU32 = AtomicU32::new(u32::MAX);

/// IPC page of the [`child_entry`] child.
static mut CHILD_IPC_PAGE: crate::IpcPage = crate::IpcPage::ZERO;

/// Child entry: register the IPC buffer, then load `PATTERN` into the FP
/// register file, issue `SYS_IPC_CALL`, and capture the registers after the
/// reply, through `crate::arch::fpu::ipc_call_capture`, whose one inline-asm
/// block spans the load, the call, and the capture.
extern "C" fn child_entry(_arg: u64) -> !
{
    // Register this thread's IPC buffer. For the empty round-trip used
    // here (`data_count=0`, `cap_count=0`) the kernel never reads or
    // writes the buffer, but registering keeps the test correct if it
    // later grows data words and matches the buffer-registered ktest
    // invariant. Done before the FP-preserving block so any FP clobber
    // here is irrelevant.
    let buf_addr = crate::IpcPage::addr(core::ptr::addr_of_mut!(CHILD_IPC_PAGE));
    // SAFETY: `CHILD_IPC_PAGE` is this child's own IPC page, used by one thread at a time
    // (`IpcPage`'s rule); no Rust object lives in it, and the child
    // reaches it only through the raw `buf_addr` pointer.
    if unsafe { ipc_buffer_set(buf_addr) }.is_err()
    {
        thread_exit();
    }

    let mismatches = crate::arch::fpu::ipc_call_capture(
        PATTERN,
        SPIN_ITERS,
        CHILD_EP.load(Ordering::Acquire),
        REQ_LABEL,
    );
    MISMATCHES.store(mismatches, Ordering::Release);
    let cpu = system_info(SystemInfoType::CurrentCpu as u64).unwrap_or(u64::MAX);
    OBSERVED_CPU.store(u32::try_from(cpu).unwrap_or(u32::MAX), Ordering::Release);

    let _ = notification_send(CHILD_DONE.load(Ordering::Acquire), 0x1);
    thread_exit();
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "fpu_survives_ipc_call: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("integration::fpu_survives_ipc_call SKIP (requires SMP)");
        return Ok(());
    }

    MISMATCHES.store(0, Ordering::Release);
    OBSERVED_CPU.store(u32::MAX, Ordering::Release);

    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "fpu_survives_ipc_call: cap_create_endpoint failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fpu_survives_ipc_call: cap_create_notification failed")?;

    let mut child =
        spawn::new_child(ctx).map_err(|_| "fpu_survives_ipc_call: spawn::new_child failed")?;
    let child_ep = cap_copy(ep, child.cs, RIGHTS_EP_SEND_GRANT)
        .map_err(|_| "fpu_survives_ipc_call: cap_copy ep failed")?;
    let child_done = cap_copy(done, child.cs, RIGHTS_NOTIFY)
        .map_err(|_| "fpu_survives_ipc_call: cap_copy done failed")?;

    CHILD_EP.store(child_ep, Ordering::Release);
    CHILD_DONE.store(child_done, Ordering::Release);

    let stack_top = ChildStack::top(core::ptr::addr_of!(STACK));
    // Pin to CPU 0 initially: the child must run there long enough to
    // become `fpu_owner` on CPU 0 before it blocks in SYS_IPC_CALL.
    // SAFETY: the stack is `STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start_pinned(&child, child_entry, stack_top, 0, 0) }
        .map_err(|_| "fpu_survives_ipc_call: configure_and_start_pinned failed")?;

    // Wait for the child's call. `ipc_recv` blocks the harness thread
    // (yielding CPU 0) so the child can run, load the pattern, and issue
    // SYS_IPC_CALL.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fpu_survives_ipc_call: ipc_recv failed")?;
    if msg.label != REQ_LABEL
    {
        return Err("fpu_survives_ipc_call: ipc_recv returned wrong label");
    }

    // Flip child affinity to CPU 1 while it is `BlockedOnReply` awaiting the
    // reply. Mirrors the affinity flip in
    // core/ktest/src/unit/fpu.rs::preempt_isolation_cross_cpu.
    thread_set_affinity(child.th, 1)
        .map_err(|_| "fpu_survives_ipc_call: thread_set_affinity(1) failed")?;

    // Reply. The kernel enqueues the child on CPU 1. CPU 0's
    // `switch_out_save` (when the child blocked at the call site) already
    // persisted the live FP regs into the child's TCB area; the lazy
    // restore on CPU 1's first FP op completes the migration.
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(REPLY_LABEL), ctx.ipc_buf) }
        .map_err(|_| "fpu_survives_ipc_call: ipc_reply failed")?;

    let _ = notification_wait(done)
        .map_err(|_| "fpu_survives_ipc_call: notification_wait done failed")?;

    let mismatches = MISMATCHES.load(Ordering::Acquire);
    let observed_cpu = OBSERVED_CPU.load(Ordering::Acquire);

    child
        .delete_thread()
        .map_err(|_| "fpu_survives_ipc_call: cap_delete child.th failed")?;
    child
        .delete_cspace()
        .map_err(|_| "fpu_survives_ipc_call: cap_delete child.cs failed")?;
    cap_delete(ep).map_err(|_| "fpu_survives_ipc_call: cap_delete ep failed")?;
    cap_delete(done).map_err(|_| "fpu_survives_ipc_call: cap_delete done failed")?;

    crate::log_u64(
        "integration::fpu_survives_ipc_call observed_cpu=",
        u64::from(observed_cpu),
    );
    crate::log_u64("integration::fpu_survives_ipc_call mismatches=", mismatches);
    if mismatches != 0
    {
        return Err("FP register file corrupted across SYS_IPC_CALL round-trip");
    }
    // Diagnostic only — do not gate on `observed_cpu`: this test checks FP
    // state, which must be intact whichever CPU the child resumes on. The
    // flip above applies on wake through `select_target_cpu` (the Blocked
    // path), and no test gates on the CPU that path lands on; the
    // Ready-queued and Running migration paths are gated, by
    // core/ktest/src/unit/thread.rs::affinity_migrate_ready_queued and
    // ::affinity_migrate_running.
    Ok(())
}
