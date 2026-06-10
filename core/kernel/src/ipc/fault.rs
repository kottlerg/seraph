// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/fault.rs

//! Fault redirection — deliver a kernel-unresolvable userspace thread fault to
//! the thread's bound fault-handler endpoint and block until it is resolved.
//!
//! This is the shared, architecture-independent core of the fault-handler
//! protocol ([`docs/fault-handling.md`](../../../docs/fault-handling.md)). The
//! architecture fault handlers (x86-64 `#PF`, RISC-V page-fault traps) marshal
//! their register frame into the canonical [`TrapFrame`] the handler will
//! read/edit, then call [`fault_dispatch`]; the disposition it returns tells the
//! arch handler whether to resume (re-execute the faulting instruction) or kill.
//!
//! Delivery reuses the synchronous-IPC machinery: the faulting thread takes the
//! caller role (parked in [`IpcThreadState::BlockedOnFault`] rather than
//! `BlockedOnReply`) and the handler services it with the ordinary receive /
//! reply cycle. Delivery is iterative (block + reschedule), never kernel-stack
//! recursion, so a fault chain cannot exhaust the kernel stack.
//!
//! [`TrapFrame`]: crate::arch::current::trap_frame::TrapFrame

use core::sync::atomic::Ordering;

use crate::sched::thread::{IpcThreadState, ThreadControlBlock};

/// [`ThreadControlBlock::fault_outcome`] value: no disposition committed yet.
pub const FAULT_OUTCOME_PENDING: u8 = 0;
/// [`ThreadControlBlock::fault_outcome`] value: resume (re-execute / continue).
pub const FAULT_OUTCOME_RESUME: u8 = 1;
/// [`ThreadControlBlock::fault_outcome`] value: kill (handler declined, handler
/// died, binding severed, or thread cancelled).
pub const FAULT_OUTCOME_KILL: u8 = 2;

/// Architecture-neutral description of a fault, marshalled into the fault
/// message's data words `[kind, d1, d2, ip]`.
#[derive(Clone, Copy)]
pub struct FaultInfo
{
    /// Fault kind: [`syscall::FAULT_KIND_VM`] or [`syscall::FAULT_KIND_EXCEPTION`].
    pub kind: u64,
    /// Kind-specific word 1 (VM: faulting virtual address; exception: code).
    pub d1: u64,
    /// Kind-specific word 2 (VM: access flags; exception: arch aux code).
    pub d2: u64,
    /// Faulting instruction pointer.
    pub ip: u64,
}

/// Disposition returned by [`fault_dispatch`] to the architecture fault handler.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FaultOutcome
{
    /// Resume the faulting thread (re-execute the faulting instruction, or
    /// continue from a handler-modified instruction pointer).
    Resume,
    /// Kill the faulting thread as an unhandled fault.
    Kill,
}

/// True iff `tcb` has a fault handler bound.
///
/// # Safety
/// `tcb` must be a valid TCB pointer.
#[cfg(not(test))]
pub unsafe fn has_handler(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: tcb validated by caller; fault_handler field always valid.
    !unsafe { (*tcb).fault_handler.load(Ordering::Acquire) }.is_null()
}

/// Deliver `info` to `tcb`'s bound fault-handler endpoint and block until the
/// handler replies or the binding is severed. Returns the disposition.
///
/// Mirrors [`crate::syscall::ipc::sys_ipc_call`] but commits the
/// [`IpcThreadState::BlockedOnFault`] state and reads the disposition from
/// `tcb.fault_outcome` on resume rather than writing a syscall return value.
///
/// # Preconditions
/// - The caller verified [`has_handler`] (i.e. `tcb.fault_handler` is non-null).
/// - `tcb.trap_frame` already points at the canonical register frame the handler
///   reads/edits via `SYS_THREAD_READ_REGS`/`SYS_THREAD_WRITE_REGS` while the
///   thread is `BlockedOnFault`.
/// - No scheduler or IPC lock is held (fault entry, IF=0 / SIE=0).
///
/// # Safety
/// `tcb` must be the current CPU's running thread.
#[cfg(not(test))]
pub unsafe fn fault_dispatch(tcb: *mut ThreadControlBlock, info: &FaultInfo) -> FaultOutcome
{
    // SAFETY: fault_handler is non-null per precondition; the binding holds an
    // inc_ref on the EndpointObject, so it (and its inline state) is live.
    let ep_state = unsafe {
        let ep_obj = (*tcb).fault_handler.load(Ordering::Acquire);
        (*ep_obj).state
    };
    // SAFETY: tcb validated; fault_badge always valid.
    let badge = unsafe { (*tcb).fault_badge.load(Ordering::Acquire) };

    // Arm the in-flight markers BEFORE delivery: `in_fault_delivery` so a
    // dequeuing `endpoint_recv` parks us `BlockedOnFault` (not `BlockedOnReply`),
    // and `fault_outcome = Pending` so a stale prior disposition cannot be
    // mistaken for this fault's. The single wake-claim winner overwrites the
    // outcome with `Resume`/`Kill`.
    // SAFETY: tcb is the running thread; these fields are owned by it until the
    // delivery below makes it wakeable.
    unsafe {
        (*tcb)
            .fault_outcome
            .store(FAULT_OUTCOME_PENDING, Ordering::Release);
        (*tcb).in_fault_delivery = true;
        // Open the park episode (the fault protocol's disposition stays in
        // fault_outcome; the episode counter is the shared debug
        // spurious-resume tripwire — see ipc-internals.md § Reply Disposition
        // and Park Episodes).
        #[cfg(debug_assertions)]
        (*tcb).park_episode.fetch_add(1, Ordering::Relaxed);
    }

    let mut msg = crate::ipc::message::Message::new(syscall::FAULT_LABEL);
    msg.badge = badge;
    msg.data[0] = info.kind;
    msg.data[1] = info.d1;
    msg.data[2] = info.d2;
    msg.data[3] = info.ip;
    msg.data_count = 4;

    // SAFETY: ep_state is a valid EndpointState; no scheduler lock held. The
    // BlockedOnFault parked-state diverges from a normal call only in the
    // committed IpcThreadState; the reply linkage is identical.
    let result = unsafe {
        crate::ipc::endpoint::endpoint_call(ep_state, tcb, &msg, IpcThreadState::BlockedOnFault)
    };

    if let Ok(woken_handler) = result
    {
        // A handler was waiting; enqueue it so it can service the fault.
        // SAFETY: woken_handler returned by endpoint_call; valid TCB.
        unsafe {
            debug_assert!((*woken_handler).magic == crate::sched::thread::TCB_MAGIC);
            let target_cpu = crate::sched::select_target_cpu(woken_handler);
            crate::sched::enqueue_and_wake(woken_handler, target_cpu);
        }
    }
    // else: no handler waiting; we are queued on the endpoint's send queue as
    // BlockedOnSend + in_fault_delivery, to be picked up by a later recv.

    // Yield the CPU — the current thread is now blocked (or, on the rare
    // concurrent-stop rollback, already Stopped/Exited and not re-enqueued).
    // SAFETY: scheduler initialised; fault context.
    unsafe {
        crate::sched::schedule(false);
    }

    // Resumed. Read the disposition the wake-claim winner committed. Anything
    // other than an explicit Resume is treated as Kill — this defensively
    // covers a spurious wake leaving the outcome at `Pending`.
    // SAFETY: tcb still valid after resume.
    let outcome = unsafe { (*tcb).fault_outcome.load(Ordering::Acquire) };
    // Spurious-resume tripwire: every legitimate fault wake stamps the
    // episode at its claim site; a mismatch means this resume was produced by
    // nothing that owed it (the #352-class leaked wake). The Kill fallback
    // above keeps release behavior fail-closed.
    #[cfg(debug_assertions)]
    // SAFETY: tcb still valid after resume.
    unsafe {
        let park = (*tcb).park_episode.load(Ordering::Relaxed);
        let deposit = (*tcb).deposit_episode.load(Ordering::Relaxed);
        debug_assert!(
            deposit == park,
            "fault_dispatch: spurious resume tid={} park_episode={park} \
             deposit_episode={deposit} outcome={outcome}",
            (*tcb).thread_id,
        );
    }
    // SAFETY: tcb still valid; clear the in-flight marker now the delivery is done.
    unsafe {
        (*tcb).in_fault_delivery = false;
    }

    if outcome == FAULT_OUTCOME_RESUME
    {
        FaultOutcome::Resume
    }
    else
    {
        FaultOutcome::Kill
    }
}
