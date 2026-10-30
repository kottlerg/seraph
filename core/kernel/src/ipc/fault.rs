// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/fault.rs

//! Fault redirection — deliver a kernel-unresolvable userspace thread fault to
//! the thread's bound fault-handler endpoint and block until it is resolved.
//!
//! This is the shared, architecture-independent core of the fault-handler
//! protocol (`docs/fault-handling.md`). The architecture trap handlers (x86-64
//! `#PF` and the other user exception vectors; RISC-V page-fault and other
//! U-mode exception causes) build a [`FaultInfo`] of kind `FAULT_KIND_VM` or
//! `FAULT_KIND_EXCEPTION`, marshal their register frame into the canonical
//! [`TrapFrame`] the handler will read/edit, then call [`fault_dispatch`]; the
//! disposition it returns tells the arch handler whether to resume
//! (re-execute the faulting instruction) or kill.
//!
//! Delivery reuses the synchronous-IPC machinery: the faulting thread takes the
//! caller role (parked in [`IpcThreadState::BlockedOnFault`] rather than
//! `BlockedOnReply`) and the handler services it with the ordinary receive /
//! reply cycle. Delivery is iterative (block + reschedule), never kernel-stack
//! recursion, so a fault chain cannot exhaust the kernel stack.
//!
//! [`TrapFrame`]: crate::arch::current::trap_frame::TrapFrame

use core::sync::atomic::Ordering;

use crate::cap::object::{EndpointObject, KernelObjectHeader};
use crate::sched::thread::{IpcThreadState, ThreadControlBlock};

/// [`ThreadControlBlock::fault_outcome`] value: no disposition committed yet.
pub const FAULT_OUTCOME_PENDING: u8 = 0;
/// [`ThreadControlBlock::fault_outcome`] value: resume (re-execute / continue).
pub const FAULT_OUTCOME_RESUME: u8 = 1;
/// [`ThreadControlBlock::fault_outcome`] value: kill (handler declined, handler
/// thread destroyed, binding severed, or thread cancelled).
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

/// True iff `tcb` has a fault handler bound at the moment of the load.
///
/// A lock-free pre-check for the architecture handlers only: a concurrent
/// unbind may clear the binding before [`fault_dispatch`] runs, so the
/// dispatcher's own load under `sched_lock` decides, and a binding found
/// cleared there takes the unhandled-fault kill.
///
/// # Safety
/// `tcb` must be a valid TCB pointer.
#[cfg(not(test))]
pub unsafe fn has_handler(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: tcb validated by caller; fault_handler field always valid.
    !unsafe { (*tcb).fault_handler.load(Ordering::Acquire) }.is_null()
}

/// Read `tcb`'s fault-handler binding once and pin its endpoint for a delivery.
///
/// Returns the bound `EndpointObject`, with a reference the caller owns and
/// MUST release, and the badge bound with it; `None` when no handler is bound.
/// The pair is read under `tcb`'s `sched_lock`, the lock
/// `sys_thread_set_fault_handler` publishes it under, so the badge is the one
/// bound with this endpoint, and the reference is taken while the binding's
/// own reference still holds the object: the binder releases the old binding's
/// reference only after it unlocks.
///
/// # Safety
/// `tcb` must be the current CPU's running thread, with no lock held.
#[cfg(not(test))]
unsafe fn pin_binding(
    tcb: *mut ThreadControlBlock,
) -> Option<(core::ptr::NonNull<EndpointObject>, u64)>
{
    // SAFETY: tcb is the running thread (contract); lock_raw is paired with
    // the unlock_raw below. A non-null fault_handler read under sched_lock
    // names an endpoint the binding references, so it is live for inc_ref.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let ep = core::ptr::NonNull::new((*tcb).fault_handler.load(Ordering::Acquire));
        let badge = (*tcb).fault_badge.load(Ordering::Relaxed);
        if let Some(ep) = ep
        {
            ep.as_ref().header.inc_ref();
        }
        (*tcb).sched_lock.unlock_raw(saved);
        ep.map(|ep| (ep, badge))
    }
}

/// Deliver `info` to `tcb`'s bound fault-handler endpoint and block until the
/// handler replies or the binding is severed. Returns the disposition.
///
/// Mirrors [`crate::syscall::ipc::sys_ipc_call`] but commits the
/// [`IpcThreadState::BlockedOnFault`] state and reads the disposition from
/// `tcb.fault_outcome` on resume rather than writing a syscall return value.
///
/// The binding is read once, under `tcb`'s `sched_lock`, and its endpoint is
/// pinned for the delivery ([`pin_binding`]); a binding a concurrent unbind
/// cleared returns [`FaultOutcome::Kill`], the unhandled-fault path. The pin
/// is released after the delivery and before the park's `schedule()` (the
/// pin-before-park rule, core/kernel/docs/scheduling-internals.md § Lock
/// Hierarchy rule 10): a release that drops the endpoint's last reference
/// runs its teardown, whose send-queue drain claims this thread with a kill
/// outcome when it is still queued there.
///
/// # Preconditions
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
    // SAFETY: tcb is the current CPU's running thread; no lock is held.
    let Some((ep_obj, badge)) = (unsafe { pin_binding(tcb) })
    else
    {
        return FaultOutcome::Kill;
    };
    // SAFETY: ep_obj is pinned by the reference pin_binding took.
    let ep_state = unsafe { ep_obj.as_ref().state };

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
        // spurious-resume tripwire; see core/kernel/docs/ipc-internals.md
        // § Park Dispositions and Episodes).
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

    // SAFETY: ep_state is a valid EndpointState (this delivery's pin keeps it
    // live); tcb is the current CPU's running thread (this fn's contract); no
    // scheduler or IPC lock is held (# Preconditions). The BlockedOnFault
    // parked-state diverges from a normal call only in the committed
    // IpcThreadState; the reply linkage is identical.
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

    // Drop the delivery's pin before parking (rule 10): the park's binding now
    // keeps this thread reachable, and a release that frees the endpoint runs
    // its teardown here, which claims this thread if it is still queued.
    // SAFETY: the reference pin_binding took is owned here; fault context with
    // interrupts disabled (a stable CPU index) and no lock held.
    unsafe { crate::cap::object::release_ref(ep_obj.cast::<KernelObjectHeader>()) };

    // Yield the CPU — the current thread is now blocked (or, on the rare
    // concurrent-stop rollback, already Stopped/Exited and not re-enqueued).
    // SAFETY: scheduler initialised; fault context.
    unsafe {
        crate::sched::schedule(crate::sched::Requeue::IfRunnable);
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
