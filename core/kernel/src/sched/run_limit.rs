// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/run_limit.rs

//! Run limit: the count of timer ticks a thread runs between two reset points,
//! and the run-limit fault the tick that reaches its limit makes pending
//! (core/kernel/docs/scheduler.md § Run Limit; docs/fault-handling.md
//! § Run-Limit Faults).
//!
//! The tick of the CPU a thread is current on counts it ([`tick`]); entry to
//! a syscall that resets the count sets it to zero
//! (`syscall::resets_run_count`). The tick that reaches the limit sets the
//! count to zero, marks the fault pending and posts this CPU's
//! `percpu::return_work::RUN_LIMIT` bit, so the thread's next return to user
//! mode delivers it ([`deliver_at_syscall`], [`deliver_at_interrupt`]) as a
//! `FAULT_EXC_RUN_LIMIT` exception through its exception binding, or ends the
//! thread with `EXIT_RUN_LIMIT` when none is bound or the handler declines.

#[cfg(not(test))]
use core::sync::atomic::Ordering;

#[cfg(not(test))]
use crate::ipc::fault;
#[cfg(not(test))]
use crate::sched::thread::{ThreadControlBlock, ThreadState};

/// What a timer tick does for the run limit of its current thread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TickAction
{
    /// The thread has no limit: the tick neither counts nor posts.
    Skip,
    /// A run-limit fault is already pending, its return-work bit taken by a
    /// return that did not deliver it: post the bit again and count nothing.
    Repost,
    /// Count the tick.
    Count,
}

/// The action of a tick on a thread whose limit is `limit` (0 for none) and
/// whose run-limit fault is `pending` or not.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`pending` is data: the thread's `run_limit_pending` flag the action decides from"
)]
#[must_use]
pub const fn tick_action(limit: u32, pending: bool) -> TickAction
{
    if limit == 0
    {
        TickAction::Skip
    }
    else if pending
    {
        TickAction::Repost
    }
    else
    {
        TickAction::Count
    }
}

/// Whether `count`, the count with this tick added, reaches `limit`.
#[must_use]
pub const fn reaches_limit(count: u32, limit: u32) -> bool
{
    count >= limit
}

/// Count a timer tick for `tcb`, this CPU's current thread
/// (core/kernel/docs/scheduler.md § Run Limit). Returns whether a run-limit
/// fault is pending on it, its return-work bit posted on this CPU: the tick
/// reached the limit, or found a fault pending whose bit a return took without
/// delivering it.
///
/// # Safety
/// The timer tick, on this CPU with interrupts disabled and its scheduler
/// lock held; `tcb` is this CPU's current thread.
#[cfg(not(test))]
#[inline]
pub unsafe fn tick(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: tcb is this CPU's current thread (contract); the field is an
    // atomic.
    let limit = unsafe { (*tcb).run_limit.load(Ordering::Relaxed) };
    if limit == 0
    {
        return false;
    }
    // SAFETY: as for the load above.
    let pending = unsafe { &(*tcb).run_limit_pending };
    match tick_action(limit, pending.load(Ordering::Relaxed))
    {
        TickAction::Skip => return false,
        TickAction::Repost =>
        {}
        TickAction::Count =>
        {
            // SAFETY: as for the load above.
            let count = unsafe { &(*tcb).run_count };
            // An add, not a store of a value read before it, so a concurrent
            // set's zero is never lost.
            let counted = count.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
            if !reaches_limit(counted, limit)
            {
                return false;
            }
            count.store(0, Ordering::Relaxed);
            pending.store(true, Ordering::Relaxed);
        }
    }
    // The post is a Release and the return's take an Acquire, so the return
    // that takes the bit reads the pending flag
    // (core/kernel/docs/scheduling-internals.md § Return Work, rule 1).
    // SAFETY: an interrupt on a CPU whose per-CPU pointer is installed.
    unsafe { crate::percpu::post_return_work(crate::percpu::return_work::RUN_LIMIT) };
    true
}

/// Set the run limit of `tcb` to `limit` ticks (0 for none), with its count
/// at zero and no run-limit fault pending.
///
/// The three writes are made under the thread's `sched_lock`, under which a
/// delivery takes the pending fault and reads the limit, so a fault a tick
/// marks pending for the previous limit is not delivered under a limit of 0.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; no lock is held.
#[cfg(not(test))]
pub unsafe fn set(tcb: *mut ThreadControlBlock, limit: u32)
{
    // SAFETY: tcb valid (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: no lock is held (contract); paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access writes an atomic run-limit field of tcb under its held sched_lock"
    )]
    // SAFETY: tcb valid (contract); the fields are atomics.
    unsafe {
        (*tcb).run_limit.store(limit, Ordering::Relaxed);
        (*tcb).run_count.store(0, Ordering::Relaxed);
        (*tcb).run_limit_pending.store(false, Ordering::Relaxed);
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
}

/// Set the count of the calling thread to zero: entry to a syscall that resets
/// it (`syscall::resets_run_count`).
///
/// # Safety
/// Syscall context on a CPU whose per-CPU pointer is installed.
#[cfg(not(test))]
#[inline]
pub unsafe fn reset_current()
{
    // SAFETY: syscall context (contract); current_tcb reads this CPU's
    // running thread.
    let tcb = unsafe { crate::syscall::current_tcb() };
    if !tcb.is_null()
    {
        // SAFETY: tcb is the running thread's live TCB; the field is an atomic.
        unsafe { (*tcb).run_count.store(0, Ordering::Relaxed) };
    }
}

/// Take the pending run-limit fault of `tcb`, clearing it: whether one was
/// pending while the thread has a limit. A thread no longer `Running` (a stop
/// has committed and the thread has not yet left its CPU) keeps it pending for
/// a return after it is started again.
///
/// # Safety
/// `tcb` must be the calling CPU's running thread; no lock is held.
#[cfg(not(test))]
unsafe fn take(tcb: *mut ThreadControlBlock) -> bool
{
    // SAFETY: tcb valid (contract); the lock-free check decides nothing, the
    // take re-reads under the sched_lock.
    if !unsafe { (*tcb).run_limit_pending.load(Ordering::Relaxed) }
    {
        return false;
    }
    // SAFETY: tcb valid (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to the state or a run-limit field of tcb, which the held \
                  sched_lock serialises"
    )]
    // SAFETY: tcb valid; the state is written under the held sched_lock, and
    // the run-limit fields are atomics a set writes under it.
    let taken = unsafe {
        (*tcb).state == ThreadState::Running
            && (*tcb).run_limit_pending.swap(false, Ordering::Relaxed)
            && (*tcb).run_limit.load(Ordering::Relaxed) != 0
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    taken
}

/// Deliver the pending run-limit fault of `tcb` with `frame` as the register
/// frame its handler reads and edits: a `FAULT_EXC_RUN_LIMIT` exception
/// through the thread's exception binding. A resume gives the thread a fresh
/// limit; no handler bound, or an unhandled outcome, ends the thread.
///
/// # Safety
/// `tcb` must be the calling CPU's running thread and `frame` its live user
/// frame on its kernel stack, holding what the thread returns to user mode
/// with; no lock is held, interrupts disabled.
#[cfg(not(test))]
unsafe fn deliver(
    tcb: *mut ThreadControlBlock,
    frame: *mut crate::arch::current::trap_frame::TrapFrame,
)
{
    // SAFETY: tcb is the running thread (contract).
    if !unsafe { take(tcb) }
    {
        return;
    }
    // SAFETY: frame is the live user frame (contract); a single read.
    let ip = unsafe { (*frame).instruction_pointer() };
    let info = fault::FaultInfo {
        kind: syscall::FAULT_KIND_EXCEPTION,
        d1: syscall::FAULT_EXC_RUN_LIMIT,
        d2: 0,
        ip,
    };
    // SAFETY: tcb is the running thread; has_handler reads only the atomic
    // binding of the class.
    if unsafe { fault::has_handler(tcb, info.kind) }
    {
        // Point trap_frame at the live frame for the handler's register
        // syscalls while the thread is fault-blocked, as the exception paths
        // do, and restore it after.
        // SAFETY: tcb is the running thread; it alone writes its trap_frame.
        let saved_tf = unsafe { (*tcb).trap_frame.load(Ordering::Relaxed) };
        // SAFETY: as for the load above.
        unsafe { (*tcb).trap_frame.store(frame, Ordering::Relaxed) };
        // SAFETY: trap_frame names the live frame; no lock held (contract).
        let outcome = unsafe { fault::fault_dispatch(tcb, &info) };
        // SAFETY: as for the store above.
        unsafe { (*tcb).trap_frame.store(saved_tf, Ordering::Relaxed) };
        match outcome
        {
            fault::FaultOutcome::Resume =>
            {
                // SAFETY: tcb is the running thread; the field is an atomic.
                unsafe { (*tcb).run_count.store(0, Ordering::Relaxed) };
                return;
            }
            fault::FaultOutcome::Kill(cause) =>
            {
                // SAFETY: tcb valid; thread_id is fixed at creation.
                fault::report_user_kill(unsafe { (*tcb).thread_id }, cause);
            }
        }
    }
    else
    {
        // SAFETY: tcb is the running user thread.
        unsafe { fault::report_unbound_kill(tcb) };
    }
    // SAFETY: tcb is the running thread, on its kernel stack; no lock held,
    // interrupts disabled (contract).
    unsafe { terminate(tcb, ip) }
}

/// End `tcb`, whose run-limit fault went unhandled: report it, record its
/// address space's end, commit its exit with `EXIT_RUN_LIMIT`, post its death
/// notifications, and switch away for good, as the architecture exception
/// paths end a thread whose fault went unhandled
/// (core/kernel/docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine).
///
/// # Safety
/// `tcb` is the calling CPU's running user thread, on its kernel stack; no
/// lock is held, interrupts disabled.
#[cfg(not(test))]
unsafe fn terminate(tcb: *mut ThreadControlBlock, ip: u64) -> !
{
    // SAFETY: tcb valid; thread_id is fixed at creation.
    let tid = unsafe { (*tcb).thread_id };
    crate::kprintln_fault!(
        "USERSPACE FAULT: tid={} cpu={} cause=run-limit ip={:#x}",
        tid,
        crate::arch::current::cpu::current_cpu(),
        ip
    );
    let reason = syscall::EXIT_RUN_LIMIT;
    // The end is recorded before the `Exited` commit, so a holder that reads
    // the thread `Exited` reads the space ended (core/kernel/docs/syscalls.md
    // § `SYS_CAP_INFO`).
    // SAFETY: tcb valid; address_space is fixed while the thread runs.
    let aspace = unsafe { (*tcb).address_space };
    // SAFETY: aspace may be null, which record_aspace_end handles; no
    // death_lock is held.
    let aspace_post = unsafe { crate::sched::record_aspace_end(aspace, reason) };
    // A refusal means the thread is already `Exited` (an object-teardown stop
    // recorded `EXIT_KILLED`); the posts below still carry this reason.
    // SAFETY: tcb valid; no lock is held.
    let _ = unsafe { crate::sched::exit_under_all_locks(tcb, reason) };
    // SAFETY: tcb is the running thread, now `Exited`; no lock is held. The
    // walks take interrupts between batches with preemption disabled, so the
    // thread stays on this CPU until the schedule below.
    unsafe { crate::sched::post_death_notification(tcb, reason) };
    // SAFETY: aspace_post comes from this path's record, the thread has stayed
    // on this CPU since and is `Exited`; no lock is held.
    unsafe { crate::sched::post_aspace_death_notification(&aspace_post) };
    // SAFETY: kernel context on the thread's kernel stack; the `Exited`
    // thread is never dispatched again.
    unsafe { crate::sched::schedule(crate::sched::Requeue::IfRunnable) };
    crate::arch::current::cpu::halt_loop()
}

/// The delivery of a pending run-limit fault at a syscall's return, ahead of
/// the syscall delivery point of an upcall: the thread's published
/// `trap_frame` holds what the syscall returns with.
///
/// # Safety
/// Syscall context on the caller's kernel stack, after the frame holds the
/// syscall's result; no lock is held, interrupts disabled.
#[cfg(not(test))]
pub unsafe fn deliver_at_syscall()
{
    // SAFETY: syscall context; current_tcb reads this CPU's running thread.
    let tcb = unsafe { crate::syscall::current_tcb() };
    if tcb.is_null()
    {
        return;
    }
    // SAFETY: tcb is the running thread; the syscall entry published its frame.
    let frame = unsafe { (*tcb).trap_frame.load(Ordering::Relaxed) };
    if frame.is_null()
    {
        return;
    }
    // SAFETY: frame is the running thread's live syscall frame (contract).
    unsafe { deliver(tcb, frame) };
}

/// The delivery of a pending run-limit fault at the return from an interrupt
/// taken in user mode, ahead of the interrupt delivery point of an upcall, or
/// of a thread the wake preemption rescheduled at the end of an exception it
/// took in user mode (`sched::exception_return_work`).
///
/// # Safety
/// As for `ipc::upcall::deliver_at_interrupt`.
#[cfg(not(test))]
pub unsafe fn deliver_at_interrupt(frame: *mut crate::arch::current::trap_frame::TrapFrame)
{
    // SAFETY: interrupt context; current_tcb reads this CPU's running thread.
    let tcb = unsafe { crate::syscall::current_tcb() };
    if tcb.is_null() || frame.is_null()
    {
        return;
    }
    // SAFETY: tcb is the running thread and frame its live user frame
    // (contract).
    unsafe { deliver(tcb, frame) };
}

#[cfg(test)]
mod tests
{
    use super::{TickAction, reaches_limit, tick_action};

    #[test]
    fn no_limit_never_counts()
    {
        assert_eq!(tick_action(0, false), TickAction::Skip);
        assert_eq!(tick_action(0, true), TickAction::Skip);
    }

    #[test]
    fn pending_fault_reposts_without_counting()
    {
        assert_eq!(tick_action(50, true), TickAction::Repost);
        assert_eq!(tick_action(1, true), TickAction::Repost);
    }

    #[test]
    fn limited_thread_counts()
    {
        assert_eq!(tick_action(1, false), TickAction::Count);
        assert_eq!(tick_action(u32::MAX, false), TickAction::Count);
    }

    #[test]
    fn limit_reached_at_the_limit_th_tick()
    {
        assert!(!reaches_limit(49, 50));
        assert!(reaches_limit(50, 50));
        assert!(reaches_limit(1, 1));
        assert!(reaches_limit(u32::MAX, u32::MAX));
        // A count past the limit, left by a set racing a tick, faults.
        assert!(reaches_limit(51, 50));
    }
}
