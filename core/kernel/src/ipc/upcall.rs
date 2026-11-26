// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/upcall.rs

//! Asynchronous upcalls — the capability-triggered dual of fault delivery
//! (`docs/fault-handling.md` § Asynchronous Upcalls).
//!
//! A post ([`post`], `SYS_THREAD_POST_UPCALL`) marks one upcall pending on a
//! thread. The thread takes it at its next delivery point, a syscall's return
//! or, for a post with `UPCALL_ANY_INSTRUCTION`, an interrupt's return to user
//! mode ([`deliver_at_syscall`], [`deliver_at_interrupt`]), unless it masks
//! upcalls ([`set_mask`]). The delivery is a fault delivery of
//! `FAULT_KIND_UPCALL` through the thread's [`CLASS_UPCALL`] binding
//! ([`fault::fault_dispatch`]): the thread is suspended fault-blocked, the
//! handler reads and edits its registers, and any disposition resumes it,
//! a decline or a cancellation dropping the upcall.
//!
//! A thread blocked when the post arrives has its block cancelled as a stop
//! cancels it, and is woken: its syscall returns `Interrupted`, and the upcall
//! is delivered at that return. A park committed after the post is refused for
//! the same reason (`sched::commit_blocked_under_local_lock`), so no post finds
//! a thread between its check and its park. A call (`SYS_IPC_CALL`) is the
//! exception: it is atomic with respect to upcalls, so its park is neither
//! cancelled nor refused, and the upcall is delivered at the call's own
//! return, with the call's result in the registers
//! (core/kernel/docs/thread-lifecycle-and-sleep.md § Upcall Cancel-and-Wake
//! Protocol).

use core::sync::atomic::Ordering;

use super::fault::{self, CLASS_UPCALL};
use crate::sched::thread::{ThreadControlBlock, ThreadState};
use syscall::SyscallError;

/// Post an upcall carrying `cookie` to `target`, deliverable at any return to
/// user mode when `any_instruction` is set, else at a syscall's return.
///
/// Refused with `InvalidState` when `target` is `Created` or `Exited`, or has
/// no handler bound for the upcall class (a right with no handler is inert),
/// and with `QueueFull` when an upcall is already pending on it; nothing is
/// then changed. Otherwise the upcall is pending, and, unless `target` masks
/// upcalls, its block is cancelled and it is woken (a call's block is left to
/// the call's return), or, for an `any_instruction` post, a CPU running it is
/// interrupted so it reaches an interrupt's return.
///
/// # Safety
/// `target` must be a valid TCB the caller pins (its capability lookup); the
/// caller holds no lock, in syscall context.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`any_instruction` is data: the `UPCALL_ANY_INSTRUCTION` bit of the caller's flags, \
              which the pending upcall records in `upcall_any_instruction`"
)]
#[cfg(not(test))]
pub unsafe fn post(
    target: *mut ThreadControlBlock,
    cookie: u64,
    any_instruction: bool,
) -> Result<(), SyscallError>
{
    // SAFETY: target valid per contract.
    let sched_lock = unsafe { &(*target).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to the state, the upcall binding or an upcall field of target, \
                  which the held sched_lock serialises"
    )]
    // SAFETY: target valid per contract; the upcall fields, the state and the
    // binding are read and written under its sched_lock.
    let (refusal, masked, running_on) = unsafe {
        let refusal = if matches!((*target).state, ThreadState::Created | ThreadState::Exited)
            || (*target).fault_handlers[CLASS_UPCALL]
                .load(Ordering::Acquire)
                .is_null()
        {
            Some(SyscallError::InvalidState)
        }
        else if (*target).upcall_pending.load(Ordering::Relaxed)
        {
            Some(SyscallError::QueueFull)
        }
        else
        {
            (*target).upcall_cookie.store(cookie, Ordering::Relaxed);
            (*target)
                .upcall_any_instruction
                .store(any_instruction, Ordering::Relaxed);
            (*target).upcall_pending.store(true, Ordering::Release);
            None
        };
        // A `Running` thread is `current` on the CPU `preferred_cpu` names,
        // which the dispatch wrote under this lock; any other thread is
        // `current` nowhere, and its dispatch, under this lock, reads the
        // pending upcall and posts it (`sched::schedule`).
        let running_on =
            ((*target).state == ThreadState::Running).then(|| (*target).preferred_cpu as usize);
        (
            refusal,
            (*target).upcall_masked.load(Ordering::Relaxed),
            running_on,
        )
    };
    // The CPU running the target owes the upcall at its next return of the
    // upcall's kind (core/kernel/docs/scheduling-internals.md § Return Work);
    // a masked upcall is posted by the unmask instead (`set_mask`).
    if refusal.is_none()
        && !masked
        && let Some(cpu) = running_on
    {
        let bit = if any_instruction
        {
            crate::percpu::return_work::UPCALL_ANY
        }
        else
        {
            crate::percpu::return_work::UPCALL_SYSCALL
        };
        // SAFETY: preferred_cpu of a Running thread names an online CPU.
        unsafe { crate::percpu::post_return_work_to(cpu, bit) };
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    if let Some(e) = refusal
    {
        return Err(e);
    }
    if masked
    {
        return Ok(());
    }

    // Cancel the target's block, in one pass. A lost claim leaves nothing to
    // repeat: a waker or a concurrent cancel owns the episode, or the thread
    // left the snapshotted park, and any park it commits while the upcall is
    // pending is refused but a call's, which the upcall waits out. A source
    // lock's contention is retried inside the cancel (ipc::lock_bound_source).
    // SAFETY: target valid and pinned; no lock held. A won cancel owes the
    // wake, which wake_in_flight (set inside the claim) keeps for this call.
    if unsafe { crate::syscall::thread::cancel_for_upcall(target) }
    {
        // SAFETY: target valid; its park was claimed by the cancel above,
        // whose wake_in_flight keeps it allocated.
        let cpu = unsafe { crate::sched::select_target_cpu(target, crate::sched::WakeHint::None) };
        // SAFETY: target valid and claimed, cpu came from select_target_cpu,
        // and no lock is held.
        unsafe { crate::sched::enqueue_and_wake(target, cpu) };
        return Ok(());
    }

    if any_instruction
    {
        // A target running on another CPU takes the prod's interrupt and
        // reaches its return to user mode, the bit posted above sending it
        // to the delivery point; one waiting on a run queue, which a return
        // to user mode preempted, passes that return's delivery point when it
        // runs again, its dispatch posting the bit (sched::schedule); a
        // fault-blocked one passes none at its fault's own return, only at a
        // later interrupt or syscall; and one running on this CPU is the
        // caller, which delivers at this syscall's return.
        if let Some(cpu) = running_on
            && cpu != crate::arch::current::cpu::current_cpu() as usize
        {
            // SAFETY: preferred_cpu of a Running thread names an online CPU.
            unsafe { crate::sched::prod_remote_cpu(cpu) };
        }
    }
    Ok(())
}

/// The return-work bit a thread being dispatched owes the CPU it runs on: its
/// pending upcall's, unless it masks upcalls, else 0.
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds, the lock
/// the post, the mask and the take write the upcall fields under.
#[cfg(not(test))]
pub unsafe fn return_work_of(tcb: *mut ThreadControlBlock) -> u32
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads an atomic upcall field of tcb under its held sched_lock"
    )]
    // SAFETY: tcb valid and its sched_lock held (contract).
    let (pending, masked, any) = unsafe {
        (
            (*tcb).upcall_pending.load(Ordering::Relaxed),
            (*tcb).upcall_masked.load(Ordering::Relaxed),
            (*tcb).upcall_any_instruction.load(Ordering::Relaxed),
        )
    };
    if !pending || masked
    {
        0
    }
    else if any
    {
        crate::percpu::return_work::UPCALL_ANY
    }
    else
    {
        crate::percpu::return_work::UPCALL_SYSCALL
    }
}

/// The `CAP_INFO_THREAD_UPCALL` word of `tcb`: its pending, masked, and
/// in-a-call bits, read in one hold of its `sched_lock`, under which the post,
/// the mask, and the park commit write them. In a call means `Blocked` in a
/// call's park (`BlockedOnSend` outside a fault or upcall delivery, or
/// `BlockedOnReply`), the parks an upcall waits out
/// (`syscall::thread::upcall_may_cancel`).
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; no lock is held.
#[cfg(not(test))]
pub unsafe fn info(tcb: *mut ThreadControlBlock) -> u64
{
    use crate::sched::thread::IpcThreadState;

    // SAFETY: tcb valid (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads a field of tcb that the held sched_lock serialises"
    )]
    // SAFETY: tcb valid; the state, the binding, in_fault_delivery and the
    // upcall fields are written under the held sched_lock.
    let (pending, masked, in_call) = unsafe {
        let in_call = (*tcb).state == ThreadState::Blocked
            && match (*tcb).ipc_state
            {
                IpcThreadState::BlockedOnReply => true,
                IpcThreadState::BlockedOnSend => !(*tcb).in_fault_delivery,
                IpcThreadState::None
                | IpcThreadState::BlockedOnRecv
                | IpcThreadState::BlockedOnFault
                | IpcThreadState::BlockedOnNotification
                | IpcThreadState::BlockedOnEventQueue
                | IpcThreadState::BlockedOnWaitSet => false,
            };
        (
            (*tcb).upcall_pending.load(Ordering::Relaxed),
            (*tcb).upcall_masked.load(Ordering::Relaxed),
            in_call,
        )
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    let bit = |set: bool, b: u64| if set { b } else { 0 };
    bit(pending, syscall::THREAD_UPCALL_PENDING)
        | bit(masked, syscall::THREAD_UPCALL_MASKED)
        | bit(in_call, syscall::THREAD_UPCALL_IN_CALL)
}

/// Set or clear the calling thread's upcall mask; returns the previous mask.
/// Clearing it leaves a pending upcall to this syscall's own return, which the
/// clear posts on this CPU (core/kernel/docs/scheduling-internals.md § Return
/// Work).
///
/// # Safety
/// `tcb` must be the calling thread's TCB; no lock is held.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`masked` is data: the upcall mask the function stores in `upcall_masked`"
)]
#[cfg(not(test))]
pub unsafe fn set_mask(tcb: *mut ThreadControlBlock, masked: bool) -> bool
{
    // SAFETY: tcb is the running thread (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    // SAFETY: tcb is the running thread; the mask is written under its
    // sched_lock, the lock a post and the park commit read it under.
    let previous = unsafe { (*tcb).upcall_masked.swap(masked, Ordering::Relaxed) };
    // SAFETY: tcb is the running thread, whose sched_lock is held.
    let owed = unsafe { return_work_of(tcb) };
    if owed != 0
    {
        // SAFETY: syscall context on the running thread's CPU, which the held
        // sched_lock (interrupts disabled) keeps it on.
        unsafe { crate::percpu::post_return_work(owed) };
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    previous
}

/// Take the pending upcall of `tcb` for a delivery at `point`, clearing it:
/// its cookie, or `None` when none is pending, the thread masks upcalls, the
/// upcall waits for a syscall's return and `point` is an interrupt's, or the
/// thread is no longer `Running` (a stop has committed and the thread has not
/// yet left its CPU), which keeps the upcall pending for a delivery point
/// after the thread is started.
///
/// # Safety
/// `tcb` must be the calling CPU's running thread; no lock is held.
#[cfg(not(test))]
unsafe fn take(tcb: *mut ThreadControlBlock, point: u64) -> Option<u64>
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access reads an atomic upcall field of tcb, the running thread's own TCB"
    )]
    // SAFETY: tcb valid; the lock-free check decides nothing, the take
    // re-reads under the sched_lock the post wrote under.
    let idle = unsafe {
        !(*tcb).upcall_pending.load(Ordering::Acquire)
            || (*tcb).upcall_masked.load(Ordering::Relaxed)
    };
    if idle
    {
        return None;
    }
    // SAFETY: tcb valid (contract).
    let sched_lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to the state or an upcall field of tcb, which the held \
                  sched_lock serialises"
    )]
    // SAFETY: tcb valid; the state and the upcall fields are read and written
    // under the held sched_lock the post wrote under.
    let taken = unsafe {
        ((*tcb).state == ThreadState::Running
            && (*tcb).upcall_pending.load(Ordering::Relaxed)
            && !(*tcb).upcall_masked.load(Ordering::Relaxed)
            && (point == syscall::UPCALL_POINT_SYSCALL
                || (*tcb).upcall_any_instruction.load(Ordering::Relaxed)))
        .then(|| {
            (*tcb).upcall_pending.store(false, Ordering::Relaxed);
            (*tcb).upcall_cookie.load(Ordering::Relaxed)
        })
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    taken
}

/// Deliver the pending upcalls of `tcb` at `point` with `frame` as the
/// register frame the handler reads and edits, one delivery after another
/// while one is pending at its end (an upcall posted during a delivery is
/// delivered after it resolves).
///
/// Each delivery is a fault delivery through the upcall class's binding; the
/// thread resumes whatever its disposition: a decline, a cancellation (a stop
/// of the thread, the handler's destruction), or a binding found cleared
/// drops the upcall, the outcome it has with no handler bound.
///
/// # Safety
/// `tcb` must be the calling CPU's running thread and `frame` its live user
/// frame on its kernel stack; no lock is held, interrupts disabled.
#[cfg(not(test))]
unsafe fn deliver(
    tcb: *mut ThreadControlBlock,
    frame: *mut crate::arch::current::trap_frame::TrapFrame,
    point: u64,
)
{
    // SAFETY: tcb is the running thread (contract).
    while let Some(cookie) = unsafe { take(tcb, point) }
    {
        // SAFETY: frame is the live user frame (contract); a single read.
        let ip = unsafe { (*frame).instruction_pointer() };
        let info = fault::FaultInfo {
            kind: syscall::FAULT_KIND_UPCALL,
            d1: cookie,
            d2: point,
            ip,
        };
        // Point trap_frame at the live frame for the handler's register
        // syscalls while the thread is upcall-blocked, as the fault paths do,
        // and restore it after.
        // SAFETY: tcb is the running thread; it alone writes its trap_frame.
        let saved_tf = unsafe { (*tcb).trap_frame.load(Ordering::Relaxed) };
        // SAFETY: as for the load above.
        unsafe { (*tcb).trap_frame.store(frame, Ordering::Relaxed) };

        // SAFETY: trap_frame names the live frame; no lock held (contract).
        // The outcome is not acted on: every disposition resumes the thread.
        let _ = unsafe { fault::fault_dispatch(tcb, &info) };
        // SAFETY: as for the store above.
        unsafe { (*tcb).trap_frame.store(saved_tf, Ordering::Relaxed) };
    }
}

/// The syscall delivery point: deliver the pending upcalls of the calling
/// thread at its syscall's return, the thread's published `trap_frame` holding
/// what the syscall returns with.
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
    unsafe { deliver(tcb, frame, syscall::UPCALL_POINT_SYSCALL) };
}

/// The interrupt delivery point: deliver the pending upcalls posted with
/// `UPCALL_ANY_INSTRUCTION` of the thread an interrupt preempted in user mode,
/// before the interrupt returns to it, or of a thread the wake preemption
/// rescheduled at the end of an exception it took in user mode
/// (`sched::exception_return_work`).
///
/// # Safety
/// The end of an interrupt handler taken from user mode, the interrupt
/// acknowledged, or of an exception taken from user mode that resumes the
/// thread, on the thread's kernel stack with `frame` its live user frame; no
/// lock is held, interrupts disabled.
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
    unsafe { deliver(tcb, frame, syscall::UPCALL_POINT_INTERRUPT) };
}
