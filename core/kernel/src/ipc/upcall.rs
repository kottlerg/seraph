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
//! a thread between its check and its park
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
/// upcalls, its block is cancelled and it is woken, or, for an
/// `any_instruction` post, a CPU running it is interrupted so it reaches an
/// interrupt's return.
///
/// # Safety
/// `target` must be a valid TCB the caller pins (its capability lookup); the
/// caller holds no lock, in syscall context.
#[cfg(not(test))]
pub unsafe fn post(
    target: *mut ThreadControlBlock,
    cookie: u64,
    any_instruction: bool,
) -> Result<(), SyscallError>
{
    // SAFETY: target valid per contract; the upcall fields, the state and the
    // binding are read and written under its sched_lock.
    let masked = unsafe {
        let saved = (*target).sched_lock.lock_raw();
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
        let masked = (*target).upcall_masked.load(Ordering::Relaxed);
        (*target).sched_lock.unlock_raw(saved);
        if let Some(e) = refusal
        {
            return Err(e);
        }
        masked
    };
    if masked
    {
        return Ok(());
    }

    // SAFETY: target valid and pinned; no lock held. A won cancel owes the
    // wake, which wake_in_flight (set inside the claim) keeps for this call.
    if unsafe { crate::syscall::thread::cancel_for_upcall(target) }
    {
        // SAFETY: target valid; its park was claimed by the cancel above.
        unsafe {
            let cpu = crate::sched::select_target_cpu(target);
            crate::sched::enqueue_and_wake(target, cpu);
        }
        return Ok(());
    }

    if any_instruction
    {
        // A target running on another CPU takes the prod's interrupt and
        // reaches its return to user mode; one running nowhere reaches a
        // delivery point when it next returns to user mode, and one running on
        // this CPU is the caller, which delivers at this syscall's return.
        // SAFETY: target valid; the scan reads each CPU's current under its lock.
        if let Some(cpu) = unsafe { running_cpu(target) }
            && cpu != crate::arch::current::cpu::current_cpu() as usize
        {
            // SAFETY: cpu is an online CPU index the scan found.
            unsafe { crate::sched::prod_remote_cpu(cpu) };
        }
    }
    Ok(())
}

/// The CPU `tcb` is `current` on at the scan, if any. A snapshot: the thread
/// may leave or reach a CPU after it.
///
/// # Safety
/// `tcb` must be a valid TCB; no scheduler lock is held.
#[cfg(not(test))]
unsafe fn running_cpu(tcb: *mut ThreadControlBlock) -> Option<usize>
{
    let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    (0..cpu_count).find(|&cpu| {
        // SAFETY: cpu < cpu_count; scheduler state read under its lock.
        unsafe {
            let s = crate::sched::scheduler_for(cpu);
            let f = s.lock.lock_raw();
            let is_cur = core::ptr::eq(s.current(), tcb);
            s.lock.unlock_raw(f);
            is_cur
        }
    })
}

/// Set or clear the calling thread's upcall mask; returns the previous mask.
/// Clearing it leaves a pending upcall to this syscall's own return.
///
/// # Safety
/// `tcb` must be the calling thread's TCB; no lock is held.
#[cfg(not(test))]
pub unsafe fn set_mask(tcb: *mut ThreadControlBlock, masked: bool) -> bool
{
    // SAFETY: tcb is the running thread; the mask is written under its
    // sched_lock, the lock a post and the park commit read it under.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let previous = (*tcb).upcall_masked.swap(masked, Ordering::Relaxed);
        (*tcb).sched_lock.unlock_raw(saved);
        previous
    }
}

/// Take the pending upcall of `tcb` for a delivery at `point`, clearing it:
/// its cookie, or `None` when none is pending, the thread masks upcalls, or
/// the upcall waits for a syscall's return and `point` is an interrupt's.
///
/// # Safety
/// `tcb` must be the calling CPU's running thread; no lock is held.
#[cfg(not(test))]
unsafe fn take(tcb: *mut ThreadControlBlock, point: u64) -> Option<u64>
{
    // SAFETY: tcb valid; the lock-free check decides nothing, the take
    // re-reads under the sched_lock the post wrote under.
    unsafe {
        if !(*tcb).upcall_pending.load(Ordering::Acquire)
            || (*tcb).upcall_masked.load(Ordering::Relaxed)
        {
            return None;
        }
        let saved = (*tcb).sched_lock.lock_raw();
        let taken = ((*tcb).upcall_pending.load(Ordering::Relaxed)
            && !(*tcb).upcall_masked.load(Ordering::Relaxed)
            && (point == syscall::UPCALL_POINT_SYSCALL
                || (*tcb).upcall_any_instruction.load(Ordering::Relaxed)))
        .then(|| {
            (*tcb).upcall_pending.store(false, Ordering::Relaxed);
            (*tcb).upcall_cookie.load(Ordering::Relaxed)
        });
        (*tcb).sched_lock.unlock_raw(saved);
        taken
    }
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
        let saved_tf = unsafe {
            let saved = (*tcb).trap_frame.load(Ordering::Relaxed);
            (*tcb).trap_frame.store(frame, Ordering::Relaxed);
            saved
        };
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
/// before the interrupt returns to it.
///
/// # Safety
/// The end of an interrupt handler taken from user mode, the interrupt
/// acknowledged, on the interrupted thread's kernel stack with `frame` its
/// live user frame; no lock is held, interrupts disabled.
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
