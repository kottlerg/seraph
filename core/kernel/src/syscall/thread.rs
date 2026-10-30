// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/thread.rs

//! Thread lifecycle syscall handlers.
//!
//! # Adding new thread syscalls
//! 1. Add a `pub fn sys_thread_*` here.
//! 2. Add the syscall constant import to `core/kernel/src/syscall/mod.rs`.
//! 3. Add a dispatch arm to `core/kernel/src/syscall/mod.rs`.
//! 4. Add a userspace wrapper to `shared/syscall/src/lib.rs`.

// cast_possible_truncation: u64→u32 casts keep the low 32 bits of 64-bit
// trap-frame cap-handle args, whose ABI width is 32 bits. Value args with a
// range contract (priority levels, split points, CPU IDs) are narrowed with
// `try_from` and rejected when out of range. u64→usize casts are lossless
// (Seraph is 64-bit only).
#![allow(clippy::cast_possible_truncation)]

#[cfg(not(test))]
use super::UserFrame;
// The host-test stubs keep the arch frame type in their signatures.
#[cfg(test)]
use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

/// `SYS_THREAD_CONFIGURE` (23): set entry point, stack, argument, and TLS base
/// for a thread.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = user entry point (virtual address).
/// arg2 = user stack pointer (virtual address).
/// arg3 = argument value (passed in rdi/a0 when the thread first runs).
/// arg4 = initial TLS base (x86-64 `IA32_FS_BASE`; RISC-V `tp`).
///        Pass 0 for a thread that does not use thread-local storage.
///
/// The thread must be in `Created` state (not yet started). Builds the initial
/// user-mode `TrapFrame` on the thread's kernel stack. The thread is not enqueued;
/// call `SYS_THREAD_START` to start it.
///
/// Returns 0 on success. Returns `InvalidArgument` if the thread is not in
/// `Created` state, if `entry >= user_va_top()`, if the stack pointer (as passed
/// or after alignment) lies above `user_va_top()`, or if the TLS base is
/// `>= user_va_top()`.
#[cfg(not(test))]
pub fn sys_thread_configure(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTrapFrame;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;
    use core::mem::size_of;

    let thread_idx = tf.arg(0) as u32;
    let entry = tf.arg(1);
    // Round the user stack pointer to the entry point's `extern "C"` ABI
    // alignment (arch-specific; see `context::align_initial_stack`).
    let stack_ptr = crate::arch::current::context::align_initial_stack(tf.arg(2));
    let arg = tf.arg(3);
    let tls_base = tf.arg(4);

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Thread; pointer is valid.
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // The entry point, the aligned stack pointer and the TLS base must be user
    // addresses: the thread's first return to user mode resumes at the entry on
    // that stack. On x86-64 an `iretq` to a non-canonical RIP faults in ring 0
    // after the GS swap back to the user base, and a non-canonical TLS base makes
    // the context switch's `wrmsr` to `IA32_FS_BASE` #GP in ring 0, on the kernel
    // GS base, on the first switch into the thread.
    let user_top = crate::mm::user_va_top();
    if entry >= user_top || tf.arg(2) > user_top || stack_ptr > user_top || tls_base >= user_top
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: target_tcb validated non-null; kernel_stack_top set at creation.
    let kstack_top = unsafe { (*target_tcb).kernel_stack_top };

    // Build the initial TrapFrame on the thread's kernel stack, just below
    // the stack top. This mirrors the setup in `sched::enter()`.
    let tf_size = size_of::<ArchTrapFrame>() as u64;
    let tf_ptr = (kstack_top - tf_size) as *mut ArchTrapFrame;

    // The thread must be `Created`, decided under its sched_lock and held for
    // the writes below: a concurrent SYS_THREAD_START's commit takes the same
    // lock, so it either commits before (and this call is refused) or after
    // the frame, `trap_frame` and `saved_state` are complete. A `Created`
    // thread is current on no CPU.
    // SAFETY: target_tcb validated non-null; lock_raw paired with the
    // unlock_raw on both paths below.
    let sched_saved = unsafe { (*target_tcb).sched_lock.lock_raw() };
    // SAFETY: state is written under the held sched_lock.
    if unsafe { (*target_tcb).state } != ThreadState::Created
    {
        // SAFETY: paired with the lock_raw above.
        unsafe { (*target_tcb).sched_lock.unlock_raw(sched_saved) };
        return Err(SyscallError::InvalidArgument);
    }

    // Zero then populate user-mode entry fields.
    // SAFETY: kstack_top - tf_size is within the allocated kernel stack (4 pages);
    //         write_bytes, init_user, and set_arg0 all operate on valid memory.
    unsafe {
        core::ptr::write_bytes(tf_ptr.cast::<u8>(), 0, tf_size as usize);
        (*tf_ptr).init_user(entry, stack_ptr);
        // Pass the argument in the first argument register.
        (*tf_ptr).set_arg0(arg);
        (*tf_ptr).set_tls_base(tls_base);
    }

    // Store the trap frame pointer so sched::schedule() can find it.
    // SAFETY: target_tcb validated non-null; trap_frame field assignment is valid.
    unsafe {
        (*target_tcb)
            .trap_frame
            .store(tf_ptr, core::sync::atomic::Ordering::Relaxed);
    }

    // The first scheduler switch into this thread pulls `SavedState.fs_base`
    // from the TCB directly into `IA32_FS_BASE` (x86-64). Seed it from the
    // caller-supplied value; no-op on architectures that carry TLS state in
    // the trap frame (RISC-V uses `tp` there).
    // SAFETY: target_tcb validated non-null; saved_state has no interior
    // mutability, and the thread is `Created` under the held sched_lock, so
    // no switch reads it meanwhile.
    unsafe {
        crate::arch::current::context::seed_tls_base(&mut (*target_tcb).saved_state, tls_base);
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { (*target_tcb).sched_lock.unlock_raw(sched_saved) };

    Ok(0)
}

/// `SYS_THREAD_START` (19): move a configured `Created` thread, or a
/// `Stopped` one (resume), to `Ready` and link it on the CPU
/// `select_target_cpu` chooses.
///
/// arg0 = Thread cap index (must have CONTROL).
///
/// The thread must have been configured via `SYS_THREAD_CONFIGURE` first
/// (`trap_frame` must be non-null). Returns 0 on success, including a start
/// that a concurrent `SYS_THREAD_STOP` overtakes after its commit (the thread
/// is then left `Stopped`, unlinked).
///
/// # Errors
/// - `InvalidCapability`: the cap is invalid or not a Thread.
/// - `InsufficientRights`: the cap lacks CONTROL.
/// - `InvalidArgument`: the target is the caller, is not configured, or is not
///   `Created`/`Stopped` when the start commits (a concurrent start resumed it,
///   or it exited or was killed).
/// - `Interrupted`: the caller was itself stopped while the start waited for
///   the target to settle.
#[cfg(not(test))]
pub fn sys_thread_start(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;

    let thread_idx = tf.arg(0) as u32;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Thread must be in Created or Stopped state with a configured trap_frame.
    // Stopped → Ready acts as a resume operation (no new trap_frame needed).
    // SAFETY: target_tcb validated non-null; state/trap_frame fields always valid.
    unsafe {
        let state = (*target_tcb).state;
        if state != ThreadState::Created && state != ThreadState::Stopped
        {
            return Err(SyscallError::InvalidArgument);
        }
        if (*target_tcb)
            .trap_frame
            .load(core::sync::atomic::Ordering::Relaxed)
            .is_null()
        {
            return Err(SyscallError::InvalidArgument);
        }

        // A thread stopped while Running may still be `current` on a remote
        // CPU, or owed a wake by a waker that claimed its park before the stop;
        // start_under_all_locks waits for both to settle and commits `Ready`
        // under the all-CPU locks only if the target is still `Created` or
        // `Stopped`, off every CPU, and owed no wake (see
        // core/kernel/docs/thread-lifecycle-and-sleep.md § Lifecycle State
        // Machine and § `sys_thread_stop` Cross-CPU Stop Protocol). The state
        // read above ran without a lock: a concurrent start may have resumed
        // the target, or a teardown or exit ended it, and the commit then
        // refuses. A thread cannot start itself: it is running, and a stop
        // landing while it waited would leave it waiting for its own
        // deschedule.
        if core::ptr::eq(target_tcb, caller_tcb)
        {
            return Err(SyscallError::InvalidArgument);
        }
        let start_seq = match crate::sched::start_under_all_locks(target_tcb, caller_tcb)
        {
            crate::sched::StartCommit::Committed(seq) => seq,
            crate::sched::StartCommit::Refused => return Err(SyscallError::InvalidArgument),
            crate::sched::StartCommit::CallerStopped =>
            {
                // Deschedule now, as a self-stop does: the settle loop's
                // preempt-disabled window made the timer skip its slice-expiry
                // switch, and the syscall epilogue reschedules only an Exited
                // thread. The restart resumes here. The target pin goes first
                // (the pin-before-park rule of `PinnedCap`): a caller killed
                // while stopped would otherwise hold it for good.
                drop(thread_slot);
                crate::sched::schedule(crate::sched::Requeue::IfRunnable);
                return Err(SyscallError::Interrupted);
            }
        };
        // Route to correct CPU based on affinity. The thread is already Ready
        // (committed above), so use enqueue_ready_thread to link it: the gated
        // enqueue_and_wake would coalesce an already-Ready thread and drop it.
        // The link is made only if this commit is still current: a concurrent
        // stop (and any restart, which links the thread itself) may have
        // superseded it, and the start then took effect and was stopped.
        let target_cpu = crate::sched::select_target_cpu(target_tcb);
        if crate::sched::enqueue_ready_thread(target_tcb, target_cpu, start_seq)
            == crate::sched::ReadyLink::Exited
        {
            return Err(SyscallError::InvalidArgument);
        }
    }

    Ok(0)
}

/// Commit `Stopped` for `tcb` over any park it holds, cancelling that park
/// (`commit_cancelling_park`), and return the CPU running it (if any). An
/// `Exited` target is terminal and refused with `InvalidState`.
///
/// # Safety
/// `tcb` must be a valid TCB pointer; the caller holds no scheduler or IPC
/// source lock.
#[cfg(not(test))]
unsafe fn commit_stopped(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
) -> Result<Option<usize>, SyscallError>
{
    use crate::sched::thread::ThreadState;
    // SAFETY: caller contract.
    match unsafe { crate::sched::commit_cancelling_park(tcb, ThreadState::Stopped, None) }
    {
        crate::sched::StateCommit::Committed(running_on) => Ok(running_on),
        // RefusedState answers an expected-state predicate, which a stop
        // commit does not pass.
        crate::sched::StateCommit::RefusedExited | crate::sched::StateCommit::RefusedState =>
        {
            Err(SyscallError::InvalidState)
        }
    }
}

/// `SYS_THREAD_STOP` (20): transition a thread to the Stopped state.
///
/// arg0 = Thread cap index (must have CONTROL).
///
/// Cancels any park — an IPC wait or a `SYS_THREAD_SLEEP` — including one the
/// target commits while the stop is in progress: on restart the stopped
/// thread's blocked syscall returns `Interrupted` and a fault-blocked thread
/// is killed (see `core/kernel/docs/syscalls.md` § `SYS_THREAD_STOP`), unless
/// a genuine waker, the sleep timer, or the target's own full-list withdrawal
/// (a timed wait or sleep that found the sleep list full) claimed it first.
/// A target parked on an endpoint, notification, event queue, or wait set
/// whose last capability is deleted concurrently is claimed by the stop or by
/// the source's teardown, which stamps the same `Interrupted`. A thread may
/// stop itself (arg0 refers to the calling thread).
///
/// Returns 0 on success.
///
/// # Errors
/// - `InvalidCapability`: no current thread, or arg0 names no Thread cap.
/// - `InsufficientRights`: the cap lacks CONTROL.
/// - `InvalidState`: the target is `Created`, `Stopped`, or `Exited` when the
///   call reads it, or exits before the commit. Two concurrent stops of one
///   running thread can both succeed.
#[cfg(not(test))]
pub fn sys_thread_stop(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;

    let thread_idx = tf.arg(0) as u32;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: target_tcb validated non-null; state field always valid.
    unsafe {
        // Unlocked precheck for the InvalidState answer; the commit
        // re-decides only `Exited`, so a stop racing another stop writes
        // Stopped again and both succeed.
        if matches!(
            (*target_tcb).state,
            ThreadState::Created | ThreadState::Exited | ThreadState::Stopped
        )
        {
            return Err(SyscallError::InvalidState);
        }

        // Cancel any park (the stopped thread's blocked syscall returns
        // Interrupted on restart) and commit Stopped over it; a Ready target
        // is unlinked by the all-locks write, and a remote Running target by
        // the drain below (its CPU's next slice-expiry schedule(Requeue::Always)). See
        // core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
        // Cross-CPU Stop Protocol; an `Exited` target is refused (terminal).
        let running_on = commit_stopped(target_tcb)?;

        // If stopping self (Running → Stopped): yield so another thread runs,
        // releasing the pin on this thread's own object first (the
        // pin-before-park rule of `PinnedCap`).
        if core::ptr::eq(target_tcb, caller_tcb)
        {
            drop(thread_slot);
            crate::sched::schedule(crate::sched::Requeue::IfRunnable);
        }
        else if let Some(run_cpu) = running_on
        {
            drain_remote_stopped(
                target_tcb,
                caller_tcb,
                caller_cspace,
                thread_idx,
                run_cpu,
                thread_slot,
            );
        }
        else
        {
            await_stopped_save(target_tcb);
        }
    }

    Ok(0)
}

/// Wait for a `Stopped` target that no CPU ran at the stop's commit to
/// publish its last register save (`context_saved`), so a register read
/// after the stop returns finds the frame settled. A target that left its
/// CPU just before the commit may still be mid-switch there; the wait is that
/// switch's tail. It ends early when an object teardown commits `Exited`.
///
/// # Safety
/// `target_tcb` must be a valid TCB, and no lock may be held.
#[cfg(not(test))]
unsafe fn await_stopped_save(target_tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::sched::thread::ThreadState;
    use core::sync::atomic::Ordering;

    let unsaved = || {
        // SAFETY: target_tcb valid per contract; state is read under the
        // sched_lock every Stopped/Exited commit holds; lock_raw paired with
        // unlock_raw.
        unsafe {
            let f = (*target_tcb).sched_lock.lock_raw();
            let stopped = (*target_tcb).state == ThreadState::Stopped;
            (*target_tcb).sched_lock.unlock_raw(f);
            stopped && (*target_tcb).context_saved.load(Ordering::Acquire) == 0
        }
    };
    if !unsaved()
    {
        return;
    }
    // Spin with interrupts enabled and preemption disabled, as the drain does,
    // so an inbound TLB-shootdown IPI is still acknowledged.
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored below.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    crate::sched::spin_site_enter(crate::sched::SPIN_SITE_STOP_SAVE);
    while unsaved()
    {
        core::hint::spin_loop();
    }
    crate::sched::spin_site_exit();
    // SAFETY: saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved_int) };
    crate::percpu::preempt_enable();
}

/// Wait for `run_cpu`, which still runs `target_tcb` after `commit_stopped`
/// marked it `Stopped`, to deschedule it and publish its register save
/// (`context_saved`), so the register snapshot `sys_thread_read_regs` reads
/// is the one that trap leaves. Returns at once
/// when `run_cpu` is this CPU, and when an object teardown commits `Exited`
/// over the target. `target_pin` pins the target's `Thread` object for the
/// drain. A stop of the calling thread landing meanwhile deschedules it in
/// place, releasing the pin first; once restarted it re-resolves
/// `thread_idx` in `caller_cspace` and resumes the drain under the new pin if
/// the slot still names `target_tcb` with Control rights, and leaves it
/// otherwise.
///
/// # Safety
/// `caller_tcb` must be the running thread's valid TCB, `target_tcb` the TCB
/// of the `Thread` object `target_pin` pins, `caller_cspace` the caller's
/// `CSpace`, `run_cpu < CPU_COUNT`, and no lock may be held.
#[cfg(not(test))]
unsafe fn drain_remote_stopped(
    target_tcb: *mut crate::sched::thread::ThreadControlBlock,
    caller_tcb: *mut crate::sched::thread::ThreadControlBlock,
    caller_cspace: *mut crate::cap::cspace::CSpace,
    thread_idx: u32,
    run_cpu: usize,
    mut target_pin: super::PinnedCap,
)
{
    use crate::sched::thread::ThreadState;

    if run_cpu == crate::arch::current::cpu::current_cpu() as usize
    {
        return;
    }
    // The IPI's trap snapshots the target's user registers; the remote CPU
    // drops the Stopped target at its next slice-expiry schedule(Requeue::Always), whose
    // trap leaves the snapshot sys_thread_read_regs reads once this drain
    // completes.
    // SAFETY: run_cpu < CPU_COUNT per contract.
    unsafe { crate::sched::prod_remote_cpu(run_cpu) };
    // SAFETY: run_cpu < CPU_COUNT; the scheduler slab is initialised.
    let sched_remote = unsafe { crate::sched::scheduler_for(run_cpu) };
    let spin_start = crate::arch::current::timer::current_tick();
    let mut warned = false;
    // The drain spins until the remote CPU deschedules `target_tcb`. This
    // syscall runs with IF=0; spinning at IF=0 would block an inbound
    // TLB-shootdown IPI targeted at this CPU and deadlock it (the initiator
    // spins for our ACK with IF enabled). Enable interrupts across the spin
    // and disable preemption so the scheduler cannot migrate us mid-drain —
    // the #207 pattern dealloc's UAF gate uses.
    crate::percpu::preempt_disable();
    // SAFETY: ring 0; restored on every exit below.
    let mut drain_saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: ring 0; IDT loaded; preempt disabled.
    unsafe { crate::arch::current::interrupts::enable() };
    loop
    {
        // A start cannot commit while the target is current here, but an
        // object teardown can commit Exited over it; the state is read under
        // the lock every all-locks commit holds, and the drain ends once the
        // target is no longer Stopped so a teardown that then reaps it is not
        // waited on.
        // SAFETY: lock_raw paired with unlock_raw; target_tcb valid per
        // contract.
        let draining = unsafe {
            let s = sched_remote.lock.lock_raw();
            let still_current = sched_remote.current() == target_tcb;
            let still_stopped = (*target_tcb).state == ThreadState::Stopped;
            sched_remote.lock.unlock_raw(s);
            // The drain also outlasts the switch-out's save: `current` moves
            // off the target before `switch()` publishes `context_saved`.
            let unsaved = (*target_tcb)
                .context_saved
                .load(core::sync::atomic::Ordering::Acquire)
                == 0;
            still_stopped && (still_current || unsaved)
        };
        if !draining
        {
            break;
        }
        if !warned
        {
            // SAFETY: target_tcb valid per contract; run_cpu < CPU_COUNT.
            warned = unsafe { warn_slow_drain(target_tcb, run_cpu, spin_start) };
        }
        // SAFETY: caller_tcb is the running thread.
        if unsafe { stopper_stopped(caller_tcb) }
        {
            // This preempt-disabled window suppresses the slice-expiry switch
            // that would deschedule a stopped stopper: deschedule in place,
            // and resume the drain once restarted. Two threads stopping each
            // other thus both end Stopped instead of both spinning.
            // SAFETY: drain_saved_int from save_and_disable_interrupts.
            unsafe { crate::arch::current::cpu::restore_interrupts(drain_saved_int) };
            crate::percpu::preempt_enable();
            // The target pin goes before the park (the pin-before-park rule
            // of `PinnedCap`): a stopper killed while stopped never resumes
            // to release it.
            drop(target_pin);
            // SAFETY: the running thread deschedules itself with no lock held.
            unsafe { crate::sched::schedule(crate::sched::Requeue::IfRunnable) };
            // SAFETY: caller_cspace is the caller's CSpace per contract; no
            // lock held.
            let Some(repinned) =
                (unsafe { slot_names_thread(caller_cspace, thread_idx, target_tcb) })
            else
            {
                return;
            };
            target_pin = repinned;
            crate::percpu::preempt_disable();
            // SAFETY: ring 0; restored on every exit.
            drain_saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
            // SAFETY: ring 0; IDT loaded; preempt disabled.
            unsafe { crate::arch::current::interrupts::enable() };
            continue;
        }
        core::hint::spin_loop();
    }
    // SAFETY: drain_saved_int from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(drain_saved_int) };
    crate::percpu::preempt_enable();
    // The drain is over: release the target pin with interrupts restored and
    // no lock held.
    drop(target_pin);
}

/// Print the single-shot diagnostic once a stop drain has spun for over
/// 100 ms; returns whether it printed.
///
/// # Safety
/// `target_tcb` must be a valid TCB, `run_cpu < CPU_COUNT`, and the caller
/// must hold no `sched_lock` and no scheduler lock.
#[cfg(not(test))]
unsafe fn warn_slow_drain(
    target_tcb: *mut crate::sched::thread::ThreadControlBlock,
    run_cpu: usize,
    spin_start: u64,
) -> bool
{
    let now = crate::arch::current::timer::current_tick();
    let tps = crate::arch::current::timer::ticks_per_second();
    if tps == 0 || now.saturating_sub(spin_start) <= tps / 10
    {
        return false;
    }
    // SAFETY: target_tcb is valid per contract; `thread_id` is immutable. The
    // target's state is read under its `sched_lock`, and the remote CPU's
    // `current` under that CPU's scheduler lock, which keeps that thread from
    // being freed while it is `current` (dealloc's not-current scan reads
    // under the same lock); both are try-locked, so the diagnostic never waits.
    let (tid, st, cur_tid) = unsafe {
        let sched = crate::sched::scheduler_for(run_cpu);
        (
            (*target_tcb).thread_id,
            (*target_tcb).sched_lock.try_lock_raw().map(|saved| {
                let st = (*target_tcb).state;
                (*target_tcb).sched_lock.unlock_raw(saved);
                st
            }),
            sched.lock.try_lock_raw().map(|saved| {
                let cur = sched.current();
                let cur_tid = if cur.is_null() { 0 } else { (*cur).thread_id };
                sched.lock.unlock_raw(saved);
                cur_tid
            }),
        )
    };
    if let (Some(st), Some(cur_tid)) = (st, cur_tid)
    {
        crate::kprintln!(
            "kernel: sys_thread_stop spin >100ms target_tid={} state={:?} run_cpu={} cur_tid={}",
            tid,
            st,
            run_cpu,
            cur_tid
        );
    }
    else
    {
        crate::kprintln!(
            "kernel: sys_thread_stop spin >100ms target_tid={} run_cpu={} (locks held)",
            tid,
            run_cpu
        );
    }
    true
}

/// Whether the calling thread has itself been stopped or exited while it
/// drains (a peer stopping its stopper, or an object teardown), read under its
/// own `sched_lock`, which every such commit holds.
///
/// # Safety
/// `caller_tcb` must be the running thread's valid TCB.
#[cfg(not(test))]
unsafe fn stopper_stopped(caller_tcb: *mut crate::sched::thread::ThreadControlBlock) -> bool
{
    use crate::sched::thread::ThreadState;
    // SAFETY: per contract; lock_raw paired with unlock_raw.
    let st = unsafe {
        let f = (*caller_tcb).sched_lock.lock_raw();
        let st = (*caller_tcb).state;
        (*caller_tcb).sched_lock.unlock_raw(f);
        st
    };
    matches!(st, ThreadState::Stopped | ThreadState::Exited)
}

/// Re-resolve `thread_idx` in `cspace` after an in-place park and return
/// the new pin if the slot still names `target_tcb` with Control rights, so a
/// stopper restarted after the park neither touches a target deleted
/// meanwhile (the slot's generation check refuses a recycled slot) nor holds
/// a pin across the park (the pin-before-park rule of `PinnedCap`).
///
/// # Safety
/// `cspace` must be the calling thread's valid `CSpace`, and no lock may be
/// held.
#[cfg(not(test))]
unsafe fn slot_names_thread(
    cspace: *mut crate::cap::cspace::CSpace,
    thread_idx: u32,
    target_tcb: *mut crate::sched::thread::ThreadControlBlock,
) -> Option<super::PinnedCap>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    // SAFETY: cspace valid per contract and no lock held; lookup_cap checks
    // tag, generation and rights.
    let pin = unsafe { super::lookup_cap(cspace, thread_idx, ThreadRights::CONTROL) }.ok()?;
    let obj = pin.object?;
    // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
    // SAFETY: `pin` keeps the object live, and a Thread slot's object is a
    // ThreadObject.
    #[allow(clippy::cast_ptr_alignment)]
    let names = unsafe { core::ptr::eq((*obj.as_ptr().cast::<ThreadObject>()).tcb, target_tcb) };
    names.then_some(pin)
}

/// Clear a park binding whose claim the caller just won, inside the
/// `sched_lock` hold the claim ran under. For a reply or fault park the claim
/// is the `reply_tcb` CAS, which leaves the server's `reply_tcb` null, so a
/// later `dealloc_object(Thread)` of the server no longer reaches this client
/// to null its binding before the free; for a source park it is the unlink
/// from the source's queue, after which the source's teardown no longer
/// reaches the thread. Either way a binding left naming the server or the
/// source past this hold would let a second canceller, or
/// `dealloc_object(Thread)` of this thread, pass its binding re-read and touch
/// a freed server or source (core/kernel/docs/scheduling-internals.md § Lock
/// Hierarchy rule 7).
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds.
#[cfg(not(test))]
unsafe fn clear_park_binding(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    // SAFETY: caller holds tcb.sched_lock, which serializes these fields.
    unsafe {
        (*tcb).ipc_state = crate::sched::thread::IpcThreadState::None;
        (*tcb).blocked_on_object = core::ptr::null_mut();
    }
}

/// Cancel the IPC block on a thread that is in `Blocked` state.
///
/// Unlinks the thread from the relevant IPC queue, for a source waiter only the
/// park it snapshotted (a later park on the same source is left to the caller's
/// retry; the reply and fault arms gate on a `blocked_on_object` re-read
/// instead and may cancel a later park on the same server), and, on each arm's
/// exclusive wake-claim win, stamps the park episode
/// [`PARK_DISPOSITION_INTERRUPTED`] (fault episodes get `FAULT_OUTCOME_KILL`)
/// so the restarted thread's resume consumes the cancellation instead of a
/// stale wake deposit, and clears the thread's park binding inside the claim's
/// `sched_lock` hold, whatever state a concurrent stop or teardown commits over
/// the claimed park afterwards. A lost claim means another claimant owns the
/// episode, its deposit stands, and rule 7 of
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy names who retires
/// the binding.
///
/// [`PARK_DISPOSITION_INTERRUPTED`]: crate::sched::thread::PARK_DISPOSITION_INTERRUPTED
///
/// A source waiter's source is reached only through `ipc::lock_bound_source`,
/// which proves the source live by the binding it re-reads under the thread's
/// `sched_lock` and try-locks the source under it, so a concurrent
/// last-capability delete of the source cannot free it under the cancel.
///
/// A plain sleep is cancelled through `sleep_list_remove`, and a timed IPC
/// wait's sleep-list entry is removed with its queue entry under the source
/// lock (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants).
///
/// # Safety
/// `tcb` must be a valid TCB. The caller MUST NOT hold the target's `sched_lock`
/// or any per-CPU scheduler lock: this function acquires `tcb.sched_lock` itself
/// for the binding read-and-clear, and a source's IPC lock under it for the
/// unlink (a try-lock, the inverse of the canonical source IPC → `sched_lock`
/// order; `SLEEP_LIST_LOCK` nests inside either as a leaf), so it MUST NOT
/// hold any IPC source lock or `SLEEP_LIST_LOCK` either. The caller MAY hold
/// `THREAD_REGISTRY_LOCK` (ordered before every lock taken here; the
/// object-teardown walk does), which keeps `tcb` from being freed meanwhile.
// too_many_lines: flat dispatch over every `IpcThreadState` variant; splitting
// adds no clarity (each arm is independent and short).
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
pub(crate) unsafe fn cancel_ipc_block(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::ipc::endpoint::{EndpointState, unlink_from_wait_queue};
    use crate::ipc::event_queue::EventQueueState;
    use crate::ipc::notification::NotificationState;
    use crate::ipc::wait_set::WaitSetState;
    use crate::sched::thread::IpcThreadState;

    // Snapshot (state, ipc_state, blocked_on_object, park_seq) under the
    // per-TCB sched_lock — the authoritative serializer for the Scheduling
    // field group; park_seq also names the park a source arm may claim.
    // Reading them without it would race enqueue_and_wake / commit_blocked
    // (which write these under sched_lock) and could observe a torn binding.
    // If a concurrent waker already moved the thread off Blocked, its wake
    // stands: there is nothing to cancel, so return without touching the
    // source or the episode. The source arms below re-read the binding under
    // a fresh sched_lock hold before they touch the source.
    //
    // A plain sleeper (Blocked, ipc_state None) is cancelled here, under
    // sched_lock so the park cannot change underneath: sleep_list_remove clears
    // the deadline with the entry, and a `true` return is the episode claim —
    // the deadline was still pending (listed, or committed but not yet added,
    // whose add then refuses). The timer pop clears the deadline under the same
    // lock, so a pop that won leaves the episode to its wake. Its claim deposits
    // nothing, so a cancellation stamp is the only deposit.
    // SAFETY: tcb validated by caller; fields read/written under sched_lock;
    // SLEEP_LIST_LOCK is a leaf, nested under sched_lock.
    let (ipc_state, blocked_on, park_seq) = unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let snap = (
            (*tcb).ipc_state,
            (*tcb).blocked_on_object,
            (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed),
        );
        let blocked = (*tcb).state == crate::sched::thread::ThreadState::Blocked;
        if blocked && snap.0 == IpcThreadState::None && crate::sched::sleep_list_remove(tcb)
        {
            crate::sched::thread::stamp_park_deposit(
                tcb,
                crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
            );
        }
        (*tcb).sched_lock.unlock_raw(saved);
        if !blocked
        {
            return;
        }
        snap
    };

    // Each source branch locks the source the snapshotted binding names
    // through `ipc::lock_bound_source`: it re-reads the binding under this
    // thread's sched_lock and, while it still names the snapshotted park,
    // try-locks the source with the sched_lock held. A binding observed under
    // sched_lock names a source that is not yet freed (that function's
    // rustdoc gives the argument), which a plain lock taken after the
    // snapshot's release could not assume: the source's last-capability
    // delete could claim the waiter, or find it already claimed, and free the
    // source in between. Under both locks the branch unlinks this thread from
    // the source's waiter queue, racing any concurrent waker for the park
    // under that same source lock (core/kernel/docs/scheduling-internals.md
    // § Lock Hierarchy, rule 7).
    //
    // A source arm claims only the snapshotted park: a waker may have claimed
    // it since, and the thread run and parked on the same source again. Every
    // park commit advances park_seq under sched_lock, so the re-read refuses a
    // later park, which the retried commit's next pass cancels. A won claim
    // clears the binding inside the same sched_lock hold, so no later reader
    // of the binding (a second canceller, this thread's own teardown drain)
    // can pass its re-read once the source no longer queues the thread.
    match ipc_state
    {
        IpcThreadState::BlockedOnSend =>
        {
            // SAFETY: tcb is valid and no lock is held (contract).
            let held = unsafe {
                crate::ipc::lock_bound_source(tcb, ipc_state, blocked_on, Some(park_seq))
            };
            if let Some(held) = held
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = blocked_on.cast::<EndpointState>();
                // SAFETY: `held` holds ep.lock on the live endpoint the binding
                // names, and tcb's sched_lock.
                unsafe {
                    let unlinked =
                        unlink_from_wait_queue(tcb, &mut (*ep).send_head, &mut (*ep).send_tail);
                    // Republish send-queue level after the unlink (#285-adjacent).
                    (*ep).refresh_send_ready();
                    // Claim = the send-queue unlink under ep.lock (recv
                    // dequeues under the same lock, so winning it makes this
                    // the episode's sole depositor). A fault sender (queued
                    // for delivery) whose fault this cancel claimed must kill,
                    // not resume, when next scheduled: its resume runs the
                    // fault helper, which has no syscall to return
                    // `Interrupted` to; `in_fault_delivery` is read only behind
                    // the won unlink, the claim that orders it after the
                    // faulter's own write. A stopped sys_ipc_call caller
                    // resumes via the disposition. A lost unlink hands the
                    // episode to a racing endpoint_recv's rebind chain (a
                    // handler reply, or its teardown, which owns the
                    // disposition; a KILL stored here would overwrite a
                    // handler's RESUME), the endpoint's dealloc drain, or a
                    // concurrent cancel that already claimed it, or the
                    // thread's own dealloc_object(Thread) unlinked it as it
                    // dies; the retry pass cancels a rebound park.
                    if unlinked
                    {
                        if (*tcb).in_fault_delivery
                        {
                            (*tcb).fault_outcome.store(
                                crate::ipc::fault::FAULT_OUTCOME_KILL,
                                core::sync::atomic::Ordering::Release,
                            );
                            crate::sched::thread::stamp_deposit_episode(tcb);
                        }
                        else
                        {
                            crate::sched::thread::stamp_park_deposit(
                                tcb,
                                crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                            );
                        }
                        clear_park_binding(tcb);
                    }
                    held.unlock();
                }
            }
        }

        IpcThreadState::BlockedOnRecv =>
        {
            // SAFETY: tcb is valid and no lock is held (contract).
            let held = unsafe {
                crate::ipc::lock_bound_source(tcb, ipc_state, blocked_on, Some(park_seq))
            };
            if let Some(held) = held
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = blocked_on.cast::<EndpointState>();
                // SAFETY: `held` holds ep.lock on the live endpoint the binding
                // names, and tcb's sched_lock.
                unsafe {
                    // Claim = the recv-queue unlink under ep.lock (endpoint_call
                    // dequeues receivers under the same lock, so winning it makes
                    // this the episode's sole depositor). A lost unlink means a
                    // caller already deposited into ipc_msg, whose delivery stands
                    // and the resume publishes (fail-open), or the endpoint's
                    // dealloc drain or a concurrent cancel already claimed the
                    // park, or the thread's own dealloc_object(Thread) unlinked
                    // it as it dies.
                    if unlink_from_wait_queue(tcb, &mut (*ep).recv_head, &mut (*ep).recv_tail)
                    {
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                        clear_park_binding(tcb);
                    }
                    held.unlock();
                }
            }
        }

        IpcThreadState::BlockedOnReply =>
        {
            // blocked_on is the server TCB. The reply_tcb CAS dereferences it under
            // this client's sched_lock, gated by a blocked_on_object re-read, per the
            // CLOSURE LEMMA (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
            // Ownership, #317).
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let server = blocked_on.cast::<crate::sched::thread::ThreadControlBlock>();
                // SAFETY: tcb valid; sched_lock paired with unlock below. server is live for
                // the CAS by the CLOSURE LEMMA.
                unsafe {
                    let saved = (*tcb).sched_lock.lock_raw();
                    if (*tcb).state == crate::sched::thread::ThreadState::Blocked
                        && (*tcb).ipc_state == IpcThreadState::BlockedOnReply
                        && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
                    {
                        let cancelled = (*server)
                            .reply_tcb
                            .compare_exchange(
                                tcb,
                                core::ptr::null_mut(),
                                core::sync::atomic::Ordering::AcqRel,
                                core::sync::atomic::Ordering::Acquire,
                            )
                            .is_ok();
                        // We cancelled the pending reply wake; release the
                        // wake-in-flight claim endpoint_call/recv set when this
                        // thread became BlockedOnReply, so a concurrent
                        // dealloc_object(Thread) does not wait for a wake that will
                        // never fire (#160). The CAS win is the episode claim:
                        // stamp Interrupted so the stopped caller's resume takes
                        // the error path instead of reading a stale ipc_msg.
                        if cancelled
                        {
                            crate::sched::thread::stamp_park_deposit(
                                tcb,
                                crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                            );
                            clear_park_binding(tcb);
                            (*tcb)
                                .wake_in_flight
                                .store(0, core::sync::atomic::Ordering::Release);
                        }
                    }
                    (*tcb).sched_lock.unlock_raw(saved);
                }
            }
        }

        IpcThreadState::BlockedOnFault =>
        {
            // Mirror BlockedOnReply: `blocked_on` is the handler (server) TCB,
            // whose `reply_tcb` points at this faulter. CAS-clear it so a later
            // handler reply cannot double-wake. On a successful cancel, mark the
            // disposition Kill (the fault helper terminates the thread on
            // resume) and release the wake-in-flight claim. If the CAS loses, a
            // genuine reply already won and committed its own disposition — leave
            // it untouched.
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let server = blocked_on.cast::<crate::sched::thread::ThreadControlBlock>();
                // SAFETY: tcb valid; sched_lock paired with unlock. server is live for the CAS
                // by the CLOSURE LEMMA (#317; mirrors the BlockedOnReply arm above).
                unsafe {
                    let saved = (*tcb).sched_lock.lock_raw();
                    if (*tcb).state == crate::sched::thread::ThreadState::Blocked
                        && (*tcb).ipc_state == IpcThreadState::BlockedOnFault
                        && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
                    {
                        let cancelled = (*server)
                            .reply_tcb
                            .compare_exchange(
                                tcb,
                                core::ptr::null_mut(),
                                core::sync::atomic::Ordering::AcqRel,
                                core::sync::atomic::Ordering::Acquire,
                            )
                            .is_ok();
                        if cancelled
                        {
                            (*tcb).fault_outcome.store(
                                crate::ipc::fault::FAULT_OUTCOME_KILL,
                                core::sync::atomic::Ordering::Release,
                            );
                            // CAS win = episode claim (fault disposition lives
                            // in fault_outcome; stamp the episode only).
                            crate::sched::thread::stamp_deposit_episode(tcb);
                            clear_park_binding(tcb);
                            (*tcb)
                                .wake_in_flight
                                .store(0, core::sync::atomic::Ordering::Release);
                        }
                    }
                    (*tcb).sched_lock.unlock_raw(saved);
                }
            }
        }

        IpcThreadState::BlockedOnNotification =>
        {
            // SAFETY: tcb is valid and no lock is held (contract).
            let held = unsafe {
                crate::ipc::lock_bound_source(tcb, ipc_state, blocked_on, Some(park_seq))
            };
            if let Some(held) = held
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let sig = blocked_on.cast::<NotificationState>();
                // SAFETY: `held` holds sig.lock on the live notification the
                // binding names, and tcb's sched_lock; SLEEP_LIST_LOCK is a
                // leaf under both.
                unsafe {
                    // Claim = the removal from the waiter queue under sig.lock
                    // (every genuine waker claims under the same lock). A lost
                    // race means the waker's deposit stands and the resume
                    // delivers it (fail-open), or a concurrent cancel already
                    // claimed and stamped it, or the thread's own
                    // dealloc_object(Thread) unlinked it as it dies, or its
                    // own full-list withdrawal dequeued it and returns 0 bits.
                    if (*sig).waiters.remove(tcb)
                    {
                        // Re-derive the observer flag like every other
                        // waiter-removal site; leaving it set would pin all
                        // future sends onto the slow path.
                        (*sig).refresh_observer();
                        // A timed wait's entry goes with the waiter, under
                        // sig.lock, as at every waiter claim.
                        if (*tcb)
                            .sleep_deadline
                            .load(core::sync::atomic::Ordering::Relaxed)
                            != 0
                        {
                            crate::sched::sleep_list_remove(tcb);
                        }
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                        clear_park_binding(tcb);
                    }
                    held.unlock();
                }
            }
        }

        IpcThreadState::BlockedOnEventQueue =>
        {
            // SAFETY: tcb is valid and no lock is held (contract).
            let held = unsafe {
                crate::ipc::lock_bound_source(tcb, ipc_state, blocked_on, Some(park_seq))
            };
            if let Some(held) = held
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let eq = blocked_on.cast::<EventQueueState>();
                // SAFETY: `held` holds eq.lock on the live event queue the
                // binding names, and tcb's sched_lock; SLEEP_LIST_LOCK is a
                // leaf under both.
                unsafe {
                    // Claim = the removal from the waiter queue under eq.lock; a
                    // lost race means a genuine wake's deposit stands
                    // (fail-open), or a concurrent cancel already claimed and
                    // stamped it, or the thread's own dealloc_object(Thread)
                    // unlinked it as it dies, or its own full-list withdrawal
                    // dequeued it and returns WouldBlock.
                    if (*eq).waiters.remove(tcb)
                    {
                        // A timed wait's entry goes with the waiter, under
                        // eq.lock, as at every waiter claim.
                        if (*tcb)
                            .sleep_deadline
                            .load(core::sync::atomic::Ordering::Relaxed)
                            != 0
                        {
                            crate::sched::sleep_list_remove(tcb);
                        }
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                        clear_park_binding(tcb);
                    }
                    held.unlock();
                }
            }
        }

        IpcThreadState::BlockedOnWaitSet =>
        {
            // SAFETY: tcb is valid and no lock is held (contract).
            let held = unsafe {
                crate::ipc::lock_bound_source(tcb, ipc_state, blocked_on, Some(park_seq))
            };
            if let Some(held) = held
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ws = blocked_on.cast::<WaitSetState>();
                // SAFETY: `held` holds ws.lock on the live wait set the
                // binding names, and tcb's sched_lock.
                unsafe {
                    // Claim = the removal from the waiter queue under ws.lock;
                    // a lost race means a genuine wake's deposit stands
                    // (fail-open), or a concurrent cancel already claimed and
                    // stamped it, or the thread's own dealloc_object(Thread)
                    // unlinked it as it dies.
                    if (*ws).waiters.remove(tcb)
                    {
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                        clear_park_binding(tcb);
                    }
                    held.unlock();
                }
            }
        }

        // A plain sleeper, cancelled (or found claimed) under sched_lock above.
        IpcThreadState::None =>
        {}
    }
}

/// `SYS_THREAD_SET_FAULT_HANDLER` (32): bind or clear a thread's fault-handler
/// endpoint.
///
/// arg0 = Thread cap index (must have CONTROL) — the thread whose handler is set.
/// arg1 = Endpoint cap index, or `0` to **unbind**.
/// arg2 = reserved; MUST be `0`. The fault message badge is the derivation
///        badge of the arg1 cap, never a binder-supplied value
///        (`docs/fault-handling.md` § Security).
/// arg3 = `fault_class_mask`; v1 accepts only [`syscall::FAULT_CLASS_ALL`].
///
/// Binding takes a reference on the endpoint object for the binding's lifetime
/// (see `docs/fault-handling.md` § Liveness); rebinding / unbinding / thread
/// destruction releases it. The target Thread and the endpoint are pinned for
/// the call (`lookup_cap`), so a concurrent delete of either one's last
/// capability frees it only after the binding is published. The endpoint and
/// its badge are published as one unit under the target's `sched_lock`, the
/// lock `ipc::fault::fault_dispatch` reads them under.
/// Binding requires only a valid `Endpoint` cap — `CONTROL` on the thread is
/// the authority; the endpoint cap names where this thread's
/// kernel-unresolvable faults are delivered and, by its badge, how they are
/// attributed.
///
/// Returns 0 on success; `InvalidArgument` for a nonzero arg2 or an
/// unsupported arg3.
#[cfg(not(test))]
pub fn sys_thread_set_fault_handler(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EndpointObject, KernelObjectHeader, ThreadObject};
    use crate::cap::slot::{EpRights, ThreadRights};
    use crate::syscall::current_tcb;
    use core::sync::atomic::Ordering;

    let thread_idx = tf.arg(0) as u32;
    let endpoint_idx = tf.arg(1) as u32;
    let reserved = tf.arg(2);
    let fault_class_mask = tf.arg(3);

    // v1 supports only the all-classes mask; the argument reserves the encoding
    // for future per-class handlers without a new syscall. arg2 once carried a
    // binder-chosen badge; it is reserved so a caller still passing one fails
    // loudly instead of having its value ignored.
    if reserved != 0 || fault_class_mask != syscall::FAULT_CLASS_ALL
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: current_tcb() returns current thread; valid in syscall context.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; CONTROL required to mutate the target.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;
    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };
    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Resolve the new handler object (index 0 = unbind), pinned until the
    // binding's own reference is taken below.
    let ep_slot = if endpoint_idx == 0
    {
        None
    }
    else
    {
        // SAFETY: caller_cspace validated; no specific endpoint right required.
        Some(unsafe { super::lookup_cap(caller_cspace, endpoint_idx, EpRights::NONE) }?)
    };
    let (new_ep, new_badge): (*mut EndpointObject, u64) = match &ep_slot
    {
        None => (core::ptr::null_mut(), 0),
        Some(slot) =>
        {
            let obj = slot.object.ok_or(SyscallError::InvalidCapability)?;
            // cast_ptr_alignment: header at offset 0 of EndpointObject; allocator guarantees alignment.
            #[allow(clippy::cast_ptr_alignment)]
            let p = obj.as_ptr().cast::<EndpointObject>();
            (p, slot.badge)
        }
    };

    // Take the new binding's reference before publishing it, so the object
    // cannot be freed between publish and a faulter's load.
    if !new_ep.is_null()
    {
        // SAFETY: new_ep is the EndpointObject `ep_slot` pins.
        unsafe { (*new_ep).header.inc_ref() };
    }

    // Publish (endpoint, badge) as one unit under the target's sched_lock.
    // `fault_dispatch` reads the pair under the same lock and takes its own
    // reference on the endpoint before unlocking, so the release of the old
    // binding below cannot free an endpoint a delivery still uses, and no
    // faulter pairs one binding's endpoint with another's badge.
    // SAFETY: target_tcb is the TCB of the Thread object `thread_slot` pins;
    // lock_raw is paired with the unlock_raw below.
    let old_ep = unsafe {
        let saved = (*target_tcb).sched_lock.lock_raw();
        (*target_tcb)
            .fault_badge
            .store(new_badge, Ordering::Relaxed);
        let old = (*target_tcb).fault_handler.swap(new_ep, Ordering::AcqRel);
        (*target_tcb).sched_lock.unlock_raw(saved);
        old
    };

    // Release the previous binding's reference, freeing the object if this was
    // its last reference, outside every lock (release_ref's precondition).
    // Rebinding to the same endpoint nets to a no-op (the inc above balances
    // this release).
    if let Some(old) = core::ptr::NonNull::new(old_ep)
    {
        // SAFETY: old was a live EndpointObject referenced by this binding,
        // whose reference this call now owns; the header is at offset 0;
        // syscall context with interrupts disabled and no lock held.
        unsafe { crate::cap::object::release_ref(old.cast::<KernelObjectHeader>()) };
    }

    Ok(0)
}

/// `SYS_THREAD_SET_PRIORITY` (37): change a thread's scheduling priority.
///
/// arg0 = Thread cap index (selects *which* thread; must have CONTROL).
/// arg1 = New priority (`1`–`PRIORITY_MAX`; 0 and 31 are rejected).
/// arg2 = `SchedControl` cap index (governs *which level*; always required).
///
/// Composition: the Thread/CONTROL cap authorises mutating that thread; the
/// `SchedControl` cap authorises the requested level — it must be a
/// `SchedControl` whose `[min, max]` band covers `arg1`. Holding no
/// `SchedControl` (or one whose band excludes the level) cannot set any
/// priority. There is no ambient priority authority.
///
/// The change takes effect at the next scheduler invocation. If the thread is
/// currently in the Ready state, it is moved to the new priority queue immediately.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_set_priority(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{SchedControlObject, ThreadObject};
    use crate::cap::slot::{SchedRights, ThreadRights};
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;
    use syscall::PRIORITY_MAX;

    let thread_idx = tf.arg(0) as u32;
    // Validate the full 64-bit argument: a value above u8 is out of range, not
    // its low byte.
    let priority = u8::try_from(tf.arg(1)).map_err(|_| SyscallError::InvalidArgument)?;
    let sched_idx = tf.arg(2) as u32;

    // Validate priority range: 0 (idle) and 31 (reserved) are rejected.
    if priority == 0 || priority > PRIORITY_MAX
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // Setting any priority requires a SchedControl cap whose band covers the
    // requested level. Presence-only — no rights bit to check.
    // SAFETY: caller_cspace validated; lookup_cap checks the tag.
    let sched_slot = unsafe { super::lookup_cap(caller_cspace, sched_idx, SchedRights::NONE) }?;
    let sched_obj = sched_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0 of SchedControlObject; allocator guarantees alignment.
    // SAFETY: tag confirmed SchedControl; pointer is a valid SchedControlObject.
    #[allow(clippy::cast_ptr_alignment)]
    let sched = unsafe { &*(sched_obj.as_ptr().cast::<SchedControlObject>()) };
    if priority < sched.min || priority > sched.max
    {
        return Err(SyscallError::InsufficientRights);
    }

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // `priority`, `state`, and the run-queue link are in the Scheduling field
    // group, whose authoritative serializer is the per-TCB `sched_lock`
    // (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership). Hold it across
    // the `state` read, the `priority` write, and the relocate so they cannot
    // race `enqueue_and_wake` / `commit_blocked` / `schedule`, which write the
    // same fields under the same lock. `sched_lock` — not the run-queue locks —
    // is the serializer for the scalar fields; the run-queue lock is needed only
    // to relink the queue entry, which `relocate_ready_priority` acquires (one
    // CPU on a `preferred_cpu` hint hit, the ascending all-CPU walk on a miss).
    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;

    // SAFETY: target_tcb validated non-null; lock_raw paired with the unlock_raw
    // below (released last, restoring the caller's interrupt state).
    let tcb_sched_saved = unsafe { (*target_tcb).sched_lock.lock_raw() };

    // SAFETY: target_tcb validated non-null. `sched_lock` (held) serializes these
    // Scheduling-group accesses against every other writer.
    unsafe {
        let old_prio = (*target_tcb).priority;
        let state = (*target_tcb).state;
        (*target_tcb).priority = priority;

        if state == ThreadState::Ready && old_prio != priority
        {
            // A Ready TCB is normally linked on exactly one CPU's run queue, the
            // one named by `preferred_cpu` (#359). Clamp the hint — a corrupt
            // value is treated as cpu 0 and corrected by the walk fallback — and
            // relocate the queue entry to the new priority. `relocate_ready_priority`
            // returns `None` when the TCB is found on no queue: the transient
            // Ready-but-unlinked window of `schedule()`'s cross-CPU outgoing
            // branch / `sys_thread_start`. The new priority is already committed
            // above, and the pending link re-reads `(*tcb).priority` under the
            // destination run-queue lock, so the link lands at the new priority.
            let hint = {
                let p = (*target_tcb).preferred_cpu as usize;
                if p < cpu_count { p } else { 0 }
            };
            let _ = crate::sched::relocate_ready_priority(
                target_tcb, old_prio, priority, hint, cpu_count,
            );
        }
    }

    // Release `sched_lock`, restoring the caller's interrupt state.
    // SAFETY: tcb_sched_saved from the lock_raw above.
    unsafe {
        (*target_tcb).sched_lock.unlock_raw(tcb_sched_saved);
    }

    Ok(0)
}

/// `SYS_SCHED_SPLIT` (52): split a `SchedControl` cap into two children
/// covering disjoint priority bands.
///
/// arg0 = `SchedControl` cap index.
/// arg1 = `split_at`: the lowest priority level of the upper child. Must
///        satisfy `min < split_at <= max` on the cap being split. The lower
///        child covers `[min, split_at - 1]`; the upper child covers
///        `[split_at, max]`.
///
/// Consumes the original cap and creates two new `SchedControl` caps covering
/// the two bands; both are reparented to the original's derivation parent.
/// `cap_derive` cannot narrow a band (it attenuates rights only), so this is
/// the sole way to hand out a sub-band. Presence-only authority; no rights bit.
///
/// Returns the two child handles in the primary and secondary return
/// registers.
#[cfg(not(test))]
pub fn sys_sched_split(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{KernelObjectHeader, ObjectType, SchedControlObject, dealloc_object};
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::seed_header_nn;
    use crate::cap::slot::{CapTag, SchedRights};
    use crate::cap::split::install_split_children;
    use crate::syscall::current_tcb;

    let sched_handle = tf.arg(0) as u32;
    // A value above u8 cannot name a level; reject it rather than its low byte.
    let split_at = u8::try_from(tf.arg(1)).map_err(|_| SyscallError::InvalidArgument)?;
    // arg2 reserved.

    // ── Capability lookup ─────────────────────────────────────────────────────

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };
    if caller_cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // `_orig_pin` keeps the original pinned until the split has consumed it,
    // so the object the split revalidates under the derivation lock is live.
    let (min, max, rights, cspace_id, orig_obj_ptr, _orig_pin) = {
        // SAFETY: caller_cspace validated; lookup_cap checks the tag (presence-only).
        let slot = unsafe { super::lookup_cap(caller_cspace, sched_handle, SchedRights::NONE) }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        // SAFETY: tag confirmed SchedControl; pointer is a valid SchedControlObject.
        #[allow(clippy::cast_ptr_alignment)]
        let sc = unsafe { &*(obj_ptr.as_ptr().cast::<SchedControlObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (sc.min, sc.max, slot.rights, cspace_id, obj_ptr, slot)
    };

    // ── Validation ────────────────────────────────────────────────────────────

    // split_at is the first level of the upper child; both halves must be
    // non-empty: lower = [min, split_at - 1], upper = [split_at, max].
    if split_at <= min || split_at > max
    {
        return Err(SyscallError::InvalidArgument);
    }

    // ── Create two child SchedControlObjects ───────────────────────────────────

    let child1_ptr = alloc_in_seed(SchedControlObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::SchedControl, seed_header_nn()),
        min,
        max: split_at - 1,
    })?;

    let child2_ptr = match alloc_in_seed(SchedControlObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::SchedControl, seed_header_nn()),
        min: split_at,
        max,
    })
    {
        Ok(p) => p,
        Err(e) =>
        {
            // SAFETY: child1_ptr is a freshly-allocated SEED-backed body with
            // refcount 1 and not yet inserted into any CSpace.
            unsafe { dealloc_object(child1_ptr) };
            return Err(e);
        }
    };

    // Install both children, rewire the derivation tree, and consume the
    // original — shared with the hardware range splits.
    // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
    // children are freshly-allocated SEED-backed SchedControlObjects (refcount 1);
    // orig_obj_ptr is the live original from lookup_cap.
    let (handle1, handle2) = unsafe {
        install_split_children(
            caller_cspace,
            cspace_id,
            sched_handle,
            CapTag::SchedControl,
            rights,
            orig_obj_ptr,
            child1_ptr,
            child2_ptr,
        )
    }?;
    // Deliver both child handles: first in the primary return register, second
    // in the secondary (rdx / a1). Never packed into one word (#349).
    tf.set_ipc_return(u64::from(handle1), u64::from(handle2));
    Ok(u64::from(handle1))
}

/// `SYS_THREAD_SET_AFFINITY` (38): set a thread's CPU affinity.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = CPU ID, or `AFFINITY_ANY` (`u32::MAX`) to clear hard affinity.
///
/// Active migration semantics:
/// - **Ready** elsewhere: dequeued from its current CPU's run queue and
///   re-enqueued on the new target via `migrate_ready_thread`.
/// - **Running** elsewhere: a reschedule-pending flag is set on the
///   source CPU and a wakeup IPI is delivered there. The wakeup IPI
///   handler does not itself call `schedule()`; the running thread
///   observes the new affinity at its next `schedule()` entry
///   (slice-expiry preemption, voluntary yield, or IPC block). The
///   affinity-vs-current-CPU check in `schedule()` then routes the
///   re-enqueue cross-CPU to the new target. Worst-case latency is
///   one time slice.
/// - **Blocked / Stopped / Created**: the new affinity takes effect on
///   the next enqueue (`enqueue_and_wake` on wake, `sys_thread_start` on
///   start or resume), both routed via `select_target_cpu`.
///
/// The affinity write, the `preferred_cpu` / `state` reads, and the action run
/// under the target's `sched_lock`, and the IPI is sent after it is released.
/// `lookup_cap` pins the target for the call, so a concurrent delete of its
/// last capability frees the TCB only after the call
/// (`core/kernel/docs/syscalls.md` § `SYS_THREAD_SET_AFFINITY`).
///
/// Returns 0 on success.
///
/// # Errors
/// - `InvalidCapability`: no current thread, or arg0 names no Thread cap.
/// - `InsufficientRights`: the cap lacks CONTROL.
/// - `InvalidArgument`: `cpu_id` is neither `AFFINITY_ANY` nor an online CPU.
#[cfg(not(test))]
pub fn sys_thread_set_affinity(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::sched::AFFINITY_ANY;
    use crate::syscall::current_tcb;
    use core::sync::atomic::Ordering;

    let thread_idx = tf.arg(0) as u32;
    // A value above u32 names no CPU and is not AFFINITY_ANY; reject it rather
    // than its low word.
    let cpu_id = u32::try_from(tf.arg(1)).map_err(|_| SyscallError::InvalidArgument)?;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Validate: must be AFFINITY_ANY or a known online CPU.
    if cpu_id != AFFINITY_ANY
    {
        let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed);
        if cpu_id >= cpu_count
        {
            return Err(SyscallError::InvalidArgument);
        }
    }

    // `cpu_affinity`, `preferred_cpu`, and `state` are in the Scheduling field
    // group, whose serializer is the target's `sched_lock`
    // (core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership). Hold
    // it across the affinity write, the reads, and the migration, so the load
    // balancer's re-check and `schedule()`'s requeue (both under the same lock)
    // see the write and the state cannot change under the decision. `lock_raw`
    // disables interrupts, so no local timer-driven `schedule()` runs inside the
    // section either. The IPI to the CPU that must act is sent after the unlock.
    // SAFETY: target_tcb is the TCB of the Thread object `thread_slot` pins for
    // the call. lock_raw is paired with the unlock_raw below.
    let tcb_sched_saved = unsafe { (*target_tcb).sched_lock.lock_raw() };

    // SAFETY: as above; every access is under the held sched_lock.
    let prod_cpu = unsafe { set_affinity_locked(target_tcb, cpu_id) };

    // SAFETY: paired with the lock_raw above.
    unsafe { (*target_tcb).sched_lock.unlock_raw(tcb_sched_saved) };

    if let Some(cpu) = prod_cpu
    {
        // SAFETY: set_affinity_locked returns only an online CPU index.
        unsafe { crate::sched::prod_remote_cpu(cpu) };
    }

    Ok(0)
}

/// Write `cpu_id` into `tcb`'s `cpu_affinity` and act on it: migrate a `Ready`
/// thread queued on another CPU, or flag the CPU running it for a reschedule.
/// Returns the CPU to prod with the wakeup IPI once the caller releases
/// `sched_lock`, if any.
///
/// # Safety
/// `tcb` is a valid TCB whose `sched_lock` the caller holds, and no scheduler
/// lock is held; `cpu_id` is `AFFINITY_ANY` or below `CPU_COUNT`.
#[cfg(not(test))]
unsafe fn set_affinity_locked(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    cpu_id: u32,
) -> Option<usize>
{
    use crate::sched::AFFINITY_ANY;
    use crate::sched::thread::ThreadState;

    // SAFETY: tcb valid and its sched_lock held (caller contract).
    let (old_cpu, state) = unsafe {
        (*tcb).cpu_affinity = cpu_id;
        ((*tcb).preferred_cpu as usize, (*tcb).state)
    };

    // No active migration when affinity is cleared (any-CPU): the load
    // balancer or the next enqueue will place the thread.
    let new_cpu = cpu_id as usize;
    if cpu_id == AFFINITY_ANY || new_cpu == old_cpu
    {
        return None;
    }

    // preferred_cpu is only ever written with an in-range CPU index (by
    // enqueue_and_wake, enqueue_ready_thread, schedule(), and the relocate /
    // migrate paths). A value >= CPU_COUNT indicates a corrupted TCB, which we
    // ignore here.
    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    if old_cpu >= cpu_count
    {
        return None;
    }

    match state
    {
        ThreadState::Ready =>
        {
            // migrate_ready_thread re-checks location under both run-queue
            // locks and declines if the thread is no longer linked on old_cpu
            // (a dequeue for dispatch already took it; `schedule()`'s
            // cross-affinity arm moves it at its next requeue).
            // SAFETY: tcb valid, its sched_lock held, no scheduler lock held;
            // both CPUs < CPU_COUNT.
            let moved = unsafe { crate::sched::migrate_ready_thread(tcb, old_cpu, new_cpu) };
            moved.then_some(new_cpu)
        }
        ThreadState::Running =>
        {
            // The Running thread's CPU sees the affinity change at its
            // next schedule() entry (see core/kernel/src/sched/mod.rs schedule() re-enqueue
            // path). The IPI does not itself call schedule(), so that entry comes at
            // worst one time slice later.
            crate::sched::set_reschedule_pending_for(old_cpu);
            Some(old_cpu)
        }
        // Blocked / Stopped / Created / Exited: next enqueue routes via
        // select_target_cpu, which reads the new affinity under sched_lock.
        _ => None,
    }
}

/// `SYS_THREAD_READ_REGS` (39): read register state of a stopped or fault-blocked
/// thread.
///
/// arg0 = Thread cap index (must have OBSERVE).
/// arg1 = Pointer to caller-supplied buffer (user VA).
/// arg2 = Size of the buffer in bytes.
///
/// The thread must be fault-blocked, or `Stopped` and descheduled
/// (`sched::with_held_frame`). Copies the full `TrapFrame` to the caller's
/// buffer. Returns the number of bytes written on success.
///
/// # Errors
/// - `InvalidCapability`: no current thread, or arg0 names no Thread cap.
/// - `InsufficientRights`: the cap lacks OBSERVE.
/// - `InvalidState`: the thread is neither `Stopped` and descheduled nor
///   fault-blocked.
/// - `InvalidArgument`: the buffer is too small or null, or the thread has no
///   register frame.
/// - `InvalidAddress`: the buffer lies outside the user half or is not
///   writable.
#[cfg(not(test))]
pub fn sys_thread_read_regs(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::syscall::current_tcb;
    use core::mem::{MaybeUninit, size_of};

    let thread_idx = tf.arg(0) as u32;
    let buf_ptr = tf.arg(1);
    let buf_size = tf.arg(2) as usize;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // OBSERVE right is sufficient for reading registers.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::OBSERVE) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Snapshot the frame while the target is held still, so the copy never
    // races the target's own trap entry or return. A fault-blocked thread
    // (Blocked + BlockedOnFault) exposes its faulting frame for the bound
    // handler to read and modify before replying, so the fault-handler
    // protocol permits register access in that state too (see
    // `docs/fault-handling.md` § Modifying the faulting thread).
    let copy_size = size_of::<ArchTF>();
    let mut frame: MaybeUninit<ArchTF> = MaybeUninit::zeroed();
    let take_snapshot = |src: *mut u8| {
        if src.is_null()
        {
            return false;
        }
        // SAFETY: src is the target's non-null trap_frame, valid for
        // copy_size reads; frame is valid for copy_size writes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.cast_const(),
                frame.as_mut_ptr().cast::<u8>(),
                copy_size,
            );
        };
        true
    };
    // SAFETY: target_tcb validated non-null; the closure only copies the
    // frame into a kernel stack buffer, which cannot fault.
    let snapshot = unsafe { crate::sched::with_held_frame(target_tcb, take_snapshot) };
    match snapshot
    {
        None => return Err(SyscallError::InvalidState),
        Some(false) => return Err(SyscallError::InvalidArgument),
        Some(true) =>
        {}
    }

    if buf_size < copy_size || buf_ptr == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    // The destination must lie wholly in the user half: SMAP/SUM gate only
    // accesses to user pages, so without this a kernel-half buf_ptr would let the
    // copy write the target's register frame into kernel memory at an
    // attacker-chosen VA. (`buf_ptr >= user_va_top` short-circuits before the
    // sum, so `buf_ptr + copy_size` cannot overflow.)
    let user_va_top = crate::mm::user_va_top();
    if buf_ptr >= user_va_top || buf_ptr + copy_size as u64 > user_va_top
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Copy the snapshot to the user buffer with fault recovery: an unmapped or
    // read-only buffer returns InvalidAddress instead of faulting.
    // SAFETY: frame holds copy_size initialised bytes; buf_ptr is the
    //         validated user destination span.
    unsafe {
        crate::uaccess::copy_to_user(buf_ptr, frame.as_ptr().cast::<u8>(), copy_size)?;
    }

    Ok(copy_size as u64)
}

/// `SYS_THREAD_WRITE_REGS` (40): write register state into a stopped or
/// fault-blocked thread.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = Pointer to register-file buffer in caller's address space.
/// arg2 = Size of the buffer in bytes.
///
/// The thread must be fault-blocked, or `Stopped` and descheduled
/// (`sched::with_held_frame`). The kernel sanitizes the frame per architecture
/// (`core/kernel/docs/arch-interface.md` § `trap_frame`) before writing; RISC-V
/// replaces the supplied `sstatus` with the user-resume value. Returns 0 on
/// success.
///
/// # Errors
/// - `InvalidCapability`: no current thread, or arg0 names no Thread cap.
/// - `InsufficientRights`: the cap lacks CONTROL.
/// - `InvalidState`: the thread is neither `Stopped` and descheduled nor
///   fault-blocked.
/// - `InvalidArgument`: the buffer is too small or null, the thread has no
///   register frame, or the frame carries illegal register values.
/// - `InvalidAddress`: the buffer lies outside the user half or is not
///   readable.
#[cfg(not(test))]
pub fn sys_thread_write_regs(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::syscall::current_tcb;
    use core::mem::{MaybeUninit, size_of};

    let thread_idx = tf.arg(0) as u32;
    let buf_ptr = tf.arg(1);
    let buf_size = tf.arg(2) as usize;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        #[allow(clippy::cast_ptr_alignment)]
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // A fault-blocked thread (Blocked + BlockedOnFault) exposes its faulting
    // register frame for the bound handler to read and modify before replying,
    // so the fault-handler protocol permits register access in that state too,
    // not only `Stopped` (see `docs/fault-handling.md` § Modifying the faulting
    // thread). The state is decided only under the target's sched_lock, by the
    // write below.

    let copy_size = size_of::<ArchTF>();
    if buf_size < copy_size || buf_ptr == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    // The source must lie wholly in the user half: SMAP/SUM gate only accesses to
    // user pages, so without this a kernel-half buf_ptr would let the copy read
    // kernel memory at an attacker-chosen VA into the register frame.
    let user_va_top = crate::mm::user_va_top();
    if buf_ptr >= user_va_top || buf_ptr + copy_size as u64 > user_va_top
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Copy from user into a stack-local TrapFrame, then validate. Never write
    // directly to the target's trap_frame before validation. The copy is
    // fault-recovered: an unmapped or read-only source returns InvalidAddress.
    let mut tmp: MaybeUninit<ArchTF> = MaybeUninit::zeroed();
    // SAFETY: tmp is valid for copy_size writes; buf_ptr is the validated user
    //         source span.
    unsafe {
        crate::uaccess::copy_from_user(tmp.as_mut_ptr().cast::<u8>(), buf_ptr, copy_size)?;
    }

    // SAFETY: tmp was zero-initialized, so every byte is a valid bit pattern for
    // ArchTF regardless of how much copy_from_user wrote before any fault.
    let mut regs = unsafe { tmp.assume_init() };

    // Architecture-specific register safety validation.
    validate_write_regs(&mut regs)?;

    // Write the validated TrapFrame into the target while it is held still, so
    // the write never races the target's own trap entry or return.
    let write_frame = |dst: *mut u8| {
        if dst.is_null()
        {
            return false;
        }
        // SAFETY: dst is the target's non-null trap_frame, valid for
        // copy_size writes; regs is valid for copy_size reads.
        unsafe {
            core::ptr::copy_nonoverlapping(core::ptr::addr_of!(regs).cast::<u8>(), dst, copy_size);
        };
        true
    };
    // SAFETY: target_tcb validated non-null; the closure only copies a kernel
    // stack buffer into the frame, which cannot fault.
    let written = unsafe { crate::sched::with_held_frame(target_tcb, write_frame) };
    match written
    {
        None => Err(SyscallError::InvalidState),
        Some(false) => Err(SyscallError::InvalidArgument),
        Some(true) => Ok(0),
    }
}

/// Validate and sanitize a user-supplied `TrapFrame` before writing it into a
/// thread, per architecture (`core/kernel/docs/arch-interface.md` § `trap_frame`
/// — `arch::current::trap_frame`); RISC-V replaces the supplied `sstatus`.
///
/// Mutates `regs` in place to force safe segment/flag values.
///
/// # Adding new checks
/// Add per-field validation in the per-arch `TrapFrame::sanitize_for_user_resume`
/// implementations (`core/kernel/src/arch/<target>/trap_frame.rs`). Use
/// `InvalidArgument` for bad user data (not a kernel invariant violation).
#[cfg(not(test))]
fn validate_write_regs(
    regs: &mut crate::arch::current::trap_frame::TrapFrame,
) -> Result<(), SyscallError>
{
    regs.sanitize_for_user_resume()
        .map_err(|()| SyscallError::InvalidArgument)
}

// Test stubs.
#[cfg(test)]
pub fn sys_thread_configure(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_start(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_stop(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_set_priority(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_sched_split(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_set_affinity(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_read_regs(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_write_regs(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
