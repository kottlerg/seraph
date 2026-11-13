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

#![cfg_attr(
    not(test),
    expect(
        clippy::cast_possible_truncation,
        reason = "the u64→usize casts of trap-frame byte counts are lossless (Seraph is 64-bit \
                  only). Value args with a range contract (priority levels, split points, CPU IDs) \
                  are narrowed with `try_from` and rejected when out of range; the casts are in \
                  the cfg(not(test)) handlers, so the lint fires outside the host test build alone"
    )
)]

#[cfg(not(test))]
use super::UserFrame;
#[cfg(not(test))]
use crate::uaccess::RestartableError;
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

    let thread_idx = tf.arg(0);
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
    // the stack top. This mirrors the setup in `sched::enter()`. A kernel stack
    // top lies in the kernel half, far above one frame, so the subtraction
    // cannot wrap.
    let tf_size = size_of::<ArchTrapFrame>() as u64;
    let tf_ptr = kstack_top.wrapping_sub(tf_size) as *mut ArchTrapFrame;

    // The thread must be `Created`, decided under its sched_lock and held for
    // the writes below: a concurrent SYS_THREAD_START's commit takes the same
    // lock, so it either commits before (and this call is refused) or after
    // the frame, `trap_frame` and `saved_state` are complete. A `Created`
    // thread is current on no CPU.
    // SAFETY: target_tcb validated non-null; the Thread object `thread_slot`
    // pins keeps it live.
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw on both paths below.
    let sched_saved = unsafe { lock.lock_raw() };
    // SAFETY: state is written under the held sched_lock.
    if unsafe { (*target_tcb).state } != ThreadState::Created
    {
        // SAFETY: target_tcb validated non-null and pinned (as above).
        let lock = unsafe { &(*target_tcb).sched_lock };
        // SAFETY: paired with the lock_raw above.
        unsafe { lock.unlock_raw(sched_saved) };
        return Err(SyscallError::InvalidArgument);
    }

    // Zero then populate user-mode entry fields.
    // SAFETY: kstack_top - tf_size is within the allocated kernel stack (4
    // pages), so the frame's tf_size bytes are valid for writes.
    unsafe { core::ptr::write_bytes(tf_ptr.cast::<u8>(), 0, tf_size as usize) };
    // SAFETY: tf_ptr is the frame-sized slot just below the kernel stack top,
    // zeroed above (an all-zero TrapFrame is valid), and the thread is
    // `Created` under the held sched_lock, so it is current on no CPU and no
    // switch or register syscall reaches the frame meanwhile.
    unsafe { (*tf_ptr).init_user(entry, stack_ptr) };
    // Pass the argument in the first argument register.
    // SAFETY: as for `init_user` above.
    unsafe { (*tf_ptr).set_arg0(arg) };
    // SAFETY: as for `init_user` above.
    unsafe { (*tf_ptr).set_tls_base(tls_base) };

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
    // SAFETY: target_tcb validated non-null and pinned (as above).
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(sched_saved) };

    Ok(0)
}

/// `SYS_THREAD_START` (19): move a configured `Created` thread, or a
/// `Stopped` one (resume), to `Ready` and link it on the CPU
/// `select_target_cpu` chooses; with [`syscall::THREAD_START_SUSPENDED`],
/// move a configured `Created` thread to `Stopped` instead, linked nowhere.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = flags: [`syscall::THREAD_START_SUSPENDED`] or `0`; every other bit
///        is reserved.
///
/// The thread must have been configured via `SYS_THREAD_CONFIGURE` first
/// (`trap_frame` must be non-null). Returns 0 on success, including a start
/// that a concurrent `SYS_THREAD_STOP` overtakes after its commit (the thread
/// is then left `Stopped`, unlinked).
///
/// # Errors
/// - `InvalidArgument`: arg1 sets a reserved bit (checked first).
/// - `InvalidCapability`: the cap is invalid or not a Thread.
/// - `InsufficientRights`: the cap lacks CONTROL.
/// - `InvalidArgument`: the target is the caller, is not configured, or is not
///   `Created`/`Stopped` when the start commits (a concurrent start resumed it,
///   or it exited or was killed); for a suspended start, is not `Created` when
///   it commits.
/// - `Interrupted`: the caller was itself stopped while the start waited for
///   the target to settle.
#[cfg(not(test))]
pub fn sys_thread_start(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;

    let thread_idx = tf.arg(0);
    let flags = tf.arg(1);
    if flags & !syscall::THREAD_START_SUSPENDED != 0
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

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    if flags & syscall::THREAD_START_SUSPENDED != 0
    {
        // The caller is running, never `Created`, so the commit refuses a
        // self-start without a separate check.
        // SAFETY: target_tcb is the TCB of the Thread object `thread_slot`
        // pins; no lock is held.
        return unsafe { commit_suspended_start(target_tcb) };
    }

    // Thread must be in Created or Stopped state with a configured trap_frame.
    // Stopped → Ready acts as a resume operation (no new trap_frame needed).
    // SAFETY: target_tcb validated non-null, the TCB of the Thread object
    // `thread_slot` pins; the state field is always valid.
    let state = unsafe { (*target_tcb).state };
    if state != ThreadState::Created && state != ThreadState::Stopped
    {
        return Err(SyscallError::InvalidArgument);
    }
    // SAFETY: target_tcb is valid (as above); trap_frame is atomic and always
    // valid.
    if unsafe {
        (*target_tcb)
            .trap_frame
            .load(core::sync::atomic::Ordering::Relaxed)
    }
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
    // SAFETY: target_tcb is a valid TCB other than the calling thread's
    // (checked above), and the caller holds no lock.
    let start_seq = match unsafe { crate::sched::start_under_all_locks(target_tcb, caller_tcb) }
    {
        crate::sched::StartCommit::Committed(seq) => seq,
        crate::sched::StartCommit::Refused => return Err(SyscallError::InvalidArgument),
        crate::sched::StartCommit::CallerStopped =>
        {
            // Deschedule now, as a self-stop does: the settle loop's
            // preempt-disabled window made the timer skip its reschedule,
            // and the syscall epilogue reschedules only an Exited
            // thread. The restart resumes here. The target pin goes first
            // (the pin-before-park rule of `PinnedCap`): a caller killed
            // while stopped would otherwise hold it for good.
            drop(thread_slot);
            // SAFETY: syscall context on a valid kernel stack, no lock held.
            unsafe { crate::sched::schedule(crate::sched::Requeue::IfRunnable) };
            return Err(SyscallError::Interrupted);
        }
    };
    // Route to correct CPU based on affinity. The thread is already Ready
    // (committed above), so use enqueue_ready_thread to link it: the gated
    // enqueue_and_wake would coalesce an already-Ready thread and drop it.
    // The link is made only if this commit is still current: a concurrent
    // stop (and any restart, which links the thread itself) may have
    // superseded it, and the start then took effect and was stopped.
    // SAFETY: target_tcb is a valid, initialized TCB, pinned by `thread_slot`.
    let target_cpu = unsafe { crate::sched::select_target_cpu(target_tcb) };
    // SAFETY: target_tcb is valid and pinned; Ready at `start_seq` it is
    // neither live nor linked on any CPU (the commit drained it); target_cpu comes from
    // select_target_cpu, so it is an initialised CPU; no run-queue lock is
    // held.
    if unsafe { crate::sched::enqueue_ready_thread(target_tcb, target_cpu, start_seq) }
        == crate::sched::ReadyLink::Exited
    {
        return Err(SyscallError::InvalidArgument);
    }

    Ok(0)
}

/// Commit a suspended start: `Created → Stopped` for a configured `tcb`,
/// linked on no run queue.
///
/// The state and the configured frame are decided under `tcb`'s `sched_lock`,
/// the owner of `state` (core/kernel/docs/scheduling-internals.md
/// § Cross-CPU TCB Ownership), which `SYS_THREAD_CONFIGURE` holds across its
/// frame writes and every start and teardown commit takes; a start or
/// teardown that lands first leaves the thread other than `Created`, and this
/// commit is refused. A `Created` thread has never run: it is `current` on no CPU, its
/// save flag is set, no waker owes it a wake, and it is on no run queue, so
/// the `Stopped` it leaves is settled for `SYS_THREAD_READ_REGS` and a later
/// resume at once, and no queue drain or CPU scan is owed.
///
/// # Errors
/// `InvalidArgument` when `tcb` is not `Created` or not configured.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins; the caller holds no lock.
#[cfg(not(test))]
unsafe fn commit_suspended_start(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
) -> Result<u64, SyscallError>
{
    use crate::sched::thread::ThreadState;
    // SAFETY: tcb is a valid TCB the caller pins (contract).
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let saved = unsafe { lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "both reads are of tcb fields its held sched_lock serialises"
    )]
    // SAFETY: tcb is valid (contract); state and trap_frame are written under
    // the held sched_lock.
    let startable = unsafe {
        (*tcb).state == ThreadState::Created
            && !(*tcb)
                .trap_frame
                .load(core::sync::atomic::Ordering::Relaxed)
                .is_null()
    };
    if startable
    {
        // SAFETY: tcb is valid (contract); state is written under the held
        // sched_lock, its owner.
        unsafe { (*tcb).state = ThreadState::Stopped };
    }
    // SAFETY: tcb is valid (contract).
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(saved) };
    if startable
    {
        Ok(0)
    }
    else
    {
        Err(SyscallError::InvalidArgument)
    }
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
/// thread's blocked syscall returns `Interrupted`, a fault-blocked thread is
/// killed (for the fault of a restartable syscall's user copy, that syscall
/// fails with `InvalidAddress`), and a thread blocked in an upcall delivery
/// has the upcall dropped and resumes (see `core/kernel/docs/syscalls.md`
/// § `SYS_THREAD_STOP`), unless a genuine waker, the elapsed deadline of a
/// sleep or a timed wait, or a handler's reply claimed it first.
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

    let thread_idx = tf.arg(0);

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
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Unlocked precheck for the InvalidState answer; the commit
    // re-decides only `Exited`, so a stop racing another stop writes
    // Stopped again and both succeed.
    // SAFETY: target_tcb validated non-null, the TCB of the Thread object
    // `thread_slot` pins; state field always valid.
    let state = unsafe { (*target_tcb).state };
    if matches!(
        state,
        ThreadState::Created | ThreadState::Exited | ThreadState::Stopped
    )
    {
        return Err(SyscallError::InvalidState);
    }

    // Cancel any park (the stopped thread's blocked syscall returns
    // Interrupted on restart) and commit Stopped over it; a Ready target
    // is unlinked by the all-locks write, and a remote Running target by
    // the drain below (its CPU's next timer_tick reschedule). See
    // core/kernel/docs/thread-lifecycle-and-sleep.md § `sys_thread_stop`
    // Cross-CPU Stop Protocol; an `Exited` target is refused (terminal).
    // SAFETY: target_tcb is a valid TCB (pinned); no scheduler or IPC source
    // lock is held.
    let running_on = unsafe { commit_stopped(target_tcb) }?;

    // If stopping self (Running → Stopped): yield so another thread runs,
    // releasing the pin on this thread's own object first (the
    // pin-before-park rule of `PinnedCap`).
    if core::ptr::eq(target_tcb, caller_tcb)
    {
        drop(thread_slot);
        // SAFETY: syscall context on a valid kernel stack, no lock held.
        unsafe { crate::sched::schedule(crate::sched::Requeue::IfRunnable) };
    }
    else if let Some(run_cpu) = running_on
    {
        // SAFETY: caller_tcb is the running thread's valid TCB, target_tcb the
        // TCB of the Thread object `thread_slot` pins, caller_cspace the
        // caller's CSpace, run_cpu a CPU the commit returned (< CPU_COUNT),
        // and no lock is held.
        unsafe {
            drain_remote_stopped(
                target_tcb,
                caller_tcb,
                caller_cspace,
                thread_idx,
                run_cpu,
                thread_slot,
            );
        }
    }
    else
    {
        // SAFETY: target_tcb is a valid TCB (pinned), and no lock is held.
        unsafe { await_stopped_save(target_tcb) };
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
        // SAFETY: target_tcb valid per contract.
        let lock = unsafe { &(*target_tcb).sched_lock };
        // SAFETY: lock_raw paired with the unlock_raw below.
        let f = unsafe { lock.lock_raw() };
        // SAFETY: target_tcb valid per contract; state is read under the
        // sched_lock every Stopped/Exited commit holds.
        let stopped = unsafe { (*target_tcb).state } == ThreadState::Stopped;
        // SAFETY: target_tcb valid per contract.
        let lock = unsafe { &(*target_tcb).sched_lock };
        // SAFETY: paired with the lock_raw above.
        unsafe { lock.unlock_raw(f) };
        // SAFETY: target_tcb valid per contract; context_saved is atomic.
        stopped && unsafe { (*target_tcb).context_saved.load(Ordering::Acquire) } == 0
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
    thread_idx: u64,
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
    // drops the Stopped target at its next timer_tick reschedule (a slice
    // expiry, or a fair-dispatched target's preemption for RT) or its own
    // park or yield, whose trap leaves the snapshot sys_thread_read_regs
    // reads once this drain completes.
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
        // SAFETY: lock_raw paired with the unlock_raw below.
        let s = unsafe { sched_remote.lock.lock_raw() };
        let still_current = sched_remote.current() == target_tcb;
        // SAFETY: target_tcb valid per contract; state is read under the
        // remote scheduler lock, which every all-locks commit holds.
        let still_stopped = unsafe { (*target_tcb).state } == ThreadState::Stopped;
        // SAFETY: paired with the lock_raw above.
        unsafe { sched_remote.lock.unlock_raw(s) };
        // The drain also outlasts the switch-out's save: `current` moves
        // off the target before `switch()` publishes `context_saved`.
        // SAFETY: target_tcb valid per contract; context_saved is atomic.
        let unsaved = unsafe {
            (*target_tcb)
                .context_saved
                .load(core::sync::atomic::Ordering::Acquire)
        } == 0;
        let draining = still_stopped && (still_current || unsaved);
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
            // This preempt-disabled window suppresses the timer's reschedule
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
    // The target's state is read under its `sched_lock`, and the remote CPU's
    // `current` under that CPU's scheduler lock; both are try-locked, so the
    // diagnostic never waits.
    // SAFETY: run_cpu < CPU_COUNT per contract, and the scheduler is
    // initialised for every online CPU.
    let sched = unsafe { crate::sched::scheduler_for(run_cpu) };
    // SAFETY: target_tcb is valid per contract; `thread_id` is immutable.
    let tid = unsafe { (*target_tcb).thread_id };
    // SAFETY: target_tcb is valid per contract.
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: on `Some` the saved flags are passed to the unlock_raw in the
    // closure, which runs only then.
    let st = unsafe { lock.try_lock_raw() }.map(|saved| {
        // SAFETY: target_tcb is valid per contract; state is read under its
        // held sched_lock.
        let st = unsafe { (*target_tcb).state };
        // SAFETY: target_tcb is valid per contract.
        let lock = unsafe { &(*target_tcb).sched_lock };
        // SAFETY: paired with the try_lock_raw above.
        unsafe { lock.unlock_raw(saved) };
        st
    });
    // SAFETY: on `Some` the saved flags are passed to the unlock_raw in the
    // closure, which runs only then.
    let cur_tid = unsafe { sched.lock.try_lock_raw() }.map(|saved| {
        let cur = sched.current();
        let cur_tid = if cur.is_null()
        {
            0
        }
        else
        {
            // SAFETY: cur is the remote CPU's `current`, which its held
            // scheduler lock keeps from being freed (dealloc's not-current
            // scan reads under the same lock); `thread_id` is immutable.
            unsafe { (*cur).thread_id }
        };
        // SAFETY: paired with the try_lock_raw above.
        unsafe { sched.lock.unlock_raw(saved) };
        cur_tid
    });
    crate::kprintln!(
        "kernel: sys_thread_stop spin >100ms target_tid={} state={} run_cpu={} cur_tid={}",
        tid,
        OrHeld(st),
        run_cpu,
        OrHeld(cur_tid)
    );
    true
}

/// A field the slow-drain warning read under a try-lock: its value, or
/// `held` when the lock was contended.
#[cfg(not(test))]
struct OrHeld<T>(Option<T>);

#[cfg(not(test))]
impl<T: core::fmt::Debug> core::fmt::Display for OrHeld<T>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match &self.0
        {
            Some(value) => write!(f, "{value:?}"),
            None => f.write_str("held"),
        }
    }
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
    // SAFETY: caller_tcb is the running thread's valid TCB (contract).
    let lock = unsafe { &(*caller_tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below.
    let f = unsafe { lock.lock_raw() };
    // SAFETY: caller_tcb is valid (contract); state is read under its held
    // sched_lock.
    let st = unsafe { (*caller_tcb).state };
    // SAFETY: caller_tcb is valid (contract).
    let lock = unsafe { &(*caller_tcb).sched_lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(f) };
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
    thread_idx: u64,
    target_tcb: *mut crate::sched::thread::ThreadControlBlock,
) -> Option<super::PinnedCap>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    // SAFETY: cspace valid per contract and no lock held; lookup_cap checks
    // tag, generation and rights.
    let pin = unsafe { super::lookup_cap(cspace, thread_idx, ThreadRights::CONTROL) }.ok()?;
    let obj = pin.object?;
    // SAFETY: `pin` keeps the object live, and a Thread slot's object is a
    // ThreadObject.
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
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "both writes are to tcb fields its held sched_lock serialises"
    )]
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
#[cfg(not(test))]
pub(crate) unsafe fn cancel_ipc_block(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    // SAFETY: this fn's contract is cancel_park's.
    let _ = unsafe { cancel_park(tcb, CancelMode::Stop) };
}

/// Cancel the block of `tcb` for a posted upcall
/// (`docs/fault-handling.md` § Asynchronous Upcalls), as [`cancel_ipc_block`]
/// cancels it for a stop, and keep the wake the cancel's claim owes: returns
/// true when this call won the park's claim, with `wake_in_flight` set inside
/// the claim's hold, and the caller MUST then wake the thread
/// (`enqueue_and_wake`), whose interrupted syscall returns `Interrupted`.
/// Nothing is cancelled, and false is returned, when the thread is not
/// `Blocked`, is in a fault or upcall delivery (`in_fault_delivery`: the
/// upcall waits for it to resolve), has masked upcalls, or has no upcall
/// pending, each read under its `sched_lock` with the park's snapshot
/// (core/kernel/docs/thread-lifecycle-and-sleep.md § Upcall Cancel-and-Wake
/// Protocol).
///
/// # Safety
/// As for [`cancel_ipc_block`].
#[cfg(not(test))]
pub(crate) unsafe fn cancel_for_upcall(tcb: *mut crate::sched::thread::ThreadControlBlock) -> bool
{
    // SAFETY: this fn's contract is cancel_park's.
    unsafe { cancel_park(tcb, CancelMode::Upcall) }
}

/// Expire the timed park the sleep-list timer popped, as [`cancel_for_upcall`]
/// cancels a park for an upcall: the park is claimed and stamped
/// [`PARK_DISPOSITION_TIMED_OUT`], its binding cleared, and `wake_in_flight`
/// set inside the claim's hold; returns true on a win, and the caller (the
/// timer) MUST then wake the thread (`enqueue_and_wake`), whose syscall
/// returns `WouldBlock`.
///
/// `popped` and `park_seq` are the pop's snapshot of the park. Only that park
/// is claimed: for a `SYS_IPC_RECV` or `SYS_WAIT_SET_WAIT` park, while
/// `ipc_state` and `park_seq` still equal the snapshot; for a `SYS_IPC_CALL`,
/// while the thread is still in the call's send or reply park of the same
/// [`call_episode`], since the timeout bounds both. Nothing is claimed for a
/// thread no longer `Blocked` in that park, or in a fault delivery (no fault
/// park is timed). A lost claim leaves the episode to its claimant, which
/// removed the entry or found it popped
/// (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List Invariants).
///
/// [`PARK_DISPOSITION_TIMED_OUT`]: crate::sched::thread::PARK_DISPOSITION_TIMED_OUT
/// [`call_episode`]: crate::sched::thread::call_episode
///
/// # Safety
/// As for [`cancel_ipc_block`]; `tcb` is kept allocated by the timer batch
/// that popped it (`sched::sleep_wakeups_quiesce`).
#[cfg(not(test))]
pub(crate) unsafe fn cancel_for_timeout(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    popped: crate::sched::thread::IpcThreadState,
    park_seq: u32,
) -> bool
{
    // A call's send park can turn into its reply park between the first hold
    // and the source lock (a receive rebinds it under ep.lock), which loses
    // the send arm's unlink while the episode goes on; the second pass claims
    // the reply park. A call rebinds once, so two passes suffice; any other
    // loss means another claimant ended the episode, and the second pass
    // loses too.
    for _ in 0..2
    {
        // SAFETY: this fn's contract is cancel_park's.
        if unsafe { cancel_park(tcb, CancelMode::Timeout { popped, park_seq }) }
        {
            return true;
        }
    }
    false
}

/// Whether the timer's expiry of the popped park (`popped`, `popped_seq`) may
/// claim `tcb`'s current park `(live, live_seq)`: the same receive or wait-set
/// park, or the same call episode, and no fault delivery.
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds.
#[cfg(not(test))]
unsafe fn timeout_may_cancel(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    (live, live_seq): (crate::sched::thread::IpcThreadState, u32),
    popped: crate::sched::thread::IpcThreadState,
    popped_seq: u32,
) -> bool
{
    use crate::sched::thread::{IpcThreadState, call_episode};
    // SAFETY: caller holds tcb.sched_lock, under which in_fault_delivery is
    // written.
    if unsafe { (*tcb).in_fault_delivery }
    {
        return false;
    }
    match popped
    {
        IpcThreadState::BlockedOnSend | IpcThreadState::BlockedOnReply =>
        {
            matches!(
                live,
                IpcThreadState::BlockedOnSend | IpcThreadState::BlockedOnReply
            ) && call_episode(live_seq) == call_episode(popped_seq)
        }
        IpcThreadState::BlockedOnRecv | IpcThreadState::BlockedOnWaitSet =>
        {
            live == popped && live_seq == popped_seq
        }
        IpcThreadState::None
        | IpcThreadState::BlockedOnFault
        | IpcThreadState::BlockedOnNotification
        | IpcThreadState::BlockedOnEventQueue => false,
    }
}

/// Who cancels a park through [`cancel_park`].
#[cfg(not(test))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CancelMode
{
    /// A stop or an object teardown: the park is stamped INTERRUPTED and no
    /// wake is kept (the stop's commit decides the thread's state).
    Stop,
    /// A posted upcall ([`cancel_for_upcall`]): stamped INTERRUPTED, and the
    /// wake is kept for the poster.
    Upcall,
    /// The sleep-list timer's expiry of the popped park
    /// ([`cancel_for_timeout`]): stamped `TIMED_OUT`, and the wake is kept for
    /// the timer.
    Timeout
    {
        popped: crate::sched::thread::IpcThreadState,
        park_seq: u32,
    },
}

#[cfg(not(test))]
impl CancelMode
{
    /// The disposition a won claim stamps on a non-fault park.
    fn disposition(self) -> u8
    {
        match self
        {
            Self::Timeout { .. } => crate::sched::thread::PARK_DISPOSITION_TIMED_OUT,
            Self::Stop | Self::Upcall => crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
        }
    }
}

/// Whether a posted upcall may cancel `tcb`'s block now: one is pending, the
/// thread does not mask upcalls, and it is in no fault or upcall delivery.
/// `sched::commit_blocked_under_local_lock` refuses a park under the same
/// predicate, restated there, which MUST stay identical to this one.
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds.
#[cfg(not(test))]
pub(crate) unsafe fn upcall_may_cancel(tcb: *mut crate::sched::thread::ThreadControlBlock) -> bool
{
    // SAFETY: tcb is valid and the caller holds its sched_lock, under which
    // in_fault_delivery is written.
    if unsafe { (*tcb).in_fault_delivery }
    {
        return false;
    }
    // SAFETY: tcb is valid; upcall_pending is atomic, written under the
    // sched_lock the caller holds.
    if !unsafe {
        (*tcb)
            .upcall_pending
            .load(core::sync::atomic::Ordering::Relaxed)
    }
    {
        return false;
    }
    // SAFETY: tcb is valid; upcall_masked is atomic, written under the
    // sched_lock the caller holds.
    !unsafe {
        (*tcb)
            .upcall_masked
            .load(core::sync::atomic::Ordering::Relaxed)
    }
}

/// Keep the wake a won cancel claim owes when the cancel is an upcall's or
/// the timer's: set `wake_in_flight` inside the claim's `sched_lock` hold, as
/// every waker's claim does, so a restart waits for the wake (the caller of
/// [`cancel_for_upcall`] or [`cancel_for_timeout`] makes it) rather than
/// starting the thread under it, and return whether the claim was won for a
/// wake.
///
/// # Safety
/// `tcb` must be a valid TCB whose `sched_lock` the caller holds, inside the
/// hold of a claim it just won.
#[cfg(not(test))]
unsafe fn keep_wake(tcb: *mut crate::sched::thread::ThreadControlBlock, mode: CancelMode) -> bool
{
    let keep = mode != CancelMode::Stop;
    if keep
    {
        // SAFETY: caller holds tcb.sched_lock inside the won claim.
        unsafe {
            (*tcb)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
        }
    }
    keep
}

/// The cancel of [`cancel_ipc_block`], [`cancel_for_upcall`], and
/// [`cancel_for_timeout`]; returns whether an upcall's or the timer's cancel
/// won the park's claim (always false for a stop's).
///
/// # Safety
/// As for [`cancel_ipc_block`].
#[expect(
    clippy::too_many_lines,
    reason = "flat dispatch over every `IpcThreadState` variant; splitting adds no clarity (each \
              arm is independent and short)"
)]
#[cfg(not(test))]
unsafe fn cancel_park(tcb: *mut crate::sched::thread::ThreadControlBlock, mode: CancelMode)
-> bool
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
    //
    // An upcall's cancel also requires, in the same hold, a pending upcall, no
    // mask, and no fault or upcall delivery: a fault park is never cancelled
    // for an upcall, which waits for the fault to resolve, and the mask is
    // written under this lock, so a thread that masked before it parked keeps
    // its block. The timer's expiry requires the park it popped (for a call,
    // the call episode it popped) and no fault delivery; it never targets a
    // plain sleeper, which the timer claims at its pop.
    let mut claimed = false;
    // SAFETY: tcb is a valid TCB (contract).
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: lock_raw paired with the unlock_raw below; the caller holds no
    // sched_lock or scheduler lock (contract).
    let saved = unsafe { lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every read is of a tcb field its held sched_lock serialises"
    )]
    // SAFETY: tcb is valid (contract); ipc_state, blocked_on_object and
    // park_seq are written under the held sched_lock.
    let snap = unsafe {
        (
            (*tcb).ipc_state,
            (*tcb).blocked_on_object,
            (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed),
        )
    };
    // SAFETY: tcb is valid (contract); state is written under the held
    // sched_lock.
    let blocked = unsafe { (*tcb).state } == crate::sched::thread::ThreadState::Blocked;
    let refused = match mode
    {
        CancelMode::Stop => false,
        CancelMode::Upcall =>
        {
            // SAFETY: tcb is valid and its sched_lock is held.
            !unsafe { upcall_may_cancel(tcb) }
        }
        CancelMode::Timeout { popped, park_seq } =>
        {
            // SAFETY: tcb is valid and its sched_lock is held.
            !unsafe { timeout_may_cancel(tcb, (snap.0, snap.2), popped, park_seq) }
        }
    };
    if blocked && !refused && snap.0 == IpcThreadState::None
    {
        // SAFETY: tcb is live, kept so by the caller (contract);
        // SLEEP_LIST_LOCK is a leaf, nested under the held sched_lock.
        let removed = unsafe { crate::sched::sleep_list_remove(tcb) };
        if removed
        {
            // SAFETY: tcb is valid, and the `true` return above is this
            // cancel's exclusive claim of the plain sleeper's park (its
            // `Blocked` + `ipc_state == None` snapshot under the held
            // sched_lock); this is the episode's one stamp.
            unsafe {
                crate::sched::thread::stamp_park_deposit(
                    tcb,
                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                );
            }
            // SAFETY: tcb is valid and its sched_lock is held, inside the hold
            // of the claim just won.
            claimed = unsafe { keep_wake(tcb, mode) };
        }
    }
    // SAFETY: tcb is a valid TCB (contract).
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(saved) };
    if !blocked || refused
    {
        return false;
    }
    let (ipc_state, blocked_on, park_seq) = snap;

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
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let ep = blocked_on.cast::<EndpointState>();
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "both places are send-queue ends of the endpoint whose ep.lock `held` \
                              holds"
                )]
                // SAFETY: `held` holds ep.lock on the live endpoint the binding
                // names, which serialises its send queue.
                let (send_head, send_tail) =
                    unsafe { (&mut (*ep).send_head, &mut (*ep).send_tail) };
                // SAFETY: `held` holds ep.lock, the queue's owning lock; tcb
                // and the queue ends are valid.
                let unlinked = unsafe { unlink_from_wait_queue(tcb, send_head, send_tail) };
                // Republish send-queue level after the unlink (#285-adjacent).
                // SAFETY: the endpoint the binding names is live while `held`
                // holds its lock.
                let endpoint = unsafe { &*ep };
                // SAFETY: `held` holds ep.lock.
                unsafe { endpoint.refresh_send_ready() };
                // Claim = the send-queue unlink under ep.lock (recv
                // dequeues under the same lock, so winning it makes this
                // the episode's sole depositor). A fault sender (queued
                // for delivery) whose fault this cancel claimed takes the
                // kill outcome, not a resume, when next scheduled (its
                // copy fault fails the syscall, its upcall is dropped,
                // docs/fault-handling.md § Reply): its resume runs the
                // fault helper, which has no syscall to return
                // `Interrupted` to; `in_fault_delivery` is read only behind
                // the won unlink, the claim that orders it after the
                // faulter's own write. A stopped sys_ipc_call caller
                // resumes via the disposition. A lost unlink hands the
                // episode to a racing receive's rebind chain (a
                // handler reply, or its teardown, which owns the
                // disposition; a KILL stored here would overwrite a
                // handler's RESUME), the endpoint's dealloc drain, or a
                // concurrent cancel that already claimed it, or the
                // thread's own dealloc_object(Thread) unlinked it as it
                // dies; the retry pass cancels a rebound park.
                if unlinked
                {
                    // SAFETY: tcb is valid, and the won unlink is the claim
                    // that orders this read after the faulter's write.
                    if unsafe { (*tcb).in_fault_delivery }
                    {
                        // SAFETY: tcb is valid; fault_outcome is atomic, and
                        // the won unlink makes this the episode's sole
                        // depositor.
                        unsafe {
                            (*tcb).fault_outcome.store(
                                crate::ipc::fault::FAULT_OUTCOME_KILL,
                                core::sync::atomic::Ordering::Release,
                            );
                        }
                        // SAFETY: tcb is valid, and the won unlink under
                        // ep.lock is this cancel's exclusive claim.
                        unsafe { crate::sched::thread::stamp_deposit_episode(tcb) };
                    }
                    else
                    {
                        // A timed call's entry ends with its episode.
                        // SAFETY: tcb is valid, its park was just claimed by
                        // the unlink under ep.lock and not yet woken; no
                        // sleep-list lock is held.
                        unsafe { crate::ipc::cancel_timed_entry(tcb) };
                        // SAFETY: tcb is valid, and the won unlink under
                        // ep.lock is this cancel's exclusive claim.
                        unsafe {
                            crate::sched::thread::stamp_park_deposit(tcb, mode.disposition());
                        }
                    }
                    // SAFETY: tcb is valid and `held` holds its sched_lock.
                    unsafe { clear_park_binding(tcb) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock,
                    // inside the hold of the claim just won.
                    claimed = unsafe { keep_wake(tcb, mode) };
                }
                // SAFETY: `held` came from lock_bound_source and both its
                // locks are still held.
                unsafe { held.unlock() };
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
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let ep = blocked_on.cast::<EndpointState>();
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "both places are recv-queue ends of the endpoint whose ep.lock `held` \
                              holds"
                )]
                // SAFETY: `held` holds ep.lock on the live endpoint the binding
                // names, which serialises its recv queue.
                let (recv_head, recv_tail) =
                    unsafe { (&mut (*ep).recv_head, &mut (*ep).recv_tail) };
                // Claim = the recv-queue unlink under ep.lock (endpoint_call
                // dequeues receivers under the same lock, so winning it makes
                // this the episode's sole depositor). A lost unlink means a
                // caller already deposited into ipc_msg, whose delivery stands
                // and the resume publishes (fail-open), or the endpoint's
                // dealloc drain or a concurrent cancel already claimed the
                // park, or the thread's own dealloc_object(Thread) unlinked
                // it as it dies.
                // SAFETY: `held` holds ep.lock, the queue's owning lock; tcb
                // and the queue ends are valid.
                let unlinked = unsafe { unlink_from_wait_queue(tcb, recv_head, recv_tail) };
                if unlinked
                {
                    // A timed receive's entry goes with the waiter.
                    // SAFETY: tcb is valid, its park was just claimed by the
                    // unlink under ep.lock and not yet woken; no sleep-list
                    // lock is held.
                    unsafe { crate::ipc::cancel_timed_entry(tcb) };
                    // SAFETY: tcb is valid, and the won unlink under ep.lock is
                    // this cancel's exclusive claim.
                    unsafe { crate::sched::thread::stamp_park_deposit(tcb, mode.disposition()) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock.
                    unsafe { clear_park_binding(tcb) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock,
                    // inside the hold of the claim just won.
                    claimed = unsafe { keep_wake(tcb, mode) };
                }
                // SAFETY: `held` came from lock_bound_source and both its
                // locks are still held.
                unsafe { held.unlock() };
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
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let server = blocked_on.cast::<crate::sched::thread::ThreadControlBlock>();
                // SAFETY: tcb is valid (contract).
                let lock = unsafe { &(*tcb).sched_lock };
                // SAFETY: no lock is held (contract); paired with the
                // unlock_raw below on every path.
                let saved = unsafe { lock.lock_raw() };
                // An upcall's cancel claims only the snapshotted park, and
                // only while the upcall may still cancel it: the thread
                // may since have run, taken the upcall, masked, and called
                // the same server again, a park this cancel must leave.
                // The timer's expiry, too, claims only the snapshotted
                // park, which its first hold matched to the popped call.
                // SAFETY: tcb is valid; park_seq is atomic.
                let seq = unsafe { (*tcb).park_seq.load(core::sync::atomic::Ordering::Relaxed) };
                let same_park = seq == park_seq;
                let may_cancel = match mode
                {
                    CancelMode::Stop => true,
                    CancelMode::Upcall =>
                    {
                        // SAFETY: tcb is valid and its sched_lock is held.
                        same_park && unsafe { upcall_may_cancel(tcb) }
                    }
                    CancelMode::Timeout { .. } =>
                    {
                        // SAFETY: tcb is valid and its sched_lock, under which
                        // in_fault_delivery is written, is held.
                        same_park && !unsafe { (*tcb).in_fault_delivery }
                    }
                };
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "every read is of a tcb field its held sched_lock serialises"
                )]
                // SAFETY: tcb is valid and its sched_lock is held.
                let bound = unsafe {
                    (*tcb).state == crate::sched::thread::ThreadState::Blocked
                        && (*tcb).ipc_state == IpcThreadState::BlockedOnReply
                        && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
                };
                if bound && may_cancel
                {
                    // SAFETY: server is live for the CAS by the CLOSURE LEMMA:
                    // the blocked_on_object re-read under tcb's held sched_lock
                    // still names it; reply_tcb is atomic.
                    let cancelled = unsafe {
                        (*server).reply_tcb.compare_exchange(
                            tcb,
                            core::ptr::null_mut(),
                            core::sync::atomic::Ordering::AcqRel,
                            core::sync::atomic::Ordering::Acquire,
                        )
                    }
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
                        // A timed call's entry ends with its episode.
                        // SAFETY: tcb is valid, its park was just claimed by
                        // the CAS and not yet woken; no sleep-list lock is
                        // held.
                        unsafe { crate::ipc::cancel_timed_entry(tcb) };
                        // SAFETY: tcb is valid, and the won CAS is this
                        // cancel's exclusive claim.
                        unsafe {
                            crate::sched::thread::stamp_park_deposit(tcb, mode.disposition());
                        }
                        // SAFETY: tcb is valid and its sched_lock is held.
                        unsafe { clear_park_binding(tcb) };
                        // An upcall's or the timer's cancel keeps the
                        // claim the reply binding set, for the wake its
                        // caller makes.
                        claimed = mode != CancelMode::Stop;
                        if !claimed
                        {
                            // SAFETY: tcb is valid; wake_in_flight is atomic,
                            // released inside the won claim's hold.
                            unsafe {
                                (*tcb)
                                    .wake_in_flight
                                    .store(0, core::sync::atomic::Ordering::Release);
                            }
                        }
                    }
                }
                // SAFETY: tcb is valid (contract).
                let lock = unsafe { &(*tcb).sched_lock };
                // SAFETY: pairs with the lock_raw above, whose `saved` this is.
                unsafe { lock.unlock_raw(saved) };
            }
        }

        IpcThreadState::BlockedOnFault =>
        {
            // Mirror BlockedOnReply: `blocked_on` is the handler (server) TCB,
            // whose `reply_tcb` points at this faulter. CAS-clear it so a later
            // handler reply cannot double-wake. On a successful cancel, mark the
            // disposition Kill (on resume the fault helper terminates the
            // thread, fails with InvalidAddress a restartable syscall whose
            // user copy faulted, or, for an upcall delivery, drops the upcall
            // and resumes the thread) and release the wake-in-flight claim. If
            // the CAS loses, a genuine reply already won and committed its own
            // disposition — leave it untouched.
            if !blocked_on.is_null()
            {
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let server = blocked_on.cast::<crate::sched::thread::ThreadControlBlock>();
                // SAFETY: tcb is valid (contract).
                let lock = unsafe { &(*tcb).sched_lock };
                // SAFETY: no lock is held (contract); paired with the
                // unlock_raw below on every path.
                let saved = unsafe { lock.lock_raw() };
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "every read is of a tcb field its held sched_lock serialises"
                )]
                // SAFETY: tcb is valid and its sched_lock is held.
                let bound = unsafe {
                    (*tcb).state == crate::sched::thread::ThreadState::Blocked
                        && (*tcb).ipc_state == IpcThreadState::BlockedOnFault
                        && core::ptr::eq((*tcb).blocked_on_object, blocked_on)
                };
                if bound
                {
                    // SAFETY: server is live for the CAS by the CLOSURE LEMMA
                    // (#317; mirrors the BlockedOnReply arm above): the
                    // blocked_on_object re-read under tcb's held sched_lock
                    // still names it; reply_tcb is atomic.
                    let cancelled = unsafe {
                        (*server).reply_tcb.compare_exchange(
                            tcb,
                            core::ptr::null_mut(),
                            core::sync::atomic::Ordering::AcqRel,
                            core::sync::atomic::Ordering::Acquire,
                        )
                    }
                    .is_ok();
                    if cancelled
                    {
                        // SAFETY: tcb is valid; fault_outcome is atomic, and
                        // the won CAS makes this the episode's sole depositor.
                        unsafe {
                            (*tcb).fault_outcome.store(
                                crate::ipc::fault::FAULT_OUTCOME_KILL,
                                core::sync::atomic::Ordering::Release,
                            );
                        }
                        // CAS win = episode claim (fault disposition lives
                        // in fault_outcome; stamp the episode only).
                        // SAFETY: tcb is valid, and the won CAS is this
                        // cancel's exclusive claim.
                        unsafe { crate::sched::thread::stamp_deposit_episode(tcb) };
                        // SAFETY: tcb is valid and its sched_lock is held.
                        unsafe { clear_park_binding(tcb) };
                        // SAFETY: tcb is valid; wake_in_flight is atomic,
                        // released inside the won claim's hold.
                        unsafe {
                            (*tcb)
                                .wake_in_flight
                                .store(0, core::sync::atomic::Ordering::Release);
                        }
                    }
                }
                // SAFETY: tcb is valid (contract).
                let lock = unsafe { &(*tcb).sched_lock };
                // SAFETY: pairs with the lock_raw above, whose `saved` this is.
                unsafe { lock.unlock_raw(saved) };
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
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let sig = blocked_on.cast::<NotificationState>();
                // SAFETY: `held` holds sig.lock on the live notification the
                // binding names, which serialises its waiter queue.
                let waiters = unsafe { &mut (*sig).waiters };
                // Claim = the removal from the waiter queue under sig.lock
                // (every genuine waker claims under the same lock). A lost
                // race means the waker's deposit stands and the resume
                // delivers it (fail-open), or a concurrent cancel already
                // claimed and stamped it, or the thread's own
                // dealloc_object(Thread) unlinked it as it dies.
                // SAFETY: tcb is valid and `held` holds sig.lock, the queue's
                // owning lock.
                let removed = unsafe { waiters.remove(tcb) };
                if removed
                {
                    // Re-derive the observer flag like every other
                    // waiter-removal site; leaving it set would pin all
                    // future sends onto the slow path.
                    // SAFETY: `held` holds sig.lock on the live notification.
                    unsafe { (*sig).refresh_observer() };
                    // A timed wait's entry goes with the waiter, under
                    // sig.lock, as at every waiter claim.
                    // SAFETY: tcb is valid, its park was just claimed by the
                    // removal under sig.lock and not yet woken;
                    // SLEEP_LIST_LOCK is a leaf under both held locks and is
                    // not held.
                    unsafe { crate::ipc::cancel_timed_entry(tcb) };
                    // SAFETY: tcb is valid, and the won removal under
                    // sig.lock is this cancel's exclusive claim.
                    unsafe {
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                    }
                    // SAFETY: tcb is valid and `held` holds its sched_lock.
                    unsafe { clear_park_binding(tcb) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock,
                    // inside the hold of the claim just won.
                    claimed = unsafe { keep_wake(tcb, mode) };
                }
                // SAFETY: `held` came from lock_bound_source and both its
                // locks are still held.
                unsafe { held.unlock() };
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
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let eq = blocked_on.cast::<EventQueueState>();
                // SAFETY: `held` holds eq.lock on the live event queue the
                // binding names, which serialises its waiter queue.
                let waiters = unsafe { &mut (*eq).waiters };
                // Claim = the removal from the waiter queue under eq.lock; a
                // lost race means a genuine wake's deposit stands
                // (fail-open), or a concurrent cancel already claimed and
                // stamped it, or the thread's own dealloc_object(Thread)
                // unlinked it as it dies.
                // SAFETY: tcb is valid and `held` holds eq.lock, the queue's
                // owning lock.
                let removed = unsafe { waiters.remove(tcb) };
                if removed
                {
                    // A timed wait's entry goes with the waiter, under
                    // eq.lock, as at every waiter claim.
                    // SAFETY: tcb is valid, its park was just claimed by the
                    // removal under eq.lock and not yet woken;
                    // SLEEP_LIST_LOCK is a leaf under both held locks and is
                    // not held.
                    unsafe { crate::ipc::cancel_timed_entry(tcb) };
                    // SAFETY: tcb is valid, and the won removal under eq.lock
                    // is this cancel's exclusive claim.
                    unsafe {
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                    }
                    // SAFETY: tcb is valid and `held` holds its sched_lock.
                    unsafe { clear_park_binding(tcb) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock,
                    // inside the hold of the claim just won.
                    claimed = unsafe { keep_wake(tcb, mode) };
                }
                // SAFETY: `held` came from lock_bound_source and both its
                // locks are still held.
                unsafe { held.unlock() };
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
                #[expect(
                    clippy::cast_ptr_alignment,
                    reason = "blocked_on_object stores type-erased pointer; original allocation \
                              guarantees alignment"
                )]
                let ws = blocked_on.cast::<WaitSetState>();
                // SAFETY: `held` holds ws.lock on the live wait set the
                // binding names, which serialises its waiter queue.
                let waiters = unsafe { &mut (*ws).waiters };
                // Claim = the removal from the waiter queue under ws.lock;
                // a lost race means a genuine wake's deposit stands
                // (fail-open), or a concurrent cancel already claimed and
                // stamped it, or the thread's own dealloc_object(Thread)
                // unlinked it as it dies.
                // SAFETY: tcb is valid and `held` holds ws.lock, the queue's
                // owning lock.
                let removed = unsafe { waiters.remove(tcb) };
                if removed
                {
                    // A timed wait's entry goes with the waiter, under
                    // ws.lock, as at every waiter claim.
                    // SAFETY: tcb is valid, its park was just claimed by the
                    // removal under ws.lock and not yet woken; no sleep-list
                    // lock is held.
                    unsafe { crate::ipc::cancel_timed_entry(tcb) };
                    // SAFETY: tcb is valid, and the won removal under ws.lock
                    // is this cancel's exclusive claim.
                    unsafe { crate::sched::thread::stamp_park_deposit(tcb, mode.disposition()) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock.
                    unsafe { clear_park_binding(tcb) };
                    // SAFETY: tcb is valid and `held` holds its sched_lock,
                    // inside the hold of the claim just won.
                    claimed = unsafe { keep_wake(tcb, mode) };
                }
                // SAFETY: `held` came from lock_bound_source and both its
                // locks are still held.
                unsafe { held.unlock() };
            }
        }

        // A plain sleeper, cancelled (or found claimed) under sched_lock above.
        IpcThreadState::None =>
        {}
    }
    claimed
}

/// `SYS_THREAD_SET_FAULT_HANDLER` (32): bind or clear a thread's fault-handler
/// endpoint for the fault classes a mask selects.
///
/// arg0 = Thread cap index (must have CONTROL) — the thread whose handler is set.
/// arg1 = Endpoint cap index, or `0` to **unbind**.
/// arg2 = reserved; MUST be `0`. The fault message badge is the derivation
///        badge of the arg1 cap, never a binder-supplied value
///        (`docs/fault-handling.md` § Security).
/// arg3 = `fault_class_mask`: [`syscall::FAULT_CLASS_ALL`], or a nonzero
///        combination of [`syscall::FAULT_CLASS_VM`],
///        [`syscall::FAULT_CLASS_EXCEPTION`], and
///        [`syscall::FAULT_CLASS_UPCALL`]; the classes it leaves out keep
///        their bindings.
///
/// Each selected class's binding takes its own reference on the endpoint object
/// for the binding's lifetime (see `docs/fault-handling.md` § Liveness);
/// rebinding / unbinding / thread destruction releases it. The target Thread
/// and the endpoint are pinned for the call (`lookup_cap`), so a concurrent
/// delete of either one's last capability frees it only after the binding is
/// published. The endpoint and its badge are published as one unit per class
/// under the target's `sched_lock`, the lock `ipc::fault::fault_dispatch` reads
/// them under.
///
/// A change of a class's binding (another endpoint, another badge, or an
/// unbind) cancels the fault delivery of that class in flight on the target
/// through the binding it replaces, unless a reply or another cancellation gave that delivery its
/// disposition first; the faulting thread then delivers the fault again under
/// the binding current when it next runs, and with none bound the fault is
/// unhandled (`ipc::fault::redeliver_in_flight`; `docs/fault-handling.md`
/// § Delivery, Resume, and Kill). A rebind to the same endpoint and badge
/// cancels nothing.
///
/// Binding requires only a valid `Endpoint` cap — `CONTROL` on the thread is
/// the authority; the endpoint cap names where this thread's
/// kernel-unresolvable faults are delivered and, by its badge, how they are
/// attributed.
///
/// Returns 0 on success; `InvalidArgument` for a nonzero arg2 or a mask
/// `ipc::fault::classes_of_mask` refuses (zero, or a bit no class defines).
#[cfg(not(test))]
pub fn sys_thread_set_fault_handler(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EndpointObject, ThreadObject};
    use crate::cap::slot::{EpRights, ThreadRights};
    use crate::syscall::current_tcb;

    let thread_idx = tf.arg(0);
    let endpoint_idx = tf.arg(1);
    let reserved = tf.arg(2);
    let fault_class_mask = tf.arg(3);

    // arg2 once carried a binder-chosen badge; it is reserved so a caller still
    // passing one fails loudly instead of having its value ignored.
    if reserved != 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    let selected = crate::ipc::fault::classes_of_mask(fault_class_mask)
        .ok_or(SyscallError::InvalidArgument)?;

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
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
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
            let p = obj.as_ptr().cast::<EndpointObject>();
            (p, slot.badge)
        }
    };

    // Take one reference per selected class before publishing, so the object
    // cannot be freed between publish and a faulter's load: each class's
    // binding holds its own.
    let mut new = [(core::ptr::null_mut(), 0); crate::ipc::fault::FAULT_CLASSES];
    for (binding, &chosen) in new.iter_mut().zip(&selected)
    {
        if chosen
        {
            if !new_ep.is_null()
            {
                // SAFETY: new_ep is the EndpointObject `ep_slot` pins.
                unsafe { (*new_ep).header.inc_ref() };
            }
            *binding = (new_ep, new_badge);
        }
    }

    // SAFETY: target_tcb is the TCB of the Thread object `thread_slot` pins,
    // and no lock is held; `new` carries one reference per selected non-null
    // endpoint.
    unsafe { apply_bindings(target_tcb, selected, new) };
    Ok(0)
}

/// Publish `new` as `tcb`'s binding for each `selected` class, cancel a
/// delivery the change makes stale, and release the replaced bindings'
/// references.
///
/// The bindings are published as one unit per class under the target's
/// `sched_lock` (`ipc::fault::publish_bindings`): `fault_dispatch` reads a
/// class's pair under the same lock and takes its own reference on the
/// endpoint before unlocking, so the release of a replaced binding cannot
/// free an endpoint a delivery still uses, and no faulter pairs one
/// binding's endpoint with another's badge. The same hold decides whether
/// the change cancels a delivery in flight: one `pin_binding` opened under a
/// replaced binding of the same class (it opens a delivery under this lock),
/// when that binding changed. That delivery is cancelled so the faulting
/// thread makes it again under the new binding (with none, the fault is
/// unhandled), before the replaced references go: a release that destroys
/// an old endpoint would otherwise claim a still-queued delivery with a kill
/// outcome (docs/fault-handling.md § Delivery, Resume, and Kill). A rebind
/// to the same endpoint nets to no reference change.
///
/// # Safety
/// `tcb` must be a valid TCB the caller pins, other than the calling
/// thread's when a delivery may be in flight on it (a thread inside a syscall
/// has none); each non-null endpoint of a selected class in `new` carries a
/// reference the caller passes to the binding; no lock is held.
#[cfg(not(test))]
unsafe fn apply_bindings(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    selected: [bool; crate::ipc::fault::FAULT_CLASSES],
    new: [crate::ipc::fault::Binding; crate::ipc::fault::FAULT_CLASSES],
)
{
    // SAFETY: caller contract.
    let (old, redeliver) = unsafe { crate::ipc::fault::publish_bindings(tcb, selected, new) };
    if let Some(class) = redeliver
    {
        // SAFETY: tcb is pinned and has a delivery in flight, so it is not
        // the caller; class < FAULT_CLASSES; no lock is held.
        unsafe { crate::ipc::fault::redeliver_in_flight(tcb, class) };
    }
    // SAFETY: each replaced endpoint's reference passed to this call; syscall
    // context with interrupts disabled and no lock held.
    unsafe { crate::ipc::fault::release_endpoints(old) };
}

/// The TCB of the Thread cap `idx` in `cspace`, which must carry `CONTROL`,
/// with the pin that keeps its object live while the returned pin is held.
///
/// # Errors
/// `InvalidCapability` for a slot that names no live Thread; the errors of
/// `lookup_cap` (`InsufficientRights` without `CONTROL`).
///
/// # Safety
/// `cspace` must be the calling thread's `CSpace`; no lock is held.
#[cfg(not(test))]
unsafe fn control_thread(
    cspace: *mut crate::cap::cspace::CSpace,
    idx: u64,
) -> Result<
    (
        super::PinnedCap,
        *mut crate::sched::thread::ThreadControlBlock,
    ),
    SyscallError,
>
{
    // SAFETY: this fn's contract is thread_with_rights's.
    unsafe { thread_with_rights(cspace, idx, crate::cap::slot::ThreadRights::CONTROL) }
}

/// The TCB of the Thread cap `idx` in `cspace`, which must carry `rights`,
/// with the pin that keeps its object live while the returned pin is held.
///
/// # Errors
/// `InvalidCapability` for a slot that names no live Thread; the errors of
/// `lookup_cap` (`InsufficientRights` without `rights`).
///
/// # Safety
/// `cspace` must be the calling thread's `CSpace`; no lock is held.
#[cfg(not(test))]
unsafe fn thread_with_rights(
    cspace: *mut crate::cap::cspace::CSpace,
    idx: u64,
    rights: crate::cap::slot::ThreadRights,
) -> Result<
    (
        super::PinnedCap,
        *mut crate::sched::thread::ThreadControlBlock,
    ),
    SyscallError,
>
{
    use crate::cap::object::ThreadObject;
    // SAFETY: cspace valid per contract; lookup_cap checks tag and rights.
    let pin = unsafe { super::lookup_cap(cspace, idx, rights) }?;
    let obj = pin.object.ok_or(SyscallError::InvalidCapability)?;
    // SAFETY: tag confirmed Thread; `pin` keeps the ThreadObject live.
    let tcb = unsafe { (*obj.as_ptr().cast::<ThreadObject>()).tcb };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    Ok((pin, tcb))
}

/// `SYS_THREAD_GET_FAULT_HANDLER` (56): read a thread's fault-handler binding
/// for one fault class.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = the class, exactly one class bit ([`syscall::FAULT_CLASS_VM`],
///        [`syscall::FAULT_CLASS_EXCEPTION`], or [`syscall::FAULT_CLASS_UPCALL`]).
///
/// Returns `1` when the class is bound and `0` when it is not, with the bound
/// badge in the secondary return register (`0` when unbound). The pair is
/// read once under the target's `sched_lock`, where binders publish it, so
/// the badge is the one bound with the endpoint the flag reports. No
/// endpoint, capability, or kernel address crosses: the badge is the
/// derivation badge of a cap the binder held (`docs/fault-handling.md`
/// § Fault-Handler Binding; `core/kernel/docs/cross-boundary-disclosure.md`).
///
/// # Errors
/// `InvalidArgument` for any other arg1 (checked first); `InvalidCapability`
/// and `InsufficientRights` for the thread cap.
#[cfg(not(test))]
pub fn sys_thread_get_fault_handler(tf: UserFrame) -> Result<u64, SyscallError>
{
    use core::sync::atomic::Ordering;
    let class = crate::ipc::fault::class_of_bit(tf.arg(1)).ok_or(SyscallError::InvalidArgument)?;
    // SAFETY: current_tcb() returns current thread; valid in syscall context.
    let caller_tcb = unsafe { crate::syscall::current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };
    // SAFETY: no lock is held.
    let (_pin, tcb) = unsafe { control_thread(caller_cspace, tf.arg(0)) }?;
    // `class_of_bit` returns a class below FAULT_CLASSES, the length of both
    // binding arrays.
    // SAFETY: tcb is pinned by `_pin`; the binding entries are atomics, read
    // through shared references.
    let handlers = unsafe { &(*tcb).fault_handlers };
    // SAFETY: as for `handlers`.
    let badges = unsafe { &(*tcb).fault_badges };
    let (handler, badge_word) = handlers
        .get(class)
        .zip(badges.get(class))
        .ok_or(SyscallError::InvalidArgument)?;
    // SAFETY: tcb is pinned by `_pin`.
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: no lock is held; lock_raw paired with the unlock_raw below; the
    // binding pair is published under this lock.
    let saved = unsafe { lock.lock_raw() };
    let bound = !handler.load(Ordering::Acquire).is_null();
    let badge = if bound
    {
        badge_word.load(Ordering::Relaxed)
    }
    else
    {
        0
    };
    // SAFETY: tcb is pinned by `_pin`.
    let lock = unsafe { &(*tcb).sched_lock };
    // SAFETY: pairs with the lock_raw above, whose `saved` this is.
    unsafe { lock.unlock_raw(saved) };
    let flag = u64::from(bound);
    tf.set_ipc_return(flag, badge);
    Ok(flag)
}

/// `SYS_THREAD_INHERIT_FAULT_HANDLER` (57): copy one thread's fault-handler
/// bindings, per class, onto another.
///
/// arg0 = destination Thread cap index (must have CONTROL).
/// arg1 = source Thread cap index (must have CONTROL).
/// arg2 = `fault_class_mask`, as for `SYS_THREAD_SET_FAULT_HANDLER`.
///
/// For each selected class the destination is bound to the source's endpoint
/// with the source's badge, or unbound where the source has none. The
/// source's pairs are read once under its `sched_lock`, each endpoint pinned
/// by a reference that becomes the destination binding's own
/// (`ipc::fault::pin_bindings`), then published on the destination as
/// `SYS_THREAD_SET_FAULT_HANDLER` publishes, with the same cancellation of a
/// delivery in flight under a changed binding (`apply_bindings`). No
/// capability to the endpoint is created: the binder needs none to copy a
/// binding, only `CONTROL` on both threads (`docs/fault-handling.md`
/// § Inheritance is userspace policy).
///
/// Returns 0 on success.
///
/// # Errors
/// `InvalidArgument` for a refused mask (checked first); `InvalidCapability`
/// and `InsufficientRights` for either thread cap.
#[cfg(not(test))]
pub fn sys_thread_inherit_fault_handler(tf: UserFrame) -> Result<u64, SyscallError>
{
    let selected =
        crate::ipc::fault::classes_of_mask(tf.arg(2)).ok_or(SyscallError::InvalidArgument)?;
    // SAFETY: current_tcb() returns current thread; valid in syscall context.
    let caller_tcb = unsafe { crate::syscall::current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let cspace = unsafe { (*caller_tcb).cspace };
    // SAFETY: cspace is the caller's; no lock is held.
    let (_dst_pin, dst) = unsafe { control_thread(cspace, tf.arg(0)) }?;
    // SAFETY: as above.
    let (_src_pin, src) = unsafe { control_thread(cspace, tf.arg(1)) }?;
    // SAFETY: src is pinned by `_src_pin`; no lock is held.
    let new = unsafe { crate::ipc::fault::pin_bindings(src, selected) };
    // SAFETY: dst is pinned by `_dst_pin`; `new` carries one reference per
    // selected non-null endpoint; no lock is held.
    unsafe { apply_bindings(dst, selected, new) };
    Ok(0)
}

/// `SYS_THREAD_POST_UPCALL` (58): post an asynchronous upcall to a thread.
///
/// arg0 = Thread cap index (must have UPCALL, and CONTROL beside it for
/// `UPCALL_ANY_INSTRUCTION`).
/// arg1 = cookie, delivered uninterpreted as the upcall message's data word 1.
/// arg2 = flags: `UPCALL_ANY_INSTRUCTION` or 0.
///
/// The upcall is delivered through the thread's `FAULT_CLASS_UPCALL` binding
/// at its next delivery point (`docs/fault-handling.md` § Asynchronous
/// Upcalls; [`crate::ipc::upcall::post`]).
///
/// # Errors
/// `InvalidArgument` for an undefined flag bit; `InvalidCapability` for a slot
/// that names no live Thread; `InsufficientRights` without the rights above;
/// `InvalidState` for a `Created` or `Exited` thread or one with no upcall
/// handler bound; `QueueFull` while an upcall is pending on the thread.
#[cfg(not(test))]
pub fn sys_thread_post_upcall(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::ThreadRights;
    let flags = tf.arg(2);
    if flags & !syscall::UPCALL_ANY_INSTRUCTION != 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    let any_instruction = flags & syscall::UPCALL_ANY_INSTRUCTION != 0;
    let rights = if any_instruction
    {
        ThreadRights::UPCALL | ThreadRights::CONTROL
    }
    else
    {
        ThreadRights::UPCALL
    };
    // SAFETY: current_tcb() returns current thread; valid in syscall context.
    let caller_tcb = unsafe { crate::syscall::current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };
    // SAFETY: no lock is held.
    let (_pin, tcb) = unsafe { thread_with_rights(caller_cspace, tf.arg(0), rights) }?;
    // SAFETY: tcb is pinned by `_pin`; syscall context, no lock held.
    unsafe { crate::ipc::upcall::post(tcb, tf.arg(1), any_instruction) }?;
    Ok(0)
}

/// `SYS_THREAD_SET_UPCALL_MASK` (59): set or clear the calling thread's upcall
/// mask.
///
/// arg0 = 1 to mask upcalls, 0 to unmask them.
///
/// Returns the previous mask (0 or 1). A pending upcall that the unmask
/// releases is delivered at this syscall's return.
///
/// # Errors
/// `InvalidArgument` for an argument other than 0 or 1.
#[cfg(not(test))]
pub fn sys_thread_set_upcall_mask(tf: UserFrame) -> Result<u64, SyscallError>
{
    let masked = match tf.arg(0)
    {
        0 => false,
        1 => true,
        _ => return Err(SyscallError::InvalidArgument),
    };
    // SAFETY: current_tcb() returns current thread; valid in syscall context.
    let tcb = unsafe { crate::syscall::current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidState);
    }
    // SAFETY: tcb is the calling thread; no lock held.
    let previous = unsafe { crate::ipc::upcall::set_mask(tcb, masked) };
    Ok(u64::from(previous))
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
/// currently in the Ready state, it is re-linked on the new level's run queue
/// immediately (at its tail, even when both levels share the fair queue).
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

    let thread_idx = tf.arg(0);
    // Validate the full 64-bit argument: a value above u8 is out of range, not
    // its low byte.
    let priority = u8::try_from(tf.arg(1)).map_err(|_| SyscallError::InvalidArgument)?;
    let sched_idx = tf.arg(2);

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
    // SAFETY: tag confirmed SchedControl; pointer is a valid SchedControlObject.
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
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
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

    // SAFETY: target_tcb validated non-null.
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: no lock is held; lock_raw paired with the unlock_raw below
    // (released last, restoring the caller's interrupt state).
    let tcb_sched_saved = unsafe { lock.lock_raw() };

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a target_tcb Scheduling-group field its held sched_lock \
                  serialises"
    )]
    // SAFETY: target_tcb validated non-null. `sched_lock` (held) serializes these
    // Scheduling-group accesses against every other writer.
    let (old_prio, state) = unsafe {
        let old_prio = (*target_tcb).priority;
        let state = (*target_tcb).state;
        (*target_tcb).priority = priority;
        (old_prio, state)
    };

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
            // SAFETY: target_tcb validated non-null; `sched_lock` (held)
            // serializes preferred_cpu.
            let p = unsafe { (*target_tcb).preferred_cpu } as usize;
            if p < cpu_count { p } else { 0 }
        };
        // SAFETY: target_tcb is valid and its sched_lock is held; no run-queue
        // lock is held; hint < cpu_count, which CPU_COUNT supplied.
        let _ = unsafe {
            crate::sched::relocate_ready_priority(target_tcb, old_prio, priority, hint, cpu_count)
        };
    }

    // Release `sched_lock`, restoring the caller's interrupt state.
    // SAFETY: target_tcb validated non-null.
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: tcb_sched_saved from the lock_raw above.
    unsafe { lock.unlock_raw(tcb_sched_saved) };

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
    use crate::cap::slot::{CapTag, SchedRights};
    use crate::cap::split::install_split_children;
    use crate::syscall::current_tcb;

    let sched_handle = tf.arg(0);
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
        // SAFETY: tag confirmed SchedControl; pointer is a valid SchedControlObject.
        let sc = unsafe { &*(obj_ptr.as_ptr().cast::<SchedControlObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (sc.min, sc.max, slot.rights, cspace_id, obj_ptr, slot)
    };

    // ── Validation ────────────────────────────────────────────────────────────

    // split_at is the first level of the upper child; both halves must be
    // non-empty: lower = [min, split_at - 1], upper = [split_at, max].
    let lower_max = split_at
        .checked_sub(1)
        .filter(|&lower_max| lower_max >= min && split_at <= max)
        .ok_or(SyscallError::InvalidArgument)?;

    // ── Create two child SchedControlObjects ───────────────────────────────────

    // The caller's CSpace, which receives both children, funds their
    // bodies from its arena (core/kernel/docs/capability-internals.md
    // § Body Arena); dealloc returns each chunk there.
    // SAFETY: caller_cspace is the running thread's own CSpace, live
    // while the thread runs.
    let funder = unsafe { crate::cap::object::arena_of(caller_cspace) }?;
    let child1_ptr = funder.alloc_body(SchedControlObject {
        header: KernelObjectHeader::new(ObjectType::SchedControl),
        min,
        max: lower_max,
    })?;

    let child2_ptr = match funder.alloc_body(SchedControlObject {
        header: KernelObjectHeader::new(ObjectType::SchedControl),
        min: split_at,
        max,
    })
    {
        Ok(p) => p,
        Err(e) =>
        {
            // SAFETY: child1_ptr is a freshly-allocated arena-backed body with
            // refcount 1 and not yet inserted into any CSpace.
            unsafe { dealloc_object(child1_ptr) };
            return Err(e);
        }
    };

    // Install both children, rewire the derivation tree, and consume the
    // original — shared with the hardware range splits.
    // SAFETY: caller_cspace validated non-null; cspace_id is its id; both
    // children are freshly-allocated arena-backed SchedControlObjects (refcount 1);
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
    tf.set_ipc_return(handle1, handle2);
    Ok(handle1)
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
///   (slice-expiry preemption, a fair-dispatched thread's preemption for
///   RT, voluntary yield, or IPC block). The
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

    let thread_idx = tf.arg(0);
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
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
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
    // the call.
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: no lock is held; paired with the unlock_raw below.
    let tcb_sched_saved = unsafe { lock.lock_raw() };

    // SAFETY: as above; every access is under the held sched_lock.
    let prod_cpu = unsafe { set_affinity_locked(target_tcb, cpu_id) };

    // SAFETY: target_tcb is still pinned by `thread_slot`.
    let lock = unsafe { &(*target_tcb).sched_lock };
    // SAFETY: paired with the lock_raw above.
    unsafe { lock.unlock_raw(tcb_sched_saved) };

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

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a tcb field its held sched_lock serialises"
    )]
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
        // The next enqueue routes via select_target_cpu, which reads the new
        // affinity under sched_lock.
        ThreadState::Created
        | ThreadState::Blocked
        | ThreadState::Stopped
        | ThreadState::Exited => None,
    }
}

/// Whether `[base, base + len)` lies wholly in the user half: it neither wraps
/// nor reaches `user_va_top`. A kernel-half address must never reach a copy:
/// the direct-map copy of `AddressSpace::copy_user_bytes` walks only user
/// tables, and SMAP and SUM gate only user pages for the caller's buffer.
#[cfg(not(test))]
fn user_range(base: u64, len: usize) -> bool
{
    base.checked_add(len as u64)
        .is_some_and(|end| end <= crate::mm::user_va_top())
}

/// A reference on the `AddressSpace` object a thread executes in
/// (`sched::pin_thread_aspace`), released on drop. Dropped in syscall context
/// with no lock held, before any park, as a `PinnedCap` is.
#[cfg(not(test))]
struct AspacePin(core::ptr::NonNull<crate::cap::object::KernelObjectHeader>);

#[cfg(not(test))]
impl AspacePin
{
    /// Pin the address space of the thread `thread_idx` names in the caller's
    /// `CSpace`, which must carry `CONTROL`.
    ///
    /// # Errors
    /// - `InvalidCapability`: no current thread, or `thread_idx` names no
    ///   Thread cap.
    /// - `InsufficientRights`: the cap lacks `CONTROL`.
    /// - `InvalidState`: the thread has exited, or has no address space.
    fn of_thread(thread_idx: u64) -> Result<Self, SyscallError>
    {
        use crate::cap::object::ThreadObject;
        use crate::cap::slot::ThreadRights;
        use crate::syscall::current_tcb;

        // SAFETY: current_tcb() returns the running thread, set in syscall context.
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
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Thread; thread_slot pins the object.
        let target_tcb = unsafe { (*obj.as_ptr().cast::<ThreadObject>()).tcb };
        if target_tcb.is_null()
        {
            return Err(SyscallError::InvalidCapability);
        }
        // SAFETY: target_tcb is valid while thread_slot pins its object; no
        // lock is held.
        unsafe { crate::sched::pin_thread_aspace(target_tcb) }
            .map(Self)
            .ok_or(SyscallError::InvalidState)
    }

    /// The pinned address space.
    fn aspace(&self) -> &crate::mm::address_space::AddressSpace
    {
        let obj = self
            .0
            .as_ptr()
            .cast::<crate::cap::object::AddressSpaceObject>();
        // SAFETY: the reference self holds keeps the object allocated.
        let space = unsafe { (*obj).address_space };
        // SAFETY: the reference self holds keeps the object's wrapper page,
        // and the AddressSpace constructed in it, allocated.
        unsafe { &*space }
    }
}

#[cfg(not(test))]
impl Drop for AspacePin
{
    fn drop(&mut self)
    {
        // SAFETY: of_thread took this reference and nothing else releases
        // it; the pin is dropped in syscall context with interrupts disabled
        // and no lock held, release_ref's preconditions.
        unsafe { crate::cap::object::release_ref(self.0) };
    }
}

/// The validated `(target VA, caller buffer, length)` of a thread-memory call.
///
/// # Errors
/// - `InvalidArgument`: `len` is 0 or above `MAX_THREAD_MEM_COPY`.
/// - `InvalidAddress`: either range is not wholly in the user half, or the
///   buffer is null.
#[cfg(not(test))]
fn thread_mem_args(tf: UserFrame) -> Result<(u64, u64, usize), SyscallError>
{
    let va = tf.arg(1);
    let buf = tf.arg(2);
    let Ok(len) = usize::try_from(tf.arg(3))
    else
    {
        return Err(SyscallError::InvalidArgument);
    };
    if len == 0 || len > syscall::MAX_THREAD_MEM_COPY
    {
        return Err(SyscallError::InvalidArgument);
    }
    if buf == 0 || !user_range(va, len) || !user_range(buf, len)
    {
        return Err(SyscallError::InvalidAddress);
    }
    Ok((va, buf, len))
}

/// `SYS_THREAD_READ_MEM` (60): copy bytes from a thread's address space into
/// the caller's buffer.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = Source VA in the thread's address space.
/// arg2 = Destination buffer (caller's user VA).
/// arg3 = Byte count, `1..=MAX_THREAD_MEM_COPY`.
///
/// The thread need not be stopped. The bytes are staged in the CPU's syscall
/// scratch buffer (`syscall::scratch`) under the target space's page-table
/// lock, then copied out. Returns the count.
///
/// # Errors
/// As in core/kernel/docs/syscalls.md § `SYS_THREAD_READ_MEM` (60), and a
/// [`RestartableError::Faulted`] copy to the buffer, which re-executes the
/// whole call on the caller's resume.
#[cfg(not(test))]
pub fn sys_thread_read_mem(tf: UserFrame) -> Result<u64, RestartableError>
{
    use crate::mm::address_space::UserCopy;

    let (va, buf, len) = thread_mem_args(tf)?;
    // SAFETY: a syscall handler, which holds `staged` only until it returns
    // and neither parks nor yields meanwhile (a faulted user copy returns,
    // and the call is re-executed from its start).
    let stage = unsafe { super::scratch::thread_mem() };
    // `thread_mem_args` bounds `len` by the buffer's size.
    let staged = stage.get_mut(..len).ok_or(SyscallError::InvalidArgument)?;
    {
        let pin = AspacePin::of_thread(tf.arg(0))?;
        // SAFETY: pin keeps the space allocated; [va, va + len) is in the
        // user half (thread_mem_args); no lock is held.
        unsafe {
            pin.aspace()
                .copy_user_bytes(va, UserCopy::Read(&mut *staged))
        }?;
    }
    // Nothing before this copy changed anything visible outside the call,
    // so a fault re-executes it from the start.
    // SAFETY: staged holds len initialised bytes; buf is the validated user
    // destination span.
    unsafe { crate::uaccess::copy_to_user_restartable(buf, staged.as_ptr(), len)? };
    Ok(len as u64)
}

/// `SYS_THREAD_WRITE_MEM` (61): copy bytes from the caller's buffer into a
/// thread's address space.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = Destination VA in the thread's address space.
/// arg2 = Source buffer (caller's user VA).
/// arg3 = Byte count, `1..=MAX_THREAD_MEM_COPY`.
/// arg4 = Flags: `THREAD_MEM_TEXT` permits a page the thread's mapping makes
///        read-only.
///
/// The bytes are copied in from the caller to the CPU's syscall scratch
/// buffer (`syscall::scratch`) first, then written under the target space's
/// page-table lock, all or nothing. Every successful write then synchronises
/// instruction fetch on every CPU before the call returns (`mm::icache`): a
/// written page is executable in the target, or, when writable there, its
/// frame may be mapped executable elsewhere, which no leaf of the target
/// shows. Returns 0.
///
/// # Errors
/// As in core/kernel/docs/syscalls.md § `SYS_THREAD_WRITE_MEM` (61), and a
/// [`RestartableError::Faulted`] copy from the buffer, which re-executes the
/// whole call on the caller's resume.
#[cfg(not(test))]
pub fn sys_thread_write_mem(tf: UserFrame) -> Result<u64, RestartableError>
{
    use crate::mm::address_space::{TextWrite, UserCopy};

    let (va, buf, len) = thread_mem_args(tf)?;
    let flags = tf.arg(4);
    if flags & !syscall::THREAD_MEM_TEXT != 0
    {
        return Err(SyscallError::InvalidArgument.into());
    }
    let text = if flags & syscall::THREAD_MEM_TEXT != 0
    {
        TextWrite::Permitted
    }
    else
    {
        TextWrite::Refused
    };
    // SAFETY: a syscall handler, which holds `staged` only until it returns
    // and neither parks nor yields meanwhile (a faulted user copy returns,
    // and the call is re-executed from its start).
    let stage = unsafe { super::scratch::thread_mem() };
    // `thread_mem_args` bounds `len` by the buffer's size.
    let staged = stage.get_mut(..len).ok_or(SyscallError::InvalidArgument)?;
    // Copy in before the target is touched, so a fault re-executes a call
    // that has changed nothing.
    // SAFETY: staged is valid for len writes; buf is the validated user
    // source span.
    unsafe { crate::uaccess::copy_from_user_restartable(staged.as_mut_ptr(), buf, len)? };
    {
        let pin = AspacePin::of_thread(tf.arg(0))?;
        // SAFETY: pin keeps the space allocated; [va, va + len) is in the
        // user half (thread_mem_args); no lock is held.
        unsafe {
            pin.aspace().copy_user_bytes(
                va,
                UserCopy::Write {
                    src: &*staged,
                    text,
                },
            )
        }?;
    }
    // The pin and pt_lock are released: the sync waits for every hart.
    crate::mm::icache::sync_user_code();
    Ok(0)
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
/// - A [`RestartableError::Faulted`] copy, which the dispatcher delivers to the
///   caller's fault handler (re-executing the call on resume) or fails with
///   `InvalidAddress` (core/kernel/docs/syscalls.md § Restartable Syscalls).
#[cfg(not(test))]
pub fn sys_thread_read_regs(tf: UserFrame) -> Result<u64, RestartableError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::syscall::current_tcb;
    use core::mem::{MaybeUninit, size_of};

    let thread_idx = tf.arg(0);
    let buf_ptr = tf.arg(1);
    let buf_size = tf.arg(2) as usize;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability.into());
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // OBSERVE right is sufficient for reading registers.
    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::OBSERVE) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability.into());
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
        None => return Err(SyscallError::InvalidState.into()),
        Some(false) => return Err(SyscallError::InvalidArgument.into()),
        Some(true) =>
        {}
    }

    if buf_size < copy_size || buf_ptr == 0
    {
        return Err(SyscallError::InvalidArgument.into());
    }
    // The destination must lie wholly in the user half: SMAP/SUM gate only
    // accesses to user pages, so without this a kernel-half buf_ptr would let the
    // copy write the target's register frame into kernel memory at an
    // attacker-chosen VA.
    if !user_range(buf_ptr, copy_size)
    {
        return Err(SyscallError::InvalidAddress.into());
    }

    // Copy the snapshot to the user buffer with fault recovery: an unbacked or
    // read-only buffer reaches the dispatcher as a restartable fault instead of
    // faulting the kernel. Nothing before the copy changed anything visible
    // outside the call, so a re-execution reads the target afresh.
    // SAFETY: frame holds copy_size initialised bytes; buf_ptr is the
    //         validated user destination span.
    unsafe {
        crate::uaccess::copy_to_user_restartable(buf_ptr, frame.as_ptr().cast::<u8>(), copy_size)?;
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
/// - A [`RestartableError::Faulted`] copy, handled as for
///   [`sys_thread_read_regs`].
#[cfg(not(test))]
pub fn sys_thread_write_regs(tf: UserFrame) -> Result<u64, RestartableError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::ThreadRights;
    use crate::syscall::current_tcb;
    use core::mem::{MaybeUninit, size_of};

    let thread_idx = tf.arg(0);
    let buf_ptr = tf.arg(1);
    let buf_size = tf.arg(2) as usize;

    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let caller_tcb = unsafe { current_tcb() };
    if caller_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability.into());
    }
    // SAFETY: caller_tcb validated non-null; cspace set at thread creation.
    let caller_cspace = unsafe { (*caller_tcb).cspace };

    // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
    let thread_slot =
        unsafe { super::lookup_cap(caller_cspace, thread_idx, ThreadRights::CONTROL) }?;

    let target_tcb = {
        let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
        let to = unsafe { &*(obj.as_ptr().cast::<ThreadObject>()) };
        to.tcb
    };

    if target_tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability.into());
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
        return Err(SyscallError::InvalidArgument.into());
    }
    // The source must lie wholly in the user half: SMAP/SUM gate only accesses to
    // user pages, so without this a kernel-half buf_ptr would let the copy read
    // kernel memory at an attacker-chosen VA into the register frame.
    if !user_range(buf_ptr, copy_size)
    {
        return Err(SyscallError::InvalidAddress.into());
    }

    // Copy from user into a stack-local TrapFrame, then validate. Never write
    // directly to the target's trap_frame before validation. The copy is
    // fault-recovered: an unbacked source reaches the dispatcher as a
    // restartable fault, and the target is untouched until after the copy.
    let mut tmp: MaybeUninit<ArchTF> = MaybeUninit::zeroed();
    // SAFETY: tmp is valid for copy_size writes; buf_ptr is the validated user
    //         source span.
    unsafe {
        crate::uaccess::copy_from_user_restartable(
            tmp.as_mut_ptr().cast::<u8>(),
            buf_ptr,
            copy_size,
        )?;
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
        None => Err(SyscallError::InvalidState.into()),
        Some(false) => Err(SyscallError::InvalidArgument.into()),
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

#[cfg(test)]
pub fn sys_thread_read_mem(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

#[cfg(test)]
pub fn sys_thread_write_mem(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}
