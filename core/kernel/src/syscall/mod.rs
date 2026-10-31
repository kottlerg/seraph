// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/mod.rs

//! Kernel syscall dispatch.
//!
//! `dispatch` is called from the architecture-specific trap/syscall entry
//! with a pointer to the current thread's [`TrapFrame`]. It reads the syscall
//! number, calls the appropriate handler, and writes the return value back.
//!
//! # Syscall ABI
//! The registers carrying the syscall number, arguments, and return value are
//! defined in core/kernel/docs/syscalls.md § Calling Convention.
//!
//! # Adding new syscalls
//! 1. Add the constant to `abi/syscall/src/lib.rs`.
//! 2. Add a handler function in the appropriate `syscall/` submodule.
//! 3. Add a `match` arm in `dispatch` below.

pub mod cap;
pub mod entropy;
pub mod hw;
pub mod ipc;
pub mod mem;
pub mod sbi;
pub mod sysinfo;
pub mod thread;

use crate::arch::current::trap_frame::TrapFrame;
#[cfg(not(test))]
use syscall::SyscallError;

#[cfg(not(test))]
use syscall::{
    SYS_ASPACE_BIND_NOTIFICATION, SYS_ASPACE_QUERY, SYS_CAP_COPY, SYS_CAP_CREATE_ASPACE,
    SYS_CAP_CREATE_CSPACE, SYS_CAP_CREATE_ENDPOINT, SYS_CAP_CREATE_EVENT_Q,
    SYS_CAP_CREATE_NOTIFICATION, SYS_CAP_CREATE_THREAD, SYS_CAP_CREATE_WAIT_SET, SYS_CAP_DELETE,
    SYS_CAP_DERIVE, SYS_CAP_DERIVE_BADGE, SYS_CAP_INFO, SYS_CAP_MOVE, SYS_CAP_REVOKE,
    SYS_EVENT_POST, SYS_EVENT_RECV, SYS_GETRANDOM, SYS_IOPORT_BIND, SYS_IOPORT_SPLIT,
    SYS_IPC_BUFFER_SET, SYS_IPC_CALL, SYS_IPC_RECV, SYS_IPC_REPLY, SYS_IRQ_ACK, SYS_IRQ_REGISTER,
    SYS_IRQ_SPLIT, SYS_MEM_MAP, SYS_MEM_PROTECT, SYS_MEM_UNMAP, SYS_MEMORY_MERGE, SYS_MEMORY_SPLIT,
    SYS_MMIO_MAP, SYS_MMIO_SPLIT, SYS_NOTIFICATION_SEND, SYS_NOTIFICATION_WAIT, SYS_PROCESS_EXIT,
    SYS_SBI_CALL, SYS_SCHED_SPLIT, SYS_SYSTEM_INFO, SYS_THREAD_BIND_NOTIFICATION,
    SYS_THREAD_CONFIGURE, SYS_THREAD_EXIT, SYS_THREAD_READ_REGS, SYS_THREAD_SET_AFFINITY,
    SYS_THREAD_SET_FAULT_HANDLER, SYS_THREAD_SET_PRIORITY, SYS_THREAD_SLEEP, SYS_THREAD_START,
    SYS_THREAD_STOP, SYS_THREAD_WRITE_REGS, SYS_THREAD_YIELD, SYS_WAIT_SET_ADD,
    SYS_WAIT_SET_REMOVE, SYS_WAIT_SET_WAIT,
};

// ── Syscall dispatch ──────────────────────────────────────────────────────────

/// Record a syscall's entry: the calling thread's `syscall_nr` stamp, this
/// CPU's stamp for the softlockup watchdog, and the thread's `trap_frame`.
///
/// Every entry from user mode at which the thread can be descheduled
/// publishes its live frame as the thread's `trap_frame` (see
/// core/kernel/docs/arch-interface.md § `trap_frame`); an interrupt or
/// exception taken since the last syscall may have pointed it at a frame
/// lower on the stack.
///
/// # Safety
/// Called from syscall entry with interrupts masked, with `frame` the live
/// frame on the calling thread's kernel stack.
#[cfg(not(test))]
unsafe fn stamp_syscall_entry(nr: u64, frame: *mut TrapFrame)
{
    // Null-guarded like every handler's own check rather than asserted: the
    // diagnostic stamp must never be the thing that faults.
    // SAFETY: kernel context with the scheduler initialised and interrupts
    // masked, so `current_tcb` reads this CPU's current thread.
    let tcb = unsafe { current_tcb() };
    crate::sched::note_cpu_syscall(nr);
    if tcb.is_null()
    {
        return;
    }
    // SAFETY: tcb is the running thread's live TCB (checked non-null above),
    // and the running thread alone writes its own `syscall_nr` and
    // `trap_frame` after configuration.
    unsafe {
        (*tcb)
            .syscall_nr
            .store(nr, core::sync::atomic::Ordering::Relaxed);
        (*tcb)
            .trap_frame
            .store(frame, core::sync::atomic::Ordering::Relaxed);
    }
}

/// The calling thread's user register frame, as a syscall handler reaches it.
///
/// The frame lives on the thread's kernel stack and is published as its
/// `trap_frame`, through which other CPUs read and write it while the thread
/// is held off-CPU (`SYS_THREAD_READ_REGS` / `SYS_THREAD_WRITE_REGS` on a
/// `Stopped` or fault-blocked thread, `sched::with_held_frame`) — including
/// while the thread is blocked inside a syscall. A `&mut TrapFrame` held by
/// the handler across such a block would be live during those foreign
/// accesses. A `UserFrame` instead carries the raw frame pointer, and each
/// accessor derives a reference for that one access, which ends before the
/// accessor returns; no access spans a block, so the thread's own accesses
/// and the foreign ones never overlap (core/kernel/docs/arch-interface.md
/// § `trap_frame`).
#[derive(Clone, Copy)]
#[cfg(not(test))]
pub struct UserFrame(core::ptr::NonNull<TrapFrame>);

#[cfg(not(test))]
impl UserFrame
{
    /// Wrap the frame `dispatch` received.
    ///
    /// # Safety
    /// `frame` must be the running thread's valid frame on its kernel stack,
    /// valid for the whole syscall, and every access to it from this thread
    /// must go through the returned value.
    unsafe fn new(frame: *mut TrapFrame) -> Self
    {
        // SAFETY: frame is non-null and valid (contract).
        Self(unsafe { core::ptr::NonNull::new_unchecked(frame) })
    }

    /// The syscall number.
    fn syscall_nr(self) -> u64
    {
        // SAFETY: the frame is valid for the syscall (`new`'s contract), and
        // the shared reference lives only for this read, which no foreign
        // write overlaps: the thread is running, so no other CPU holds it.
        unsafe { (*self.0.as_ptr()).syscall_nr() }
    }

    /// Syscall argument `n`.
    pub fn arg(self, n: usize) -> u64
    {
        // SAFETY: as for `syscall_nr`.
        unsafe { (*self.0.as_ptr()).arg(n) }
    }

    /// Write the primary return value.
    fn set_return(self, val: i64)
    {
        // SAFETY: as for `syscall_nr`; the exclusive reference lives only for
        // this write.
        unsafe { (*self.0.as_ptr()).set_return(val) };
    }

    /// Write the two-register IPC return (primary, secondary).
    pub fn set_ipc_return(self, primary: u64, label: u64)
    {
        // SAFETY: as for `set_return`.
        unsafe { (*self.0.as_ptr()).set_ipc_return(primary, label) };
    }

    /// Write the three-register return (primary, secondary, tertiary): rax,
    /// rdx, rsi on x86-64; a0, a1, a2 on RISC-V. `SYS_EVENT_RECV` returns an
    /// entry's payload and tag words through it.
    pub fn set_ipc_return_with_badge(self, primary: u64, label: u64, badge: u64)
    {
        // SAFETY: as for `set_return`.
        unsafe { (*self.0.as_ptr()).set_ipc_return_with_badge(primary, label, badge) };
    }

    /// Write the `SYS_IPC_CALL` return registers.
    pub fn set_ipc_call_return(self, primary: u64, reply_label: u64, reply_word_count: u64)
    {
        // SAFETY: as for `set_return`.
        unsafe { (*self.0.as_ptr()).set_ipc_call_return(primary, reply_label, reply_word_count) };
    }

    /// Write the `SYS_IPC_RECV` return registers.
    pub fn set_ipc_recv_return(self, primary: u64, label: u64, badge: u64, word_count: u64)
    {
        // SAFETY: as for `set_return`.
        unsafe {
            (*self.0.as_ptr()).set_ipc_recv_return(primary, label, badge, word_count);
        };
    }
}

/// Syscall dispatcher: called from the arch-specific trap/syscall entry stub.
///
/// Reads the syscall number from `tf`, invokes the handler, and writes the
/// return value (or negative error code) back into `tf`.
///
/// # Safety
/// `tf` must point to a valid, kernel-stack-resident [`TrapFrame`] for the
/// currently running thread. The caller must have already switched to the
/// kernel stack.
#[cfg(not(test))]
pub unsafe fn dispatch(tf: *mut TrapFrame)
{
    crate::arch::current::cpu::debug_assert_kernel_entry_flags();
    let frame = tf;
    // SAFETY: caller guarantees tf is the running thread's valid frame for
    // the whole syscall. The handlers reach it only through `UserFrame`,
    // whose accesses each end before the next statement, so no reference to
    // the frame lives across a block, while other paths access the frame
    // through the published `trap_frame` (core/kernel/docs/arch-interface.md
    // § `trap_frame`).
    let tf = unsafe { UserFrame::new(tf) };

    let nr = tf.syscall_nr();
    // SAFETY: syscall entry with interrupts masked, on the caller's kernel
    // stack; `frame` is its live frame.
    unsafe { stamp_syscall_entry(nr, frame) };

    let ret: Result<u64, SyscallError> = match nr
    {
        SYS_IPC_CALL => ipc::sys_ipc_call(tf),
        SYS_IPC_REPLY => ipc::sys_ipc_reply(tf),
        SYS_IPC_RECV => ipc::sys_ipc_recv(tf),
        SYS_NOTIFICATION_SEND => ipc::sys_notification_send(tf),
        SYS_NOTIFICATION_WAIT => ipc::sys_notification_wait(tf),
        SYS_CAP_CREATE_ENDPOINT => cap::sys_cap_create_endpoint(tf),
        SYS_CAP_CREATE_NOTIFICATION => cap::sys_cap_create_notification(tf),
        SYS_CAP_CREATE_ASPACE => cap::sys_cap_create_aspace(tf),
        SYS_CAP_CREATE_CSPACE => cap::sys_cap_create_cspace(tf),
        SYS_CAP_CREATE_THREAD => cap::sys_cap_create_thread(tf),
        SYS_CAP_COPY => cap::sys_cap_copy(tf),
        SYS_CAP_DERIVE => cap::sys_cap_derive(tf),
        SYS_CAP_DELETE => cap::sys_cap_delete(tf),
        SYS_CAP_REVOKE => cap::sys_cap_revoke(tf),
        SYS_CAP_MOVE => cap::sys_cap_move(tf),
        SYS_MEM_MAP => mem::sys_mem_map(tf),
        SYS_MEM_UNMAP => mem::sys_mem_unmap(tf),
        SYS_MEM_PROTECT => mem::sys_mem_protect(tf),
        SYS_MEMORY_SPLIT => mem::sys_memory_split(tf),
        SYS_MEMORY_MERGE => mem::sys_memory_merge(tf),
        SYS_THREAD_CONFIGURE => thread::sys_thread_configure(tf),
        SYS_THREAD_START => thread::sys_thread_start(tf),
        SYS_THREAD_STOP => thread::sys_thread_stop(tf),
        SYS_THREAD_SET_PRIORITY => thread::sys_thread_set_priority(tf),
        SYS_THREAD_SET_AFFINITY => thread::sys_thread_set_affinity(tf),
        SYS_THREAD_READ_REGS => thread::sys_thread_read_regs(tf),
        SYS_THREAD_WRITE_REGS => thread::sys_thread_write_regs(tf),
        SYS_THREAD_SET_FAULT_HANDLER => thread::sys_thread_set_fault_handler(tf),
        SYS_IPC_BUFFER_SET => sys_ipc_buffer_set(tf),
        SYS_THREAD_YIELD => sys_yield(tf),
        SYS_THREAD_EXIT => sys_exit(tf),
        SYS_PROCESS_EXIT => sys_process_exit(tf),
        SYS_SYSTEM_INFO => sysinfo::sys_system_info(tf),
        SYS_ASPACE_QUERY => sysinfo::sys_aspace_query(tf),
        SYS_GETRANDOM => entropy::sys_getrandom(tf),
        SYS_EVENT_POST => ipc::sys_event_post(tf),
        SYS_EVENT_RECV => ipc::sys_event_recv(tf),
        SYS_CAP_CREATE_EVENT_Q => cap::sys_cap_create_event_queue(tf),
        SYS_CAP_CREATE_WAIT_SET => cap::sys_cap_create_wait_set(tf),
        SYS_WAIT_SET_ADD => ipc::sys_wait_set_add(tf),
        SYS_WAIT_SET_REMOVE => ipc::sys_wait_set_remove(tf),
        SYS_WAIT_SET_WAIT => ipc::sys_wait_set_wait(tf),
        SYS_IRQ_ACK => hw::sys_irq_ack(tf),
        SYS_IRQ_REGISTER => hw::sys_irq_register(tf),
        SYS_MMIO_MAP => hw::sys_mmio_map(tf),
        SYS_IOPORT_BIND => hw::sys_ioport_bind(tf),
        SYS_MMIO_SPLIT => hw::sys_mmio_split(tf),
        SYS_IRQ_SPLIT => hw::sys_irq_split(tf),
        SYS_IOPORT_SPLIT => hw::sys_ioport_split(tf),
        SYS_SCHED_SPLIT => thread::sys_sched_split(tf),
        SYS_SBI_CALL => sbi::sys_sbi_call(tf),
        SYS_THREAD_SLEEP => sys_thread_sleep(tf),
        SYS_THREAD_BIND_NOTIFICATION => sys_thread_bind_notification(tf),
        SYS_ASPACE_BIND_NOTIFICATION => sys_aspace_bind_notification(tf),
        SYS_CAP_DERIVE_BADGE => cap::sys_cap_derive_badge(tf),
        SYS_CAP_INFO => cap::sys_cap_info(tf),
        _ => Err(SyscallError::UnknownSyscall),
    };

    let ret_val = match ret
    {
        Ok(v) => v.cast_signed(),
        Err(e) => e as i64,
    };

    tf.set_return(ret_val);

    // Self-teardown epilogue (#341): a live thread drains this CPU's
    // deferred-reclaim stack; a thread found `Exited` (before or after the drain)
    // reschedules away and never returns to userspace. Protocol and invariants:
    // core/kernel/docs/thread-lifecycle-and-sleep.md § Self-teardown (the caller
    // is the freed thread).
    // SAFETY: syscall context on the caller's kernel stack with interrupts
    // disabled (the drain re-enables them only with preemption disabled), so
    // this CPU and its `current` are stable across both checks.
    unsafe {
        let this_cpu = crate::arch::current::cpu::current_cpu() as usize;
        if !crate::sched::running_thread_stopped(this_cpu)
        {
            crate::cap::object::drain_deferred_reclaim(this_cpu);
        }
        if crate::sched::running_thread_stopped(this_cpu)
        {
            crate::sched::schedule(crate::sched::Requeue::IfRunnable);
            crate::arch::current::cpu::halt_loop();
        }
        let tcb = current_tcb();
        if !tcb.is_null()
        {
            (*tcb)
                .syscall_nr
                .store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

// ── Thread syscall handlers ───────────────────────────────────────────────────

/// `SYS_THREAD_YIELD` (21): voluntarily yield the CPU.
#[cfg(not(test))]
// unnecessary_wraps: all dispatch arms must return Result<u64, SyscallError>; signature is fixed.
#[allow(clippy::unnecessary_wraps)]
fn sys_yield(_tf: UserFrame) -> Result<u64, SyscallError>
{
    // SAFETY: called from syscall handler on a valid kernel stack.
    // Requeue::Always: thread is voluntarily yielding but should remain runnable.
    unsafe {
        crate::sched::schedule(crate::sched::Requeue::Always);
    }
    Ok(0)
}

/// `SYS_THREAD_EXIT` (22): terminate the calling thread.
///
/// Marks the current thread as `Exited` and calls `schedule()` to switch
/// to the next runnable thread. The exited thread is never re-enqueued.
///
/// Its kernel stack and TCB are freed by `dealloc_object(Thread)` when its
/// last capability is deleted (procmgr's cap-revoke teardown, for process
/// threads).
#[cfg(not(test))]
fn sys_exit(_tf: UserFrame) -> Result<u64, SyscallError>
{
    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if !tcb.is_null()
    {
        // Commit Exited under all-CPU scheduler.locks so a concurrent
        // dealloc on another CPU observes a coherent state and the local
        // schedule() below sees the Exited skip-bit. The reason (0 = clean
        // exit) is written in the same hold. A refusal means the thread was
        // already torn down: an object-teardown stop recorded `EXIT_KILLED`,
        // or a `dealloc_object(Thread)` committed `Exited`. This path still
        // posts its own reason below (no death walk posts `EXIT_KILLED`; see
        // the ABI constant), so after a teardown stop only the retained value
        // says killed.
        // SAFETY: tcb validated non-null.
        let _ = unsafe { crate::sched::exit_under_all_locks(tcb, 0) };

        // Post death notification if bound (exit_reason 0 = clean exit).
        // SAFETY: tcb is valid; post_death_notification handles null eq check.
        unsafe {
            crate::sched::post_death_notification(tcb, 0);
        }
    }
    // Switch to the next runnable thread. The exited thread must not be
    // re-enqueued.
    // SAFETY: called from syscall handler on a valid kernel stack.
    unsafe {
        crate::sched::schedule(crate::sched::Requeue::IfRunnable);
    }
    // schedule() returns here if the same thread is re-selected (shouldn't
    // happen for an Exited thread, but halt as a safety net).
    crate::arch::current::cpu::halt_loop();
}

/// `SYS_PROCESS_EXIT` (54): terminate the calling process with an exit code.
///
/// Encodes `arg0` via [`syscall::encode_exit_code`] into the voluntary range
/// `[0, EXIT_FAULT_BASE)`, records it as the calling thread's exit reason, and
/// posts it to the calling thread's death observers — a parent that bound the
/// main thread (so `ExitStatus::code()` carries it) and procmgr's per-thread
/// observer (which reaps the process). Structurally identical to [`sys_exit`]
/// but with the encoded caller-supplied reason (zero for `exit(0)`); in
/// particular it schedules away immediately
/// after the post, with no further dereference of the thread or its address
/// space, so it cannot race procmgr's cap-revoke teardown.
///
/// It does NOT post to the address-space death-observer surface, which is
/// reserved for terminal faults (rationale: docs/process-lifecycle.md § Exit
/// reason). Whole-process exit from a non-main thread is not yet modelled.
///
/// Like [`sys_exit`], this stops only the calling thread; sibling threads and
/// the process's resources are torn down by procmgr (see
/// docs/process-lifecycle.md § Process Death).
#[cfg(not(test))]
// cast_possible_truncation: arg0 carries a u32 exit code zero-extended to u64
// by the `process_exit` wrapper; truncating back to u32 is the intended decode.
#[allow(clippy::cast_possible_truncation)]
fn sys_process_exit(tf: UserFrame) -> Result<u64, SyscallError>
{
    let reason = syscall::encode_exit_code(tf.arg(0) as u32);
    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if !tcb.is_null()
    {
        // Commit Exited under all-CPU scheduler.locks (see sys_exit); the
        // reason is written in the same hold. A refusal means the thread was
        // already torn down: an object-teardown stop recorded `EXIT_KILLED`,
        // or a `dealloc_object(Thread)` committed `Exited`. The post below
        // still carries this path's own reason (no death walk posts
        // `EXIT_KILLED`).
        // SAFETY: tcb validated non-null.
        let _ = unsafe { crate::sched::exit_under_all_locks(tcb, reason) };

        // Notify the calling thread's observers (a parent that bound the main
        // thread; procmgr's per-thread observer), then schedule immediately —
        // no further tcb/aspace dereference, matching sys_exit's safe window.
        // SAFETY: tcb is valid; post_death_notification handles null eq check.
        unsafe {
            crate::sched::post_death_notification(tcb, reason);
        }
    }
    // Switch to the next runnable thread. The exited thread must not be
    // re-enqueued.
    // SAFETY: called from syscall handler on a valid kernel stack.
    unsafe {
        crate::sched::schedule(crate::sched::Requeue::IfRunnable);
    }
    // schedule() returns here if the same thread is re-selected (shouldn't
    // happen for an Exited thread, but halt as a safety net).
    crate::arch::current::cpu::halt_loop();
}

// ── SYS_THREAD_SLEEP ─────────────────────────────────────────────────────────

/// `SYS_THREAD_SLEEP` (46): sleep the calling thread for `arg0` milliseconds.
///
/// The thread is added to a global sleep list and removed from the run queue.
/// The timer tick handler wakes it when `current_tick() >= deadline`.
#[cfg(not(test))]
fn sys_thread_sleep(tf: UserFrame) -> Result<u64, SyscallError>
{
    let ms = tf.arg(0);
    if ms == 0
    {
        return Ok(0);
    }

    let deadline = crate::sched::sleep_deadline_after_ms(ms);

    // SAFETY: current_tcb() returns this CPU's running thread.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Open the park episode before the thread can become Blocked-claimable.
    // SAFETY: tcb is the running caller, not yet claimable.
    unsafe { crate::sched::thread::open_park_episode(tcb) };

    // Set before the park commit: from the commit on, a cancellation
    // (`cancel_ipc_block` under sched_lock) can clear it, and the add below
    // then refuses.
    // SAFETY: tcb validated non-null.
    unsafe {
        (*tcb)
            .sleep_deadline
            .store(deadline, core::sync::atomic::Ordering::Relaxed);
    }

    // Commit Running→Blocked under the per-TCB sched_lock (the authoritative
    // serializer for the Scheduling field group). A sleep has no IPC source, so
    // ipc_state stays None. A refusal means a concurrent stop/exit won or a
    // wake was deposited (refuse-to-park): abandon the sleep.
    // SAFETY: tcb is this CPU's current (running) thread.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            tcb,
            crate::sched::thread::IpcThreadState::None,
            core::ptr::null_mut(),
        )
    };
    match committed
    {
        crate::sched::ParkCommit::Committed =>
        {}
        crate::sched::ParkCommit::RefusedWake =>
        {
            // Stray coalesced wake; no sleep-list entry was added and the
            // thread stays runnable — report the (zero-length) sleep done.
            // SAFETY: tcb valid; never parked, so no canceller targets it.
            unsafe {
                (*tcb)
                    .sleep_deadline
                    .store(0, core::sync::atomic::Ordering::Relaxed);
            }
            return Ok(0);
        }
        crate::sched::ParkCommit::RefusedStop =>
        {
            // A stop won against the park. Deschedule in place (the requeue
            // denylist drops a Stopped thread); on restart the continuation
            // completes and nothing rewrites the trap frame afterwards, so
            // the direct error return survives to userspace.
            // SAFETY: tcb valid; no sleep-list entry was added. schedule is
            // called from syscall context on a valid kernel stack.
            unsafe {
                (*tcb)
                    .sleep_deadline
                    .store(0, core::sync::atomic::Ordering::Relaxed);
                crate::sched::schedule(crate::sched::Requeue::IfRunnable);
            }
            return Err(SyscallError::Interrupted);
        }
    }

    // SAFETY: tcb is this CPU's running thread.
    match unsafe { crate::sched::sleep_list_add(tcb) }
    {
        Ok(()) | Err(crate::sched::SleepAddError::Cancelled) =>
        {
            // Cancelled: a stop or teardown cancelled the park between the
            // commit and the add, stamped it INTERRUPTED, and commits Stopped
            // or Exited; schedule() below deschedules the thread and the
            // resume takes that stamp.
        }
        Err(crate::sched::SleepAddError::Full) =>
        {
            // Sleep list at capacity: withdraw the park. sys_thread_sleep has
            // no IPC source to fall back on, so the honest answer is to
            // surface the failure (core/kernel/docs/thread-lifecycle-and-sleep.md
            // § Sleep List Invariants). The withdrawal is the claim a cancel makes,
            // sleep_list_remove under sched_lock, true while the deadline is
            // still pending: winning it means no stop or teardown claimed the
            // park, so restore Running and report OutOfMemory (a later stop
            // commits over the restored Running). Losing it means one did and
            // stamped the park INTERRUPTED; fall through to schedule() as the
            // Ok path does, and the resume consumes the stamp.
            // A won withdrawal leaves the thread Running with cs = 0 (the
            // commit_blocked above cleared context_saved), which is
            // intentional and benign: cs = 0 truthfully means "live registers
            // authoritative" for a still-`current`, never-switched-out thread,
            // no path dispatches a not-linked `current` thread cross-CPU, and
            // the next switch-out republishes cs = 1. Do NOT "restore" cs = 1
            // here.
            // SAFETY: tcb valid; SLEEP_LIST_LOCK is a leaf under sched_lock;
            // restoring before any schedule().
            let withdrawn = unsafe {
                let saved = (*tcb).sched_lock.lock_raw();
                let won = crate::sched::sleep_list_remove(tcb);
                if won && (*tcb).state == crate::sched::thread::ThreadState::Blocked
                {
                    (*tcb).state = crate::sched::thread::ThreadState::Running;
                }
                (*tcb).sched_lock.unlock_raw(saved);
                won
            };
            if withdrawn
            {
                return Err(SyscallError::OutOfMemory);
            }
        }
    }

    // SAFETY: called from syscall handler on valid kernel stack.
    unsafe {
        crate::sched::schedule(crate::sched::Requeue::IfRunnable);
    }

    // On resume, either timer_tick's sleep-list claim woke us (success) or a
    // cancellation claim (`cancel_ipc_block`'s `sleep_list_remove` returning
    // true) stamped the park INTERRUPTED.
    // SAFETY: tcb still valid after resume.
    if unsafe { crate::sched::thread::consume_park_interrupted(tcb) }
    {
        return Err(SyscallError::Interrupted);
    }
    Ok(0)
}

// ── SYS_THREAD_BIND_NOTIFICATION ─────────────────────────────────────────────

/// `SYS_THREAD_BIND_NOTIFICATION` (47): register a death-notification
/// observer on a thread.
///
/// arg0 = Thread cap slot (CONTROL right required).
/// arg1 = `EventQueue` cap slot (POST right required).
/// arg2 = caller-chosen `correlator: u64` (opaque routing tag; every bit kept).
///
/// When the target thread exits or faults, the kernel posts the two-word
/// entry `(exit_reason, correlator)` to the bound `EventQueue`: the exit
/// reason as the payload word, the correlator as the tag word.
///
/// Binding onto a thread that has *already* exited posts the retained
/// `exit_reason` to the `EventQueue` immediately. The bind serialises on the
/// thread's `sched_lock` against the death transition and the post-death
/// observer walk, so a death concurrent with the bind is delivered exactly
/// once and never dropped — letting a supervisor that binds after the thread
/// was started still observe a death in the bind-after-start window.
///
/// A binding holds a reference on the `EventQueue` object until the thread's
/// teardown releases it, so deleting the queue's last capability leaves the
/// queue live for the death post (core/kernel/docs/syscalls.md
/// § `SYS_THREAD_BIND_NOTIFICATION`). A bind onto an exited thread takes none.
///
/// Multiple independent observers may be registered (up to
/// `MAX_DEATH_OBSERVERS`); all fire on death. Returns `OutOfMemory` if the
/// per-thread observer array is full (only reachable while the thread is
/// still live — a bind onto an already-exited thread consumes no slot).
#[cfg(not(test))]
// cast_possible_truncation: cap handles are u32 by ABI contract; the
// truncation discards any upper bits a caller sets.
#[allow(clippy::cast_possible_truncation)]
fn sys_thread_bind_notification(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::{EqRights, ThreadRights};
    use crate::sched::thread::{DeathObserver, MAX_DEATH_OBSERVERS, ThreadState};

    let thread_cap_idx = tf.arg(0) as u32;
    let eq_cap_idx = tf.arg(1) as u32;
    let correlator = tf.arg(2);

    // SAFETY: current_tcb valid in syscall context.
    let caller = unsafe { current_tcb() };
    if caller.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller validated non-null.
    let cspace = unsafe { (*caller).cspace };

    // Look up the Thread cap (CONTROL right required).
    // SAFETY: cspace from current thread; lookup_cap validates index, tag, rights.
    let thread_slot = unsafe { lookup_cap(cspace, thread_cap_idx, ThreadRights::CONTROL) }?;

    // Extract target TCB from the Thread cap.
    // SAFETY: slot validated as Thread cap; header at offset 0.
    let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
    // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
    #[allow(clippy::cast_ptr_alignment)]
    let target_tcb = unsafe { (*obj.as_ptr().cast::<crate::cap::object::ThreadObject>()).tcb };

    // Look up the EventQueue cap (POST right required).
    // SAFETY: cspace from current thread; lookup_cap validates.
    let eq_slot = unsafe { lookup_cap(cspace, eq_cap_idx, EqRights::POST) }?;

    let eq_obj = eq_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0 of EventQueueObject; allocator guarantees alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let eq = eq_obj
        .as_ptr()
        .cast::<crate::cap::object::EventQueueObject>();

    // Serialise on the target thread's `sched_lock` against the death
    // transition (`set_state_under_all_locks`) and the post-death observer
    // snapshot (`post_death_notification`):
    //
    //   * Already `Exited`: the death walk ran without this observer. The
    //     thread's `exit_reason` was written in the same all-locks hold as
    //     the `Exited` commit (`exit_under_all_locks`), which includes this
    //     lock, so it is visible here; re-deliver it to the newly
    //     bound queue and do not append (the thread cannot die again). Closes
    //     the bind-after-death window for services bound after start (#106).
    //   * Not yet `Exited`: append the observer; the eventual death walk posts
    //     to it.
    //
    // Deliver outside the lock — `post_one_death_event` posts to the event
    // queue and may wake a receiver.
    // SAFETY: target_tcb is a valid TCB from a validated Thread cap; lock_raw
    // pairs with an unlock_raw on every path below.
    let saved = unsafe { (*target_tcb).sched_lock.lock_raw() };
    // SAFETY: state and exit_reason are plain TCB fields read under sched_lock.
    let (already_exited, retained_reason) = unsafe {
        (
            (*target_tcb).state == ThreadState::Exited,
            (*target_tcb).exit_reason,
        )
    };
    if already_exited
    {
        // SAFETY: paired with the lock_raw above.
        unsafe { (*target_tcb).sched_lock.unlock_raw(saved) };
        // SAFETY: eq is the EventQueueObject `eq_slot` pins for the call, so
        // it is live for the post; sched_lock is released.
        unsafe { crate::sched::post_one_death_event(eq, correlator, retained_reason) };
        return Ok(0);
    }
    // SAFETY: lock held; the append stays within MAX_DEATH_OBSERVERS. The
    // binding's reference is taken while `eq_slot` pins the queue; the
    // thread's teardown releases it (dealloc_object, Thread arm).
    let result = unsafe {
        let count = (*target_tcb).death_observer_count as usize;
        if count >= MAX_DEATH_OBSERVERS
        {
            Err(SyscallError::OutOfMemory)
        }
        else
        {
            (*eq).header.inc_ref();
            (*target_tcb).death_observers[count] = DeathObserver { eq, correlator };
            (*target_tcb).death_observer_count = (count + 1) as u8;
            Ok(0)
        }
    };
    // SAFETY: paired with the lock_raw above.
    unsafe { (*target_tcb).sched_lock.unlock_raw(saved) };
    result
}

/// `SYS_ASPACE_BIND_NOTIFICATION` (53): bind a terminal-fault death observer
/// to an address space.
///
/// arg0 = `AddressSpace` cap slot index (`CONTROL` right required).
/// arg1 = `EventQueue` cap slot index (`POST` right required).
/// arg2 = caller-chosen `correlator: u64` (opaque routing tag; every bit kept).
///
/// On a terminal fault by any thread in the address space (no handler bound,
/// the handler replied `KILL`, or the fault episode was cancelled by
/// destruction of the handler thread, by destruction of the handler endpoint
/// while the fault is still queued on it, or by a later receive on the
/// handler thread that passes its capability and headroom checks while the
/// fault reply is pending; a stop of the faulting thread defers the terminal
/// fault, cancelling the episode before any reply claims it or keeping a
/// claimed `KILL`, and it takes effect, and is posted, only if the thread is
/// started again; see docs/fault-handling.md § Delivery, Resume, and Kill),
/// the kernel posts the entry `(terminal-fault reason, correlator)` to each
/// bound observer. The kernel only notifies; it
/// never enumerates or terminates threads, and normal `thread_exit` does NOT
/// fire these observers.
///
/// A binding holds a reference on the `EventQueue` object until the address
/// space's teardown releases it (core/kernel/docs/syscalls.md
/// § `SYS_ASPACE_BIND_NOTIFICATION`); a bind after the fault takes none.
///
/// Binding onto an address space that has *already* terminal-faulted posts the
/// retained fault reason to the `EventQueue` immediately (serialised on the
/// space's `death_lock`), so an observer bound after the space was running does
/// not miss the fault. Returns `OutOfMemory` if the per-address-space observer
/// array is full (only reachable before the first fault).
#[cfg(not(test))]
// cast_possible_truncation: cap handles are u32 by ABI contract; the
// truncation discards any upper bits a caller sets.
#[allow(clippy::cast_possible_truncation)]
fn sys_aspace_bind_notification(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::{AsRights, EqRights};

    let aspace_cap_idx = tf.arg(0) as u32;
    let eq_cap_idx = tf.arg(1) as u32;
    let correlator = tf.arg(2);

    // SAFETY: current_tcb valid in syscall context.
    let caller = unsafe { current_tcb() };
    if caller.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: caller validated non-null.
    let cspace = unsafe { (*caller).cspace };

    // Look up the AddressSpace cap (CONTROL right required).
    // SAFETY: cspace from current thread; lookup_cap validates index, tag, rights.
    let aspace_slot = unsafe { lookup_cap(cspace, aspace_cap_idx, AsRights::CONTROL) }?;

    // Extract the inner AddressSpace from the AddressSpace cap.
    // SAFETY: slot validated as AddressSpace cap; header at offset 0.
    let aspace_obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: the header pointer names an AddressSpaceObject
    // constructed in place at the start of its page-aligned wrapper page, so
    // the cast target's 8-byte alignment holds.
    // SAFETY: tag confirmed AddressSpace; pointer is valid AddressSpaceObject.
    #[allow(clippy::cast_ptr_alignment)]
    let as_ptr = unsafe {
        (*aspace_obj
            .as_ptr()
            .cast::<crate::cap::object::AddressSpaceObject>())
        .address_space
    };
    if as_ptr.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // Look up the EventQueue cap (POST right required).
    // SAFETY: cspace from current thread; lookup_cap validates.
    let eq_slot = unsafe { lookup_cap(cspace, eq_cap_idx, EqRights::POST) }?;

    let eq_obj = eq_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0 of EventQueueObject; allocator guarantees alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let eq = eq_obj
        .as_ptr()
        .cast::<crate::cap::object::EventQueueObject>();

    // Bind the observer, or — if the address space already terminal-faulted —
    // deliver the retained reason to the new queue immediately.
    // `bind_or_retained` serialises on the space's `death_lock` against the
    // terminal-fault post, so a fault before this bind is not lost (the
    // address-space analogue of the thread bind-after-death path above).
    //
    // SAFETY: as_ptr is a valid AddressSpace from a validated AddressSpace cap;
    // eq is the EventQueueObject `eq_slot` pins for the call.
    match unsafe {
        crate::mm::address_space::AddressSpace::bind_or_retained(as_ptr, eq, correlator)
    }
    {
        Ok(None) => Ok(0),
        Ok(Some(reason)) =>
        {
            // SAFETY: eq is the EventQueueObject `eq_slot` pins for the call;
            // death_lock is released.
            unsafe { crate::sched::post_one_death_event(eq, correlator, reason) };
            Ok(0)
        }
        Err(()) => Err(SyscallError::OutOfMemory),
    }
}

// ── Scheduler / IPC helpers ───────────────────────────────────────────────────

/// Get the current thread's TCB pointer for the executing CPU.
///
/// # Safety
/// Must be called from a kernel context. The current CPU's scheduler must have
/// been initialised by `sched::init`.
#[cfg(not(test))]
pub(crate) unsafe fn current_tcb() -> *mut crate::sched::thread::ThreadControlBlock
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: SCHEDULERS[cpu] is initialised for all online CPUs; per-CPU data indexed by CPU ID.
    unsafe { crate::sched::scheduler_for(cpu).current() }
}

/// A capability resolved from a user handle, with the object it names pinned
/// for as long as the value lives.
///
/// [`pin_slot`] reads the slot's tag, generation, rights, badge, and object
/// under the slot's `CSpace` lock and takes a reference on the object inside
/// that hold. Every path that frees an occupied slot clears it under the same
/// lock before it releases the reference the slot held (the pin invariant of
/// core/kernel/docs/capability-internals.md § Kernel Object Reference
/// Counting), so a slot still occupied under the lock names an object whose
/// count is not zero, and the increment cannot revive a freed object. The
/// reference is a kernel-internal owner: neither a concurrent delete of the
/// last capability nor a revoke of an ancestor by another holder can free the
/// object while the handler uses it.
///
/// Dropping the value releases the reference
/// ([`release_ref`](crate::cap::object::release_ref)); when it was the last,
/// the object is freed from the dropping context. A `PinnedCap` MUST
/// therefore be dropped with no lock held, and before the thread parks: a
/// thread killed while parked never runs its destructor, so a pin held across
/// a park would keep the object alive for good. Blocking handlers drop it
/// after their park commit and source unlock, before `schedule()`, and a loop
/// that parks re-resolves its handle afterwards (the pin-before-park rule of
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy).
///
/// The fields are a snapshot: the slot itself may be freed or recycled while
/// the value lives; only the object is pinned.
#[cfg(not(test))]
#[must_use]
pub(crate) struct PinnedCap
{
    /// The slot's tag at resolution (never `Null`).
    pub tag: crate::cap::slot::CapTag,
    /// The slot's rights at resolution.
    pub rights: crate::cap::slot::Rights,
    /// The slot's badge at resolution.
    pub badge: u64,
    /// The object the slot named at resolution, pinned while `self` lives.
    pub object: Option<core::ptr::NonNull<crate::cap::object::KernelObjectHeader>>,
}

#[cfg(not(test))]
impl Drop for PinnedCap
{
    fn drop(&mut self)
    {
        if let Some(obj) = self.object
        {
            // SAFETY: `pin_slot` took this reference and nothing else
            // releases it; the type's contract has its holder drop it in
            // syscall context with interrupts disabled and no lock held, the
            // preconditions `release_ref` states.
            unsafe { crate::cap::object::release_ref(obj) };
        }
    }
}

/// Resolve `handle` in `cspace` to an occupied slot of any tag and pin the
/// object it names (see [`PinnedCap`]).
///
/// `handle` is the encoded value userspace passes: slot index in the low
/// [`syscall::CAP_INDEX_BITS`] bits, per-slot generation in the high bits.
/// Handlers that accept several tags (`SYS_CAP_INFO`, `SYS_WAIT_SET_ADD`'s
/// source) check the tag and rights themselves, as do copy, derive, and
/// derive-badge for their source; every other handler resolves through
/// [`lookup_cap`].
///
/// # Errors
/// [`SyscallError::InvalidCapability`] for a null `cspace`, a missing or
/// `Null` slot, or a generation mismatch (a stale handle to a recycled
/// slot, #349).
///
/// # Safety
/// `cspace` must be null or the `CSpace` bound to the calling (running)
/// thread, and the caller must be in syscall context with interrupts disabled
/// and hold no lock: the `CSpace` lock is taken here. A bound `CSpace`
/// outlives the call, because its refcount-0 teardown first stops every bound
/// thread and waits until it is off every CPU (`sched::stop_threads_bound_to`).
#[cfg(not(test))]
pub(crate) unsafe fn pin_slot(
    cspace: *mut crate::cap::cspace::CSpace,
    handle: u32,
) -> Result<PinnedCap, SyscallError>
{
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    let index = syscall::cap_handle_index(handle);
    // SAFETY: cspace is the running thread's bound CSpace (contract), live for
    // the call. Its lock serialises slot occupancy, and every slot free clears
    // the slot under it before releasing the slot's reference, so an occupied
    // slot read here names an object whose count is at least one, and the
    // inc_ref below lands before any release can reach zero. lock_raw and
    // unlock_raw are paired.
    let snapshot = unsafe {
        let saved = (*cspace).lock.lock_raw();
        let snapshot = (*cspace).slot(index).and_then(|slot| {
            (slot.tag != crate::cap::slot::CapTag::Null
                && slot.generation() == syscall::cap_handle_gen(handle))
            .then_some((slot.tag, slot.rights, slot.badge, slot.object))
        });
        if let Some((_, _, _, Some(obj))) = snapshot
        {
            obj.as_ref().inc_ref();
        }
        (*cspace).lock.unlock_raw(saved);
        snapshot
    };
    let (tag, rights, badge, object) = snapshot.ok_or(SyscallError::InvalidCapability)?;
    Ok(PinnedCap {
        tag,
        rights,
        badge,
        object,
    })
}

/// Resolve `handle` to a capability of the type `required_rights` names,
/// holding those rights, and pin the object it names (see [`PinnedCap`]).
///
/// This is the chokepoint for resolving a user-supplied handle of one
/// expected type; [`pin_slot`] serves the multi-tag handlers and the
/// copy and derive sources, and the capability-tree handlers that act on a
/// slot under the derivation lock decode and generation-check the handle
/// themselves (see core/kernel/docs/capability-internals.md § Per-Slot
/// Generation).
///
/// The expected slot tag is fixed by the required-rights argument's type:
/// `required_rights: TypedRights<K>` selects `K::TAG`, so a rights constant of
/// the wrong capability type cannot compile. Presence-only lookups pass the
/// type's `NONE` (e.g. `SchedRights::NONE`).
///
/// # Errors
/// - Null cspace pointer, missing or `Null` slot, or a generation mismatch
///   (a stale handle to a recycled slot, #349) →
///   [`SyscallError::InvalidCapability`].
/// - Tag mismatch → [`SyscallError::InvalidCapability`].
/// - Insufficient rights → [`SyscallError::InsufficientRights`].
///
/// Both checks read the snapshot taken under the `CSpace` lock, so a slot
/// being cleared concurrently answers `InvalidCapability`, never a rights
/// refusal read from a half-cleared slot.
///
/// # Safety
/// As for [`pin_slot`]; the returned [`PinnedCap`] carries the drop rules.
#[cfg(not(test))]
pub(crate) unsafe fn lookup_cap<K: crate::cap::slot::CapKind>(
    cspace: *mut crate::cap::cspace::CSpace,
    handle: u32,
    required_rights: crate::cap::slot::TypedRights<K>,
) -> Result<PinnedCap, SyscallError>
{
    // SAFETY: forwarded caller contract.
    let pinned = unsafe { pin_slot(cspace, handle) }?;
    if pinned.tag != K::TAG
    {
        return Err(SyscallError::InvalidCapability);
    }
    if !pinned.rights.contains(required_rights.erase())
    {
        return Err(SyscallError::InsufficientRights);
    }
    Ok(pinned)
}

// ── IPC buffer ────────────────────────────────────────────────────────────────

/// `SYS_IPC_BUFFER_SET` (42): register (or clear) the per-thread IPC buffer page.
///
/// arg0 = virtual address of the IPC buffer page (0 = deregister; otherwise
/// must be 4 KiB-aligned).
#[cfg(not(test))]
fn sys_ipc_buffer_set(tf: UserFrame) -> Result<u64, SyscallError>
{
    let virt = tf.arg(0);
    // A non-zero buffer must be page-aligned AND in the user half. Without the
    // user-half check a page-aligned kernel or non-canonical VA would be stored
    // and later copied by the IPC fast paths; SMAP/SUM do not gate kernel-half
    // pages, so it must be rejected here rather than relying on copy-fault
    // recovery (which only catches user-page faults).
    // Addresses at or above the user-half top are kernel/non-canonical.
    if virt != 0 && ((virt & 0xFFF) != 0 || virt >= crate::mm::user_va_top())
    {
        return Err(SyscallError::InvalidAddress);
    }
    // SAFETY: current_tcb() is valid from a syscall context.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb is a valid TCB.
    unsafe {
        (*tcb).ipc_buffer = virt;
    }
    Ok(0)
}

// Host unit tests for the exit-code encoding (`syscall::encode_exit_code`)
// that `sys_process_exit` applies to the caller's exit code.
#[cfg(test)]
mod exit_code_tests
{
    use syscall::{EXIT_FAULT_BASE, EXIT_VOLUNTARY, encode_exit_code};

    #[test]
    fn zero_is_voluntary_success()
    {
        assert_eq!(encode_exit_code(0), EXIT_VOLUNTARY);
    }

    #[test]
    fn small_codes_roundtrip_below_fault_base()
    {
        for code in [1u32, 2, 42, 255, 0x0FFE, 0x0FFF]
        {
            assert_eq!(encode_exit_code(code), u64::from(code));
            assert!(encode_exit_code(code) < EXIT_FAULT_BASE);
        }
    }

    #[test]
    fn large_codes_saturate_and_never_alias()
    {
        // Saturates to the top of the voluntary range: never reaches the fault
        // range, and never aliases success (0).
        assert_eq!(encode_exit_code(0x1000), EXIT_FAULT_BASE - 1);
        assert_eq!(encode_exit_code(u32::MAX), EXIT_FAULT_BASE - 1);
        assert_ne!(encode_exit_code(u32::MAX), EXIT_VOLUNTARY);
        assert!(encode_exit_code(u32::MAX) < EXIT_FAULT_BASE);
    }
}
