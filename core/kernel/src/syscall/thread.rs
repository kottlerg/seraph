// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/thread.rs

//! Thread lifecycle syscall handlers.
//!
//! # Adding new thread syscalls
//! 1. Add a `pub fn sys_thread_*` here.
//! 2. Add the syscall constant import to `syscall/mod.rs`.
//! 3. Add a dispatch arm to `syscall/mod.rs`.
//! 4. Add a userspace wrapper to `shared/syscall/src/lib.rs`.

// cast_possible_truncation: u64→u32/usize casts extract cap indices and field values
// from 64-bit trap frame args. Seraph is 64-bit only; all values fit in the target type.
#![allow(clippy::cast_possible_truncation)]

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
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_configure(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTrapFrame;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;

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

    // Thread must be in Created state to configure.
    // SAFETY: target_tcb validated non-null; state field always valid.
    if unsafe { (*target_tcb).state } != ThreadState::Created
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: target_tcb validated non-null; kernel_stack_top set at creation.
    let kstack_top = unsafe { (*target_tcb).kernel_stack_top };

    // Build the initial TrapFrame on the thread's kernel stack, just below
    // the stack top. This mirrors the setup in `sched::enter()`.
    let tf_size = size_of::<ArchTrapFrame>() as u64;
    let tf_ptr = (kstack_top - tf_size) as *mut ArchTrapFrame;

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
        (*target_tcb).trap_frame = tf_ptr;
    }

    // The first scheduler switch into this thread pulls `SavedState.fs_base`
    // from the TCB directly into `IA32_FS_BASE` (x86-64). Seed it from the
    // caller-supplied value; no-op on architectures that carry TLS state in
    // the trap frame (RISC-V uses `tp` there).
    // SAFETY: target_tcb validated non-null; saved_state has no interior
    // mutability and is exclusively owned by this thread in Created state.
    unsafe {
        crate::arch::current::context::seed_tls_base(&mut (*target_tcb).saved_state, tls_base);
    }

    Ok(0)
}

/// `SYS_THREAD_START` (19): move a configured thread from Created to Ready.
///
/// arg0 = Thread cap index (must have CONTROL).
///
/// The thread must have been configured via `SYS_THREAD_CONFIGURE` first
/// (`trap_frame` must be non-null). Enqueues the thread on the BSP scheduler.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_start(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;

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
        if (*target_tcb).trap_frame.is_null()
        {
            return Err(SyscallError::InvalidArgument);
        }

        // A thread stopped while Running may still be `current` and physically
        // executing on a remote CPU (a SYS_THREAD_STOP drain and this resume can
        // race). Force-linking it via enqueue_ready_thread while it is still live
        // there would dispatch it on a second CPU — the cross-CPU double-dispatch
        // behind #314/#293. Drain it off every CPU's `current` (and wait for its
        // register save to publish) BEFORE committing Ready: while it is still
        // Stopped/Created the owning CPU's schedule() requeue denylist drops it
        // without re-linking, so the drain leaves it not-`current` and (for a
        // single start) unlinked. The same barrier dealloc_object(Thread) (#207)
        // and sys_thread_stop use. A Created (never-dispatched) thread is
        // `current` nowhere, so first-start returns from the drain immediately.
        crate::sched::await_descheduled(target_tcb);
        // All-CPU lock commit closes the cross-CPU dealloc race; see
        // docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine. The
        // target is now not-`current` and unlinked, so the force-link below
        // establishes enqueue_ready_thread's not-live precondition.
        crate::sched::set_state_under_all_locks(target_tcb, ThreadState::Ready);
        // Route to correct CPU based on affinity. The thread is already Ready
        // (committed above), so use enqueue_ready_thread to link it: the gated
        // enqueue_and_wake would coalesce an already-Ready thread and drop it.
        let target_cpu = crate::sched::select_target_cpu(target_tcb);
        crate::sched::enqueue_ready_thread(target_tcb, target_cpu);
    }

    Ok(0)
}

/// `SYS_THREAD_STOP` (20): transition a thread to the Stopped state.
///
/// arg0 = Thread cap index (must have CONTROL).
///
/// Cancels any pending IPC block (the stopped thread's blocked syscall returns
/// `Interrupted`). If the thread is already Stopped or Exited, returns
/// `InvalidState`. A thread may stop itself (arg0 refers to the calling thread).
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_stop(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;

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
        let state = (*target_tcb).state;

        match state
        {
            ThreadState::Created | ThreadState::Exited | ThreadState::Stopped =>
            {
                return Err(SyscallError::InvalidState);
            }

            ThreadState::Blocked =>
            {
                // Cancel the IPC block: unlink the thread from whatever it is
                // blocked on and set its trap-frame return to Interrupted.
                cancel_ipc_block(target_tcb);
            }

            ThreadState::Ready | ThreadState::Running =>
            {
                // No source-side cleanup; the all-locks Stopped write
                // below + the scheduler skip-loop + the cross-CPU IPI
                // (Running case) drain the target.
            }
        }

        // See docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine
        // (sys_thread_stop rows).
        let running_on = crate::sched::set_state_under_all_locks(target_tcb, ThreadState::Stopped);

        // If stopping self (Running → Stopped): yield so another thread runs.
        if core::ptr::eq(target_tcb, caller_tcb)
        {
            crate::sched::schedule(false);
        }
        else if let Some(run_cpu) = running_on
        {
            // Cross-CPU drain: IPI forces the remote into schedule() so
            // sys_thread_read_regs sees a fresh trap_frame.
            let current_cpu = crate::arch::current::cpu::current_cpu() as usize;
            if run_cpu != current_cpu
            {
                // SAFETY: run_cpu < CPU_COUNT.
                crate::sched::prod_remote_cpu(run_cpu);

                let sched_remote = crate::sched::scheduler_for(run_cpu);
                let spin_start = crate::arch::current::timer::current_tick();
                let mut warned = false;
                // The drain spins until the remote CPU deschedules `target_tcb`.
                // This syscall runs with IF=0; spinning at IF=0 would block an
                // inbound TLB-shootdown IPI targeted at this CPU and deadlock it
                // (the initiator spins for our ACK with IF enabled). Enable
                // interrupts across the spin and disable preemption so the
                // scheduler cannot migrate us mid-drain — the #207 pattern
                // dealloc's UAF gate uses.
                crate::percpu::preempt_disable();
                // SAFETY: ring 0; restored after the spin below.
                let drain_saved_int = crate::arch::current::cpu::save_and_disable_interrupts();
                // SAFETY: ring 0; IDT loaded; preempt disabled.
                crate::arch::current::interrupts::enable();
                while {
                    let s = sched_remote.lock.lock_raw();
                    let still_current = sched_remote.current == target_tcb;
                    // A concurrent sys_thread_start may resume the target out of
                    // Stopped (last-writer-wins). The bounded-spin invariant
                    // assumes the target stays in schedule()'s requeue denylist
                    // (Stopped); once it is no longer Stopped the stop was
                    // overtaken and the re-dispatched target may never
                    // deschedule. Read state under the same lock
                    // set_state_under_all_locks holds, then bail.
                    let still_stopped = (*target_tcb).state == ThreadState::Stopped;
                    sched_remote.lock.unlock_raw(s);
                    still_current && still_stopped
                }
                {
                    // Single-shot diagnostic at >100 ms.
                    if !warned
                    {
                        let now = crate::arch::current::timer::current_tick();
                        let tps = crate::arch::current::timer::ticks_per_second();
                        if tps != 0 && now.saturating_sub(spin_start) > tps / 10
                        {
                            warned = true;
                            // SAFETY: target_tcb validated above; cur read racily for diagnostic.
                            #[allow(unused_unsafe)]
                            unsafe {
                                let tid = (*target_tcb).thread_id;
                                let st = (*target_tcb).state;
                                let cur = sched_remote.current;
                                let cur_tid = if cur.is_null() { 0 } else { (*cur).thread_id };
                                crate::kprintln!(
                                    "kernel: sys_thread_stop spin >100ms target_tid={} \
                                     state={:?} run_cpu={} cur_tid={}",
                                    tid,
                                    st,
                                    run_cpu,
                                    cur_tid
                                );
                            }
                        }
                    }
                    core::hint::spin_loop();
                }
                // SAFETY: drain_saved_int from save_and_disable_interrupts above.
                crate::arch::current::cpu::restore_interrupts(drain_saved_int);
                crate::percpu::preempt_enable();
            }
        }
    }

    Ok(0)
}

/// Cancel the IPC block on a thread that is in `Blocked` state.
///
/// Unlinks the thread from the relevant IPC queue and sets its trap-frame
/// return value to `Interrupted` so the halted syscall returns that error.
///
/// # Safety
/// `tcb` must be a valid TCB. The caller MUST NOT hold the target's `sched_lock`
/// or any per-CPU scheduler lock: this function acquires `tcb.sched_lock` itself
/// for the binding read-and-clear, and per-source IPC locks for the unlink (lock
/// order: source IPC → `sched_lock`, so the two are never held together).
// too_many_lines: flat dispatch over every `IpcThreadState` variant; splitting
// adds no clarity (each arm is independent and short).
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
unsafe fn cancel_ipc_block(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::ipc::endpoint::{EndpointState, unlink_from_wait_queue};
    use crate::ipc::event_queue::EventQueueState;
    use crate::ipc::notification::NotificationState;
    use crate::ipc::wait_set::WaitSetState;
    use crate::sched::thread::IpcThreadState;
    use syscall::SyscallError;

    // Snapshot (state, ipc_state, blocked_on_object) under the per-TCB sched_lock
    // — the authoritative serializer for the Scheduling field group. Reading the
    // pair without it would race enqueue_and_wake / commit_blocked (which write
    // these under sched_lock) and could observe a torn binding. If a concurrent
    // waker already moved the thread off Blocked, its wake stands: there is
    // nothing to cancel, so return without touching the source or the trap frame.
    // sched_lock is released before any per-source IPC lock is taken below (lock
    // order is source IPC → sched_lock, so the two are never held together).
    // SAFETY: tcb validated by caller; fields read/written under sched_lock.
    let (ipc_state, blocked_on) = unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        let snap = ((*tcb).ipc_state, (*tcb).blocked_on_object);
        let blocked = (*tcb).state == crate::sched::thread::ThreadState::Blocked;
        (*tcb).sched_lock.unlock_raw(saved);
        if !blocked
        {
            return;
        }
        snap
    };

    // Each branch takes only the source IPC lock matching `ipc_state` (the
    // sched_lock snapshot above is already released; lock order source IPC →
    // sched_lock means the two are never nested) and unlinks this thread from the
    // source's waiter / queue, racing any concurrent waker for the binding under
    // that same source lock. See docs/scheduling-internals.md § Lock Hierarchy.
    match ipc_state
    {
        IpcThreadState::BlockedOnSend =>
        {
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = blocked_on.cast::<EndpointState>();
                // SAFETY: blocked_on is a valid EndpointState ptr.
                unsafe {
                    let saved = (*ep).lock.lock_raw();
                    unlink_from_wait_queue(tcb, &mut (*ep).send_head, &mut (*ep).send_tail);
                    // Republish send-queue level after the unlink (#285-adjacent).
                    (*ep).refresh_send_ready();
                    (*ep).lock.unlock_raw(saved);
                }
            }
            // A fault sender (queued for delivery) cancelled mid-fault must kill,
            // not resume, when next scheduled: its resume runs the fault helper,
            // which has no syscall to return `Interrupted` to. No reply can be
            // in flight for a send-queued faulter, so the marker is unconditional.
            // SAFETY: tcb valid; fault_outcome / in_fault_delivery always valid.
            if unsafe { (*tcb).in_fault_delivery }
            {
                // SAFETY: tcb valid.
                unsafe {
                    (*tcb).fault_outcome.store(
                        crate::ipc::fault::FAULT_OUTCOME_KILL,
                        core::sync::atomic::Ordering::Release,
                    );
                }
            }
        }

        IpcThreadState::BlockedOnRecv =>
        {
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = blocked_on.cast::<EndpointState>();
                // SAFETY: blocked_on is a valid EndpointState ptr.
                unsafe {
                    let saved = (*ep).lock.lock_raw();
                    unlink_from_wait_queue(tcb, &mut (*ep).recv_head, &mut (*ep).recv_tail);
                    (*ep).lock.unlock_raw(saved);
                }
            }
        }

        IpcThreadState::BlockedOnReply =>
        {
            // blocked_on is the server TCB. The reply_tcb CAS dereferences the
            // server, which a concurrent dealloc(server) could free (#317). Guard
            // it: hold THIS client's sched_lock across a `blocked_on_object` re-read
            // and the CAS. dealloc(server) nulls a claimed client's blocked_on under
            // that same client sched_lock strictly before retype_free, so observing
            // `blocked_on == server` under the lock proves the server is not yet
            // freed (CLOSURE LEMMA — docs/scheduling-internals.md § Cross-CPU TCB
            // Ownership). A Blocked client's blocked_on can only transition
            // server→null (a waker), never server→server2, so the re-read suffices.
            // Only this client's sched_lock is held; the reply_tcb CAS on the server
            // is wait-free, so the "one TCB sched_lock at a time" rule holds.
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let server = blocked_on.cast::<crate::sched::thread::ThreadControlBlock>();
                // SAFETY: tcb valid; sched_lock paired with unlock below. server is
                // pinned alive for the CAS by the blocked_on re-read under this lock.
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
                        // never fire (#160).
                        if cancelled
                        {
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
                // SAFETY: tcb valid; sched_lock paired with unlock. server is pinned
                // alive for the CAS by the blocked_on re-read under this lock (#317,
                // CLOSURE LEMMA — mirrors the BlockedOnReply arm above).
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
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let sig = blocked_on.cast::<NotificationState>();
                // SAFETY: blocked_on is a valid NotificationState ptr.
                unsafe {
                    let saved = (*sig).lock.lock_raw();
                    if core::ptr::eq((*sig).waiter, tcb)
                    {
                        (*sig).waiter = core::ptr::null_mut();
                    }
                    (*sig).lock.unlock_raw(saved);
                }
            }
        }

        IpcThreadState::BlockedOnEventQueue =>
        {
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let eq = blocked_on.cast::<EventQueueState>();
                // SAFETY: blocked_on is a valid EventQueueState ptr.
                unsafe {
                    let saved = (*eq).lock.lock_raw();
                    if core::ptr::eq((*eq).waiter, tcb)
                    {
                        (*eq).waiter = core::ptr::null_mut();
                    }
                    (*eq).lock.unlock_raw(saved);
                }
            }
        }

        IpcThreadState::BlockedOnWaitSet =>
        {
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let ws = blocked_on.cast::<WaitSetState>();
                // SAFETY: blocked_on is a valid WaitSetState ptr.
                unsafe {
                    let saved = (*ws).lock.lock_raw();
                    if core::ptr::eq((*ws).waiter, tcb)
                    {
                        (*ws).waiter = core::ptr::null_mut();
                    }
                    (*ws).lock.unlock_raw(saved);
                }
            }
        }

        IpcThreadState::None =>
        {}
    }

    // If the thread was parked with a timeout (notification-wait or event-recv
    // with `timeout_ms != 0`), it is also on the global sleep list. Drop
    // the entry now so a later timer tick does not dereference a freed TCB.
    //
    // ORDER (issue #117): call `sleep_list_remove` BEFORE clearing
    // `sleep_deadline`. The timer path (`sleep_check_wakeups`) treats
    // `sleep_deadline <= now` as expired; clearing the deadline first
    // would let the timer claim a wake that this cancel path is delivering.
    // SAFETY: tcb is valid; sleep_list_remove is safe to call when the
    // thread is not registered (returns without effect).
    unsafe {
        if (*tcb).sleep_deadline != 0
        {
            crate::sched::sleep_list_remove(tcb);
            (*tcb).sleep_deadline = 0;
        }
    }

    // Clear the binding under sched_lock, but only if the thread is still Blocked
    // on the same object we cancelled: a waker that won the source-lock race above
    // may have already woken (and possibly re-bound) it, in which case
    // enqueue_and_wake already cleared these fields and we must not clobber a
    // fresh binding.
    // SAFETY: tcb is valid; fields written under sched_lock.
    unsafe {
        let saved = (*tcb).sched_lock.lock_raw();
        if (*tcb).state == crate::sched::thread::ThreadState::Blocked
            && (*tcb).ipc_state == ipc_state
        {
            (*tcb).ipc_state = IpcThreadState::None;
            (*tcb).blocked_on_object = core::ptr::null_mut();
        }
        (*tcb).sched_lock.unlock_raw(saved);
    }

    // Write Interrupted into the stopped thread's trap-frame return slot so
    // when the thread eventually resumes its original blocking syscall returns
    // this error code.
    // SAFETY: trap_frame is set for all user threads that have been configured.
    unsafe {
        let trap_frame = (*tcb).trap_frame;
        if !trap_frame.is_null()
        {
            (*trap_frame).set_return(SyscallError::Interrupted as i64);
        }
    }
}

/// `SYS_THREAD_SET_FAULT_HANDLER` (32): bind or clear a thread's fault-handler
/// endpoint.
///
/// arg0 = Thread cap index (must have CONTROL) — the thread whose handler is set.
/// arg1 = Endpoint cap index, or `0` to **unbind**.
/// arg2 = `badge` delivered in the fault message identifying the faulting thread.
/// arg3 = `fault_class_mask`; v1 accepts only [`syscall::FAULT_CLASS_ALL`].
///
/// Binding takes a reference on the endpoint object for the binding's lifetime
/// (see `docs/fault-handling.md` § Liveness); rebinding / unbinding / thread
/// destruction releases it. Binding requires only a valid `Endpoint` cap —
/// `CONTROL` on the thread is the authority; the endpoint cap merely names where
/// this thread's kernel-unresolvable faults are delivered.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_set_fault_handler(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{EndpointObject, KernelObjectHeader, ThreadObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::syscall::current_tcb;
    use core::sync::atomic::Ordering;

    let thread_idx = tf.arg(0) as u32;
    let endpoint_idx = tf.arg(1) as u32;
    let badge = tf.arg(2);
    let fault_class_mask = tf.arg(3);

    // v1 supports only the all-classes mask; the argument reserves the encoding
    // for future per-class handlers without a new syscall.
    if fault_class_mask != syscall::FAULT_CLASS_ALL
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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;
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

    // Resolve the new handler object (index 0 = unbind).
    let new_ep: *mut EndpointObject = if endpoint_idx == 0
    {
        core::ptr::null_mut()
    }
    else
    {
        // SAFETY: caller_cspace validated; no specific endpoint right required.
        let ep_slot = unsafe {
            super::lookup_cap(caller_cspace, endpoint_idx, CapTag::Endpoint, Rights::NONE)
        }?;
        let obj = ep_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0 of EndpointObject; allocator guarantees alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let p = obj.as_ptr().cast::<EndpointObject>();
        p
    };

    // Take the new binding's reference before publishing it, so the object
    // cannot be freed between publish and a faulter's load.
    if !new_ep.is_null()
    {
        // SAFETY: new_ep is a live EndpointObject (its cap slot holds a ref).
        unsafe { (*new_ep).header.inc_ref() };
    }

    // Publish the badge first, then atomically swap the handler pointer, so a
    // faulter that observes the new handler also observes the matching badge.
    // SAFETY: target_tcb is kept alive by the caller's Thread cap reference;
    // both fields are atomics safe to write cross-thread.
    let old_ep = unsafe {
        (*target_tcb).fault_badge.store(badge, Ordering::Release);
        (*target_tcb).fault_handler.swap(new_ep, Ordering::AcqRel)
    };

    // Release the previous binding's reference, freeing the object if this was
    // its last reference (mirrors cap_delete's dec-ref-then-dealloc, outside any
    // lock since dealloc_object may take inner locks). Rebinding to the same
    // endpoint nets to a no-op (the inc above balances this dec).
    if !old_ep.is_null()
    {
        // SAFETY: old_ep was a live EndpointObject referenced by this binding.
        let remaining = unsafe { (*old_ep).header.dec_ref() };
        if remaining == 0
        {
            // SAFETY: refcount reached 0; old_ep header is at offset 0.
            unsafe {
                crate::cap::object::dealloc_object(core::ptr::NonNull::new_unchecked(
                    old_ep.cast::<KernelObjectHeader>(),
                ));
            }
        }
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
pub fn sys_thread_set_priority(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{SchedControlObject, ThreadObject};
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;
    use syscall::PRIORITY_MAX;

    let thread_idx = tf.arg(0) as u32;
    let priority = tf.arg(1) as u8;
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
    let sched_slot =
        unsafe { super::lookup_cap(caller_cspace, sched_idx, CapTag::SchedControl, Rights::NONE) }?;
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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;

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

    // `priority`, `state`, and `queued_on` are in the Scheduling field group,
    // whose authoritative serializer is the per-TCB `sched_lock`
    // (docs/scheduling-internals.md § Cross-CPU TCB Ownership). Acquire it FIRST
    // (outermost), then every CPU's run-queue lock in ascending order — the same
    // shape as `dealloc_object(Thread)` and `set_state_under_all_locks`. Without
    // `sched_lock` this `state` read and the `remove_from_queue` / `enqueue`
    // below race `enqueue_and_wake` / `commit_blocked` / `schedule`, which write
    // those fields under `sched_lock` — an unserialized Scheduling-group writer
    // the per-TCB-lock redesign (STEP 5) converted everywhere else but here.
    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;

    // SAFETY: target_tcb validated non-null; lock_raw paired with the unlock_raw
    // after the all-CPU-locks release below (released last, restoring caller IF).
    let tcb_sched_saved = unsafe { (*target_tcb).sched_lock.lock_raw() };

    // Ascending order matches the lock hierarchy rule. Each CPU's saved
    // interrupt-flag word is stashed in its own scheduler (under that lock).
    for cpu in 0..cpu_count
    {
        // SAFETY: cpu < cpu_count; scheduler slab initialised by `sched::init`.
        unsafe {
            let s = crate::sched::scheduler_for(cpu);
            s.saved_lock_flags = s.lock.lock_raw();
        }
    }

    // SAFETY: target_tcb validated non-null. `sched_lock` (held, outermost)
    // serializes the `state` read and the `queued_on` mutation against every
    // other Scheduling-group writer; the all-CPU run-queue locks (held) cover
    // the intrusive remove/enqueue list structure.
    unsafe {
        let old_prio = (*target_tcb).priority;
        let state = (*target_tcb).state;
        (*target_tcb).priority = priority;

        if state == ThreadState::Ready && old_prio != priority
        {
            // A Ready TCB is normally linked on exactly one CPU's run queue.
            // Locate that scheduler by trying `remove_from_queue` on each
            // one; the succeeding remove identifies the home, and we
            // re-enqueue there at the new priority. If no scheduler reports
            // `true` the TCB is in the transient Ready-and-unlinked window
            // of `schedule()`'s cross-CPU outgoing branch
            // (`sched/mod.rs` cross_cpu re-enqueue): `state` was set to
            // `Ready` under the local sched.lock, that lock was released,
            // and the in-flight `enqueue_and_wake` on the destination
            // scheduler has not yet acquired its target lock. That
            // `enqueue_and_wake` re-reads `(*tcb).priority` under the
            // target lock, so the write we just committed is picked up
            // there and the queue link lands at the new priority. No
            // action is needed in that case.
            #[allow(clippy::needless_range_loop)]
            for cpu in 0..cpu_count
            {
                let sched = crate::sched::scheduler_for(cpu);
                if sched.remove_from_queue(target_tcb, old_prio)
                {
                    sched.enqueue(target_tcb, priority);
                    break;
                }
            }
        }
    }

    for cpu in (0..cpu_count).rev()
    {
        // SAFETY: `lock_raw` above paired with this unlock; same CPU index.
        unsafe {
            let s = crate::sched::scheduler_for(cpu);
            s.lock.unlock_raw(s.saved_lock_flags);
        }
    }

    // Release `sched_lock` LAST (first-acquired → last-released), restoring the
    // caller's interrupt state.
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
/// Returns `slot1 | (slot2 << 32)` on success.
#[cfg(not(test))]
pub fn sys_sched_split(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::{KernelObjectHeader, ObjectType, SchedControlObject, dealloc_object};
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::seed_header_nn;
    use crate::cap::slot::{CapTag, Rights};
    use crate::cap::split::install_split_children;
    use crate::syscall::current_tcb;

    let sched_idx = tf.arg(0) as u32;
    let split_at = tf.arg(1) as u8;
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

    let (min, max, rights, cspace_id, orig_obj_ptr) = {
        // SAFETY: caller_cspace validated; lookup_cap checks the tag (presence-only).
        let slot = unsafe {
            super::lookup_cap(caller_cspace, sched_idx, CapTag::SchedControl, Rights::NONE)
        }?;
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?;
        // cast_ptr_alignment: header at offset 0; allocator guarantees alignment.
        // SAFETY: tag confirmed SchedControl; pointer is a valid SchedControlObject.
        #[allow(clippy::cast_ptr_alignment)]
        let sc = unsafe { &*(obj_ptr.as_ptr().cast::<SchedControlObject>()) };
        // SAFETY: caller_cspace validated non-null; id() reads discriminator.
        let cspace_id = unsafe { (*caller_cspace).id() };
        (sc.min, sc.max, slot.rights, cspace_id, obj_ptr)
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
            sched_idx,
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
///   the next `enqueue_and_wake` via `select_target_cpu`.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_set_affinity(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::AFFINITY_ANY;
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;
    use core::sync::atomic::Ordering;

    let thread_idx = tf.arg(0) as u32;
    let cpu_id = tf.arg(1) as u32;

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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;

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

    // SAFETY: target_tcb validated non-null; field access is valid.
    unsafe {
        let old_cpu = (*target_tcb).preferred_cpu as usize;

        // Pin preemption across the `cpu_affinity` write and the matching
        // state-read + action that follows. Defense-in-depth: the current
        // syscall-entry discipline keeps IF=0 / SIE=0 throughout the
        // handler body (no path inside re-enables interrupts — only
        // spinlock save/restore — so a local timer tick cannot fire
        // here), but if a future syscall path were to enable interrupts
        // mid-handler, a timer-driven `schedule()` between the
        // `cpu_affinity` store and the matching `migrate_ready_thread`
        // call would dispatch the Ready target locally — `schedule()`'s
        // skip loop checks state but not `cpu_affinity` on the incoming
        // dispatched thread (see scheduling-internals.md § Cross-CPU TCB
        // Ownership). Mirrors the load-bearing pattern in `schedule()`'s
        // cross-CPU re-enqueue branch (`core/kernel/src/sched/mod.rs`), where
        // the inter-lock window IS visible to interrupts.
        //
        // `sys_thread_set_priority` above takes every CPU's scheduler.lock
        // in ascending order around its Scheduling-group writes, so it
        // serialises with `migrate_ready_thread` directly and does not need
        // a preempt bracket.
        //
        // See issue #116.
        crate::percpu::preempt_disable();
        (*target_tcb).cpu_affinity = cpu_id;

        // No active migration when affinity is cleared (any-CPU): the load
        // balancer or the next enqueue will place the thread.
        if cpu_id == AFFINITY_ANY
        {
            crate::percpu::preempt_enable();
            return Ok(0);
        }
        let new_cpu = cpu_id as usize;
        if new_cpu == old_cpu
        {
            crate::percpu::preempt_enable();
            return Ok(0);
        }

        // preferred_cpu is bounded by select_target_cpu (writes always come
        // from enqueue_and_wake or schedule(); both clamp to CPU_COUNT). A
        // higher value indicates a corrupted TCB, which we ignore here.
        let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
        if old_cpu >= cpu_count
        {
            crate::percpu::preempt_enable();
            return Ok(0);
        }

        // Unlocked read; revalidated under-lock by migrate_ready_thread or
        // tolerated as a spurious IPI in the Running case.
        match (*target_tcb).state
        {
            ThreadState::Ready =>
            {
                // Best-effort: migrate_ready_thread re-checks state and
                // location under both scheduler locks and bails on race.
                let _ = crate::sched::migrate_ready_thread(target_tcb, old_cpu, new_cpu);
            }
            ThreadState::Running =>
            {
                // The Running thread's CPU sees the affinity change at its
                // next schedule() entry (see sched/mod.rs schedule() re-enqueue
                // path). Nudging that CPU bounds the latency to one IPI.
                crate::sched::set_reschedule_pending_for(old_cpu);
                crate::sched::prod_remote_cpu(old_cpu);
            }
            _ =>
            {
                // Blocked / Stopped / Created / Exited: next enqueue routes
                // via select_target_cpu which now sees the new affinity.
            }
        }
        crate::percpu::preempt_enable();
    }

    Ok(0)
}

/// `SYS_THREAD_READ_REGS` (39): read register state of a stopped thread.
///
/// arg0 = Thread cap index (must have OBSERVE).
/// arg1 = Pointer to caller-supplied buffer (user VA).
/// arg2 = Size of the buffer in bytes.
///
/// The thread must be in Stopped state. Copies the full `TrapFrame` to the
/// caller's buffer. Returns the number of bytes written on success.
#[cfg(not(test))]
pub fn sys_thread_read_regs(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;
    use core::mem::size_of;

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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::OBSERVE) }?;

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

    // SAFETY: target_tcb validated non-null; state/trap_frame fields always valid.
    unsafe {
        // A fault-blocked thread (Blocked + BlockedOnFault) exposes its faulting
        // register frame through `trap_frame` for the bound handler to read and
        // modify before replying, so the fault-handler protocol permits register
        // access in that state too — not only `Stopped`. See
        // `docs/fault-handling.md` § Modifying the faulting thread.
        let st = (*target_tcb).state;
        let fault_blocked = st == ThreadState::Blocked
            && (*target_tcb).ipc_state == crate::sched::thread::IpcThreadState::BlockedOnFault;
        if st != ThreadState::Stopped && !fault_blocked
        {
            return Err(SyscallError::InvalidState);
        }
        if (*target_tcb).trap_frame.is_null()
        {
            return Err(SyscallError::InvalidArgument);
        }
    }

    let copy_size = size_of::<ArchTF>();
    if buf_size < copy_size || buf_ptr == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Copy TrapFrame to user buffer under SMAP/SUM bracket.
    // SAFETY: trap_frame validated non-null; buf_ptr user VA; copy_size bounded;
    //         user_access_begin/end bracket enables SMAP bypass.
    unsafe {
        let src = (*target_tcb).trap_frame as *const u8;
        let dst = buf_ptr as *mut u8;
        crate::arch::current::cpu::user_access_begin();
        core::ptr::copy_nonoverlapping(src, dst, copy_size);
        crate::arch::current::cpu::user_access_end();
    }

    Ok(copy_size as u64)
}

/// `SYS_THREAD_WRITE_REGS` (40): write register state into a stopped thread.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = Pointer to register-file buffer in caller's address space.
/// arg2 = Size of the buffer in bytes.
///
/// The thread must be in Stopped state. The kernel validates register values
/// for safety (no privilege escalation) before writing. Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_write_regs(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::arch::current::trap_frame::TrapFrame as ArchTF;
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::thread::ThreadState;
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
        unsafe { super::lookup_cap(caller_cspace, thread_idx, CapTag::Thread, Rights::CONTROL) }?;

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

    // SAFETY: target_tcb is valid.
    unsafe {
        // A fault-blocked thread (Blocked + BlockedOnFault) exposes its faulting
        // register frame through `trap_frame` for the bound handler to read and
        // modify before replying, so the fault-handler protocol permits register
        // access in that state too — not only `Stopped`. See
        // `docs/fault-handling.md` § Modifying the faulting thread.
        let st = (*target_tcb).state;
        let fault_blocked = st == ThreadState::Blocked
            && (*target_tcb).ipc_state == crate::sched::thread::IpcThreadState::BlockedOnFault;
        if st != ThreadState::Stopped && !fault_blocked
        {
            return Err(SyscallError::InvalidState);
        }
        if (*target_tcb).trap_frame.is_null()
        {
            return Err(SyscallError::InvalidArgument);
        }
    }

    let copy_size = size_of::<ArchTF>();
    if buf_size < copy_size || buf_ptr == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Copy from user into a stack-local TrapFrame, then validate.
    // Never write directly to the target's trap_frame before validation.
    let mut tmp: MaybeUninit<ArchTF> = MaybeUninit::zeroed();
    // SAFETY: buf_ptr is a non-null user VA; copy_size matches the struct.
    unsafe {
        crate::arch::current::cpu::user_access_begin();
        core::ptr::copy_nonoverlapping(
            buf_ptr as *const u8,
            tmp.as_mut_ptr().cast::<u8>(),
            copy_size,
        );
        crate::arch::current::cpu::user_access_end();
    }

    // SAFETY: all bytes just written by copy_nonoverlapping above.
    let mut regs = unsafe { tmp.assume_init() };

    // Architecture-specific register safety validation.
    validate_write_regs(&mut regs)?;

    // Write the validated TrapFrame into the target thread.
    // SAFETY: target_tcb and trap_frame are valid.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(regs).cast::<u8>(),
            (*target_tcb).trap_frame.cast::<u8>(),
            copy_size,
        );
    }

    Ok(0)
}

/// Validate and sanitize a user-supplied `TrapFrame` before writing it into a
/// thread. Enforces that no privilege bits are set and instruction/stack
/// pointers are in the canonical user address range.
///
/// Mutates `regs` in place to force safe segment/flag values.
///
/// # Adding new checks
/// Add per-field validation in the per-arch `TrapFrame::sanitize_for_user_resume`
/// implementations (`arch/<target>/trap_frame.rs`). Use `InvalidArgument` for
/// bad user data (not a kernel invariant violation).
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
