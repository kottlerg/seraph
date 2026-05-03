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
    let stack_ptr = tf.arg(2);
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

        // All-CPU lock commit closes the cross-CPU dealloc race; see
        // docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine.
        crate::sched::set_state_under_all_locks(target_tcb, ThreadState::Ready);
        let prio = (*target_tcb).priority;
        // Route to correct CPU based on affinity.
        let target_cpu = crate::sched::select_target_cpu(target_tcb);
        crate::sched::enqueue_and_wake(target_tcb, target_cpu, prio);
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
                while {
                    let s = sched_remote.lock.lock_raw();
                    let still_current = sched_remote.current == target_tcb;
                    sched_remote.lock.unlock_raw(s);
                    still_current
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
/// `tcb` must be a valid TCB in `Blocked` state. Must be called with the
/// scheduler lock held (or in single-CPU context).
// too_many_lines: flat dispatch over every `IpcThreadState` variant; splitting
// adds no clarity (each arm is independent and short).
#[allow(clippy::too_many_lines)]
#[cfg(not(test))]
unsafe fn cancel_ipc_block(tcb: *mut crate::sched::thread::ThreadControlBlock)
{
    use crate::ipc::endpoint::{EndpointState, unlink_from_wait_queue};
    use crate::ipc::event_queue::EventQueueState;
    use crate::ipc::signal::SignalState;
    use crate::ipc::wait_set::WaitSetState;
    use crate::sched::thread::IpcThreadState;
    use syscall::SyscallError;

    // SAFETY: tcb validated by caller; ipc_state field always valid.
    let ipc_state = unsafe { (*tcb).ipc_state };
    // SAFETY: tcb validated by caller; blocked_on_object field always valid.
    let blocked_on = unsafe { (*tcb).blocked_on_object };

    // Each branch acquires the source IPC lock matching `ipc_state` before
    // touching the source's waiter / queue. Lock order: scheduler.lock
    // (outer, held by caller) → source IPC lock (inner). See
    // docs/scheduling-internals.md § Lock Hierarchy rule 7.
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
                    (*ep).lock.unlock_raw(saved);
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
            // blocked_on is the server TCB. compare_exchange so we don't
            // clobber a different client's binding (server may have moved on).
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let server = blocked_on.cast::<crate::sched::thread::ThreadControlBlock>();
                // SAFETY: server is a valid TCB pointer; reply_tcb is AtomicPtr.
                unsafe {
                    let _ = (*server).reply_tcb.compare_exchange(
                        tcb,
                        core::ptr::null_mut(),
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    );
                }
            }
        }

        IpcThreadState::BlockedOnSignal =>
        {
            if !blocked_on.is_null()
            {
                // cast_ptr_alignment: blocked_on_object stores type-erased pointer; original allocation guarantees alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let sig = blocked_on.cast::<SignalState>();
                // SAFETY: blocked_on is a valid SignalState ptr.
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

    // If the thread was parked with a timeout (signal-wait or event-recv
    // with `timeout_ms != 0`), it is also on the global sleep list. Drop
    // the entry now so a later timer tick does not dereference a freed TCB.
    // SAFETY: tcb is valid; sleep_list_remove is safe to call when the
    // thread is not registered (returns without effect).
    unsafe {
        if (*tcb).sleep_deadline != 0
        {
            (*tcb).sleep_deadline = 0;
            crate::sched::sleep_list_remove(tcb);
        }
    }

    // Reset IPC state and blocked_on_object.
    // SAFETY: tcb is valid.
    unsafe {
        (*tcb).ipc_state = IpcThreadState::None;
        (*tcb).blocked_on_object = core::ptr::null_mut();
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

/// `SYS_THREAD_SET_PRIORITY` (37): change a thread's scheduling priority.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = New priority (`1`–`PRIORITY_MAX`; 0 and 31 are rejected).
/// arg2 = `SchedControl` cap index (required only when priority ≥ `SCHED_ELEVATED_MIN`).
///
/// The change takes effect at the next scheduler invocation. If the thread is
/// currently in the Ready state, it is moved to the new priority queue immediately.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_set_priority(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::thread::ThreadState;
    use crate::syscall::current_tcb;
    use syscall::{PRIORITY_MAX, SCHED_ELEVATED_MIN};

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

    // Elevated priorities require a SchedControl cap with ELEVATE rights.
    if priority >= SCHED_ELEVATED_MIN
    {
        // SAFETY: caller_cspace validated; lookup_cap checks tag and rights.
        unsafe {
            super::lookup_cap(
                caller_cspace,
                sched_idx,
                CapTag::SchedControl,
                Rights::ELEVATE,
            )
        }?;
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

    // SAFETY: target_tcb validated non-null; priority/state fields always valid.
    unsafe {
        let old_prio = (*target_tcb).priority;
        (*target_tcb).priority = priority;

        // If the thread is Ready, move it to the new priority queue immediately.
        if (*target_tcb).state == ThreadState::Ready
        {
            // Use the thread's preferred CPU (where it last ran).
            let target_cpu = (*target_tcb).preferred_cpu as usize;
            crate::sched::scheduler_for(target_cpu).change_priority(target_tcb, old_prio, priority);
        }
    }

    Ok(0)
}

/// `SYS_THREAD_SET_AFFINITY` (38): set a thread's CPU affinity.
///
/// arg0 = Thread cap index (must have CONTROL).
/// arg1 = CPU ID, or `AFFINITY_ANY` (`u32::MAX`) to clear hard affinity.
///
/// Takes effect on the thread's next enqueue (`select_target_cpu`
/// consults `cpu_affinity`). A thread that is currently running on or
/// queued on another CPU is not migrated.
/// TODO(SMP): active migration so affinity changes apply to already-
/// running or already-queued threads.
///
/// Returns 0 on success.
#[cfg(not(test))]
pub fn sys_thread_set_affinity(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::ThreadObject;
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::AFFINITY_ANY;
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

    // SAFETY: target_tcb validated non-null; cpu_affinity field assignment is valid.
    unsafe {
        (*target_tcb).cpu_affinity = cpu_id;
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
        if (*target_tcb).state != ThreadState::Stopped
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
        if (*target_tcb).state != ThreadState::Stopped
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
/// Add per-field validation below the existing blocks. Use `InvalidArgument`
/// for bad user data (not a kernel invariant violation).
#[cfg(not(test))]
fn validate_write_regs(
    regs: &mut crate::arch::current::trap_frame::TrapFrame,
) -> Result<(), SyscallError>
{
    #[cfg(target_arch = "x86_64")]
    {
        // Canonical user address: bits [63:47] must all be zero.
        const USER_ADDR_MASK: u64 = 0xFFFF_8000_0000_0000;

        if regs.rip & USER_ADDR_MASK != 0
        {
            return Err(SyscallError::InvalidArgument);
        }
        if regs.rsp & USER_ADDR_MASK != 0
        {
            return Err(SyscallError::InvalidArgument);
        }

        // Force segment selectors to user-mode values (ring 3, RPL=3).
        regs.cs = u64::from(crate::arch::current::gdt::USER_CS);
        regs.ss = u64::from(crate::arch::current::gdt::USER_DS);

        // rflags: must have IF (bit 9) set. Clear IOPL (bits 12-13), VM (bit
        // 17), VIF (bit 19), VIP (bit 20) — none of which should be set in
        // user mode. Bit 1 (reserved) must be 1 per the x86 spec.
        regs.rflags = (regs.rflags | 0x202) & !0x0013_F000;
    }

    #[cfg(target_arch = "riscv64")]
    {
        // sepc must be a valid user address. On RV64, virtual addresses in
        // the supervisor range start at 0xFFFF_FFC0_0000_0000 (sv39). Any
        // address ≥ 0x8000_0000_0000_0000 is non-user.
        const USER_ADDR_LIMIT: u64 = 0x8000_0000_0000_0000;
        if regs.sepc >= USER_ADDR_LIMIT
        {
            return Err(SyscallError::InvalidArgument);
        }

        // scause and stval are kernel-internal; zero them out to prevent
        // spurious fault handling on resume.
        regs.scause = 0;
        regs.stval = 0;
    }

    Ok(())
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
