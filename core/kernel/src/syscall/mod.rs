// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/mod.rs

//! Kernel syscall dispatch.
//!
//! `dispatch` is called from the architecture-specific trap/syscall entry
//! with a pointer to the current thread's [`TrapFrame`]. It reads the syscall
//! number, calls the appropriate handler, and writes the return value back.
//!
//! # Syscall ABI
//! - x86-64: number in `rax`; args in `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`;
//!   return value in `rax`.
//! - RISC-V: number in `a7`; args in `a0`–`a5`; return value in `a0`.
//!
//! # Adding new syscalls
//! 1. Add the constant to `abi/syscall/src/lib.rs`.
//! 2. Add a handler function in the appropriate `syscall/` submodule.
//! 3. Add a `match` arm in `dispatch` below.

pub mod cap;
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
    SYS_ASPACE_QUERY, SYS_CAP_COPY, SYS_CAP_CREATE_ASPACE, SYS_CAP_CREATE_CSPACE,
    SYS_CAP_CREATE_ENDPOINT, SYS_CAP_CREATE_EVENT_Q, SYS_CAP_CREATE_SIGNAL, SYS_CAP_CREATE_THREAD,
    SYS_CAP_CREATE_WAIT_SET, SYS_CAP_DELETE, SYS_CAP_DERIVE, SYS_CAP_DERIVE_TOKEN, SYS_CAP_INFO,
    SYS_CAP_INSERT, SYS_CAP_MOVE, SYS_CAP_REVOKE, SYS_EVENT_POST, SYS_EVENT_RECV, SYS_FRAME_MERGE,
    SYS_FRAME_SPLIT, SYS_IOPORT_BIND, SYS_IPC_BUFFER_SET, SYS_IPC_CALL, SYS_IPC_RECV,
    SYS_IPC_REPLY, SYS_IRQ_ACK, SYS_IRQ_REGISTER, SYS_IRQ_SPLIT, SYS_MEM_MAP, SYS_MEM_PROTECT,
    SYS_MEM_UNMAP, SYS_MMIO_MAP, SYS_MMIO_SPLIT, SYS_SBI_CALL, SYS_SIGNAL_SEND, SYS_SIGNAL_WAIT,
    SYS_SYSTEM_INFO, SYS_THREAD_BIND_NOTIFICATION, SYS_THREAD_CONFIGURE, SYS_THREAD_EXIT,
    SYS_THREAD_READ_REGS, SYS_THREAD_SET_AFFINITY, SYS_THREAD_SET_PRIORITY, SYS_THREAD_SLEEP,
    SYS_THREAD_START, SYS_THREAD_STOP, SYS_THREAD_WRITE_REGS, SYS_THREAD_YIELD, SYS_WAIT_SET_ADD,
    SYS_WAIT_SET_REMOVE, SYS_WAIT_SET_WAIT,
};

// ── TrapFrame accessor shims ──────────────────────────────────────────────────
// `TrapFrame::syscall_nr`, `::set_return`, and `::arg` are defined as methods
// on `TrapFrame` in each arch's `trap_frame.rs`. Callers (ipc.rs etc.) use
// `tf.arg(n)` directly; this comment marks where the free functions used to
// live so the removal is easy to trace.

// ── Syscall dispatch ──────────────────────────────────────────────────────────

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
    // SAFETY: caller guarantees tf is valid and exclusively accessible.
    let tf = unsafe { &mut *tf };

    let nr = tf.syscall_nr();

    let ret: Result<u64, SyscallError> = match nr
    {
        SYS_IPC_CALL => ipc::sys_ipc_call(tf),
        SYS_IPC_REPLY => ipc::sys_ipc_reply(tf),
        SYS_IPC_RECV => ipc::sys_ipc_recv(tf),
        SYS_SIGNAL_SEND => ipc::sys_signal_send(tf),
        SYS_SIGNAL_WAIT => ipc::sys_signal_wait(tf),
        SYS_CAP_CREATE_ENDPOINT => cap::sys_cap_create_endpoint(tf),
        SYS_CAP_CREATE_SIGNAL => cap::sys_cap_create_signal(tf),
        SYS_CAP_CREATE_ASPACE => cap::sys_cap_create_aspace(tf),
        SYS_CAP_CREATE_CSPACE => cap::sys_cap_create_cspace(tf),
        SYS_CAP_CREATE_THREAD => cap::sys_cap_create_thread(tf),
        SYS_CAP_COPY => cap::sys_cap_copy(tf),
        SYS_CAP_DERIVE => cap::sys_cap_derive(tf),
        SYS_CAP_DELETE => cap::sys_cap_delete(tf),
        SYS_CAP_REVOKE => cap::sys_cap_revoke(tf),
        SYS_CAP_MOVE => cap::sys_cap_move(tf),
        SYS_CAP_INSERT => cap::sys_cap_insert(tf),
        SYS_MEM_MAP => mem::sys_mem_map(tf),
        SYS_MEM_UNMAP => mem::sys_mem_unmap(tf),
        SYS_MEM_PROTECT => mem::sys_mem_protect(tf),
        SYS_FRAME_SPLIT => mem::sys_frame_split(tf),
        SYS_FRAME_MERGE => mem::sys_frame_merge(tf),
        SYS_THREAD_CONFIGURE => thread::sys_thread_configure(tf),
        SYS_THREAD_START => thread::sys_thread_start(tf),
        SYS_THREAD_STOP => thread::sys_thread_stop(tf),
        SYS_THREAD_SET_PRIORITY => thread::sys_thread_set_priority(tf),
        SYS_THREAD_SET_AFFINITY => thread::sys_thread_set_affinity(tf),
        SYS_THREAD_READ_REGS => thread::sys_thread_read_regs(tf),
        SYS_THREAD_WRITE_REGS => thread::sys_thread_write_regs(tf),
        SYS_IPC_BUFFER_SET => sys_ipc_buffer_set(tf),
        SYS_THREAD_YIELD => sys_yield(tf),
        SYS_THREAD_EXIT => sys_exit(tf),
        SYS_SYSTEM_INFO => sysinfo::sys_system_info(tf),
        SYS_ASPACE_QUERY => sysinfo::sys_aspace_query(tf),
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
        SYS_SBI_CALL => sbi::sys_sbi_call(tf),
        SYS_THREAD_SLEEP => sys_thread_sleep(tf),
        SYS_THREAD_BIND_NOTIFICATION => sys_thread_bind_notification(tf),
        SYS_CAP_DERIVE_TOKEN => cap::sys_cap_derive_token(tf),
        SYS_CAP_INFO => cap::sys_cap_info(tf),
        _ => Err(SyscallError::UnknownSyscall),
    };

    let ret_val = match ret
    {
        Ok(v) => v.cast_signed(),
        Err(e) => e as i64,
    };

    tf.set_return(ret_val);
}

// ── Thread syscall handlers ───────────────────────────────────────────────────

/// `SYS_THREAD_YIELD` (21): voluntarily yield the CPU.
// unnecessary_wraps: all dispatch arms must return Result<u64, SyscallError>; signature is fixed.
#[cfg(not(test))]
#[allow(clippy::unnecessary_wraps)]
fn sys_yield(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // SAFETY: called from syscall handler on a valid kernel stack.
    // requeue=true: thread is voluntarily yielding but should remain runnable.
    unsafe {
        crate::sched::schedule(true);
    }
    Ok(0)
}

/// `SYS_THREAD_EXIT` (22): terminate the calling thread.
///
/// Marks the current thread as `Exited` and calls `schedule()` to switch
/// to the next runnable thread. The exited thread is never re-enqueued.
///
/// Note: full resource cleanup (freeing kernel stack, TCB, `CSpace` entries)
/// requires a process-manager teardown path that does not yet exist. For now
/// the TCB is abandoned in place — it will not be scheduled again.
#[cfg(not(test))]
fn sys_exit(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::sched::thread::ThreadState;
    // SAFETY: current_tcb() returns current thread; interrupt context ensures it is set.
    let tcb = unsafe { current_tcb() };
    if !tcb.is_null()
    {
        // Commit Exited under all-CPU scheduler.locks so a concurrent
        // dealloc on another CPU observes a coherent state and the local
        // schedule() below sees the Exited skip-bit.
        // SAFETY: tcb validated non-null.
        unsafe {
            crate::sched::set_state_under_all_locks(tcb, ThreadState::Exited);
        }

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
        crate::sched::schedule(false);
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
fn sys_thread_sleep(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let ms = tf.arg(0);
    if ms == 0
    {
        return Ok(0);
    }

    let tps = crate::arch::current::timer::ticks_per_second();
    let now = crate::arch::current::timer::current_tick();
    let deadline = now.saturating_add(ms.saturating_mul(tps) / 1000);

    // SAFETY: current_tcb() returns this CPU's running thread.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: tcb validated non-null; fields always valid for initialized TCB.
    unsafe {
        (*tcb).sleep_deadline = deadline;
        (*tcb).state = crate::sched::thread::ThreadState::Blocked;
    }

    if crate::sched::sleep_list_add(tcb).is_err()
    {
        // Sleep list at capacity. Roll back: sys_thread_sleep has no IPC
        // source to fall back on; the only honest answer is to surface the
        // failure to userspace. See docs/thread-lifecycle-and-sleep.md
        // § Sleep List Invariants.
        // SAFETY: tcb valid; restoring to Ready before any schedule().
        unsafe {
            (*tcb).sleep_deadline = 0;
            (*tcb).state = crate::sched::thread::ThreadState::Running;
        }
        return Err(SyscallError::OutOfMemory);
    }

    // SAFETY: called from syscall handler on valid kernel stack.
    unsafe {
        crate::sched::schedule(false);
    }

    // Woken up by timer_tick — return success.
    Ok(0)
}

// ── SYS_THREAD_BIND_NOTIFICATION ─────────────────────────────────────────────

/// `SYS_THREAD_BIND_NOTIFICATION` (47): register a death-notification
/// observer on a thread.
///
/// arg0 = Thread cap slot (CONTROL right required).
/// arg1 = `EventQueue` cap slot (POST right required).
/// arg2 = caller-chosen `correlator: u32` (opaque routing tag).
///
/// When the target thread exits or faults, the kernel posts
/// `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` to the bound
/// `EventQueue`. Passing `correlator = 0` makes the payload equal to the
/// exit reason (the pre-multi-bind behaviour).
///
/// Multiple independent observers may be registered (up to
/// `MAX_DEATH_OBSERVERS`); all fire on death. Returns
/// `OutOfMemory` if the per-thread observer array is full.
#[cfg(not(test))]
#[allow(clippy::cast_possible_truncation)]
fn sys_thread_bind_notification(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::{CapTag, Rights};
    use crate::sched::thread::{DeathObserver, MAX_DEATH_OBSERVERS};

    let thread_cap_idx = tf.arg(0) as u32;
    let eq_cap_idx = tf.arg(1) as u32;
    let correlator = tf.arg(2) as u32;

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
    let thread_slot =
        unsafe { lookup_cap(cspace, thread_cap_idx, CapTag::Thread, Rights::CONTROL) }?;

    // Extract target TCB from the Thread cap.
    // SAFETY: slot validated as Thread cap; header at offset 0.
    let obj = thread_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0 of ThreadObject; allocator guarantees alignment.
    // SAFETY: tag confirmed Thread; pointer is valid ThreadObject.
    #[allow(clippy::cast_ptr_alignment)]
    let target_tcb = unsafe { (*obj.as_ptr().cast::<crate::cap::object::ThreadObject>()).tcb };

    // Look up the EventQueue cap (POST right required).
    // SAFETY: cspace from current thread; lookup_cap validates.
    let eq_slot = unsafe { lookup_cap(cspace, eq_cap_idx, CapTag::EventQueue, Rights::POST) }?;

    let eq_obj = eq_slot.object.ok_or(SyscallError::InvalidCapability)?;
    // cast_ptr_alignment: header at offset 0 of EventQueueObject; allocator guarantees alignment.
    // SAFETY: tag confirmed EventQueue; pointer is valid EventQueueObject.
    #[allow(clippy::cast_ptr_alignment)]
    let eq_state = unsafe {
        (*eq_obj
            .as_ptr()
            .cast::<crate::cap::object::EventQueueObject>())
        .state
    };

    // Append a new observer. `death_observer_count` is only mutated here
    // (and cleared on TCB init); the death-post path reads under scheduler
    // lock so the append must also be protected.
    //
    // SAFETY: target_tcb is a valid TCB from a validated Thread cap; the
    // scheduler lock is held across this syscall entry, so the TCB's
    // observer array is not concurrently mutated.
    // SAFETY: target_tcb validated non-null; read pre-append snapshot.
    // SAFETY: target_tcb is a valid TCB from a validated Thread cap.
    unsafe {
        let count = (*target_tcb).death_observer_count as usize;
        if count >= MAX_DEATH_OBSERVERS
        {
            return Err(SyscallError::OutOfMemory);
        }
        (*target_tcb).death_observers[count] = DeathObserver {
            eq: eq_state,
            correlator,
        };
        (*target_tcb).death_observer_count = (count + 1) as u8;
    }

    Ok(0)
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
    unsafe { crate::sched::scheduler_for(cpu).current }
}

/// Look up a capability slot in a `CSpace` by index.
///
/// Returns a reference to the slot, or an appropriate [`SyscallError`]:
/// - Null cspace pointer or missing slot → [`SyscallError::InvalidCapability`].
/// - Tag mismatch → [`SyscallError::InvalidCapability`].
/// - Insufficient rights → [`SyscallError::InsufficientRights`].
#[cfg(not(test))]
pub(crate) unsafe fn lookup_cap(
    cspace: *mut crate::cap::cspace::CSpace,
    index: u32,
    expected_tag: crate::cap::slot::CapTag,
    required_rights: crate::cap::slot::Rights,
) -> Result<&'static crate::cap::slot::CapabilitySlot, SyscallError>
{
    if cspace.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: cspace is a valid CSpace pointer from the current thread's TCB.
    let cs = unsafe { &*cspace };
    let slot = cs.slot(index).ok_or(SyscallError::InvalidCapability)?;
    if slot.tag != expected_tag
    {
        return Err(SyscallError::InvalidCapability);
    }
    if !slot.rights.contains(required_rights)
    {
        return Err(SyscallError::InsufficientRights);
    }
    // ref_as_ptr: intentional — raw pointer cast to extend lifetime to 'static.
    #[allow(clippy::ref_as_ptr)]
    // SAFETY: slot lives in the CSpace which is heap-allocated for the lifetime of the process.
    Ok(unsafe { &*(slot as *const _) })
}

// ── IPC buffer ────────────────────────────────────────────────────────────────

/// `SYS_IPC_BUFFER_SET` (42): register (or clear) the per-thread IPC buffer page.
///
/// arg0 = virtual address of the IPC buffer page (0 = deregister; otherwise
/// must be 4 KiB-aligned).
#[cfg(not(test))]
fn sys_ipc_buffer_set(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let virt = tf.arg(0);
    if virt != 0 && (virt & 0xFFF) != 0
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
