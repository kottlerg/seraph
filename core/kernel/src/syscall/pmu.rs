// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/pmu.rs

//! Performance counter syscall handlers.
//!
//! `SYS_PMU_INFO` (79) describes the calling CPU's counters,
//! `SYS_PMU_CONFIGURE` (80) programs them, and `SYS_PMU_BIND` (81) grants or
//! revokes a thread's direct user-mode reads. Each takes a `PmuControl`
//! capability carrying `Configure`. The call contracts are in
//! `core/kernel/docs/syscalls.md` § `SYS_PMU_INFO` (79),
//! § `SYS_PMU_CONFIGURE` (80) and § `SYS_PMU_BIND` (81); the mechanism is in
//! `core/kernel/docs/perfmon.md`.

#[cfg(not(test))]
use super::{PinnedCap, UserFrame};
#[cfg(not(test))]
use crate::cap::slot::PmuRights;
#[cfg(not(test))]
use pmu::{EventList, PmuMode};
#[cfg(not(test))]
use syscall::SyscallError;

/// Pin the caller's `PmuControl` capability `handle`, which must carry
/// `Configure`, and return it with the caller's `CSpace`.
///
/// # Errors
/// `InvalidCapability` for no `PmuControl` capability, `InsufficientRights`
/// without `Configure`.
#[cfg(not(test))]
fn authority(handle: u64) -> Result<(PinnedCap, *mut crate::cap::cspace::CSpace), SyscallError>
{
    // SAFETY: syscall context, so current_tcb() is the caller's live TCB.
    let tcb = unsafe { super::current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; the cspace field is valid for an
    // initialised TCB.
    let cspace = unsafe { (*tcb).cspace };
    // SAFETY: cspace is the caller's; no lock is held.
    let pin = unsafe { super::lookup_cap(cspace, handle, PmuRights::CONFIGURE) }?;
    Ok((pin, cspace))
}

/// `SYS_PMU_INFO` (79): describe the calling CPU's performance counters.
///
/// arg0 = `PmuControl` capability handle (requires `Configure`).
///
/// Returns the description packed at the `PMU_INFO_*` shifts: the counters a
/// configuration may take, their width in bits, and the supported events,
/// one bit per event id.
///
/// # Errors
/// - `InvalidCapability` — the handle names no `PmuControl` capability.
/// - `InsufficientRights` — the capability lacks `Configure`.
/// - `NotSupported` — the calling CPU has no counters the kernel drives.
#[cfg(not(test))]
pub fn sys_pmu_info(tf: UserFrame) -> Result<u64, SyscallError>
{
    let _authority = authority(tf.arg(0))?;
    // SAFETY: syscall context on a CPU whose per-CPU pointer is installed.
    let info = unsafe { crate::perfmon::info() };
    if !info.present()
    {
        return Err(SyscallError::NotSupported);
    }
    Ok(info.pack())
}

/// `SYS_PMU_CONFIGURE` (80): program the calling CPU's user counters, or
/// release them.
///
/// arg0 = `PmuControl` capability handle (requires `Configure`), arg1 = the
/// event word, one event id per byte from the low byte up, arg2 = the number
/// of events, 0 to release, arg3 = the mode (`PMU_MODE_*` bits; read only
/// when arg2 is not 0).
///
/// Returns the read handles, one per byte in the order of the events; 0 for a
/// release. The configuration replaces the CPU's previous one, whoever made
/// it. The caller's hard affinity must name the CPU it runs on.
///
/// # Errors
/// - `InvalidCapability`, `InsufficientRights` — as for `SYS_PMU_INFO`.
/// - `InvalidArgument` — more than `PMU_CONFIGURE_MAX` events, an unknown or
///   repeated event id, or a mode word that names no mode.
/// - `NotSupported` — the CPU has no counters, has fewer than the events, or
///   does not count one of them.
/// - `InvalidState` — the caller's hard affinity does not name the CPU it
///   runs on.
#[cfg(not(test))]
pub fn sys_pmu_configure(tf: UserFrame) -> Result<u64, SyscallError>
{
    let _authority = authority(tf.arg(0))?;
    let events =
        EventList::decode(tf.arg(1), tf.arg(2)).map_err(|_| SyscallError::InvalidArgument)?;
    let mode = if events.is_empty()
    {
        PmuMode::User
    }
    else
    {
        PmuMode::from_raw(tf.arg(3)).ok_or(SyscallError::InvalidArgument)?
    };
    // SAFETY: syscall context, so current_tcb() is the caller's live TCB.
    let tcb = unsafe { super::current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidState);
    }
    // Interrupts stay disabled from the affinity check to the end of the
    // configuration, so the caller is not descheduled between them and
    // programs the CPU the check named.
    // SAFETY: kernel context; paired with the restore below.
    let irq = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    let result = (|| {
        // SAFETY: syscall context on a CPU whose per-CPU pointer is
        // installed.
        if !unsafe { crate::perfmon::info() }.present()
        {
            return Err(SyscallError::NotSupported);
        }
        // SAFETY: tcb is the caller's live TCB.
        let sched_lock = unsafe { &(*tcb).sched_lock };
        // SAFETY: no lock is held; paired with the unlock_raw below.
        let saved = unsafe { sched_lock.lock_raw() };
        // SAFETY: cpu_affinity is written under the sched_lock held here.
        let affinity = unsafe { (*tcb).cpu_affinity };
        // SAFETY: paired with the lock_raw above.
        unsafe { sched_lock.unlock_raw(saved) };
        if affinity != crate::arch::current::cpu::current_cpu()
        {
            return Err(SyscallError::InvalidState);
        }
        // SAFETY: syscall context on this CPU with interrupts disabled.
        unsafe { crate::perfmon::configure(&events, mode) }
    })();
    // SAFETY: irq came from the save above.
    unsafe { crate::arch::current::cpu::restore_interrupts(irq) };
    result
}

/// `SYS_PMU_BIND` (81): grant or revoke a thread's direct user-mode reads of
/// the counters of the CPU it runs on.
///
/// arg0 = `PmuControl` capability handle (requires `Configure`), arg1 =
/// Thread capability handle (requires `Control`), arg2 = 1 to grant, 0 to
/// revoke.
///
/// Returns 0. The grant holds until a bind revokes it or the thread exits;
/// revoking the `PmuControl` capability does not end it. It takes effect
/// before the thread's next instruction when the thread is the caller, and
/// at the thread's next entry to the kernel otherwise.
///
/// # Errors
/// - `InvalidCapability` — arg0 names no `PmuControl` capability, or arg1 no
///   Thread.
/// - `InsufficientRights` — the `PmuControl` capability lacks `Configure`,
///   or the Thread capability `Control`.
/// - `InvalidArgument` — arg2 is neither 0 nor 1.
/// - `NotSupported` — the calling CPU has no counters the kernel drives.
#[cfg(not(test))]
pub fn sys_pmu_bind(tf: UserFrame) -> Result<u64, SyscallError>
{
    let (_authority, cspace) = authority(tf.arg(0))?;
    // SAFETY: cspace is the caller's; no lock is held.
    let (_pin, target) = unsafe {
        super::thread::thread_with_rights(
            cspace,
            tf.arg(1),
            crate::cap::slot::ThreadRights::CONTROL,
        )
    }?;
    let on = match tf.arg(2)
    {
        0 => false,
        1 => true,
        _ => return Err(SyscallError::InvalidArgument),
    };
    // SAFETY: syscall context on a CPU whose per-CPU pointer is installed.
    if !unsafe { crate::perfmon::info() }.present()
    {
        return Err(SyscallError::NotSupported);
    }
    // SAFETY: target is a valid TCB that _pin keeps live; syscall context,
    // no lock held.
    unsafe { crate::perfmon::bind(target, on) };
    Ok(0)
}
