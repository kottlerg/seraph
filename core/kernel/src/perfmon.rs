// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/perfmon.rs

//! Per-CPU performance counters behind a `PmuControl` capability
//! (core/kernel/docs/perfmon.md; docs/capability-model.md § `PmuControl`).
//!
//! Each CPU describes its counters once at bring-up ([`init_this_cpu`]).
//! `SYS_PMU_CONFIGURE` programs the calling CPU's user counters
//! ([`configure`]), and `SYS_PMU_BIND` sets a thread's reader flag
//! (`ThreadControlBlock::pmu_reader`, [`bind`]), which decides whether user
//! mode reads the counters directly while that thread runs: `CR4.PCE` on
//! x86-64, the configured counters' `scounteren` bits on riscv64.
//!
//! The grant in effect on a CPU follows the user thread that runs there, and
//! holds only while the CPU has a user configuration: a CPU with none grants
//! no thread, so its dispatch pays one per-CPU load of [`CpuPmu::armed`] and a
//! not-taken branch ([`armed`]). On a configured CPU the dispatch of a user
//! thread applies its flag ([`switch_in`]), and a bind posts
//! `percpu::return_work::PMU_GRANT` to the CPU running the thread, whose next
//! return to user mode applies the flag again ([`sync_grant`]). A CPU writes
//! the grant only when the one it applies differs from the one in effect, so a
//! switch between two threads of the same flag writes nothing.

use core::sync::atomic::AtomicU32;
#[cfg(not(test))]
use core::sync::atomic::Ordering;

use pmu::Info;
#[cfg(not(test))]
use pmu::{EventList, PmuMode, pack_handles};
#[cfg(not(test))]
use syscall::{PMU_CONFIGURE_MAX, SyscallError};

use crate::arch::current::pmu::ArchPmu;
#[cfg(not(test))]
use crate::sched::thread::{ThreadControlBlock, ThreadState};

/// One CPU's counters and the grant in effect on it, in its
/// `PerCpuData::pmu`. Read and written only by that CPU, with interrupts
/// disabled: at bring-up, in a dispatch, at a return to user mode, and in
/// `SYS_PMU_CONFIGURE`.
pub struct CpuPmu
{
    /// 1 while the CPU has a user configuration, else 0: the word a dispatch
    /// tests ([`armed`]) before it reads anything else of the grant. 0 implies
    /// no grant in effect. Written only by this CPU with interrupts disabled,
    /// in [`configure`]; an atomic since [`armed`] reads it with one
    /// GS- or `tp`-relative load, outside any reference to this struct.
    armed: AtomicU32,
    /// What the counters offer; [`Info::NONE`] for a CPU with none.
    info: Info,
    /// Whether the grant in effect is a reader's.
    reader: bool,
    /// The architecture's state.
    arch: ArchPmu,
}

impl CpuPmu
{
    /// A CPU not yet described: no counters, no grant.
    pub const fn new() -> Self
    {
        Self {
            armed: AtomicU32::new(0),
            info: Info::NONE,
            reader: false,
            arch: ArchPmu::new(),
        }
    }
}

/// The offset of [`CpuPmu::armed`] in `PerCpuData`.
#[cfg(not(test))]
const ARMED_OFFSET: usize =
    core::mem::offset_of!(crate::percpu::PerCpuData, pmu) + core::mem::offset_of!(CpuPmu, armed);

/// Whether this CPU has a user configuration, so that a dispatch applies the
/// incoming thread's grant ([`switch_in`]): one per-CPU load.
///
/// # Safety
/// This CPU's per-CPU pointer is installed and interrupts are disabled.
#[cfg(not(test))]
#[inline]
pub unsafe fn armed() -> bool
{
    // SAFETY: the per-CPU pointer is installed (contract); ARMED_OFFSET is
    // that of the aligned AtomicU32 `armed` of this CPU's PerCpuData, below
    // the 2 KiB reach of a riscv64 load's immediate (`PerCpuData` is far
    // smaller), which only this CPU writes, with interrupts disabled.
    unsafe { crate::arch::current::cpu::read_percpu_u32::<ARMED_OFFSET>() != 0 }
}

/// This CPU's [`CpuPmu`].
///
/// # Safety
/// This CPU's per-CPU pointer is installed and interrupts are disabled, and
/// the reference is dropped before they are enabled again: only this CPU
/// touches its `CpuPmu`, and nothing this CPU runs with interrupts disabled
/// holds another reference to it.
#[cfg(not(test))]
unsafe fn this_cpu_pmu<'a>() -> &'a mut CpuPmu
{
    // SAFETY: the per-CPU pointer is installed (contract).
    let cpu = unsafe { crate::percpu::this_cpu() };
    // SAFETY: cpu is this CPU's live PerCpuData, whose pmu field no other
    // reference reaches (contract).
    unsafe { &mut (*cpu).pmu }
}

/// Describe this CPU's counters and leave its user counters stopped at zero,
/// with no grant in effect. The boot CPU logs the description.
///
/// # Safety
/// Ring 0 or S-mode on the CPU being initialised, with interrupts disabled,
/// once, after its per-CPU pointer is installed and before it enters user
/// mode; on x86-64 after `cpu::enable_smep_smap` cleared `CR4.PCE`, on
/// riscv64 after `interrupts` wrote `scounteren`.
#[cfg(not(test))]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "boot is data: whether this CPU is the one that logs the description"
)]
pub unsafe fn init_this_cpu(boot: bool)
{
    // SAFETY: the per-CPU pointer is installed and interrupts are disabled
    // (contract).
    let pmu = unsafe { this_cpu_pmu() };
    // SAFETY: ring 0 or S-mode on this CPU with interrupts disabled
    // (contract); the state is this CPU's.
    let info = unsafe { crate::arch::current::pmu::init(&mut pmu.arch) };
    pmu.info = info;
    if boot
    {
        if info.present()
        {
            crate::kprintln!(
                "pmu: counters={} width={} events={:#x}",
                info.counters,
                info.width,
                info.events
            );
        }
        else
        {
            crate::kprintln!("pmu: no counters");
        }
    }
}

/// This CPU's counters, [`Info::NONE`] for none.
///
/// # Safety
/// This CPU's per-CPU pointer is installed.
#[cfg(not(test))]
pub unsafe fn info() -> Info
{
    // SAFETY: the per-CPU pointer is installed (contract).
    let cpu = unsafe { crate::percpu::this_cpu() };
    // SAFETY: cpu is this CPU's live PerCpuData; info is written once, at
    // bring-up, before user mode, and is a copy.
    unsafe { (*cpu).pmu.info }
}

/// Make `reader` the grant in effect on `pmu`'s CPU, writing it when it
/// differs from the one in effect.
///
/// # Safety
/// `pmu` is this CPU's, and interrupts are disabled.
#[cfg(not(test))]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "reader is data: the pmu_reader flag of the thread the grant is applied for"
)]
unsafe fn apply(pmu: &mut CpuPmu, reader: bool)
{
    if pmu.reader == reader
    {
        return;
    }
    pmu.reader = reader;
    // SAFETY: the caller's contract is write_grant's.
    unsafe { write_grant(pmu) };
}

/// Write the grant `pmu` records as in effect to its CPU.
///
/// # Safety
/// `pmu` is this CPU's, and interrupts are disabled.
#[cfg(not(test))]
unsafe fn write_grant(pmu: &CpuPmu)
{
    if pmu.info.present()
    {
        // SAFETY: interrupts disabled on this CPU (contract); the state is
        // this CPU's.
        unsafe { crate::arch::current::pmu::apply_grant(&pmu.arch, pmu.reader) };
    }
}

/// Apply the reader flag of `tcb`, the thread this CPU dispatches, when it is
/// a user thread, under its held `sched_lock`, which orders the read after
/// every `SYS_PMU_BIND` whose post does not reach this CPU. Called only on a
/// CPU [`armed`] reports configured; a kernel thread leaves the grant as it
/// is, since it runs no user code.
///
/// # Safety
/// `tcb` is a valid TCB whose `sched_lock` this CPU holds; this CPU's
/// per-CPU pointer is installed and interrupts are disabled.
#[cfg(not(test))]
#[cold]
#[inline(never)]
pub unsafe fn switch_in(tcb: *const ThreadControlBlock)
{
    // SAFETY: tcb valid (contract); is_user is immutable.
    if !unsafe { (*tcb).is_user }
    {
        return;
    }
    // SAFETY: tcb valid (contract); the flag is an atomic.
    let reader = unsafe { (*tcb).pmu_reader.load(Ordering::Relaxed) };
    // SAFETY: the per-CPU pointer is installed and interrupts are disabled
    // (contract).
    let pmu = unsafe { this_cpu_pmu() };
    // SAFETY: pmu is this CPU's; interrupts are disabled (contract).
    unsafe { apply(pmu, reader) };
}

/// Apply the reader flag of this CPU's running thread, on a CPU with a user
/// configuration: the return to user mode that took a `PMU_GRANT` bit. The
/// take's Acquire orders the read after the bind's store, which the post's
/// Release follows.
///
/// # Safety
/// A return to user mode on this CPU with interrupts disabled, no lock held.
#[cfg(not(test))]
pub unsafe fn sync_grant()
{
    // SAFETY: a return to user mode runs on a CPU whose per-CPU pointer is
    // installed (contract).
    let current = unsafe { crate::percpu::current_thread() };
    if current.is_null()
    {
        return;
    }
    // SAFETY: current is this CPU's running thread, a valid TCB; the flag is
    // an atomic.
    let reader = unsafe { (*current).pmu_reader.load(Ordering::Relaxed) };
    // SAFETY: the per-CPU pointer is installed and interrupts are disabled
    // (contract).
    let pmu = unsafe { this_cpu_pmu() };
    let armed = *pmu.armed.get_mut() != 0;
    // SAFETY: pmu is this CPU's; interrupts are disabled (contract).
    unsafe { apply(pmu, armed && reader) };
}

/// Program this CPU's user counters with `events` counting in `mode`, or
/// release them for an empty list, then record whether the CPU holds a
/// configuration ([`armed`]) and write the caller's grant again, whose
/// counters the call changed, whether it succeeded or not: on riscv64 a
/// failed configuration leaves none. Returns the read handles, one per byte
/// in the order of the events.
///
/// # Errors
/// `NotSupported` for a CPU with no counters, more events than it has, or an
/// event it does not count.
///
/// # Safety
/// Syscall context on this CPU with interrupts disabled.
#[cfg(not(test))]
pub unsafe fn configure(events: &EventList, mode: PmuMode) -> Result<u64, SyscallError>
{
    // SAFETY: syscall context on a CPU whose per-CPU pointer is installed,
    // with interrupts disabled (contract).
    let pmu = unsafe { this_cpu_pmu() };
    let info = pmu.info;
    if !info.present()
    {
        return Err(SyscallError::NotSupported);
    }
    let mut handles = [0u8; PMU_CONFIGURE_MAX];
    // SAFETY: ring 0 or S-mode on this CPU with interrupts disabled
    // (contract); the state and info are this CPU's.
    let result = unsafe {
        crate::arch::current::pmu::configure(&mut pmu.arch, info, events, mode, &mut handles)
    };
    let armed = pmu.arch.configured();
    *pmu.armed.get_mut() = u32::from(armed);
    // SAFETY: syscall context on a CPU whose per-CPU pointer is installed
    // (contract).
    let caller = unsafe { crate::percpu::current_thread() };
    // SAFETY: in syscall context this CPU's running thread is the caller, a
    // valid TCB; the flag is an atomic.
    let reader = unsafe { (*caller).pmu_reader.load(Ordering::Relaxed) };
    pmu.reader = armed && reader;
    // SAFETY: pmu is this CPU's; interrupts are disabled (contract).
    unsafe { write_grant(pmu) };
    result?;
    Ok(pack_handles(handles.get(..events.len()).unwrap_or(&[])))
}

/// Set the reader flag of `target` to `on`, and post `PMU_GRANT` to the CPU
/// running it, which applies the flag at its next return to user mode: this
/// CPU's when `target` is the caller, another's after an interrupt this
/// prods it with. A thread running nowhere takes the flag at its dispatch
/// ([`switch_in`]).
///
/// The store, the state read and the post are made under `target`'s
/// `sched_lock`, under which a dispatch marks the thread `Running` on its
/// CPU and reads the flag: a dispatch before the store is followed by the post
/// to its CPU, and one after it reads the new flag.
///
/// # Safety
/// `target` is a valid TCB the caller pins; syscall context, no lock held.
#[cfg(not(test))]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "on is data: the flag SYS_PMU_BIND's caller passed, which the thread records"
)]
pub unsafe fn bind(target: *mut ThreadControlBlock, on: bool)
{
    // SAFETY: target valid (contract).
    let sched_lock = unsafe { &(*target).sched_lock };
    // SAFETY: no lock is held (contract); paired with the unlock_raw below.
    let saved = unsafe { sched_lock.lock_raw() };
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to the flag, the state or preferred_cpu of target, under its \
                  held sched_lock"
    )]
    // SAFETY: target valid (contract); state and preferred_cpu are read under
    // its sched_lock, held here, and the flag is an atomic.
    let running_on = unsafe {
        (*target).pmu_reader.store(on, Ordering::Relaxed);
        ((*target).state == ThreadState::Running).then(|| (*target).preferred_cpu as usize)
    };
    if let Some(cpu) = running_on
    {
        // SAFETY: preferred_cpu of a Running thread names an online CPU; the
        // post's Release follows the store above.
        unsafe {
            crate::percpu::post_return_work_to(cpu, crate::percpu::return_work::PMU_GRANT);
        }
    }
    // SAFETY: paired with the lock_raw above.
    unsafe { sched_lock.unlock_raw(saved) };
    if let Some(cpu) = running_on
        && cpu != crate::arch::current::cpu::current_cpu() as usize
    {
        // SAFETY: preferred_cpu of a Running thread names an online CPU.
        unsafe { crate::sched::prod_remote_cpu(cpu) };
    }
}
