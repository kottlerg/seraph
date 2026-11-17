// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/smt_siblings.rs

//! Integration: the kernel's SMT sibling rings are the cores the CPUs report
//! (core/kernel/docs/scheduler.md § SMT Awareness).
//!
//! The case pins this thread to each CPU in turn and reads there the core key
//! the CPU reports for itself (`crate::arch::core_key`: on x86-64 the x2APIC
//! ID with the SMT level's bits shifted out, from `CPUID` in user mode; on
//! riscv64 the CPU index, each hart a core). It sorts the keys and requires
//! `SYS_SYSTEM_INFO(SmtSibling)` to give, for every CPU, the next CPU of its
//! key's group in ascending index order, wrapping: so every CPU's ring holds
//! itself, the rings partition the CPUs, and each ring holds exactly the CPUs
//! that report its core. A CPU whose bring-up recorded no key, or a wrong one,
//! fails it. It logs the core count and the most CPUs a core holds, which under
//! QEMU is the `-smp` `threads` count. The work grows with the CPU count:
//! one pin and one query per CPU, and a sort of their keys.

use syscall::{smt_sibling, system_info, thread_set_affinity, thread_yield};
use syscall_abi::SystemInfoType;

use crate::{TestContext, TestResult};

/// Yields that may pass before a thread pinned to a CPU runs there: the first
/// yield after the pin migrates it; the bound only keeps a scheduler defect
/// from hanging the case.
const MAX_YIELDS: u32 = 64;

/// One CPU's reported core key and its index, ordered by key, then index.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Slot
{
    key: u32,
    cpu: u32,
}

/// Every CPU's slot, filled by [`collect`]: one per CPU up to the boot
/// protocol's ceiling, since ktest has no heap.
static mut SLOTS: [Slot; boot_protocol::MAX_CPUS] =
    [Slot { key: 0, cpu: 0 }; boot_protocol::MAX_CPUS];

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::smt_siblings: system_info(CpuCount) failed")?;
    let count = usize::try_from(cpus)
        .ok()
        .filter(|&n| n <= boot_protocol::MAX_CPUS)
        .ok_or("integration::smt_siblings: CpuCount past MAX_CPUS")?;
    // SAFETY: the harness runs one case at a time on its one thread, and only
    // this case reaches SLOTS, so this is the only reference to it.
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(SLOTS) };
    let slots = slots
        .get_mut(..count)
        .ok_or("integration::smt_siblings: CpuCount past MAX_CPUS")?;
    let collected = collect(ctx, slots);
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "integration::smt_siblings: restore affinity failed");
    collected?;
    restore?;

    slots.sort_unstable();
    let mut cores = 0u64;
    let mut max_threads = 0usize;
    for core in slots.chunk_by(|a, b| a.key == b.key)
    {
        let first = core
            .first()
            .ok_or("integration::smt_siblings: empty core group")?;
        let nexts = core.iter().skip(1).chain(core::iter::once(first));
        for (slot, next) in core.iter().zip(nexts)
        {
            let got = smt_sibling(u64::from(slot.cpu))
                .map_err(|_| "integration::smt_siblings: system_info(SmtSibling) failed")?;
            if got != u64::from(next.cpu)
            {
                crate::log_args(format_args!(
                    "ktest: smt cpu={} key={:#x} sibling={} expected={}",
                    slot.cpu, slot.key, got, next.cpu
                ));
                return Err("integration::smt_siblings: a ring is not its core's CPUs");
            }
        }
        cores = cores.saturating_add(1);
        max_threads = max_threads.max(core.len());
    }
    crate::log_args(format_args!(
        "ktest: smt cores={cores} threads_per_core={max_threads} on {cpus} CPUs"
    ));
    Ok(())
}

/// Pin this thread to each CPU in turn and record in `slots` the core key it
/// reports there.
fn collect(ctx: &TestContext, slots: &mut [Slot]) -> TestResult
{
    for (cpu, slot) in (0u32..).zip(slots.iter_mut())
    {
        thread_set_affinity(ctx.thread_cap, cpu)
            .map_err(|_| "integration::smt_siblings: pin failed")?;
        let on_cpu = || system_info(SystemInfoType::CurrentCpu as u64) == Ok(u64::from(cpu));
        for _ in 0..MAX_YIELDS
        {
            if on_cpu()
            {
                break;
            }
            thread_yield().map_err(|_| "integration::smt_siblings: yield failed")?;
        }
        if !on_cpu()
        {
            return Err("integration::smt_siblings: thread never ran on its CPU");
        }
        *slot = Slot {
            key: crate::arch::core_key(cpu),
            cpu,
        };
    }
    Ok(())
}
