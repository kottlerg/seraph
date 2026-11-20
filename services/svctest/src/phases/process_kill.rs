// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/process_kill.rs

//! What the phases that kill a process share: the kill through the debug
//! authority, and the IOMMU driver's name on this architecture.

use super::swap::attach;
use crate::arch::current::{IP_OFFSET, REGS_SIZE};

/// The IOMMU driver's name in `LIST_PROCESSES` on this architecture; it runs
/// only where the platform has an IOMMU.
#[cfg(target_arch = "x86_64")]
pub(super) const IOMMU_NAME: &str = "/services/drivers/iommu-vtd";
/// The IOMMU driver's name in `LIST_PROCESSES` on this architecture; it runs
/// only where the platform has an IOMMU.
#[cfg(target_arch = "riscv64")]
pub(super) const IOMMU_NAME: &str = "/services/drivers/iommu-riscv";

/// Kill the process `process` through an attach: stop its main thread, set its
/// instruction pointer to the first page, which no process maps, and start it,
/// so it takes a fault no handler resolves. A failure panics naming `phase`.
pub(super) fn kill(authority: u64, process: u64, what: &str, phase: &str)
{
    let threads = attach(authority, process, what);
    let main = *threads.first().expect("the attach returned a thread");
    syscall::thread_stop(main).unwrap_or_else(|e| panic!("{phase}: stopping {what} ({e})"));
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(main, &mut regs)
        .unwrap_or_else(|e| panic!("{phase}: reading {what}'s registers ({e})"));
    regs.get_mut(IP_OFFSET..IP_OFFSET.saturating_add(8))
        .unwrap_or_else(|| panic!("{phase}: the instruction pointer within the register file"))
        .copy_from_slice(&0u64.to_ne_bytes());
    // SAFETY: the thread is the attached process's, bound to its address
    // space, so the frame it resumes on touches none of svctest's memory; the
    // write only makes it fault.
    unsafe { syscall::thread_write_regs(main, &regs) }
        .unwrap_or_else(|e| panic!("{phase}: writing {what}'s instruction pointer ({e})"));
    syscall::thread_start(main)
        .unwrap_or_else(|e| panic!("{phase}: starting {what}'s main thread ({e})"));
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}
