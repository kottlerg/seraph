// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// pwrmgr/src/riscv64.rs

//! RISC-V platform shutdown and reboot via the SBI SRST extension.
//!
//! Forwards an SBI `system_reset` call through the kernel to M-mode
//! firmware. The `SbiControl` capability gates kernel-side acceptance of
//! the forwarded call; pwrmgr's cap-gating gates the userspace IPC.

use crate::caps::PwrmgrCaps;

const SBI_EXT_SRST: u64 = 0x5352_5354; // "SRST" in ASCII.
const SBI_SRST_RESET: u64 = 0; // function 0: system_reset
const SRST_TYPE_SHUTDOWN: u64 = 0;
const SRST_TYPE_COLD_REBOOT: u64 = 2;
const SRST_REASON_NONE: u64 = 0;

/// Attempt SBI SRST shutdown. Logs and returns on failure.
pub fn shutdown(_self_thread: u32, caps: &PwrmgrCaps)
{
    sbi_reset(caps, SRST_TYPE_SHUTDOWN);
}

/// Attempt SBI SRST cold reboot. Logs and returns on failure.
pub fn reboot(_self_thread: u32, caps: &PwrmgrCaps)
{
    sbi_reset(caps, SRST_TYPE_COLD_REBOOT);
}

fn sbi_reset(caps: &PwrmgrCaps, reset_type: u64)
{
    if caps.arch_cap == 0
    {
        std::os::seraph::log!("SBI SRST failed (no SbiControl cap)");
        return;
    }
    let _ = syscall::sbi_call(
        caps.arch_cap,
        SBI_EXT_SRST,
        SBI_SRST_RESET,
        reset_type,
        SRST_REASON_NONE,
        0,
    );
    // If we reach here, SRST returned unexpectedly. Halt to prevent
    // partial output from racing the reset.
    loop
    {
        // SAFETY: `wfi` on RISC-V is non-privileged; it merely hints
        // the hart to enter a low-power wait state.
        unsafe {
            core::arch::asm!("wfi", options(nomem, nostack));
        }
    }
}
