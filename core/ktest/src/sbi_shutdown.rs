// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/sbi_shutdown.rs

//! SBI SRST (System Reset) shutdown for RISC-V.
//!
//! Uses the `SYS_SBI_CALL` syscall to forward an SBI SRST shutdown request
//! through the kernel to M-mode firmware.

use init_protocol::InitInfo;

/// SBI SRST extension ID.
const SBI_EXT_SRST: u64 = 0x5352_5354;

/// SBI SRST function 0: `system_reset`.
const SBI_SRST_RESET: u64 = 0;

/// SRST reset type: shutdown (power off).
const SRST_TYPE_SHUTDOWN: u64 = 0;

/// SRST reset reason: no reason.
const SRST_REASON_NONE: u64 = 0;

/// Attempt SBI SRST shutdown. Does not return on success.
///
/// On failure (missing cap, SBI not supported), logs a warning and returns.
pub fn shutdown(info: &InitInfo)
{
    let sbi_cap = info.sbi_control_cap;
    if sbi_cap == 0
    {
        crate::log("ktest: shutdown failed (no SbiControl cap)");
        return;
    }

    let _ = syscall::sbi_call(
        sbi_cap,
        SBI_EXT_SRST,
        SBI_SRST_RESET,
        SRST_TYPE_SHUTDOWN,
        SRST_REASON_NONE,
        0,
    );

    // If we reach here, SRST failed or returned unexpectedly. Halt to prevent
    // partial output leaking to serial.
    crate::halt();
}
