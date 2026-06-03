// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/sbi.rs

//! Generic SBI ecall forwarding for RISC-V.
//!
//! Provides a thin wrapper around the `ecall` instruction that forwards
//! arbitrary SBI calls from S-mode to M-mode firmware. The wrapper itself is
//! unrestricted; the userspace-reachable path (`SYS_SBI_CALL`) admits only the
//! sanctioned extensions enumerated by `syscall::sbi::sbi_required_right`
//! (SRST, SUSP, CPPC, Base, DBCN, PMU), each behind a per-extension
//! `SbiControl` right; the kernel-managed extensions (TIME/IPI/RFENCE/HSM) are
//! never forwardable.

/// SBI return value: error code and value.
pub struct SbiRet
{
    /// SBI error code (a0). 0 = success, negative = error.
    pub error: i64,
    /// SBI return value (a1).
    pub value: u64,
}

/// Issue a generic SBI ecall.
///
/// - `extension`: SBI extension ID (a7)
/// - `function`: SBI function ID (a6)
/// - `a0`–`a2`: SBI arguments
///
/// Returns the SBI return value pair (error in a0, value in a1).
#[cfg(not(test))]
pub fn sbi_call(extension: u64, function: u64, a0: u64, a1: u64, a2: u64) -> SbiRet
{
    let error: i64;
    let value: u64;
    // SAFETY: ecall is always available in RISC-V supervisor mode. The SBI
    // firmware handles unknown extensions gracefully (returns SBI_ERR_NOT_SUPPORTED).
    // `nomem` is intentionally absent: this is a generic dispatcher that
    // accepts any extension/function. Several SBI extensions inspect or
    // write caller-pointed memory (RFENCE hart-mask pointer, HSM opaque
    // arg, Debug Console Buffer write, …). Claiming `nomem` would license
    // LLVM to reorder memory ops across the call and silently break any
    // such caller. Today's only caller (`sys_sbi_call`) forwards scalar
    // userspace registers, but the primitive must stay honest.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") a0 => error,
            inout("a1") a1 => value,
            in("a2") a2,
            inout("a6") function => _,
            inout("a7") extension => _,
            options(nostack),
        );
    }
    SbiRet { error, value }
}

#[cfg(test)]
pub fn sbi_call(_extension: u64, _function: u64, _a0: u64, _a1: u64, _a2: u64) -> SbiRet
{
    SbiRet {
        error: -2,
        value: 0,
    } // SBI_ERR_NOT_SUPPORTED
}
