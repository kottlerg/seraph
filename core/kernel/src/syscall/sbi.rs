// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/sbi.rs

//! `SYS_SBI_CALL` (44): forward an SBI call to M-mode firmware.
//!
//! RISC-V only. The kernel forwards an SBI call only for a fixed set of
//! sanctioned extensions, each gated by a per-extension `SbiControl` right.
//! [`sbi_required_right`] maps an extension ID to the right it requires; an
//! extension with no entry — kernel-reserved (TIME/IPI/RFENCE/HSM) or
//! architecturally disallowed (DBCN/PMU) — is never forwardable, regardless
//! of cap. A sanctioned extension is forwarded only if the caller's `SbiControl`
//! cap carries the required right. See `docs/capability-model.md`.
//!
//! On x86-64, this syscall returns `SyscallError::NotSupported`.
//!
//! # Arguments
//! - arg0: `SbiControl` capability slot index
//! - arg1: SBI extension ID
//! - arg2: SBI function ID
//! - arg3: SBI a0 argument
//! - arg4: SBI a1 argument
//! - arg5: SBI a2 argument
//!
//! # Returns
//! On success: SBI return value (sbiret.value). SBI error code is packed
//! into the secondary return register (rdx on x86-64, a1 on RISC-V).

use crate::arch::current::trap_frame::TrapFrame;

#[cfg(not(test))]
use syscall::SyscallError;

/// SBI System Reset (SRST) extension ID — ASCII "SRST".
#[cfg(all(not(test), target_arch = "riscv64"))]
const SBI_EXT_SRST: u64 = 0x5352_5354;

/// SBI System Suspend (SUSP) extension ID — ASCII "SUSP".
#[cfg(all(not(test), target_arch = "riscv64"))]
const SBI_EXT_SUSP: u64 = 0x5355_5350;

/// SBI CPPC (processor performance control) extension ID — ASCII "CPPC".
#[cfg(all(not(test), target_arch = "riscv64"))]
const SBI_EXT_CPPC: u64 = 0x4350_5043;

/// SBI Base extension ID (version / extension probe; read-only).
#[cfg(all(not(test), target_arch = "riscv64"))]
const SBI_EXT_BASE: u64 = 0x10;

/// Map an SBI extension ID to the `SbiControl` right required to forward it.
///
/// `None` means the extension is not sanctioned for userspace forwarding —
/// either kernel-reserved (TIME/IPI/RFENCE/HSM) or architecturally disallowed
/// (DBCN/PMU) — and `sys_sbi_call` rejects it regardless of cap. Adding a
/// sanctioned extension is one entry here plus one `Rights` bit in
/// `cap::slot::Rights`.
#[cfg(all(not(test), target_arch = "riscv64"))]
fn sbi_required_right(extension: u64) -> Option<crate::cap::slot::Rights>
{
    use crate::cap::slot::Rights;
    match extension
    {
        SBI_EXT_SRST => Some(Rights::SBI_RESET),
        SBI_EXT_SUSP => Some(Rights::SBI_SUSPEND),
        SBI_EXT_CPPC => Some(Rights::SBI_CPPC),
        SBI_EXT_BASE => Some(Rights::SBI_BASE),
        _ => None,
    }
}

/// `SYS_SBI_CALL` handler — RISC-V implementation.
#[cfg(all(not(test), target_arch = "riscv64"))]
pub fn sys_sbi_call(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::CapTag;
    use crate::syscall::current_tcb;

    #[allow(clippy::cast_possible_truncation)] // CSpace slot indices are u32.
    let sbi_cap_idx = tf.arg(0) as u32;
    let extension = tf.arg(1);
    let function = tf.arg(2);
    let a0 = tf.arg(3);
    let a1 = tf.arg(4);
    let a2 = tf.arg(5);

    // Kernel floor: only sanctioned extensions are forwardable, each behind its
    // own right. An unsanctioned extension is rejected before the cap is even
    // inspected — no cap can authorize it.
    let required = sbi_required_right(extension).ok_or(SyscallError::InvalidArgument)?;

    // Validate the SbiControl cap carries the extension's required right.
    // SAFETY: current_tcb() is valid from a syscall context.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace field always valid for initialized TCB.
    let cspace = unsafe { (*tcb).cspace };
    // SAFETY: cspace from current TCB; lookup_cap validates tag and rights.
    let _slot = unsafe { super::lookup_cap(cspace, sbi_cap_idx, CapTag::SbiControl, required) }?;

    // Forward the SBI call.
    let ret = crate::arch::current::sbi::sbi_call(extension, function, a0, a1, a2);

    if ret.error != 0
    {
        // SBI errors are small negative integers (-1 through -9).
        return Err(SyscallError::NotSupported);
    }

    Ok(ret.value)
}

/// `SYS_SBI_CALL` stub — x86-64 (SBI does not exist on x86-64).
#[cfg(all(not(test), target_arch = "x86_64"))]
pub fn sys_sbi_call(_tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    Err(SyscallError::NotSupported)
}

/// Test stub.
#[cfg(test)]
pub fn sys_sbi_call(_tf: &mut TrapFrame) -> Result<u64, syscall::SyscallError>
{
    Err(syscall::SyscallError::NotSupported)
}
