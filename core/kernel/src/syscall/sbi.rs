// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/sbi.rs

//! `SYS_SBI_CALL` (44): forward an SBI call to M-mode firmware.
//!
//! RISC-V only. The kernel forwards an SBI call only for a fixed set of
//! sanctioned extensions, each gated by a per-extension `SbiControl` right.
//! [`sbi_required_right`] maps an extension ID to the right it requires; an
//! extension with no entry is one the kernel manages internally
//! (TIME/IPI/RFENCE/HSM) and is never forwardable, regardless of cap. Every
//! other extension is sanctioned and forwarded only if the caller's `SbiControl`
//! cap carries the required right; whether any consumer holds such a cap is
//! userspace policy. See `docs/capability-model.md`.
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
#[cfg(not(test))]
const SBI_EXT_SRST: u64 = 0x5352_5354;

/// SBI System Suspend (SUSP) extension ID — ASCII "SUSP".
#[cfg(not(test))]
const SBI_EXT_SUSP: u64 = 0x5355_5350;

/// SBI CPPC (processor performance control) extension ID — ASCII "CPPC".
#[cfg(not(test))]
const SBI_EXT_CPPC: u64 = 0x4350_5043;

/// SBI Base extension ID (version / extension probe; read-only).
#[cfg(not(test))]
const SBI_EXT_BASE: u64 = 0x10;

/// SBI Debug Console (DBCN) extension ID — ASCII "DBCN".
#[cfg(not(test))]
const SBI_EXT_DBCN: u64 = 0x4442_434E;

/// SBI Performance Monitoring Unit (PMU) extension ID — ASCII "PMU".
#[cfg(not(test))]
const SBI_EXT_PMU: u64 = 0x0050_4D55;

/// Map an SBI extension ID to the `SbiControl` right required to forward it.
///
/// `None` means the extension is the kernel's to manage internally
/// (TIME/IPI/RFENCE/HSM) and is never forwardable from userspace regardless of
/// cap. Every other extension is sanctioned with a right; whether any consumer
/// receives a cap bearing that right is userspace cap-distribution policy.
/// Adding a sanctioned extension is one entry here plus one `Rights` bit in
/// `cap::slot::Rights`.
#[cfg(not(test))]
fn sbi_required_right(extension: u64) -> Option<crate::cap::slot::Rights>
{
    use crate::cap::slot::Rights;
    match extension
    {
        SBI_EXT_SRST => Some(Rights::SBI_RESET),
        SBI_EXT_SUSP => Some(Rights::SBI_SUSPEND),
        SBI_EXT_CPPC => Some(Rights::SBI_CPPC),
        SBI_EXT_BASE => Some(Rights::SBI_BASE),
        SBI_EXT_DBCN => Some(Rights::SBI_DBCN),
        SBI_EXT_PMU => Some(Rights::SBI_PMU),
        _ => None,
    }
}

/// `SYS_SBI_CALL` handler — RISC-V implementation.
#[cfg(not(test))]
pub fn sys_sbi_call(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::CapTag;
    use crate::syscall::current_tcb;

    // SBI is a RISC-V firmware interface; x86-64 has no equivalent.
    if !crate::arch::current::HAS_SBI
    {
        return Err(SyscallError::NotSupported);
    }

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

    // Forward the SBI call to firmware; SBI errors map to NotSupported.
    crate::arch::current::sbi_forward(extension, function, a0, a1, a2)
        .map_err(|()| SyscallError::NotSupported)
}

/// Test stub.
#[cfg(test)]
pub fn sys_sbi_call(_tf: &mut TrapFrame) -> Result<u64, syscall::SyscallError>
{
    Err(syscall::SyscallError::NotSupported)
}
