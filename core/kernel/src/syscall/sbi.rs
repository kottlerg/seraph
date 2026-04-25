// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/sbi.rs

//! `SYS_SBI_CALL` (44): forward an SBI call to M-mode firmware.
//!
//! RISC-V only. Validates the caller holds an `SbiControl` capability with
//! `CALL` rights, then issues an `ecall` with the provided extension, function,
//! and arguments.
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

/// `SYS_SBI_CALL` handler — RISC-V implementation.
#[cfg(all(not(test), target_arch = "riscv64"))]
pub fn sys_sbi_call(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::slot::{CapTag, Rights};
    use crate::syscall::current_tcb;

    #[allow(clippy::cast_possible_truncation)] // CSpace slot indices are u32.
    let sbi_cap_idx = tf.arg(0) as u32;
    let extension = tf.arg(1);
    let function = tf.arg(2);
    let a0 = tf.arg(3);
    let a1 = tf.arg(4);
    let a2 = tf.arg(5);

    // Validate SbiControl capability.
    // SAFETY: current_tcb() is valid from a syscall context.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null; cspace field always valid for initialized TCB.
    let cspace = unsafe { (*tcb).cspace };
    // SAFETY: cspace from current TCB; lookup_cap validates tag and rights.
    let _slot =
        unsafe { super::lookup_cap(cspace, sbi_cap_idx, CapTag::SbiControl, Rights::CALL) }?;

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
