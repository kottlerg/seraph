// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/fpu.rs

//! RISC-V extended-state (F / D / V) control primitives.
//!
//! Concentrates the unsafe surface for FP and Vector state management.
//! Step 4: only establishes the boot invariant `sstatus.FS = sstatus.VS = 00
//! (Off)`. With both fields Off, any F/D or V instruction in U-mode raises an
//! illegal-instruction trap (`scause = 2`), which the lazy save/restore path
//! installed in later commits will use to restore extended state.

/// `sstatus.FS` field — bits [14:13]. Two-bit FP unit state: 00=Off,
/// 01=Initial, 10=Clean, 11=Dirty.
const SSTATUS_FS_MASK: u64 = 0x3 << 13;

/// `sstatus.VS` field — bits [10:9]. Two-bit Vector unit state, same encoding
/// as `FS`.
const SSTATUS_VS_MASK: u64 = 0x3 << 9;

/// Force `sstatus.FS = sstatus.VS = 00 (Off)` for the current hart.
///
/// After this returns, any U-mode F/D or V instruction raises an
/// illegal-instruction trap (`scause = 2`). Kernel code remains soft-float
/// (RV64IMAC target) and never touches F/D/V, so the kernel side itself
/// never trips the trap.
///
/// Must be called once per hart at early init (BSP and each AP) before any
/// userspace runs.
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
#[inline]
pub unsafe fn enable_fpu_vector()
{
    // csrc clears the bits given in the mask. Clearing FS[14:13] and VS[10:9]
    // forces both fields to 00 (Off).
    // SAFETY: csrc sstatus is a privileged S-mode instruction; mask is constant
    // and architected.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (SSTATUS_FS_MASK | SSTATUS_VS_MASK),
            options(nostack, nomem),
        );
    }
}

/// No-op test stub: CSR access cannot run in host unit tests.
#[cfg(test)]
pub unsafe fn enable_fpu_vector() {}
