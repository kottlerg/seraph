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

/// Promote `sstatus.FS` and `sstatus.VS` from 00 (Off) to 01 (Initial) so the
/// next FP/V instruction executes without re-trapping.
///
/// Called from the illegal-instruction trap handler on first user F/D/V
/// touch. csrs only sets bits; from the Off boot invariant the bit-13 and
/// bit-9 sets transition both fields to Initial. Once the user code writes
/// an F or V register the hardware advances the field to Dirty.
///
/// Adding XRSTOR-equivalent restore of a per-thread save area is deferred
/// to the commit that introduces TCB extended state.
///
/// # Safety
/// Must execute in supervisor mode.
#[cfg(not(test))]
#[inline]
pub unsafe fn lazy_enable_fp_v_initial()
{
    // sstatus.FS[14:13] and sstatus.VS[10:9]: setting only bit 13 / bit 9
    // turns each field from 00 (Off) into 01 (Initial).
    let mask = (1u64 << 13) | (1u64 << 9);
    // SAFETY: csrs sstatus is privileged S-mode; mask is architected.
    unsafe {
        core::arch::asm!(
            "csrs sstatus, {mask}",
            mask = in(reg) mask,
            options(nostack, nomem),
        );
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn lazy_enable_fp_v_initial() {}

/// Return `true` if `insn` (a 32-bit RISC-V instruction encoding from
/// `stval` on an illegal-instruction trap) is an F, D, or V instruction —
/// i.e. the trap was caused by FS=Off or VS=Off and is a candidate for
/// lazy enable.
///
/// Decodes the major opcode (bits [6:0]):
/// - `0x07` LOAD-FP    (FLW/FLD, vector loads)
/// - `0x27` STORE-FP   (FSW/FSD, vector stores)
/// - `0x43` MADD       (FMADD)
/// - `0x47` MSUB       (FMSUB)
/// - `0x4B` NMSUB      (FNMSUB)
/// - `0x4F` NMADD      (FNMADD)
/// - `0x53` OP-FP      (FP arithmetic)
/// - `0x57` OP-V       (vector arithmetic, vsetvl[i])
///
/// Returns `false` if `insn == 0`, which some implementations write to
/// `stval` instead of the trapping encoding — the caller must then treat
/// the trap as a non-FP/V illegal instruction.
#[allow(dead_code)] // Consumed by trap_dispatch in the same commit (build-order).
pub fn is_fp_or_v_opcode(insn: u64) -> bool
{
    if insn == 0
    {
        return false;
    }
    let major = (insn & 0x7F) as u8;
    matches!(major, 0x07 | 0x27 | 0x43 | 0x47 | 0x4B | 0x4F | 0x53 | 0x57)
}
