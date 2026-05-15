// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/fpu.rs

//! RISC-V extended-state (F / D / V) control primitives.
//!
//! Concentrates the unsafe surface for FP and Vector state management.
//! The boot invariant is `sstatus.FS = sstatus.VS = 00 (Off)`. Any F/D or V
//! instruction in U-mode raises an illegal-instruction trap (`scause = 2`);
//! the trap handler decodes the opcode (see [`is_fp_or_v_opcode`]) and
//! lazy-restores via [`lazy_restore_fp_v`].
//!
//! The scheduler calls [`switch_out_save`] on switch-out of every user
//! thread. It reads `sstatus.FS`: when `FS == 11 (Dirty)`, the live F/D
//! register file is saved to the thread's per-TCB area; `sstatus.FS` is
//! then forced back to `00 (Off)` to re-arm the lazy trap. The same
//! pattern is intended for V state, but V-register save under preemption
//! is deferred to a follow-up commit (see the head-of-branch design
//! notes).

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
pub fn is_fp_or_v_opcode(insn: u64) -> bool
{
    if insn == 0
    {
        return false;
    }
    let major = (insn & 0x7F) as u8;
    matches!(major, 0x07 | 0x27 | 0x43 | 0x47 | 0x4B | 0x4F | 0x53 | 0x57)
}

/// Save the live F/D register file to `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller (`switch_out_save`)
/// verifies this by checking the field is `Dirty`.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at a per-thread
/// F/D save area allocated by [`alloc_area`]. `sstatus.FS` must be non-Off.
#[cfg(not(test))]
#[inline]
unsafe fn save_fp_to(area: *mut u8)
{
    // .option arch, +d locally enables the D extension for the assembler
    // even though the kernel target is RV64IMAC. The CPU executes these
    // instructions only when FS is non-Off, which the caller enforces.
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fsd f0,    0({a})",
            "fsd f1,    8({a})",
            "fsd f2,   16({a})",
            "fsd f3,   24({a})",
            "fsd f4,   32({a})",
            "fsd f5,   40({a})",
            "fsd f6,   48({a})",
            "fsd f7,   56({a})",
            "fsd f8,   64({a})",
            "fsd f9,   72({a})",
            "fsd f10,  80({a})",
            "fsd f11,  88({a})",
            "fsd f12,  96({a})",
            "fsd f13, 104({a})",
            "fsd f14, 112({a})",
            "fsd f15, 120({a})",
            "fsd f16, 128({a})",
            "fsd f17, 136({a})",
            "fsd f18, 144({a})",
            "fsd f19, 152({a})",
            "fsd f20, 160({a})",
            "fsd f21, 168({a})",
            "fsd f22, 176({a})",
            "fsd f23, 184({a})",
            "fsd f24, 192({a})",
            "fsd f25, 200({a})",
            "fsd f26, 208({a})",
            "fsd f27, 216({a})",
            "fsd f28, 224({a})",
            "fsd f29, 232({a})",
            "fsd f30, 240({a})",
            "fsd f31, 248({a})",
            "csrr {tmp}, fcsr",
            "sd {tmp}, 256({a})",
            ".option pop",
            a = in(reg) area,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Restore the F/D register file from `area`.
///
/// Precondition: `sstatus.FS` is not `Off`. Caller (`lazy_restore_fp_v`)
/// has just promoted FS to Initial.
///
/// # Safety
/// Must execute in supervisor mode. `area` must point at a per-thread
/// F/D save area previously written by [`save_fp_to`] or zero-initialised
/// by [`alloc_area`] (the zeroed area restores to f0..f31 = 0.0 and
/// fcsr = 0, matching the architected initial FP state).
#[cfg(not(test))]
#[inline]
unsafe fn restore_fp_from(area: *const u8)
{
    // SAFETY: caller's contract.
    unsafe {
        core::arch::asm!(
            ".option push",
            ".option arch, +d",
            "fld f0,    0({a})",
            "fld f1,    8({a})",
            "fld f2,   16({a})",
            "fld f3,   24({a})",
            "fld f4,   32({a})",
            "fld f5,   40({a})",
            "fld f6,   48({a})",
            "fld f7,   56({a})",
            "fld f8,   64({a})",
            "fld f9,   72({a})",
            "fld f10,  80({a})",
            "fld f11,  88({a})",
            "fld f12,  96({a})",
            "fld f13, 104({a})",
            "fld f14, 112({a})",
            "fld f15, 120({a})",
            "fld f16, 128({a})",
            "fld f17, 136({a})",
            "fld f18, 144({a})",
            "fld f19, 152({a})",
            "fld f20, 160({a})",
            "fld f21, 168({a})",
            "fld f22, 176({a})",
            "fld f23, 184({a})",
            "fld f24, 192({a})",
            "fld f25, 200({a})",
            "fld f26, 208({a})",
            "fld f27, 216({a})",
            "fld f28, 224({a})",
            "fld f29, 232({a})",
            "fld f30, 240({a})",
            "fld f31, 248({a})",
            "ld {tmp}, 256({a})",
            "csrw fcsr, {tmp}",
            ".option pop",
            a = in(reg) area,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Context-switch hook: if `sstatus.FS == Dirty`, save the live F/D state
/// to `area`. Always force `sstatus.FS = sstatus.VS = 00 (Off)` afterwards
/// so the next user F/D or V instruction takes the lazy trap.
///
/// Calling this with `area == null` is incorrect — kernel-only threads
/// (whose `extended.area` is null) never reach this hook because the
/// scheduler guards on the area pointer.
///
/// # Safety
/// Must execute in supervisor mode with interrupts disabled.
#[cfg(not(test))]
#[inline]
pub unsafe fn switch_out_save(area: *mut u8)
{
    let sstatus: u64;
    // SAFETY: csrr sstatus is a privileged S-mode read.
    unsafe {
        core::arch::asm!(
            "csrr {0}, sstatus",
            out(reg) sstatus,
            options(nostack, nomem),
        );
    }
    let fs = (sstatus >> 13) & 0x3;
    if fs == 0x3
    {
        // SAFETY: FS = Dirty, so the FP register file is live and fsd
        // executes without trapping.
        unsafe {
            save_fp_to(area);
        }
    }
    // Force FS = VS = Off to re-arm the lazy trap.
    // SAFETY: csrc sstatus is privileged S-mode; mask is architected.
    unsafe {
        core::arch::asm!(
            "csrc sstatus, {mask}",
            mask = in(reg) (SSTATUS_FS_MASK | SSTATUS_VS_MASK),
            options(nostack, nomem),
        );
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn switch_out_save(_area: *mut u8) {}

/// Lazy-trap handler body: promote `sstatus.FS` and `sstatus.VS` from Off
/// to Initial, then restore the F/D register file from `area` if non-null.
/// V state is intentionally not restored — V-register save+restore is
/// deferred to a follow-up commit.
///
/// # Safety
/// Must execute in supervisor mode from the illegal-instruction trap path.
#[cfg(not(test))]
#[inline]
pub unsafe fn lazy_restore_fp_v(area: *const u8)
{
    // SAFETY: csrs sstatus is privileged S-mode; this is the architected
    // FS/VS promotion sequence.
    unsafe {
        lazy_enable_fp_v_initial();
    }
    if !area.is_null()
    {
        // SAFETY: area is a valid F/D save area pointer or zero-initialised
        // (Box::new zeroes the [u64; 33]).
        unsafe {
            restore_fp_from(area);
        }
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn lazy_restore_fp_v(_area: *const u8) {}
