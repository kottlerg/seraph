// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/user_controls.rs

//! The riscv64 half of `integration::user_mode_controls`: the instructions
//! U-mode is denied, and the fault each raises.
//!
//! The kernel writes `scounteren` whole with `CY` alone on every hart, so a
//! U-mode read of `time`, `instret` or `hpmcounter3` raises an
//! illegal-instruction exception, and `senvcfg` whole with no field set, so
//! does a U-mode cache-block operation or read of `ssp`. A hart without
//! Zicbom, Zicboz or Zicfiss raises the same exception whatever `senvcfg`
//! holds, and there the entry shows the instruction traps, not which control
//! trapped it. Where the SBI firmware takes the trap first
//! (to emulate a counter the hart lacks), it hands a read `scounteren` denies
//! on to the kernel as the same exception.
//! A firmware that leaves `TM` or `IR` set fails the case where the kernel
//! keeps that bit. The granted `cycle` read is
//! the one `bench::Counters` makes. The exception's `stval` holds the
//! instruction or zero, at the hart's and the firmware's choice, so the case
//! does not check it.

use core::sync::atomic::AtomicU64;

use syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION;

use crate::integration::user_mode_controls::{DeniedInstruction, StateCheck};

/// No granted control has a state to check beyond the `cycle` read
/// `bench::Counters` makes.
pub const STATE_CHECKS: &[StateCheck] = &[];

/// The instructions U-mode is denied: reads of the counters `time`,
/// `instret` and the first programmable counter, `hpmcounter3`
/// (`scounteren`); the cache-block operations (`senvcfg.CBZE`, `CBCFE`,
/// `CBIE`); and a read of the shadow-stack pointer `ssp` (`senvcfg.SSE`).
/// Each raises an illegal-instruction exception; no error code is checked
/// (`stval`, above).
pub const DENIED: &[DeniedInstruction] = &[
    DeniedInstruction {
        exec: read_time,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode read of time did not trap",
    },
    DeniedInstruction {
        exec: read_instret,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode read of instret did not trap",
    },
    DeniedInstruction {
        exec: read_hpmcounter3,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode read of hpmcounter3 did not trap",
    },
    DeniedInstruction {
        exec: cbo_zero,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode cbo.zero did not trap",
    },
    DeniedInstruction {
        exec: cbo_clean,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode cbo.clean did not trap",
    },
    DeniedInstruction {
        exec: cbo_flush,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode cbo.flush did not trap",
    },
    DeniedInstruction {
        exec: cbo_inval,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode cbo.inval did not trap",
    },
    DeniedInstruction {
        exec: read_ssp,
        fault: FAULT_EXC_ILLEGAL_INSTRUCTION,
        fault_code: None,
        not_denied: "integration::user_mode_controls: a U-mode read of ssp did not trap",
    },
];

/// A function that stores the address of a `csrr` of `$csr` into its slot,
/// then executes it.
macro_rules! denied_read {
    ($name:ident, $csr:literal) => {
        #[doc = concat!("Store the address of a `csrr` of `", $csr, "` into `slot`, then execute it.")]
        fn $name(slot: &AtomicU64)
        {
            let slot = slot.as_ptr();
            // SAFETY: `lla` and the store use the scratch register `t` and
            // write only the `AtomicU64` behind `slot`; the `csrr` writes only
            // `v`, and a denied one raises an illegal-instruction exception
            // and writes nothing. RISC-V has no flags register.
            unsafe {
                core::arch::asm!(
                    "lla {t}, 2f",
                    "sd {t}, 0({slot})",
                    "2:",
                    concat!("csrr {v}, ", $csr),
                    t = out(reg) _,
                    v = out(reg) _,
                    slot = in(reg) slot,
                    options(nostack),
                );
            }
        }
    };
}

denied_read!(read_time, "time");
denied_read!(read_instret, "instret");
denied_read!(read_hpmcounter3, "hpmcounter3");
// `ssp` is CSR 0x011, named by number: the assembler knows the name only
// under the Zicfiss target feature.
denied_read!(read_ssp, "0x011");

/// A page-aligned page of the child's memory, the target of the cache-block
/// operations: a cache block lies within one page.
#[repr(C, align(4096))]
struct CboTarget([u8; 4096]);

/// The page the cache-block operations name. Written only if an operation
/// that should trap completes, which fails the case.
static mut CBO_TARGET: CboTarget = CboTarget([0; 4096]);

/// A function that stores the address of the cache-block operation `$op`
/// (its `funct12`, `$funct12`) on [`CBO_TARGET`] into its slot, then
/// executes it.
macro_rules! denied_cbo {
    ($name:ident, $op:literal, $funct12:literal) => {
        #[doc = concat!("Store the address of a `", $op, "` on [`CBO_TARGET`] into `slot`, then execute it.")]
        fn $name(slot: &AtomicU64)
        {
            let slot = slot.as_ptr();
            let target = core::ptr::addr_of_mut!(CBO_TARGET).cast::<u8>();
            // SAFETY: `lla` and the store use the scratch register `t` and
            // write only the `AtomicU64` behind `slot`. The operation
            // (MISC-MEM, `funct3` 2, written with `.insn` because the
            // assembler knows the mnemonic only under the Zicbom and Zicboz
            // target features) names `CBO_TARGET`, a page of this child's
            // writable memory that nothing else reads; a denied one raises an
            // illegal-instruction exception and changes nothing. RISC-V has
            // no flags register.
            unsafe {
                core::arch::asm!(
                    "lla {t}, 2f",
                    "sd {t}, 0({slot})",
                    "2:",
                    concat!(".insn i 0x0f, 2, x0, {target}, ", $funct12),
                    t = out(reg) _,
                    slot = in(reg) slot,
                    target = in(reg) target,
                    options(nostack),
                );
            }
        }
    };
}

denied_cbo!(cbo_inval, "cbo.inval", "0");
denied_cbo!(cbo_clean, "cbo.clean", "1");
denied_cbo!(cbo_flush, "cbo.flush", "2");
denied_cbo!(cbo_zero, "cbo.zero", "4");
