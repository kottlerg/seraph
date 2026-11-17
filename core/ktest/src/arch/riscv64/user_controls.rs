// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/user_counters.rs

//! The riscv64 half of `integration::user_counter_grants`: the counters U-mode
//! is denied, and the fault a read of one raises.
//!
//! The kernel writes `scounteren` whole with `CY` alone on every hart, so a
//! U-mode read of `time`, `instret` or `hpmcounter3` raises an
//! illegal-instruction exception. Where the SBI firmware takes the trap first
//! (to emulate a counter the hart lacks), it hands a read `scounteren` denies
//! on to the kernel as the same exception.
//! A firmware that leaves `TM` or `IR` set fails the case where the kernel
//! keeps that bit. The granted `cycle` read is
//! the one `crate::arch::cycles_now` makes. The exception's `stval` holds the
//! instruction or zero, at the hart's and the firmware's choice, so the case
//! does not check it.

use core::sync::atomic::AtomicU64;

use syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION;

use crate::integration::user_counter_grants::DeniedCounter;

/// The counters U-mode is denied: `time`, `instret`, and the first
/// programmable counter, `hpmcounter3`.
pub const DENIED: &[DeniedCounter] = &[
    DeniedCounter {
        read: read_time,
        not_denied: "integration::user_counter_grants: a U-mode read of time did not trap",
    },
    DeniedCounter {
        read: read_instret,
        not_denied: "integration::user_counter_grants: a U-mode read of instret did not trap",
    },
    DeniedCounter {
        read: read_hpmcounter3,
        not_denied: "integration::user_counter_grants: a U-mode read of hpmcounter3 did not trap",
    },
];

/// The fault class of a denied read: an illegal-instruction exception.
pub const DENIED_FAULT: u64 = FAULT_EXC_ILLEGAL_INSTRUCTION;

/// No error code is checked (`stval`, above).
pub const DENIED_FAULT_CODE: Option<u64> = None;

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
