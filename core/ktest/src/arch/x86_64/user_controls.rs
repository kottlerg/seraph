// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/user_counters.rs

//! The x86-64 half of `integration::user_counter_grants`: the counter ring 3
//! is denied, and the fault a read of it raises.
//!
//! The kernel clears `CR4.PCE` on every CPU (`cpu::enable_smep_smap`), so a
//! ring-3 `RDPMC` raises `#GP(0)`. With `CR4.PCE` set, `RDPMC` of counter 0
//! completes where the CPU has that counter (CPUID leaf 0AH reports at least
//! one general-purpose counter), and raises `#UD` under QEMU's TCG; either
//! fails the case. On a CPU with no performance counter, `RDPMC` raises
//! `#GP(0)` for every index whatever `CR4.PCE`, so there the case shows the
//! read faults and not which control faulted it. The granted timestamp counter
//! (`CR4.TSD` clear) is the read `crate::arch::cycles_now` makes.

use core::sync::atomic::AtomicU64;

use syscall_abi::FAULT_EXC_PROTECTION;

use crate::integration::user_counter_grants::DeniedCounter;

/// The counters ring 3 is denied: the performance counters, through `RDPMC`.
pub const DENIED: &[DeniedCounter] = &[DeniedCounter {
    read: read_pmc0,
    not_denied: "integration::user_counter_grants: ring-3 RDPMC did not raise #GP",
}];

/// The fault class of a denied read: `#GP`.
pub const DENIED_FAULT: u64 = FAULT_EXC_PROTECTION;

/// The error code of a denied read's `#GP`.
pub const DENIED_FAULT_CODE: Option<u64> = Some(0);

/// Store the address of an `RDPMC` of counter 0 into `slot`, then execute it.
fn read_pmc0(slot: &AtomicU64)
{
    let slot = slot.as_ptr();
    // SAFETY: `lea` and the store use the scratch register `t` and write only
    // the `AtomicU64` behind `slot`; `rdpmc` reads counter ECX = 0 into EDX:EAX,
    // both declared clobbered, and touches no memory or flag. Under
    // `CR4.PCE` clear it raises #GP and writes nothing.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            "rdpmc",
            t = out(reg) _,
            slot = in(reg) slot,
            inout("ecx") 0u32 => _,
            out("eax") _,
            out("edx") _,
            options(nostack, preserves_flags),
        );
    }
}
