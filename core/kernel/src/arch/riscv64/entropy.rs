// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/entropy.rs

//! RISC-V hardware entropy primitives.
//!
//! No S-mode-accessible hardware RNG is exposed: the `Zkr` `seed` CSR is
//! M-mode-gated (`mseccfg.SSEED`) and unavailable to S-mode under default
//! `OpenSBI`, and there is no standard SBI entropy call. [`hw_rng_available`] is
//! therefore `false` and the subsystem runs on jitter alone — the documented
//! graceful-degradation path (see `core/kernel/docs/entropy.md`). Enabling the
//! `seed` CSR is future work requiring M-mode cooperation.
//!
//! The raw cycle counter (the `time` CSR, always S-mode readable) feeds jitter
//! sampling. Same `arch::current` entropy contract as the x86-64 counterpart.

/// No S-mode hardware RNG under current firmware. See the module docs.
pub fn hw_rng_available() -> bool
{
    false
}

/// Always `None`: no S-mode hardware RNG. See [`hw_rng_available`].
pub fn hw_rng_u64() -> Option<u64>
{
    None
}

/// Read the `time` CSR for jitter sampling. S-mode readable, no side effects;
/// use deltas only.
pub fn read_cycle_counter() -> u64
{
    let t: u64;
    // SAFETY: the time CSR is always readable in S-mode; read-only.
    unsafe {
        core::arch::asm!("csrr {0}, time", out(reg) t, options(nostack, nomem));
    }
    t
}
