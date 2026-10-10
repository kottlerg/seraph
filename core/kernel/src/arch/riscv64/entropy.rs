// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/entropy.rs

//! RISC-V hardware entropy primitives.
//!
//! No S-mode hardware RNG is available on riscv64, so [`hw_rng_available`] is
//! `false`; the reason, the firmware boot seed that replaces it, and the
//! degradation to jitter are documented in `core/kernel/docs/entropy.md`
//! § Sources and graceful degradation (S-mode hardware entropy: #393).
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
