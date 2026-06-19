// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/entropy.rs

//! RISC-V hardware entropy primitives.
//!
//! No S-mode-accessible hardware RNG is exposed: the `Zkr` `seed` CSR is
//! M-mode-owned (`mseccfg.SSEED`) and unavailable to S-mode under default
//! `OpenSBI`, and there is no standard SBI entropy call. [`hw_rng_available`] is
//! therefore `false` — this in-kernel arch path provides no hardware RNG by
//! design. Early-boot entropy is meant to arrive as a conditioned seed the
//! bootloader draws from UEFI `EFI_RNG_PROTOCOL` and passes in `BootInfo`, but
//! the current riscv64 EDK2 does not implement that protocol, so today riscv64
//! seeds from timing jitter alone (see `core/kernel/docs/entropy.md`). Exposing
//! a firmware seed, and a *runtime* riscv64 hardware-RNG source via a userspace
//! virtio-rng/hwrng driver — the mechanism the RISC-V design intends for lower
//! privilege levels — are tracked as future work.
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
