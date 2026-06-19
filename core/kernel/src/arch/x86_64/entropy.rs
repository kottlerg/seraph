// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/entropy.rs

//! x86-64 hardware entropy primitives.
//!
//! Hardware RNG via RDSEED (a conditioned seed, preferred for seeding a
//! CSPRNG) with an RDRAND fallback, gated on CPUID support; plus the raw cycle
//! counter (TSC) used for jitter sampling. Part of the `arch::current` entropy
//! contract; the RISC-V counterpart in `arch/riscv64/entropy.rs` exposes the
//! same signatures.

use super::cpu::cpuid;

/// CPUID.01H:ECX bit 30 — RDRAND support.
const RDRAND_BIT: u32 = 1 << 30;
/// CPUID.07H:EBX bit 18 — RDSEED support.
const RDSEED_BIT: u32 = 1 << 18;

/// Whether the CPU exposes a hardware RNG instruction (RDRAND or RDSEED).
pub fn hw_rng_available() -> bool
{
    cpuid(1).2 & RDRAND_BIT != 0 || cpuid(7).1 & RDSEED_BIT != 0
}

/// Draw a 64-bit hardware-RNG word, or `None` if no source succeeded.
///
/// Prefers RDSEED (the seed-grade source); falls back to RDRAND. Both set CF=1
/// on success; a bounded retry tolerates the transient CF=0 the ISA permits.
pub fn hw_rng_u64() -> Option<u64>
{
    if cpuid(7).1 & RDSEED_BIT != 0
        && let Some(v) = rdseed_u64()
    {
        return Some(v);
    }
    if cpuid(1).2 & RDRAND_BIT != 0
    {
        return rdrand_u64();
    }
    None
}

/// One RDSEED word with bounded retry; `None` if the source stayed unready.
fn rdseed_u64() -> Option<u64>
{
    for _ in 0..32
    {
        let val: u64;
        let ok: u8;
        // SAFETY: RDSEED is valid when CPUID.07H:EBX[18]=1 (caller-checked). It
        // writes the destination register and sets CF (captured via setc);
        // it affects flags so preserves_flags is omitted.
        unsafe {
            core::arch::asm!(
                "rdseed {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) ok,
                options(nostack, nomem),
            );
        }
        if ok != 0
        {
            return Some(val);
        }
        core::hint::spin_loop();
    }
    None
}

/// One RDRAND word with bounded retry; `None` if the source stayed unready.
fn rdrand_u64() -> Option<u64>
{
    for _ in 0..32
    {
        let val: u64;
        let ok: u8;
        // SAFETY: RDRAND is valid when CPUID.01H:ECX[30]=1 (caller-checked); as
        // RDSEED above, it writes the register and sets CF.
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) ok,
                options(nostack, nomem),
            );
        }
        if ok != 0
        {
            return Some(val);
        }
        core::hint::spin_loop();
    }
    None
}

/// Read the Time Stamp Counter for jitter sampling. Use deltas only.
pub fn read_cycle_counter() -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc does not fault at ring 0; writes EAX/EDX only.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    u64::from(hi) << 32 | u64::from(lo)
}
