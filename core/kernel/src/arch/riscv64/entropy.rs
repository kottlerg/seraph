// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/entropy.rs

//! RISC-V hardware entropy primitives.
//!
//! The hardware RNG is the `Zkr` entropy source, read through its `seed` CSR
//! (0x015), which S-mode may read only where M-mode firmware grants it
//! (`mseccfg.SSEED`). S-mode cannot read `mseccfg`, and an ISA string that
//! names `zkr` says only that the hart implements the CSR, so the first
//! [`hw_rng_available`] call probes by reading it: on a hart without `Zkr`, or
//! one whose firmware left `SSEED` clear, the read raises an illegal-instruction
//! exception, which `interrupts::kernel_exception` recovers through
//! [`seed_fault_fixup`], and the source is absent. The samples are raw,
//! unconditioned entropy, which the caller health-gates; the source's place
//! among the pool's inputs is in `core/kernel/docs/entropy.md` § Sources and
//! graceful degradation.
//!
//! The raw cycle counter (the `time` CSR, always S-mode readable) feeds jitter
//! sampling. Same `arch::current` entropy contract as the x86-64 counterpart.

use core::sync::atomic::{AtomicU8, Ordering};

use super::encoding::{SeedError, SeedPoll, decode_seed, seed_word};
use crate::bounded_wait::WaitTimer;

/// [`SEED_SOURCE`] before the first [`hw_rng_available`] call.
const UNPROBED: u8 = 0;
/// [`SEED_SOURCE`] once the probe trapped or read `DEAD`, or a draw read `DEAD`.
const ABSENT: u8 = 1;
/// [`SEED_SOURCE`] once the probe read a status other than `DEAD`.
const PRESENT: u8 = 2;

/// Whether the `seed` CSR is a usable source: [`UNPROBED`], [`ABSENT`], or
/// [`PRESENT`]. The BSP alone reads the source, during Phase 5 seeding, so a
/// difference in `mseccfg.SSEED` between harts is never seen; the value
/// publishes no other data, so its accesses are `Relaxed`.
static SEED_SOURCE: AtomicU8 = AtomicU8::new(UNPROBED);

/// Time, in microseconds, one [`hw_rng_u64`] word may wait on a source that
/// reports `BIST` or `WAIT` before the draw gives up. A tuning value, not a
/// capacity: a physical source's sample rate is the platform's, and the
/// budget tolerates a slow one or a self-test at reset without stalling the
/// boot on one that never becomes ready.
const SEED_WORD_BUDGET_US: u64 = 10_000;

// `__seed_read` is the one `seed` CSR access: `csrrw a0, seed, zero` (CSR
// 0x015, written by number since the kernel target does not enable Zkr), the
// write form the specification requires, since a read-only access (`csrrs` or
// `csrrc` with `rs1 = x0`) is illegal; the written zero is ignored. It
// clobbers `a0`, its return value, alone, and touches no memory or stack. An
// illegal-instruction trap at the access (no `Zkr`, or `mseccfg.SSEED` clear)
// resumes at `__seed_fault_fixup`, which returns `u64::MAX`, a value whose
// `OPST` is `DEAD` and which no read can return (a status other than `ES16`
// carries zero entropy bits); see [`seed_fault_fixup`] for the hook.
core::arch::global_asm!(
    ".section .text.seed_read, \"ax\"",
    ".global __seed_read",
    ".global __seed_fault_start",
    ".global __seed_fault_end",
    ".global __seed_fault_fixup",
    // fn __seed_read() -> a0 (the `seed` value, or u64::MAX if the access trapped)
    "__seed_read:",
    "__seed_fault_start:",
    "    csrrw a0, 0x015, zero",
    "__seed_fault_end:",
    "    ret",
    "__seed_fault_fixup:",
    "    li    a0, -1",
    "    ret",
);

unsafe extern "C" {
    /// Read the `seed` CSR once; `u64::MAX` when the access trapped.
    fn __seed_read() -> u64;
    /// The `seed` access, the one faultable instruction of `__seed_read`.
    static __seed_fault_start: u8;
    /// First byte past the `seed` access.
    static __seed_fault_end: u8;
    /// Recovery landing pad: returns `u64::MAX`.
    static __seed_fault_fixup: u8;
}

/// Read the `seed` CSR once: its value, or `u64::MAX` when this hart cannot
/// read it.
fn read_seed() -> u64
{
    // SAFETY: `__seed_read` is the routine above, a C-ABI leaf that writes
    // `a0` alone and touches no memory. Its one instruction that can trap is
    // the `seed` access, whose illegal-instruction trap `kernel_exception`
    // resumes at the fixup through `seed_fault_fixup`; the kernel runs in
    // S-mode with `stvec` installed (Phase 5, before entropy seeding).
    unsafe { __seed_read() }
}

/// If `pc` is the `seed` CSR access, return the address of its recovery
/// fixup; otherwise `None`. Consulted by `interrupts::kernel_exception` on an
/// S-mode illegal-instruction trap, which redirects `sepc` to the fixup so the
/// read reports the source absent instead of halting the hart.
pub(super) fn seed_fault_fixup(pc: u64) -> Option<u64>
{
    let lo = core::ptr::addr_of!(__seed_fault_start) as u64;
    let hi = core::ptr::addr_of!(__seed_fault_end) as u64;
    if pc >= lo && pc < hi
    {
        Some(core::ptr::addr_of!(__seed_fault_fixup) as u64)
    }
    else
    {
        None
    }
}

/// Whether this hart can read the `Zkr` `seed` CSR. The first call probes it
/// by one read (see the module docs) and caches the answer: a trapped read or
/// a `DEAD` status is absent, any other status present; a later `DEAD` draw
/// turns it absent.
pub fn hw_rng_available() -> bool
{
    match SEED_SOURCE.load(Ordering::Relaxed)
    {
        UNPROBED =>
        {
            let present = decode_seed(read_seed()) != SeedPoll::Dead;
            SEED_SOURCE.store(if present { PRESENT } else { ABSENT }, Ordering::Relaxed);
            present
        }
        source => source == PRESENT,
    }
}

/// Draw a 64-bit hardware-RNG word from four `seed` samples, or `None` if the
/// source is absent, read `DEAD` (which latches it absent), or stayed in
/// `BIST` or `WAIT` past [`SEED_WORD_BUDGET_US`].
pub fn hw_rng_u64() -> Option<u64>
{
    if !hw_rng_available()
    {
        return None;
    }
    let mut wait = WaitTimer::start(super::timer::elapsed_us());
    let word = seed_word(read_seed, || {
        wait.elapsed(super::timer::elapsed_us()) >= SEED_WORD_BUDGET_US
    });
    match word
    {
        Ok(word) => Some(word),
        Err(SeedError::Dead) =>
        {
            SEED_SOURCE.store(ABSENT, Ordering::Relaxed);
            None
        }
        Err(SeedError::TimedOut) => None,
    }
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
