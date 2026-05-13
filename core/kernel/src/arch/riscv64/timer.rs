// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/timer.rs

//! RISC-V supervisor-mode timer using the SBI timer extension.
//!
//! The RISC-V time-compare mechanism works by scheduling a deadline:
//! when `time` CSR ≥ `timecmp`, a supervisor timer interrupt fires.
//!
//! The timebase frequency is hardcoded to 10 MHz, which matches the reference
//! platform and every test target the kernel runs on. The boot protocol does
//! not yet carry this value; on hardware whose timebase differs the kernel
//! would still boot but its time-derived deadlines would be miscalibrated.
//!
//! # SBI timer extension
//! Extension ID `0x54494D45` ("TIME"), function ID 0.
//! - a7 = extension ID
//! - a6 = function ID (0 = `sbi_set_timer`)
//! - a0 = timer value (next deadline)
//!
//! # Modification notes
//! - To use the `sstc` extension instead of SBI: write `stimecmp` CSR directly.

use core::sync::atomic::{AtomicU64, Ordering};

use super::interrupts;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default RISC-V `time` CSR tick rate (10 MHz). Matches the reference
/// platform; bootloader handoff for the discovered value is not yet wired.
const TIMEBASE_FREQ: u64 = 10_000_000;

/// SBI TIME extension ID: ASCII "TIME" = 0x54494D45.
const SBI_EXT_TIME: u64 = 0x5449_4D45;

// ── Tick state ────────────────────────────────────────────────────────────────

/// Number of timer ticks per period; returned by [`ticks_per_second`].
static TICKS_PER_SEC: AtomicU64 = AtomicU64::new(0);

/// Ticks per period (stored to rearm the timer on each interrupt).
static TIMER_PERIOD_TICKS: AtomicU64 = AtomicU64::new(0);

// ── High-resolution time state ────────────────────────────────────────────────

/// `time` CSR value recorded at the end of `init()` ("boot time = 0").
/// Zero means not yet initialised.
static BOOT_TIME_TICKS: AtomicU64 = AtomicU64::new(0);

/// `time` CSR ticks per microsecond. At 10 MHz: 10 ticks/µs.
const TIME_TICKS_PER_US: u64 = TIMEBASE_FREQ / 1_000_000;

// ── SBI helper ────────────────────────────────────────────────────────────────

/// Call the SBI timer extension to set the next timer deadline.
///
/// `val` is the absolute `time` CSR value at which the next interrupt fires.
fn sbi_set_timer(val: u64)
{
    // SAFETY: SBI ecall is always available in RISC-V supervisor mode.
    unsafe {
        core::arch::asm!(
            "ecall",
            inout("a0") val => _,
            // a1 unused (high 32 bits for RV32; zero for RV64).
            inout("a1") 0u64 => _,
            // a6 = function ID 0 (sbi_set_timer).
            inout("a6") 0u64 => _,
            // a7 = extension ID.
            inout("a7") SBI_EXT_TIME => _,
            options(nostack, nomem),
        );
    }
}

/// Read the `time` CSR (supervisor-mode read of the machine-mode timer).
#[cfg(not(test))]
fn read_time() -> u64
{
    let t: u64;
    // SAFETY: time CSR is always readable in S-mode; read-only, no side effects.
    unsafe {
        core::arch::asm!("csrr {0}, time", out(reg) t, options(nostack, nomem));
    }
    t
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise the supervisor timer for periodic preemption at `period_us` µs.
///
/// Sets the first SBI timer deadline, stores the period, and enables
/// supervisor interrupts (`sstatus.SIE`).
///
/// Must be called after `interrupts::init()`.
///
/// # Safety
/// Must execute in supervisor mode from a single-threaded context.
#[cfg(not(test))]
pub unsafe fn init(period_us: u64)
{
    let period_ticks = TIMEBASE_FREQ * period_us / 1_000_000;
    TIMER_PERIOD_TICKS.store(period_ticks, Ordering::Relaxed);
    TICKS_PER_SEC.store(1_000_000 / period_us, Ordering::Relaxed);

    let now = read_time();
    let deadline = now + period_ticks;
    sbi_set_timer(deadline);

    // Record the high-resolution boot reference: the `time` CSR value at the
    // moment the timer is armed. Used by elapsed_us() for timestamps.
    BOOT_TIME_TICKS.store(now, Ordering::Relaxed);

    // Enable supervisor interrupts — the timer will now fire.
    // SAFETY: stvec is installed.
    unsafe {
        interrupts::enable();
    }
}

/// Initialise the supervisor timer on an AP hart using the BSP's stored tick rate.
///
/// The BSP must have called [`init`] first to populate [`TIMER_PERIOD_TICKS`].
/// Sets the first SBI timer deadline and enables supervisor interrupts.
///
/// # Safety
/// Must execute in supervisor mode on the AP being initialised.
/// [`interrupts::init_ap`] must have been called first to configure `stvec`
/// and `sie` before enabling interrupts here.
#[cfg(not(test))]
pub unsafe fn init_ap(period_us: u64)
{
    let period_ticks = TIMER_PERIOD_TICKS.load(Ordering::Relaxed);
    if period_ticks == 0
    {
        // BSP calibration not yet done — fall back to computing from period_us.
        // This path should not occur in practice since APs start after Phase 5.
        let fallback = TIMEBASE_FREQ * period_us / 1_000_000;
        sbi_set_timer(read_time() + fallback);
    }
    else
    {
        sbi_set_timer(read_time() + period_ticks);
    }
    // Enable supervisor interrupts — the timer will now fire.
    // SAFETY: stvec is installed (interrupts::init_ap called first).
    unsafe {
        interrupts::enable();
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn init_ap(_period_us: u64) {}

/// Handle a supervisor timer interrupt.
///
/// Called from `trap_dispatch` on scause = 5 (supervisor timer interrupt).
/// Rearms the timer, then calls the scheduler tick which may preempt the
/// current thread. The monotonic tick counter is derived from the `time`
/// CSR (see [`current_tick`]) so that sleep deadlines stay phase-locked
/// with userspace `Instant::now()` regardless of which hart delivers the
/// next ISR.
pub fn handle_tick()
{
    let period = TIMER_PERIOD_TICKS.load(Ordering::Relaxed);
    // Rearm timer before calling schedule() so the next tick is not missed.
    #[cfg(not(test))]
    sbi_set_timer(read_time() + period);
    // SAFETY: called from interrupt handler on a valid kernel stack.
    #[cfg(not(test))]
    unsafe {
        crate::sched::timer_tick();
    }
}

/// Return the current monotonic tick count.
///
/// Derived from the `time` CSR so that sleep deadlines and userspace
/// `Instant::now()` (which reads `elapsed_us` via `SYS_SYSTEM_INFO`) share
/// a single counter. Returns `0` if `init()` has not yet been called.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
#[cfg(not(test))]
pub fn current_tick() -> u64
{
    let Some(us) = elapsed_us()
    else
    {
        return 0;
    };
    let tps = TICKS_PER_SEC.load(Ordering::Relaxed);
    if tps == 0
    {
        return 0;
    }
    us.saturating_mul(tps) / 1_000_000
}

/// Test stub — host tests have no `time` CSR.
#[cfg(test)]
pub fn current_tick() -> u64
{
    0
}

/// Return the configured number of ticks per second.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn ticks_per_second() -> u64
{
    TICKS_PER_SEC.load(Ordering::Relaxed)
}

/// Return microseconds elapsed since timer initialisation, or `None` if
/// `init()` has not yet been called (pre-Phase 5).
///
/// Uses the `time` CSR directly — no interrupt dependency. At 10 MHz the
/// resolution is 100 ns (0.1 µs); returned value is truncated to whole µs.
#[cfg(not(test))]
pub fn elapsed_us() -> Option<u64>
{
    let boot = BOOT_TIME_TICKS.load(Ordering::Relaxed);
    if boot == 0
    {
        return None;
    }
    Some((read_time().saturating_sub(boot)) / TIME_TICKS_PER_US)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn default_timebase_freq_is_10_mhz()
    {
        assert_eq!(TIMEBASE_FREQ, 10_000_000);
    }

    #[test]
    fn period_ticks_for_10ms()
    {
        // 10 ms = 10_000 µs → 10_000_000 * 10_000 / 1_000_000 = 100_000 ticks.
        let ticks = TIMEBASE_FREQ * 10_000 / 1_000_000;
        assert_eq!(ticks, 100_000);
    }

    #[test]
    fn period_ticks_for_1ms()
    {
        let ticks = TIMEBASE_FREQ * 1_000 / 1_000_000;
        assert_eq!(ticks, 10_000);
    }

    #[test]
    fn sbi_ext_time_constant()
    {
        // ASCII "TIME" = 0x54494D45.
        assert_eq!(SBI_EXT_TIME, 0x5449_4D45);
    }
}
