// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/timer.rs

//! RISC-V supervisor-mode timer using the Sstc extension (`stimecmp` CSR).
//!
//! The RISC-V time-compare mechanism works by scheduling a deadline: the
//! supervisor timer interrupt is pending exactly while `time` CSR ≥
//! `stimecmp`, so writing a future deadline both re-arms the timer and
//! clears the pending condition — no firmware round-trip per tick.
//!
//! The timebase frequency is discovered by the bootloader (ACPI RHCT or the
//! DTB `/cpus` `timebase-frequency` property) and carried in
//! `KernelMmio::timebase_freq`. Sstc support, likewise discovered per hart,
//! is carried in `KernelMmio::hart_caps`. [`init`] refuses to boot when
//! either is missing: Sstc is RVA23-mandated and classified Required by
//! [platform-requirements.md](../../../../docs/platform-requirements.md),
//! and there is no compiled-in timebase fallback.

use core::sync::atomic::{AtomicU64, Ordering};

use super::interrupts;

// ── Constants ─────────────────────────────────────────────────────────────────

/// `stimecmp` CSR number (Sstc extension). Written by CSR number because the
/// kernel's target feature set (`+m,+a,+c`) does not enable the Sstc
/// mnemonics in the assembler.
#[cfg(not(test))]
const CSR_STIMECMP: u16 = 0x14D;

// ── Tick state ────────────────────────────────────────────────────────────────

/// Number of timer ticks per period; returned by [`ticks_per_second`].
static TICKS_PER_SEC: AtomicU64 = AtomicU64::new(0);

/// Ticks per period (stored to rearm the timer on each interrupt).
static TIMER_PERIOD_TICKS: AtomicU64 = AtomicU64::new(0);

// ── High-resolution time state ────────────────────────────────────────────────

/// `time` CSR value recorded at the end of `init()` ("boot time = 0").
/// Zero means not yet initialised.
static BOOT_TIME_TICKS: AtomicU64 = AtomicU64::new(0);

/// Discovered `time` CSR frequency in Hz. Written once by [`init`] (which
/// validates it as non-zero and ≤ `u32::MAX`); zero before that.
static TIMEBASE_FREQ_HZ: AtomicU64 = AtomicU64::new(0);

// ── CSR helpers ───────────────────────────────────────────────────────────────

/// Write the Sstc supervisor timer compare CSR with the next deadline.
///
/// `val` is the absolute `time` CSR value at which the next interrupt fires.
/// The supervisor timer pending bit (`sip.STIP`) is a hardware comparison
/// (`time` ≥ `stimecmp`), so a future deadline also clears a pending tick.
#[cfg(not(test))]
fn write_stimecmp(val: u64)
{
    // SAFETY: S-mode CSR write, no memory access. Requires the Sstc
    // extension and M-mode delegation (`menvcfg.STCE`), both established
    // by the boot firmware on hardware that passes init()'s Sstc gate.
    unsafe {
        core::arch::asm!(
            "csrw {csr}, {val}",
            csr = const CSR_STIMECMP,
            val = in(reg) val,
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

// ── Tick math (pure, host-testable) ───────────────────────────────────────────

/// Ticks of a `freq` Hz counter in a period of `period_us` microseconds.
// The product is computed in u128 so arbitrary discovered frequencies cannot
// overflow; the quotient fits u64 for every freq ≤ u32::MAX (enforced by
// `init`) and sane period.
#[allow(clippy::cast_possible_truncation)]
fn ticks_for_period(freq: u64, period_us: u64) -> u64
{
    (u128::from(freq) * u128::from(period_us) / 1_000_000) as u64
}

/// Convert `ticks` of a `freq` Hz counter to whole microseconds.
///
/// Exact for arbitrary frequencies via a div/mod split: the remainder
/// product `(ticks % freq) * 1_000_000` cannot overflow because `init`
/// bounds `freq` to `u32::MAX` (< 2^32 · 2^20 = 2^52). Returns 0 when
/// `freq` is zero (timer not initialised).
fn ticks_to_us(ticks: u64, freq: u64) -> u64
{
    if freq == 0
    {
        return 0;
    }
    (ticks / freq) * 1_000_000 + (ticks % freq) * 1_000_000 / freq
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise the supervisor timer for periodic preemption at `period_us` µs.
///
/// Verifies the bootloader-discovered hart capabilities (Sstc) and timebase,
/// arms the first `stimecmp` deadline, stores the period, and enables
/// supervisor interrupts (`sstatus.SIE`). Refuses to boot — with a
/// diagnostic — on hardware without Sstc or without a discovered timebase,
/// per the subsystem-gate policy in
/// [platform-requirements.md](../../../../docs/platform-requirements.md).
///
/// Must be called after `interrupts::init()` and after
/// `platform::capture_kernel_mmio()`.
///
/// # Safety
/// Must execute in supervisor mode from a single-threaded context.
#[cfg(not(test))]
pub unsafe fn init(period_us: u64)
{
    let km = crate::platform::kernel_mmio();

    if km.hart_caps & boot_protocol::HART_CAP_SSTC == 0
    {
        crate::fatal(
            "Sstc (stimecmp) not advertised for every hart — required (RVA23); \
             the SBI-timer path was removed. Check firmware tables (ACPI RHCT / \
             DTB) or the QEMU -cpu selection.",
        );
    }
    if km.timebase_freq == 0 || km.timebase_freq > u64::from(u32::MAX)
    {
        crate::fatal(
            "timebase-frequency undiscovered or out of range — the bootloader \
             must provide it (ACPI RHCT / DTB); there is no compiled-in default.",
        );
    }

    let freq = km.timebase_freq;
    TIMEBASE_FREQ_HZ.store(freq, Ordering::Relaxed);

    let period_ticks = ticks_for_period(freq, period_us).max(1);
    TIMER_PERIOD_TICKS.store(period_ticks, Ordering::Relaxed);
    TICKS_PER_SEC.store(1_000_000 / period_us, Ordering::Relaxed);

    let now = read_time();
    write_stimecmp(now + period_ticks);

    // Record the high-resolution boot reference: the `time` CSR value at the
    // moment the timer is armed. Used by elapsed_us() for timestamps.
    BOOT_TIME_TICKS.store(now, Ordering::Relaxed);

    crate::kprintln!("timer: Sstc stimecmp, timebase {} Hz", freq);

    // Enable supervisor interrupts — the timer will now fire.
    // SAFETY: stvec is installed.
    unsafe {
        interrupts::enable();
    }
}

/// Initialise the supervisor timer on an AP hart using the BSP's stored tick rate.
///
/// The BSP must have called [`init`] first: it populates the timebase and
/// period and gates Sstc for every hart (the bootloader confirms the
/// capability across all enabled harts, so no per-AP probe is needed).
/// Arms the first `stimecmp` deadline and enables supervisor interrupts.
///
/// # Safety
/// Must execute in supervisor mode on the AP being initialised.
/// [`interrupts::init_ap`] must have been called first to configure `stvec`
/// and `sie` before enabling interrupts here.
#[cfg(not(test))]
pub unsafe fn init_ap(period_us: u64)
{
    let freq = TIMEBASE_FREQ_HZ.load(Ordering::Relaxed);
    if freq == 0
    {
        crate::fatal("timer: init_ap before BSP timer::init");
    }
    let mut period_ticks = TIMER_PERIOD_TICKS.load(Ordering::Relaxed);
    if period_ticks == 0
    {
        // Defensive: recompute from the stored timebase. This path should
        // not occur in practice since APs start after Phase 5.
        period_ticks = ticks_for_period(freq, period_us).max(1);
    }
    write_stimecmp(read_time() + period_ticks);
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
    // Rearm before calling schedule() so the next tick is not missed; the
    // stimecmp write also clears the pending STIP condition.
    #[cfg(not(test))]
    write_stimecmp(read_time() + period);
    #[cfg(test)]
    let _ = period;
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
/// Uses the `time` CSR directly — no interrupt dependency. Resolution is
/// one timebase tick (100 ns at 10 MHz); the value is truncated to whole µs.
#[cfg(not(test))]
pub fn elapsed_us() -> Option<u64>
{
    let boot = BOOT_TIME_TICKS.load(Ordering::Relaxed);
    if boot == 0
    {
        return None;
    }
    let freq = TIMEBASE_FREQ_HZ.load(Ordering::Relaxed);
    Some(ticks_to_us(read_time().saturating_sub(boot), freq))
}

/// Busy-wait for approximately `us` microseconds using the `time` CSR.
///
/// Requires [`init`] to have run (the discovered timebase converts µs to
/// ticks); there is no pre-init fallback because no pre-init caller exists.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
#[cfg(not(test))]
pub fn delay_us(us: u64)
{
    let freq = TIMEBASE_FREQ_HZ.load(Ordering::Relaxed);
    debug_assert!(freq != 0, "timer::delay_us before timer::init");
    let deadline = read_time().saturating_add(ticks_for_period(freq, us));
    while read_time() < deadline
    {
        core::hint::spin_loop();
    }
}

/// No-op test stub.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
#[cfg(test)]
pub fn delay_us(_us: u64) {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn period_ticks_for_10ms_at_10_mhz()
    {
        // 10 ms = 10_000 µs → 10_000_000 * 10_000 / 1_000_000 = 100_000 ticks.
        assert_eq!(ticks_for_period(10_000_000, 10_000), 100_000);
    }

    #[test]
    fn period_ticks_for_1ms_at_10_mhz()
    {
        assert_eq!(ticks_for_period(10_000_000, 1_000), 10_000);
    }

    #[test]
    fn period_ticks_for_1ms_at_non_mhz_multiple()
    {
        // 1_193_182 Hz (a frequency with no whole ticks-per-µs ratio):
        // 1 ms = 1_193.182 ticks, truncated.
        assert_eq!(ticks_for_period(1_193_182, 1_000), 1_193);
    }

    #[test]
    fn ticks_to_us_exact_at_10_mhz()
    {
        assert_eq!(ticks_to_us(12_345, 10_000_000), 1_234);
        assert_eq!(ticks_to_us(10_000_000, 10_000_000), 1_000_000);
    }

    #[test]
    fn ticks_to_us_exact_at_arbitrary_frequencies()
    {
        for freq in [1_193_182u64, 24_000_000, 3, u64::from(u32::MAX)]
        {
            for ticks in [0u64, 1, freq - 1, freq, freq + 1, 1 << 40, 1 << 60]
            {
                let expected = (u128::from(ticks) * 1_000_000 / u128::from(freq)) as u64;
                assert_eq!(
                    ticks_to_us(ticks, freq),
                    expected,
                    "ticks={ticks} freq={freq}"
                );
            }
        }
    }

    #[test]
    fn ticks_to_us_zero_frequency_is_zero()
    {
        assert_eq!(ticks_to_us(12_345, 0), 0);
    }
}
