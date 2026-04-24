// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/timer.rs

//! x86-64 preemption timer using the local APIC timer (xAPIC).
//!
//! # Calibration
//! The APIC timer frequency is CPU-specific and unknown at compile time.
//! We calibrate it against the 8254 PIT (Programmable Interval Timer) by:
//!
//! 1. Programming PIT channel 2 for a ~10 ms one-shot countdown.
//! 2. Starting the APIC timer with initial count `0xFFFF_FFFF`, divide-by-16.
//! 3. Spinning until the PIT expires.
//! 4. Reading the remaining APIC count to derive ticks per 10 ms.
//!
//! The PIT output is readable on port 0x61 (bit 5: channel 2 output).
//!
//! # Timer ISR
//! The ISR increments `TICK_COUNT` and sends EOI. It is called from the naked
//! stub `idt::isr_timer`.
//!
//! # Modification notes
//! - To change the tick period: pass a different `period_us` to `init()`.
//! - To get higher resolution: reduce divide ratio and recalculate.
//! - To use TSC deadline mode: replace periodic mode programming; requires
//!   CPUID feature check and x2APIC.

// cast_possible_truncation: APIC timer counts fit in u32; TIMER_VECTOR fits in u32.
// cast_lossless: u32→u64 conversions in TSC math are lossless.
// inline_always: read_tsc is a tiny asm stub; always-inline is appropriate here.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::inline_always
)]

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(test))]
use super::interrupts;
#[cfg(not(test))]
use crate::mm::paging::DIRECT_MAP_BASE;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Vector number assigned to the APIC timer interrupt.
pub const TIMER_VECTOR: u8 = 32;

/// APIC register offsets (relative to the APIC base reported by
/// [`super::platform::lapic_base`]).
const APIC_LVT_TIMER: usize = 0x320;
const APIC_TIMER_INITIAL: usize = 0x380;
const APIC_TIMER_CURRENT: usize = 0x390;
const APIC_TIMER_DIVIDE: usize = 0x3E0;

/// LVT timer mode: periodic (bit 17 set).
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

/// Divide-by-16 configuration for the APIC timer divide register.
const DIVIDE_BY_16: u32 = 0x3;

// PIT I/O port numbers.
const PIT_CMD: u16 = 0x43;
const PIT_CH2: u16 = 0x42;
const PIT_GATE: u16 = 0x61;

// PIT oscillator frequency (Hz).
const PIT_HZ: u64 = 1_193_182;

// ── Tick state ────────────────────────────────────────────────────────────────

/// Monotonically increasing tick counter; incremented by the timer ISR.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Raw APIC hardware ticks per second (computed during calibration).
/// Used for initial-count computation; NOT the interrupt rate.
static APIC_TICKS_PER_SEC: AtomicU64 = AtomicU64::new(0);

/// Timer interrupt rate (interrupts per second) matching `TICK_COUNT`.
/// Set to `1_000_000 / period_us` during init.
static INTERRUPT_RATE: AtomicU64 = AtomicU64::new(0);

// ── High-resolution time state ────────────────────────────────────────────────

/// TSC value recorded at the end of APIC timer calibration ("boot time = 0").
/// Zero means not yet calibrated.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// TSC ticks per microsecond, measured over the 10 ms PIT calibration window.
/// Zero means not yet calibrated.
static TSC_PER_US: AtomicU64 = AtomicU64::new(0);

// ── TSC helper ───────────────────────────────────────────────────────────────

/// Read the Time Stamp Counter.
///
/// `rdtsc` is accessible from U-mode (CR4.TSD is not set) and from ring 0.
/// Returns a 64-bit cycle count. Use deltas; the absolute value is arbitrary.
#[cfg(not(test))]
#[inline(always)]
fn read_tsc() -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc does not fault at ring 0 (or ring 3 with TSD=0).
    // preserves_flags: rdtsc only writes EAX/EDX.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    (hi as u64) << 32 | lo as u64
}

// ── APIC register helpers ─────────────────────────────────────────────────────

#[cfg(not(test))]
unsafe fn apic_write(offset: usize, val: u32)
{
    let vaddr = (DIRECT_MAP_BASE + super::platform::lapic_base()) as usize + offset;
    // SAFETY: APIC base mapped via direct map (Phase 3); vaddr points to a
    // valid APIC MMIO register within the 4 KiB APIC page.
    unsafe {
        core::ptr::write_volatile(vaddr as *mut u32, val);
    }
}

#[cfg(not(test))]
fn apic_read(offset: usize) -> u32
{
    let vaddr = (DIRECT_MAP_BASE + super::platform::lapic_base()) as usize + offset;
    // SAFETY: APIC base mapped via direct map (Phase 3); vaddr points to a
    // valid APIC MMIO register within the 4 KiB APIC page.
    unsafe { core::ptr::read_volatile(vaddr as *const u32) }
}

// ── Port I/O helpers ──────────────────────────────────────────────────────────

/// Write `val` to x86 I/O port `port`.
#[cfg(not(test))]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: x86 I/O port instruction; caller must ensure `port` is valid and
    // that I/O privilege level (IOPL) or I/O permission bitmap allows access at ring 0.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, nomem),
        );
    }
}

/// Read a byte from x86 I/O port `port`.
#[cfg(not(test))]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: x86 I/O port instruction; caller must ensure `port` is valid and
    // that I/O privilege level (IOPL) or I/O permission bitmap allows access at ring 0.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, nomem),
        );
    }
    val
}

// ── Calibration ───────────────────────────────────────────────────────────────

/// Calibrate the APIC timer using the 8254 PIT as the reference.
///
/// Programs PIT channel 2 for `pit_ticks` counts (~= `pit_ms` ms), starts
/// the APIC timer at full count with divide-by-16, spins until PIT expires,
/// then returns the number of APIC ticks that elapsed.
///
/// Returns `(apic_ticks_per_pit_interval, pit_ms)`.
#[cfg(not(test))]
unsafe fn calibrate_apic_timer() -> u64
{
    // PIT calibration interval: ~10 ms.
    const PIT_CALIBRATION_MS: u64 = 10;
    // PIT counts for 10 ms.
    let pit_counts = (PIT_HZ * PIT_CALIBRATION_MS / 1000) as u16;

    // Gate channel 2: clear bit 0 (disable gate), keep bit 1.
    // SAFETY: port I/O at ring 0.
    unsafe {
        let gate = inb(PIT_GATE);
        outb(PIT_GATE, gate & 0xFD); // gate off
    }

    // Program PIT channel 2: mode 0 (interrupt on terminal count), binary.
    // Command byte: channel=10 (ch2), access=11 (lo+hi byte), mode=000, BCD=0.
    // SAFETY: PIT ports (0x42, 0x43) are standard legacy hardware; ring 0 I/O access.
    unsafe {
        outb(PIT_CMD, 0b1011_0000);
        outb(PIT_CH2, (pit_counts & 0xFF) as u8);
        outb(PIT_CH2, (pit_counts >> 8) as u8);
    }

    // Set APIC timer divide-by-16 and start with max initial count.
    // SAFETY: APIC MMIO registers are valid; single-threaded calibration context.
    unsafe {
        apic_write(APIC_TIMER_DIVIDE, DIVIDE_BY_16);
        apic_write(APIC_TIMER_INITIAL, 0xFFFF_FFFF);
    }

    // Enable PIT channel 2 gate (bit 0 of port 0x61).
    // Read TSC immediately before starting the gate so the measurement window
    // starts as close to gate-enable as possible.
    let tsc_start = read_tsc();
    // SAFETY: port 0x61 (PIT gate control) is standard legacy hardware; ring 0 I/O access.
    unsafe {
        let gate = inb(PIT_GATE);
        outb(PIT_GATE, gate | 0x01);
    }

    // Spin until PIT output (bit 5 of port 0x61) goes high.
    // SAFETY: port 0x61 read is safe at ring 0; polling PIT status.
    unsafe {
        while inb(PIT_GATE) & 0x20 == 0
        {
            core::hint::spin_loop();
        }
    }
    let tsc_end = read_tsc();

    // Store TSC calibration data: ticks per µs and the "zero" reference.
    // This is used by elapsed_us() for high-resolution timestamps that do not
    // depend on the APIC timer interrupt having fired.
    let tsc_per_10ms = tsc_end.saturating_sub(tsc_start);
    TSC_PER_US.store((tsc_per_10ms / 10_000).max(1), Ordering::Relaxed);
    BOOT_TSC.store(tsc_end, Ordering::Relaxed);

    // Stop the APIC timer.
    let remaining = apic_read(APIC_TIMER_CURRENT);
    // SAFETY: APIC MMIO register write to stop the timer; single-threaded calibration context.
    unsafe {
        apic_write(APIC_TIMER_INITIAL, 0);
    }

    let elapsed = 0xFFFF_FFFFu64 - remaining as u64;
    // Scale to ticks/second: elapsed ticks in PIT_CALIBRATION_MS ms.
    elapsed * 1000 / PIT_CALIBRATION_MS
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise the APIC timer for periodic preemption at `period_us` microseconds.
///
/// Calibrates the APIC timer frequency against the PIT, configures the timer
/// for periodic mode at vector `TIMER_VECTOR`, and **enables interrupts** (`sti`).
///
/// Must be called after `interrupts::init()`.
///
/// # Safety
/// Must execute at ring 0 from a single-threaded context.
#[cfg(not(test))]
pub unsafe fn init(period_us: u64)
{
    // Calibrate: measure APIC ticks per second.
    // SAFETY: ring 0, single-threaded; PIT and APIC hardware are accessible.
    let tps = unsafe { calibrate_apic_timer() };
    APIC_TICKS_PER_SEC.store(tps, Ordering::Relaxed);
    INTERRUPT_RATE.store(1_000_000 / period_us.max(1), Ordering::Relaxed);

    // Compute initial count for the requested period.
    // Formula: initial_count = tps * period_us / 1_000_000 / divide_ratio.
    // divide_ratio = 16 (DIVIDE_BY_16).
    let initial_count = (tps * period_us / 1_000_000).max(1);

    // Configure APIC timer: periodic mode, vector TIMER_VECTOR.
    // SAFETY: APIC MMIO registers are valid; single-threaded init context.
    unsafe {
        apic_write(APIC_TIMER_DIVIDE, DIVIDE_BY_16);
        apic_write(APIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        apic_write(APIC_TIMER_INITIAL, initial_count as u32);
    }

    // Enable interrupts — the timer will now fire.
    // SAFETY: IDT is loaded; timer ISR is registered.
    unsafe {
        interrupts::enable();
    }
}

/// No-op test stub: timer hardware cannot be accessed in host unit tests.
#[cfg(test)]
pub unsafe fn init(_period_us: u64) {}

/// Initialise the APIC timer on an AP using the BSP's calibrated tick rate.
///
/// The BSP must have called [`init`] first to populate [`APIC_TICKS_PER_SEC`].
/// Configures periodic timer at `period_us` on this AP's local APIC.
/// Enables interrupts (`sti`) after programming the timer.
///
/// # Safety
/// Ring 0. LAPIC must be software-enabled ([`interrupts::init_ap`]) before calling.
#[cfg(not(test))]
pub unsafe fn init_ap(period_us: u64)
{
    let tps = APIC_TICKS_PER_SEC.load(Ordering::Relaxed);
    if tps == 0
    {
        // BSP calibration not yet done — skip. This path should not occur in
        // practice since APs start after BSP completes Phase 5.
        return;
    }
    let initial_count = (tps * period_us / 1_000_000).max(1);
    // SAFETY: APIC MMIO registers are valid; IDT and timer ISR are initialized.
    // Enabling interrupts is safe as timer handler is registered.
    unsafe {
        apic_write(APIC_TIMER_DIVIDE, DIVIDE_BY_16);
        apic_write(APIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        apic_write(APIC_TIMER_INITIAL, initial_count as u32);
        interrupts::enable();
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn init_ap(_period_us: u64) {}

/// Busy-wait for approximately `us` microseconds using the TSC.
///
/// Uses the TSC frequency calibrated during [`init`] (stored in [`TSC_PER_US`]).
/// If calibration has not yet run (pre-Phase 5), falls back to a coarse spin loop
/// so callers in early boot do not need to handle the unavailable case specially.
///
/// Suitable for short delays (microseconds to low milliseconds). For longer
/// waits, prefer event-driven approaches.
#[cfg(not(test))]
pub fn delay_us(us: u64)
{
    let per_us = TSC_PER_US.load(Ordering::Relaxed);
    if per_us == 0
    {
        // Fallback before calibration: spin ~200 iterations per µs (very rough).
        for _ in 0..us * 200
        {
            core::hint::spin_loop();
        }
        return;
    }
    let start = read_tsc();
    let target = start.wrapping_add(per_us.saturating_mul(us));
    while read_tsc() < target
    {
        core::hint::spin_loop();
    }
}

/// No-op test stub.
#[cfg(test)]
pub fn delay_us(_us: u64) {}

/// Timer ISR body — called from the naked stub in `idt.rs`.
///
/// Increments the tick counter, sends EOI to the local APIC, then calls
/// the scheduler tick which may preempt the current thread.
/// Must not allocate or block.
#[cfg(not(test))]
pub extern "C" fn timer_isr()
{
    // Only the BSP increments the global tick counter. All CPUs fire this ISR
    // via their local APIC timers, but TICK_COUNT must advance at the single-CPU
    // interrupt rate so that sleep deadline math (ms * ticks_per_second / 1000)
    // produces correct wall-clock durations.
    if crate::arch::current::cpu::current_cpu() == 0
    {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    // EOI must be sent before calling schedule() to avoid masking the APIC.
    interrupts::acknowledge(TIMER_VECTOR as u32);
    // SAFETY: called from interrupt handler on a valid kernel stack.
    unsafe {
        crate::sched::timer_tick();
    }
}

/// Return the current monotonic tick count.
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn current_tick() -> u64
{
    TICK_COUNT.load(Ordering::Relaxed)
}

/// Return the timer interrupt rate (interrupts per second, matching `current_tick()`).
#[allow(dead_code)] // Required by arch interface: kernel/docs/arch-interface.md
pub fn ticks_per_second() -> u64
{
    INTERRUPT_RATE.load(Ordering::Relaxed)
}

/// Return microseconds elapsed since timer calibration, or `None` if the
/// timer has not yet been calibrated (pre-Phase 5).
///
/// Uses `rdtsc` directly — no interrupt dependency, sub-microsecond source.
/// The TSC frequency is measured against the PIT during `init()`.
#[cfg(not(test))]
pub fn elapsed_us() -> Option<u64>
{
    let per_us = TSC_PER_US.load(Ordering::Relaxed);
    if per_us == 0
    {
        return None;
    }
    let boot = BOOT_TSC.load(Ordering::Relaxed);
    Some(read_tsc().saturating_sub(boot) / per_us)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn timer_vector_is_32()
    {
        assert_eq!(TIMER_VECTOR, 32);
    }

    #[test]
    fn apic_timer_divide_offset()
    {
        assert_eq!(APIC_TIMER_DIVIDE, 0x3E0);
    }

    #[test]
    fn apic_timer_initial_offset()
    {
        assert_eq!(APIC_TIMER_INITIAL, 0x380);
    }

    #[test]
    fn tick_rate_math_10ms()
    {
        // At 100 MHz APIC clock, 10 ms = 1_000_000 ticks.
        let tps: u64 = 100_000_000;
        let period_us: u64 = 10_000; // 10 ms
        let initial_count = (tps * period_us / 1_000_000).max(1);
        assert_eq!(initial_count, 1_000_000);
    }

    #[test]
    fn tick_rate_math_1ms()
    {
        // At 100 MHz APIC clock, 1 ms = 100_000 ticks.
        let tps: u64 = 100_000_000;
        let period_us: u64 = 1_000;
        let initial_count = (tps * period_us / 1_000_000).max(1);
        assert_eq!(initial_count, 100_000);
    }

    #[test]
    fn divide_by_16_constant()
    {
        assert_eq!(DIVIDE_BY_16, 0x3);
    }

    #[test]
    fn lvt_timer_periodic_bit()
    {
        assert_eq!(LVT_TIMER_PERIODIC, 1 << 17);
    }
}
