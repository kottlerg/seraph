// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/timer.rs

//! x86-64 preemption timer: TSC-deadline mode where the CPU advertises it
//! (CPUID.01H:ECX[24]), otherwise the periodic local APIC timer.
//!
//! The mode is decided once on the BSP during [`init`] and mirrored by every
//! AP. TSC-deadline is classified Opportunistic by
//! [platform-requirements.md](../../../../../docs/platform-requirements.md):
//! the periodic fallback stays because the QEMU TCG emulator used for
//! continuous integration does not expose the CPUID bit. Neither mode
//! requires x2APIC — the LVT mode bits exist in both xAPIC and x2APIC
//! register layouts, and the shared `apic_write` accessor abstracts them.
//!
//! # Rates
//! The TSC rate (`TSC_PER_US`), which `elapsed_us()` and TSC-deadline
//! arming consume, is taken once on the BSP from the first of three sources
//! that gives a plausible rate: CPUID leaf 0x15's crystal frequency and ratio,
//! one 8254 PIT channel-2 window, or CPUID leaf 0x16's base frequency
//! (approximate). [`super::timer_rate`] holds the order and the arithmetic;
//! this file holds the probes. The source taken is logged; where no source
//! gives a rate, the boot halts.
//!
//! The 8254 window is measured only where leaf 0x15 gives no crystal
//! frequency. It programs channel 2 for ~10 ms and spins until the output on
//! port 0x61 (bit 5) rises, counting TSC ticks from the gate-enable; it clears
//! the channel-2 gate before programming the count (firmware may leave it
//! set), so the PIT window starts at the gate-enable together with the TSC
//! window. A window that never ends within its poll budget, or gives an
//! implausible rate (an undecoded port 0x61 reads all ones and ends it at
//! once), counts as no working 8254.
//!
//! The local-APIC timer's rate, which only the periodic tick uses, is measured
//! against the TSC once the TSC rate is known, whatever its source: the timer
//! runs at divide-by-16 from `0xFFFF_FFFF` over a 10 ms TSC window. Which clock
//! feeds the APIC timer differs by platform and is not enumerable, so it is
//! never taken from the crystal.
//!
//! # Timer ISR
//! The ISR re-arms the deadline (TSC-deadline mode only; periodic mode
//! reloads in hardware), sends EOI, and invokes the scheduler tick for
//! preemption. The monotonic tick counter is derived from the TSC (see
//! [`current_tick`]) so that sleep deadlines stay phase-locked with
//! userspace `Instant::now()` across host preemption windows.
//!
//! # Modification notes
//! - To change the tick period: pass a different `period_us` to `init()`.
//! - To get higher resolution (periodic mode): reduce divide ratio and
//!   recalculate.

#![cfg_attr(
    not(test),
    expect(
        clippy::cast_possible_truncation,
        reason = "the APIC initial count fits the 32-bit register; the PIT reload value (~11 932) \
                  fits u16 and is written as two u8 halves; the code it covers is compiled out of \
                  the host test build, so the lint fires outside it alone"
    )
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::cast_lossless,
        reason = "u32→u64 widening in TSC/APIC math and the u8 TIMER_VECTOR widened to u32 are \
                  lossless; the code it covers is compiled out of the host test build, so the lint \
                  fires outside it alone"
    )
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::inline_always,
        reason = "read_tsc is a tiny asm stub; always-inline is appropriate here; the code it \
                  covers is compiled out of the host test build, so the lint fires outside it \
                  alone"
    )
)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(not(test))]
use super::cpu;
#[cfg(not(test))]
use super::interrupts;
#[cfg(not(test))]
use super::interrupts::{apic_read, apic_write};
#[cfg(not(test))]
use super::timer_rate::{self, Leaf15, NoSource, PitFault, PitWindow, Source, TscRate};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Vector number assigned to the APIC timer interrupt.
pub const TIMER_VECTOR: u8 = 32;

/// APIC timer register offsets, passed to the shared
/// [`super::interrupts::apic_write`] accessor (which translates them to the
/// xAPIC MMIO window or the x2APIC MSRs depending on the active mode).
const APIC_LVT_TIMER: usize = 0x320;
const APIC_TIMER_INITIAL: usize = 0x380;
const APIC_TIMER_CURRENT: usize = 0x390;
const APIC_TIMER_DIVIDE: usize = 0x3E0;

/// LVT timer mode: periodic (bits 18:17 = 0b01).
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

/// LVT timer mode: TSC-deadline (bits 18:17 = 0b10, SDM Vol. 3A §11.5.4.1).
const LVT_TIMER_TSC_DEADLINE: u32 = 0b10 << 17;

/// `IA32_TSC_DEADLINE` MSR: writing an absolute TSC value arms a one-shot
/// interrupt for when the TSC reaches it; writing 0 disarms.
const IA32_TSC_DEADLINE: u32 = 0x6E0;

/// Divide-by-16 configuration for the APIC timer divide register.
const DIVIDE_BY_16: u32 = 0x3;

// PIT I/O port numbers.
const PIT_CMD: u16 = 0x43;
const PIT_CH2: u16 = 0x42;
const PIT_GATE: u16 = 0x61;

/// PIT window length: ~10 ms. A sampling window, not a capacity; it keeps
/// [`PIT_WINDOW_COUNTS`] inside the PIT's 16-bit counter (about 54.9 ms at
/// [`timer_rate::PIT_HZ`]).
#[cfg(not(test))]
const PIT_CALIBRATION_MS: u64 = 10;

/// PIT counts in one window of [`PIT_CALIBRATION_MS`].
#[cfg(not(test))]
const PIT_WINDOW_COUNTS: u16 = (timer_rate::PIT_HZ * PIT_CALIBRATION_MS / 1000) as u16;

/// Local-APIC timer measurement window, in milliseconds of TSC time. A
/// sampling window, not a capacity: at divide-by-16 the timer's 32-bit count
/// lasts far longer at any APIC timer clock.
#[cfg(not(test))]
const APIC_CALIBRATION_MS: u64 = 10;

/// Budget, in TSC ticks, for the calibration poll to see PIT channel 2 expire. 2^32 ticks is
/// 0.43 s at a 10 GHz TSC, over 40 times the 10 ms window, and longer at any slower rate; the
/// TSC is not calibrated yet, so the budget is set against the fastest plausible rate. A
/// tuning value that bounds no capacity: it only separates a missing PIT from a slow one.
#[cfg(not(test))]
const PIT_POLL_BUDGET_TSC_TICKS: u64 = 1 << 32;

// ── Tick state ────────────────────────────────────────────────────────────────

/// APIC timer count rate in ticks per second at the divide-by-16 setting
/// (computed during calibration).
/// Used for initial-count computation; NOT the interrupt rate.
static APIC_TICKS_PER_SEC: AtomicU64 = AtomicU64::new(0);

/// Timer interrupt rate (interrupts per second) returned by
/// [`ticks_per_second`]. Set to `1_000_000 / period_us` during init.
static INTERRUPT_RATE: AtomicU64 = AtomicU64::new(0);

/// True when the tick uses TSC-deadline mode. Decided once on the BSP in
/// [`init`] (CPUID probe) and mirrored by every AP in [`init_ap`] — the
/// same BSP-decides pattern as `interrupts::X2APIC_ENABLED`.
static TSC_DEADLINE_MODE: AtomicBool = AtomicBool::new(false);

/// Tick period in TSC ticks (TSC-deadline mode). Computed on the BSP from
/// `TSC_PER_US` and reused on every core, relying on the invariant TSC
/// required by
/// [platform-requirements.md](../../../../../docs/platform-requirements.md)
/// § x86-64 Classification.
static PERIOD_TSC_TICKS: AtomicU64 = AtomicU64::new(0);

// ── High-resolution time state ────────────────────────────────────────────────

/// TSC value recorded once the TSC rate is known ("boot time = 0").
/// Zero means not yet calibrated.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// TSC ticks per microsecond, from the rate source [`init`] takes (whole
/// ticks; the plausible floor keeps it at 100 or more). Zero means not yet
/// calibrated.
static TSC_PER_US: AtomicU64 = AtomicU64::new(0);

// ── TSC helper ───────────────────────────────────────────────────────────────

/// Read the Time Stamp Counter.
///
/// `rdtsc` is accessible from ring 0 and from U-mode, the kernel clearing
/// `CR4.TSD` on every CPU (`cpu::enable_smep_smap`).
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
    ((hi as u64) << 32) | lo as u64
}

/// True when CPUID.01H:ECX[24] advertises the TSC-deadline timer mode.
#[cfg(not(test))]
fn tsc_deadline_supported() -> bool
{
    cpu::cpuid(1).2 & (1 << 24) != 0
}

/// Serialize an LVT-timer mode change ahead of the first deadline write.
///
/// SDM Vol. 3A §11.5.4.1: xAPIC LVT writes are MMIO stores and are not
/// serializing, so a deadline MSR write could otherwise be processed while
/// the timer is still in its previous mode. Harmless (but unneeded) when
/// the LVT write went through the x2APIC MSR interface.
#[cfg(not(test))]
fn mfence()
{
    // SAFETY: mfence orders memory accesses only; no registers or memory
    // are modified beyond the ordering effect.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
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

/// Measure one 8254 PIT channel-2 window against the TSC.
///
/// Programs PIT channel 2 for [`PIT_WINDOW_COUNTS`] counts (~10 ms) and spins
/// until the channel-2 output rises, bounded by [`PIT_POLL_BUDGET_TSC_TICKS`].
/// The channel-2 gate is cleared before the count is programmed, so the PIT
/// counts only from the gate-enable that opens the TSC window, whatever state
/// firmware left the gate in.
///
/// Returns the TSC ticks the window took, or [`PitWindow::NeverExpired`] when
/// the output never rose; [`timer_rate::pit_rate`] judges the result.
///
/// # Safety
/// Ring 0, from a single-threaded context: the window owns the 8254's
/// channel 2 and the port-0x61 gate.
#[cfg(not(test))]
unsafe fn measure_pit_window() -> PitWindow
{
    // Clear bit 1 of port 0x61 (speaker data enable) and bit 0 (channel 2
    // gate). Mode 0 counts only while the gate is high, so with the gate low
    // the count written below waits for the gate-enable after `tsc_start`; a
    // gate firmware left set would start the PIT window at the count write
    // instead, and the measured rate would read low by that skew.
    // SAFETY: port I/O at ring 0.
    let gate = unsafe { inb(PIT_GATE) };
    // SAFETY: port I/O at ring 0; the write keeps port 0x61's other bits as read.
    unsafe { outb(PIT_GATE, gate & 0xFC) }; // speaker data off; channel 2 gate off

    // Program PIT channel 2: mode 0 (interrupt on terminal count), binary.
    // Command byte: channel=10 (ch2), access=11 (lo+hi byte), mode=000, BCD=0.
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every write is a step of the one PIT channel 2 programming sequence"
    )]
    // SAFETY: PIT ports (0x42, 0x43) are standard legacy hardware; ring 0 I/O access.
    unsafe {
        outb(PIT_CMD, 0b1011_0000);
        outb(PIT_CH2, (PIT_WINDOW_COUNTS & 0xFF) as u8);
        outb(PIT_CH2, (PIT_WINDOW_COUNTS >> 8) as u8);
    }

    // Set PIT channel 2 gate (bit 0 of port 0x61, cleared above). Setting it
    // starts the countdown, and reading the TSC immediately before starts the
    // measurement window as close to gate-enable as possible.
    let tsc_start = read_tsc();
    // SAFETY: port 0x61 (PIT gate control) is standard legacy hardware; ring 0 I/O access.
    let gate = unsafe { inb(PIT_GATE) };
    // SAFETY: as for the read; the write keeps port 0x61's other bits as read.
    unsafe { outb(PIT_GATE, gate | 0x01) };

    // Spin until PIT output (bit 5 of port 0x61) goes high, bounded in TSC ticks: the TSC is
    // not yet calibrated, but it always reads, and `PIT_POLL_BUDGET_TSC_TICKS` covers the
    // window at any plausible TSC rate. An 8254 whose clock is gated off never raises the
    // output, so the window ends as never expired rather than hanging.
    let expired = crate::bounded_wait::spin_until(
        || {
            // SAFETY: port 0x61 read is safe at ring 0; polling PIT status.
            let status = unsafe { inb(PIT_GATE) };
            status & 0x20 != 0
        },
        || Some(read_tsc()),
        PIT_POLL_BUDGET_TSC_TICKS,
    );
    if !expired
    {
        return PitWindow::NeverExpired;
    }
    let tsc_end = read_tsc();
    PitWindow::Expired {
        tsc_ticks: tsc_end.saturating_sub(tsc_start),
    }
}

/// Measure the local-APIC timer's rate against the TSC, running at `tsc_hz`.
///
/// Starts the timer at divide-by-16 from `0xFFFF_FFFF`, spins for
/// [`APIC_CALIBRATION_MS`] of TSC time, and scales the count it ran down.
/// Halts the boot when the timer did not count.
///
/// Returns APIC timer ticks per second at divide-by-16.
///
/// # Safety
/// Ring 0, from a single-threaded context, with this CPU's local APIC enabled
/// and its timer not in use.
#[cfg(not(test))]
unsafe fn measure_apic_timer(tsc_hz: u64) -> u64
{
    let window = tsc_hz.saturating_mul(APIC_CALIBRATION_MS) / 1000;

    // SAFETY: APIC registers are valid; single-threaded init context.
    unsafe {
        apic_write(APIC_TIMER_DIVIDE, DIVIDE_BY_16);
    }
    // SAFETY: as for the divide register; the initial count starts the timer.
    unsafe {
        apic_write(APIC_TIMER_INITIAL, 0xFFFF_FFFF);
    }
    let tsc_start = read_tsc();
    // The invariant TSC always advances, so the spin ends.
    while read_tsc().wrapping_sub(tsc_start) < window
    {
        core::hint::spin_loop();
    }
    let tsc_end = read_tsc();
    let remaining = apic_read(APIC_TIMER_CURRENT);
    // SAFETY: APIC register write to stop the timer; single-threaded init context.
    unsafe {
        apic_write(APIC_TIMER_INITIAL, 0);
    }

    // The count ran down from 0xFFFF_FFFF, so the ticks elapsed are its complement.
    let elapsed = u64::from(!remaining);
    timer_rate::apic_ticks_per_sec(elapsed, tsc_end.wrapping_sub(tsc_start), tsc_hz)
        .unwrap_or_else(|| crate::fatal("timer: local APIC timer did not count against the TSC"))
}

/// CPUID leaf 0x15, and leaf 0x16 EAX[15:0] (the base frequency in MHz), each
/// where the CPU's maximum basic leaf reaches it: a leaf above the maximum
/// returns another leaf's data on Intel.
#[cfg(not(test))]
fn probe_frequency_leaves() -> (Option<Leaf15>, Option<u32>)
{
    let max_leaf = cpu::cpuid(0).0;
    let leaf15 = (max_leaf >= 0x15).then(|| {
        let (eax, ebx, ecx, _) = cpu::cpuid(0x15);
        Leaf15 {
            denominator: eax,
            numerator: ebx,
            crystal_hz: ecx,
        }
    });
    let base_mhz = (max_leaf >= 0x16).then(|| cpu::cpuid(0x16).0 & 0xFFFF);
    (leaf15, base_mhz)
}

/// Leaf 0x15 as probed, for the boot log.
#[cfg(not(test))]
struct Leaf15Note(Option<Leaf15>);

#[cfg(not(test))]
impl core::fmt::Display for Leaf15Note
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self.0
        {
            None => write!(f, "CPUID leaf 0x15 absent"),
            Some(leaf) => write!(
                f,
                "CPUID leaf 0x15 crystal {} Hz, ratio {}/{}",
                leaf.crystal_hz, leaf.numerator, leaf.denominator
            ),
        }
    }
}

/// Why the 8254 gave no rate, for the boot log.
#[cfg(not(test))]
struct PitNote(PitFault);

#[cfg(not(test))]
impl core::fmt::Display for PitNote
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self.0
        {
            PitFault::NeverExpired => write!(f, "8254 channel 2 never expired"),
            PitFault::Implausible { hz } => write!(
                f,
                "8254 window gave {hz} Hz, outside {}..={} Hz",
                timer_rate::TSC_RATE_MIN_HZ,
                timer_rate::TSC_RATE_MAX_HZ
            ),
        }
    }
}

/// Log the TSC rate and the source it was taken from.
#[cfg(not(test))]
fn log_tsc_rate(rate: TscRate, leaf15: Option<Leaf15>)
{
    let hz = rate.hz;
    match rate.source
    {
        Source::Crystal(_) =>
        {
            crate::kprintln!("timer: TSC {hz} Hz from {}", Leaf15Note(leaf15));
        }
        Source::Pit =>
        {
            crate::kprintln!("timer: TSC {hz} Hz from the 8254 ({})", Leaf15Note(leaf15));
        }
        Source::BaseFrequency { base_mhz, pit } =>
        {
            crate::kprintln!(
                "timer: TSC {hz} Hz from CPUID leaf 0x16 base {base_mhz} MHz, approximate ({}; {})",
                Leaf15Note(leaf15),
                PitNote(pit)
            );
        }
    }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise the preemption timer at `period_us` microseconds and
/// **enable interrupts** (`sti`).
///
/// Takes the TSC rate from the first source that gives one (module
/// documentation, § Rates), then arms the tick: TSC-deadline mode when CPUID
/// advertises it, periodic APIC timer otherwise, at the rate measured against
/// the TSC. The decision is stored for [`init_ap`] to mirror. Halts the boot
/// when no source gives a TSC rate.
///
/// Must be called after `interrupts::init()`.
///
/// # Safety
/// Must execute at ring 0 from a single-threaded context.
#[cfg(not(test))]
pub unsafe fn init(period_us: u64)
{
    // The TSC rate, which elapsed_us() and the deadline path consume.
    let (leaf15, base_mhz) = probe_frequency_leaves();
    let rate = timer_rate::select(leaf15, base_mhz, PIT_WINDOW_COUNTS, || {
        // SAFETY: ring 0, single-threaded; the 8254 ports are legacy I/O ports.
        unsafe { measure_pit_window() }
    });
    let tsc_hz = match rate
    {
        Ok(rate) =>
        {
            log_tsc_rate(rate, leaf15);
            rate.hz
        }
        Err(NoSource { pit }) =>
        {
            crate::kprintln!(
                "timer: no TSC rate: {}; {}; CPUID leaf 0x16 base {:?} MHz",
                Leaf15Note(leaf15),
                PitNote(pit),
                base_mhz
            );
            crate::fatal(
                "timer: no TSC rate source (CPUID leaf 0x15 crystal, 8254 PIT, CPUID leaf 0x16 \
                 base frequency)",
            );
        }
    };
    BOOT_TSC.store(read_tsc(), Ordering::Relaxed);
    TSC_PER_US.store(tsc_hz / 1_000_000, Ordering::Relaxed);
    // A zero period is taken as one microsecond.
    INTERRUPT_RATE.store(
        1_000_000u64.checked_div(period_us).unwrap_or(1_000_000),
        Ordering::Relaxed,
    );

    if tsc_deadline_supported()
    {
        let period_tsc = TSC_PER_US
            .load(Ordering::Relaxed)
            .saturating_mul(period_us)
            .max(1);
        PERIOD_TSC_TICKS.store(period_tsc, Ordering::Relaxed);
        TSC_DEADLINE_MODE.store(true, Ordering::Relaxed);

        // Configure the LVT for TSC-deadline mode, then arm the first
        // deadline. The divide and initial-count registers are meaningless
        // in this mode and are left untouched.
        // SAFETY: APIC registers are valid; single-threaded init context.
        unsafe {
            apic_write(APIC_LVT_TIMER, LVT_TIMER_TSC_DEADLINE | TIMER_VECTOR as u32);
        }
        mfence();
        // SAFETY: ring 0; wrmsr to IA32_TSC_DEADLINE is valid once the LVT
        // mode change is serialized by the mfence.
        unsafe {
            cpu::write_msr(IA32_TSC_DEADLINE, read_tsc().wrapping_add(period_tsc));
        }
        crate::kprintln!("timer: mode = TSC-deadline");
    }
    else
    {
        // SAFETY: ring 0, single-threaded init context; the local APIC is enabled.
        let tps = unsafe { measure_apic_timer(tsc_hz) };
        APIC_TICKS_PER_SEC.store(tps, Ordering::Relaxed);

        // Compute initial count for the requested period.
        // Formula: initial_count = tps * period_us / 1_000_000. `tps` was
        // measured with DIVIDE_BY_16 already applied, so no further division
        // by the divide ratio is needed.
        let initial_count = (tps.saturating_mul(period_us) / 1_000_000).max(1);

        // Configure APIC timer: periodic mode, vector TIMER_VECTOR.
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a register of this CPU's local APIC timer, at a constant \
                      offset"
        )]
        // SAFETY: APIC registers are valid; single-threaded init context.
        unsafe {
            apic_write(APIC_TIMER_DIVIDE, DIVIDE_BY_16);
            apic_write(APIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
            apic_write(APIC_TIMER_INITIAL, initial_count as u32);
        }
        crate::kprintln!("timer: mode = periodic APIC (TSC-deadline unavailable)");
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

/// Initialise the preemption timer on an AP, mirroring the BSP's mode.
///
/// The BSP must have called [`init`] first: it decides the mode and
/// populates the calibration statics. In TSC-deadline mode the deadline is
/// armed from this AP's own TSC (the deadline MSR is per-core); in periodic
/// mode this AP's local APIC timer is programmed with the BSP's calibrated
/// rate. Enables interrupts (`sti`) after programming the timer.
///
/// # Safety
/// Ring 0. LAPIC must be software-enabled ([`interrupts::init_ap`]) before calling.
#[cfg(not(test))]
pub unsafe fn init_ap(period_us: u64)
{
    if TSC_DEADLINE_MODE.load(Ordering::Relaxed)
    {
        let period_tsc = PERIOD_TSC_TICKS.load(Ordering::Relaxed);
        // SAFETY: this AP's APIC registers are valid (LAPIC software-enabled,
        // caller's contract).
        unsafe {
            apic_write(APIC_LVT_TIMER, LVT_TIMER_TSC_DEADLINE | TIMER_VECTOR as u32);
        }
        mfence();
        // SAFETY: ring 0; the mfence serializes the LVT mode change before the
        // per-core deadline MSR write.
        unsafe {
            cpu::write_msr(IA32_TSC_DEADLINE, read_tsc().wrapping_add(period_tsc));
        }
        // SAFETY: IDT and timer ISR are initialized, so enabling interrupts is
        // safe as the timer handler is registered.
        unsafe {
            interrupts::enable();
        }
        return;
    }

    let tps = APIC_TICKS_PER_SEC.load(Ordering::Relaxed);
    if tps == 0
    {
        // BSP calibration not yet done — skip. This path should not occur in
        // practice since APs start after BSP completes Phase 5.
        return;
    }
    let initial_count = (tps.saturating_mul(period_us) / 1_000_000).max(1);
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a register of this CPU's local APIC timer, at a constant \
                  offset"
    )]
    // SAFETY: APIC MMIO registers are valid (LAPIC software-enabled, caller's
    // contract).
    unsafe {
        apic_write(APIC_TIMER_DIVIDE, DIVIDE_BY_16);
        apic_write(APIC_LVT_TIMER, LVT_TIMER_PERIODIC | TIMER_VECTOR as u32);
        apic_write(APIC_TIMER_INITIAL, initial_count as u32);
    }
    // SAFETY: IDT and timer ISR are initialized, so enabling interrupts is
    // safe as the timer handler is registered.
    unsafe {
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
        // A tuning value for early boot only; it bounds no capacity.
        for _ in 0..us.saturating_mul(200)
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

/// Timer ISR body — called from `irq_dispatch` in `idt.rs`, which the naked
/// `common_irq_trampoline` invokes for the timer vector.
///
/// In TSC-deadline mode, re-arms the (one-shot) deadline first; periodic
/// mode reloads in hardware. Then sends EOI and calls the scheduler tick,
/// which may preempt the current thread. Both the re-arm and the EOI must
/// precede `timer_tick()` because it may context-switch away and not
/// return promptly. Must not allocate or block.
#[cfg(not(test))]
pub extern "C" fn timer_isr()
{
    if TSC_DEADLINE_MODE.load(Ordering::Relaxed)
    {
        // No fence needed: the LVT mode is unchanged since init; this is a
        // plain per-core deadline MSR write.
        // SAFETY: wrmsr to IA32_TSC_DEADLINE with a future TSC value; the
        // mode was established by init()/init_ap() on this core.
        unsafe {
            cpu::write_msr(
                IA32_TSC_DEADLINE,
                read_tsc().wrapping_add(PERIOD_TSC_TICKS.load(Ordering::Relaxed)),
            );
        }
    }
    // EOI must be sent before `crate::sched::timer_tick()` (which may switch
    // away) to avoid masking the APIC.
    interrupts::acknowledge(TIMER_VECTOR as u32);
    // SAFETY: called from interrupt handler on a valid kernel stack.
    unsafe {
        crate::sched::timer_tick();
    }
}

/// Return the current monotonic tick count.
///
/// Derived from the TSC so that sleep deadlines and userspace
/// `Instant::now()` (which reads `elapsed_us` via `SYS_SYSTEM_INFO`) share
/// a single counter.
#[cfg(not(test))]
pub fn current_tick() -> u64
{
    let Some(us) = elapsed_us()
    else
    {
        return 0;
    };
    let tps = INTERRUPT_RATE.load(Ordering::Relaxed);
    if tps == 0
    {
        return 0;
    }
    us.saturating_mul(tps) / 1_000_000
}

/// Test stub — host tests have no TSC calibration.
#[cfg(test)]
pub fn current_tick() -> u64
{
    0
}

/// Return the timer interrupt rate (interrupts per second, matching `current_tick()`).
pub fn ticks_per_second() -> u64
{
    INTERRUPT_RATE.load(Ordering::Relaxed)
}

/// Return microseconds elapsed since timer calibration, or `None` if the
/// timer has not yet been calibrated (pre-Phase 5).
///
/// Uses `rdtsc` directly — no interrupt dependency, sub-microsecond source.
/// The TSC rate is the one `init()` takes from its first source that gives one
/// (module documentation, § Rates).
#[cfg(not(test))]
pub fn elapsed_us() -> Option<u64>
{
    let per_us = TSC_PER_US.load(Ordering::Relaxed);
    let boot = BOOT_TSC.load(Ordering::Relaxed);
    read_tsc().saturating_sub(boot).checked_div(per_us)
}
