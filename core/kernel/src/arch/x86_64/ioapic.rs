// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/ioapic.rs

//! I/O APIC driver for x86-64.
//!
//! Programs interrupt redirection entries so device IRQs (GSIs) are delivered
//! to the CPU as IDT vectors. Supports up to [`boot_protocol::MAX_IOAPICS`]
//! per system; per-IOAPIC bases and `gsi_base` are read from
//! `BootInfo.kernel_mmio.ioapics[..]` (cached at boot via
//! [`crate::platform::capture_kernel_mmio`]) with a single-IOAPIC fallback at
//! [`super::platform`]'s default.
//!
//! # Hardware interface
//! Each I/O APIC is memory-mapped at its `phys_base`, accessible via the
//! kernel direct map. Two 32-bit registers control access:
//! - `IOREGSEL` (offset 0x00): index of the register to read/write.
//! - `IOWIN`    (offset 0x10): data window for the selected register.
//!
//! Redirection entries are 64-bit values spanning two 32-bit registers:
//! - Low  dword at index `0x10 + 2 * pin`
//! - High dword at index `0x11 + 2 * pin`
//!
//! `pin` is the intra-IOAPIC pin number; the global GSI is `gsi_base + pin`.
//!
//! # Locking
//! Every register access is an `IOREGSEL` store followed by an `IOWIN` access,
//! and [`mask`] and [`unmask`] read-modify-write an entry. [`route`], [`mask`]
//! and [`unmask`] run on any CPU (`SYS_IRQ_REGISTER`, `SYS_IRQ_ACK`, the
//! device-IRQ dispatch in interrupt context, and the Interrupt and Notification
//! dealloc paths, which mask a line), so each holds `IOAPIC_LOCK`, a
//! leaf lock taken with interrupts disabled, across its whole access sequence;
//! otherwise another CPU's select could land between a select and its window
//! access and redirect the value to another entry. [`init`] runs single-threaded
//! before any IRQ is routed and takes no lock.
//!
//! # Vector assignment
//! A GSI is assigned an IDT vector when it is routed ([`assign_vector`], from
//! `interrupts::route_device_irq`) and releases it when its route is cleared
//! ([`release_vector`]). The device vectors are `DEVICE_VECTOR_BASE..=DEVICE_VECTOR_LAST`
//! (33-249), between the timer vector and the IPI vectors; `idt::init` installs a generated
//! stub on every one, and `idt::irq_dispatch` maps the vector back to its GSI through
//! [`gsi_for_vector`]. Any GSI the discovered I/O APICs cover can be routed, up to
//! [`DEVICE_VECTOR_COUNT`] of them at once; a route past that is refused
//! (`irq::RouteError::Exhausted`). The vector table is written only by the route changes,
//! which `irq` serialises under its routing lock, and read lock-free by the dispatch.
//!
//! # Destination
//! Each route names one destination CPU, chosen at route time by `irq::next_target_cpu`
//! among the CPUs whose APIC id fits the 8-bit physical destination field of a redirection
//! entry (`interrupts::route_device_irq`). An I/O APIC cannot name a CPU with a wider
//! x2APIC id without interrupt remapping, which the kernel does not program.
//!
//! # Limitations / deferred work
//!
//! - **No MSI/MSI-X support.** Required for modern `PCIe` devices (#325).
//!
//! - **Edge-triggered, active-high only.** Level-triggered and active-low sources (PCI `INTx`
//!   lines, MADT interrupt-source overrides) are not handled; no trigger/polarity information
//!   reaches the kernel (`InterruptObject` carries only `start` and `count`).
//!
//! # Modification notes
//! - Every GSI is routed by `interrupts::route_device_irq` (from `SYS_IRQ_REGISTER`, through
//!   `irq::register`), released by `interrupts::unroute_device_irq`, and unmasked by
//!   `interrupts::unmask` (from `SYS_IRQ_ACK`).
//! - To support level-triggered IRQs: set bit 15 (level-sensitive) and
//!   bit 13 (active-low polarity) in the redirection entry low dword.

// cast_possible_truncation: u64→usize APIC MMIO address arithmetic; bounded by APIC layout.
// cast_lossless: u8→u32 vector widening casts.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

use core::sync::atomic::{AtomicU32, Ordering};

use boot_protocol::{IoApicEntry, MAX_IOAPICS};

// ── Hardware constants ────────────────────────────────────────────────────────

/// Register select offset (write GSI index here).
const IOREGSEL: usize = 0x00;
/// Data window offset (read/write data here after selecting register).
const IOWIN: usize = 0x10;

/// I/O APIC identification register.
const IOAPICID: u32 = 0x00;
/// I/O APIC version register (bits [23:16] = max redirection entry index).
const IOAPICVER: u32 = 0x01;

/// First IDT vector assigned to device IRQs, the one after the timer vector.
pub const DEVICE_VECTOR_BASE: u8 = 33;

/// Last IDT vector assigned to device IRQs, the one below the IPI vectors (250 and 251;
/// the spurious vector is 255).
pub const DEVICE_VECTOR_LAST: u8 = 249;

/// Number of device vectors, and so the number of GSIs routed at once: 217.
pub const DEVICE_VECTOR_COUNT: usize = (DEVICE_VECTOR_LAST - DEVICE_VECTOR_BASE) as usize + 1;

/// Pins an I/O APIC can have: its version register reports the last redirection entry in
/// an 8-bit field.
pub const IOAPIC_MAX_PINS: u32 = 256;

/// GSI each device vector is assigned to, plus one; 0 for a free vector, so the zeroed
/// table is all free. Index `v - DEVICE_VECTOR_BASE` for vector `v`. Written only by
/// [`assign_vector`] and [`release_vector`], which `irq` serialises under its routing lock;
/// read lock-free by [`gsi_for_vector`] in interrupt context.
#[cfg(not(test))]
static VECTOR_GSI: [AtomicU32; DEVICE_VECTOR_COUNT] =
    [const { AtomicU32::new(0) }; DEVICE_VECTOR_COUNT];

/// The device vector at `index` of a vector table.
fn vector_at(index: usize) -> Option<u8>
{
    u8::try_from(index)
        .ok()
        .and_then(|offset| DEVICE_VECTOR_BASE.checked_add(offset))
}

/// The vector `table` assigns to `gsi`, if any.
fn find_vector(table: &[AtomicU32], gsi: u32) -> Option<u8>
{
    let tag = gsi.checked_add(1)?;
    let index = table
        .iter()
        .position(|entry| entry.load(Ordering::Relaxed) == tag)?;
    vector_at(index)
}

/// The vector `table` assigns to `gsi`: its existing one, else the lowest free vector,
/// now assigned to it. `None` when every vector is assigned (or `gsi` is `u32::MAX`, which
/// no I/O APIC covers).
fn assign_vector_in(table: &[AtomicU32], gsi: u32) -> Option<u8>
{
    if let Some(vector) = find_vector(table, gsi)
    {
        return Some(vector);
    }
    let tag = gsi.checked_add(1)?;
    let index = table
        .iter()
        .position(|entry| entry.load(Ordering::Relaxed) == 0)?;
    // Release: a dispatch that reads the tag (Acquire) once the redirection entry that
    // names this vector fires sees a complete assignment.
    table[index].store(tag, Ordering::Release);
    vector_at(index)
}

/// Free every vector `table` assigns to `gsi`.
fn release_vector_in(table: &[AtomicU32], gsi: u32)
{
    let Some(tag) = gsi.checked_add(1)
    else
    {
        return;
    };
    for entry in table
    {
        if entry.load(Ordering::Relaxed) == tag
        {
            entry.store(0, Ordering::Release);
        }
    }
}

/// Assign `gsi` a device vector (its existing one if it has one). `None` when every device
/// vector is assigned. Called under `irq`'s routing lock.
#[cfg(not(test))]
#[must_use]
pub fn assign_vector(gsi: u32) -> Option<u8>
{
    assign_vector_in(&VECTOR_GSI, gsi)
}

/// The device vector assigned to `gsi`, if it is routed.
#[cfg(not(test))]
#[must_use]
pub fn vector_of(gsi: u32) -> Option<u8>
{
    find_vector(&VECTOR_GSI, gsi)
}

/// Free `gsi`'s device vector. Called under `irq`'s routing lock, after the redirection
/// entry is masked.
#[cfg(not(test))]
pub fn release_vector(gsi: u32)
{
    release_vector_in(&VECTOR_GSI, gsi);
}

/// The GSI device vector `vector` is assigned to, or `None` for a free vector or one
/// outside the device range. Read in interrupt context (`idt::irq_dispatch`): an interrupt
/// latched before its vector was released finds `None` and is dropped.
#[cfg(not(test))]
#[must_use]
pub fn gsi_for_vector(vector: u8) -> Option<u32>
{
    let index = vector.checked_sub(DEVICE_VECTOR_BASE)? as usize;
    let tag = VECTOR_GSI.get(index)?.load(Ordering::Acquire);
    tag.checked_sub(1)
}

/// Mask bit in the low dword of a redirection entry (bit 16).
const REDIR_MASK: u32 = 1 << 16;

/// Fixed delivery mode (000), physical destination, vector in [7:0].
/// Logical destination mode would be bit 11; we leave it clear (physical).
const REDIR_FIXED: u32 = 0x0000_0000;

// ── Per-IOAPIC state ──────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct IoApicState
{
    phys_base: u64,
    gsi_base: u32,
    pin_count: u32,
}

const EMPTY_STATE: IoApicState = IoApicState {
    phys_base: 0,
    gsi_base: 0,
    pin_count: 0,
};

/// Discovered I/O APICs, populated once by [`init`] from
/// `kernel_mmio.ioapics[..]` (with a single-entry fallback when the bootloader
/// reports none).
///
/// SAFETY: written exactly once during Phase 5 `init`, single-threaded;
/// subsequent reads happen from IRQ paths after SMP is active and observe a
/// fully-written value because the write precedes SMP bring-up.
static mut IOAPICS: [IoApicState; MAX_IOAPICS] = [EMPTY_STATE; MAX_IOAPICS];
static mut IOAPIC_COUNT: usize = 0;

/// Serialises the `IOREGSEL`/`IOWIN` access sequences of [`route`], [`mask`]
/// and [`unmask`] across CPUs (module doc § Locking). A leaf lock: nothing is
/// acquired while it is held.
static IOAPIC_LOCK: crate::sync::Spinlock = crate::sync::Spinlock::new();

/// One past the highest GSI the I/O APICs in `states` cover, capped at `ceiling`: the
/// routing table's line count.
fn gsi_limit_of(states: &[IoApicState], ceiling: u32) -> u32
{
    states
        .iter()
        .map(|s| s.gsi_base.saturating_add(s.pin_count))
        .max()
        .unwrap_or(0)
        .min(ceiling)
}

/// One past the highest GSI the discovered I/O APICs cover, capped at the Interrupt id
/// space (`super::ROOT_IRQ_COUNT`): the number of lines the routing table needs. Zero
/// before [`init`].
#[cfg(not(test))]
#[must_use]
pub fn gsi_limit() -> u32
{
    // SAFETY: IOAPIC_COUNT and IOAPICS are written exactly once during init,
    // before any reader; entries [0..count) are initialized.
    let states = unsafe {
        core::slice::from_raw_parts(
            core::ptr::addr_of!(IOAPICS).cast::<IoApicState>(),
            IOAPIC_COUNT,
        )
    };
    gsi_limit_of(states, super::ROOT_IRQ_COUNT)
}

/// Whether a discovered I/O APIC implements `gsi`.
#[cfg(not(test))]
#[must_use]
pub fn owns(gsi: u32) -> bool
{
    lookup_ioapic_for_gsi(gsi).is_some()
}

/// Locate the IOAPIC owning `gsi`. Returns `(phys_base, intra_ioapic_pin)`.
fn lookup_ioapic_for_gsi(gsi: u32) -> Option<(u64, u32)>
{
    // SAFETY: IOAPIC_COUNT and IOAPICS are written exactly once during init,
    // before any IRQ delivery; reads observe the fully-written value.
    let count = unsafe { IOAPIC_COUNT };
    let base = core::ptr::addr_of!(IOAPICS).cast::<IoApicState>();
    for i in 0..count
    {
        // SAFETY: i < count ≤ MAX_IOAPICS; entries [0..count) are initialized.
        let s = unsafe { *base.add(i) };
        if gsi >= s.gsi_base && gsi - s.gsi_base < s.pin_count
        {
            return Some((s.phys_base, gsi - s.gsi_base));
        }
    }
    None
}

// ── Register access ───────────────────────────────────────────────────────────

/// Write `val` to register `reg` of the IOAPIC at `phys_base`.
///
/// # Safety
/// Must only be called after Phase 3 (direct map active) with a valid IOAPIC
/// physical base, either from single-threaded [`init`] or with `IOAPIC_LOCK`
/// held across the caller's whole access sequence.
unsafe fn ioapic_write(phys_base: u64, reg: u32, val: u32)
{
    let base = (super::paging::direct_map_base() + phys_base) as usize;
    // SAFETY: phys_base is a valid IOAPIC MMIO base mapped through the direct
    // map; IOREGSEL/IOWIN offsets are within IOAPIC register range; volatile
    // ensures proper ordering of register select and data writes.
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
        core::ptr::write_volatile((base + IOWIN) as *mut u32, val);
    }
}

/// Read register `reg` of the IOAPIC at `phys_base`.
///
/// # Safety
/// Same as [`ioapic_write`].
unsafe fn ioapic_read(phys_base: u64, reg: u32) -> u32
{
    let base = (super::paging::direct_map_base() + phys_base) as usize;
    // SAFETY: see ioapic_write.
    unsafe {
        core::ptr::write_volatile((base + IOREGSEL) as *mut u32, reg);
        core::ptr::read_volatile((base + IOWIN) as *const u32)
    }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Initialise every I/O APIC reported by the bootloader: read its pin count
/// from the version register, mask all entries.
///
/// # Safety
/// Must be called from a single-threaded context after Phase 3 completes and
/// after `kernel_mmio` has been captured.
#[cfg(not(test))]
pub unsafe fn init()
{
    let mut buf = [IoApicEntry::default(); MAX_IOAPICS];
    let entries = super::platform::ioapics_into(&mut buf);

    let count = entries.len().min(MAX_IOAPICS);
    for (i, entry) in entries.iter().take(count).enumerate()
    {
        // SAFETY: single-threaded init phase after Phase 3; direct map active.
        let ver = unsafe { ioapic_read(entry.phys_base, IOAPICVER) };
        let max_entry = (ver >> 16) & 0xFF;
        let pin_count = max_entry + 1;

        // SAFETY: single-threaded init phase; reading IOAPICID register.
        let ioapic_id = unsafe { ioapic_read(entry.phys_base, IOAPICID) };

        // SAFETY: single-threaded init phase; pre-SMP write.
        unsafe {
            IOAPICS[i] = IoApicState {
                phys_base: entry.phys_base,
                gsi_base: entry.gsi_base,
                pin_count,
            };
        }

        crate::kprintln!(
            "ioapic[{}]: base={:#x} id={:#x} gsi_base={} pins={}",
            i,
            entry.phys_base,
            ioapic_id,
            entry.gsi_base,
            pin_count
        );
        if entry.gsi_base.saturating_add(pin_count) > super::ROOT_IRQ_COUNT
        {
            crate::kprintln!(
                "ioapic[{}]: GSIs from {} lie past the Interrupt id space ({}); not routable",
                i,
                super::ROOT_IRQ_COUNT.max(entry.gsi_base),
                super::ROOT_IRQ_COUNT
            );
        }

        // Mask all entries on this IOAPIC (bit 16 = interrupt mask = 1).
        for pin in 0..pin_count
        {
            // SAFETY: single-threaded init phase; programming redirection
            // entries to masked state; no concurrent access or IRQ delivery.
            unsafe {
                ioapic_write(entry.phys_base, 0x10 + 2 * pin, REDIR_MASK);
                ioapic_write(entry.phys_base, 0x11 + 2 * pin, 0);
            }
        }
    }

    // SAFETY: single-threaded init phase; pre-SMP write.
    unsafe {
        IOAPIC_COUNT = count;
    }
}

/// Program a redirection entry for `gsi` to deliver `vector` to the local APIC
/// with id `destination` (physical destination mode, so at most `0xFF`).
///
/// The entry is programmed masked; call [`unmask`] when ready to receive.
/// Uses edge-triggered, active-high, fixed delivery. A GSI no discovered I/O
/// APIC owns is left alone (`interrupts::route_device_irq` checks [`owns`] first).
///
/// # Safety
/// Must only be called after [`init`].
#[cfg(not(test))]
pub unsafe fn route(gsi: u32, vector: u8, destination: u8)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        return;
    };
    // Low dword: vector | fixed delivery | masked.
    // High dword: destination APIC id in bits [31:24] (entry bits [63:56]).
    let low = REDIR_MASK | REDIR_FIXED | (vector as u32);
    let high = u32::from(destination) << 24;

    // SAFETY: caller ensures init() has completed; entry remains masked
    // until unmask(). IOAPIC_LOCK covers both select/window pairs.
    unsafe {
        let saved = IOAPIC_LOCK.lock_raw();
        ioapic_write(base, 0x10 + 2 * pin, low);
        ioapic_write(base, 0x11 + 2 * pin, high);
        IOAPIC_LOCK.unlock_raw(saved);
    }
}

/// Mask (suppress delivery of) the redirection entry for `gsi`.
///
/// # Safety
/// Must only be called after [`init`].
#[cfg(not(test))]
pub unsafe fn mask(gsi: u32)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        return;
    };
    let reg = 0x10 + 2 * pin;
    // SAFETY: caller ensures init() has completed; setting the mask bit is
    // architecture-defined. IOAPIC_LOCK covers the whole read-modify-write.
    unsafe {
        let saved = IOAPIC_LOCK.lock_raw();
        let current = ioapic_read(base, reg);
        ioapic_write(base, reg, current | REDIR_MASK);
        IOAPIC_LOCK.unlock_raw(saved);
    }
}

/// Unmask (enable delivery of) the redirection entry for `gsi`.
///
/// # Safety
/// Must only be called after [`init`] and after [`route`] has programmed the entry.
#[cfg(not(test))]
pub unsafe fn unmask(gsi: u32)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        return;
    };
    let reg = 0x10 + 2 * pin;
    // SAFETY: caller ensures init() and route() have completed; clearing the
    // mask bit enables IRQ delivery for a registered handler. IOAPIC_LOCK
    // covers the whole read-modify-write.
    unsafe {
        let saved = IOAPIC_LOCK.lock_raw();
        let current = ioapic_read(base, reg);
        ioapic_write(base, reg, current & !REDIR_MASK);
        IOAPIC_LOCK.unlock_raw(saved);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    fn table() -> [AtomicU32; DEVICE_VECTOR_COUNT]
    {
        [const { AtomicU32::new(0) }; DEVICE_VECTOR_COUNT]
    }

    #[test]
    fn routed_gsis_get_distinct_device_vectors()
    {
        // GSIs past the old 23-gate range (a second I/O APIC's) are assigned too.
        let t = table();
        let a = assign_vector_in(&t, 2).expect("vector");
        let b = assign_vector_in(&t, 40).expect("vector");
        assert_ne!(a, b);
        assert_eq!(find_vector(&t, 40), Some(b));
    }

    #[test]
    fn a_gsi_routed_again_keeps_its_vector()
    {
        let t = table();
        let first = assign_vector_in(&t, 7).expect("vector");
        assert_eq!(assign_vector_in(&t, 7), Some(first));
    }

    #[test]
    fn exhausted_vectors_refuse_a_new_gsi_until_one_is_released()
    {
        let t = table();
        for gsi in 0..DEVICE_VECTOR_COUNT as u32
        {
            assert!(assign_vector_in(&t, gsi).is_some());
        }
        assert_eq!(assign_vector_in(&t, 1000), None);
        release_vector_in(&t, 5);
        assert_eq!(find_vector(&t, 5), None);
        assert!(assign_vector_in(&t, 1000).is_some());
    }

    #[test]
    fn gsi_zero_is_assignable()
    {
        // The table marks a free vector with 0, so GSI 0 must not read as free.
        let t = table();
        let v = assign_vector_in(&t, 0).expect("vector");
        assert_eq!(find_vector(&t, 0), Some(v));
        assert_ne!(assign_vector_in(&t, 1), Some(v));
    }

    #[test]
    fn device_vectors_avoid_the_exception_timer_ipi_and_spurious_vectors()
    {
        use crate::arch::current::interrupts::{IPI_VECTOR_TLB_SHOOTDOWN, IPI_VECTOR_WAKEUP};
        use crate::arch::current::timer::TIMER_VECTOR;

        /// The spurious-interrupt vector `idt::init` installs.
        const SPURIOUS_VECTOR: u8 = 255;

        let t = table();
        for gsi in 0..DEVICE_VECTOR_COUNT as u32
        {
            let vector = assign_vector_in(&t, gsi).expect("vector");
            assert!(vector > 31, "GSI {gsi} assigned exception vector {vector}");
            for reserved in [
                TIMER_VECTOR,
                IPI_VECTOR_TLB_SHOOTDOWN,
                IPI_VECTOR_WAKEUP,
                SPURIOUS_VECTOR,
            ]
            {
                assert_ne!(vector, reserved, "GSI {gsi} assigned a reserved vector");
            }
        }
    }

    #[test]
    fn gsi_limit_covers_every_ioapic_and_stops_at_the_id_space()
    {
        let states = [
            IoApicState {
                phys_base: 0xFEC0_0000,
                gsi_base: 0,
                pin_count: 24,
            },
            IoApicState {
                phys_base: 0xFEC0_1000,
                gsi_base: 24,
                pin_count: 32,
            },
        ];
        assert_eq!(gsi_limit_of(&states, 2048), 56);
        assert_eq!(gsi_limit_of(&states, 40), 40);
        assert_eq!(gsi_limit_of(&[], 2048), 0);
    }
}
