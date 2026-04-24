// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/ioapic.rs

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
//! # Vector assignment
//! GSI `n` is assigned to IDT vector `DEVICE_VECTOR_BASE + n` (33 + n). This
//! keeps the mapping trivial and avoids a vector allocator.
//!
//! # Limitations / deferred work
//!
//! - **No MSI/MSI-X support.** Required for modern `PCIe` devices.
//!
//! - **Edge-triggered, active-high only.** Level-triggered and active-low
//!   sources (some legacy ISA IRQs via PCI interrupt routing) are not handled.
//!   Add `flags` parsing from the `InterruptObject` when needed.
//!
//! # Modification notes
//! - To add a new GSI: `route(gsi, DEVICE_VECTOR_BASE + gsi as u8)` then
//!   `unmask(gsi)` after registering a signal handler.
//! - To support level-triggered IRQs: set bit 15 (level-sensitive) and
//!   bit 13 (active-low polarity) in the redirection entry low dword.

// cast_possible_truncation: u64→usize APIC MMIO address arithmetic; bounded by APIC layout.
// cast_lossless: u8→u32 vector widening casts.
#![allow(clippy::cast_possible_truncation, clippy::cast_lossless)]

use boot_protocol::{IoApicEntry, MAX_IOAPICS};

use crate::mm::paging::DIRECT_MAP_BASE;

// ── Hardware constants ────────────────────────────────────────────────────────

/// Register select offset (write GSI index here).
const IOREGSEL: usize = 0x00;
/// Data window offset (read/write data here after selecting register).
const IOWIN: usize = 0x10;

/// I/O APIC identification register.
const IOAPICID: u32 = 0x00;
/// I/O APIC version register (bits [23:16] = max redirection entry index).
const IOAPICVER: u32 = 0x01;

/// Base IDT vector for device IRQs.
/// GSI `n` maps to vector `DEVICE_VECTOR_BASE + n`.
pub const DEVICE_VECTOR_BASE: u8 = 33;

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
        if gsi >= s.gsi_base && gsi < s.gsi_base + s.pin_count
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
/// physical base.
unsafe fn ioapic_write(phys_base: u64, reg: u32, val: u32)
{
    let base = (DIRECT_MAP_BASE + phys_base) as usize;
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
    let base = (DIRECT_MAP_BASE + phys_base) as usize;
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

/// Program a redirection entry for `gsi` to deliver `vector`.
///
/// The entry is programmed masked; call [`unmask`] when ready to receive.
/// Uses edge-triggered, active-high, fixed delivery to LAPIC 0.
///
/// TODO: per-IRQ affinity. Every GSI is currently pinned to the BSP LAPIC
/// (destination field = 0). At the current scale this is fine — one block
/// device, one IRQ — but with multiple high-rate sources the BSP becomes
/// the trap bottleneck. Replace the hard-coded destination with a per-GSI
/// selector (round-robin, user-supplied affinity, or a rebalancer). Mirror
/// the matching change on RISC-V (`arch/riscv64/interrupts.rs::plic_enable`).
///
/// # Safety
/// Must only be called after [`init`].
#[cfg(not(test))]
pub unsafe fn route(gsi: u32, vector: u8)
{
    let Some((base, pin)) = lookup_ioapic_for_gsi(gsi)
    else
    {
        crate::kprintln!("ioapic: no IOAPIC owns GSI {} — route ignored", gsi);
        return;
    };
    // Low dword: vector | fixed delivery | masked.
    // High dword: destination LAPIC ID 0 in bits [27:24].
    let low = REDIR_MASK | REDIR_FIXED | (vector as u32);
    let high: u32 = 0; // dest LAPIC ID 0

    // SAFETY: caller ensures init() has completed; entry remains masked
    // until unmask().
    unsafe {
        ioapic_write(base, 0x10 + 2 * pin, low);
        ioapic_write(base, 0x11 + 2 * pin, high);
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
    // SAFETY: caller ensures init() has completed; reading current entry.
    let current = unsafe { ioapic_read(base, reg) };
    // SAFETY: setting mask bit; serializes with IRQ dispatch.
    unsafe {
        ioapic_write(base, reg, current | REDIR_MASK);
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
    // SAFETY: caller ensures init() and route() have completed; reading entry.
    let current = unsafe { ioapic_read(base, reg) };
    // SAFETY: clearing mask bit enables IRQ delivery; caller registered handler.
    unsafe {
        ioapic_write(base, reg, current & !REDIR_MASK);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn device_vector_base_is_33()
    {
        assert_eq!(DEVICE_VECTOR_BASE, 33);
    }

    #[test]
    fn redir_mask_bit_is_16()
    {
        assert_eq!(REDIR_MASK, 1 << 16);
    }

    #[test]
    fn redirection_entry_low_encoding()
    {
        // For GSI 0 with vector 33:
        // low = REDIR_MASK | 33 = 0x0001_0021
        let vector: u8 = 33;
        let low = REDIR_MASK | REDIR_FIXED | (vector as u32);
        assert_eq!(low & 0xFF, 33, "vector in bits [7:0]");
        assert!(low & REDIR_MASK != 0, "entry starts masked");
    }
}
