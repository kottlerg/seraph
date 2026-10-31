// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/platform.rs

//! x86-64 bootloader-discovered hardware accessors.
//!
//! Reads `BootInfo.kernel_mmio` (cached at boot by
//! [`crate::platform::capture_kernel_mmio`]) and falls back to xAPIC
//! architectural defaults when the bootloader did not populate a value.
//!
//! All accessors that are likely to be called repeatedly cache the resolved
//! value so the hot path is a single relaxed atomic load.

use core::sync::atomic::{AtomicU64, Ordering};

// The direct-map region derivation is shared with the bootloader's KASLR
// window selection through `boot_protocol::layout`, so both sides agree on
// what Phase 3 maps above the RAM ceiling.
#[cfg(test)]
use boot_protocol::layout::MMIO_REGION_SIZE;
pub use boot_protocol::layout::collect_mmio_direct_map_regions;
use boot_protocol::layout::{DEFAULT_IOAPIC_BASE, DEFAULT_LAPIC_BASE};

/// Most entries [`collect_mmio_direct_map_regions`] writes: the LAPIC window
/// plus one window per I/O APIC `BootInfo.kernel_mmio` can describe. Derived
/// from the producer's own bounds, so a larger `MAX_IOAPICS` grows the Phase 3
/// buffer with it and no region is dropped.
pub const MMIO_DIRECT_MAP_REGIONS: usize = 1 + boot_protocol::MAX_IOAPICS;
use boot_protocol::{IoApicEntry, KernelMmio};

static CACHED_LAPIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Local APIC physical base.
///
/// Returns the bootloader-discovered value when non-zero, otherwise
/// [`DEFAULT_LAPIC_BASE`]. The first call after `crate::platform::capture_kernel_mmio`
/// populates an internal cache; subsequent calls are a single relaxed load.
#[must_use]
pub fn lapic_base() -> u64
{
    let cached = CACHED_LAPIC_BASE.load(Ordering::Relaxed);
    if cached != 0
    {
        return cached;
    }
    let km = crate::platform::kernel_mmio();
    let v = if km.lapic_base != 0
    {
        km.lapic_base
    }
    else
    {
        DEFAULT_LAPIC_BASE
    };
    CACHED_LAPIC_BASE.store(v, Ordering::Relaxed);
    v
}

/// Copy the discovered I/O APIC entries into `out` and return the populated
/// slice. If the bootloader reported no I/O APICs, synthesise one entry at
/// [`DEFAULT_IOAPIC_BASE`] covering GSI 0.
///
/// `out.len()` must be ≥ 1.
pub fn ioapics_into(out: &mut [IoApicEntry]) -> &[IoApicEntry]
{
    select_ioapics(&crate::platform::kernel_mmio(), out)
}

/// Selection behind [`ioapics_into`], taking the `KernelMmio` snapshot as a
/// parameter so the host tests can drive both the discovered and the
/// synthesised-default outcome.
fn select_ioapics<'a>(km: &KernelMmio, out: &'a mut [IoApicEntry]) -> &'a [IoApicEntry]
{
    debug_assert!(!out.is_empty());
    let count = (km.ioapic_count as usize).min(km.ioapics.len());
    if count == 0
    {
        out[0] = IoApicEntry {
            id: 0,
            phys_base: DEFAULT_IOAPIC_BASE,
            gsi_base: 0,
        };
        return &out[..1];
    }
    let n = count.min(out.len());
    out[..n].copy_from_slice(&km.ioapics[..n]);
    &out[..n]
}

/// UART physical base passed to `serial_init` by `crate::console::init`
/// (Phase 1).
///
/// x86-64 console uses the COM1 I/O port (`0x3F8`), not MMIO, so this always
/// returns 0 and the x86-64 `serial_init` ignores it. Present for symmetry
/// with the RISC-V variant: it takes `&KernelMmio` to match the riscv64
/// signature that `crate::console::init` calls on both architectures.
#[must_use]
pub fn uart_base_for_boot_info(_km: &KernelMmio) -> u64
{
    0
}

/// Physical `(base, size)` of a boot console UART needing a dedicated `Mmio`
/// capability at Phase 7. Returns `None` on x86-64: the boot console is the
/// legacy COM1 I/O-port UART (`0x3F8`), reached via an `IoPort` capability, not
/// MMIO.
#[must_use]
pub fn console_mmio() -> Option<(u64, u64)>
{
    None
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn km_zero() -> KernelMmio
    {
        KernelMmio::zero()
    }

    #[test]
    fn direct_map_default_when_kernel_mmio_zero()
    {
        let km = km_zero();
        let mut out = [(0u64, 0u64); 16];
        let n = collect_mmio_direct_map_regions(&km, &mut out);
        assert_eq!(n, 2);
        assert_eq!(out[0], (DEFAULT_LAPIC_BASE, MMIO_REGION_SIZE));
        assert_eq!(out[1], (DEFAULT_IOAPIC_BASE, MMIO_REGION_SIZE));
    }

    #[test]
    fn direct_map_uses_discovered_values()
    {
        let mut km = km_zero();
        km.lapic_base = 0xDEAD_0000;
        km.ioapic_count = 2;
        km.ioapics[0] = IoApicEntry {
            id: 0,
            phys_base: 0xCAFE_0000,
            gsi_base: 0,
        };
        km.ioapics[1] = IoApicEntry {
            id: 1,
            phys_base: 0xBEEF_0000,
            gsi_base: 24,
        };
        let mut out = [(0u64, 0u64); 16];
        let n = collect_mmio_direct_map_regions(&km, &mut out);
        assert_eq!(n, 3);
        assert_eq!(out[0], (0xDEAD_0000, MMIO_REGION_SIZE));
        assert_eq!(out[1], (0xCAFE_0000, MMIO_REGION_SIZE));
        assert_eq!(out[2], (0xBEEF_0000, MMIO_REGION_SIZE));
    }

    #[test]
    fn ioapics_synthesise_the_default_when_none_discovered()
    {
        let km = km_zero();
        let mut out = [IoApicEntry::default(); 4];
        let got = select_ioapics(&km, &mut out);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, 0);
        assert_eq!(got[0].phys_base, DEFAULT_IOAPIC_BASE);
        assert_eq!(got[0].gsi_base, 0);
    }

    #[test]
    fn ioapics_copy_the_discovered_entries_up_to_the_buffer_length()
    {
        let mut km = km_zero();
        km.ioapic_count = 3;
        for (e, (id, phys_base, gsi_base)) in km.ioapics.iter_mut().zip([
            (0, 0xFEC0_0000, 0),
            (1, 0xFEC0_1000, 24),
            (2, 0xFEC0_2000, 48),
        ])
        {
            *e = IoApicEntry {
                id,
                phys_base,
                gsi_base,
            };
        }
        let mut out = [IoApicEntry::default(); 2];
        let got = select_ioapics(&km, &mut out);
        assert_eq!(got.len(), 2, "clamped to the buffer length");
        assert_eq!(got[0].phys_base, 0xFEC0_0000);
        assert_eq!(got[1].phys_base, 0xFEC0_1000);
        assert_eq!(got[1].gsi_base, 24);
    }

    #[test]
    fn ioapics_clamp_an_oversized_reported_count_to_the_table()
    {
        let mut km = km_zero();
        km.ioapic_count = u32::try_from(km.ioapics.len()).unwrap() + 1;
        let mut out = [IoApicEntry::default(); 2 * boot_protocol::MAX_IOAPICS];
        let got = select_ioapics(&km, &mut out);
        assert_eq!(got.len(), boot_protocol::MAX_IOAPICS);
    }
}
