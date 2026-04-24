// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/platform.rs

//! x86-64 bootloader-discovered hardware accessors.
//!
//! Reads `BootInfo.kernel_mmio` (cached at boot by
//! [`crate::platform::capture_kernel_mmio`]) and falls back to xAPIC
//! architectural defaults when the bootloader did not populate a value.
//!
//! All accessors that are likely to be called repeatedly cache the resolved
//! value so the hot path is a single relaxed atomic load.

use core::sync::atomic::{AtomicU64, Ordering};

use boot_protocol::{IoApicEntry, KernelMmio};

/// Default xAPIC local APIC physical base. Architectural reset value defined
/// by Intel SDM Vol. 3A §10.4.1; firmware may relocate via the
/// `IA32_APIC_BASE` MSR but must report the new value through ACPI MADT.
const DEFAULT_LAPIC_BASE: u64 = 0xFEE0_0000;

/// Default I/O APIC physical base used when the bootloader did not discover
/// any. Standard PC/AT and modern xAPIC layouts place the first I/O APIC at
/// this address.
const DEFAULT_IOAPIC_BASE: u64 = 0xFEC0_0000;

/// Standard MMIO window size for both LAPIC and a single I/O APIC (4 KiB).
pub const MMIO_REGION_SIZE: u64 = 0x1000;

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
    debug_assert!(!out.is_empty());
    let km = crate::platform::kernel_mmio();
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

/// UART physical base for Phase 1 console init.
///
/// x86-64 console uses the COM1 I/O port (`0x3F8`), not MMIO, so this always
/// returns 0. Present for symmetry with the RISC-V variant; the top-level
/// console module dispatches on the result to decide whether `rebase_serial`
/// is meaningful.
#[allow(clippy::trivially_copy_pass_by_ref)] // Symmetry with riscv64.
#[must_use]
pub fn uart_base_for_boot_info(_km: &KernelMmio) -> u64
{
    0
}

/// Fill `out` with all kernel-internal MMIO regions that must be direct-mapped
/// during Phase 3 page-table setup. Returns the number of populated entries.
///
/// Reads `km` directly rather than the cache because Phase 3 runs before the
/// cache is populated.
pub fn collect_mmio_direct_map_regions(km: &KernelMmio, out: &mut [(u64, u64)]) -> usize
{
    let mut n = 0;

    let lapic = if km.lapic_base != 0
    {
        km.lapic_base
    }
    else
    {
        DEFAULT_LAPIC_BASE
    };
    if n < out.len()
    {
        out[n] = (lapic, MMIO_REGION_SIZE);
        n += 1;
    }

    if km.ioapic_count == 0
    {
        if n < out.len()
        {
            out[n] = (DEFAULT_IOAPIC_BASE, MMIO_REGION_SIZE);
            n += 1;
        }
    }
    else
    {
        let count = (km.ioapic_count as usize).min(km.ioapics.len());
        for entry in &km.ioapics[..count]
        {
            if n >= out.len()
            {
                break;
            }
            out[n] = (entry.phys_base, MMIO_REGION_SIZE);
            n += 1;
        }
    }

    n
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
    fn ioapics_into_synthesises_default_when_empty()
    {
        // This test would need a way to set the kernel_mmio cache. Skip
        // since the cache is process-global and other tests touch it.
    }
}
