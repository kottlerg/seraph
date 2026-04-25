// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/platform.rs

//! RISC-V bootloader-discovered hardware accessors.
//!
//! Reads `BootInfo.kernel_mmio` (cached at boot by
//! [`crate::platform::capture_kernel_mmio`]) and falls back to the `SiFive`
//! PLIC / ns16550 conventions when the bootloader did not populate a value.

use core::sync::atomic::{AtomicU64, Ordering};

use boot_protocol::KernelMmio;

/// Default ns16550-compatible UART physical base. Matches the RISC-V Platform
/// Spec reference layout and every UEFI-on-RISC-V firmware observed in this
/// project's test set.
const DEFAULT_UART_BASE: u64 = 0x1000_0000;

/// Default UART MMIO window size when the bootloader did not report one.
const DEFAULT_UART_SIZE: u64 = 0x1000;

/// Default PLIC physical base. The `SiFive` PLIC reference layout places it
/// here; most UEFI-on-RISC-V firmwares match.
const DEFAULT_PLIC_BASE: u64 = 0x0C00_0000;

/// Default PLIC MMIO window size when the bootloader did not report one.
/// 4 MiB covers the priority + per-context enable + threshold + claim/complete
/// ranges defined by the RISC-V PLIC spec.
#[allow(dead_code)] // Exposed via plic_size(); no current in-tree caller.
const DEFAULT_PLIC_SIZE: u64 = 0x0040_0000;

static CACHED_UART_BASE: AtomicU64 = AtomicU64::new(0);
static CACHED_UART_SIZE: AtomicU64 = AtomicU64::new(0);
static CACHED_PLIC_BASE: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)] // Exposed via plic_size(); no current in-tree caller.
static CACHED_PLIC_SIZE: AtomicU64 = AtomicU64::new(0);

fn page_round_up(n: u64) -> u64
{
    (n + 0xFFF) & !0xFFF
}

/// UART physical base. Returns the bootloader-discovered value when non-zero,
/// otherwise [`DEFAULT_UART_BASE`].
#[must_use]
pub fn uart_base() -> u64
{
    let cached = CACHED_UART_BASE.load(Ordering::Relaxed);
    if cached != 0
    {
        return cached;
    }
    let km = crate::platform::kernel_mmio();
    let v = if km.uart_base != 0
    {
        km.uart_base
    }
    else
    {
        DEFAULT_UART_BASE
    };
    CACHED_UART_BASE.store(v, Ordering::Relaxed);
    v
}

/// UART MMIO window size, page-rounded.
#[must_use]
pub fn uart_size() -> u64
{
    let cached = CACHED_UART_SIZE.load(Ordering::Relaxed);
    if cached != 0
    {
        return cached;
    }
    let km = crate::platform::kernel_mmio();
    let raw = if km.uart_size != 0
    {
        km.uart_size
    }
    else
    {
        DEFAULT_UART_SIZE
    };
    let v = page_round_up(raw);
    CACHED_UART_SIZE.store(v, Ordering::Relaxed);
    v
}

/// PLIC physical base.
#[must_use]
pub fn plic_base() -> u64
{
    let cached = CACHED_PLIC_BASE.load(Ordering::Relaxed);
    if cached != 0
    {
        return cached;
    }
    let km = crate::platform::kernel_mmio();
    let v = if km.plic_base != 0
    {
        km.plic_base
    }
    else
    {
        DEFAULT_PLIC_BASE
    };
    CACHED_PLIC_BASE.store(v, Ordering::Relaxed);
    v
}

/// PLIC MMIO window size, page-rounded.
#[allow(dead_code)] // Part of the arch interface; no current in-tree caller.
#[must_use]
pub fn plic_size() -> u64
{
    let cached = CACHED_PLIC_SIZE.load(Ordering::Relaxed);
    if cached != 0
    {
        return cached;
    }
    let km = crate::platform::kernel_mmio();
    let raw = if km.plic_size != 0
    {
        km.plic_size
    }
    else
    {
        DEFAULT_PLIC_SIZE
    };
    let v = page_round_up(raw);
    CACHED_PLIC_SIZE.store(v, Ordering::Relaxed);
    v
}

/// UART physical base for Phase 1 console init.
///
/// Reads `km` directly because Phase 1 runs before the `kernel_mmio` cache
/// is populated. Falls back to [`DEFAULT_UART_BASE`] if the bootloader did
/// not discover a UART (e.g. ACPI-only firmware without an SPCR table).
#[must_use]
pub fn uart_base_for_boot_info(km: &KernelMmio) -> u64
{
    if km.uart_base != 0
    {
        km.uart_base
    }
    else
    {
        DEFAULT_UART_BASE
    }
}

/// Fill `out` with all kernel-internal MMIO regions that must be direct-mapped
/// during Phase 3 page-table setup. Returns the number of populated entries.
///
/// On RISC-V every device the kernel touches (PLIC + UART) lies inside the
/// physical RAM range that the large-page direct map already covers, so this
/// always returns 0. Present for symmetry with the x86 variant.
#[allow(clippy::trivially_copy_pass_by_ref)] // Symmetry with x86_64 signature.
pub fn collect_mmio_direct_map_regions(_km: &KernelMmio, _out: &mut [(u64, u64)]) -> usize
{
    0
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn page_round_up_aligns()
    {
        assert_eq!(page_round_up(1), 0x1000);
        assert_eq!(page_round_up(0x1000), 0x1000);
        assert_eq!(page_round_up(0x1001), 0x2000);
    }

    #[test]
    fn riscv_direct_map_always_empty()
    {
        let mut km = KernelMmio::zero();
        km.plic_base = 0xC000_0000;
        km.uart_base = 0x1000_0000;
        let mut out = [(0u64, 0u64); 4];
        assert_eq!(collect_mmio_direct_map_regions(&km, &mut out), 0);
    }
}
