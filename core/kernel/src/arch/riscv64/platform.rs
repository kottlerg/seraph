// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/platform.rs

//! RISC-V bootloader-discovered hardware accessors.
//!
//! Reads `BootInfo.kernel_mmio` (cached at boot by
//! [`crate::platform::capture_kernel_mmio`]) and falls back to the ns16550
//! conventions when the bootloader did not populate a UART. The AIA
//! controllers have no fallback: `aia` reads `kernel_mmio` itself and halts the
//! boot when the bootloader reported none.

use core::sync::atomic::{AtomicU64, Ordering};

use boot_protocol::KernelMmio;

use super::encoding::page_round_up;

/// Default ns16550-compatible UART physical base. Matches the QEMU `virt`
/// machine layout and every UEFI-on-RISC-V firmware observed in this
/// project's test set.
const DEFAULT_UART_BASE: u64 = 0x1000_0000;

/// Default UART MMIO window size when the bootloader did not report one.
const DEFAULT_UART_SIZE: u64 = 0x1000;

static CACHED_UART_BASE: AtomicU64 = AtomicU64::new(0);
static CACHED_UART_SIZE: AtomicU64 = AtomicU64::new(0);

/// Physical `(base, size)` of the boot console UART that needs a dedicated
/// `Mmio` capability minted at Phase 7. On RISC-V the `ns16550` UART is reported
/// through `BootInfo.kernel_mmio` rather than the coarse aperture list; its range
/// may also lie inside an aperture, in which case this cap overlaps an aperture
/// cap. It is surfaced here so init's serial scan finds a dedicated `Mmio`
/// descriptor for it.
// unnecessary_wraps: the Option is part of the cross-arch contract — x86-64's
// `console_mmio` returns None (its console is a legacy I/O-port UART).
#[allow(clippy::unnecessary_wraps)]
#[must_use]
pub fn console_mmio() -> Option<(u64, u64)>
{
    Some((uart_base(), uart_size()))
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
    // A size whose rounding passes the end of the address space is not a UART's.
    let v = page_round_up(raw).unwrap_or(DEFAULT_UART_SIZE);
    CACHED_UART_SIZE.store(v, Ordering::Relaxed);
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

// The direct-map region derivation is shared with the bootloader's KASLR
// window selection through `boot_protocol::layout`; the riscv64 variant
// always returns 0 (APLIC, IMSIC and UART lie inside the RAM direct map).
pub use boot_protocol::layout::collect_mmio_direct_map_regions;

/// The most entries [`collect_mmio_direct_map_regions`] writes, which sizes
/// the Phase 3 buffer: the producer's own bound, so the two cannot disagree.
pub use boot_protocol::layout::MAX_MMIO_DIRECT_MAP_REGIONS as MMIO_DIRECT_MAP_REGIONS;

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn riscv_direct_map_always_empty()
    {
        let mut km = KernelMmio::zero();
        km.aplic.base = 0xC000_0000;
        km.uart_base = 0x1000_0000;
        let mut out = [(0u64, 0u64); 4];
        assert_eq!(collect_mmio_direct_map_regions(&km, &mut out), 0);
    }
}
