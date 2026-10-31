// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/platform.rs

//! RISC-V bootloader-discovered hardware accessors.
//!
//! Reads `BootInfo.kernel_mmio` (cached at boot by
//! [`crate::platform::capture_kernel_mmio`]) and falls back to the `SiFive`
//! PLIC / ns16550 conventions when the bootloader did not populate a value.

use core::sync::atomic::{AtomicU64, Ordering};

use boot_protocol::KernelMmio;

/// Default ns16550-compatible UART physical base. Matches the QEMU `virt`
/// machine layout and every UEFI-on-RISC-V firmware observed in this
/// project's test set.
const DEFAULT_UART_BASE: u64 = 0x1000_0000;

/// Default UART MMIO window size when the bootloader did not report one.
const DEFAULT_UART_SIZE: u64 = 0x1000;

/// Default PLIC physical base. The `SiFive` PLIC reference layout places it
/// here; most UEFI-on-RISC-V firmwares match.
const DEFAULT_PLIC_BASE: u64 = 0x0C00_0000;

/// Default PLIC MMIO window size when the bootloader did not report one: the
/// 64 MiB register map of the RISC-V PLIC specification, whose threshold and
/// claim/complete blocks hold all 15 872 contexts. A hardware spec value, so a
/// firmware hart id whose S-mode context the specification admits is never
/// refused for want of a reported size.
pub(super) const DEFAULT_PLIC_SIZE: u64 = 0x0400_0000;

static CACHED_UART_BASE: AtomicU64 = AtomicU64::new(0);
static CACHED_UART_SIZE: AtomicU64 = AtomicU64::new(0);
static CACHED_PLIC_BASE: AtomicU64 = AtomicU64::new(0);
static CACHED_PLIC_SIZE: AtomicU64 = AtomicU64::new(0);
static CACHED_PLIC_NDEV: AtomicU64 = AtomicU64::new(0);

/// The PLIC source count to program for a reported `riscv,ndev` of `reported`: the report
/// when it lies in `1..=PLIC_MAX_SOURCES`, else the specification's
/// [`super::interrupts::PLIC_MAX_SOURCES`]. An unreported count (0) programs every source
/// the specification allows, which is harmless for the ones the PLIC lacks (their
/// priority and enable bits read as zero); a report past the specification is clamped.
fn ndev_for(reported: u64) -> u32
{
    match u32::try_from(reported)
    {
        Ok(n) if (1..=super::interrupts::PLIC_MAX_SOURCES).contains(&n) => n,
        _ => super::interrupts::PLIC_MAX_SOURCES,
    }
}

fn page_round_up(n: u64) -> u64
{
    (n + 0xFFF) & !0xFFF
}

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

/// PLIC MMIO window size, page-rounded. Bounds the per-hart context registers
/// `interrupts::init` and `interrupts::init_ap` program.
// dead_code: host test builds compile out its only readers (interrupts::init
// and init_ap).
#[cfg_attr(test, allow(dead_code))]
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

/// Number of PLIC interrupt sources the kernel programs (sources `1..=plic_ndev()`), from
/// `BootInfo.kernel_mmio.plic_ndev` (the firmware's `riscv,ndev`; see [`ndev_for`]).
#[must_use]
pub fn plic_ndev() -> u32
{
    let cached = CACHED_PLIC_NDEV.load(Ordering::Relaxed);
    if cached != 0
    {
        // The cache holds a value `ndev_for` returned, at most 1023.
        #[allow(clippy::cast_possible_truncation)]
        return cached as u32;
    }
    let v = ndev_for(crate::platform::kernel_mmio().plic_ndev);
    CACHED_PLIC_NDEV.store(u64::from(v), Ordering::Relaxed);
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
// always returns 0 (PLIC + UART lie inside the RAM direct map).
pub use boot_protocol::layout::collect_mmio_direct_map_regions;

/// Most entries [`collect_mmio_direct_map_regions`] writes: none, since the
/// riscv64 producer reports no kernel MMIO outside the RAM direct map.
pub const MMIO_DIRECT_MAP_REGIONS: usize = 0;

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

    // Defect caught: a reported source count trusted past the PLIC specification (the
    // enable and priority loops would write past the source registers), or an unreported
    // count leaving every source unprogrammed.
    #[test]
    fn plic_ndev_takes_the_report_within_the_specification()
    {
        assert_eq!(ndev_for(95), 95);
        assert_eq!(ndev_for(1023), 1023);
        assert_eq!(ndev_for(1024), 1023);
        assert_eq!(ndev_for(u64::MAX), 1023);
        assert_eq!(ndev_for(0), 1023);
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
