// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/riscv64/dtb_kernel_mmio.rs

//! RISC-V `kernel_mmio` extraction from the Flattened Device Tree.
//!
//! Walks an FDT blob for compatible matches and writes first-match
//! values into [`KernelMmio::uart_base`] / `uart_size`, the supervisor-level AIA
//! controllers into [`KernelMmio::aplic`] and [`KernelMmio::imsic`], and
//! fills the non-MMIO hart
//! facts [`KernelMmio::timebase_freq`] and [`KernelMmio::hart_caps`]
//! from the `/cpus` nodes. Runs only for fields the caller left zero
//! (`hart_caps` bits are only ever set), so an earlier ACPI pass's
//! values take precedence.
//!
//! The FDT walker itself lives in [`crate::dtb`]; this module consumes
//! the [`Fdt`] surface and applies the RISC-V-specific compatible
//! mapping.

use crate::dtb::Fdt;
use boot_protocol::KernelMmio;

/// Populate the arch-specific `kernel_mmio` fields for RISC-V from the DTB.
///
/// Walks the device tree for compatible matches:
/// - `ns16550a` → `uart_base`, `uart_size`.
/// - The supervisor-level `riscv,aplic` and `riscv,imsics` nodes (via
///   [`crate::dtb::parse_aia`]) → `aplic`, `imsic`.
/// - `/cpus` nodes → `timebase_freq` and the `HART_CAP_*` bits every
///   enabled hart advertises (Sstc, Svpbmt, Svinval, Svnapot, Ssaia).
///
/// First match wins (real boards have one primary UART).
/// A field already populated by a prior pass is left untouched; the
/// caller is responsible for running higher-authority sources (ACPI)
/// first if both are available.
///
/// # Safety
/// `dtb_addr` must be the physical address of a valid, identity-mapped FDT.
pub unsafe fn parse_kernel_mmio(dtb_addr: u64, km: &mut KernelMmio)
{
    if dtb_addr == 0
    {
        return;
    }
    // SAFETY: caller guarantees dtb_addr is a valid, identity-mapped DTB.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return;
    };

    if km.uart_base == 0
    {
        fdt.walk_compatible(b"ns16550a", |node| {
            if node.reg_count > 0 && km.uart_base == 0
            {
                km.uart_base = node.reg_entries[0].0;
                km.uart_size = node.reg_entries[0].1;
            }
            km.uart_base == 0
        });
    }

    if km.aplic.base == 0 || km.imsic.base == 0
    {
        // SAFETY: caller guarantees dtb_addr is a valid, identity-mapped DTB.
        let aia = unsafe { crate::dtb::parse_aia(dtb_addr) };
        if km.aplic.base == 0
        {
            km.aplic = aia.aplic;
        }
        if km.imsic.base == 0
        {
            km.imsic = aia.imsic;
        }
    }

    // SAFETY: caller guarantees dtb_addr is a valid, identity-mapped DTB.
    let (timebase_freq, caps) = unsafe { crate::dtb::parse_hart_caps(dtb_addr) };
    if km.timebase_freq == 0
    {
        km.timebase_freq = timebase_freq;
    }
    km.hart_caps |= caps;
}
