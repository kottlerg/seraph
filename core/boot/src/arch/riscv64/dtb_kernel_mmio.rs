// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/dtb_kernel_mmio.rs

//! RISC-V `kernel_mmio` extraction from the Flattened Device Tree.
//!
//! Walks an FDT blob for compatible matches and writes first-match
//! values into [`KernelMmio::plic_base`] / `plic_size` and
//! [`KernelMmio::uart_base`] / `uart_size`. Runs only for fields the
//! caller left zero, so an earlier ACPI pass's values take precedence.
//!
//! The FDT walker itself lives in [`crate::dtb`]; this module consumes
//! the [`Fdt`] surface and applies the RISC-V-specific compatible
//! mapping.

use crate::dtb::Fdt;
use boot_protocol::KernelMmio;

/// Populate the arch-specific `kernel_mmio` fields for RISC-V from the DTB.
///
/// Walks the device tree for compatible matches:
/// - `sifive,plic-1.0.0` / `riscv,plic0` → `plic_base`, `plic_size`.
/// - `ns16550a` → `uart_base`, `uart_size`.
///
/// First match wins (real boards have one PLIC and one primary UART).
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

    if km.plic_base == 0
    {
        // PLIC — try the SiFive-qualified compatible first, then the generic.
        fdt.walk_compatible(b"sifive,plic-1.0.0", |node| {
            if node.reg_count > 0 && km.plic_base == 0
            {
                km.plic_base = node.reg_entries[0].0;
                km.plic_size = node.reg_entries[0].1;
            }
            km.plic_base == 0
        });
    }
    if km.plic_base == 0
    {
        fdt.walk_compatible(b"riscv,plic0", |node| {
            if node.reg_count > 0
            {
                km.plic_base = node.reg_entries[0].0;
                km.plic_size = node.reg_entries[0].1;
            }
            km.plic_base == 0
        });
    }

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
}
