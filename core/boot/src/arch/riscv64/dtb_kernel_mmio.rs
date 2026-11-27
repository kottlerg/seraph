// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/riscv64/dtb_kernel_mmio.rs

//! RISC-V `kernel_mmio` extraction from the Flattened Device Tree.
//!
//! Writes the first `ns16550a` node's window into [`KernelMmio::uart_base`]
//! / `uart_size`, the supervisor-level AIA controllers into
//! [`KernelMmio::aplic`] and [`KernelMmio::imsic`], and the non-MMIO hart
//! facts [`KernelMmio::timebase_freq`] and [`KernelMmio::hart_caps`] from
//! the `/cpus` nodes. Runs only for fields the caller left zero
//! (`hart_caps` bits are only ever set), so an earlier ACPI pass's values
//! take precedence.
//!
//! The tree reaches it as a [`Tree`] over the blob
//! [`crate::tables::device_tree`] views through the memory map;
//! `boot_firmware::dtb` walks it.

use boot_firmware::dtb::Tree;
use boot_protocol::KernelMmio;

use crate::bprintln;

/// Populate the arch-specific `kernel_mmio` fields for RISC-V from the tree:
/// - The first `ns16550a` node's first `reg` window with a non-zero base
///   ([`Tree::uart`]) → `uart_base`, `uart_size`.
/// - The supervisor-level `riscv,aplic` and `riscv,imsics` nodes
///   ([`Tree::aia`]) → `aplic`, `imsic`.
/// - `/cpus` nodes ([`Tree::hart_caps`]) → `timebase_freq` and the
///   `HART_CAP_*` bits every enabled hart advertises (Sstc, Svpbmt, Svinval,
///   Svnapot, Ssaia, Zawrs).
///
/// A field already populated by a prior pass is left untouched; the caller
/// runs higher-authority sources (ACPI) first when both are available.
pub fn parse_kernel_mmio(tree: &Tree<'_>, km: &mut KernelMmio)
{
    if km.uart_base == 0
        && let Some((base, size)) = tree.uart()
    {
        km.uart_base = base;
        km.uart_size = size;
    }

    if km.aplic.base == 0 || km.imsic.base == 0
    {
        let aia = tree.aia();
        if let Some(hart) = aia.off_layout_hart
        {
            bprintln!("[--------] boot: dtb: IMSIC not reported, off-layout hart={hart}");
        }
        if km.aplic.base == 0
        {
            km.aplic = aia.aplic;
        }
        if km.imsic.base == 0
        {
            km.imsic = aia.imsic;
        }
    }

    let (timebase_freq, caps) = tree.hart_caps();
    if km.timebase_freq == 0
    {
        km.timebase_freq = timebase_freq;
    }
    km.hart_caps |= caps;
}
