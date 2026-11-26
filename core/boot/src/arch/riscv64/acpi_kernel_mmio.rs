// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/riscv64/acpi_kernel_mmio.rs

//! RISC-V `kernel_mmio` extraction from ACPI.
//!
//! Reads the MADT's APLIC, IMSIC and RINTC structures (types 0x1A, 0x19,
//! 0x18) into [`KernelMmio::aplic`] and [`KernelMmio::imsic`], the SPCR's
//! UART into [`KernelMmio::uart_base`] and `uart_size`, and the RHCT into
//! the non-MMIO hart facts [`KernelMmio::timebase_freq`] and
//! [`KernelMmio::hart_caps`]. Fields already non-zero are left untouched so
//! a caller that has run an earlier pass (currently: none; reserved for future
//! higher-authority sources) wins; `hart_caps` bits are only ever set, never
//! cleared.
//!
//! The tables reach it as slices [`crate::tables::Acpi`] views through the
//! memory map; `boot_firmware::acpi` decodes them. Only the RISC-V-specific
//! use of the readings and the UART size convention live here.

use boot_firmware::acpi::{madt_aia, rhct_hart_caps, spcr_mmio_base};
use boot_protocol::KernelMmio;

use crate::bprintln;
use crate::tables::Acpi;

/// Conventional ns16550a register-file size. SPCR carries no region size; a
/// later DTB pass does not replace this value, because it fills only fields
/// ACPI left zero (per `core/boot/docs/firmware-parsing.md`
/// [§ Architecture Dispatch](../../../docs/firmware-parsing.md#architecture-dispatch)).
const NS16550A_MMIO_SIZE: u64 = 0x100;

/// The UART base the first SPCR `acpi` lists with a memory-mapped base names
/// ([`spcr_mmio_base`]).
pub fn spcr_uart_base(acpi: &Acpi<'_, '_>) -> Option<u64>
{
    acpi.tables(&[*b"SPCR"]).find_map(spcr_mmio_base)
}

/// Populate the arch-specific `kernel_mmio` fields for RISC-V from ACPI:
/// - The MADT's APLIC, IMSIC and RINTC structures ([`madt_aia`]) →
///   `km.aplic` and `km.imsic`.
/// - The SPCR ([`spcr_uart_base`]) → `km.uart_base`; `km.uart_size` is the
///   ns16550a conventional [`NS16550A_MMIO_SIZE`] (0x100), since SPCR
///   carries no size.
/// - The RHCT ([`rhct_hart_caps`]) → `km.timebase_freq` and the
///   `HART_CAP_*` bits every hart's ISA string names (Sstc, Svpbmt, Svinval,
///   Svnapot, Ssaia).
///
/// Fields the caller left non-zero are preserved; fields left zero are
/// populated when the corresponding table is present.
pub fn parse_kernel_mmio(acpi: &Acpi<'_, '_>, km: &mut KernelMmio)
{
    if let Some(madt) = acpi.table(*b"APIC")
    {
        fill_aia(madt, km);
    }

    if km.uart_base == 0
        && let Some(base) = spcr_uart_base(acpi)
    {
        km.uart_base = base;
        km.uart_size = NS16550A_MMIO_SIZE;
    }

    let (timebase_freq, caps) = acpi.table(*b"RHCT").map_or((0, 0), rhct_hart_caps);
    if km.timebase_freq == 0
    {
        km.timebase_freq = timebase_freq;
    }
    km.hart_caps |= caps;
}

/// Write the MADT's supervisor-level APLIC domain and IMSIC layout
/// ([`madt_aia`]) into `km.aplic` and `km.imsic`, each only when still zero.
/// An IMSIC whose harts' files lie off its layout is not reported, and a
/// diagnostic names the first such hart.
fn fill_aia(table: &[u8], km: &mut KernelMmio)
{
    let aia = madt_aia(table);
    if km.aplic.base == 0
    {
        km.aplic = aia.aplic;
    }
    if km.imsic.base == 0
    {
        km.imsic = aia.imsic;
    }
    if let Some(hart) = aia.off_layout_hart
    {
        bprintln!(
            "[--------] boot: ACPI: MADT RINTC of hart {hart} names an IMSIC file off the \
             IMSIC layout; IMSIC not reported"
        );
    }
}
