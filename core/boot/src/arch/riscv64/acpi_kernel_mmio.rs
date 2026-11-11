// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/riscv64/acpi_kernel_mmio.rs

//! RISC-V `kernel_mmio` extraction from ACPI.
//!
//! Walks RSDP → XSDT → MADT for the PLIC entry (type 0x1B) to populate
//! [`KernelMmio::plic_base`], `plic_size` and `plic_ndev`, and for the APLIC,
//! IMSIC and RINTC entries (types 0x1A, 0x19, 0x18) to populate
//! [`KernelMmio::aplic`] and [`KernelMmio::imsic`], uses the shared SPCR
//! walker to populate [`KernelMmio::uart_base`] and `uart_size`, and
//! uses the shared RHCT walker to populate the non-MMIO hart facts
//! [`KernelMmio::timebase_freq`] and [`KernelMmio::hart_caps`]. Fields
//! already non-zero are left untouched so a caller that has run an
//! earlier pass (currently: none; reserved for future higher-authority
//! sources) wins; `hart_caps` bits are only ever set, never cleared.
//!
//! The generic ACPI primitives (RSDP/XSDT validation, byte readers, the
//! RHCT walker) live in [`crate::acpi`]; the SPCR walker lives in
//! [`super::acpi_spcr`]. Only the RISC-V-specific interpretation of MADT
//! entries and the UART size convention live here.

use super::acpi_spcr::find_spcr_base;
use crate::acpi::{
    MADT_ENTRIES_OFF, MADT_TYPE_PLIC, find_acpi_table, madt_aia, read_u8, read_u16, read_u32,
    read_u64,
};
use crate::bprintln;
use boot_protocol::KernelMmio;

/// Conventional ns16550a register-file size. SPCR carries no region size; a
/// later DTB pass does not replace this value, because it fills only fields
/// ACPI left zero (per `core/boot/docs/firmware-parsing.md`
/// [§ Architecture Dispatch](../../../docs/firmware-parsing.md#architecture-dispatch)).
const NS16550A_MMIO_SIZE: u64 = 0x100;

/// Populate the arch-specific `kernel_mmio` fields for RISC-V from ACPI.
///
/// Walks:
/// - RSDP → XSDT → MADT for type-0x1B `PlicStructure` entries → first
///   match writes `km.plic_base` / `km.plic_size` (MADT-supplied size
///   used verbatim) and `km.plic_ndev` (the total external interrupt
///   sources).
/// - The same MADT's APLIC, IMSIC and RINTC entries (via the shared
///   [`madt_aia`]) → `km.aplic` and `km.imsic`.
/// - SPCR (via the shared walker) → `km.uart_base` is taken from the
///   Generic Address Structure's `address` field; `km.uart_size` is set
///   to the ns16550a conventional [`NS16550A_MMIO_SIZE`] (0x100) since
///   SPCR does not carry a size field.
/// - RHCT (via the shared walker) → `km.timebase_freq` and the
///   `HART_CAP_*` bits every hart's ISA string names (Sstc, Svpbmt,
///   Svinval, Svnapot, Ssaia).
///
/// Fields the caller left non-zero are preserved; fields left zero are
/// populated when the corresponding table is present.
///
/// # Safety
/// `rsdp_addr` must be the physical address of a valid, identity-mapped
/// ACPI RSDP.
pub unsafe fn parse_kernel_mmio(rsdp_addr: u64, km: &mut KernelMmio)
{
    if rsdp_addr == 0
    {
        return;
    }

    // SAFETY: caller guarantees rsdp_addr is valid and identity-mapped.
    if let Some(madt) = unsafe { find_acpi_table(rsdp_addr, *b"APIC") }
    {
        scan_madt_for_plic(madt, km);
        fill_aia(madt, km);
    }

    if km.uart_base == 0
    {
        // SAFETY: rsdp_addr validity propagates.
        if let Some(base) = unsafe { find_spcr_base(rsdp_addr) }
        {
            km.uart_base = base;
            km.uart_size = NS16550A_MMIO_SIZE;
        }
    }

    // SAFETY: rsdp_addr validity propagates.
    let (timebase_freq, caps) = unsafe { crate::acpi::parse_hart_caps(rsdp_addr) };
    if km.timebase_freq == 0
    {
        km.timebase_freq = timebase_freq;
    }
    km.hart_caps |= caps;
}

/// Iterate MADT entries; write the first type-0x1B entry into `km`.
///
/// PLIC structure layout (ACPI 6.5+):
/// - `off+ 0`: `type(u8) = 0x1B`
/// - `off+ 1`: `length(u8)` (= 36)
/// - `off+ 2`: `version(u8)`
/// - `off+ 3`: `id(u8)`
/// - `off+ 4`: `hardware_id(8B)`
/// - `off+12`: `total_ext_int_sources(u16)`
/// - `off+14`: `max_priority(u16)`
/// - `off+16`: `flags(u32)`
/// - `off+20`: `size(u32)`
/// - `off+24`: `base(u64)`
/// - `off+32`: `gsi_base(u32)`
fn scan_madt_for_plic(table: &[u8], km: &mut KernelMmio)
{
    let mut off = MADT_ENTRIES_OFF;
    while off + 2 <= table.len()
    {
        let entry_type = read_u8(table, off);
        let entry_len = read_u8(table, off + 1) as usize;
        if entry_len < 2 || off + entry_len > table.len()
        {
            break;
        }
        if entry_type == MADT_TYPE_PLIC && entry_len >= 36 && km.plic_base == 0
        {
            let size = u64::from(read_u32(table, off + 20));
            let base = read_u64(table, off + 24);
            if base != 0
            {
                km.plic_base = base;
                km.plic_size = size;
                km.plic_ndev = u64::from(read_u16(table, off + 12));
                return;
            }
        }
        off += entry_len;
    }
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
