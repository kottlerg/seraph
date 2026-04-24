// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/acpi_kernel_mmio.rs

//! RISC-V `kernel_mmio` extraction from ACPI.
//!
//! Walks RSDP → XSDT → MADT for the PLIC entry (type 0x1B) to populate
//! [`KernelMmio::plic_base`] and `plic_size`, and uses the shared SPCR
//! walker to populate [`KernelMmio::uart_base`] and `uart_size`. Fields
//! already non-zero are left untouched so a caller that has run an
//! earlier pass (currently: none; reserved for future higher-authority
//! sources) wins.
//!
//! The generic ACPI primitives (RSDP/XSDT validation, byte readers,
//! SPCR walker) live in [`crate::acpi`]; only the RISC-V-specific
//! interpretation of MADT entries and the UART size convention live
//! here.

use super::acpi_spcr::find_spcr_base;
use crate::acpi::{
    MADT_ENTRIES_OFF, MADT_TYPE_PLIC, RSDP_OFF_REVISION, RSDP_OFF_XSDT, RSDP_SIG, SDT_HDR_LEN,
    SDT_OFF_LENGTH, SDT_OFF_SIGNATURE, phys_slice, read_u8, read_u32, read_u64,
};
use boot_protocol::KernelMmio;

/// Conventional ns16550a register-file size. SPCR does not specify a
/// region size; DTB (if subsequently run) does and overrides this.
const NS16550A_MMIO_SIZE: u64 = 0x100;

/// Populate the arch-specific `kernel_mmio` fields for RISC-V from ACPI.
///
/// Walks:
/// - RSDP → XSDT → MADT for type-0x1B `PlicStructure` entries → first
///   match writes `km.plic_base` / `km.plic_size` (MADT-supplied size
///   used verbatim).
/// - SPCR (via the shared walker) → `km.uart_base` is taken from the
///   Generic Address Structure's `address` field; `km.uart_size` is set
///   to the ns16550a conventional [`NS16550A_MMIO_SIZE`] (0x100) since
///   SPCR does not carry a size field.
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
    unsafe { extract_madt_plic(rsdp_addr, km) };

    if km.uart_base == 0
    {
        // SAFETY: rsdp_addr validity propagates.
        if let Some(base) = unsafe { find_spcr_base(rsdp_addr) }
        {
            km.uart_base = base;
            km.uart_size = NS16550A_MMIO_SIZE;
        }
    }
}

/// Walk RSDP → XSDT → MADT on the RISC-V arch and populate the PLIC fields.
///
/// # Safety
/// `rsdp_addr` must be a valid, identity-mapped ACPI RSDP.
unsafe fn extract_madt_plic(rsdp_addr: u64, km: &mut KernelMmio)
{
    // SAFETY: caller guarantees rsdp_addr is valid.
    let rsdp = unsafe { phys_slice(rsdp_addr, 36) };
    if &rsdp[..8] != RSDP_SIG || read_u8(rsdp, RSDP_OFF_REVISION) < 2
    {
        return;
    }
    let xsdt_addr = read_u64(rsdp, RSDP_OFF_XSDT);
    if xsdt_addr == 0
    {
        return;
    }

    // SAFETY: xsdt_addr from validated RSDP.
    let xsdt_hdr = unsafe { phys_slice(xsdt_addr, SDT_HDR_LEN) };
    if &xsdt_hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"XSDT"
    {
        return;
    }
    let xsdt_len = read_u32(xsdt_hdr, SDT_OFF_LENGTH) as usize;
    if xsdt_len < SDT_HDR_LEN
    {
        return;
    }
    // SAFETY: length validated above.
    let xsdt = unsafe { phys_slice(xsdt_addr, xsdt_len) };
    let entries_bytes = &xsdt[SDT_HDR_LEN..];
    let entry_count = entries_bytes.len() / 8;

    for i in 0..entry_count
    {
        let table_addr = read_u64(entries_bytes, i * 8);
        if table_addr == 0
        {
            continue;
        }
        // SAFETY: table_addr read from validated XSDT.
        let hdr = unsafe { phys_slice(table_addr, SDT_HDR_LEN) };
        if &hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] != b"APIC"
        {
            continue;
        }
        let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
        if table_len < SDT_HDR_LEN
        {
            continue;
        }
        // SAFETY: length validated above.
        let table = unsafe { phys_slice(table_addr, table_len) };
        scan_madt_for_plic(table, km);
        return;
    }
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
                return;
            }
        }
        off += entry_len;
    }
}
