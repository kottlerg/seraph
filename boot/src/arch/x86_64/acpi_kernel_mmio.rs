// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/x86_64/acpi_kernel_mmio.rs

//! x86-64 `kernel_mmio` extraction from ACPI.
//!
//! Walks RSDP → XSDT → MADT to populate [`KernelMmio::lapic_base`] and
//! [`KernelMmio::ioapics`]. The arch-neutral ACPI table-walk primitives
//! (signature constants, byte readers, `phys_slice`) live in
//! [`crate::acpi`]; only the x86-specific MADT-entry interpretation
//! lives here.

use crate::acpi::{
    MADT_ENTRIES_OFF, MADT_TYPE_IOAPIC, MADT_TYPE_LAPIC_OVERRIDE, RSDP_OFF_REVISION, RSDP_OFF_XSDT,
    RSDP_SIG, SDT_HDR_LEN, SDT_OFF_LENGTH, SDT_OFF_SIGNATURE, phys_slice, read_u8, read_u32,
    read_u64,
};
use crate::bprintln;
use boot_protocol::{IoApicEntry, KernelMmio, MAX_IOAPICS};

/// Populate the arch-specific `kernel_mmio` fields for x86-64 from ACPI.
///
/// Walks RSDP → XSDT → MADT. Extracts the Local APIC base (header field,
/// potentially overridden by MADT type 5) and the I/O APIC register
/// windows from MADT type-1 entries. Fields that cannot be sourced are
/// left at their caller-provided default (typically zero, in which case
/// the kernel falls back to its hardcoded constants).
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
    // SAFETY: caller guarantees rsdp_addr is a valid, identity-mapped RSDP.
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

    // SAFETY: xsdt_addr comes from a validated RSDP.
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
        if &hdr[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4] == b"APIC"
        {
            let table_len = read_u32(hdr, SDT_OFF_LENGTH) as usize;
            if table_len >= SDT_HDR_LEN
            {
                // SAFETY: length validated.
                let table = unsafe { phys_slice(table_addr, table_len) };
                extract_madt_kernel_mmio(table, km);
                return;
            }
        }
    }
}

/// Walk a validated MADT and populate `km.lapic_base` + `km.ioapics[..]`.
///
/// Oversize IOAPIC counts (> [`MAX_IOAPICS`]) are truncated with a
/// diagnostic.
fn extract_madt_kernel_mmio(table: &[u8], km: &mut KernelMmio)
{
    // LAPIC base from the MADT header (offset 36, u32).
    km.lapic_base = u64::from(read_u32(table, SDT_HDR_LEN));

    let mut truncated = false;
    let mut off = MADT_ENTRIES_OFF;
    while off + 2 <= table.len()
    {
        let entry_type = read_u8(table, off);
        let entry_len = read_u8(table, off + 1) as usize;
        if entry_len < 2 || off + entry_len > table.len()
        {
            break;
        }

        match entry_type
        {
            MADT_TYPE_IOAPIC if entry_len >= 12 =>
            {
                // Type 1 (I/O APIC), length 12:
                //   off+2: id(u8)  off+3: reserved
                //   off+4: address(u32)  off+8: gsi_base(u32)
                let id = u32::from(read_u8(table, off + 2));
                let phys_base = u64::from(read_u32(table, off + 4));
                let gsi_base = read_u32(table, off + 8);
                let idx = km.ioapic_count as usize;
                if idx < MAX_IOAPICS
                {
                    km.ioapics[idx] = IoApicEntry {
                        id,
                        phys_base,
                        gsi_base,
                    };
                    km.ioapic_count += 1;
                }
                else
                {
                    truncated = true;
                }
            }
            MADT_TYPE_LAPIC_OVERRIDE if entry_len >= 12 =>
            {
                // Type 5 (Local APIC Address Override):
                //   off+2-3: reserved  off+4: address(u64)
                km.lapic_base = read_u64(table, off + 4);
            }
            _ =>
            {}
        }

        off += entry_len;
    }

    if truncated
    {
        bprintln!("[--------] boot: ACPI: MADT reports > MAX_IOAPICS IOAPICs; surplus dropped");
    }
}
