// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/x86_64/acpi_kernel_mmio.rs

//! x86-64 `kernel_mmio` extraction from ACPI.
//!
//! Walks RSDP → XSDT → MADT to populate [`KernelMmio::lapic_base`] and
//! [`KernelMmio::ioapics`]. The arch-neutral ACPI table-walk primitives
//! (signature constants, byte readers, `phys_slice`) live in
//! [`crate::acpi`]; only the x86-specific MADT-entry interpretation
//! lives here.

use crate::acpi::{
    MADT_TYPE_IOAPIC, MADT_TYPE_LAPIC_OVERRIDE, SDT_HDR_LEN, find_acpi_table, madt_entries,
    read_u8, read_u32, read_u64,
};
use crate::bprintln;
use boot_protocol::{IoApicEntry, KernelMmio};

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
    // SAFETY: caller guarantees rsdp_addr is a valid, identity-mapped RSDP.
    if let Some(madt) = unsafe { find_acpi_table(rsdp_addr, *b"APIC") }
    {
        extract_madt_kernel_mmio(madt, km);
    }
}

/// Walk a validated MADT and populate `km.lapic_base` + `km.ioapics[..]`.
///
/// Oversize IOAPIC counts (> [`boot_protocol::MAX_IOAPICS`]) are truncated with a
/// diagnostic.
fn extract_madt_kernel_mmio(table: &[u8], km: &mut KernelMmio)
{
    // LAPIC base from the MADT header (offset 36, u32).
    km.lapic_base = u64::from(read_u32(table, SDT_HDR_LEN));

    let mut truncated = false;
    for (entry_type, e) in madt_entries(table)
    {
        match entry_type
        {
            MADT_TYPE_IOAPIC if e.len() >= 12 =>
            {
                // Type 1 (I/O APIC), length 12:
                //   off+2: id(u8)  off+3: reserved
                //   off+4: address(u32)  off+8: gsi_base(u32)
                let id = u32::from(read_u8(e, 2));
                let phys_base = u64::from(read_u32(e, 4));
                let gsi_base = read_u32(e, 8);
                let idx = km.ioapic_count as usize;
                if let Some(slot) = km.ioapics.get_mut(idx)
                {
                    *slot = IoApicEntry {
                        id,
                        phys_base,
                        gsi_base,
                    };
                    // `idx` indexed a slot of `ioapics`, so the count is far below `u32::MAX`.
                    km.ioapic_count = km.ioapic_count.saturating_add(1);
                }
                else
                {
                    truncated = true;
                }
            }
            MADT_TYPE_LAPIC_OVERRIDE if e.len() >= 12 =>
            {
                // Type 5 (Local APIC Address Override):
                //   off+2-3: reserved  off+4: address(u64)
                km.lapic_base = read_u64(e, 4);
            }
            _ =>
            {}
        }
    }

    if truncated
    {
        bprintln!("[--------] boot: ACPI: MADT reports > MAX_IOAPICS IOAPICs; surplus dropped");
    }
}
