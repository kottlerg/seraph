// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/x86_64/acpi_kernel_mmio.rs

//! x86-64 `kernel_mmio` extraction from ACPI.
//!
//! Reads the MADT into [`KernelMmio::lapic_base`] and [`KernelMmio::ioapics`].
//! The MADT reaches it as a slice [`crate::tables::Acpi`] views through the
//! memory map, and `boot_firmware::acpi` decodes it; only the copy into the
//! x86-64 boot protocol's types lives here.

use boot_firmware::acpi::{madt_entries, madt_io_apic, madt_lapic_base};
use boot_protocol::{IoApicEntry, KernelMmio};

use crate::bprintln;
use crate::tables::Acpi;

/// Populate the arch-specific `kernel_mmio` fields for x86-64 from the MADT
/// `acpi` lists: the Local APIC base (the header field, replaced by a type-5
/// override) and the I/O APIC register windows of its type-1 structures.
/// Fields that cannot be sourced are left at their caller-provided default
/// (zero, in which case the kernel falls back to its compiled-in constants).
pub fn parse_kernel_mmio(acpi: &Acpi<'_, '_>, km: &mut KernelMmio)
{
    if let Some(madt) = acpi.table(*b"APIC")
    {
        extract_madt_kernel_mmio(madt, km);
    }
}

/// Write the MADT `table`'s Local APIC base and I/O APICs into
/// `km.lapic_base` and `km.ioapics[..]`. I/O APICs past
/// [`boot_protocol::MAX_IOAPICS`] are dropped with a diagnostic.
fn extract_madt_kernel_mmio(table: &[u8], km: &mut KernelMmio)
{
    km.lapic_base = madt_lapic_base(table);

    let mut truncated = false;
    for io in madt_entries(table).filter_map(|(kind, entry)| madt_io_apic(kind, entry))
    {
        let idx = km.ioapic_count as usize;
        if let Some(slot) = km.ioapics.get_mut(idx)
        {
            *slot = IoApicEntry {
                id: io.id,
                phys_base: io.phys_base,
                gsi_base: io.gsi_base,
            };
            // `idx` indexed a slot of `ioapics`, so the count is far below `u32::MAX`.
            km.ioapic_count = km.ioapic_count.saturating_add(1);
        }
        else
        {
            truncated = true;
        }
    }

    if truncated
    {
        bprintln!("[--------] boot: ACPI: MADT reports > MAX_IOAPICS IOAPICs; surplus dropped");
    }
}
