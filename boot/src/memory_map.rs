// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/memory_map.rs

//! Memory map translation helpers.
//!
//! Converts the UEFI memory descriptor list into the boot protocol's
//! `MemoryMapEntry` format and sorts the result by physical base address.

use crate::uefi::{
    EFI_ACPI_RECLAIM_MEMORY, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA,
    EFI_CONVENTIONAL_MEMORY, EFI_LOADER_CODE, EFI_LOADER_DATA, EFI_PERSISTENT_MEMORY,
    EfiMemoryDescriptor,
};
use boot_protocol::{MemoryMapEntry, MemoryType};

/// Translate a UEFI memory map into the boot protocol's `MemoryMapEntry` format.
///
/// Iterates `uefi_map.map_size / uefi_map.descriptor_size` descriptors and
/// converts each UEFI memory type to a [`MemoryType`]. Writes at most
/// `max_entries` entries to `out`. Returns the number of entries written.
///
/// # Safety
/// `out` must point to an allocation of at least `max_entries * size_of::<MemoryMapEntry>()`
/// bytes. `uefi_map.buffer_phys` must be the UEFI raw map buffer from the most
/// recent `GetMemoryMap` call, with valid descriptors.
pub unsafe fn translate_memory_map(
    uefi_map: &crate::uefi::MemoryMapResult,
    out: *mut MemoryMapEntry,
    max_entries: usize,
) -> usize
{
    let mut count: usize = 0;
    let mut offset: usize = 0;

    while offset + uefi_map.descriptor_size <= uefi_map.map_size && count < max_entries
    {
        // SAFETY: uefi_map.buffer_phys is the UEFI raw map buffer; offset is
        // within map_size; the descriptor at this offset is a valid EfiMemoryDescriptor.
        // cast_possible_truncation: buffer_phys is a UEFI physical address; on all
        // supported UEFI targets (x86_64, riscv64) usize == u64, so no truncation occurs.
        #[allow(clippy::cast_possible_truncation)]
        let desc =
            unsafe { &*((uefi_map.buffer_phys as usize + offset) as *const EfiMemoryDescriptor) };

        let memory_type = translate_memory_type(desc.memory_type);
        let size_bytes = desc.number_of_pages * 4096;

        // SAFETY: count < max_entries; out[count] is within the allocated array.
        unsafe {
            core::ptr::write(
                out.add(count),
                MemoryMapEntry {
                    physical_base: desc.physical_start,
                    size: size_bytes,
                    memory_type,
                },
            );
        }
        count += 1;
        offset += uefi_map.descriptor_size;
    }

    count
}

/// Translate a UEFI `EFI_MEMORY_TYPE` value to the boot protocol's [`MemoryType`].
///
/// Per `boot/docs/uefi-environment.md`:
/// - `EfiConventionalMemory`, `EfiBootServicesCode/Data` → `Usable` (reclaimable)
/// - `EfiLoaderCode/Data` → `Loaded` (in-use by bootloader)
/// - `EfiACPIReclaimMemory` → `AcpiReclaimable`
/// - `EfiPersistentMemory` → `Persistent`
/// - All other types → `Reserved`
fn translate_memory_type(uefi_type: u32) -> MemoryType
{
    match uefi_type
    {
        EFI_CONVENTIONAL_MEMORY | EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA =>
        {
            MemoryType::Usable
        }

        EFI_LOADER_CODE | EFI_LOADER_DATA => MemoryType::Loaded,

        EFI_ACPI_RECLAIM_MEMORY => MemoryType::AcpiReclaimable,

        EFI_PERSISTENT_MEMORY => MemoryType::Persistent,

        // EfiRuntimeServicesCode/Data, EfiACPIMemoryNVS, EfiMemoryMappedIO,
        // EfiMemoryMappedIOPortSpace, and all unrecognised types are Reserved.
        _ => MemoryType::Reserved,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use core::mem::size_of;

    use super::{insertion_sort_memory_map, translate_memory_map, translate_memory_type};
    use crate::uefi::{
        EFI_ACPI_MEMORY_NVS, EFI_ACPI_RECLAIM_MEMORY, EFI_BOOT_SERVICES_CODE,
        EFI_BOOT_SERVICES_DATA, EFI_CONVENTIONAL_MEMORY, EFI_LOADER_CODE, EFI_LOADER_DATA,
        EFI_MEMORY_MAPPED_IO, EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_PERSISTENT_MEMORY,
        EFI_RUNTIME_SERVICES_CODE, EFI_RUNTIME_SERVICES_DATA, EfiMemoryDescriptor, MemoryMapResult,
    };
    use boot_protocol::{MemoryMapEntry, MemoryType};

    // ── translate_memory_type ─────────────────────────────────────────────────

    #[test]
    fn conventional_memory_maps_to_usable()
    {
        assert_eq!(
            translate_memory_type(EFI_CONVENTIONAL_MEMORY),
            MemoryType::Usable
        );
    }

    #[test]
    fn boot_services_code_maps_to_usable()
    {
        assert_eq!(
            translate_memory_type(EFI_BOOT_SERVICES_CODE),
            MemoryType::Usable
        );
    }

    #[test]
    fn boot_services_data_maps_to_usable()
    {
        assert_eq!(
            translate_memory_type(EFI_BOOT_SERVICES_DATA),
            MemoryType::Usable
        );
    }

    #[test]
    fn loader_code_maps_to_loaded()
    {
        assert_eq!(translate_memory_type(EFI_LOADER_CODE), MemoryType::Loaded);
    }

    #[test]
    fn loader_data_maps_to_loaded()
    {
        assert_eq!(translate_memory_type(EFI_LOADER_DATA), MemoryType::Loaded);
    }

    #[test]
    fn acpi_reclaim_maps_to_acpi_reclaimable()
    {
        assert_eq!(
            translate_memory_type(EFI_ACPI_RECLAIM_MEMORY),
            MemoryType::AcpiReclaimable
        );
    }

    #[test]
    fn persistent_memory_maps_to_persistent()
    {
        assert_eq!(
            translate_memory_type(EFI_PERSISTENT_MEMORY),
            MemoryType::Persistent
        );
    }

    #[test]
    fn runtime_services_code_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_RUNTIME_SERVICES_CODE),
            MemoryType::Reserved
        );
    }

    #[test]
    fn runtime_services_data_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_RUNTIME_SERVICES_DATA),
            MemoryType::Reserved
        );
    }

    #[test]
    fn acpi_nvs_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_ACPI_MEMORY_NVS),
            MemoryType::Reserved
        );
    }

    #[test]
    fn mmio_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_MEMORY_MAPPED_IO),
            MemoryType::Reserved
        );
    }

    #[test]
    fn mmio_port_space_maps_to_reserved()
    {
        assert_eq!(
            translate_memory_type(EFI_MEMORY_MAPPED_IO_PORT_SPACE),
            MemoryType::Reserved
        );
    }

    #[test]
    fn unknown_type_maps_to_reserved()
    {
        assert_eq!(translate_memory_type(0xFF), MemoryType::Reserved);
    }

    // ── insertion_sort_memory_map ─────────────────────────────────────────────

    /// Build a `MemoryMapEntry` with the given physical base; other fields are
    /// irrelevant for sort order tests.
    fn make_entry(physical_base: u64) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base,
            size: 0x1000,
            memory_type: MemoryType::Usable,
        }
    }

    #[test]
    fn already_sorted_input_unchanged()
    {
        let mut entries = vec![make_entry(0x1000), make_entry(0x2000), make_entry(0x3000)];
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), entries.len()) };
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[1].physical_base, 0x2000);
        assert_eq!(entries[2].physical_base, 0x3000);
    }

    #[test]
    fn reverse_sorted_input_is_sorted()
    {
        let mut entries = vec![make_entry(0x3000), make_entry(0x2000), make_entry(0x1000)];
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), entries.len()) };
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[1].physical_base, 0x2000);
        assert_eq!(entries[2].physical_base, 0x3000);
    }

    #[test]
    fn empty_input_does_not_panic()
    {
        let mut entries: Vec<MemoryMapEntry> = Vec::new();
        // count=0: the loop body never runs; nothing is read or written.
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), 0) };
    }

    #[test]
    fn single_element_input_unchanged()
    {
        let mut entries = vec![make_entry(0xABCD)];
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), 1) };
        assert_eq!(entries[0].physical_base, 0xABCD);
    }

    #[test]
    fn duplicate_bases_do_not_panic()
    {
        let mut entries = vec![
            make_entry(0x2000),
            make_entry(0x1000),
            make_entry(0x1000),
            make_entry(0x3000),
        ];
        // Must not crash; exact ordering of duplicates is unspecified.
        unsafe { insertion_sort_memory_map(entries.as_mut_ptr(), entries.len()) };
        // First element must be one of the 0x1000 entries.
        assert_eq!(entries[0].physical_base, 0x1000);
        assert_eq!(entries[3].physical_base, 0x3000);
    }

    // ── translate_memory_map ──────────────────────────────────────────────────

    /// Construct a single-descriptor UEFI memory map buffer, run
    /// `translate_memory_map`, and return the translated entries.
    fn run_translate(descs: &[EfiMemoryDescriptor], max_entries: usize) -> Vec<MemoryMapEntry>
    {
        let stride = size_of::<EfiMemoryDescriptor>();
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            map_size: descs.len() * stride,
            map_key: 0,
            descriptor_size: stride,
        };
        let dummy = MemoryMapEntry {
            physical_base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
        };
        let mut out = vec![dummy; max_entries];
        let count = unsafe { translate_memory_map(&uefi_map, out.as_mut_ptr(), max_entries) };
        out.truncate(count);
        out
    }

    #[test]
    fn single_descriptor_translates_correctly()
    {
        let descs = [EfiMemoryDescriptor {
            memory_type: EFI_CONVENTIONAL_MEMORY,
            physical_start: 0x10_0000,
            virtual_start: 0,
            number_of_pages: 8,
            attribute: 0,
        }];
        let entries = run_translate(&descs, 8);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].physical_base, 0x10_0000);
        assert_eq!(entries[0].size, 8 * 4096);
        assert_eq!(entries[0].memory_type, MemoryType::Usable);
    }

    #[test]
    fn multiple_descriptors_translated()
    {
        let descs = [
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x0000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
            EfiMemoryDescriptor {
                memory_type: EFI_LOADER_DATA,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 2,
                attribute: 0,
            },
        ];
        let entries = run_translate(&descs, 8);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].memory_type, MemoryType::Usable);
        assert_eq!(entries[1].memory_type, MemoryType::Loaded);
        assert_eq!(entries[1].size, 2 * 4096);
    }

    #[test]
    fn max_entries_cap_limits_output()
    {
        let descs = [
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x0000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
            EfiMemoryDescriptor {
                memory_type: EFI_CONVENTIONAL_MEMORY,
                physical_start: 0x1000,
                virtual_start: 0,
                number_of_pages: 1,
                attribute: 0,
            },
        ];
        // max_entries=1 must cap output even though there are 2 descriptors.
        let entries = run_translate(&descs, 1);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn zero_length_map_returns_zero_entries()
    {
        let descs: &[EfiMemoryDescriptor] = &[];
        let entries = run_translate(descs, 8);
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn padded_descriptor_size_handled_correctly()
    {
        // Simulate UEFI returning descriptors with 8 bytes of trailing padding
        // (descriptor_size > size_of::<EfiMemoryDescriptor>()).
        let stride = size_of::<EfiMemoryDescriptor>() + 8;
        // Allocate one stride-sized slot, zeroed, then write the descriptor at
        // the start of that slot. The trailing 8 bytes remain zero (padding).
        let mut buf = vec![0u8; stride];
        let desc = EfiMemoryDescriptor {
            memory_type: EFI_PERSISTENT_MEMORY,
            physical_start: 0x4000,
            virtual_start: 0,
            number_of_pages: 4,
            attribute: 0,
        };
        // SAFETY: buf has stride >= size_of::<EfiMemoryDescriptor>() bytes and
        // is properly aligned (Vec<u8> for a struct starting with u32 is fine on
        // x86-64/aarch64 where u32 alignment <= 8). We write one descriptor.
        unsafe { core::ptr::write(buf.as_mut_ptr() as *mut EfiMemoryDescriptor, desc) };
        let uefi_map = MemoryMapResult {
            buffer_phys: buf.as_ptr() as u64,
            map_size: stride,
            map_key: 0,
            descriptor_size: stride,
        };
        let dummy = MemoryMapEntry {
            physical_base: 0,
            size: 0,
            memory_type: MemoryType::Reserved,
        };
        let mut out = vec![dummy; 4];
        let count = unsafe { translate_memory_map(&uefi_map, out.as_mut_ptr(), 4) };
        assert_eq!(count, 1);
        assert_eq!(out[0].memory_type, MemoryType::Persistent);
        assert_eq!(out[0].physical_base, 0x4000);
        assert_eq!(out[0].size, 4 * 4096);
    }
}

/// Sort `MemoryMapEntry` elements in `[0..count)` by `physical_base` ascending.
///
/// Uses insertion sort — O(n²) worst case, but n is always small (< 700) and
/// the UEFI memory map is often already nearly sorted by the firmware.
///
/// # Safety
/// `entries` must point to an allocation of at least `count` valid, initialised
/// `MemoryMapEntry` elements.
pub unsafe fn insertion_sort_memory_map(entries: *mut MemoryMapEntry, count: usize)
{
    for i in 1..count
    {
        // SAFETY: i < count; entries[i] is a valid initialised MemoryMapEntry.
        let key = unsafe { core::ptr::read(entries.add(i)) };
        let mut j = i;

        while j > 0
        {
            // SAFETY: j - 1 < i < count; entries[j-1] is initialised.
            let prev_base = unsafe { (*entries.add(j - 1)).physical_base };
            if prev_base <= key.physical_base
            {
                break;
            }
            // SAFETY: j and j-1 are both < count and within the allocation.
            unsafe { core::ptr::copy_nonoverlapping(entries.add(j - 1), entries.add(j), 1) };
            j -= 1;
        }

        // SAFETY: j < count; entries[j] is within the allocation.
        unsafe { core::ptr::write(entries.add(j), key) };
    }
}
