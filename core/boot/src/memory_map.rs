// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/memory_map.rs

//! Memory map translation helpers.
//!
//! Converts the UEFI memory descriptor list into the boot protocol's
//! `MemoryMapEntry` format and sorts the result by physical base address.

use crate::bprintln;
use crate::uefi::{
    EFI_ACPI_RECLAIM_MEMORY, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA,
    EFI_CONVENTIONAL_MEMORY, EFI_LOADER_CODE, EFI_LOADER_DATA, EFI_MEMORY_MAPPED_IO,
    EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_PERSISTENT_MEMORY, EfiMemoryDescriptor,
};
use boot_protocol::{MAX_APERTURES, MemoryMapEntry, MemoryType, MmioAperture};

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
/// The mapping is defined in `core/boot/docs/memory-map.md`
/// § UEFI Memory Type → `MemoryType`.
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

        // Every other type is Reserved, per core/boot/docs/memory-map.md
        // § UEFI Memory Type → `MemoryType`.
        _ => MemoryType::Reserved,
    }
}

// ── MMIO aperture derivation ─────────────────────────────────────────────────

/// Derive the coarse MMIO aperture array from the raw UEFI memory map and
/// the caller-supplied firmware and framebuffer seeds (`seed`), following
/// `core/boot/docs/firmware-parsing.md` § `mmio_apertures` construction.
/// Writes at most `MAX_APERTURES` entries to `out` and returns the number
/// written; surplus is dropped with a diagnostic.
///
/// Apertures are coarse by design; see `docs/device-management.md`
/// § Raw Firmware Passthrough for where device-level discovery happens.
///
/// # Safety
/// `uefi_map.buffer_phys` must be the UEFI raw map buffer from the most
/// recent `GetMemoryMap` call, with valid descriptors covering
/// `uefi_map.map_size` bytes. `seed` is a caller-owned slice of already
/// validated apertures.
pub unsafe fn derive_mmio_apertures(
    uefi_map: &crate::uefi::MemoryMapResult,
    seed: &[MmioAperture],
    out: &mut [MmioAperture; MAX_APERTURES],
) -> usize
{
    // Scratch buffer: MAX_APERTURES * 4 gives headroom for fragmented UEFI
    // maps plus seed entries before the merge pass. 16 apertures × 4 × 16
    // bytes = 1 KiB, stack-safe.
    const SCRATCH: usize = MAX_APERTURES * 4;
    let mut buf: [MmioAperture; SCRATCH] = [MmioAperture {
        phys_base: 0,
        size: 0,
    }; SCRATCH];
    let mut n: usize = 0;
    let mut dropped = false;

    // Collect MMIO-class descriptors from the UEFI map.
    let mut offset: usize = 0;
    while offset + uefi_map.descriptor_size <= uefi_map.map_size
    {
        // SAFETY: uefi_map.buffer_phys is the UEFI raw map buffer; offset is
        // within map_size; the descriptor at this offset is a valid
        // EfiMemoryDescriptor produced by firmware.
        // cast_possible_truncation: buffer_phys is a UEFI physical address;
        // on all supported UEFI targets (x86_64, riscv64) usize == u64.
        #[allow(clippy::cast_possible_truncation)]
        let desc =
            unsafe { &*((uefi_map.buffer_phys as usize + offset) as *const EfiMemoryDescriptor) };
        offset += uefi_map.descriptor_size;

        let is_mmio = desc.memory_type == EFI_MEMORY_MAPPED_IO
            || desc.memory_type == EFI_MEMORY_MAPPED_IO_PORT_SPACE;
        if is_mmio
        {
            if n < SCRATCH
            {
                buf[n] = MmioAperture {
                    phys_base: desc.physical_start,
                    size: desc.number_of_pages * 4096,
                };
                n += 1;
            }
            else
            {
                dropped = true;
            }
        }
    }

    // Fold in firmware-seeded apertures.
    for s in seed
    {
        if s.size == 0
        {
            continue;
        }
        if n < SCRATCH
        {
            buf[n] = *s;
            n += 1;
        }
        else
        {
            dropped = true;
        }
    }

    if n == 0
    {
        return 0;
    }

    // Insertion sort by phys_base; O(n²) is fine with n ≤ 64.
    for i in 1..n
    {
        let mut j = i;
        while j > 0 && buf[j - 1].phys_base > buf[j].phys_base
        {
            buf.swap(j - 1, j);
            j -= 1;
        }
    }

    // Merge adjacent / overlapping entries in one pass.
    let mut out_count: usize = 0;
    let mut i: usize = 0;
    while i < n
    {
        let base = buf[i].phys_base;
        let mut end = base.saturating_add(buf[i].size);
        let mut j = i + 1;
        while j < n && buf[j].phys_base <= end
        {
            let j_end = buf[j].phys_base.saturating_add(buf[j].size);
            if j_end > end
            {
                end = j_end;
            }
            j += 1;
        }
        if out_count < out.len()
        {
            out[out_count] = MmioAperture {
                phys_base: base,
                size: end - base,
            };
            out_count += 1;
        }
        else
        {
            dropped = true;
        }
        i = j;
    }

    if dropped
    {
        bprintln!(
            "[--------] boot: MMIO apertures: entries dropped (scratch buffer or MAX_APERTURES cap)"
        );
    }

    out_count
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use core::mem::size_of;

    use super::{
        derive_mmio_apertures, insertion_sort_memory_map, translate_memory_map,
        translate_memory_type,
    };
    use crate::uefi::{
        EFI_ACPI_MEMORY_NVS, EFI_ACPI_RECLAIM_MEMORY, EFI_BOOT_SERVICES_CODE,
        EFI_BOOT_SERVICES_DATA, EFI_CONVENTIONAL_MEMORY, EFI_LOADER_CODE, EFI_LOADER_DATA,
        EFI_MEMORY_MAPPED_IO, EFI_MEMORY_MAPPED_IO_PORT_SPACE, EFI_PERSISTENT_MEMORY,
        EFI_RUNTIME_SERVICES_CODE, EFI_RUNTIME_SERVICES_DATA, EfiMemoryDescriptor, MemoryMapResult,
    };
    use boot_protocol::{MAX_APERTURES, MemoryMapEntry, MemoryType, MmioAperture};

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

    /// Construct a UEFI memory map buffer from `descs`, run
    /// `translate_memory_map`, and return the translated entries.
    fn run_translate(descs: &[EfiMemoryDescriptor], max_entries: usize) -> Vec<MemoryMapEntry>
    {
        let stride = size_of::<EfiMemoryDescriptor>();
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: descs.len() * stride,
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
        // `u64` storage gives the buffer the descriptor's 8-byte alignment.
        let mut buf = vec![0u64; stride / 8];
        let desc = EfiMemoryDescriptor {
            memory_type: EFI_PERSISTENT_MEMORY,
            physical_start: 0x4000,
            virtual_start: 0,
            number_of_pages: 4,
            attribute: 0,
        };
        // SAFETY: buf holds stride >= size_of::<EfiMemoryDescriptor>() bytes and,
        // as `u64` storage, is 8-byte aligned, which EfiMemoryDescriptor needs.
        unsafe { core::ptr::write(buf.as_mut_ptr().cast::<EfiMemoryDescriptor>(), desc) };
        let uefi_map = MemoryMapResult {
            buffer_phys: buf.as_ptr() as u64,
            buffer_size: stride,
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

    // ── derive_mmio_apertures ─────────────────────────────────────────────────

    fn mmio_desc(physical_start: u64, number_of_pages: u64) -> EfiMemoryDescriptor
    {
        EfiMemoryDescriptor {
            memory_type: EFI_MEMORY_MAPPED_IO,
            physical_start,
            virtual_start: 0,
            number_of_pages,
            attribute: 0,
        }
    }

    /// Run `derive_mmio_apertures` over `descs` and `seed`; return the output.
    fn run_derive(descs: &[EfiMemoryDescriptor], seed: &[MmioAperture]) -> Vec<MmioAperture>
    {
        let stride = size_of::<EfiMemoryDescriptor>();
        let uefi_map = MemoryMapResult {
            buffer_phys: descs.as_ptr() as u64,
            buffer_size: descs.len() * stride,
            map_size: descs.len() * stride,
            map_key: 0,
            descriptor_size: stride,
        };
        let mut out = [MmioAperture {
            phys_base: 0,
            size: 0,
        }; MAX_APERTURES];
        // SAFETY: `descs` is a live, aligned descriptor array covering `map_size`.
        let n = unsafe { derive_mmio_apertures(&uefi_map, seed, &mut out) };
        out[..n].to_vec()
    }

    #[test]
    fn overlapping_and_adjacent_apertures_merge()
    {
        let descs = [mmio_desc(0x1000_0000, 1), mmio_desc(0x1000_1000, 1)];
        let seed = [MmioAperture {
            phys_base: 0x1000_0800,
            size: 0x1000,
        }];
        let out = run_derive(&descs, &seed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].phys_base, 0x1000_0000);
        assert_eq!(out[0].size, 0x2000);
    }

    #[test]
    fn zero_size_seed_is_ignored()
    {
        let seed = [MmioAperture {
            phys_base: 0x2000_0000,
            size: 0,
        }];
        assert!(run_derive(&[], &seed).is_empty());
    }

    #[test]
    fn exactly_max_apertures_disjoint_are_all_kept()
    {
        let descs: Vec<_> = (0..MAX_APERTURES as u64)
            .map(|i| mmio_desc(0x1000_0000 + i * 0x10_0000, 1))
            .collect();
        let out = run_derive(&descs, &[]);
        assert_eq!(out.len(), MAX_APERTURES);
    }

    #[test]
    fn surplus_over_max_apertures_keeps_the_lowest_bases()
    {
        // Listed highest first, so the cap must apply after the sort.
        let descs: Vec<_> = (0..=MAX_APERTURES as u64)
            .rev()
            .map(|i| mmio_desc(0x1000_0000 + i * 0x10_0000, 1))
            .collect();
        let out = run_derive(&descs, &[]);
        assert_eq!(out.len(), MAX_APERTURES);
        assert_eq!(out[0].phys_base, 0x1000_0000);
        assert_eq!(
            out[MAX_APERTURES - 1].phys_base,
            0x1000_0000 + (MAX_APERTURES as u64 - 1) * 0x10_0000
        );
    }
}

/// Sort `MemoryMapEntry` elements in `[0..count)` by `physical_base` ascending.
///
/// Uses an in-place insertion sort; see `core/boot/docs/memory-map.md`
/// § Sort Algorithm for why the algorithm class is acceptable.
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
