// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/platform.rs

//! Phase 6: platform resource validation.
//!
//! Validates the `platform_resources` slice from [`BootInfo`] before Phase 7
//! mints capabilities from it. Corrupt or malformed resource descriptors are
//! rejected here so the capability layer never sees invalid data.
//!
//! The top-level entry point is [`validate_platform_resources`]. All helper
//! predicates are pure functions operating on borrowed data and are unit-tested
//! without unsafe pointer work. The unsafe portion is confined to the entry
//! point, which re-derives the `BootInfo` reference via the direct physical
//! map (active since Phase 3).

// cast_possible_truncation: u64→usize address arithmetic bounded by platform memory layout.
#![allow(clippy::cast_possible_truncation)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
use alloc::vec::Vec;

use boot_protocol::{BootInfo, MemoryMapEntry, MemoryType, PlatformResource, ResourceType};

use crate::arch::current::{HAS_IO_PORTS, MAX_IRQ_ID, MIN_IRQ_ID};
use crate::kprintln;
use crate::mm::{PAGE_SIZE, paging::phys_to_virt};

// ── Public entry point ────────────────────────────────────────────────────────

/// Validate platform resources from `BootInfo`.
///
/// Re-derives the `BootInfo` reference via `phys_to_virt`, then delegates to
/// [`validate_resources_inner`]. Returns only valid, non-overlapping entries.
///
/// Fatally halts if:
/// - `entries` is null with a non-zero count (`BootInfo` corruption).
/// - The entries slice falls outside Usable/Loaded memory map regions.
pub fn validate_platform_resources(boot_info_phys: u64) -> Vec<PlatformResource>
{
    // SAFETY: boot_info_phys was validated in Phase 0; the direct physical map
    // is active since Phase 3.
    let info: &BootInfo = unsafe { &*(phys_to_virt(boot_info_phys) as *const BootInfo) };
    validate_resources_inner(info)
}

// ── Inner validation logic ────────────────────────────────────────────────────

/// Core validation logic, separated from the entry point for unit-test access.
///
/// Accepts a `&BootInfo` directly so tests can pass constructed data without
/// pointer arithmetic against the direct physical map.
fn validate_resources_inner(info: &BootInfo) -> Vec<PlatformResource>
{
    let pr = &info.platform_resources;

    // Fast path: no entries to validate.
    if pr.count == 0
    {
        kprintln!("platform resources: 0 validated (0 skipped)");
        return Vec::new();
    }

    // A null pointer with non-zero count indicates BootInfo corruption.
    if pr.entries.is_null()
    {
        crate::fatal("Phase 6: platform_resources.entries is null with non-zero count");
    }

    // Build a slice view of the physical memory map for range verification.
    let mmap: &[MemoryMapEntry] = if info.memory_map.count == 0 || info.memory_map.entries.is_null()
    {
        &[]
    }
    else
    {
        // SAFETY: Phase 0 confirmed memory_map pointer is valid and non-null;
        // direct map is active; count bounds the slice.
        unsafe {
            core::slice::from_raw_parts(
                phys_to_virt(info.memory_map.entries as u64) as *const MemoryMapEntry,
                info.memory_map.count as usize,
            )
        }
    };

    // The entries slice must lie entirely within Usable or Loaded memory.
    let entries_phys = pr.entries as u64;
    let slice_bytes = pr.count * core::mem::size_of::<PlatformResource>() as u64;
    let slice_end = entries_phys + slice_bytes;

    if !slice_in_boot_memory(entries_phys, slice_end, mmap)
    {
        crate::fatal("Phase 6: platform_resources slice falls outside Usable/Loaded memory");
    }

    // Build a Rust slice via the direct physical map.
    // SAFETY: slice verified to lie within Usable/Loaded physical memory;
    //         direct map is active; count is bounded above.
    let raw_entries: &[PlatformResource] = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(entries_phys) as *const PlatformResource,
            pr.count as usize,
        )
    };

    let mut validated: Vec<PlatformResource> = Vec::with_capacity(pr.count as usize);
    let mut skip_count: usize = 0;

    for (i, entry_ref) in raw_entries.iter().enumerate()
    {
        // Read the discriminant as a raw u32 to avoid undefined behaviour from
        // constructing a typed reference to an invalid enum value.
        // SAFETY: PlatformResource is repr(C); resource_type is the first field
        //         (repr(u32)), so reading *(entry_ptr as *const u32) is sound.
        let discriminant: u32 =
            unsafe { core::ptr::read(core::ptr::addr_of!(*entry_ref).cast::<u32>()) };

        let resource_type = match discriminant
        {
            0 => ResourceType::MmioRange,
            1 => ResourceType::IrqLine,
            2 => ResourceType::PciEcam,
            3 => ResourceType::PlatformTable,
            4 => ResourceType::IoPortRange,
            5 => ResourceType::IommuUnit,
            _ =>
            {
                kprintln!(
                    "  platform[{}]: unknown resource_type discriminant {}, skipping",
                    i,
                    discriminant
                );
                skip_count += 1;
                continue;
            }
        };

        // IoPortRange on architectures without I/O port space: silently skip,
        // excluded from the summary skip count per design decision.
        if resource_type == ResourceType::IoPortRange && !HAS_IO_PORTS
        {
            continue;
        }

        let valid = match resource_type
        {
            // Mapped device regions: must be page-aligned (the kernel maps them
            // as whole pages and these addresses come from hardware spec).
            ResourceType::MmioRange | ResourceType::PciEcam | ResourceType::IommuUnit =>
            {
                validate_mmio_resource(entry_ref, i)
            }
            // Firmware table blobs (ACPI RSDP, SPCR, …): arbitrary physical
            // address and byte size set by firmware. Only basic sanity needed.
            ResourceType::PlatformTable => validate_platform_table(entry_ref, i),
            ResourceType::IrqLine => validate_irq_line(entry_ref, i),
            ResourceType::IoPortRange => validate_io_port_range(entry_ref, i),
        };

        if valid
        {
            validated.push(*entry_ref);
        }
        else
        {
            skip_count += 1;
        }
    }

    // Remove overlapping entries within MmioRange and PciEcam types.
    // The boot protocol guarantees these are sorted by (type, base), so only
    // adjacent entries of the same type need comparison.
    let (validated, overlap_count) = remove_overlaps(validated);
    let total_skipped = skip_count + overlap_count;

    kprintln!(
        "platform resources: {} validated ({} skipped)",
        validated.len(),
        total_skipped
    );

    validated
}

// ── Helper predicates ─────────────────────────────────────────────────────────

/// Return `true` if `[slice_start, slice_end)` is fully covered by Usable or
/// Loaded memory-map regions.
///
/// Coverage is computed by summing the intersection of each qualifying region
/// with the slice interval. An empty slice (`slice_start >= slice_end`) is
/// trivially covered.
fn slice_in_boot_memory(slice_start: u64, slice_end: u64, map: &[MemoryMapEntry]) -> bool
{
    if slice_start >= slice_end
    {
        return true;
    }

    let needed = slice_end - slice_start;
    let mut covered: u64 = 0;

    for entry in map
    {
        if entry.memory_type != MemoryType::Usable && entry.memory_type != MemoryType::Loaded
        {
            continue;
        }
        let region_end = entry.physical_base + entry.size;
        let overlap_start = entry.physical_base.max(slice_start);
        let overlap_end = region_end.min(slice_end);
        if overlap_end > overlap_start
        {
            covered += overlap_end - overlap_start;
        }
    }

    covered >= needed
}

/// Validate a memory-mapped address range resource (`MmioRange`, `PciEcam`,
/// `PlatformTable`, `IommuUnit`).
///
/// Requirements:
/// - `base` is page-aligned.
/// - `size` is page-aligned and non-zero.
/// - `base + size` does not wrap u64.
fn validate_mmio_resource(entry: &PlatformResource, index: usize) -> bool
{
    let page = PAGE_SIZE as u64;

    if !entry.base.is_multiple_of(page)
    {
        kprintln!(
            "  platform[{}]: MMIO base {:#x} is not page-aligned, skipping",
            index,
            entry.base
        );
        return false;
    }

    if entry.size == 0
    {
        kprintln!("  platform[{}]: MMIO size is zero, skipping", index);
        return false;
    }

    if !entry.size.is_multiple_of(page)
    {
        kprintln!(
            "  platform[{}]: MMIO size {:#x} is not page-aligned, skipping",
            index,
            entry.size
        );
        return false;
    }

    if entry.base.checked_add(entry.size).is_none()
    {
        kprintln!(
            "  platform[{}]: MMIO range {:#x}+{:#x} wraps u64, skipping",
            index,
            entry.base,
            entry.size
        );
        return false;
    }

    true
}

/// Validate a firmware table region resource (`PlatformTable`).
///
/// Firmware tables (ACPI RSDP, SPCR, etc.) live at arbitrary physical
/// addresses with arbitrary byte sizes — page-alignment is not required.
/// Only checks: base non-zero, size non-zero, no u64 wrap.
fn validate_platform_table(entry: &PlatformResource, index: usize) -> bool
{
    if entry.base == 0
    {
        kprintln!(
            "  platform[{}]: PlatformTable base is zero, skipping",
            index
        );
        return false;
    }

    if entry.size == 0
    {
        kprintln!(
            "  platform[{}]: PlatformTable size is zero, skipping",
            index
        );
        return false;
    }

    if entry.base.checked_add(entry.size).is_none()
    {
        kprintln!(
            "  platform[{}]: PlatformTable range {:#x}+{:#x} wraps u64, skipping",
            index,
            entry.base,
            entry.size
        );
        return false;
    }

    true
}

/// Validate an x86 I/O port range resource.
///
/// Requirements:
/// - `base` ≤ 0xFFFF (port numbers are 16-bit).
/// - `base + size` ≤ 0x10000 (no wrap past the port space boundary).
///
/// Returns `false` on RISC-V; callers must handle the silent-skip case (do not
/// count towards the skip total) before calling this function.
fn validate_io_port_range(entry: &PlatformResource, index: usize) -> bool
{
    if entry.base > 0xFFFF
    {
        kprintln!(
            "  platform[{}]: I/O port base {:#x} exceeds 0xFFFF, skipping",
            index,
            entry.base
        );
        return false;
    }

    // saturating_add prevents overflow on pathologically large size values.
    if entry.base.saturating_add(entry.size) > 0x10000
    {
        kprintln!(
            "  platform[{}]: I/O port range [{:#x}, +{:#x}) exceeds port space, skipping",
            index,
            entry.base,
            entry.size
        );
        return false;
    }

    true
}

/// Validate a hardware interrupt line resource.
///
/// Requirements: `id` must be in `[MIN_IRQ_ID, MAX_IRQ_ID]` for the current
/// architecture (GSI on x86-64; PLIC source on RISC-V).
fn validate_irq_line(entry: &PlatformResource, index: usize) -> bool
{
    if entry.id < u64::from(MIN_IRQ_ID) || entry.id > u64::from(MAX_IRQ_ID)
    {
        kprintln!(
            "  platform[{}]: IRQ id {} out of range [{}, {}], skipping",
            index,
            entry.id,
            MIN_IRQ_ID,
            MAX_IRQ_ID
        );
        return false;
    }

    true
}

/// Remove overlapping entries within `MmioRange` and `PciEcam` resource types.
///
/// The boot protocol guarantees entries are pre-sorted by `(resource_type,
/// base)`, so only adjacent same-type pairs need comparison. Entry `i` overlaps
/// `i+1` when `entries[i].base + entries[i].size > entries[i+1].base`.
///
/// Returns the cleaned list and the number of removed entries.
fn remove_overlaps(mut entries: Vec<PlatformResource>) -> (Vec<PlatformResource>, usize)
{
    let mut removed: usize = 0;
    let mut i: usize = 0;

    while i + 1 < entries.len()
    {
        let a_type = entries[i].resource_type;
        let b_type = entries[i + 1].resource_type;

        // Only check overlaps within MmioRange and PciEcam.
        if !matches!(a_type, ResourceType::MmioRange | ResourceType::PciEcam) || a_type != b_type
        {
            i += 1;
            continue;
        }

        // saturating_add avoids overflow on malformed size values that slipped
        // through per-entry validation (should not happen in practice).
        let a_end = entries[i].base.saturating_add(entries[i].size);
        if a_end > entries[i + 1].base
        {
            kprintln!(
                "  platform: {:?} overlap at {:#x}..{:#x} vs {:#x}, removing second",
                a_type,
                entries[i].base,
                a_end,
                entries[i + 1].base
            );
            entries.remove(i + 1);
            removed += 1;
            // Do not advance i: re-check the new entries[i+1] against entries[i].
        }
        else
        {
            i += 1;
        }
    }

    (entries, removed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::{MemoryMapSlice, PlatformResourceSlice};

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Construct a zeroed BootInfo with the given platform_resources slice.
    ///
    /// For count=0 the entries pointer is null. For non-zero count the pointer
    /// points into the caller's `resources` slice (valid for the test scope).
    fn make_boot_info_with_resources(resources: &[PlatformResource]) -> BootInfo
    {
        // SAFETY: zeroed BootInfo is valid for test construction; all pointer
        // fields are set immediately below.
        let mut info = unsafe { core::mem::zeroed::<BootInfo>() };
        info.platform_resources = PlatformResourceSlice {
            entries: if resources.is_empty()
            {
                core::ptr::null()
            }
            else
            {
                resources.as_ptr()
            },
            count: resources.len() as u64,
        };
        info
    }

    /// Build a BootInfo whose memory map covers the given platform_resources
    /// slice, so that `slice_in_boot_memory` passes inside `validate_resources_inner`.
    fn make_boot_info_covered(resources: &[PlatformResource], map: &[MemoryMapEntry]) -> BootInfo
    {
        let mut info = make_boot_info_with_resources(resources);
        info.memory_map = MemoryMapSlice {
            entries: if map.is_empty()
            {
                core::ptr::null()
            }
            else
            {
                map.as_ptr()
            },
            count: map.len() as u64,
        };
        info
    }

    /// Construct a PlatformResource with MmioRange type and given base/size.
    fn mmio(base: u64, size: u64) -> PlatformResource
    {
        PlatformResource {
            resource_type: ResourceType::MmioRange,
            flags: 0,
            base,
            size,
            id: 0,
        }
    }

    /// Construct a PlatformResource with PciEcam type.
    fn ecam(base: u64, size: u64) -> PlatformResource
    {
        PlatformResource {
            resource_type: ResourceType::PciEcam,
            flags: 0,
            base,
            size,
            id: 0,
        }
    }

    /// Construct a PlatformResource with IoPortRange type.
    fn ioport(base: u64, size: u64) -> PlatformResource
    {
        PlatformResource {
            resource_type: ResourceType::IoPortRange,
            flags: 0,
            base,
            size,
            id: 0,
        }
    }

    /// Construct a PlatformResource with IrqLine type.
    fn irq(id: u64) -> PlatformResource
    {
        PlatformResource {
            resource_type: ResourceType::IrqLine,
            flags: 0,
            base: 0,
            size: 0,
            id,
        }
    }

    /// A Usable memory-map entry spanning [base, base+size).
    fn usable(base: u64, size: u64) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base: base,
            size,
            memory_type: MemoryType::Usable,
        }
    }

    // ── validate_resources_inner ──────────────────────────────────────────────

    #[test]
    fn empty_resources_returns_empty_vec()
    {
        let info = make_boot_info_with_resources(&[]);
        let result = validate_resources_inner(&info);
        assert!(result.is_empty());
    }

    // ── validate_mmio_resource ────────────────────────────────────────────────

    #[test]
    fn valid_mmio_entry_accepted()
    {
        let entry = mmio(0x1000_0000, 0x1000);
        assert!(validate_mmio_resource(&entry, 0));
    }

    #[test]
    fn mmio_unaligned_base_rejected()
    {
        let entry = mmio(0x1001, 0x1000);
        assert!(!validate_mmio_resource(&entry, 0));
    }

    #[test]
    fn mmio_zero_size_rejected()
    {
        let entry = mmio(0x1000_0000, 0);
        assert!(!validate_mmio_resource(&entry, 0));
    }

    #[test]
    fn mmio_unaligned_size_rejected()
    {
        let entry = mmio(0x1000_0000, 0x1001);
        assert!(!validate_mmio_resource(&entry, 0));
    }

    #[test]
    fn mmio_wrap_rejected()
    {
        // base + size overflows u64
        let entry = mmio(u64::MAX - 0x0FFF, 0x1000);
        assert!(!validate_mmio_resource(&entry, 0));
    }

    // ── validate_io_port_range ────────────────────────────────────────────────

    #[test]
    fn io_port_valid_accepted()
    {
        let entry = ioport(0x3F8, 8); // COM1
        assert!(validate_io_port_range(&entry, 0));
    }

    #[test]
    fn io_port_base_too_high_rejected()
    {
        let entry = ioport(0x1_0000, 1);
        assert!(!validate_io_port_range(&entry, 0));
    }

    #[test]
    fn io_port_overflow_rejected()
    {
        // base + size > 0x10000
        let entry = ioport(0xFF00, 0x200);
        assert!(!validate_io_port_range(&entry, 0));
    }

    // ── validate_irq_line ─────────────────────────────────────────────────────

    #[test]
    fn irq_valid_accepted()
    {
        // Use a mid-range value valid on both x86-64 and RISC-V.
        let entry = irq(MIN_IRQ_ID as u64 + 1);
        assert!(validate_irq_line(&entry, 0));
    }

    #[test]
    fn irq_out_of_range_rejected()
    {
        let entry = irq(MAX_IRQ_ID as u64 + 1);
        assert!(!validate_irq_line(&entry, 0));
    }

    // ── slice_in_boot_memory ──────────────────────────────────────────────────

    #[test]
    fn slice_in_boot_memory_covered()
    {
        let map = [usable(0x1000, 0x8000)];
        assert!(slice_in_boot_memory(0x2000, 0x4000, &map));
    }

    #[test]
    fn slice_in_boot_memory_partial_outside()
    {
        // Slice extends past the end of the only Usable region.
        let map = [usable(0x0, 0x4000)];
        assert!(!slice_in_boot_memory(0x3000, 0x5000, &map));
    }

    #[test]
    fn slice_in_boot_memory_reserved_rejected()
    {
        // The only region is Reserved; nothing covers the slice.
        let map = [MemoryMapEntry {
            physical_base: 0x0,
            size: 0x10000,
            memory_type: MemoryType::Reserved,
        }];
        assert!(!slice_in_boot_memory(0x1000, 0x2000, &map));
    }

    // ── remove_overlaps ───────────────────────────────────────────────────────

    #[test]
    fn overlaps_removed()
    {
        // Two MmioRange entries where the first extends into the second.
        let entries = vec![mmio(0x0, 0x3000), mmio(0x2000, 0x1000)];
        let (result, count) = remove_overlaps(entries);
        assert_eq!(count, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].base, 0x0);
    }

    #[test]
    fn different_types_no_overlap_check()
    {
        // MmioRange and PciEcam at the same base: different types, both kept.
        let entries = vec![mmio(0x0, 0x1000), ecam(0x0, 0x1000)];
        let (result, count) = remove_overlaps(entries);
        assert_eq!(count, 0);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn no_overlaps_unchanged()
    {
        // Two non-overlapping MmioRange entries.
        let entries = vec![mmio(0x0000, 0x1000), mmio(0x2000, 0x1000)];
        let (result, count) = remove_overlaps(entries);
        assert_eq!(count, 0);
        assert_eq!(result.len(), 2);
    }
}
