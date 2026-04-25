// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/platform.rs

//! Phase 6: platform resource validation.
//!
//! Reads the coarse `mmio_apertures` slice from [`BootInfo`] and validates
//! it before Phase 7 mints capabilities from it. Also stashes the
//! arch-specific `kernel_mmio` descriptor in the module-local cache so
//! later kernel code can read it; no current arch code does, but the
//! bootloader always produces the field.
//!
//! Validation on the replacement ABI is intentionally minimal: each aperture
//! must be page-aligned, non-zero, and its slice pointer must lie within
//! Usable or Loaded memory.

// cast_possible_truncation: u64→usize address arithmetic bounded by platform memory layout.
#![allow(clippy::cast_possible_truncation)]

#[cfg(not(test))]
extern crate alloc;
#[cfg(not(test))]
use alloc::vec::Vec;

use boot_protocol::{BootInfo, KernelMmio, MemoryMapEntry, MemoryType, MmioAperture};
use core::cell::UnsafeCell;

use crate::kprintln;
use crate::mm::{PAGE_SIZE, paging::phys_to_virt};

// ── Kernel MMIO cache ────────────────────────────────────────────────────────

/// Module-local cache of `BootInfo.kernel_mmio`.
///
/// Populated once during Phase 6 via [`capture_kernel_mmio`] and read later
/// by arch code that wants bootloader-provided MMIO bases. Today the arch
/// code still uses compiled-in constants; this cache makes the values
/// available for the next round of work without forcing an immediate
/// refactor (see `TODO.md`).
///
/// # Safety
/// Written exactly once, single-threaded, from Phase 6. Subsequent reads
/// happen after SMP is active but only from code paths that have not yet
/// been migrated; concurrent readers are always observing a fully-written
/// value because the write precedes SMP bring-up.
struct KernelMmioCell(UnsafeCell<KernelMmio>);

// SAFETY: See `KernelMmioCell` docs — writes are single-threaded pre-SMP,
// and the contents are arch-specific integers with no internal mutability.
unsafe impl Sync for KernelMmioCell {}

static KERNEL_MMIO_CELL: KernelMmioCell = KernelMmioCell(UnsafeCell::new(KernelMmio::zero()));

/// Current cached `kernel_mmio` snapshot.
///
/// Valid once [`capture_kernel_mmio`] has been called (Phase 6). Before
/// then, fields read as zero (the default produced by [`KernelMmio::zero`]).
#[allow(dead_code)] // The getter is the public surface; no current arch-code reader.
#[must_use]
pub fn kernel_mmio() -> KernelMmio
{
    // SAFETY: single-writer invariant documented on `KernelMmioCell`.
    unsafe { *KERNEL_MMIO_CELL.0.get() }
}

/// Capture `BootInfo.kernel_mmio` into [`KERNEL_MMIO_CELL`].
///
/// # Safety
/// Must be called exactly once during Phase 6, single-threaded, after
/// Phase 3 (direct map active).
pub unsafe fn capture_kernel_mmio(boot_info_phys: u64)
{
    // SAFETY: boot_info_phys was validated in Phase 0; direct map active
    // since Phase 3.
    let info: &BootInfo = unsafe { &*(phys_to_virt(boot_info_phys) as *const BootInfo) };
    // SAFETY: single-writer pre-SMP per the function's contract.
    unsafe {
        *KERNEL_MMIO_CELL.0.get() = info.kernel_mmio;
    }
}

// ── MMIO aperture validation ─────────────────────────────────────────────────

/// Validate MMIO apertures from `BootInfo` and return the accepted list.
///
/// Re-derives the `BootInfo` reference via `phys_to_virt`, then delegates to
/// [`validate_apertures_inner`].
///
/// Fatally halts if:
/// - `entries` is null with a non-zero count (`BootInfo` corruption).
/// - The entries slice falls outside Usable/Loaded memory map regions.
pub fn validate_mmio_apertures(boot_info_phys: u64) -> Vec<MmioAperture>
{
    // SAFETY: boot_info_phys was validated in Phase 0; the direct physical map
    // is active since Phase 3.
    let info: &BootInfo = unsafe { &*(phys_to_virt(boot_info_phys) as *const BootInfo) };
    validate_apertures_inner(info)
}

/// Core validation, separated from the entry point for unit-test access.
fn validate_apertures_inner(info: &BootInfo) -> Vec<MmioAperture>
{
    let ap = &info.mmio_apertures;

    if ap.count == 0
    {
        kprintln!("mmio apertures: 0 validated (0 skipped)");
        return Vec::new();
    }

    if ap.entries.is_null()
    {
        crate::fatal("Phase 6: mmio_apertures.entries is null with non-zero count");
    }

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

    let entries_phys = ap.entries as u64;
    let slice_bytes = ap.count * core::mem::size_of::<MmioAperture>() as u64;
    let slice_end = entries_phys + slice_bytes;

    if !slice_in_boot_memory(entries_phys, slice_end, mmap)
    {
        crate::fatal("Phase 6: mmio_apertures slice falls outside Usable/Loaded memory");
    }

    // SAFETY: slice verified to lie within Usable/Loaded physical memory;
    // direct map is active; count is bounded above.
    let raw: &[MmioAperture] = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(entries_phys) as *const MmioAperture,
            ap.count as usize,
        )
    };

    let mut validated: Vec<MmioAperture> = Vec::with_capacity(ap.count as usize);
    let mut skip_count: usize = 0;

    for (i, entry) in raw.iter().enumerate()
    {
        if aperture_valid(entry, i)
        {
            validated.push(*entry);
        }
        else
        {
            skip_count += 1;
        }
    }

    kprintln!(
        "mmio apertures: {} validated ({} skipped)",
        validated.len(),
        skip_count
    );

    validated
}

/// Accept an aperture iff its base is page-aligned, its size is non-zero
/// and page-aligned, and `base + size` does not wrap.
fn aperture_valid(ap: &MmioAperture, index: usize) -> bool
{
    let page = PAGE_SIZE as u64;

    if !ap.phys_base.is_multiple_of(page)
    {
        kprintln!(
            "  aperture[{}]: base {:#x} is not page-aligned, skipping",
            index,
            ap.phys_base
        );
        return false;
    }

    if ap.size == 0
    {
        kprintln!("  aperture[{}]: size is zero, skipping", index);
        return false;
    }

    if !ap.size.is_multiple_of(page)
    {
        kprintln!(
            "  aperture[{}]: size {:#x} is not page-aligned, skipping",
            index,
            ap.size
        );
        return false;
    }

    if ap.phys_base.checked_add(ap.size).is_none()
    {
        kprintln!(
            "  aperture[{}]: range {:#x}+{:#x} wraps u64, skipping",
            index,
            ap.phys_base,
            ap.size
        );
        return false;
    }

    true
}

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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::{MemoryMapSlice, MmioApertureSlice};

    fn aperture(base: u64, size: u64) -> MmioAperture
    {
        MmioAperture {
            phys_base: base,
            size,
        }
    }

    fn usable(base: u64, size: u64) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base: base,
            size,
            memory_type: MemoryType::Usable,
        }
    }

    fn make_boot_info(apertures: &[MmioAperture], map: &[MemoryMapEntry]) -> BootInfo
    {
        // SAFETY: zeroed BootInfo is valid for test construction; the
        // aperture/map pointers are written immediately below.
        let mut info = unsafe { core::mem::zeroed::<BootInfo>() };
        info.mmio_apertures = MmioApertureSlice {
            entries: if apertures.is_empty()
            {
                core::ptr::null()
            }
            else
            {
                apertures.as_ptr()
            },
            count: apertures.len() as u64,
        };
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

    #[test]
    fn empty_apertures_returns_empty_vec()
    {
        let info = make_boot_info(&[], &[]);
        let result = validate_apertures_inner(&info);
        assert!(result.is_empty());
    }

    #[test]
    fn valid_aperture_accepted()
    {
        let ap = aperture(0x1000_0000, 0x1000);
        assert!(aperture_valid(&ap, 0));
    }

    #[test]
    fn unaligned_base_rejected()
    {
        let ap = aperture(0x1001, 0x1000);
        assert!(!aperture_valid(&ap, 0));
    }

    #[test]
    fn zero_size_rejected()
    {
        let ap = aperture(0x1000_0000, 0);
        assert!(!aperture_valid(&ap, 0));
    }

    #[test]
    fn unaligned_size_rejected()
    {
        let ap = aperture(0x1000_0000, 0x1001);
        assert!(!aperture_valid(&ap, 0));
    }

    #[test]
    fn wrap_rejected()
    {
        let ap = aperture(u64::MAX - 0x0FFF, 0x1000);
        assert!(!aperture_valid(&ap, 0));
    }

    #[test]
    fn slice_in_boot_memory_covered()
    {
        let map = [usable(0x1000, 0x8000)];
        assert!(slice_in_boot_memory(0x2000, 0x4000, &map));
    }

    #[test]
    fn slice_in_boot_memory_partial_outside()
    {
        let map = [usable(0x0, 0x4000)];
        assert!(!slice_in_boot_memory(0x3000, 0x5000, &map));
    }

    #[test]
    fn slice_in_boot_memory_reserved_rejected()
    {
        let map = [MemoryMapEntry {
            physical_base: 0x0,
            size: 0x10000,
            memory_type: MemoryType::Reserved,
        }];
        assert!(!slice_in_boot_memory(0x1000, 0x2000, &map));
    }
}
