// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/platform.rs

//! Platform resources from `BootInfo`: the `kernel_mmio` cache and MMIO-aperture validation.
//!
//! [`capture_kernel_mmio`] caches `BootInfo.kernel_mmio` during Phase 4; Phase 5 arch hardware
//! init and later arch code (interrupt-controller and UART bases, the riscv64 timebase and hart
//! capabilities) read it through [`kernel_mmio`]. [`validate_mmio_apertures`] validates the
//! coarse `mmio_apertures` slice during Phase 6, before Phase 7 mints capabilities from it.
//!
//! The Phase 6 checks and failure modes are specified in
//! `core/kernel/docs/initialization.md` § Phase 6.

// cast_possible_truncation: u64→usize address arithmetic bounded by platform memory layout.
#![allow(clippy::cast_possible_truncation)]

use boot_protocol::{BootInfo, KernelMmio, MemoryMapEntry, MemoryType, MmioAperture};
use core::cell::UnsafeCell;

use crate::kprintln;
use crate::mm::{PAGE_SIZE, paging::phys_to_virt};

// ── Kernel MMIO cache ────────────────────────────────────────────────────────

/// Module-local cache of `BootInfo.kernel_mmio`.
///
/// Populated once, before Phase 5 arch hardware init, via
/// [`capture_kernel_mmio`], and read by arch code for bootloader-discovered
/// platform values (interrupt-controller and UART bases, the riscv64
/// timebase and hart capabilities).
///
/// # Safety
/// Written exactly once, single-threaded, before Phase 5. Concurrent
/// readers are always observing a fully-written value because the write
/// precedes SMP bring-up.
struct KernelMmioCell(UnsafeCell<KernelMmio>);

// SAFETY: See `KernelMmioCell` docs — writes are single-threaded pre-SMP,
// and the contents are arch-specific integers with no internal mutability.
unsafe impl Sync for KernelMmioCell {}

static KERNEL_MMIO_CELL: KernelMmioCell = KernelMmioCell(UnsafeCell::new(KernelMmio::zero()));

/// Current cached `kernel_mmio` snapshot.
///
/// Valid once [`capture_kernel_mmio`] has been called (before Phase 5 arch
/// hardware init). Before then, fields read as zero (the default produced
/// by [`KernelMmio::zero`]).
#[must_use]
pub fn kernel_mmio() -> KernelMmio
{
    // SAFETY: single-writer invariant documented on `KernelMmioCell`.
    unsafe { *KERNEL_MMIO_CELL.0.get() }
}

/// Capture `BootInfo.kernel_mmio` into [`KERNEL_MMIO_CELL`].
///
/// # Safety
/// Must be called exactly once, single-threaded, after Phase 3 (direct map
/// active) and before Phase 5 arch hardware init reads the cache.
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

/// The MMIO apertures `BootInfo` reports, with the boot memory map that judges
/// them. Phase 6 builds it ([`validate_mmio_apertures`]) and Phase 7 mints one
/// `Mmio` capability per aperture [`ValidatedApertures::iter`] yields: exactly
/// the ones Phase 6 accepted, in order. Nothing is copied, so no count of
/// apertures is bounded here.
#[derive(Clone, Copy)]
pub struct ValidatedApertures
{
    raw: &'static [MmioAperture],
    mmap: &'static [MemoryMapEntry],
}

impl ValidatedApertures
{
    /// No apertures.
    #[must_use]
    pub const fn empty() -> Self
    {
        Self {
            raw: &[],
            mmap: &[],
        }
    }

    /// The accepted apertures, in `BootInfo` order.
    pub fn iter(&self) -> impl Iterator<Item = &'static MmioAperture> + use<>
    {
        let mmap = self.mmap;
        self.raw
            .iter()
            .filter(move |ap| aperture_fault(ap).is_none() && ram_overlap(ap, mmap).is_none())
    }
}

/// Validate the MMIO apertures `BootInfo` reports and return the view of the
/// accepted ones.
///
/// Re-derives the `BootInfo` reference via `phys_to_virt`, then delegates to
/// [`validate_apertures_inner`].
///
/// Fatally halts if:
/// - `entries` is null with a non-zero count (`BootInfo` corruption).
/// - The entries slice falls outside Usable/Loaded memory map regions.
///
/// # Safety
/// Must be called during Phase 6, single-threaded, with the direct map active.
#[cfg(not(test))]
pub unsafe fn validate_mmio_apertures(boot_info_phys: u64) -> ValidatedApertures
{
    // SAFETY: boot_info_phys was validated in Phase 0; the direct physical map
    // is active since Phase 3.
    let info: &BootInfo = unsafe { &*(phys_to_virt(boot_info_phys) as *const BootInfo) };
    validate_apertures_inner(info)
}

/// Host-test stub. The only call site, `kernel_entry_post_rebase`, is
/// `#[cfg(not(test))]`, so nothing calls this in test builds; it returns no
/// apertures without exercising the production validation path.
#[cfg(test)]
// missing_safety_doc: host-test stub; the production `validate_mmio_apertures` carries the
// `# Safety` contract.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn validate_mmio_apertures(_boot_info_phys: u64) -> ValidatedApertures
{
    ValidatedApertures::empty()
}

/// Core validation, separated from the entry point for unit-test access:
/// checks the aperture slice, reports each rejected aperture and the counts,
/// and returns the view of the accepted ones.
fn validate_apertures_inner(info: &'static BootInfo) -> ValidatedApertures
{
    let ap = &info.mmio_apertures;

    if ap.count == 0
    {
        kprintln!("mmio apertures: 0 validated (0 skipped)");
        return ValidatedApertures::empty();
    }

    if ap.entries.is_null()
    {
        crate::fatal("Phase 6: mmio_apertures.entries is null with non-zero count");
    }

    let mmap: &'static [MemoryMapEntry] = if info.memory_map.count == 0
        || info.memory_map.entries.is_null()
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
    let raw: &'static [MmioAperture] = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(entries_phys) as *const MmioAperture,
            ap.count as usize,
        )
    };

    let counts = report_apertures(raw, mmap);
    kprintln!(
        "mmio apertures: {} validated ({} skipped)",
        counts.accepted,
        counts.skipped
    );
    ValidatedApertures { raw, mmap }
}

/// Outcome of [`report_apertures`]: entries accepted and entries skipped as
/// invalid or RAM-overlapping.
struct ApertureCounts
{
    accepted: usize,
    skipped: usize,
}

/// Report every aperture of `raw` that [`aperture_fault`] rejects or that
/// intersects a RAM-class region of `mmap` ([`ram_overlap`]), and count the
/// accepted and skipped ones. The accepted set is the one
/// [`ValidatedApertures::iter`] yields.
fn report_apertures(raw: &[MmioAperture], mmap: &[MemoryMapEntry]) -> ApertureCounts
{
    let mut counts = ApertureCounts {
        accepted: 0,
        skipped: 0,
    };

    for (i, entry) in raw.iter().enumerate()
    {
        if let Some(fault) = aperture_fault(entry)
        {
            report_fault(i, entry, fault);
            counts.skipped += 1;
            continue;
        }
        if let Some(ram) = ram_overlap(entry, mmap)
        {
            kprintln!(
                "  aperture[{}]: range {:#x}+{:#x} intersects {:?} memory {:#x}+{:#x}, skipping",
                i,
                entry.phys_base,
                entry.size,
                ram.memory_type,
                ram.physical_base,
                ram.size
            );
            counts.skipped += 1;
            continue;
        }
        counts.accepted += 1;
    }

    counts
}

/// The first RAM-class (`Usable`, `Loaded`, `AcpiReclaimable`, `Persistent`)
/// entry of `map` that `ap` intersects, or `None`. An `Mmio` capability over
/// RAM would let its holder map and write frames outside Memory-capability
/// accounting, so Phase 6 rejects such an aperture
/// (`core/kernel/docs/initialization.md` § Phase 6). Called only for an `ap`
/// [`aperture_fault`] accepts, so its end does not wrap.
fn ram_overlap<'a>(ap: &MmioAperture, map: &'a [MemoryMapEntry]) -> Option<&'a MemoryMapEntry>
{
    let ap_end = ap.phys_base + ap.size;
    map.iter().find(|e| {
        matches!(
            e.memory_type,
            MemoryType::Usable
                | MemoryType::Loaded
                | MemoryType::AcpiReclaimable
                | MemoryType::Persistent
        ) && e.physical_base < ap_end
            && ap.phys_base < e.physical_base.saturating_add(e.size)
    })
}

/// Why an aperture is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApertureFault
{
    /// The base is not page-aligned.
    UnalignedBase,
    /// The size is zero.
    EmptySize,
    /// The size is not page-aligned.
    UnalignedSize,
    /// `base + size` wraps `u64`.
    Wraps,
}

/// The fault of a malformed aperture, or `None` when its base is
/// page-aligned, its size is non-zero and page-aligned, and `base + size`
/// does not wrap.
fn aperture_fault(ap: &MmioAperture) -> Option<ApertureFault>
{
    let page = PAGE_SIZE as u64;
    if !ap.phys_base.is_multiple_of(page)
    {
        Some(ApertureFault::UnalignedBase)
    }
    else if ap.size == 0
    {
        Some(ApertureFault::EmptySize)
    }
    else if !ap.size.is_multiple_of(page)
    {
        Some(ApertureFault::UnalignedSize)
    }
    else if ap.phys_base.checked_add(ap.size).is_none()
    {
        Some(ApertureFault::Wraps)
    }
    else
    {
        None
    }
}

/// Report aperture `index`'s `fault` on the kernel console.
fn report_fault(index: usize, ap: &MmioAperture, fault: ApertureFault)
{
    match fault
    {
        ApertureFault::UnalignedBase =>
        {
            kprintln!(
                "  aperture[{}]: base {:#x} is not page-aligned, skipping",
                index,
                ap.phys_base
            );
        }
        ApertureFault::EmptySize => kprintln!("  aperture[{}]: size is zero, skipping", index),
        ApertureFault::UnalignedSize =>
        {
            kprintln!(
                "  aperture[{}]: size {:#x} is not page-aligned, skipping",
                index,
                ap.size
            );
        }
        ApertureFault::Wraps =>
        {
            kprintln!(
                "  aperture[{}]: range {:#x}+{:#x} wraps u64, skipping",
                index,
                ap.phys_base,
                ap.size
            );
        }
    }
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
        let info: &'static BootInfo = Box::leak(Box::new(make_boot_info(&[], &[])));
        assert_eq!(validate_apertures_inner(info).iter().count(), 0);
    }

    #[test]
    fn valid_aperture_accepted()
    {
        assert_eq!(aperture_fault(&aperture(0x1000_0000, 0x1000)), None);
    }

    #[test]
    fn malformed_apertures_are_rejected_by_cause()
    {
        assert_eq!(
            aperture_fault(&aperture(0x1001, 0x1000)),
            Some(ApertureFault::UnalignedBase)
        );
        assert_eq!(
            aperture_fault(&aperture(0x1000_0000, 0)),
            Some(ApertureFault::EmptySize)
        );
        assert_eq!(
            aperture_fault(&aperture(0x1000_0000, 0x1001)),
            Some(ApertureFault::UnalignedSize)
        );
        assert_eq!(
            aperture_fault(&aperture(u64::MAX - 0x0FFF, 0x1000)),
            Some(ApertureFault::Wraps)
        );
    }

    fn entry(base: u64, size: u64, memory_type: MemoryType) -> MemoryMapEntry
    {
        MemoryMapEntry {
            physical_base: base,
            size,
            memory_type,
        }
    }

    /// The accepted apertures of `raw` against `map`, and the skip count.
    fn run_filter(raw: &[MmioAperture], map: &[MemoryMapEntry]) -> (Vec<MmioAperture>, usize)
    {
        let raw: &'static [MmioAperture] = Box::leak(raw.to_vec().into_boxed_slice());
        let mmap: &'static [MemoryMapEntry] = Box::leak(map.to_vec().into_boxed_slice());
        let view = ValidatedApertures { raw, mmap };
        let counts = report_apertures(raw, mmap);
        let accepted: Vec<MmioAperture> = view.iter().copied().collect();
        assert_eq!(
            accepted.len(),
            counts.accepted,
            "the view and the report agree"
        );
        (accepted, counts.skipped)
    }

    // Defect caught: the former 64-entry buffer dropping valid apertures, so
    // the devices behind them were unreachable.
    #[test]
    fn every_valid_aperture_is_kept_however_many_there_are()
    {
        let raw: Vec<MmioAperture> = (0..200u64)
            .map(|i| aperture(0x1_0000_0000 + i * 0x10_0000, 0x1000))
            .collect();
        let (accepted, skipped) = run_filter(&raw, &[]);
        assert_eq!((accepted.len(), skipped), (200, 0));
        assert_eq!(accepted[199].phys_base, raw[199].phys_base);
    }

    #[test]
    fn aperture_intersecting_any_ram_type_is_rejected_as_skipped()
    {
        for ty in [
            MemoryType::Usable,
            MemoryType::Loaded,
            MemoryType::AcpiReclaimable,
            MemoryType::Persistent,
        ]
        {
            // RAM [0x10_0000, 0x20_0000); the aperture overlaps its last page.
            let map = [entry(0x10_0000, 0x10_0000, ty)];
            let (accepted, skipped) = run_filter(&[aperture(0x1F_F000, 0x2000)], &map);
            assert!(accepted.is_empty(), "{ty:?} overlap accepted");
            assert_eq!(skipped, 1, "{ty:?} overlap not counted as skipped");
        }
    }

    #[test]
    fn aperture_adjacent_to_ram_is_accepted()
    {
        let map = [
            entry(0x10_0000, 0x10_0000, MemoryType::Usable),
            entry(0x30_0000, 0x10_0000, MemoryType::Loaded),
        ];
        let ap = aperture(0x20_0000, 0x10_0000);
        let (accepted, skipped) = run_filter(&[ap], &map);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].phys_base, ap.phys_base);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn aperture_over_reserved_memory_is_accepted()
    {
        let map = [entry(0xFEC0_0000, 0x10_0000, MemoryType::Reserved)];
        let (accepted, skipped) = run_filter(&[aperture(0xFEC0_0000, 0x1000)], &map);
        assert_eq!(accepted.len(), 1);
        assert_eq!(skipped, 0);
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
