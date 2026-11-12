// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/paging.rs

//! Architecture-neutral page table trait and boot mapping orchestration.
//!
//! Defines [`PageTableBuilder`] implemented by each architecture, and the
//! [`build_initial_tables`] function that orchestrates the full mapping for
//! kernel handoff.

use crate::arch;
use crate::elf::KernelInfo;
use crate::error::BootError;

/// Permission flags for a page table mapping.
pub struct PageFlags
{
    /// The mapping is writable.
    pub writable: bool,
    /// The mapping is executable.
    pub executable: bool,
}

/// Errors that can occur during page table construction.
#[derive(Clone, Copy, Debug)]
pub enum MapError
{
    /// Physical memory allocation for an intermediate table frame failed.
    OutOfMemory,
    /// The flags request both writable and executable permissions (W^X violation).
    WxViolation,
    /// The range to map runs past the end of the address space, or an address
    /// selects no slot of a translation table.
    AddressRange,
}

/// Architecture-specific page table builder.
///
/// Implementors take their page table frames from one pool allocated via UEFI
/// `AllocatePages` at construction, sized by [`table_frame_bound`], and
/// construct the minimal initial mapping needed for kernel handoff. All
/// allocation must occur before `ExitBootServices`.
///
/// # Implementor requirements
/// All implementations must enforce W^X: any call to [`map`] with
/// `flags.writable && flags.executable` must return [`MapError::WxViolation`]
/// without modifying any table.
///
/// [`map`]: PageTableBuilder::map
pub trait PageTableBuilder: Sized
{
    /// Translation levels of the paging mode the builder builds for (the root
    /// included), which [`table_frame_bound`] sizes the frame pool from.
    fn translation_levels() -> usize;

    /// Allocate a pool of `table_frames` contiguous frames from UEFI
    /// `AllocatePages` and take a new, empty root page table from it. Every
    /// intermediate table [`map`][Self::map] needs comes from the same pool.
    /// Returns `None` if the allocation fails.
    ///
    /// # Safety
    /// `bs` must be a valid pointer to UEFI boot services (before `ExitBootServices`).
    fn new(bs: *mut crate::uefi::EfiBootServices, table_frames: u64) -> Option<Self>;

    /// Map the virtual range `[virt, virt+size)` to `[phys, phys+size)`.
    ///
    /// `size` must be page-aligned. Returns [`MapError::WxViolation`] if both
    /// `flags.writable` and `flags.executable` are set, without modifying any table.
    /// Returns [`MapError::OutOfMemory`] if the frame pool holds no frame for an
    /// intermediate table, which a pool sized by [`table_frame_bound`] over
    /// every mapped range never meets.
    fn map(&mut self, virt: u64, phys: u64, size: u64, flags: PageFlags) -> Result<(), MapError>;

    /// Return the physical address of the root page table frame.
    ///
    /// This value is written to CR3 on x86-64, or encoded into the `satp` PPN field
    /// on RISC-V.
    fn root_physical(&self) -> u64;

    /// The `(physical base, page count)` spans this builder allocated that are
    /// dead once the kernel runs: the whole frame pool, used or not, and on
    /// x86-64 the LA57 toggle page when one is installed.
    ///
    /// Step 9 records each span as one entry of `BootInfo.reclaim_ranges`; see
    /// `core/boot/docs/page-tables.md` § Page Table Frame Tracking.
    fn reclaim_spans(&self) -> &[(u64, u64)];

    /// The frame pool [`new`](Self::new) allocated, as `(physical base, page
    /// count)`: the one allocation the builder makes. A redo of steps 6 and 7
    /// frees this span alone, since the x86-64 LA57 toggle page among
    /// [`reclaim_spans`](Self::reclaim_spans) is an earlier step's allocation
    /// that the handoff still runs from.
    fn pool_span(&self) -> (u64, u64);
}

/// Most page-table frames a builder of `levels` translation levels takes to map
/// every `(virt, size)` range of `ranges` with 4 KiB leaves, the root included.
///
/// A table one level above the leaves (a PT) covers 2 MiB of virtual space and
/// each level above multiplies that by 512, so the tables a range needs at a
/// level are the blocks of that level's span the range touches. The bound sums
/// that count over the ranges and the levels below the root, so tables two
/// ranges share are counted twice: it is an upper bound, never below what the
/// builder allocates for the same ranges.
pub fn table_frame_bound(levels: usize, ranges: impl IntoIterator<Item = (u64, u64)>) -> u64
{
    let mut frames: u64 = 1;
    for (virt, size) in ranges
    {
        if size == 0
        {
            continue;
        }
        // A range past the end of the address space maps nothing: `map`
        // refuses it.
        let Some((base, span)) = page_span(virt, size)
        else
        {
            continue;
        };
        // `size` is non-zero, so `span` is at least one page and `last` lies
        // within the range.
        let last = base.saturating_add(span.saturating_sub(1));
        // One shift per level below the root: 21, 30, 39, ...
        for shift in (21u32..).step_by(9).take(levels.saturating_sub(1))
        {
            // `last` is at least `base`, so the span count is exact; the
            // count of tables a range needs is far below `u64::MAX`.
            let tables = (last >> shift)
                .saturating_sub(base >> shift)
                .saturating_add(1);
            frames = frames.saturating_add(tables);
        }
    }
    frames
}

/// Convert a [`MapError`] to a [`BootError`].
pub fn map_err(e: MapError) -> BootError
{
    match e
    {
        MapError::OutOfMemory => BootError::OutOfMemory,
        MapError::WxViolation => BootError::WxViolation,
        MapError::AddressRange => BootError::MapAddressRange,
    }
}

/// Build the initial page tables for kernel handoff.
///
/// Maps all kernel ELF segments at their virtual addresses with per-segment
/// permissions, then identity-maps every page a provided boot region (`BootInfo`,
/// modules, stack, memory map buffer, etc.) touches as readable+writable.
///
/// # Errors
/// Returns [`BootError::OutOfMemory`] if page table frame allocation fails,
/// or [`BootError::WxViolation`] if a kernel segment has both W and X; this
/// is where kernel-image W^X is enforced (see
/// `core/boot/docs/elf-loading.md` § LOAD Segment Processing).
pub fn build_initial_tables(
    bs: *mut crate::uefi::EfiBootServices,
    kernel: &KernelInfo,
    identity_regions: &[(u64, u64)],
) -> Result<arch::current::BootPageTable, BootError>
{
    // Size the frame pool over every range the tables will map: the kernel
    // segments, the identity regions, and the handoff trampoline's page or
    // pages, which `install_handoff_trampoline_mapping` maps afterwards.
    let (tramp_first, tramp_last) = arch::current::trampoline_page_range();
    let trampoline = [(tramp_first, 4096), (tramp_last, 4096)]
        .into_iter()
        .filter(|&(page, _)| page != 0);
    let loaded = kernel
        .segments
        .get(..kernel.segment_count)
        .ok_or(BootError::InvalidElf(
            "kernel segment count exceeds the segment array",
        ))?;
    // An identity region past the end of the address space has no page span;
    // refuse it before the pool is allocated.
    if identity_regions
        .iter()
        .any(|&(phys, size)| size != 0 && page_span(phys, size).is_none())
    {
        return Err(BootError::MapAddressRange);
    }
    let segments = loaded.iter().map(|seg| (seg.virt_base, seg.size));
    let frames = table_frame_bound(
        arch::current::BootPageTable::translation_levels(),
        segments
            .chain(identity_regions.iter().copied())
            .chain(trampoline),
    );
    let mut table = arch::current::BootPageTable::new(bs, frames).ok_or(BootError::OutOfMemory)?;

    // Map each kernel ELF segment at its ELF virtual address with segment permissions.
    for seg in loaded
    {
        let flags = PageFlags {
            writable: seg.writable,
            executable: seg.executable,
        };
        table
            .map(seg.virt_base, seg.phys_base, seg.size, flags)
            .map_err(map_err)?;
    }

    // Identity-map all boot regions as readable+writable, non-executable.
    // The region set is the identity map that core/boot/docs/page-tables.md
    // § Contract at Kernel Entry defines; collect_identity_regions builds it.
    for &(phys, size) in identity_regions
    {
        if size == 0
        {
            continue;
        }

        let (base, span) = page_span(phys, size).ok_or(BootError::MapAddressRange)?;
        let flags = PageFlags {
            writable: true,
            executable: false,
        };
        table.map(base, base, span, flags).map_err(map_err)?;
    }

    Ok(table)
}

/// Mask used for page-aligning addresses (4 KiB pages).
const PAGE_ALIGN_MASK: u64 = 4095;

/// Return `(base, size)` of the whole pages covering the byte range
/// `[phys, phys + size)`: the base rounded down and the end rounded up to
/// page boundaries, so a region that does not start on a page boundary
/// keeps its last page (an init segment's `phys_addr` carries its
/// `p_vaddr` in-page offset). `None` when the rounded-up end runs past the end
/// of the address space.
fn page_span(phys: u64, size: u64) -> Option<(u64, u64)>
{
    let base = phys & !PAGE_ALIGN_MASK;
    let end = phys.checked_add(size)?.checked_add(PAGE_ALIGN_MASK)? & !PAGE_ALIGN_MASK;
    // `end` is at least `phys`, which is at least `base`.
    Some((base, end.checked_sub(base)?))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::collections::HashSet;

    /// The tables a builder of `levels` levels allocates for `ranges`: the
    /// root and one table per distinct block of each lower level's span that
    /// a mapped page falls in.
    fn tables_needed(levels: usize, ranges: &[(u64, u64)]) -> u64
    {
        let mut tables = HashSet::new();
        for &(virt, size) in ranges
        {
            if size == 0
            {
                continue;
            }
            let Some((base, span)) = page_span(virt, size)
            else
            {
                continue;
            };
            for page in (base..base + span).step_by(4096)
            {
                for level in 0..levels - 1
                {
                    tables.insert((level, page >> (21 + 9 * level)));
                }
            }
        }
        1 + tables.len() as u64
    }

    /// Defect caught: a pool bound below the frames the builder takes, which
    /// exhausts the pool and fails the boot with `OutOfMemory`.
    #[test]
    fn the_frame_bound_covers_every_table_the_mappings_need()
    {
        let kernel = [
            (0xFFFF_FFFF_8000_0000, 0x21_0000),
            (0xFFFF_FFFF_8021_0000, 0x8_1000),
            (0xFFFF_FFFF_8029_2000, 0x3_0010),
        ];
        let identity = [
            (0x7E00_0000, 0x1000),
            (0x7E00_1000, 0x1000),
            (0x7DF0_0000, 0x4000),
            (0x7DE0_0000, 0x1_1000),
            (0x1F_FFFF_F000, 0x2000), // straddles a 1 GiB and a 2 MiB boundary
            (0x8000_0000, 7680 * 4320 * 4), // an 8K framebuffer
            (0x1000_0000, 0x1F00),
        ];
        let all: Vec<(u64, u64)> = kernel.iter().chain(identity.iter()).copied().collect();
        for levels in [3, 4, 5]
        {
            let bound = table_frame_bound(levels, all.iter().copied());
            let needed = tables_needed(levels, &all);
            assert!(
                bound >= needed,
                "levels {levels}: bound {bound} < needed {needed}"
            );
        }
    }

    /// Defect caught: a bound that drops the root, or counts one table per
    /// range at the PT level where a range crosses a 2 MiB boundary.
    #[test]
    fn a_range_crossing_a_pt_boundary_needs_a_second_pt()
    {
        // One page: a table per level below the root, plus the root.
        assert_eq!(table_frame_bound(4, [(0x20_0000, 0x1000)]), 4);
        // Two pages either side of a 2 MiB boundary: one more PT.
        assert_eq!(table_frame_bound(4, [(0x1F_F000, 0x2000)]), 5);
        // An empty range maps nothing.
        assert_eq!(table_frame_bound(4, [(0x20_0000, 0)]), 1);
    }

    /// A region whose in-page offset pushes its end across one more page
    /// boundary than its size alone keeps that last page.
    #[test]
    fn offset_region_spans_the_page_its_tail_reaches()
    {
        // 0x1F00 + 0x200 ends at 0x2100: pages 0x1000 and 0x2000.
        assert_eq!(page_span(0x1F00, 0x200), Some((0x1000, 0x2000)));
    }

    /// A page-aligned region of whole pages maps exactly those pages.
    #[test]
    fn aligned_region_spans_exactly_its_pages()
    {
        assert_eq!(page_span(0x4000, 0x2000), Some((0x4000, 0x2000)));
    }

    /// A page-aligned region with a partial last page rounds up to it.
    #[test]
    fn partial_last_page_rounds_up()
    {
        assert_eq!(page_span(0x4000, 0x1001), Some((0x4000, 0x2000)));
    }

    /// Defect caught: a range running past the end of the address space
    /// wrapping `phys + size` into a span below its base, or mapping nothing
    /// without an error.
    #[test]
    fn a_range_past_the_address_space_end_is_refused()
    {
        assert_eq!(page_span(u64::MAX - 0x10, 0x1000), None);
        assert_eq!(
            page_span(0xFFFF_FFFF_FFFF_E000, 0x1000),
            Some((0xFFFF_FFFF_FFFF_E000, 0x1000))
        );
        let kernel = KernelInfo {
            physical_base: 0,
            virtual_base: 0,
            size: 0,
            entry_virtual: 0,
            segments: core::array::from_fn(|_| crate::elf::LoadedSegment {
                phys_base: 0,
                virt_base: 0,
                size: 0,
                writable: false,
                executable: false,
            }),
            segment_count: 0,
            kind: crate::elf::ElfKind::Exec,
            rela_phys: 0,
            rela_size: 0,
        };
        // The span check runs before the builder allocates, so no boot
        // services are needed to reach it.
        let r = build_initial_tables(core::ptr::null_mut(), &kernel, &[(u64::MAX - 0x10, 0x1000)]);
        assert!(matches!(r, Err(BootError::MapAddressRange)));
    }

    /// Defect caught: a segment count above the segment array slices past it
    /// instead of failing the build.
    #[test]
    fn a_segment_count_above_the_array_is_an_invalid_elf()
    {
        let seg = || crate::elf::LoadedSegment {
            phys_base: 0,
            virt_base: 0,
            size: 0,
            writable: false,
            executable: false,
        };
        let kernel = KernelInfo {
            physical_base: 0,
            virtual_base: 0,
            size: 0,
            entry_virtual: 0,
            segments: core::array::from_fn(|_| seg()),
            segment_count: 9,
            kind: crate::elf::ElfKind::Exec,
            rela_phys: 0,
            rela_size: 0,
        };
        let r = build_initial_tables(core::ptr::null_mut(), &kernel, &[]);
        assert!(matches!(r, Err(BootError::InvalidElf(_))));
    }
}
