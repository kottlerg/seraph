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
}

/// Architecture-specific page table builder.
///
/// Implementors allocate page table frames via UEFI `AllocatePages` and construct
/// the minimal initial mapping needed for kernel handoff. All allocation must occur
/// before `ExitBootServices`.
///
/// # Safety
/// All implementations must enforce W^X: any call to [`map`] with
/// `flags.writable && flags.executable` must return [`MapError::WxViolation`]
/// without modifying any table.
///
/// [`map`]: PageTableBuilder::map
pub trait PageTableBuilder: Sized
{
    /// Allocate a new, empty root page table.
    ///
    /// Frames are allocated from UEFI `AllocatePages`. Returns `None` if the
    /// allocation fails.
    ///
    /// # Safety
    /// `bs` must be a valid pointer to UEFI boot services (before `ExitBootServices`).
    fn new(bs: *mut crate::uefi::EfiBootServices) -> Option<Self>;

    /// Map the virtual range `[virt, virt+size)` to `[phys, phys+size)`.
    ///
    /// `size` must be page-aligned. Returns [`MapError::WxViolation`] if both
    /// `flags.writable` and `flags.executable` are set, without modifying any table.
    /// Returns [`MapError::OutOfMemory`] if an intermediate frame allocation fails.
    fn map(&mut self, virt: u64, phys: u64, size: u64, flags: PageFlags) -> Result<(), MapError>;

    /// Return the physical address of the root page table frame.
    ///
    /// This value is written to CR3 on x86-64, or encoded into the `satp` PPN field
    /// on RISC-V.
    fn root_physical(&self) -> u64;

    /// Physical addresses of every frame this builder allocated for its own page
    /// tables (the root frame and every intermediate frame allocated during
    /// [`map`][Self::map]).
    ///
    /// Step 9 records these in `BootInfo.reclaim_ranges`; see
    /// `core/boot/docs/page-tables.md` § Page Table Frame Tracking.
    fn allocated_frames(&self) -> &[u64];
}

/// Convert a [`MapError`] to a [`BootError`].
fn map_err(e: MapError) -> BootError
{
    match e
    {
        MapError::OutOfMemory => BootError::OutOfMemory,
        MapError::WxViolation => BootError::WxViolation,
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
    let mut table = arch::current::BootPageTable::new(bs).ok_or(BootError::OutOfMemory)?;

    // Map each kernel ELF segment at its ELF virtual address with segment permissions.
    for seg in &kernel.segments[0..kernel.segment_count]
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

        let (base, span) = page_span(phys, size);
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
/// `p_vaddr` in-page offset).
fn page_span(phys: u64, size: u64) -> (u64, u64)
{
    let base = phys & !PAGE_ALIGN_MASK;
    let end = (phys + size + PAGE_ALIGN_MASK) & !PAGE_ALIGN_MASK;
    (base, end - base)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A region whose in-page offset pushes its end across one more page
    /// boundary than its size alone keeps that last page.
    #[test]
    fn offset_region_spans_the_page_its_tail_reaches()
    {
        // 0x1F00 + 0x200 ends at 0x2100: pages 0x1000 and 0x2000.
        assert_eq!(page_span(0x1F00, 0x200), (0x1000, 0x2000));
    }

    /// A page-aligned region of whole pages maps exactly those pages.
    #[test]
    fn aligned_region_spans_exactly_its_pages()
    {
        assert_eq!(page_span(0x4000, 0x2000), (0x4000, 0x2000));
    }

    /// A page-aligned region with a partial last page rounds up to it.
    #[test]
    fn partial_last_page_rounds_up()
    {
        assert_eq!(page_span(0x4000, 0x1001), (0x4000, 0x2000));
    }
}
