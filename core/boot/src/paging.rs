// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/paging.rs

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
/// permissions, then identity-maps all provided boot regions (`BootInfo`, modules,
/// stack, memory map buffer, etc.) as readable+writable.
///
/// # Errors
/// Returns [`BootError::OutOfMemory`] if page table frame allocation fails,
/// or [`BootError::WxViolation`] if a segment has both W and X (should not
/// happen if ELF loading already checked, but enforced again here).
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
    // These regions (BootInfo, modules, stack, memory map buffer) must be
    // accessible to the kernel before it establishes its own page tables.
    for &(phys, size) in identity_regions
    {
        if size == 0
        {
            continue;
        }

        // Round size up to the next page boundary so no partial page is unmapped.
        let aligned_size = (size + PAGE_ALIGN_MASK) & !PAGE_ALIGN_MASK;

        let flags = PageFlags {
            writable: true,
            executable: false,
        };
        table
            .map(phys, phys, aligned_size, flags)
            .map_err(map_err)?;
    }

    Ok(table)
}

/// Mask used for page-aligning sizes upward (4 KiB pages).
const PAGE_ALIGN_MASK: u64 = 4095;
