// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/x86_64/paging.rs

//! x86-64 4-level (PML4) page table construction for the bootloader.
//!
//! Builds the minimal initial page tables needed for kernel handoff.
//! All intermediate frames are allocated via UEFI `AllocatePages` before
//! `ExitBootServices`. W^X is enforced: any mapping with both writable and
//! executable flags returns [`MapError::WxViolation`].

use crate::paging::{MapError, PageFlags, PageTableBuilder};

/// PTE bit: Present.
const PTE_PRESENT: u64 = 1 << 0;
/// PTE bit: Writable (R/W).
const PTE_WRITABLE: u64 = 1 << 1;
// Bit 2 (U/S) = 0 for supervisor-only; never set in bootloader mappings.
/// PTE bit: No-Execute (NX, bit 63). Set for all non-executable mappings.
const PTE_NO_EXECUTE: u64 = 1 << 63;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;
/// Number of entries in a single page table (all levels).
const TABLE_ENTRIES: usize = 512;

/// x86-64 4-level page table builder.
///
/// Holds the physical address of the PML4 root and the UEFI boot services
/// pointer used to allocate intermediate table frames on demand.
pub struct BootPageTable
{
    /// Physical address of the PML4 root table.
    root_phys: u64,
    /// UEFI boot services pointer for frame allocation.
    bs: *mut crate::uefi::EfiBootServices,
}

impl PageTableBuilder for BootPageTable
{
    fn new(bs: *mut crate::uefi::EfiBootServices) -> Option<Self>
    {
        // SAFETY: bs is valid pre-ExitBootServices; allocate_pages returns a
        // physical address of a freshly allocated EfiLoaderData region.
        let root_phys = unsafe { crate::uefi::allocate_pages(bs, 1).ok()? };
        // SAFETY: root_phys points to one PAGE_SIZE region of allocated memory.
        // Zeroing ensures all entries have P=0 (not present); absent entries
        // are never walked by the hardware regardless of other bits.
        // cast_possible_truncation: PAGE_SIZE is 4096, fits in usize on all targets.
        #[allow(clippy::cast_possible_truncation)]
        unsafe {
            core::ptr::write_bytes(root_phys as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(Self { root_phys, bs })
    }

    fn map(&mut self, virt: u64, phys: u64, size: u64, flags: PageFlags) -> Result<(), MapError>
    {
        // W^X enforcement: reject before touching any table.
        if flags.writable && flags.executable
        {
            return Err(MapError::WxViolation);
        }

        // Round size up to a page boundary so callers with non-aligned sizes are
        // handled safely. Well-behaved callers always pass aligned sizes.
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        let mut offset: u64 = 0;
        while offset < aligned_size
        {
            self.map_4k_page(virt + offset, phys + offset, &flags)?;
            offset += PAGE_SIZE;
        }

        Ok(())
    }

    fn root_physical(&self) -> u64
    {
        self.root_phys
    }
}

impl BootPageTable
{
    /// Map a single 4 KiB page at virtual address `virt` to physical address `phys`.
    ///
    /// Walks the four-level PML4 hierarchy, allocating intermediate table frames
    /// on demand. Writes the leaf PTE with the permissions encoded in `flags`.
    fn map_4k_page(&mut self, virt: u64, phys: u64, flags: &PageFlags) -> Result<(), MapError>
    {
        // Extract 9-bit table indices from the virtual address.
        // Each index selects one of 512 entries in the corresponding table.
        let pml4_idx = ((virt >> 39) & 0x1FF) as usize;
        let pml3_idx = ((virt >> 30) & 0x1FF) as usize;
        let pml2_idx = ((virt >> 21) & 0x1FF) as usize;
        let pml1_idx = ((virt >> 12) & 0x1FF) as usize;

        // ── Level 4 (PML4) ────────────────────────────────────────────────────
        // SAFETY: root_phys is the physical address of a valid, zeroed 4 KiB
        // frame allocated in new(). The index is within [0, 511].
        let pml4 =
            unsafe { core::slice::from_raw_parts_mut(self.root_phys as *mut u64, TABLE_ENTRIES) };

        let pml3_phys = self.ensure_table(&mut pml4[pml4_idx])?;

        // ── Level 3 (PDPT) ────────────────────────────────────────────────────
        // SAFETY: Same as pml4 above; frame from ensure_table, index in [0, 511].
        let pml3 = unsafe { core::slice::from_raw_parts_mut(pml3_phys as *mut u64, TABLE_ENTRIES) };

        let pml2_phys = self.ensure_table(&mut pml3[pml3_idx])?;

        // ── Level 2 (PD) ─────────────────────────────────────────────────────
        // SAFETY: Same as pml4 above; frame from ensure_table, index in [0, 511].
        let pml2 = unsafe { core::slice::from_raw_parts_mut(pml2_phys as *mut u64, TABLE_ENTRIES) };

        let pml1_phys = self.ensure_table(&mut pml2[pml2_idx])?;

        // ── Level 1 (PT) — leaf PTE ───────────────────────────────────────────
        // SAFETY: Same as pml4 above; frame from ensure_table, index in [0, 511].
        let pml1 = unsafe { core::slice::from_raw_parts_mut(pml1_phys as *mut u64, TABLE_ENTRIES) };

        // Build the leaf PTE. Physical frame number occupies bits [51:12].
        let mut pte = PTE_PRESENT | (phys & !0xFFF);
        if flags.writable
        {
            pte |= PTE_WRITABLE;
        }
        // Set NX for all non-executable mappings; leave clear only for executable.
        if !flags.executable
        {
            pte |= PTE_NO_EXECUTE;
        }

        pml1[pml1_idx] = pte;

        Ok(())
    }

    /// Ensure that an intermediate-level PTE points to a valid child table frame.
    ///
    /// If the entry is already present, extracts and returns the child frame address.
    /// If the entry is absent (P=0), allocates a new zeroed frame, writes the entry,
    /// and returns the new frame address.
    ///
    /// Intermediate entries use `PTE_PRESENT | PTE_WRITABLE` with NX=0 so that
    /// child tables may contain executable leaf PTEs. The actual executable
    /// permission is enforced by the leaf PTE.
    fn ensure_table(&mut self, entry: &mut u64) -> Result<u64, MapError>
    {
        if *entry & PTE_PRESENT != 0
        {
            // Extract the physical address: bits [51:12] of the PTE.
            return Ok(*entry & 0x000F_FFFF_FFFF_F000);
        }

        let frame = self.alloc_table().ok_or(MapError::OutOfMemory)?;
        // Intermediate PTEs: present + writable. NX is 0 (bit 63 = 0) so child
        // tables can contain executable leaf PTEs. U/S = 0 (supervisor-only).
        *entry = frame | PTE_PRESENT | PTE_WRITABLE;
        Ok(frame)
    }

    /// Allocate and zero one 4 KiB frame for use as an intermediate page table.
    ///
    /// Returns the physical address of the frame, or `None` on allocation failure.
    fn alloc_table(&mut self) -> Option<u64>
    {
        // SAFETY: self.bs is valid pre-ExitBootServices; allocate_pages returns a
        // physical address of a freshly allocated EfiLoaderData region.
        let frame = unsafe { crate::uefi::allocate_pages(self.bs, 1).ok()? };
        // SAFETY: frame points to one PAGE_SIZE region of allocated memory.
        // Zeroing ensures all entries have P=0 (not present).
        // cast_possible_truncation: PAGE_SIZE is 4096, fits in usize on all targets.
        #[allow(clippy::cast_possible_truncation)]
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(frame)
    }
}
