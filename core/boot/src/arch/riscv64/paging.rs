// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/riscv64/paging.rs

//! RISC-V Sv48 4-level page table construction for the bootloader.
//!
//! Sv48 uses a four-level hierarchy with 512-entry, 4 KiB tables at each
//! level. Intermediate PTEs have V=1 with R=0, W=0, X=0. Leaf PTEs set
//! the A bit always and the D bit for writable mappings, to avoid
//! hardware faults on implementations that trap A/D updates.
//! W^X is enforced: W=1 and X=1 together return [`MapError::WxViolation`].

use crate::paging::{MapError, PageFlags, PageTableBuilder};

/// PTE bit: Valid.
const PTE_V: u64 = 1 << 0;
/// PTE bit: Readable.
const PTE_R: u64 = 1 << 1;
/// PTE bit: Writable.
const PTE_W: u64 = 1 << 2;
/// PTE bit: Executable.
const PTE_X: u64 = 1 << 3;
// Bit 4 (U) = 0: supervisor-only; never set in bootloader mappings.
// Bit 5 (G) = 0: not global.
/// PTE bit: Accessed. Set in all leaf PTEs to avoid A-flag faults on
/// implementations that trap rather than set A in hardware.
const PTE_A: u64 = 1 << 6;
/// PTE bit: Dirty. Set for writable leaf PTEs to avoid D-flag faults on
/// implementations that trap rather than set D in hardware.
const PTE_D: u64 = 1 << 7;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;
/// Page size as `usize` — 4096 always fits, cast is exact.
const PAGE_SIZE_USIZE: usize = 4096;
/// Number of entries in a single page table (all levels).
const TABLE_ENTRIES: usize = 512;

/// RISC-V Sv48 4-level page table builder.
///
/// Holds the physical address of the root table and the UEFI boot services
/// pointer used to allocate intermediate table frames on demand.
pub struct BootPageTable
{
    /// Physical address of the Sv48 root table.
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
        // Zeroing ensures all entries have V=0 (invalid), which is the correct
        // initial state for an Sv48 page table.
        unsafe {
            core::ptr::write_bytes(root_phys as *mut u8, 0, PAGE_SIZE_USIZE);
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
    /// Walks the four-level Sv48 hierarchy, allocating intermediate table frames
    /// on demand. Writes the leaf PTE with the permissions encoded in `flags`.
    ///
    /// In Sv48, a PTE is a pointer to the next-level table when R=0, W=0, X=0, V=1.
    /// A PTE is a leaf when R=1 or X=1 (or both). This function always produces 4 KiB
    /// leaf PTEs at level 0.
    fn map_4k_page(&mut self, virt: u64, phys: u64, flags: &PageFlags) -> Result<(), MapError>
    {
        // Extract 9-bit table indices from the virtual address (Sv48).
        // Each index selects one of 512 entries in the corresponding table.
        let root_idx = ((virt >> 39) & 0x1FF) as usize; // bits [47:39]
        let l2_idx = ((virt >> 30) & 0x1FF) as usize; // bits [38:30]
        let l1_idx = ((virt >> 21) & 0x1FF) as usize; // bits [29:21]
        let l0_idx = ((virt >> 12) & 0x1FF) as usize; // bits [20:12]

        // ── Root table (level 3) ──────────────────────────────────────────────
        // SAFETY: root_phys is the physical address of a valid, zeroed 4 KiB
        // frame allocated in new(). The index is within [0, 511].
        let root =
            unsafe { core::slice::from_raw_parts_mut(self.root_phys as *mut u64, TABLE_ENTRIES) };

        let l2_phys = self.ensure_table(&mut root[root_idx])?;

        // ── Level 2 table ─────────────────────────────────────────────────────
        // SAFETY: Same as root above; frame from ensure_table, index in [0, 511].
        let l2 = unsafe { core::slice::from_raw_parts_mut(l2_phys as *mut u64, TABLE_ENTRIES) };

        let l1_phys = self.ensure_table(&mut l2[l2_idx])?;

        // ── Level 1 table ─────────────────────────────────────────────────────
        // SAFETY: Same as root above; frame from ensure_table, index in [0, 511].
        let l1 = unsafe { core::slice::from_raw_parts_mut(l1_phys as *mut u64, TABLE_ENTRIES) };

        let l0_phys = self.ensure_table(&mut l1[l1_idx])?;

        // ── Level 0 table — leaf PTE ──────────────────────────────────────────
        // SAFETY: Same as root above; frame from ensure_table, index in [0, 511].
        let l0 = unsafe { core::slice::from_raw_parts_mut(l0_phys as *mut u64, TABLE_ENTRIES) };

        // Build the leaf PTE. The PPN field occupies bits [53:10]:
        // PPN = (phys >> 12) << 10.
        let ppn = (phys >> 12) << 10;

        // All leaf PTEs set R=1 (readable) and A=1 to avoid A-flag faults.
        let mut pte = PTE_V | PTE_R | PTE_A | ppn;
        if flags.writable
        {
            // Set W=1 and D=1 to avoid D-flag faults on writable pages.
            pte |= PTE_W | PTE_D;
        }
        if flags.executable
        {
            pte |= PTE_X;
        }

        l0[l0_idx] = pte;

        Ok(())
    }

    /// Ensure that an intermediate-level PTE points to a valid child table frame.
    ///
    /// If the entry is already valid (V=1), extracts and returns the child frame
    /// address from the PPN field. If the entry is invalid (V=0), allocates a new
    /// zeroed frame, writes an intermediate PTE (V=1, R=0, W=0, X=0), and returns
    /// the new frame address.
    ///
    /// Intermediate PTEs have only V=1 set (R=0, W=0, X=0), which signals to the
    /// hardware that this is a pointer to the next-level table, not a leaf.
    fn ensure_table(&mut self, entry: &mut u64) -> Result<u64, MapError>
    {
        if *entry & PTE_V != 0
        {
            // Extract the physical frame address from the PPN field (bits [53:10]).
            // PPN → phys: (pte >> 10) << 12.
            return Ok((*entry >> 10) << 12);
        }

        let frame = self.alloc_table().ok_or(MapError::OutOfMemory)?;
        // Intermediate PTE: V=1, R=0, W=0, X=0. Hardware treats this as a
        // pointer to the next-level table (not a leaf).
        let ppn = (frame >> 12) << 10;
        *entry = PTE_V | ppn;
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
        // Zeroing ensures all entries have V=0 (invalid).
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE_USIZE);
        }
        Some(frame)
    }
}
