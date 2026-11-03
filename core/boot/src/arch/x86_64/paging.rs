// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/arch/x86_64/paging.rs

//! x86-64 page table construction for the bootloader, parameterized over
//! the negotiated paging depth.
//!
//! [`negotiate_paging`] picks the depth at boot: 5-level (`CR4.LA57`) when
//! CPUID reports LA57, 4-level otherwise. The depth fixes the hierarchy
//! (four or five levels of 512-entry, 4 KiB tables) that [`BootPageTable`]
//! builds, and the handoff installs it, through the LA57 toggle trampoline
//! when the firmware runs the other depth
//! (`core/boot/docs/page-tables.md` § x86-64: Negotiated Paging Depth).
//! Frame allocation and W^X enforcement follow `core/boot/docs/page-tables.md`
//! (preamble and § W^X Enforcement); `map` reports a W^X request as
//! [`MapError::WxViolation`].

use core::sync::atomic::{AtomicU8, Ordering};

use boot_protocol::x86_paging::{PagingDepth, table_index};

use crate::paging::{MapError, PageFlags, PageTableBuilder};

// ── Depth negotiation ─────────────────────────────────────────────────────────

/// The paging depth negotiated by [`negotiate_paging`], as a level count. The
/// bootloader is single-threaded; the 4-level default only stands in until
/// negotiation runs (step 5), before any consumer (steps 6 and 10).
static NEGOTIATED_LEVELS: AtomicU8 = AtomicU8::new(PagingDepth::Four as u8);

/// The paging depth the bootloader builds tables for and installs at handoff.
pub(crate) fn negotiated_depth() -> PagingDepth
{
    // The store site only writes PagingDepth discriminants, so the decode
    // cannot fail.
    match PagingDepth::from_levels(NEGOTIATED_LEVELS.load(Ordering::Relaxed))
    {
        Some(depth) => depth,
        None => unreachable!(),
    }
}

/// Negotiate the paging depth: 5-level when CPUID reports LA57, else 4-level.
///
/// When the chosen depth differs from the one the firmware runs (its
/// `CR4.LA57`), the handoff must leave long mode to change it; this reserves
/// an `EfiLoaderCode` page below 4 GiB for the LA57 toggle trampoline and
/// copies the trampoline into it. When no such page can be allocated, or the
/// assembled trampoline does not fit one (the page is then freed), the
/// firmware's depth is kept, which needs no toggle.
///
/// # Safety
/// `bs` must be valid boot services (before `ExitBootServices`), and the call
/// must precede step 6, which builds the tables at the negotiated depth.
#[cfg(not(test))]
pub unsafe fn negotiate_paging(bs: *mut crate::uefi::EfiBootServices)
{
    let (max_leaf, ..) = super::cpuid(0, 0);
    let leaf7_ecx = if max_leaf >= 7
    {
        super::cpuid(7, 0).2
    }
    else
    {
        0
    };
    let advertised = PagingDepth::from_cpuid_7_ecx(leaf7_ecx);
    let firmware = PagingDepth::from_cr4(super::read_cr4());

    let mut depth = advertised;
    if depth != firmware
    {
        // SAFETY: bs is valid pre-ExitBootServices (caller contract).
        let page = unsafe { crate::uefi::allocate_code_pages_max_addr(bs, 0xFFFF_FFFF, 1) };
        if let Ok(page) = page
        {
            // SAFETY: page is a fresh, exclusively-owned EfiLoaderCode frame
            // below 4 GiB, identity-mapped by the firmware; step 6 has not run.
            if !unsafe { super::handoff::install_la57_toggle(page) }
            {
                // SAFETY: bs is valid pre-ExitBootServices; page is our
                // allocation, not installed and not touched again. A refused
                // free only leaves the page `Loaded`.
                let _ = unsafe { crate::uefi::free_pages(bs, page, 1) };
                crate::bprintln!(
                    "[--------] boot: WARNING: the LA57 toggle template does not fit \
                     one page; keeping the firmware's paging depth"
                );
                depth = firmware;
            }
        }
        else
        {
            crate::bprintln!(
                "[--------] boot: WARNING: no page below 4 GiB for the LA57 toggle; \
                 keeping the firmware's paging depth"
            );
            depth = firmware;
        }
    }

    NEGOTIATED_LEVELS.store(depth as u8, Ordering::Relaxed);
    crate::bprintln!(
        "[--------] boot: paging depth {} (cpuid la57 {}; firmware {}-level; handoff {})",
        depth.levels(),
        if advertised.la57() { "yes" } else { "no" },
        firmware.levels(),
        if depth == firmware
        {
            "keeps the firmware depth"
        }
        else
        {
            "toggles CR4.LA57"
        }
    );
}

/// Host-test stand-in: the CPUID and CR4 reads need ring 0, so host tests
/// keep the 4-level default.
///
/// # Safety
/// Safe to call at any point; the argument is unused.
#[cfg(test)]
pub unsafe fn negotiate_paging(_bs: *mut crate::uefi::EfiBootServices) {}

// ── Page tables ───────────────────────────────────────────────────────────────

/// PTE bit: Present.
const PTE_PRESENT: u64 = 1 << 0;
/// PTE bit: Writable (R/W).
const PTE_WRITABLE: u64 = 1 << 1;
// Bit 2 (U/S) = 0 for supervisor-only; never set in bootloader mappings.
/// PTE bit: No-Execute (NX, bit 63). Set for all non-executable mappings.
const PTE_NO_EXECUTE: u64 = 1 << 63;
/// Mask of the physical-address bits \[51:12\] of a table-pointer entry.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;
/// Number of entries in a single page table (all levels).
const TABLE_ENTRIES: usize = 512;

/// Highest physical address the root table may occupy: the LA57 toggle
/// trampoline loads it into CR3 with paging off, in legacy protected mode,
/// with a 32-bit move.
const ROOT_MAX_PHYS: u64 = 0xFFFF_FFFF;

/// Capacity of the page-table frame log used for post-handoff reclamation.
///
/// Covers the root plus every intermediate frame `map` allocates for the
/// mappings `core/boot/docs/page-tables.md` § Contract at Kernel Entry lists,
/// and the LA57 toggle page when one is installed. Five-level paging adds
/// one intermediate level (one extra frame per distinct top-level chain), so
/// the cap matches the riscv64 builder's, which covers Sv57. The reclaim
/// array's backing page in `BootInfo` holds up to
/// `boot_protocol::MAX_RECLAIM_RANGES` (256) entries, so this cap is the
/// binding limit; `alloc_table` returns `None` once exhausted, propagating as
/// `BootError::OutOfMemory` — diagnose by bumping this constant rather than
/// silently truncating.
const FRAME_LOG_CAP: usize = 160;

/// x86-64 page table builder for the negotiated paging depth.
///
/// Holds the physical address of the root table (PML4 or PML5) and the UEFI
/// boot services pointer used to allocate intermediate table frames on
/// demand.
pub struct BootPageTable
{
    /// Physical address of the root table, below 4 GiB.
    root_phys: u64,
    /// Translation levels of the negotiated depth (4 / 5), captured from
    /// [`negotiated_depth`] at construction.
    levels: usize,
    /// UEFI boot services pointer for frame allocation.
    bs: *mut crate::uefi::EfiBootServices,
    /// Physical addresses of every frame allocated for this builder's tables
    /// (root + every intermediate frame), and of the LA57 toggle page when
    /// one is installed, which is dead once the kernel runs. Appended to
    /// `BootInfo.reclaim_ranges` for kernel reclamation per
    /// `core/boot/docs/page-tables.md` § Page Table Frame Tracking.
    frame_log: [u64; FRAME_LOG_CAP],
    /// Number of valid entries in [`Self::frame_log`].
    frame_log_len: usize,
}

impl PageTableBuilder for BootPageTable
{
    fn new(bs: *mut crate::uefi::EfiBootServices) -> Option<Self>
    {
        // SAFETY: bs is valid pre-ExitBootServices; the allocation returns the
        // physical address of a fresh EfiLoaderData page below 4 GiB.
        let root_phys = unsafe { crate::uefi::allocate_pages_max_addr(bs, ROOT_MAX_PHYS, 1).ok()? };
        // SAFETY: root_phys points to one PAGE_SIZE region of allocated memory.
        // Zeroing ensures all entries have P=0 (not present); absent entries
        // are never walked by the hardware regardless of other bits.
        // cast_possible_truncation: PAGE_SIZE is 4096, fits in usize on all targets.
        #[allow(clippy::cast_possible_truncation)]
        unsafe {
            core::ptr::write_bytes(root_phys as *mut u8, 0, PAGE_SIZE as usize);
        }
        let mut frame_log = [0u64; FRAME_LOG_CAP];
        frame_log[0] = root_phys;
        let mut frame_log_len = 1;
        let toggle = super::handoff::la57_toggle_page();
        if toggle != 0
        {
            frame_log[1] = toggle;
            frame_log_len = 2;
        }
        Some(Self {
            root_phys,
            levels: negotiated_depth().levels(),
            bs,
            frame_log,
            frame_log_len,
        })
    }

    fn map(&mut self, virt: u64, phys: u64, size: u64, flags: PageFlags) -> Result<(), MapError>
    {
        // W^X enforcement: reject before touching any table.
        if flags.writable && flags.executable
        {
            return Err(MapError::WxViolation);
        }

        // Round size up to a page boundary: kernel segments arrive with their
        // unaligned ELF p_memsz (`build_initial_tables` in core/boot/src/paging.rs).
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

    fn allocated_frames(&self) -> &[u64]
    {
        &self.frame_log[..self.frame_log_len]
    }
}

impl BootPageTable
{
    /// Map a single 4 KiB page at virtual address `virt` to physical address `phys`.
    ///
    /// Walks the negotiated depth's hierarchy from the root (PML5 or PML4)
    /// down, allocating intermediate table frames on demand. Writes the leaf
    /// PTE with the permissions encoded in `flags`.
    fn map_4k_page(&mut self, virt: u64, phys: u64, flags: &PageFlags) -> Result<(), MapError>
    {
        let mut table_phys = self.root_phys;
        for level in (1..self.levels).rev()
        {
            // SAFETY: table_phys is the root frame allocated in new() or a
            // child frame from ensure_table: a valid, identity-mapped 4 KiB
            // table. The index is within [0, 511].
            let table =
                unsafe { core::slice::from_raw_parts_mut(table_phys as *mut u64, TABLE_ENTRIES) };
            table_phys = self.ensure_table(&mut table[table_index(level, virt)])?;
        }

        // ── Level 0 (PT) — leaf PTE ───────────────────────────────────────────
        // SAFETY: Same as the walk above; frame from ensure_table, index in [0, 511].
        let pt = unsafe { core::slice::from_raw_parts_mut(table_phys as *mut u64, TABLE_ENTRIES) };

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

        pt[table_index(0, virt)] = pte;

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
            return Ok(*entry & PTE_ADDR_MASK);
        }

        let frame = self.alloc_table().ok_or(MapError::OutOfMemory)?;
        // Intermediate PTEs: present + writable. NX is 0 (bit 63 = 0) so child
        // tables can contain executable leaf PTEs. U/S = 0 (supervisor-only).
        *entry = frame | PTE_PRESENT | PTE_WRITABLE;
        Ok(frame)
    }

    /// Allocate and zero one 4 KiB frame for use as an intermediate page table.
    ///
    /// Returns the physical address of the frame, or `None` on allocation failure
    /// (UEFI out-of-memory or [`FRAME_LOG_CAP`] exhausted).
    fn alloc_table(&mut self) -> Option<u64>
    {
        if self.frame_log_len >= FRAME_LOG_CAP
        {
            return None;
        }
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
        self.frame_log[self.frame_log_len] = frame;
        self.frame_log_len += 1;
        Some(frame)
    }
}
