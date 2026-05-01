// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/paging.rs

//! RISC-V RV64GC Sv48 four-level page table operations.
//!
//! Mirrors the x86-64 interface. All page table frames come from the
//! BSS-resident pool supplied via [`PoolState`].
//!
//! # Sv48 index layout (48-bit VA, 4 levels)
//! - Bits \[47:39\] → VPN\[3\] — root level (512 entries × 512 GiB each)
//! - Bits \[38:30\] → VPN\[2\] — level 2     (512 entries × 1 GiB each)
//! - Bits \[29:21\] → VPN\[1\] — level 1     (512 entries × 2 MiB each)
//! - Bits \[20:12\] → VPN\[0\] — leaf level  (512 entries × 4 KiB each)
//!
//! # PTE layout
//! Bits \[53:10\]: PPN (physical page number, 44 bits).
//! Bit 0: V (Valid). Bit 1: R (Read). Bit 2: W (Write). Bit 3: X (Execute).
//! Non-leaf: V=1, R=0, W=0, X=0. Leaf: V=1, at least one of R/W/X set.
//! A megapage (2 MiB) is a leaf installed at level 1 (VPN\[1\]).

use crate::mm::paging::{PageFlags, PagingError, PoolState};

// ── PTE bit constants ─────────────────────────────────────────────────────────

/// Entry is valid.
const VALID: u64 = 1 << 0;
/// Read permission.
const READ: u64 = 1 << 1;
/// Write permission.
const WRITE: u64 = 1 << 2;
/// Execute permission.
const EXECUTE: u64 = 1 << 3;
/// Accessed — must be pre-set in leaf PTEs.
///
/// Per RISC-V Privileged Spec §5.4.1, an implementation may either update
/// the A bit in hardware or raise a page fault when a load/store/fetch
/// observes A=0. Hardware update is opt-in via the Svadu extension; absent
/// Svadu, software must pre-set A=1.
const ACCESSED: u64 = 1 << 6;
/// Dirty — must be pre-set in writable leaf PTEs (same rationale as ACCESSED).
const DIRTY: u64 = 1 << 7;
/// PPN field mask: bits \[53:10\], representing `(phys >> 12) << 10`.
const PPN_MASK: u64 = 0x003F_FFFF_FFFF_FC00;

// ── PageTableEntry ────────────────────────────────────────────────────────────

/// A 64-bit RISC-V Sv48 page table entry (PTE).
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

// verbose_bit_mask: `phys & 0xFFF == 0` is idiomatic for alignment assertions;
// trailing_zeros() alternative is less readable here.
#[allow(clippy::verbose_bit_mask)]
impl PageTableEntry
{
    /// Construct a non-leaf entry pointing to a child table at `phys`.
    ///
    /// V=1, R=0, W=0, X=0. PPN holds `phys >> 12`. `phys` must be 4 KiB-aligned.
    pub fn new_table(phys: u64) -> Self
    {
        debug_assert!(phys & 0xFFF == 0, "table PA not 4 KiB-aligned");
        // PPN in bits [53:10] = (phys >> 12) << 10.
        Self(VALID | ((phys >> 2) & PPN_MASK))
    }

    /// Construct a 4 KiB leaf page entry with `flags`.
    ///
    /// `phys` must be 4 KiB-aligned.
    ///
    /// Note: `flags.uncacheable` has no effect under Sv48 without Svpbmt —
    /// MMIO physical addresses are inherently device-ordered by the platform
    /// memory map. No PTE bits need to be set for correct behavior.
    // TODO: With Svpbmt, set PTE bits [62:61] = 01 (NC) when
    // flags.uncacheable is true. Pick up when adding Svpbmt support.
    pub fn new_page(phys: u64, flags: PageFlags) -> Self
    {
        debug_assert!(phys & 0xFFF == 0, "page PA not 4 KiB-aligned");
        // Pre-set A (and D for writable leaves) — see `ACCESSED` const for
        // the Priv-Spec §5.4.1 / Svadu rationale.
        let mut bits = VALID | ACCESSED | ((phys >> 2) & PPN_MASK);
        if flags.readable
        {
            bits |= READ;
        }
        if flags.writable
        {
            bits |= WRITE | DIRTY;
        }
        if flags.executable
        {
            bits |= EXECUTE;
        }
        Self(bits)
    }

    /// Construct a 2 MiB megapage entry (leaf at VPN\[1\] level) with `flags`.
    ///
    /// `phys` must be 2 MiB-aligned.
    pub fn new_large_page(phys: u64, flags: PageFlags) -> Self
    {
        debug_assert!(phys & 0x1F_FFFF == 0, "large page PA not 2 MiB-aligned");
        // Same encoding as new_page; the "large" nature is conveyed by level.
        Self::new_page(phys, flags)
    }

    /// Return the physical address encoded in this entry.
    ///
    /// Extracts PPN from bits \[53:10\] and shifts left by 12.
    pub fn phys_addr(self) -> u64
    {
        // PPN is (bits & PPN_MASK) >> 10, then PA = PPN << 12 = PPN << 12.
        // Combined: (bits & PPN_MASK) >> 10 << 12 = (bits & PPN_MASK) << 2.
        (self.0 & PPN_MASK) << 2
    }

    /// Return `true` if the Valid bit is set.
    pub fn is_present(self) -> bool
    {
        self.0 & VALID != 0
    }
}

// ── VA index extraction ───────────────────────────────────────────────────────

/// VPN\[3\] (root) index from a VA (bits \[47:39\]).
pub fn vpn3_index(va: u64) -> usize
{
    ((va >> 39) & 0x1FF) as usize
}

/// VPN\[2\] index from a VA (bits \[38:30\]).
pub fn vpn2_index(va: u64) -> usize
{
    ((va >> 30) & 0x1FF) as usize
}

/// VPN\[1\] index from a VA (bits \[29:21\]).
pub fn vpn1_index(va: u64) -> usize
{
    ((va >> 21) & 0x1FF) as usize
}

/// VPN\[0\] (leaf) index from a VA (bits \[20:12\]).
pub fn vpn0_index(va: u64) -> usize
{
    ((va >> 12) & 0x1FF) as usize
}

// ── Table frame access ────────────────────────────────────────────────────────

/// Reinterpret a 4 KiB pool frame as an array of 512 PTEs.
///
/// # Safety
/// `frame_va` must be the virtual address of a valid, writable, 4 KiB-aligned
/// pool frame. No other mutable reference to the same frame may exist.
unsafe fn table_at(frame_va: u64) -> &'static mut [PageTableEntry; 512]
{
    // SAFETY: frame_va is a valid direct-map VA; caller guarantees page table frame
    // is allocated, writable, 4 KiB-aligned, and exclusively owned.
    unsafe { &mut *(frame_va as *mut [PageTableEntry; 512]) }
}

// ── Mapping functions ─────────────────────────────────────────────────────────

/// Map VA `virt` → PA `phys` as a 4 KiB page with `flags`.
///
/// # Errors
/// `PagingError::OutOfFrames` if the pool cannot supply an intermediate frame.
pub fn map_page(
    root_va: u64,
    virt: u64,
    phys: u64,
    flags: PageFlags,
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    // SAFETY: root_va is the direct-map VA of a valid Sv48 root frame allocated from pool.
    let root = unsafe { table_at(root_va) };
    let l2_pa = walk_or_alloc(&mut root[vpn3_index(virt)], pool)?;

    // SAFETY: l2_pa returned by walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l2 = unsafe { table_at(pool.phys_to_virt(l2_pa)) };
    let l1_pa = walk_or_alloc(&mut l2[vpn2_index(virt)], pool)?;

    // SAFETY: l1_pa returned by walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l1 = unsafe { table_at(pool.phys_to_virt(l1_pa)) };
    let l0_pa = walk_or_alloc(&mut l1[vpn1_index(virt)], pool)?;

    // SAFETY: l0_pa returned by walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l0 = unsafe { table_at(pool.phys_to_virt(l0_pa)) };
    l0[vpn0_index(virt)] = PageTableEntry::new_page(phys, flags);
    Ok(())
}

/// Map VA `virt` → PA `phys` as a 2 MiB megapage with `flags`.
///
/// Installs a leaf entry at the VPN\[1\] level; no VPN\[0\] table is allocated.
///
/// # Errors
/// `PagingError::OutOfFrames` if the pool cannot supply an intermediate frame.
pub fn map_large_page(
    root_va: u64,
    virt: u64,
    phys: u64,
    flags: PageFlags,
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    // SAFETY: root_va is the direct-map VA of a valid Sv48 root frame allocated from pool.
    let root = unsafe { table_at(root_va) };
    let l2_pa = walk_or_alloc(&mut root[vpn3_index(virt)], pool)?;

    // SAFETY: l2_pa returned by walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l2 = unsafe { table_at(pool.phys_to_virt(l2_pa)) };
    let l1_pa = walk_or_alloc(&mut l2[vpn2_index(virt)], pool)?;

    // SAFETY: l1_pa returned by walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l1 = unsafe { table_at(pool.phys_to_virt(l1_pa)) };
    l1[vpn1_index(virt)] = PageTableEntry::new_large_page(phys, flags);
    Ok(())
}

/// Return the child table physical address from `entry`, allocating and
/// zeroing a new pool frame when the entry is not present.
// similar_names: frame_va and frame_pa are a VA/PA pair — the similarity is intentional.
#[allow(clippy::similar_names)]
fn walk_or_alloc(entry: &mut PageTableEntry, pool: &mut PoolState) -> Result<u64, PagingError>
{
    if entry.is_present()
    {
        Ok(entry.phys_addr())
    }
    else
    {
        let (frame_va, frame_pa) = pool.alloc_frame()?;
        // SAFETY: frame_va is a freshly allocated, exclusively-owned pool frame;
        // write_bytes zeroes exactly one 4 KiB page.
        unsafe {
            core::ptr::write_bytes(frame_va as *mut u8, 0, 4096);
        }
        *entry = PageTableEntry::new_table(frame_pa);
        Ok(frame_pa)
    }
}

// ── Hardware operations ───────────────────────────────────────────────────────

/// Activate Sv48 paging by writing `satp` and issuing `sfence.vma`.
///
/// `satp` encoding: mode 9 (Sv48) in bits \[63:60\], ASID 0, root PPN in
/// bits \[43:0\].
///
/// # Safety
/// The tables must map the currently executing code and active stack.
#[cfg(not(test))]
/// Write `satp` to point at `root_phys` without executing `sfence.vma`.
///
/// Used when transitioning to idle where stale user TLB entries are harmless
/// (kernel code only touches kernel-mapped addresses). The caller is
/// responsible for ensuring the next user-mode transition does a proper
/// `activate()` which includes `sfence.vma`.
///
/// # Safety
/// `root_phys` must be a valid page table root with correct kernel mappings.
#[cfg(not(test))]
pub unsafe fn write_satp_no_fence(root_phys: u64)
{
    let satp = (9u64 << 60) | (root_phys >> 12);
    // SAFETY: satp CSR write is safe in S-mode; root_phys is valid.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            in(reg) satp,
            options(nostack),
        );
    }
}

/// Activate the given page table root by writing `satp` and flushing the TLB.
///
/// # Safety
/// `root_phys` must be a valid page table root. The page tables must map
/// the currently executing code, the kernel stack, and the direct map.
#[cfg(not(test))]
pub unsafe fn activate(root_phys: u64)
{
    let satp = (9u64 << 60) | (root_phys >> 12);
    // SAFETY: satp write switches active Sv48 page table; root_phys is a valid root frame;
    // caller guarantees tables map current code, stack, and direct map. sfence.vma flushes
    // TLB. RISC-V S-mode architecture primitive.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma zero, zero",
            in(reg) satp,
            options(nostack),
        );
    }
}

/// No-op on RISC-V: the XN/NX mechanism is always available via PTE X bit.
#[cfg(not(test))]
pub unsafe fn enable_nx() {}

/// Read the current stack pointer (sp register).
pub fn read_stack_pointer() -> u64
{
    let sp: u64;
    // SAFETY: sp register read is always safe in S-mode; RISC-V architecture primitive.
    unsafe {
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nostack, nomem));
    }
    sp
}

/// Rebase the boot stack from identity-mapped to the direct physical map.
///
/// Adds `direct_map_base` to `sp` and `s0` (frame pointer), switching from
/// VA == PA to VA == `direct_map_base` + PA. Both mappings cover the same
/// physical frames; this eliminates the 64 KiB identity-map limit.
///
/// # Safety
/// Must be called exactly once, immediately after `activate`, while the
/// boot stack identity mapping is still valid. `direct_map_base` must be
/// the base of a direct physical map that covers all of physical RAM.
#[cfg(not(test))]
pub unsafe fn rebase_boot_stack(direct_map_base: u64)
{
    // SAFETY: adding the direct-map offset to sp switches to the same
    // physical memory through the direct map virtual range. Both the
    // identity mapping (old) and direct map (new) are valid at this point.
    // s0 is NOT rebased: in release mode it is a general-purpose register,
    // not a frame pointer, and adding to it would corrupt live data.
    unsafe {
        core::arch::asm!(
            "add sp, sp, {base}",
            base = in(reg) direct_map_base,
            options(nostack),
        );
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn rebase_boot_stack(_direct_map_base: u64) {}

/// Read the current page table root physical address from `satp`.
///
/// Extracts PPN from `satp[43:0]` and converts to a physical address.
///
/// # Safety
/// Must be called in S-mode.
#[cfg(not(test))]
pub unsafe fn read_root_phys() -> u64
{
    let satp: u64;
    // SAFETY: satp CSR read is always safe in S-mode; RISC-V architecture primitive.
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) satp, options(nostack, nomem));
    }
    // PPN is satp[43:0]; physical address = PPN << 12.
    (satp & 0x000F_FFFF_FFFF_FFFF) << 12
}

/// Map a single 4 KiB user page `virt` → `phys` in the Sv48 page table
/// rooted at `root_virt`, allocating missing intermediate frames from `allocator`.
///
/// Sets U (user) bit so userspace can access the mapping.
///
/// # Errors
/// Returns `Err(())` if the buddy allocator is exhausted.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB Sv48
/// root frame. `virt` must be in the lower (user) half. `phys` must be 4 KiB-aligned.
// similar_names: frame_va and frame_pa are a VA/PA pair — the similarity is intentional.
#[cfg(not(test))]
#[allow(clippy::similar_names)]
pub unsafe fn map_user_page(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
    allocator: &mut crate::mm::BuddyAllocator,
) -> Result<(), ()>
{
    use crate::mm::paging::phys_to_virt;
    // U bit (bit 4) allows user-mode access.
    const USER: u64 = 1 << 4;

    // SAFETY: root_virt is direct-map VA of valid user Sv48 root PT; caller contract.
    let root = unsafe { table_at(root_virt) };

    let l2_pa = rv_walk_or_alloc(&mut root[vpn3_index(virt)], allocator)?;
    // SAFETY: l2_pa from rv_walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l2 = unsafe { table_at(phys_to_virt(l2_pa)) };

    let l1_pa = rv_walk_or_alloc(&mut l2[vpn2_index(virt)], allocator)?;
    // SAFETY: l1_pa from rv_walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l1 = unsafe { table_at(phys_to_virt(l1_pa)) };

    let l0_pa = rv_walk_or_alloc(&mut l1[vpn1_index(virt)], allocator)?;
    // SAFETY: l0_pa from rv_walk_or_alloc is valid; phys_to_virt yields direct-map VA.
    let l0 = unsafe { table_at(phys_to_virt(l0_pa)) };
    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER;
    l0[vpn0_index(virt)] = pte;

    Ok(())
}

/// Walk an existing Sv48 page table entry or allocate a new child frame.
// similar_names: frame_va and frame_pa are a VA/PA pair — the similarity is intentional.
#[cfg(not(test))]
#[allow(clippy::similar_names)]
fn rv_walk_or_alloc(
    entry: &mut PageTableEntry,
    allocator: &mut crate::mm::BuddyAllocator,
) -> Result<u64, ()>
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    let frame_pa = allocator.alloc(0).ok_or(())?;
    let frame_va = phys_to_virt(frame_pa);

    // SAFETY: frame_va is direct-map VA of freshly allocated buddy frame; exclusively
    // owned; write_bytes zeroes exactly PAGE_SIZE (4 KiB).
    unsafe {
        core::ptr::write_bytes(frame_va as *mut u8, 0, PAGE_SIZE);
    }

    *entry = PageTableEntry::new_table(frame_pa);
    Ok(frame_pa)
}

/// Map a single 4 KiB user page, drawing intermediate page-table frames from
/// an `AddressSpaceObject`'s growth pool instead of the buddy allocator.
///
/// # Safety
/// Same contract as [`map_user_page`]. `aso` must be the wrapper paired
/// with the page table at `root_virt`.
#[cfg(not(test))]
pub unsafe fn map_user_page_pooled(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
    aso: &crate::cap::object::AddressSpaceObject,
) -> Result<(), ()>
{
    use crate::mm::paging::phys_to_virt;
    const USER: u64 = 1 << 4;

    // SAFETY: root_virt is direct-map VA of valid user Sv48 root PT.
    let root = unsafe { table_at(root_virt) };

    let l2_pa = rv_walk_or_alloc_pooled(&mut root[vpn3_index(virt)], aso)?;
    // SAFETY: l2_pa is a valid PT frame phys addr.
    let l2 = unsafe { table_at(phys_to_virt(l2_pa)) };

    let l1_pa = rv_walk_or_alloc_pooled(&mut l2[vpn2_index(virt)], aso)?;
    // SAFETY: l1_pa is a valid PT frame phys addr.
    let l1 = unsafe { table_at(phys_to_virt(l1_pa)) };

    let l0_pa = rv_walk_or_alloc_pooled(&mut l1[vpn1_index(virt)], aso)?;
    // SAFETY: l0_pa is a valid PT frame phys addr.
    let l0 = unsafe { table_at(phys_to_virt(l0_pa)) };

    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER;
    l0[vpn0_index(virt)] = pte;

    Ok(())
}

/// Pooled equivalent of [`rv_walk_or_alloc`]: pulls a freshly-zeroed PT
/// frame from the AS's growth pool when an entry is absent.
#[cfg(not(test))]
fn rv_walk_or_alloc_pooled(
    entry: &mut PageTableEntry,
    aso: &crate::cap::object::AddressSpaceObject,
) -> Result<u64, ()>
{
    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    let frame_pa = aso.alloc_pt_page().ok_or(())?;
    *entry = PageTableEntry::new_table(frame_pa);
    Ok(frame_pa)
}

/// Walk the user half of the Sv48 page table rooted at `root_virt` and free
/// every intermediate table frame (VPN\[2\], VPN\[1\], VPN\[0\]) back to
/// `allocator`.
///
/// Leaf PTEs (R/W/X any set) point at physical memory owned by Frame
/// capabilities; those frames are freed through `FrameObject` teardown when
/// the owning `CSpace` is destroyed, not here. This function only reclaims
/// the *page-table* pages the aspace allocated via `rv_walk_or_alloc`. The
/// root VPN\[3\] frame itself is not freed here; the caller in
/// `dealloc_object(AddressSpace)` frees it after this walk completes.
///
/// Only entries in VPN\[3\] indices 0..256 (user half) are examined. Entries
/// 256..512 are copies of the global kernel root; freeing any of their
/// descendants would corrupt every other address space.
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB Sv48 root frame.
/// No CPU may still be using this address space (the caller verifies
/// `active_cpu_mask() == 0` before invocation).
#[cfg(not(test))]
#[allow(dead_code)]
pub unsafe fn free_user_page_tables(root_virt: u64, allocator: &mut crate::mm::BuddyAllocator)
{
    use crate::mm::paging::phys_to_virt;

    // Sv48 leaf detection: R/W/X bits; non-leaves are V=1 with R=W=X=0.
    const LEAF_BITS: u64 = READ | WRITE | EXECUTE;
    let is_leaf = |e: PageTableEntry| e.0 & LEAF_BITS != 0;

    // SAFETY: root_virt is direct-map VA of a valid Sv48 root; caller's contract.
    let root = unsafe { table_at(root_virt) };
    for root_e in root.iter().take(256)
    {
        if !root_e.is_present()
        {
            continue;
        }
        // VPN[3] leaves (512 GiB pages) aren't produced by the mapping path;
        // guard against them regardless.
        if is_leaf(*root_e)
        {
            continue;
        }
        let l2_pa = root_e.phys_addr();
        // SAFETY: l2_pa from a present VPN[3] entry points at a live L2 frame.
        let l2 = unsafe { table_at(phys_to_virt(l2_pa)) };
        for l2_e in l2.iter()
        {
            if !l2_e.is_present()
            {
                continue;
            }
            // VPN[2] leaf = 1 GiB gigapage — no L1 to free under it.
            if is_leaf(*l2_e)
            {
                continue;
            }
            let l1_pa = l2_e.phys_addr();
            // SAFETY: l1_pa from a present VPN[2] entry points at a live L1 frame.
            let l1 = unsafe { table_at(phys_to_virt(l1_pa)) };
            for l1_e in l1.iter()
            {
                if !l1_e.is_present()
                {
                    continue;
                }
                // VPN[1] leaf = 2 MiB megapage — no L0 to free under it.
                if is_leaf(*l1_e)
                {
                    continue;
                }
                let l0_pa = l1_e.phys_addr();
                // SAFETY: l0_pa allocated by `rv_walk_or_alloc` from the
                // buddy as order-0; no CPU references it (caller's contract).
                unsafe { allocator.free(l0_pa, 0) };
            }
            // SAFETY: l1_pa allocated by `rv_walk_or_alloc` from the buddy
            // as order-0; all descendant L0 frames just freed above.
            unsafe { allocator.free(l1_pa, 0) };
        }
        // SAFETY: l2_pa allocated by `rv_walk_or_alloc` from the buddy as
        // order-0; all descendant L1 frames just freed above.
        unsafe { allocator.free(l2_pa, 0) };
    }
}

/// Flush the TLB entry for a single virtual address using `sfence.vma addr`.
///
/// # Safety
/// Must execute in S-mode or higher. `virt` need not be mapped.
#[cfg(not(test))]
pub unsafe fn flush_page(virt: u64)
{
    // SAFETY: sfence.vma flushes TLB for single VA; RISC-V S-mode architecture primitive;
    // safe for any virtual address (mapped or unmapped).
    unsafe {
        core::arch::asm!(
            "sfence.vma {}, zero",
            in(reg) virt,
            options(nostack),
        );
    }
}

/// Remove a single user-space mapping at `virt` from the Sv48 page table
/// rooted at `root_virt`.
///
/// Walks VPN[3] → VPN[2] → VPN[1] → VPN[0]. If any intermediate level is
/// not present, returns immediately (nothing to unmap). On reaching the leaf,
/// zeros the PTE and calls `flush_page`.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB Sv48
/// root frame. Does not allocate.
#[cfg(not(test))]
pub unsafe fn unmap_user_page(root_virt: u64, virt: u64)
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: root_virt is direct-map VA of valid user Sv48 root PT; caller contract.
    let root = unsafe { table_at(root_virt) };
    let e = root[vpn3_index(virt)];
    if !e.is_present()
    {
        return;
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l2 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = l2[vpn2_index(virt)];
    if !e.is_present()
    {
        return;
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l1 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = l1[vpn1_index(virt)];
    if !e.is_present()
    {
        return;
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l0 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    l0[vpn0_index(virt)] = PageTableEntry(0);

    // SAFETY: virt may now be unmapped; flush_page is safe for any VA.
    unsafe { flush_page(virt) };
}

/// Change the permission flags on an existing user-space leaf PTE at `virt`.
///
/// Returns `Err(PagingError::NotMapped)` if any level is not present. On
/// success, rewrites the leaf PTE with the new `flags` (preserving physical
/// address and USER bit) and calls `flush_page`.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB Sv48
/// root frame. Caller must have validated W^X and rights before calling.
#[cfg(not(test))]
pub unsafe fn protect_user_page(
    root_virt: u64,
    virt: u64,
    flags: crate::mm::paging::PageFlags,
) -> Result<(), crate::mm::paging::PagingError>
{
    use crate::mm::paging::{PagingError, phys_to_virt};
    // Set USER (U) bit (bit 4) to preserve user accessibility.
    const USER: u64 = 1 << 4;

    // SAFETY: root_virt is direct-map VA of valid user Sv48 root PT; caller contract.
    let root = unsafe { table_at(root_virt) };
    let e = root[vpn3_index(virt)];
    if !e.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l2 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = l2[vpn2_index(virt)];
    if !e.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l1 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = l1[vpn1_index(virt)];
    if !e.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l0 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let leaf = &mut l0[vpn0_index(virt)];
    if !leaf.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    let phys = leaf.phys_addr();
    let mut new_pte = PageTableEntry::new_page(phys, flags);
    new_pte.0 |= USER;
    *leaf = new_pte;

    // SAFETY: virt is mapped; flush_page is safe for any VA.
    unsafe { flush_page(virt) };
    Ok(())
}

/// Translate a user virtual address to its mapped physical address and raw PTE.
///
/// Walks L3 → L2 → L1 → L0 (Sv48) without modifying any entry or flushing the
/// TLB. Returns `Some((phys_addr, raw_pte_bits))` if the page is present at
/// every level, or `None` if any level is not present.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB L3
/// page table frame.
#[cfg(not(test))]
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: root_virt is direct-map VA of valid user Sv48 root PT; caller contract.
    let root = unsafe { table_at(root_virt) };
    let e = root[vpn3_index(virt)];
    if !e.is_present()
    {
        return None;
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l2 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = l2[vpn2_index(virt)];
    if !e.is_present()
    {
        return None;
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l1 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = l1[vpn1_index(virt)];
    if !e.is_present()
    {
        return None;
    }

    // SAFETY: e.phys_addr() extracted from present PTE; phys_to_virt yields direct-map VA.
    let l0 = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let leaf = l0[vpn0_index(virt)];
    if !leaf.is_present()
    {
        return None;
    }

    Some((leaf.phys_addr(), leaf.0))
}

// ── TLB flush operations ──────────────────────────────────────────────────────

/// Flush all TLB entries for all address spaces.
///
/// Uses `sfence.vma` with both arguments zero to invalidate all TLB entries.
/// Used by the TLB shootdown IPI handler.
///
/// # Safety
/// Must be called in supervisor mode. Caller must ensure this hart is not in
/// the middle of a page table walk that would be invalidated by the flush.
#[cfg(not(test))]
pub unsafe fn flush_tlb_all()
{
    // SAFETY: sfence.vma with both arguments zero invalidates all TLB entries.
    unsafe {
        core::arch::asm!("sfence.vma zero, zero", options(nostack, preserves_flags),);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::mm::paging::DIRECT_MAP_BASE;

    // ── PTE construction ──────────────────────────────────────────────────────

    #[test]
    fn new_table_sets_valid_clears_rwx()
    {
        let pte = PageTableEntry::new_table(0x1000);
        assert!(pte.is_present());
        assert_eq!(pte.0 & READ, 0);
        assert_eq!(pte.0 & WRITE, 0);
        assert_eq!(pte.0 & EXECUTE, 0);
    }

    #[test]
    fn new_page_rw_sets_read_write_clears_execute()
    {
        let flags = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_page(0x2000, flags);
        assert!(pte.is_present());
        assert!(pte.0 & READ != 0);
        assert!(pte.0 & WRITE != 0);
        assert_eq!(pte.0 & EXECUTE, 0);
    }

    #[test]
    fn new_page_rx_sets_read_execute_clears_write()
    {
        let flags = PageFlags {
            readable: true,
            writable: false,
            executable: true,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_page(0x3000, flags);
        assert!(pte.0 & READ != 0);
        assert_eq!(pte.0 & WRITE, 0);
        assert!(pte.0 & EXECUTE != 0);
    }

    #[test]
    fn phys_addr_roundtrip()
    {
        let pa: u64 = 0x8020_0000;
        let pte = PageTableEntry::new_table(pa);
        assert_eq!(pte.phys_addr(), pa);
    }

    #[test]
    fn is_present_false_for_zero_entry()
    {
        assert!(!PageTableEntry(0).is_present());
    }

    // ── VA index extraction ───────────────────────────────────────────────────

    #[test]
    fn direct_map_base_vpn3_index_is_256()
    {
        assert_eq!(vpn3_index(DIRECT_MAP_BASE), 256);
    }

    #[test]
    fn direct_map_base_lower_indices_are_zero()
    {
        assert_eq!(vpn2_index(DIRECT_MAP_BASE), 0);
        assert_eq!(vpn1_index(DIRECT_MAP_BASE), 0);
    }

    #[test]
    fn kernel_vbase_vpn3_is_511_vpn2_is_510()
    {
        let kv: u64 = 0xFFFF_FFFF_8000_0000;
        assert_eq!(vpn3_index(kv), 511);
        assert_eq!(vpn2_index(kv), 510);
        assert_eq!(vpn1_index(kv), 0);
    }
}
