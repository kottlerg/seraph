// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/paging.rs

//! x86-64 four-level (PML4 → PDPT → PD → PT) page table operations.
//!
//! All page table frames must come from the BSS-resident pool supplied via
//! [`PoolState`]. Physical addresses of pool frames convert to virtual
//! addresses with the kernel VA/PA offset embedded in `PoolState`.
//!
//! # Index layout (48-bit canonical VA)
//! - Bits \[47:39\] → PML4 index  (512 entries × 512 GiB each)
//! - Bits \[38:30\] → PDPT index  (512 entries × 1 GiB each)
//! - Bits \[29:21\] → PD index    (512 entries × 2 MiB each)
//! - Bits \[20:12\] → PT index    (512 entries × 4 KiB each)

// similar_names: pml4/pdpt/pd/pt and repeated e shadowing are intentional page-table idioms.
// cast_possible_truncation: u64→u32 EFER register splits; values are bounded by shift width.
#![allow(clippy::similar_names, clippy::cast_possible_truncation)]

use crate::mm::paging::{PageFlags, PagingError, PoolState};

// ── PTE bit constants ─────────────────────────────────────────────────────────

/// Entry is valid; must be set for all live entries.
const PRESENT: u64 = 1 << 0;
/// Read/Write — 1 allows writes, 0 makes the mapping read-only.
const WRITABLE: u64 = 1 << 1;
/// Page Write-Through — used with PCD to select strong uncacheable memory type.
const PWT: u64 = 1 << 3;
/// Page Cache Disable — set to force uncacheable mapping (e.g., MMIO).
/// When combined with PWT (UC-), or used alone per PAT, gives strong UC.
const PCD: u64 = 1 << 4;
/// Page Size (PS) — set in a PDE/PDPTE to make it a large-page leaf.
const LARGE_PAGE: u64 = 1 << 7;
/// No-Execute — blocks instruction fetch; requires `IA32_EFER.NXE` = 1.
const NO_EXECUTE: u64 = 1 << 63;
/// Mask extracting the physical page number from bits \[51:12\].
const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ── PageTableEntry ────────────────────────────────────────────────────────────

/// A 64-bit x86-64 page table entry (PML4E, PDPTE, PDE, or PTE).
///
/// Transparent newtype over `u64`. Methods cover the three entry kinds:
/// table pointer, 4 KiB leaf page, and 2 MiB large-page leaf.
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

// verbose_bit_mask: `phys & 0xFFF == 0` is the idiomatic alignment assertion form;
// the trailing_zeros() alternative is less readable for power-of-2 alignment checks.
#[allow(clippy::verbose_bit_mask)]
impl PageTableEntry
{
    /// Construct a non-leaf (table pointer) entry pointing to `phys`.
    ///
    /// Sets P=1 and R/W=1 so the subordinate table is always writable.
    /// Clears NX so executable pages in the subtree are reachable.
    /// `phys` must be 4 KiB-aligned.
    pub fn new_table(phys: u64) -> Self
    {
        debug_assert!(phys & 0xFFF == 0, "table PA not 4 KiB-aligned");
        Self(PRESENT | WRITABLE | (phys & PHYS_MASK))
    }

    /// Construct a 4 KiB leaf page entry with `flags`.
    ///
    /// `phys` must be 4 KiB-aligned. `readable` has no effect on x86-64
    /// (all present entries are readable); included for cross-arch symmetry.
    pub fn new_page(phys: u64, flags: PageFlags) -> Self
    {
        debug_assert!(phys & 0xFFF == 0, "page PA not 4 KiB-aligned");
        let mut bits = PRESENT | (phys & PHYS_MASK);
        if flags.writable
        {
            bits |= WRITABLE;
        }
        if !flags.executable
        {
            bits |= NO_EXECUTE;
        }
        if flags.uncacheable
        {
            // PCD|PWT selects the strong uncacheable (UC) memory type,
            // regardless of PAT configuration. Required for MMIO mappings.
            bits |= PCD | PWT;
        }
        Self(bits)
    }

    /// Construct a 2 MiB large-page entry (PS bit set in a PDE) with `flags`.
    ///
    /// `phys` must be 2 MiB-aligned.
    pub fn new_large_page(phys: u64, flags: PageFlags) -> Self
    {
        debug_assert!(phys & 0x1F_FFFF == 0, "large page PA not 2 MiB-aligned");
        let mut bits = PRESENT | LARGE_PAGE | (phys & PHYS_MASK);
        if flags.writable
        {
            bits |= WRITABLE;
        }
        if !flags.executable
        {
            bits |= NO_EXECUTE;
        }
        if flags.uncacheable
        {
            // For large pages, bit 12 in the PDE is the PAT bit, but PCD|PWT
            // still select the strong UC type when PAT is in default config.
            bits |= PCD | PWT;
        }
        Self(bits)
    }

    /// Return the physical address encoded in this entry (bits \[51:12\] × 4 KiB).
    pub fn phys_addr(self) -> u64
    {
        self.0 & PHYS_MASK
    }

    /// Return `true` if the Present bit is set.
    pub fn is_present(self) -> bool
    {
        self.0 & PRESENT != 0
    }
}

// ── VA index extraction ───────────────────────────────────────────────────────

/// PML4 index from a 64-bit VA (bits \[47:39\]).
pub fn pml4_index(va: u64) -> usize
{
    ((va >> 39) & 0x1FF) as usize
}

/// PDPT index from a 64-bit VA (bits \[38:30\]).
pub fn pdpt_index(va: u64) -> usize
{
    ((va >> 30) & 0x1FF) as usize
}

/// PD index from a 64-bit VA (bits \[29:21\]).
pub fn pd_index(va: u64) -> usize
{
    ((va >> 21) & 0x1FF) as usize
}

/// PT index from a 64-bit VA (bits \[20:12\]).
pub fn pt_index(va: u64) -> usize
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
    // SAFETY: frame_va is a valid direct-map VA; page table frame allocated and aligned.
    unsafe { &mut *(frame_va as *mut [PageTableEntry; 512]) }
}

// ── Mapping functions ─────────────────────────────────────────────────────────

/// Map VA `virt` → PA `phys` as a 4 KiB page with `flags`.
///
/// Walks PML4 → PDPT → PD → PT, allocating missing intermediate tables from
/// `pool`. `root_va` is the virtual address of the root PML4 frame.
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
    // SAFETY: root_va is direct-map VA of valid user PML4; table entries validated before dereference.
    let pml4 = unsafe { table_at(root_va) };
    let pdpt_pa = walk_or_alloc(&mut pml4[pml4_index(virt)], pool)?;

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pdpt = unsafe { table_at(pool.phys_to_virt(pdpt_pa)) };
    let pd_pa = walk_or_alloc(&mut pdpt[pdpt_index(virt)], pool)?;

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pd = unsafe { table_at(pool.phys_to_virt(pd_pa)) };
    let pt_pa = walk_or_alloc(&mut pd[pd_index(virt)], pool)?;

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pt = unsafe { table_at(pool.phys_to_virt(pt_pa)) };
    pt[pt_index(virt)] = PageTableEntry::new_page(phys, flags);
    Ok(())
}

/// Map VA `virt` → PA `phys` as a 2 MiB large page with `flags`.
///
/// Walks PML4 → PDPT → PD, allocating missing tables from `pool`, then
/// installs a large-page leaf at the PD level (no PT allocated).
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
    // SAFETY: root_va is direct-map VA of valid user PML4; table entries validated before dereference.
    let pml4 = unsafe { table_at(root_va) };
    let pdpt_pa = walk_or_alloc(&mut pml4[pml4_index(virt)], pool)?;

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pdpt = unsafe { table_at(pool.phys_to_virt(pdpt_pa)) };
    let pd_pa = walk_or_alloc(&mut pdpt[pdpt_index(virt)], pool)?;

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pd = unsafe { table_at(pool.phys_to_virt(pd_pa)) };
    pd[pd_index(virt)] = PageTableEntry::new_large_page(phys, flags);
    Ok(())
}

/// Return the child table physical address from `entry`, allocating a new
/// zeroed pool frame and installing it when `entry` is not present.
fn walk_or_alloc(entry: &mut PageTableEntry, pool: &mut PoolState) -> Result<u64, PagingError>
{
    if entry.is_present()
    {
        Ok(entry.phys_addr())
    }
    else
    {
        let (frame_va, frame_pa) = pool.alloc_frame()?;
        // SAFETY: frame_va is a freshly allocated, exclusively-owned pool frame; write_bytes initializes valid memory.
        unsafe {
            core::ptr::write_bytes(frame_va as *mut u8, 0, 4096);
        }
        *entry = PageTableEntry::new_table(frame_pa);
        Ok(frame_pa)
    }
}

// ── Hardware operations ───────────────────────────────────────────────────────
// These functions use privileged instructions. They are excluded from unit
// test builds (they compile fine on x86-64 hosts but must never be called
// from user-space tests; the cfg gate prevents accidental invocation).

/// Write CR3 without an explicit TLB flush.
///
/// On x86-64 without PCID, writing CR3 implicitly flushes the TLB, so this
/// is functionally identical to [`activate`]. Provided for cross-arch API
/// compatibility with RISC-V where `satp` can be written without `sfence.vma`.
///
/// # Safety
/// `root_phys` must be a valid PML4 page table root with correct kernel mappings.
#[cfg(not(test))]
pub unsafe fn write_satp_no_fence(root_phys: u64)
{
    // SAFETY: delegated to activate; root_phys is valid per caller contract.
    unsafe { activate(root_phys) };
}

/// Activate the page tables rooted at `root_phys` by writing CR3.
///
/// The CPU immediately begins using the new tables. Any virtual address that
/// is not mapped in the new tables will fault.
///
/// # Safety
/// The tables must map:
/// - The currently executing kernel code at its virtual address.
/// - The active stack at its current virtual address.
/// - All data accessed immediately after this call.
#[cfg(not(test))]
pub unsafe fn activate(root_phys: u64)
{
    // SAFETY: cr3 write changes active page table; root_phys is a valid PML4 frame.
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) root_phys,
            options(nostack),
        );
    }
}

/// Enable No-Execute by setting `IA32_EFER.NXE` (bit 11) via RDMSR/WRMSR.
///
/// Must be called before activating page tables that use the NX bit,
/// because bit 63 of a PTE is "reserved" when NXE = 0.
///
/// # Safety
/// Must execute at privilege level 0. Does not check CPUID; all QEMU
/// configurations and modern x86-64 hardware support NX.
#[cfg(not(test))]
pub unsafe fn enable_nx()
{
    /// `IA32_EFER` MSR address.
    const IA32_EFER: u32 = 0xC000_0080;
    /// No-Execute Enable bit.
    const NXE: u64 = 1 << 11;

    // SAFETY: rdmsr/wrmsr execute at ring 0; IA32_EFER read/write is architecture-defined MSR operation.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") IA32_EFER,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
        let efer = (u64::from(hi) << 32 | u64::from(lo)) | NXE;
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_EFER,
            in("eax") (efer & 0xFFFF_FFFF) as u32,
            in("edx") (efer >> 32) as u32,
            options(nostack, nomem),
        );
    }
}

/// Read the current stack pointer (RSP).
///
/// Used before activating new page tables to determine which region to
/// identity-map for the boot stack.
pub fn read_stack_pointer() -> u64
{
    let sp: u64;
    // SAFETY: reading RSP is architecture primitive; safe at ring 0.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nostack, nomem));
    }
    sp
}

/// Rebase the boot stack from identity-mapped to the direct physical map.
///
/// Adds `direct_map_base` to RSP and RBP, switching from VA == PA to
/// VA == `direct_map_base` + PA. Both mappings cover the same physical
/// frames; this eliminates the 64 KiB identity-map limit.
///
/// # Safety
/// Must be called exactly once, immediately after `activate`, while the
/// boot stack identity mapping is still valid. `direct_map_base` must be
/// the base of a direct physical map that covers all of physical RAM.
#[cfg(not(test))]
pub unsafe fn rebase_boot_stack(direct_map_base: u64)
{
    // SAFETY: adding the direct-map offset to RSP switches to the same
    // physical memory through the direct map virtual range. Both the
    // identity mapping (old) and direct map (new) are valid at this point.
    // RBP is NOT rebased: in release mode it is a general-purpose register,
    // not a frame pointer, and adding to it would corrupt live data.
    unsafe {
        core::arch::asm!(
            "add rsp, {base}",
            base = in(reg) direct_map_base,
            options(nostack),
        );
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn rebase_boot_stack(_direct_map_base: u64) {}

/// Read the current page table root physical address from CR3.
///
/// Returns the physical address of the active PML4 table. Strips the low
/// 12 bits (PCID and flags) per the CR3 layout specification.
///
/// # Safety
/// Must be called at ring 0.
#[cfg(not(test))]
pub unsafe fn read_root_phys() -> u64
{
    let cr3: u64;
    // SAFETY: reading cr3 is architecture primitive; safe at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
    }
    // Strip low 12 bits (PCID field / flags in no-PCID mode).
    cr3 & !0xFFF
}

/// Map a single 4 KiB user page `virt` → `phys` in the page table rooted at
/// `root_virt`, allocating missing intermediate frames from `allocator`.
///
/// Unlike `map_page` (which uses a BSS pool), this function allocates
/// intermediate page table frames dynamically from the buddy allocator.
/// Used for building user address spaces after Phase 4 (heap active).
///
/// # Errors
/// Returns `Err(())` if the buddy allocator is exhausted.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB PML4
/// frame. `virt` must be in the lower (user) half. `phys` must be 4 KiB-aligned.
#[cfg(not(test))]
pub unsafe fn map_user_page(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
    allocator: &mut crate::mm::BuddyAllocator,
) -> Result<(), ()>
{
    use crate::mm::paging::phys_to_virt;

    // Set USER bit (bit 2) so ring-3 code can access the page.
    const USER: u64 = 1 << 2;

    // SAFETY: root_virt is direct-map VA of valid user PML4; table entries validated before dereference.
    let pml4 = unsafe { table_at(root_virt) };

    let pdpt_pa = user_walk_or_alloc(&mut pml4[pml4_index(virt)], allocator)?;
    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pdpt = unsafe { table_at(phys_to_virt(pdpt_pa)) };

    let pd_pa = user_walk_or_alloc(&mut pdpt[pdpt_index(virt)], allocator)?;
    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pd = unsafe { table_at(phys_to_virt(pd_pa)) };

    let pt_pa = user_walk_or_alloc(&mut pd[pd_index(virt)], allocator)?;
    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pt = unsafe { table_at(phys_to_virt(pt_pa)) };

    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER;
    pt[pt_index(virt)] = pte;

    Ok(())
}

/// Walk an existing page table entry or allocate a new child frame from the
/// buddy allocator.
///
/// Used by `map_user_page` in place of `walk_or_alloc` (which uses `PoolState`).
#[cfg(not(test))]
fn user_walk_or_alloc(
    entry: &mut PageTableEntry,
    allocator: &mut crate::mm::BuddyAllocator,
) -> Result<u64, ()>
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    // Set USER bit so lower-level tables are accessible from ring 3.
    const USER: u64 = 1 << 2;

    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    let frame_pa = allocator.alloc(0).ok_or(())?;
    let frame_va = phys_to_virt(frame_pa);

    // SAFETY: frame_va is exclusively-owned direct-map kernel address; write_bytes initializes valid memory.
    unsafe {
        core::ptr::write_bytes(frame_va as *mut u8, 0, PAGE_SIZE);
    }

    let mut table_pte = PageTableEntry::new_table(frame_pa);
    table_pte.0 |= USER;
    *entry = table_pte;

    Ok(frame_pa)
}

/// Walk the user half of the page table rooted at `root_virt` and free every
/// intermediate table frame (PDPT, PD, PT) back to `allocator`.
///
/// Leaf PTEs (4 KiB and 2 MiB large pages) point at physical memory owned by
/// Frame capabilities; those frames are freed through `FrameObject` teardown
/// when the owning `CSpace` is destroyed, not here. This function only
/// reclaims the *page-table* pages the aspace allocated via
/// `user_walk_or_alloc`. The root PML4 itself is not freed here; the caller
/// in `dealloc_object(AddressSpace)` frees it after this walk completes.
///
/// Only entries in PML4 indices 0..256 (user half) are examined. Kernel-half
/// entries (256..512) are copies of the global kernel PML4; freeing any of
/// their descendants would corrupt every other address space.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB PML4
/// frame. No CPU may still be using this address space (the caller verifies
/// `active_cpu_mask() == 0` before invocation).
#[cfg(not(test))]
pub unsafe fn free_user_page_tables(root_virt: u64, allocator: &mut crate::mm::BuddyAllocator)
{
    use crate::mm::paging::phys_to_virt;

    const LARGE_PAGE_BIT: u64 = 1 << 7;

    // SAFETY: root_virt is direct-map VA of a valid PML4 page; caller's contract.
    let pml4 = unsafe { table_at(root_virt) };
    for pml4e in pml4.iter().take(256)
    {
        if !pml4e.is_present()
        {
            continue;
        }
        // PML4 entries never encode a leaf on x86-64 (no 512 GiB page support
        // on this target). Treat every present entry as a PDPT pointer.
        let pdpt_pa = pml4e.phys_addr();
        // SAFETY: pdpt_pa from a present PML4E points at a live PDPT frame.
        let pdpt = unsafe { table_at(phys_to_virt(pdpt_pa)) };
        for pdpte in pdpt.iter()
        {
            if !pdpte.is_present()
            {
                continue;
            }
            // 1 GiB large-page leaves are not produced by the user mapping
            // path today; guard against them anyway so future additions don't
            // leak or crash.
            if pdpte.0 & LARGE_PAGE_BIT != 0
            {
                continue;
            }
            let pd_pa = pdpte.phys_addr();
            // SAFETY: pd_pa from a present PDPTE points at a live PD frame.
            let pd = unsafe { table_at(phys_to_virt(pd_pa)) };
            for pde in pd.iter()
            {
                if !pde.is_present()
                {
                    continue;
                }
                // 2 MiB large-page leaves skip the PT level — no PT to free.
                if pde.0 & LARGE_PAGE_BIT != 0
                {
                    continue;
                }
                let pt_pa = pde.phys_addr();
                // SAFETY: pt_pa allocated by `user_walk_or_alloc` from the
                // buddy as order-0; caller guarantees no CPU still references it.
                unsafe { allocator.free(pt_pa, 0) };
            }
            // SAFETY: pd_pa allocated by `user_walk_or_alloc` from the buddy
            // as order-0; all descendant PT frames just freed above.
            unsafe { allocator.free(pd_pa, 0) };
        }
        // SAFETY: pdpt_pa allocated by `user_walk_or_alloc` from the buddy
        // as order-0; all descendant PD frames just freed above.
        unsafe { allocator.free(pdpt_pa, 0) };
    }
}

/// Flush the TLB entry for a single page at `virt` using `invlpg`.
///
/// Must be called after modifying or clearing a leaf PTE so the CPU stops
/// using the cached translation.
///
/// # Safety
/// Must execute at ring 0. `virt` need not be mapped; `invlpg` on an
/// unmapped address is safe (architecturally a no-op with respect to faults).
#[cfg(not(test))]
pub unsafe fn flush_page(virt: u64)
{
    // SAFETY: invlpg flushes TLB entry for specified VA; architecture primitive.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virt,
            options(nostack),
        );
    }
}

/// Remove a single user-space mapping at `virt` from the page table rooted at
/// `root_virt`.
///
/// Walks PML4 → PDPT → PD → PT. If any intermediate level is not present,
/// returns immediately (nothing to unmap). On reaching the leaf, zeros the
/// PTE and calls `flush_page`.
///
/// Intermediate page table frames are left in place even if they become
/// empty. Full teardown is deferred until address space destruction.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB PML4
/// frame. Called from a kernel context with the frame allocator lock NOT held
/// (this function does not allocate).
#[cfg(not(test))]
pub unsafe fn unmap_user_page(root_virt: u64, virt: u64)
{
    use crate::mm::paging::phys_to_virt;

    // Walk PML4 → PDPT → PD → PT, bailing silently at any absent level.
    // SAFETY: root_virt is direct-map VA of valid user PML4; table entries validated before dereference.
    let pml4 = unsafe { table_at(root_virt) };
    let e = pml4[pml4_index(virt)];
    if !e.is_present()
    {
        return;
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pdpt = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = pdpt[pdpt_index(virt)];
    if !e.is_present()
    {
        return;
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pd = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = pd[pd_index(virt)];
    if !e.is_present()
    {
        return;
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pt = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    pt[pt_index(virt)] = PageTableEntry(0);

    // SAFETY: invlpg flushes TLB entry for specified VA; architecture primitive.
    unsafe { flush_page(virt) };
}

/// Change the permission flags on an existing user-space leaf PTE at `virt`.
///
/// Walks PML4 → PDPT → PD → PT. Returns `Err(PagingError::NotMapped)` if
/// the page is not present at any level. On success, rewrites the leaf PTE
/// with the new `flags` (preserving the physical address and USER bit) and
/// calls `flush_page`.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB PML4
/// frame. Caller must have validated W^X and rights before calling.
#[cfg(not(test))]
pub unsafe fn protect_user_page(
    root_virt: u64,
    virt: u64,
    flags: crate::mm::paging::PageFlags,
) -> Result<(), crate::mm::paging::PagingError>
{
    use crate::mm::paging::{PagingError, phys_to_virt};

    // Set USER bit (bit 2) to preserve user accessibility.
    const USER: u64 = 1 << 2;

    // SAFETY: root_virt is direct-map VA of valid user PML4; table entries validated before dereference.
    let pml4 = unsafe { table_at(root_virt) };
    let e = pml4[pml4_index(virt)];
    if !e.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pdpt = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = pdpt[pdpt_index(virt)];
    if !e.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pd = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = pd[pd_index(virt)];
    if !e.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pt = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let leaf = &mut pt[pt_index(virt)];
    if !leaf.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    let phys = leaf.phys_addr();
    let mut new_pte = PageTableEntry::new_page(phys, flags);
    new_pte.0 |= USER;
    *leaf = new_pte;

    // SAFETY: invlpg flushes TLB entry for specified VA; architecture primitive.
    unsafe { flush_page(virt) };
    Ok(())
}

/// Translate a user virtual address to its mapped physical address and raw PTE.
///
/// Walks PML4 → PDPT → PD → PT without modifying any entry or flushing the
/// TLB. Returns `Some((phys_addr, raw_pte_bits))` if the page is present at
/// every level, or `None` if any level is not present.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB PML4
/// frame.
#[cfg(not(test))]
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: root_virt is direct-map VA of valid user PML4; table entries validated before dereference.
    let pml4 = unsafe { table_at(root_virt) };
    let e = pml4[pml4_index(virt)];
    if !e.is_present()
    {
        return None;
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pdpt = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = pdpt[pdpt_index(virt)];
    if !e.is_present()
    {
        return None;
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pd = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let e = pd[pd_index(virt)];
    if !e.is_present()
    {
        return None;
    }

    // SAFETY: direct map active; phys + DIRECT_MAP_BASE yields valid kernel VA.
    let pt = unsafe { table_at(phys_to_virt(e.phys_addr())) };
    let leaf = pt[pt_index(virt)];
    if !leaf.is_present()
    {
        return None;
    }

    Some((leaf.phys_addr(), leaf.0))
}

// ── TLB flush operations ──────────────────────────────────────────────────────

/// Flush all TLB entries by reloading CR3.
///
/// Invalidates all non-global TLB entries for the current address space.
/// Used by the TLB shootdown IPI handler.
///
/// # Safety
/// Must be called at ring 0. Caller must ensure this CPU is not in the middle
/// of a page table walk that would be invalidated by the flush.
#[cfg(not(test))]
pub unsafe fn flush_tlb_all()
{
    // SAFETY: CR3 is readable and writable at ring 0; reloading CR3 with its
    // current value is the standard x86-64 TLB flush mechanism.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr3",
            "mov cr3, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags),
        );
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
    fn new_table_sets_present_and_writable()
    {
        let pte = PageTableEntry::new_table(0x1000);
        assert!(pte.is_present());
        assert!(pte.0 & WRITABLE != 0);
    }

    #[test]
    fn new_table_clears_no_execute()
    {
        let pte = PageTableEntry::new_table(0x1000);
        assert!(pte.0 & NO_EXECUTE == 0);
    }

    #[test]
    fn new_page_rx_sets_present_clears_writable_clears_nx()
    {
        let flags = PageFlags {
            readable: true,
            writable: false,
            executable: true,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_page(0x2000, flags);
        assert!(pte.is_present());
        assert_eq!(pte.0 & WRITABLE, 0);
        assert_eq!(pte.0 & NO_EXECUTE, 0);
    }

    #[test]
    fn new_page_rw_sets_present_sets_writable_sets_nx()
    {
        let flags = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_page(0x3000, flags);
        assert!(pte.is_present());
        assert!(pte.0 & WRITABLE != 0);
        assert!(pte.0 & NO_EXECUTE != 0);
    }

    #[test]
    fn new_page_uncacheable_sets_pcd_pwt()
    {
        let flags = PageFlags {
            readable: true,
            writable: false,
            executable: false,
            uncacheable: true,
        };
        let pte = PageTableEntry::new_page(0x4000, flags);
        assert!(pte.0 & PCD != 0, "PCD must be set for uncacheable");
        assert!(pte.0 & PWT != 0, "PWT must be set for uncacheable");
    }

    #[test]
    fn new_page_cacheable_clears_pcd_pwt()
    {
        let flags = PageFlags {
            readable: true,
            writable: false,
            executable: false,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_page(0x4000, flags);
        assert_eq!(pte.0 & PCD, 0, "PCD must be clear for cacheable");
        assert_eq!(pte.0 & PWT, 0, "PWT must be clear for cacheable");
    }

    #[test]
    fn new_large_page_sets_ps_bit()
    {
        let flags = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_large_page(0x20_0000, flags);
        assert!(pte.0 & LARGE_PAGE != 0);
    }

    #[test]
    fn phys_addr_masks_out_flag_bits()
    {
        let pte = PageTableEntry::new_table(0xDEAD_B000);
        assert_eq!(pte.phys_addr(), 0xDEAD_B000);
    }

    #[test]
    fn is_present_false_for_zero_entry()
    {
        let pte = PageTableEntry(0);
        assert!(!pte.is_present());
    }

    // ── VA index extraction ───────────────────────────────────────────────────

    #[test]
    fn direct_map_base_pml4_index_is_256()
    {
        assert_eq!(pml4_index(DIRECT_MAP_BASE), 256);
    }

    #[test]
    fn direct_map_base_pdpt_and_pd_index_are_zero()
    {
        assert_eq!(pdpt_index(DIRECT_MAP_BASE), 0);
        assert_eq!(pd_index(DIRECT_MAP_BASE), 0);
    }

    #[test]
    fn kernel_vbase_indices()
    {
        // Kernel image at 0xFFFF_FFFF_8000_0000: PML4=511, PDPT=510, PD=0.
        let kv: u64 = 0xFFFF_FFFF_8000_0000;
        assert_eq!(pml4_index(kv), 511);
        assert_eq!(pdpt_index(kv), 510);
        assert_eq!(pd_index(kv), 0);
    }

    #[test]
    fn pt_index_extracts_bits_20_to_12()
    {
        // VA = 0x0000_0000_0012_3456: bits [20:12] = 0x123 = 291
        assert_eq!(pt_index(0x0000_0000_0012_3000), 0x123);
    }
}
