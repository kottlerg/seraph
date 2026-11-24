// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/paging.rs

//! RISC-V page table operations, parameterized over the active paging mode.
//!
//! Mirrors the x86-64 interface. [`map_page`] and [`map_large_page`] (kernel
//! page-table construction) draw intermediate frames from the [`PoolState`]
//! the caller supplies: the BSS-resident seed, then the Phase 3 carve of RAM,
//! each resolved by `PoolState::phys_to_virt`. The user-mapping functions draw them
//! from `crate::mm::kernel_pt_pool` ([`map_user_page`]) or the address space's
//! growth pool ([`map_user_page_pooled`]).
//!
//! # Index layout
//! The mode negotiated at boot ([`PagingMode`]: Sv39, Sv48, or Sv57) fixes
//! the level count (3, 4, or 5). Every level indexes 512 entries with 9 VA
//! bits above the 12-bit page offset; level 0 is the 4 KiB leaf tier and the
//! root sits at `levels - 1`. Walkers load the mode once per entry point and
//! loop from the root down ([`boot_protocol::riscv_paging::vpn_index`] is the
//! per-level index).
//!
//! # PTE layout (identical in every mode)
//! Bits \[53:10\]: PPN (physical page number, 44 bits).
//! Bit 0: V (Valid). Bit 1: R (Read). Bit 2: W (Write). Bit 3: X (Execute).
//! Bits \[9:8\]: RSW, ignored by hardware: a user leaf's grant
//! (`encoding::PTE_GRANT_WRITE`, `encoding::PTE_GRANT_EXECUTE`), a table
//! pointer's [`POOLED_TABLE`] mark.
//! Bits \[62:61\]: PBMT (Svpbmt page-based memory type; 00=PMA, 01=NC,
//! 10=IO). Bit 63: N (Svnapot naturally-aligned power-of-two contiguity).
//! Non-leaf: V=1, R=0, W=0, X=0. Leaf: V=1, at least one of R/W/X set.
//! A megapage (2 MiB) is a leaf installed at level 1 in every mode.
//!
//! Svpbmt, Svinval, and Svnapot are asserted by [`verify_paging_extensions`]
//! at boot (required per
//! [platform-requirements.md](../../../../../docs/platform-requirements.md));
//! the code paths below use them unconditionally.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub use boot_protocol::riscv_paging::PagingMode;
use boot_protocol::riscv_paging::{next_level_boundary, vpn_index};

use crate::mm::paging::{LeafGrant, PageFlags, PagingError, PoolState, UserAccess};

// ── Active paging mode ────────────────────────────────────────────────────────

/// The paging mode this hart booted under, as a raw `satp.MODE` value.
///
/// Written once by [`init_paging_mode`] at kernel entry, before any consumer
/// runs and before APs start (SBI `hart_start` plus the trampoline param
/// block provide the happens-before for secondary harts); read lock-free
/// everywhere after. The Sv48 default keeps host unit tests on today's
/// behaviour without an init call.
static PAGING_MODE: AtomicU8 = AtomicU8::new(PagingMode::Sv48 as u8);

/// Virtual base of the direct physical map, published once by
/// [`init_paging_mode`] from the bootloader's (possibly KASLR-randomized)
/// `BootInfo.direct_map_base` so the hot `phys_to_virt` path is a single
/// relaxed load plus add. The default is the Sv48 kernel-half base, keeping
/// host unit tests deterministic without an init call.
static DIRECT_MAP_BASE_VAL: AtomicU64 = AtomicU64::new(0xFFFF_8000_0000_0000);

/// The active mode's exclusive user-half top, resolved at [`init_paging_mode`].
static USER_VA_TOP_VAL: AtomicU64 = AtomicU64::new(0x0000_8000_0000_0000);

/// Publish the active paging mode and the direct-map base at kernel entry.
///
/// The bootloader hands the kernel a running translation regime; `satp.MODE`
/// is therefore the authoritative record of the negotiated mode. The
/// direct-map base comes from `BootInfo`: the mode's kernel-half base, or a
/// randomized base above it (KASLR). Halts the hart on an unrecognizable
/// MODE, a base below the mode's kernel half, or a misaligned base — this
/// runs pre-console, matching the silent-halt policy of `BootInfo`
/// validation.
#[cfg(not(test))]
pub fn init_paging_mode(info: &boot_protocol::BootInfo)
{
    let satp: u64;
    // SAFETY: reads the satp CSR only; always valid in S-mode.
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) satp, options(nomem, nostack, preserves_flags));
    }
    let Some(mode) = PagingMode::from_satp_mode(satp >> 60)
    else
    {
        super::cpu::halt_loop();
    };
    let base = info.direct_map_base;
    if base < mode.kernel_va_base() || !base.is_multiple_of(1 << 30)
    {
        super::cpu::halt_loop();
    }
    PAGING_MODE.store(mode as u8, Ordering::Relaxed);
    DIRECT_MAP_BASE_VAL.store(base, Ordering::Relaxed);
    USER_VA_TOP_VAL.store(mode.user_va_top(), Ordering::Relaxed);
}

/// Test-build stub: host unit tests run with the [`PAGING_MODE`] default.
#[cfg(test)]
pub fn init_paging_mode(_info: &boot_protocol::BootInfo) {}

/// The active paging mode published at kernel entry.
#[expect(
    clippy::unreachable,
    reason = "the decode of PAGING_MODE cannot fail: its initialiser and its one store, in \
              init_paging_mode, write only PagingMode discriminants"
)]
pub fn paging_mode() -> PagingMode
{
    match PagingMode::from_satp_mode(u64::from(PAGING_MODE.load(Ordering::Relaxed)))
    {
        Some(mode) => mode,
        None => unreachable!(),
    }
}

/// Construct a `satp` value for `root_pa` under the active mode, ASID 0.
pub(super) fn make_kernel_satp(root_pa: u64) -> u64
{
    paging_mode().make_satp(root_pa, 0)
}

/// Base virtual address of the direct physical map: at or above the active
/// mode's kernel-half base, as published from `BootInfo` (KASLR).
#[inline]
pub fn direct_map_base() -> u64
{
    DIRECT_MAP_BASE_VAL.load(Ordering::Relaxed)
}

/// Exclusive upper bound of user-half virtual addresses under the active mode.
#[inline]
pub fn user_va_top() -> u64
{
    USER_VA_TOP_VAL.load(Ordering::Relaxed)
}

// ── PTE bit constants ─────────────────────────────────────────────────────────

/// Entry is valid.
const VALID: u64 = super::encoding::PTE_VALID;
/// Read permission.
const READ: u64 = super::encoding::PTE_READ;
/// Write permission.
const WRITE: u64 = super::encoding::PTE_WRITE;
/// Execute permission.
const EXECUTE: u64 = super::encoding::PTE_EXECUTE;
/// Accessed — pre-set in every leaf PTE the kernel builds.
///
/// Per RISC-V Privileged Spec §5.4.1, an implementation either updates the A
/// bit in hardware (Svadu, with `menvcfg.ADUE` set) or raises a page fault
/// when an access observes A=0 (Svade, the baseline the kernel requires).
/// Pre-setting it spares a new leaf that fault; a user leaf loses it only to
/// `SYS_ASPACE_HARVEST` ([`clear_user_accessed`]), and the fault path sets it
/// again ([`user_fault_is_spurious`]).
const ACCESSED: u64 = 1 << 6;
/// Dirty — pre-set in writable leaf PTEs (as ACCESSED; the fault path sets it
/// on a store to a writable leaf that lacks it).
const DIRTY: u64 = 1 << 7;
/// PPN field mask: bits \[53:10\], representing `(phys >> 12) << 10`.
const PPN_MASK: u64 = 0x003F_FFFF_FFFF_FC00;
/// A leaf at any level sets at least one of R/W/X; a table pointer has none.
const LEAF_BITS: u64 = READ | WRITE | EXECUTE;
/// Software bit (RSW, reserved for supervisor software and ignored by
/// hardware) set in a table-pointer entry whose table frame came from the
/// address space's own page-table pool (`rv_walk_or_alloc_pooled`). A
/// reclaiming unmap frees an empty table to that pool only when its parent
/// entry carries this bit; tables from `kernel_pt_pool` (the kernel-direct
/// `map_page` path) do not. On a leaf, the same bit is the grant's write
/// (`encoding::PTE_GRANT_WRITE`); every reader of this one first checks that
/// the entry is a table pointer (no R, W or X).
const POOLED_TABLE: u64 = 1 << 8;
/// Svpbmt PBMT field, bits \[62:61\]: 00=PMA (defer to platform memory
/// attributes), 01=NC (non-cacheable idempotent main memory), 10=IO.
const PBMT_MASK: u64 = super::encoding::PTE_PBMT_MASK;
/// U bit (bit 4): the page is reachable from U-mode.
const USER: u64 = super::encoding::PTE_USER;
/// PBMT=IO: non-cacheable, non-idempotent, strongly-ordered (channel 0) —
/// the device-MMIO memory type, the analogue of x86-64 PCD|PWT (strong UC).
/// NC (01) is deliberately unused: `PageFlags` carries a single
/// `uncacheable` bool today, and device correctness under the
/// `shared/mmio` I/O fences requires the IO type.
const PBMT_IO: u64 = 0b10 << 61;

// ── PageTableEntry ────────────────────────────────────────────────────────────

/// A 64-bit RISC-V page table entry (PTE).
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

#[expect(
    clippy::verbose_bit_mask,
    reason = "`phys & 0xFFF == 0` is idiomatic for alignment assertions; the `trailing_zeros()` \
              alternative is less readable here"
)]
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
    /// `flags.uncacheable` selects the Svpbmt IO memory type (see
    /// [`PBMT_IO`]); a clear flag leaves PBMT=PMA, deferring to the
    /// platform's physical memory attributes.
    pub fn new_page(phys: u64, flags: PageFlags) -> Self
    {
        debug_assert!(phys & 0xFFF == 0, "page PA not 4 KiB-aligned");
        // Pre-set A (and D for writable leaves): see `ACCESSED` for the
        // Priv-Spec §5.4.1 Svade / Svadu rationale.
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
        if flags.uncacheable
        {
            bits |= PBMT_IO;
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

// ── NAPOT contiguity (Svnapot) ────────────────────────────────────────────────
// 64 KiB Svnapot groups: 16 index-aligned 4 KiB leaves carrying N=1 and
// ppn[3:0]=0b1000. Eligibility, the no-flush and demote-before-divergence
// invariants, and the reader rules are in core/kernel/docs/memory-internals.md
// § NAPOT Contiguity (RISC-V). A 16-slot group is index-aligned, so it never
// crosses an L0 table.

/// Svnapot N bit: this leaf is one member of a NAPOT group.
const NAPOT: u64 = 1 << 63;
/// Pages per 64 KiB NAPOT group (the only size RVA23 mandates).
const NAPOT_64K_PAGES: usize = 16;
/// The 64 KiB size encoding, `ppn[3:0] = 0b1000`, in PTE bit position.
const NAPOT_64K_PPN: u64 = 0b1000 << 10;

/// Physical address this leaf maps for `virt`, NAPOT-aware: a NAPOT member
/// repurposes `ppn[3:0]` as the size encoding, so PA bits \[15:12\] come
/// from the VA instead.
fn leaf_phys(pte: PageTableEntry, virt: u64) -> u64
{
    if pte.0 & NAPOT != 0
    {
        (pte.phys_addr() & !0xF000) | (virt & 0xF000)
    }
    else
    {
        pte.phys_addr()
    }
}

/// Rewrite the aligned 16-slot group containing `virt` as one 64 KiB NAPOT
/// translation iff every slot is a valid PBMT=IO leaf with identical
/// non-PPN bits and PPNs contiguous from a 64 KiB-aligned base. Otherwise
/// leaves the table untouched.
///
/// Needs no TLB flush, per [memory-internals.md](../../../docs/memory-internals.md)
/// § NAPOT Contiguity (RISC-V).
fn try_promote_napot_64k(l0: &mut [PageTableEntry; 512], virt: u64)
{
    let Some(group) = napot_group(l0, virt)
    else
    {
        return;
    };
    let [base, ..] = *group;
    // Eligible only for valid, uncacheable (PBMT=IO) leaves not already
    // promoted, on a 64 KiB-aligned physical base.
    if base.0 & VALID == 0
        || base.0 & LEAF_BITS == 0
        || base.0 & PBMT_MASK != PBMT_IO
        || base.0 & NAPOT != 0
    {
        return;
    }
    let base_pa = base.phys_addr();
    if base_pa & 0xFFFF != 0
    {
        return;
    }
    let attrs = base.0 & !PPN_MASK;
    let contiguous = group
        .iter()
        .zip((base_pa..).step_by(4096))
        .all(|(e, pa)| e.0 & !PPN_MASK == attrs && e.phys_addr() == pa);
    if !contiguous
    {
        return;
    }
    group.fill(PageTableEntry(
        attrs | NAPOT | ((base_pa >> 2) & PPN_MASK) | NAPOT_64K_PPN,
    ));
}

/// Restore the 16 per-page PTEs of the NAPOT group containing `virt`
/// (clear N, rewrite each slot's true `ppn[3:0]`). No-op when the slot is
/// not a NAPOT member.
///
/// Demotion needs no flush of its own, and every writer must demote before a
/// slot of the group diverges; both invariants are in
/// [memory-internals.md](../../../docs/memory-internals.md) § NAPOT Contiguity (RISC-V).
fn demote_napot_64k(l0: &mut [PageTableEntry; 512], virt: u64)
{
    let Some(group) = napot_group(l0, virt)
    else
    {
        return;
    };
    let [member, ..] = *group;
    if member.0 & NAPOT == 0
    {
        return;
    }
    let attrs = member.0 & !PPN_MASK & !NAPOT;
    let base_pa = member.phys_addr() & !0xF000;
    for (e, pa) in group.iter_mut().zip((base_pa..).step_by(4096))
    {
        *e = PageTableEntry(attrs | ((pa >> 2) & PPN_MASK));
    }
}

/// The aligned 16-slot NAPOT group of `l0` that holds `virt`'s leaf. A table is
/// 32 whole groups and a leaf index is below 512, so the `None` arm is never
/// taken.
fn napot_group(
    l0: &mut [PageTableEntry; 512],
    virt: u64,
) -> Option<&mut [PageTableEntry; NAPOT_64K_PAGES]>
{
    let (groups, _) = l0.as_chunks_mut::<NAPOT_64K_PAGES>();
    groups.get_mut(vpn_index(0, virt) / NAPOT_64K_PAGES)
}

/// Whether `virt`'s leaf in `l0` is a member of a NAPOT group.
fn is_napot(l0: &[PageTableEntry; 512], virt: u64) -> bool
{
    entry(l0, 0, virt).is_some_and(|e| e.0 & NAPOT != 0)
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

/// The entry of `table` that `va` selects at `level`. `vpn_index` keeps nine
/// VA bits, so every index it returns names one of the 512 entries and the
/// `None` arm, which each caller sends down its own error or early return, is
/// never taken.
fn entry_mut(
    table: &mut [PageTableEntry; 512],
    level: usize,
    va: u64,
) -> Option<&mut PageTableEntry>
{
    table.get_mut(vpn_index(level, va))
}

/// The value of the entry of `table` that `va` selects at `level`
/// ([`entry_mut`]).
fn entry(table: &[PageTableEntry; 512], level: usize, va: u64) -> Option<PageTableEntry>
{
    table.get(vpn_index(level, va)).copied()
}

/// Read entry `index` of the 512-entry table at `table_va` without forming a
/// reference to the table.
///
/// # Safety
/// `table_va` must address a readable, 8-byte-aligned 512-entry table and
/// `index` must be below 512.
unsafe fn read_entry(table_va: u64, index: usize) -> PageTableEntry
{
    debug_assert!(index < 512);
    // SAFETY: index is below 512, so the entry lies inside the table (caller contract).
    let entry = unsafe { (table_va as *const PageTableEntry).add(index) };
    // SAFETY: per the caller contract the table is readable and aligned.
    unsafe { entry.read() }
}

// ── Level descent ─────────────────────────────────────────────────────────────

/// Level of the root table under the active mode: 4 (Sv57), 3 (Sv48) or 2 (Sv39).
fn root_level() -> usize
{
    // A mode has three to five levels, so the subtraction never saturates.
    paging_mode().levels().saturating_sub(1)
}

/// The levels of `(stop, top]`, from `top` down: the tables a descent from a
/// table at level `top` to the table at level `stop` reads an entry of.
fn levels_above(stop: usize, top: usize) -> impl Iterator<Item = usize>
{
    (stop..=top).rev().take_while(move |&level| level > stop)
}

/// Descend from the table at `root_va` to the table at level `stop`,
/// resolving-or-allocating a child at each level in `(stop, top]` via
/// `ensure`. `ensure` returns the child table's *virtual* address, so each
/// caller supplies its own PA→VA translation alongside its allocator.
///
/// # Errors
/// The first error `ensure` returns, and [`PagingError::OutOfFrames`] for an
/// entry [`entry_mut`] does not find.
///
/// # Safety
/// `root_va` must be the VA of a valid, exclusively-owned table frame at
/// level `top`, and `ensure` must return the VA of a valid, exclusively-owned
/// table frame for every entry it is handed.
unsafe fn descend_alloc(
    root_va: u64,
    virt: u64,
    top: usize,
    stop: usize,
    mut ensure: impl FnMut(&mut PageTableEntry) -> Result<u64, PagingError>,
) -> Result<&'static mut [PageTableEntry; 512], PagingError>
{
    // SAFETY: root_va is a valid exclusively-owned table frame (caller contract).
    let mut table = unsafe { table_at(root_va) };
    for level in levels_above(stop, top)
    {
        let child_va = ensure(entry_mut(table, level, virt).ok_or(PagingError::OutOfFrames)?)?;
        // SAFETY: ensure returned the VA of a valid exclusively-owned table frame.
        table = unsafe { table_at(child_va) };
    }
    Ok(table)
}

/// Walk existing tables from `root_va` down to level `stop`, translating
/// child physical addresses through `to_virt`. Returns `None` when any entry
/// on the path is absent or is a large leaf (R/W/X set above `stop`) — a
/// leaf's PPN points at data, not a child table, and must not be descended.
///
/// # Safety
/// `root_va` must be the VA of a valid table frame at level `top` whose
/// reachable child frames are all live; `to_virt` must map their physical
/// addresses to valid VAs.
#[cfg(not(test))]
unsafe fn descend_existing(
    root_va: u64,
    virt: u64,
    top: usize,
    stop: usize,
    to_virt: impl Fn(u64) -> u64,
) -> Option<&'static mut [PageTableEntry; 512]>
{
    // SAFETY: root_va is a valid table frame (caller contract).
    let mut table = unsafe { table_at(root_va) };
    for level in levels_above(stop, top)
    {
        let e = entry(table, level, virt)?;
        if !e.is_present() || e.0 & LEAF_BITS != 0
        {
            return None;
        }
        // SAFETY: present non-leaf entry points at a live child table frame.
        table = unsafe { table_at(to_virt(e.phys_addr())) };
    }
    Some(table)
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
    // SAFETY: root_va is the VA of a valid root frame allocated from pool;
    // walk_or_alloc yields pool frames whose VAs pool.phys_to_virt resolves.
    let l0 = unsafe {
        descend_alloc(root_va, virt, root_level(), 0, |e| {
            walk_or_alloc(e, pool).map(|pa| pool.phys_to_virt(pa))
        })?
    };
    *entry_mut(l0, 0, virt).ok_or(PagingError::OutOfFrames)? =
        PageTableEntry::new_page(phys, flags);
    Ok(())
}

/// Map VA `virt` → PA `phys` as a 2 MiB megapage with `flags`.
///
/// Installs a leaf entry at level 1; no leaf-level table is allocated.
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
    // SAFETY: root_va is the VA of a valid root frame allocated from pool;
    // walk_or_alloc yields pool frames whose VAs pool.phys_to_virt resolves.
    let l1 = unsafe {
        descend_alloc(root_va, virt, root_level(), 1, |e| {
            walk_or_alloc(e, pool).map(|pa| pool.phys_to_virt(pa))
        })?
    };
    *entry_mut(l1, 1, virt).ok_or(PagingError::OutOfFrames)? =
        PageTableEntry::new_large_page(phys, flags);
    Ok(())
}

/// Return the child table physical address from `entry`, allocating and
/// zeroing a new pool frame when the entry is not present.
#[expect(
    clippy::similar_names,
    reason = "frame_va and frame_pa are a VA/PA pair — the similarity is intentional"
)]
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

/// Write `satp` to point at `root_phys` without executing `sfence.vma`.
///
/// Used when transitioning to idle where stale user TLB entries are harmless
/// (kernel code only touches kernel-mapped addresses). The caller is
/// responsible for ensuring the next user-mode transition goes through
/// `AddressSpace::activate`, which either flushes ([`activate`], untagged) or
/// loads the space under its own ASID ([`activate_tagged`], with the generation
/// check), so a stale user entry is never used.
///
/// # Safety
/// `root_phys` must be a valid page table root with correct kernel mappings.
#[cfg(not(test))]
pub unsafe fn write_satp_no_fence(root_phys: u64)
{
    let satp = make_kernel_satp(root_phys);
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
    let satp = make_kernel_satp(root_phys);
    // SAFETY: satp write switches the active page table; root_phys is a valid root frame;
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

/// Activate the tables rooted at `root_phys` under ASID `tag` **without**
/// issuing `sfence.vma`.
///
/// Encodes `tag` into `satp[59:44]` and the root PPN into `satp[43:0]`; cached
/// translations for `tag` and every other ASID survive (the context-switch fast
/// path). The caller is responsible for any ASID invalidation required for
/// correctness (the generation check in `AddressSpace::activate`).
///
/// # Safety
/// Must execute in S-mode on a hart with a non-zero implemented ASID width.
/// `root_phys` must be a valid root mapping the currently executing code,
/// the active stack, and the direct map.
#[cfg(not(test))]
pub unsafe fn activate_tagged(root_phys: u64, tag: u16)
{
    let satp = paging_mode().make_satp(root_phys, tag);
    // SAFETY: satp write switches the active root and ASID; the deliberate
    // absence of sfence.vma retains cached translations; caller guarantees the
    // tables map current code, stack, and the direct map.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            in(reg) satp,
            options(nostack),
        );
    }
}

/// Per-CPU enable of ASID-tagged TLBs: report the number of hardware tags
/// (ASIDs) this hart implements.
///
/// Called on the BSP and every AP. RISC-V needs no per-hart enable bit — the
/// ASID is written directly into `satp` — so this only probes the implemented
/// width. The BSP uses the returned count to seed the tag pool.
///
/// ASID-tagged TLBs are required by the platform baseline
/// ([platform-requirements.md](../../../../../docs/platform-requirements.md)); a
/// hart with a zero-width `satp` ASID field is refused here. The check lives
/// here, not in `cpu::verify_baseline`, because `satp` cannot be safely probed
/// before the kernel page tables are active.
///
/// # Safety
/// Must execute in S-mode with `satp` holding a valid root (Phase 5 onward).
#[cfg(not(test))]
pub unsafe fn enable_tagged_tlb() -> usize
{
    // SAFETY: caller's contract (S-mode, valid satp).
    let bits = unsafe { super::cpu::probe_asid_bits() };
    if bits == 0
    {
        crate::fatal("RISC-V ASID-tagged TLB unsupported — required by the platform baseline");
    }
    1usize << bits
}

/// No-op on RISC-V: the XN/NX mechanism is always available via PTE X bit.
///
/// # Safety
/// No preconditions: the body is empty; the `unsafe` qualifier matches the
/// x86-64 surface.
#[cfg(not(test))]
pub unsafe fn enable_nx() {}

/// Refuse to boot unless the bootloader confirmed the RVA23-required
/// supervisor paging extensions — Svpbmt, Svinval, Svnapot — on every
/// enabled hart.
///
/// Called once on the BSP. The capability bits are the conservative
/// per-bit `AND` across all enabled harts, computed by the bootloader's
/// firmware-table parse, so a BSP-only check covers the machine. After
/// this gate the paging code uses the three extensions unconditionally,
/// per the subsystem-gate policy in
/// [platform-requirements.md](../../../../../docs/platform-requirements.md).
///
/// Must be called after `platform::capture_kernel_mmio()` and before the
/// first userspace mapping or TLB shootdown.
///
/// # Safety
/// Must execute in supervisor mode from a single-threaded boot context.
#[cfg(not(test))]
pub unsafe fn verify_paging_extensions()
{
    let km = crate::platform::kernel_mmio();
    let required = [
        (boot_protocol::HART_CAP_SVPBMT, "Svpbmt"),
        (boot_protocol::HART_CAP_SVINVAL, "Svinval"),
        (boot_protocol::HART_CAP_SVNAPOT, "Svnapot"),
    ];
    for (bit, name) in required
    {
        if km.hart_caps & bit == 0
        {
            crate::kprintln!("paging: {name} not advertised for every hart");
            crate::fatal(
                "RVA23 supervisor paging extensions (Svpbmt, Svinval, Svnapot) \
                 not advertised for every hart — required; there is no fallback \
                 path. Check firmware tables (ACPI RHCT / DTB) or the QEMU -cpu \
                 selection (svpbmt=on,svinval=on,svnapot=on).",
            );
        }
    }
}

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
/// Adds `direct_map_base` to `sp`, switching from VA == PA to
/// VA == `direct_map_base` + PA. Both mappings cover the same physical
/// frames; this eliminates the 64 KiB identity-map limit.
///
/// # Safety
/// Must be called exactly once, immediately after `activate`, while the
/// boot stack identity mapping is still valid. `direct_map_base` must be
/// the base of a direct physical map that covers all of physical RAM.
///
/// # Codegen invariant — `#[inline(never)]` plus no `options(nostack)`
/// This `asm!` block rewrites `sp` to its direct-map alias. Rust inline asm
/// cannot list `sp` as an output (it is a reserved register), so LLVM cannot
/// learn that this asm modifies `sp`, and may hoist sp-relative address
/// materialisation (`add reg, sp, imm`) in the caller to before the rebase,
/// producing a stale low-VA pointer. `#[inline(never)]` keeps the rebase an
/// opaque call; the caller additionally runs every post-rebase phase through
/// the `#[inline(never)]` `kernel_entry_post_rebase` boundary, which keeps
/// sp-derived values on the correct side of the rebase (see the comment at the
/// call in `kernel_entry`). Omitting `options(nostack)` keeps the asm's
/// declared contract truthful: the body modifies `sp`.
#[cfg(not(test))]
#[inline(never)]
pub unsafe fn rebase_boot_stack(direct_map_base: u64)
{
    // SAFETY: adding the direct-map offset to sp switches to the same
    // physical memory through the direct map virtual range. Both the
    // identity mapping (old) and direct map (new) are valid at this point.
    unsafe {
        core::arch::asm!(
            "add sp, sp, {base}",
            base = in(reg) direct_map_base,
        );
    }
}

/// No-op test stub.
///
/// # Safety
/// No preconditions: the body is empty; the signature matches the S-mode
/// implementation.
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
    // PPN is satp[43:0] (44 bits); physical address = PPN << 12. The mask must
    // exclude the ASID field (satp[59:44]) — a non-zero ASID under tagged TLBs
    // would otherwise leak into the returned address.
    (satp & 0x0000_0FFF_FFFF_FFFF) << 12
}

/// Map a single 4 KiB user page `virt` → `phys` in the page table rooted at
/// `root_virt`, allocating missing intermediate frames from the kernel PT
/// pool.
///
/// Sets U (user) bit so userspace can access the mapping, and records `grant`
/// in the leaf's RSW bits.
///
/// # Errors
/// Returns `Err(())` if the pool is exhausted.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB user
/// root frame. `virt` must be in the lower (user) half. `phys` must be 4 KiB-aligned.
#[cfg(not(test))]
pub unsafe fn map_user_page(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
    grant: LeafGrant,
) -> Result<crate::mm::paging::MapOutcome, ()>
{
    use crate::mm::paging::phys_to_virt;

    let top = root_level();
    // The user_va_top gate in the syscall layer keeps user VAs out of the
    // kernel half; a root index >= 256 here would clobber shared kernel-half
    // entries.
    debug_assert!(vpn_index(top, virt) < 256);
    // SAFETY: root_virt is the direct-map VA of a valid user root PT (caller
    // contract); rv_walk_or_alloc yields live PT frames resolvable via
    // phys_to_virt.
    let l0 = unsafe {
        descend_alloc(root_virt, virt, top, 0, |e| {
            rv_walk_or_alloc(e).map(phys_to_virt)
        })
    }
    .map_err(drop)?;
    install_user_leaf(l0, virt, phys, flags, grant).ok_or(())
}

/// Shared leaf-install tail of [`map_user_page`] / [`map_user_page_pooled`]:
/// demote any NAPOT group the slot belongs to (so the prior PTE read for
/// classification is always a plain per-page leaf), install the new leaf
/// with the U bit and the RSW bits of `grant`, classify the rewrite, and opportunistically promote the
/// containing group when the new mapping is uncacheable. `None`, installing
/// nothing, when [`entry_mut`] finds no slot.
#[cfg(not(test))]
fn install_user_leaf(
    l0: &mut [PageTableEntry; 512],
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
    grant: LeafGrant,
) -> Option<crate::mm::paging::MapOutcome>
{
    if is_napot(l0, virt)
    {
        demote_napot_64k(l0, virt);
    }
    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER | super::encoding::grant_bits(grant);
    let slot = entry_mut(l0, 0, virt)?;
    let prior = slot.0;
    *slot = pte;
    let outcome = classify_user_map(prior, pte.0);
    if flags.uncacheable
    {
        try_promote_napot_64k(l0, virt);
    }
    Some(outcome)
}

/// Walk an existing page table entry or allocate a new child frame
/// from the kernel PT pool (`crate::mm::kernel_pt_pool`).
#[cfg(not(test))]
fn rv_walk_or_alloc(entry: &mut PageTableEntry) -> Result<u64, PagingError>
{
    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    // Pool returns zero-filled pages; no further write_bytes needed.
    let frame_pa = crate::mm::kernel_pt_pool::alloc_pt_page().ok_or(PagingError::OutOfFrames)?;

    *entry = PageTableEntry::new_table(frame_pa);
    Ok(frame_pa)
}

/// Map a single 4 KiB user page, drawing intermediate page-table frames from
/// an `AddressSpaceObject`'s growth pool instead of the kernel page-table
/// pool. The leaf records `grant` in its RSW bits.
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
    grant: LeafGrant,
    aso: &crate::cap::object::AddressSpaceObject,
) -> Result<crate::mm::paging::MapOutcome, ()>
{
    use crate::mm::paging::phys_to_virt;

    let top = root_level();
    // Same kernel-half guard as map_user_page.
    debug_assert!(vpn_index(top, virt) < 256);
    // SAFETY: root_virt is the direct-map VA of a valid user root PT (caller
    // contract); rv_walk_or_alloc_pooled yields live PT frames resolvable via
    // phys_to_virt.
    let l0 = unsafe {
        descend_alloc(root_virt, virt, top, 0, |e| {
            rv_walk_or_alloc_pooled(e, aso).map(phys_to_virt)
        })
    }
    .map_err(drop)?;

    install_user_leaf(l0, virt, phys, flags, grant).ok_or(())
}

/// Pooled equivalent of [`rv_walk_or_alloc`]: pulls a freshly-zeroed PT
/// frame from the AS's growth pool when an entry is absent.
#[cfg(not(test))]
fn rv_walk_or_alloc_pooled(
    entry: &mut PageTableEntry,
    aso: &crate::cap::object::AddressSpaceObject,
) -> Result<u64, PagingError>
{
    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    let frame_pa = aso.alloc_pt_page().ok_or(PagingError::OutOfFrames)?;
    let mut table_pte = PageTableEntry::new_table(frame_pa);
    table_pte.0 |= POOLED_TABLE;
    *entry = table_pte;
    Ok(frame_pa)
}

/// Whether a per-VA invalidation ([`flush_page`], [`inval_page`]) also drops the
/// cached non-leaf entries that name a freed intermediate table. False on
/// RISC-V: an `sfence.vma`/`sinval.vma` with `rs1 != x0` is only required to
/// invalidate leaf entries for that address, so freeing a table frame needs an
/// `rs1 = x0` fence.
pub const VA_INVAL_DROPS_TABLE_CACHES: bool = false;

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

// ── Tagged (ASID) invalidation ────────────────────────────────────────────────
// `sfence.vma` with a non-zero ASID operand invalidates only that ASID's
// translations, independent of the ASID currently loaded in `satp`. Used by the
// tagged-TLB path for per-VA remote shootdown and whole-tag flush.

/// Invalidate the TLB entry for `virt` tagged with ASID `tag` on the current
/// hart (`sfence.vma virt, asid`), regardless of the ASID in `satp`.
///
/// # Safety
/// Must execute in S-mode. `virt` need not be mapped.
#[cfg(not(test))]
pub unsafe fn flush_page_tagged(virt: u64, tag: u16)
{
    // SAFETY: sfence.vma with a VA and a non-zero ASID invalidates that leaf
    // within that ASID; S-mode primitive, safe for any VA.
    unsafe {
        core::arch::asm!(
            "sfence.vma {va}, {asid}",
            va = in(reg) virt,
            asid = in(reg) u64::from(tag),
            options(nostack),
        );
    }
}

/// Invalidate all entries tagged with ASID `tag` on the current hart
/// (`sfence.vma zero, asid`). Used when an ASID is (re)assigned to a new address
/// space or when a switched-away space accrued unmaps while this hart was
/// elsewhere.
///
/// # Safety
/// Must execute in S-mode.
#[cfg(not(test))]
pub unsafe fn flush_tag(tag: u16)
{
    // SAFETY: sfence.vma with x0 VA and a non-zero ASID invalidates all leaves
    // within that ASID; S-mode primitive.
    unsafe {
        core::arch::asm!(
            "sfence.vma zero, {asid}",
            asid = in(reg) u64::from(tag),
            options(nostack),
        );
    }
}

// ── Batched invalidation (Svinval) ────────────────────────────────────────────
// The Svinval sequence `sfence.w.inval; sinval.vma …; sfence.inval.ir` is
// architecturally equivalent to issuing `sfence.vma` for each address at the
// bracket's position, but lets many per-VA invalidations share the two fence
// ends. The single-VA primitives above deliberately stay `sfence.vma` — for
// one address a bracket is three instructions instead of one. Svinval is
// asserted at boot by `verify_paging_extensions`.

/// Open a batched-invalidation window: order this hart's prior stores
/// (the PTE rewrites) before the `sinval.vma` invalidations that follow.
///
/// # Safety
/// Must execute in S-mode. Every `inval_page` / `inval_page_tagged` issued
/// after this call must be followed by [`inval_batch_end`] before the
/// invalidation is relied upon.
#[cfg(not(test))]
pub unsafe fn inval_batch_begin()
{
    // SAFETY: sfence.w.inval is an S-mode Svinval fence; no registers
    // clobbered, no memory operands.
    unsafe {
        core::arch::asm!("sfence.w.inval", options(nostack, preserves_flags));
    }
}

/// Invalidate `virt` across all ASIDs inside an open batch window
/// (`sinval.vma virt, zero`).
///
/// # Safety
/// Must execute in S-mode, between [`inval_batch_begin`] and
/// [`inval_batch_end`]. `virt` need not be mapped.
#[cfg(not(test))]
pub unsafe fn inval_page(virt: u64)
{
    // SAFETY: sinval.vma mirrors sfence.vma operand semantics (VA in rs1,
    // x0 rs2 = all ASIDs) but only queues the invalidation; the caller's
    // bracket fences complete it. Safe for any VA in S-mode.
    unsafe {
        core::arch::asm!(
            "sinval.vma {va}, zero",
            va = in(reg) virt,
            options(nostack),
        );
    }
}

/// Invalidate `virt` within ASID `tag` inside an open batch window
/// (`sinval.vma virt, asid`).
///
/// # Safety
/// Must execute in S-mode, between [`inval_batch_begin`] and
/// [`inval_batch_end`]. A non-zero `tag` requires tagging enabled.
#[cfg(not(test))]
pub unsafe fn inval_page_tagged(virt: u64, tag: u16)
{
    // SAFETY: sinval.vma with VA and non-zero ASID queues invalidation of
    // that leaf within that ASID; bracketed by the caller's fences.
    unsafe {
        core::arch::asm!(
            "sinval.vma {va}, {asid}",
            va = in(reg) virt,
            asid = in(reg) u64::from(tag),
            options(nostack),
        );
    }
}

/// Close a batched-invalidation window: order the queued `sinval.vma`
/// invalidations before this hart's subsequent implicit references. The
/// batch's invalidations are architecturally complete when this returns.
///
/// # Safety
/// Must execute in S-mode, paired with a preceding [`inval_batch_begin`].
#[cfg(not(test))]
pub unsafe fn inval_batch_end()
{
    // SAFETY: sfence.inval.ir is an S-mode Svinval fence; no registers
    // clobbered, no memory operands.
    unsafe {
        core::arch::asm!("sfence.inval.ir", options(nostack, preserves_flags));
    }
}

/// Remove a single user-space mapping at `virt` from the page table rooted
/// at `root_virt`.
///
/// Walks from the root to the leaf level. If any intermediate level is not
/// present (or is a mega/gigapage leaf, which the user path never installs),
/// returns immediately (nothing to unmap). On reaching the leaf, zeros the
/// PTE and calls `flush_page`.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB user
/// root frame. Does not allocate.
#[cfg(not(test))]
pub unsafe fn unmap_user_page(root_virt: u64, virt: u64)
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: root_virt is direct-map VA of a valid user root PT (caller
    // contract); its reachable child frames are live PT-pool frames.
    let Some(l0) = (unsafe { descend_existing(root_virt, virt, root_level(), 0, phys_to_virt) })
    else
    {
        return;
    };
    // Demote-first (core/kernel/docs/memory-internals.md § NAPOT Contiguity (RISC-V)).
    if is_napot(l0, virt)
    {
        demote_napot_64k(l0, virt);
    }
    if let Some(slot) = entry_mut(l0, 0, virt)
    {
        *slot = PageTableEntry(0);
    }

    // SAFETY: virt may now be unmapped; flush_page is safe for any VA (and
    // kills any cached 64 KiB entry covering it).
    unsafe { flush_page(virt) };
}

/// `true` if no entry in `table` is present (all 512 slots clear).
#[cfg(not(test))]
fn table_is_empty(table: &[PageTableEntry; 512]) -> bool
{
    table.iter().all(|e| !e.is_present())
}

/// Unmap every 4 KiB leaf in `[virt_base, virt_base + page_count*4 KiB)` and
/// reclaim each intermediate table the cleared span leaves empty back to
/// `aso`'s page-table growth pool. Returns the number of non-root table frames freed.
/// Passes the frame of each present leaf it clears to `on_leaf`, in VA order,
/// after the clear.
///
/// Walks from the root to the leaf level over the span, clearing in-range
/// leaf PTEs. A table is freed only when it is fully empty afterwards **and**
/// its parent entry carries [`POOLED_TABLE`] (the frame came from `aso`'s
/// pool) — emptiness, not span-containment, is the gate, so a boundary table
/// shared with a live neighbour (or the guard-page table whose first slot
/// sits just outside the span) is reclaimed exactly when its last live entry
/// clears.
/// Leaf entries at a non-leaf level (mega/gigapages: R/W/X set) are not
/// produced by the user mapping path; they are skipped (never descended, never
/// freed), so a table holding one is never seen as empty. The root frame is
/// never freed.
///
/// Issues no TLB flush: the caller (`AddressSpace::unmap_region_pooled`)
/// performs one invalidation for the whole span, plus one span invalidation
/// each time the cleared frames overflow the frame-map release batch (its
/// leaf callback's drain), and holds `pt_lock` across them, so a freed frame
/// cannot be popped and reused before the closing invalidation completes.
/// When this returns a non-zero count, that closing invalidation must be a
/// full `rs1 = x0` fence on every hart (`flush_tlb_all` locally, the
/// full-flush shootdown remotely): a per-VA `sfence.vma` or `sinval.vma`
/// invalidates only leaf translations for that VA, so cached non-leaf entries
/// pointing at a freed table survive it. The batched per-page window (up to
/// `RANGE_FLUSH_CEILING_PAGES`) suffices only for a span that freed no table.
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB root frame, `aso`
/// must wrap that page table, and the caller must hold the address space's
/// `pt_lock`. `[virt_base, virt_base + page_count*4 KiB)` must lie in the user
/// half.
#[cfg(not(test))]
pub unsafe fn unmap_user_region_pooled(
    root_virt: u64,
    virt_base: u64,
    page_count: usize,
    aso: &crate::cap::object::AddressSpaceObject,
    on_leaf: &mut dyn FnMut(u64),
) -> usize
{
    use crate::mm::PAGE_SIZE;

    let top = root_level();
    // The caller's span lies in the user half, so neither operation saturates.
    let virt_end = virt_base.saturating_add((page_count as u64).saturating_mul(PAGE_SIZE as u64));
    let mut freed = 0usize;

    // SAFETY: root_virt is the direct-map VA of a valid root (caller's
    // contract); unmap_span's contract is met by the same guarantees.
    let root = unsafe { table_at(root_virt) };
    // SAFETY: root is a live table at the root level; aso wraps this page
    // table and the caller holds its pt_lock (caller's contract).
    unsafe { unmap_span(root, top, virt_base, virt_end, aso, &mut freed, on_leaf) };
    freed
}

/// Clear every in-range leaf PTE of `[lo, hi)` under `table` (a table at
/// `level`), then free each child table the clear left empty — gated on
/// emptiness and the parent entry's [`POOLED_TABLE`] bit as documented on
/// [`unmap_user_region_pooled`]. The frame holding `table` itself is left to
/// the caller (the root call's frame is never freed). Bounded recursion:
/// `level <= 4`.
///
/// # Safety
/// `table` must be a live table at `level` whose reachable child frames are
/// live; `aso` must wrap the containing page table; the caller must hold its
/// `pt_lock`.
#[cfg(not(test))]
unsafe fn unmap_span(
    table: &mut [PageTableEntry; 512],
    level: usize,
    lo: u64,
    hi: u64,
    aso: &crate::cap::object::AddressSpaceObject,
    freed: &mut usize,
    on_leaf: &mut dyn FnMut(u64),
)
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    let Some(child_level) = level.checked_sub(1)
    else
    {
        // Level 0: clear the span's leaves.
        for va in (lo..hi).step_by(PAGE_SIZE)
        {
            let Some(leaf) = entry(table, 0, va)
            else
            {
                continue;
            };
            // Demote-first: a span edge can cut through a NAPOT group
            // (core/kernel/docs/memory-internals.md § NAPOT Contiguity (RISC-V)).
            if leaf.0 & NAPOT != 0
            {
                demote_napot_64k(table, va);
            }
            if let Some(slot) = entry_mut(table, 0, va)
            {
                *slot = PageTableEntry(0);
            }
            if leaf.is_present()
            {
                on_leaf(leaf_phys(leaf, va));
            }
        }
        return;
    };

    let mut va = lo;
    while va < hi
    {
        let entry_end = hi.min(next_level_boundary(level, va));
        // Skip mega/gigapage leaves (not produced by the user path).
        if let Some(slot) = entry_mut(table, level, va)
            && slot.is_present()
            && slot.0 & LEAF_BITS == 0
        {
            let e = *slot;
            let child_pa = e.phys_addr();
            // SAFETY: present non-leaf entry points at a live child table.
            let child = unsafe { table_at(phys_to_virt(child_pa)) };
            // SAFETY: child is a live table at child_level; same aso/pt_lock
            // guarantees as this call.
            unsafe { unmap_span(child, child_level, va, entry_end, aso, freed, on_leaf) };
            if table_is_empty(child) && e.0 & POOLED_TABLE != 0
            {
                *slot = PageTableEntry(0);
                // SAFETY: child is empty and unlinked above; frame came from
                // this aso's pool (POOLED_TABLE).
                unsafe { aso.free_pt_page(child_pa) };
                // Bounded by the table frames of the address space.
                *freed = freed.saturating_add(1);
            }
        }
        va = entry_end;
    }
}

/// Pass the frame of every present 4 KiB leaf below `user_va_top()` in the
/// page table rooted at `root_virt` to `on_leaf`, changing nothing. Leaf
/// entries at a non-leaf level are skipped, as in [`unmap_user_region_pooled`]:
/// the user mapping path never installs one. A NAPOT member reports its own
/// page's frame.
///
/// Drives the frame-map release of an address space's teardown
/// (`AddressSpace::release_mapped_frames`). `on_table` runs before each
/// table's entries are read, the root's included, so the caller counts the
/// walk's work in tables and may open an interrupt window there.
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB root frame whose
/// tables no other hart modifies during the walk.
#[cfg(not(test))]
pub unsafe fn for_each_user_leaf(
    root_virt: u64,
    on_table: &mut dyn FnMut(),
    on_leaf: &mut dyn FnMut(u64),
)
{
    // SAFETY: root_virt is the direct-map VA of a valid root (caller's contract).
    let root = unsafe { table_at(root_virt) };
    // SAFETY: root is a live table at the root level, unmodified meanwhile.
    unsafe {
        walk_leaves(
            root,
            root_level(),
            0,
            crate::mm::user_va_top(),
            on_table,
            on_leaf,
        );
    };
}

/// Pass the frame of every present leaf of `[lo, hi)` under `table` (a table
/// at `level`) to `on_leaf`, running `on_table` before each table's entries
/// are read, `table`'s first. Bounded recursion: `level <= 4`.
///
/// # Safety
/// `table` must be a live table at `level` whose reachable child frames are
/// live and unmodified during the walk.
#[cfg(not(test))]
unsafe fn walk_leaves(
    table: &[PageTableEntry; 512],
    level: usize,
    lo: u64,
    hi: u64,
    on_table: &mut dyn FnMut(),
    on_leaf: &mut dyn FnMut(u64),
)
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    on_table();
    let Some(child_level) = level.checked_sub(1)
    else
    {
        // Level 0: report the span's present leaves.
        for va in (lo..hi).step_by(PAGE_SIZE)
        {
            if let Some(e) = entry(table, 0, va)
                && e.is_present()
            {
                on_leaf(leaf_phys(e, va));
            }
        }
        return;
    };

    let mut va = lo;
    while va < hi
    {
        let entry_end = hi.min(next_level_boundary(level, va));
        if let Some(e) = entry(table, level, va)
            && e.is_present()
            && e.0 & LEAF_BITS == 0
        {
            // SAFETY: a present non-leaf entry points at a live child table.
            let child = unsafe { table_at(phys_to_virt(e.phys_addr())) };
            // SAFETY: child is a live table at child_level (this call's contract).
            unsafe { walk_leaves(child, child_level, va, entry_end, on_table, on_leaf) };
        }
        va = entry_end;
    }
}

// ── Accessed-bit harvest ──────────────────────────────────────────────────────

/// The leaf `slot` as an atomic word. The A and D bits of a user leaf change
/// under three writers that do not share a lock: the hart itself (under
/// Svadu), the lock-free fault path ([`user_fault_is_spurious`]), and a
/// harvest under `pt_lock`, so each of them updates the word atomically and
/// none loses another's bit.
#[cfg(not(test))]
fn leaf_word(slot: &mut PageTableEntry) -> &AtomicU64
{
    // SAFETY: `PageTableEntry` is `repr(transparent)` over `u64`, so `slot` is
    // a valid, 8-byte-aligned `u64` for the borrow's lifetime, and every
    // concurrent access to a leaf's A and D bits is atomic (see above).
    unsafe { AtomicU64::from_ptr(core::ptr::from_mut(slot).cast::<u64>()) }
}

/// Pass the VA of each present 4 KiB leaf of
/// `[virt_base, virt_base + page_count * 4 KiB)`, in the page table rooted at
/// `root_virt`, whose accessed bit (A) is set to `on_accessed`, in VA order.
/// Changes no leaf.
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB user root frame, the
/// caller must hold the address space's `pt_lock`, and the span must lie in
/// the user half.
#[cfg(not(test))]
pub unsafe fn read_user_accessed(
    root_virt: u64,
    virt_base: u64,
    page_count: usize,
    on_accessed: &mut dyn FnMut(u64),
)
{
    // SAFETY: root_virt is the direct-map VA of a valid root, and pt_lock is
    // held (caller's contract).
    unsafe {
        for_each_leaf_slot(root_virt, virt_base, page_count, &mut |l0, va| {
            if let Some(slot) = entry_mut(l0, 0, va)
                && slot.is_present()
                && leaf_word(slot).load(Ordering::Relaxed) & ACCESSED != 0
            {
                on_accessed(va);
            }
        });
    }
}

/// Clear the accessed bit (A) of each present 4 KiB leaf of
/// `[virt_base, virt_base + page_count * 4 KiB)` whose VA `reported` names
/// (the pages a [`read_user_accessed`] found accessed). A page unmapped since
/// is skipped.
///
/// A NAPOT member is demoted first (demote-before-divergence,
/// [memory-internals.md](../../../docs/memory-internals.md) § NAPOT Contiguity
/// (RISC-V)), so each page's A is its own; a live group therefore never lacks
/// A, since a group is promoted only from 16 identical leaves including a newly
/// installed one, which carries A. Flushes no TLB: a hart that still caches the
/// leaf with A set completes accesses without setting it again, so the next
/// harvest under-reports that page
/// ([memory-internals.md](../../../docs/memory-internals.md) § Accessed Bits).
///
/// # Safety
/// As [`read_user_accessed`].
#[cfg(not(test))]
pub unsafe fn clear_user_accessed(
    root_virt: u64,
    virt_base: u64,
    page_count: usize,
    reported: &dyn Fn(u64) -> bool,
)
{
    // SAFETY: as for read_user_accessed (caller's contract).
    unsafe {
        for_each_leaf_slot(root_virt, virt_base, page_count, &mut |l0, va| {
            if !is_present_at(l0, va) || !reported(va)
            {
                return;
            }
            if is_napot(l0, va)
            {
                demote_napot_64k(l0, va);
            }
            if let Some(slot) = entry_mut(l0, 0, va)
            {
                leaf_word(slot).fetch_and(!ACCESSED, Ordering::Relaxed);
            }
        });
    }
}

/// Whether `va`'s slot in the leaf table `l0` holds a present leaf.
#[cfg(not(test))]
fn is_present_at(l0: &[PageTableEntry; 512], va: u64) -> bool
{
    entry(l0, 0, va).is_some_and(PageTableEntry::is_present)
}

/// Pass each page VA of `[virt_base, virt_base + page_count * 4 KiB)` that a
/// present leaf table covers, with that table, to `on_slot`, in VA order.
///
/// # Safety
/// As [`read_user_accessed`].
#[cfg(not(test))]
unsafe fn for_each_leaf_slot(
    root_virt: u64,
    virt_base: u64,
    page_count: usize,
    on_slot: &mut dyn FnMut(&mut [PageTableEntry; 512], u64),
)
{
    use crate::mm::PAGE_SIZE;

    // The caller's span lies in the user half, so neither operation saturates.
    let virt_end = virt_base.saturating_add((page_count as u64).saturating_mul(PAGE_SIZE as u64));
    // SAFETY: root_virt is the direct-map VA of a valid root (caller's contract).
    let root = unsafe { table_at(root_virt) };
    // SAFETY: root is a live table at the root level; pt_lock is held.
    unsafe { walk_leaf_tables(root, root_level(), virt_base, virt_end, on_slot) };
}

/// Pass each page VA of `[lo, hi)` under `table` (a table at `level`) that a
/// present leaf table covers, with that table, to `on_slot`. Leaf entries at a
/// non-leaf level are skipped, as in [`unmap_user_region_pooled`]. Bounded
/// recursion: `level <= 4`.
///
/// # Safety
/// `table` must be a live table at `level` whose reachable child frames are
/// live; the caller must hold the address space's `pt_lock`.
#[cfg(not(test))]
unsafe fn walk_leaf_tables(
    table: &mut [PageTableEntry; 512],
    level: usize,
    lo: u64,
    hi: u64,
    on_slot: &mut dyn FnMut(&mut [PageTableEntry; 512], u64),
)
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    let Some(child_level) = level.checked_sub(1)
    else
    {
        for va in (lo..hi).step_by(PAGE_SIZE)
        {
            on_slot(table, va);
        }
        return;
    };

    let mut va = lo;
    while va < hi
    {
        let entry_end = hi.min(next_level_boundary(level, va));
        if let Some(e) = entry(table, level, va)
            && e.is_present()
            && e.0 & LEAF_BITS == 0
        {
            // SAFETY: a present non-leaf entry points at a live child table.
            let child = unsafe { table_at(phys_to_virt(e.phys_addr())) };
            // SAFETY: child is a live table at child_level (this call's contract).
            unsafe { walk_leaf_tables(child, child_level, va, entry_end, on_slot) };
        }
        va = entry_end;
    }
}

// ── Page enumeration ──────────────────────────────────────────────────────────

/// Pass each present 4 KiB user leaf of `[start, hi)`, in the page table
/// rooted at `root_virt`, to `on_leaf` in VA order, as its VA, its frame and
/// its raw bits, examining at most `budget` table entries at any level.
/// `on_leaf` returns whether it took the leaf, and the scan stops at the first
/// it does not take. Leaf entries at a non-leaf level are skipped, as in
/// [`unmap_user_region_pooled`]: the user mapping path never installs one. A
/// NAPOT member reports its own page's frame ([`leaf_phys`]).
///
/// Returns the first VA the scan did not finish: the VA of the leaf `on_leaf`
/// did not take, the start of the span of the entry the budget stopped
/// before, or `hi` once the whole span is scanned.
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB user root frame, the
/// caller must hold the address space's `pt_lock`, `start` must be
/// page-aligned, and `[start, hi)` must lie in the user half.
#[cfg(not(test))]
pub unsafe fn scan_user_leaves(
    root_virt: u64,
    start: u64,
    hi: u64,
    budget: usize,
    on_leaf: &mut dyn FnMut(u64, u64, u64) -> bool,
) -> u64
{
    let mut scan = LeafScan {
        budget,
        to_virt: crate::mm::paging::phys_to_virt,
        on_leaf,
    };
    // SAFETY: root_virt is the direct-map VA of a valid root at the root
    // level, whose tables pt_lock keeps unchanged and every one of which the
    // direct map reaches at phys_to_virt of its frame (caller's contract).
    unsafe { scan.table(root_virt, root_level(), start, hi) }.unwrap_or(hi)
}

/// The state of one [`scan_user_leaves`]: the entries it may still examine,
/// the translation that reaches a table from its frame, and the leaf sink.
struct LeafScan<'a>
{
    budget: usize,
    to_virt: fn(u64) -> u64,
    on_leaf: &'a mut dyn FnMut(u64, u64, u64) -> bool,
}

impl LeafScan<'_>
{
    /// Scan `[lo, hi)` under the table at `table_va`, a table at `level`;
    /// `Some` of the VA the scan stopped at, or `None` once the span is
    /// scanned. Bounded recursion: `level <= 4`.
    ///
    /// # Safety
    /// `table_va` must address a readable 512-entry table at `level`, and
    /// `to_virt` must map the frame of every table a present non-leaf entry
    /// under it names to a readable address of that table, none of which
    /// changes during the scan.
    unsafe fn table(&mut self, table_va: u64, level: usize, lo: u64, hi: u64) -> Option<u64>
    {
        let mut va = lo;
        while va < hi
        {
            let Some(left) = self.budget.checked_sub(1)
            else
            {
                return Some(va);
            };
            self.budget = left;
            // The span's last entry at the top level ends at 2^64, which the
            // boundary wraps to 0; the user half never reaches it.
            let boundary = next_level_boundary(level, va);
            let end = if boundary == 0 { hi } else { hi.min(boundary) };
            // SAFETY: table_va is a readable table (this call's contract); the
            // index is below 512.
            let e = unsafe { read_entry(table_va, vpn_index(level, va)) };
            if let Some(child_level) = level.checked_sub(1)
            {
                if e.is_present() && e.0 & LEAF_BITS == 0
                {
                    let child = (self.to_virt)(e.phys_addr());
                    // SAFETY: a present non-leaf entry names a table at
                    // child_level, readable at `child` (this call's contract).
                    if let Some(stop) = unsafe { self.table(child, child_level, va, end) }
                    {
                        return Some(stop);
                    }
                }
            }
            else if e.is_present() && !(self.on_leaf)(va, leaf_phys(e, va), e.0)
            {
                return Some(va);
            }
            va = end;
        }
        None
    }
}

/// RISC-V counterpart to [`crate::mm::paging::unmap_identity_page`].
///
/// Walks the kernel root from `phys_to_virt(kernel_root_table_pa())` down to the
/// leaf covering `pa` and clears the leaf entry. Bails silently if any
/// intermediate level is absent or is a large leaf (clearing inside one
/// would corrupt unrelated memory). Issues a local `sfence.vma pa, x0`,
/// then broadcasts a TLB shootdown to every other online hart.
///
/// The kernel installs this identity mapping in Phase 3
/// (`crate::mm::paging::init_kernel_page_tables`) so the AP trampoline page can
/// execute the three instructions after `csrw satp` (sfence.vma, mv sp, jr)
/// while PC is still inside the trampoline at its physical address. Once the AP has
/// reached its kernel-VA entry, the mapping is no longer needed.
///
/// Intermediate tables are NOT freed — they may host other low-VA
/// mappings (notably the boot-stack identity mapping installed by
/// `crate::mm::paging::map_boot_stack`, and any future low-PA identity entries).
///
/// # Safety
/// Must execute in S-mode after Phase 3 installed the kernel root. `pa` must be
/// 4 KiB-aligned, and no thread (BSP or AP) may execute code on or reference
/// data inside the page after this returns. The caller must not migrate
/// between harts during the call: the local flush and the `current_cpu()` read
/// that excludes this hart from the shootdown precede the routine's own
/// `preempt_disable()`, which covers only the remote shootdown. The sole
/// caller, the Phase 8 boot path, runs on the BSP before `sched::enter` and
/// cannot migrate.
#[cfg(not(test))]
#[expect(
    clippy::similar_names,
    reason = "root_va and root_pa are a VA/PA pair — the similarity is intentional and follows the \
              pattern used elsewhere in this file"
)]
pub unsafe fn unmap_identity_page(pa: u64)
{
    use crate::mm::paging::{kernel_root_table_pa, phys_to_virt};

    let root_pa = kernel_root_table_pa();
    if root_pa == 0
    {
        return;
    }
    let root_va = phys_to_virt(root_pa);
    let virt = pa; // identity: VA == PA

    // SAFETY: root_va is the direct-map VA of the kernel root installed in
    // Phase 3; table walk is read-only until the leaf clear at the bottom.
    let Some(leaf) = (unsafe { descend_existing(root_va, virt, root_level(), 0, phys_to_virt) })
        .and_then(|l0| entry_mut(l0, 0, virt))
    else
    {
        return;
    };
    *leaf = PageTableEntry(0);

    // Local invalidate, then broadcast to every other online hart. The
    // shootdown routine requires preemption disabled and handles the
    // interrupt window for mutual shootdown itself.
    // SAFETY: sfence.vma is a per-hart architectural primitive; shootdown
    // contract met by acquiring preemption around the broadcast.
    unsafe { flush_page(virt) };

    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let remote = crate::cpu_mask::MaskSource::Below(cpu_count);
    crate::percpu::preempt_disable();
    // SAFETY: root_pa is the active kernel root; remote names only online harts
    // (the shootdown leaves this one out, and returns at once when it is the
    // only one); preemption disabled around the shootdown. Tag 0: this is a
    // kernel identity mapping torn down at boot, not a tagged user space.
    unsafe { crate::mm::tlb_shootdown::shootdown(root_pa, &remote, virt, 0) };
    crate::percpu::preempt_enable();
}

// ── Direct-map holes ──────────────────────────────────────────────────────────
// A guard page below a kernel stack (`crate::mm::stack_guard`) is a hole in
// the direct map: one 4 KiB entry left invalid. The 2 MiB megapage that maps
// a guard's chunk is first split into a leaf table of the same translation.
// `stack_guard` serialises every edit; a hole's stale translations are
// dropped by a local flush at boot or the guard epoch at a later switch-in,
// and a fill's by its local flush and the guard epoch or the spurious-fault
// retry (core/kernel/docs/memory-internals.md § Kernel Stack Guards).

/// Direct-map flags of a RAM page: read-write, never executable, PMA memory
/// type (`mm::paging::init_kernel_page_tables` maps RAM so).
const DIRECT_RAM: PageFlags = PageFlags {
    readable: true,
    writable: true,
    executable: false,
    uncacheable: false,
};

/// Leave the direct-map page at `virt` invalid. When a 2 MiB megapage maps
/// it, the megapage is first replaced by a leaf table with the same
/// translation, built in the frame `take_table` returns.
///
/// # Errors
/// - [`PagingError::NotMapped`] when the direct map does not map `virt`.
/// - [`PagingError::OutOfFrames`] when a split is needed and `take_table`
///   returns `None`.
///
/// # Safety
/// `virt` is the direct-map address of a RAM page nothing reaches through the
/// direct map until [`fill_direct_map_page`] restores it. The caller
/// serialises every direct-map edit and makes stale translations of the page
/// harmless before the guard's thread runs: a local flush while only the boot
/// CPU runs, or the guard epoch (`stack_guard::flush_before_run`) after SMP
/// bringup.
#[cfg(not(test))]
pub unsafe fn hole_direct_map_page(
    virt: u64,
    take_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), PagingError>
{
    use crate::mm::paging::{LARGE_PAGE_SIZE, kernel_root_table_pa, phys_to_virt};

    let root_va = phys_to_virt(kernel_root_table_pa());
    // SAFETY: the kernel root and the tables under it are live table frames
    // reached through the direct map; the caller serialises their edits.
    let l1 = unsafe { descend_existing(root_va, virt, root_level(), 1, phys_to_virt) }
        .ok_or(PagingError::NotMapped)?;
    let slot = entry_mut(l1, 1, virt).ok_or(PagingError::NotMapped)?;
    if !slot.is_present()
    {
        return Err(PagingError::NotMapped);
    }
    if slot.0 & LEAF_BITS != 0
    {
        let table_pa = take_table().ok_or(PagingError::OutOfFrames)?;
        // SAFETY: the frame is the caller's alone, reached through the direct
        // map, and no table names it yet.
        let table = unsafe { table_at(phys_to_virt(table_pa)) };
        crate::mm::paging::fill_split_table(
            table,
            slot.phys_addr() & !(LARGE_PAGE_SIZE - 1),
            |phys| PageTableEntry::new_page(phys, DIRECT_RAM),
        );
        // The entries are written before the level-1 entry names the table,
        // so a walk through it, which reads the table through that entry,
        // finds them.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        *slot = PageTableEntry::new_table(table_pa);
    }
    // SAFETY: the level-1 entry names a live leaf table (split above, or by
    // an earlier hole).
    let l0 = unsafe { table_at(phys_to_virt(slot.phys_addr())) };
    *entry_mut(l0, 0, virt).ok_or(PagingError::NotMapped)? = PageTableEntry(0);
    Ok(())
}

/// Give the direct-map page at `virt` the shadow-stack encoding: refused with
/// [`PagingError::NotMapped`]. The kernel runs on no shadow stack on riscv64
/// (`shadow_stack::enabled` is false), so `mm::stack_guard` never asks; the
/// Zicfiss encoding and the fault paths that recognise it come with the
/// riscv64 shadow-stack support (core/kernel/docs/return-address-integrity.md).
///
/// # Errors
/// Always [`PagingError::NotMapped`].
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
#[cfg(not(test))]
pub unsafe fn shadow_direct_map_page(
    _virt: u64,
    _phys: u64,
    _take_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), PagingError>
{
    Err(PagingError::NotMapped)
}

/// Map the direct-map page at `virt` to `phys` again, closing a hole
/// [`hole_direct_map_page`] left. A hart may have cached the invalid entry
/// ([`CACHES_NOT_PRESENT_ENTRIES`]): the caller flushes this hart, and another
/// hart that kept it either flushes before it runs a thread whose kernel stack
/// the page becomes or takes the spurious-fault retry
/// ([`kernel_fault_is_spurious`]) on its first other use of the page
/// (core/kernel/docs/memory-internals.md § Kernel Stack Guards).
///
/// # Safety
/// `virt` is `direct_map_base() + phys`, holed by [`hole_direct_map_page`];
/// the caller serialises every direct-map edit.
#[cfg(not(test))]
pub unsafe fn fill_direct_map_page(virt: u64, phys: u64)
{
    use crate::mm::paging::{kernel_root_table_pa, phys_to_virt};

    let root_va = phys_to_virt(kernel_root_table_pa());
    // SAFETY: as in hole_direct_map_page; the hole left a leaf table here.
    if let Some(slot) = unsafe { descend_existing(root_va, virt, root_level(), 0, phys_to_virt) }
        .and_then(|l0| entry_mut(l0, 0, virt))
    {
        *slot = PageTableEntry::new_page(phys, DIRECT_RAM);
    }
}

/// Whether the kernel's tables map the direct-map address `virt`.
///
/// # Safety
/// The caller serialises the read against direct-map edits.
#[cfg(not(test))]
pub unsafe fn direct_map_page_present(virt: u64) -> bool
{
    use crate::mm::paging::{kernel_root_table_pa, phys_to_virt};

    let root_va = phys_to_virt(kernel_root_table_pa());
    // SAFETY: as in hole_direct_map_page.
    let Some(l1_entry) =
        (unsafe { descend_existing(root_va, virt, root_level(), 1, phys_to_virt) })
            .and_then(|l1| entry(l1, 1, virt))
    else
    {
        return false;
    };
    if !l1_entry.is_present() || l1_entry.0 & LEAF_BITS != 0
    {
        return l1_entry.is_present();
    }
    // SAFETY: a present non-leaf level-1 entry names a live leaf table.
    let l0 = unsafe { table_at(phys_to_virt(l1_entry.phys_addr())) };
    entry(l0, 0, virt).is_some_and(PageTableEntry::is_present)
}

pub use super::encoding::KernelAccess;

/// Whether an S-mode load or store page fault at the kernel address `va` is
/// stale: the kernel's tables map `va` with a 4 KiB leaf that permits the
/// access, so the hart cached the invalid entry a closed direct-map hole
/// ([`fill_direct_map_page`]) left, and resolves it on retry after a local
/// `sfence.vma`.
///
/// A megapage leaf is never stale this way (no megapage of the direct map is
/// ever invalid), so only a leaf table is consulted.
///
/// # Safety
/// Must run in S-mode.
#[cfg(not(test))]
pub unsafe fn kernel_fault_is_spurious(va: u64, access: KernelAccess) -> bool
{
    use crate::mm::paging::{kernel_root_table_pa, phys_to_virt};

    let root_pa = kernel_root_table_pa();
    if root_pa == 0 || va >> 63 == 0
    {
        return false;
    }
    // SAFETY: the kernel root and its tables are live frames reached through
    // the direct map; a racing edit at worst makes this read report a stale
    // answer, and a wrong `true` re-faults on retry into the same check.
    let Some(leaf) =
        (unsafe { descend_existing(phys_to_virt(root_pa), va, root_level(), 0, phys_to_virt) })
            .and_then(|l0| entry(l0, 0, va))
    else
    {
        return false;
    };
    super::encoding::kernel_leaf_permits(leaf.0, access)
}

/// Invalidate every translation this hart caches, in every address space
/// (`sfence.vma zero, zero`).
///
/// # Safety
/// Must execute in S-mode.
#[cfg(not(test))]
pub unsafe fn flush_all_contexts()
{
    // SAFETY: S-mode (caller contract).
    unsafe { flush_tlb_all() };
}

/// Whether a hart may cache an invalid entry, so that a page made valid again
/// can fault on a hart that kept it until that hart flushes: true on RISC-V
/// without Svvptc, which the kernel does not require.
pub const CACHES_NOT_PRESENT_ENTRIES: bool = true;

/// Invalidate this hart's cached translations of the kernel address `virt`
/// in every address space: `sfence.vma virt, zero` covers every ASID.
///
/// # Safety
/// Must execute in S-mode.
#[cfg(not(test))]
pub unsafe fn flush_kernel_page(virt: u64)
{
    // SAFETY: S-mode (caller contract).
    unsafe { flush_page(virt) };
}

/// Change the permission flags on an existing user-space leaf PTE at `virt`.
///
/// Returns `Err(PagingError::NotMapped)` if any level is not present, and
/// `Err(PagingError::NotGranted)`, leaving the leaf's rights as they were, if
/// `flags` asks for W or X the leaf's grant lacks. On success, rewrites the leaf PTE with the
/// rights of `flags` (preserving the physical address, the USER bit, the
/// grant, and the leaf's memory type (PBMT), whatever `flags.uncacheable`
/// says; `encoding::protected_leaf`), calls `flush_page`, and returns the
/// [`MapOutcome`](crate::mm::paging::MapOutcome) classifying the rights change
/// (a same-frame rewrite, so never `Fresh`).
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB
/// root frame. Caller must have validated W^X and rights before calling.
#[cfg(not(test))]
pub unsafe fn protect_user_page(
    root_virt: u64,
    virt: u64,
    flags: crate::mm::paging::PageFlags,
) -> Result<crate::mm::paging::MapOutcome, crate::mm::paging::PagingError>
{
    use crate::mm::paging::{PagingError, phys_to_virt};
    // USER (U) is set below to preserve user accessibility.

    // SAFETY: root_virt is direct-map VA of a valid user root PT (caller
    // contract); its reachable child frames are live PT-pool frames.
    let l0 = unsafe { descend_existing(root_virt, virt, root_level(), 0, phys_to_virt) }
        .ok_or(PagingError::NotMapped)?;
    // Demote-first (core/kernel/docs/memory-internals.md § NAPOT Contiguity
    // (RISC-V)). The demoted per-page PTE carries the same rights and PA, so
    // the classification below is unaffected.
    if is_napot(l0, virt)
    {
        demote_napot_64k(l0, virt);
    }
    let leaf = entry_mut(l0, 0, virt).ok_or(PagingError::NotMapped)?;
    if !leaf.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    let prior = leaf.0;
    let phys = leaf.phys_addr();
    let new_pte = PageTableEntry(super::encoding::protected_leaf(
        prior,
        PageTableEntry::new_page(phys, flags).0 | USER,
    )?);
    *leaf = new_pte;

    // SAFETY: virt is mapped; flush_page is safe for any VA (and kills any
    // cached 64 KiB entry covering it).
    unsafe { flush_page(virt) };
    Ok(classify_user_map(prior, new_pte.0))
}

/// Translate a user virtual address to its mapped physical address and raw PTE.
///
/// Walks from the root to the leaf level without modifying any entry or
/// flushing the TLB. Returns `Some((phys_addr, raw_pte_bits))` if the page is
/// present at every level, or `None` if any level is not present.
///
/// Assumes 4 KiB user leaves: a present R/W/X entry at an intermediate level
/// (a mega/gigapage leaf) yields `None` rather than a translation. The user
/// mapping path never installs a large leaf, so this holds for every user
/// VA; a change that introduces user large pages adds a large-leaf branch
/// here and in [`user_fault_is_spurious`], which walks the tables itself.
/// NAPOT members are still level-0 leaves: the returned physical address is decoded per page
/// ([`leaf_phys`]); the raw PTE bits carry N and the size encoding.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB user
/// root page table frame.
#[cfg(not(test))]
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: root_virt is direct-map VA of a valid user root PT (caller
    // contract); its reachable child frames are live PT-pool frames.
    let l0 = unsafe { descend_existing(root_virt, virt, root_level(), 0, phys_to_virt) }?;
    let leaf = entry(l0, 0, virt)?;
    if !leaf.is_present()
    {
        return None;
    }

    Some((leaf_phys(leaf, virt), leaf.0))
}

// ── Shootdown-elision classification ──────────────────────────────────────────

/// Classify a leaf-PTE rewrite (`prior` → `new`) into a
/// [`MapOutcome`](crate::mm::paging::MapOutcome) for shootdown elision.
///
/// `prior`/`new` are raw leaf PTE bits (`new` is presumed valid). A not-
/// valid `prior` is a fresh map; a same-frame rights *widening* needs only the
/// spurious-fault retry; any frame change or rights *narrowing* strands a
/// dangerous stale entry and must shoot down. See
/// [`MapOutcome`](crate::mm::paging::MapOutcome) and
/// [memory-internals.md](../../../docs/memory-internals.md) § SMP TLB Shootdown
/// for the full argument.
fn classify_user_map(prior: u64, new: u64) -> crate::mm::paging::MapOutcome
{
    use crate::mm::paging::MapOutcome;

    // Writers demote a NAPOT group before rewriting any member, so the
    // prior PTE is always a plain per-page leaf whose PPN is the true PA.
    debug_assert!(prior & NAPOT == 0, "classify_user_map on a NAPOT member");

    if prior & VALID == 0
    {
        return MapOutcome::Fresh;
    }
    if PageTableEntry(prior).phys_addr() == PageTableEntry(new).phys_addr()
        && map_rights_superset(new, prior)
    {
        MapOutcome::Widen
    }
    else
    {
        MapOutcome::Replace
    }
}

/// Whether `new` grants every user access `prior` granted (leaf R/W/X bits).
///
/// Each access class checks its own bit: R (load), W (store), X (fetch).
fn map_rights_superset(new: u64, prior: u64) -> bool
{
    let r_ok = prior & READ == 0 || new & READ != 0;
    let w_ok = prior & WRITE == 0 || new & WRITE != 0;
    let x_ok = prior & EXECUTE == 0 || new & EXECUTE != 0;
    r_ok && w_ok && x_ok
}

// ── Spurious-fault classification ─────────────────────────────────────────────

/// Whether a leaf PTE grants a user-mode `access`.
///
/// A user page fault is *spurious* (stale TLB) only when the live PTE is
/// valid, user-accessible (U), and already grants the access: a load needs
/// `READ`, a store or AMO needs `WRITE`, a fetch needs `EXECUTE`. The kernel
/// does not make execute-only pages readable (MXR is kept clear), so each
/// access checks exactly its own bit. The NAPOT N bit does not participate: a
/// NAPOT member carries the same V/U/R/W/X bits as the per-page leaf it stands
/// for.
fn pte_permits_user_access(pte: u64, access: UserAccess) -> bool
{
    let grant = match access
    {
        UserAccess::Load => READ,
        UserAccess::Store => WRITE,
        UserAccess::Fetch => EXECUTE,
    };
    pte & VALID != 0 && pte & USER != 0 && pte & grant != 0
}

/// The access a user leaf PTE (from [`translate_user_page`]) grants, or
/// `None` when it is not valid or not user-accessible: R, W and X as they are,
/// and `uncacheable` for a PBMT other than PMA (the decoder is
/// `encoding::user_leaf_flags`).
pub fn user_leaf_flags(pte: u64) -> Option<PageFlags>
{
    super::encoding::user_leaf_flags(pte)
}

/// The [`LeafGrant`] a user leaf PTE (from [`translate_user_page`]) records
/// in its RSW bits (the decoder is `encoding::user_leaf_grant`).
pub fn user_leaf_grant(pte: u64) -> LeafGrant
{
    super::encoding::user_leaf_grant(pte)
}

/// The A and D bits a user `access` that the leaf `pte` permits needs set
/// before a Svade hart completes it: A, and D too for a store. Returns the leaf
/// with them set, or `None` when the leaf already carries them.
fn svade_update(pte: u64, access: UserAccess) -> Option<u64>
{
    let needed = match access
    {
        UserAccess::Store => ACCESSED | DIRTY,
        UserAccess::Load | UserAccess::Fetch => ACCESSED,
    };
    (pte & needed != needed).then_some(pte | needed)
}

/// Classify a userspace page fault at `va` as one the hart resolves on retry,
/// setting the A (and D) bit the access needs where the leaf lacks it.
///
/// Walks the *current* (`satp`) page tables for `va` and returns `false` for
/// any genuine fault (unmapped, or the live mapping still forbids the
/// access); the caller then delivers it as a genuine fault per
/// [fault-handling.md](../../../../../docs/fault-handling.md). When the live
/// leaf is user-accessible and permits `access`, the fault is either a stale
/// TLB entry or, under Svade, a leaf whose A bit `SYS_ASPACE_HARVEST` cleared
/// (or a writable leaf without D, on a store): the walk sets the missing bits
/// with one compare-and-swap ([`svade_update`]) and returns `true`, and the
/// caller flushes the local entry and retries the access. A failed swap also
/// returns `true`: the leaf changed under it, and the retried access faults
/// again into this check if it still needs to. Each `true` either finds the
/// bits set or sets them, so the retry completes unless the leaf changes
/// again, and no retry counter is needed.
///
/// The swap runs without `pt_lock`. SIE is clear and the space is active on
/// this hart, so a teardown that frees the leaf's table waits for this hart's
/// acknowledgement of its shootdown before the frame can be reused; a freed
/// frame holds no valid leaf, so a swap on one fails. A NAPOT member that lacks
/// A is reported genuine instead: setting one member's bit would diverge the
/// group, and no live group lacks A ([`clear_user_accessed`]).
///
/// Assumes 4 KiB user leaves, as the user mapping path installs no other: the
/// walk to level 0 ([`descend_existing`]) yields `None` at a mega/gigapage
/// leaf, which then reads as genuine. A change that introduces user large
/// pages adds a large-leaf branch here, setting A and D on that leaf as
/// [`svade_update`] does on a 4 KiB one.
///
/// # Safety
/// Must run in S-mode in the faulting thread's context, i.e. before `satp` has
/// been changed by a context switch, with SIE clear.
#[cfg(not(test))]
pub unsafe fn user_fault_is_spurious(va: u64, access: UserAccess) -> bool
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: S-mode; reads satp to recover the active page-table root.
    let root_virt = phys_to_virt(unsafe { read_root_phys() });
    // SAFETY: root_virt is the direct-map VA of the active root; its tables
    // stay allocated while this hart, with SIE clear, runs the space (above).
    let Some(l0) = (unsafe { descend_existing(root_virt, va, root_level(), 0, phys_to_virt) })
    else
    {
        return false;
    };
    let Some(slot) = entry_mut(l0, 0, va)
    else
    {
        return false;
    };
    let word = leaf_word(slot);
    let pte = word.load(Ordering::Relaxed);
    if !pte_permits_user_access(pte, access)
    {
        return false;
    }
    match svade_update(pte, access)
    {
        None => true,
        Some(_) if pte & NAPOT != 0 => false,
        Some(updated) =>
        {
            // A failure means the leaf changed; the retry re-evaluates it.
            let _ = word.compare_exchange(pte, updated, Ordering::Relaxed, Ordering::Relaxed);
            true
        }
    }
}

/// The `FAULT_ACCESS_PRESENT` bit a fault message carries for a fault at the
/// user address `va` that no trap cause describes (a kernel copy's, delivered
/// by the syscall dispatcher): always clear, as for every RISC-V fault
/// message, since `scause` does not encode presence
/// (docs/fault-handling.md § Fault Message).
///
/// # Safety
/// None on RISC-V; `unsafe` for parity with the x86-64 walk.
#[cfg(not(test))]
pub unsafe fn copy_fault_present(_va: u64) -> bool
{
    false
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
    fn new_page_uncacheable_sets_pbmt_io()
    {
        let flags = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: true,
        };
        let pte = PageTableEntry::new_page(0x4000, flags);
        assert_eq!(pte.0 & PBMT_MASK, PBMT_IO);
        // The PBMT field must not disturb the PPN.
        assert_eq!(pte.phys_addr(), 0x4000);
    }

    #[test]
    fn new_page_cacheable_leaves_pbmt_pma()
    {
        let flags = PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };
        let pte = PageTableEntry::new_page(0x5000, flags);
        assert_eq!(pte.0 & PBMT_MASK, 0);
    }

    // ── NAPOT promotion / demotion ────────────────────────────────────────────

    const MMIO_FLAGS: PageFlags = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: true,
    };

    /// A level-0 table with `n` consecutive leaves at `start` mapping
    /// `base_pa + i*4096` with `flags`.
    fn table_with_run(
        start: usize,
        n: usize,
        base_pa: u64,
        flags: PageFlags,
    ) -> [PageTableEntry; 512]
    {
        let mut t = [PageTableEntry(0); 512];
        for i in 0..n
        {
            t[start + i] = PageTableEntry::new_page(base_pa + i as u64 * 4096, flags);
        }
        t
    }

    /// VA whose `vpn[0]` is `idx` (level-0 index ↔ VA bits [20:12]).
    fn va_at(idx: usize) -> u64
    {
        (idx as u64) << 12
    }

    #[test]
    fn napot_promotion_encodes_group()
    {
        let mut t = table_with_run(16, 16, 0x1_0000, MMIO_FLAGS);
        try_promote_napot_64k(&mut t, va_at(20));
        let first = t[16];
        assert_ne!(first.0 & NAPOT, 0);
        // ppn[3:0] must carry the 64 KiB size encoding.
        assert_eq!(first.0 & (0xF << 10), NAPOT_64K_PPN);
        // Every member is bit-identical.
        for entry in &t[16..32]
        {
            assert_eq!(entry.0, first.0);
        }
        // Untouched outside the group.
        assert_eq!(t[15].0, 0);
        assert_eq!(t[32].0, 0);
    }

    #[test]
    fn napot_leaf_phys_reconstructs_all_offsets()
    {
        let mut t = table_with_run(0, 16, 0x1_0000, MMIO_FLAGS);
        try_promote_napot_64k(&mut t, va_at(0));
        for (i, entry) in t.iter().enumerate().take(16)
        {
            assert_eq!(leaf_phys(*entry, va_at(i)), 0x1_0000 + i as u64 * 4096);
        }
    }

    #[test]
    fn napot_demotion_round_trips()
    {
        let original = table_with_run(48, 16, 0x3_0000, MMIO_FLAGS);
        let mut t = original;
        try_promote_napot_64k(&mut t, va_at(48));
        assert_ne!(t[48].0 & NAPOT, 0);
        demote_napot_64k(&mut t, va_at(50));
        for i in 0..512
        {
            assert_eq!(t[i].0, original[i].0);
        }
    }

    #[test]
    fn napot_promotion_refused_for_cacheable_run()
    {
        let mut t = table_with_run(
            16,
            16,
            0x1_0000,
            PageFlags {
                uncacheable: false,
                ..MMIO_FLAGS
            },
        );
        let before = t[16].0;
        try_promote_napot_64k(&mut t, va_at(16));
        assert_eq!(t[16].0, before);
    }

    #[test]
    fn napot_promotion_refused_for_noncontiguous_phys()
    {
        let mut t = table_with_run(16, 16, 0x1_0000, MMIO_FLAGS);
        t[20] = PageTableEntry::new_page(0x9_0000, MMIO_FLAGS);
        let before = t[16].0;
        try_promote_napot_64k(&mut t, va_at(16));
        assert_eq!(t[16].0, before);
        assert_eq!(t[16].0 & NAPOT, 0);
    }

    #[test]
    fn napot_promotion_refused_for_partial_group()
    {
        let mut t = table_with_run(16, 15, 0x1_0000, MMIO_FLAGS);
        try_promote_napot_64k(&mut t, va_at(16));
        assert_eq!(t[16].0 & NAPOT, 0);
    }

    #[test]
    fn napot_promotion_refused_for_unaligned_phys_base()
    {
        // Contiguous but starting at a non-64 KiB-aligned PA.
        let mut t = table_with_run(16, 16, 0x1_1000, MMIO_FLAGS);
        try_promote_napot_64k(&mut t, va_at(16));
        assert_eq!(t[16].0 & NAPOT, 0);
    }

    #[test]
    fn napot_promotion_refused_for_mixed_rights()
    {
        let mut t = table_with_run(16, 16, 0x1_0000, MMIO_FLAGS);
        t[21] = PageTableEntry::new_page(
            0x1_0000 + 5 * 4096,
            PageFlags {
                writable: false,
                ..MMIO_FLAGS
            },
        );
        try_promote_napot_64k(&mut t, va_at(16));
        assert_eq!(t[16].0 & NAPOT, 0);
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

    const ALL_MODES: [PagingMode; 3] = [PagingMode::Sv39, PagingMode::Sv48, PagingMode::Sv57];

    #[test]
    fn kernel_half_base_root_index_is_256_in_every_mode()
    {
        for mode in ALL_MODES
        {
            let top = mode.levels() - 1;
            assert_eq!(vpn_index(top, mode.kernel_va_base()), 256);
            for level in 0..top
            {
                assert_eq!(vpn_index(level, mode.kernel_va_base()), 0);
            }
        }
        // The direct map sits at the active mode's kernel-half base
        // (host-test default: Sv48).
        assert_eq!(vpn_index(3, crate::mm::paging::direct_map_base()), 256);
    }

    #[test]
    fn kernel_image_base_root_index_per_mode()
    {
        // The kernel links at the top-2-GiB VA, canonical in every mode.
        let kv: u64 = 0xFFFF_FFFF_8000_0000;
        assert_eq!(vpn_index(PagingMode::Sv39.levels() - 1, kv), 510);
        assert_eq!(vpn_index(PagingMode::Sv48.levels() - 1, kv), 511);
        assert_eq!(vpn_index(PagingMode::Sv57.levels() - 1, kv), 511);
        assert_eq!(vpn_index(1, kv), 0);
    }

    #[test]
    fn test_default_mode_is_sv48()
    {
        assert_eq!(paging_mode(), PagingMode::Sv48);
    }

    // ── Spurious-fault classification ──────────────────────────────────────────

    #[test]
    fn permits_load_only_when_readable()
    {
        let x_only = VALID | USER | EXECUTE; // execute-only, MXR clear
        let r = VALID | USER | READ;
        assert!(!pte_permits_user_access(x_only, UserAccess::Load));
        assert!(pte_permits_user_access(r, UserAccess::Load));
    }

    #[test]
    fn permits_store_only_when_writable()
    {
        let ro = VALID | USER | READ;
        let rw = VALID | USER | READ | WRITE;
        assert!(!pte_permits_user_access(ro, UserAccess::Store));
        assert!(pte_permits_user_access(rw, UserAccess::Store));
    }

    #[test]
    fn permits_fetch_only_when_executable()
    {
        let rw = VALID | USER | READ | WRITE;
        let rx = VALID | USER | READ | EXECUTE;
        assert!(!pte_permits_user_access(rw, UserAccess::Fetch));
        assert!(pte_permits_user_access(rx, UserAccess::Fetch));
    }

    #[test]
    fn rejects_non_user_and_invalid_pages()
    {
        // Valid + RWX but supervisor-only (U clear): a U-mode access is genuine.
        let kernel = VALID | READ | WRITE | EXECUTE;
        assert!(!pte_permits_user_access(kernel, UserAccess::Load));
        // Invalid: genuine fault regardless of other bits.
        let invalid = USER | READ | WRITE | EXECUTE;
        assert!(!pte_permits_user_access(invalid, UserAccess::Load));
    }

    #[test]
    fn svade_update_sets_accessed_for_a_load_or_fetch()
    {
        let harvested = VALID | USER | READ | EXECUTE | DIRTY;
        assert_eq!(
            svade_update(harvested, UserAccess::Load),
            Some(harvested | ACCESSED)
        );
        assert_eq!(
            svade_update(harvested, UserAccess::Fetch),
            Some(harvested | ACCESSED)
        );
        assert_eq!(svade_update(harvested | ACCESSED, UserAccess::Load), None);
    }

    #[test]
    fn svade_update_sets_accessed_and_dirty_for_a_store()
    {
        let rw = VALID | USER | READ | WRITE;
        assert_eq!(
            svade_update(rw, UserAccess::Store),
            Some(rw | ACCESSED | DIRTY)
        );
        assert_eq!(
            svade_update(rw | ACCESSED, UserAccess::Store),
            Some(rw | ACCESSED | DIRTY)
        );
        assert_eq!(svade_update(rw | ACCESSED | DIRTY, UserAccess::Store), None);
    }

    // ── Shootdown-elision classification ───────────────────────────────────────

    use crate::mm::paging::MapOutcome;

    const FRAME_A: u64 = 0x10_000;
    const FRAME_B: u64 = 0x20_000;

    /// The rights of a test leaf, as the classification cases need them.
    #[derive(Clone, Copy)]
    enum Rights
    {
        ReadOnly,
        Writable,
        Executable,
    }

    /// Raw leaf PTE bits: valid user page on `frame` with `rights`.
    fn leaf(frame: u64, rights: Rights) -> u64
    {
        let pte = VALID | USER | ((frame >> 12) << 10) | READ;
        match rights
        {
            Rights::ReadOnly => pte,
            Rights::Writable => pte | WRITE,
            Rights::Executable => pte | EXECUTE,
        }
    }

    #[test]
    fn classify_fresh_when_prior_invalid()
    {
        assert_eq!(
            classify_user_map(0, leaf(FRAME_A, Rights::Writable)),
            MapOutcome::Fresh
        );
    }

    #[test]
    fn classify_widen_when_adding_write_same_frame()
    {
        let prior = leaf(FRAME_A, Rights::ReadOnly); // R--
        let new = leaf(FRAME_A, Rights::Writable); // RW-
        assert_eq!(classify_user_map(prior, new), MapOutcome::Widen);
    }

    #[test]
    fn classify_widen_when_adding_exec_same_frame()
    {
        let prior = leaf(FRAME_A, Rights::ReadOnly); // R--
        let new = leaf(FRAME_A, Rights::Executable); // R-X
        assert_eq!(classify_user_map(prior, new), MapOutcome::Widen);
    }

    #[test]
    fn classify_widen_when_identical()
    {
        let pte = leaf(FRAME_A, Rights::Writable);
        assert_eq!(classify_user_map(pte, pte), MapOutcome::Widen);
    }

    #[test]
    fn classify_replace_when_narrowing_write()
    {
        let prior = leaf(FRAME_A, Rights::Writable); // RW-
        let new = leaf(FRAME_A, Rights::ReadOnly); // R--
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    #[test]
    fn classify_replace_when_narrowing_exec()
    {
        let prior = leaf(FRAME_A, Rights::Executable); // R-X
        let new = leaf(FRAME_A, Rights::ReadOnly); // R--
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    #[test]
    fn classify_replace_when_frame_changes()
    {
        let prior = leaf(FRAME_A, Rights::Writable);
        let new = leaf(FRAME_B, Rights::Writable);
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    // ── Leaf scan ─────────────────────────────────────────────────────────────

    /// A page-table frame on the host heap; its host address stands for its
    /// physical address (host addresses lie below bit 56, so `PPN_MASK` keeps
    /// them), and the scan reaches it through an identity translation.
    #[repr(C, align(4096))]
    struct Table([PageTableEntry; 512]);

    /// A user space under a mode, built on host frames: the path from the root
    /// to one level-1 table over the 1 GiB-aligned `base`, whose entry 0 and
    /// entry 2 name leaf tables and whose entry 1 is a megapage leaf over the
    /// bait, every entry of which is a valid user "leaf", so a scan that read a
    /// megapage's frame as a table would report them. Entry 2's table holds a
    /// NAPOT group in slots 16..32. `leaves` lists each leaf in VA order.
    struct Space
    {
        _boxes: Vec<Box<Table>>,
        root: u64,
        top: usize,
        base: u64,
        leaves: Vec<(u64, u64, u64)>,
    }

    impl Space
    {
        /// The end of the level-1 table's span: every leaf lies below it.
        fn hi(&self) -> u64
        {
            self.base + (1 << 30)
        }

        /// Scan `[start, hi)` with `budget`, taking every leaf until
        /// `refuse` names one; the leaves taken and where the scan stopped.
        fn scan(
            &self,
            start: u64,
            budget: usize,
            refuse: Option<u64>,
        ) -> (Vec<(u64, u64, u64)>, u64)
        {
            let mut got = Vec::new();
            let mut on_leaf = |va, pa, bits| {
                if refuse == Some(va)
                {
                    return false;
                }
                got.push((va, pa, bits));
                true
            };
            let mut scan = LeafScan {
                budget,
                to_virt: |pa| pa,
                on_leaf: &mut on_leaf,
            };
            // SAFETY: every table of the space is a live host frame reached
            // through its address (identity translation); the boxes are not
            // touched while the scan reads.
            let stop = unsafe { scan.table(self.root, self.top, start, self.hi()) };
            (got, stop.unwrap_or(self.hi()))
        }
    }

    fn base_for(mode: PagingMode) -> u64
    {
        match mode
        {
            PagingMode::Sv39 => 0x20_4000_0000,
            PagingMode::Sv48 => 0x7F_4000_0000,
            PagingMode::Sv57 => 0x00F0_7F40_4000_0000,
        }
    }

    fn space(mode: PagingMode) -> Space
    {
        let base = base_for(mode);
        let top = mode.levels() - 1;
        // The path's tables (root to level 1), two leaf tables, the bait.
        let mut boxes: Vec<Box<Table>> = (0..top + 3)
            .map(|_| Box::new(Table([PageTableEntry(0); 512])))
            .collect();
        let addr = |t: &Table| core::ptr::from_ref(t) as u64;
        let addrs: Vec<u64> = boxes.iter().map(|t| addr(t)).collect();
        let (l1, pt_a, pt_b, bait) = (top - 1, top, top + 1, top + 2);
        for (i, level) in (2..=top).rev().enumerate()
        {
            boxes[i].0[vpn_index(level, base)] = PageTableEntry::new_table(addrs[i + 1]);
        }
        let ppn = |pa: u64| (pa >> 2) & PPN_MASK;
        boxes[bait].0 = [PageTableEntry(VALID | READ | USER | ppn(addrs[bait])); 512];
        boxes[l1].0[0] = PageTableEntry::new_table(addrs[pt_a]);
        boxes[l1].0[1] = PageTableEntry(VALID | READ | USER | ppn(addrs[bait]));
        boxes[l1].0[2] = PageTableEntry::new_table(addrs[pt_b]);
        let mut leaves = Vec::new();
        for (pt, l1_index, slot, write) in [
            (pt_a, 0u64, 0usize, WRITE),
            (pt_a, 0, 1, WRITE),
            (pt_a, 0, 2, EXECUTE),
            (pt_a, 0, 511, 0),
            (pt_b, 2, 0, WRITE),
        ]
        {
            let va = base + (l1_index << 21) + ((slot as u64) << 12);
            let frame = 0x8000_0000 + ((slot as u64) << 12) + (l1_index << 24);
            let bits = VALID | READ | USER | write | ppn(frame);
            boxes[pt].0[slot] = PageTableEntry(bits);
            leaves.push((va, frame, bits));
        }
        // A 64 KiB NAPOT group over a 64 KiB-aligned base: each member carries
        // the base's PPN with the size encoding in ppn[3:0].
        let napot_base = 0x9000_0000u64;
        let member = VALID | READ | USER | PBMT_IO | NAPOT | ppn(napot_base) | NAPOT_64K_PPN;
        for (slot, entry) in boxes[pt_b].0.iter_mut().enumerate().skip(16).take(16)
        {
            *entry = PageTableEntry(member);
            let va = base + (2 << 21) + ((slot as u64) << 12);
            leaves.push((va, napot_base + ((slot as u64 - 16) << 12), member));
        }
        Space {
            _boxes: boxes,
            root: addrs[0],
            top,
            base,
            leaves,
        }
    }

    // The defects caught: a scan that misses a leaf, reports one out of VA
    // order or with another frame or bits, reports a NAPOT member's group
    // base instead of its own frame, or reads a megapage's frame as a table.
    #[test]
    fn a_leaf_scan_reports_every_valid_leaf_in_va_order()
    {
        for mode in ALL_MODES
        {
            let s = space(mode);
            let (got, stop) = s.scan(s.base, usize::MAX, None);
            assert_eq!(got, s.leaves, "{mode:?}");
            assert_eq!(stop, s.hi(), "{mode:?}");
            let (got, _) = s.scan(s.leaves[2].0, usize::MAX, None);
            assert_eq!(got, s.leaves[2..], "{mode:?}: a scan from a leaf's VA");
        }
    }

    // The defects caught: a budget that is not honoured, a resume VA that
    // skips a leaf or repeats one, or a resumed scan that makes no progress.
    #[test]
    fn a_budgeted_leaf_scan_resumes_where_it_stopped()
    {
        for mode in ALL_MODES
        {
            let s = space(mode);
            for budget in [s.top + 1, s.top + 2, s.top + 5, 64, 600]
            {
                let mut all = Vec::new();
                let mut start = s.base;
                while start < s.hi()
                {
                    let (got, stop) = s.scan(start, budget, None);
                    assert!(
                        stop > start,
                        "{mode:?} budget {budget}: no progress at {start:#x}"
                    );
                    all.extend(got);
                    start = stop;
                }
                assert_eq!(all, s.leaves, "{mode:?} budget {budget}");
            }
        }
    }

    // The defect caught: a refused leaf that is skipped instead of reported as
    // the place to resume.
    #[test]
    fn a_refused_leaf_stops_the_scan_at_its_va()
    {
        for mode in ALL_MODES
        {
            let s = space(mode);
            let (got, stop) = s.scan(s.base, usize::MAX, Some(s.leaves[4].0));
            assert_eq!(got, s.leaves[..4], "{mode:?}");
            assert_eq!(stop, s.leaves[4].0, "{mode:?}");
        }
    }
}
