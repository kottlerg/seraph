// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/paging.rs

//! x86-64 page table operations at the boot paging depth: four levels
//! (PML4 → PDPT → PD → PT) or, under `CR4.LA57`, five (a PML5 above them).
//!
//! The bootloader negotiates the depth and hands the kernel a running
//! translation regime; [`init_paging_mode`] recovers it from `CR4.LA57` at
//! entry, as the riscv64 layer recovers its mode from `satp`, and every walk
//! below starts at the root level that depth implies, so one kernel binary
//! supports both depths.
//!
//! [`map_page`] and [`map_large_page`] (kernel page-table construction) draw
//! intermediate frames from the [`PoolState`] the caller supplies: the
//! BSS-resident seed, reached through the kernel image, then the Phase 3 carve
//! of RAM, reached through the direct map; [`PoolState::phys_to_virt`]
//! resolves a frame of either. The user-mapping functions
//! draw them from `crate::mm::kernel_pt_pool` ([`map_user_page`]) or the
//! address space's growth pool ([`map_user_page_pooled`]).
//!
//! # Index layout (level n reads VA bits \[20 + 9n : 12 + 9n\])
//! - Level 4: bits \[56:48\] → PML5 index (512 entries × 256 TiB each; 5-level only)
//! - Level 3: bits \[47:39\] → PML4 index (512 entries × 512 GiB each)
//! - Level 2: bits \[38:30\] → PDPT index (512 entries × 1 GiB each)
//! - Level 1: bits \[29:21\] → PD index   (512 entries × 2 MiB each)
//! - Level 0: bits \[20:12\] → PT index   (512 entries × 4 KiB each)

// similar_names: root_va/root_pa and repeated e shadowing are intentional page-table idioms.
// cast_possible_truncation: u64→u32 EFER register splits; values are bounded by shift width.
#![allow(clippy::similar_names, clippy::cast_possible_truncation)]

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub use boot_protocol::x86_paging::PagingDepth;
#[cfg(not(test))]
use boot_protocol::x86_paging::next_level_boundary;
use boot_protocol::x86_paging::table_index;

use crate::mm::paging::{PageFlags, PagingError, PoolState};

// ── PTE bit constants ─────────────────────────────────────────────────────────

/// Entry is valid; must be set for all live entries.
const PRESENT: u64 = 1 << 0;
/// Read/Write — 1 allows writes, 0 makes the mapping read-only.
const WRITABLE: u64 = 1 << 1;
/// Page Write-Through — used with PCD to select strong uncacheable memory type.
const PWT: u64 = 1 << 3;
/// Page Cache Disable — with PWT clear it selects UC- (PAT entry 2); combined
/// with PWT it selects strong UC (PAT entry 3) under the power-on default PAT,
/// which the kernel does not reprogram.
const PCD: u64 = 1 << 4;
/// Page Size (PS) — set in a PDE/PDPTE to make it a large-page leaf.
const LARGE_PAGE: u64 = 1 << 7;
/// No-Execute — blocks instruction fetch; requires `IA32_EFER.NXE` = 1.
const NO_EXECUTE: u64 = 1 << 63;
/// Software bit (AVL, ignored by hardware in every entry type) that
/// `user_walk_or_alloc_pooled` sets in a table-pointer entry whose table frame
/// came from the address space's own page-table pool; `unmap_user_region_pooled`
/// gates reclamation on it. See
/// [memory-internals.md](../../../docs/memory-internals.md) § Page Table Node
/// Ownership.
const POOLED_TABLE: u64 = 1 << 9;
/// Mask extracting the physical page number from bits \[51:12\].
const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ── PageTableEntry ────────────────────────────────────────────────────────────

/// A 64-bit x86-64 page table entry (PML5E, PML4E, PDPTE, PDE, or PTE).
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
            // PCD|PWT selects PAT entry 3, the strong uncacheable (UC) memory type
            // under the power-on default PAT (the kernel does not reprogram
            // IA32_PAT). Required for MMIO mappings.
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

// ── Entry classification ───────────────────────────────────────────────────────

/// Whether `e`, an entry of a table at `level`, names a child table: it is
/// present and is not a large-page leaf (PS set in a PDPTE, level 2, or a
/// PDE, level 1). PML4 and PML5 entries have no PS bit.
fn names_table(e: PageTableEntry, level: usize) -> bool
{
    e.is_present() && (level > 2 || e.0 & LARGE_PAGE == 0)
}

// ── Table frame access ────────────────────────────────────────────────────────

/// Reinterpret a 4 KiB pool frame as an array of 512 PTEs.
///
/// # Safety
/// `frame_va` must be the virtual address of a valid, writable, 4 KiB-aligned
/// pool frame. No other mutable reference to the same frame may exist.
unsafe fn table_at(frame_va: u64) -> &'static mut [PageTableEntry; 512]
{
    // SAFETY: per the caller contract, frame_va is the VA (direct-map or boot-pool)
    // of a valid, writable, 4 KiB-aligned page-table frame with no other live
    // mutable reference.
    unsafe { &mut *(frame_va as *mut [PageTableEntry; 512]) }
}

// ── Level descent ─────────────────────────────────────────────────────────────

/// Descend from the table at `root_va` (level `top`) to the table at level
/// `stop`, resolving-or-allocating a child at each level in `(stop, top]` via
/// `ensure`. `ensure` returns the child table's *virtual* address, so each
/// caller supplies its own PA→VA translation alongside its allocator.
///
/// # Safety
/// `root_va` must be the VA of a valid, exclusively-owned table frame at
/// level `top`, and `ensure` must return the VA of a valid, exclusively-owned
/// table frame for every entry it is handed.
unsafe fn descend_alloc<E>(
    root_va: u64,
    virt: u64,
    top: usize,
    stop: usize,
    mut ensure: impl FnMut(&mut PageTableEntry) -> Result<u64, E>,
) -> Result<&'static mut [PageTableEntry; 512], E>
{
    // SAFETY: root_va is a valid exclusively-owned table frame (caller contract).
    let mut table = unsafe { table_at(root_va) };
    for level in (stop + 1..=top).rev()
    {
        let child_va = ensure(&mut table[table_index(level, virt)])?;
        // SAFETY: ensure returned the VA of a valid exclusively-owned table frame.
        table = unsafe { table_at(child_va) };
    }
    Ok(table)
}

/// Walk existing tables from `root_va` (level `top`) down to level `stop`,
/// translating child physical addresses through `to_virt`. Returns `None`
/// when an entry on the path is absent or is a large-page leaf
/// ([`names_table`]): a leaf's frame holds data, not a child table, and must
/// not be descended.
///
/// # Safety
/// `root_va` must be the VA of a valid table frame at level `top` whose
/// reachable child frames are all live; `to_virt` must map their physical
/// addresses to valid VAs, and no other reference to a table on the path may
/// be live while the returned one is.
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
    for level in (stop + 1..=top).rev()
    {
        let e = table[table_index(level, virt)];
        if !names_table(e, level)
        {
            return None;
        }
        // SAFETY: a present non-leaf entry points at a live child table frame.
        table = unsafe { table_at(to_virt(e.phys_addr())) };
    }
    Some(table)
}

// ── Mapping functions ─────────────────────────────────────────────────────────

/// Map VA `virt` → PA `phys` as a 4 KiB page with `flags`.
///
/// Walks from the root (PML5 or PML4) to the PT, allocating missing
/// intermediate tables from `pool`. `root_va` is the virtual address of the
/// root frame.
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
    // SAFETY: root_va is the VA of the kernel root under construction, a frame
    // `pool` handed out (caller's contract); every child is a table frame
    // `pool` handed out, which PoolState::phys_to_virt resolves (a seed frame
    // through the image, a carve frame through the direct map, which stage 1
    // maps over the carve).
    let pt = unsafe {
        descend_alloc(root_va, virt, root_level(), 0, |e| {
            walk_or_alloc(e, pool).map(|pa| pool.phys_to_virt(pa))
        })?
    };
    pt[table_index(0, virt)] = PageTableEntry::new_page(phys, flags);
    Ok(())
}

/// Map VA `virt` → PA `phys` as a 2 MiB large page with `flags`.
///
/// Walks from the root to the PD, allocating missing tables from `pool`, then
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
    // SAFETY: as in map_page.
    let pd = unsafe {
        descend_alloc(root_va, virt, root_level(), 1, |e| {
            walk_or_alloc(e, pool).map(|pa| pool.phys_to_virt(pa))
        })?
    };
    pd[table_index(1, virt)] = PageTableEntry::new_large_page(phys, flags);
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
// Most functions below use privileged instructions and are gated
// `#[cfg(not(test))]` (with `#[cfg(test)]` stubs where host tests need the
// symbol); the direct-map base accessors, `user_va_top`, and
// `read_stack_pointer` also build in test builds and must not be called from
// host tests that would execute their asm.

// ── Boot paging depth ─────────────────────────────────────────────────────────

/// Level count of the paging depth this CPU booted under.
///
/// Written once by [`init_paging_mode`] at kernel entry, before any consumer
/// runs and before APs start (INIT/SIPI provides the happens-before for
/// secondary CPUs, which enter at the BSP's depth); read lock-free everywhere
/// after. The 4-level default keeps host unit tests deterministic without an
/// init call.
static PAGING_LEVELS: AtomicU8 = AtomicU8::new(PagingDepth::Four as u8);

/// Virtual base of the direct physical map, published once by
/// [`init_paging_mode`] from the bootloader's (possibly KASLR-randomized)
/// `BootInfo.direct_map_base`, with the same ordering as [`PAGING_LEVELS`].
/// The default is the 4-level kernel-half floor.
static DIRECT_MAP_BASE_VAL: AtomicU64 = AtomicU64::new(PagingDepth::Four.kernel_va_base());

/// The active depth's exclusive user-mappable top ([`user_va_top`]), resolved
/// at [`init_paging_mode`].
static USER_VA_TOP_VAL: AtomicU64 = AtomicU64::new(PagingDepth::Four.user_va_top());

/// The active depth's exclusive top of the lower canonical half
/// (`1 << 47` or `1 << 56`), resolved at [`init_paging_mode`]. A user RIP at
/// or above it is non-canonical; `syscall_entry` reads it to divert such a
/// return RIP away from `sysretq`.
pub(super) static USER_CANONICAL_LIMIT: AtomicU64 =
    AtomicU64::new(PagingDepth::Four.canonical_user_limit());

/// Publish the paging depth and the direct-map base at kernel entry.
///
/// The bootloader hands the kernel a running translation regime, so
/// `CR4.LA57` is the authoritative record of the negotiated depth. The
/// direct-map base comes from `BootInfo`: the depth's kernel-half floor, or
/// a randomized base above it (KASLR). Halts on a base below that floor or
/// not 1 GiB-aligned; this runs pre-console, matching the silent-halt policy
/// of `BootInfo` validation.
#[cfg(not(test))]
pub fn init_paging_mode(info: &boot_protocol::BootInfo)
{
    let depth = PagingDepth::from_cr4(super::cpu::read_cr4());
    let base = info.direct_map_base;
    if base < depth.kernel_va_base() || !base.is_multiple_of(1 << 30)
    {
        super::cpu::halt_loop();
    }
    PAGING_LEVELS.store(depth as u8, Ordering::Relaxed);
    DIRECT_MAP_BASE_VAL.store(base, Ordering::Relaxed);
    USER_VA_TOP_VAL.store(depth.user_va_top(), Ordering::Relaxed);
    USER_CANONICAL_LIMIT.store(depth.canonical_user_limit(), Ordering::Relaxed);
}

/// Test-build stub: host unit tests run with the 4-level defaults.
#[cfg(test)]
pub fn init_paging_mode(_info: &boot_protocol::BootInfo) {}

/// The paging depth published at kernel entry.
pub fn paging_depth() -> PagingDepth
{
    // The store site only writes PagingDepth discriminants, so the decode
    // cannot fail.
    match PagingDepth::from_levels(PAGING_LEVELS.load(Ordering::Relaxed))
    {
        Some(depth) => depth,
        None => unreachable!(),
    }
}

/// Exclusive top of the active depth's lower canonical half: `1 << 47`, or
/// `1 << 56` under `CR4.LA57`. A user RIP or RSP at or above it is
/// non-canonical.
#[inline]
pub fn user_canonical_limit() -> u64
{
    USER_CANONICAL_LIMIT.load(Ordering::Relaxed)
}

/// Level of the root table under the active depth: 4 (PML5) or 3 (PML4).
fn root_level() -> usize
{
    paging_depth().levels() - 1
}

/// Base virtual address of the direct physical map: at or above the active
/// depth's kernel-half floor, as published from `BootInfo` (KASLR).
#[inline]
pub fn direct_map_base() -> u64
{
    DIRECT_MAP_BASE_VAL.load(Ordering::Relaxed)
}

/// Exclusive upper bound of user-accessible virtual addresses: the active
/// depth's lower canonical half (`1 << 47`, or `1 << 56` under `CR4.LA57`)
/// less its top 4 KiB page.
///
/// The top page stays unmappable, as Linux's `TASK_SIZE_MAX` keeps it, so no
/// user instruction can end at the canonical boundary: the hardware-saved
/// return RIP of a ring-3 interrupt, trap, or `syscall` (the address after the
/// last executed instruction) is then always canonical, and every ring-3
/// `iretq` / `sysretq` is to a canonical RIP. A RIP at the boundary would
/// raise `#GP` in ring 0 after the exit's `swapgs` back to the user GS base,
/// where the CS-keyed `#GP` stub would run kernel code on that base.
#[inline]
pub fn user_va_top() -> u64
{
    USER_VA_TOP_VAL.load(Ordering::Relaxed)
}

/// Write CR3 without an explicit TLB flush.
///
/// On x86-64 without PCID, writing CR3 implicitly flushes the TLB, so this
/// is functionally identical to [`activate`]. Provided for cross-arch API
/// compatibility with RISC-V where `satp` can be written without `sfence.vma`.
///
/// # Safety
/// `root_phys` must be a valid root table (PML5 or PML4) with correct kernel mappings.
#[cfg(not(test))]
pub unsafe fn write_satp_no_fence(root_phys: u64)
{
    // With PCID enabled, load the kernel root under PCID 0 without flushing
    // (CR3 bit 63). Kernel translations are identical across roots, so retaining
    // PCID 0's cached entries across this transition is correct and avoids a
    // flush. Without PCID a CR3 write always flushes, so this degrades to the
    // flushing form (functionally equivalent to `activate`).
    // SAFETY: root_phys is a valid kernel root per caller contract.
    unsafe {
        if crate::mm::tag_allocator::tagging_enabled()
        {
            activate_tagged(root_phys, 0);
        }
        else
        {
            activate(root_phys);
        }
    }
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
    // SAFETY: cr3 write changes active page table; root_phys is a valid root frame.
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) root_phys,
            options(nostack),
        );
    }
}

/// Activate the page tables rooted at `root_phys` under PCID `tag` **without
/// flushing** the TLB.
///
/// Writes CR3 with the PCID in bits \[11:0\] and bit 63 set, which (with
/// `CR4.PCIDE = 1`) requests "do not invalidate" — cached translations for
/// `tag` and every other PCID are retained (Intel SDM Vol. 3A §4.10.4.1). This
/// is the context-switch fast path: the outgoing space's translations survive.
///
/// # Safety
/// Must execute at ring 0 with `CR4.PCIDE` set. `root_phys` must be a valid
/// root frame (4 KiB-aligned, low 12 bits zero). The tables must map the
/// currently executing code, the active stack, and all data accessed
/// immediately after this call. The caller is responsible for any tag
/// invalidation required for correctness (the generation check in
/// `AddressSpace::activate`).
#[cfg(not(test))]
pub unsafe fn activate_tagged(root_phys: u64, tag: u16)
{
    // Bit 63 = no-invalidate request (valid only when CR4.PCIDE = 1); the PCID
    // occupies bits [11:0]; root_phys supplies bits [51:12] with low bits zero.
    let cr3 = root_phys | u64::from(tag) | (1u64 << 63);
    // SAFETY: CR3 write changes the active page table; root_phys is a valid
    // root frame with zero low bits; PCIDE is set so bit 63 is honoured as the
    // no-flush request rather than faulting.
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) cr3,
            options(nostack),
        );
    }
}

/// Per-CPU enable of PCID-tagged TLBs: set `CR4.PCIDE` and report the number of
/// hardware tags (PCIDs) available, or `0` when PCID/INVPCID are unsupported.
///
/// Called on the BSP and every AP. On the BSP the returned count seeds the tag
/// pool; on every CPU it sets `CR4.PCIDE`, required before any tagged CR3 load.
///
/// # Safety
/// Must execute at ring 0 with the kernel root in CR3 (low 12 bits zero), at
/// most once per CPU, before any tagged CR3 load.
#[cfg(not(test))]
pub unsafe fn enable_tagged_tlb() -> usize
{
    // SAFETY: caller's contract (ring 0, kernel root in CR3).
    if unsafe { super::cpu::enable_pcid() }
    {
        // 12-bit PCID field ⇒ 4096 tags; tag 0 is reserved for kernel/fallback.
        4096
    }
    else
    {
        0
    }
}

/// No-op on x86-64: this arch has no boot-gated paging extensions beyond
/// the baseline already asserted by `cpu::verify_baseline` and
/// [`enable_nx`]. The riscv64 implementation refuses hardware lacking
/// Svpbmt/Svinval/Svnapot here.
#[cfg(not(test))]
pub unsafe fn verify_paging_extensions() {}

/// Enable No-Execute by setting `IA32_EFER.NXE` (bit 11) via RDMSR/WRMSR.
///
/// Must be called before activating page tables that use the NX bit,
/// because bit 63 of a PTE is "reserved" when NXE = 0.
///
/// # Safety
/// Must execute at privilege level 0. Does not check CPUID: NX is a required
/// feature gated by `cpu::verify_baseline` (see
/// [platform-requirements.md](../../../../../docs/platform-requirements.md)
/// § x86-64 Classification).
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
/// Adds `direct_map_base` to RSP, switching from VA == PA to
/// VA == `direct_map_base` + PA. Both mappings cover the same physical
/// frames; this eliminates the 64 KiB identity-map limit.
///
/// # Safety
/// Must be called exactly once, immediately after `activate`, while the
/// boot stack identity mapping is still valid. `direct_map_base` must be
/// the base of a direct physical map that covers all of physical RAM.
///
/// # Codegen invariant — `#[inline(never)]` plus no `options(nostack)`
/// Rust inline asm cannot list RSP as an output (it's a reserved
/// register), so LLVM has no formal channel to learn that the
/// `add rsp, {base}` body modifies RSP. If LLVM inlines this function
/// into the caller (`kernel_entry`), it freely hoists any RSP-relative
/// local-address materialisation (`lea reg, [rsp + imm]`) to *before*
/// the rebase, producing a stale low-VA pointer the kernel page tables
/// do not cover. The next dereference page-faults. riscv64's
/// `rebase_boot_stack` has the same hazard and the same fix.
///
/// `#[inline(never)]` is the fix: an opaque function call is an
/// optimisation barrier the scheduler cannot move ops across, so every
/// RSP-derived expression in the caller materialises on the correct
/// side of the rebase. Dropping `options(nostack)` is belt-and-braces.
#[cfg(not(test))]
#[inline(never)]
pub unsafe fn rebase_boot_stack(direct_map_base: u64)
{
    // SAFETY: adding the direct-map offset to RSP switches to the same
    // physical memory through the direct map virtual range. Both the
    // identity mapping (old) and direct map (new) are valid at this point.
    unsafe {
        core::arch::asm!(
            "add rsp, {base}",
            base = in(reg) direct_map_base,
        );
    }
}

/// No-op test stub.
#[cfg(test)]
pub unsafe fn rebase_boot_stack(_direct_map_base: u64) {}

/// Read the current page table root physical address from CR3.
///
/// Returns the physical address of the active root table. Strips the low
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
/// `root_virt`, drawing missing intermediate frames from
/// `crate::mm::kernel_pt_pool`.
///
/// Returns the [`MapOutcome`](crate::mm::paging::MapOutcome) classifying the
/// rewrite so the caller can decide whether a remote shootdown is required.
///
/// # Errors
/// Returns `Err(())` if the kernel PT pool is exhausted.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB root
/// frame (PML5 or PML4). `virt` must be in the lower (user) half. `phys` must be 4 KiB-aligned.
#[cfg(not(test))]
pub unsafe fn map_user_page(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
) -> Result<crate::mm::paging::MapOutcome, ()>
{
    use crate::mm::paging::phys_to_virt;

    // Set USER bit (bit 2) so ring-3 code can access the page.
    const USER: u64 = 1 << 2;

    // SAFETY: root_virt is the direct-map VA of a valid user root (caller
    // contract); every child user_walk_or_alloc yields is a kernel PT-pool
    // frame, reachable through the direct map.
    let pt = unsafe {
        descend_alloc(root_virt, virt, root_level(), 0, |e| {
            user_walk_or_alloc(e).map(phys_to_virt)
        })?
    };

    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER;
    let prior = pt[table_index(0, virt)].0;
    pt[table_index(0, virt)] = pte;

    Ok(classify_user_map(prior, pte.0))
}

/// Walk an existing page table entry or allocate a new child frame from the
/// kernel PT pool (`crate::mm::kernel_pt_pool`).
#[cfg(not(test))]
fn user_walk_or_alloc(entry: &mut PageTableEntry) -> Result<u64, ()>
{
    // Set USER bit so lower-level tables are accessible from ring 3.
    const USER: u64 = 1 << 2;

    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    // Pool returns zero-filled pages; no further write_bytes needed.
    let frame_pa = crate::mm::kernel_pt_pool::alloc_pt_page().ok_or(())?;

    let mut table_pte = PageTableEntry::new_table(frame_pa);
    table_pte.0 |= USER;
    *entry = table_pte;

    Ok(frame_pa)
}

/// Map a single 4 KiB user page, drawing intermediate page-table frames from
/// an `AddressSpaceObject`'s growth pool instead of the kernel page-table
/// pool.
///
/// Each new PT page is charged to the AS's growth budget; exhaustion returns
/// `Err(())` (see [capability-model.md](../../../../../docs/capability-model.md)
/// § Address-space and `CSpace` growth budgets).
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
) -> Result<crate::mm::paging::MapOutcome, ()>
{
    use crate::mm::paging::phys_to_virt;
    const USER: u64 = 1 << 2;

    // SAFETY: root_virt is the direct-map VA of a valid user root (caller
    // contract); every child user_walk_or_alloc_pooled yields is a frame of
    // aso's pool, reachable through the direct map.
    let pt = unsafe {
        descend_alloc(root_virt, virt, root_level(), 0, |e| {
            user_walk_or_alloc_pooled(e, aso).map(phys_to_virt)
        })?
    };

    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER;
    let prior = pt[table_index(0, virt)].0;
    pt[table_index(0, virt)] = pte;

    Ok(classify_user_map(prior, pte.0))
}

/// Pooled equivalent of [`user_walk_or_alloc`]: pulls a freshly-zeroed PT
/// frame from the AS's growth pool when an entry is absent.
#[cfg(not(test))]
fn user_walk_or_alloc_pooled(
    entry: &mut PageTableEntry,
    aso: &crate::cap::object::AddressSpaceObject,
) -> Result<u64, ()>
{
    const USER: u64 = 1 << 2;

    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    let frame_pa = aso.alloc_pt_page().ok_or(())?;

    let mut table_pte = PageTableEntry::new_table(frame_pa);
    table_pte.0 |= USER | POOLED_TABLE;
    *entry = table_pte;

    Ok(frame_pa)
}

/// Whether a per-VA invalidation ([`flush_page`], [`inval_page`]) also drops the
/// paging-structure-cache entries that name a freed intermediate table. True on
/// x86-64: `invlpg` invalidates every paging-structure-cache entry of the current
/// PCID.
pub const VA_INVAL_DROPS_TABLE_CACHES: bool = true;

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

// ── Tagged (PCID) invalidation ────────────────────────────────────────────────
// INVPCID lets a CPU invalidate translations tagged with an arbitrary PCID,
// independent of the PCID currently loaded in CR3. Used by the tagged-TLB path
// for per-VA remote shootdown (type 0) and whole-tag flush (type 1).

/// INVPCID type 0: invalidate one linear address within one PCID.
const INVPCID_TYPE_ADDR: u64 = 0;
/// INVPCID type 1: invalidate all non-global entries of one PCID.
const INVPCID_TYPE_SINGLE: u64 = 1;

/// 128-bit INVPCID descriptor (Intel SDM Vol. 2A, "INVPCID").
///
/// First qword: PCID in bits \[11:0\], bits \[63:12\] reserved (must be zero).
/// Second qword: the linear address (ignored for type 1).
///
/// `dead_code`: the fields are consumed by `invpcid` through a pointer in inline
/// asm, which the lint cannot see as a read.
#[allow(dead_code)]
#[repr(C, align(16))]
struct InvpcidDescriptor
{
    pcid: u64,
    linear_addr: u64,
}

/// Execute `invpcid` with the given invalidation `kind` and descriptor.
///
/// # Safety
/// Must execute at ring 0 with `CR4.PCIDE` set; the descriptor's reserved bits
/// must be zero.
#[cfg(not(test))]
unsafe fn invpcid(kind: u64, desc: &InvpcidDescriptor)
{
    // SAFETY: invpcid is a ring-0 TLB primitive; desc is a valid 16-byte
    // descriptor with reserved bits zero (constructed by the callers below).
    // The asm reads the descriptor memory, so no nomem/readonly is asserted.
    unsafe {
        core::arch::asm!(
            "invpcid {kind}, [{desc}]",
            kind = in(reg) kind,
            desc = in(reg) desc,
            options(nostack),
        );
    }
}

/// Invalidate the TLB entry for `virt` tagged with PCID `tag` on the current
/// CPU (INVPCID type 0), regardless of the PCID currently loaded in CR3.
///
/// # Safety
/// Must execute at ring 0 with `CR4.PCIDE` set.
#[cfg(not(test))]
pub unsafe fn flush_page_tagged(virt: u64, tag: u16)
{
    let desc = InvpcidDescriptor {
        pcid: u64::from(tag),
        linear_addr: virt,
    };
    // SAFETY: ring 0 with PCIDE set (caller contract); well-formed type-0 descriptor.
    unsafe {
        invpcid(INVPCID_TYPE_ADDR, &desc);
    }
}

/// Invalidate all non-global TLB entries tagged with PCID `tag` on the current
/// CPU (INVPCID type 1). Used when a tag is (re)assigned to a new address space
/// or when a switched-away space accrued unmaps while this CPU was elsewhere.
///
/// # Safety
/// Must execute at ring 0 with `CR4.PCIDE` set.
#[cfg(not(test))]
pub unsafe fn flush_tag(tag: u16)
{
    let desc = InvpcidDescriptor {
        pcid: u64::from(tag),
        linear_addr: 0,
    };
    // SAFETY: ring 0 with PCIDE set (caller contract); well-formed type-1 descriptor.
    unsafe {
        invpcid(INVPCID_TYPE_SINGLE, &desc);
    }
}

// ── Batched invalidation ──────────────────────────────────────────────────────
// x86-64 has no deferred-invalidation instructions: `invlpg` and INVPCID are
// individually complete, so the batch brackets are no-ops and the per-VA
// calls delegate to the single-VA primitives. The surface exists for the
// riscv64 Svinval sequence (`sfence.w.inval; sinval.vma …; sfence.inval.ir`).

/// Open a batched-invalidation window. No-op on x86-64.
///
/// # Safety
/// Must execute at ring 0 (for symmetry with the riscv64 contract).
#[cfg(not(test))]
pub unsafe fn inval_batch_begin() {}

/// Invalidate `virt` inside an open batch window — `invlpg`, identical to
/// [`flush_page`].
///
/// # Safety
/// As [`flush_page`].
#[cfg(not(test))]
pub unsafe fn inval_page(virt: u64)
{
    // SAFETY: caller contract matches flush_page.
    unsafe { flush_page(virt) }
}

/// Invalidate `virt` within PCID `tag` inside an open batch window —
/// INVPCID type 0, identical to [`flush_page_tagged`].
///
/// # Safety
/// As [`flush_page_tagged`].
#[cfg(not(test))]
pub unsafe fn inval_page_tagged(virt: u64, tag: u16)
{
    // SAFETY: caller contract matches flush_page_tagged.
    unsafe { flush_page_tagged(virt, tag) }
}

/// Close a batched-invalidation window. No-op on x86-64.
///
/// # Safety
/// Must execute at ring 0, paired with a preceding [`inval_batch_begin`].
#[cfg(not(test))]
pub unsafe fn inval_batch_end() {}

/// Remove a single user-space mapping at `virt` from the page table rooted at
/// `root_virt`.
///
/// Walks from the root to the PT. If any intermediate level is not present,
/// returns immediately (nothing to unmap). On reaching the leaf, zeros the
/// PTE and calls `flush_page`.
///
/// Intermediate page table frames are left in place even if they become
/// empty; the reclaiming span path is [`unmap_user_region_pooled`] (see
/// [memory-internals.md](../../../docs/memory-internals.md) § Page Table Node
/// Ownership).
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB root
/// frame. Called from a kernel context with the frame allocator lock NOT held
/// (this function does not allocate).
#[cfg(not(test))]
pub unsafe fn unmap_user_page(root_virt: u64, virt: u64)
{
    use crate::mm::paging::phys_to_virt;

    // SAFETY: root_virt is the direct-map VA of a valid user root (caller
    // contract); its reachable child frames are live PT frames.
    let Some(pt) = (unsafe { descend_existing(root_virt, virt, root_level(), 0, phys_to_virt) })
    else
    {
        return;
    };
    pt[table_index(0, virt)] = PageTableEntry(0);

    // SAFETY: invlpg flushes TLB entry for specified VA; architecture primitive.
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
/// `aso`'s page-table growth pool. Returns the number of non-root table frames
/// freed. Passes the frame of each present leaf it clears to `on_leaf`, in VA
/// order, after the clear.
///
/// Walks from the root (PML5 or PML4) to the PT over the span, clearing
/// in-range leaf PTEs. A table is freed only when it is fully empty afterwards
/// **and** its parent entry carries [`POOLED_TABLE`] (the frame came from
/// `aso`'s pool) — emptiness, not span-containment, is the gate, so a boundary
/// table shared with a live neighbour (or the guard-page table whose first
/// slot sits just outside the span) is reclaimed exactly when its last live
/// entry clears. Large-page leaves (1 GiB / 2 MiB) are not produced by the
/// user mapping path; they are skipped (never descended, never freed), so a
/// table holding one is never seen as empty. The root frame is never freed.
///
/// Issues no TLB flush: the caller (`AddressSpace::unmap_region_pooled`)
/// invalidates the span's TLB and paging-structure-cache entries on every CPU
/// running the space while holding `pt_lock`, so a freed frame cannot be popped
/// and reused before every CPU is coherent (see
/// [memory-internals.md](../../../docs/memory-internals.md) § TLB Management).
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

    let virt_end = virt_base + page_count as u64 * PAGE_SIZE as u64;
    let mut freed = 0usize;

    // SAFETY: root_virt is the direct-map VA of a valid user root (caller's
    // contract).
    let root = unsafe { table_at(root_virt) };
    // SAFETY: root is a live table at the root level; aso wraps this page
    // table and the caller holds its pt_lock (caller's contract).
    unsafe {
        unmap_span(
            root,
            root_level(),
            virt_base,
            virt_end,
            aso,
            &mut freed,
            on_leaf,
        );
    }
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

    if level == 0
    {
        let mut va = lo;
        while va < hi
        {
            let leaf = table[table_index(0, va)];
            table[table_index(0, va)] = PageTableEntry(0);
            if leaf.is_present()
            {
                on_leaf(leaf.phys_addr());
            }
            va += PAGE_SIZE as u64;
        }
        return;
    }

    let mut va = lo;
    while va < hi
    {
        let entry_end = hi.min(next_level_boundary(level, va));
        let idx = table_index(level, va);
        let e = table[idx];
        // Skip large-page leaves (not produced by the user path).
        if names_table(e, level)
        {
            let child_pa = e.phys_addr();
            // SAFETY: a present non-leaf entry points at a live child table.
            let child = unsafe { table_at(phys_to_virt(child_pa)) };
            // SAFETY: child is a live table at level - 1; same aso/pt_lock
            // guarantees as this call.
            unsafe { unmap_span(child, level - 1, va, entry_end, aso, freed, on_leaf) };
            if table_is_empty(child) && e.0 & POOLED_TABLE != 0
            {
                table[idx] = PageTableEntry(0);
                // SAFETY: child is empty and unlinked above; frame came from
                // this aso's pool (POOLED_TABLE).
                unsafe { aso.free_pt_page(child_pa) };
                *freed += 1;
            }
        }
        va = entry_end;
    }
}

/// Pass the frame of every present 4 KiB leaf in the user half (root slots
/// 0..256, below the active depth's canonical split) of the page table rooted
/// at `root_virt` to `on_leaf`, changing nothing. Large-page leaves are
/// skipped, as in [`unmap_user_region_pooled`]: the user mapping path never
/// installs one.
///
/// Drives the frame-map release of an address space's teardown
/// (`AddressSpace::release_mapped_frames`).
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB root frame whose
/// tables no other CPU modifies during the walk.
#[cfg(not(test))]
pub unsafe fn for_each_user_leaf(root_virt: u64, on_leaf: &mut dyn FnMut(u64))
{
    let limit = USER_CANONICAL_LIMIT.load(Ordering::Relaxed);
    // SAFETY: root_virt is the direct-map VA of a valid root (caller's contract).
    let root = unsafe { table_at(root_virt) };
    // SAFETY: root is a live table at the root level, unmodified meanwhile.
    unsafe { walk_leaves(root, root_level(), 0, limit, on_leaf) };
}

/// Pass the frame of every present leaf of `[lo, hi)` under `table` (a table
/// at `level`) to `on_leaf`. Bounded recursion: `level <= 4`.
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
    on_leaf: &mut dyn FnMut(u64),
)
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    let mut va = lo;
    while va < hi
    {
        let e = table[table_index(level, va)];
        if level == 0
        {
            if e.is_present()
            {
                on_leaf(e.phys_addr());
            }
            va += PAGE_SIZE as u64;
            continue;
        }
        let entry_end = hi.min(next_level_boundary(level, va));
        if names_table(e, level)
        {
            // SAFETY: a present non-leaf entry points at a live child table.
            let child = unsafe { table_at(phys_to_virt(e.phys_addr())) };
            // SAFETY: child is a live table at level - 1 (this call's contract).
            unsafe { walk_leaves(child, level - 1, va, entry_end, on_leaf) };
        }
        va = entry_end;
    }
}

/// x86-64 implementation of [`crate::mm::paging::unmap_identity_page`].
///
/// Walks the kernel root from `phys_to_virt(kernel_root_table_pa())` down to
/// the leaf PT covering `pa` and clears the leaf entry. Bails silently if any
/// intermediate level is absent (the mapping was already torn down or
/// never installed) or is a large-page leaf (clearing a 4 KiB region inside
/// one would corrupt the leaf's physical range). Issues a local `invlpg`, then broadcasts a TLB
/// shootdown to every other online CPU.
///
/// Intermediate tables are NOT freed — they may host other low-VA mappings
/// (additional trampoline pages, future low-PA identity entries).
#[cfg(not(test))]
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
    // Phase 3; the walk is read-only until the leaf clear below.
    let Some(pt) = (unsafe { descend_existing(root_va, virt, root_level(), 0, phys_to_virt) })
    else
    {
        return;
    };
    pt[table_index(0, virt)] = PageTableEntry(0);

    // Local invalidate, then broadcast to every other online CPU. The
    // shootdown routine requires preemption disabled and handles the
    // interrupt window for mutual shootdown itself.
    // SAFETY: invlpg is a per-CPU architectural primitive; shootdown
    // contract met by acquiring preemption around the broadcast.
    unsafe { flush_page(virt) };

    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let remote = crate::cpu_mask::MaskSource::Below(cpu_count);
    crate::percpu::preempt_disable();
    // SAFETY: root_pa is the active kernel root; remote names only online CPUs
    // (the shootdown leaves this one out, and returns at once when it is the
    // only one); preemption disabled around the shootdown. Tag 0: this is a
    // kernel identity mapping torn down at boot, not a tagged user space.
    unsafe { crate::mm::tlb_shootdown::shootdown(root_pa, &remote, virt, 0) };
    crate::percpu::preempt_enable();
}

// ── Direct-map holes ──────────────────────────────────────────────────────────
// A guard page below a kernel stack (`crate::mm::stack_guard`) is a hole in
// the direct map: one 4 KiB entry left not present. The 2 MiB leaf that maps
// a guard's chunk is first split into a leaf table of the same translation.
// `stack_guard` serialises every edit and flushes the TLB.

/// Direct-map flags of a RAM page: read-write, never executable, write-back
/// (`mm::paging::init_kernel_page_tables` maps RAM so).
const DIRECT_RAM: PageFlags = PageFlags {
    readable: true,
    writable: true,
    executable: false,
    uncacheable: false,
};

/// Fill `table` with the 512 4 KiB direct-map entries of the 2 MiB chunk at
/// `chunk`: the translation of the large leaf it replaces.
fn split_chunk_entries(table: &mut [PageTableEntry; 512], chunk: u64)
{
    crate::mm::paging::fill_split_table(table, chunk, |phys| {
        PageTableEntry::new_page(phys, DIRECT_RAM)
    });
}

/// Leave the direct-map page at `virt` not present. When a 2 MiB leaf maps
/// it, the leaf is first replaced by a leaf table with the same translation,
/// built in the frame `take_table` returns.
///
/// # Errors
/// - [`PagingError::NotMapped`] when the direct map does not map `virt`.
/// - [`PagingError::OutOfFrames`] when a split is needed and `take_table`
///   returns `None`.
///
/// # Safety
/// `virt` is the direct-map address of a RAM page nothing reaches through the
/// direct map until [`fill_direct_map_page`] restores it. The caller
/// serialises every direct-map edit and flushes the TLB afterwards.
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
    let pd = unsafe { descend_existing(root_va, virt, root_level(), 1, phys_to_virt) }
        .ok_or(PagingError::NotMapped)?;
    let pde = &mut pd[table_index(1, virt)];
    if !pde.is_present()
    {
        return Err(PagingError::NotMapped);
    }
    if pde.0 & LARGE_PAGE != 0
    {
        let table_pa = take_table().ok_or(PagingError::OutOfFrames)?;
        // SAFETY: the frame is the caller's alone, reached through the direct
        // map, and no table names it yet.
        let table = unsafe { table_at(phys_to_virt(table_pa)) };
        split_chunk_entries(table, pde.phys_addr() & !(LARGE_PAGE_SIZE - 1));
        // The entries are written before the directory names the table, so a
        // walk through the new entry finds them.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        *pde = PageTableEntry::new_table(table_pa);
    }
    // SAFETY: the directory entry names a live leaf table (split above, or
    // by an earlier hole or the Phase 3 build).
    let pt = unsafe { table_at(phys_to_virt(pde.phys_addr())) };
    pt[table_index(0, virt)] = PageTableEntry(0);
    Ok(())
}

/// Map the direct-map page at `virt` to `phys` again, closing a hole
/// [`hole_direct_map_page`] left. No flush is needed: x86-64 caches no
/// not-present entry ([`CACHES_NOT_PRESENT_ENTRIES`]).
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
    if let Some(pt) = unsafe { descend_existing(root_va, virt, root_level(), 0, phys_to_virt) }
    {
        pt[table_index(0, virt)] = PageTableEntry::new_page(phys, DIRECT_RAM);
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
    let Some(pd) = (unsafe { descend_existing(root_va, virt, root_level(), 1, phys_to_virt) })
    else
    {
        return false;
    };
    let pde = pd[table_index(1, virt)];
    if !pde.is_present() || pde.0 & LARGE_PAGE != 0
    {
        return pde.is_present();
    }
    // SAFETY: a present non-large directory entry names a live leaf table.
    let pt = unsafe { table_at(phys_to_virt(pde.phys_addr())) };
    pt[table_index(0, virt)].is_present()
}

/// Whether a CPU may cache a not-present entry, so that a page made present
/// again needs a flush on every CPU: never on x86-64.
pub const CACHES_NOT_PRESENT_ENTRIES: bool = false;

/// Invalidate every translation this CPU caches, in every address space:
/// INVPCID's all-context form with tagged TLBs; without them every entry
/// sits under PCID 0 and is not global, so a CR3 reload drops it.
///
/// # Safety
/// Must execute at ring 0.
#[cfg(not(test))]
pub unsafe fn flush_all_contexts()
{
    if crate::mm::tag_allocator::tagging_enabled()
    {
        let desc = InvpcidDescriptor {
            pcid: 0,
            linear_addr: 0,
        };
        // SAFETY: tagging enabled implies CR4.PCIDE on every CPU; the type-2
        // descriptor's fields are ignored and zero.
        unsafe { invpcid(INVPCID_TYPE_ALL_GLOBAL, &desc) };
    }
    else
    {
        // SAFETY: ring 0 (caller contract).
        unsafe { flush_tlb_all() };
    }
}

/// INVPCID type 2: invalidate every translation, global ones included, of
/// every PCID.
const INVPCID_TYPE_ALL_GLOBAL: u64 = 2;

/// Invalidate this CPU's cached translations of the kernel address `virt` in
/// every address-space context.
///
/// The direct map's entries are not global, so with tagged TLBs a CPU caches
/// them under each PCID it has run, and `invlpg` reaches only the loaded one;
/// INVPCID type 2 drops every PCID's (the whole TLB). Without tagging every
/// entry is cached under PCID 0, which `invlpg` reaches.
///
/// # Safety
/// Must execute at ring 0.
#[cfg(not(test))]
pub unsafe fn flush_kernel_page(virt: u64)
{
    if crate::mm::tag_allocator::tagging_enabled()
    {
        // SAFETY: ring 0 (caller contract); with tags this is INVPCID's
        // all-context form.
        unsafe { flush_all_contexts() };
    }
    else
    {
        // SAFETY: ring 0 (caller contract).
        unsafe { flush_page(virt) };
    }
}

/// Change the permission flags on an existing user-space leaf PTE at `virt`.
///
/// Walks from the root to the PT. Returns `Err(PagingError::NotMapped)` if
/// the page is not present at any level. On success, rewrites the leaf PTE
/// with the new `flags` (preserving the physical address and USER bit), calls
/// `flush_page`, and returns the [`MapOutcome`](crate::mm::paging::MapOutcome)
/// classifying the rights change (a same-frame rewrite, so never `Fresh`).
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB root
/// frame (PML5 or PML4). Caller must have validated W^X and rights before calling.
#[cfg(not(test))]
pub unsafe fn protect_user_page(
    root_virt: u64,
    virt: u64,
    flags: crate::mm::paging::PageFlags,
) -> Result<crate::mm::paging::MapOutcome, crate::mm::paging::PagingError>
{
    use crate::mm::paging::{PagingError, phys_to_virt};

    // Set USER bit (bit 2) to preserve user accessibility.
    const USER: u64 = 1 << 2;

    // SAFETY: root_virt is the direct-map VA of a valid user root (caller
    // contract); its reachable child frames are live PT frames.
    let pt = unsafe { descend_existing(root_virt, virt, root_level(), 0, phys_to_virt) }
        .ok_or(PagingError::NotMapped)?;
    let leaf = &mut pt[table_index(0, virt)];
    if !leaf.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    let prior = leaf.0;
    let phys = leaf.phys_addr();
    let mut new_pte = PageTableEntry::new_page(phys, flags);
    new_pte.0 |= USER;
    *leaf = new_pte;

    // SAFETY: invlpg flushes TLB entry for specified VA; architecture primitive.
    unsafe { flush_page(virt) };
    Ok(classify_user_map(prior, new_pte.0))
}

/// Translate a user virtual address to its mapped physical address and raw PTE.
///
/// Walks from the root to the PT without modifying any entry or flushing the
/// TLB. Returns `Some((phys_addr, raw_pte_bits))` if the page is present at
/// every level, or `None` if any level is not present.
///
/// Accepts 4 KiB user leaves only: a present PDPT or PD entry with the PS
/// (large-page) bit set yields `None` rather than a translation, since its
/// frame is a 1 GiB or 2 MiB page, not a page table. The user mapping path
/// never installs a large leaf, so every user VA resolves; a large leaf is
/// reached only through a kernel-half VA (the direct map's 2 MiB leaves). A
/// caller that introduces user large pages must add a large-leaf branch here.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB root
/// frame (PML5 or PML4).
#[cfg(not(test))]
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>
{
    // SAFETY: root_virt is the direct-map VA of a valid root at the active
    // depth (caller contract), and every table frame a present non-leaf entry
    // names is reachable through the direct map at `phys_to_virt` of its
    // physical address.
    let leaf = unsafe {
        walk_to_4k_leaf(
            root_virt,
            root_level(),
            virt,
            crate::mm::paging::phys_to_virt,
        )
    }?;
    Some((leaf.phys_addr(), leaf.0))
}

/// Walk from the table at `root_virt`, a root at level `top` (4 for a PML5,
/// 3 for a PML4), down to the PT for `virt`, reading each entry in place and
/// reaching each next table at `to_virt(phys)`.
///
/// Returns the present 4 KiB leaf, or `None` when an entry on the path is not
/// present or a PDPT or PD entry is a large leaf (PS set): its frame holds data,
/// not entries, so the walk never reads it as a table.
///
/// # Safety
/// `root_virt` must address a readable 512-entry table at level `top`, and
/// `to_virt` must map the physical address of every table a present non-leaf
/// entry on the path names to a readable address of that table.
unsafe fn walk_to_4k_leaf(
    root_virt: u64,
    top: usize,
    virt: u64,
    to_virt: impl Fn(u64) -> u64,
) -> Option<PageTableEntry>
{
    let mut table = root_virt;
    for level in (1..=top).rev()
    {
        // SAFETY: `table` is the root (caller contract) or `to_virt` of the table
        // a present non-leaf entry named (the check below), readable per the
        // caller contract; the index is < 512.
        let e = unsafe { read_entry(table, table_index(level, virt)) };
        if !names_table(e, level)
        {
            return None;
        }
        table = to_virt(e.phys_addr());
    }
    // SAFETY: as above; `table` is the PT the PD entry named.
    let leaf = unsafe { read_entry(table, table_index(0, virt)) };
    leaf.is_present().then_some(leaf)
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
    // SAFETY: per the caller contract the entry lies inside a readable,
    // aligned table.
    unsafe { (table_va as *const PageTableEntry).add(index).read() }
}

// ── Shootdown-elision classification ──────────────────────────────────────────

/// Classify a leaf-PTE rewrite (`prior` → `new`) into a
/// [`MapOutcome`](crate::mm::paging::MapOutcome) for shootdown elision.
///
/// `prior`/`new` are raw x86-64 leaf PTE bits (`new` is presumed present). The
/// classes and why each is safe are defined in
/// [memory-internals.md](../../../docs/memory-internals.md) § SMP TLB Shootdown.
fn classify_user_map(prior: u64, new: u64) -> crate::mm::paging::MapOutcome
{
    use crate::mm::paging::MapOutcome;

    if prior & PRESENT == 0
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

/// Whether `new` grants every user access `prior` granted (x86-64 leaf bits).
///
/// On x86-64 every present user page is readable, so only W (WRITABLE) and X
/// (NX clear) can narrow.
fn map_rights_superset(new: u64, prior: u64) -> bool
{
    // W: if prior was writable, new must be writable.
    let w_ok = prior & WRITABLE == 0 || new & WRITABLE != 0;
    // X: if prior was executable (NX clear), new must be executable (NX clear).
    let x_ok = prior & NO_EXECUTE != 0 || new & NO_EXECUTE == 0;
    w_ok && x_ok
}

// ── Spurious-fault classification ─────────────────────────────────────────────

/// Whether a leaf PTE grants a user-mode access of the given class.
///
/// `write` = the faulting access was a write; `instr` = an instruction fetch
/// (mutually: a plain read has both false). A user page fault is *spurious*
/// (stale TLB) only when the live PTE is present, user-accessible, and already
/// grants the access — on x86 every present page is readable, so a read needs
/// only presence; a write needs `WRITABLE`; a fetch needs NX clear.
fn pte_permits_user_access(pte: u64, write: bool, instr: bool) -> bool
{
    /// User/Supervisor bit — the page is reachable from ring 3.
    const USER: u64 = 1 << 2;

    if pte & PRESENT == 0 || pte & USER == 0
    {
        return false;
    }
    if instr
    {
        pte & NO_EXECUTE == 0
    }
    else if write
    {
        pte & WRITABLE != 0
    }
    else
    {
        true
    }
}

/// Classify a userspace page fault at `va` as a spurious stale-TLB fault.
///
/// Walks the *current* (CR3) page tables for `va` and returns `true` iff `va`
/// is mapped, user-accessible, and the live leaf PTE permits the faulting
/// access — meaning the fault must be a stale TLB entry the CPU resolves on
/// retry after a local `invlpg`. Returns `false` for any genuine fault
/// (unmapped, or the live mapping still forbids the access); the caller then
/// delivers the fault to the thread's fault handler or, with none bound, kills
/// the thread (see [fault-handling.md](../../../../../docs/fault-handling.md)).
/// Because a `true` result requires the live PTE to grant the access (and x86
/// updates A/D in hardware), the retried instruction is guaranteed to make
/// progress — no retry counter is needed.
///
/// A `va` at or above [`user_va_top`] (the unmappable top user page and the
/// kernel half) is never a user mapping, so it is never a stale-TLB fault: it
/// returns `false` without walking the tables
/// ([`fault_is_spurious_given`]).
///
/// # Safety
/// Must run at ring 0 in the faulting thread's context, i.e. before CR3 has
/// been changed by a context switch.
#[cfg(not(test))]
pub unsafe fn user_fault_is_spurious(va: u64, write: bool, instr: bool) -> bool
{
    fault_is_spurious_given(va, write, instr, |va| {
        // SAFETY: ring 0; reads CR3 to recover the active page-table root.
        let root_phys = unsafe { read_root_phys() };
        let root_virt = crate::mm::paging::phys_to_virt(root_phys);
        // SAFETY: root_virt is the direct-map VA of the active root.
        unsafe { translate_user_page(root_virt, va) }.map(|(_pa, pte)| pte)
    })
}

/// The decision of [`user_fault_is_spurious`], with the live leaf PTE of a `va`
/// below [`user_va_top`] supplied by `live_leaf` (`None` when `va` is
/// unmapped). `live_leaf` is not called for a `va` at or above it.
fn fault_is_spurious_given(
    va: u64,
    write: bool,
    instr: bool,
    live_leaf: impl FnOnce(u64) -> Option<u64>,
) -> bool
{
    if va >= user_va_top()
    {
        return false;
    }
    live_leaf(va).is_some_and(|pte| pte_permits_user_access(pte, write, instr))
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

    // ── Direct-map split ──────────────────────────────────────────────────────

    // The defect caught: split entries with other flags than the large
    // direct-map leaf they replace (read-only, executable, uncacheable, or a
    // stray PS bit), which would change every direct-map access in the chunk.
    #[test]
    fn a_split_chunk_maps_its_pages_read_write_no_execute_write_back()
    {
        let chunk = 0x4020_0000;
        let mut table = [PageTableEntry(0); 512];
        split_chunk_entries(&mut table, chunk);
        for (i, e) in table.iter().enumerate()
        {
            assert_eq!(e.phys_addr(), chunk + (i as u64) * 4096);
            assert!(e.is_present() && e.0 & WRITABLE != 0 && e.0 & NO_EXECUTE != 0);
            assert_eq!(e.0 & (PCD | PWT | LARGE_PAGE), 0);
        }
    }

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

    // ── Entry classification ──────────────────────────────────────────────────

    #[test]
    fn large_page_leaf_names_no_table_at_the_pdpt_and_pd_levels_only()
    {
        let table = PageTableEntry::new_table(0x1000);
        let large = PageTableEntry(table.0 | LARGE_PAGE);
        for level in 1..=4
        {
            assert!(names_table(table, level), "level {level}");
        }
        // PS marks a 2 MiB (PD) or 1 GiB (PDPT) leaf; PML4 and PML5 entries
        // have no PS bit, so a set bit 7 there does not make a leaf.
        assert!(!names_table(large, 1));
        assert!(!names_table(large, 2));
        assert!(names_table(large, 3));
        assert!(names_table(large, 4));
        assert!(!names_table(PageTableEntry(0), 3));
    }

    // ── Spurious-fault classification ──────────────────────────────────────────

    const USER_BIT: u64 = 1 << 2;

    #[test]
    fn permits_read_of_present_user_page()
    {
        let pte = PRESENT | USER_BIT | NO_EXECUTE; // R-- (NX, not writable)
        assert!(pte_permits_user_access(pte, false, false));
    }

    #[test]
    fn permits_write_only_when_writable()
    {
        let ro = PRESENT | USER_BIT | NO_EXECUTE;
        let rw = PRESENT | USER_BIT | WRITABLE | NO_EXECUTE;
        assert!(!pte_permits_user_access(ro, true, false));
        assert!(pte_permits_user_access(rw, true, false));
    }

    #[test]
    fn permits_fetch_only_when_executable()
    {
        let nx = PRESENT | USER_BIT | NO_EXECUTE;
        let exec = PRESENT | USER_BIT; // NX clear
        assert!(!pte_permits_user_access(nx, false, true));
        assert!(pte_permits_user_access(exec, false, true));
    }

    #[test]
    fn rejects_non_user_and_absent_pages()
    {
        // Present + writable but supervisor-only: a user access is genuine.
        let kernel = PRESENT | WRITABLE;
        assert!(!pte_permits_user_access(kernel, false, false));
        // Not present: genuine fault regardless of other bits.
        let absent = USER_BIT | WRITABLE;
        assert!(!pte_permits_user_access(absent, false, false));
    }

    #[test]
    fn kernel_half_fault_is_never_spurious_even_when_the_lookup_permits()
    {
        let permitting = |_| Some(PRESENT | USER_BIT | WRITABLE);
        let floor = PagingDepth::Four.kernel_va_base();
        let kernel_half = [user_va_top(), floor, floor + (1 << 30), u64::MAX];
        for va in kernel_half
        {
            assert!(!fault_is_spurious_given(va, true, false, permitting));
        }
    }

    #[test]
    fn user_half_fault_is_spurious_only_when_the_live_leaf_permits()
    {
        let read_only = |_| Some(PRESENT | USER_BIT | NO_EXECUTE);
        let unmapped = |_| None;
        let va = 0x40_0000;
        assert!(fault_is_spurious_given(va, false, false, read_only));
        assert!(!fault_is_spurious_given(va, true, false, read_only));
        assert!(!fault_is_spurious_given(va, false, false, unmapped));
    }

    // ── Host page-table frames ────────────────────────────────────────────────

    /// A page-table frame on the host heap; its host address stands for its
    /// physical address (host addresses lie below bit 52, so `PHYS_MASK` keeps
    /// them), and the walks reach it through an identity translation.
    #[repr(C, align(4096))]
    struct Table([PageTableEntry; 512]);

    /// Host frames for the walk and descent tests: each address is taken from
    /// a `&mut` borrow once its box sits in its final heap place, and the
    /// tests reach the frames only through those addresses until the boxes
    /// drop, so a walk may read and a descent write through them (`table_at`
    /// forms `&mut`).
    struct Frames
    {
        _boxes: Vec<Box<Table>>,
        addrs: Vec<u64>,
    }

    fn frames(count: usize) -> Frames
    {
        let mut boxes: Vec<Box<Table>> = (0..count)
            .map(|_| Box::new(Table([PageTableEntry(0); 512])))
            .collect();
        let addrs = boxes
            .iter_mut()
            .map(|t| core::ptr::from_mut::<Table>(t) as u64)
            .collect();
        Frames {
            _boxes: boxes,
            addrs,
        }
    }

    impl Frames
    {
        /// Write `e` at `index` of this set's frame at `table`.
        ///
        /// # Panics
        /// When `table` is not one of this set's addresses.
        fn set_entry(&self, table: u64, index: usize, e: PageTableEntry)
        {
            assert!(self.addrs.contains(&table), "not a frame of this set");
            // SAFETY: `table` is one of this set's addresses (checked above):
            // a live host frame with write provenance, alive while `self` is.
            // The tests reach the frames only through these addresses and
            // hold no reference into one across this call, so the `&mut`
            // `table_at` forms is the only one.
            unsafe { table_at(table)[index] = e };
        }
    }

    /// The address of the table `table` refers to.
    fn addr_of(table: &[PageTableEntry; 512]) -> u64
    {
        core::ptr::from_ref(table) as u64
    }

    const DEPTHS: [PagingDepth; 2] = [PagingDepth::Four, PagingDepth::Five];

    /// The 4-level VA sits below `1 << 47`; the 5-level one above it, with a
    /// non-zero PML5 index, so a walk that skipped the PML5 or read the wrong
    /// bits for it would leave the path.
    fn va_for(depth: PagingDepth) -> u64
    {
        match depth
        {
            PagingDepth::Four => 0x7F_4060_3000_u64,
            PagingDepth::Five => 0x00F0_7F40_6060_3000_u64,
        }
    }

    // ── User-page walk ────────────────────────────────────────────────────────

    /// A user VA and the path from a root at `depth` to it: `top` frames, root
    /// first and the PD last, each linked to the next at `va`; the PD entry is
    /// left for the test to fill. Two more frames follow them: the PT, and the
    /// bait, every entry of which is a present, user, writable "leaf", so a
    /// walk that read a large leaf's frame (the bait) as a page table would
    /// return a permitting entry.
    struct Path
    {
        va: u64,
        top: usize,
        f: Frames,
    }

    impl Path
    {
        fn root(&self) -> u64
        {
            self.f.addrs[0]
        }

        fn pdpt(&self) -> u64
        {
            self.f.addrs[self.top - 2]
        }

        fn pd(&self) -> u64
        {
            self.f.addrs[self.top - 1]
        }

        fn pt(&self) -> u64
        {
            self.f.addrs[self.top]
        }

        fn bait(&self) -> u64
        {
            self.f.addrs[self.top + 1]
        }
    }

    fn path(depth: PagingDepth) -> Path
    {
        let va = va_for(depth);
        let top = depth.levels() - 1;
        let p = Path {
            va,
            top,
            f: frames(top + 2),
        };
        let lure = PageTableEntry(PRESENT | USER_BIT | WRITABLE | (p.bait() & PHYS_MASK));
        for index in 0..512
        {
            p.f.set_entry(p.bait(), index, lure);
        }
        for (i, level) in (2..=top).rev().enumerate()
        {
            let child = PageTableEntry(PageTableEntry::new_table(p.f.addrs[i + 1]).0 | USER_BIT);
            p.f.set_entry(p.f.addrs[i], table_index(level, va), child);
        }
        p
    }

    fn walk(p: &Path) -> Option<PageTableEntry>
    {
        // SAFETY: every table on the path is a live host frame reached through
        // its `Frames` address (identity translation), and no reference to
        // any of them is live while the walk reads.
        unsafe { walk_to_4k_leaf(p.root(), p.top, p.va, |pa| pa) }
    }

    #[test]
    fn walk_reaches_a_present_4k_leaf_at_either_depth()
    {
        for depth in DEPTHS
        {
            let p = path(depth);
            let leaf = PageTableEntry(PRESENT | USER_BIT | 0x1234_5000);
            p.f.set_entry(p.pt(), table_index(0, p.va), leaf);
            let pt = PageTableEntry(PageTableEntry::new_table(p.pt()).0 | USER_BIT);
            p.f.set_entry(p.pd(), table_index(1, p.va), pt);
            assert_eq!(walk(&p).map(|e| e.0), Some(leaf.0), "{depth:?}");
            p.f.set_entry(p.pt(), table_index(0, p.va), PageTableEntry(0));
            assert!(walk(&p).is_none(), "{depth:?}");
        }
    }

    #[test]
    fn walk_stops_at_a_large_pd_leaf()
    {
        // The leaf names the bait frame itself (not 2 MiB-aligned, which only
        // the hardware would care about), so a walk that read it as a PT would
        // return the bait's permitting entry.
        for depth in DEPTHS
        {
            let p = path(depth);
            let large = PageTableEntry(PRESENT | USER_BIT | LARGE_PAGE | (p.bait() & PHYS_MASK));
            p.f.set_entry(p.pd(), table_index(1, p.va), large);
            assert!(walk(&p).is_none(), "{depth:?}");
        }
    }

    #[test]
    fn walk_stops_at_a_large_pdpt_leaf()
    {
        for depth in DEPTHS
        {
            let p = path(depth);
            let large = PageTableEntry(PRESENT | USER_BIT | LARGE_PAGE | (p.bait() & PHYS_MASK));
            p.f.set_entry(p.pdpt(), table_index(2, p.va), large);
            assert!(walk(&p).is_none(), "{depth:?}");
        }
    }

    // ── Level descent ─────────────────────────────────────────────────────────

    /// An `ensure` for `descend_alloc` that hands out `addrs` in order, one per
    /// absent entry it is handed, linking each into that entry; `handed`
    /// counts the frames handed out.
    fn hand_out<'a>(
        addrs: &'a [u64],
        handed: &'a mut usize,
    ) -> impl FnMut(&mut PageTableEntry) -> Result<u64, ()> + 'a
    {
        move |e: &mut PageTableEntry| {
            if !e.is_present()
            {
                *e = PageTableEntry::new_table(addrs[*handed]);
                *handed += 1;
            }
            Ok(e.phys_addr())
        }
    }

    /// Build the path from a root at `depth` (`f.addrs[0]`) to the PD for `va`
    /// out of `f.addrs[1..top]`, returning the PD's address.
    fn link_to_pd(f: &Frames, depth: PagingDepth, va: u64) -> u64
    {
        let top = depth.levels() - 1;
        let mut handed = 0;
        // SAFETY: every address names a live, zeroed host frame with write
        // provenance (`Frames`), and the identity addresses are their VAs.
        let pd = unsafe {
            descend_alloc(
                f.addrs[0],
                va,
                top,
                1,
                hand_out(&f.addrs[1..top], &mut handed),
            )
        };
        pd.map(|t| addr_of(t)).unwrap()
    }

    #[test]
    fn descend_alloc_builds_one_table_per_level_below_the_root_at_either_depth()
    {
        for depth in DEPTHS
        {
            let top = depth.levels() - 1;
            let va = va_for(depth);
            // The root plus one table per level below it, and one spare, so a
            // descent that took one table too many is counted.
            let f = frames(top + 2);
            let children = &f.addrs[1..];
            let mut handed = 0;
            let mut ensure = hand_out(children, &mut handed);
            // SAFETY: as in `link_to_pd`.
            let pt =
                unsafe { descend_alloc(f.addrs[0], va, top, 0, &mut ensure) }.map(|t| addr_of(t));
            // SAFETY: as above; the second descent walks the tables the first built.
            let again =
                unsafe { descend_alloc(f.addrs[0], va, top, 0, &mut ensure) }.map(|t| addr_of(t));
            drop(ensure);
            // One table per level below the root, all by the first descent:
            // the PT is the last of them, and the second descent built none.
            assert_eq!(handed, top, "{depth:?}");
            assert_eq!(pt, Ok(children[top - 1]), "{depth:?}");
            assert_eq!(again, pt, "{depth:?}");
            // SAFETY: the root is a live host frame with write provenance;
            // `read_entry` forms no reference.
            let root_entry = unsafe { read_entry(f.addrs[0], table_index(top, va)) };
            assert_eq!(root_entry.phys_addr(), children[0], "{depth:?}");
        }
    }

    #[test]
    fn descend_alloc_propagates_an_allocation_failure()
    {
        let f = frames(1);
        let mut calls = 0;
        // SAFETY: the root is a live host frame with write provenance; `ensure`
        // fails before any child is named.
        let result = unsafe {
            descend_alloc(f.addrs[0], va_for(PagingDepth::Five), 4, 0, |_| {
                calls += 1;
                Err::<u64, &str>("out of frames")
            })
        };
        assert_eq!(result.err(), Some("out of frames"));
        assert_eq!(calls, 1);
    }

    #[test]
    fn descend_existing_reaches_the_pd_and_stops_at_an_absent_entry()
    {
        for depth in DEPTHS
        {
            let top = depth.levels() - 1;
            let va = va_for(depth);
            let f = frames(top);
            let pd = link_to_pd(&f, depth, va);
            // SAFETY: the path is built of live host frames with write
            // provenance, reached through the identity translation.
            let reached = unsafe { descend_existing(f.addrs[0], va, top, 1, |pa| pa) };
            assert_eq!(reached.map(|t| addr_of(t)), Some(pd), "{depth:?}");

            // The PD entry is absent: no PT to reach.
            // SAFETY: as above.
            let pt = unsafe { descend_existing(f.addrs[0], va, top, 0, |pa| pa) };
            assert!(pt.is_none(), "{depth:?}");

            // A VA whose root entry is absent leaves the path at the root.
            let other = va ^ (1 << (12 + 9 * top));
            // SAFETY: as above.
            let off_path = unsafe { descend_existing(f.addrs[0], other, top, 1, |pa| pa) };
            assert!(off_path.is_none(), "{depth:?}");
        }
    }

    #[test]
    fn descend_existing_never_descends_a_large_pd_leaf()
    {
        // A descent that read the leaf's frame as a PT would return that frame.
        for depth in DEPTHS
        {
            let top = depth.levels() - 1;
            let va = va_for(depth);
            let f = frames(top + 1);
            let pd = link_to_pd(&f, depth, va);
            let data = f.addrs[top];
            let large = PageTableEntry(PRESENT | USER_BIT | LARGE_PAGE | (data & PHYS_MASK));
            f.set_entry(pd, table_index(1, va), large);
            // SAFETY: as in the test above.
            let pt = unsafe { descend_existing(f.addrs[0], va, top, 0, |pa| pa) };
            assert!(pt.is_none(), "{depth:?}");
        }
    }

    // ── Shootdown-elision classification ───────────────────────────────────────

    use crate::mm::paging::MapOutcome;

    const FRAME_A: u64 = 0x10_000;
    const FRAME_B: u64 = 0x20_000;

    /// Raw leaf PTE bits: present user page on `frame` with the given rights.
    fn leaf(frame: u64, writable: bool, executable: bool) -> u64
    {
        let mut pte = PRESENT | USER_BIT | (frame & PHYS_MASK);
        if writable
        {
            pte |= WRITABLE;
        }
        if !executable
        {
            pte |= NO_EXECUTE;
        }
        pte
    }

    #[test]
    fn classify_fresh_when_prior_absent()
    {
        assert_eq!(
            classify_user_map(0, leaf(FRAME_A, true, false)),
            MapOutcome::Fresh
        );
    }

    #[test]
    fn classify_widen_when_adding_write_same_frame()
    {
        let prior = leaf(FRAME_A, false, false); // R--
        let new = leaf(FRAME_A, true, false); // RW-
        assert_eq!(classify_user_map(prior, new), MapOutcome::Widen);
    }

    #[test]
    fn classify_widen_when_adding_exec_same_frame()
    {
        let prior = leaf(FRAME_A, false, false); // R-- (NX)
        let new = leaf(FRAME_A, false, true); // R-X
        assert_eq!(classify_user_map(prior, new), MapOutcome::Widen);
    }

    #[test]
    fn classify_widen_when_identical()
    {
        let pte = leaf(FRAME_A, true, false);
        assert_eq!(classify_user_map(pte, pte), MapOutcome::Widen);
    }

    #[test]
    fn classify_replace_when_narrowing_write()
    {
        let prior = leaf(FRAME_A, true, false); // RW-
        let new = leaf(FRAME_A, false, false); // R--
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    #[test]
    fn classify_replace_when_narrowing_exec()
    {
        let prior = leaf(FRAME_A, false, true); // R-X
        let new = leaf(FRAME_A, false, false); // R-- (NX)
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    #[test]
    fn classify_replace_when_frame_changes()
    {
        // Same rights but a different frame is a dangerous stale entry.
        let prior = leaf(FRAME_A, true, false);
        let new = leaf(FRAME_B, true, false);
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }
}
