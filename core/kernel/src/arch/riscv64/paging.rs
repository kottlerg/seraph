// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/paging.rs

//! RISC-V page table operations, parameterized over the active paging mode.
//!
//! Mirrors the x86-64 interface. All page table frames come from the
//! BSS-resident pool supplied via [`PoolState`].
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
//! Bits \[62:61\]: PBMT (Svpbmt page-based memory type; 00=PMA, 01=NC,
//! 10=IO). Bit 63: N (Svnapot naturally-aligned power-of-two contiguity).
//! Non-leaf: V=1, R=0, W=0, X=0. Leaf: V=1, at least one of R/W/X set.
//! A megapage (2 MiB) is a leaf installed at level 1 in every mode.
//!
//! Svpbmt, Svinval, and Svnapot are RVA23-required and asserted by
//! [`verify_paging_extensions`] at boot; the code paths below use them
//! unconditionally.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub use boot_protocol::riscv_paging::PagingMode;
use boot_protocol::riscv_paging::{next_level_boundary, vpn_index};

use crate::mm::paging::{PageFlags, PagingError, PoolState};

// ── Active paging mode ────────────────────────────────────────────────────────

/// The paging mode this hart booted under, as a raw `satp.MODE` value.
///
/// Written once by [`init_paging_mode`] at kernel entry, before any consumer
/// runs and before APs start (SBI `hart_start` plus the trampoline param
/// block provide the happens-before for secondary harts); read lock-free
/// everywhere after. The Sv48 default keeps host unit tests on today's
/// behaviour without an init call.
static PAGING_MODE: AtomicU8 = AtomicU8::new(PagingMode::Sv48 as u8);

/// The active mode's kernel-half base, resolved once at [`init_paging_mode`]
/// so the hot `phys_to_virt` path is a single relaxed load plus add.
static DIRECT_MAP_BASE_VAL: AtomicU64 = AtomicU64::new(0xFFFF_8000_0000_0000);

/// The active mode's exclusive user-half top, resolved with the base above.
static USER_VA_TOP_VAL: AtomicU64 = AtomicU64::new(0x0000_8000_0000_0000);

/// Publish the active paging mode from the `satp` CSR.
///
/// The bootloader hands the kernel a running translation regime; `satp.MODE`
/// is therefore the authoritative record of the negotiated mode and needs no
/// boot-protocol field. Halts the hart on an unrecognizable MODE — this runs
/// pre-console, matching the silent-halt policy of `BootInfo` validation.
#[cfg(not(test))]
pub fn init_paging_mode()
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
    PAGING_MODE.store(mode as u8, Ordering::Relaxed);
    DIRECT_MAP_BASE_VAL.store(mode.kernel_va_base(), Ordering::Relaxed);
    USER_VA_TOP_VAL.store(mode.user_va_top(), Ordering::Relaxed);
}

/// Test-build stub: host unit tests run with the [`PAGING_MODE`] default.
#[cfg(test)]
pub fn init_paging_mode() {}

/// The active paging mode published at kernel entry.
pub fn paging_mode() -> PagingMode
{
    // The store site only writes values produced by `PagingMode::from_satp_mode`,
    // so the decode cannot fail.
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

/// Base virtual address of the direct physical map: the active mode's
/// kernel-half base (root entry 256 in every mode).
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
/// A leaf at any level sets at least one of R/W/X; a table pointer has none.
const LEAF_BITS: u64 = READ | WRITE | EXECUTE;
/// Svpbmt PBMT field, bits \[62:61\]: 00=PMA (defer to platform memory
/// attributes), 01=NC (non-cacheable idempotent main memory), 10=IO.
const PBMT_MASK: u64 = 0b11 << 61;
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
    /// `flags.uncacheable` selects the Svpbmt IO memory type (see
    /// [`PBMT_IO`]); a clear flag leaves PBMT=PMA, deferring to the
    /// platform's physical memory attributes.
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
// A 64 KiB NAPOT translation is 16 consecutive, identically-attributed 4 KiB
// leaves whose PPNs are contiguous from a 64 KiB-aligned base: each of the 16
// PTEs carries N=1 and the size encoding ppn[3:0]=0b1000, and hardware may
// cache the whole group as one TLB entry. Promotion is applied only to
// uncacheable (PBMT=IO) user mappings — the MMIO map path is the one producer
// of eligible phys-contiguous runs — and is a pure hint: every reader below
// decodes both shapes. A 16-slot group is index-aligned, so it never crosses
// an L0 table.

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
/// Needs no TLB flush: the NAPOT encoding translates every VA in the group
/// identically to the 16 per-page PTEs it replaces, so a cached
/// pre-promotion entry is benignly stale. Each slot rewrite is a single
/// aligned u64 store, so a concurrent lock-free reader (the spurious-fault
/// walk) sees either shape — both translate its VA identically.
fn try_promote_napot_64k(l0: &mut [PageTableEntry; 512], virt: u64)
{
    let start = vpn_index(0, virt) & !(NAPOT_64K_PAGES - 1);
    let base = l0[start];
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
    for (i, e) in l0[start..start + NAPOT_64K_PAGES].iter().enumerate()
    {
        if e.0 & !PPN_MASK != attrs || e.phys_addr() != base_pa + i as u64 * 4096
        {
            return;
        }
    }
    let napot = PageTableEntry(attrs | NAPOT | ((base_pa >> 2) & PPN_MASK) | NAPOT_64K_PPN);
    for e in &mut l0[start..start + NAPOT_64K_PAGES]
    {
        *e = napot;
    }
}

/// Restore the 16 per-page PTEs of the NAPOT group containing `virt`
/// (clear N, rewrite each slot's true `ppn[3:0]`). No-op when the slot is
/// not a NAPOT member.
///
/// Demotion itself needs no flush — every intermediate state translates
/// identically (same single-store argument as promotion). The caller's
/// subsequent invalidation of the VA it is about to modify also kills any
/// cached 64 KiB entry: an `sfence.vma`/`sinval.vma` naming any address
/// inside a NAPOT range must invalidate a cached translation covering it.
/// Writers MUST demote before making any slot of a group diverge —
/// partially zeroing or narrowing inside a live NAPOT group would leave
/// siblings whose cached group entry still translates the modified VA.
fn demote_napot_64k(l0: &mut [PageTableEntry; 512], virt: u64)
{
    let start = vpn_index(0, virt) & !(NAPOT_64K_PAGES - 1);
    let member = l0[start];
    if member.0 & NAPOT == 0
    {
        return;
    }
    let attrs = member.0 & !PPN_MASK & !NAPOT;
    let base_pa = member.phys_addr() & !0xF000;
    for (i, e) in l0[start..start + NAPOT_64K_PAGES].iter_mut().enumerate()
    {
        let pa = base_pa + i as u64 * 4096;
        *e = PageTableEntry(attrs | ((pa >> 2) & PPN_MASK));
    }
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

// ── Level descent ─────────────────────────────────────────────────────────────

/// Descend from the table at `root_va` to the table at level `stop`,
/// resolving-or-allocating a child at each level in `(stop, top]` via
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
        let child_va = ensure(&mut table[vpn_index(level, virt)])?;
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
    for level in (stop + 1..=top).rev()
    {
        let e = table[vpn_index(level, virt)];
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
    let top = paging_mode().levels() - 1;
    // SAFETY: root_va is the VA of a valid root frame allocated from pool;
    // walk_or_alloc yields pool frames whose VAs pool.phys_to_virt resolves.
    let l0 = unsafe {
        descend_alloc(root_va, virt, top, 0, |e| {
            walk_or_alloc(e, pool).map(|pa| pool.phys_to_virt(pa))
        })?
    };
    l0[vpn_index(0, virt)] = PageTableEntry::new_page(phys, flags);
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
    let top = paging_mode().levels() - 1;
    // SAFETY: root_va is the VA of a valid root frame allocated from pool;
    // walk_or_alloc yields pool frames whose VAs pool.phys_to_virt resolves.
    let l1 = unsafe {
        descend_alloc(root_va, virt, top, 1, |e| {
            walk_or_alloc(e, pool).map(|pa| pool.phys_to_virt(pa))
        })?
    };
    l1[vpn_index(1, virt)] = PageTableEntry::new_large_page(phys, flags);
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
/// ([platform-requirements.md](../../../../docs/platform-requirements.md)); a
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
/// [platform-requirements.md](../../../../docs/platform-requirements.md).
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
/// This `asm!` block rewrites `sp` from the identity-mapped value to
/// its direct-map alias. Rust inline asm cannot list `sp` as an output
/// (it's a reserved register), so LLVM has no way to learn that this
/// asm modifies `sp`. If LLVM inlines this function into the caller,
/// it freely hoists any sp-relative local-address materialisation
/// (`add reg, sp, imm`) to *before* the rebase, producing a stale
/// low-VA pointer that page-faults on next dereference (PR #138 hit
/// this in `kernel_entry`'s Phase 6 body — sepc=0xffffffff8000d972,
/// stval=0x9ddc0f58 on CI's riscv64 release ktest).
///
/// `#[inline(never)]` is the fix: an opaque function call is an
/// optimisation barrier the scheduler cannot move ops across, so every
/// sp-derived expression in the caller materialises on the correct
/// side of the rebase. Dropping `options(nostack)` is belt-and-braces
/// in case a future revision re-inlines this — `nostack` would still
/// be a factual lie about the body.
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
/// Sets U (user) bit so userspace can access the mapping.
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
) -> Result<crate::mm::paging::MapOutcome, ()>
{
    use crate::mm::paging::phys_to_virt;

    let top = paging_mode().levels() - 1;
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
        })?
    };
    Ok(install_user_leaf(l0, virt, phys, flags))
}

/// Shared leaf-install tail of [`map_user_page`] / [`map_user_page_pooled`]:
/// demote any NAPOT group the slot belongs to (so the prior PTE read for
/// classification is always a plain per-page leaf), install the new leaf
/// with the U bit, classify the rewrite, and opportunistically promote the
/// containing group when the new mapping is uncacheable.
#[cfg(not(test))]
fn install_user_leaf(
    l0: &mut [PageTableEntry; 512],
    virt: u64,
    phys: u64,
    flags: crate::mm::paging::PageFlags,
) -> crate::mm::paging::MapOutcome
{
    // U bit (bit 4) allows user-mode access.
    const USER: u64 = 1 << 4;

    if l0[vpn_index(0, virt)].0 & NAPOT != 0
    {
        demote_napot_64k(l0, virt);
    }
    let mut pte = PageTableEntry::new_page(phys, flags);
    pte.0 |= USER;
    let prior = l0[vpn_index(0, virt)].0;
    l0[vpn_index(0, virt)] = pte;
    let outcome = classify_user_map(prior, pte.0);
    if flags.uncacheable
    {
        try_promote_napot_64k(l0, virt);
    }
    outcome
}

/// Walk an existing page table entry or allocate a new child frame
/// from the kernel PT pool (`crate::mm::kernel_pt_pool`).
#[cfg(not(test))]
fn rv_walk_or_alloc(entry: &mut PageTableEntry) -> Result<u64, ()>
{
    if entry.is_present()
    {
        return Ok(entry.phys_addr());
    }

    // Pool returns zero-filled pages; no further write_bytes needed.
    let frame_pa = crate::mm::kernel_pt_pool::alloc_pt_page().ok_or(())?;

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
) -> Result<crate::mm::paging::MapOutcome, ()>
{
    use crate::mm::paging::phys_to_virt;

    let top = paging_mode().levels() - 1;
    // Same kernel-half guard as map_user_page.
    debug_assert!(vpn_index(top, virt) < 256);
    // SAFETY: root_virt is the direct-map VA of a valid user root PT (caller
    // contract); rv_walk_or_alloc_pooled yields live PT frames resolvable via
    // phys_to_virt.
    let l0 = unsafe {
        descend_alloc(root_virt, virt, top, 0, |e| {
            rv_walk_or_alloc_pooled(e, aso).map(phys_to_virt)
        })?
    };

    Ok(install_user_leaf(l0, virt, phys, flags))
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

/// Walk the user half of the page table rooted at `root_virt` and free every
/// intermediate table frame back to the kernel PT pool.
///
/// Leaf PTEs (R/W/X any set) point at physical memory owned by Memory
/// capabilities; those frames are freed through `MemoryObject` teardown when
/// the owning `CSpace` is destroyed, not here. This function only reclaims
/// the *page-table* pages the aspace allocated via `rv_walk_or_alloc`. The
/// root frame itself is not freed here; the caller in
/// `dealloc_object(AddressSpace)` frees it after this walk completes.
///
/// Only root entries 0..256 (the user half in every mode) are examined.
/// Entries 256..512 are copies of the global kernel root; freeing any of
/// their descendants would corrupt every other address space.
///
/// # Safety
/// `root_virt` must be the direct-map VA of a valid 4 KiB root frame.
/// No CPU may still be using this address space (the caller verifies
/// `active_cpu_mask().is_empty()` before invocation).
#[cfg(not(test))]
#[allow(dead_code)]
pub unsafe fn free_user_page_tables(root_virt: u64)
{
    let top = paging_mode().levels() - 1;
    // SAFETY: root_virt is direct-map VA of a valid root; caller's contract.
    let root = unsafe { table_at(root_virt) };
    for root_e in root.iter().take(256)
    {
        // Root-level leaves aren't produced by the mapping path; guard
        // against them regardless — a leaf has no child tables to free.
        if !root_e.is_present() || root_e.0 & LEAF_BITS != 0
        {
            continue;
        }
        // SAFETY: present non-leaf root entry points at a live child table
        // one level below the root; caller guarantees exclusive access.
        unsafe { free_subtree(root_e.phys_addr(), top - 1) };
    }
}

/// Free the kernel-PT-pool frame holding the level-`level` table at
/// `table_pa`, after recursively freeing every descendant table frame.
/// Large leaves (R/W/X set) are skipped — their PPN is data, not a table.
/// Bounded recursion: `level < levels - 1 <= 4`.
///
/// # Safety
/// `table_pa` must be a live PT-pool frame holding a table at `level` whose
/// present non-leaf entries all point at live PT-pool frames; no CPU may be
/// using the containing address space.
#[cfg(not(test))]
unsafe fn free_subtree(table_pa: u64, level: usize)
{
    if level > 0
    {
        // SAFETY: table_pa is a live PT frame (caller contract).
        let table = unsafe { table_at(crate::mm::paging::phys_to_virt(table_pa)) };
        for e in table.iter()
        {
            if e.is_present() && e.0 & LEAF_BITS == 0
            {
                // SAFETY: present non-leaf entry points at a live child table.
                unsafe { free_subtree(e.phys_addr(), level - 1) };
            }
        }
    }
    crate::mm::kernel_pt_pool::free_pt_page(table_pa);
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

    let top = paging_mode().levels() - 1;
    // SAFETY: root_virt is direct-map VA of a valid user root PT (caller
    // contract); its reachable child frames are live PT-pool frames.
    let Some(l0) = (unsafe { descend_existing(root_virt, virt, top, 0, phys_to_virt) })
    else
    {
        return;
    };
    // Demote-first: zeroing one slot of a live NAPOT group would leave
    // siblings whose cached group entry still translates this VA.
    if l0[vpn_index(0, virt)].0 & NAPOT != 0
    {
        demote_napot_64k(l0, virt);
    }
    l0[vpn_index(0, virt)] = PageTableEntry(0);

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
/// `aso`'s page-table growth pool. Returns the number of L0/L1/L2 frames freed.
///
/// Walks from the root to the leaf level over the span, clearing in-range
/// leaf PTEs. A table is freed only when it is fully empty afterwards **and**
/// `aso` owns the frame
/// ([`owns_phys`](crate::cap::object::AddressSpaceObject::owns_phys)) —
/// emptiness, not span-containment, is the gate, so a boundary table shared
/// with a live neighbour (or the guard-page table whose first slot sits just
/// outside the span) is reclaimed exactly when its last live entry clears.
/// Leaf entries at a non-leaf level (mega/gigapages: R/W/X set) are not
/// produced by the user mapping path; they are skipped (never descended, never
/// freed), so a table holding one is never seen as empty. The root frame is
/// never freed.
///
/// Issues no TLB flush: the caller performs one coarse `sfence.vma` shootdown
/// for the whole span and holds `pt_lock` across it, so a freed frame cannot be
/// popped and reused before every hart is coherent.
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
) -> usize
{
    use crate::mm::PAGE_SIZE;

    let top = paging_mode().levels() - 1;
    let virt_end = virt_base + page_count as u64 * PAGE_SIZE as u64;
    let mut freed = 0usize;

    // SAFETY: root_virt is the direct-map VA of a valid root (caller's
    // contract); unmap_span's contract is met by the same guarantees.
    let root = unsafe { table_at(root_virt) };
    // SAFETY: root is a live table at the root level; aso wraps this page
    // table and the caller holds its pt_lock (caller's contract).
    unsafe { unmap_span(root, top, virt_base, virt_end, aso, &mut freed) };
    freed
}

/// Clear every in-range leaf PTE of `[lo, hi)` under `table` (a table at
/// `level`), then free each child table the clear left empty — gated on
/// emptiness and `aso` ownership as documented on
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
)
{
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    if level == 0
    {
        let mut va = lo;
        while va < hi
        {
            // Demote-first: a span edge can cut through a NAPOT group;
            // zeroing only the in-span members of a live group would leave
            // out-of-span siblings whose cached 64 KiB entry still
            // translates the zeroed VAs. The caller's span-wide flush
            // covers the demoted members it modifies.
            if table[vpn_index(0, va)].0 & NAPOT != 0
            {
                demote_napot_64k(table, va);
            }
            table[vpn_index(0, va)] = PageTableEntry(0);
            va += PAGE_SIZE as u64;
        }
        return;
    }

    let mut va = lo;
    while va < hi
    {
        let entry_end = hi.min(next_level_boundary(level, va));
        let idx = vpn_index(level, va);
        let e = table[idx];
        // Skip mega/gigapage leaves (not produced by the user path).
        if e.is_present() && e.0 & LEAF_BITS == 0
        {
            let child_pa = e.phys_addr();
            // SAFETY: present non-leaf entry points at a live child table.
            let child = unsafe { table_at(phys_to_virt(child_pa)) };
            // SAFETY: child is a live table at level - 1; same aso/pt_lock
            // guarantees as this call.
            unsafe { unmap_span(child, level - 1, va, entry_end, aso, freed) };
            if table_is_empty(child) && aso.owns_phys(child_pa)
            {
                table[idx] = PageTableEntry(0);
                // SAFETY: child is empty and unlinked above; frame came from
                // this aso's pool (owns_phys).
                unsafe { aso.free_pt_page(child_pa) };
                *freed += 1;
            }
        }
        va = entry_end;
    }
}

/// RISC-V counterpart to [`crate::mm::paging::unmap_identity_page`].
///
/// Walks the kernel root from `phys_to_virt(kernel_pml4_pa())` down to the
/// leaf covering `pa` and clears the leaf entry. Bails silently if any
/// intermediate level is absent or is a large leaf (clearing inside one
/// would corrupt unrelated memory). Issues a local `sfence.vma pa, x0`,
/// then broadcasts a TLB shootdown to every other online hart.
///
/// The kernel installs this identity mapping in Phase 3 (arch-neutral
/// `mm/paging.rs`) so the AP trampoline page can execute the four
/// instructions after `csrw satp` (sfence.vma, mv sp, jr) while PC is
/// still inside the trampoline at its physical address. Once the AP has
/// reached its kernel-VA entry, the mapping is no longer needed.
///
/// Intermediate tables are NOT freed — they may host other low-VA
/// mappings (notably the boot-stack identity mapping installed by
/// `map_boot_stack` in `mm/paging.rs`, and any future low-PA identity entries).
// similar_names: root_va and root_pa are a VA/PA pair — the similarity is
// intentional and follows the pattern used elsewhere in this file.
#[cfg(not(test))]
#[allow(clippy::similar_names)]
pub unsafe fn unmap_identity_page(pa: u64)
{
    use crate::mm::paging::{kernel_pml4_pa, phys_to_virt};

    let root_pa = kernel_pml4_pa();
    if root_pa == 0
    {
        return;
    }
    let root_va = phys_to_virt(root_pa);
    let virt = pa; // identity: VA == PA
    let top = paging_mode().levels() - 1;

    // SAFETY: root_va is the direct-map VA of the kernel root installed in
    // Phase 3; table walk is read-only until the leaf clear at the bottom.
    let Some(l0) = (unsafe { descend_existing(root_va, virt, top, 0, phys_to_virt) })
    else
    {
        return;
    };
    l0[vpn_index(0, virt)] = PageTableEntry(0);

    // Local invalidate, then broadcast to every other online hart. The
    // shootdown routine requires preemption disabled and handles the
    // interrupt window for mutual shootdown itself.
    // SAFETY: sfence.vma is a per-hart architectural primitive; shootdown
    // contract met by acquiring preemption around the broadcast.
    unsafe { flush_page(virt) };

    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let current = crate::arch::current::cpu::current_cpu() as usize;
    let mut remote = crate::cpu_mask::CpuMask::range(cpu_count);
    remote.clear(current);
    if !remote.is_empty()
    {
        crate::percpu::preempt_disable();
        // SAFETY: root_pa is the active kernel root; remote covers
        // only online harts; preemption disabled around the shootdown. Tag 0:
        // this is a kernel identity mapping torn down at boot, not a tagged
        // user space.
        unsafe { crate::mm::tlb_shootdown::shootdown(root_pa, &remote, virt, 0) };
        crate::percpu::preempt_enable();
    }
}

/// Change the permission flags on an existing user-space leaf PTE at `virt`.
///
/// Returns `Err(PagingError::NotMapped)` if any level is not present. On
/// success, rewrites the leaf PTE with the new `flags` (preserving physical
/// address and USER bit), calls `flush_page`, and returns the
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
    // Set USER (U) bit (bit 4) to preserve user accessibility.
    const USER: u64 = 1 << 4;

    let top = paging_mode().levels() - 1;
    // SAFETY: root_virt is direct-map VA of a valid user root PT (caller
    // contract); its reachable child frames are live PT-pool frames.
    let l0 = unsafe { descend_existing(root_virt, virt, top, 0, phys_to_virt) }
        .ok_or(PagingError::NotMapped)?;
    // Demote-first: a rights change on one slot of a NAPOT group must not
    // leave the other 15 members claiming a group that no longer exists.
    // The demoted per-page PTE carries the same rights and PA, so the
    // classification below is unaffected.
    if l0[vpn_index(0, virt)].0 & NAPOT != 0
    {
        demote_napot_64k(l0, virt);
    }
    let leaf = &mut l0[vpn_index(0, virt)];
    if !leaf.is_present()
    {
        return Err(PagingError::NotMapped);
    }

    let prior = leaf.0;
    let phys = leaf.phys_addr();
    let mut new_pte = PageTableEntry::new_page(phys, flags);
    new_pte.0 |= USER;
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
/// VA — the spurious-fault classifier relies on it. A caller that introduces
/// user large pages must add a large-leaf branch here. NAPOT members are
/// still level-0 leaves: the returned physical address is decoded per page
/// ([`leaf_phys`]); the raw PTE bits carry N and the size encoding.
///
/// # Safety
/// `root_virt` must be the direct-map virtual address of a valid 4 KiB user
/// root page table frame.
#[cfg(not(test))]
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>
{
    use crate::mm::paging::phys_to_virt;

    let top = paging_mode().levels() - 1;
    // SAFETY: root_virt is direct-map VA of a valid user root PT (caller
    // contract); its reachable child frames are live PT-pool frames.
    let l0 = unsafe { descend_existing(root_virt, virt, top, 0, phys_to_virt) }?;
    let leaf = l0[vpn_index(0, virt)];
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
/// dangerous stale entry and must shoot down. See [`MapOutcome`] for the full
/// argument.
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

/// Whether a leaf PTE grants a user-mode access of the given class.
///
/// `write` = the faulting access was a store/AMO; `instr` = an instruction
/// fetch (a plain load has both false). A user page fault is *spurious* (stale
/// TLB) only when the live PTE is valid, user-accessible (U), and already
/// grants the access: a load needs `READ`, a store needs `WRITE`, a fetch
/// needs `EXECUTE`. The kernel does not make execute-only pages readable (MXR is
/// kept clear), so each access class checks exactly its own bit. The NAPOT N
/// bit does not participate: a NAPOT member carries the same V/U/R/W/X bits
/// as the per-page leaf it stands for.
fn pte_permits_user_access(pte: u64, write: bool, instr: bool) -> bool
{
    /// U bit — the page is reachable from U-mode.
    const USER: u64 = 1 << 4;

    if pte & VALID == 0 || pte & USER == 0
    {
        return false;
    }
    if instr
    {
        pte & EXECUTE != 0
    }
    else if write
    {
        pte & WRITE != 0
    }
    else
    {
        pte & READ != 0
    }
}

/// Classify a userspace page fault at `va` as a spurious stale-TLB fault.
///
/// Walks the *current* (`satp`) page tables for `va` and returns `true` iff
/// `va` is mapped, user-accessible, and the live leaf PTE permits the faulting
/// access — meaning the fault must be a stale TLB entry the hart resolves on
/// retry after a local `sfence.vma`. Returns `false` for any genuine fault
/// (unmapped, or the live mapping still forbids the access); the caller then
/// kills the faulting thread. A `true` result requires the live PTE to grant
/// the access, and [`PageTableEntry::new_page`] pre-sets A (and D for writable
/// leaves), so the retried instruction cannot re-fault on an A/D update even
/// without Svadu — no retry counter is needed.
///
/// # Safety
/// Must run in S-mode in the faulting thread's context, i.e. before `satp` has
/// been changed by a context switch.
#[cfg(not(test))]
pub unsafe fn user_fault_is_spurious(va: u64, write: bool, instr: bool) -> bool
{
    // SAFETY: S-mode; reads satp to recover the active page-table root.
    let root_phys = unsafe { read_root_phys() };
    let root_virt = crate::mm::paging::phys_to_virt(root_phys);
    // SAFETY: root_virt is the direct-map VA of the active root.
    match unsafe { translate_user_page(root_virt, va) }
    {
        Some((_pa, pte)) => pte_permits_user_access(pte, write, instr),
        None => false,
    }
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
        for i in 16..32
        {
            assert_eq!(t[i].0, first.0);
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
        for i in 0..16
        {
            assert_eq!(leaf_phys(t[i], va_at(i)), 0x1_0000 + i as u64 * 4096);
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

    const USER_BIT: u64 = 1 << 4;

    #[test]
    fn permits_load_only_when_readable()
    {
        let x_only = VALID | USER_BIT | EXECUTE; // execute-only, MXR clear
        let r = VALID | USER_BIT | READ;
        assert!(!pte_permits_user_access(x_only, false, false));
        assert!(pte_permits_user_access(r, false, false));
    }

    #[test]
    fn permits_store_only_when_writable()
    {
        let ro = VALID | USER_BIT | READ;
        let rw = VALID | USER_BIT | READ | WRITE;
        assert!(!pte_permits_user_access(ro, true, false));
        assert!(pte_permits_user_access(rw, true, false));
    }

    #[test]
    fn permits_fetch_only_when_executable()
    {
        let rw = VALID | USER_BIT | READ | WRITE;
        let rx = VALID | USER_BIT | READ | EXECUTE;
        assert!(!pte_permits_user_access(rw, false, true));
        assert!(pte_permits_user_access(rx, false, true));
    }

    #[test]
    fn rejects_non_user_and_invalid_pages()
    {
        // Valid + RWX but supervisor-only (U clear): a U-mode access is genuine.
        let kernel = VALID | READ | WRITE | EXECUTE;
        assert!(!pte_permits_user_access(kernel, false, false));
        // Invalid: genuine fault regardless of other bits.
        let invalid = USER_BIT | READ | WRITE | EXECUTE;
        assert!(!pte_permits_user_access(invalid, false, false));
    }

    // ── Shootdown-elision classification ───────────────────────────────────────

    use crate::mm::paging::MapOutcome;

    const FRAME_A: u64 = 0x10_000;
    const FRAME_B: u64 = 0x20_000;

    /// Raw leaf PTE bits: valid user page on `frame` with the given rights.
    fn leaf(frame: u64, r: bool, w: bool, x: bool) -> u64
    {
        let mut pte = VALID | USER_BIT | ((frame >> 12) << 10);
        if r
        {
            pte |= READ;
        }
        if w
        {
            pte |= WRITE;
        }
        if x
        {
            pte |= EXECUTE;
        }
        pte
    }

    #[test]
    fn classify_fresh_when_prior_invalid()
    {
        assert_eq!(
            classify_user_map(0, leaf(FRAME_A, true, true, false)),
            MapOutcome::Fresh
        );
    }

    #[test]
    fn classify_widen_when_adding_write_same_frame()
    {
        let prior = leaf(FRAME_A, true, false, false); // R--
        let new = leaf(FRAME_A, true, true, false); // RW-
        assert_eq!(classify_user_map(prior, new), MapOutcome::Widen);
    }

    #[test]
    fn classify_widen_when_adding_exec_same_frame()
    {
        let prior = leaf(FRAME_A, true, false, false); // R--
        let new = leaf(FRAME_A, true, false, true); // R-X
        assert_eq!(classify_user_map(prior, new), MapOutcome::Widen);
    }

    #[test]
    fn classify_widen_when_identical()
    {
        let pte = leaf(FRAME_A, true, true, false);
        assert_eq!(classify_user_map(pte, pte), MapOutcome::Widen);
    }

    #[test]
    fn classify_replace_when_narrowing_write()
    {
        let prior = leaf(FRAME_A, true, true, false); // RW-
        let new = leaf(FRAME_A, true, false, false); // R--
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    #[test]
    fn classify_replace_when_narrowing_exec()
    {
        let prior = leaf(FRAME_A, true, false, true); // R-X
        let new = leaf(FRAME_A, true, false, false); // R--
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }

    #[test]
    fn classify_replace_when_frame_changes()
    {
        let prior = leaf(FRAME_A, true, true, false);
        let new = leaf(FRAME_B, true, true, false);
        assert_eq!(classify_user_map(prior, new), MapOutcome::Replace);
    }
}
