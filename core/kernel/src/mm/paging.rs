// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/paging.rs

//! Kernel page table initialization (Phase 3).
//!
//! Establishes two permanent kernel mappings:
//! - **Direct physical map** at [`direct_map_base`]: every 2 MiB chunk of RAM
//!   is mapped R/W- via 2 MiB large pages, so any physical address is
//!   accessible as `direct_map_base() + phys`.
//! - **Kernel image** at `BootInfo::kernel_virtual_base`, a KASLR-randomized
//!   base in the top 2 GiB (`0xFFFF_FFFF_8000_0000`, the link base, when the
//!   slide is 0; see core/boot/docs/boot-flow.md § Step 5d: Apply the KASLR
//!   Slide): `.text` as R-X, `.rodata` as R--, `.data`+`.bss` as RW- (W^X
//!   enforced per section).
//!
//! The boot stack's identity mapping is preserved so the CPU has a valid
//! stack immediately after `activate`. The framebuffer and arch kernel MMIO
//! regions above the RAM ceiling (`max_phys_rounded`, the 2 MiB-rounded top of
//! RAM-backed memory) get 4 KiB direct-map pages, and the AP trampoline page
//! is identity-mapped until [`unmap_identity_page`] retires it after SMP
//! bringup.
//!
//! ## Table frames: a BSS seed, then carved RAM
//!
//! The bootloader identity-maps only specific regions, not free RAM, so the
//! tables are built in two stages. Stage 1 draws its frames from a small
//! `.bss` seed of [`BOOT_TABLE_POOL_SIZE`] frames, which lies inside the kernel
//! image the bootloader already mapped (at its KASLR-slid link address); their
//! physical addresses are derived from the kernel VA/PA offset in
//! [`BootInfo`]. It maps the kernel image, the boot stack, and the direct-map
//! chunks covering a carve of free RAM sized to [`stage2_table_bound`], then
//! activates the tables. Stage 2 draws its frames from the carve, now reachable
//! through the live direct map, and maps the rest: the direct map of all RAM,
//! the framebuffer and kernel MMIO above it, and the AP trampoline page.
//! Phase 2's free-range stream keeps the frames stage 2 used out of the buddy
//! (`mm::init::record_boot_table_carve`). The seed's size is fixed by the
//! stage-1 mappings, and the carve's by the machine, so no amount of RAM
//! exhausts either.

// cast_possible_truncation: u64→usize memory-map entry count; 64-bit targets
// only, so the cast is exact.
// cast_lossless: u32→u64 widening of the framebuffer stride × height byte count.
// inline_always: phys_to_virt/virt_to_phys are called on every memory access path; always-inline
//   avoids call overhead in these hot helpers.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::inline_always
)]

use boot_protocol::BootInfo;

use super::PAGE_SIZE;
// Production-only imports (linker symbols and arch paging are unavailable
// when running unit tests on the host).
#[cfg(not(test))]
use crate::arch::current::paging as arch_paging;

// ── Kernel root page table physical address ───────────────────────────────────

/// Physical address of the kernel's root page table (PML4 on x86-64, the
/// negotiated-mode root on RISC-V).
///
/// Set once during Phase 3 by `init_kernel_page_tables`. APs load this into CR3
/// (x86-64) or `satp` (RISC-V) during the SMP startup sequence.
#[cfg(not(test))]
static KERNEL_ROOT_TABLE_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Return the physical address of the kernel root page table.
///
/// Returns 0 until `init_kernel_page_tables` completes (Phase 3).
#[cfg(not(test))]
pub fn kernel_root_table_pa() -> u64
{
    KERNEL_ROOT_TABLE_PA.load(core::sync::atomic::Ordering::Relaxed)
}

/// Test stub.
#[cfg(test)]
pub fn kernel_root_table_pa() -> u64
{
    0
}

// ── Public constants ──────────────────────────────────────────────────────────

/// Base virtual address of the direct physical map.
///
/// Every physical address `phys` is accessible at `direct_map_base() + phys`
/// after Phase 3 completes. The base is a per-boot, KASLR-chosen, 1 GiB-aligned
/// address at or above the paging mode's kernel-half floor, published once at
/// kernel entry by `init_paging_mode`; reading it is a single relaxed load (see
/// core/kernel/docs/memory-internals.md § Direct Physical Map Access).
#[cfg(not(test))]
#[inline(always)]
pub fn direct_map_base() -> u64
{
    arch_paging::direct_map_base()
}

/// Test stub: the 4-level / Sv48 kernel-half floor, matching the arch layers'
/// host-test default for `DIRECT_MAP_BASE_VAL`.
#[cfg(test)]
#[inline(always)]
pub fn direct_map_base() -> u64
{
    0xFFFF_8000_0000_0000
}

/// Size of a 2 MiB large page (used for the direct physical map).
/// Fixed by hardware: an x86-64 PDE leaf and an Sv39 level-1 megapage each map 2 MiB.
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Convert a physical address to its direct-map virtual address.
#[inline(always)]
pub fn phys_to_virt(phys: u64) -> u64
{
    direct_map_base() + phys
}

/// Convert a direct-map virtual address back to a physical address.
#[inline(always)]
pub fn virt_to_phys(virt: u64) -> u64
{
    virt - direct_map_base()
}

// ── Error and flags types ─────────────────────────────────────────────────────

/// Errors that can occur during page table construction or modification.
#[derive(Debug, PartialEq, Eq)]
pub enum PagingError
{
    /// The table-frame source is exhausted: the BSS seed in stage 1, or the
    /// carve in stage 2 (its size is an upper bound, so this is a defect).
    OutOfFrames,
    /// The target virtual address is not mapped (returned by the protect walk,
    /// `AddressSpace::protect_page`).
    NotMapped,
}

/// Why [`init_kernel_page_tables`] could not build the kernel's tables.
#[derive(Debug, PartialEq, Eq)]
pub enum BootTableError
{
    /// A mapping found no table frame ([`PagingError::OutOfFrames`]).
    OutOfFrames,
    /// No free RAM range holds the stage-2 carve.
    NoTableCarve,
}

impl From<PagingError> for BootTableError
{
    fn from(_: PagingError) -> Self
    {
        // The boot builders map fresh, present-less ranges, so a walk never
        // reports `NotMapped`; only frame exhaustion reaches here.
        Self::OutOfFrames
    }
}

/// Page permission flags for a mapping.
///
/// On x86-64, `readable` has no effect (all present pages are readable);
/// it is included for cross-architecture symmetry with RISC-V which
/// has an explicit R bit.
// struct_excessive_bools: PageFlags is a cross-arch PTE flag set; each bool is a distinct
// architectural attribute. A bitfield enum would need extra decode logic at every call site.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug)]
pub struct PageFlags
{
    /// Page is readable (relevant on RISC-V; has no dedicated bit on x86-64).
    // allow: x86-64 ignores this field; it is read by
    // core/kernel/src/arch/riscv64/paging.rs (`PageTableEntry::new_page`).
    #[allow(dead_code)]
    pub readable: bool,
    /// Page is writable.
    pub writable: bool,
    /// Page is executable (if `false`, the NX/X bit blocks instruction fetch).
    pub executable: bool,
    /// Force device/uncacheable memory type.
    ///
    /// On x86-64: sets PCD|PWT in the PTE (strong uncacheable).
    /// On RISC-V: sets the Svpbmt IO memory type (PTE bits \[62:61\] = 10 —
    /// non-cacheable, non-idempotent, strongly ordered), making MMIO
    /// attributes explicit rather than dependent on platform PMAs.
    pub uncacheable: bool,
}

/// How a leaf-PTE rewrite changed an existing mapping, used to decide whether a
/// cross-CPU TLB shootdown is required once the new PTE is committed.
///
/// The arch mapping primitives classify the rewrite; `mm::address_space` acts on
/// it. Which outcomes may elide the remote shootdown, and why, is defined in
/// core/kernel/docs/memory-internals.md § SMP TLB Shootdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapOutcome
{
    /// No prior mapping existed at this VA (the leaf was not-present).
    ///
    /// x86-64 does not cache not-present translations (Intel SDM 4.10.2.3), so
    /// no remote CPU holds a stale entry. RISC-V may cache an invalid PTE, but
    /// an access through it is a spurious fault the handler resolves against the
    /// now-present live PTE. Either way, no remote shootdown is required.
    Fresh,
    /// A prior mapping existed; the rewrite keeps the same frame and only
    /// *widens* permissions (new rights ⊇ prior).
    ///
    /// No remote shootdown is required (core/kernel/docs/memory-internals.md
    /// § SMP TLB Shootdown); the local flush still runs so the initiating CPU sees
    /// the new rights.
    Widen,
    /// A prior mapping existed and the rewrite can leave a *dangerous* stale
    /// entry on a remote CPU — a different frame (use-after-free / stale data)
    /// or a permission *narrowing* (stale, over-broad rights). Requires a
    /// synchronous remote shootdown before the operation returns.
    Replace,
}

impl MapOutcome
{
    /// Whether committing this rewrite requires a synchronous cross-CPU TLB
    /// shootdown. Only [`MapOutcome::Replace`] can strand a dangerous stale
    /// entry; `Fresh` and `Widen` rely on the spurious-fault retry path.
    #[must_use]
    pub fn needs_remote_shootdown(self) -> bool
    {
        matches!(self, MapOutcome::Replace)
    }
}

// ── Static boot table pool ────────────────────────────────────────────────────

/// Number of 4 KiB frames in the stage-1 BSS seed (256 KiB).
///
/// Stage 1 maps only the root, the kernel image, the boot stack window and the
/// direct-map chunks of the stage-2 carve, so the seed's need is fixed by the
/// image size, not by RAM: the image's tables (one per 2 MiB of image plus its
/// upper levels), about eight for the stack window, and one directory per GiB
/// of carve, which is about 1 MiB of carve per 256 GiB of RAM. 64 frames leave
/// room for a 64 MiB image beside the carve of any direct map up to the
/// 128 TiB kernel half. A seed too small fails the boot in Phase 3 by name.
pub const BOOT_TABLE_POOL_SIZE: usize = 64;

/// Contiguous 4 KiB-aligned block of zeroed BSS frames for boot page tables.
///
/// Placed in `.bss` so it occupies no space in the kernel binary.
#[cfg(not(test))]
#[repr(C, align(4096))]
struct BootTablePool
{
    frames: [[u8; 4096]; BOOT_TABLE_POOL_SIZE],
}

#[cfg(not(test))]
static mut BOOT_TABLE_POOL: BootTablePool = BootTablePool {
    frames: [[0u8; 4096]; BOOT_TABLE_POOL_SIZE],
};

// ── PoolState ─────────────────────────────────────────────────────────────────

/// Allocation state for the boot page-table frames: the BSS seed, then (after
/// [`PoolState::switch_to_carve`]) a carve of RAM reached through the direct
/// map.
///
/// Handed to arch-specific mapping functions so they can allocate intermediate
/// page table frames and convert frame physical addresses back to virtual ones.
pub struct PoolState
{
    /// `kernel_virtual_base - kernel_physical_base` (wrapping arithmetic).
    ///
    /// Adding this offset to any seed frame's physical address yields its
    /// virtual address: `frame_va = frame_pa.wrapping_add(kv_minus_kp)`.
    kv_minus_kp: u64,
    pool_va_base: u64,
    pool_pa_base: u64,
    pool_capacity: usize,
    next: usize,
    /// Physical base of the stage-2 carve; frames come from it once
    /// `carve_capacity` is non-zero.
    carve_pa_base: u64,
    carve_capacity: usize,
    carve_next: usize,
    /// Direct-map base through which carve frames are reached.
    dm_base: u64,
}

impl PoolState
{
    /// Construct for production use from [`BootInfo`].
    ///
    /// Pool physical base is derived from `BOOT_TABLE_POOL`'s virtual address
    /// and the kernel VA/PA offset supplied by the bootloader.
    ///
    /// Call once, during single-threaded boot: every `PoolState` built from
    /// `BootInfo` starts at frame 0 and hands out the same `BOOT_TABLE_POOL` frames.
    // similar_names: pool_va_base and pool_pa_base are the VA and PA of the same pool region.
    #[cfg(not(test))]
    #[allow(clippy::similar_names)]
    pub fn new(info: &BootInfo) -> Self
    {
        // SAFETY: BOOT_TABLE_POOL is in BSS; single-threaded boot access.
        let pool_va_base = core::ptr::addr_of!(BOOT_TABLE_POOL) as u64;
        let kv = info.kernel_virtual_base;
        let kp = info.kernel_physical_base;
        let pool_pa_base = pool_va_base.wrapping_sub(kv).wrapping_add(kp);
        Self {
            kv_minus_kp: kv.wrapping_sub(kp),
            pool_va_base,
            pool_pa_base,
            pool_capacity: BOOT_TABLE_POOL_SIZE,
            next: 0,
            carve_pa_base: 0,
            carve_capacity: 0,
            carve_next: 0,
            dm_base: 0,
        }
    }

    /// Construct for unit tests with an explicit pool buffer.
    ///
    /// `pool_va == pool_pa` (identity mapping), so `phys_to_virt` is a no-op.
    /// `capacity` is the number of 4 KiB frames available in the buffer at
    /// `pool_va`. The buffer must remain live for the lifetime of this state.
    #[cfg(test)]
    pub fn new_for_test(pool_va: u64, capacity: usize) -> Self
    {
        Self {
            kv_minus_kp: 0,
            pool_va_base: pool_va,
            pool_pa_base: pool_va,
            pool_capacity: capacity,
            next: 0,
            carve_pa_base: 0,
            carve_capacity: 0,
            carve_next: 0,
            dm_base: 0,
        }
    }

    /// Allocate one 4 KiB frame from the pool.
    ///
    /// Returns `(virtual_address, physical_address)`.
    ///
    /// # Errors
    /// `PagingError::OutOfFrames` when the pool is exhausted. Call
    /// `fatal()` in the caller if this is unacceptable.
    pub fn alloc_frame(&mut self) -> Result<(u64, u64), PagingError>
    {
        if self.carve_capacity != 0
        {
            if self.carve_next >= self.carve_capacity
            {
                return Err(PagingError::OutOfFrames);
            }
            let pa = self.carve_pa_base + (self.carve_next * 4096) as u64;
            self.carve_next += 1;
            return Ok((self.dm_base.wrapping_add(pa), pa));
        }
        if self.next >= self.pool_capacity
        {
            return Err(PagingError::OutOfFrames);
        }
        let offset = (self.next * 4096) as u64;
        let va = self.pool_va_base + offset;
        let pa = self.pool_pa_base + offset;
        self.next += 1;
        Ok((va, pa))
    }

    /// Draw every later frame from the `frames` frames of RAM at `base`,
    /// reached through the direct map at `dm_base`, which must already map
    /// them.
    pub fn switch_to_carve(&mut self, base: u64, frames: usize, dm_base: u64)
    {
        self.carve_pa_base = base;
        self.carve_capacity = frames;
        self.carve_next = 0;
        self.dm_base = dm_base;
    }

    /// Frames drawn from the carve so far.
    #[must_use]
    pub fn carve_used(&self) -> usize
    {
        self.carve_next
    }

    /// Convert a table frame's physical address to its virtual address: the
    /// seed's through the kernel image, a carve frame's through the direct map.
    ///
    /// Only valid for addresses of frames this pool handed out; the result is
    /// meaningless for arbitrary physical addresses.
    pub fn phys_to_virt(&self, phys: u64) -> u64
    {
        let seed_end = self.pool_pa_base + (self.pool_capacity * 4096) as u64;
        if self.carve_capacity == 0 || (self.pool_pa_base..seed_end).contains(&phys)
        {
            phys.wrapping_add(self.kv_minus_kp)
        }
        else
        {
            self.dm_base.wrapping_add(phys)
        }
    }
}

// ── Stage-2 frame bound ───────────────────────────────────────────────────────

/// Upper bound on the page-table frames, the root excluded, that mapping
/// `[start, end)` with leaves of `2^leaf_shift` bytes (12 for 4 KiB, 21 for
/// 2 MiB) can allocate, under paging of up to five levels: at each level from
/// the leaf tables up to the one below a five-level root, one table per
/// aligned block of that table's reach that the span touches. A four- or
/// three-level root makes the top terms over-count, never under-count.
#[must_use]
pub fn span_table_bound(start: u64, end: u64, leaf_shift: u32) -> u64
{
    if end <= start
    {
        return 0;
    }
    let mut total = 0;
    // A table one level above a leaf reaches 512 leaves.
    let mut shift = leaf_shift + 9;
    while shift <= 48
    {
        total += ((end - 1) >> shift) - (start >> shift) + 1;
        shift += 9;
    }
    total
}

/// Upper bound on the frames stage 2 of [`init_kernel_page_tables`] draws from
/// its carve: the direct map of `[0, direct_top)` in 2 MiB leaves, one leaf
/// table per kernel-MMIO region below `direct_top` (its 2 MiB chunk is split),
/// and 4 KiB mappings of every region above it, of the framebuffer span
/// `fb` when it lies above, and of the AP trampoline page.
#[must_use]
pub fn stage2_table_bound(
    direct_top: u64,
    mmio_regions: &[(u64, u64)],
    fb: Option<(u64, u64)>,
    trampoline: u64,
) -> u64
{
    let mut frames = span_table_bound(0, direct_top, 21);
    for &(base, size) in mmio_regions
    {
        frames += if base < direct_top
        {
            1
        }
        else
        {
            span_table_bound(base, base.saturating_add(size), 12)
        };
    }
    if let Some((base, size)) = fb
    {
        frames += span_table_bound(base, base.saturating_add(size), 12);
    }
    if trampoline != 0
    {
        frames += span_table_bound(trampoline, trampoline + PAGE_SIZE as u64, 12);
    }
    frames
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Whether `[base, base + len)` overlaps any `(base, size)` region in `regions`.
fn span_overlaps_regions(base: u64, len: u64, regions: &[(u64, u64)]) -> bool
{
    let end = base.saturating_add(len);
    regions
        .iter()
        .any(|&(r_base, r_size)| r_base < end && base < r_base.saturating_add(r_size))
}

/// Flags of the direct-map page at `phys`: read-write, never executable, and
/// uncacheable exactly when the page overlaps one of the kernel's own MMIO
/// `regions`, so their memory type never depends on the firmware's MTRRs
/// (`core/kernel/docs/arch-interface.md` § `paging`).
fn direct_map_page_flags(phys: u64, regions: &[(u64, u64)]) -> PageFlags
{
    PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: span_overlaps_regions(phys, PAGE_SIZE as u64, regions),
    }
}

/// Scan the memory map for the highest `physical_base + size` across all
/// RAM-backed entries.
///
/// Only `Usable`, `Loaded`, `AcpiReclaimable`, and `Persistent` entries are
/// considered. `Reserved` entries are excluded because they may represent
/// high-address MMIO regions (`PCIe` BARs, firmware flash, LAPIC, etc.) whose
/// physical addresses can be in the hundreds-of-GiB range, which would
/// require far more page table frames than the boot pool provides.
///
/// Kernel-internal MMIO above the RAM ceiling and a framebuffer above it are
/// mapped separately by `init_kernel_page_tables` (the arch
/// `collect_mmio_direct_map_regions` set) and `map_framebuffer_if_needed`;
/// device MMIO reaches userspace drivers as MMIO capabilities
/// (docs/device-management.md), never through the direct map.
///
/// Returns 0 if the map contains no RAM entries.
pub fn compute_max_physical_address(info: &BootInfo) -> u64
{
    // SAFETY: Phase 0 validated that memory_map.entries is non-null and
    // count > 0; the region is identity-mapped by the bootloader (pre-Phase
    // 3) or covered by the direct map (from Phase 3 on).
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };
    boot_protocol::max_ram_address(entries)
}

// ── Page table initialization ─────────────────────────────────────────────────
// Excluded from unit test builds: references linker symbols and arch hardware.

#[cfg(not(test))]
unsafe extern "C" {
    /// Start of the kernel `.text` section (virtual address).
    static __text_start: u8;
    /// End of the kernel `.text` section (virtual address).
    static __text_end: u8;
    /// Start of the kernel `.rodata` section (virtual address).
    static __rodata_start: u8;
    /// End of the kernel `.rodata` section (virtual address).
    static __rodata_end: u8;
    /// Start of the kernel `.data` section (virtual address).
    static __data_start: u8;
    /// End of `.bss` (marks the end of the kernel's R/W region).
    static __bss_end: u8;
}

/// Initialize the kernel's own page tables and activate them (Phase 3).
///
/// After this function returns:
/// - Any physical address is accessible via `direct_map_base() + phys`.
/// - Kernel sections are mapped with W^X permissions.
/// - The boot stack remains accessible at its current virtual address.
///
/// Every frame this function needs comes from the BSS seed
/// ([`BOOT_TABLE_POOL_SIZE`]) or the carve of free RAM it sizes with
/// [`stage2_table_bound`] (see the module documentation), not the buddy
/// allocator, which is populated after it returns.
///
/// # Errors
/// - [`BootTableError::NoTableCarve`] when no free RAM range holds the carve;
///   returned before the switch.
/// - [`BootTableError::OutOfFrames`] when the seed runs out in stage 1 (a seed
///   too small for the kernel image), or the carve in stage 2 (a defect in the
///   bound).
///
/// The caller should `fatal()` on either.
///
/// In test builds this is a no-op stub so `main.rs` compiles unchanged.
#[cfg(test)]
pub fn init_kernel_page_tables(_info: &BootInfo) -> Result<(), BootTableError>
{
    Ok(())
}

// similar_names: root_va/root_pa and other va/pa pairs are VA/PA of the same frame.
#[cfg(not(test))]
#[allow(clippy::similar_names)]
pub fn init_kernel_page_tables(info: &BootInfo) -> Result<(), BootTableError>
{
    // Enable NX on x86-64 before we install tables with NX entries; a no-op
    // on RISC-V (X bit is always independently controllable).
    // SAFETY: single-threaded boot at ring 0 / S-mode.
    unsafe {
        arch_paging::enable_nx();
    }

    let mut pool = PoolState::new(info);

    // Allocate and zero the root page table.
    let (root_va, root_pa) = pool.alloc_frame()?;
    // SAFETY: root_va is a freshly allocated pool frame.
    unsafe {
        core::ptr::write_bytes(root_va as *mut u8, 0, 4096);
    }

    // Save the root page table physical address so APs can load it during startup.
    KERNEL_ROOT_TABLE_PA.store(root_pa, core::sync::atomic::Ordering::Relaxed);

    // Compute the highest physical address to determine direct map extent.
    let max_phys = compute_max_physical_address(info);
    let max_phys_rounded = (max_phys + LARGE_PAGE_SIZE - 1) & !(LARGE_PAGE_SIZE - 1);

    let dm_base = direct_map_base();
    // Re-check, on the shared `boot_protocol::direct_map_ceiling`, that the
    // direct map ends at or below the kernel image base; fail with a diagnostic
    // rather than overlap the image mapping (core/kernel/docs/initialization.md
    // § Phase 3: Kernel Page Tables; Sv39 margin: docs/memory-model.md § RISC-V
    // (Sv39 / Sv48 / Sv57)).
    {
        // SAFETY: Phase 0 validated the memory map; identity-mapped at this
        // point (pre-activate).
        let entries = unsafe {
            core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
        };
        let ceiling =
            boot_protocol::direct_map_ceiling(entries, &info.framebuffer, &info.kernel_mmio);
        if dm_base
            .checked_add(ceiling)
            .is_none_or(|end| end > info.kernel_virtual_base)
        {
            crate::fatal("Phase 3: direct map would overlap the kernel image window");
        }
    }

    // Kernel-internal MMIO regions (xAPIC + I/O APIC bases on x86-64; none on
    // RISC-V, whose PLIC and UART take their device memory type from the
    // platform PMAs). Bases come from `BootInfo.kernel_mmio` directly because
    // `crate::platform::capture_kernel_mmio` does not run until Phase 4.
    let mut mmio_regions = [(0u64, 0u64); crate::arch::current::platform::MMIO_DIRECT_MAP_REGIONS];
    let mmio_count = crate::arch::current::platform::collect_mmio_direct_map_regions(
        &info.kernel_mmio,
        &mut mmio_regions,
    );
    let mmio_regions = &mmio_regions[..mmio_count];

    // Everything stage 2 maps is read from `info` now: after the stage-1
    // switch the bootloader's identity map of `info` is gone.
    let fb = framebuffer_above(info, max_phys_rounded);
    let trampoline = info.ap_trampoline_page;
    let carve_frames = stage2_table_bound(max_phys_rounded, mmio_regions, fb, trampoline);
    let carve = crate::mm::init::find_boot_table_carve(info, carve_frames)
        .ok_or(BootTableError::NoTableCarve)?;
    let carve_end = carve + carve_frames * PAGE_SIZE as u64;
    let carve_chunks = (
        carve & !(LARGE_PAGE_SIZE - 1),
        (carve_end + LARGE_PAGE_SIZE - 1) & !(LARGE_PAGE_SIZE - 1),
    );

    // ── Stage 1, from the BSS seed ────────────────────────────────────────────
    map_kernel_image(root_va, info, &mut pool)?;
    map_boot_stack(root_va, info, &mut pool)?;
    let mut phys = carve_chunks.0;
    while phys < carve_chunks.1
    {
        map_direct_chunk(root_va, dm_base, phys, mmio_regions, &mut pool)?;
        phys += LARGE_PAGE_SIZE;
    }
    // SAFETY: the tables map the kernel image (code, data, this stack's frame
    // via the boot stack window) and the carve's direct map; nothing below
    // touches `info` or other identity-mapped memory.
    unsafe {
        arch_paging::activate(root_pa);
    }

    // ── Stage 2, from the carve ───────────────────────────────────────────────
    // The carve frames' bound fits `usize` on the 64-bit kernel.
    pool.switch_to_carve(carve, carve_frames as usize, dm_base);

    // Direct physical map of [0, max_phys_rounded) in 2 MiB pages, except a
    // chunk holding a kernel MMIO page (`map_direct_chunk`). The carve's own
    // chunks were mapped in stage 1.
    let mut phys: u64 = 0;
    while phys < max_phys_rounded
    {
        if phys < carve_chunks.0 || phys >= carve_chunks.1
        {
            map_direct_chunk(root_va, dm_base, phys, mmio_regions, &mut pool)?;
        }
        phys += LARGE_PAGE_SIZE;
    }

    // Framebuffer, when it lies above the RAM ceiling.
    if let Some((fb_phys, fb_bytes)) = fb
    {
        map_direct_pages(root_va, dm_base, fb_phys, fb_bytes, &[], &mut pool)?;
    }

    // Kernel MMIO above the RAM ceiling: a region below it was mapped
    // uncacheable by the direct-map loop; one above gets its own uncacheable
    // 4 KiB pages here.
    for &(phys_base, size) in mmio_regions
    {
        if phys_base >= max_phys_rounded
        {
            map_direct_pages(root_va, dm_base, phys_base, size, mmio_regions, &mut pool)?;
        }
    }

    // ── AP trampoline identity mapping (arch-neutral) ────────────────────────
    // Map the AP trampoline page at its physical address as a 4 KiB identity
    // page (VA = PA). Both arches need this: on x86-64 the AP enables paging
    // (writes CR3 = kernel PML4) during the PM32 → LM64 transition and must
    // keep fetching trampoline instructions at their PA through the LM64 relay
    // stub until its `jmp rax` reaches the kernel-VA entry; on RISC-V the
    // trampoline executes
    // `csrw satp` and the next instructions (sfence.vma, mv sp, jr) likewise
    // execute at the trampoline PA before the final `jr` lands at
    // `kernel_entry_ap`'s kernel virtual address.
    //
    // The kernel's other mappings are at high virtual addresses
    // (direct map, kernel image), so the low-VA identity mapping does
    // not conflict. Once SMP bringup completes,
    // `mm::paging::unmap_identity_page` (called in Phase 8) retires the
    // mapping so the page can be reclaimed as a Memory cap.
    if trampoline != 0
    {
        // R/W/X: the trampoline page contains startup code AND writable patch areas.
        let rwx = PageFlags {
            readable: true,
            writable: true,
            executable: true,
            uncacheable: false,
        };
        arch_paging::map_page(root_va, trampoline, trampoline, rwx, &mut pool)?;
    }

    // Reload the root: drops any translation cached while stage 2 filled
    // entries that stage 1 left not-present (RISC-V may cache invalid
    // entries). After this point the direct map covers all RAM.
    // SAFETY: the same tables as above, now complete.
    unsafe {
        arch_paging::activate(root_pa);
    }
    crate::mm::init::record_boot_table_carve(carve, pool.carve_used() as u64);

    Ok(())
}

/// Map the 2 MiB direct-map chunk at `phys`: one large page, or, when the
/// chunk holds a kernel MMIO page, 4 KiB pages so the MMIO pages can be
/// uncacheable while the rest stay write-back (`direct_map_page_flags`).
#[cfg(not(test))]
fn map_direct_chunk(
    root_va: u64,
    dm_base: u64,
    phys: u64,
    mmio_regions: &[(u64, u64)],
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    if span_overlaps_regions(phys, LARGE_PAGE_SIZE, mmio_regions)
    {
        return map_direct_pages(root_va, dm_base, phys, LARGE_PAGE_SIZE, mmio_regions, pool);
    }
    let rw = direct_map_page_flags(phys, &[]);
    arch_paging::map_large_page(root_va, dm_base + phys, phys, rw, pool)
}

/// Map every 4 KiB page `[phys, phys + len)` touches at `dm_base + phys`,
/// uncacheable where a page overlaps one of `mmio_regions`.
#[cfg(not(test))]
fn map_direct_pages(
    root_va: u64,
    dm_base: u64,
    phys: u64,
    len: u64,
    mmio_regions: &[(u64, u64)],
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    let page_mask = !(PAGE_SIZE as u64 - 1);
    let mut page = phys & page_mask;
    let end = (phys + len + PAGE_SIZE as u64 - 1) & page_mask;
    while page < end
    {
        let flags = direct_map_page_flags(page, mmio_regions);
        arch_paging::map_page(root_va, dm_base + page, page, flags, pool)?;
        page += PAGE_SIZE as u64;
    }
    Ok(())
}

/// The framebuffer's `(physical base, bytes)` when it lies at or above
/// `max_phys_rounded`, outside the RAM direct map; `None` when there is none
/// or the RAM direct map covers it.
#[cfg(not(test))]
fn framebuffer_above(info: &BootInfo, max_phys_rounded: u64) -> Option<(u64, u64)>
{
    let fb_phys = info.framebuffer.physical_base;
    (fb_phys != 0 && fb_phys >= max_phys_rounded).then(|| {
        (
            fb_phys,
            u64::from(info.framebuffer.stride) * u64::from(info.framebuffer.height),
        )
    })
}

/// Tear down a 4 KiB identity mapping (VA == PA) in the kernel root page
/// table, flush the local TLB, and broadcast a shootdown to all other
/// online CPUs so the underlying physical page becomes reclaim-safe.
///
/// Used to retire the AP-trampoline identity mapping after SMP bringup
/// completes. The walk only clears the leaf PTE; intermediate tables are
/// left in place because they host other live low-VA mappings — notably
/// the boot-stack identity mapping installed by `init_kernel_page_tables`
/// — and freeing them would corrupt unrelated live state.
///
/// # Safety
/// `pa` must be 4 KiB-aligned. No thread (BSP or AP) may execute code on
/// or reference data inside the page after this returns. Caller need not
/// hold any lock, but must not migrate between CPUs during the call (each
/// implementation flushes the local TLB and reads the current CPU to exclude
/// it from the shootdown before disabling preemption).
#[cfg(not(test))]
pub unsafe fn unmap_identity_page(pa: u64)
{
    // SAFETY: arch implementation handles the walk, local invalidate, and
    // cross-CPU shootdown; caller's pa-aligned + no-live-reference contract
    // is forwarded.
    unsafe {
        arch_paging::unmap_identity_page(pa);
    }
}

/// Test stub.
#[cfg(test)]
pub unsafe fn unmap_identity_page(_pa: u64) {}

/// Map kernel image sections with W^X permissions using 4 KiB pages.
///
/// Physical addresses are derived from the kernel VA/PA offset in `info`.
#[cfg(not(test))]
fn map_kernel_image(root_va: u64, info: &BootInfo, pool: &mut PoolState)
-> Result<(), PagingError>
{
    let kv = info.kernel_virtual_base;
    let kp = info.kernel_physical_base;

    // Helper: map a virtual range [start, end) with given flags.
    // Physical address = virt - kv + kp.
    let map_range = |root_va: u64,
                     virt_start: u64,
                     virt_end: u64,
                     flags: PageFlags,
                     pool: &mut PoolState|
     -> Result<(), PagingError> {
        let mut virt = virt_start;
        while virt < virt_end
        {
            let pa = virt.wrapping_sub(kv).wrapping_add(kp);
            arch_paging::map_page(root_va, virt, pa, flags, pool)?;
            virt += PAGE_SIZE as u64;
        }
        Ok(())
    };

    // .text: readable + executable, not writable (W^X).
    let rx = PageFlags {
        readable: true,
        writable: false,
        executable: true,
        uncacheable: false,
    };
    let text_start = core::ptr::addr_of!(__text_start) as u64;
    let text_end = core::ptr::addr_of!(__text_end) as u64;
    map_range(root_va, text_start, text_end, rx, pool)?;

    // .rodata: readable only.
    let ro = PageFlags {
        readable: true,
        writable: false,
        executable: false,
        uncacheable: false,
    };
    let rodata_start = core::ptr::addr_of!(__rodata_start) as u64;
    let rodata_end = core::ptr::addr_of!(__rodata_end) as u64;
    map_range(root_va, rodata_start, rodata_end, ro, pool)?;

    // .data + .bss: readable + writable, not executable (W^X).
    let rw = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: false,
    };
    let data_start = core::ptr::addr_of!(__data_start) as u64;
    let bss_end = core::ptr::addr_of!(__bss_end) as u64;
    map_range(root_va, data_start, bss_end, rw, pool)?;

    Ok(())
}

/// Identity-map the window that holds the bootloader's handoff stack, so the
/// stack stays usable after the page-table switch until `kernel_entry`
/// rebases it into the direct map.
///
/// The handoff stack is [`HANDOFF_STACK_BYTES`] long, 4 KiB-aligned, and the
/// stack pointer lies inside it (core/boot/docs/kernel-handoff.md), so its top
/// is above `sp` and at most that many bytes above the page holding `sp`:
/// [`handoff_stack_window`] covers every such placement. It also maps up to
/// one stack's worth of pages beside the stack, which are never accessed
/// through this low-half alias.
///
/// If the stack pointer is already within the kernel image mapping (unlikely
/// but possible), this is a no-op.
///
/// [`HANDOFF_STACK_BYTES`]: boot_protocol::layout::HANDOFF_STACK_BYTES
#[cfg(not(test))]
fn map_boot_stack(root_va: u64, info: &BootInfo, pool: &mut PoolState) -> Result<(), PagingError>
{
    let sp = arch_paging::read_stack_pointer();

    // Skip if SP already falls within the kernel image mapping.
    let kv = info.kernel_virtual_base;
    let kv_end = kv.wrapping_add(info.kernel_size);
    if sp >= kv && sp < kv_end
    {
        return Ok(());
    }

    let (lo, hi) = handoff_stack_window(sp);
    let rw = PageFlags {
        readable: true,
        writable: true,
        executable: false,
        uncacheable: false,
    };
    let mut virt = lo;
    while virt < hi
    {
        arch_paging::map_page(root_va, virt, virt, rw, pool)?;
        virt += PAGE_SIZE as u64;
    }

    Ok(())
}

/// The page-aligned `[lo, hi)` that holds every [`HANDOFF_STACK_BYTES`]-long,
/// page-aligned stack containing `sp`.
///
/// The stack's top `t` is a page boundary with `sp < t <= sp + S`, so
/// `page(sp) + 4 KiB <= t <= page(sp) + S`, and its base `t - S` is at least
/// `page(sp) + 4 KiB - S`.
///
/// [`HANDOFF_STACK_BYTES`]: boot_protocol::layout::HANDOFF_STACK_BYTES
fn handoff_stack_window(sp: u64) -> (u64, u64)
{
    let stack = boot_protocol::layout::HANDOFF_STACK_BYTES as u64;
    let page = PAGE_SIZE as u64;
    let sp_page = sp & !(page - 1);
    (
        (sp_page + page).saturating_sub(stack),
        sp_page.saturating_add(stack),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::{MemoryMapEntry, MemoryMapSlice, MemoryType};

    // ── Kernel MMIO in the direct map ────────────────────────────────────────

    /// The xAPIC page at its architectural default, below a >4 GiB RAM ceiling.
    const LAPIC: (u64, u64) = (0xFEE0_0000, 0x1000);

    #[test]
    fn direct_map_marks_exactly_the_kernel_mmio_pages_uncacheable()
    {
        let regions = [LAPIC];
        assert!(direct_map_page_flags(LAPIC.0, &regions).uncacheable);
        assert!(!direct_map_page_flags(LAPIC.0 - 0x1000, &regions).uncacheable);
        assert!(!direct_map_page_flags(LAPIC.0 + 0x1000, &regions).uncacheable);
        let wb = direct_map_page_flags(LAPIC.0, &[]);
        assert!(wb.writable && !wb.executable && !wb.uncacheable);
    }

    #[test]
    fn only_the_large_page_chunk_holding_kernel_mmio_is_split()
    {
        let regions = [LAPIC];
        let chunk = LAPIC.0 & !(LARGE_PAGE_SIZE - 1);
        assert!(span_overlaps_regions(chunk, LARGE_PAGE_SIZE, &regions));
        assert!(!span_overlaps_regions(
            chunk - LARGE_PAGE_SIZE,
            LARGE_PAGE_SIZE,
            &regions
        ));
        assert!(!span_overlaps_regions(
            chunk + LARGE_PAGE_SIZE,
            LARGE_PAGE_SIZE,
            &regions
        ));
        // A region ending exactly where a chunk begins does not overlap it.
        assert!(!span_overlaps_regions(
            0x20_0000,
            LARGE_PAGE_SIZE,
            &[(0x1F_F000, 0x1000)]
        ));
    }

    // ── phys_to_virt / virt_to_phys ──────────────────────────────────────────

    #[test]
    fn phys_virt_roundtrip()
    {
        let phys: u64 = 0x8000_0000;
        assert_eq!(virt_to_phys(phys_to_virt(phys)), phys);
    }

    // ── compute_max_physical_address ─────────────────────────────────────────

    /// Construct a minimal [`BootInfo`] pointing to `entries` for testing.
    ///
    /// Valid only while `entries` is live in the caller's scope.
    fn boot_info_with_map(entries: &[MemoryMapEntry]) -> BootInfo
    {
        // SAFETY: every BootInfo field is an integer, a raw pointer, or a fieldless
        // enum with a 0 discriminant (`SegmentFlags::Read`, `PixelFormat::Rgbx8`), so
        // the all-zero bit pattern is a valid BootInfo; `entries` outlives `info`.
        let mut info = unsafe { core::mem::zeroed::<BootInfo>() };
        info.memory_map = MemoryMapSlice {
            entries: entries.as_ptr(),
            count: entries.len() as u64,
        };
        info
    }

    #[test]
    fn max_phys_single_entry()
    {
        let entries = [MemoryMapEntry {
            physical_base: 0x0,
            size: 0x1000_0000, // 256 MiB
            memory_type: MemoryType::Usable,
        }];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x1000_0000);
    }

    #[test]
    fn max_phys_multiple_entries()
    {
        let entries = [
            MemoryMapEntry {
                physical_base: 0x0,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                physical_base: 0x4000_0000,
                size: 0x1000_0000,
                memory_type: MemoryType::Usable,
            },
        ];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x5000_0000);
    }

    #[test]
    fn max_phys_out_of_order_entries()
    {
        let entries = [
            MemoryMapEntry {
                physical_base: 0x8000_0000,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                physical_base: 0x1000,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
        ];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x8000_1000);
    }

    /// `Reserved` entries (e.g. 64-bit PCIe MMIO windows reported by UEFI
    /// firmware) must not inflate `max_phys`, otherwise Phase 3 would direct-map
    /// the aperture with 2 MiB pages, sizing its page-table carve for it.
    #[test]
    fn max_phys_reserved_entries_are_excluded()
    {
        let entries = [
            MemoryMapEntry {
                physical_base: 0x0,
                size: 0x2000_0000, // 512 MiB of usable RAM
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                // Simulates a 64-bit PCIe MMIO window at 512 GiB.
                physical_base: 0x80_0000_0000,
                size: 0x80_0000_0000,
                memory_type: MemoryType::Reserved,
            },
        ];
        let info = boot_info_with_map(&entries);
        // Only the Usable entry should be considered; the 512 GiB Reserved
        // entry must be ignored.
        assert_eq!(compute_max_physical_address(&info), 0x2000_0000);
    }

    #[test]
    fn max_phys_includes_loaded_acpi_persistent()
    {
        // Loaded, AcpiReclaimable, and Persistent are RAM-backed and must be
        // included in the max calculation.
        let entries = [
            MemoryMapEntry {
                physical_base: 0x0,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            },
            MemoryMapEntry {
                physical_base: 0x1000_0000,
                size: 0x1000,
                memory_type: MemoryType::Loaded,
            },
            MemoryMapEntry {
                physical_base: 0x2000_0000,
                size: 0x1000,
                memory_type: MemoryType::AcpiReclaimable,
            },
            MemoryMapEntry {
                physical_base: 0x3000_0000,
                size: 0x1000,
                memory_type: MemoryType::Persistent,
            },
        ];
        let info = boot_info_with_map(&entries);
        assert_eq!(compute_max_physical_address(&info), 0x3000_1000);
    }

    // ── Boot stack window ────────────────────────────────────────────────────

    // Defect caught: the former 64 KiB-aligned window around SP, which leaves
    // the low part of a stack that is only 4 KiB-aligned unmapped.
    #[test]
    fn the_stack_window_covers_every_page_aligned_stack_holding_sp()
    {
        let size = boot_protocol::layout::HANDOFF_STACK_BYTES as u64;
        // A stack straddling a 64 KiB boundary, its base only 4 KiB-aligned.
        let base = 0x4_3000;
        for sp in [base, base + 0x10, base + size / 2, base + size - 8]
        {
            let (lo, hi) = handoff_stack_window(sp);
            assert!(
                lo <= base && base + size <= hi,
                "sp {sp:#x}: {lo:#x}..{hi:#x}"
            );
            assert_eq!(hi - lo, 2 * size - 0x1000);
        }
    }

    // ── Stage-2 frame bound ──────────────────────────────────────────────────

    #[test]
    fn span_bound_counts_one_table_per_level_for_a_small_span()
    {
        // One 2 MiB leaf: a PD, a PDPT, and a level-4 table (five-level).
        assert_eq!(span_table_bound(0, LARGE_PAGE_SIZE, 21), 3);
        // One 4 KiB leaf adds its PT.
        assert_eq!(span_table_bound(0x1000, 0x2000, 12), 4);
        assert_eq!(span_table_bound(0x1000, 0x1000, 12), 0);
    }

    // Defect caught: a carve sized below what stage 2 allocates, which would
    // exhaust it after the stage-1 switch, where the boot cannot report it.
    #[test]
    fn the_stage2_bound_covers_every_table_a_large_direct_map_allocates()
    {
        let top: u64 = 600 << 30;
        let lapic = (0xFEE0_0000, 0x1000);
        let high_mmio = (top + (5 << 30), 0x1000);
        let fb = (top + (7 << 30), 8 << 20);
        let trampoline = 0x8000;
        let regions = [lapic, high_mmio];
        let bound = stage2_table_bound(top, &regions, Some(fb), trampoline);
        let frames = bound as usize + 1; // plus the root
        let buf = make_test_pool_buf(frames);
        let mut pool = PoolState::new_for_test(aligned_start(&buf), frames);
        let (root_va, _) = pool.alloc_frame().unwrap();
        let dm = direct_map_base();
        let map = crate::arch::current::paging::map_page;
        let mut phys = 0;
        while phys < top
        {
            if span_overlaps_regions(phys, LARGE_PAGE_SIZE, &regions)
            {
                for page in (phys..phys + LARGE_PAGE_SIZE).step_by(0x1000)
                {
                    let flags = direct_map_page_flags(page, &regions);
                    map(root_va, dm + page, page, flags, &mut pool).unwrap();
                }
            }
            else
            {
                let flags = direct_map_page_flags(phys, &[]);
                crate::arch::current::paging::map_large_page(
                    root_va,
                    dm + phys,
                    phys,
                    flags,
                    &mut pool,
                )
                .unwrap();
            }
            phys += LARGE_PAGE_SIZE;
        }
        for (base, len) in [high_mmio, fb, (trampoline, 0x1000)]
        {
            for page in (base..base + len).step_by(0x1000)
            {
                let va = if base == trampoline { page } else { dm + page };
                let flags = direct_map_page_flags(page, &regions);
                map(root_va, va, page, flags, &mut pool).unwrap();
            }
        }
        // Every map succeeded inside a pool of `bound` frames past the root.
        assert!(pool.next <= frames);
    }

    // ── PoolState ─────────────────────────────────────────────────────────────

    // Allocate a test pool buffer of `n` × 4 KiB frames aligned to 4 KiB.
    // The Vec must stay alive for the duration of the test.
    fn make_test_pool_buf(n: usize) -> Vec<u8>
    {
        // Over-allocate by one frame so we can find a 4 KiB-aligned start.
        let align = 4096usize;
        let total = n * align + align;
        vec![0u8; total]
    }

    fn aligned_start(buf: &[u8]) -> u64
    {
        let ptr = buf.as_ptr() as u64;
        (ptr + 4095) & !4095
    }

    #[test]
    fn pool_alloc_returns_sequential_frames()
    {
        let buf = make_test_pool_buf(4);
        let base = aligned_start(&buf);
        let mut pool = PoolState::new_for_test(base, 4);

        let (va0, pa0) = pool.alloc_frame().unwrap();
        let (va1, pa1) = pool.alloc_frame().unwrap();

        assert_eq!(va1, va0 + 4096);
        assert_eq!(pa1, pa0 + 4096);
    }

    #[test]
    fn pool_exhaustion_returns_err()
    {
        let buf = make_test_pool_buf(2);
        let base = aligned_start(&buf);
        let mut pool = PoolState::new_for_test(base, 2);

        assert!(pool.alloc_frame().is_ok());
        assert!(pool.alloc_frame().is_ok());
        assert_eq!(pool.alloc_frame(), Err(PagingError::OutOfFrames));
    }

    // Defect caught: a stage-2 walk resolving a seed table through the direct
    // map (which does not cover it then) or a carve table through the image.
    #[test]
    fn after_the_switch_frames_come_from_the_carve_and_each_resolves_by_source()
    {
        let buf = make_test_pool_buf(2);
        let seed = aligned_start(&buf);
        let mut pool = PoolState::new_for_test(seed, 2);
        let (_, seed_pa) = pool.alloc_frame().unwrap();
        let dm = 0xFFFF_9000_0000_0000;
        pool.switch_to_carve(0x10_0000, 2, dm);
        let (va, pa) = pool.alloc_frame().unwrap();
        assert_eq!((va, pa), (dm + 0x10_0000, 0x10_0000));
        assert_eq!(pool.phys_to_virt(pa), dm + pa);
        assert_eq!(pool.phys_to_virt(seed_pa), seed_pa);
        pool.alloc_frame().unwrap();
        assert_eq!(pool.alloc_frame(), Err(PagingError::OutOfFrames));
        assert_eq!(pool.carve_used(), 2);
    }

    #[test]
    fn pool_phys_to_virt_identity_in_test_mode()
    {
        let buf = make_test_pool_buf(1);
        let base = aligned_start(&buf);
        let pool = PoolState::new_for_test(base, 1);
        // new_for_test uses kv_minus_kp = 0, so phys_to_virt is identity.
        assert_eq!(pool.phys_to_virt(base), base);
    }
}
