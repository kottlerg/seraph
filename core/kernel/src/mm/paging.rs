// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/paging.rs

//! Kernel page table initialization (Phase 3).
//!
//! Establishes two permanent kernel mappings:
//! - **Direct physical map** at [`direct_map_base`]: every 2 MiB chunk of RAM
//!   is mapped R/W- via 2 MiB large pages, so any physical address is
//!   accessible as `direct_map_base() + phys`, except the guard page below the
//!   handoff stack ([`handoff_guard_phys`]), which the build leaves unmapped
//!   in a chunk of 4 KiB pages so an overflow of the stack faults (the other
//!   kernel stacks' guards are holed later, `mm::stack_guard`).
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
//! [`BootInfo`]. It maps the kernel image, the boot stack, and the first two
//! direct-map chunks of a carve of free RAM sized to [`stage2_table_bound`]
//! ([`carve_bootstrap_end`]), then activates the tables. Stage 2 draws its
//! frames from the carve, reachable through the live direct map: first it maps
//! the carve's other chunks, each from frames of the part already mapped
//! ([`map_carve_rest`]), then the rest: the direct map of all RAM, the
//! framebuffer and kernel MMIO above it, and the AP trampoline page. Phase 2's
//! free-range stream keeps the frames stage 2 used out of the buddy
//! (`mm::init::record_boot_table_carve`). The seed's size is fixed by the
//! kernel image, and the carve's by the machine, so no amount of RAM exhausts
//! either ([`BOOT_TABLE_POOL_SIZE`]).

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

/// Physical address of the kernel's root page table (the boot depth's PML4 or
/// PML5 on x86-64, the negotiated-mode root on RISC-V).
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
    /// A permission change asked for write or execute that the leaf's
    /// [`LeafGrant`] lacks (returned by the protect walk).
    NotGranted,
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

/// The most a user leaf may ever allow: the Write and Execute rights of the
/// capability that installed it, kept in two software bits of the leaf.
///
/// `SYS_MEM_MAP` records the Memory capability's rights, whatever protection
/// the call asks for; `SYS_MMIO_MAP` records the Mmio capability's Write and
/// never Execute; the kernel's own mappings for init record the rights they
/// install. A permission change keeps the grant and refuses write or execute
/// beyond it, and a text write of `SYS_THREAD_WRITE_MEM` reaches a read-only
/// leaf only when it grants one of them (core/kernel/docs/memory-internals.md
/// § Leaf Grant).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeafGrant
{
    /// The installing capability carries Write.
    pub writable: bool,
    /// The installing capability carries Execute.
    pub executable: bool,
}

impl LeafGrant
{
    /// The grant of a leaf whose most is its own rights, `flags`.
    pub fn of(flags: PageFlags) -> Self
    {
        Self {
            writable: flags.writable,
            executable: flags.executable,
        }
    }

    /// Whether a leaf with this grant may take the rights `flags`: write only
    /// when it grants write, execute only when it grants execute.
    pub fn admits(self, flags: PageFlags) -> bool
    {
        (self.writable || !flags.writable) && (self.executable || !flags.executable)
    }
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

/// The access a user page fault made, decoded once from the architecture's
/// fault report: the spurious-fault retry
/// (`arch::current::paging::user_fault_is_spurious`) asks whether the live leaf
/// PTE grants it, and the fault message names it ([`Self::fault_access_bit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserAccess
{
    /// A data read.
    Load,
    /// A data write (on RISC-V, a store or AMO).
    Store,
    /// An instruction fetch.
    Fetch,
}

impl UserAccess
{
    /// The `FAULT_ACCESS_*` bit that names this access in a `FAULT_KIND_VM`
    /// fault message's `d2` (docs/fault-handling.md).
    pub fn fault_access_bit(self) -> u64
    {
        match self
        {
            Self::Load => syscall::FAULT_ACCESS_READ,
            Self::Store => syscall::FAULT_ACCESS_WRITE,
            Self::Fetch => syscall::FAULT_ACCESS_EXEC,
        }
    }
}

// ── Static boot table pool ────────────────────────────────────────────────────

/// Number of 4 KiB frames in the stage-1 BSS seed (256 KiB).
///
/// Stage 1 maps only the root, the kernel image, the boot stack window and the
/// first two direct-map chunks of the stage-2 carve, whose frames map the rest
/// of it ([`map_carve_rest`]), so the seed's need is fixed by the image size,
/// not by RAM: the image's tables (one per 2 MiB of image plus its upper
/// levels), about eight for the stack window, and for the two carve chunks at
/// most two table chains (they can straddle a table boundary at their virtual
/// address) and two leaf tables (a chunk holding a kernel MMIO page or the
/// handoff stack's guard). 64
/// frames leave room for a 64 MiB image at any paging depth (a fifth level
/// adds one table to each chain). A seed too small fails the boot
/// in Phase 3 by name.
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
    /// Carve frames the direct map reaches so far: frames are handed out only
    /// below it ([`PoolState::extend_carve_mapped`]).
    carve_mapped: usize,
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
            carve_mapped: 0,
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
            carve_mapped: 0,
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
            if self.carve_next >= self.carve_capacity.min(self.carve_mapped)
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
    /// the first `mapped` of them; later ones are handed out once
    /// [`Self::extend_carve_mapped`] says the direct map reaches them.
    pub fn switch_to_carve(&mut self, base: u64, frames: usize, dm_base: u64, mapped: usize)
    {
        self.carve_pa_base = base;
        self.carve_capacity = frames;
        self.carve_next = 0;
        self.carve_mapped = mapped;
        self.dm_base = dm_base;
    }

    /// Record that the direct map now reaches the carve's first `mapped`
    /// frames.
    pub fn extend_carve_mapped(&mut self, mapped: usize)
    {
        self.carve_mapped = self.carve_mapped.max(mapped);
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

// ── Carve bootstrap ───────────────────────────────────────────────────────────

/// End of the carve chunks stage 1 maps from the seed: the first two of the
/// carve's 2 MiB chunks `chunks` (all of them, when there are fewer). Two
/// hold at least 513 of the carve's frames whenever the carve spans more,
/// since only its first chunk can be partial, so the seed's share is a
/// constant whatever the carve's size.
#[must_use]
pub fn carve_bootstrap_end(chunks: (u64, u64)) -> u64
{
    chunks.1.min(chunks.0.saturating_add(2 * LARGE_PAGE_SIZE))
}

/// Frames of the carve of `frames` frames at `base` that lie below `end`.
#[must_use]
pub fn carve_frames_below(base: u64, frames: usize, end: u64) -> usize
{
    ((end.saturating_sub(base) / PAGE_SIZE as u64) as usize).min(frames)
}

/// Switch `pool` to the carve `(base, frames, dm_base)` (see
/// [`PoolState::switch_to_carve`]), whose chunks below `rest.0` the direct map
/// reaches, and map its other chunks `[rest.0, rest.1)` with frames from the
/// carve: after each chunk `map_chunk` maps, the pool may hand out the carve
/// frames it holds. A chunk's mapping takes at most one table per level below the
/// root, and each chunk mapped makes 512 more frames reachable, so the
/// frames handed out stay inside the mapped prefix, which starts with the
/// chunks stage 1 mapped ([`carve_bootstrap_end`]). `map_chunk` makes the
/// chunk usable before it returns, the TLB fence a fresh mapping needs
/// included, since its frames are handed out, and written, next.
///
/// # Errors
/// [`PagingError::OutOfFrames`] if a chunk's tables outrun the mapped prefix
/// (a prefix too small, a defect in the bound above), or `map_chunk`'s error.
pub fn map_carve_rest(
    pool: &mut PoolState,
    (base, frames, dm_base): (u64, usize, u64),
    rest: (u64, u64),
    mut map_chunk: impl FnMut(&mut PoolState, u64) -> Result<(), PagingError>,
) -> Result<(), PagingError>
{
    pool.switch_to_carve(
        base,
        frames,
        dm_base,
        carve_frames_below(base, frames, rest.0),
    );
    let mut phys = rest.0;
    while phys < rest.1
    {
        map_chunk(pool, phys)?;
        phys += LARGE_PAGE_SIZE;
        pool.extend_carve_mapped(carve_frames_below(base, frames, phys));
    }
    Ok(())
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
/// table per kernel-MMIO region below `direct_top` and one for the direct-map
/// `hole` when it lies below it (each splits its 2 MiB chunk), and 4 KiB
/// mappings of every region above it, of the framebuffer span `fb` when it
/// lies above, and of the AP trampoline page (identity-mapped).
///
/// The tables are indexed by virtual address, `dm_base + phys` in the direct
/// map, and `dm_base` is only 1 GiB-aligned, so every span is counted at its
/// virtual address: a span can touch one more 512 GiB block virtually than
/// physically.
#[must_use]
pub fn stage2_table_bound(
    dm_base: u64,
    direct_top: u64,
    mmio_regions: &[(u64, u64)],
    fb: Option<(u64, u64)>,
    trampoline: u64,
    hole: Option<u64>,
) -> u64
{
    let mut frames = span_table_bound(dm_base, dm_base.saturating_add(direct_top), 21);
    if hole.is_some_and(|h| h < direct_top)
    {
        frames += 1;
    }
    for &(base, size) in mmio_regions
    {
        frames += if base < direct_top
        {
            1
        }
        else
        {
            let va = dm_base.saturating_add(base);
            span_table_bound(va, va.saturating_add(size), 12)
        };
    }
    if let Some((base, size)) = fb
    {
        let va = dm_base.saturating_add(base);
        frames += span_table_bound(va, va.saturating_add(size), 12);
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

/// What the direct map maps at a page other than plain RAM: the kernel's own
/// MMIO `regions`, uncacheable, and the one `hole` page it leaves unmapped
/// (the handoff stack's guard). A 2 MiB chunk holding either is mapped in
/// 4 KiB pages.
#[derive(Clone, Copy)]
struct DirectMapLayout<'a>
{
    mmio: &'a [(u64, u64)],
    hole: Option<u64>,
}

impl DirectMapLayout<'_>
{
    /// Whether the chunk at `chunk` is mapped in 4 KiB pages rather than one
    /// large page.
    fn splits_chunk(&self, chunk: u64) -> bool
    {
        span_overlaps_regions(chunk, LARGE_PAGE_SIZE, self.mmio)
            || self
                .hole
                .is_some_and(|h| (chunk..chunk + LARGE_PAGE_SIZE).contains(&h))
    }

    /// Flags of the 4 KiB page at `page`, or `None` for the hole.
    fn page_flags(&self, page: u64) -> Option<PageFlags>
    {
        (self.hole != Some(page)).then(|| direct_map_page_flags(page, self.mmio))
    }
}

/// Fill `table` with the 512 4 KiB leaves `leaf` builds for the pages of the
/// 2 MiB chunk at `chunk`, in order: the leaf table that splits a large
/// direct-map leaf into the same translation (each arch's
/// `hole_direct_map_page`).
pub fn fill_split_table<E>(table: &mut [E; 512], chunk: u64, leaf: impl Fn(u64) -> E)
{
    for (i, entry) in table.iter_mut().enumerate()
    {
        *entry = leaf(chunk + (i * PAGE_SIZE) as u64);
    }
}

/// The handoff stack's guard page for the stack pointer `entry_sp` at
/// `kernel_entry`'s first statement, when `base_mark` (the word at the stack
/// base derived from it, `stack_depth::handoff_base`) confirms the reference
/// bootloader's layout: the stack base holds
/// [`HANDOFF_STACK_BASE_MARK`](boot_protocol::layout::HANDOFF_STACK_BASE_MARK)
/// and the page below it is the allocation's guard
/// (core/boot/docs/kernel-handoff.md). `None` when no pointer was recorded or
/// the mark is absent: under another bootloader the page below may be live.
fn handoff_guard_for(entry_sp: u64, base_mark: impl FnOnce(u64) -> u64) -> Option<u64>
{
    if entry_sp == 0
    {
        return None;
    }
    let base = crate::stack_depth::handoff_base(
        entry_sp,
        PAGE_SIZE as u64,
        boot_protocol::layout::HANDOFF_STACK_BYTES as u64,
    );
    (base >= PAGE_SIZE as u64 && base_mark(base) == boot_protocol::layout::HANDOFF_STACK_BASE_MARK)
        .then(|| base - PAGE_SIZE as u64)
}

/// Physical address of the handoff stack's guard page, which the direct map
/// leaves unmapped, or 0 when Phase 3 found none (`handoff_guard_for`).
#[cfg(not(test))]
static HANDOFF_GUARD_PHYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The handoff stack's guard page the direct map leaves unmapped, if Phase 3
/// found one.
#[cfg(not(test))]
pub fn handoff_guard_phys() -> Option<u64>
{
    match HANDOFF_GUARD_PHYS.load(core::sync::atomic::Ordering::Relaxed)
    {
        0 => None,
        phys => Some(phys),
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
    check_direct_map_below_image(info, dm_base);

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
    // The handoff stack's guard, left out of the direct map.
    let hole = find_handoff_guard();
    let layout = DirectMapLayout {
        mmio: mmio_regions,
        hole,
    };

    // Everything stage 2 maps is read from `info` now: after the stage-1
    // switch the bootloader's identity map of `info` is gone.
    let fb = framebuffer_above(info, max_phys_rounded);
    let trampoline = info.ap_trampoline_page;
    let carve_frames = stage2_table_bound(
        dm_base,
        max_phys_rounded,
        mmio_regions,
        fb,
        trampoline,
        hole,
    );
    let carve = crate::mm::init::find_boot_table_carve(info, carve_frames)
        .ok_or(BootTableError::NoTableCarve)?;
    let carve_end = carve + carve_frames * PAGE_SIZE as u64;
    let carve_chunks = (
        carve & !(LARGE_PAGE_SIZE - 1),
        (carve_end + LARGE_PAGE_SIZE - 1) & !(LARGE_PAGE_SIZE - 1),
    );

    // ── Stage 1, from the BSS seed ────────────────────────────────────────────
    // Only the carve's first chunks: they hold the frames that map the rest
    // of it, so the seed's need does not grow with the carve.
    map_kernel_image(root_va, info, &mut pool)?;
    map_boot_stack(root_va, info, &mut pool)?;
    let bootstrap_end = carve_bootstrap_end(carve_chunks);
    map_direct_chunks(
        root_va,
        dm_base,
        (carve_chunks.0, bootstrap_end),
        layout,
        &mut pool,
    )?;
    // SAFETY: the tables map the kernel image (code, data, this stack's frame
    // via the boot stack window) and the carve's first chunks in the direct
    // map; nothing below touches `info` or other identity-mapped memory.
    unsafe {
        arch_paging::activate(root_pa);
    }

    // ── Stage 2, from the carve ───────────────────────────────────────────────
    // The carve frames' bound fits `usize` on the 64-bit kernel. The rest of
    // the carve is mapped first, from the frames its mapped prefix holds.
    map_carve_rest(
        &mut pool,
        (carve, carve_frames as usize, dm_base),
        (bootstrap_end, carve_chunks.1),
        |pool, phys| {
            map_direct_chunk(root_va, dm_base, phys, layout, pool)?;
            // The next frames handed out lie in the chunk just mapped, and
            // stage 2 writes them through these entries at once: RISC-V may
            // cache an invalid entry, so the full fence (both operands zero,
            // non-leaf entries included) precedes those writes. A CR3 reload
            // on x86-64, which caches no not-present entry.
            // SAFETY: Phase 3, single-threaded, on the tables activated
            // above; nothing relies on a translation the flush drops.
            unsafe { arch_paging::flush_tlb_all() };
            Ok(())
        },
    )?;

    // Direct physical map of [0, max_phys_rounded) in 2 MiB pages, except a
    // chunk holding a kernel MMIO page or the hole (`map_direct_chunk`). The
    // carve's own chunks are mapped already.
    let mut phys: u64 = 0;
    while phys < max_phys_rounded
    {
        if phys < carve_chunks.0 || phys >= carve_chunks.1
        {
            map_direct_chunk(root_va, dm_base, phys, layout, &mut pool)?;
        }
        phys += LARGE_PAGE_SIZE;
    }

    // Framebuffer, when it lies above the RAM ceiling.
    if let Some((fb_phys, fb_bytes)) = fb
    {
        let plain = DirectMapLayout {
            mmio: &[],
            hole: None,
        };
        map_direct_pages(root_va, dm_base, (fb_phys, fb_bytes), plain, &mut pool)?;
    }

    // Kernel MMIO above the RAM ceiling: a region below it was mapped
    // uncacheable by the direct-map loop; one above gets its own uncacheable
    // 4 KiB pages here.
    for &(phys_base, size) in mmio_regions
    {
        if phys_base >= max_phys_rounded
        {
            map_direct_pages(root_va, dm_base, (phys_base, size), layout, &mut pool)?;
        }
    }

    map_ap_trampoline(root_va, trampoline, &mut pool)?;

    // Reload the root: drops any translation cached while stage 2 filled
    // entries that stage 1 left not-present (RISC-V may cache invalid
    // entries). After this point the direct map covers all RAM but the
    // handoff stack's guard page (`handoff_guard_phys`).
    // SAFETY: the same tables as above, now complete.
    unsafe {
        arch_paging::activate(root_pa);
    }
    crate::mm::init::record_boot_table_carve(carve, pool.carve_used() as u64);

    Ok(())
}

/// Re-check, on the shared `boot_protocol::direct_map_ceiling`, that the
/// direct map at `dm_base` ends at or below the kernel image base; halt with a
/// diagnostic rather than overlap the image mapping
/// (core/kernel/docs/initialization.md § Phase 3: Kernel Page Tables; Sv39
/// margin: docs/memory-model.md § RISC-V (Sv39 / Sv48 / Sv57)).
#[cfg(not(test))]
fn check_direct_map_below_image(info: &BootInfo, dm_base: u64)
{
    // SAFETY: Phase 0 validated the memory map; identity-mapped at this point
    // (pre-activate).
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };
    let ceiling = boot_protocol::direct_map_ceiling(entries, &info.framebuffer, &info.kernel_mmio);
    if dm_base
        .checked_add(ceiling)
        .is_none_or(|end| end > info.kernel_virtual_base)
    {
        crate::fatal("Phase 3: direct map would overlap the kernel image window");
    }
}

/// Map the AP trampoline page at its physical address as a 4 KiB identity page
/// (VA = PA), when there is one (`trampoline` nonzero).
///
/// Both arches need this: on x86-64 the AP enables paging (writes CR3 = kernel
/// root) during the PM32 → LM64 transition and must keep fetching trampoline
/// instructions at their PA through the LM64 relay stub until its `jmp rax`
/// reaches the kernel-VA entry; on RISC-V the trampoline executes `csrw satp`
/// and the next instructions (sfence.vma, mv sp, jr) likewise execute at the
/// trampoline PA before the final `jr` lands at `kernel_entry_ap`'s kernel
/// virtual address.
///
/// The kernel's other mappings are at high virtual addresses (direct map,
/// kernel image), so the low-VA identity mapping does not conflict. Once SMP
/// bringup completes, [`unmap_identity_page`] (called in Phase 8) retires the
/// mapping so the page can be reclaimed as a Memory cap.
#[cfg(not(test))]
fn map_ap_trampoline(root_va: u64, trampoline: u64, pool: &mut PoolState)
-> Result<(), PagingError>
{
    if trampoline == 0
    {
        return Ok(());
    }
    // R/W/X: the trampoline page contains startup code AND writable patch areas.
    let rwx = PageFlags {
        readable: true,
        writable: true,
        executable: true,
        uncacheable: false,
    };
    arch_paging::map_page(root_va, trampoline, trampoline, rwx, pool)
}

/// Find the handoff stack's guard page (`handoff_guard_for`), reading the
/// stack's base mark through the bootloader's tables, and record it for
/// [`handoff_guard_phys`].
#[cfg(not(test))]
fn find_handoff_guard() -> Option<u64>
{
    // The derived base lies inside the `HANDOFF_STACK_BYTES` the boot protocol
    // guarantees below the entry stack pointer.
    let hole = handoff_guard_for(crate::stack_depth::boot_entry_sp(), |base| {
        // SAFETY: `base` is page-aligned and inside the guaranteed stack,
        // which the bootloader's tables (active until Phase 3's switch) map.
        unsafe { core::ptr::read_volatile(base as *const u64) }
    });
    HANDOFF_GUARD_PHYS.store(hole.unwrap_or(0), core::sync::atomic::Ordering::Relaxed);
    hole
}

/// Map the 2 MiB direct-map chunk at `phys`: one large page, or, when the
/// chunk holds a kernel MMIO page or the hole, 4 KiB pages so the MMIO pages
/// can be uncacheable while the rest stay write-back
/// (`direct_map_page_flags`) and the hole stays unmapped.
#[cfg(not(test))]
fn map_direct_chunk(
    root_va: u64,
    dm_base: u64,
    phys: u64,
    layout: DirectMapLayout<'_>,
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    if layout.splits_chunk(phys)
    {
        return map_direct_pages(root_va, dm_base, (phys, LARGE_PAGE_SIZE), layout, pool);
    }
    let rw = direct_map_page_flags(phys, &[]);
    arch_paging::map_large_page(root_va, dm_base + phys, phys, rw, pool)
}

/// Map the 2 MiB direct-map chunks `[chunks.0, chunks.1)` ([`map_direct_chunk`]).
#[cfg(not(test))]
fn map_direct_chunks(
    root_va: u64,
    dm_base: u64,
    chunks: (u64, u64),
    layout: DirectMapLayout<'_>,
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    let mut phys = chunks.0;
    while phys < chunks.1
    {
        map_direct_chunk(root_va, dm_base, phys, layout, pool)?;
        phys += LARGE_PAGE_SIZE;
    }
    Ok(())
}

/// Map every 4 KiB page the span `(phys, len)` touches at `dm_base + phys`,
/// uncacheable where a page overlaps one of the layout's MMIO regions and
/// leaving its hole unmapped.
#[cfg(not(test))]
fn map_direct_pages(
    root_va: u64,
    dm_base: u64,
    (phys, len): (u64, u64),
    layout: DirectMapLayout<'_>,
    pool: &mut PoolState,
) -> Result<(), PagingError>
{
    let page_mask = !(PAGE_SIZE as u64 - 1);
    let mut page = phys & page_mask;
    let end = (phys + len + PAGE_SIZE as u64 - 1) & page_mask;
    while page < end
    {
        if let Some(flags) = layout.page_flags(page)
        {
            arch_paging::map_page(root_va, dm_base + page, page, flags, pool)?;
        }
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
/// The window is [`handoff_stack_window`] of the stack pointer `kernel_entry`
/// recorded at its first statement (`stack_depth::boot_entry_sp`). For that
/// pointer the window leaves out the page below the stack, the reference
/// bootloader's guard (core/boot/docs/boot-flow.md § Step 6), since
/// `kernel_entry`'s frame is smaller than a page. When no pointer was recorded
/// (never on the boot path, where recording is `kernel_entry`'s first
/// statement) the window is that of the current stack pointer, which may map
/// the guard.
///
/// If the stack pointer is already within the kernel image mapping (unlikely
/// but possible), this is a no-op.
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

    let entry_sp = match crate::stack_depth::boot_entry_sp()
    {
        0 => sp,
        recorded => recorded,
    };
    let (lo, hi) = handoff_stack_window(entry_sp);
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

/// The page-aligned `[lo, hi)` the kernel identity-maps over the handoff
/// stack, given `entry_sp`, the stack pointer at `kernel_entry`'s first
/// statement.
///
/// With `S` = [`HANDOFF_STACK_BYTES`] and `t` = `entry_sp` rounded up to a
/// page, the window is `[t - S, t + S)`. Its floor is the base of the stack
/// the kernel's depth report derives from the same pointer
/// (`stack_depth::handoff_base`): under the reference bootloader, whose stack
/// top is page-aligned, `t` is that top whenever `kernel_entry`'s frame is
/// smaller than a page, so the window starts at the stack's lowest page and
/// leaves out the guard page below it. Its ceiling lies at least `S` above
/// `entry_sp`, so it holds the entry stack pointer and `kernel_entry`'s frame
/// whatever their alignment, since that frame lies inside the stack.
///
/// [`HANDOFF_STACK_BYTES`]: boot_protocol::layout::HANDOFF_STACK_BYTES
fn handoff_stack_window(entry_sp: u64) -> (u64, u64)
{
    let stack = boot_protocol::layout::HANDOFF_STACK_BYTES as u64;
    let lo = crate::stack_depth::handoff_base(entry_sp, PAGE_SIZE as u64, stack);
    (lo, lo + 2 * stack)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::{MemoryMapEntry, MemoryMapSlice, MemoryType};

    // ── Leaf grant ────────────────────────────────────────────────────────────

    // The defect caught: a grant test that let a leaf take write or execute
    // its installing capability lacked, so SYS_MEM_PROTECT would widen a
    // read-only Mmio or Memory mapping past that capability (#868); or one
    // that refused a right the grant holds, or a narrowing, so a protect
    // within the mapping's capability would fail.
    #[test]
    fn a_grant_admits_only_the_rights_it_holds()
    {
        let rights = |writable, executable| PageFlags {
            readable: true,
            writable,
            executable,
            uncacheable: false,
        };
        let none = LeafGrant::default();
        let write = LeafGrant {
            writable: true,
            executable: false,
        };
        let exec = LeafGrant {
            writable: false,
            executable: true,
        };
        let both = LeafGrant {
            writable: true,
            executable: true,
        };
        for grant in [none, write, exec, both]
        {
            assert!(grant.admits(rights(false, false)), "{grant:?}");
        }
        assert!(!none.admits(rights(true, false)));
        assert!(!none.admits(rights(false, true)));
        assert!(write.admits(rights(true, false)));
        assert!(!write.admits(rights(false, true)));
        assert!(exec.admits(rights(false, true)));
        assert!(!exec.admits(rights(true, false)));
        assert!(both.admits(rights(true, false)) && both.admits(rights(false, true)));
        assert_eq!(LeafGrant::of(rights(true, false)), write);
        assert_eq!(LeafGrant::of(rights(false, true)), exec);
        assert_eq!(LeafGrant::of(rights(false, false)), none);
    }

    // ── User fault access ────────────────────────────────────────────────────

    // The defect caught: a fault message that names the wrong access (a store
    // reported to the handler as a read, a fetch as a write), which a pager
    // reads to decide how to satisfy the fault.
    #[test]
    fn each_user_access_names_its_own_fault_access_bit()
    {
        assert_eq!(
            UserAccess::Load.fault_access_bit(),
            syscall::FAULT_ACCESS_READ
        );
        assert_eq!(
            UserAccess::Store.fault_access_bit(),
            syscall::FAULT_ACCESS_WRITE
        );
        assert_eq!(
            UserAccess::Fetch.fault_access_bit(),
            syscall::FAULT_ACCESS_EXEC
        );
    }

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

    // Defect caught: a window that reaches below the stack the depth report
    // derives, mapping the reference bootloader's guard page so an overflow of
    // the stack no longer faults.
    #[test]
    fn the_stack_window_starts_at_the_stack_and_leaves_out_its_guard_page()
    {
        let size = boot_protocol::layout::HANDOFF_STACK_BYTES as u64;
        let top = 0x5_3000u64;
        // kernel_entry's frame is smaller than a page.
        for entry_sp in [top - 8, top - 0x800, top - 0xff8]
        {
            let (lo, hi) = handoff_stack_window(entry_sp);
            assert_eq!(lo, top - size, "entry sp {entry_sp:#x}");
            assert!(top <= hi, "entry sp {entry_sp:#x}: {lo:#x}..{hi:#x}");
        }
    }

    // Defect caught: a window whose ceiling is the derived top, which drops the
    // entry stack pointer's page when kernel_entry's frame crosses a page
    // boundary below an entry pointer that is not page-aligned.
    #[test]
    fn the_stack_window_holds_the_entry_frame_whatever_its_alignment()
    {
        let size = boot_protocol::layout::HANDOFF_STACK_BYTES as u64;
        for entry in [0x5_3000u64, 0x5_3008, 0x5_2ff8]
        {
            for frame in [8u64, 0x200, 0x1000, 0x3000]
            {
                let (lo, hi) = handoff_stack_window(entry - frame);
                assert!(
                    lo < entry - frame && entry <= hi && hi - lo == 2 * size,
                    "entry {entry:#x}, frame {frame:#x}: {lo:#x}..{hi:#x}"
                );
            }
        }
    }

    // ── Direct-map hole ──────────────────────────────────────────────────────

    // Defect caught: a split table whose entry i maps any frame but the
    // chunk's page i (an index or stride slip), which would alias every
    // direct-map access in the chunk to the wrong memory.
    #[test]
    fn a_split_table_maps_each_entry_to_its_own_page_of_the_chunk()
    {
        let chunk = 0x8060_0000u64;
        let mut table = [0u64; 512];
        fill_split_table(&mut table, chunk, |phys| phys);
        for (i, &phys) in table.iter().enumerate()
        {
            assert_eq!(phys, chunk + (i as u64) * 0x1000);
        }
    }

    // Defect caught: a hole that splits the wrong chunk, or a split chunk that
    // leaves out a page other than the hole (or none), so the guard is mapped
    // or a live page is not.
    #[test]
    fn only_the_hole_is_left_out_and_only_its_chunk_is_split()
    {
        let hole = 0x4060_3000;
        let layout = DirectMapLayout {
            mmio: &[],
            hole: Some(hole),
        };
        let chunk = hole & !(LARGE_PAGE_SIZE - 1);
        assert!(layout.splits_chunk(chunk));
        assert!(!layout.splits_chunk(chunk + LARGE_PAGE_SIZE));
        assert!(!layout.splits_chunk(chunk - LARGE_PAGE_SIZE));
        let unmapped: Vec<u64> = (chunk..chunk + LARGE_PAGE_SIZE)
            .step_by(0x1000)
            .filter(|&p| layout.page_flags(p).is_none())
            .collect();
        assert_eq!(unmapped, [hole]);
    }

    // Defect caught: a guard derived without the base mark, which under a
    // bootloader that puts live data below the stack would unmap that data,
    // or a guard placed anywhere but the page below the derived base.
    #[test]
    fn the_handoff_guard_is_the_page_below_a_marked_stack_base()
    {
        let mark = boot_protocol::layout::HANDOFF_STACK_BASE_MARK;
        let size = boot_protocol::layout::HANDOFF_STACK_BYTES as u64;
        let top = 0x8053_0000u64;
        let base = top - size;
        let read = |want: u64| move |at: u64| if at == base { want } else { 0 };
        assert_eq!(
            handoff_guard_for(top - 0x40, read(mark)),
            Some(base - 0x1000)
        );
        assert_eq!(handoff_guard_for(top - 0x40, read(mark ^ 1)), None);
        assert_eq!(handoff_guard_for(0, read(mark)), None);
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

    // Defect caught: a bound counted over physical spans, which misses the
    // extra 512 GiB block a direct map at a 1 GiB-aligned KASLR base touches.
    #[test]
    fn the_stage2_bound_counts_the_blocks_the_virtual_span_touches()
    {
        let top: u64 = 600 << 30;
        let aligned = 0xFFFF_8000_0000_0000;
        let misaligned = aligned + (511 << 30);
        // [511 GiB, 1111 GiB) touches three 512 GiB blocks; [0, 600 GiB) two.
        assert_eq!(
            stage2_table_bound(misaligned, top, &[], None, 0, None)
                - stage2_table_bound(aligned, top, &[], None, 0, None),
            1
        );
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
        // The handoff stack's guard, in a chunk of its own.
        let hole = Some((3 << 30) + 0x5000);
        let layout = DirectMapLayout {
            mmio: &regions,
            hole,
        };
        // A KASLR base that is 1 GiB- but not 512 GiB-aligned, so the virtual
        // spans touch more 512 GiB blocks than the physical ones.
        let dm = 0xFFFF_8000_0000_0000 + (511 << 30);
        let bound = stage2_table_bound(dm, top, &regions, Some(fb), trampoline, hole);
        let frames = bound as usize + 1; // plus the root
        let buf = make_test_pool_buf(frames);
        let mut pool = PoolState::new_for_test(aligned_start(&buf), frames);
        let (root_va, _) = pool.alloc_frame().unwrap();
        let map = crate::arch::current::paging::map_page;
        let mut phys = 0;
        while phys < top
        {
            if layout.splits_chunk(phys)
            {
                for page in (phys..phys + LARGE_PAGE_SIZE).step_by(0x1000)
                {
                    if let Some(flags) = layout.page_flags(page)
                    {
                        map(root_va, dm + page, page, flags, &mut pool).unwrap();
                    }
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
        pool.switch_to_carve(0x10_0000, 2, dm, 2);
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

    // Defect caught: a carve whose rest is mapped from frames the direct map
    // does not reach yet, or a stage-1 share that grows with the carve, which
    // brings back a seed sized by RAM.
    #[test]
    fn the_carve_maps_its_rest_from_its_own_mapped_prefix_at_any_size()
    {
        // Each chunk's mapping takes up to one table per level below a
        // five-level root; only frame accounting is modelled, so a carve of
        // any size costs no memory.
        const TABLES_PER_CHUNK: usize = 4;
        let large = LARGE_PAGE_SIZE;
        for (offset_pages, frames) in [
            (0u64, 1usize),
            (0, 600),
            (511, 600),
            (511, 1_000_000),
            (7, 50_000_000),
        ]
        {
            let base = (1u64 << 40) + offset_pages * PAGE_SIZE as u64;
            let end = base + frames as u64 * PAGE_SIZE as u64;
            let chunks = (base & !(large - 1), (end + large - 1) & !(large - 1));
            let prefix_end = carve_bootstrap_end(chunks);
            assert!(
                (prefix_end - chunks.0) / large <= 2,
                "stage 1 maps at most two chunks"
            );
            let mut pool = PoolState::new_for_test(0x1000, 0);
            let mut chunks_mapped = 0usize;
            map_carve_rest(
                &mut pool,
                (base, frames, 0),
                (prefix_end, chunks.1),
                |pool, _| {
                    chunks_mapped += 1;
                    for _ in 0..TABLES_PER_CHUNK.min(frames)
                    {
                        pool.alloc_frame()?;
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|e| panic!("carve of {frames} frames at +{offset_pages}: {e:?}"));
            assert_eq!(
                pool.carve_mapped, frames,
                "the whole carve is reachable afterwards"
            );
            assert_eq!(
                pool.carve_used(),
                chunks_mapped * TABLES_PER_CHUNK.min(frames)
            );
        }
    }

    // Defect caught: a pool that hands out a carve frame past the mapped
    // prefix, which stage 2 would then write through an unmapped address.
    #[test]
    fn a_carve_frame_past_the_mapped_prefix_is_refused()
    {
        let mut pool = PoolState::new_for_test(0x1000, 0);
        pool.switch_to_carve(0x10_0000, 4, 0, 2);
        pool.alloc_frame().unwrap();
        pool.alloc_frame().unwrap();
        assert_eq!(pool.alloc_frame(), Err(PagingError::OutOfFrames));
        pool.extend_carve_mapped(3);
        assert_eq!(pool.alloc_frame(), Ok((0x10_2000, 0x10_2000)));
    }
}
