// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/init.rs

//! Physical memory initialization.
//!
//! Phase 2 ([`init_physical_memory`]) parses the boot-time memory map from
//! [`BootInfo`] and subtracts the boot payload's frames (kernel image, init
//! segments, boot modules, `BootInfo` struct, AP trampoline page), keeping
//! the surviving ranges. The first act of Phase 3 after the page-table switch
//! ([`populate_buddy`]) sizes the device tree blob through the direct map,
//! subtracts it too, and populates the [`BuddyAllocator`], whose free-list
//! links live in the free pages and so need the direct map
//! (core/kernel/docs/initialization.md § Phase 2 and § Phase 3).

// cast_possible_truncation: u64→usize physical address arithmetic; bounded by memory map sizes.
#![allow(clippy::cast_possible_truncation)]

use core::mem::size_of;

use boot_protocol::{BootInfo, MemoryType};

use super::buddy::{BuddyAllocator, PAGE_SIZE};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::kprintln;

/// Lowest and highest physical addresses among entries that represent
/// actual DRAM (`Usable`, `Loaded`, `AcpiReclaimable`, `Persistent`).
/// A `Reserved` entry whose range falls entirely outside
/// `[dram_bottom, dram_top)` is an address-space window
/// (`PCIe MMCFG` / `LAPIC` above DRAM on x86-64,
/// `PLIC` / `CLINT` below DRAM on riscv64-virt), not RAM.
/// Returns `(0, 0)` if no DRAM-typed entries exist.
fn compute_dram_bounds(entries: &[boot_protocol::MemoryMapEntry]) -> (u64, u64)
{
    let mut dram_bottom: u64 = u64::MAX;
    let mut dram_top: u64 = 0;
    for entry in entries
    {
        if entry.size == 0
        {
            continue;
        }
        if matches!(
            entry.memory_type,
            MemoryType::Usable
                | MemoryType::Loaded
                | MemoryType::AcpiReclaimable
                | MemoryType::Persistent
        )
        {
            let start = entry.physical_base;
            let end = start + entry.size;
            if start < dram_bottom
            {
                dram_bottom = start;
            }
            if end > dram_top
            {
                dram_top = end;
            }
        }
    }
    if dram_top == 0
    {
        (0, 0)
    }
    else
    {
        (dram_bottom, dram_top)
    }
}

/// Print one merged memory map line.
fn print_memory_line(idx: usize, start: u64, end: u64, ty: MemoryType)
{
    let size_kib = (end - start) / 1024;
    kprintln!(
        "  [{:3}]  {:#018x} - {:#018x}  {:8} KiB  {}",
        idx,
        start,
        end,
        size_kib,
        memory_type_name(ty)
    );
}

/// Total installed DRAM in bytes, captured by [`print_memory_map`].
/// Read once at Phase 9 to populate `InitInfo::system_ram_bytes`.
static SYSTEM_RAM_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Total installed DRAM in bytes (the sum of every DRAM-typed memory-map
/// region). Zero until [`print_memory_map`] runs at early boot.
#[must_use]
pub fn system_ram_bytes() -> u64
{
    SYSTEM_RAM_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Lowest and highest DRAM addresses (`compute_dram_bounds`), captured by
/// [`print_memory_map`]. Read once at Phase 4 to size the frame map table.
static DRAM_BOUNDS: [core::sync::atomic::AtomicU64; 2] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// The `[bottom, top)` span of DRAM-typed memory-map entries, `(0, 0)` until
/// [`print_memory_map`] runs at early boot or when the map holds no DRAM.
#[must_use]
pub fn dram_bounds() -> (u64, u64)
{
    (
        DRAM_BOUNDS[0].load(core::sync::atomic::Ordering::Relaxed),
        DRAM_BOUNDS[1].load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Print the physical memory map from the bootloader to the serial console.
///
/// Prints one line per run of contiguous same-type entries (address range,
/// size in KiB, type), then a DRAM summary broken down by type in scaled
/// units (KiB/MiB/GiB), plus persistent and MMIO lines when non-zero.
/// Records the DRAM total for [`system_ram_bytes`] and the DRAM span for
/// [`dram_bounds`].
///
/// Must be called before Phase 3 activates the kernel page tables; the
/// `memory_map.entries` pointer is a physical address covered by the
/// bootloader's identity map, which is replaced in Phase 3.
// too_many_lines: a flat, sequential memory-map dump; the per-type tallying,
// run-merging, and summary print read as one unit and gain nothing from
// being split across helpers.
#[allow(clippy::too_many_lines)]
pub fn print_memory_map(info: &BootInfo)
{
    kprintln!("Memory map:");

    // SAFETY: Phase 0 validated entries is non-null and count > 0. The memory
    // map region is identity-mapped by the bootloader at handoff.
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };

    let mut usable_bytes: u64 = 0;
    let mut loaded_bytes: u64 = 0;
    let mut reserved_bytes: u64 = 0;
    let mut acpi_bytes: u64 = 0;
    let mut persistent_bytes: u64 = 0;

    let (dram_bottom, dram_top) = compute_dram_bounds(entries);
    DRAM_BOUNDS[0].store(dram_bottom, core::sync::atomic::Ordering::Relaxed);
    DRAM_BOUNDS[1].store(dram_top, core::sync::atomic::Ordering::Relaxed);
    let mut mmio_bytes: u64 = 0;

    // Merge contiguous entries of the same type to reduce output volume.
    // Track current run; emit when type changes or a gap appears.
    let mut run_start: u64 = 0;
    let mut run_end: u64 = 0;
    let mut run_type: Option<MemoryType> = None;
    let mut line_idx: usize = 0;

    for entry in entries
    {
        if entry.size == 0
        {
            continue;
        }

        let start = entry.physical_base;
        let end = start + entry.size;

        match entry.memory_type
        {
            MemoryType::Usable => usable_bytes = usable_bytes.saturating_add(entry.size),
            MemoryType::Loaded => loaded_bytes = loaded_bytes.saturating_add(entry.size),
            MemoryType::Reserved =>
            {
                let entry_end = entry.physical_base + entry.size;
                let outside_dram = entry.physical_base >= dram_top || entry_end <= dram_bottom;
                if outside_dram
                {
                    mmio_bytes = mmio_bytes.saturating_add(entry.size);
                }
                else
                {
                    reserved_bytes = reserved_bytes.saturating_add(entry.size);
                }
            }
            MemoryType::AcpiReclaimable => acpi_bytes = acpi_bytes.saturating_add(entry.size),
            MemoryType::Persistent =>
            {
                persistent_bytes = persistent_bytes.saturating_add(entry.size);
            }
        }

        if let Some(rt) = run_type
        {
            if rt == entry.memory_type && start == run_end
            {
                // Extend current run.
                run_end = end;
                continue;
            }
            // Emit previous run.
            print_memory_line(line_idx, run_start, run_end, rt);
            line_idx += 1;
        }

        // Start new run.
        run_start = start;
        run_end = end;
        run_type = Some(entry.memory_type);
    }

    // Emit final run.
    if let Some(rt) = run_type
    {
        print_memory_line(line_idx, run_start, run_end, rt);
    }

    // The bootloader-supplied map contains both DRAM regions and address-
    // space windows that the firmware reports as `Reserved` (PCIe MMCFG,
    // LAPIC, etc.). The latter are not memory; they are split off as
    // `mmio` here so the DRAM sum is accurate.
    let dram_total_bytes =
        usable_bytes + loaded_bytes + reserved_bytes + acpi_bytes + persistent_bytes;
    SYSTEM_RAM_BYTES.store(dram_total_bytes, core::sync::atomic::Ordering::Relaxed);
    let (dram_v, dram_u) = scaled_unit(dram_total_bytes);
    let (use_v, use_u) = scaled_unit(usable_bytes);
    let (lod_v, lod_u) = scaled_unit(loaded_bytes);
    let (res_v, res_u) = scaled_unit(reserved_bytes);
    let (acp_v, acp_u) = scaled_unit(acpi_bytes);
    kprintln!(
        "RAM: {} {} DRAM = usable {} {} + loaded {} {} + firmware-reserved {} {} + \
         acpi-reclaimable {} {}",
        dram_v,
        dram_u,
        use_v,
        use_u,
        lod_v,
        lod_u,
        res_v,
        res_u,
        acp_v,
        acp_u,
    );
    if persistent_bytes > 0
    {
        let (per_v, per_u) = scaled_unit(persistent_bytes);
        kprintln!("RAM: persistent {} {}", per_v, per_u);
    }
    if mmio_bytes > 0
    {
        let (mm_v, mm_u) = scaled_unit(mmio_bytes);
        kprintln!(
            "MMIO: {} {} address-space windows outside DRAM (PCIe MMCFG / LAPIC / PLIC / CLINT \
             / etc. — not RAM)",
            mm_v,
            mm_u,
        );
    }
}

/// Pick the largest base-1024 unit (`KiB`, `MiB`, `GiB`) such that the
/// scaled value is at least 1, returning `(value, "unit")`. Sub-KiB
/// inputs round to zero KiB rather than displaying bytes — boot-time
/// memory totals are never that small in practice.
fn scaled_unit(bytes: u64) -> (u64, &'static str)
{
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB
    {
        (bytes / GIB, "GiB")
    }
    else if bytes >= MIB
    {
        (bytes / MIB, "MiB")
    }
    else
    {
        (bytes / KIB, "KiB")
    }
}

/// Return a human-readable name for a [`MemoryType`] variant.
fn memory_type_name(ty: MemoryType) -> &'static str
{
    match ty
    {
        MemoryType::Usable => "usable",
        MemoryType::Loaded => "loaded",
        MemoryType::Reserved => "reserved",
        MemoryType::AcpiReclaimable => "acpi-reclaimable",
        MemoryType::Persistent => "persistent",
    }
}

/// Maximum usable physical ranges tracked during init. Memory maps are
/// typically small; 64 entries is generous for real hardware.
const MAX_RANGES: usize = 64;

/// Maximum exclusion regions: kernel, `BootInfo`, each init segment (up to
/// `INIT_MAX_SEGMENTS`, 8), up to 16 boot modules, and the AP trampoline
/// page — 27 at most, so 32 is sufficient. The DTB blob is subtracted
/// separately, at population.
const MAX_EXCL: usize = 32;

/// Capacity of the surviving-range list. The usable ranges are disjoint, so
/// each subtracted extent lies strictly inside at most one of them and adds
/// at most one piece: the `MAX_RANGES` usable ranges, one piece per
/// `MAX_EXCL` exclusion, and one for the DTB blob bound the count.
const FREE_RANGE_CAP: usize = MAX_RANGES + MAX_EXCL + 1;

/// Surviving free ranges, written once in Phase 2 by
/// [`init_physical_memory`] and consumed once by [`populate_buddy`], both on
/// the single boot thread.
static mut FREE_RANGES: RangeList<FREE_RANGE_CAP> = RangeList::new();

/// Physical address of the device tree blob from `BootInfo.device_tree`
/// (0 when none), recorded in Phase 2 for [`populate_buddy`].
static DTB_PHYS: AtomicU64 = AtomicU64::new(0);

/// Top of the physical span the direct map covers
/// (`compute_max_physical_address`), recorded in Phase 2.
static DIRECT_MAP_TOP: AtomicU64 = AtomicU64::new(0);

/// The DTB blob's page-aligned `(base, size)`, `(0, 0)` when there is none;
/// written by [`populate_buddy`].
static DTB_EXTENT: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Phase 2: collect the free physical ranges derived from `info`.
///
/// Filters for [`MemoryType::Usable`] entries and subtracts the kernel image,
/// init segments, boot modules, the `BootInfo` struct, and the AP trampoline
/// page. The surviving page-aligned ranges are kept for [`populate_buddy`];
/// nothing is written to free RAM, which the bootloader's tables do not map
/// (core/boot/docs/page-tables.md § What Gets Mapped).
///
/// Calls [`crate::fatal`] and halts if no usable memory survives.
///
/// Called once, on the single boot thread, while the bootloader's identity
/// map still covers `info` and its memory map.
pub fn init_physical_memory(info: &BootInfo)
{
    let usable = collect_usable_ranges(info);
    let excl = collect_exclusions(info);

    let mut free = RangeList::<FREE_RANGE_CAP>::new();
    for &(r_start, r_end) in usable.iter().filter(|&&(s, e)| s < e)
    {
        add_surviving_subranges(&mut free, r_start, r_end, excl.as_slice());
    }

    // Frame 0 never reaches the buddy (`BuddyAllocator::add_region`).
    if free.iter().all(|&(s, e)| e <= s.max(PAGE_SIZE as u64))
    {
        crate::fatal("no usable physical memory after exclusions");
    }

    DTB_PHYS.store(info.device_tree, Ordering::Relaxed);
    DIRECT_MAP_TOP.store(
        super::paging::compute_max_physical_address(info),
        Ordering::Relaxed,
    );
    // SAFETY: single boot thread; FREE_RANGES is written only here, before
    // `populate_buddy` reads it.
    unsafe { *core::ptr::addr_of_mut!(FREE_RANGES) = free };
}

/// First act of Phase 3 after the page-table switch: subtract the device tree
/// blob from the Phase-2 free ranges and populate `alloc` with the rest.
///
/// The blob is sized from its FDT header, read through the direct map
/// ([`fdt_extent`]); a `BootInfo.device_tree` that does not name a valid blob
/// inside the direct-mapped span halts the boot, since its pages could not be
/// kept out of the allocator. The extent is published for [`dtb_extent`].
///
/// # Safety
///
/// Called once, on the single boot thread, after [`init_physical_memory`] and
/// after the kernel page tables (with the direct map over all RAM) are
/// active; `alloc` is empty and nothing has allocated from it.
pub unsafe fn populate_buddy(alloc: &mut BuddyAllocator)
{
    // SAFETY: single boot thread; `init_physical_memory` finished writing.
    let mut free = unsafe { core::ptr::read(core::ptr::addr_of!(FREE_RANGES)) };

    let dtb_phys = DTB_PHYS.load(Ordering::Relaxed);
    if dtb_phys != 0
    {
        let span_top = DIRECT_MAP_TOP.load(Ordering::Relaxed);
        let extent = fdt_extent(dtb_phys, span_top, || {
            let ptr = super::paging::phys_to_virt(dtb_phys) as *const [u8; FDT_SIZE_PREFIX];
            // SAFETY: `fdt_extent` calls this only when the header lies below
            // `span_top`, which the active direct map covers.
            unsafe { core::ptr::read_volatile(ptr) }
        })
        .unwrap_or_else(|e| dtb_fatal(dtb_phys, &e));
        DTB_EXTENT[0].store(extent.0, Ordering::Relaxed);
        DTB_EXTENT[1].store(extent.1, Ordering::Relaxed);
        free = subtract(&free, extent.0, extent.0 + extent.1);
    }

    for &(start, end) in free.iter()
    {
        // SAFETY: these ranges are usable RAM holding no live data (the
        // exclusion subtraction above and in Phase 2), reachable through the
        // direct map the caller guarantees is live.
        unsafe { alloc.add_region(start, end) };
    }

    if alloc.free_page_count() == 0
    {
        crate::fatal("no usable physical memory after exclusions");
    }
}

/// The device tree blob's page-aligned `(base, size)`, or `None` when the
/// bootloader passed none. Valid after [`populate_buddy`].
#[must_use]
pub fn dtb_extent() -> Option<(u64, u64)>
{
    let size = DTB_EXTENT[1].load(Ordering::Relaxed);
    (size != 0).then(|| (DTB_EXTENT[0].load(Ordering::Relaxed), size))
}

// ── Helper types ─────────────────────────────────────────────────────────────

/// A fixed-size list of physical address ranges.
struct RangeList<const N: usize>
{
    data: [(u64, u64); N],
    len: usize,
}

impl<const N: usize> RangeList<N>
{
    const fn new() -> Self
    {
        Self {
            data: [(0, 0); N],
            len: 0,
        }
    }

    fn push(&mut self, start: u64, end: u64)
    {
        if start < end && self.len < N
        {
            self.data[self.len] = (start, end);
            self.len += 1;
        }
    }

    /// Push a range whose slot [`FREE_RANGE_CAP`]'s count guarantees.
    fn push_counted(&mut self, start: u64, end: u64)
    {
        debug_assert!(
            start >= end || self.len < N,
            "free-range count exceeds its proven bound"
        );
        self.push(start, end);
    }

    fn as_slice(&self) -> &[(u64, u64)]
    {
        &self.data[..self.len]
    }

    fn iter(&self) -> core::slice::Iter<'_, (u64, u64)>
    {
        self.as_slice().iter()
    }
}

// ── Collection helpers ────────────────────────────────────────────────────────

/// Collect page-aligned usable ranges from the memory map.
fn collect_usable_ranges(info: &BootInfo) -> RangeList<MAX_RANGES>
{
    let mut ranges = RangeList::new();

    // SAFETY: Phase 0 validated entries is non-null and count > 0. The memory
    // map region is identity-mapped by the bootloader at handoff.
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };

    for entry in entries
    {
        if entry.memory_type != MemoryType::Usable
        {
            continue;
        }
        let start = align_up(entry.physical_base, PAGE_SIZE as u64);
        let end = align_down(entry.physical_base + entry.size, PAGE_SIZE as u64);
        ranges.push(start, end);
    }

    ranges
}

/// Build the exclusion list: all physical ranges that must not be allocated.
///
/// Exclusion boundaries are rounded outward (start down, end up) to page
/// granularity so no live data sits on a partially-excluded page.
///
/// The `BootInfo` and AP-trampoline exclusions are redundant guards: the
/// bootloader allocates both as `EfiLoaderData`, which the memory map reports
/// as `Loaded`, so neither lies in a `Usable` range. The authoritative
/// reclamation mechanism for bootloader scratch pages is
/// `BootInfo.reclaim_ranges` (`core/kernel/docs/initialization.md` § Phase 7:
/// Capability System).
fn collect_exclusions(info: &BootInfo) -> RangeList<MAX_EXCL>
{
    let mut excl = RangeList::new();

    let mut add = |start: u64, end: u64| {
        excl.push(
            align_down(start, PAGE_SIZE as u64),
            align_up(end, PAGE_SIZE as u64),
        );
    };

    // Kernel image.
    add(
        info.kernel_physical_base,
        info.kernel_physical_base + info.kernel_size,
    );

    // Init ELF segments (pre-parsed by the bootloader).
    let seg_count = info.init_image.segment_count as usize;
    for seg in &info.init_image.segments[..seg_count]
    {
        add(seg.phys_addr, seg.phys_addr + seg.size);
    }

    // Boot modules.
    if !info.modules.entries.is_null() && info.modules.count > 0
    {
        // SAFETY: entries is non-null and the region is identity-mapped.
        let modules = unsafe {
            core::slice::from_raw_parts(info.modules.entries, info.modules.count as usize)
        };
        for m in modules
        {
            add(m.physical_base, m.physical_base + m.size);
        }
    }

    // The BootInfo struct itself (pointed to by the kernel entry parameter).
    let boot_info_addr = core::ptr::addr_of!(*info) as u64;
    add(
        boot_info_addr,
        boot_info_addr + size_of::<BootInfo>() as u64,
    );

    // AP trampoline page (SIPI on x86-64, SBI HSM hart_start on riscv64). The
    // bootloader allocates it as EfiLoaderData, so the memory map reports it as
    // `Loaded` and it never lies in a `Usable` range; this exclusion is a guard.
    // The page is reclaimed in Phase 8 (core/kernel/docs/initialization.md
    // § Phase 8: Scheduler and SMP Bringup).
    if info.ap_trampoline_page != 0
    {
        add(
            info.ap_trampoline_page,
            info.ap_trampoline_page + PAGE_SIZE as u64,
        );
    }

    excl
}

/// FDT magic in big-endian: bytes `d0 0d fe ed`.
const FDT_MAGIC: u32 = 0xd00d_feed;

/// Bytes of the FDT header [`fdt_extent`] reads: `magic` and `totalsize`.
const FDT_SIZE_PREFIX: usize = 8;

/// Size of the version-17 FDT header; no valid blob is smaller.
const FDT_HEADER_BYTES: u64 = 40;

/// Why `BootInfo.device_tree` does not name a usable blob.
#[derive(Debug, PartialEq, Eq)]
enum DtbError
{
    /// The header itself lies past the direct-mapped span.
    HeaderPastSpan,
    /// The first word is not the FDT magic.
    BadMagic(u32),
    /// `totalsize` is smaller than the FDT header.
    TooSmall(u64),
    /// `totalsize` runs the blob past the direct-mapped span.
    PastSpan(u64),
}

/// Size the device tree blob at `base` from its header.
///
/// The DTB pages are commonly reported as `EfiBootServicesData`, so `Usable`;
/// userspace parses the blob through the read-only Memory cap Phase 7 mints
/// from this extent, and keeping the extent out of the buddy keeps that cap's
/// memory live. `read_prefix` returns the blob's first [`FDT_SIZE_PREFIX`]
/// bytes and is called only when the header lies below `span_top`. The
/// blob's only bounds are the FDT format's (a `u32` `totalsize` no smaller
/// than the header) and the direct-mapped span `[0, span_top)` the kernel
/// reads it through. Returns the page-aligned extent covering
/// `[base, base + totalsize)`.
fn fdt_extent(
    base: u64,
    span_top: u64,
    read_prefix: impl FnOnce() -> [u8; FDT_SIZE_PREFIX],
) -> Result<(u64, u64), DtbError>
{
    if base
        .checked_add(FDT_HEADER_BYTES)
        .is_none_or(|end| end > span_top)
    {
        return Err(DtbError::HeaderPastSpan);
    }
    let prefix = read_prefix();
    let magic = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    if magic != FDT_MAGIC
    {
        return Err(DtbError::BadMagic(magic));
    }
    let size = u64::from(u32::from_be_bytes([
        prefix[4], prefix[5], prefix[6], prefix[7],
    ]));
    if size < FDT_HEADER_BYTES
    {
        return Err(DtbError::TooSmall(size));
    }
    let end = base.saturating_add(size);
    if end > span_top
    {
        return Err(DtbError::PastSpan(size));
    }
    let page = PAGE_SIZE as u64;
    let first = align_down(base, page);
    Ok((first, align_up(end, page) - first))
}

/// Halt the boot on a `BootInfo.device_tree` that names no usable blob.
fn dtb_fatal(phys: u64, err: &DtbError) -> !
{
    let top = DIRECT_MAP_TOP.load(Ordering::Relaxed);
    match *err
    {
        DtbError::HeaderPastSpan =>
        {
            kprintln!("Phase 3: device tree at {phys:#x}: header past the direct map end {top:#x}");
        }
        DtbError::BadMagic(magic) =>
        {
            kprintln!("Phase 3: device tree at {phys:#x}: bad FDT magic {magic:#010x}");
        }
        DtbError::TooSmall(size) =>
        {
            kprintln!("Phase 3: device tree at {phys:#x}: totalsize {size} below the FDT header");
        }
        DtbError::PastSpan(size) =>
        {
            kprintln!(
                "Phase 3: device tree at {phys:#x}: totalsize {size:#x} runs past the direct \
                 map end {top:#x}"
            );
        }
    }
    crate::fatal("Phase 3: BootInfo.device_tree names no valid FDT blob")
}

// ── Range subtraction ─────────────────────────────────────────────────────────

/// Append to `free` the sub-ranges of `[r_start, r_end)` that don't overlap
/// any exclusion in `excls`.
fn add_surviving_subranges(
    free: &mut RangeList<FREE_RANGE_CAP>,
    r_start: u64,
    r_end: u64,
    excls: &[(u64, u64)],
)
{
    // `work` holds the set of ranges still available after applying each
    // exclusion in turn. A fixed-size array needs no allocation.
    let mut work = RangeList::<MAX_RANGES>::new();
    work.push(r_start, r_end);

    for &(e_start, e_end) in excls
    {
        let mut next = RangeList::<MAX_RANGES>::new();

        for &(w_start, w_end) in work.iter()
        {
            // Left sub-range: portion of [w_start, w_end) before the exclusion.
            let left_end = w_end.min(e_start);
            next.push(w_start, left_end);

            // Right sub-range: portion after the exclusion.
            let right_start = w_start.max(e_end);
            next.push(right_start, w_end);
        }

        work = next;
    }

    for &(start, end) in work.iter()
    {
        free.push_counted(start, end);
    }
}

/// `list` with `[e_start, e_end)` removed.
fn subtract(list: &RangeList<FREE_RANGE_CAP>, e_start: u64, e_end: u64)
-> RangeList<FREE_RANGE_CAP>
{
    let mut out = RangeList::new();
    for &(start, end) in list.iter()
    {
        out.push_counted(start, end.min(e_start));
        out.push_counted(start.max(e_end), end);
    }
    out
}

// ── Alignment utilities ───────────────────────────────────────────────────────

/// Round `val` up to the next multiple of `align`. `align` must be a power of two.
fn align_up(val: u64, align: u64) -> u64
{
    (val + align - 1) & !(align - 1)
}

/// Round `val` down to the nearest multiple of `align`. `align` must be a power of two.
fn align_down(val: u64, align: u64) -> u64
{
    val & !(align - 1)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// The first header bytes of a blob of `totalsize` bytes.
    fn header(magic: u32, totalsize: u32) -> [u8; FDT_SIZE_PREFIX]
    {
        let mut prefix = [0u8; FDT_SIZE_PREFIX];
        prefix[..4].copy_from_slice(&magic.to_be_bytes());
        prefix[4..].copy_from_slice(&totalsize.to_be_bytes());
        prefix
    }

    const BLOB: u64 = 0x8000_1100;

    #[test]
    fn fdt_extent_covers_a_blob_ending_exactly_at_the_span_top()
    {
        // A 3 MiB blob, past any fixed ceiling, at an unaligned base: the
        // extent must start on the blob's page and cover its last byte.
        let size: u32 = 3 << 20;
        let top = BLOB + u64::from(size);
        let extent = fdt_extent(BLOB, top, || header(FDT_MAGIC, size));
        assert_eq!(extent, Ok((0x8000_1000, align_up(top, 4096) - 0x8000_1000)));
    }

    #[test]
    fn fdt_extent_rejects_a_blob_one_byte_past_the_span()
    {
        let size: u32 = 0x1_0000;
        let top = BLOB + u64::from(size) - 1;
        assert_eq!(
            fdt_extent(BLOB, top, || header(FDT_MAGIC, size)),
            Err(DtbError::PastSpan(u64::from(size)))
        );
    }

    #[test]
    fn fdt_extent_rejects_a_size_below_the_header()
    {
        assert_eq!(
            fdt_extent(BLOB, u64::MAX, || header(FDT_MAGIC, 39)),
            Err(DtbError::TooSmall(39))
        );
    }

    #[test]
    fn fdt_extent_rejects_a_bad_magic()
    {
        assert_eq!(
            fdt_extent(BLOB, u64::MAX, || header(0xfeed_d00d, 0x1000)),
            Err(DtbError::BadMagic(0xfeed_d00d))
        );
    }

    #[test]
    fn fdt_extent_never_reads_a_header_past_the_span()
    {
        let read = || -> [u8; FDT_SIZE_PREFIX] { panic!("header read past the span") };
        assert_eq!(
            fdt_extent(BLOB, BLOB + FDT_HEADER_BYTES - 1, read),
            Err(DtbError::HeaderPastSpan)
        );
    }

    #[test]
    fn subtract_splits_only_the_range_holding_the_extent()
    {
        let mut list = RangeList::<FREE_RANGE_CAP>::new();
        list.push(0x1000, 0x9000);
        list.push(0x10000, 0x20000);
        let out = subtract(&list, 0x3000, 0x5000);
        assert_eq!(
            out.as_slice(),
            &[(0x1000, 0x3000), (0x5000, 0x9000), (0x10000, 0x20000)]
        );
    }
}
