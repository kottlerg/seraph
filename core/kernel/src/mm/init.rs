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

use boot_protocol::{BootInfo, BootModule, MemoryMapEntry, MemoryType};

use super::buddy::{BuddyAllocator, PAGE_SIZE};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::kprintln;

/// Whether a memory-map entry of type `ty` is DRAM (`Usable`, `Loaded`,
/// `AcpiReclaimable`, `Persistent`), as opposed to a `Reserved` window.
#[must_use]
pub fn is_dram(ty: MemoryType) -> bool
{
    matches!(
        ty,
        MemoryType::Usable
            | MemoryType::Loaded
            | MemoryType::AcpiReclaimable
            | MemoryType::Persistent
    )
}

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
        if is_dram(entry.memory_type)
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
/// Read at Phase 4 to size the `CSpace` registry arena
/// (`cap::init_cspace_registry`) and at Phase 9 to populate
/// `InitInfo::system_ram_bytes`.
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

/// Physical address of the `BootInfo` struct (the kernel entry argument),
/// recorded in Phase 2 so [`populate_buddy`] can re-read it, and the memory
/// map and module list it points to, through the direct map.
static BOOT_INFO_PHYS: AtomicU64 = AtomicU64::new(0);

/// Physical address of the device tree blob from `BootInfo.device_tree`
/// (0 when none), recorded in Phase 2 for [`populate_buddy`].
static DTB_PHYS: AtomicU64 = AtomicU64::new(0);

/// Top of the physical span the direct map covers
/// (`compute_max_physical_address`), recorded in Phase 2.
static DIRECT_MAP_TOP: AtomicU64 = AtomicU64::new(0);

/// The DTB blob's page-aligned `(base, size)`, `(0, 0)` when there is none;
/// written by [`populate_buddy`].
static DTB_EXTENT: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// The `(base, size)` of the RAM Phase 3 carved for its page tables
/// ([`record_boot_table_carve`]), `(0, 0)` when it carved none; kept out of the
/// buddy by [`populate_buddy`].
static BOOT_TABLE_CARVE: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// The boot memory map, read through the direct map.
///
/// # Safety
/// `boot_info_phys` is the Phase-0-validated `BootInfo` address, and the
/// direct map (Phase 3) covers it and the map it points to.
#[must_use]
pub unsafe fn memory_map(boot_info_phys: u64) -> &'static [MemoryMapEntry]
{
    // SAFETY: caller's contract.
    let info = unsafe { &*(super::paging::phys_to_virt(boot_info_phys) as *const BootInfo) };
    // SAFETY: Phase 0 validated entries and count; the direct map covers them.
    unsafe {
        core::slice::from_raw_parts(
            super::paging::phys_to_virt(info.memory_map.entries as u64) as *const MemoryMapEntry,
            info.memory_map.count as usize,
        )
    }
}

/// Phase 2: check that free physical memory survives the boot payload, and
/// record what [`populate_buddy`] needs to find it again.
///
/// The free memory is every [`MemoryType::Usable`] entry less the kernel
/// image, init segments, boot modules, the `BootInfo` struct, and the AP
/// trampoline page (the boot payload); Phase 3 subtracts the device tree blob
/// and its own page-table carve as well. Nothing is stored per range: the
/// subtraction streams over the memory map ([`for_each_free_piece`]), so no
/// count of memory-map entries, usable ranges, or boot modules is bounded.
/// Nothing is written to free RAM, which the bootloader's tables do not map
/// (core/boot/docs/page-tables.md § What Gets Mapped).
///
/// Calls [`crate::fatal`] and halts if no usable memory survives.
///
/// Called once, on the single boot thread, while the bootloader's identity
/// map still covers `info` and its memory map.
pub fn init_physical_memory(info: &BootInfo)
{
    let mut survives = false;
    // Identity-mapped at this point: a physical address is its own pointer.
    for_each_payload_free_piece(
        info,
        core::ptr::from_ref(info) as u64,
        |p| p,
        &[],
        |s, e| {
            // Frame 0 never reaches the buddy (`BuddyAllocator::add_region`).
            survives |= e > s.max(PAGE_SIZE as u64);
        },
    );
    if !survives
    {
        crate::fatal("no usable physical memory after exclusions");
    }

    BOOT_INFO_PHYS.store(core::ptr::from_ref(info) as u64, Ordering::Relaxed);
    DTB_PHYS.store(info.device_tree, Ordering::Relaxed);
    DIRECT_MAP_TOP.store(
        super::paging::compute_max_physical_address(info),
        Ordering::Relaxed,
    );
}

/// The first page-aligned free piece of at least `frames` frames, for the
/// Phase 3 page-table carve, or `None`.
///
/// A free piece here also avoids everything from the device tree blob's start
/// to the end of its range: the blob's size is in its header, which Phase 3
/// cannot read before its own tables are active.
///
/// Called on the single boot thread while the bootloader's identity map still
/// covers `info`, its memory map, and its module list.
#[must_use]
pub fn find_boot_table_carve(info: &BootInfo, frames: u64) -> Option<u64>
{
    let want = frames * PAGE_SIZE as u64;
    let dtb_tail = if info.device_tree == 0
    {
        (0, 0)
    }
    else
    {
        (align_down(info.device_tree, PAGE_SIZE as u64), u64::MAX)
    };
    let mut found = None;
    for_each_payload_free_piece(
        info,
        core::ptr::from_ref(info) as u64,
        |p| p,
        &[dtb_tail],
        |s, e| {
            // Frame 0 is never handed out (it is the buddy's list end marker).
            let s = s.max(PAGE_SIZE as u64);
            if found.is_none() && e > s && e - s >= want
            {
                found = Some(s);
            }
        },
    );
    found
}

/// Record the `frames` frames at `base` Phase 3 used for its page tables, so
/// [`populate_buddy`] keeps them out of the buddy.
pub fn record_boot_table_carve(base: u64, frames: u64)
{
    BOOT_TABLE_CARVE[0].store(base, Ordering::Relaxed);
    BOOT_TABLE_CARVE[1].store(frames * PAGE_SIZE as u64, Ordering::Relaxed);
}

/// First act of Phase 3 after the page-table switch: populate `alloc` with the
/// free physical memory, less the device tree blob and the Phase 3 page-table
/// carve.
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
    let info_phys = BOOT_INFO_PHYS.load(Ordering::Relaxed);
    // SAFETY: recorded in Phase 2 from the validated entry argument; the
    // direct map covers it.
    let info = unsafe { &*(super::paging::phys_to_virt(info_phys) as *const BootInfo) };

    let mut dtb = (0, 0);
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
        dtb = (extent.0, extent.0 + extent.1);
    }
    let carve_base = BOOT_TABLE_CARVE[0].load(Ordering::Relaxed);
    let carve = (
        carve_base,
        carve_base + BOOT_TABLE_CARVE[1].load(Ordering::Relaxed),
    );

    let to_ptr = |phys: u64| super::paging::phys_to_virt(phys);
    for_each_payload_free_piece(info, info_phys, to_ptr, &[dtb, carve], |start, end| {
        // SAFETY: the piece is usable RAM holding no live data (every boot
        // payload extent, the blob and the page-table carve are subtracted),
        // reachable through the direct map the caller guarantees is live.
        unsafe { alloc.add_region(start, end) };
    });

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

// ── Free-memory streaming ─────────────────────────────────────────────────────

/// Call `emit(start, end)` for every page-aligned piece of a `Usable` entry of
/// `info`'s memory map that no boot payload extent and no `extra` extent
/// covers.
///
/// `info_phys` is the `BootInfo` struct's own physical address (an exclusion);
/// `to_ptr` turns a physical address from `info` into a readable pointer (the
/// identity before Phase 3, the direct map after). The exclusions are the
/// kernel image, the init segments, every boot module, the `BootInfo` struct,
/// and the AP trampoline page, rounded outward to whole pages so no live data
/// sits on a partly excluded page.
///
/// The `BootInfo` and AP-trampoline exclusions are redundant guards: the
/// bootloader allocates both as `EfiLoaderData`, which the memory map reports
/// as `Loaded`, so neither lies in a `Usable` range. The authoritative
/// reclamation mechanism for bootloader scratch pages is
/// `BootInfo.reclaim_ranges` (`core/kernel/docs/initialization.md` § Phase 7:
/// Capability System).
fn for_each_payload_free_piece(
    info: &BootInfo,
    info_phys: u64,
    to_ptr: impl Fn(u64) -> u64,
    extra: &[(u64, u64)],
    mut emit: impl FnMut(u64, u64),
)
{
    // SAFETY: Phase 0 validated the memory map; `to_ptr` reaches it.
    let entries = unsafe {
        core::slice::from_raw_parts(
            to_ptr(info.memory_map.entries as u64) as *const MemoryMapEntry,
            info.memory_map.count as usize,
        )
    };
    let modules: &[BootModule] = if info.modules.entries.is_null() || info.modules.count == 0
    {
        &[]
    }
    else
    {
        // SAFETY: a non-null module list from the validated BootInfo, which
        // `to_ptr` reaches.
        unsafe {
            core::slice::from_raw_parts(
                to_ptr(info.modules.entries as u64) as *const BootModule,
                info.modules.count as usize,
            )
        }
    };
    let seg_count = (info.init_image.segment_count as usize).min(info.init_image.segments.len());
    let segments = &info.init_image.segments[..seg_count];
    let trampoline = if info.ap_trampoline_page == 0
    {
        (0, 0)
    }
    else
    {
        (
            info.ap_trampoline_page,
            info.ap_trampoline_page + PAGE_SIZE as u64,
        )
    };
    let fixed = [
        (
            info.kernel_physical_base,
            info.kernel_physical_base + info.kernel_size,
        ),
        (info_phys, info_phys + size_of::<BootInfo>() as u64),
        trampoline,
    ];
    let page = PAGE_SIZE as u64;
    let exclusions = || {
        fixed
            .iter()
            .copied()
            .chain(segments.iter().map(|s| (s.phys_addr, s.phys_addr + s.size)))
            .chain(
                modules
                    .iter()
                    .map(|m| (m.physical_base, m.physical_base + m.size)),
            )
            .chain(extra.iter().copied())
            .map(move |(s, e)| (align_down(s, page), align_up_saturating(e, page)))
    };

    for entry in entries
        .iter()
        .filter(|e| e.memory_type == MemoryType::Usable)
    {
        let start = align_up_saturating(entry.physical_base, page);
        let end = align_down(entry.physical_base.saturating_add(entry.size), page);
        for_each_free_piece(start, end, &exclusions, &mut emit);
    }
}

/// Call `emit` for every maximal sub-range of `[start, end)` that no range
/// `exclusions()` yields covers, in ascending order.
///
/// The exclusions may be unsorted, overlapping, or empty, and are re-iterated
/// once per piece, so nothing is stored and no count of either bounds the
/// subtraction: the cost is the number of pieces times the number of
/// exclusions.
fn for_each_free_piece<I>(
    start: u64,
    end: u64,
    exclusions: &impl Fn() -> I,
    emit: &mut impl FnMut(u64, u64),
) where
    I: Iterator<Item = (u64, u64)>,
{
    let mut cursor = start;
    while cursor < end
    {
        // The lowest-starting exclusion that still overlaps [cursor, end).
        let next = exclusions()
            .filter(|&(s, e)| s < e && s < end && e > cursor)
            .min_by_key(|&(s, _)| s);
        match next
        {
            None =>
            {
                emit(cursor, end);
                return;
            }
            Some((s, e)) =>
            {
                if s > cursor
                {
                    emit(cursor, s);
                }
                cursor = e;
            }
        }
    }
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

// ── Alignment utilities ───────────────────────────────────────────────────────

/// Round `val` up to the next multiple of `align`. `align` must be a power of two.
fn align_up(val: u64, align: u64) -> u64
{
    (val + align - 1) & !(align - 1)
}

/// Round `val` up to the next multiple of `align`, saturating at the highest
/// multiple below `u64::MAX`. `align` must be a power of two.
fn align_up_saturating(val: u64, align: u64) -> u64
{
    val.checked_add(align - 1)
        .map_or(!(align - 1), |v| v & !(align - 1))
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

    /// The pieces `for_each_free_piece` emits for `[start, end)` less `excl`.
    fn pieces(start: u64, end: u64, excl: &[(u64, u64)]) -> Vec<(u64, u64)>
    {
        let mut out = Vec::new();
        for_each_free_piece(start, end, &|| excl.iter().copied(), &mut |s, e| {
            out.push((s, e));
        });
        out
    }

    #[test]
    fn free_pieces_skip_unsorted_and_overlapping_exclusions()
    {
        let excl = [
            (0x6000, 0x8000),
            (0x2000, 0x3000),
            (0x2800, 0x4000),
            (0x7000, 0x7800),
        ];
        assert_eq!(
            pieces(0x1000, 0x9000, &excl),
            [(0x1000, 0x2000), (0x4000, 0x6000), (0x8000, 0x9000)]
        );
    }

    #[test]
    fn free_pieces_of_a_fully_excluded_range_are_none()
    {
        assert!(pieces(0x1000, 0x3000, &[(0, 0x2000), (0x2000, 0x4000)]).is_empty());
    }

    #[test]
    fn free_pieces_ignore_empty_and_outside_exclusions()
    {
        let excl = [(0x5000, 0x5000), (0, 0x1000), (0x9000, 0xa000)];
        assert_eq!(pieces(0x1000, 0x9000, &excl), [(0x1000, 0x9000)]);
    }

    // Defect caught: the former 64-entry range and 32-entry exclusion lists
    // dropping RAM, or exclusions, past their bound.
    #[test]
    fn free_pieces_need_no_bound_on_the_exclusion_count()
    {
        // 200 one-page holes, one every other page.
        let excl: Vec<(u64, u64)> = (0..200u64)
            .map(|i| (0x1000 + 0x2000 * i, 0x2000 + 0x2000 * i))
            .collect();
        let out = pieces(0x1000, 0x1000 + 0x2000 * 200, &excl);
        assert_eq!(out.len(), 200);
        assert!(out.iter().all(|&(s, e)| e - s == 0x1000));
    }

    #[test]
    fn saturating_alignment_never_wraps_to_zero()
    {
        assert_eq!(align_up_saturating(u64::MAX - 5, 0x1000), !0xFFF);
        assert_eq!(align_up_saturating(0x1001, 0x1000), 0x2000);
    }
}
