// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/init.rs

//! Physical memory initialization.
//!
//! Parses the boot-time memory map from [`BootInfo`], subtracts all reserved
//! regions (kernel image, init segments, boot modules, `BootInfo` struct), and
//! populates a caller-supplied [`BuddyAllocator`] with the surviving ranges.
//!
//! The allocator is passed by mutable reference rather than returned by value
//! because it is ~41 KiB — too large for the kernel's boot stack. The caller
//! should hold the allocator in static storage (BSS).

// cast_possible_truncation: u64→usize physical address arithmetic; bounded by memory map sizes.
#![allow(clippy::cast_possible_truncation)]

use core::mem::size_of;

use boot_protocol::{BootInfo, MemoryType};

use super::buddy::{BuddyAllocator, PAGE_SIZE};

use crate::kprintln;

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

/// Print the physical memory map from the bootloader to the serial console.
///
/// Iterates all entries in `info.memory_map`, printing address range, size in
/// KiB, and memory type for each entry. Prints a summary line with usable and
/// total RAM in MiB at the end.
///
/// Must be called before Phase 3 activates the kernel page tables; the
/// `memory_map.entries` pointer is a physical address covered by the
/// bootloader's identity map, which is replaced in Phase 3.
pub fn print_memory_map(info: &BootInfo)
{
    kprintln!("Memory map:");

    // SAFETY: Phase 0 validated entries is non-null and count > 0. The memory
    // map region is identity-mapped by the bootloader at handoff.
    let entries = unsafe {
        core::slice::from_raw_parts(info.memory_map.entries, info.memory_map.count as usize)
    };

    let mut usable_bytes: u64 = 0;
    let mut total_bytes: u64 = 0;

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

        total_bytes = total_bytes.saturating_add(entry.size);
        if entry.memory_type == MemoryType::Usable
        {
            usable_bytes = usable_bytes.saturating_add(entry.size);
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

    let usable_mib = usable_bytes / (1024 * 1024);
    let total_mib = total_bytes / (1024 * 1024);
    kprintln!("RAM: {} MiB usable ({} MiB total)", usable_mib, total_mib);
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

/// Maximum exclusion regions. One per: kernel, `BootInfo`, each init segment
/// (up to 8), plus up to 16 boot modules — 32 is comfortably sufficient.
const MAX_EXCL: usize = 32;

/// Populate `alloc` with usable physical frames derived from `info`.
///
/// Filters for [`MemoryType::Usable`] entries, subtracts the kernel image,
/// init segments, boot modules, and the `BootInfo` struct itself, then feeds
/// the surviving page-aligned sub-ranges to `alloc`.
///
/// Calls [`crate::fatal`] and halts if no usable memory survives.
///
/// `alloc` must be a freshly-created (empty) allocator — this function does
/// not reset it first.
pub fn init_physical_memory(info: &BootInfo, alloc: &mut BuddyAllocator)
{
    let usable = collect_usable_ranges(info);
    let excl = collect_exclusions(info);

    for &(r_start, r_end) in usable.iter().filter(|&&(s, e)| s < e)
    {
        add_surviving_subranges(alloc, r_start, r_end, excl.as_slice());
    }

    if alloc.free_page_count() == 0
    {
        crate::fatal("no usable physical memory after exclusions");
    }
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

    // AP SIPI trampoline page (x86-64 SMP). Reported as Usable by the bootloader
    // (EfiBootServicesData → Usable), so without this exclusion the buddy
    // allocator would hand it out for IST stacks or heap, zeroing the trampoline
    // code that the BSP writes there during AP startup.
    if info.ap_trampoline_page != 0
    {
        add(
            info.ap_trampoline_page,
            info.ap_trampoline_page + PAGE_SIZE as u64,
        );
    }

    // DTB blob pages. Commonly reported as EfiBootServicesData → Usable by
    // UEFI; userspace parses the DTB through a read-only Frame cap minted
    // in Phase 7. Excluding the pages from the buddy keeps that cap's
    // backing memory live.
    if info.device_tree != 0
        && let Some(size) = read_dtb_totalsize(info.device_tree)
    {
        add(info.device_tree, info.device_tree + size);
    }

    excl
}

/// Read the `totalsize` field of a flattened device tree blob.
///
/// Returns `None` if the magic does not match or the reported size is
/// implausible. Size is clamped to `DTB_MAX_SIZE` to bound the Frame cap.
fn read_dtb_totalsize(phys: u64) -> Option<u64>
{
    /// FDT magic in big-endian: bytes `d0 0d fe ed`.
    const FDT_MAGIC: u32 = 0xd00d_feed;
    /// Safety clamp on the DTB blob size — 64 KiB is far above any realistic
    /// DTB; bounds the exclusion on malformed firmware.
    const DTB_MAX_SIZE: u64 = 64 * 1024;

    // `phys` is a bootloader-provided identity-mapped physical address
    // during Phase 2 (before page tables are rewritten in Phase 3). The
    // first 8 bytes of an FDT blob are magic + totalsize by spec.
    let ptr = phys as *const u8;
    // SAFETY: identity-mapped physical address; FDT header is defined by
    // the FDT spec to occupy the first bytes of the blob.
    let magic_bytes = unsafe { core::ptr::read_volatile(ptr.cast::<[u8; 4]>()) };
    let magic = u32::from_be_bytes(magic_bytes);
    if magic != FDT_MAGIC
    {
        return None;
    }
    // SAFETY: identity-mapped; totalsize is the 4 bytes following the magic.
    let size_bytes = unsafe { core::ptr::read_volatile(ptr.add(4).cast::<[u8; 4]>()) };
    let size = u64::from(u32::from_be_bytes(size_bytes));
    if size == 0 || size > DTB_MAX_SIZE
    {
        return None;
    }
    Some(size)
}

// ── Range subtraction ─────────────────────────────────────────────────────────

/// Feed the sub-ranges of `[r_start, r_end)` that don't overlap any exclusion
/// in `excls` to the allocator.
fn add_surviving_subranges(
    alloc: &mut BuddyAllocator,
    r_start: u64,
    r_end: u64,
    excls: &[(u64, u64)],
)
{
    // `work` holds the set of ranges still available after applying each
    // exclusion in turn. Using a fixed-size array avoids heap allocation.
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

    // Add all surviving sub-ranges to the allocator.
    for &(start, end) in work.iter()
    {
        if start < end
        {
            // SAFETY: These ranges are usable RAM not occupied by any live data,
            // confirmed by the exclusion subtraction above. The bootloader's
            // identity map covers them at this point in boot.
            unsafe { alloc.add_region(start, end) };
        }
    }
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
