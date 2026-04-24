// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/elf.rs

//! UEFI-coupled ELF image loader.
//!
//! Wraps `shared/elf` (the workspace's authoritative ELF format decoder)
//! with the bootloader-specific responsibilities:
//!
//! - Allocate physical pages via UEFI for each `PT_LOAD` segment, copy
//!   file data in, and zero the BSS tail.
//! - For the kernel: place segments at their ELF-declared `p_paddr` via
//!   `AllocatePages(AllocateAddress, …)`.
//! - For init: place segments at any available physical address while
//!   preserving the in-page byte offset of `p_vaddr`, so the kernel can
//!   identity-map a page without a second copy.
//! - Pre-parse init's segments into the [`InitImage`] ABI surface so the
//!   kernel never needs an ELF parser.
//! - Load opaque boot modules as flat binaries (no ELF parsing).
//!
//! W^X policy is enforced by the bootloader's page-table builder
//! (`paging.rs` and `arch/*/paging.rs`). A `PT_LOAD` segment with both
//! `PF_W` and `PF_X` is rejected when its first page is mapped, surfaced
//! as [`BootError::WxViolation`].
//!
//! Header and segment validation come from `shared/elf`; format errors
//! arrive here as `elf::ElfError` and bridge to [`BootError::InvalidElf`]
//! via the `From` impl in `error.rs`.

use crate::error::BootError;
use boot_protocol::BootModule;

// Both constants are re-exported here for arch-mod consumers; only one is
// referenced per target arch build.
#[allow(unused_imports)]
pub use elf::{EM_RISCV, EM_X86_64};

// ── Output types ──────────────────────────────────────────────────────────────

/// Maximum number of `PT_LOAD` segments supported in a kernel ELF.
const MAX_LOAD_SEGMENTS: usize = 8;

/// A single loaded ELF `PT_LOAD` segment with physical placement and permissions.
pub struct LoadedSegment
{
    /// Physical base address where this segment was placed.
    pub phys_base: u64,
    /// ELF virtual base address this segment is mapped at.
    pub virt_base: u64,
    /// Size of the segment in memory (`p_memsz`).
    pub size: u64,
    /// Segment is writable (`PF_W` set).
    pub writable: bool,
    /// Segment is executable (`PF_X` set).
    pub executable: bool,
}

/// Result of loading the kernel ELF into physical memory.
///
/// Produced by [`load_kernel`] and consumed by the page table builder and by
/// the `BootInfo` population step.
pub struct KernelInfo
{
    /// Lowest physical address across all `PT_LOAD` segments.
    pub physical_base: u64,
    /// Lowest virtual address across all `PT_LOAD` segments.
    pub virtual_base: u64,
    /// Physical span from `physical_base` to the end of the highest `PT_LOAD` segment.
    pub size: u64,
    /// Virtual address of the kernel entry point (`e_entry` from the ELF header).
    pub entry_virtual: u64,
    /// Loaded segments; valid entries occupy indices `0..segment_count`.
    pub segments: [LoadedSegment; MAX_LOAD_SEGMENTS],
    /// Number of valid entries in `segments`.
    pub segment_count: usize,
}

// ── Kernel loading ────────────────────────────────────────────────────────────

/// Load the kernel ELF from `data` into physical memory allocated via UEFI.
///
/// For each `PT_LOAD` segment: allocates physical pages at `p_paddr` via
/// `AllocateAddress`, copies `p_filesz` bytes of file data into the region,
/// and zeroes the BSS tail (`p_memsz - p_filesz` bytes).
///
/// Up to 8 `PT_LOAD` segments are supported; an ELF with more returns
/// `InvalidElf`.
///
/// # Errors
///
/// - `BootError::InvalidElf` — header or segment constraint check failed
///   (bridged from `elf::ElfError`).
/// - `BootError::OutOfMemory` — `AllocatePages(AllocateAddress)` returned
///   failure (typically because the requested physical range is occupied).
///
/// # Safety
///
/// `bs` must be a valid pointer to UEFI boot services and boot services must
/// not yet have been exited. `data` must remain valid for the duration of the
/// call (it is a temporary read buffer from file I/O).
pub unsafe fn load_kernel(
    bs: *mut crate::uefi::EfiBootServices,
    data: &[u8],
    expected_machine: u16,
) -> Result<KernelInfo, BootError>
{
    let ehdr = elf::validate(data, expected_machine)?;

    let mut segments: [LoadedSegment; MAX_LOAD_SEGMENTS] =
        core::array::from_fn(|_| LoadedSegment {
            phys_base: 0,
            virt_base: 0,
            size: 0,
            writable: false,
            executable: false,
        });
    let mut segment_count: usize = 0;

    for seg in elf::load_segments(ehdr, data)
    {
        let seg = seg?;
        if seg.memsz == 0
        {
            continue;
        }
        if seg.memsz < seg.filesz
        {
            return Err(BootError::InvalidElf("LOAD segment: p_memsz < p_filesz"));
        }
        if segment_count >= MAX_LOAD_SEGMENTS
        {
            return Err(BootError::InvalidElf("ELF has more than 8 LOAD segments"));
        }

        // p_memsz → usize: 64-bit on all supported UEFI targets; cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let page_count = (seg.memsz as usize).div_ceil(4096);
        // SAFETY: `bs` is valid boot services per the function's safety contract.
        // `seg.paddr` is the ELF-specified physical base; UEFI fails if the
        // range is already occupied, which we surface as `OutOfMemory`.
        unsafe { crate::uefi::allocate_address(bs, seg.paddr, page_count)? };

        // Copy file data (filesz bytes) into the allocated physical region.
        // p_offset / p_filesz → usize: 64-bit targets only; cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let file_off = seg.offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let file_sz = seg.filesz as usize;
        if file_sz > 0
        {
            let src = data[file_off..].as_ptr();
            let dst = seg.paddr as *mut u8;
            // SAFETY: `src` points into `data`; `elf::load_segments` already
            // validated that `[file_off, file_off + file_sz)` is in bounds
            // (yields SegmentOverflow otherwise). `dst` is a freshly UEFI-
            // allocated region of `page_count * 4096 ≥ memsz ≥ filesz` bytes,
            // identity-mapped in the bootloader address space and disjoint
            // from the temporary read buffer.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, file_sz) };
        }

        // Zero the BSS tail: bytes [filesz, memsz).
        // Difference fits in usize: memsz ≤ allocated region; 64-bit only.
        #[allow(clippy::cast_possible_truncation)]
        let bss_sz = (seg.memsz - seg.filesz) as usize;
        if bss_sz > 0
        {
            let bss_ptr = (seg.paddr + seg.filesz) as *mut u8;
            // SAFETY: `bss_ptr` is `filesz` bytes past the segment's physical
            // base, which is within the allocated region (`memsz` bytes total).
            // `bss_sz = memsz - filesz` bytes remain. UEFI does not guarantee
            // pages are zeroed; we must zero BSS here.
            unsafe { core::ptr::write_bytes(bss_ptr, 0, bss_sz) };
        }

        segments[segment_count] = LoadedSegment {
            phys_base: seg.paddr,
            virt_base: seg.vaddr,
            size: seg.memsz,
            writable: seg.writable,
            executable: seg.executable,
        };
        segment_count += 1;
    }

    if segment_count == 0
    {
        return Err(BootError::InvalidElf(
            "ELF has no PT_LOAD segments with non-zero p_memsz",
        ));
    }

    let init_segs = &segments[..segment_count];

    let physical_base = init_segs
        .iter()
        .map(|s| s.phys_base)
        .fold(u64::MAX, u64::min);

    let virtual_base = init_segs
        .iter()
        .map(|s| s.virt_base)
        .fold(u64::MAX, u64::min);

    let phys_end = init_segs
        .iter()
        .map(|s| s.phys_base.saturating_add(s.size))
        .fold(0u64, u64::max);

    let size = phys_end.saturating_sub(physical_base);

    Ok(KernelInfo {
        physical_base,
        virtual_base,
        size,
        entry_virtual: elf::entry_point(ehdr),
        segments,
        segment_count,
    })
}

// ── Init ELF loading ─────────────────────────────────────────────────────────

/// Parse and load a userspace init ELF into physical memory.
///
/// Unlike [`load_kernel`], the init ELF is a regular userspace executable whose
/// `p_paddr` values are in low memory already occupied by UEFI. Each LOAD
/// segment is allocated at any available physical address via `AllocateAnyPages`,
/// then the data is copied in. The resulting [`InitImage`] records both the
/// physical allocation address and the virtual address from the ELF so the
/// kernel can build init's page tables without parsing the ELF itself.
///
/// The in-page byte offset of `p_vaddr` is preserved in `phys_addr` so the
/// kernel can identity-map a page without a second copy step:
///   `InitSegment.phys_addr = phys_base + (p_vaddr & 0xFFF)`
///   `InitSegment.virt_addr = p_vaddr`
///
/// # Errors
///
/// - `BootError::OutOfMemory` if any segment's physical allocation fails.
/// - `BootError::InvalidElf` if the image is malformed (bridged from
///   `elf::ElfError`).
///
/// # Safety
///
/// `bs` must be a valid pointer to UEFI boot services and boot services must
/// not yet have been exited.
pub unsafe fn load_init(
    bs: *mut crate::uefi::EfiBootServices,
    data: &[u8],
    expected_machine: u16,
) -> Result<boot_protocol::InitImage, BootError>
{
    use boot_protocol::{INIT_MAX_SEGMENTS, InitImage, InitSegment, SegmentFlags};

    let ehdr = elf::validate(data, expected_machine)?;

    let mut segments = [InitSegment {
        phys_addr: 0,
        virt_addr: 0,
        size: 0,
        flags: SegmentFlags::Read,
    }; INIT_MAX_SEGMENTS];
    let mut count: usize = 0;

    for seg in elf::load_segments(ehdr, data)
    {
        let seg = seg?;
        if seg.memsz == 0
        {
            continue;
        }
        if seg.memsz < seg.filesz
        {
            return Err(BootError::InvalidElf("LOAD segment: p_memsz < p_filesz"));
        }
        if count >= INIT_MAX_SEGMENTS
        {
            return Err(BootError::InvalidElf(
                "init ELF has more than INIT_MAX_SEGMENTS LOAD segments",
            ));
        }

        // p_vaddr & 0xFFF fits in usize (≤ 4095). p_memsz → usize: 64-bit only.
        #[allow(clippy::cast_possible_truncation)]
        let in_page_off = (seg.vaddr & 0xFFF) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let page_count = (in_page_off + seg.memsz as usize).div_ceil(4096);
        // SAFETY: `bs` is valid per the caller's contract.
        let phys_base = unsafe { crate::uefi::allocate_pages(bs, page_count)? };

        // Copy file data at the correct in-page offset.
        // p_offset and p_filesz → usize: 64-bit targets only; cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let file_off = seg.offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let file_sz = seg.filesz as usize;
        if file_sz > 0
        {
            let src = data[file_off..].as_ptr();
            // Destination: phys_base + in-page offset, so virtual virt_addr
            // maps to exactly this physical byte after the kernel activates
            // the page table entry (phys_base → virtual page of virt_addr).
            let dst = (phys_base + in_page_off as u64) as *mut u8;
            // SAFETY: `dst` is within the freshly allocated region (size =
            // page_count * 4096 ≥ in_page_off + file_sz). `src` is within
            // `data`, validated by `elf::load_segments`. Regions are disjoint.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, file_sz) };
        }

        // Zero BSS tail (bytes [file_sz, memsz) relative to virt_addr).
        // Difference fits in usize: memsz ≤ allocated region; 64-bit only.
        #[allow(clippy::cast_possible_truncation)]
        let bss_sz = (seg.memsz - seg.filesz) as usize;
        if bss_sz > 0
        {
            let bss_ptr = (phys_base + in_page_off as u64 + seg.filesz) as *mut u8;
            // SAFETY: `bss_ptr` is within the allocated region.
            unsafe { core::ptr::write_bytes(bss_ptr, 0, bss_sz) };
        }

        let flags = if seg.executable
        {
            SegmentFlags::ReadExecute
        }
        else if seg.writable
        {
            SegmentFlags::ReadWrite
        }
        else
        {
            SegmentFlags::Read
        };

        segments[count] = InitSegment {
            // Encode the in-page offset: phys_addr & 0xFFF = virt_addr & 0xFFF.
            // The kernel maps the physical PAGE (phys_addr & !0xFFF) to the
            // virtual PAGE (virt_addr & !0xFFF) for each page of the segment.
            phys_addr: phys_base + in_page_off as u64,
            virt_addr: seg.vaddr,
            size: seg.memsz,
            flags,
        };
        count += 1;
    }

    if count == 0
    {
        return Err(BootError::InvalidElf("init ELF has no PT_LOAD segments"));
    }

    // count ≤ INIT_MAX_SEGMENTS (≤ 8), well within u32 range.
    #[allow(clippy::cast_possible_truncation)]
    Ok(InitImage {
        entry_point: elf::entry_point(ehdr),
        segments,
        segment_count: count as u32,
    })
}

// ── Boot module loading ───────────────────────────────────────────────────────

/// Load a flat binary boot module from `data` into physical memory.
///
/// Allocates pages at any available physical address via `AllocateAnyPages`,
/// copies `data` into the region, and returns a [`BootModule`] descriptor for
/// inclusion in [`boot_protocol::BootInfo`].
///
/// The allocated region is rounded up to a page boundary. `BootModule.size`
/// records the exact file size (not the page-rounded allocation size) so the
/// kernel knows the precise extent of valid data.
///
/// # Errors
///
/// Returns `BootError::OutOfMemory` if `AllocatePages` fails.
///
/// # Safety
///
/// `bs` must be a valid pointer to UEFI boot services and boot services must
/// not yet have been exited.
pub unsafe fn load_module(
    bs: *mut crate::uefi::EfiBootServices,
    data: &[u8],
) -> Result<BootModule, BootError>
{
    let page_count = data.len().div_ceil(4096);

    // SAFETY: `bs` is valid boot services per the caller's contract.
    let phys_base = unsafe { crate::uefi::allocate_pages(bs, page_count)? };

    let dst = phys_base as *mut u8;
    // SAFETY: `dst` is the base of a freshly UEFI-allocated region of at least
    // `page_count * 4096 >= data.len()` bytes, identity-mapped in the bootloader
    // address space. `data` is a valid `&[u8]` of exactly `data.len()` bytes.
    // The source (temporary file read buffer) and destination (new physical
    // allocation) are disjoint regions; no overlap is possible.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };

    // data.len() is a byte count that fits in u64 on any realistic system.
    #[allow(clippy::cast_possible_truncation)]
    Ok(BootModule {
        physical_base: phys_base,
        size: data.len() as u64,
    })
}
