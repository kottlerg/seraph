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
//! - For the kernel: allocate one contiguous span at any available physical
//!   base via `AllocatePages(AllocateAnyPages, …)` and place each segment at
//!   its ELF-relative offset within the span, so kernel placement tolerates
//!   any firmware memory layout.
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

/// Physical span and link-time bases of a kernel image, derived from its
/// `PT_LOAD` segments by [`validate_kernel_layout`].
///
/// The loader allocates one contiguous region of `span_bytes` at any free
/// physical base and places each segment at `span_base + (p_paddr -
/// link_phys)`, preserving the ELF's relative layout.
struct KernelSpan
{
    /// Lowest `p_paddr` across all segments — the ELF's link-time physical origin.
    link_phys: u64,
    /// Lowest `p_vaddr` across all segments — the kernel's link-time virtual base.
    link_virt: u64,
    /// Span from `link_phys` to the end of the highest segment (`p_paddr + p_memsz`).
    span_bytes: u64,
}

/// Validate the kernel `PT_LOAD` layout and compute its physical span.
///
/// The kernel image is placed as a single contiguous span at a dynamically
/// chosen physical base (issue #377: a fixed `p_paddr` collides with
/// hart-scaled firmware allocations). That relocation is sound only if the
/// segments form one linearly-offset, page-aligned, non-overlapping block: the
/// kernel maps every page at `pa = va - link_virt + span_base`
/// (`map_kernel_image`), and the per-segment copy below places each segment by
/// the same offset. These checks guarantee both hold.
///
/// # Errors
///
/// Returns [`BootError::InvalidElf`] if `segs` is empty, any segment has
/// `p_memsz < p_filesz`, any `p_vaddr`/`p_paddr` is not 4 KiB-aligned, the
/// segments do not share a single `p_vaddr → p_paddr` offset, any two segments'
/// physical ranges overlap, or `entry` lies outside every segment.
fn validate_kernel_layout(segs: &[elf::LoadSegment], entry: u64) -> Result<KernelSpan, BootError>
{
    if segs.is_empty()
    {
        return Err(BootError::InvalidElf("kernel ELF has no PT_LOAD segments"));
    }

    let link_phys = segs.iter().map(|s| s.paddr).fold(u64::MAX, u64::min);
    let link_virt = segs.iter().map(|s| s.vaddr).fold(u64::MAX, u64::min);

    for s in segs
    {
        if s.memsz < s.filesz
        {
            return Err(BootError::InvalidElf("LOAD segment: p_memsz < p_filesz"));
        }
        if s.vaddr % 4096 != 0 || s.paddr % 4096 != 0
        {
            return Err(BootError::InvalidElf(
                "LOAD segment: p_vaddr or p_paddr not 4 KiB-aligned",
            ));
        }
        // A single linear offset is what lets span placement and the kernel's
        // `pa = va - link_virt + span_base` mapping agree.
        if s.paddr.wrapping_sub(link_phys) != s.vaddr.wrapping_sub(link_virt)
        {
            return Err(BootError::InvalidElf(
                "LOAD segments do not share one p_vaddr->p_paddr offset",
            ));
        }
    }

    // Pairwise physical non-overlap (≤ 8 segments; O(n²) is trivial).
    // Overlapping segments would corrupt the copy into the single span.
    for (i, a) in segs.iter().enumerate()
    {
        let a_end = a.paddr.saturating_add(a.memsz);
        for b in &segs[i + 1..]
        {
            let b_end = b.paddr.saturating_add(b.memsz);
            if a.paddr < b_end && b.paddr < a_end
            {
                return Err(BootError::InvalidElf(
                    "LOAD segments overlap in physical memory",
                ));
            }
        }
    }

    if !segs
        .iter()
        .any(|s| entry >= s.vaddr && entry < s.vaddr.saturating_add(s.memsz))
    {
        return Err(BootError::InvalidElf(
            "entry point not within any LOAD segment",
        ));
    }

    let phys_end = segs
        .iter()
        .map(|s| s.paddr.saturating_add(s.memsz))
        .fold(0u64, u64::max);

    Ok(KernelSpan {
        link_phys,
        link_virt,
        span_bytes: phys_end.saturating_sub(link_phys),
    })
}

/// Load the kernel ELF from `data` into physical memory allocated via UEFI.
///
/// The image is placed as a single contiguous span allocated at any free
/// physical base via `AllocateAnyPages`; each `PT_LOAD` segment is copied to
/// `span_base + (p_paddr - link_phys)`, preserving the ELF's relative offsets,
/// and its BSS tail (`p_memsz - p_filesz` bytes) is zeroed. Dynamic placement
/// tolerates any firmware memory layout (issue #377); the kernel learns the
/// chosen base through `BootInfo.kernel_physical_base`.
///
/// Up to 8 `PT_LOAD` segments are supported; an ELF with more returns
/// `InvalidElf`.
///
/// # Errors
///
/// - `BootError::InvalidElf` — header check failed (bridged from
///   `elf::ElfError`), or the segment layout failed [`validate_kernel_layout`].
/// - `BootError::OutOfMemory` — no free contiguous span of the required size.
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

    // Collect the PT_LOAD segments (skipping pure-padding entries) before any
    // allocation, so the whole layout can be validated as a unit.
    let mut raw = [elf::LoadSegment {
        vaddr: 0,
        paddr: 0,
        offset: 0,
        filesz: 0,
        memsz: 0,
        writable: false,
        executable: false,
    }; MAX_LOAD_SEGMENTS];
    let mut segment_count: usize = 0;

    for seg in elf::load_segments(ehdr, data)
    {
        let seg = seg?;
        if seg.memsz == 0
        {
            continue;
        }
        if segment_count >= MAX_LOAD_SEGMENTS
        {
            return Err(BootError::InvalidElf("ELF has more than 8 LOAD segments"));
        }
        raw[segment_count] = seg;
        segment_count += 1;
    }

    let span = validate_kernel_layout(&raw[..segment_count], elf::entry_point(ehdr))?;

    // One contiguous allocation for the whole image, placed wherever the
    // firmware has free RAM.
    // span_bytes → usize: 64-bit on all supported UEFI targets; cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let page_count = (span.span_bytes as usize).div_ceil(4096);
    // SAFETY: `bs` is valid boot services per the function's safety contract.
    let span_base = unsafe { crate::uefi::allocate_pages(bs, page_count)? };

    let mut segments: [LoadedSegment; MAX_LOAD_SEGMENTS] =
        core::array::from_fn(|_| LoadedSegment {
            phys_base: 0,
            virt_base: 0,
            size: 0,
            writable: false,
            executable: false,
        });

    for (i, seg) in raw[..segment_count].iter().enumerate()
    {
        // Destination preserves the ELF's relative physical offset. Page-aligned
        // because `span_base` and `(paddr - link_phys)` are both 4 KiB multiples
        // (the latter validated).
        let dst_phys = span_base + (seg.paddr - span.link_phys);

        // Copy file data (filesz bytes) into the placed region.
        // p_offset / p_filesz → usize: 64-bit targets only; cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let file_off = seg.offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let file_sz = seg.filesz as usize;
        if file_sz > 0
        {
            let src = data[file_off..].as_ptr();
            let dst = dst_phys as *mut u8;
            // SAFETY: `src` points into `data`; `elf::load_segments` already
            // validated that `[file_off, file_off + file_sz)` is in bounds
            // (yields SegmentOverflow otherwise). `dst` lies within the single
            // span allocation (`page_count * 4096 ≥ span_bytes ≥ (paddr -
            // link_phys) + memsz ≥ … + filesz`), identity-mapped in the
            // bootloader address space and disjoint from the read buffer.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, file_sz) };
        }

        // Zero the BSS tail: bytes [filesz, memsz).
        // Difference fits in usize: memsz ≤ allocated region; 64-bit only.
        #[allow(clippy::cast_possible_truncation)]
        let bss_sz = (seg.memsz - seg.filesz) as usize;
        if bss_sz > 0
        {
            let bss_ptr = (dst_phys + seg.filesz) as *mut u8;
            // SAFETY: `bss_ptr` is `filesz` bytes into the segment's placed
            // region, which spans `memsz` bytes within the span allocation.
            // UEFI does not guarantee zeroed pages; we must zero BSS here.
            unsafe { core::ptr::write_bytes(bss_ptr, 0, bss_sz) };
        }

        segments[i] = LoadedSegment {
            phys_base: dst_phys,
            virt_base: seg.vaddr,
            size: seg.memsz,
            writable: seg.writable,
            executable: seg.executable,
        };
    }

    Ok(KernelInfo {
        physical_base: span_base,
        virtual_base: span.link_virt,
        size: span.span_bytes,
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

// Boot modules are exposed in place by referencing the single bundle UEFI
// allocation in `BootModule.physical_base`; only the `init` entry is ELF-
// loaded (via [`load_init`]). See `main.rs::step4_parse_bundle`.

#[cfg(test)]
mod tests
{
    use super::*;

    // A realistic kernel link layout: one linear vaddr→paddr offset, 4 KiB-aligned.
    const VBASE: u64 = 0xFFFF_FFFF_8000_0000;
    const PBASE: u64 = 0x8020_0000;

    fn seg(vaddr: u64, paddr: u64, filesz: u64, memsz: u64) -> elf::LoadSegment
    {
        elf::LoadSegment {
            vaddr,
            paddr,
            offset: 0,
            filesz,
            memsz,
            writable: false,
            executable: false,
        }
    }

    // text / rodata / data / bss, page-contiguous, BSS tail extends past a page.
    fn contiguous_layout() -> [elf::LoadSegment; 4]
    {
        [
            seg(VBASE, PBASE, 0x1000, 0x1000),
            seg(VBASE + 0x1000, PBASE + 0x1000, 0x1000, 0x1000),
            seg(VBASE + 0x2000, PBASE + 0x2000, 0x1000, 0x1000),
            seg(VBASE + 0x3000, PBASE + 0x3000, 0x800, 0x1800),
        ]
    }

    #[test]
    fn valid_layout_yields_link_bases_and_span()
    {
        let span = validate_kernel_layout(&contiguous_layout(), VBASE).expect("valid layout");
        assert_eq!(span.link_phys, PBASE);
        assert_eq!(span.link_virt, VBASE);
        // phys_end = PBASE + 0x3000 + 0x1800; span = 0x4800.
        assert_eq!(span.span_bytes, 0x4800);
    }

    #[test]
    fn span_covers_unaligned_final_segment_end()
    {
        // Last segment ends at a non-page boundary; span must still reach it.
        let segs = [seg(VBASE, PBASE, 0x10, 0x10)];
        let span = validate_kernel_layout(&segs, VBASE).expect("valid layout");
        assert_eq!(span.span_bytes, 0x10);
    }

    #[test]
    fn empty_segment_slice_is_rejected()
    {
        assert!(validate_kernel_layout(&[], VBASE).is_err());
    }

    #[test]
    fn memsz_less_than_filesz_is_rejected()
    {
        let segs = [seg(VBASE, PBASE, 0x2000, 0x1000)];
        assert!(validate_kernel_layout(&segs, VBASE).is_err());
    }

    #[test]
    fn unaligned_vaddr_is_rejected()
    {
        let segs = [seg(VBASE + 0x100, PBASE, 0x1000, 0x1000)];
        assert!(validate_kernel_layout(&segs, VBASE + 0x100).is_err());
    }

    #[test]
    fn unaligned_paddr_is_rejected()
    {
        let segs = [seg(VBASE, PBASE + 0x100, 0x1000, 0x1000)];
        assert!(validate_kernel_layout(&segs, VBASE).is_err());
    }

    #[test]
    fn inconsistent_linear_offset_is_rejected()
    {
        // Second segment's paddr offset (0x2000) differs from its vaddr offset (0x1000).
        let segs = [
            seg(VBASE, PBASE, 0x1000, 0x1000),
            seg(VBASE + 0x1000, PBASE + 0x2000, 0x1000, 0x1000),
        ];
        assert!(validate_kernel_layout(&segs, VBASE).is_err());
    }

    #[test]
    fn overlapping_physical_ranges_are_rejected()
    {
        // Consistent linear offset, but segment 0's memsz overruns into segment 1.
        let segs = [
            seg(VBASE, PBASE, 0x800, 0x2000),
            seg(VBASE + 0x1000, PBASE + 0x1000, 0x800, 0x1000),
        ];
        assert!(validate_kernel_layout(&segs, VBASE).is_err());
    }

    #[test]
    fn entry_outside_all_segments_is_rejected()
    {
        assert!(validate_kernel_layout(&contiguous_layout(), VBASE + 0x10000).is_err());
    }
}
