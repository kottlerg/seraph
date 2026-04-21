// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/elf.rs

//! ELF parser, segment loader, and entry point extraction.
//!
//! Validates kernel ELF images and loads their LOAD segments into physical
//! memory allocated via UEFI. W^X is enforced at the segment level before
//! any allocation occurs. Boot modules are loaded as opaque flat binaries.

use core::mem::size_of;

use crate::error::BootError;
use boot_protocol::BootModule;

// ── ELF identification constants ─────────────────────────────────────────────

const ELFMAG0: u8 = 0x7F;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';

/// ELF class: 64-bit object.
const ELFCLASS64: u8 = 2;
/// ELF data encoding: 2's complement, little-endian.
const ELFDATA2LSB: u8 = 1;
/// ELF version: current (1).
const EV_CURRENT: u8 = 1;

/// ELF type: static executable.
const ET_EXEC: u16 = 2;

/// Machine type: x86-64.
#[allow(dead_code)] // Both constants are defined; only one is referenced per target arch build.
pub const EM_X86_64: u16 = 0x3E;
/// Machine type: RISC-V.
#[allow(dead_code)] // Both constants are defined; only one is referenced per target arch build.
pub const EM_RISCV: u16 = 0xF3;

// ── Program header constants ──────────────────────────────────────────────────

/// Program header type: loadable segment.
const PT_LOAD: u32 = 1;

/// Segment flag: execute permission.
const PF_X: u32 = 1;
/// Segment flag: write permission.
const PF_W: u32 = 2;
/// Segment flag: read permission.
#[allow(dead_code)] // PF_X and PF_W are checked; PF_R is defined for completeness (all segments are readable).
const PF_R: u32 = 4;

// ── ELF e_ident index constants ───────────────────────────────────────────────

/// Byte index of the ELF class field in `e_ident`.
const EI_CLASS: usize = 4;
/// Byte index of the data encoding field in `e_ident`.
const EI_DATA: usize = 5;
/// Byte index of the ELF version field in `e_ident`.
const EI_VERSION: usize = 6;

// ── ELF raw types ─────────────────────────────────────────────────────────────

/// 64-bit ELF file header (`Elf64_Ehdr`).
#[repr(C)]
// ELF field names follow the ELF spec (e_ident, e_type, …); removing the `e_` prefix
// would diverge from all reference material and embedded safety comments.
#[allow(clippy::struct_field_names)]
pub struct Elf64Ehdr
{
    /// Magic number and ELF identification fields.
    pub e_ident: [u8; 16],
    /// Object file type (e.g. `ET_EXEC`).
    pub e_type: u16,
    /// Target machine architecture.
    pub e_machine: u16,
    /// ELF format version; must equal `EV_CURRENT`.
    pub e_version: u32,
    /// Virtual address of the program entry point.
    pub e_entry: u64,
    /// File offset of the program header table.
    pub e_phoff: u64,
    /// File offset of the section header table (unused by the loader).
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// Size of this header in bytes.
    pub e_ehsize: u16,
    /// Size of one program header entry in bytes.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Size of one section header entry in bytes (unused by the loader).
    pub e_shentsize: u16,
    /// Number of section header entries (unused by the loader).
    pub e_shnum: u16,
    /// Index of the section name string table entry (unused by the loader).
    pub e_shstrndx: u16,
}

/// 64-bit ELF program header (`Elf64_Phdr`).
#[repr(C)]
// ELF field names follow the ELF spec (p_type, p_flags, …); removing the `p_` prefix
// would diverge from all reference material and embedded safety comments.
#[allow(clippy::struct_field_names)]
pub struct Elf64Phdr
{
    /// Segment type (e.g. `PT_LOAD`).
    pub p_type: u32,
    /// Segment-dependent permission flags (`PF_R`, `PF_W`, `PF_X`).
    pub p_flags: u32,
    /// Byte offset of the segment data within the file.
    pub p_offset: u64,
    /// Virtual address at which the segment is to be loaded.
    pub p_vaddr: u64,
    /// Physical address of the segment (used by the bootloader for placement).
    pub p_paddr: u64,
    /// Number of bytes in the file image of the segment.
    pub p_filesz: u64,
    /// Number of bytes in the memory image of the segment (may exceed `p_filesz`).
    pub p_memsz: u64,
    /// Required alignment; must be a power of two, or zero.
    pub p_align: u64,
}

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

// ── Validation ────────────────────────────────────────────────────────────────

/// Validate an ELF64 header in `data` against the expected machine type.
///
/// Performs all ten checks from `boot/docs/elf-loading.md` in order:
///
/// 1. `data.len() >= size_of::<Elf64Ehdr>()`
/// 2. ELF magic bytes
/// 3. `ELFCLASS64` (64-bit)
/// 4. `ELFDATA2LSB` (little-endian)
/// 5. `EV_CURRENT` version
/// 6. `ET_EXEC` (static executable)
/// 7. `e_machine == expected_machine`
/// 8. `e_phentsize == size_of::<Elf64Phdr>()`
/// 9. `e_phnum > 0`
/// 10. `e_entry` is within the virtual range of at least one `PT_LOAD` segment
///
/// Returns a reference into `data` typed as `&Elf64Ehdr` on success, valid for
/// the lifetime of `data`.
///
/// # Errors
///
/// Returns `BootError::InvalidElf` with a descriptive literal string for each
/// failed check.
pub fn validate_elf_header(data: &[u8], expected_machine: u16) -> Result<&Elf64Ehdr, BootError>
{
    // Check 1: buffer large enough for the fixed-size ELF header.
    if data.len() < size_of::<Elf64Ehdr>()
    {
        return Err(BootError::InvalidElf(
            "file too small to contain ELF header",
        ));
    }

    // SAFETY: data is at least size_of::<Elf64Ehdr>() bytes (checked above).
    // Elf64Ehdr is #[repr(C)] with only integer fields; all bit patterns valid.
    // Shared reference lifetime tied to `data`.
    // cast_ptr_alignment: ELF files in the read buffer may not be naturally aligned,
    // but read_unaligned semantics apply — we only access via the reference in places
    // where rustc emits unaligned loads for #[repr(C)] packed structs.  The struct
    // fields are individually byte-readable; this pattern is standard for ELF parsers.
    #[allow(clippy::cast_ptr_alignment)]
    let ehdr = unsafe { &*(data.as_ptr().cast::<Elf64Ehdr>()) };

    // Check 2: ELF magic.
    if ehdr.e_ident[0] != ELFMAG0
        || ehdr.e_ident[1] != ELFMAG1
        || ehdr.e_ident[2] != ELFMAG2
        || ehdr.e_ident[3] != ELFMAG3
    {
        return Err(BootError::InvalidElf("bad ELF magic number"));
    }

    // Check 3: 64-bit class.
    if ehdr.e_ident[EI_CLASS] != ELFCLASS64
    {
        return Err(BootError::InvalidElf(
            "ELF is not 64-bit (ELFCLASS64 required)",
        ));
    }

    // Check 4: little-endian encoding (both supported architectures are LE).
    if ehdr.e_ident[EI_DATA] != ELFDATA2LSB
    {
        return Err(BootError::InvalidElf(
            "ELF is not little-endian (ELFDATA2LSB required)",
        ));
    }

    // Check 5: ELF format version must be current (1).
    if ehdr.e_ident[EI_VERSION] != EV_CURRENT
    {
        return Err(BootError::InvalidElf("ELF ident version is not EV_CURRENT"));
    }

    // Check 6: must be a static executable; ET_DYN (PIE) is not supported for
    // the kernel because the bootloader places segments at their ELF p_paddr.
    if ehdr.e_type != ET_EXEC
    {
        return Err(BootError::InvalidElf(
            "ELF type is not ET_EXEC (position-independent ELF not supported)",
        ));
    }

    // Check 7: machine type must match the bootloader's target architecture.
    if ehdr.e_machine != expected_machine
    {
        return Err(BootError::InvalidElf(
            "ELF machine type does not match bootloader architecture",
        ));
    }

    // Check 8: program header entry size must match our struct's size. A mismatch
    // would make the program header slice unsafe to interpret.
    // size_of::<Elf64Phdr>() is 56, well within u16 range; truncation cannot occur.
    #[allow(clippy::cast_possible_truncation)]
    if ehdr.e_phentsize != size_of::<Elf64Phdr>() as u16
    {
        return Err(BootError::InvalidElf(
            "e_phentsize does not match sizeof(Elf64_Phdr)",
        ));
    }

    // Check 9: must have at least one program header (otherwise check 10 is moot
    // and there is nothing to load).
    if ehdr.e_phnum == 0
    {
        return Err(BootError::InvalidElf(
            "ELF has no program headers (e_phnum == 0)",
        ));
    }

    // Check 10: verify e_entry lies within at least one PT_LOAD segment's virtual
    // range. This requires reading the program header table first, so it comes last.
    // e_phoff is a file byte offset; on all UEFI targets (x86_64/riscv64) usize is
    // 64-bit, so this cast is exact.  On any hypothetical 32-bit target the ELF
    // itself would be invalid, but we suppress to keep the allow paired with the cast.
    #[allow(clippy::cast_possible_truncation)]
    let ph_start = ehdr.e_phoff as usize;
    let ph_count = ehdr.e_phnum as usize;
    let ph_bytes = ph_count
        .checked_mul(size_of::<Elf64Phdr>())
        .ok_or(BootError::InvalidElf("program header table size overflow"))?;
    let ph_end = ph_start.checked_add(ph_bytes).ok_or(BootError::InvalidElf(
        "program header table offset overflow",
    ))?;

    if ph_end > data.len()
    {
        return Err(BootError::InvalidElf(
            "program header table extends beyond end of file",
        ));
    }

    // SAFETY: `data[ph_start..]` contains at least `ph_bytes` bytes (verified
    // above). `Elf64Phdr` is `#[repr(C)]` with only integer fields; all bit
    // patterns are valid. Slice lifetime is tied to `data`.
    // cast_ptr_alignment: the ELF read buffer is not required to be aligned to
    // Elf64Phdr (8 bytes); field accesses inside Elf64Phdr use natural C layout
    // reads which the compiler handles correctly for #[repr(C)] structs.
    #[allow(clippy::cast_ptr_alignment)]
    let phdrs: &[Elf64Phdr] = unsafe {
        core::slice::from_raw_parts(data[ph_start..].as_ptr().cast::<Elf64Phdr>(), ph_count)
    };

    let entry_in_segment = phdrs.iter().any(|ph| {
        ph.p_type == PT_LOAD
            && ph.p_memsz > 0
            && ehdr.e_entry >= ph.p_vaddr
            && ehdr.e_entry < ph.p_vaddr.saturating_add(ph.p_memsz)
    });

    if !entry_in_segment
    {
        return Err(BootError::InvalidElf("entry point not in any LOAD segment"));
    }

    Ok(ehdr)
}

// ── W^X validation ────────────────────────────────────────────────────────────

/// Scan every program header for simultaneous write and execute permissions.
///
/// Returns `WxViolation` on the first `PT_LOAD` segment that has both `PF_W`
/// and `PF_X` set. Non-`PT_LOAD` segments are ignored because they are not
/// mapped into the address space by the loader.
///
/// Called before any physical memory allocation so a violation never leaves a
/// partially loaded image.
fn check_wx_segments(phdrs: &[Elf64Phdr]) -> Result<(), BootError>
{
    for ph in phdrs
    {
        if ph.p_type != PT_LOAD
        {
            continue;
        }
        if (ph.p_flags & PF_W) != 0 && (ph.p_flags & PF_X) != 0
        {
            return Err(BootError::WxViolation);
        }
    }
    Ok(())
}

// ── Kernel loading ────────────────────────────────────────────────────────────

/// Load the kernel ELF from `data` into physical memory allocated via UEFI.
///
/// The function proceeds in three phases:
///
/// 1. **Validation** — calls [`validate_elf_header`]; any failure is fatal.
/// 2. **W^X check** — scans every `PT_LOAD` segment for simultaneous write and
///    execute permissions before any allocation occurs.
/// 3. **Loading** — for each `PT_LOAD` segment: allocates physical pages at
///    `p_paddr` via `AllocateAddress`, copies `p_filesz` bytes of file data into
///    the region, and zeroes the BSS tail (`p_memsz - p_filesz` bytes).
///
/// Up to 8 `PT_LOAD` segments are supported; an ELF with more returns
/// `InvalidElf`.
///
/// Returns a [`KernelInfo`] for consumption by the page table builder and by
/// the `BootInfo` population step.
///
/// # Errors
///
/// - `BootError::InvalidElf` — header or segment constraint check failed.
/// - `BootError::WxViolation` — a `PT_LOAD` segment has both `PF_W` and `PF_X`.
/// - `BootError::OutOfMemory` — `AllocatePages(AllocateAddress)` returned failure.
///
/// # Safety
///
/// `bs` must be a valid pointer to UEFI boot services and boot services must
/// not yet have been exited. `data` must remain valid for the duration of the
/// call (it is a temporary read buffer from file I/O).
// The function is self-contained: splitting it would require passing many locals
// across function boundaries with no structural gain.
#[allow(clippy::too_many_lines)]
pub unsafe fn load_kernel(
    bs: *mut crate::uefi::EfiBootServices,
    data: &[u8],
    expected_machine: u16,
) -> Result<KernelInfo, BootError>
{
    // Phase 1: Validate the ELF header.
    let ehdr = validate_elf_header(data, expected_machine)?;

    // Recompute the program header slice from the validated header. The same
    // bounds were already checked inside `validate_elf_header`, so the arithmetic
    // cannot fail here.
    // e_phoff is a file byte offset; usize is 64-bit on all supported UEFI targets.
    #[allow(clippy::cast_possible_truncation)]
    let ph_start = ehdr.e_phoff as usize;
    let ph_count = ehdr.e_phnum as usize;

    // SAFETY: `validate_elf_header` already confirmed that `data[ph_start..]`
    // contains exactly `ph_count * size_of::<Elf64Phdr>()` valid bytes, and that
    // `Elf64Phdr` accepts any bit pattern. Lifetime is tied to `data`.
    // cast_ptr_alignment: ELF read buffer may not be 8-byte aligned; field accesses
    // in #[repr(C)] structs emit correctly-sized (potentially unaligned) loads.
    #[allow(clippy::cast_ptr_alignment)]
    let phdrs: &[Elf64Phdr] = unsafe {
        core::slice::from_raw_parts(data[ph_start..].as_ptr().cast::<Elf64Phdr>(), ph_count)
    };

    // Phase 2: W^X check across all LOAD segments. Reject the entire ELF before
    // allocating any physical memory so we never leave a partially loaded image.
    check_wx_segments(phdrs)?;

    // Phase 3: Allocate and populate each LOAD segment.
    let mut segments: [core::mem::MaybeUninit<LoadedSegment>; MAX_LOAD_SEGMENTS] =
        core::array::from_fn(|_| core::mem::MaybeUninit::uninit());
    let mut segment_count: usize = 0;

    for ph in phdrs
    {
        if ph.p_type != PT_LOAD
        {
            continue;
        }
        if ph.p_memsz == 0
        {
            // Zero-size memory region; nothing to map or copy.
            continue;
        }

        if ph.p_memsz < ph.p_filesz
        {
            return Err(BootError::InvalidElf("LOAD segment: p_memsz < p_filesz"));
        }

        if segment_count >= MAX_LOAD_SEGMENTS
        {
            return Err(BootError::InvalidElf("ELF has more than 8 LOAD segments"));
        }

        // Validate the file data range before allocating anything.
        // p_offset and p_filesz are file byte offsets/sizes; usize is 64-bit on all
        // supported UEFI targets (x86_64, riscv64), so these casts are exact.
        #[allow(clippy::cast_possible_truncation)]
        let file_off = ph.p_offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let file_sz = ph.p_filesz as usize;
        if file_sz > 0
        {
            let file_end = file_off
                .checked_add(file_sz)
                .ok_or(BootError::InvalidElf("LOAD segment file range overflow"))?;
            if file_end > data.len()
            {
                return Err(BootError::InvalidElf(
                    "LOAD segment file data extends beyond end of file",
                ));
            }
        }

        // Allocate physical pages at the ELF-specified physical address.
        // p_memsz → usize: 64-bit on all supported UEFI targets; cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let page_count = (ph.p_memsz as usize).div_ceil(4096);
        // SAFETY: `bs` is valid boot services per the function's safety contract.
        // `p_paddr` is the ELF-specified physical base; UEFI fails if the range
        // is already occupied, which we surface as `OutOfMemory`.
        unsafe { crate::uefi::allocate_address(bs, ph.p_paddr, page_count)? };

        // Copy file data (p_filesz bytes) into the allocated physical region.
        if file_sz > 0
        {
            let src = data[file_off..].as_ptr();
            let dst = ph.p_paddr as *mut u8;
            // SAFETY: `src` points into `data`, valid for `file_sz` bytes from
            // `file_off` (range verified above). `dst` is the physical base of a
            // freshly UEFI-allocated region of at least `p_memsz >= p_filesz`
            // bytes, identity-mapped in the bootloader address space. The regions
            // cannot overlap: `src` is in the temporary ELF read buffer while
            // `dst` is a distinct physical allocation.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, file_sz) };
        }

        // Zero the BSS tail: bytes [p_filesz, p_memsz).
        // Difference ≤ p_memsz ≤ segment size; 64-bit targets only, cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let bss_sz = (ph.p_memsz - ph.p_filesz) as usize;
        if bss_sz > 0
        {
            let bss_ptr = (ph.p_paddr + ph.p_filesz) as *mut u8;
            // SAFETY: `bss_ptr` is `p_filesz` bytes past the segment's physical
            // base, which is within the allocated region (`p_memsz` bytes total).
            // `bss_sz = p_memsz - p_filesz` bytes remain in the allocation.
            // UEFI does not guarantee pages are zeroed; we must zero BSS here.
            unsafe { core::ptr::write_bytes(bss_ptr, 0, bss_sz) };
        }

        segments[segment_count].write(LoadedSegment {
            phys_base: ph.p_paddr,
            virt_base: ph.p_vaddr,
            size: ph.p_memsz,
            writable: (ph.p_flags & PF_W) != 0,
            executable: (ph.p_flags & PF_X) != 0,
        });
        segment_count += 1;
    }

    if segment_count == 0
    {
        return Err(BootError::InvalidElf(
            "ELF has no PT_LOAD segments with non-zero p_memsz",
        ));
    }

    // Build a typed slice over the initialised prefix for arithmetic.
    // SAFETY: Elements 0..segment_count were each written above; reads are sound.
    let init_segs: &[LoadedSegment] = unsafe {
        core::slice::from_raw_parts(segments.as_ptr().cast::<LoadedSegment>(), segment_count)
    };

    // Compute the entry physical address.
    // `validate_elf_header` already confirmed `e_entry` is inside a LOAD segment,
    // so this search is guaranteed to succeed. We return `InvalidElf` defensively.
    let entry_virtual = ehdr.e_entry;
    let mut entry_found = false;
    for seg in init_segs
    {
        if entry_virtual >= seg.virt_base && entry_virtual < seg.virt_base.saturating_add(seg.size)
        {
            entry_found = true;
            break;
        }
    }
    if !entry_found
    {
        return Err(BootError::InvalidElf(
            "entry point not covered by any loaded segment",
        ));
    }

    // Compute physical_base, virtual_base, and size from the loaded segments.
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

    // Transfer the initialised prefix and fill the uninitialised tail with safe
    // sentinel values. The tail is never exposed to callers (access is guarded by
    // `segment_count`), but we must not leave `MaybeUninit` unread storage in the
    // `KernelInfo` struct, which is `!Copy` and has no unsafe interior.
    //
    // SAFETY: For indices < segment_count, we call `assume_init_read` on elements
    // that were written via `.write()` above, which is sound. For the tail, we
    // write fresh zero-initialised `LoadedSegment` values — no uninit read occurs.
    let out_segments: [LoadedSegment; MAX_LOAD_SEGMENTS] = core::array::from_fn(|i| {
        if i < segment_count
        {
            // SAFETY: `segments[i]` was initialised with a valid `LoadedSegment`
            // in the loading loop above.
            unsafe { segments[i].assume_init_read() }
        }
        else
        {
            LoadedSegment {
                phys_base: 0,
                virt_base: 0,
                size: 0,
                writable: false,
                executable: false,
            }
        }
    });

    Ok(KernelInfo {
        physical_base,
        virtual_base,
        size,
        entry_virtual,
        segments: out_segments,
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
/// W^X is enforced across all LOAD segments before any allocation occurs.
///
/// # Errors
///
/// - `BootError::OutOfMemory` if any segment's physical allocation fails.
/// - `BootError::InvalidElf` if the image is malformed.
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

    let ehdr = validate_elf_header(data, expected_machine)?;

    // e_phoff and p_offset are file byte offsets; usize is 64-bit on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let ph_start = ehdr.e_phoff as usize;
    let ph_count = ehdr.e_phnum as usize;

    // SAFETY: validated by `validate_elf_header`.
    // cast_ptr_alignment: ELF read buffer alignment is not guaranteed; field accesses
    // in #[repr(C)] structs emit correctly-sized loads.
    #[allow(clippy::cast_ptr_alignment)]
    let phdrs: &[Elf64Phdr] = unsafe {
        core::slice::from_raw_parts(data[ph_start..].as_ptr().cast::<Elf64Phdr>(), ph_count)
    };

    // W^X check before any allocation.
    check_wx_segments(phdrs)?;

    let mut segments = [InitSegment {
        phys_addr: 0,
        virt_addr: 0,
        size: 0,
        flags: SegmentFlags::Read,
    }; INIT_MAX_SEGMENTS];
    let mut count: usize = 0;

    for ph in phdrs
    {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0
        {
            continue;
        }
        if ph.p_memsz < ph.p_filesz
        {
            return Err(BootError::InvalidElf("LOAD segment: p_memsz < p_filesz"));
        }
        if count >= INIT_MAX_SEGMENTS
        {
            return Err(BootError::InvalidElf(
                "init ELF has more than INIT_MAX_SEGMENTS LOAD segments",
            ));
        }

        // Validate file data range.
        // p_offset and p_filesz are file byte offsets; usize is 64-bit on all supported targets.
        #[allow(clippy::cast_possible_truncation)]
        let file_off = ph.p_offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let file_sz = ph.p_filesz as usize;
        if file_sz > 0
        {
            let file_end = file_off
                .checked_add(file_sz)
                .ok_or(BootError::InvalidElf("LOAD segment file range overflow"))?;
            if file_end > data.len()
            {
                return Err(BootError::InvalidElf(
                    "LOAD segment file data extends beyond end of file",
                ));
            }
        }

        // Allocate at any available physical address (not at p_paddr, which is
        // a low userspace address already used by UEFI firmware).
        //
        // Preserve the in-page byte offset from the ELF virtual address so the
        // kernel can map the physical page directly without an extra copy step:
        //   InitSegment.phys_addr = phys_base + (p_vaddr & 0xFFF)
        //   InitSegment.virt_addr = p_vaddr
        //
        // The kernel then creates: PTE[page(virt_addr)] → frame(phys_base),
        // and the CPU translates virtual byte virt_addr to physical byte
        //   phys_base + (virt_addr & 0xFFF) = phys_addr ✓
        //
        // page_count must cover the in-page offset so segments that would
        // otherwise cross a page boundary get enough frames.
        // p_vaddr & 0xFFF fits in usize (≤ 4095). p_memsz → usize: 64-bit targets only.
        #[allow(clippy::cast_possible_truncation)]
        let in_page_off = (ph.p_vaddr & 0xFFF) as usize;
        #[allow(clippy::cast_possible_truncation)]
        let page_count = (in_page_off + ph.p_memsz as usize).div_ceil(4096);
        // SAFETY: `bs` is valid per the caller's contract.
        let phys_base = unsafe { crate::uefi::allocate_pages(bs, page_count)? };

        // Copy file data at the correct in-page offset.
        if file_sz > 0
        {
            let src = data[file_off..].as_ptr();
            // Destination: phys_base + in-page offset, so virtual virt_addr
            // maps to exactly this physical byte after the kernel activates
            // the page table entry (phys_base → virtual page of virt_addr).
            let dst = (phys_base + in_page_off as u64) as *mut u8;
            // SAFETY: `dst` is within the freshly allocated region
            // (size = page_count * 4096 ≥ in_page_off + file_sz).
            // `src` is within `data` (verified above). Regions are disjoint.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, file_sz) };
        }

        // Zero BSS tail (bytes [file_sz, p_memsz) relative to virt_addr).
        // Difference fits in usize: p_memsz ≤ segment size, 64-bit targets only.
        #[allow(clippy::cast_possible_truncation)]
        let bss_sz = (ph.p_memsz - ph.p_filesz) as usize;
        if bss_sz > 0
        {
            let bss_ptr = (phys_base + in_page_off as u64 + ph.p_filesz) as *mut u8;
            // SAFETY: `bss_ptr` is within the allocated region.
            unsafe { core::ptr::write_bytes(bss_ptr, 0, bss_sz) };
        }

        let flags = if (ph.p_flags & PF_X) != 0
        {
            SegmentFlags::ReadExecute
        }
        else if (ph.p_flags & PF_W) != 0
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
            virt_addr: ph.p_vaddr,
            size: ph.p_memsz,
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
        entry_point: ehdr.e_entry,
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// Build a minimal valid ELF64 little-endian executable binary in memory.
    ///
    /// The resulting image contains:
    /// - One `Elf64Ehdr` (64 bytes)
    /// - One `Elf64Phdr` (56 bytes) describing a single `PT_LOAD` segment
    /// - One byte of segment file data
    ///
    /// The segment virtual range is `[0x1000, 0x2000)` and the entry point is
    /// `0x1000`, which is exactly at the segment's start. Permissions are
    /// `PF_R | PF_X`.
    fn make_test_elf(machine: u16) -> Vec<u8>
    {
        let ehdr_sz = size_of::<Elf64Ehdr>(); // 64
        let phdr_sz = size_of::<Elf64Phdr>(); // 56
        let total = ehdr_sz + phdr_sz + 1;
        let mut buf = vec![0u8; total];

        // ── e_ident ──
        buf[0] = ELFMAG0;
        buf[1] = ELFMAG1;
        buf[2] = ELFMAG2;
        buf[3] = ELFMAG3;
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;

        // ── Fixed header fields (offsets per the ELF64 spec) ──
        // e_type  @ 16  (u16)
        buf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        // e_machine @ 18 (u16)
        buf[18..20].copy_from_slice(&machine.to_le_bytes());
        // e_version @ 20 (u32)
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry @ 24 (u64) — points into the segment
        buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        // e_phoff @ 32 (u64) — program headers immediately follow the ELF header
        buf[32..40].copy_from_slice(&(ehdr_sz as u64).to_le_bytes());
        // e_ehsize @ 52 (u16)
        buf[52..54].copy_from_slice(&(ehdr_sz as u16).to_le_bytes());
        // e_phentsize @ 54 (u16)
        buf[54..56].copy_from_slice(&(phdr_sz as u16).to_le_bytes());
        // e_phnum @ 56 (u16)
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());

        // ── Program header at offset ehdr_sz ──
        let ph = ehdr_sz;
        // p_type @ ph+0 (u32)
        buf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        // p_flags @ ph+4 (u32) — R+X
        buf[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        // p_offset @ ph+8 (u64) — file data immediately after the program header
        buf[ph + 8..ph + 16].copy_from_slice(&((ehdr_sz + phdr_sz) as u64).to_le_bytes());
        // p_vaddr @ ph+16 (u64)
        buf[ph + 16..ph + 24].copy_from_slice(&0x1000u64.to_le_bytes());
        // p_paddr @ ph+24 (u64)
        buf[ph + 24..ph + 32].copy_from_slice(&0x1000u64.to_le_bytes());
        // p_filesz @ ph+32 (u64)
        buf[ph + 32..ph + 40].copy_from_slice(&1u64.to_le_bytes());
        // p_memsz @ ph+40 (u64) — [0x1000, 0x2000) covers e_entry = 0x1000
        buf[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        // p_align @ ph+48 (u64)
        buf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        buf
    }

    // ── check_wx_segments ─────────────────────────────────────────────────────

    /// Helper: build a minimal `Elf64Phdr` with the given type and flags.
    fn make_phdr(p_type: u32, p_flags: u32) -> Elf64Phdr
    {
        Elf64Phdr {
            p_type,
            p_flags,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        }
    }

    #[test]
    fn wx_load_segment_returns_wx_violation()
    {
        let phdrs = [make_phdr(PT_LOAD, PF_W | PF_X)];
        assert!(matches!(
            check_wx_segments(&phdrs),
            Err(BootError::WxViolation)
        ));
    }

    #[test]
    fn write_only_load_segment_passes()
    {
        let phdrs = [make_phdr(PT_LOAD, PF_W)];
        assert!(check_wx_segments(&phdrs).is_ok());
    }

    #[test]
    fn execute_only_load_segment_passes()
    {
        let phdrs = [make_phdr(PT_LOAD, PF_X)];
        assert!(check_wx_segments(&phdrs).is_ok());
    }

    #[test]
    fn non_load_wx_segment_is_ignored()
    {
        // p_type != PT_LOAD: W^X combination must be ignored.
        let phdrs = [make_phdr(0x6474_E551 /* GNU_STACK */, PF_W | PF_X)];
        assert!(check_wx_segments(&phdrs).is_ok());
    }

    #[test]
    fn empty_phdr_slice_passes()
    {
        assert!(check_wx_segments(&[]).is_ok());
    }

    // ── Success-path tests ────────────────────────────────────────────────────

    #[test]
    fn valid_x86_64_elf_passes_validation()
    {
        let elf = make_test_elf(EM_X86_64);
        assert!(validate_elf_header(&elf, EM_X86_64).is_ok());
    }

    #[test]
    fn valid_riscv_elf_passes_validation()
    {
        let elf = make_test_elf(EM_RISCV);
        assert!(validate_elf_header(&elf, EM_RISCV).is_ok());
    }

    #[test]
    fn validate_returns_correct_entry_field()
    {
        let elf = make_test_elf(EM_X86_64);
        let ehdr = validate_elf_header(&elf, EM_X86_64).unwrap();
        assert_eq!(ehdr.e_entry, 0x1000);
    }

    #[test]
    fn validate_returns_correct_machine_field()
    {
        let elf = make_test_elf(EM_RISCV);
        let ehdr = validate_elf_header(&elf, EM_RISCV).unwrap();
        assert_eq!(ehdr.e_machine, EM_RISCV);
    }

    #[test]
    fn entry_at_last_byte_of_segment_passes()
    {
        // Segment is [0x1000, 0x2000); last valid entry address is 0x1FFF.
        let mut elf = make_test_elf(EM_X86_64);
        elf[24..32].copy_from_slice(&0x1FFFu64.to_le_bytes());
        assert!(validate_elf_header(&elf, EM_X86_64).is_ok());
    }

    // ── Check 1: buffer size ──────────────────────────────────────────────────

    #[test]
    fn empty_buffer_returns_invalid_elf()
    {
        let result = validate_elf_header(&[], EM_X86_64);
        assert!(matches!(result, Err(BootError::InvalidElf(_))));
    }

    #[test]
    fn buffer_shorter_than_header_returns_invalid_elf()
    {
        let short = vec![0u8; 32];
        let result = validate_elf_header(&short, EM_X86_64);
        assert!(matches!(result, Err(BootError::InvalidElf(_))));
    }

    // ── Check 2: ELF magic ────────────────────────────────────────────────────

    #[test]
    fn corrupted_magic_byte_0_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        elf[0] = 0x00;
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    #[test]
    fn corrupted_magic_byte_1_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        elf[1] = b'X';
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 3: ELF class ────────────────────────────────────────────────────

    #[test]
    fn elf_class32_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        elf[EI_CLASS] = 1; // ELFCLASS32
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 4: data encoding ────────────────────────────────────────────────

    #[test]
    fn big_endian_elf_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        elf[EI_DATA] = 2; // ELFDATA2MSB
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 5: ELF version ──────────────────────────────────────────────────

    #[test]
    fn elf_version_zero_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        elf[EI_VERSION] = 0;
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 6: object type ──────────────────────────────────────────────────

    #[test]
    fn et_dyn_elf_type_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        // ET_DYN = 3 at offset 16
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 7: machine type ─────────────────────────────────────────────────

    #[test]
    fn riscv_elf_with_x86_expected_returns_invalid_elf()
    {
        let elf = make_test_elf(EM_RISCV);
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    #[test]
    fn x86_elf_with_riscv_expected_returns_invalid_elf()
    {
        let elf = make_test_elf(EM_X86_64);
        assert!(matches!(
            validate_elf_header(&elf, EM_RISCV),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 8: phentsize ────────────────────────────────────────────────────

    #[test]
    fn wrong_phentsize_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        // e_phentsize @ offset 54
        elf[54..56].copy_from_slice(&32u16.to_le_bytes());
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 9: phnum ────────────────────────────────────────────────────────

    #[test]
    fn zero_phnum_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        // e_phnum @ offset 56
        elf[56..58].copy_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    // ── Check 10: entry point in LOAD segment ─────────────────────────────────

    #[test]
    fn entry_outside_all_segments_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        // Set e_entry to an address outside [0x1000, 0x2000)
        elf[24..32].copy_from_slice(&0xDEAD_0000u64.to_le_bytes());
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }

    #[test]
    fn entry_one_past_segment_end_returns_invalid_elf()
    {
        let mut elf = make_test_elf(EM_X86_64);
        // Segment is [0x1000, 0x2000); 0x2000 is one past the end
        elf[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        assert!(matches!(
            validate_elf_header(&elf, EM_X86_64),
            Err(BootError::InvalidElf(_))
        ));
    }
}
