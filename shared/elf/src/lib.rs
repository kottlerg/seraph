// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/elf/src/lib.rs

//! Shared ELF64 parsing crate for Seraph userspace components.
//!
//! Provides validation, header parsing, `PT_LOAD` segment enumeration, and
//! `.rela.dyn` relocation-table extraction for ELF64 executables — both
//! fixed-address `ET_EXEC` images and position-independent `ET_DYN` images
//! (loaded at a caller-chosen bias with `RELATIVE` relocations applied).
//! Used by init (to load memmgr and procmgr from boot modules), by procmgr
//! (to load all subsequent processes), and by the kernel (Phase 9 relocation
//! of a PIE init via `mm/init_reloc`).
//!
//! This crate is `no_std` and performs no allocation or I/O. All functions
//! operate on a byte slice representing the raw ELF image (or, for the
//! `*_metadata` variants, its header page plus a caller-supplied reader).

#![cfg_attr(not(test), no_std)]
// cast_possible_truncation: this crate targets 64-bit only (x86-64, riscv64);
// ELF64 u64 fields fit in usize on these platforms.
#![allow(clippy::cast_possible_truncation)]

use core::mem::size_of;

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
/// ELF type: shared object / position-independent executable.
const ET_DYN: u16 = 3;

/// Machine type: x86-64.
pub const EM_X86_64: u16 = 0x3E;
/// Machine type: RISC-V.
pub const EM_RISCV: u16 = 0xF3;

// ── Program header constants ─────────────────────────────────────────────────

/// Program header type: loadable segment.
const PT_LOAD: u32 = 1;

/// Program header type: dynamic linking information.
const PT_DYNAMIC: u32 = 2;

/// Program header type: thread-local storage template.
const PT_TLS: u32 = 7;

/// Program header type: read-only-after-relocation region (`PT_GNU_RELRO`).
const PT_GNU_RELRO: u32 = 0x6474_E552;

/// Segment flag: execute permission.
const PF_X: u32 = 1;
/// Segment flag: write permission.
const PF_W: u32 = 2;

// ── Dynamic section constants ────────────────────────────────────────────────

/// Dynamic tag: end of the dynamic array.
const DT_NULL: i64 = 0;
/// Dynamic tag: total byte size of the PLT relocation entries.
const DT_PLTRELSZ: i64 = 2;
/// Dynamic tag: link VA of the `Elf64_Rela` relocation table.
const DT_RELA: i64 = 7;
/// Dynamic tag: total byte size of the `Elf64_Rela` table.
const DT_RELASZ: i64 = 8;
/// Dynamic tag: byte size of one `Elf64_Rela` entry.
const DT_RELAENT: i64 = 9;
/// Dynamic tag: link VA of an `Elf64_Rel` (implicit-addend) table.
const DT_REL: i64 = 17;
/// Dynamic tag: link VA of the PLT relocation entries.
const DT_JMPREL: i64 = 23;
/// Dynamic tag: total byte size of a packed `Relr` table.
const DT_RELRSZ: i64 = 35;
/// Dynamic tag: link VA of a packed `Relr` table.
const DT_RELR: i64 = 36;

/// Relocation type `R_X86_64_RELATIVE`: word64 at `offset` := bias + addend.
pub const R_X86_64_RELATIVE: u32 = 8;
/// Relocation type `R_RISCV_RELATIVE`: word64 at `offset` := bias + addend.
pub const R_RISCV_RELATIVE: u32 = 3;

/// Size in bytes of one `Elf64_Rela` record.
pub const RELA_ENTRY_SIZE: usize = 24;

/// Size in bytes of one `Elf64_Dyn` entry.
const DYN_ENTRY_SIZE: usize = 16;

/// Upper bound on an accepted `.rela.dyn` table (≈175k relocations).
/// Tier-1/2 binaries carry a few thousand; the cap bounds loader work on a
/// malformed or hostile image.
pub const MAX_RELA_TABLE_SIZE: u64 = 4 * 1024 * 1024;

/// Upper bound on the `PT_DYNAMIC` segment size accepted by the streaming
/// parser (256 entries). lld emits well under 32 entries for `-Bsymbolic`
/// PIE with no dynamic linking; the cap keeps the on-stack buffer fixed.
pub const MAX_STREAMING_DYNAMIC: usize = 4096;

// ── e_ident index constants ──────────────────────────────────────────────────

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors returned by ELF validation and parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError
{
    /// Data too small to contain the ELF header.
    TooSmall,
    /// ELF magic bytes do not match.
    BadMagic,
    /// Not a 64-bit ELF (`ELFCLASS64`).
    Not64Bit,
    /// Not little-endian (`ELFDATA2LSB`).
    NotLittleEndian,
    /// ELF version is not `EV_CURRENT`.
    BadVersion,
    /// Not a static executable (`ET_EXEC`).
    NotExecutable,
    /// Machine type does not match the expected architecture.
    WrongMachine,
    /// Program header entry size does not match `Elf64Phdr`.
    BadPhentsize,
    /// No program headers present.
    NoSegments,
    /// Program header table extends beyond the file data.
    PhdrTableOverflow,
    /// A `PT_LOAD` segment references data beyond the file.
    SegmentOverflow,
    /// The `PT_DYNAMIC` segment or the relocation table it describes is
    /// malformed: bad bounds or entry size, size cap exceeded, table not
    /// backed by a `PT_LOAD` segment's file data, or a streaming read of
    /// either failed.
    MalformedDynamic,
    /// The image carries a relocation table format or relocation type other
    /// than the architecture's `RELATIVE` type.
    UnsupportedRelocation,
    /// A relocation target falls outside the loaded image's segments.
    RelocOutOfBounds,
}

// ── Raw ELF types ────────────────────────────────────────────────────────────

/// 64-bit ELF file header (`Elf64_Ehdr`).
#[repr(C)]
// ELF field names follow the ELF spec (e_ident, e_type, …); removing the `e_`
// prefix would diverge from all reference material.
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
    /// File offset of the section header table (unused).
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// Size of this header in bytes.
    pub e_ehsize: u16,
    /// Size of one program header entry in bytes.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Size of one section header entry in bytes (unused).
    pub e_shentsize: u16,
    /// Number of section header entries (unused).
    pub e_shnum: u16,
    /// Index of the section name string table entry (unused).
    pub e_shstrndx: u16,
}

/// 64-bit ELF program header (`Elf64_Phdr`).
#[repr(C)]
// ELF field names follow the ELF spec (p_type, p_flags, …).
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
    /// Physical address of the segment.
    ///
    /// Userspace loaders ignore this field (they place segments at any
    /// available physical address). For the kernel image it defines the
    /// segment's offset within the image; the bootloader places the image at
    /// a dynamically chosen base and preserves those relative offsets.
    pub p_paddr: u64,
    /// Number of bytes in the file image of the segment.
    pub p_filesz: u64,
    /// Number of bytes in the memory image (may exceed `p_filesz` for BSS).
    pub p_memsz: u64,
    /// Required alignment; must be a power of two, or zero.
    pub p_align: u64,
}

// ── Output types ─────────────────────────────────────────────────────────────

/// A `PT_LOAD` segment extracted from an ELF image.
///
/// Describes where to find the segment data in the raw ELF byte slice and
/// where to place it in the target address space.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment
{
    /// Virtual address at which this segment must be mapped.
    pub vaddr: u64,
    /// Physical address declared by the ELF (`p_paddr`).
    ///
    /// Userspace loaders ignore this and pick any available physical
    /// address. For the kernel image it defines each segment's relative
    /// offset; the bootloader places the image at a dynamically chosen base
    /// and preserves those offsets. No consumer requires fixed placement.
    pub paddr: u64,
    /// Byte offset within the ELF file where segment data starts.
    pub offset: u64,
    /// Number of bytes of file data to copy (`p_filesz`).
    pub filesz: u64,
    /// Total size in memory (`p_memsz`). Bytes beyond `filesz` are zero (BSS).
    pub memsz: u64,
    /// Segment is writable.
    pub writable: bool,
    /// Segment is executable.
    pub executable: bool,
}

/// A `PT_TLS` segment extracted from an ELF image.
///
/// Describes the thread-local-storage template: the initialized part
/// (`.tdata`, `filesz` bytes) followed by the zero-initialized part
/// (`.tbss`, `memsz - filesz` bytes). Each thread gets its own copy of
/// this template at runtime; the loader is responsible for allocating
/// per-thread TLS blocks and copying the template into them.
#[derive(Debug, Clone, Copy)]
pub struct TlsSegment
{
    /// Virtual address of the TLS template in the loaded image (the `.tdata`
    /// section, which a `PT_LOAD` segment also maps at the same VA).
    pub vaddr: u64,
    /// Byte offset within the ELF file where the template's `.tdata` starts.
    pub offset: u64,
    /// Number of `.tdata` bytes (initialized portion).
    pub filesz: u64,
    /// Total template size (`.tdata` + `.tbss`).
    pub memsz: u64,
    /// Required alignment of the per-thread TLS block.
    pub align: u64,
}

// ── Validation ───────────────────────────────────────────────────────────────

/// The object-file type of a validated executable image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfKind
{
    /// Fixed-address static executable (`ET_EXEC`): loaded at its link VAs
    /// with bias 0, no relocations.
    Exec,
    /// Position-independent executable (`ET_DYN`): the loader chooses a load
    /// bias and applies the image's `RELATIVE` relocations.
    Dyn,
}

/// Validate an ELF64 header and return a typed reference.
///
/// Checks: minimum size, magic, class (64-bit), data encoding (little-endian),
/// version, type (`ET_EXEC`), machine, program header entry size, and program
/// header count. Kernel-image loading is `ET_EXEC`-only and uses this;
/// userspace loaders use [`validate_executable`], which also accepts
/// `ET_DYN`.
///
/// # Errors
///
/// Returns an [`ElfError`] variant for each failed check.
pub fn validate(data: &[u8], expected_machine: u16) -> Result<&Elf64Ehdr, ElfError>
{
    let ehdr = validate_ident(data)?;
    if ehdr.e_type != ET_EXEC
    {
        return Err(ElfError::NotExecutable);
    }
    validate_tail(ehdr, data, expected_machine)?;
    Ok(ehdr)
}

/// Validate an ELF64 executable header, accepting both `ET_EXEC` and
/// `ET_DYN`, and return a typed reference plus the detected [`ElfKind`].
///
/// Same checks as [`validate`] apart from the type check. Loader callers
/// branch on the kind: `Exec` images load at their link VAs with bias 0;
/// `Dyn` images load at a caller-chosen bias with relocations applied.
///
/// # Errors
///
/// Returns an [`ElfError`] variant for each failed check.
pub fn validate_executable(
    data: &[u8],
    expected_machine: u16,
) -> Result<(&Elf64Ehdr, ElfKind), ElfError>
{
    let ehdr = validate_ident(data)?;
    let kind = match ehdr.e_type
    {
        ET_EXEC => ElfKind::Exec,
        ET_DYN => ElfKind::Dyn,
        _ => return Err(ElfError::NotExecutable),
    };
    validate_tail(ehdr, data, expected_machine)?;
    Ok((ehdr, kind))
}

/// Size, magic, class, data-encoding, and version checks shared by
/// [`validate`] and [`validate_executable`]; the caller checks `e_type`
/// next, then [`validate_tail`].
fn validate_ident(data: &[u8]) -> Result<&Elf64Ehdr, ElfError>
{
    if data.len() < size_of::<Elf64Ehdr>()
    {
        return Err(ElfError::TooSmall);
    }

    // SAFETY: length check above guarantees data is large enough for Elf64Ehdr.
    // cast_ptr_alignment: ELF files from the bootloader are loaded at
    // page-aligned physical addresses; the u8 slice spans that region.
    #[allow(clippy::cast_ptr_alignment)]
    let ehdr = unsafe { &*data.as_ptr().cast::<Elf64Ehdr>() };

    if ehdr.e_ident[0] != ELFMAG0
        || ehdr.e_ident[1] != ELFMAG1
        || ehdr.e_ident[2] != ELFMAG2
        || ehdr.e_ident[3] != ELFMAG3
    {
        return Err(ElfError::BadMagic);
    }
    if ehdr.e_ident[EI_CLASS] != ELFCLASS64
    {
        return Err(ElfError::Not64Bit);
    }
    if ehdr.e_ident[EI_DATA] != ELFDATA2LSB
    {
        return Err(ElfError::NotLittleEndian);
    }
    if ehdr.e_ident[EI_VERSION] != EV_CURRENT
    {
        return Err(ElfError::BadVersion);
    }
    Ok(ehdr)
}

/// Machine, program-header entry size/count, and program-header table
/// bounds checks shared by [`validate`] and [`validate_executable`].
fn validate_tail(ehdr: &Elf64Ehdr, data: &[u8], expected_machine: u16) -> Result<(), ElfError>
{
    if ehdr.e_machine != expected_machine
    {
        return Err(ElfError::WrongMachine);
    }
    if ehdr.e_phentsize as usize != size_of::<Elf64Phdr>()
    {
        return Err(ElfError::BadPhentsize);
    }
    if ehdr.e_phnum == 0
    {
        return Err(ElfError::NoSegments);
    }

    // Verify the program header table fits within the file data.
    let phdr_end = (ehdr.e_phoff as usize)
        .checked_add(ehdr.e_phnum as usize * size_of::<Elf64Phdr>())
        .ok_or(ElfError::PhdrTableOverflow)?;
    if phdr_end > data.len()
    {
        return Err(ElfError::PhdrTableOverflow);
    }

    Ok(())
}

/// Return the entry point virtual address from a validated ELF header.
#[must_use]
pub fn entry_point(ehdr: &Elf64Ehdr) -> u64
{
    ehdr.e_entry
}

// ── Segment iteration ────────────────────────────────────────────────────────

/// Iterator over `PT_LOAD` segments in a validated ELF image.
///
/// Created by [`load_segments`]. Yields [`LoadSegment`] values for each
/// `PT_LOAD` program header, skipping all other segment types.
pub struct LoadSegmentIter<'a>
{
    data: &'a [u8],
    phdr_base: usize,
    phdr_count: usize,
    index: usize,
}

impl Iterator for LoadSegmentIter<'_>
{
    type Item = Result<LoadSegment, ElfError>;

    fn next(&mut self) -> Option<Self::Item>
    {
        while self.index < self.phdr_count
        {
            let offset = self.phdr_base + self.index * size_of::<Elf64Phdr>();
            self.index += 1;

            // SAFETY: validate() confirmed the entire program header table
            // fits within data. Each entry is at a known offset.
            // cast_ptr_alignment: see validate() — ELF data is page-aligned.
            #[allow(clippy::cast_ptr_alignment)]
            let phdr = unsafe { &*self.data.as_ptr().add(offset).cast::<Elf64Phdr>() };

            if phdr.p_type != PT_LOAD
            {
                continue;
            }

            // Validate that the file data for this segment is in bounds.
            let seg_end = (phdr.p_offset as usize).checked_add(phdr.p_filesz as usize);
            match seg_end
            {
                Some(end) if end <= self.data.len() =>
                {}
                _ => return Some(Err(ElfError::SegmentOverflow)),
            }

            return Some(Ok(LoadSegment {
                vaddr: phdr.p_vaddr,
                paddr: phdr.p_paddr,
                offset: phdr.p_offset,
                filesz: phdr.p_filesz,
                memsz: phdr.p_memsz,
                writable: phdr.p_flags & PF_W != 0,
                executable: phdr.p_flags & PF_X != 0,
            }));
        }
        None
    }
}

/// Return an iterator over `PT_LOAD` segments in a validated ELF image.
///
/// `ehdr` must have been returned by a successful [`validate`] call on `data`.
/// The iterator yields one [`LoadSegment`] per `PT_LOAD` program header,
/// skipping all other segment types.
///
/// # Errors
///
/// Individual segments may yield `Err(`[`ElfError::SegmentOverflow`]`)` if
/// their file data extends beyond the ELF image.
#[must_use]
pub fn load_segments<'a>(ehdr: &Elf64Ehdr, data: &'a [u8]) -> LoadSegmentIter<'a>
{
    LoadSegmentIter {
        data,
        phdr_base: ehdr.e_phoff as usize,
        phdr_count: ehdr.e_phnum as usize,
        index: 0,
    }
}

// ── Header-only segment metadata ────────────────────────────────────────────

/// Iterator over `PT_LOAD` segments using only the ELF header page.
///
/// Like [`LoadSegmentIter`], but validates segment file bounds against a
/// declared `file_size` instead of requiring the full file data in memory.
/// This enables streaming ELF loading where only the header page is mapped.
pub struct LoadSegmentMetaIter<'a>
{
    header_data: &'a [u8],
    file_size: u64,
    phdr_base: usize,
    phdr_count: usize,
    index: usize,
}

impl Iterator for LoadSegmentMetaIter<'_>
{
    type Item = Result<LoadSegment, ElfError>;

    fn next(&mut self) -> Option<Self::Item>
    {
        while self.index < self.phdr_count
        {
            let offset = self.phdr_base + self.index * size_of::<Elf64Phdr>();
            self.index += 1;

            // SAFETY: validate() confirmed the entire program header table
            // fits within header_data. Each entry is at a known offset.
            // cast_ptr_alignment: see validate() — ELF data is page-aligned.
            #[allow(clippy::cast_ptr_alignment)]
            let phdr = unsafe { &*self.header_data.as_ptr().add(offset).cast::<Elf64Phdr>() };

            if phdr.p_type != PT_LOAD
            {
                continue;
            }

            // Validate that the file data for this segment is within the file.
            let seg_end = phdr.p_offset.checked_add(phdr.p_filesz);
            match seg_end
            {
                Some(end) if end <= self.file_size =>
                {}
                _ => return Some(Err(ElfError::SegmentOverflow)),
            }

            return Some(Ok(LoadSegment {
                vaddr: phdr.p_vaddr,
                paddr: phdr.p_paddr,
                offset: phdr.p_offset,
                filesz: phdr.p_filesz,
                memsz: phdr.p_memsz,
                writable: phdr.p_flags & PF_W != 0,
                executable: phdr.p_flags & PF_X != 0,
            }));
        }
        None
    }
}

/// Return an iterator over `PT_LOAD` segments from the ELF header page only.
///
/// `ehdr` must have been returned by a successful [`validate`] call on
/// `header_data`. Segment file bounds are checked against `file_size`
/// rather than the buffer length, allowing the caller to hold only the
/// first page of the ELF file.
///
/// # Errors
///
/// Individual segments may yield `Err(`[`ElfError::SegmentOverflow`]`)` if
/// their file data extends beyond `file_size`.
#[must_use]
pub fn load_segments_metadata<'a>(
    ehdr: &Elf64Ehdr,
    header_data: &'a [u8],
    file_size: u64,
) -> LoadSegmentMetaIter<'a>
{
    LoadSegmentMetaIter {
        header_data,
        file_size,
        phdr_base: ehdr.e_phoff as usize,
        phdr_count: ehdr.e_phnum as usize,
        index: 0,
    }
}

// ── PT_TLS lookup ────────────────────────────────────────────────────────────

/// Return the `PT_TLS` segment from a validated ELF image, or `None` if the
/// binary has no thread-local storage template.
///
/// `ehdr` must have been returned by a successful [`validate`] call on `data`.
///
/// The ELF spec guarantees at most one `PT_TLS` program header per object.
/// The returned [`TlsSegment`] describes where the `.tdata` template lives in
/// the file and in the loaded image; the loader is responsible for
/// allocating a per-thread block and copying the template into it.
///
/// # Errors
///
/// Returns [`ElfError::SegmentOverflow`] if the `PT_TLS` segment's file data
/// extends beyond the ELF image.
pub fn tls_segment(ehdr: &Elf64Ehdr, data: &[u8]) -> Result<Option<TlsSegment>, ElfError>
{
    let phdr_base = ehdr.e_phoff as usize;
    let phdr_count = ehdr.e_phnum as usize;

    for i in 0..phdr_count
    {
        let offset = phdr_base + i * size_of::<Elf64Phdr>();
        // SAFETY: validate() confirmed the phdr table fits within data.
        // cast_ptr_alignment: ELF data is page-aligned (see validate()).
        #[allow(clippy::cast_ptr_alignment)]
        let phdr = unsafe { &*data.as_ptr().add(offset).cast::<Elf64Phdr>() };

        if phdr.p_type != PT_TLS
        {
            continue;
        }

        let seg_end = (phdr.p_offset as usize).checked_add(phdr.p_filesz as usize);
        match seg_end
        {
            Some(end) if end <= data.len() =>
            {}
            _ => return Err(ElfError::SegmentOverflow),
        }

        return Ok(Some(TlsSegment {
            vaddr: phdr.p_vaddr,
            offset: phdr.p_offset,
            filesz: phdr.p_filesz,
            memsz: phdr.p_memsz,
            align: phdr.p_align,
        }));
    }

    Ok(None)
}

// ── Seraph stack-size note parser ───────────────────────────────────────────
//
// The on-disk note format and the `stack_pages!` macro live in
// `process-abi` (the binary contract between spawner and child). This
// crate consumes the same constants on the loader side: section header
// walking and note-payload validation.

/// Section type: notes (`SHT_NOTE`).
const SHT_NOTE: u32 = 7;

/// 64-bit ELF section header (`Elf64_Shdr`). Used only when locating the
/// stack-size note; loaders never depend on section headers for segment
/// data (which lives in `PT_LOAD`).
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct Elf64Shdr
{
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// Locate the `.note.seraph.stack` note in a fully-mapped ELF image and
/// return the declared page count.
///
/// Returns `None` when the binary has no note, or when the note is
/// malformed (wrong name, wrong type, wrong descsz). Loaders should
/// treat `None` as "use default."
///
/// `ehdr` must come from a successful [`validate`] on `data`. Walks the
/// section header table; the descriptor is read directly from the byte
/// slice without allocating.
#[must_use]
pub fn parse_stack_note(ehdr: &Elf64Ehdr, data: &[u8]) -> Option<u32>
{
    let shoff = ehdr.e_shoff as usize;
    let shnum = ehdr.e_shnum as usize;
    let shentsize = ehdr.e_shentsize as usize;
    if shoff == 0 || shnum == 0 || shentsize < size_of::<Elf64Shdr>()
    {
        return None;
    }
    let table_end = shoff.checked_add(shnum.checked_mul(shentsize)?)?;
    if table_end > data.len()
    {
        return None;
    }
    let strtab_idx = ehdr.e_shstrndx as usize;
    if strtab_idx >= shnum
    {
        return None;
    }

    let strtab = read_shdr(data, shoff, shentsize, strtab_idx)?;
    let strtab_off = strtab.sh_offset as usize;
    let strtab_size = strtab.sh_size as usize;
    let strtab_end = strtab_off.checked_add(strtab_size)?;
    if strtab_end > data.len()
    {
        return None;
    }
    let strtab_bytes = &data[strtab_off..strtab_end];

    for i in 0..shnum
    {
        let Some(shdr) = read_shdr(data, shoff, shentsize, i)
        else
        {
            continue;
        };
        if shdr.sh_type != SHT_NOTE
        {
            continue;
        }
        if !section_name_eq(
            strtab_bytes,
            shdr.sh_name as usize,
            process_abi::SERAPH_STACK_NOTE_SECTION,
        )
        {
            continue;
        }
        let off = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;
        let end = off.checked_add(size)?;
        if end > data.len()
        {
            return None;
        }
        return parse_note_payload(&data[off..end]);
    }
    None
}

/// Locate `.note.seraph.stack` when only the ELF header page is in
/// memory. `read_at` fetches `dst.len()` bytes from `file_offset` and
/// returns the number of bytes copied (or `None` on I/O error).
///
/// Used by procmgr's VFS-streaming spawn path: the section header table
/// and the matching note section are fetched on demand via the same
/// `vfs_read` primitive that loads `PT_LOAD` pages.
pub fn parse_stack_note_streaming<F>(
    ehdr: &Elf64Ehdr,
    file_size: u64,
    mut read_at: F,
) -> Option<u32>
where
    F: FnMut(u64, &mut [u8]) -> Option<usize>,
{
    let shoff = ehdr.e_shoff;
    let shnum = ehdr.e_shnum as usize;
    let shentsize = ehdr.e_shentsize as usize;
    if shoff == 0 || shnum == 0 || shentsize < size_of::<Elf64Shdr>()
    {
        return None;
    }
    let table_size = (shnum as u64).checked_mul(shentsize as u64)?;
    let table_end = shoff.checked_add(table_size)?;
    if table_end > file_size
    {
        return None;
    }
    let strtab_idx = ehdr.e_shstrndx as usize;
    if strtab_idx >= shnum
    {
        return None;
    }

    let strtab_shdr = read_shdr_streaming(shoff, shentsize, strtab_idx, &mut read_at)?;
    let strtab_off = strtab_shdr.sh_offset;
    let strtab_size = strtab_shdr.sh_size as usize;
    if strtab_size == 0 || strtab_size > MAX_STREAMING_STRTAB
    {
        return None;
    }
    if strtab_off.checked_add(strtab_size as u64)? > file_size
    {
        return None;
    }
    let mut strtab_buf = [0u8; MAX_STREAMING_STRTAB];
    let got = read_at(strtab_off, &mut strtab_buf[..strtab_size])?;
    if got < strtab_size
    {
        return None;
    }
    let strtab_bytes = &strtab_buf[..strtab_size];

    for i in 0..shnum
    {
        let Some(shdr) = read_shdr_streaming(shoff, shentsize, i, &mut read_at)
        else
        {
            continue;
        };
        if shdr.sh_type != SHT_NOTE
        {
            continue;
        }
        if !section_name_eq(
            strtab_bytes,
            shdr.sh_name as usize,
            process_abi::SERAPH_STACK_NOTE_SECTION,
        )
        {
            continue;
        }
        let size = shdr.sh_size as usize;
        if size == 0 || size > MAX_STREAMING_NOTE
        {
            return None;
        }
        if shdr.sh_offset.checked_add(size as u64)? > file_size
        {
            return None;
        }
        let mut buf = [0u8; MAX_STREAMING_NOTE];
        let got = read_at(shdr.sh_offset, &mut buf[..size])?;
        if got < size
        {
            return None;
        }
        return parse_note_payload(&buf[..size]);
    }
    None
}

/// Upper bound on the section name string table size accepted by the
/// streaming parser. Tier-1/2 binaries land well under 4 KiB; the cap
/// keeps the on-stack buffer fixed without heap allocation.
const MAX_STREAMING_STRTAB: usize = 4096;

/// Upper bound on the note section size accepted by the streaming
/// parser. Our note is 28 bytes; 64 leaves headroom for future fields.
const MAX_STREAMING_NOTE: usize = 64;

fn read_shdr(data: &[u8], shoff: usize, shentsize: usize, idx: usize) -> Option<Elf64Shdr>
{
    let offset = shoff.checked_add(idx.checked_mul(shentsize)?)?;
    let end = offset.checked_add(size_of::<Elf64Shdr>())?;
    if end > data.len()
    {
        return None;
    }
    // SAFETY: bounds-checked above. cast_ptr_alignment: we read fields one
    // at a time below to avoid any alignment requirement on `data`.
    let bytes = &data[offset..end];
    Some(decode_shdr(bytes))
}

fn read_shdr_streaming<F>(
    shoff: u64,
    shentsize: usize,
    idx: usize,
    read_at: &mut F,
) -> Option<Elf64Shdr>
where
    F: FnMut(u64, &mut [u8]) -> Option<usize>,
{
    let offset = shoff.checked_add((idx as u64).checked_mul(shentsize as u64)?)?;
    let mut buf = [0u8; size_of::<Elf64Shdr>()];
    let got = read_at(offset, &mut buf)?;
    if got < buf.len()
    {
        return None;
    }
    Some(decode_shdr(&buf))
}

fn decode_shdr(bytes: &[u8]) -> Elf64Shdr
{
    Elf64Shdr {
        sh_name: u32_le(&bytes[0..4]),
        sh_type: u32_le(&bytes[4..8]),
        sh_flags: u64_le(&bytes[8..16]),
        sh_addr: u64_le(&bytes[16..24]),
        sh_offset: u64_le(&bytes[24..32]),
        sh_size: u64_le(&bytes[32..40]),
        sh_link: u32_le(&bytes[40..44]),
        sh_info: u32_le(&bytes[44..48]),
        sh_addralign: u64_le(&bytes[48..56]),
        sh_entsize: u64_le(&bytes[56..64]),
    }
}

fn u32_le(b: &[u8]) -> u32
{
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u64_le(b: &[u8]) -> u64
{
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn section_name_eq(strtab: &[u8], offset: usize, expected: &str) -> bool
{
    if offset >= strtab.len()
    {
        return false;
    }
    let bytes = expected.as_bytes();
    let end = offset.saturating_add(bytes.len());
    if end >= strtab.len() || strtab[offset..end] != *bytes
    {
        return false;
    }
    strtab[end] == 0
}

fn parse_note_payload(bytes: &[u8]) -> Option<u32>
{
    if bytes.len() < 12
    {
        return None;
    }
    let namesz = u32_le(&bytes[0..4]) as usize;
    let descsz = u32_le(&bytes[4..8]) as usize;
    let ntype = u32_le(&bytes[8..12]);
    if ntype != process_abi::NT_SERAPH_STACK || namesz != 7 || descsz != 8
    {
        return None;
    }
    let name_padded = (namesz + 3) & !3;
    let name_end = 12usize.checked_add(name_padded)?;
    let desc_end = name_end.checked_add(descsz)?;
    if desc_end > bytes.len()
    {
        return None;
    }
    if bytes[12..12 + 7] != process_abi::SERAPH_NOTE_NAME[..7]
    {
        return None;
    }
    let pages = u32_le(&bytes[name_end..name_end + 4]);
    Some(pages)
}

/// Locate the `PT_TLS` segment using only the ELF header page, validating
/// `p_filesz` against a declared `file_size` instead of a buffer length.
///
/// Mirror of [`tls_segment`] for the streaming-from-VFS loader path, which
/// holds only the first file page in memory during ELF parsing.
///
/// # Errors
///
/// Returns [`ElfError::SegmentOverflow`] if the `PT_TLS` segment's file data
/// extends beyond `file_size`.
pub fn tls_segment_metadata(
    ehdr: &Elf64Ehdr,
    header_data: &[u8],
    file_size: u64,
) -> Result<Option<TlsSegment>, ElfError>
{
    let phdr_base = ehdr.e_phoff as usize;
    let phdr_count = ehdr.e_phnum as usize;

    for i in 0..phdr_count
    {
        let offset = phdr_base + i * size_of::<Elf64Phdr>();
        // SAFETY: validate() confirmed the phdr table fits within header_data.
        // cast_ptr_alignment: ELF data is page-aligned (see validate()).
        #[allow(clippy::cast_ptr_alignment)]
        let phdr = unsafe { &*header_data.as_ptr().add(offset).cast::<Elf64Phdr>() };

        if phdr.p_type != PT_TLS
        {
            continue;
        }

        let seg_end = phdr.p_offset.checked_add(phdr.p_filesz);
        match seg_end
        {
            Some(end) if end <= file_size =>
            {}
            _ => return Err(ElfError::SegmentOverflow),
        }

        return Ok(Some(TlsSegment {
            vaddr: phdr.p_vaddr,
            offset: phdr.p_offset,
            filesz: phdr.p_filesz,
            memsz: phdr.p_memsz,
            align: phdr.p_align,
        }));
    }

    Ok(None)
}

// ── Load span ────────────────────────────────────────────────────────────────

/// Compute the link-VA span of all `PT_LOAD` segments: the pair
/// `(min_vaddr, max_vaddr_end)` where `max_vaddr_end` is the largest
/// `p_vaddr + p_memsz`.
///
/// Needs only the program header table, which [`validate`] /
/// [`validate_executable`] confirmed lies within `data` — so the ELF header
/// page suffices; full file data is not required. Zero-`memsz` segments are
/// ignored. For `ET_DYN` images the span is bias-relative: callers add the
/// load bias and validate placement (e.g. via
/// `process_layout::validate_image_placement`).
///
/// # Errors
///
/// - [`ElfError::NoSegments`] if the image has no `PT_LOAD` segment.
/// - [`ElfError::SegmentOverflow`] if a segment's `p_vaddr + p_memsz`
///   overflows.
pub fn load_span(ehdr: &Elf64Ehdr, data: &[u8]) -> Result<(u64, u64), ElfError>
{
    let mut min_vaddr = u64::MAX;
    let mut max_end = 0u64;
    let mut found = false;
    for i in 0..ehdr.e_phnum as usize
    {
        let phdr = read_phdr(data, ehdr, i);
        if phdr.p_type != PT_LOAD || phdr.p_memsz == 0
        {
            continue;
        }
        let end = phdr
            .p_vaddr
            .checked_add(phdr.p_memsz)
            .ok_or(ElfError::SegmentOverflow)?;
        min_vaddr = min_vaddr.min(phdr.p_vaddr);
        max_end = max_end.max(end);
        found = true;
    }
    if !found
    {
        return Err(ElfError::NoSegments);
    }
    Ok((min_vaddr, max_end))
}

/// Return the `PT_GNU_RELRO` span `(vaddr, memsz)`, or `None` when the image
/// has no RELRO region.
///
/// The span marks data that must become read-only once relocations are
/// applied (GOT, `.data.rel.ro`, the in-image TLS template). Loaders map the
/// fully-covered pages of a writable segment read-only; link VAs — `ET_DYN`
/// callers add the load bias. Needs only the program header table, so the
/// ELF header page suffices (like [`load_span`]).
#[must_use]
pub fn relro_span(ehdr: &Elf64Ehdr, data: &[u8]) -> Option<(u64, u64)>
{
    for i in 0..ehdr.e_phnum as usize
    {
        let phdr = read_phdr(data, ehdr, i);
        if phdr.p_type == PT_GNU_RELRO && phdr.p_memsz > 0
        {
            return Some((phdr.p_vaddr, phdr.p_memsz));
        }
    }
    None
}

// ── PT_DYNAMIC / RELATIVE relocations ────────────────────────────────────────

/// Location of an image's `.rela.dyn` relocation table.
///
/// Returned by [`rela_table`] / [`rela_table_metadata`]. The caller reads
/// `size` bytes at `file_offset` (whole or in chunks that are multiples of
/// [`RELA_ENTRY_SIZE`]) and feeds them to [`relative_relocs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaTable
{
    /// Link VA of the first `Elf64_Rela` record (`DT_RELA`).
    pub vaddr: u64,
    /// File offset of the table bytes within the ELF image, resolved through
    /// the `PT_LOAD` segment whose file data contains the table.
    pub file_offset: u64,
    /// Table size in bytes (`DT_RELASZ`); a multiple of [`RELA_ENTRY_SIZE`],
    /// at most [`MAX_RELA_TABLE_SIZE`].
    pub size: u64,
}

/// One decoded `Elf64_Rela` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rela
{
    /// Link VA of the 8-byte relocation target (`r_offset`); for `ET_DYN`
    /// images the loader adds the load bias to locate the target.
    pub offset: u64,
    /// Relocation type (low 32 bits of `r_info`).
    pub rtype: u32,
    /// Constant addend (`r_addend`); a `RELATIVE` relocation writes
    /// `bias + addend`.
    pub addend: i64,
}

/// Map an ELF machine to its `RELATIVE` relocation type, or `None` for
/// machines this crate does not support.
#[must_use]
pub const fn relative_reloc_type(machine: u16) -> Option<u32>
{
    match machine
    {
        EM_X86_64 => Some(R_X86_64_RELATIVE),
        EM_RISCV => Some(R_RISCV_RELATIVE),
        _ => None,
    }
}

/// Decode one `Elf64_Rela` record from its 24 raw bytes.
#[must_use]
pub fn decode_rela(bytes: &[u8; RELA_ENTRY_SIZE]) -> Rela
{
    Rela {
        offset: u64_le(&bytes[0..8]),
        rtype: u32_le(&bytes[8..12]),
        addend: i64_le(&bytes[16..24]),
    }
}

/// Tags gathered from one walk of a `PT_DYNAMIC` segment.
#[derive(Default)]
struct DynamicSummary
{
    rela: Option<u64>,
    relasz: Option<u64>,
    relaent: Option<u64>,
    pltrelsz: u64,
    jmprel: bool,
    rel: bool,
    relr: bool,
}

/// Walk `Elf64_Dyn` entries until `DT_NULL` or the end of the segment.
fn parse_dynamic(dyn_bytes: &[u8]) -> DynamicSummary
{
    let mut summary = DynamicSummary::default();
    let mut off = 0;
    while off + DYN_ENTRY_SIZE <= dyn_bytes.len()
    {
        let tag = i64_le(&dyn_bytes[off..off + 8]);
        let val = u64_le(&dyn_bytes[off + 8..off + 16]);
        off += DYN_ENTRY_SIZE;
        match tag
        {
            DT_NULL => break,
            DT_RELA => summary.rela = Some(val),
            DT_RELASZ => summary.relasz = Some(val),
            DT_RELAENT => summary.relaent = Some(val),
            DT_PLTRELSZ => summary.pltrelsz = val,
            DT_JMPREL => summary.jmprel = true,
            DT_REL => summary.rel = true,
            DT_RELR | DT_RELRSZ => summary.relr = true,
            _ =>
            {}
        }
    }
    summary
}

/// Validate the gathered dynamic tags and resolve the table's file offset
/// through the containing `PT_LOAD` segment.
fn resolve_rela_table(
    summary: &DynamicSummary,
    ehdr: &Elf64Ehdr,
    phdr_data: &[u8],
    file_size: u64,
) -> Result<Option<RelaTable>, ElfError>
{
    // A table format the loaders cannot apply must reject the image, not be
    // silently skipped: an unrelocated PIE is corrupt, not degraded.
    if summary.rel || summary.relr || (summary.jmprel && summary.pltrelsz != 0)
    {
        return Err(ElfError::UnsupportedRelocation);
    }
    let (vaddr, size) = match (summary.rela, summary.relasz)
    {
        (None, None | Some(0)) | (Some(_), Some(0)) => return Ok(None),
        (Some(vaddr), Some(size)) => (vaddr, size),
        (None, Some(_)) | (Some(_), None) => return Err(ElfError::MalformedDynamic),
    };
    if summary.relaent != Some(RELA_ENTRY_SIZE as u64)
        || !size.is_multiple_of(RELA_ENTRY_SIZE as u64)
        || size > MAX_RELA_TABLE_SIZE
    {
        return Err(ElfError::MalformedDynamic);
    }
    let table_end = vaddr.checked_add(size).ok_or(ElfError::MalformedDynamic)?;

    for i in 0..ehdr.e_phnum as usize
    {
        let phdr = read_phdr(phdr_data, ehdr, i);
        if phdr.p_type != PT_LOAD
        {
            continue;
        }
        let seg_file_end = phdr
            .p_vaddr
            .checked_add(phdr.p_filesz)
            .ok_or(ElfError::MalformedDynamic)?;
        if vaddr >= phdr.p_vaddr && table_end <= seg_file_end
        {
            let file_offset = phdr.p_offset + (vaddr - phdr.p_vaddr);
            let file_end = file_offset
                .checked_add(size)
                .ok_or(ElfError::MalformedDynamic)?;
            if file_end > file_size
            {
                return Err(ElfError::MalformedDynamic);
            }
            return Ok(Some(RelaTable {
                vaddr,
                file_offset,
                size,
            }));
        }
    }
    Err(ElfError::MalformedDynamic)
}

/// Locate the `PT_DYNAMIC` program header; returns `(p_offset, p_filesz)`.
fn find_dynamic_phdr(ehdr: &Elf64Ehdr, phdr_data: &[u8]) -> Option<(u64, u64)>
{
    for i in 0..ehdr.e_phnum as usize
    {
        let phdr = read_phdr(phdr_data, ehdr, i);
        if phdr.p_type == PT_DYNAMIC
        {
            return Some((phdr.p_offset, phdr.p_filesz));
        }
    }
    None
}

/// Locate the `.rela.dyn` table of a fully-mapped, validated ELF image.
///
/// Walks the `PT_DYNAMIC` segment for `DT_RELA`/`DT_RELASZ`/`DT_RELAENT`
/// and resolves the table's file offset through the `PT_LOAD` segment
/// containing it. Returns `Ok(None)` when the image has no `PT_DYNAMIC`
/// segment or an empty relocation table (an `ET_EXEC` image, or a PIE with
/// no relocations).
///
/// # Errors
///
/// - [`ElfError::UnsupportedRelocation`] if the dynamic section describes
///   `DT_REL`, `DT_RELR`, or active `DT_JMPREL` relocations — formats the
///   loaders do not apply.
/// - [`ElfError::MalformedDynamic`] for structural failures: `PT_DYNAMIC`
///   out of file bounds, a missing counterpart tag, `DT_RELAENT` ≠
///   [`RELA_ENTRY_SIZE`], `DT_RELASZ` not a multiple of it or above
///   [`MAX_RELA_TABLE_SIZE`], or a table not fully backed by one `PT_LOAD`
///   segment's file data.
pub fn rela_table(ehdr: &Elf64Ehdr, data: &[u8]) -> Result<Option<RelaTable>, ElfError>
{
    let Some((offset, filesz)) = find_dynamic_phdr(ehdr, data)
    else
    {
        return Ok(None);
    };
    let end = offset
        .checked_add(filesz)
        .ok_or(ElfError::MalformedDynamic)?;
    if end > data.len() as u64
    {
        return Err(ElfError::MalformedDynamic);
    }
    let summary = parse_dynamic(&data[offset as usize..end as usize]);
    resolve_rela_table(&summary, ehdr, data, data.len() as u64)
}

/// Locate the `.rela.dyn` table when only the ELF header page is in memory.
///
/// Mirror of [`rela_table`] for the streaming-from-VFS loader path.
/// `read_at` fetches `dst.len()` bytes from a file offset and returns the
/// number of bytes copied (or `None` on I/O error). The `PT_DYNAMIC`
/// content is fetched through `read_at` into a fixed on-stack buffer;
/// segments larger than [`MAX_STREAMING_DYNAMIC`] are rejected.
///
/// # Errors
///
/// As [`rela_table`]; a failed or short `read_at`, or an oversized
/// `PT_DYNAMIC` segment, is [`ElfError::MalformedDynamic`].
pub fn rela_table_metadata<F>(
    ehdr: &Elf64Ehdr,
    header_data: &[u8],
    file_size: u64,
    mut read_at: F,
) -> Result<Option<RelaTable>, ElfError>
where
    F: FnMut(u64, &mut [u8]) -> Option<usize>,
{
    let Some((offset, filesz)) = find_dynamic_phdr(ehdr, header_data)
    else
    {
        return Ok(None);
    };
    if filesz > MAX_STREAMING_DYNAMIC as u64
        || offset.checked_add(filesz).is_none_or(|end| end > file_size)
    {
        return Err(ElfError::MalformedDynamic);
    }
    let mut buf = [0u8; MAX_STREAMING_DYNAMIC];
    let want = filesz as usize;
    let got = read_at(offset, &mut buf[..want]).ok_or(ElfError::MalformedDynamic)?;
    if got < want
    {
        return Err(ElfError::MalformedDynamic);
    }
    let summary = parse_dynamic(&buf[..want]);
    resolve_rela_table(&summary, ehdr, header_data, file_size)
}

/// Iterator over the `RELATIVE` relocations of a raw `.rela.dyn` table.
///
/// Created by [`relative_relocs`]. Yields one [`Rela`] per record; a record
/// of any other relocation type (or with a nonzero symbol index) yields
/// `Err(`[`ElfError::UnsupportedRelocation`]`)`.
pub struct RelativeRelocIter<'a>
{
    table: &'a [u8],
    expected_rtype: u32,
    off: usize,
}

impl Iterator for RelativeRelocIter<'_>
{
    type Item = Result<Rela, ElfError>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.off + RELA_ENTRY_SIZE > self.table.len()
        {
            return None;
        }
        let bytes: &[u8; RELA_ENTRY_SIZE] = self.table[self.off..self.off + RELA_ENTRY_SIZE]
            .try_into()
            .ok()?;
        self.off += RELA_ENTRY_SIZE;
        let rela = decode_rela(bytes);
        // r_info's high half is the symbol index; RELATIVE records must not
        // reference a symbol.
        let sym = u32_le(&bytes[12..16]);
        if rela.rtype != self.expected_rtype || sym != 0
        {
            return Some(Err(ElfError::UnsupportedRelocation));
        }
        Some(Ok(rela))
    }
}

/// Iterate the `RELATIVE` relocations in a raw relocation table.
///
/// `table` holds `.rela.dyn` bytes located by [`rela_table`] /
/// [`rela_table_metadata`] — the whole table, or one chunk at a time as
/// long as chunk boundaries are multiples of [`RELA_ENTRY_SIZE`].
///
/// # Errors
///
/// - [`ElfError::UnsupportedRelocation`] if `machine` has no `RELATIVE`
///   mapping ([`relative_reloc_type`]).
/// - [`ElfError::MalformedDynamic`] if `table` is not a whole number of
///   records.
pub fn relative_relocs(table: &[u8], machine: u16) -> Result<RelativeRelocIter<'_>, ElfError>
{
    let expected_rtype = relative_reloc_type(machine).ok_or(ElfError::UnsupportedRelocation)?;
    if !table.len().is_multiple_of(RELA_ENTRY_SIZE)
    {
        return Err(ElfError::MalformedDynamic);
    }
    Ok(RelativeRelocIter {
        table,
        expected_rtype,
        off: 0,
    })
}

/// Whether a relocation's whole 8-byte target lies inside the link-VA span
/// `[span_min, span_end)`.
#[must_use]
pub fn reloc_target_in_span(rela: &Rela, span_min: u64, span_end: u64) -> bool
{
    rela.offset >= span_min
        && rela
            .offset
            .checked_add(8)
            .is_some_and(|end| end <= span_end)
}

/// Validate a whole in-memory `.rela.dyn` table: every record must decode as
/// the machine's `RELATIVE` type and target 8 bytes inside the image's
/// link-VA load span. Returns the record count for the caller's
/// applied-count invariant.
///
/// # Errors
///
/// - [`ElfError::UnsupportedRelocation`] / [`ElfError::MalformedDynamic`]
///   as [`relative_relocs`].
/// - [`ElfError::RelocOutOfBounds`] if a target lies outside
///   `[span_min, span_end)`.
pub fn validate_relative_relocs(
    table: &[u8],
    machine: u16,
    span_min: u64,
    span_end: u64,
) -> Result<u64, ElfError>
{
    let mut count = 0u64;
    for record in relative_relocs(table, machine)?
    {
        let rela = record?;
        if !reloc_target_in_span(&rela, span_min, span_end)
        {
            return Err(ElfError::RelocOutOfBounds);
        }
        count += 1;
    }
    Ok(count)
}

/// Apply one `RELATIVE` relocation to a copied span starting at link VA
/// `span_vaddr`: writes `bias + addend` little-endian at the target if the
/// whole 8-byte target lies inside the span. Returns the number applied
/// (0 or 1) for the caller's applied-count invariant.
pub fn apply_reloc_in_span(rela: &Rela, bias: u64, span_vaddr: u64, span: &mut [u8]) -> u64
{
    let Some(span_end) = span_vaddr.checked_add(span.len() as u64)
    else
    {
        return 0;
    };
    let Some(target_end) = rela.offset.checked_add(8)
    else
    {
        return 0;
    };
    if rela.offset < span_vaddr || target_end > span_end
    {
        return 0;
    }
    let pos = (rela.offset - span_vaddr) as usize;
    let value = bias.wrapping_add(rela.addend.cast_unsigned());
    span[pos..pos + 8].copy_from_slice(&value.to_le_bytes());
    1
}

/// Apply every `RELATIVE` relocation in an in-memory table whose 8-byte
/// target lies within `[span_vaddr, span_vaddr + span.len())`; records
/// outside the span are skipped. Returns the number applied.
///
/// Records should have been pre-validated by [`validate_relative_relocs`];
/// a decode error stops the walk early, and the caller's applied-count
/// check (sum over all spans == validated count) then rejects the image.
pub fn apply_relative_relocs(
    table: &[u8],
    machine: u16,
    bias: u64,
    span_vaddr: u64,
    span: &mut [u8],
) -> u64
{
    let Ok(iter) = relative_relocs(table, machine)
    else
    {
        return 0;
    };
    let mut applied = 0u64;
    for rela in iter.flatten()
    {
        applied += apply_reloc_in_span(&rela, bias, span_vaddr, span);
    }
    applied
}

/// Decode program header `idx` from a validated ELF image or header page.
/// Byte decoding avoids any alignment requirement on `data`; bounds were
/// established by [`validate`] / [`validate_executable`].
fn read_phdr(data: &[u8], ehdr: &Elf64Ehdr, idx: usize) -> Elf64Phdr
{
    let offset = ehdr.e_phoff as usize + idx * size_of::<Elf64Phdr>();
    let b = &data[offset..offset + size_of::<Elf64Phdr>()];
    Elf64Phdr {
        p_type: u32_le(&b[0..4]),
        p_flags: u32_le(&b[4..8]),
        p_offset: u64_le(&b[8..16]),
        p_vaddr: u64_le(&b[16..24]),
        p_paddr: u64_le(&b[24..32]),
        p_filesz: u64_le(&b[32..40]),
        p_memsz: u64_le(&b[40..48]),
        p_align: u64_le(&b[48..56]),
    }
}

fn i64_le(b: &[u8]) -> i64
{
    i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[cfg(test)]
mod tests
{
    use super::*;

    const MACHINE: u16 = EM_X86_64;
    /// Segment flag: read permission (tests only; the parser ignores it).
    const PF_R: u32 = 4;

    // Canonical hand-assembled image (all file offsets equal link VAs):
    //   0x000  ELF header (phoff = 64, phnum = 3)
    //   0x040  program headers (3 × 56 bytes)
    //   0x200  .rela.dyn (2 × 24 bytes)
    //   0x300  PT_DYNAMIC content
    //   0x400  end of file
    // LOAD0 R·X covers [0x000, 0x200); LOAD1 RW covers [0x200, 0x400) in the
    // file and extends to memsz 0x300 (0x100 of BSS).
    const RELA_OFF: u64 = 0x200;
    const DYN_OFF: u64 = 0x300;
    const FILE_SIZE: usize = 0x400;

    fn put(img: &mut [u8], off: usize, bytes: &[u8])
    {
        img[off..off + bytes.len()].copy_from_slice(bytes);
    }

    fn ehdr_bytes(e_type: u16, phnum: u16) -> [u8; 64]
    {
        let mut b = [0u8; 64];
        b[0] = ELFMAG0;
        b[1] = ELFMAG1;
        b[2] = ELFMAG2;
        b[3] = ELFMAG3;
        b[EI_CLASS] = ELFCLASS64;
        b[EI_DATA] = ELFDATA2LSB;
        b[EI_VERSION] = EV_CURRENT;
        put(&mut b, 16, &e_type.to_le_bytes());
        put(&mut b, 18, &MACHINE.to_le_bytes());
        put(&mut b, 20, &1u32.to_le_bytes()); // e_version
        put(&mut b, 24, &0x1000u64.to_le_bytes()); // e_entry
        put(&mut b, 32, &64u64.to_le_bytes()); // e_phoff
        put(&mut b, 52, &64u16.to_le_bytes()); // e_ehsize
        put(&mut b, 54, &56u16.to_le_bytes()); // e_phentsize
        put(&mut b, 56, &phnum.to_le_bytes()); // e_phnum
        b
    }

    fn phdr_bytes(
        p_type: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
    ) -> [u8; 56]
    {
        let mut b = [0u8; 56];
        put(&mut b, 0, &p_type.to_le_bytes());
        put(&mut b, 4, &flags.to_le_bytes());
        put(&mut b, 8, &offset.to_le_bytes());
        put(&mut b, 16, &vaddr.to_le_bytes());
        put(&mut b, 24, &vaddr.to_le_bytes()); // p_paddr mirrors p_vaddr
        put(&mut b, 32, &filesz.to_le_bytes());
        put(&mut b, 40, &memsz.to_le_bytes());
        put(&mut b, 48, &0x1000u64.to_le_bytes()); // p_align
        b
    }

    fn dyn_entry(tag: i64, val: u64) -> [u8; 16]
    {
        let mut b = [0u8; 16];
        put(&mut b, 0, &tag.to_le_bytes());
        put(&mut b, 8, &val.to_le_bytes());
        b
    }

    fn rela_record(offset: u64, rtype: u32, sym: u32, addend: i64) -> [u8; 24]
    {
        let mut b = [0u8; 24];
        put(&mut b, 0, &offset.to_le_bytes());
        put(&mut b, 8, &rtype.to_le_bytes());
        put(&mut b, 12, &sym.to_le_bytes());
        put(&mut b, 16, &addend.to_le_bytes());
        b
    }

    /// Assemble the canonical image with the given type and dynamic entries.
    fn build_image(e_type: u16, dyn_entries: &[[u8; 16]]) -> Vec<u8>
    {
        let mut img = vec![0u8; FILE_SIZE];
        put(&mut img, 0, &ehdr_bytes(e_type, 3));
        put(
            &mut img,
            64,
            &phdr_bytes(PT_LOAD, PF_R | PF_X, 0, 0, 0x200, 0x200),
        );
        put(
            &mut img,
            64 + 56,
            &phdr_bytes(PT_LOAD, PF_R | PF_W, 0x200, 0x200, 0x200, 0x300),
        );
        let dyn_size = (dyn_entries.len() * DYN_ENTRY_SIZE) as u64;
        put(
            &mut img,
            64 + 112,
            &phdr_bytes(
                PT_DYNAMIC,
                PF_R | PF_W,
                DYN_OFF,
                DYN_OFF,
                dyn_size,
                dyn_size,
            ),
        );
        put(
            &mut img,
            RELA_OFF as usize,
            &rela_record(0x250, R_X86_64_RELATIVE, 0, 0x180),
        );
        put(
            &mut img,
            RELA_OFF as usize + RELA_ENTRY_SIZE,
            &rela_record(0x260, R_X86_64_RELATIVE, 0, 0x1000),
        );
        for (i, entry) in dyn_entries.iter().enumerate()
        {
            put(&mut img, DYN_OFF as usize + i * DYN_ENTRY_SIZE, entry);
        }
        img
    }

    fn std_dynamic() -> Vec<[u8; 16]>
    {
        vec![
            dyn_entry(DT_RELA, RELA_OFF),
            dyn_entry(DT_RELASZ, 48),
            dyn_entry(DT_RELAENT, 24),
            dyn_entry(DT_NULL, 0),
        ]
    }

    fn valid_executable(img: &[u8]) -> (&Elf64Ehdr, ElfKind)
    {
        match validate_executable(img, MACHINE)
        {
            Ok(v) => v,
            Err(e) => panic!("validate_executable failed: {e:?}"),
        }
    }

    fn rela_of(img: &[u8]) -> Result<Option<RelaTable>, ElfError>
    {
        let (ehdr, _) = valid_executable(img);
        rela_table(ehdr, img)
    }

    #[test]
    fn detects_exec_kind()
    {
        let img = build_image(ET_EXEC, &std_dynamic());
        let (_, kind) = valid_executable(&img);
        assert_eq!(kind, ElfKind::Exec);
        assert!(
            validate(&img, MACHINE).is_ok(),
            "ET_EXEC must pass validate"
        );
    }

    #[test]
    fn detects_dyn_kind()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        let (_, kind) = valid_executable(&img);
        assert_eq!(kind, ElfKind::Dyn);
        // The kernel-image path stays ET_EXEC-only.
        assert_eq!(
            validate(&img, MACHINE).map(|_| ()),
            Err(ElfError::NotExecutable)
        );
    }

    #[test]
    fn rejects_other_types()
    {
        let img = build_image(1, &std_dynamic()); // ET_REL
        assert_eq!(
            validate_executable(&img, MACHINE).map(|(_, kind)| kind),
            Err(ElfError::NotExecutable)
        );
    }

    #[test]
    fn header_checks_apply()
    {
        let mut img = build_image(ET_DYN, &std_dynamic());
        img[1] = b'X';
        assert_eq!(
            validate_executable(&img, MACHINE).map(|(_, kind)| kind),
            Err(ElfError::BadMagic)
        );
    }

    #[test]
    fn finds_rela_table()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        assert_eq!(
            rela_of(&img),
            Ok(Some(RelaTable {
                vaddr: RELA_OFF,
                file_offset: RELA_OFF,
                size: 48,
            }))
        );
    }

    #[test]
    fn no_dynamic_is_none()
    {
        let mut img = build_image(ET_DYN, &std_dynamic());
        // Truncate the phdr table to the two PT_LOADs.
        put(&mut img, 0, &ehdr_bytes(ET_DYN, 2));
        assert_eq!(rela_of(&img), Ok(None));
    }

    #[test]
    fn dynamic_without_rela_is_none()
    {
        let img = build_image(ET_DYN, &[dyn_entry(DT_NULL, 0)]);
        assert_eq!(rela_of(&img), Ok(None));
    }

    #[test]
    fn zero_relasz_is_none()
    {
        let img = build_image(
            ET_DYN,
            &[
                dyn_entry(DT_RELA, RELA_OFF),
                dyn_entry(DT_RELASZ, 0),
                dyn_entry(DT_NULL, 0),
            ],
        );
        assert_eq!(rela_of(&img), Ok(None));
    }

    #[test]
    fn rejects_bad_relaent()
    {
        let img = build_image(
            ET_DYN,
            &[
                dyn_entry(DT_RELA, RELA_OFF),
                dyn_entry(DT_RELASZ, 48),
                dyn_entry(DT_RELAENT, 16),
                dyn_entry(DT_NULL, 0),
            ],
        );
        assert_eq!(rela_of(&img), Err(ElfError::MalformedDynamic));
    }

    #[test]
    fn rejects_ragged_relasz()
    {
        let img = build_image(
            ET_DYN,
            &[
                dyn_entry(DT_RELA, RELA_OFF),
                dyn_entry(DT_RELASZ, 47),
                dyn_entry(DT_RELAENT, 24),
                dyn_entry(DT_NULL, 0),
            ],
        );
        assert_eq!(rela_of(&img), Err(ElfError::MalformedDynamic));
    }

    #[test]
    fn rejects_oversized_table()
    {
        // A multiple of 24 above the cap, so only the cap check can fire.
        let img = build_image(
            ET_DYN,
            &[
                dyn_entry(DT_RELA, RELA_OFF),
                dyn_entry(DT_RELASZ, 24 * 200_000),
                dyn_entry(DT_RELAENT, 24),
                dyn_entry(DT_NULL, 0),
            ],
        );
        assert_eq!(rela_of(&img), Err(ElfError::MalformedDynamic));
    }

    #[test]
    fn rejects_rela_missing_relasz()
    {
        let img = build_image(
            ET_DYN,
            &[dyn_entry(DT_RELA, RELA_OFF), dyn_entry(DT_NULL, 0)],
        );
        assert_eq!(rela_of(&img), Err(ElfError::MalformedDynamic));
    }

    #[test]
    fn rejects_table_outside_load_file_data()
    {
        // 0x480 lies within LOAD1's memsz (BSS) but beyond its filesz.
        let img = build_image(
            ET_DYN,
            &[
                dyn_entry(DT_RELA, 0x480),
                dyn_entry(DT_RELASZ, 48),
                dyn_entry(DT_RELAENT, 24),
                dyn_entry(DT_NULL, 0),
            ],
        );
        assert_eq!(rela_of(&img), Err(ElfError::MalformedDynamic));
    }

    #[test]
    fn rejects_rel_table()
    {
        let mut entries = std_dynamic();
        entries.insert(0, dyn_entry(DT_REL, RELA_OFF));
        let img = build_image(ET_DYN, &entries);
        assert_eq!(rela_of(&img), Err(ElfError::UnsupportedRelocation));
    }

    #[test]
    fn rejects_relr_table()
    {
        let mut entries = std_dynamic();
        entries.insert(0, dyn_entry(DT_RELR, RELA_OFF));
        let img = build_image(ET_DYN, &entries);
        assert_eq!(rela_of(&img), Err(ElfError::UnsupportedRelocation));
    }

    #[test]
    fn rejects_active_jmprel()
    {
        let mut entries = std_dynamic();
        entries.insert(0, dyn_entry(DT_JMPREL, RELA_OFF));
        entries.insert(1, dyn_entry(DT_PLTRELSZ, 24));
        let img = build_image(ET_DYN, &entries);
        assert_eq!(rela_of(&img), Err(ElfError::UnsupportedRelocation));
    }

    #[test]
    fn accepts_inactive_jmprel()
    {
        let mut entries = std_dynamic();
        entries.insert(0, dyn_entry(DT_JMPREL, RELA_OFF));
        let img = build_image(ET_DYN, &entries);
        assert!(matches!(rela_of(&img), Ok(Some(_))));
    }

    #[test]
    fn decodes_relative_relocs()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        let table = &img[RELA_OFF as usize..RELA_OFF as usize + 48];
        let relocs: Vec<Rela> = match relative_relocs(table, MACHINE)
        {
            Ok(iter) => match iter.collect()
            {
                Ok(v) => v,
                Err(e) => panic!("record decode failed: {e:?}"),
            },
            Err(e) => panic!("relative_relocs failed: {e:?}"),
        };
        assert_eq!(
            relocs,
            vec![
                Rela {
                    offset: 0x250,
                    rtype: R_X86_64_RELATIVE,
                    addend: 0x180,
                },
                Rela {
                    offset: 0x260,
                    rtype: R_X86_64_RELATIVE,
                    addend: 0x1000,
                },
            ]
        );
    }

    #[test]
    fn rejects_foreign_reloc_type()
    {
        // R_X86_64_64 (type 1) is not RELATIVE.
        let record = rela_record(0x250, 1, 0, 0);
        let items: Vec<Result<Rela, ElfError>> = match relative_relocs(&record, MACHINE)
        {
            Ok(iter) => iter.collect(),
            Err(e) => panic!("relative_relocs failed: {e:?}"),
        };
        assert_eq!(items, vec![Err(ElfError::UnsupportedRelocation)]);

        // An x86-64 RELATIVE record read with RISC-V expectations must also
        // reject (the numeric types differ: 8 vs 3).
        let record = rela_record(0x250, R_X86_64_RELATIVE, 0, 0);
        let items: Vec<Result<Rela, ElfError>> = match relative_relocs(&record, EM_RISCV)
        {
            Ok(iter) => iter.collect(),
            Err(e) => panic!("relative_relocs failed: {e:?}"),
        };
        assert_eq!(items, vec![Err(ElfError::UnsupportedRelocation)]);
    }

    #[test]
    fn rejects_nonzero_symbol()
    {
        let record = rela_record(0x250, R_X86_64_RELATIVE, 5, 0);
        let items: Vec<Result<Rela, ElfError>> = match relative_relocs(&record, MACHINE)
        {
            Ok(iter) => iter.collect(),
            Err(e) => panic!("relative_relocs failed: {e:?}"),
        };
        assert_eq!(items, vec![Err(ElfError::UnsupportedRelocation)]);
    }

    #[test]
    fn rejects_ragged_table_slice()
    {
        let record = rela_record(0x250, R_X86_64_RELATIVE, 0, 0);
        assert!(matches!(
            relative_relocs(&record[..20], MACHINE),
            Err(ElfError::MalformedDynamic)
        ));
    }

    #[test]
    fn rejects_unknown_machine()
    {
        let record = rela_record(0x250, R_X86_64_RELATIVE, 0, 0);
        assert!(matches!(
            relative_relocs(&record, 0x1234),
            Err(ElfError::UnsupportedRelocation)
        ));
        assert_eq!(relative_reloc_type(EM_RISCV), Some(R_RISCV_RELATIVE));
        assert_eq!(relative_reloc_type(EM_X86_64), Some(R_X86_64_RELATIVE));
    }

    #[test]
    fn computes_load_span()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        let (ehdr, _) = valid_executable(&img);
        assert_eq!(load_span(ehdr, &img), Ok((0, 0x500)));
    }

    #[test]
    fn finds_relro_span()
    {
        let mut img = build_image(ET_DYN, &std_dynamic());
        let (ehdr, _) = valid_executable(&img);
        assert_eq!(relro_span(ehdr, &img), None);
        // Rewrite the PT_DYNAMIC header as PT_GNU_RELRO covering [0x200, 0x300).
        put(
            &mut img,
            64 + 112,
            &phdr_bytes(PT_GNU_RELRO, PF_R, 0x200, 0x200, 0x100, 0x100),
        );
        let (ehdr, _) = valid_executable(&img);
        assert_eq!(relro_span(ehdr, &img), Some((0x200, 0x100)));
    }

    #[test]
    fn load_span_requires_load_segment()
    {
        let mut img = build_image(ET_DYN, &std_dynamic());
        // Rewrite both PT_LOADs as PT_NULL, keeping PT_DYNAMIC.
        put(&mut img, 64, &phdr_bytes(0, 0, 0, 0, 0, 0));
        put(&mut img, 64 + 56, &phdr_bytes(0, 0, 0, 0, 0, 0));
        let (ehdr, _) = valid_executable(&img);
        assert_eq!(load_span(ehdr, &img), Err(ElfError::NoSegments));
    }

    #[test]
    fn streaming_matches_in_memory()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        let (ehdr, _) = valid_executable(&img);
        let header_page = &img[..0x100];
        let streamed = rela_table_metadata(ehdr, header_page, img.len() as u64, |off, dst| {
            let off = off as usize;
            img.get(off..off + dst.len()).map(|src| {
                dst.copy_from_slice(src);
                dst.len()
            })
        });
        assert_eq!(streamed, rela_table(ehdr, &img));
    }

    #[test]
    fn streaming_rejects_failed_read()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        let (ehdr, _) = valid_executable(&img);
        let failed = rela_table_metadata(ehdr, &img[..0x100], img.len() as u64, |_, _| None);
        assert_eq!(failed, Err(ElfError::MalformedDynamic));
    }

    #[test]
    fn validates_and_applies_relocs()
    {
        let img = build_image(ET_DYN, &std_dynamic());
        let table = &img[RELA_OFF as usize..RELA_OFF as usize + 48];

        // Both records (targets 0x250, 0x260) lie inside the load span.
        assert_eq!(validate_relative_relocs(table, MACHINE, 0, 0x500), Ok(2));
        // A span that excludes the second target rejects the table.
        assert_eq!(
            validate_relative_relocs(table, MACHINE, 0, 0x260),
            Err(ElfError::RelocOutOfBounds)
        );

        // Apply to a span covering [0x200, 0x500) at bias 0x1000_0000.
        let mut span = vec![0u8; 0x300];
        let applied = apply_relative_relocs(table, MACHINE, 0x1000_0000, 0x200, &mut span);
        assert_eq!(applied, 2);
        let word = |off: usize| u64_le(&span[off..off + 8]);
        assert_eq!(word(0x50), 0x1000_0000 + 0x180); // target 0x250, addend 0x180
        assert_eq!(word(0x60), 0x1000_0000 + 0x1000); // target 0x260, addend 0x1000

        // A span not covering the targets applies nothing and stays zero.
        let mut other = vec![0u8; 0x40];
        assert_eq!(
            apply_relative_relocs(table, MACHINE, 0x1000_0000, 0x600, &mut other),
            0
        );
        assert!(other.iter().all(|&b| b == 0));
    }

    #[test]
    fn streaming_rejects_oversized_dynamic()
    {
        let mut img = build_image(ET_DYN, &std_dynamic());
        let oversized = (MAX_STREAMING_DYNAMIC + DYN_ENTRY_SIZE) as u64;
        put(
            &mut img,
            64 + 112,
            &phdr_bytes(
                PT_DYNAMIC,
                PF_R | PF_W,
                DYN_OFF,
                DYN_OFF,
                oversized,
                oversized,
            ),
        );
        let (ehdr, _) = valid_executable(&img);
        let streamed = rela_table_metadata(ehdr, &img[..0x100], 1 << 20, |off, dst| {
            let off = off as usize;
            img.get(off..off + dst.len()).map(|src| {
                dst.copy_from_slice(src);
                dst.len()
            })
        });
        assert_eq!(streamed, Err(ElfError::MalformedDynamic));
    }
}
