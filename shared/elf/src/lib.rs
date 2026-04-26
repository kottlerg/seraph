// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/elf/src/lib.rs

//! Shared ELF64 parsing crate for Seraph userspace components.
//!
//! Provides validation, header parsing, and `PT_LOAD` segment enumeration for
//! ELF64 static executables. Used by init (to load procmgr from a boot module)
//! and by procmgr (to load all subsequent processes).
//!
//! This crate is `no_std` and performs no allocation or I/O. All functions
//! operate on a byte slice representing the raw ELF image.

#![no_std]
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

/// Machine type: x86-64.
pub const EM_X86_64: u16 = 0x3E;
/// Machine type: RISC-V.
pub const EM_RISCV: u16 = 0xF3;

// ── Program header constants ─────────────────────────────────────────────────

/// Program header type: loadable segment.
const PT_LOAD: u32 = 1;

/// Program header type: thread-local storage template.
const PT_TLS: u32 = 7;

/// Segment flag: execute permission.
const PF_X: u32 = 1;
/// Segment flag: write permission.
const PF_W: u32 = 2;

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
    /// available physical address). The bootloader honours it for the
    /// kernel image, where the ELF dictates a fixed physical placement.
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
    /// address. The bootloader honours it for the kernel image, which
    /// requires fixed placement.
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

/// Validate an ELF64 header and return a typed reference.
///
/// Checks: minimum size, magic, class (64-bit), data encoding (little-endian),
/// version, type (`ET_EXEC`), machine, program header entry size, and program
/// header count.
///
/// # Errors
///
/// Returns an [`ElfError`] variant for each failed check.
pub fn validate(data: &[u8], expected_machine: u16) -> Result<&Elf64Ehdr, ElfError>
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
    if ehdr.e_type != ET_EXEC
    {
        return Err(ElfError::NotExecutable);
    }
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

    Ok(ehdr)
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
