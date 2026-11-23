// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/elf/src/property.rs

//! The contract of this crate's parsers of an ELF image as one property over
//! any input, [`elf_holds`], which the fuzz target `elf` (`xtask/fuzz/targets`)
//! drives, the replay test of the checked-in inputs under `fuzz/elf/` runs on
//! every `cargo xtask test`, and the proofs of `lib.rs` check on every input up
//! to their bounds (docs/testing.md § Fuzzing, § Bounded verification). The
//! bootloader, init, procmgr and the kernel run these parsers on the bytes of
//! an image a storage writer supplies, and devmgr runs the header check and
//! the streaming note locator on driver files it has not verified.
//!
//! Each check holds a parser to a model that reads the image's fields at
//! their offsets with `from_le_bytes`, apart from the parser's own decoding,
//! and computes every bound in `u128`, where no sum of two 64-bit fields wraps.

use core::ops::Range;

use crate::{
    DT_JMPREL, DT_NULL, DT_PLTRELSZ, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELR, DT_RELRSZ,
    EM_RISCV, EM_X86_64, ET_DYN, ET_EXEC, Elf64Ehdr, ElfError, ElfKind, MAX_STREAMING_STRTAB,
    PT_DYNAMIC, PT_GNU_RELRO, PT_LOAD, PT_TLS, R_RISCV_RELATIVE, R_X86_64_RELATIVE,
    RELA_ENTRY_SIZE, RelaTable, SHT_NOTE, apply_relative_relocs, decode_rela, entry_point,
    find_note, find_note_streaming, load_segments, load_span, parse_stack_note, rela_table,
    relative_relocs, reloc_target_in_span, relro_span, tls_segment, validate, validate_executable,
    validate_relative_relocs,
};

/// Bytes of the ELF header.
const EHDR_BYTES: usize = 64;

/// Bytes of one program header, the only entry size the parsers accept.
const PHDR_BYTES: usize = 56;

/// Bytes of the section header the note locators read.
const SHDR_BYTES: usize = 64;

/// The longest load span [`image_holds`] relocates into through
/// [`apply_holds`]: a longer span is cut to it, so the records that target
/// past it lie outside the span.
const MAX_SPAN: usize = 64;

/// The byte a span holds before it is relocated, so a write is seen.
const UNWRITTEN: u8 = 0xA5;

/// The note-section buffer [`elf_holds`] gives the streaming locator, which
/// refuses a larger section.
pub(crate) const NOTE_BUF: usize = 256;

/// A note the note checks look for: the section that holds it, its owner and
/// its type.
pub(crate) struct Note
{
    pub(crate) section: &'static str,
    pub(crate) owner: &'static [u8],
    pub(crate) ntype: u32,
}

/// The stack note, which [`parse_stack_note`] locates.
pub(crate) const STACK: Note = Note {
    section: process_abi::SERAPH_STACK_NOTE_SECTION,
    owner: process_abi::SERAPH_NOTE_OWNER,
    ntype: process_abi::NT_SERAPH_STACK,
};

/// Check the parsers' contract on `input` read as an ELF image: the header
/// checks for each supported machine and, past an accepted header, every
/// program-header fold, the relocation table and its records, their
/// application, and the stack note, in memory and streamed; and the records
/// of `input` read as a raw relocation table, as the kernel reads the table
/// the bootloader hands it, against a span its first 16 bytes name; and the
/// shared reads, of a program header at the index its first byte names, of
/// `input` as note records, and of the section name at that offset.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn elf_holds(input: &[u8])
{
    for machine in [EM_X86_64, EM_RISCV]
    {
        if let Some(ehdr) = header_holds(input, machine)
        {
            image_holds(&ehdr, input, machine);
        }
    }
    let first = usize::from(input.first().copied().unwrap_or(0));
    phdr_read_holds(input, EHDR_BYTES, first);
    note_walk_holds(input, &STACK);
    section_name_holds(input, first, &STACK);
    let span_min = le_u64(input, 0).unwrap_or(0);
    let span_end = le_u64(input, 8).unwrap_or(u64::MAX);
    let whole = input.as_chunks::<RELA_ENTRY_SIZE>().0.as_flattened();
    for machine in [EM_X86_64, EM_RISCV, 0]
    {
        relocs_holds(input, machine, span_min, span_end);
        relocs_holds(whole, machine, span_min, span_end);
    }
}

/// The checks past a header [`header_holds`] accepted for `machine`: the
/// program-header folds, the relocation table they locate, its records and
/// their application at the header's entry as the bias, and the stack note.
pub(crate) fn image_holds(ehdr: &Elf64Ehdr, data: &[u8], machine: u16)
{
    segments_holds(ehdr, data);
    tls_holds(ehdr, data);
    let span = span_holds(ehdr, data);
    relro_holds(ehdr, data);
    if let Some(table) = dynamic_holds(ehdr, data)
    {
        let bytes = slice(data, table.file_offset, table.size);
        let (span_min, span_end) = span.unwrap_or((0, u64::MAX));
        relocs_holds(bytes, machine, span_min, span_end);
        apply_holds::<MAX_SPAN>(bytes, machine, ehdr.e_entry, span_min, span_end);
    }
    notes_holds(ehdr, data, &STACK);
    stack_note_holds(ehdr, data);
    streaming_holds::<NOTE_BUF, MAX_STREAMING_STRTAB>(ehdr, data, &STACK);
    failed_reads_hold::<NOTE_BUF, MAX_STREAMING_STRTAB>(ehdr, data, &STACK);
}

// ── Model reads ──────────────────────────────────────────────────────────────

/// The `N` bytes of `data` at `at`, or `None` past its end.
fn le<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]>
{
    data.get(at..)?.first_chunk::<N>().copied()
}

fn le_u16(data: &[u8], at: usize) -> Option<u16>
{
    le(data, at).map(u16::from_le_bytes)
}

fn le_u32(data: &[u8], at: usize) -> Option<u32>
{
    le(data, at).map(u32::from_le_bytes)
}

fn le_u64(data: &[u8], at: usize) -> Option<u64>
{
    le(data, at).map(u64::from_le_bytes)
}

/// `a + b`, which cannot wrap in `u128`.
fn sum(a: u64, b: u64) -> u128
{
    u128::from(a).saturating_add(u128::from(b))
}

/// Whether the `size` bytes from `offset` lie inside `len` bytes.
fn inside(offset: u64, size: u64, len: usize) -> bool
{
    sum(offset, size) <= len as u128
}

/// The `size` bytes of `data` from `offset`; empty when they do not lie inside
/// it, which a caller has ruled out.
fn slice(data: &[u8], offset: u64, size: u64) -> &[u8]
{
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
    data.get(start..end).unwrap_or_default()
}

/// A program header as the model reads it.
#[derive(Clone, Copy, Default)]
struct Phdr
{
    ty: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

/// Program header `index` of an accepted header's table, which
/// [`header_holds`] has checked lies inside `data`, so no field falls back to
/// its default.
fn phdr(ehdr: &Elf64Ehdr, data: &[u8], index: usize) -> Phdr
{
    let at = index
        .saturating_mul(PHDR_BYTES)
        .saturating_add(usize::try_from(ehdr.e_phoff).unwrap_or(usize::MAX));
    phdr_at(data, at)
}

/// The program header at byte `at` of `data`, a field past its end read as 0.
fn phdr_at(data: &[u8], at: usize) -> Phdr
{
    let field = |offset: usize| le_u64(data, at.saturating_add(offset)).unwrap_or(0);
    Phdr {
        ty: le_u32(data, at).unwrap_or(0),
        flags: le_u32(data, at.saturating_add(4)).unwrap_or(0),
        offset: field(8),
        vaddr: field(16),
        paddr: field(24),
        filesz: field(32),
        memsz: field(40),
        align: field(48),
    }
}

/// The program headers of an accepted header's table, in order.
fn phdrs<'a>(ehdr: &'a Elf64Ehdr, data: &'a [u8]) -> impl Iterator<Item = Phdr> + 'a
{
    (0..usize::from(ehdr.e_phnum)).map(move |index| phdr(ehdr, data, index))
}

/// [`read_phdr_at`](crate::read_phdr_at), through which every fold reads its
/// headers, decodes the 56 bytes at `base + 56 * index` of `data` when they
/// lie inside it, and refuses with `PhdrTableOverflow` otherwise. A fold
/// reads the table's place only through it, so its proofs fix the table at
/// offset 64 and this check covers every other place.
pub(crate) fn phdr_read_holds(data: &[u8], base: usize, index: usize)
{
    let at = (base as u128).saturating_add((index as u128).saturating_mul(PHDR_BYTES as u128));
    let got = crate::read_phdr_at(data, base, index);
    if at.saturating_add(PHDR_BYTES as u128) > data.len() as u128
    {
        assert!(
            matches!(got, Err(ElfError::PhdrTableOverflow)),
            "a header past the data was read"
        );
        return;
    }
    let p = phdr_at(data, usize::try_from(at).unwrap_or(usize::MAX));
    let same = got.is_ok_and(|h| {
        h.p_type == p.ty
            && h.p_flags == p.flags
            && h.p_offset == p.offset
            && h.p_vaddr == p.vaddr
            && h.p_paddr == p.paddr
            && h.p_filesz == p.filesz
            && h.p_memsz == p.memsz
            && h.p_align == p.align
    });
    assert!(same, "a header inside the data was refused or misread");
}

// ── The header ───────────────────────────────────────────────────────────────

/// The refusal of the first of the header's checks that fails, in the order
/// [`validate`] documents, the types `accepted` taken (`ET_EXEC` for
/// `validate`, `ET_EXEC` and `ET_DYN` for [`validate_executable`]); else the
/// header's type.
fn expected_header(data: &[u8], machine: u16, accepted: &[u16]) -> Result<u16, ElfError>
{
    if data.len() < EHDR_BYTES
    {
        return Err(ElfError::TooSmall);
    }
    let byte = |at: usize| data.get(at).copied().unwrap_or(0);
    if byte(0) != 0x7F || byte(1) != b'E' || byte(2) != b'L' || byte(3) != b'F'
    {
        return Err(ElfError::BadMagic);
    }
    if byte(4) != 2
    {
        return Err(ElfError::Not64Bit);
    }
    if byte(5) != 1
    {
        return Err(ElfError::NotLittleEndian);
    }
    if byte(6) != 1
    {
        return Err(ElfError::BadVersion);
    }
    let half = |at: usize| le_u16(data, at).unwrap_or(0);
    let e_type = half(16);
    if !accepted.contains(&e_type)
    {
        return Err(ElfError::NotExecutable);
    }
    if half(18) != machine
    {
        return Err(ElfError::WrongMachine);
    }
    if usize::from(half(54)) != PHDR_BYTES
    {
        return Err(ElfError::BadPhentsize);
    }
    let phnum = half(56);
    if phnum == 0
    {
        return Err(ElfError::NoSegments);
    }
    let table = u64::from(phnum).saturating_mul(PHDR_BYTES as u64);
    if !inside(le_u64(data, 32).unwrap_or(0), table, data.len())
    {
        return Err(ElfError::PhdrTableOverflow);
    }
    Ok(e_type)
}

/// [`validate`] and [`validate_executable`] of `data` for `machine` refuse with
/// the first failed check in their documented order, and accept a header
/// whose every field is the bytes at its offset, with the kind of its type;
/// [`entry_point`] reads its entry. Returns the header `validate_executable`
/// accepted, whose program-header table the checks put inside `data`.
pub(crate) fn header_holds(data: &[u8], machine: u16) -> Option<Elf64Ehdr>
{
    let exec = validate(data, machine);
    assert_eq!(
        exec.as_ref().map(|_| ()).map_err(|e| *e),
        expected_header(data, machine, &[ET_EXEC]).map(|_| ()),
        "validate judged a header against its checks"
    );
    let expected = expected_header(data, machine, &[ET_EXEC, ET_DYN]);
    let got = validate_executable(data, machine);
    assert_eq!(
        got.as_ref().map(|_| ()).map_err(|e| *e),
        expected.map(|_| ()),
        "validate_executable judged a header against its checks"
    );
    let ((ehdr, kind), Ok(e_type)) = (got.ok()?, expected)
    else
    {
        return None;
    };
    let typed = if e_type == ET_EXEC
    {
        ElfKind::Exec
    }
    else
    {
        ElfKind::Dyn
    };
    assert_eq!(
        kind, typed,
        "a header was given another kind than its type's"
    );
    if let Ok(exec) = exec
    {
        header_fields_hold(&exec, data);
    }
    header_fields_hold(&ehdr, data);
    assert_eq!(entry_point(&ehdr), ehdr.e_entry, "another entry was read");
    Some(ehdr)
}

/// Each field of a decoded header is the bytes at its offset, each compared
/// at its own index.
fn header_fields_hold(ehdr: &Elf64Ehdr, data: &[u8])
{
    for (at, byte) in ehdr.e_ident.iter().enumerate()
    {
        assert_eq!(
            Some(byte),
            data.get(at),
            "an identification byte was misread"
        );
    }
    let same = le_u16(data, 16) == Some(ehdr.e_type)
        && le_u16(data, 18) == Some(ehdr.e_machine)
        && le_u32(data, 20) == Some(ehdr.e_version)
        && le_u64(data, 24) == Some(ehdr.e_entry)
        && le_u64(data, 32) == Some(ehdr.e_phoff)
        && le_u64(data, 40) == Some(ehdr.e_shoff)
        && le_u32(data, 48) == Some(ehdr.e_flags)
        && le_u16(data, 52) == Some(ehdr.e_ehsize)
        && le_u16(data, 54) == Some(ehdr.e_phentsize)
        && le_u16(data, 56) == Some(ehdr.e_phnum)
        && le_u16(data, 58) == Some(ehdr.e_shentsize)
        && le_u16(data, 60) == Some(ehdr.e_shnum)
        && le_u16(data, 62) == Some(ehdr.e_shstrndx);
    assert!(same, "a header field was misread");
}

// ── Program-header folds ─────────────────────────────────────────────────────

/// [`load_segments`] yields, in table order, one item per `PT_LOAD` header and
/// none for another type: `SegmentOverflow` when the header's file bytes pass
/// the image's end, else the header's fields.
pub(crate) fn segments_holds(ehdr: &Elf64Ehdr, data: &[u8])
{
    let mut segments = load_segments(ehdr, data);
    for p in phdrs(ehdr, data).filter(|p| p.ty == PT_LOAD)
    {
        let fits = inside(p.offset, p.filesz, data.len());
        let item = segments.next();
        assert!(item.is_some(), "a PT_LOAD header yielded nothing");
        match item
        {
            Some(Ok(s)) =>
            {
                assert!(fits, "a segment past the image was yielded");
                let same = s.vaddr == p.vaddr
                    && s.paddr == p.paddr
                    && s.offset == p.offset
                    && s.filesz == p.filesz
                    && s.memsz == p.memsz
                    && s.writable == (p.flags & 2 != 0)
                    && s.executable == (p.flags & 1 != 0);
                assert!(
                    same,
                    "a segment was yielded with other fields than its header's"
                );
            }
            Some(Err(e)) =>
            {
                assert!(!fits, "a segment inside the image was refused");
                assert_eq!(
                    e,
                    ElfError::SegmentOverflow,
                    "a segment was refused for another cause"
                );
            }
            None =>
            {}
        }
    }
    assert!(
        segments.next().is_none(),
        "a segment was yielded past the table"
    );
}

/// [`tls_segment`] is the first `PT_TLS` header's template: refused when its
/// file bytes pass the image's end or its file size passes its memory size,
/// else its fields; `None` without one.
pub(crate) fn tls_holds(ehdr: &Elf64Ehdr, data: &[u8])
{
    let got = tls_segment(ehdr, data);
    let Some(p) = phdrs(ehdr, data).find(|p| p.ty == PT_TLS)
    else
    {
        assert!(
            matches!(got, Ok(None)),
            "a template was found without a PT_TLS header"
        );
        return;
    };
    if !inside(p.offset, p.filesz, data.len()) || p.filesz > p.memsz
    {
        assert!(
            matches!(got, Err(ElfError::SegmentOverflow)),
            "a template that does not fit was taken"
        );
        return;
    }
    let same = got.is_ok_and(|t| {
        t.is_some_and(|t| {
            t.vaddr == p.vaddr
                && t.offset == p.offset
                && t.filesz == p.filesz
                && t.memsz == p.memsz
                && t.align == p.align
        })
    });
    assert!(same, "a template that fits was refused or misread");
}

/// [`load_span`] is the least `p_vaddr` and the greatest `p_vaddr + p_memsz`
/// over the `PT_LOAD` headers of nonzero `p_memsz`; `SegmentOverflow` when one
/// of them overflows, `NoSegments` when there are none. Returns the span.
pub(crate) fn span_holds(ehdr: &Elf64Ehdr, data: &[u8]) -> Option<(u64, u64)>
{
    let mut expected = Err(ElfError::NoSegments);
    for p in phdrs(ehdr, data).filter(|p| p.ty == PT_LOAD && p.memsz > 0)
    {
        let Ok(end) = u64::try_from(sum(p.vaddr, p.memsz))
        else
        {
            expected = Err(ElfError::SegmentOverflow);
            break;
        };
        let (min, max) = expected.unwrap_or((u64::MAX, 0));
        expected = Ok((min.min(p.vaddr), max.max(end)));
    }
    let got = load_span(ehdr, data);
    assert_eq!(got, expected, "the span is not its segments' bounds");
    got.ok()
}

/// [`relro_span`] is the first `PT_GNU_RELRO` header of nonzero `p_memsz`.
pub(crate) fn relro_holds(ehdr: &Elf64Ehdr, data: &[u8])
{
    let expected = phdrs(ehdr, data)
        .find(|p| p.ty == PT_GNU_RELRO && p.memsz > 0)
        .map(|p| (p.vaddr, p.memsz));
    assert_eq!(
        relro_span(ehdr, data),
        Ok(expected),
        "another RELRO span was read"
    );
}

// ── The relocation table ─────────────────────────────────────────────────────

/// The tags of a `PT_DYNAMIC` walk, as the model gathers them.
#[derive(Default)]
struct Tags
{
    rela: Option<u64>,
    relasz: Option<u64>,
    relaent: Option<u64>,
    pltrelsz: u64,
    jmprel: bool,
    rel: bool,
    relr: bool,
}

/// The tags of the whole 16-byte entries of `dynamic` before the first
/// `DT_NULL`, a later tag replacing an earlier one.
fn tags(dynamic: &[u8]) -> Tags
{
    let mut tags = Tags::default();
    for entry in dynamic.as_chunks::<16>().0
    {
        let tag = le(entry, 0).map_or(0, i64::from_le_bytes);
        let val = le_u64(entry, 8).unwrap_or(0);
        match tag
        {
            DT_NULL => break,
            DT_RELA => tags.rela = Some(val),
            DT_RELASZ => tags.relasz = Some(val),
            DT_RELAENT => tags.relaent = Some(val),
            DT_PLTRELSZ => tags.pltrelsz = val,
            DT_JMPREL => tags.jmprel = true,
            DT_REL => tags.rel = true,
            DT_RELR | DT_RELRSZ => tags.relr = true,
            _ =>
            {}
        }
    }
    tags
}

/// The table [`rela_table`] documents for an accepted header: `None` without
/// a `PT_DYNAMIC` header or with an empty table; refused for a format the
/// loaders do not apply, a dynamic segment past the image, a missing
/// counterpart tag, an entry size other than a record's, a size not a
/// multiple of it, or a table no `PT_LOAD` header's file bytes back, the first
/// such header in table order resolving it.
fn expected_table(ehdr: &Elf64Ehdr, data: &[u8]) -> Result<Option<RelaTable>, ElfError>
{
    let Some(dynamic) = phdrs(ehdr, data).find(|p| p.ty == PT_DYNAMIC)
    else
    {
        return Ok(None);
    };
    if !inside(dynamic.offset, dynamic.filesz, data.len())
    {
        return Err(ElfError::MalformedDynamic);
    }
    let tags = tags(slice(data, dynamic.offset, dynamic.filesz));
    if tags.rel || tags.relr || (tags.jmprel && tags.pltrelsz != 0)
    {
        return Err(ElfError::UnsupportedRelocation);
    }
    let (vaddr, size) = match (tags.rela, tags.relasz)
    {
        (_, Some(0)) | (None, None) => return Ok(None),
        (Some(vaddr), Some(size)) => (vaddr, size),
        (None, Some(_)) | (Some(_), None) => return Err(ElfError::MalformedDynamic),
    };
    let record = RELA_ENTRY_SIZE as u64;
    if tags.relaent != Some(record) || !size.is_multiple_of(record)
    {
        return Err(ElfError::MalformedDynamic);
    }
    let table_end = sum(vaddr, size);
    if table_end > u128::from(u64::MAX)
    {
        return Err(ElfError::MalformedDynamic);
    }
    for p in phdrs(ehdr, data).filter(|p| p.ty == PT_LOAD)
    {
        let file_end = sum(p.vaddr, p.filesz);
        if file_end > u128::from(u64::MAX)
        {
            return Err(ElfError::MalformedDynamic);
        }
        if vaddr >= p.vaddr && table_end <= file_end
        {
            let file_offset = sum(p.offset, vaddr.saturating_sub(p.vaddr));
            return match u64::try_from(file_offset)
            {
                Ok(file_offset) if inside(file_offset, size, data.len()) => Ok(Some(RelaTable {
                    vaddr,
                    file_offset,
                    size,
                })),
                _ => Err(ElfError::MalformedDynamic),
            };
        }
    }
    Err(ElfError::MalformedDynamic)
}

/// [`rela_table`] locates the table [`expected_table`] describes, which is a
/// nonzero whole number of records inside the image; returns it.
pub(crate) fn dynamic_holds(ehdr: &Elf64Ehdr, data: &[u8]) -> Option<RelaTable>
{
    let got = rela_table(ehdr, data);
    assert_eq!(
        got,
        expected_table(ehdr, data),
        "another relocation table was located"
    );
    let table = got.ok().flatten()?;
    assert!(
        table.size > 0
            && table.size.is_multiple_of(RELA_ENTRY_SIZE as u64)
            && inside(table.file_offset, table.size, data.len()),
        "a located table is not whole records inside the image"
    );
    Some(table)
}

/// A relocation record as the model reads it: `r_offset`, the type and the
/// symbol of `r_info`, and `r_addend`.
fn record(bytes: &[u8; RELA_ENTRY_SIZE]) -> (u64, u32, u32, i64)
{
    (
        le_u64(bytes, 0).unwrap_or(0),
        le_u32(bytes, 8).unwrap_or(0),
        le_u32(bytes, 12).unwrap_or(0),
        le(bytes, 16).map_or(0, i64::from_le_bytes),
    )
}

/// The machine's `RELATIVE` type.
fn relative_type(machine: u16) -> Option<u32>
{
    match machine
    {
        EM_X86_64 => Some(R_X86_64_RELATIVE),
        EM_RISCV => Some(R_RISCV_RELATIVE),
        _ => None,
    }
}

/// [`decode_rela`] reads each field of any record at its offset.
pub(crate) fn decode_holds(bytes: &[u8; RELA_ENTRY_SIZE])
{
    let (offset, rtype, _, addend) = record(bytes);
    let rela = decode_rela(bytes);
    assert!(
        rela.offset == offset && rela.rtype == rtype && rela.addend == addend,
        "a record was decoded with other fields than its bytes'"
    );
}

/// [`relative_relocs`] of `table` refuses a machine with no `RELATIVE` type,
/// then a table not a whole number of records, and otherwise yields each
/// record in order: its decode when it is the machine's `RELATIVE` type with
/// symbol 0, else `UnsupportedRelocation`; [`reloc_target_in_span`] judges
/// whether its 8-byte target lies in `[span_min, span_end)`; and
/// [`validate_relative_relocs`] counts the records when each is `RELATIVE`
/// and in the span, and otherwise refuses with the first record's failure.
pub(crate) fn relocs_holds(table: &[u8], machine: u16, span_min: u64, span_end: u64)
{
    let validated = validate_relative_relocs(table, machine, span_min, span_end);
    let records = relative_relocs(table, machine);
    let Some(expected_type) = relative_type(machine)
    else
    {
        assert!(matches!(records, Err(ElfError::UnsupportedRelocation)));
        assert_eq!(validated, Err(ElfError::UnsupportedRelocation));
        return;
    };
    let (whole, ragged) = table.as_chunks::<RELA_ENTRY_SIZE>();
    let Ok(mut records) = records
    else
    {
        assert!(!ragged.is_empty(), "a whole table was refused");
        assert!(matches!(records, Err(ElfError::MalformedDynamic)));
        assert_eq!(validated, Err(ElfError::MalformedDynamic));
        return;
    };
    assert!(ragged.is_empty(), "a ragged table was taken");
    let mut expected = Ok(0u64);
    for bytes in whole
    {
        decode_holds(bytes);
        let (offset, rtype, sym, addend) = record(bytes);
        let relative = rtype == expected_type && sym == 0;
        let fits = offset >= span_min && sum(offset, 8) <= u128::from(span_end);
        let item = records.next();
        assert!(item.is_some(), "a record was not yielded");
        match item
        {
            Some(Ok(rela)) =>
            {
                assert!(
                    relative,
                    "a record of another type or with a symbol was yielded"
                );
                assert!(rela.offset == offset && rela.rtype == rtype && rela.addend == addend);
                assert_eq!(reloc_target_in_span(&rela, span_min, span_end), fits);
            }
            Some(Err(e)) =>
            {
                assert!(!relative, "a RELATIVE record was refused");
                assert_eq!(e, ElfError::UnsupportedRelocation);
            }
            None =>
            {}
        }
        expected = expected.and_then(|count: u64| {
            if !relative
            {
                Err(ElfError::UnsupportedRelocation)
            }
            else if !fits
            {
                Err(ElfError::RelocOutOfBounds)
            }
            else
            {
                Ok(count.saturating_add(1))
            }
        });
    }
    assert!(
        records.next().is_none(),
        "a record was yielded past the table"
    );
    assert_eq!(
        validated, expected,
        "a table was validated against its records"
    );
}

/// [`apply_relative_relocs`] of `table` at load bias `bias` into the span from
/// link VA `span_vaddr` (at most `SPAN` bytes, a multiple of 8, and none past
/// `span_end`) writes `bias + r_addend`, little-endian, at the target of each
/// `RELATIVE` record whose 8 bytes lie in the span, in table order; skips
/// every other record; writes nothing else; and returns the count written.
pub(crate) fn apply_holds<const SPAN: usize>(
    table: &[u8],
    machine: u16,
    bias: u64,
    span_vaddr: u64,
    span_end: u64,
)
{
    const { assert!(SPAN.is_multiple_of(8), "the span is compared in words") };
    let len = usize::try_from(span_end.saturating_sub(span_vaddr))
        .unwrap_or(SPAN)
        .min(SPAN);
    let mut got = [UNWRITTEN; SPAN];
    let applied = apply_relative_relocs(
        table,
        machine,
        bias,
        span_vaddr,
        got.get_mut(..len).unwrap_or_default(),
    );
    let mut expected = [UNWRITTEN; SPAN];
    let mut count = 0u64;
    let (whole, ragged) = table.as_chunks::<RELA_ENTRY_SIZE>();
    let end = sum(span_vaddr, len as u64);
    if let Some(expected_type) = relative_type(machine)
        && ragged.is_empty()
        && end <= u128::from(u64::MAX)
    {
        for bytes in whole
        {
            let (offset, rtype, sym, addend) = record(bytes);
            if rtype != expected_type || sym != 0 || offset < span_vaddr || sum(offset, 8) > end
            {
                continue;
            }
            let at = usize::try_from(offset.saturating_sub(span_vaddr)).unwrap_or(usize::MAX);
            if let Some(target) = expected
                .get_mut(at..)
                .and_then(<[u8]>::first_chunk_mut::<8>)
            {
                *target = bias.wrapping_add(addend.cast_unsigned()).to_le_bytes();
            }
            count = count.saturating_add(1);
        }
    }
    assert_eq!(applied, count, "another number of relocations was applied");
    // Compared eight bytes at a time, each at its own place, so a proof's walk
    // of the span takes `SPAN / 8` steps.
    for (got, want) in got
        .as_chunks::<8>()
        .0
        .iter()
        .zip(expected.as_chunks::<8>().0)
    {
        assert_eq!(
            u64::from_le_bytes(*got),
            u64::from_le_bytes(*want),
            "a span byte was relocated against its records"
        );
    }
}

// ── Notes ────────────────────────────────────────────────────────────────────

/// A section header as the model reads it: name, type, offset, size.
fn shdr(data: &[u8], at: usize) -> Option<(u32, u32, u64, u64)>
{
    Some((
        le_u32(data, at)?,
        le_u32(data, at.saturating_add(4))?,
        le_u64(data, at.saturating_add(24))?,
        le_u64(data, at.saturating_add(32))?,
    ))
}

/// Where the note locators find `note`, as their documents describe the
/// walk: the first `SHT_NOTE` section named `note.section` in the section
/// header table, and in it the first record of owner `note.owner` and type
/// `note.ntype`. The section's range in `data`, and the descriptor's within the
/// section; `None` when a header, the name table, the section or a record
/// before the note lies outside its container, or no such note exists.
fn expected_note(ehdr: &Elf64Ehdr, data: &[u8], note: &Note)
-> Option<(Range<usize>, Range<usize>)>
{
    let shnum = usize::from(ehdr.e_shnum);
    let shentsize = usize::from(ehdr.e_shentsize);
    if ehdr.e_shoff == 0 || shnum == 0 || shentsize < SHDR_BYTES
    {
        return None;
    }
    let table = u64::from(ehdr.e_shnum).saturating_mul(u64::from(ehdr.e_shentsize));
    if !inside(ehdr.e_shoff, table, data.len()) || usize::from(ehdr.e_shstrndx) >= shnum
    {
        return None;
    }
    let base = usize::try_from(ehdr.e_shoff).ok()?;
    let header = |index: usize| shdr(data, base.saturating_add(index.saturating_mul(shentsize)));
    let (_, _, str_offset, str_size) = header(usize::from(ehdr.e_shstrndx))?;
    if !inside(str_offset, str_size, data.len())
    {
        return None;
    }
    let strtab = slice(data, str_offset, str_size);
    for index in 0..shnum
    {
        let (name, ty, offset, size) = header(index)?;
        if ty != SHT_NOTE || !named(strtab, name as usize, note.section)
        {
            continue;
        }
        if !inside(offset, size, data.len())
        {
            return None;
        }
        let start = usize::try_from(offset).ok()?;
        let section = start..start.saturating_add(usize::try_from(size).ok()?);
        let desc = note_in(slice(data, offset, size), note)?;
        return Some((section, desc));
    }
    None
}

/// Whether the string at `at` in `strtab` is `section` and a NUL, each byte
/// compared at its own index.
fn named(strtab: &[u8], at: usize, section: &str) -> bool
{
    strtab
        .get(at..)
        .is_some_and(|found| spells(found, section.as_bytes()))
}

/// Whether `found` begins with `want` and a NUL, each byte compared at its
/// own index. The index runs to `want`'s length, a constant in every use, so a
/// proof unwinds the walk exactly that often.
fn spells(found: &[u8], want: &[u8]) -> bool
{
    let mut at = 0;
    while at < want.len()
    {
        if found.get(at) != want.get(at)
        {
            return false;
        }
        at += 1;
    }
    found.get(want.len()) == Some(&0)
}

/// The descriptor range of the first record of `note`'s owner and type among
/// the records of `notes` (each a 12-byte header, the name padded to 4 bytes, the
/// descriptor padded to 4 bytes), or `None` when a record runs past them
/// before one is found.
fn note_in(notes: &[u8], note: &Note) -> Option<Range<usize>>
{
    let align = |n: u128| n.saturating_add(3) & !3;
    let len = notes.len() as u128;
    let mut at = 0u128;
    while at.saturating_add(12) <= len
    {
        let header = usize::try_from(at).ok()?;
        let namesz = u128::from(le_u32(notes, header)?);
        let descsz = u128::from(le_u32(notes, header.saturating_add(4))?);
        let ty = le_u32(notes, header.saturating_add(8))?;
        let name_start = at.saturating_add(12);
        let desc_start = name_start.saturating_add(align(namesz));
        let desc_end = desc_start.saturating_add(descsz);
        if desc_end > len
        {
            return None;
        }
        let owned = namesz == note.owner.len() as u128 + 1 && {
            let start = usize::try_from(name_start).ok()?;
            spells(notes.get(start..)?, note.owner)
        };
        if owned && ty == note.ntype
        {
            return Some(usize::try_from(desc_start).ok()?..usize::try_from(desc_end).ok()?);
        }
        at = align(desc_end);
    }
    None
}

/// The note walk [`find_note`] and [`find_note_streaming`] share,
/// [`note_desc`](crate::note_desc), finds in `notes` the descriptor range of
/// `note` that [`note_in`] finds.
pub(crate) fn note_walk_holds(notes: &[u8], note: &Note)
{
    assert_eq!(
        crate::note_desc(notes, note.owner, note.ntype),
        note_in(notes, note),
        "the note walk found another note"
    );
}

/// The section-name compare the note locators share,
/// [`section_name_eq`](crate::section_name_eq), takes the string at `at` in
/// `strtab` as `note`'s section exactly when [`named`] does.
pub(crate) fn section_name_holds(strtab: &[u8], at: usize, note: &Note)
{
    assert_eq!(
        crate::section_name_eq(strtab, at, note.section),
        named(strtab, at, note.section),
        "a section name was compared against its bytes"
    );
}

/// The bytes of `data` at the descriptor of `note` that [`expected_note`]
/// locates.
fn expected_desc<'a>(ehdr: &Elf64Ehdr, data: &'a [u8], note: &Note) -> Option<&'a [u8]>
{
    expected_note(ehdr, data, note).and_then(|(section, desc)| {
        data.get(section.start.saturating_add(desc.start)..section.start.saturating_add(desc.end))
    })
}

/// [`find_note`] returns the descriptor of `note` that [`expected_note`]
/// locates, as the image's own bytes at its place.
pub(crate) fn notes_holds(ehdr: &Elf64Ehdr, data: &[u8], note: &Note)
{
    let place = |bytes: &[u8]| (bytes.as_ptr().addr(), bytes.len());
    assert_eq!(
        find_note(ehdr, data, note.section, note.owner, note.ntype).map(place),
        expected_desc(ehdr, data, note).map(place),
        "a note was located, or missed, against the walk"
    );
}

/// [`parse_stack_note`] returns the first four bytes of the stack note's
/// descriptor when it is eight bytes long, and `None` for any other.
pub(crate) fn stack_note_holds(ehdr: &Elf64Ehdr, data: &[u8])
{
    if let Some(desc) = expected_desc(ehdr, data, &STACK)
    {
        stack_pages_holds(desc);
    }
    let pages = expected_desc(ehdr, data, &STACK)
        .filter(|desc| desc.len() == 8)
        .and_then(|desc| le_u32(desc, 0));
    assert_eq!(
        parse_stack_note(ehdr, data),
        pages,
        "another stack size was read"
    );
}

/// The stack note's descriptor check [`parse_stack_note`] makes of the
/// descriptor [`find_note`] locates,
/// [`stack_pages_of`](crate::stack_pages_of), reads the first four bytes of
/// an eight-byte `desc`, and nothing of any other.
pub(crate) fn stack_pages_holds(desc: &[u8])
{
    let pages = if desc.len() == 8
    {
        le_u32(desc, 0)
    }
    else
    {
        None
    };
    assert_eq!(
        crate::stack_pages_of(desc),
        pages,
        "another stack size was read from a descriptor"
    );
}

/// The reader [`find_note_streaming`] gets in the checks: `data`'s bytes from
/// the offset asked, as many as fit.
fn read_of(data: &[u8]) -> impl Fn(u64, &mut [u8]) -> Option<usize> + '_
{
    |offset: u64, dst: &mut [u8]| {
        let src = data.get(usize::try_from(offset).ok()?..)?;
        let n = dst.len().min(src.len());
        dst.get_mut(..n)?.copy_from_slice(src.get(..n)?);
        Some(n)
    }
}

/// [`find_note_streaming`], with a section-name table buffer of `STRTAB`
/// bytes, looking for `note` and reading the image through a reader of its
/// bytes into a buffer of `BUF` bytes, returns the range within the note
/// section of the descriptor [`expected_note`] locates, the section copied
/// to the buffer's front, when the section name table holds 1 to `STRTAB`
/// bytes and the section 1 to `BUF`, and `None` otherwise.
pub(crate) fn streaming_holds<const BUF: usize, const STRTAB: usize>(
    ehdr: &Elf64Ehdr,
    data: &[u8],
    note: &Note,
)
{
    let size = data.len() as u64;
    let mut buf = [0u8; BUF];
    let got = locate_streaming::<STRTAB>(
        ehdr,
        size,
        note.section,
        note.owner,
        note.ntype,
        &mut buf,
        read_of(data),
    );
    let fits = strtab_size(ehdr, data).is_some_and(|n| n > 0 && n <= STRTAB as u64);
    let expected = expected_note(ehdr, data, note)
        .filter(|(section, _)| fits && !section.is_empty() && section.len() <= BUF);
    assert_eq!(
        got,
        expected.as_ref().map(|(_, desc)| desc.clone()),
        "a note was streamed, or missed, against the walk"
    );
    if let Some((section, _)) = expected
    {
        // Every byte under a test or the fuzzer; under a proof any one, which
        // covers each without a walk of the section's symbolic length.
        #[cfg(not(kani))]
        for at in 0..section.len()
        {
            section_byte_holds(&buf, data, &section, at);
        }
        #[cfg(kani)]
        section_byte_holds(&buf, data, &section, kani::any());
    }
}

/// [`find_note_streaming`], with a section-name table buffer of `STRTAB`
/// bytes and looking for `note` in a buffer of `BUF` bytes,
/// returns `None` through a reader that fails, and through one that comes
/// back a byte short of each read of `data`.
pub(crate) fn failed_reads_hold<const BUF: usize, const STRTAB: usize>(
    ehdr: &Elf64Ehdr,
    data: &[u8],
    note: &Note,
)
{
    let size = data.len() as u64;
    let mut buf = [0u8; BUF];
    let failed = locate_streaming::<STRTAB>(
        ehdr,
        size,
        note.section,
        note.owner,
        note.ntype,
        &mut buf,
        |_, _| None,
    );
    assert!(failed.is_none(), "a note was located through a failed read");
    let read = read_of(data);
    let short = |offset: u64, dst: &mut [u8]| read(offset, dst).map(|n| n.saturating_sub(1));
    let mut buf = [0u8; BUF];
    let shorted = locate_streaming::<STRTAB>(
        ehdr,
        size,
        note.section,
        note.owner,
        note.ntype,
        &mut buf,
        short,
    );
    assert!(shorted.is_none(), "a note was located through a short read");
}

/// Byte `at` of the buffer holds byte `at` of `section` in `data`, when
/// `at` lies within the section.
fn section_byte_holds(buf: &[u8], data: &[u8], section: &Range<usize>, at: usize)
{
    if at < section.len()
    {
        assert_eq!(
            buf.get(at),
            data.get(section.start.saturating_add(at)),
            "the note section was misread"
        );
    }
}

/// The streaming locator with a section-name table buffer of `STRTAB` bytes:
/// [`find_note_streaming`] itself at its own bound, so the replay and the
/// fuzz target check the function callers use.
fn locate_streaming<const STRTAB: usize>(
    ehdr: &Elf64Ehdr,
    file_size: u64,
    section: &str,
    owner: &[u8],
    ntype: u32,
    buf: &mut [u8],
    read_at: impl FnMut(u64, &mut [u8]) -> Option<usize>,
) -> Option<Range<usize>>
{
    if STRTAB == MAX_STREAMING_STRTAB
    {
        find_note_streaming(ehdr, file_size, section, owner, ntype, buf, read_at)
    }
    else
    {
        let mut strtab_buf = [0u8; STRTAB];
        crate::note_streaming(
            ehdr,
            file_size,
            section,
            owner,
            ntype,
            buf,
            &mut strtab_buf,
            read_at,
        )
    }
}

/// The size the section name table's header gives, when the header lies
/// inside the image.
fn strtab_size(ehdr: &Elf64Ehdr, data: &[u8]) -> Option<u64>
{
    let index = usize::from(ehdr.e_shstrndx).saturating_mul(usize::from(ehdr.e_shentsize));
    let at = usize::try_from(ehdr.e_shoff).ok()?.saturating_add(index);
    shdr(data, at).map(|(_, _, _, size)| size)
}
