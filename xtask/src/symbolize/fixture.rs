// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/symbolize/fixture.rs

//! ELF fixtures with a known symbol table and DWARF, written in-test, for
//! the symbolizer's tests, the crash-log tests and the frame-check tests.
//!
//! The writers emit exactly the fixture's shape: a little-endian ELF64
//! relocatable file with `.text`, a symbol table and named extra sections,
//! and DWARF 4 (32-bit format, 8-byte addresses) for one compile unit with
//! one inlined call, every string inline (`DW_FORM_string`).

/// The fixture's ELF machine.
#[derive(Clone, Copy)]
pub(crate) enum Architecture
{
    X86_64,
    Riscv64,
}

impl Architecture
{
    /// The ELF header's `e_machine`.
    fn e_machine(self) -> u16
    {
        match self
        {
            Architecture::X86_64 => 62,
            Architecture::Riscv64 => 243,
        }
    }
}

/// Link address of the fixture's functions' base for a user PIE.
pub(crate) const USER_BASE: u64 = 0;
/// Link address of the fixture's functions' base for a kernel image.
pub(crate) const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;

// The fixture's layout, as offsets from its base: `outer` at 0x100..0x140,
// with `inner` inlined into it at 0x110..0x120 from a call on line 11;
// `anon` at 0x180..0x1c0, an unnamed DWARF function with no line rows;
// `leaf` at 0x200..0x220 and `tail` at 0x280 with no size, in the symbol
// table only. The compile unit spans 0x100..0x1c0.
pub(crate) const OUTER: u64 = 0x100;
pub(crate) const INNER: u64 = 0x110;
pub(crate) const ANON: u64 = 0x180;
pub(crate) const LEAF: u64 = 0x200;
pub(crate) const TAIL: u64 = 0x280;
pub(crate) const OUTER_MANGLED: &str = "_ZN7fixture5outer17h0123456789abcdefE";
pub(crate) const SYMBOLS: [(&str, u64, u64); 4] = [
    (OUTER_MANGLED, OUTER, 0x40),
    ("_ZN7fixture4anon17h0123456789abcdefE", ANON, 0x40),
    ("_ZN7fixture4leaf17h0123456789abcdefE", LEAF, 0x20),
    ("_ZN7fixture4tail17h0123456789abcdefE", TAIL, 0),
];

/// Size of the fixture's `.text`, zero-filled.
const TEXT_SIZE: u64 = 0x300;

/// Which sections the fixture image carries.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Debug
{
    Dwarf,
    SymbolsOnly,
}

// ELF constants the writer uses.
const ET_REL: u16 = 1;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
/// `STB_GLOBAL << 4 | STT_FUNC`.
const GLOBAL_FUNC: u8 = 0x12;
const EHDR_SIZE: u16 = 64;
const SHDR_SIZE: u16 = 64;
const SYM_SIZE: u64 = 24;

// DWARF constants the writer uses.
const DW_TAG_COMPILE_UNIT: u8 = 0x11;
const DW_TAG_SUBPROGRAM: u8 = 0x2e;
const DW_TAG_INLINED_SUBROUTINE: u8 = 0x1d;
const DW_AT_NAME: u8 = 0x03;
const DW_AT_STMT_LIST: u8 = 0x10;
const DW_AT_LOW_PC: u8 = 0x11;
const DW_AT_HIGH_PC: u8 = 0x12;
const DW_AT_COMP_DIR: u8 = 0x1b;
const DW_AT_INLINE: u8 = 0x20;
const DW_AT_ABSTRACT_ORIGIN: u8 = 0x31;
const DW_AT_CALL_FILE: u8 = 0x58;
const DW_AT_CALL_LINE: u8 = 0x59;
const DW_AT_LINKAGE_NAME: u8 = 0x6e;
const DW_FORM_ADDR: u8 = 0x01;
const DW_FORM_STRING: u8 = 0x08;
const DW_FORM_DATA1: u8 = 0x0b;
const DW_FORM_UDATA: u8 = 0x0f;
const DW_FORM_REF4: u8 = 0x13;
const DW_FORM_SEC_OFFSET: u8 = 0x17;
const DW_INL_INLINED: u8 = 1;
const DW_LNS_COPY: u8 = 0x01;
const DW_LNS_ADVANCE_PC: u8 = 0x02;
const DW_LNS_ADVANCE_LINE: u8 = 0x03;
const DW_LNE_END_SEQUENCE: u8 = 0x01;
const DW_LNE_SET_ADDRESS: u8 = 0x02;

/// Append `value` as ULEB128.
fn uleb(out: &mut Vec<u8>, mut value: u64)
{
    loop
    {
        let byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        if value == 0
        {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Append `value` as SLEB128.
fn sleb(out: &mut Vec<u8>, mut value: i64)
{
    loop
    {
        let byte = u8::try_from(value & 0x7f).unwrap();
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done
        {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Append `text` and its terminating NUL.
fn cstr(out: &mut Vec<u8>, text: &str)
{
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

/// One abbreviation: its code, its tag, whether its entries have children,
/// and its attributes' names and forms.
type Abbrev = (u8, u8, bool, &'static [(u8, u8)]);

/// The fixture's `.debug_abbrev`: codes 1 to 5 are the unit, `inner`'s
/// abstract instance, `outer`, the inlined call, and `anon`.
fn debug_abbrev() -> Vec<u8>
{
    let table: [Abbrev; 5] = [
        (
            1,
            DW_TAG_COMPILE_UNIT,
            true,
            &[
                (DW_AT_NAME, DW_FORM_STRING),
                (DW_AT_COMP_DIR, DW_FORM_STRING),
                (DW_AT_LOW_PC, DW_FORM_ADDR),
                (DW_AT_HIGH_PC, DW_FORM_UDATA),
                (DW_AT_STMT_LIST, DW_FORM_SEC_OFFSET),
            ],
        ),
        // The name comes first, so the byte ahead of it is the entry's
        // abbreviation code (the malformed-entry tests rely on it).
        (
            2,
            DW_TAG_SUBPROGRAM,
            false,
            &[(DW_AT_NAME, DW_FORM_STRING), (DW_AT_INLINE, DW_FORM_DATA1)],
        ),
        (
            3,
            DW_TAG_SUBPROGRAM,
            true,
            &[
                (DW_AT_LOW_PC, DW_FORM_ADDR),
                (DW_AT_HIGH_PC, DW_FORM_UDATA),
                (DW_AT_NAME, DW_FORM_STRING),
                (DW_AT_LINKAGE_NAME, DW_FORM_STRING),
            ],
        ),
        (
            4,
            DW_TAG_INLINED_SUBROUTINE,
            false,
            &[
                (DW_AT_LOW_PC, DW_FORM_ADDR),
                (DW_AT_HIGH_PC, DW_FORM_UDATA),
                (DW_AT_ABSTRACT_ORIGIN, DW_FORM_REF4),
                (DW_AT_CALL_FILE, DW_FORM_UDATA),
                (DW_AT_CALL_LINE, DW_FORM_UDATA),
            ],
        ),
        (
            5,
            DW_TAG_SUBPROGRAM,
            false,
            &[(DW_AT_LOW_PC, DW_FORM_ADDR), (DW_AT_HIGH_PC, DW_FORM_UDATA)],
        ),
    ];
    let mut out = Vec::new();
    for (code, tag, children, attrs) in table
    {
        out.extend_from_slice(&[code, tag, u8::from(children)]);
        for &(name, form) in attrs
        {
            out.extend_from_slice(&[name, form]);
        }
        out.extend_from_slice(&[0, 0]);
    }
    out.push(0);
    out
}

/// The fixture's `.debug_info`: one unit whose entries follow
/// [`debug_abbrev`], its functions at link addresses from `base`.
fn debug_info(base: u64) -> Vec<u8>
{
    // Unit header past `unit_length`: version 4, abbreviation offset 0,
    // 8-byte addresses. Entry offsets (`DW_FORM_ref4`) count from the
    // start of `unit_length`.
    let mut unit = vec![0; 4];
    unit.extend_from_slice(&4u16.to_le_bytes());
    unit.extend_from_slice(&0u32.to_le_bytes());
    unit.push(8);

    unit.push(1);
    cstr(&mut unit, "fixture.rs");
    cstr(&mut unit, "/src");
    unit.extend_from_slice(&(base + OUTER).to_le_bytes());
    uleb(&mut unit, ANON + 0x40 - OUTER);
    unit.extend_from_slice(&0u32.to_le_bytes());

    let inner = u32::try_from(unit.len()).unwrap();
    unit.push(2);
    cstr(&mut unit, "inner");
    unit.push(DW_INL_INLINED);

    unit.push(3);
    unit.extend_from_slice(&(base + OUTER).to_le_bytes());
    uleb(&mut unit, 0x40);
    cstr(&mut unit, "outer");
    cstr(&mut unit, OUTER_MANGLED);

    unit.push(4);
    unit.extend_from_slice(&(base + INNER).to_le_bytes());
    uleb(&mut unit, 0x10);
    unit.extend_from_slice(&inner.to_le_bytes());
    uleb(&mut unit, 1);
    uleb(&mut unit, 11);
    // The end of `outer`'s children.
    unit.push(0);

    unit.push(5);
    unit.extend_from_slice(&(base + ANON).to_le_bytes());
    uleb(&mut unit, 0x40);
    // The end of the unit's children.
    unit.push(0);

    let length = u32::try_from(unit.len() - 4).unwrap();
    unit[..4].copy_from_slice(&length.to_le_bytes());
    unit
}

/// The fixture's `.debug_line`: one sequence over `outer`, in file 1
/// (`fixture.rs` in the unit's directory, `/src`): line 10 from its start,
/// 20 over the inlined call, 12 from offset 0x20.
fn debug_line(base: u64) -> Vec<u8>
{
    let mut header = Vec::new();
    // minimum_instruction_length, maximum_operations_per_instruction,
    // default_is_stmt, line_base, line_range, opcode_base.
    header.extend_from_slice(&[1, 1, 1, (-5i8).to_le_bytes()[0], 14, 13]);
    header.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
    // No include directory beyond the unit's own.
    header.push(0);
    cstr(&mut header, "fixture.rs");
    // Directory 0, no modification time, no length; then the list's end.
    header.extend_from_slice(&[0, 0, 0, 0]);

    let mut program = vec![0, 9, DW_LNE_SET_ADDRESS];
    program.extend_from_slice(&(base + OUTER).to_le_bytes());
    for (advance, line_delta) in [(0, 9), (INNER - OUTER, 10), (0x10, -8)]
    {
        if advance != 0
        {
            program.push(DW_LNS_ADVANCE_PC);
            uleb(&mut program, advance);
        }
        program.push(DW_LNS_ADVANCE_LINE);
        sleb(&mut program, line_delta);
        program.push(DW_LNS_COPY);
    }
    program.push(DW_LNS_ADVANCE_PC);
    uleb(&mut program, 0x20);
    program.extend_from_slice(&[0, 1, DW_LNE_END_SEQUENCE]);

    let mut out = Vec::new();
    // unit_length covers the version, header_length, header and program.
    let length = 2 + 4 + header.len() + program.len();
    out.extend_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&u32::try_from(header.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(&program);
    out
}

/// The fixture's DWARF sections, by name.
pub(crate) fn fixture_dwarf(base: u64) -> Vec<(&'static str, Vec<u8>)>
{
    vec![
        (".debug_abbrev", debug_abbrev()),
        (".debug_info", debug_info(base)),
        (".debug_line", debug_line(base)),
    ]
}

/// One section header's fields, before the file offsets are known.
struct Section
{
    name: u32,
    kind: u32,
    flags: u64,
    data: Vec<u8>,
    align: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

/// Append `name` to the string table `table` and return its offset.
fn add_string(table: &mut Vec<u8>, name: &str) -> u32
{
    let offset = u32::try_from(table.len()).unwrap();
    cstr(table, name);
    offset
}

/// An ELF image of `arch` whose functions sit at link addresses from
/// `base`, with [`SYMBOLS`] in its symbol table and `debug` as its further
/// sections: name, contents, and ELF section flags.
pub(crate) fn elf(arch: Architecture, base: u64, debug: Vec<(&str, Vec<u8>, u64)>) -> Vec<u8>
{
    let mut shstrtab = vec![0];
    let mut sections = vec![Section {
        name: add_string(&mut shstrtab, ".text"),
        kind: SHT_PROGBITS,
        flags: SHF_ALLOC | SHF_EXECINSTR,
        data: vec![0; usize::try_from(TEXT_SIZE).unwrap()],
        align: 16,
        link: 0,
        info: 0,
        entsize: 0,
    }];
    for (name, data, flags) in debug
    {
        sections.push(Section {
            name: add_string(&mut shstrtab, name),
            kind: SHT_PROGBITS,
            flags,
            data,
            align: 1,
            link: 0,
            info: 0,
            entsize: 0,
        });
    }

    // Section indices count the null section at 0.
    let text_index = 1u16;
    let symtab_index = u32::try_from(sections.len()).unwrap() + 1;
    let mut strtab = vec![0];
    let mut symtab = vec![0; usize::try_from(SYM_SIZE).unwrap()];
    for (name, offset, size) in SYMBOLS
    {
        symtab.extend_from_slice(&add_string(&mut strtab, name).to_le_bytes());
        symtab.extend_from_slice(&[GLOBAL_FUNC, 0]);
        symtab.extend_from_slice(&text_index.to_le_bytes());
        symtab.extend_from_slice(&(base + offset).to_le_bytes());
        symtab.extend_from_slice(&size.to_le_bytes());
    }
    sections.push(Section {
        name: add_string(&mut shstrtab, ".symtab"),
        kind: SHT_SYMTAB,
        flags: 0,
        data: symtab,
        align: 8,
        link: symtab_index + 1,
        // The index of the first global symbol: every symbol past the null
        // one is global.
        info: 1,
        entsize: SYM_SIZE,
    });
    sections.push(Section {
        name: add_string(&mut shstrtab, ".strtab"),
        kind: SHT_STRTAB,
        flags: 0,
        data: strtab,
        align: 1,
        link: 0,
        info: 0,
        entsize: 0,
    });
    let shstrtab_name = add_string(&mut shstrtab, ".shstrtab");
    sections.push(Section {
        name: shstrtab_name,
        kind: SHT_STRTAB,
        flags: 0,
        data: shstrtab,
        align: 1,
        link: 0,
        info: 0,
        entsize: 0,
    });
    write_file(arch, &sections)
}

/// The length of `out` as a file offset.
fn offset(out: &[u8]) -> u64
{
    u64::try_from(out.len()).unwrap()
}

/// The ELF file of `arch` holding `sections` after the null section, the
/// last of them the section-name string table.
fn write_file(arch: Architecture, sections: &[Section]) -> Vec<u8>
{
    let mut out = vec![0; usize::from(EHDR_SIZE)];
    let mut offsets = Vec::with_capacity(sections.len());
    for section in sections
    {
        while !offset(&out).is_multiple_of(section.align)
        {
            out.push(0);
        }
        offsets.push(offset(&out));
        out.extend_from_slice(&section.data);
    }
    while !out.len().is_multiple_of(8)
    {
        out.push(0);
    }
    let shoff = offset(&out);
    out.resize(out.len() + usize::from(SHDR_SIZE), 0);
    for (section, offset) in sections.iter().zip(offsets)
    {
        out.extend_from_slice(&section.name.to_le_bytes());
        out.extend_from_slice(&section.kind.to_le_bytes());
        out.extend_from_slice(&section.flags.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&u64::try_from(section.data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&section.link.to_le_bytes());
        out.extend_from_slice(&section.info.to_le_bytes());
        out.extend_from_slice(&section.align.to_le_bytes());
        out.extend_from_slice(&section.entsize.to_le_bytes());
    }

    let shnum = u16::try_from(sections.len() + 1).unwrap();
    let mut header = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    header.extend_from_slice(&[0; 8]);
    header.extend_from_slice(&ET_REL.to_le_bytes());
    header.extend_from_slice(&arch.e_machine().to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes()); // e_version
    header.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    header.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
    header.extend_from_slice(&shoff.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    header.extend_from_slice(&EHDR_SIZE.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
    header.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
    header.extend_from_slice(&SHDR_SIZE.to_le_bytes());
    header.extend_from_slice(&shnum.to_le_bytes());
    header.extend_from_slice(&(shnum - 1).to_le_bytes()); // e_shstrndx
    out[..header.len()].copy_from_slice(&header);
    out
}

/// The fixture image: [`elf`] with the DWARF of [`fixture_dwarf`] for
/// `Debug::Dwarf`, with no debug sections for `Debug::SymbolsOnly`.
pub(crate) fn fixture(arch: Architecture, base: u64, debug: Debug) -> Vec<u8>
{
    let sections = match debug
    {
        Debug::Dwarf => fixture_dwarf(base)
            .into_iter()
            .map(|(name, data)| (name, data, 0))
            .collect(),
        Debug::SymbolsOnly => Vec::new(),
    };
    elf(arch, base, sections)
}

/// The fixture's DWARF with section `name`'s contents passed through
/// `edit` and its flags set to `sh_flags`.
pub(crate) fn fixture_with_section(
    name: &str,
    sh_flags: u64,
    edit: impl Fn(Vec<u8>) -> Vec<u8>,
) -> Vec<u8>
{
    let sections = fixture_dwarf(USER_BASE)
        .into_iter()
        .map(|(id, data)| {
            if id == name
            {
                (id, edit(data), sh_flags)
            }
            else
            {
                (id, data, 0)
            }
        })
        .collect();
    elf(Architecture::X86_64, USER_BASE, sections)
}
