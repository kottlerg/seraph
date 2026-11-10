// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/symbolize.rs

//! ELF address symbolization: an address in a loaded image, less the image's
//! load bias, resolved to function, file, and line from the image's DWARF, or
//! to the nearest function symbol from its symbol table when no DWARF covers
//! the address.
//!
//! The DWARF reader is the `addr2line` crate over sections the `object` crate
//! parses, so no host tool is involved. A compressed debug section is refused,
//! since the reader is built without decompression; rustc writes its DWARF
//! uncompressed unless asked otherwise.

use std::borrow::Cow;

use addr2line::gimli::{self, EndianSlice, RunTimeEndian};
use anyhow::{Context as _, Result, bail};
use object::{
    CompressionFormat, Object as _, ObjectSection as _, ObjectSegment as _, ObjectSymbol as _,
    SegmentFlags, SymbolKind,
};

/// The DWARF context type the symbolizer reads through.
type DwarfContext<'data> = addr2line::Context<EndianSlice<'data, RunTimeEndian>>;

/// A function symbol from the image's symbol table, its name demangled.
struct FunctionSymbol
{
    address: u64,
    /// The symbol's `st_size`; `0` when the symbol table gives none.
    size: u64,
    name: String,
}

/// One frame of a DWARF resolution: the function and the source position.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame
{
    /// Demangled function name, `None` when the DWARF names none.
    pub function: Option<String>,
    /// Source file path as the DWARF records it, `None` when it gives none.
    pub file: Option<String>,
    /// Source line, `None` when the DWARF gives none.
    pub line: Option<u32>,
    /// `None` when the DWARF gives no column.
    pub column: Option<u32>,
}

/// What an image-relative address resolved to, and from which source.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolution
{
    /// From DWARF: the innermost (possibly inlined) frame first, then each
    /// caller it is inlined into, each with the position of its call.
    DebugInfo(Vec<Frame>),
    /// From the symbol table: the nearest function symbol at or below the
    /// address, and the address's offset into it.
    SymbolTable
    {
        name: String, offset: u64
    },
    /// Neither source covers the address.
    Unresolved,
}

/// Symbolizer over one ELF image held in memory.
pub struct Symbolizer<'data>
{
    /// `None` when the image carries no `.debug_info`.
    dwarf: Option<DwarfContext<'data>>,
    /// Function symbols sorted by address.
    symbols: Vec<FunctionSymbol>,
}

impl<'data> Symbolizer<'data>
{
    /// Parse `data` as an ELF image and prepare its DWARF and symbol table.
    ///
    /// # Errors
    ///
    /// Fails when `data` is not an ELF image, when a debug section is
    /// compressed or malformed, or when the DWARF cannot be parsed.
    pub fn new(data: &'data [u8]) -> Result<Self>
    {
        let file = object::File::parse(data).context("not an ELF image")?;
        let dwarf = if file.section_by_name(".debug_info").is_some()
        {
            Some(load_dwarf(&file)?)
        }
        else
        {
            None
        };
        Ok(Symbolizer {
            dwarf,
            symbols: function_symbols(&file),
        })
    }

    /// Whether the image carries DWARF at all.
    pub fn has_debug_info(&self) -> bool
    {
        self.dwarf.is_some()
    }

    /// Resolve `vaddr`, an address in the image's own (link-time) address
    /// space: DWARF first, the symbol table when no DWARF covers it.
    ///
    /// # Errors
    ///
    /// Fails when the DWARF covering `vaddr` is malformed.
    pub fn resolve(&self, vaddr: u64) -> Result<Resolution>
    {
        if let Some(dwarf) = &self.dwarf
        {
            let frames = dwarf_frames(dwarf, vaddr)?;
            if !frames.is_empty()
            {
                return Ok(Resolution::DebugInfo(frames));
            }
        }
        Ok(self.resolve_symbol(vaddr))
    }

    /// The symbol-table resolution of `vaddr`.
    fn resolve_symbol(&self, vaddr: u64) -> Resolution
    {
        let after = self.symbols.partition_point(|sym| sym.address <= vaddr);
        let Some(sym) = after.checked_sub(1).map(|idx| &self.symbols[idx])
        else
        {
            return Resolution::Unresolved;
        };
        let offset = vaddr - sym.address;
        if sym.size != 0 && offset >= sym.size
        {
            return Resolution::Unresolved;
        }
        Resolution::SymbolTable {
            name: sym.name.clone(),
            offset,
        }
    }
}

/// Load every DWARF section of `file` and build the lookup context.
fn load_dwarf<'data>(file: &object::File<'data>) -> Result<DwarfContext<'data>>
{
    let endian = if file.is_little_endian()
    {
        RunTimeEndian::Little
    }
    else
    {
        RunTimeEndian::Big
    };
    let dwarf = gimli::Dwarf::load(|id| -> Result<EndianSlice<'data, RunTimeEndian>> {
        let data = match file.section_by_name(id.name())
        {
            Some(section) =>
            {
                if section.compressed_file_range()?.format != CompressionFormat::None
                {
                    bail!("compressed debug section {} is not supported", id.name());
                }
                section.data()?
            }
            None => &[],
        };
        Ok(EndianSlice::new(data, endian))
    })?;
    addr2line::Context::from_dwarf(dwarf).context("cannot parse the image's DWARF")
}

/// The function symbols of `file`, demangled and sorted by address.
fn function_symbols(file: &object::File<'_>) -> Vec<FunctionSymbol>
{
    let mut symbols: Vec<FunctionSymbol> = file
        .symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text && sym.is_definition())
        .filter_map(|sym| {
            let name = sym.name().ok()?;
            Some(FunctionSymbol {
                address: sym.address(),
                size: sym.size(),
                name: addr2line::demangle_auto(Cow::Borrowed(name), None).into_owned(),
            })
        })
        .collect();
    symbols.sort_by_key(|sym| sym.address);
    symbols
}

/// The DWARF frames covering `vaddr`, innermost first; empty when no unit
/// covers it.
fn dwarf_frames(dwarf: &DwarfContext<'_>, vaddr: u64) -> Result<Vec<Frame>>
{
    let mut iter = dwarf.find_frames(vaddr).skip_all_loads()?;
    let mut frames = Vec::new();
    while let Some(frame) = iter.next()?
    {
        let function = match &frame.function
        {
            Some(name) => Some(name.demangle()?.into_owned()),
            None => None,
        };
        let (file, line, column) = match &frame.location
        {
            // Column 0 is DWARF's "no column".
            Some(loc) => (
                loc.file.map(str::to_owned),
                loc.line,
                loc.column.filter(|&column| column != 0),
            ),
            None => (None, None, None),
        };
        if function.is_none() && file.is_none()
        {
            continue;
        }
        frames.push(Frame {
            function,
            file,
            line,
            column,
        });
    }
    Ok(frames)
}

/// The unbiased bounds of `data`'s executable loadable segments: the lowest
/// segment address to one past the highest segment end (address plus memory
/// size), the span procmgr biases into a crash report's `text`. `None` for
/// data that is not an ELF image or an image without an executable segment.
pub fn text_span(data: &[u8]) -> Option<(u64, u64)>
{
    let file = object::File::parse(data).ok()?;
    file.segments()
        .filter(|segment| match segment.flags()
        {
            SegmentFlags::Elf { p_flags, .. } => p_flags.contains(object::elf::PF_X),
            _ => false,
        })
        .map(|segment| (segment.address(), segment.address() + segment.size()))
        .filter(|(start, end)| start < end)
        .reduce(|(lo, hi), (start, end)| (lo.min(start), hi.max(end)))
}

/// The image address of runtime address `addr` in an image loaded at
/// `bias` past its link addresses.
///
/// # Errors
///
/// Fails when `addr` lies below `bias`, so no image address maps to it.
pub fn image_address(addr: u64, bias: u64) -> Result<u64>
{
    match addr.checked_sub(bias)
    {
        Some(vaddr) => Ok(vaddr),
        None => bail!("address {addr:#x} lies below the load bias {bias:#x}"),
    }
}

/// Render one resolved address as report lines: the first names the address
/// and the source used; each further line is a caller an inlined frame sits
/// in.
///
/// `addr` is the runtime address and `vaddr` its image address (`addr` less
/// the bias), shown beside it when the two differ; `resolution` is what
/// [`Symbolizer::resolve`] returned for `vaddr`.
pub fn format_resolution(addr: u64, vaddr: u64, resolution: &Resolution) -> Vec<String>
{
    let head = if addr == vaddr
    {
        format!("{addr:#018x}")
    }
    else
    {
        format!("{addr:#018x} (image {vaddr:#x})")
    };
    let mut lines = describe_resolution(resolution);
    lines[0] = format!("{head}: {}", lines[0]);
    lines
}

/// Render a resolution without its address: the first line is the resolution
/// and its source in brackets (`<function> at <file>:<line> [debug-info]`,
/// `<symbol>+<offset> [symbol-table]`, or `?? [unresolved]`); each further
/// line, indented, is a caller the first frame is inlined into. Never empty.
pub fn describe_resolution(resolution: &Resolution) -> Vec<String>
{
    match resolution
    {
        Resolution::DebugInfo(frames) if !frames.is_empty() =>
        {
            let mut lines = Vec::with_capacity(frames.len());
            for (idx, frame) in frames.iter().enumerate()
            {
                let text = format_frame(frame);
                if idx == 0
                {
                    lines.push(format!("{text} [debug-info]"));
                }
                else
                {
                    lines.push(format!("    inlined into {text}"));
                }
            }
            lines
        }
        Resolution::SymbolTable { name, offset } =>
        {
            vec![format!("{name}+{offset:#x} [symbol-table]")]
        }
        Resolution::DebugInfo(_) | Resolution::Unresolved => vec!["?? [unresolved]".to_owned()],
    }
}

/// `function at file:line:column`, with `??` for an unnamed function and the
/// position elided as far as the DWARF leaves it unknown.
fn format_frame(frame: &Frame) -> String
{
    let function = frame.function.as_deref().unwrap_or("??");
    let Some(file) = &frame.file
    else
    {
        return function.to_owned();
    };
    match (frame.line, frame.column)
    {
        (Some(line), Some(column)) => format!("{function} at {file}:{line}:{column}"),
        (Some(line), _) => format!("{function} at {file}:{line}"),
        (None, _) => format!("{function} at {file}"),
    }
}

/// Parse a hexadecimal address, with or without a `0x` prefix.
///
/// # Errors
///
/// Fails on an empty string, a non-hex digit, or a value past 64 bits.
pub fn parse_hex(text: &str) -> Result<u64>
{
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(digits, 16).with_context(|| format!("not a hex address: {text:?}"))
}

/// ELF fixtures with a known symbol table and DWARF, written in-test, for
/// this module's tests and the crash-log tests.
#[cfg(test)]
pub(crate) mod fixture
{
    use ::gimli::write::{
        Address, AttributeValue, DwarfUnit, EndianVec, FileId, LineProgram, LineString, Sections,
        Unit, UnitEntryId,
    };
    use ::gimli::{Encoding, Format, LineEncoding, LittleEndian, constants};
    pub(crate) use object::Architecture;
    use object::write::{Object, StandardSection, Symbol, SymbolSection};
    use object::{BinaryFormat, Endianness, SectionFlags, SectionKind, SymbolFlags, SymbolScope};

    use super::SymbolKind;

    /// Link address of the fixture's functions' base for a user PIE.
    pub(crate) const USER_BASE: u64 = 0;
    /// Link address of the fixture's functions' base for a kernel image.
    pub(super) const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;

    // The fixture's layout, as offsets from its base: `outer` at 0x100..0x140,
    // with `inner` inlined into it at 0x110..0x120 from a call on line 11;
    // `anon` at 0x180..0x1c0, an unnamed DWARF function with no line rows;
    // `leaf` at 0x200..0x220 and `tail` at 0x280 with no size, in the symbol
    // table only. The compile unit spans 0x100..0x1c0.
    pub(crate) const OUTER: u64 = 0x100;
    pub(crate) const INNER: u64 = 0x110;
    pub(super) const ANON: u64 = 0x180;
    pub(crate) const LEAF: u64 = 0x200;
    pub(super) const TAIL: u64 = 0x280;
    pub(super) const OUTER_MANGLED: &str = "_ZN7fixture5outer17h0123456789abcdefE";
    pub(super) const SYMBOLS: [(&str, u64, u64); 4] = [
        (OUTER_MANGLED, OUTER, 0x40),
        ("_ZN7fixture4anon17h0123456789abcdefE", ANON, 0x40),
        ("_ZN7fixture4leaf17h0123456789abcdefE", LEAF, 0x20),
        ("_ZN7fixture4tail17h0123456789abcdefE", TAIL, 0),
    ];

    /// Which sections the fixture image carries.
    #[derive(Clone, Copy, PartialEq)]
    pub(crate) enum Debug
    {
        Dwarf,
        SymbolsOnly,
    }

    /// The fixture's line program: one sequence over `outer`.
    pub(super) fn fixture_line_program(encoding: Encoding, base: u64) -> (LineProgram, FileId)
    {
        let mut program = LineProgram::new(
            encoding,
            LineEncoding::default(),
            LineString::String(b"/src".to_vec()),
            None,
            LineString::String(b"fixture.rs".to_vec()),
            None,
        );
        let dir = program.default_directory();
        let file = program.add_file(LineString::String(b"fixture.rs".to_vec()), dir, None);
        program.begin_sequence(Some(Address::Constant(base + OUTER)));
        for (offset, line) in [(0, 10), (INNER - OUTER, 20), (0x20, 12)]
        {
            let row = program.row();
            row.address_offset = offset;
            row.file = file;
            row.line = line;
            program.generate_row();
        }
        program.end_sequence(0x40);
        (program, file)
    }

    /// Add a DIE of `tag` under `parent` covering `base + start` for `len`
    /// bytes, with the further attributes `attrs`.
    pub(super) fn add_ranged_die(
        unit: &mut Unit,
        parent: UnitEntryId,
        tag: constants::DwTag,
        (start, len): (u64, u64),
        attrs: Vec<(constants::DwAt, AttributeValue)>,
    ) -> UnitEntryId
    {
        let id = unit.add(parent, tag);
        let die = unit.get_mut(id);
        die.set(
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(start)),
        );
        die.set(constants::DW_AT_high_pc, AttributeValue::Udata(len));
        for (name, value) in attrs
        {
            die.set(name, value);
        }
        id
    }

    /// The fixture's DIEs: the unit, `inner`'s abstract instance, `outer`
    /// with `inner` inlined into it, and the unnamed `anon`.
    pub(super) fn fixture_dies(unit: &mut Unit, base: u64, file: FileId)
    {
        let root = unit.root();
        let cu = unit.get_mut(root);
        cu.set(
            constants::DW_AT_name,
            AttributeValue::String(b"fixture.rs".to_vec()),
        );
        cu.set(
            constants::DW_AT_comp_dir,
            AttributeValue::String(b"/src".to_vec()),
        );
        cu.set(
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(base + OUTER)),
        );
        cu.set(
            constants::DW_AT_high_pc,
            AttributeValue::Udata(ANON + 0x40 - OUTER),
        );

        let inner = unit.add(root, constants::DW_TAG_subprogram);
        let die = unit.get_mut(inner);
        die.set(
            constants::DW_AT_name,
            AttributeValue::String(b"inner".to_vec()),
        );
        die.set(
            constants::DW_AT_inline,
            AttributeValue::Inline(constants::DW_INL_inlined),
        );

        let outer = add_ranged_die(
            unit,
            root,
            constants::DW_TAG_subprogram,
            (base + OUTER, 0x40),
            vec![
                (
                    constants::DW_AT_name,
                    AttributeValue::String(b"outer".to_vec()),
                ),
                (
                    constants::DW_AT_linkage_name,
                    AttributeValue::String(OUTER_MANGLED.as_bytes().to_vec()),
                ),
            ],
        );
        add_ranged_die(
            unit,
            outer,
            constants::DW_TAG_inlined_subroutine,
            (base + INNER, 0x10),
            vec![
                (
                    constants::DW_AT_abstract_origin,
                    AttributeValue::UnitRef(inner),
                ),
                (
                    constants::DW_AT_call_file,
                    AttributeValue::FileIndex(Some(file)),
                ),
                (constants::DW_AT_call_line, AttributeValue::Udata(11)),
            ],
        );
        add_ranged_die(
            unit,
            root,
            constants::DW_TAG_subprogram,
            (base + ANON, 0x40),
            vec![],
        );
    }

    /// The fixture's DWARF sections, by name.
    pub(super) fn fixture_dwarf(base: u64) -> Vec<(&'static str, Vec<u8>)>
    {
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = DwarfUnit::new(encoding);
        let (program, file) = fixture_line_program(encoding, base);
        dwarf.unit.line_program = program;
        fixture_dies(&mut dwarf.unit, base, file);

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).expect("write DWARF");
        let mut out = Vec::new();
        sections
            .for_each(|id, data| -> Result<(), ()> {
                if !data.slice().is_empty()
                {
                    out.push((id.name(), data.slice().to_vec()));
                }
                Ok(())
            })
            .expect("collect DWARF sections");
        out
    }

    /// An ELF image of `arch` whose functions sit at link addresses from
    /// `base`, with [`SYMBOLS`] in its symbol table and `debug` as its debug
    /// sections: name, contents, and ELF section flags.
    pub(super) fn elf(arch: Architecture, base: u64, debug: Vec<(&str, Vec<u8>, u64)>) -> Vec<u8>
    {
        let mut obj = Object::new(BinaryFormat::Elf, arch, Endianness::Little);
        let text = obj.section_id(StandardSection::Text);
        obj.append_section_data(text, &[0; 0x300], 16);
        for (name, offset, size) in SYMBOLS
        {
            obj.add_symbol(Symbol {
                name: name.as_bytes().to_vec(),
                value: base + offset,
                size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(text),
                flags: SymbolFlags::None,
            });
        }
        for (name, data, sh_flags) in debug
        {
            let id = obj.add_section(Vec::new(), name.as_bytes().to_vec(), SectionKind::Debug);
            obj.append_section_data(id, &data, 1);
            obj.section_mut(id).flags = SectionFlags::Elf {
                sh_type: object::elf::SHT_PROGBITS,
                sh_flags: object::elf::SectionFlags(sh_flags),
            };
        }
        obj.write().expect("write ELF")
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
}

#[cfg(test)]
mod tests
{
    use super::fixture::*;
    use super::*;

    fn frame(function: &str, line: u32) -> Frame
    {
        Frame {
            function: Some(function.to_owned()),
            file: Some("/src/fixture.rs".to_owned()),
            line: Some(line),
            column: None,
        }
    }

    #[test]
    fn user_address_resolves_through_its_bias_to_the_inlined_frame_and_its_caller()
    {
        let image = fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf);
        let sym = Symbolizer::new(&image).unwrap();
        let bias = 0x7f12_3456_7000;
        let vaddr = image_address(bias + USER_BASE + INNER + 4, bias).unwrap();
        assert_eq!(
            sym.resolve(vaddr).unwrap(),
            Resolution::DebugInfo(vec![frame("inner", 20), frame("fixture::outer", 11)])
        );
    }

    #[test]
    fn kernel_address_resolves_through_its_slide_to_function_and_line()
    {
        let image = fixture(Architecture::Riscv64, KERNEL_BASE, Debug::Dwarf);
        let sym = Symbolizer::new(&image).unwrap();
        let slide = 0x3a40_0000;
        let vaddr = image_address(slide + KERNEL_BASE + 0x124, slide).unwrap();
        assert_eq!(
            sym.resolve(vaddr).unwrap(),
            Resolution::DebugInfo(vec![frame("fixture::outer", 12)])
        );
    }

    #[test]
    fn address_no_dwarf_covers_falls_back_to_the_symbol_table()
    {
        let image = fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf);
        let sym = Symbolizer::new(&image).unwrap();
        assert_eq!(
            sym.resolve(LEAF + 8).unwrap(),
            Resolution::SymbolTable {
                name: "fixture::leaf".to_owned(),
                offset: 8
            }
        );
    }

    #[test]
    fn image_without_debug_info_resolves_from_the_symbol_table()
    {
        let image = fixture(Architecture::Riscv64, KERNEL_BASE, Debug::SymbolsOnly);
        let sym = Symbolizer::new(&image).unwrap();
        assert!(!sym.has_debug_info());
        assert_eq!(
            sym.resolve(KERNEL_BASE + INNER + 4).unwrap(),
            Resolution::SymbolTable {
                name: "fixture::outer".to_owned(),
                offset: INNER + 4 - OUTER
            }
        );
    }

    #[test]
    fn address_before_the_first_symbol_or_past_a_sized_symbol_is_unresolved()
    {
        let image = fixture(Architecture::X86_64, USER_BASE, Debug::SymbolsOnly);
        let sym = Symbolizer::new(&image).unwrap();
        assert_eq!(sym.resolve(OUTER - 1).unwrap(), Resolution::Unresolved);
        assert_eq!(sym.resolve(LEAF + 0x20).unwrap(), Resolution::Unresolved);
    }

    #[test]
    fn unnamed_dwarf_function_without_line_rows_falls_back_to_the_symbol_table()
    {
        let image = fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf);
        let sym = Symbolizer::new(&image).unwrap();
        assert_eq!(
            sym.resolve(ANON + 8).unwrap(),
            Resolution::SymbolTable {
                name: "fixture::anon".to_owned(),
                offset: 8
            }
        );
    }

    #[test]
    fn symbol_without_a_size_covers_every_address_up_to_the_next_symbol()
    {
        let image = fixture(Architecture::X86_64, USER_BASE, Debug::SymbolsOnly);
        let sym = Symbolizer::new(&image).unwrap();
        assert_eq!(
            sym.resolve(TAIL + 0x1000).unwrap(),
            Resolution::SymbolTable {
                name: "fixture::tail".to_owned(),
                offset: 0x1000
            }
        );
    }

    #[test]
    fn compressed_debug_section_is_refused()
    {
        // An ELF compression header (`Elf64_Chdr`: ch_type ELFCOMPRESS_ZLIB,
        // reserved, ch_size, ch_addralign) ahead of the section's bytes.
        let image = fixture_with_section(".debug_info", object::elf::SHF_COMPRESSED.0, |data| {
            let mut out = Vec::new();
            out.extend_from_slice(&object::elf::ELFCOMPRESS_ZLIB.0.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
            out.extend_from_slice(&1u64.to_le_bytes());
            out.extend_from_slice(&data);
            out
        });
        let err = Symbolizer::new(&image)
            .err()
            .expect("compressed section accepted");
        assert!(format!("{err:#}").contains("compressed debug section .debug_info"));
    }

    #[test]
    fn malformed_unit_header_is_refused()
    {
        let image = fixture_with_section(".debug_info", 0, |_| vec![0xff; 16]);
        assert!(Symbolizer::new(&image).is_err());
    }

    #[test]
    fn malformed_function_entry_fails_the_resolution()
    {
        // The unit header and its root entry stay intact, so the image loads;
        // `inner`'s entry, whose abbreviation code is the byte ahead of its
        // inline name, gets a code the abbreviation table lacks, which the
        // function lookup a resolution runs meets.
        let image = fixture_with_section(".debug_info", 0, |mut data| {
            let name = data
                .windows(6)
                .position(|bytes| bytes == b"inner\0")
                .expect("inner's name in .debug_info");
            data[name - 1] = 0x7f;
            data
        });
        let sym = Symbolizer::new(&image).unwrap();
        assert!(sym.resolve(OUTER + 4).is_err());
    }

    #[test]
    fn address_below_the_bias_is_refused()
    {
        assert!(image_address(0xfff, 0x1000).is_err());
        assert_eq!(image_address(0x1000, 0x1000).unwrap(), 0);
    }

    #[test]
    fn data_that_is_not_an_object_file_is_refused()
    {
        assert!(Symbolizer::new(b"not an ELF image").is_err());
    }

    #[test]
    fn report_lines_name_the_source_and_each_inlined_caller()
    {
        let inlined = Resolution::DebugInfo(vec![
            Frame {
                column: Some(5),
                ..frame("inner", 20)
            },
            Frame {
                function: None,
                line: None,
                ..frame("middle", 0)
            },
            Frame {
                file: None,
                line: None,
                ..frame("outer", 0)
            },
        ]);
        assert_eq!(
            format_resolution(0x1114, 0x114, &inlined),
            vec![
                "0x0000000000001114 (image 0x114): inner at /src/fixture.rs:20:5 [debug-info]",
                "    inlined into ?? at /src/fixture.rs",
                "    inlined into outer",
            ]
        );
        let symbol = Resolution::SymbolTable {
            name: "leaf".to_owned(),
            offset: 8,
        };
        assert_eq!(
            format_resolution(0x208, 0x208, &symbol),
            vec!["0x0000000000000208: leaf+0x8 [symbol-table]"]
        );
        assert_eq!(
            format_resolution(0x5, 0x5, &Resolution::Unresolved),
            vec!["0x0000000000000005: ?? [unresolved]"]
        );
        assert_eq!(
            describe_resolution(&Resolution::DebugInfo(Vec::new())),
            vec!["?? [unresolved]"]
        );
    }

    #[test]
    fn hex_addresses_parse_with_or_without_prefix_and_reject_junk()
    {
        assert_eq!(
            parse_hex("0xffffffff80001000").unwrap(),
            0xffff_ffff_8000_1000
        );
        assert_eq!(parse_hex("1F").unwrap(), 0x1f);
        assert!(parse_hex("").is_err());
        assert!(parse_hex("0x").is_err());
        assert!(parse_hex("12g").is_err());
        assert!(parse_hex("10000000000000000").is_err());
    }
}
