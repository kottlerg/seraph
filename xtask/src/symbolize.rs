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
use object::{CompressionFormat, Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind};

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
    pub file: Option<String>,
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
    match resolution
    {
        Resolution::DebugInfo(frames) =>
        {
            let mut lines = Vec::with_capacity(frames.len());
            for (idx, frame) in frames.iter().enumerate()
            {
                let text = format_frame(frame);
                if idx == 0
                {
                    lines.push(format!("{head}: {text} [debug-info]"));
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
            vec![format!("{head}: {name}+{offset:#x} [symbol-table]")]
        }
        Resolution::Unresolved => vec![format!("{head}: ?? [unresolved]")],
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

#[cfg(test)]
mod tests
{
    use ::gimli::write::{
        Address, AttributeValue, DwarfUnit, EndianVec, LineProgram, LineString, Sections,
    };
    use ::gimli::{Encoding, Format, LineEncoding, LittleEndian, constants};
    use object::write::{Object, StandardSection, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolScope};

    use super::*;

    /// Link address of the fixture's functions' base for a user PIE.
    const USER_BASE: u64 = 0;
    /// Link address of the fixture's functions' base for a kernel image.
    const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;

    // The fixture's layout, as offsets from its base: `outer` at 0x100..0x140,
    // with `inner` inlined into it at 0x110..0x120 from a call on line 11;
    // `leaf` at 0x200..0x220, in the symbol table only.
    const OUTER: u64 = 0x100;
    const INNER: u64 = 0x110;
    const LEAF: u64 = 0x200;
    const OUTER_MANGLED: &str = "_ZN7fixture5outer17h0123456789abcdefE";
    const LEAF_MANGLED: &str = "_ZN7fixture4leaf17h0123456789abcdefE";

    /// Which sections the fixture image carries.
    #[derive(Clone, Copy, PartialEq)]
    enum Debug
    {
        Dwarf,
        SymbolsOnly,
    }

    /// The fixture's DWARF sections, by name.
    fn fixture_dwarf(base: u64) -> Vec<(&'static str, Vec<u8>)>
    {
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = DwarfUnit::new(encoding);
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
        dwarf.unit.line_program = program;

        let root = dwarf.unit.root();
        let cu = dwarf.unit.get_mut(root);
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
        cu.set(constants::DW_AT_high_pc, AttributeValue::Udata(0x40));

        let inner = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        let die = dwarf.unit.get_mut(inner);
        die.set(
            constants::DW_AT_name,
            AttributeValue::String(b"inner".to_vec()),
        );
        die.set(
            constants::DW_AT_inline,
            AttributeValue::Inline(constants::DW_INL_inlined),
        );

        let outer = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        let die = dwarf.unit.get_mut(outer);
        die.set(
            constants::DW_AT_name,
            AttributeValue::String(b"outer".to_vec()),
        );
        die.set(
            constants::DW_AT_linkage_name,
            AttributeValue::String(OUTER_MANGLED.as_bytes().to_vec()),
        );
        die.set(
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(base + OUTER)),
        );
        die.set(constants::DW_AT_high_pc, AttributeValue::Udata(0x40));

        let call = dwarf.unit.add(outer, constants::DW_TAG_inlined_subroutine);
        let die = dwarf.unit.get_mut(call);
        die.set(
            constants::DW_AT_abstract_origin,
            AttributeValue::UnitRef(inner),
        );
        die.set(
            constants::DW_AT_low_pc,
            AttributeValue::Address(Address::Constant(base + INNER)),
        );
        die.set(constants::DW_AT_high_pc, AttributeValue::Udata(0x10));
        die.set(
            constants::DW_AT_call_file,
            AttributeValue::FileIndex(Some(file)),
        );
        die.set(constants::DW_AT_call_line, AttributeValue::Udata(11));

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
    /// `base`, with `outer` and `leaf` in its symbol table and, for
    /// `Debug::Dwarf`, the DWARF of [`fixture_dwarf`].
    fn fixture(arch: Architecture, base: u64, debug: Debug) -> Vec<u8>
    {
        let mut obj = Object::new(BinaryFormat::Elf, arch, Endianness::Little);
        let text = obj.section_id(StandardSection::Text);
        obj.append_section_data(text, &[0; 0x300], 16);
        for (name, offset, size) in [(OUTER_MANGLED, OUTER, 0x40), (LEAF_MANGLED, LEAF, 0x20)]
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
        if debug == Debug::Dwarf
        {
            for (name, data) in fixture_dwarf(base)
            {
                let id = obj.add_section(
                    Vec::new(),
                    name.as_bytes().to_vec(),
                    object::SectionKind::Debug,
                );
                obj.append_section_data(id, &data, 1);
            }
        }
        obj.write().expect("write ELF")
    }

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
                file: None,
                line: None,
                ..frame("outer", 0)
            },
        ]);
        assert_eq!(
            format_resolution(0x1114, 0x114, &inlined),
            vec![
                "0x0000000000001114 (image 0x114): inner at /src/fixture.rs:20:5 [debug-info]",
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
