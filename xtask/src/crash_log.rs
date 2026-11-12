// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/crash_log.rs

//! Symbolized crash reports from a serial log.
//!
//! The crash service logs one block per faulting process
//! (services/crashd/docs/block-format.md), read here with
//! `shared/crash-report`'s parser. Each block names its process by badge
//! only. logd's `reclaim:` line for that badge gives the process's log name,
//! and the image is the sysroot binary of that name, accepted only when its
//! executable segments span the block's text; a process logd names no name
//! for is matched by that span alone. Each address in the block's text is
//! then the image address `address - load_bias`, which [`crate::symbolize`]
//! resolves.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::PathBuf;

use crash_report::Block;
use logd_codec::reclaim::UNNAMED;
use procmgr_process_table::threads;

use crate::symbolize::{Symbolizer, describe_resolution, text_span};

/// logd's tag and the message of each of its reclaim lines, the fields after
/// which name the slot: a death drained from logd's death queue, and a
/// resync's eviction (services/logd/docs/ipc-interface.md § Death-notification
/// cascade, § Death-queue resync).
const RECLAIM_TAGS: [&str; 2] = ["[logd] reclaim: ", "[logd] reclaim (resync): "];

/// The sysroot directories searched, in this order, for the binary a log
/// name names: the boot modules and services, the drivers, the filesystem
/// drivers, the programs, the harnesses, the test-only drivers, and the
/// per-program testers (last, since a tester installs under its program's
/// name).
const IMAGE_DIRS: [&str; 7] = [
    "services",
    "services/drivers",
    "services/fs",
    "programs",
    "tests",
    "tests/drivers",
    "tests/programs",
];

/// The badge and registered log name of each logd reclaim line of `log`,
/// read from the line's fields (`logd_codec::record::fields`), so a quoted
/// name is read whole and unescaped. A slot that registered no name (logd
/// prints it as `?`) has no entry.
pub fn reclaimed_names(log: &str) -> HashMap<u64, String>
{
    let mut names = HashMap::new();
    for line in log.lines()
    {
        let Some(rest) = RECLAIM_TAGS
            .iter()
            .find_map(|tag| line.split_once(tag).map(|(_, after)| after))
        else
        {
            continue;
        };
        let fields: Vec<_> = logd_codec::record::fields(rest.trim_end_matches('\r')).collect();
        let badge = fields
            .iter()
            .find(|f| f.key == "badge")
            .and_then(|f| String::from_utf8(f.value.bytes().collect()).ok())
            .and_then(|b| b.parse().ok());
        let name = fields.iter().find(|f| f.key == "name");
        if let (Some(badge), Some(name)) = (badge, name)
            && !name.value.is(UNNAMED.as_bytes())
        {
            let name: Vec<u8> = name.value.bytes().collect();
            names.insert(badge, String::from_utf8_lossy(&name).into_owned());
        }
    }
    names
}

/// Where a block's image comes from: a set of binaries, each named by its
/// path relative to the image root.
pub trait ImageSource
{
    /// The architecture the images are built for, `Ok(None)` when unrecorded.
    ///
    /// # Errors
    ///
    /// The record exists but cannot be read.
    fn arch(&self) -> Result<Option<String>, String>;

    /// Every binary's relative path.
    ///
    /// # Errors
    ///
    /// A directory of the images exists but cannot be read.
    fn list(&self) -> Result<Vec<String>, String>;

    /// The bytes of the binary at `relative`, `Ok(None)` when there is none.
    ///
    /// # Errors
    ///
    /// The binary exists but cannot be read.
    fn read(&self, relative: &str) -> Result<Option<Vec<u8>>, String>;
}

/// The images of a sysroot: the files of [`IMAGE_DIRS`].
pub struct SysrootImages
{
    pub sysroot: PathBuf,
}

impl ImageSource for SysrootImages
{
    fn arch(&self) -> Result<Option<String>, String>
    {
        let path = self.sysroot.join(".arch");
        match std::fs::read_to_string(&path)
        {
            Ok(tag) => Ok(Some(tag.trim().to_owned())),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("cannot read {}: {err}", path.display())),
        }
    }

    fn list(&self) -> Result<Vec<String>, String>
    {
        let mut paths = Vec::new();
        for dir in IMAGE_DIRS
        {
            let path = self.sysroot.join(dir);
            let entries = match std::fs::read_dir(&path)
            {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(format!("cannot list {}: {err}", path.display())),
            };
            for entry in entries
            {
                let entry =
                    entry.map_err(|err| format!("cannot list {}: {err}", path.display()))?;
                let is_file = entry
                    .file_type()
                    .map_err(|err| format!("cannot stat {}: {err}", entry.path().display()))?
                    .is_file();
                if let (true, Some(name)) = (is_file, entry.file_name().to_str())
                {
                    paths.push(format!("{dir}/{name}"));
                }
            }
        }
        paths.sort();
        Ok(paths)
    }

    fn read(&self, relative: &str) -> Result<Option<Vec<u8>>, String>
    {
        let path = self.sysroot.join(relative);
        match std::fs::read(&path)
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("cannot read {}: {err}", path.display())),
        }
    }
}

/// The sysroot-relative paths a binary logged as `name` may have, in search
/// order: the name's first word in each of [`IMAGE_DIRS`]; none for a name
/// whose first word is not a single path component. Every name registered
/// in the tree today is a bare binary name; taking the first word keeps a
/// name that carries more after a space (logd prints what a process
/// registered, spaces included) resolvable, and the text-span check refuses
/// a wrong binary either way.
fn candidate_paths(name: &str) -> Vec<String>
{
    let binary = name.split(' ').next().unwrap_or_default();
    if binary.is_empty() || binary.contains(['/', '\\']) || binary == "." || binary == ".."
    {
        return Vec::new();
    }
    IMAGE_DIRS
        .iter()
        .map(|dir| format!("{dir}/{binary}"))
        .collect()
}

/// Each image's relative path and unbiased text span, or why the images
/// cannot be read.
type ImageSpans = Result<Vec<(String, (u64, u64))>, String>;

/// The unbiased text span of each image of `images`, computed once per log
/// and only for a log with an unnamed block.
struct Spans<'a>
{
    images: &'a dyn ImageSource,
    spans: OnceCell<ImageSpans>,
}

impl Spans<'_>
{
    /// The images whose executable segments span exactly `span`.
    fn matching(&self, span: (u64, u64)) -> Result<Vec<&str>, String>
    {
        let spans = self
            .spans
            .get_or_init(|| {
                let mut spans = Vec::new();
                for relative in self.images.list()?
                {
                    if let Some(span) = self.images.read(&relative)?.as_deref().and_then(text_span)
                    {
                        spans.push((relative, span));
                    }
                }
                Ok(spans)
            })
            .as_ref()
            .map_err(Clone::clone)?;
        Ok(spans
            .iter()
            .filter(|(_, image_span)| *image_span == span)
            .map(|(relative, _)| relative.as_str())
            .collect())
    }
}

/// The symbolized report of every crash-report block in `log`, `None` when
/// the log holds none.
pub fn symbolize_log(log: &str, images: &dyn ImageSource) -> Option<String>
{
    let blocks = crash_report::parse(log);
    if blocks.is_empty()
    {
        return None;
    }
    let names = reclaimed_names(log);
    let images_arch = images.arch();
    let spans = Spans {
        images,
        spans: OnceCell::new(),
    };
    let mut out = String::new();
    for block in &blocks
    {
        let name = block
            .get("badge")
            .and_then(|badge| badge.parse::<u64>().ok())
            .and_then(|badge| names.get(&badge));
        let source = BlockSource {
            name: name.map(String::as_str),
            images,
            images_arch: images_arch
                .as_ref()
                .map(Option::as_deref)
                .map_err(String::as_str),
            spans: &spans,
        };
        symbolize_block(&mut out, block, &source);
    }
    Some(out)
}

/// What a block's image is looked up with.
struct BlockSource<'a>
{
    /// The process's registered log name, from logd's reclaim line for its
    /// badge.
    name: Option<&'a str>,
    images: &'a dyn ImageSource,
    /// The images' architecture, or why it cannot be read.
    images_arch: Result<Option<&'a str>, &'a str>,
    spans: &'a Spans<'a>,
}

/// Append `block`'s report to `out`: a header naming the block, its
/// process, and its image, then every field line as logged, with the
/// instruction pointer and each stack frame inside the image's text followed
/// by what it resolves to.
fn symbolize_block(out: &mut String, block: &Block, source: &BlockSource<'_>)
{
    let badge = block.get("badge").unwrap_or("absent");
    let process = match source.name
    {
        Some(name) => format!("process {name}"),
        // A block whose attach failed carries the fault message's badge,
        // which for a registered thread is its crash badge: it names no
        // process, and no `reclaim:` line names it
        // (services/crashd/docs/block-format.md § Fields).
        None if badge.parse().is_ok_and(threads::is_crash_badge) => format!(
            "process unknown (thread crash badge {badge}: the attach failed, so the block names \
             no process)"
        ),
        None => format!("process unnamed (badge {badge}: logd has no registered name for it)"),
    };
    let _ = writeln!(
        out,
        "crash report {:016x} (format version {}): {process}",
        block.id, block.version
    );
    if let Err(defect) = block.check()
    {
        let _ = writeln!(out, "  defective block ({defect:?}): fields as logged");
    }
    let image = block_image_lines(out, block, source);
    let symbolizer = match image.as_deref().map(Symbolizer::new)
    {
        Some(Ok(symbolizer)) => Some(symbolizer),
        Some(Err(err)) =>
        {
            let _ = writeln!(out, "  not symbolized: {err:#}");
            None
        }
        None => None,
    };
    if symbolizer.as_ref().is_some_and(|s| !s.has_debug_info())
    {
        let _ = writeln!(
            out,
            "  no debug information: addresses resolve from the symbol table"
        );
    }
    let resolver = symbolizer
        .as_ref()
        .and_then(|symbolizer| Resolver::new(block, symbolizer));
    write_fields(out, block, resolver.as_ref());
    let _ = writeln!(out, "end {:016x}", block.id);
}

/// Look up `block`'s image and append the line saying which it is, or why
/// there is none and how to resolve the block once the binary is known; the
/// image's bytes, if any.
fn block_image_lines(out: &mut String, block: &Block, source: &BlockSource<'_>) -> Option<Vec<u8>>
{
    match block_image(block, source)
    {
        Ok((label, bytes)) =>
        {
            let _ = writeln!(out, "  image: {label}");
            Some(bytes)
        }
        Err(reason) =>
        {
            let _ = writeln!(out, "  not symbolized: {reason}");
            if let Some(command) = rerun_command(block)
            {
                let _ = writeln!(out, "  with its binary: {command}");
            }
            None
        }
    }
}

/// Append every field line of `block` as logged, each code address followed
/// by what `resolver` resolves it to.
fn write_fields(out: &mut String, block: &Block, resolver: Option<&Resolver<'_, '_>>)
{
    for (key, value) in block.fields()
    {
        let lines = resolver
            .and_then(|r| r.resolve(key, value))
            .unwrap_or_default();
        match lines.split_first()
        {
            Some((first, rest)) =>
            {
                let _ = writeln!(out, "  {key}={value}  {first}");
                for line in rest
                {
                    let _ = writeln!(out, "  {line}");
                }
            }
            None =>
            {
                let _ = writeln!(out, "  {key}={value}");
            }
        }
    }
}

/// The address form that resolves `block`'s instruction pointer and frames
/// once its binary is known, `None` for a block without a load bias. Frames
/// past the first are return addresses: run this way they resolve at their
/// own address, not inside the call.
fn rerun_command(block: &Block) -> Option<String>
{
    let bias = block.hex("load_bias")?;
    let mut addresses = block.frames();
    if addresses.is_empty()
    {
        addresses.extend(block.hex("ip"));
    }
    let mut command = format!("cargo xtask symbolize --binary <binary> --bias {bias:#x}");
    for addr in addresses
    {
        let _ = write!(command, " {addr:#x}");
    }
    Some(command)
}

/// The image of `block`'s process, labelled with how it was found, or why
/// there is none to symbolize with. A named process's image is the first
/// binary of its name in [`IMAGE_DIRS`], accepted only when its executable
/// segments span exactly the block's `text` less its `load_bias` (a binary
/// rebuilt since the boot is refused); an unnamed one's is the one binary
/// whose span matches, never a guess among several.
fn block_image(block: &Block, source: &BlockSource<'_>) -> Result<(String, Vec<u8>), String>
{
    let (Some(load_bias), Some((text_start, text_end))) =
        (block.hex("load_bias"), text_range(block))
    else
    {
        return Err("the block carries no load bias and text range".to_owned());
    };
    let images_arch = source
        .images_arch
        .map_err(|err| format!("the images' architecture: {err}"))?;
    if let (Some(block_arch), Some(images_arch)) = (block.get("arch"), images_arch)
        && block_arch != images_arch
    {
        return Err(format!(
            "the block is {block_arch}, the images are built for {images_arch}"
        ));
    }
    let span = (
        text_start.wrapping_sub(load_bias),
        text_end.wrapping_sub(load_bias),
    );
    match source.name
    {
        Some(name) => named_image(source.images, name, span),
        None => unnamed_image(source, span),
    }
}

/// The first binary of `name` in [`IMAGE_DIRS`], refused unless its
/// executable segments span `span`.
fn named_image(
    images: &dyn ImageSource,
    name: &str,
    span: (u64, u64),
) -> Result<(String, Vec<u8>), String>
{
    for relative in candidate_paths(name)
    {
        let Some(bytes) = images.read(&relative)?
        else
        {
            continue;
        };
        return match text_span(&bytes)
        {
            Some(image_span) if image_span == span => Ok((format!("sysroot/{relative}"), bytes)),
            Some((start, end)) => Err(format!(
                "sysroot/{relative}'s text spans {start:#x}-{end:#x}, the block's {:#x}-{:#x}: \
                 the binary is not the one that ran",
                span.0, span.1
            )),
            None => Err(format!(
                "sysroot/{relative} is not an ELF image with an executable segment"
            )),
        };
    }
    Err(format!("no binary named {name} in the images"))
}

/// The one binary whose executable segments span `span`.
fn unnamed_image(source: &BlockSource<'_>, span: (u64, u64)) -> Result<(String, Vec<u8>), String>
{
    match source.spans.matching(span)?.as_slice()
    {
        [] => Err("the process is unnamed, and no binary's text matches the block's".to_owned()),
        [relative] => source
            .images
            .read(relative)?
            .map(|bytes| {
                (
                    format!("sysroot/{relative} (the one binary whose text matches the block's)"),
                    bytes,
                )
            })
            .ok_or_else(|| format!("sysroot/{relative} is gone")),
        several => Err(format!(
            "the process is unnamed, and the text of several binaries matches the block's: {}",
            several.join(", ")
        )),
    }
}

/// The block's `text` field as `[start, end)`.
fn text_range(block: &Block) -> Option<(u64, u64)>
{
    let (start, end) = block.get("text")?.split_once('-')?;
    let start = u64::from_str_radix(start.strip_prefix("0x")?, 16).ok()?;
    let end = u64::from_str_radix(end.strip_prefix("0x")?, 16).ok()?;
    Some((start, end))
}

/// Resolves a block's code addresses against its image.
struct Resolver<'a, 'data>
{
    symbolizer: &'a Symbolizer<'data>,
    load_bias: u64,
    text: (u64, u64),
}

impl<'a, 'data> Resolver<'a, 'data>
{
    fn new(block: &Block, symbolizer: &'a Symbolizer<'data>) -> Option<Self>
    {
        Some(Resolver {
            symbolizer,
            load_bias: block.hex("load_bias")?,
            text: text_range(block)?,
        })
    }

    /// The resolution lines of field `key`, `None` for a field that is not a
    /// code address. `ip` and `frame.0` resolve at their address; a later
    /// frame is a candidate return address, so it resolves at the address
    /// less one, inside the call it returns from. An address outside the
    /// text is not resolved and reads `outside the image's text`.
    fn resolve(&self, key: &str, value: &str) -> Option<Vec<String>>
    {
        let return_address = match key
        {
            "ip" | "frame.0" => false,
            _ if key.starts_with("frame.") => true,
            _ => return None,
        };
        let addr = u64::from_str_radix(value.strip_prefix("0x")?, 16).ok()?;
        if addr < self.text.0 || addr >= self.text.1
        {
            return Some(vec!["outside the image's text".to_owned()]);
        }
        let probe = addr
            .checked_sub(self.load_bias)?
            .checked_sub(u64::from(return_address))?;
        match self.symbolizer.resolve(probe)
        {
            Ok(resolution) => Some(describe_resolution(&resolution)),
            Err(err) => Some(vec![format!("?? [malformed debug information: {err:#}]")]),
        }
    }
}

#[cfg(test)]
mod tests
{
    use crash_report::{Access, Arch, Fault, Image, Report, Status, Thread};
    use logd_codec::reclaim::{Cause, ReclaimLine};

    use super::*;
    use crate::symbolize::fixture::{
        Architecture, Debug, INNER, LEAF, OUTER, USER_BASE, fixture, fixture_with_section,
    };

    /// The fixture image's load bias in the reports below.
    const BIAS: u64 = 0x30_1234_5000;
    const IMAGE: Image = Image {
        load_bias: BIAS,
        text_start: BIAS + USER_BASE + OUTER,
        text_end: BIAS + USER_BASE + 0x300,
    };

    /// Images of one architecture, by relative path; with `list_error`,
    /// listing them fails.
    struct Fixture
    {
        arch: &'static str,
        images: Vec<(&'static str, Vec<u8>)>,
        list_error: bool,
    }

    impl Fixture
    {
        /// `image` as `programs/crashme`, built for `arch`.
        fn crashme(arch: &'static str, image: Vec<u8>) -> Self
        {
            Fixture {
                arch,
                images: vec![("programs/crashme", image)],
                list_error: false,
            }
        }

        /// The DWARF fixture as `programs/crashme`, built for `arch`.
        fn dwarf(arch: &'static str) -> Self
        {
            Self::crashme(
                arch,
                with_text_segment(fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf)),
            )
        }
    }

    impl ImageSource for Fixture
    {
        fn arch(&self) -> Result<Option<String>, String>
        {
            Ok(Some(self.arch.to_owned()))
        }

        fn list(&self) -> Result<Vec<String>, String>
        {
            if self.list_error
            {
                return Err("cannot list the images: denied".to_owned());
            }
            Ok(self
                .images
                .iter()
                .map(|(path, _)| (*path).to_owned())
                .collect())
        }

        fn read(&self, relative: &str) -> Result<Option<Vec<u8>>, String>
        {
            Ok(self
                .images
                .iter()
                .find(|(path, _)| *path == relative)
                .map(|(_, bytes)| bytes.clone()))
        }
    }

    /// A minimal little-endian x86-64 `ET_DYN` image with no sections and
    /// one loadable segment per `(p_flags, p_vaddr, p_memsz)`.
    fn segments_only(segments: &[(u32, u64, u64)]) -> Vec<u8>
    {
        let mut elf = Vec::new();
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        elf.extend_from_slice(&[0; 8]);
        elf.extend_from_slice(&3u16.to_le_bytes()); // e_type: ET_DYN
        elf.extend_from_slice(&0x3eu16.to_le_bytes()); // e_machine: x86-64
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf.extend_from_slice(&u16::try_from(segments.len()).unwrap().to_le_bytes());
        elf.extend_from_slice(&[0; 6]); // e_shentsize, e_shnum, e_shstrndx
        for &(flags, vaddr, memsz) in segments
        {
            elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
            elf.extend_from_slice(&flags.to_le_bytes());
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
            elf.extend_from_slice(&vaddr.to_le_bytes());
            elf.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_filesz
            elf.extend_from_slice(&memsz.to_le_bytes());
            elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        }
        elf
    }

    /// `PF_R | PF_X`, and `PF_R` alone.
    const RX: u32 = 5;
    const R: u32 = 4;

    /// `elf`, an ELF64 image without program headers, given one executable
    /// loadable segment over `[OUTER, 0x300)`: the span of [`IMAGE`]'s text
    /// less its bias.
    fn with_text_segment(mut elf: Vec<u8>) -> Vec<u8>
    {
        while elf.len() % 8 != 0
        {
            elf.push(0);
        }
        let phoff = u64::try_from(elf.len()).unwrap();
        elf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        elf.extend_from_slice(&RX.to_le_bytes());
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        elf.extend_from_slice(&(USER_BASE + OUTER).to_le_bytes());
        elf.extend_from_slice(&(USER_BASE + OUTER).to_le_bytes()); // p_paddr
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_filesz
        elf.extend_from_slice(&(0x300 - OUTER).to_le_bytes()); // p_memsz
        elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        elf[0x20..0x28].copy_from_slice(&phoff.to_le_bytes()); // e_phoff
        elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        elf
    }

    /// logd's reclaim line for `badge`, as its self-log prints it.
    fn reclaim_line(badge: u64, cause: Cause, name: &str) -> String
    {
        let line = ReclaimLine {
            badge,
            cause,
            name: name.as_bytes(),
        };
        format!("[2.6] [logd] {line}\r\n")
    }

    /// The serial lines of `report`'s block as logd prints crashd's lines,
    /// and, when `name` is given, logd's reclaim line naming the process.
    fn log_of(report: &Report<'_>, name: Option<&str>) -> String
    {
        let mut log = String::new();
        report.emit(|line| log.push_str(&format!("[2.5] [crashd] {line}\r\n")));
        if let Some(name) = name
        {
            log.push_str(&reclaim_line(
                report.badge,
                Cause::Death {
                    exit_reason: 0x100e,
                },
                name,
            ));
        }
        log
    }

    /// A complete main-thread report of a write fault at `ip`, with frames
    /// `frames`.
    fn report<'a>(ip: u64, regs: &'a [u64], frames: &'a [u64]) -> Report<'a>
    {
        Report {
            id: 0xaa,
            badge: 42,
            arch: Arch::X86_64,
            thread: Thread::Main,
            status: Status::Complete,
            fault: Fault::Vm {
                access: Access::Write,
                addr: 0,
                pager_reason: None,
            },
            ip,
            image: Some(IMAGE),
            regs,
            code: &[0x0f, 0x0b],
            frames,
        }
    }

    #[test]
    fn a_blocks_ip_and_return_frames_resolve_against_its_named_image()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        // A return address one past `leaf + 8` resolves inside the call,
        // at `leaf + 8`.
        let frames = [ip, BIAS + LEAF + 9];
        let out = symbolize_log(
            &log_of(&report(ip, &regs, &frames), Some("crashme")),
            &Fixture::dwarf("x86_64"),
        )
        .unwrap();
        assert!(
            out.starts_with("crash report 00000000000000aa (format version 1): process crashme\n")
        );
        assert!(out.contains("\n  image: sysroot/programs/crashme\n"));
        assert!(out.contains(&format!(
            "\n  ip={ip:#018x}  inner at /src/fixture.rs:20 [debug-info]\n      inlined into \
             fixture::outer at /src/fixture.rs:11\n"
        )));
        assert!(out.contains(&format!(
            "\n  frame.1={:#018x}  fixture::leaf+0x8 [symbol-table]\n",
            BIAS + LEAF + 9
        )));
        assert!(out.contains("\n  reg.rax=0x0000000000000000\n"));
        assert!(out.ends_with("end 00000000000000aa\n"));
    }

    #[test]
    fn an_ip_outside_the_text_is_not_resolved()
    {
        let regs = [0u64; 21];
        let out = symbolize_log(
            &log_of(&report(0x10, &regs, &[0x10]), Some("crashme")),
            &Fixture::dwarf("x86_64"),
        )
        .unwrap();
        assert!(out.contains("\n  ip=0x0000000000000010  outside the image's text\n"));
    }

    #[test]
    fn a_block_without_a_usable_image_is_printed_unresolved_with_the_reason()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER;
        let cases = [
            (
                Some("other"),
                "x86_64",
                "not symbolized: no binary named other in the images",
            ),
            (
                Some("crashme"),
                "riscv64",
                "not symbolized: the block is x86_64, the images are built for riscv64",
            ),
        ];
        for (name, arch, reason) in cases
        {
            let out = symbolize_log(
                &log_of(&report(ip, &regs, &[ip]), name),
                &Fixture::dwarf(arch),
            )
            .unwrap();
            assert!(out.contains(reason), "{reason} missing from:\n{out}");
            assert!(out.contains(&format!("\n  ip={ip:#018x}\n")), "{out}");
        }
    }

    #[test]
    fn an_incomplete_block_is_marked_defective()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER;
        let log: String = log_of(&report(ip, &regs, &[ip]), Some("crashme"))
            .lines()
            .filter(|line| !line.contains("CRASH-END"))
            .map(|line| format!("{line}\n"))
            .collect();
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(out.contains("\n  defective block (Incomplete): fields as logged\n"));
    }

    #[test]
    fn an_image_without_debug_information_resolves_from_its_symbol_table()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let images = Fixture::crashme(
            "x86_64",
            with_text_segment(fixture(Architecture::X86_64, USER_BASE, Debug::SymbolsOnly)),
        );
        let out =
            symbolize_log(&log_of(&report(ip, &regs, &[ip]), Some("crashme")), &images).unwrap();
        assert!(
            out.contains("\n  no debug information: addresses resolve from the symbol table\n")
        );
        assert!(out.contains(&format!(
            "\n  ip={ip:#018x}  fixture::outer+{:#x} [symbol-table]\n",
            INNER + 4 - OUTER
        )));
    }

    #[test]
    fn an_unreadable_image_or_its_malformed_debug_information_is_reported()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let log = log_of(&report(ip, &regs, &[ip]), Some("crashme"));
        let not_elf = Fixture::crashme("x86_64", b"not an ELF image".to_vec());
        let out = symbolize_log(&log, &not_elf).unwrap();
        assert!(
            out.contains(
                "\n  not symbolized: sysroot/programs/crashme is not an ELF image with an executable \
                 segment\n"
            ),
            "{out}"
        );
        assert!(out.contains(&format!("\n  ip={ip:#018x}\n")));
        // `inner`'s entry gets an abbreviation code the table lacks, so the
        // image loads but the resolution fails.
        let broken = Fixture::crashme(
            "x86_64",
            with_text_segment(fixture_with_section(".debug_info", 0, |mut data| {
                let name = data
                    .windows(6)
                    .position(|bytes| bytes == b"inner\0")
                    .expect("inner's name in .debug_info");
                data[name - 1] = 0x7f;
                data
            })),
        );
        let out = symbolize_log(&log, &broken).unwrap();
        assert!(
            out.contains(&format!(
                "\n  ip={ip:#018x}  ?? [malformed debug information: "
            )),
            "{out}"
        );
    }

    #[test]
    fn a_block_without_its_image_bounds_is_not_symbolized()
    {
        let ip = BIAS + INNER;
        let mut unattached = report(ip, &[], &[]);
        unattached.status = Status::Unattached;
        unattached.image = None;
        let out = symbolize_log(
            &log_of(&unattached, Some("crashme")),
            &Fixture::dwarf("x86_64"),
        )
        .unwrap();
        assert!(
            out.contains("\n  not symbolized: the block carries no load bias and text range\n")
        );
        assert!(out.contains(&format!("\n  ip={ip:#018x}\n")));
    }

    #[test]
    fn a_block_with_a_thread_value_the_parser_does_not_know_is_still_printed_and_resolved()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let log = log_of(&report(ip, &regs, &[ip]), Some("crashme"))
            .replace("thread=main", "thread=fiber");
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(out.contains("\n  thread=fiber\n"), "{out}");
        assert!(
            out.contains(&format!(
                "\n  ip={ip:#018x}  inner at /src/fixture.rs:20 [debug-info]\n"
            )),
            "{out}"
        );
    }

    #[test]
    fn a_log_without_a_block_has_no_report()
    {
        assert_eq!(
            symbolize_log(
                "[1.0] [svctest] ALL TESTS PASSED\n",
                &Fixture::dwarf("x86_64")
            ),
            None
        );
    }

    #[test]
    fn a_log_name_is_searched_in_the_sysroot_directories_in_order()
    {
        assert_eq!(candidate_paths("fatfs /data")[0], "services/fatfs");
        assert_eq!(
            candidate_paths("crashme"),
            [
                "services/crashme",
                "services/drivers/crashme",
                "services/fs/crashme",
                "programs/crashme",
                "tests/crashme",
                "tests/drivers/crashme",
                "tests/programs/crashme",
            ]
        );
        for name in ["", ".", "..", "../kernel", "a/b", "a\\b"]
        {
            assert!(candidate_paths(name).is_empty(), "{name:?} names a path");
        }
    }

    #[test]
    fn an_unnamed_block_is_printed_with_its_badge_and_the_command_for_its_binary()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER;
        let frames = [ip, BIAS + LEAF + 9];
        let none = Fixture {
            arch: "x86_64",
            images: Vec::new(),
            list_error: false,
        };
        let out = symbolize_log(&log_of(&report(ip, &regs, &frames), None), &none).unwrap();
        assert!(out.contains("process unnamed (badge 42: logd has no registered name for it)"));
        assert!(out.contains(
            "\n  not symbolized: the process is unnamed, and no binary's text matches the block's\n"
        ));
        assert!(out.contains(&format!(
            "\n  with its binary: cargo xtask symbolize --binary <binary> --bias {BIAS:#x} {ip:#x} \
             {:#x}\n",
            BIAS + LEAF + 9
        )));
    }

    #[test]
    fn an_unattached_block_with_a_thread_crash_badge_names_no_process()
    {
        let ip = BIAS + INNER;
        let mut unattached = report(ip, &[], &[]);
        unattached.status = Status::Unattached;
        unattached.thread = Thread::Unidentified;
        unattached.image = None;
        unattached.badge = threads::CRASH_BADGE_TAG | 7;
        // crashme registered its log name; the reclaim line names its process
        // badge, which the block does not carry.
        let mut log = log_of(&unattached, None);
        log.push_str(&reclaim_line(
            42,
            Cause::Death {
                exit_reason: 0x100e,
            },
            "crashme",
        ));
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(
            out.starts_with(&format!(
                "crash report 00000000000000aa (format version 1): process unknown (thread crash \
                 badge {}: the attach failed, so the block names no process)\n",
                threads::CRASH_BADGE_TAG | 7
            )),
            "{out}"
        );
        assert!(!out.contains("process unnamed"), "{out}");
        assert!(!out.contains("defective block"), "{out}");
    }

    #[test]
    fn an_unnamed_block_resolves_against_the_one_binary_whose_text_matches()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER;
        let matching = segments_only(&[(R, 0, 0x100), (RX, OUTER, 0x200)]);
        let other = segments_only(&[(RX, OUTER, 0x1f0)]);
        let images = Fixture {
            arch: "x86_64",
            images: vec![
                ("programs/one", matching.clone()),
                ("programs/other", other),
            ],
            list_error: false,
        };
        let log = log_of(&report(ip, &regs, &[ip]), None);
        let out = symbolize_log(&log, &images).unwrap();
        assert!(
            out.contains(
                "\n  image: sysroot/programs/one (the one binary whose text matches the block's)\n"
            ),
            "{out}"
        );
        assert!(
            out.contains(&format!("\n  ip={ip:#018x}  ?? [unresolved]\n")),
            "{out}"
        );

        let twins = Fixture {
            arch: "x86_64",
            images: vec![("programs/one", matching.clone()), ("tests/two", matching)],
            list_error: false,
        };
        let out = symbolize_log(&log, &twins).unwrap();
        assert!(out.contains(
            "not symbolized: the process is unnamed, and the text of several binaries matches the \
             block's: programs/one, tests/two"
        ));
    }

    #[test]
    fn a_text_span_covers_every_executable_segment_and_no_other()
    {
        assert_eq!(
            text_span(&segments_only(&[
                (R, 0, 0x1000),
                (RX, 0x1000, 0x500),
                (RX, 0x3000, 0x10),
                (R, 0x5000, 0x100),
            ])),
            Some((0x1000, 0x3010))
        );
        assert_eq!(text_span(&segments_only(&[(R, 0, 0x1000)])), None);
        // An executable segment whose end wraps makes the image unusable.
        assert_eq!(
            text_span(&segments_only(&[
                (RX, 0x1000, 0x500),
                (RX, u64::MAX - 0xf, 0x20)
            ])),
            None
        );
        assert_eq!(text_span(b"not an ELF image"), None);
    }

    #[test]
    fn a_slot_logd_names_question_mark_is_unnamed_and_matched_by_its_text()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let log = log_of(&report(ip, &regs, &[ip]), Some(""));
        assert!(log.contains("name=?"), "{log}");
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(out.contains("process unnamed (badge 42: "), "{out}");
        assert!(out.contains(
            "\n  image: sysroot/programs/crashme (the one binary whose text matches the block's)\n"
        ));
    }

    #[test]
    fn a_resync_reclaim_line_names_its_process()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let mut log = log_of(&report(ip, &regs, &[ip]), None);
        log.push_str(&reclaim_line(42, Cause::Resync, "crashme"));
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(out.contains("): process crashme\n"), "{out}");
        assert!(
            out.contains("\n  image: sysroot/programs/crashme\n"),
            "{out}"
        );
    }

    #[test]
    fn a_name_with_an_instance_resolves_through_its_first_word()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let log = log_of(&report(ip, &regs, &[ip]), Some("crashme /data"));
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(out.contains("): process crashme /data\n"), "{out}");
        assert!(
            out.contains("\n  image: sysroot/programs/crashme\n"),
            "{out}"
        );
    }

    #[test]
    fn a_named_binary_whose_text_differs_from_the_blocks_is_refused()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER + 4;
        let rebuilt = Fixture::crashme("x86_64", segments_only(&[(RX, OUTER, 0x180)]));
        let out = symbolize_log(
            &log_of(&report(ip, &regs, &[ip]), Some("crashme")),
            &rebuilt,
        )
        .unwrap();
        assert!(
            out.contains(
                "\n  not symbolized: sysroot/programs/crashme's text spans 0x100-0x280, the \
                 block's 0x100-0x300: the binary is not the one that ran\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn an_image_listing_that_fails_is_reported_for_an_unnamed_block()
    {
        let regs = [0u64; 21];
        let ip = BIAS + INNER;
        let images = Fixture {
            list_error: true,
            ..Fixture::dwarf("x86_64")
        };
        let out = symbolize_log(&log_of(&report(ip, &regs, &[ip]), None), &images).unwrap();
        assert!(
            out.contains("\n  not symbolized: cannot list the images: denied\n"),
            "{out}"
        );
    }

    #[test]
    fn a_sysroot_reads_its_binaries_and_reports_what_it_cannot_read()
    {
        let root = std::env::temp_dir().join(format!("seraph-crash-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("programs")).unwrap();
        std::fs::create_dir_all(root.join("tests/programs/dir-not-file")).unwrap();
        std::fs::write(root.join("programs/crashme"), b"bytes").unwrap();
        std::fs::write(root.join(".arch"), "riscv64\n").unwrap();
        let images = SysrootImages {
            sysroot: root.clone(),
        };
        assert_eq!(images.arch(), Ok(Some("riscv64".to_owned())));
        assert_eq!(images.list(), Ok(vec!["programs/crashme".to_owned()]));
        assert_eq!(images.read("programs/crashme"), Ok(Some(b"bytes".to_vec())));
        assert_eq!(images.read("programs/absent"), Ok(None));
        assert!(images.read("tests/programs/dir-not-file").is_err());

        // A directory of the images that is a file, and an `.arch` that is a
        // directory, cannot be read: errors, not absences.
        std::fs::write(root.join("services"), b"").unwrap();
        assert!(images.list().is_err());
        std::fs::remove_file(root.join(".arch")).unwrap();
        std::fs::create_dir(root.join(".arch")).unwrap();
        assert!(images.arch().is_err());
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(images.arch(), Ok(None));
        assert_eq!(images.list(), Ok(Vec::new()));
    }

    #[test]
    fn reclaimed_names_read_both_line_forms_and_skip_unregistered_slots()
    {
        let log = [
            reclaim_line(1, Cause::Death { exit_reason: 0 }, "shell"),
            reclaim_line(2, Cause::Resync, "fatfs /data"),
            reclaim_line(3, Cause::Death { exit_reason: 0 }, ""),
            "[2.7] [hello] reclaim: badge=4 exit_reason=0x0 name=impostor\n".to_owned(),
            reclaim_line(5, Cause::Death { exit_reason: 0 }, "x badge=9 name=\"y\""),
        ]
        .concat();
        let names = reclaimed_names(&log);
        assert_eq!(names.len(), 3, "{names:?}");
        assert_eq!(names[&1], "shell");
        assert_eq!(names[&2], "fatfs /data");
        assert_eq!(names[&5], "x badge=9 name=\"y\"");
    }
}
