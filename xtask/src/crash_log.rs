// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/crash_log.rs

//! Symbolized crash reports from a serial log.
//!
//! The crash service logs one block per faulting process
//! (services/crashd/docs/block-format.md), read here with
//! `shared/crash-report`'s parser. Each block names its process by badge
//! only; logd's `reclaim:` line for that badge gives the process's log name,
//! and the image is the sysroot binary of that file name. Each address in
//! the block's text is then the image address `address - load_bias`, which
//! [`crate::symbolize`] resolves.

use std::cell::OnceCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use crash_report::Block;

use crate::symbolize::{Symbolizer, describe_resolution, text_span};

/// The start of logd's death-drain reclaim line after its timestamp
/// (services/logd/docs/ipc-interface.md § Death-notification cascade).
const RECLAIM_TAG: &str = "[logd] reclaim: badge=";

/// The sysroot directories searched, in this order, for the binary a log
/// name names: the boot modules and services, the drivers, the filesystem
/// drivers, the programs, the harnesses, and the per-program testers (last,
/// since a tester installs under its program's name).
const IMAGE_DIRS: [&str; 6] = [
    "services",
    "services/drivers",
    "services/fs",
    "programs",
    "tests",
    "tests/programs",
];

/// The badge and log name of each `[logd] reclaim:` line of `log`.
pub fn reclaimed_names(log: &str) -> HashMap<u64, String>
{
    let mut names = HashMap::new();
    for line in log.lines()
    {
        let Some(at) = line.find(RECLAIM_TAG)
        else
        {
            continue;
        };
        let rest = &line[at + RECLAIM_TAG.len()..];
        let Some((badge, rest)) = rest.split_once(' ')
        else
        {
            continue;
        };
        let Some((_, name)) = rest.split_once(" name=")
        else
        {
            continue;
        };
        if let Ok(badge) = badge.parse()
        {
            names.insert(badge, name.trim_end_matches('\r').to_string());
        }
    }
    names
}

/// Where a block's image comes from: a set of binaries, each named by its
/// path relative to the image root.
pub trait ImageSource
{
    /// The architecture the images are built for, `None` when unknown.
    fn arch(&self) -> Option<String>;

    /// Every binary's relative path.
    fn list(&self) -> Vec<String>;

    /// The bytes of the binary at `relative`, `None` when there is none.
    fn read(&self, relative: &str) -> Option<Vec<u8>>;
}

/// The images of a sysroot: the files of [`IMAGE_DIRS`].
pub struct SysrootImages
{
    pub sysroot: PathBuf,
}

impl ImageSource for SysrootImages
{
    fn arch(&self) -> Option<String>
    {
        let tag = std::fs::read_to_string(self.sysroot.join(".arch")).ok()?;
        Some(tag.trim().to_owned())
    }

    fn list(&self) -> Vec<String>
    {
        let mut paths = Vec::new();
        for dir in IMAGE_DIRS
        {
            let Ok(entries) = std::fs::read_dir(self.sysroot.join(dir))
            else
            {
                continue;
            };
            for entry in entries.flatten()
            {
                let is_file = entry.file_type().is_ok_and(|kind| kind.is_file());
                if let (true, Some(name)) = (is_file, entry.file_name().to_str())
                {
                    paths.push(format!("{dir}/{name}"));
                }
            }
        }
        paths.sort();
        paths
    }

    fn read(&self, relative: &str) -> Option<Vec<u8>>
    {
        std::fs::read(self.sysroot.join(relative)).ok()
    }
}

/// The sysroot-relative paths a binary logged as `name` may have, in search
/// order; none for a name that is not a single path component.
fn candidate_paths(name: &str) -> Vec<String>
{
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".."
    {
        return Vec::new();
    }
    IMAGE_DIRS
        .iter()
        .map(|dir| format!("{dir}/{name}"))
        .collect()
}

/// The unbiased text span of each image of `images`, computed once per log
/// and only for a log with an unnamed block.
struct Spans<'a>
{
    images: &'a dyn ImageSource,
    spans: OnceCell<Vec<(String, (u64, u64))>>,
}

impl Spans<'_>
{
    /// The images whose executable segments span exactly `span`.
    fn matching(&self, span: (u64, u64)) -> Vec<&str>
    {
        self.spans
            .get_or_init(|| {
                self.images
                    .list()
                    .into_iter()
                    .filter_map(|relative| {
                        let span = text_span(&self.images.read(&relative)?)?;
                        Some((relative, span))
                    })
                    .collect()
            })
            .iter()
            .filter(|(_, image_span)| *image_span == span)
            .map(|(relative, _)| relative.as_str())
            .collect()
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
            images_arch: images_arch.as_deref(),
            spans: &spans,
        };
        symbolize_block(&mut out, block, &source);
    }
    Some(out)
}

/// What a block's image is looked up with.
struct BlockSource<'a>
{
    /// The process's log name, from logd's reclaim line for its badge.
    name: Option<&'a str>,
    images: &'a dyn ImageSource,
    images_arch: Option<&'a str>,
    spans: &'a Spans<'a>,
}

/// Append `block`'s report to `out`: a header naming the block, its
/// process, and its image, then every field line as logged, with the
/// instruction pointer and each stack frame inside the image's text followed
/// by what it resolves to.
fn symbolize_block(out: &mut String, block: &Block, source: &BlockSource<'_>)
{
    let process = match source.name
    {
        Some(name) => format!("process {name}"),
        None => format!(
            "process unnamed (badge {}: no logd reclaim line carries it)",
            block.get("badge").unwrap_or("absent")
        ),
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
    let image = match block_image(block, source)
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
    };
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
    for (key, value) in block.fields()
    {
        match resolver.as_ref().and_then(|r| r.resolve(key, value))
        {
            Some(lines) =>
            {
                let _ = writeln!(out, "  {key}={value}  {}", lines[0]);
                for line in &lines[1..]
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
    let _ = writeln!(out, "end {:016x}", block.id);
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
/// binary of its name in [`IMAGE_DIRS`]; an unnamed one's is the one binary
/// whose executable segments span exactly the block's `text` less its
/// `load_bias`, never a guess among several.
fn block_image(block: &Block, source: &BlockSource<'_>) -> Result<(String, Vec<u8>), String>
{
    let (Some(load_bias), Some((text_start, text_end))) =
        (block.hex("load_bias"), text_range(block))
    else
    {
        return Err("the block carries no load bias and text range".to_owned());
    };
    if let (Some(block_arch), Some(images_arch)) = (block.get("arch"), source.images_arch)
        && block_arch != images_arch
    {
        return Err(format!(
            "the block is {block_arch}, the images are built for {images_arch}"
        ));
    }
    if let Some(name) = source.name
    {
        return candidate_paths(name)
            .into_iter()
            .find_map(|relative| {
                let bytes = source.images.read(&relative)?;
                Some((format!("sysroot/{relative}"), bytes))
            })
            .ok_or_else(|| format!("no binary named {name} in the images"));
    }
    let span = (
        text_start.wrapping_sub(load_bias),
        text_end.wrapping_sub(load_bias),
    );
    match source.spans.matching(span).as_slice()
    {
        [] => Err("the process is unnamed, and no binary's text matches the block's".to_owned()),
        [relative] => source
            .images
            .read(relative)
            .map(|bytes| {
                (
                    format!("sysroot/{relative} (the one binary whose text matches the block's)"),
                    bytes,
                )
            })
            .ok_or_else(|| format!("cannot read {relative}")),
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
    /// text resolves to nothing.
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

    /// Images of one architecture, by relative path.
    struct Fixture
    {
        arch: &'static str,
        images: Vec<(&'static str, Vec<u8>)>,
    }

    impl Fixture
    {
        /// `image` as `programs/crashme`, built for `arch`.
        fn crashme(arch: &'static str, image: Vec<u8>) -> Self
        {
            Fixture {
                arch,
                images: vec![("programs/crashme", image)],
            }
        }

        /// The DWARF fixture as `programs/crashme`, built for `arch`.
        fn dwarf(arch: &'static str) -> Self
        {
            Self::crashme(arch, fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf))
        }
    }

    impl ImageSource for Fixture
    {
        fn arch(&self) -> Option<String>
        {
            Some(self.arch.to_owned())
        }

        fn list(&self) -> Vec<String>
        {
            self.images
                .iter()
                .map(|(path, _)| (*path).to_owned())
                .collect()
        }

        fn read(&self, relative: &str) -> Option<Vec<u8>>
        {
            self.images
                .iter()
                .find(|(path, _)| *path == relative)
                .map(|(_, bytes)| bytes.clone())
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

    /// The serial lines of `report`'s block as logd prints crashd's lines,
    /// and, when `name` is given, logd's reclaim line naming the process.
    fn log_of(report: &Report<'_>, name: Option<&str>) -> String
    {
        let mut log = String::new();
        report.emit(|line| log.push_str(&format!("[2.5] [crashd] {line}\r\n")));
        if let Some(name) = name
        {
            log.push_str(&format!(
                "[2.6] [logd] reclaim: badge={} exit_reason=0x100e name={name}\r\n",
                report.badge
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
                None,
                "x86_64",
                "not symbolized: the process is unnamed, and no binary's text matches the block's",
            ),
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
            fixture(Architecture::X86_64, USER_BASE, Debug::SymbolsOnly),
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
            out.contains("\n  not symbolized: not an ELF image"),
            "{out}"
        );
        assert!(out.contains(&format!("\n  ip={ip:#018x}\n")));
        // `inner`'s entry gets an abbreviation code the table lacks, so the
        // image loads but the resolution fails.
        let broken = Fixture::crashme(
            "x86_64",
            fixture_with_section(".debug_info", 0, |mut data| {
                let name = data
                    .windows(6)
                    .position(|bytes| bytes == b"inner\0")
                    .expect("inner's name in .debug_info");
                data[name - 1] = 0x7f;
                data
            }),
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
            .replace("thread=main", "thread=spawned");
        let out = symbolize_log(&log, &Fixture::dwarf("x86_64")).unwrap();
        assert!(out.contains("\n  thread=spawned\n"), "{out}");
        assert!(
            out.contains(&format!("\n  ip={ip:#018x}  inner at /src/fixture.rs:20 [debug-info]\n")),
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
        assert_eq!(
            candidate_paths("crashme"),
            [
                "services/crashme",
                "services/drivers/crashme",
                "services/fs/crashme",
                "programs/crashme",
                "tests/crashme",
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
        let out = symbolize_log(
            &log_of(&report(ip, &regs, &frames), None),
            &Fixture::dwarf("x86_64"),
        )
        .unwrap();
        assert!(out.contains("process unnamed (badge 42: no logd reclaim line carries it)"));
        assert!(out.contains(&format!(
            "\n  with its binary: cargo xtask symbolize --binary <binary> --bias {BIAS:#x} {ip:#x} \
             {:#x}\n",
            BIAS + LEAF + 9
        )));
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
        assert_eq!(text_span(b"not an ELF image"), None);
    }
}
