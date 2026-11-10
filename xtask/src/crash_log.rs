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

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use crash_report::Block;

use crate::symbolize::{Symbolizer, describe_resolution};

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

/// Where a block's image comes from.
pub trait ImageSource
{
    /// The architecture the images are built for, `None` when unknown.
    fn arch(&self) -> Option<String>;

    /// The image of the process logged as `name`: a label naming where it
    /// was found, and its bytes; `None` when there is none.
    fn find(&self, name: &str) -> Option<(String, Vec<u8>)>;
}

/// The images of a sysroot: the binary whose file name is the log name, in
/// the first of [`IMAGE_DIRS`] that holds one.
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

    fn find(&self, name: &str) -> Option<(String, Vec<u8>)>
    {
        candidate_paths(name).into_iter().find_map(|relative| {
            let bytes = std::fs::read(self.sysroot.join(&relative)).ok()?;
            Some((format!("sysroot/{relative}"), bytes))
        })
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
    let mut out = String::new();
    for block in &blocks
    {
        let name = block
            .get("badge")
            .and_then(|badge| badge.parse::<u64>().ok())
            .and_then(|badge| names.get(&badge));
        symbolize_block(
            &mut out,
            block,
            name.map(String::as_str),
            images,
            images_arch.as_deref(),
        );
    }
    Some(out)
}

/// Append `block`'s report to `out`: a header naming the block, its
/// process, and its image, then every field line as logged, with the
/// instruction pointer and each stack frame inside the image's text followed
/// by what it resolves to.
fn symbolize_block(
    out: &mut String,
    block: &Block,
    name: Option<&str>,
    images: &dyn ImageSource,
    images_arch: Option<&str>,
)
{
    let process = name.map_or_else(
        || "process unnamed (no logd reclaim line for its badge)".to_owned(),
        |name| format!("process {name}"),
    );
    let _ = writeln!(
        out,
        "crash report {:016x} (format version {}): {process}",
        block.id, block.version
    );
    if let Err(defect) = block.check()
    {
        let _ = writeln!(out, "  defective block ({defect:?}): fields as logged");
    }
    let image = match block_image(block, name, images, images_arch)
    {
        Ok((label, bytes)) =>
        {
            let _ = writeln!(out, "  image: {label}");
            Some(bytes)
        }
        Err(reason) =>
        {
            let _ = writeln!(out, "  not symbolized: {reason}");
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

/// The image of `block`'s process, or why there is none to symbolize with.
fn block_image(
    block: &Block,
    name: Option<&str>,
    images: &dyn ImageSource,
    images_arch: Option<&str>,
) -> Result<(String, Vec<u8>), String>
{
    let name = name.ok_or("the process is unnamed")?;
    if block.hex("load_bias").is_none() || text_range(block).is_none()
    {
        return Err("the block carries no load bias and text range".to_owned());
    }
    if let (Some(block_arch), Some(images_arch)) = (block.get("arch"), images_arch)
        && block_arch != images_arch
    {
        return Err(format!(
            "the block is {block_arch}, the images are built for {images_arch}"
        ));
    }
    images
        .find(name)
        .ok_or_else(|| format!("no binary named {name} in the images"))
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

    /// Images of one architecture, holding `image` as `crashme`.
    struct Fixture
    {
        arch: &'static str,
        image: Vec<u8>,
    }

    impl Fixture
    {
        /// The DWARF fixture, as images built for `arch`.
        fn dwarf(arch: &'static str) -> Self
        {
            Fixture {
                arch,
                image: fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf),
            }
        }
    }

    impl ImageSource for Fixture
    {
        fn arch(&self) -> Option<String>
        {
            Some(self.arch.to_owned())
        }

        fn find(&self, name: &str) -> Option<(String, Vec<u8>)>
        {
            (name == "crashme").then(|| ("fixture/crashme".to_owned(), self.image.clone()))
        }
    }

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
        assert!(out.contains("\n  image: fixture/crashme\n"));
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
            (None, "x86_64", "not symbolized: the process is unnamed"),
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
        let images = Fixture {
            arch: "x86_64",
            image: fixture(Architecture::X86_64, USER_BASE, Debug::SymbolsOnly),
        };
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
        let not_elf = Fixture {
            arch: "x86_64",
            image: b"not an ELF image".to_vec(),
        };
        let out = symbolize_log(&log, &not_elf).unwrap();
        assert!(
            out.contains("\n  not symbolized: not an ELF image"),
            "{out}"
        );
        assert!(out.contains(&format!("\n  ip={ip:#018x}\n")));
        // `inner`'s entry gets an abbreviation code the table lacks, so the
        // image loads but the resolution fails.
        let broken = Fixture {
            arch: "x86_64",
            image: fixture_with_section(".debug_info", 0, |mut data| {
                let name = data
                    .windows(6)
                    .position(|bytes| bytes == b"inner\0")
                    .expect("inner's name in .debug_info");
                data[name - 1] = 0x7f;
                data
            }),
        };
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
}
