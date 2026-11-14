// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/compare_images.rs

//! `compare-images`: whether two commits build the same images, compared in
//! every part a loader reads (`docs/testing.md` § Coverage tiers, Inert
//! changes).
//!
//! Both commits are built in one scratch worktree, by that commit's own
//! `cargo xtask clean` and `cargo xtask build`, once per architecture and
//! profile, and each built sysroot is moved beside it, in the same scratch
//! directory; only the report is written to `target/xtask/compare-images/`.
//! One path serves both sides because a build embeds absolute source paths
//! (the panic locations of the `-Z build-std` crates under
//! `target/seraph-toolchain/`), so two checkouts at different paths never
//! build equal images. The scratch worktree's `target/` is a cache that later
//! builds reuse. A repository has one scratch directory, which every checkout
//! of it shares and one run at a time holds (`scratch_path`, `lock_scratch`).
//!
//! Each build is the commit's own: the scratch worktree lies in the user's
//! cache directory, outside the checkout, whose
//! `.cargo/config.toml` Cargo would otherwise merge into both builds, and each
//! nested `cargo xtask` runs without the variables the outer `cargo run` set
//! (`removed_variables`), among them `RUSTUP_TOOLCHAIN`, which would pin both
//! to the outer checkout's toolchain, and the `[env]` table's
//! `RUST_TARGET_PATH`, which would pin both to its target specifications.
//!
//! Every file the build installs is compared by the parts of it a loader
//! reads (`image_parts`): an ELF image by its loader-relevant header fields,
//! its program headers and the bytes of its `PT_LOAD` segments, and its
//! allocated and note sections; a PE image by its headers and sections, the
//! link time stamps and the debug directory masked; the bootloader bundle by
//! its entries; any other file by its bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use boot_protocol::bundle as bundle_fmt;
use object::Endianness;
use object::elf::{FileHeader64, PT_LOAD, SHF_ALLOC, SHT_NOTE};
use object::read::elf::{FileHeader as _, ProgramHeader as _, SectionHeader as _};
use object::read::pe::PeFile64;

use crate::arch::Arch;
use crate::cli::CompareImagesArgs;
use crate::context::{Context as BuildContext, Profile};
use crate::util::{run_cmd, run_cmd_capture, step};

/// Bytes of the ELF64 file header. A `PT_LOAD` segment that starts at file
/// offset 0 maps it; its section-table fields (`e_shoff`, `e_shnum`,
/// `e_shstrndx`) locate data no loader maps, so the segment's bytes are
/// compared from past it, and the fields a loader reads are compared apart.
const ELF64_HEADER_BYTES: u64 = 64;

/// The ELF identification bytes.
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// The DOS header's magic, which opens a PE image.
const PE_DOS_MAGIC: &[u8] = b"MZ";

/// Offset of `e_lfanew`, the PE signature's offset, in the DOS header.
const PE_LFANEW_OFFSET: usize = 0x3c;

/// Offset of the COFF header's `TimeDateStamp` from the PE signature: the
/// signature (4 bytes), `Machine` (2), and `NumberOfSections` (2).
const PE_TIME_STAMP_OFFSET: usize = 8;

/// Offset of the optional header's `CheckSum` from the PE signature: the
/// signature (4), the COFF header (20), and 64 bytes of the optional header.
const PE_CHECKSUM_OFFSET: usize = 88;

/// Index of the debug directory among a PE image's data directories.
const PE_DEBUG_DIRECTORY: usize = 6;

/// Bytes of one PE debug directory entry (`IMAGE_DEBUG_DIRECTORY`).
const PE_DEBUG_ENTRY_BYTES: usize = 28;

/// Offset of `SizeOfData` in a PE debug directory entry; `AddressOfRawData`
/// follows it.
const PE_DEBUG_SIZE_OFFSET: usize = 16;

/// The name a file's part takes when the file is compared by its bytes.
const CONTENTS: &str = "contents";

// ── Image parts ───────────────────────────────────────────────────────────────

/// One compared part of an image: a name the report gives it, and the bytes
/// that stand for it, its loader-relevant fields included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part
{
    pub name: String,
    pub bytes: Vec<u8>,
}

impl Part
{
    fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self
    {
        Self {
            name: name.into(),
            bytes,
        }
    }
}

/// The parts of the file `data` that a loader reads, by its format: an ELF,
/// a PE, or a bootloader bundle; any other file, or one whose headers do
/// not parse, is one part, its bytes.
pub fn image_parts(data: &[u8]) -> Vec<Part>
{
    let parsed = if data.starts_with(ELF_MAGIC)
    {
        elf_parts(data)
    }
    else if data.starts_with(PE_DOS_MAGIC)
    {
        pe_parts(data)
    }
    else if data.starts_with(&bundle_fmt::MAGIC)
    {
        bundle_parts(data)
    }
    else
    {
        None
    };
    parsed.unwrap_or_else(|| vec![Part::new(CONTENTS, data.to_vec())])
}

/// An ELF64 image's parts: the header fields a loader reads, each program
/// header with the bytes of a `PT_LOAD` segment, and each section that is
/// allocated or is a note (the system's loaders read `.note.seraph.*` by
/// name through the section table, `shared/elf`'s note locator).
fn elf_parts(data: &[u8]) -> Option<Vec<Part>>
{
    let header = FileHeader64::<Endianness>::parse(data).ok()?;
    let endian = header.endian().ok()?;
    let mut parts = vec![Part::new(
        "ELF header",
        format!(
            "type {:#x} machine {:#x} flags {:#x} entry {:#x}",
            header.e_type(endian),
            header.e_machine(endian),
            header.e_flags(endian),
            header.e_entry(endian)
        )
        .into_bytes(),
    )];
    for (index, segment) in header
        .program_headers(endian, data)
        .ok()?
        .iter()
        .enumerate()
    {
        let mut bytes = format!(
            "type {:#x} flags {:#x} vaddr {:#x} paddr {:#x} filesz {:#x} memsz {:#x} align {:#x}\n",
            segment.p_type(endian),
            segment.p_flags(endian),
            segment.p_vaddr(endian),
            segment.p_paddr(endian),
            segment.p_filesz(endian),
            segment.p_memsz(endian),
            segment.p_align(endian)
        )
        .into_bytes();
        if segment.p_type(endian) == PT_LOAD
        {
            let file = segment.data(endian, data).ok()?;
            let skip = ELF64_HEADER_BYTES.saturating_sub(segment.p_offset(endian));
            bytes.extend_from_slice(file.get(usize::try_from(skip).ok()?..).unwrap_or_default());
        }
        parts.push(Part::new(format!("segment {index}"), bytes));
    }
    let sections = header.sections(endian, data).ok()?;
    for section in sections.iter()
    {
        let flags = section.sh_flags(endian);
        let kind = section.sh_type(endian);
        if !flags.contains(SHF_ALLOC) && kind != SHT_NOTE
        {
            continue;
        }
        let name = sections.section_name(endian, section).ok()?;
        let mut bytes = format!(
            "type {kind:#x} flags {flags:#x} addr {:#x} size {:#x}\n",
            section.sh_addr(endian),
            section.sh_size(endian)
        )
        .into_bytes();
        bytes.extend_from_slice(section.data(endian, data).ok()?);
        parts.push(Part::new(String::from_utf8_lossy(name), bytes));
    }
    Some(parts)
}

/// A PE32+ image's parts: its headers, with the COFF header's link time
/// stamp and the optional header's checksum masked, and each section, with
/// the debug directory and the data its entries point to masked. The linker
/// writes the time of the link into the time stamps; no UEFI loader checks
/// the checksum or reads the debug directory, and no code reads its own.
fn pe_parts(data: &[u8]) -> Option<Vec<Part>>
{
    let file = PeFile64::parse(data).ok()?;
    let header_bytes = usize::try_from(
        file.nt_headers()
            .optional_header
            .size_of_headers
            .get(object::LittleEndian),
    )
    .ok()?;
    let signature = usize::try_from(read_u32(data, PE_LFANEW_OFFSET)?).ok()?;
    let mut headers = data.get(..header_bytes)?.to_vec();
    for offset in [PE_TIME_STAMP_OFFSET, PE_CHECKSUM_OFFSET]
    {
        let at = signature.checked_add(offset)?;
        zero(&mut headers, at, 4);
    }
    let mut parts = vec![Part::new("PE headers", headers)];
    let masks = pe_debug_masks(&file, data)?;
    for section in file.section_table().iter()
    {
        let address = section.virtual_address.get(object::LittleEndian);
        let mut bytes = section.pe_data(data).ok()?.to_vec();
        for &(start, length) in &masks
        {
            mask_range(&mut bytes, address, start, length);
        }
        let name = section.raw_name();
        let name = name.split(|&b| b == 0).next().unwrap_or(name);
        parts.push(Part::new(
            format!("section {}", String::from_utf8_lossy(name)),
            bytes,
        ));
    }
    Some(parts)
}

/// The address ranges, as (RVA, length), of a PE image's debug directory and
/// of the data each of its entries points to; none when it has none.
fn pe_debug_masks(file: &PeFile64<'_>, data: &[u8]) -> Option<Vec<(u32, u32)>>
{
    let Some(directory) = file.data_directory(PE_DEBUG_DIRECTORY)
    else
    {
        return Some(Vec::new());
    };
    let address = directory.virtual_address.get(object::LittleEndian);
    let size = directory.size.get(object::LittleEndian);
    if address == 0 || size == 0
    {
        return Some(Vec::new());
    }
    let mut masks = vec![(address, size)];
    let entries = file.section_table().pe_data_at(data, address)?;
    let entries = entries.get(..usize::try_from(size).ok()?)?;
    for entry in entries.as_chunks::<PE_DEBUG_ENTRY_BYTES>().0
    {
        let length = read_u32(entry, PE_DEBUG_SIZE_OFFSET)?;
        let start = read_u32(entry, PE_DEBUG_SIZE_OFFSET.checked_add(4)?)?;
        masks.push((start, length));
    }
    Some(masks)
}

/// Zero, in `bytes` that are mapped at the RVA `base`, the part of the range
/// of `length` bytes at the RVA `start` that they hold.
fn mask_range(bytes: &mut [u8], base: u32, start: u32, length: u32)
{
    let (base, start, length) = (u64::from(base), u64::from(start), u64::from(length));
    let end = start.saturating_add(length);
    let from = start.max(base).saturating_sub(base);
    let to = end.saturating_sub(base);
    if let (Ok(from), Ok(to)) = (usize::try_from(from), usize::try_from(to))
        && from < to
    {
        let to = to.min(bytes.len());
        if let Some(range) = bytes.get_mut(from..to)
        {
            range.fill(0);
        }
    }
}

/// Zero `length` bytes of `bytes` at `at`, those of them that it holds.
fn zero(bytes: &mut [u8], at: usize, length: usize)
{
    let end = at.saturating_add(length).min(bytes.len());
    if let Some(range) = bytes.get_mut(at..end)
    {
        range.fill(0);
    }
}

/// The little-endian `u32` at `at` in `bytes`.
fn read_u32(bytes: &[u8], at: usize) -> Option<u32>
{
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

/// The little-endian `u64` at `at` in `bytes`.
fn read_u64(bytes: &[u8], at: usize) -> Option<u64>
{
    let raw = bytes.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(raw.try_into().ok()?))
}

/// A bootloader bundle's parts (`boot_protocol::bundle`): its header, the
/// names of its entries in order, and each entry's parts, named after the
/// entry. An entry's offset and size are not compared: they move with bytes
/// of the entries that no loader maps.
fn bundle_parts(data: &[u8]) -> Option<Vec<Part>>
{
    let version = read_u32(data, bundle_fmt::MAGIC.len())?;
    let count = read_u32(data, bundle_fmt::MAGIC.len().checked_add(4)?)?;
    let mut parts = vec![Part::new(
        "bundle header",
        format!("version {version} entries {count}").into_bytes(),
    )];
    let mut names = Vec::new();
    for index in 0..usize::try_from(count).ok()?
    {
        let at = index
            .checked_mul(bundle_fmt::ENTRY_HEADER_SIZE)?
            .checked_add(bundle_fmt::HEADER_SIZE)?;
        let raw_name = data.get(at..at.checked_add(bundle_fmt::ENTRY_NAME_LEN)?)?;
        let name = raw_name.split(|&b| b == 0).next().unwrap_or(raw_name);
        let name = String::from_utf8_lossy(name).into_owned();
        let offset = read_u64(data, at.checked_add(bundle_fmt::ENTRY_NAME_LEN)?)?;
        let size = read_u64(
            data,
            at.checked_add(bundle_fmt::ENTRY_NAME_LEN)?.checked_add(8)?,
        )?;
        let start = usize::try_from(offset).ok()?;
        let body = data.get(start..start.checked_add(usize::try_from(size).ok()?)?)?;
        parts.extend(
            image_parts(body)
                .into_iter()
                .map(|part| Part::new(format!("entry {name}: {}", part.name), part.bytes)),
        );
        names.push(name);
    }
    parts.push(Part::new("bundle entries", names.join(",").into_bytes()));
    Some(parts)
}

// ── Comparison ────────────────────────────────────────────────────────────────

/// The names of the parts that differ between two images' parts: a part in
/// both with other bytes, and a part on one side only, marked `(removed)` or
/// `(added)`. A name a file repeats takes ` #2`, ` #3`, ... from its second
/// occurrence, so each occurrence is compared with its counterpart.
pub fn part_differences(base: &[Part], head: &[Part]) -> Vec<String>
{
    let base = keyed(base);
    let head = keyed(head);
    let head_parts: BTreeMap<&str, &[u8]> = head.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let base_names: BTreeSet<&str> = base.iter().map(|(n, _)| n.as_str()).collect();
    let mut out = Vec::new();
    for (name, bytes) in &base
    {
        match head_parts.get(name.as_str())
        {
            Some(other) if other == bytes =>
            {}
            Some(_) => out.push(name.clone()),
            None => out.push(format!("{name} (removed)")),
        }
    }
    out.extend(
        head.iter()
            .filter(|(name, _)| !base_names.contains(name.as_str()))
            .map(|(name, _)| format!("{name} (added)")),
    );
    out
}

/// Parts keyed by a name unique within the image, in their order.
fn keyed(parts: &[Part]) -> Vec<(String, &[u8])>
{
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    parts
        .iter()
        .map(|part| {
            let count = seen.entry(part.name.as_str()).or_insert(0);
            *count = count.saturating_add(1);
            let name = if *count == 1
            {
                part.name.clone()
            }
            else
            {
                format!("{} #{count}", part.name)
            };
            (name, part.bytes.as_slice())
        })
        .collect()
}

/// Where a file of a cell's two sysroots is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presence
{
    /// In both sysroots.
    Both(String),
    /// In the base's sysroot only.
    Base(String),
    /// In the head's sysroot only.
    Head(String),
}

/// Pair the files of two sysroots by their relative path, in path order.
pub fn pair_paths(base: &[String], head: &[String]) -> Vec<Presence>
{
    let base_set: BTreeSet<&String> = base.iter().collect();
    let head_set: BTreeSet<&String> = head.iter().collect();
    base_set
        .union(&head_set)
        .map(
            |path| match (base_set.contains(path), head_set.contains(path))
            {
                (true, true) => Presence::Both((*path).clone()),
                (true, false) => Presence::Base((*path).clone()),
                (false, _) => Presence::Head((*path).clone()),
            },
        )
        .collect()
}

/// One architecture and profile the comparison builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell
{
    pub arch: Arch,
    pub profile: Profile,
}

impl Cell
{
    /// The cell's label: `<arch>-<profile>`, which also names its sysroot
    /// copies.
    pub fn label(self) -> String
    {
        format!("{}-{}", self.arch, self.profile.dir_name())
    }
}

/// What the comparison found in one cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellReport
{
    pub cell: Cell,
    /// The number of files compared, both sides counted once.
    pub files: usize,
    /// Each difference, as `<path>: <part>`.
    pub differences: Vec<String>,
}

/// The report: one block per cell, then the verdict line, which names the two
/// commits and every cell compared.
pub fn render(base: &str, head: &str, reports: &[CellReport]) -> String
{
    let mut out = String::new();
    let mut total = 0usize;
    for report in reports
    {
        let count = report.differences.len();
        total = total.saturating_add(count);
        let _ = writeln!(
            out,
            "{}: {} files, {}",
            report.cell.label(),
            report.files,
            if count == 0
            {
                String::from("identical")
            }
            else
            {
                format!("{count} differences")
            }
        );
        for difference in &report.differences
        {
            let _ = writeln!(out, "  {difference}");
        }
    }
    let cells: Vec<String> = reports.iter().map(|r| r.cell.label()).collect();
    let verdict = if total == 0
    {
        String::from("IDENTICAL")
    }
    else
    {
        format!("DIFFERENT ({total})")
    };
    let _ = writeln!(
        out,
        "compare-images: {verdict} base {base} head {head} cells {}",
        cells.join(",")
    );
    out
}

// ── Building ──────────────────────────────────────────────────────────────────

/// Which commit a sysroot was built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side
{
    Base,
    Head,
}

impl Side
{
    fn dir_name(self) -> &'static str
    {
        match self
        {
            Self::Base => "base",
            Self::Head => "head",
        }
    }
}

/// Run `git` in `dir` and return its trimmed output.
fn git(dir: &Path, args: &[&str]) -> Result<String>
{
    let out = run_cmd_capture(Command::new("git").current_dir(dir).args(args))
        .with_context(|| format!("git {}", args.join(" ")))?;
    Ok(out.trim().to_owned())
}

/// How each nested `cargo xtask` runs: the host wait it passes on, and the
/// variables it removes from the environment it inherits.
struct Nested
{
    wait_host: Option<u64>,
    removed: Vec<String>,
}

/// Run `cargo xtask <args>` in the scratch worktree, as a shell in it would:
/// with none of the variables the outer `cargo run` set, so that the
/// commit's own toolchain, target specifications, and Cargo configuration
/// build it.
fn xtask(tree: &Path, args: &[&str], nested: &Nested) -> Result<()>
{
    let mut cmd = Command::new("cargo");
    cmd.current_dir(tree).arg("xtask").args(args);
    if let Some(secs) = nested.wait_host
    {
        cmd.arg("--wait-host").arg(secs.to_string());
    }
    for name in &nested.removed
    {
        cmd.env_remove(name);
    }
    run_cmd(&mut cmd)
}

/// Whether the variable `name` of `cargo xtask`'s environment is one that
/// `cargo run` or the rustup proxy sets for the program it runs, rather than
/// one of the user's: `CARGO` and every `CARGO_*` but `CARGO_HOME` (the
/// target directory among them), `RUSTUP_TOOLCHAIN`, which outranks a
/// commit's own `rust-toolchain.toml`, and the proxy's `RUST_RECURSION_COUNT`.
fn set_by_cargo_run(name: &str) -> bool
{
    name == "CARGO"
        || (name.starts_with("CARGO_") && name != "CARGO_HOME")
        || name == "RUSTUP_TOOLCHAIN"
        || name == "RUST_RECURSION_COUNT"
}

/// The variables the `[env]` table of a Cargo configuration file sets, as
/// `NAME = ...` keys of `[env]` or as `[env.NAME]` tables. Cargo sets them
/// for the program `cargo run` runs, and a nested Cargo does not replace a
/// variable already set, so each would override the commit's own value.
fn config_env_keys(text: &str) -> Vec<String>
{
    let unquote = |name: &str| name.trim().trim_matches('"').to_owned();
    let mut keys = Vec::new();
    let mut in_env = false;
    for line in text.lines().map(str::trim)
    {
        if line.starts_with('#')
        {
            continue;
        }
        if let Some(header) = line.strip_prefix('[')
        {
            let header = header
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("");
            let header = header.trim();
            in_env = header == "env";
            if let Some(name) = header.strip_prefix("env.")
            {
                keys.push(unquote(name));
            }
            continue;
        }
        if in_env && let Some((key, _)) = line.split_once('=')
        {
            let name = key.split('.').next().unwrap_or(key);
            if !name.trim().is_empty()
            {
                keys.push(unquote(name));
            }
        }
    }
    keys
}

/// The Cargo configuration files in the `.cargo` directory `dot_cargo`.
fn configs_in(dot_cargo: &Path) -> Vec<PathBuf>
{
    ["config.toml", "config"]
        .into_iter()
        .map(|name| dot_cargo.join(name))
        .filter(|path| path.is_file())
        .collect()
}

/// Cargo's home directory: `CARGO_HOME`, or `.cargo` in the user's home.
fn cargo_home() -> Option<PathBuf>
{
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|home| home.join(".cargo")))
}

/// The variables to remove from each nested build's environment: those
/// `set_by_cargo_run` names, and those the `[env]` tables of the Cargo
/// configuration files the outer `cargo xtask` read set (`root`'s and its
/// ancestors', and Cargo's home's).
fn removed_variables(root: &Path) -> Vec<String>
{
    let mut configs: Vec<PathBuf> = root
        .ancestors()
        .flat_map(|dir| configs_in(&dir.join(".cargo")))
        .collect();
    configs.extend(cargo_home().into_iter().flat_map(|home| configs_in(&home)));
    let mut names: BTreeSet<String> = configs
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .flat_map(|text| config_env_keys(&text))
        .collect();
    names.extend(
        std::env::vars_os()
            .filter_map(|(name, _)| name.into_string().ok())
            .filter(|name| set_by_cargo_run(name)),
    );
    names.into_iter().collect()
}

/// The scratch directory of the repository whose git common directory is
/// `common`, in the user's cache directory `cache`: one per repository, so
/// that every checkout of it shares one scratch worktree and its build
/// cache, and outside every checkout, whose Cargo configuration a build in a
/// directory below it would merge with the commit's own. The name keeps each
/// ASCII letter, digit, `.` and `_` of the path and writes every other byte
/// as `-` and two hex digits, so two paths never share a name.
fn scratch_path(cache: &Path, common: &Path) -> PathBuf
{
    let mut name = String::new();
    for byte in common.to_string_lossy().bytes()
    {
        if byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_'
        {
            name.push(char::from(byte));
        }
        else
        {
            let _ = write!(name, "-{byte:02x}");
        }
    }
    cache.join("seraph-compare-images").join(name)
}

/// How often a run waiting for the scratch lock tries it again and reads the
/// interrupt flag.
const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Hold the scratch directory `scratch` for this run: one run at a time uses
/// a repository's scratch worktree, and a second waits for the first, trying
/// the lock every [`LOCK_POLL`] and ending the wait once `interrupted`
/// reports Ctrl+C (`crate::term::signal::interrupted`), which a blocking
/// lock would not see.
fn lock_scratch(scratch: &Path, interrupted: &dyn Fn() -> bool) -> Result<fs::File>
{
    fs::create_dir_all(scratch).with_context(|| format!("creating {}", scratch.display()))?;
    let path = scratch.join("lock");
    let file = fs::File::create(&path).with_context(|| format!("opening {}", path.display()))?;
    let mut announced = false;
    loop
    {
        match file.try_lock()
        {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) =>
            {}
            Err(fs::TryLockError::Error(error)) =>
            {
                return Err(error).with_context(|| format!("locking {}", path.display()));
            }
        }
        if interrupted()
        {
            bail!("interrupted while waiting for another run to release the scratch worktree");
        }
        if !announced
        {
            step("compare-images: waiting for another run to release the scratch worktree");
            announced = true;
        }
        std::thread::sleep(LOCK_POLL);
    }
}

/// The user's cache directory: `XDG_CACHE_HOME`, `.cache` in the home
/// directory, or `LOCALAPPDATA` on Windows.
fn cache_dir() -> Result<PathBuf>
{
    let absolute = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    absolute("XDG_CACHE_HOME")
        .or_else(|| std::env::home_dir().map(|home| home.join(".cache")))
        .or_else(|| absolute("LOCALAPPDATA"))
        .context("no cache directory: set XDG_CACHE_HOME")
}

/// The Cargo configuration files of the directories above `tree`, which a
/// build in it would merge with the commit's own, but for Cargo's home
/// `home`, which every build reads alike.
fn foreign_configs(tree: &Path, home: Option<&Path>) -> Vec<PathBuf>
{
    let same = |a: &Path, b: &Path| match (fs::canonicalize(a), fs::canonicalize(b))
    {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    };
    tree.ancestors()
        .skip(1)
        .map(|dir| dir.join(".cargo"))
        .filter(|dot_cargo| home.is_none_or(|home| !same(dot_cargo, home)))
        .flat_map(|dot_cargo| configs_in(&dot_cargo))
        .collect()
}

/// Create the scratch worktree at `tree`, or reuse the one there when it is
/// a worktree of `root`'s repository.
fn prepare_tree(root: &Path, tree: &Path) -> Result<()>
{
    let foreign = foreign_configs(tree, cargo_home().as_deref());
    if let Some(config) = foreign.first()
    {
        bail!(
            "{} would be merged into both builds in {}; set XDG_CACHE_HOME to a directory \
             with no Cargo configuration above it",
            config.display(),
            tree.display()
        );
    }
    git(root, &["worktree", "prune"])?;
    if tree.join(".git").exists()
    {
        let common = |dir: &Path| {
            git(
                dir,
                &["rev-parse", "--path-format=absolute", "--git-common-dir"],
            )
        };
        if common(tree).ok() == Some(common(root)?)
        {
            return Ok(());
        }
        fs::remove_dir_all(tree).with_context(|| format!("removing {}", tree.display()))?;
        git(root, &["worktree", "prune"])?;
    }
    if let Some(parent) = tree.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let path = tree
        .to_str()
        .context("the scratch worktree's path is not UTF-8")?;
    git(root, &["worktree", "add", "--detach", path, "HEAD"])?;
    Ok(())
}

/// Build `commit` in the scratch worktree for every cell, moving each built
/// sysroot to `<scratch>/<side>/<cell>`.
fn build_side(
    tree: &Path,
    scratch: &Path,
    (side, commit): (Side, &str),
    cells: &[Cell],
    nested: &Nested,
) -> Result<()>
{
    step(&format!(
        "compare-images: building the {} {commit}",
        side.dir_name()
    ));
    git(tree, &["checkout", "--detach", "--force", commit])?;
    git(tree, &["clean", "-ffdx", "-e", "/target"])?;
    for cell in cells
    {
        xtask(tree, &["clean"], nested)?;
        let arch = cell.arch.to_string();
        let mut args = vec!["build", "--skip-lints", "--arch", arch.as_str()];
        if cell.profile == Profile::Release
        {
            args.push("--release");
        }
        xtask(tree, &args, nested)?;
        let dst = scratch.join(side.dir_name()).join(cell.label());
        if dst.exists()
        {
            fs::remove_dir_all(&dst).with_context(|| format!("removing {}", dst.display()))?;
        }
        if let Some(parent) = dst.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::rename(tree.join("sysroot"), &dst)
            .with_context(|| format!("moving the sysroot to {}", dst.display()))?;
    }
    Ok(())
}

/// The files under `dir`, as `/`-separated paths relative to it.
fn files_under(dir: &Path) -> Result<Vec<String>>
{
    let mut out = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop()
    {
        let here = dir.join(&relative);
        for entry in fs::read_dir(&here).with_context(|| format!("reading {}", here.display()))?
        {
            let entry = entry?;
            let path = relative.join(entry.file_name());
            if entry.file_type()?.is_dir()
            {
                pending.push(path);
            }
            else
            {
                let text = path.to_str().context("a sysroot path is not UTF-8")?;
                out.push(text.replace('\\', "/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Compare one cell's two sysroots.
fn compare_cell(cell: Cell, base: &Path, head: &Path) -> Result<CellReport>
{
    let pairs = pair_paths(&files_under(base)?, &files_under(head)?);
    let mut differences = Vec::new();
    for pair in &pairs
    {
        match pair
        {
            Presence::Both(path) =>
            {
                let read = |dir: &Path| {
                    fs::read(dir.join(path)).with_context(|| format!("reading {path}"))
                };
                let (old, new) = (read(base)?, read(head)?);
                if old != new
                {
                    let parts = part_differences(&image_parts(&old), &image_parts(&new));
                    differences.extend(parts.into_iter().map(|part| format!("{path}: {part}")));
                }
            }
            Presence::Base(path) => differences.push(format!("{path}: removed")),
            Presence::Head(path) => differences.push(format!("{path}: added")),
        }
    }
    Ok(CellReport {
        cell,
        files: pairs.len(),
        differences,
    })
}

/// The cells the arguments select: every named architecture in every named
/// profile, both of each when none is named.
fn cells(args: &CompareImagesArgs) -> Vec<Cell>
{
    let arches = if args.arch.is_empty()
    {
        vec![Arch::X86_64, Arch::Riscv64]
    }
    else
    {
        args.arch.clone()
    };
    let profiles = if args.profile.is_empty()
    {
        vec![Profile::Debug, Profile::Release]
    }
    else
    {
        args.profile.clone()
    };
    arches
        .iter()
        .flat_map(|&arch| profiles.iter().map(move |&profile| Cell { arch, profile }))
        .collect()
}

/// Entry point for `cargo xtask compare-images`.
pub fn run(ctx: &BuildContext, args: &CompareImagesArgs) -> Result<()>
{
    let root = ctx.root.as_path();
    let head = git(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("{}^{{commit}}", args.head),
        ],
    )?;
    let base = match &args.base
    {
        Some(base) => git(
            root,
            &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
        )?,
        None => git(root, &["merge-base", &head, "origin/master"])?,
    };
    let cells = cells(args);
    let common = git(
        root,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let scratch = scratch_path(&cache_dir()?, Path::new(&common));
    let _held = lock_scratch(&scratch, &crate::term::signal::interrupted)?;
    let tree = scratch.join("tree");
    prepare_tree(root, &tree)?;
    let nested = Nested {
        wait_host: args.host.wait_host,
        removed: removed_variables(root),
    };
    build_side(&tree, &scratch, (Side::Base, &base), &cells, &nested)?;
    build_side(&tree, &scratch, (Side::Head, &head), &cells, &nested)?;
    let mut reports = Vec::new();
    for &cell in &cells
    {
        let dir = |side: Side| scratch.join(side.dir_name()).join(cell.label());
        reports.push(compare_cell(cell, &dir(Side::Base), &dir(Side::Head))?);
    }
    let report = render(&base, &head, &reports);
    let short = |sha: &str| sha.get(..12).unwrap_or(sha).to_owned();
    let reports_dir = ctx.target_dir.join("xtask").join("compare-images");
    fs::create_dir_all(&reports_dir)
        .with_context(|| format!("creating {}", reports_dir.display()))?;
    let path = reports_dir.join(format!("report-{}-{}.txt", short(&base), short(&head)));
    fs::write(&path, &report).with_context(|| format!("writing {}", path.display()))?;
    print!("{report}");
    println!("report: {}", path.display());
    if reports.iter().any(|r| !r.differences.is_empty())
    {
        bail!("the images differ");
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A section of an ELF fixture.
    #[derive(Clone)]
    struct Sec
    {
        name: &'static str,
        kind: u32,
        flags: u64,
        data: Vec<u8>,
    }

    /// An allocated `PROGBITS` section.
    fn alloc(name: &'static str, data: &[u8]) -> Sec
    {
        Sec {
            name,
            kind: 1,
            flags: 2,
            data: data.to_vec(),
        }
    }

    /// A `PROGBITS` section no loader maps.
    fn unmapped(name: &'static str, data: &[u8]) -> Sec
    {
        Sec {
            name,
            kind: 1,
            flags: 0,
            data: data.to_vec(),
        }
    }

    /// Write `bytes` at `at`, growing `out` as needed.
    fn put(out: &mut Vec<u8>, at: usize, bytes: &[u8])
    {
        if out.len() < at + bytes.len()
        {
            out.resize(at + bytes.len(), 0);
        }
        out[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A little-endian x86-64 ELF64 executable: the header, one `PT_LOAD`
    /// segment from file offset 0 over the header and the allocated sections,
    /// which come first, then the other sections, the section names, and the
    /// section table, as a linker lays out the system's images. An allocated
    /// section's address is its file offset.
    fn elf(entry: u64, sections: &[Sec]) -> Vec<u8>
    {
        let mut ordered: Vec<&Sec> = sections.iter().filter(|s| s.flags & 2 != 0).collect();
        let mapped = ordered.len();
        ordered.extend(sections.iter().filter(|s| s.flags & 2 == 0));
        let mut out = vec![0u8; 64 + 56];
        let mut placed = Vec::new();
        let mut load_end = out.len();
        for (index, sec) in ordered.iter().enumerate()
        {
            placed.push(out.len());
            out.extend_from_slice(&sec.data);
            if index < mapped
            {
                load_end = out.len();
            }
        }
        let mut names = vec![0u8];
        let mut name_at = Vec::new();
        for sec in &ordered
        {
            name_at.push(names.len());
            names.extend_from_slice(sec.name.as_bytes());
            names.push(0);
        }
        let shstrtab_name = names.len();
        names.extend_from_slice(b".shstrtab\0");
        let shstrtab_at = out.len();
        out.extend_from_slice(&names);
        let shoff = out.len();
        out.extend_from_slice(&[0u8; 64]);
        let mut header =
            |name: usize, kind: u32, flags: u64, addr: usize, at: usize, size: usize| {
                let mut sh = [0u8; 64];
                sh[0..4].copy_from_slice(&u32::try_from(name).unwrap().to_le_bytes());
                sh[4..8].copy_from_slice(&kind.to_le_bytes());
                sh[8..16].copy_from_slice(&flags.to_le_bytes());
                sh[16..24].copy_from_slice(&(addr as u64).to_le_bytes());
                sh[24..32].copy_from_slice(&(at as u64).to_le_bytes());
                sh[32..40].copy_from_slice(&(size as u64).to_le_bytes());
                out.extend_from_slice(&sh);
            };
        for (index, sec) in ordered.iter().enumerate()
        {
            let addr = if sec.flags & 2 != 0 { placed[index] } else { 0 };
            header(
                name_at[index],
                sec.kind,
                sec.flags,
                addr,
                placed[index],
                sec.data.len(),
            );
        }
        header(shstrtab_name, 3, 0, 0, shstrtab_at, names.len());
        let shnum = u16::try_from(ordered.len()).unwrap() + 2;
        // The file header.
        put(&mut out, 0, b"\x7fELF\x02\x01\x01");
        put(&mut out, 16, &3u16.to_le_bytes());
        put(&mut out, 18, &62u16.to_le_bytes());
        put(&mut out, 20, &1u32.to_le_bytes());
        put(&mut out, 24, &entry.to_le_bytes());
        put(&mut out, 32, &64u64.to_le_bytes());
        put(&mut out, 40, &(shoff as u64).to_le_bytes());
        put(&mut out, 52, &64u16.to_le_bytes());
        put(&mut out, 54, &56u16.to_le_bytes());
        put(&mut out, 56, &1u16.to_le_bytes());
        put(&mut out, 58, &64u16.to_le_bytes());
        put(&mut out, 60, &shnum.to_le_bytes());
        put(&mut out, 62, &(shnum - 1).to_le_bytes());
        // The one program header: `PT_LOAD`, read and execute.
        put(&mut out, 64, &1u32.to_le_bytes());
        put(&mut out, 68, &5u32.to_le_bytes());
        put(&mut out, 96, &(load_end as u64).to_le_bytes());
        put(&mut out, 104, &(load_end as u64).to_le_bytes());
        put(&mut out, 112, &0x1000u64.to_le_bytes());
        out
    }

    fn differences(base: &[u8], head: &[u8]) -> Vec<String>
    {
        part_differences(&image_parts(base), &image_parts(head))
    }

    fn sample(text: &[u8], comment: &[u8]) -> Vec<Sec>
    {
        vec![
            alloc(".text", text),
            alloc(".rodata", b"constant"),
            unmapped(".comment", comment),
        ]
    }

    #[test]
    fn an_elf_change_outside_the_loaded_parts_is_no_difference()
    {
        // The longer unmapped section moves the section table, so the
        // header's `e_shoff`, which the segment maps, differs too.
        let base = elf(0x100, &sample(b"\x90\xc3", b"rustc 1"));
        let head = elf(
            0x100,
            &sample(b"\x90\xc3", b"rustc 1, and a longer comment"),
        );
        assert_ne!(base, head);
        assert_eq!(differences(&base, &head), Vec::<String>::new());
    }

    #[test]
    fn an_elf_change_to_an_allocated_section_names_it_and_its_segment()
    {
        let base = elf(0x100, &sample(b"\x90\xc3", b"c"));
        let head = elf(0x100, &sample(b"\xcc\xc3", b"c"));
        assert_eq!(differences(&base, &head), ["segment 0", ".text"]);
    }

    #[test]
    fn an_elf_note_is_compared_even_when_no_segment_maps_it()
    {
        let note = |desc: &[u8]| Sec {
            name: ".note.seraph.stack",
            kind: 7,
            flags: 0,
            data: desc.to_vec(),
        };
        let mut base = sample(b"\xc3", b"c");
        base.push(note(b"\x08\0\0\0"));
        let mut head = sample(b"\xc3", b"c");
        head.push(note(b"\x10\0\0\0"));
        assert_eq!(
            differences(&elf(0x100, &base), &elf(0x100, &head)),
            [".note.seraph.stack"]
        );
    }

    #[test]
    fn an_elf_entry_change_names_the_header()
    {
        let sections = sample(b"\xc3", b"c");
        assert_eq!(
            differences(&elf(0x100, &sections), &elf(0x104, &sections)),
            ["ELF header"]
        );
    }

    #[test]
    fn an_elf_section_on_one_side_only_is_added_or_removed()
    {
        let base = sample(b"\xc3", b"c");
        let mut head = base.clone();
        head.push(alloc(".data", b"\x01"));
        assert_eq!(
            differences(&elf(0x100, &base), &elf(0x100, &head)),
            ["segment 0", ".data (added)"]
        );
    }

    /// A PE32+ image with `.text` at RVA 0x1000 and `.rdata` at 0x2000.
    /// `.rdata` opens with one debug directory entry, whose `CodeView` data,
    /// `guid`, follows it at 0x2020; `stamp` is the link time in the COFF
    /// header and the entry, and the checksum.
    fn pe(stamp: u32, guid: &[u8; 16], text: &[u8]) -> Vec<u8>
    {
        let mut out = vec![0u8; 0x800];
        put(&mut out, 0, b"MZ");
        put(&mut out, 0x3c, &64u32.to_le_bytes());
        put(&mut out, 64, b"PE\0\0");
        // The COFF header.
        put(&mut out, 68, &0x8664u16.to_le_bytes());
        put(&mut out, 70, &2u16.to_le_bytes());
        put(&mut out, 72, &stamp.to_le_bytes());
        put(&mut out, 84, &240u16.to_le_bytes());
        put(&mut out, 86, &0x22u16.to_le_bytes());
        // The optional header.
        let opt = 88;
        put(&mut out, opt, &0x20bu16.to_le_bytes());
        put(&mut out, opt + 16, &0x1000u32.to_le_bytes());
        put(&mut out, opt + 24, &0x1_4000_0000u64.to_le_bytes());
        put(&mut out, opt + 32, &0x1000u32.to_le_bytes());
        put(&mut out, opt + 36, &0x200u32.to_le_bytes());
        put(&mut out, opt + 56, &0x3000u32.to_le_bytes());
        put(&mut out, opt + 60, &0x400u32.to_le_bytes());
        put(&mut out, opt + 64, &stamp.to_le_bytes());
        put(&mut out, opt + 68, &10u16.to_le_bytes());
        put(&mut out, opt + 108, &16u32.to_le_bytes());
        // The debug data directory.
        put(&mut out, opt + 112 + 6 * 8, &0x2000u32.to_le_bytes());
        put(&mut out, opt + 112 + 6 * 8 + 4, &28u32.to_le_bytes());
        // The section table.
        let sections: [(&[u8], u32, u32); 2] =
            [(b".text", 0x1000, 0x400), (b".rdata", 0x2000, 0x600)];
        for (index, (name, rva, raw)) in sections.iter().enumerate()
        {
            let at = opt + 240 + index * 40;
            put(&mut out, at, name);
            put(&mut out, at + 8, &0x200u32.to_le_bytes());
            put(&mut out, at + 12, &rva.to_le_bytes());
            put(&mut out, at + 16, &0x200u32.to_le_bytes());
            put(&mut out, at + 20, &raw.to_le_bytes());
            put(&mut out, at + 36, &0x4000_0040u32.to_le_bytes());
        }
        put(&mut out, 0x400, text);
        // The debug directory entry: its stamp, type `CodeView`, and where
        // its data is.
        put(&mut out, 0x604, &stamp.to_le_bytes());
        put(&mut out, 0x60c, &2u32.to_le_bytes());
        put(&mut out, 0x610, &16u32.to_le_bytes());
        put(&mut out, 0x614, &0x2020u32.to_le_bytes());
        put(&mut out, 0x618, &0x620u32.to_le_bytes());
        put(&mut out, 0x620, guid);
        put(&mut out, 0x630, b"read-only data");
        out
    }

    #[test]
    fn a_pe_link_stamp_and_debug_directory_are_no_difference()
    {
        let base = pe(0x6af7_bde5, &[1; 16], b"\x90\xc3");
        let head = pe(0x6af8_0000, &[2; 16], b"\x90\xc3");
        assert!(
            image_parts(&base)
                .iter()
                .any(|p| p.name == "section .rdata")
        );
        assert_eq!(differences(&base, &head), Vec::<String>::new());
    }

    #[test]
    fn a_pe_section_change_names_the_section()
    {
        let base = pe(1, &[1; 16], b"\x90\xc3");
        let head = pe(1, &[1; 16], b"\xcc\xc3");
        assert_eq!(differences(&base, &head), ["section .text"]);
        let mut data = pe(1, &[1; 16], b"\x90\xc3");
        put(&mut data, 0x630, b"other data");
        assert_eq!(differences(&base, &data), ["section .rdata"]);
    }

    /// A bundle of the named entries, each body at the next 4096-byte
    /// boundary.
    fn bundle(entries: &[(&str, Vec<u8>)]) -> Vec<u8>
    {
        let mut out = Vec::new();
        out.extend_from_slice(&bundle_fmt::MAGIC);
        out.extend_from_slice(&bundle_fmt::VERSION.to_le_bytes());
        out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_le_bytes());
        let mut offset = 4096u64;
        let mut bodies = Vec::new();
        for (name, body) in entries
        {
            let mut raw = [0u8; bundle_fmt::ENTRY_NAME_LEN];
            raw[..name.len()].copy_from_slice(name.as_bytes());
            out.extend_from_slice(&raw);
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&(body.len() as u64).to_le_bytes());
            bodies.push((offset, body));
            offset += (body.len() as u64).div_ceil(4096).max(1) * 4096;
        }
        for (at, body) in bodies
        {
            put(&mut out, usize::try_from(at).unwrap(), body);
        }
        out
    }

    #[test]
    fn a_bundle_is_compared_by_its_entries_loaded_parts()
    {
        let init = |comment: &[u8]| elf(0x100, &sample(b"\xc3", comment));
        let base = bundle(&[("init", init(b"c")), ("procmgr", init(b"c"))]);
        let longer = bundle(&[("init", init(b"a longer comment")), ("procmgr", init(b"c"))]);
        assert_eq!(differences(&base, &longer), Vec::<String>::new());
        let renamed = bundle(&[("init", init(b"c")), ("memmgr", init(b"c"))]);
        let found = differences(&base, &renamed);
        assert!(found.contains(&String::from("bundle entries")));
        assert!(found.contains(&String::from("entry procmgr: .text (removed)")));
        assert!(found.contains(&String::from("entry memmgr: .text (added)")));
    }

    #[test]
    fn any_other_file_is_compared_by_its_bytes()
    {
        assert_eq!(
            differences(b"name = procmgr\n", b"name = memmgr\n"),
            [CONTENTS]
        );
        // A file with an image's magic whose headers do not parse falls
        // back to its bytes.
        assert_eq!(differences(b"\x7fELF\x02", b"\x7fELF\x01"), [CONTENTS]);
    }

    #[test]
    fn a_repeated_part_name_is_compared_by_occurrence()
    {
        let part = |name: &str, byte: u8| Part::new(name, vec![byte]);
        let base = [part(".text", 1), part(".text", 2)];
        let head = [part(".text", 1), part(".text", 3), part(".text", 4)];
        assert_eq!(
            part_differences(&base, &head),
            [".text #2", ".text #3 (added)"]
        );
    }

    #[test]
    fn sysroot_files_pair_by_path()
    {
        let names = |list: &[&str]| list.iter().map(|s| String::from(*s)).collect::<Vec<_>>();
        assert_eq!(
            pair_paths(
                &names(&["a", "services/init"]),
                &names(&["b", "services/init"])
            ),
            [
                Presence::Base(String::from("a")),
                Presence::Head(String::from("b")),
                Presence::Both(String::from("services/init")),
            ]
        );
    }

    #[test]
    fn the_verdict_line_names_the_commits_the_cells_and_the_count()
    {
        let cell = |arch, profile| Cell { arch, profile };
        let same = CellReport {
            cell: cell(Arch::X86_64, Profile::Debug),
            files: 3,
            differences: Vec::new(),
        };
        let identical = render("b1", "h1", std::slice::from_ref(&same));
        assert!(
            identical.ends_with("compare-images: IDENTICAL base b1 head h1 cells x86_64-debug\n")
        );
        let differs = CellReport {
            cell: cell(Arch::Riscv64, Profile::Release),
            files: 3,
            differences: vec![String::from("esp/EFI/seraph/kernel: .text")],
        };
        let report = render("b1", "h1", &[same, differs]);
        assert!(
            report.contains(
                "riscv64-release: 3 files, 1 differences\n  esp/EFI/seraph/kernel: .text\n"
            )
        );
        assert!(report.ends_with(
            "compare-images: DIFFERENT (1) base b1 head h1 cells x86_64-debug,riscv64-release\n"
        ));
    }

    #[test]
    fn the_variables_cargo_run_and_rustup_set_are_removed_and_the_users_kept()
    {
        for name in [
            "CARGO",
            "CARGO_MANIFEST_DIR",
            "CARGO_TARGET_DIR",
            "RUSTUP_TOOLCHAIN",
            "RUST_RECURSION_COUNT",
        ]
        {
            assert!(set_by_cargo_run(name), "{name}");
        }
        for name in ["CARGO_HOME", "RUSTUP_HOME", "PATH", "HOME", "CARGOX"]
        {
            assert!(!set_by_cargo_run(name), "{name}");
        }
    }

    #[test]
    fn a_config_env_table_names_its_variables()
    {
        let text = "\
[alias]
xtask = \"run --package xtask --\"

[env]
# COMMENTED = \"no\"
RUST_TARGET_PATH = { value = \"xtask/targets\", relative = true }
\"QUOTED\" = \"1\"
DOTTED.value = \"2\"

[env.TABLED]
value = \"3\"

[build]
rustflags = [\"-Zunstable-options\"]
";
        assert_eq!(
            config_env_keys(text),
            ["RUST_TARGET_PATH", "QUOTED", "DOTTED", "TABLED"]
        );
        assert_eq!(config_env_keys("[build]\njobs = 4\n"), Vec::<String>::new());
    }

    #[test]
    fn each_repository_has_one_scratch_directory_in_the_cache()
    {
        let cache = Path::new("/cache");
        assert_eq!(
            scratch_path(cache, Path::new("/home/u/seraph/.git")),
            Path::new("/cache/seraph-compare-images/-2fhome-2fu-2fseraph-2f.git")
        );
        // Two paths that a plain separator replacement would merge stay
        // apart.
        assert_ne!(
            scratch_path(cache, Path::new("/a/b-c/.git")),
            scratch_path(cache, Path::new("/a/b/c/.git"))
        );
    }

    #[test]
    fn a_second_run_waits_for_the_scratch_lock()
    {
        let scratch =
            std::env::temp_dir().join(format!("xtask-compare-lock-{}", std::process::id()));
        let held = lock_scratch(&scratch, &|| false).unwrap();
        let other = fs::File::open(scratch.join("lock")).unwrap();
        assert!(matches!(
            other.try_lock(),
            Err(fs::TryLockError::WouldBlock)
        ));
        // A waiting run ends its wait on Ctrl+C rather than blocking on.
        let error = lock_scratch(&scratch, &|| true).unwrap_err();
        assert!(error.to_string().contains("interrupted"), "{error}");
        drop(held);
        other.try_lock().unwrap();
        drop(other);
        // A free lock is taken before the interrupt flag is read.
        drop(lock_scratch(&scratch, &|| true).unwrap());
        fs::remove_dir_all(&scratch).unwrap();
    }

    #[test]
    fn a_cargo_config_above_the_tree_is_foreign_unless_it_is_cargo_home()
    {
        let root =
            std::env::temp_dir().join(format!("xtask-compare-images-{}", std::process::id()));
        let tree = root.join("checkout").join("tree");
        fs::create_dir_all(&tree).unwrap();
        assert_eq!(foreign_configs(&tree, None), Vec::<PathBuf>::new());
        let dot_cargo = root.join("checkout").join(".cargo");
        fs::create_dir_all(&dot_cargo).unwrap();
        fs::write(dot_cargo.join("config.toml"), "[env]\n").unwrap();
        // The tree's own configuration is the commit's, not a foreign one.
        fs::create_dir_all(tree.join(".cargo")).unwrap();
        fs::write(tree.join(".cargo").join("config.toml"), "[env]\n").unwrap();
        assert_eq!(
            foreign_configs(&tree, None),
            [dot_cargo.join("config.toml")]
        );
        assert_eq!(
            foreign_configs(&tree, Some(&dot_cargo)),
            Vec::<PathBuf>::new()
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
