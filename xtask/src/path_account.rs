// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/path_account.rs

//! The per-path instruction account's logic, for `cargo xtask path-account`:
//! the images a traced boot placed and where, the attribution of a window's
//! instructions to functions, the result file of one configuration, and the
//! Markdown block that sets the configurations side by side.
//!
//! xtask/README.md (`cargo xtask path-account`) states the method and its
//! checks; `crate::path_record` reads the plugin's record into windows, and
//! `commands::path_account` drives the boot and reads the files.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::error::{Result, bail, ensure};

/// The frame an instruction is counted against: the innermost of `frames`
/// (innermost first) that is not the standard library's, so an inlined
/// `core` helper counts against the kernel or ktest function that called it;
/// the innermost when every frame is the library's.
pub fn attributed(frames: &[String]) -> &str
{
    frames
        .iter()
        .find(|f| !is_library(f))
        .or_else(|| frames.first())
        .map_or("", String::as_str)
}

/// Whether `path`, a demangled function path, is a function of the standard
/// library: one of `core`, `alloc` or `compiler_builtins`, or a method of a
/// primitive type, whose inherent impls are `core`'s.
pub fn is_library(path: &str) -> bool
{
    const CRATES: [&str; 3] = ["core::", "alloc::", "compiler_builtins::"];
    const PRIMITIVES: [&str; 17] = [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
        "bool", "char", "str", "f32", "f64",
    ];
    let Some(inner) = path.strip_prefix('<')
    else
    {
        return CRATES.iter().any(|c| path.starts_with(c));
    };
    if CRATES.iter().any(|c| inner.starts_with(c))
        || ["*const ", "*mut ", "&", "["]
            .iter()
            .any(|p| inner.starts_with(p))
    {
        return true;
    }
    let ty = inner.split(['>', ' ']).next().unwrap_or_default();
    PRIMITIVES.contains(&ty)
}

/// The image name of the kernel's instructions.
pub const KERNEL: &str = "kernel";

/// The image name of an instruction no image covers.
pub const OTHER: &str = "other";

/// One image a boot placed: the name its placement line gives it, and the
/// offset of its runtime addresses from its link addresses (the kernel's
/// KASLR slide, a process's load bias).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement
{
    pub name: String,
    pub bias: u64,
}

/// The hexadecimal number after `field` in `line`, up to the next space.
fn hex_after(line: &str, field: &str) -> Option<u64>
{
    let (_, rest) = line.split_once(field)?;
    let digits = rest.split_whitespace().next()?;
    u64::from_str_radix(digits.trim_start_matches("0x"), 16).ok()
}

/// The images a boot's serial log places, in the order it placed them: the
/// kernel at its slide (`kaslr: slide=`), the init image (`init: PIE bias=`),
/// named `init` (ktest, in the ktest harness), memmgr and procmgr, which init
/// loads, and each process procmgr creates (`spawn image bias=0x.. (<name>)`).
/// A process created without a name takes the name of the service svcmgr
/// logged it was launching (`svcmgr: launching: <name>`) just before; one
/// with neither has no placement, and its instructions are no image's.
pub fn placements(lines: &[String], init: &str) -> Vec<Placement>
{
    let mut out = Vec::new();
    let mut launching: Option<String> = None;
    for line in lines
    {
        let named = |name: &str, field: &str| {
            hex_after(line, field).map(|bias| Placement {
                name: name.to_owned(),
                bias,
            })
        };
        let found = if line.contains("kaslr: slide=")
        {
            named(KERNEL, "slide=")
        }
        else if line.contains("init: PIE bias=")
        {
            named(init, "bias=")
        }
        else if line.contains("init: memmgr image bias=")
        {
            named("memmgr", "bias=")
        }
        else if line.contains("init: procmgr image bias=")
        {
            named("procmgr", "bias=")
        }
        else if let Some((_, service)) = line.split_once("svcmgr: launching: ")
        {
            launching = Some(service.trim().to_owned());
            None
        }
        else if line.contains("spawn image bias=")
        {
            let pending = launching.take();
            line.rsplit_once(" (")
                .and_then(|(_, name)| name.strip_suffix(')'))
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .or(pending)
                .and_then(|name| named(&name, "bias="))
        }
        else
        {
            None
        };
        out.extend(found);
    }
    out
}

/// The function an instruction belongs to: its image, and the innermost
/// source function of its code, inlined or not.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Place
{
    /// [`KERNEL`], [`OTHER`], or the name of the process image.
    pub image: String,
    pub function: String,
}

/// One window's instructions, by the function each belongs to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tally
{
    pub total: u64,
    pub by_place: BTreeMap<Place, u64>,
}

impl Tally
{
    /// Tally `(address, count)` pairs, each address attributed by `place`.
    pub fn of(
        counts: impl IntoIterator<Item = (u64, u64)>,
        mut place: impl FnMut(u64) -> Place,
    ) -> Self
    {
        let mut tally = Self::default();
        for (pc, n) in counts
        {
            tally.total = tally.total.saturating_add(n);
            let count = tally.by_place.entry(place(pc)).or_insert(0);
            *count = count.saturating_add(n);
        }
        tally
    }

    /// The instructions of `image`.
    pub fn of_image(&self, image: &str) -> u64
    {
        self.by_place
            .iter()
            .filter(|(place, _)| place.image == image)
            .map(|(_, &count)| count)
            .fold(0, u64::saturating_add)
    }

    /// The images of the tally.
    fn images(&self) -> impl Iterator<Item = &str>
    {
        self.by_place.keys().map(|p| p.image.as_str())
    }
}

/// One traced measurement: its name, the counts it was checked against, and
/// its tally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path
{
    /// The measurement, as `bench-check` names it (`<suite>.<name> [variant] cpus=1`).
    pub key: String,
    /// The p50 of the boot that was traced.
    pub p50: u64,
    /// The reference count: the lowest p50 of the reference logs.
    pub reference: u64,
    /// The sample traced: its index, from 0, among the measurement's samples
    /// in the order the benchmark took them.
    pub iteration: u32,
    pub tally: Tally,
}

/// The account of one architecture and profile, as the result file holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Configuration
{
    pub arch: String,
    pub profile: String,
    /// The commit traced, `-dirty` appended when the tree differed from it.
    pub head: String,
    /// The UTC date of the trace, `YYYY-MM-DD`.
    pub date: String,
    /// `qemu-system-<arch> --version`'s first line.
    pub qemu: String,
    /// What the counts were checked against.
    pub reference: String,
    pub paths: Vec<Path>,
}

/// The first line of a result file.
const RESULT_HEADER: &str = "# path-account result";

impl Configuration
{
    /// The configuration's column title: `<arch> <profile>`.
    pub fn title(&self) -> String
    {
        format!("{} {}", self.arch, self.profile)
    }

    /// The result file: tab-separated records, one a line.
    pub fn render(&self) -> String
    {
        let mut out = format!("{RESULT_HEADER}\n");
        for (key, value) in [
            ("arch", &self.arch),
            ("profile", &self.profile),
            ("head", &self.head),
            ("date", &self.date),
            ("qemu", &self.qemu),
            ("reference", &self.reference),
        ]
        {
            let _ = writeln!(out, "{key}\t{value}");
        }
        for path in &self.paths
        {
            let _ = writeln!(
                out,
                "path\t{}\t{}\t{}\t{}",
                path.key, path.p50, path.reference, path.iteration
            );
            for (place, count) in &path.tally.by_place
            {
                let _ = writeln!(out, "fn\t{}\t{}\t{count}", place.image, place.function);
            }
        }
        out
    }

    /// Read a result file.
    ///
    /// # Errors
    ///
    /// The header is missing, a record is malformed or unknown, a field is
    /// missing, or a `fn` record comes before any `path` record.
    pub fn parse(text: &str) -> Result<Self>
    {
        let mut lines = text.lines();
        ensure!(
            lines.next() == Some(RESULT_HEADER),
            "not a path-account result file"
        );
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        let mut paths: Vec<Path> = Vec::new();
        for line in lines.filter(|l| !l.is_empty())
        {
            let cols: Vec<&str> = line.split('\t').collect();
            match cols.as_slice()
            {
                ["path", key, p50, reference, iteration] =>
                {
                    paths.push(Path {
                        key: (*key).to_owned(),
                        p50: number(p50, line)?,
                        reference: number(reference, line)?,
                        iteration: u32::try_from(number(iteration, line)?)?,
                        tally: Tally::default(),
                    });
                }
                ["fn", image, function, count] =>
                {
                    let Some(path) = paths.last_mut()
                    else
                    {
                        bail!("{line:?}: a function before any path");
                    };
                    ensure!(!image.is_empty(), "{line:?}: no image");
                    let count = number(count, line)?;
                    path.tally.total = path.tally.total.saturating_add(count);
                    path.tally.by_place.insert(
                        Place {
                            image: (*image).to_owned(),
                            function: (*function).to_owned(),
                        },
                        count,
                    );
                }
                [key, value] =>
                {
                    fields.insert((*key).to_owned(), (*value).to_owned());
                }
                _ => bail!("{line:?}: not a result record"),
            }
        }
        let mut field = |key: &str| -> Result<String> {
            match fields.remove(key)
            {
                Some(value) => Ok(value),
                None => bail!("the result file has no {key} record"),
            }
        };
        Ok(Self {
            arch: field("arch")?,
            profile: field("profile")?,
            head: field("head")?,
            date: field("date")?,
            qemu: field("qemu")?,
            reference: field("reference")?,
            paths,
        })
    }
}

fn number(value: &str, line: &str) -> Result<u64>
{
    match value.parse()
    {
        Ok(n) => Ok(n),
        Err(_) => bail!("{line:?}: {value:?} is not a decimal number"),
    }
}

/// The marker lines that bound the generated block of the account document.
pub const BLOCK_BEGIN: &str =
    "<!-- path-account: begin; generated by cargo xtask path-account write -->";
pub const BLOCK_END: &str = "<!-- path-account: end -->";

/// The generated block: the configurations' provenance, a table of each
/// path's totals, and per path a table of its functions, one column per
/// configuration, in the order given.
pub fn render_block(configs: &[Configuration]) -> String
{
    let mut out = format!("{BLOCK_BEGIN}\n\n");
    out.push_str(
        "| Configuration | Head | Taken | QEMU | Checked against |\n|---|---|---|---|---|\n",
    );
    for c in configs
    {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {} | {} |",
            c.title(),
            c.head,
            c.date,
            c.qemu,
            c.reference
        );
    }
    let keys = path_keys(configs);
    out.push_str("\n#### Totals\n\n");
    header(&mut out, "Path", "Image", configs);
    for key in &keys
    {
        let images = total_images(configs, key);
        for image in std::iter::once(None).chain(images.iter().map(|i| Some(i.as_str())))
        {
            let cells: Vec<Option<u64>> = configs
                .iter()
                .map(|c| {
                    let path = c.paths.iter().find(|p| &p.key == key)?;
                    Some(image.map_or(path.tally.total, |i| path.tally.of_image(i)))
                })
                .collect();
            row(
                &mut out,
                &format!("`{key}`"),
                image.unwrap_or("all"),
                &cells,
            );
        }
    }
    for key in &keys
    {
        let _ = write!(out, "\n#### `{key}`\n\n");
        header(&mut out, "Function", "Image", configs);
        let rows = place_rows(configs, key);
        let largest = configs
            .iter()
            .filter_map(|c| c.paths.iter().find(|p| &p.key == key))
            .map(|p| p.tally.total)
            .max()
            .unwrap_or(0);
        let floor = row_floor(largest);
        let mut rest: Vec<Option<u64>> = vec![None; configs.len()];
        let mut hidden = 0usize;
        for (place, cells) in rows
        {
            if most(&cells) >= floor
            {
                row(
                    &mut out,
                    &format!("`{}`", place.function),
                    &place.image,
                    &cells,
                );
                continue;
            }
            hidden = hidden.saturating_add(1);
            for (sum, cell) in rest.iter_mut().zip(&cells)
            {
                if let Some(n) = cell
                {
                    *sum = Some(sum.unwrap_or(0).saturating_add(*n));
                }
            }
        }
        if hidden > 0
        {
            row(
                &mut out,
                &format!("{hidden} functions below {floor} each"),
                "",
                &rest,
            );
        }
    }
    out.push('\n');
    out.push_str(BLOCK_END);
    out.push('\n');
    out
}

/// Every path any configuration traced, in the first order they appear.
fn path_keys(configs: &[Configuration]) -> Vec<String>
{
    let mut keys: Vec<String> = Vec::new();
    for path in configs.iter().flat_map(|c| &c.paths)
    {
        if !keys.contains(&path.key)
        {
            keys.push(path.key.clone());
        }
    }
    keys
}

/// The images of path `key`'s totals, after its row of all instructions:
/// the benchmark program's (the image named as the key's suite), the other
/// processes' by name, the kernel's, then the instructions no image covers;
/// each only when some configuration ran an instruction in it.
fn total_images(configs: &[Configuration], key: &str) -> Vec<String>
{
    let suite = key.split('.').next().unwrap_or_default();
    let present: std::collections::BTreeSet<&str> = configs
        .iter()
        .filter_map(|c| c.paths.iter().find(|p| p.key == key))
        .flat_map(|p| p.tally.images())
        .collect();
    let rank = |image: &str| match image
    {
        i if i == suite => 0,
        KERNEL => 2,
        OTHER => 3,
        _ => 1,
    };
    let mut images: Vec<&str> = present.into_iter().collect();
    images.sort_by_key(|i| (rank(i), *i));
    images.into_iter().map(str::to_owned).collect()
}

/// The functions of path `key` with each configuration's count, the largest
/// first by their largest count, then by image and name.
fn place_rows(configs: &[Configuration], key: &str) -> Vec<(Place, Vec<Option<u64>>)>
{
    let mut rows: BTreeMap<Place, Vec<Option<u64>>> = BTreeMap::new();
    for (column, config) in configs.iter().enumerate()
    {
        let Some(path) = config.paths.iter().find(|p| p.key == key)
        else
        {
            continue;
        };
        for (place, &count) in &path.tally.by_place
        {
            let cells = rows
                .entry(place.clone())
                .or_insert_with(|| vec![None; configs.len()]);
            if let Some(cell) = cells.get_mut(column)
            {
                *cell = Some(count);
            }
        }
    }
    let mut rows: Vec<(Place, Vec<Option<u64>>)> = rows.into_iter().collect();
    rows.sort_by(|(pa, ca), (pb, cb)| most(cb).cmp(&most(ca)).then_with(|| pa.cmp(pb)));
    rows
}

/// The largest of a row's counts.
fn most(cells: &[Option<u64>]) -> u64
{
    cells.iter().flatten().copied().max().unwrap_or(0)
}

/// The fewest instructions a function shows its own row with, in a path whose
/// largest configuration ran `largest`: 3, or half a percent of the path when
/// that is more, so a long path's table stays readable. The functions below
/// it share one row; the result files keep every function.
pub const fn row_floor(largest: u64) -> u64
{
    let share = largest / 200;
    if share > 3 { share } else { 3 }
}

fn header(out: &mut String, first: &str, second: &str, configs: &[Configuration])
{
    let _ = write!(out, "| {first} | {second} |");
    for c in configs
    {
        let _ = write!(out, " {} |", c.title());
    }
    out.push_str("\n|---|---|");
    for _ in configs
    {
        out.push_str("---:|");
    }
    out.push('\n');
}

fn row(out: &mut String, first: &str, second: &str, cells: &[Option<u64>])
{
    let _ = write!(out, "| {first} | {second} |");
    for cell in cells
    {
        match cell
        {
            Some(n) =>
            {
                let _ = write!(out, " {n} |");
            }
            None => out.push_str(" |"),
        }
    }
    out.push('\n');
}

/// `doc` with its generated block replaced by `block`.
///
/// # Errors
///
/// `doc` does not hold the begin marker, then the end marker, once each.
pub fn replace_block(doc: &str, block: &str) -> Result<String>
{
    let (Some(begin), Some(end)) = (doc.find(BLOCK_BEGIN), doc.find(BLOCK_END))
    else
    {
        bail!("the document holds no {BLOCK_BEGIN:?} ... {BLOCK_END:?} block");
    };
    ensure!(
        doc.matches(BLOCK_BEGIN).count() == 1 && doc.matches(BLOCK_END).count() == 1 && begin < end,
        "the document's generated block markers are not one begin before one end"
    );
    let after = end.saturating_add(BLOCK_END.len());
    let tail = doc.get(after..).unwrap_or("");
    let tail = tail.strip_prefix('\n').unwrap_or(tail);
    let head = doc.get(..begin).unwrap_or("");
    Ok(format!("{head}{block}{tail}"))
}

/// The first line of a provenance file.
const PROVENANCE_HEADER: &str = "# path-account provenance";

/// What a traced boot ran: the tree, the date and the QEMU of the trace, and
/// the build id of each image the boot placed, by its name. `trace` writes
/// it beside the plugin's record; `trace --reuse` takes the first three from
/// it and accounts the record only against the images it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance
{
    /// The commit traced, `-dirty` appended when the tree differed from it.
    pub head: String,
    /// The UTC date of the trace, `YYYY-MM-DD`.
    pub date: String,
    /// `qemu-system-<arch> --version`'s first line.
    pub qemu: String,
    /// Each placed image's build id (`none` for an image without one).
    pub images: BTreeMap<String, String>,
}

impl Provenance
{
    /// The provenance file: tab-separated records, one a line.
    pub fn render(&self) -> String
    {
        let mut out = format!("{PROVENANCE_HEADER}\n");
        for (key, value) in [
            ("head", &self.head),
            ("date", &self.date),
            ("qemu", &self.qemu),
        ]
        {
            let _ = writeln!(out, "{key}\t{value}");
        }
        for (name, id) in &self.images
        {
            let _ = writeln!(out, "image\t{name}\t{id}");
        }
        out
    }

    /// Read a provenance file.
    ///
    /// # Errors
    ///
    /// The header is missing, a record is malformed or unknown, or the head,
    /// date or QEMU record is missing.
    pub fn parse(text: &str) -> Result<Self>
    {
        let mut lines = text.lines();
        ensure!(
            lines.next() == Some(PROVENANCE_HEADER),
            "not a path-account provenance file"
        );
        let (mut head, mut date, mut qemu) = (None, None, None);
        let mut images = BTreeMap::new();
        for line in lines.filter(|l| !l.is_empty())
        {
            match line.split('\t').collect::<Vec<_>>().as_slice()
            {
                ["head", value] => head = Some((*value).to_owned()),
                ["date", value] => date = Some((*value).to_owned()),
                ["qemu", value] => qemu = Some((*value).to_owned()),
                ["image", name, id] =>
                {
                    images.insert((*name).to_owned(), (*id).to_owned());
                }
                _ => bail!("{line:?}: not a provenance record"),
            }
        }
        let (Some(head), Some(date), Some(qemu)) = (head, date, qemu)
        else
        {
            bail!("the provenance file lacks its head, date or QEMU record");
        };
        Ok(Self {
            head,
            date,
            qemu,
            images,
        })
    }

    /// Each image whose build id in `now` is not the traced one, or that one
    /// of the two lacks, as `<name>: traced <id>, now <id>`.
    pub fn mismatches(&self, now: &BTreeMap<String, String>) -> Vec<String>
    {
        let mut names: Vec<&String> = self.images.keys().chain(now.keys()).collect();
        names.sort();
        names.dedup();
        names
            .into_iter()
            .filter_map(|name| {
                let traced = self.images.get(name).map_or("absent", String::as_str);
                let current = now.get(name).map_or("absent", String::as_str);
                (traced != current).then(|| format!("{name}: traced {traced}, now {current}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_provenance_reads_back_and_names_each_image_that_moved()
    {
        let traced = Provenance {
            head: "471226fdaaff".to_owned(),
            date: "2026-11-23".to_owned(),
            qemu: "QEMU emulator version 11.1.3".to_owned(),
            images: BTreeMap::from([
                ("kernel".to_owned(), "eb1a".to_owned()),
                ("fatfs:/".to_owned(), "00ff".to_owned()),
            ]),
        };
        assert_eq!(Provenance::parse(&traced.render()).unwrap(), traced);
        assert_eq!(traced.mismatches(&traced.images), Vec::<String>::new());
        let now = BTreeMap::from([
            ("kernel".to_owned(), "eb1b".to_owned()),
            ("ubench".to_owned(), "0101".to_owned()),
        ]);
        assert_eq!(
            traced.mismatches(&now),
            [
                "fatfs:/: traced 00ff, now absent",
                "kernel: traced eb1a, now eb1b",
                "ubench: traced absent, now 0101",
            ]
        );
        Provenance::parse("# path-account provenance\nhead\tx\n").unwrap_err();
        Provenance::parse("head\tx\n").unwrap_err();
    }

    #[test]
    fn library_frames_count_against_their_caller()
    {
        for library in [
            "core::sync::atomic::atomic_load::<u32, false>",
            "<*const _>::is_null::runtime",
            "<usize>::overflowing_add",
            "<u64 as core::convert::From<u32>>::from",
            "<core::result::Result<u64, E>>::map_err::<F, G>",
            "alloc::vec::Vec::push",
            "<[u8]>::len",
            "<&T as core::fmt::Debug>::fmt",
        ]
        {
            assert!(is_library(library), "{library}");
        }
        for own in [
            "kernel::sched::scheduler_for",
            "<kernel::syscall::UserFrame>::arg",
            "<bench::counters::Counters>::read",
            "<core_ext::Thing>::new",
            "seraph_enter_from_user",
        ]
        {
            assert!(!is_library(own), "{own}");
        }
        let frames: Vec<String> = [
            "core::sync::atomic::atomic_load::<u32, false>",
            "kernel::sched::scheduler_for",
            "kernel::syscall::dispatch",
        ]
        .map(str::to_owned)
        .to_vec();
        assert_eq!(attributed(&frames), "kernel::sched::scheduler_for");
        let only_library = vec!["<usize>::overflowing_add".to_owned()];
        assert_eq!(attributed(&only_library), "<usize>::overflowing_add");
        assert_eq!(attributed(&[]), "");
    }

    fn place(image: &str, function: &str) -> Place
    {
        Place {
            image: image.to_owned(),
            function: function.to_owned(),
        }
    }

    fn config(arch: &str, profile: &str, null: u64) -> Configuration
    {
        let tally = Tally::of([(0, 4), (4, 1), (5, null - 5)], |pc| match pc
        {
            0 => place("ktest", "bench::arch::current::cycles"),
            4 => place(KERNEL, "kernel::cap::sole_reference::drain"),
            _ => place(KERNEL, "kernel::syscall::dispatch"),
        });
        Configuration {
            arch: arch.to_owned(),
            profile: profile.to_owned(),
            head: "0123456789ab".to_owned(),
            date: "2026-11-23".to_owned(),
            qemu: "QEMU emulator version 11.1.3".to_owned(),
            reference: "1 icount boot(s)".to_owned(),
            paths: vec![Path {
                key: "ktest.null_syscall_roundtrip cpus=1".to_owned(),
                p50: null,
                reference: null,
                iteration: 64,
                tally,
            }],
        }
    }

    #[test]
    fn a_tally_counts_each_place()
    {
        let c = config("x86_64", "dev", 20);
        let tally = &c.paths[0].tally;
        assert_eq!(tally.total, 20);
        assert_eq!(tally.of_image("ktest"), 4);
        assert_eq!(tally.of_image(KERNEL), 16);
        assert_eq!(tally.of_image(OTHER), 0);
    }

    #[test]
    fn a_result_file_round_trips()
    {
        let c = config("riscv64", "release", 20);
        assert_eq!(Configuration::parse(&c.render()).unwrap(), c);
    }

    #[test]
    fn a_malformed_result_file_is_rejected()
    {
        Configuration::parse(
            "arch	x86_64
",
        )
        .unwrap_err();
        let text = format!(
            "{RESULT_HEADER}
fn	kernel	f	3
"
        );
        Configuration::parse(&text).unwrap_err();
        let text = format!(
            "{RESULT_HEADER}
arch	x86_64
"
        );
        let err = Configuration::parse(&text).unwrap_err().to_string();
        assert!(err.contains("no profile"), "{err}");
        let text = format!(
            "{RESULT_HEADER}
path	k	1	1	64
fn		f	1
"
        );
        Configuration::parse(&text).unwrap_err();
    }

    #[test]
    fn the_block_sets_the_configurations_side_by_side()
    {
        let block = render_block(&[config("x86_64", "dev", 20), config("riscv64", "dev", 30)]);
        assert!(block.starts_with(BLOCK_BEGIN) && block.trim_end().ends_with(BLOCK_END));
        assert!(block.contains("| `ktest.null_syscall_roundtrip cpus=1` | all | 20 | 30 |"));
        assert!(block.contains("| `ktest.null_syscall_roundtrip cpus=1` | kernel | 16 | 26 |"));
        // The largest function first; one below the floor of 3 folds into
        // the closing row.
        let dispatch = block
            .find("| `kernel::syscall::dispatch` | kernel | 15 | 25 |")
            .unwrap();
        let cycles = block
            .find("| `bench::arch::current::cycles` | ktest | 4 | 4 |")
            .unwrap();
        assert!(dispatch < cycles);
        assert!(!block.contains("sole_reference"));
        assert!(block.contains("| 1 functions below 3 each |  | 1 | 1 |"));
        // A configuration without "other" instructions gets no such row.
        assert!(!block.contains("| other |"));
        // The program's row comes before the kernel's.
        let ktest = block
            .find("| `ktest.null_syscall_roundtrip cpus=1` | ktest | 4 | 4 |")
            .unwrap();
        let kernel = block
            .find("| `ktest.null_syscall_roundtrip cpus=1` | kernel |")
            .unwrap();
        assert!(ktest < kernel);
    }

    #[test]
    fn a_userspace_path_totals_each_process_between_its_program_and_the_kernel()
    {
        let mut c = config("riscv64", "release", 20);
        let path = c.paths.first_mut().unwrap();
        path.key = "ubench.fault_fill path=fault pages=16 cpus=1".to_owned();
        path.tally = Tally::of([(0, 5), (1, 3), (2, 7), (3, 2), (4, 1)], |pc| match pc
        {
            0 => place("ubench", "ubench::fault::run"),
            1 => place("vfsd", "vfsd::serve"),
            2 => place(KERNEL, "kernel::mm::fault"),
            3 => place("memmgr", "memmgr::fill"),
            _ => place(OTHER, "<page 0x1000>"),
        });
        let block = render_block(&[c]);
        let order: Vec<usize> = ["ubench", "memmgr", "vfsd", "kernel", "other"]
            .iter()
            .map(|i| {
                block
                    .find(&format!(
                        "| `ubench.fault_fill path=fault pages=16 cpus=1` | {i} |"
                    ))
                    .unwrap()
            })
            .collect();
        assert!(order.is_sorted(), "{block}");
    }

    #[test]
    fn a_serial_log_places_the_kernel_and_each_named_process()
    {
        let lines: Vec<String> = [
            "[--------] kernel: kaslr: slide=0x7fa00000 image_base=0xffffffffffa00000",
            "[0.253334] kernel: init: PIE bias=0x339d749000 (20 relocations)",
            "[0.282779] [init] init: memmgr image bias=0x36fde57000",
            "[0.283550] [init] init: procmgr image bias=0x30c0606000",
            "[0.350848] [procmgr] spawn image bias=0x34aeaa4000 (devmgr)",
            "[0.502772] [procmgr] spawn image bias=0x37036e3000 (/services/drivers/virtio-blk)",
            "[0.641718] [procmgr] spawn image bias=0x36c6f02000 (fatfs:/data)",
            "[0.900000] [svcmgr] svcmgr: launching: acpid",
            "[1.000000] [procmgr] spawn image bias=0x30c0dc6000 ()",
            "[1.050000] [procmgr] spawn image bias=0x30c0dc7000 ()",
            "[1.060000] [svcmgr] svcmgr: launching: sessiond",
            "[1.070000] [procmgr] spawn image bias=0x30d55da000 (sessiond)",
            "[1.100000] [ubench] bench ubench.ipc_rt words=0 arch=riscv64",
        ]
        .map(str::to_owned)
        .to_vec();
        let got = placements(&lines, "init");
        let want: Vec<(&str, u64)> = vec![
            (KERNEL, 0x7fa0_0000),
            ("init", 0x33_9d74_9000),
            ("memmgr", 0x36_fde5_7000),
            ("procmgr", 0x30_c060_6000),
            ("devmgr", 0x34_aeaa_4000),
            ("/services/drivers/virtio-blk", 0x37_036e_3000),
            ("fatfs:/data", 0x36_c6f0_2000),
            // Unnamed: named by svcmgr's launch line, once.
            ("acpid", 0x30_c0dc_6000),
            ("sessiond", 0x30_d55d_a000),
        ];
        let got: Vec<(&str, u64)> = got.iter().map(|p| (p.name.as_str(), p.bias)).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn the_row_floor_grows_with_the_path()
    {
        assert_eq!(row_floor(0), 3);
        assert_eq!(row_floor(358), 3);
        assert_eq!(row_floor(97_213), 486);
    }

    #[test]
    fn the_block_is_replaced_in_place()
    {
        let doc = format!("# Title\n\nIntro.\n\n{BLOCK_BEGIN}\nold\n{BLOCK_END}\n\nAfter.\n");
        let new = format!("{BLOCK_BEGIN}\nnew\n{BLOCK_END}\n");
        assert_eq!(
            replace_block(&doc, &new).unwrap(),
            format!("# Title\n\nIntro.\n\n{BLOCK_BEGIN}\nnew\n{BLOCK_END}\n\nAfter.\n")
        );
        replace_block("# Title\n", &new).unwrap_err();
        let twice = format!("{doc}{BLOCK_BEGIN}\n");
        replace_block(&twice, &new).unwrap_err();
        let reversed = format!("{BLOCK_END}\n{BLOCK_BEGIN}\n");
        replace_block(&reversed, &new).unwrap_err();
    }
}
