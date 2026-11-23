// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/path_account.rs

//! The per-path instruction account's logic, for `cargo xtask path-account`:
//! the counter reads a stepped trace holds, the window between the two whose
//! difference is the sample ktest recorded, the attribution of the window's
//! instructions to functions, the result file of one configuration, and the
//! Markdown block that sets the configurations side by side.
//!
//! xtask/README.md (`cargo xtask path-account`) states the method and its
//! checks; `commands::path_account` drives the boot and reads the files.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::ops::Range;

use crate::arch::Arch;
use crate::error::{Result, bail, ensure};

/// Where a counter read leaves the counter: `rdtsc` in EDX:EAX, `csrr cycle`
/// in one integer register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterDest
{
    /// x86-64 `rdtsc`: the high half in EDX, the low half in EAX.
    EdxEax,
    /// riscv64 `csrr rd, cycle`: the whole counter in `x<rd>`.
    Register(u8),
}

/// The counter read the instruction whose first bytes are `bytes` makes, if
/// it is one: `rdtsc` (`0f 31`) on x86-64, `csrrs rd, cycle, x0` on riscv64,
/// the two reads `shared/bench` makes. `bytes` starts at an instruction
/// boundary, as a stepped program counter does.
pub fn counter_read(arch: Arch, bytes: &[u8]) -> Option<CounterDest>
{
    match arch
    {
        Arch::X86_64 => bytes
            .starts_with(&[0x0f, 0x31])
            .then_some(CounterDest::EdxEax),
        Arch::Riscv64 =>
        {
            let word = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
            let opcode = word & 0x7f;
            let funct3 = (word >> 12) & 0x7;
            let rs1 = (word >> 15) & 0x1f;
            let csr = word >> 20;
            let rd = u8::try_from((word >> 7) & 0x1f).ok()?;
            (opcode == 0x73 && funct3 == 0b010 && rs1 == 0 && csr == 0xc00 && rd != 0)
                .then_some(CounterDest::Register(rd))
        }
    }
}

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

/// One stepped instruction: its program counter, and the counter value it
/// read when it is a counter read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step
{
    pub pc: u64,
    pub counter: Option<u64>,
}

/// The steps of the measured window: from the counter read that opened it to
/// the one that closed it, the closing read excluded, so the window holds the
/// instructions the counter advanced over.
///
/// The window is the one pair of counter reads in `steps` whose values differ
/// by `sample`, the value ktest recorded for the iteration.
///
/// # Errors
///
/// No pair or several pairs differ by `sample`; or the pair that does lies a
/// different number of steps apart than the counter advanced, so the stepped
/// path is not the one the counter measured.
pub fn window(steps: &[Step], sample: u64) -> Result<Range<usize>>
{
    let reads: Vec<(usize, u64)> = steps
        .iter()
        .enumerate()
        .filter_map(|(at, step)| Some((at, step.counter?)))
        .collect();
    let mut found = Vec::new();
    for (n, &(open, from)) in reads.iter().enumerate()
    {
        for &(close, to) in reads.iter().skip(n.saturating_add(1))
        {
            if to.wrapping_sub(from) == sample
            {
                found.push(open..close);
            }
        }
    }
    let window = match found.as_slice()
    {
        [one] => one.clone(),
        [] => bail!(
            "no two of the {} counter reads stepped differ by the sample {sample}",
            reads.len()
        ),
        several => bail!(
            "{} pairs of counter reads differ by the sample {sample}",
            several.len()
        ),
    };
    let stepped = u64::try_from(window.len())?;
    ensure!(
        stepped == sample,
        "{stepped} instructions were stepped between the counter reads, which advanced by \
         {sample}: the stepped path is not the measured one"
    );
    Ok(window)
}

/// The image an instruction lies in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Image
{
    /// The kernel.
    Kernel,
    /// ktest, the benchmark program: its loop, the syscall wrappers and the
    /// counter reads.
    Ktest,
    /// Neither: the firmware, or code no image covers.
    Other,
}

impl Image
{
    /// The image's name in the result file and the account.
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::Kernel => "kernel",
            Self::Ktest => "ktest",
            Self::Other => "other",
        }
    }

    fn from_name(name: &str) -> Option<Self>
    {
        match name
        {
            "kernel" => Some(Self::Kernel),
            "ktest" => Some(Self::Ktest),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

/// The function an instruction belongs to: its image, and the innermost
/// source function of its code, inlined or not.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Place
{
    pub image: Image,
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
    /// Tally the program counters `pcs`, each attributed by `place`.
    pub fn of(pcs: impl IntoIterator<Item = u64>, mut place: impl FnMut(u64) -> Place) -> Self
    {
        let mut tally = Self::default();
        for pc in pcs
        {
            tally.total = tally.total.saturating_add(1);
            let count = tally.by_place.entry(place(pc)).or_insert(0);
            *count = count.saturating_add(1);
        }
        tally
    }

    /// The instructions of `image`.
    pub fn of_image(&self, image: Image) -> u64
    {
        self.by_place
            .iter()
            .filter(|(place, _)| place.image == image)
            .map(|(_, &count)| count)
            .fold(0, u64::saturating_add)
    }
}

/// One traced measurement: its name, the counts it was checked against, and
/// its tally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path
{
    /// The measurement, as `bench-check` names it (`ktest.<name> [variant] cpus=1`).
    pub key: String,
    /// The p50 of the boot that was traced.
    pub p50: u64,
    /// The reference count: the checked-in baseline, or the reference logs' p50.
    pub reference: u64,
    /// The sample index traced.
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
                let _ = writeln!(
                    out,
                    "fn\t{}\t{}\t{count}",
                    place.image.name(),
                    place.function
                );
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
                    let Some(image) = Image::from_name(image)
                    else
                    {
                        bail!("{line:?}: unknown image");
                    };
                    let count = number(count, line)?;
                    path.tally.total = path.tally.total.saturating_add(count);
                    path.tally.by_place.insert(
                        Place {
                            image,
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
        for image in [
            None,
            Some(Image::Ktest),
            Some(Image::Kernel),
            Some(Image::Other),
        ]
        {
            let cells: Vec<Option<u64>> = configs
                .iter()
                .map(|c| {
                    let path = c.paths.iter().find(|p| &p.key == key)?;
                    Some(image.map_or(path.tally.total, |i| path.tally.of_image(i)))
                })
                .collect();
            if image == Some(Image::Other) && cells.iter().all(|c| matches!(c, None | Some(0)))
            {
                continue;
            }
            let label = image.map_or("all", Image::name);
            row(&mut out, &format!("`{key}`"), label, &cells);
        }
    }
    for key in &keys
    {
        let _ = write!(out, "\n#### `{key}`\n\n");
        header(&mut out, "Function", "Image", configs);
        for (place, cells) in place_rows(configs, key)
        {
            row(
                &mut out,
                &format!("`{}`", place.function),
                place.image.name(),
                &cells,
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
    rows.sort_by(|(pa, ca), (pb, cb)| {
        let most = |cells: &[Option<u64>]| cells.iter().flatten().copied().max().unwrap_or(0);
        most(cb).cmp(&most(ca)).then_with(|| pa.cmp(pb))
    });
    rows
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
