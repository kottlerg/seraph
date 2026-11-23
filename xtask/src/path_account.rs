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
    /// The reference count: the lowest p50 of the reference logs.
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
                    place.image.name(),
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

#[cfg(test)]
mod tests
{
    use super::*;

    fn step(pc: u64, counter: Option<u64>) -> Step
    {
        Step { pc, counter }
    }

    /// Steps 0..n, with counter reads at the given indices and values.
    fn steps(n: u64, reads: &[(u64, u64)]) -> Vec<Step>
    {
        (0..n)
            .map(|i| step(i, reads.iter().find(|(at, _)| *at == i).map(|(_, v)| *v)))
            .collect()
    }

    #[test]
    fn rdtsc_is_a_counter_read_on_x86_64_only()
    {
        assert_eq!(
            counter_read(Arch::X86_64, &[0x0f, 0x31, 0x48, 0x89]),
            Some(CounterDest::EdxEax)
        );
        assert_eq!(counter_read(Arch::X86_64, &[0x0f, 0x05]), None);
        assert_eq!(counter_read(Arch::Riscv64, &[0x0f, 0x31, 0x00, 0x00]), None);
    }

    #[test]
    fn csrr_cycle_is_a_counter_read_on_riscv64()
    {
        // csrr a0, cycle = csrrs x10, 0xc00, x0.
        let word: u32 = (0xc00 << 20) | (0b010 << 12) | (10 << 7) | 0x73;
        assert_eq!(
            counter_read(Arch::Riscv64, &word.to_le_bytes()),
            Some(CounterDest::Register(10))
        );
        // csrr a0, time (0xc01) is not the cycle counter.
        let time: u32 = (0xc01 << 20) | (0b010 << 12) | (10 << 7) | 0x73;
        assert_eq!(counter_read(Arch::Riscv64, &time.to_le_bytes()), None);
        // A read into x0 is discarded.
        let zero: u32 = (0xc00 << 20) | (0b010 << 12) | 0x73;
        assert_eq!(counter_read(Arch::Riscv64, &zero.to_le_bytes()), None);
        // A csrrs that sets bits (rs1 != x0) is not a plain read.
        let set: u32 = (0xc00 << 20) | (5 << 15) | (0b010 << 12) | (10 << 7) | 0x73;
        assert_eq!(counter_read(Arch::Riscv64, &set.to_le_bytes()), None);
        assert_eq!(counter_read(Arch::Riscv64, &[0x73, 0x00]), None);
    }

    #[test]
    fn the_window_is_the_pair_that_differs_by_the_sample()
    {
        // Reads at 2 (100) and 9 (107): 7 instructions, 2..9.
        let trace = steps(12, &[(2, 100), (9, 107), (11, 200)]);
        assert_eq!(window(&trace, 7).unwrap(), 2..9);
    }

    #[test]
    fn a_window_whose_steps_differ_from_the_sample_is_rejected()
    {
        // The counter advanced by 5 over 7 stepped instructions.
        let trace = steps(12, &[(2, 100), (9, 105)]);
        let err = window(&trace, 5).unwrap_err().to_string();
        assert!(err.contains("not the measured one"), "{err}");
    }

    #[test]
    fn no_pair_or_several_pairs_are_rejected()
    {
        let trace = steps(12, &[(1, 100), (4, 103), (7, 106)]);
        window(&trace, 4).unwrap_err();
        let err = window(&trace, 3).unwrap_err().to_string();
        assert!(err.contains("2 pairs"), "{err}");
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

    fn place(image: Image, function: &str) -> Place
    {
        Place {
            image,
            function: function.to_owned(),
        }
    }

    fn config(arch: &str, profile: &str, null: u64) -> Configuration
    {
        let tally = Tally::of(0..null, |pc| match pc
        {
            0..=3 => place(Image::Ktest, "bench::arch::current::cycles"),
            4 => place(Image::Kernel, "kernel::cap::sole_reference::drain"),
            _ => place(Image::Kernel, "kernel::syscall::dispatch"),
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
        assert_eq!(tally.of_image(Image::Ktest), 4);
        assert_eq!(tally.of_image(Image::Kernel), 16);
        assert_eq!(tally.of_image(Image::Other), 0);
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
fn	firmware	f	1
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
