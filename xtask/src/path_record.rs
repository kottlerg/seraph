// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/path_record.rs

//! The path-account plugin's record of a traced boot
//! (xtask/path-account-plugin/README.md), read back: its counter reads, a
//! benchmark program's measured windows among them, the result lines those
//! windows make up, and the instructions each window retired.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use bench::Summary;
use seraph_path_account_plugin::class::Arch as GuestArch;
use seraph_path_account_plugin::record::{Event, parse};

use crate::benchmark::Key;
use crate::error::{Context as _, Result, bail, ensure};

/// One user-mode counter read, and the segment of the boot it ended.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read
{
    pub pc: u64,
    pub value: u64,
    /// The histogram of the instructions run since the previous read.
    pub hist: u64,
    /// The addresses of the attempts in that segment that did not retire:
    /// instructions a trap interrupted, a counter read's executions before
    /// the one that retired among them.
    pub unretired: Vec<u64>,
}

/// A record, read.
#[derive(Debug)]
pub struct Record
{
    pub arch: GuestArch,
    hists: HashMap<u64, Vec<(u64, u64)>>,
    pub reads: Vec<Read>,
}

impl Record
{
    /// Read a record. A last line without its newline is left out: the
    /// plugin writes whole lines and flushes after each read, so such a line
    /// is one QEMU was killed in the middle of writing, after the last read.
    ///
    /// # Errors
    /// The header is missing or not first, a line is malformed, a read names
    /// a histogram not yet written, or a histogram identifier repeats.
    pub fn parse(text: &str) -> Result<Self>
    {
        let whole = text
            .rfind('\n')
            .and_then(|end| text.get(..=end))
            .unwrap_or("");
        let mut lines = whole.lines().enumerate();
        let Some(Ok(Event::Header { arch })) = lines.next().map(|(_, l)| parse(l))
        else
        {
            bail!("not a path-account record: its first line is not the header");
        };
        let mut hists = HashMap::new();
        let mut reads = Vec::new();
        let mut unretired = Vec::new();
        for (index, line) in lines
        {
            let at = || format!("record line {}", index.saturating_add(1));
            let event = parse(line)
                .map_err(crate::error::Error::msg)
                .with_context(at)?;
            match event
            {
                Event::Header { .. } => bail!("{}: a second header", at()),
                Event::Hist { id, entries } =>
                {
                    ensure!(
                        hists.insert(id, entries).is_none(),
                        "{}: histogram {id} written twice",
                        at()
                    );
                }
                Event::Read { pc, hist, value } =>
                {
                    ensure!(
                        hists.contains_key(&hist),
                        "{}: a read names histogram {hist}, not written before it",
                        at()
                    );
                    reads.push(Read {
                        pc,
                        value,
                        hist,
                        unretired: std::mem::take(&mut unretired),
                    });
                }
                Event::Attempt { pc } => unretired.push(pc),
            }
        }
        Ok(Self { arch, hists, reads })
    }

    /// The instructions retired from read `open` (itself included) to read
    /// `close` (excluded), by address: the segments the reads after `open`
    /// up to `close` ended, less each attempt in them that did not retire.
    ///
    /// # Errors
    /// An index past the reads, `close` not after `open`, or an attempt at an
    /// address its segments did not run.
    pub fn retired(&self, open: usize, close: usize) -> Result<BTreeMap<u64, u64>>
    {
        ensure!(open < close, "a window from read {open} to read {close}");
        let reads = self
            .reads
            .get(open.saturating_add(1)..=close)
            .context("a window past the record's reads")?;
        let mut by_pc: BTreeMap<u64, u64> = BTreeMap::new();
        for read in reads
        {
            let entries = self
                .hists
                .get(&read.hist)
                .context("a read's histogram is missing")?;
            for &(pc, count) in entries
            {
                let n = by_pc.entry(pc).or_insert(0);
                *n = n.saturating_add(count);
            }
        }
        for pc in reads.iter().flat_map(|r| &r.unretired)
        {
            let Some(n) = by_pc.get_mut(pc).filter(|n| **n > 0)
            else
            {
                bail!("an attempt at {pc:#x} that the window did not run");
            };
            *n = n.saturating_sub(1);
        }
        by_pc.retain(|_, n| *n > 0);
        Ok(by_pc)
    }
}

/// One measured window: an opening and a closing read of a program, as
/// indices into the record's reads, the addresses of the two reads (the
/// window's site: the measurement loop that read them), and the sample their
/// values make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window
{
    pub open: usize,
    pub close: usize,
    pub site: (u64, u64),
    pub sample: u64,
}

/// The windows of a program: its reads (those `in_program` takes) in order,
/// paired as the benchmarks read them, an opening read then a closing one. A
/// last read without its pair (the boot ended inside a window) is left out.
///
/// # Errors
/// A pair whose closing value is below its opening one.
pub fn windows(record: &Record, in_program: impl Fn(u64) -> bool) -> Result<Vec<Window>>
{
    let ours: Vec<usize> = record
        .reads
        .iter()
        .enumerate()
        .filter(|(_, r)| in_program(r.pc))
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::with_capacity(ours.len() / 2);
    for &[open, close] in ours.as_chunks::<2>().0
    {
        let (Some(a), Some(b)) = (record.reads.get(open), record.reads.get(close))
        else
        {
            bail!("a read index past the record");
        };
        let sample = b.value.checked_sub(a.value).with_context(|| {
            format!("the counter ran backwards from read {open} to read {close}")
        })?;
        out.push(Window {
            open,
            close,
            site: (a.pc, b.pc),
            sample,
        });
    }
    Ok(out)
}

/// One result line of a program and the windows that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row
{
    pub key: Key,
    pub summary: Summary,
    /// The warm-up windows before the row's samples, which the benchmark
    /// read and did not keep.
    pub warm_up: usize,
    /// Indices into the program's windows.
    pub windows: Range<usize>,
}

/// The line a division of the windows got furthest to and why it failed
/// there.
#[derive(Default)]
struct Miss
{
    line: usize,
    why: String,
}

/// Divide a program's windows among its result lines, in order.
///
/// A benchmark measures in a loop that reads the counter at the same two
/// addresses on every iteration, and runs a fixed number of warm-up
/// iterations, read as its samples are but not kept, before the `n` samples
/// of each line. The windows therefore fall into runs of one site, each the
/// windows of one or more consecutive lines (`ubench.ipc_rt`'s four lines
/// share one loop). A run of `T` windows taken by `k` lines of `n_1..n_k`
/// samples gives each line `(T - Σn) / k` warm-up windows, then its samples.
/// The division is the one in which every line's samples summarize to the
/// line's own summary, trying for each run the most lines first.
///
/// # Errors
/// No division of the windows into the lines' samples summarizes to every
/// line: the pairing of the reads is not the program's, or a benchmark does
/// not keep the last `n` windows of its loop.
pub fn rows(lines: &[(Key, Summary)], windows: &[Window]) -> Result<Vec<Row>>
{
    let mut runs: Vec<Range<usize>> = Vec::new();
    for (i, w) in windows.iter().enumerate()
    {
        let same = runs
            .last()
            .and_then(|run| windows.get(run.start))
            .is_some_and(|first| first.site == w.site);
        match runs.last_mut()
        {
            Some(run) if same => run.end = i.saturating_add(1),
            _ => runs.push(i..i.saturating_add(1)),
        }
    }
    let mut out = Vec::with_capacity(lines.len());
    let mut miss = Miss::default();
    if divide(lines, 0, windows, &runs, &mut out, &mut miss)?
    {
        return Ok(out);
    }
    let at = lines
        .get(miss.line)
        .map_or_else(|| "the lines".to_owned(), |(key, _)| key.to_string());
    bail!(
        "{at}: no division of the program's {} windows ({} runs of one site) among its {} lines \
         summarizes to every line: {}",
        windows.len(),
        runs.len(),
        lines.len(),
        miss.why
    )
}

impl Miss
{
    /// Note that line `line` failed for `why`, unless a division got further.
    fn note(&mut self, line: usize, why: impl FnOnce() -> String)
    {
        if line >= self.line
        {
            *self = Self { line, why: why() };
        }
    }
}

/// Give the first of `runs` to the most of `lines` (the program's lines
/// from index `first`) whose samples it holds, then the rest in turn.
fn divide(
    lines: &[(Key, Summary)],
    first: usize,
    windows: &[Window],
    runs: &[Range<usize>],
    out: &mut Vec<Row>,
    miss: &mut Miss,
) -> Result<bool>
{
    let Some((run, rest)) = runs.split_first()
    else
    {
        if lines.is_empty()
        {
            return Ok(true);
        }
        miss.note(first, || "no windows are left for it".to_owned());
        return Ok(false);
    };
    // The line counts whose samples fit the run with an equal warm-up each,
    // and that warm-up.
    let mut fits = Vec::new();
    let mut need = 0usize;
    for (taken, (_, summary)) in (1usize..).zip(lines)
    {
        need = need
            .checked_add(usize::try_from(summary.n)?)
            .context("a sample count out of range")?;
        let Some(spare) = run.len().checked_sub(need)
        else
        {
            break;
        };
        if spare.is_multiple_of(taken)
        {
            fits.push((taken, spare.checked_div(taken).unwrap_or(0)));
        }
    }
    if fits.is_empty()
    {
        miss.note(first, || {
            format!(
                "the run of windows {}..{} holds too few for its samples",
                run.start, run.end
            )
        });
    }
    for &(taken, warm_up) in fits.iter().rev()
    {
        let mark = out.len();
        let mut next = run.start;
        let mut kept = true;
        for (line, (key, summary)) in (first..).zip(lines.iter().take(taken))
        {
            let start = next
                .checked_add(warm_up)
                .context("a window index out of range")?;
            let end = start
                .checked_add(usize::try_from(summary.n)?)
                .context("a window index out of range")?;
            let mut samples: Vec<u64> = windows
                .get(start..end)
                .context("a run past the windows")?
                .iter()
                .map(|w| w.sample)
                .collect();
            let got = bench::summarize(&mut samples);
            if got.as_ref() != Some(summary)
            {
                miss.note(line, || {
                    format!(
                        "after {warm_up} warm-up windows, windows {start}..{end} summarize to \
                         {got:?}, not to the line's {summary:?}"
                    )
                });
                kept = false;
                break;
            }
            out.push(Row {
                key: key.clone(),
                summary: *summary,
                warm_up,
                windows: start..end,
            });
            next = end;
        }
        if kept
            && divide(
                lines.get(taken..).unwrap_or_default(),
                first.saturating_add(taken),
                windows,
                rest,
                out,
                miss,
            )?
        {
            return Ok(true);
        }
        out.truncate(mark);
    }
    Ok(false)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn key(name: &str) -> Key
    {
        Key {
            bench: format!("ubench.{name}"),
            variant: String::new(),
            cpus: 1,
        }
    }

    const RECORD: &str = "seraph-path-account 1 x86_64
H 0 100:5
R 1000 0 10
H 1 1000:1 1002:3 ffffffff80000000:2
A 1002
R 1000 1 15
H 2 1000:1 1002:3
R 1000 2 19
R 2000 2 50
R 1000 2 23
";

    #[test]
    fn a_record_reads_into_its_reads_and_windows()
    {
        let record = Record::parse(RECORD).unwrap();
        assert_eq!(record.arch, GuestArch::X86_64);
        assert_eq!(record.reads.len(), 5);
        assert_eq!(record.reads[1].unretired, [0x1002]);
        let w = windows(&record, |pc| pc == 0x1000).unwrap();
        assert_eq!(
            w,
            [
                Window {
                    open: 0,
                    close: 1,
                    site: (0x1000, 0x1000),
                    sample: 5
                },
                Window {
                    open: 2,
                    close: 4,
                    site: (0x1000, 0x1000),
                    sample: 4
                },
            ]
        );
    }

    #[test]
    fn a_window_retires_its_segments_less_their_unretired_attempts()
    {
        let record = Record::parse(RECORD).unwrap();
        let one = record.retired(0, 1).unwrap();
        assert_eq!(
            one,
            BTreeMap::from([(0x1000, 1), (0x1002, 2), (0xffff_ffff_8000_0000, 2)])
        );
        assert_eq!(one.values().sum::<u64>(), 5);
        // A window across another program's read sums both segments.
        let two = record.retired(2, 4).unwrap();
        assert_eq!(two, BTreeMap::from([(0x1000, 2), (0x1002, 6)]));
        record.retired(1, 1).unwrap_err();
        record.retired(3, 9).unwrap_err();
    }

    #[test]
    fn a_read_run_twice_counts_its_attempt_in_the_window_it_opens()
    {
        // The read at 1000 opening the window ran twice; its attempt follows
        // it and the window retires it once.
        let record = Record::parse(
            "seraph-path-account 1 x86_64
H 0 100:5
R 1000 0 10
A 1000
H 1 1000:2 1002:3
R 1000 1 14
",
        )
        .unwrap();
        assert_eq!(
            record.retired(0, 1).unwrap(),
            BTreeMap::from([(0x1000, 1), (0x1002, 3)])
        );
    }

    #[test]
    fn malformed_records_are_refused()
    {
        Record::parse("R 1000 0 10\n").unwrap_err();
        Record::parse("seraph-path-account 1 x86_64\nR 1000 0 10\n").unwrap_err();
        Record::parse("seraph-path-account 1 x86_64\nH 0\nH 0\n").unwrap_err();
        Record::parse("seraph-path-account 1 x86_64\nseraph-path-account 1 x86_64\n").unwrap_err();
        // A partly written last line is left out.
        let cut = Record::parse("seraph-path-account 1 x86_64\nH 0 10:1\nR 1 0 1\nH 1 1").unwrap();
        assert_eq!(cut.reads.len(), 1);
        let unrun =
            Record::parse("seraph-path-account 1 x86_64\nH 0 10:1\nR 1 0 1\nA 20\nR 1 0 2\n")
                .unwrap();
        unrun.retired(0, 1).unwrap_err();
    }

    #[test]
    fn a_backwards_counter_is_refused()
    {
        let record =
            Record::parse("seraph-path-account 1 x86_64\nH 0\nR 1 0 9\nR 1 0 3\n").unwrap();
        windows(&record, |_| true).unwrap_err();
    }

    fn window(site: u64, sample: u64) -> Window
    {
        Window {
            open: 0,
            close: 1,
            site: (site, site + 8),
            sample,
        }
    }

    fn summary(samples: &[u64]) -> Summary
    {
        bench::summarize(&mut samples.to_vec()).unwrap()
    }

    fn at(site: u64, samples: &[u64]) -> Vec<Window>
    {
        samples.iter().map(|&s| window(site, s)).collect()
    }

    #[test]
    fn rows_take_their_windows_in_turn()
    {
        let ws = [at(1, &[5, 6, 5]), at(2, &[9, 9])].concat();
        let lines = [
            (key("a"), summary(&[5, 6, 5])),
            (key("b"), summary(&[9, 9])),
        ];
        let got = rows(&lines, &ws).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got.first().unwrap().windows, 0..3);
        assert_eq!(got[1].windows, 3..5);
    }

    #[test]
    fn rows_of_one_loop_skip_an_equal_warm_up_each()
    {
        // Two lines of one site, two warm-up windows before each line's
        // samples, then a line of its own site with none.
        let ws = [at(1, &[90, 80, 5, 6, 5, 70, 60, 7, 8]), at(2, &[9, 9])].concat();
        let lines = [
            (key("a"), summary(&[5, 6, 5])),
            (key("b"), summary(&[7, 8])),
            (key("c"), summary(&[9, 9])),
        ];
        let got = rows(&lines, &ws).unwrap();
        let spans: Vec<(usize, Range<usize>)> =
            got.iter().map(|r| (r.warm_up, r.windows.clone())).collect();
        assert_eq!(spans, [(2, 2..5), (2, 7..9), (0, 9..11)]);
    }

    #[test]
    fn rows_whose_windows_do_not_summarize_to_the_line_are_refused()
    {
        // One window short.
        let ws = [at(1, &[5, 6, 5]), at(2, &[9])].concat();
        let lines = [
            (key("a"), summary(&[5, 6, 5])),
            (key("b"), summary(&[9, 9])),
        ];
        rows(&lines, &ws).unwrap_err();
        // Misaligned: the line's samples are not the run's last windows.
        let ws = at(1, &[6, 5, 9, 1]);
        let lines = [(key("a"), summary(&[6, 5, 9]))];
        rows(&lines, &ws).unwrap_err();
        // A run that no line takes.
        let ws = [at(1, &[5, 6, 5]), at(2, &[9, 9])].concat();
        let lines = [(key("a"), summary(&[5, 6, 5]))];
        rows(&lines, &ws).unwrap_err();
    }
}
