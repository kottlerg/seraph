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
    /// instructions a trap interrupted, and reads begun again.
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
                Event::Attempt { pc } | Event::Retry { pc } => unretired.push(pc),
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
/// indices into the record's reads, and the sample their values make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window
{
    pub open: usize,
    pub close: usize,
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
    /// Indices into the program's windows.
    pub windows: Range<usize>,
}

/// Divide a program's windows among its result lines, in order: each line
/// takes the next `n` windows, and their samples must summarize to the
/// line's.
///
/// # Errors
/// Too few windows for the lines, or a line whose windows' summary is not
/// its own: the pairing of the reads is not the program's.
pub fn rows(lines: &[(Key, Summary)], windows: &[Window]) -> Result<Vec<Row>>
{
    let mut out = Vec::with_capacity(lines.len());
    let mut next = 0usize;
    for (key, summary) in lines
    {
        let n = usize::try_from(summary.n)?;
        let end = next.checked_add(n).context("a sample count out of range")?;
        let Some(taken) = windows.get(next..end)
        else
        {
            bail!(
                "{key}: {n} samples, but {} windows are left of the program's reads",
                windows.len().saturating_sub(next)
            );
        };
        let mut samples: Vec<u64> = taken.iter().map(|w| w.sample).collect();
        let got = bench::summarize(&mut samples);
        ensure!(
            got.as_ref() == Some(summary),
            "{key}: the windows read for its {n} samples summarize to {got:?}, not to the \
             line's {summary:?}: the reads are not paired as the benchmark paired them"
        );
        out.push(Row {
            key: key.clone(),
            summary: *summary,
            windows: next..end,
        });
        next = end;
    }
    Ok(out)
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
                    sample: 5
                },
                Window {
                    open: 2,
                    close: 4,
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

    fn window(sample: u64) -> Window
    {
        Window {
            open: 0,
            close: 1,
            sample,
        }
    }

    fn summary(samples: &[u64]) -> Summary
    {
        bench::summarize(&mut samples.to_vec()).unwrap()
    }

    #[test]
    fn rows_take_their_windows_in_turn()
    {
        let ws: Vec<Window> = [5, 6, 5, 9, 9].into_iter().map(window).collect();
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
    fn rows_whose_windows_do_not_summarize_to_the_line_are_refused()
    {
        let ws: Vec<Window> = [5, 6, 5, 9].into_iter().map(window).collect();
        // One window short.
        let lines = [
            (key("a"), summary(&[5, 6, 5])),
            (key("b"), summary(&[9, 9])),
        ];
        rows(&lines, &ws).unwrap_err();
        // Misaligned: the first line's samples are not the first windows'.
        let lines = [(key("a"), summary(&[6, 5, 9]))];
        rows(&lines, &ws).unwrap_err();
    }
}
