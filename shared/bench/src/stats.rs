// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/stats.rs

//! Sample recording and the summary the result line reports.
//!
//! A benchmark records one sample per measured operation into a buffer the
//! caller owns ([`Samples`]), so the crate needs no allocator: ktest hands it
//! a static array, a program a `Vec`. The summary sorts the samples in place
//! and reads the minimum, the maximum and the 50th, 90th and 99th percentiles
//! by nearest rank: the p-th percentile of n sorted samples is the sample of
//! rank ceil(p * n / 100), counting ranks from 1. Every reported value is a
//! sample that was taken, never an interpolation between two.

/// The summary of one benchmark's samples, in the unit they were recorded in.
///
/// [`summarize`] builds one with `n >= 1` and
/// `min <= p50 <= p90 <= p99 <= max`; [`Summary::is_well_formed`] checks a
/// summary built any other way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary
{
    /// Samples summarised.
    pub n: u64,
    /// Smallest sample.
    pub min: u64,
    /// 50th percentile (the median), by nearest rank.
    pub p50: u64,
    /// 90th percentile, by nearest rank.
    pub p90: u64,
    /// 99th percentile, by nearest rank.
    pub p99: u64,
    /// Largest sample.
    pub max: u64,
}

impl Summary
{
    /// Whether the summary covers at least one sample and its values are in
    /// order: `min <= p50 <= p90 <= p99 <= max`.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool
    {
        self.n >= 1
            && self.min <= self.p50
            && self.p50 <= self.p90
            && self.p90 <= self.p99
            && self.p99 <= self.max
    }
}

/// The 0-based index of the nearest-rank `percent`-th percentile among
/// `n >= 1` sorted samples: rank ceil(percent * n / 100), less one. The
/// product is taken in `u128`, so no `n` overflows it.
fn nearest_rank_index(n: usize, percent: u8) -> usize
{
    let scaled = (n as u128).saturating_mul(u128::from(percent));
    let rank = scaled.div_ceil(100).max(1);
    usize::try_from(rank.saturating_sub(1)).unwrap_or(usize::MAX)
}

/// Sort `samples` in place and summarise them; `None` for no sample.
#[must_use]
pub fn summarize(samples: &mut [u64]) -> Option<Summary>
{
    samples.sort_unstable();
    let n = samples.len();
    let at = |percent: u8| samples.get(nearest_rank_index(n, percent)).copied();
    Some(Summary {
        n: u64::try_from(n).ok()?,
        min: *samples.first()?,
        p50: at(50)?,
        p90: at(90)?,
        p99: at(99)?,
        max: *samples.last()?,
    })
}

/// A benchmark's samples, recorded into a buffer the caller owns.
///
/// The buffer's length is the capacity: a benchmark sizes its iteration count
/// to [`Samples::capacity`], and a sample past it is refused, never wrapped
/// over an earlier one.
#[derive(Debug)]
pub struct Samples<'a>
{
    /// The caller's buffer; the first `len` entries are the samples.
    buf: &'a mut [u64],
    /// Samples recorded.
    len: usize,
}

impl<'a> Samples<'a>
{
    /// An empty recorder over `buf`, whose earlier contents are ignored.
    #[must_use]
    pub const fn new(buf: &'a mut [u64]) -> Self
    {
        Self { buf, len: 0 }
    }

    /// The most samples the buffer holds.
    #[must_use]
    pub const fn capacity(&self) -> usize
    {
        self.buf.len()
    }

    /// Samples recorded so far.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.len
    }

    /// Whether no sample is recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// Record one sample; `false`, recording nothing, once the buffer is
    /// full.
    pub fn record(&mut self, sample: u64) -> bool
    {
        let Some(slot) = self.buf.get_mut(self.len)
        else
        {
            return false;
        };
        *slot = sample;
        self.len = self.len.saturating_add(1);
        true
    }

    /// The samples recorded, in the order recorded until [`Samples::summary`]
    /// sorts them.
    #[must_use]
    pub fn as_slice(&self) -> &[u64]
    {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Sort the recorded samples in place and summarise them; `None` when
    /// none is recorded. Recording may go on after it.
    #[must_use]
    pub fn summary(&mut self) -> Option<Summary>
    {
        summarize(self.buf.get_mut(..self.len)?)
    }
}

#[cfg(test)]
mod tests
{
    use super::{Samples, Summary, nearest_rank_index, summarize};

    #[test]
    fn nearest_rank_matches_the_definition()
    {
        // n = 1: every percentile is the one sample.
        assert_eq!(nearest_rank_index(1, 50), 0);
        assert_eq!(nearest_rank_index(1, 99), 0);
        // n = 100: rank p.
        assert_eq!(nearest_rank_index(100, 50), 49);
        assert_eq!(nearest_rank_index(100, 90), 89);
        assert_eq!(nearest_rank_index(100, 99), 98);
        // n = 101: ceil(50.5) = 51, ceil(90.9) = 91, ceil(99.99) = 100.
        assert_eq!(nearest_rank_index(101, 50), 50);
        assert_eq!(nearest_rank_index(101, 90), 90);
        assert_eq!(nearest_rank_index(101, 99), 99);
        // n = 10: ceil(5) = 5, ceil(9) = 9, ceil(9.9) = 10.
        assert_eq!(nearest_rank_index(10, 50), 4);
        assert_eq!(nearest_rank_index(10, 90), 8);
        assert_eq!(nearest_rank_index(10, 99), 9);
        // No overflow at the largest n.
        assert_eq!(nearest_rank_index(usize::MAX, 100), usize::MAX - 1);
    }

    #[test]
    fn summarize_sorts_and_reads_nearest_ranks()
    {
        // 1..=100 shuffled by a fixed stride coprime to 100.
        let mut samples: [u64; 100] = core::array::from_fn(|i| ((i * 37) % 100 + 1) as u64);
        let summary = summarize(&mut samples);
        assert_eq!(
            summary,
            Some(Summary {
                n: 100,
                min: 1,
                p50: 50,
                p90: 90,
                p99: 99,
                max: 100,
            })
        );
        assert!(samples.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn summarize_of_one_sample_is_that_sample()
    {
        let mut samples = [7u64];
        assert_eq!(
            summarize(&mut samples),
            Some(Summary {
                n: 1,
                min: 7,
                p50: 7,
                p90: 7,
                p99: 7,
                max: 7,
            })
        );
    }

    #[test]
    fn summarize_of_nothing_is_none()
    {
        assert_eq!(summarize(&mut []), None);
    }

    #[test]
    fn summaries_are_well_formed()
    {
        let mut samples = [5u64, 1, 9, 9, 3, 0, u64::MAX, 4];
        let summary = summarize(&mut samples);
        assert!(summary.is_some_and(|s| s.is_well_formed()));
        assert_eq!(summary.map(|s| (s.min, s.max)), Some((0, u64::MAX)));
    }

    #[test]
    fn ill_formed_summaries_are_detected()
    {
        let good = Summary {
            n: 3,
            min: 1,
            p50: 2,
            p90: 3,
            p99: 3,
            max: 3,
        };
        assert!(good.is_well_formed());
        assert!(!Summary { n: 0, ..good }.is_well_formed());
        assert!(!Summary { min: 3, ..good }.is_well_formed());
        assert!(!Summary { p90: 1, ..good }.is_well_formed());
        assert!(!Summary { max: 2, ..good }.is_well_formed());
    }

    #[test]
    fn samples_refuse_past_capacity()
    {
        let mut buf = [0u64; 3];
        let mut samples = Samples::new(&mut buf);
        assert_eq!(samples.capacity(), 3);
        assert!(samples.is_empty());
        assert!(samples.record(30));
        assert!(samples.record(10));
        assert!(samples.record(20));
        assert!(!samples.record(40));
        assert_eq!(samples.len(), 3);
        assert_eq!(samples.as_slice(), &[30, 10, 20]);
        assert_eq!(
            samples.summary().map(|s| (s.n, s.min, s.p50, s.max)),
            Some((3, 10, 20, 30))
        );
        assert_eq!(samples.as_slice(), &[10, 20, 30]);
    }

    #[test]
    fn samples_ignore_the_buffer_past_the_recorded_count()
    {
        let mut buf = [99u64; 4];
        let mut samples = Samples::new(&mut buf);
        assert_eq!(samples.summary(), None);
        assert!(samples.record(1));
        assert_eq!(samples.summary().map(|s| (s.n, s.max)), Some((1, 1)));
    }
}
