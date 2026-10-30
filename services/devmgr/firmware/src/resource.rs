// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/resource.rs

//! Growable table of range capabilities that devmgr carves per-device caps from.
//!
//! devmgr holds its MMIO apertures and its Interrupt range as capabilities over
//! contiguous ranges, and narrows them with a split syscall (`SYS_MMIO_SPLIT`,
//! `SYS_IRQ_SPLIT`) that consumes a cap and returns its lower and upper
//! children. [`SpanTable`] records which cap covers which range and carves a
//! sub-range out of the covering cap, keeping both remainders in the table, so
//! no carve gives up authority over the rest of the range. The split itself is
//! passed in by the caller, which keeps this module free of syscalls and
//! host-testable.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

/// One range capability: `slot` covers `[base, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span<S>
{
    /// The capability over the range.
    pub slot: S,
    /// First address (or line) of the range.
    pub base: u64,
    /// One past the last address (or line) of the range. For a cap whose
    /// exact end is unknown it is an upper bound; see [`SplitError::OutOfRange`].
    pub end: u64,
}

/// Why the caller's split operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitError
{
    /// The split point lies outside the cap's range. When it is the upper
    /// cut of a carve, the cap ends at or below that point (its recorded end
    /// was only an upper bound), so the whole cap is the carved range.
    OutOfRange,
    /// Any other failure; the cap is unchanged.
    Failed,
}

/// Why [`SpanTable::carve`] carved nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarveError
{
    /// The range is empty, overflows, or no single span covers it.
    NotCovered,
    /// The table could not grow to hold a remainder; nothing was split.
    NoMemory,
    /// A split failed; the table still describes every cap that remains.
    Split,
}

/// Growable table of range capabilities, sorted by `base`, non-overlapping.
pub struct SpanTable<S>
{
    spans: Vec<Span<S>>,
}

impl<S: Copy> Default for SpanTable<S>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<S: Copy> SpanTable<S>
{
    /// An empty table.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { spans: Vec::new() }
    }

    /// The spans the table holds, sorted by `base`.
    #[must_use]
    pub fn spans(&self) -> &[Span<S>]
    {
        &self.spans
    }

    /// Record `slot` as covering `[base, base + size)`. An empty or
    /// overflowing range is not recorded and returns `Ok(false)`; the caller
    /// keeps the cap.
    ///
    /// # Errors
    /// Returns the allocation error when the table cannot grow.
    pub fn insert(&mut self, slot: S, base: u64, size: u64) -> Result<bool, TryReserveError>
    {
        let Some(end) = base.checked_add(size)
        else
        {
            return Ok(false);
        };
        if size == 0
        {
            return Ok(false);
        }
        self.spans.try_reserve(1)?;
        let at = self.spans.partition_point(|s| s.base < base);
        self.spans.insert(at, Span { slot, base, end });
        Ok(true)
    }

    /// Carve `[base, base + size)`, with its end rounded up to a multiple of
    /// `granule` (clamped to the covering span's end), out of the span that
    /// covers it, and return the carved cap. The lower remainder
    /// `[span.base, base)` and the upper remainder stay in the table as caps
    /// of their own.
    ///
    /// `split(span, at)` splits `span.slot` at the absolute point `at`,
    /// returning its lower and upper children; the caller converts `at` to
    /// whatever its syscall takes.
    ///
    /// # Errors
    /// [`CarveError::NotCovered`] when the range is empty, overflows, or no
    /// span covers it; [`CarveError::NoMemory`] when the table cannot grow (no
    /// split was made); [`CarveError::Split`] when a split fails, the table
    /// then still describing every remaining cap.
    pub fn carve(
        &mut self,
        base: u64,
        size: u64,
        granule: u64,
        mut split: impl FnMut(&Span<S>, u64) -> Result<(S, S), SplitError>,
    ) -> Result<S, CarveError>
    {
        let end = base.checked_add(size).ok_or(CarveError::NotCovered)?;
        if size == 0
        {
            return Err(CarveError::NotCovered);
        }
        let mut i = self
            .spans
            .iter()
            .position(|s| s.base <= base && end <= s.end)
            .ok_or(CarveError::NotCovered)?;
        // A carve below the span's base keeps its lower remainder as one more
        // entry; reserving first means the insert after the split cannot fail.
        self.spans
            .try_reserve(1)
            .map_err(|_| CarveError::NoMemory)?;

        let span = self.spans[i];
        if base > span.base
        {
            let (lower, upper) = split(&span, base).map_err(|_| CarveError::Split)?;
            self.spans[i] = Span {
                slot: lower,
                base: span.base,
                end: base,
            };
            self.spans.insert(
                i + 1,
                Span {
                    slot: upper,
                    base,
                    end: span.end,
                },
            );
            i += 1;
        }

        let span = self.spans[i];
        let cut = round_up(end, granule).map_or(span.end, |c| c.min(span.end));
        if cut < span.end
        {
            match split(&span, cut)
            {
                Ok((carved, rest)) =>
                {
                    self.spans[i] = Span {
                        slot: rest,
                        base: cut,
                        end: span.end,
                    };
                    return Ok(carved);
                }
                Err(SplitError::OutOfRange) =>
                {}
                Err(SplitError::Failed) => return Err(CarveError::Split),
            }
        }
        self.spans.remove(i);
        Ok(span.slot)
    }
}

/// `value` rounded up to a multiple of `granule` (a `granule` of 0 or 1
/// leaves it unchanged); `None` on overflow.
fn round_up(value: u64, granule: u64) -> Option<u64>
{
    if granule <= 1
    {
        return Some(value);
    }
    value.div_ceil(granule).checked_mul(granule)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A model of the kernel's range split: a cap is `(base, end)` and a
    /// split at `at` must satisfy `base < at < end`.
    fn split_model(span: &Span<(u64, u64)>, at: u64)
    -> Result<((u64, u64), (u64, u64)), SplitError>
    {
        let (b, e) = span.slot;
        if at <= b || at >= e
        {
            return Err(SplitError::OutOfRange);
        }
        Ok(((b, at), (at, e)))
    }

    fn table(ranges: &[(u64, u64)]) -> SpanTable<(u64, u64)>
    {
        let mut t = SpanTable::new();
        for &(b, e) in ranges
        {
            assert!(t.insert((b, e), b, e - b).unwrap());
        }
        t
    }

    /// Every span's recorded range matches the cap it holds, so no carve
    /// left the table describing a cap it no longer has.
    fn assert_consistent(t: &SpanTable<(u64, u64)>)
    {
        for s in t.spans()
        {
            assert_eq!(s.slot, (s.base, s.end));
        }
    }

    #[test]
    fn carve_keeps_both_remainders_past_any_fixed_table_size()
    {
        let mut t = table(&[(0, 0x100_0000)]);
        for k in 0..40u64
        {
            let base = 0x2000 + k * 0x4000;
            let carved = t.carve(base, 0x1000, 0x1000, split_model).unwrap();
            assert_eq!(carved, (base, base + 0x1000));
        }
        // 40 carves from one aperture leave 41 remainders, every one held.
        assert_eq!(t.spans().len(), 41);
        assert_eq!(t.spans()[0].slot, (0, 0x2000));
        assert_consistent(&t);
    }

    #[test]
    fn carve_rounds_the_end_up_to_the_granule_and_clamps_to_the_span()
    {
        let mut t = table(&[(0x1000, 0x5000)]);
        assert_eq!(
            t.carve(0x1000, 0x10, 0x1000, split_model),
            Ok((0x1000, 0x2000))
        );
        // The rounded end would pass the span: the carve takes the rest.
        let mut t2 = table(&[(0x1000, 0x1800)]);
        assert_eq!(
            t2.carve(0x1000, 0x10, 0x1000, split_model),
            Ok((0x1000, 0x1800))
        );
        assert!(t2.spans().is_empty());
        assert_consistent(&t);
    }

    #[test]
    fn carve_of_a_whole_span_removes_it_without_splitting()
    {
        let mut t = table(&[(0, 0x1000), (0x4000, 0x8000)]);
        let carved = t
            .carve(0x4000, 0x4000, 0x1000, |_, _| -> Result<_, SplitError> {
                panic!("a whole-span carve must not split")
            })
            .unwrap();
        assert_eq!(carved, (0x4000, 0x8000));
        assert_eq!(t.spans().len(), 1);
    }

    #[test]
    fn carve_not_covered_by_one_span_is_refused()
    {
        let mut t = table(&[(0, 0x1000), (0x1000, 0x2000)]);
        // Straddles two spans, lies past every span, is empty, overflows.
        assert_eq!(
            t.carve(0x800, 0x1000, 1, split_model),
            Err(CarveError::NotCovered)
        );
        assert_eq!(
            t.carve(0x3000, 1, 1, split_model),
            Err(CarveError::NotCovered)
        );
        assert_eq!(
            t.carve(0x10, 0, 1, split_model),
            Err(CarveError::NotCovered)
        );
        assert_eq!(
            t.carve(u64::MAX, 2, 1, split_model),
            Err(CarveError::NotCovered)
        );
        assert_eq!(t.spans().len(), 2);
    }

    #[test]
    fn failed_upper_split_keeps_the_part_from_the_carve_onward()
    {
        let mut t = table(&[(0, 0x4000)]);
        let mut calls = 0;
        let r = t.carve(0x1000, 0x1000, 0x1000, |s, at| {
            calls += 1;
            if calls == 2
            {
                Err(SplitError::Failed)
            }
            else
            {
                split_model(s, at)
            }
        });
        assert_eq!(r, Err(CarveError::Split));
        assert_eq!(t.spans().len(), 2);
        assert_consistent(&t);
    }

    #[test]
    fn failed_lower_split_leaves_the_table_unchanged()
    {
        let mut t = table(&[(0, 0x4000)]);
        let r = t.carve(0x1000, 0x1000, 1, |_, _| Err(SplitError::Failed));
        assert_eq!(r, Err(CarveError::Split));
        assert_eq!(
            t.spans(),
            &[Span {
                slot: (0, 0x4000),
                base: 0,
                end: 0x4000
            }]
        );
    }

    #[test]
    fn lower_line_isolated_after_a_higher_one_still_succeeds()
    {
        // An interrupt range whose end is unknown is recorded with an upper
        // bound; isolating line 40 first must keep lines 0..40.
        let mut t = SpanTable::new();
        assert!(t.insert((0, 64), 0, 1 << 32).unwrap());
        let model = |s: &Span<(u64, u64)>, at| split_model(s, at);
        assert_eq!(t.carve(40, 1, 1, model), Ok((40, 41)));
        assert_eq!(t.carve(33, 1, 1, model), Ok((33, 34)));
        assert_eq!(t.carve(39, 1, 1, model), Ok((39, 40)));
        assert_eq!(t.carve(0, 1, 1, model), Ok((0, 1)));
        let held: Vec<_> = t.spans().iter().map(|s| s.slot).collect();
        assert_eq!(held, [(1, 33), (34, 39), (41, 64)]);
    }

    #[test]
    fn out_of_range_upper_cut_takes_the_whole_cap_as_the_carve()
    {
        // The cap really ends at line 41; the table only knows an upper bound.
        let mut t = SpanTable::new();
        assert!(t.insert((0, 41), 0, 1 << 32).unwrap());
        assert_eq!(t.carve(40, 1, 1, split_model), Ok((40, 41)));
        assert_eq!(t.spans().len(), 1);
        assert_eq!(t.spans()[0].slot, (0, 40));
    }

    #[test]
    fn insert_keeps_spans_sorted_and_skips_empty_ranges()
    {
        let mut t = SpanTable::new();
        assert!(t.insert((0x5000, 0x6000), 0x5000, 0x1000).unwrap());
        assert!(t.insert((0x1000, 0x2000), 0x1000, 0x1000).unwrap());
        assert!(!t.insert((0x9000, 0x9000), 0x9000, 0).unwrap());
        assert!(!t.insert((0, 0), u64::MAX, 2).unwrap());
        let bases: Vec<_> = t.spans().iter().map(|s| s.base).collect();
        assert_eq!(bases, [0x1000, 0x5000]);
    }
}
