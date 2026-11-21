// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/snapshot.rs

//! The pure parts of `SNAPSHOT` (`services/procmgr/docs/ipc-interface.md`
//! § Label 33: `SNAPSHOT`): the joining of the runs `SYS_THREAD_LIST_PAGES` lists over
//! several calls, the pages a capture copies, and the layout's runs built from
//! what the capture found.
//!
//! A capture lists the held space's mapped pages ([`Listing`]), copies each
//! into the next data page of the object, in address order, a page whose copy
//! failed taking none, and records the pages whose copy failed and the ranges
//! memmgr reported it could not make resident. [`layout`] turns the three into the object's runs
//! (`ipc::procmgr_snapshot::Run`): the listed runs, cut where a copy failed,
//! and the reported ranges no listed page covers, each marked absent.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use ipc::procmgr_snapshot::{NO_OBJECT_PAGE, RUN_ABSENT, Run, layout_pages};
use syscall_abi::{
    PAGE_RUN_EXECUTE, PAGE_RUN_NO_COPY, PAGE_RUN_READ, PAGE_RUN_WRITE, PAGE_SIZE, PageRun,
};

/// The runs of one listing of a space, in ascending address order, a run
/// that continues the one before it with its protection joined to it, as the
/// last run of one `SYS_THREAD_LIST_PAGES` call and the first of the next may.
#[derive(Default)]
pub struct Listing
{
    runs: Vec<PageRun>,
}

impl Listing
{
    /// Add the runs one call listed, after those of the calls before it.
    ///
    /// # Errors
    /// The heap's refusal of the runs' memory.
    pub fn push(&mut self, listed: &[PageRun]) -> Result<(), TryReserveError>
    {
        for run in listed
        {
            if let Some(last) = self.runs.last_mut()
                && last.prot == run.prot
                && last.va.checked_add(last.pages.saturating_mul(PAGE_SIZE)) == Some(run.va)
            {
                last.pages = last.pages.saturating_add(run.pages);
                continue;
            }
            self.runs.try_reserve(1)?;
            self.runs.push(*run);
        }
        Ok(())
    }

    /// The runs listed.
    #[must_use]
    pub fn runs(&self) -> &[PageRun]
    {
        &self.runs
    }

    /// Pages the capture copies: every listed page but those of
    /// `PAGE_RUN_NO_COPY` runs, which `SYS_THREAD_READ_MEM` refuses.
    #[must_use]
    pub fn copied_pages(&self) -> u64
    {
        self.runs
            .iter()
            .filter(|r| r.prot & PAGE_RUN_NO_COPY == 0)
            .fold(0u64, |n, r| n.saturating_add(r.pages))
    }
}

/// A range memmgr reported it could not make resident (`RESIDENT_REPORT`):
/// `[va, end)`, with its region's protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reported
{
    /// First address, page-aligned.
    pub va: u64,
    /// End, exclusive, page-aligned.
    pub end: u64,
    /// The region's protection, `PAGE_RUN_*` bits.
    pub prot: u64,
}

impl Reported
{
    /// The range of `len` bytes at `va` that memmgr reported, of a region
    /// registered with the `MAP_*` bits `region_prot`. Every page memmgr
    /// maps is readable, whether or not the region names `MAP_READ` (the
    /// kernel lists a resident page of a region registered `MAP_WRITABLE`
    /// alone as `PAGE_RUN_READ | PAGE_RUN_WRITE`), so the range takes
    /// `PAGE_RUN_READ` beside the region's write and execute bits, as its
    /// listed pages would.
    #[must_use]
    pub fn new(va: u64, len: u64, region_prot: u64) -> Self
    {
        Self {
            va,
            end: va.saturating_add(len),
            prot: (region_prot & (PAGE_RUN_WRITE | PAGE_RUN_EXECUTE)) | PAGE_RUN_READ,
        }
    }
}

/// The layout of a capture: its runs, in ascending address order, with
/// their object pages, and what the header says of them.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout
{
    /// The runs, as `ipc::procmgr_snapshot::Run` entries.
    pub runs: Vec<Run>,
    /// Pages of the layout itself.
    pub layout_pages: u64,
    /// Data pages the runs use, after the layout's.
    pub data_pages: u64,
    /// No run is absent.
    pub complete: bool,
}

/// The layout of a capture whose listing under the hold is `listed`, whose
/// copy failed for the pages at the addresses `failed` (ascending), and for
/// which memmgr reported the ranges `reported` (ascending). Each page of a
/// listed run that is not `PAGE_RUN_NO_COPY` and whose copy held takes the
/// next data page, in address order, as the copy placed it. A run is cut
/// where a copy failed, the failed pages marked [`RUN_ABSENT`] with no object
/// page; a `PAGE_RUN_NO_COPY` run has no object page and is not absent; a reported
/// range is absent wherever no listed page covers it. Adjacent runs of one
/// flag word whose bytes follow one another in the object, or which have
/// none, are joined.
///
/// # Errors
/// The heap's refusal of the runs' memory.
pub fn layout(
    listed: &[PageRun],
    failed: &[u64],
    reported: &[Reported],
) -> Result<Layout, TryReserveError>
{
    let mut runs = Runs::default();
    let mut failed = failed.iter().copied().peekable();
    let mut data = 0u64;
    let mut gaps = Gaps { listed, next: 0 };
    let mut reported = reported.iter().copied().peekable();
    for run in listed
    {
        // The reported ranges below this run, and the parts of those that
        // reach into it, below it.
        while let Some(r) = reported.next_if(|r| r.va < run.va)
        {
            gaps.absent(&mut runs, r)?;
        }
        let end = run.va.saturating_add(run.pages.saturating_mul(PAGE_SIZE));
        if run.prot & PAGE_RUN_NO_COPY != 0
        {
            runs.push(run.va, run.pages, run.prot, NO_OBJECT_PAGE)?;
            continue;
        }
        let mut at = run.va;
        while at < end
        {
            while failed.next_if(|&va| va < at).is_some()
            {}
            let stop = failed.peek().copied().filter(|&va| va < end);
            let (pages, flags, page) = match stop
            {
                Some(va) if va == at => (1, run.prot | RUN_ABSENT, NO_OBJECT_PAGE),
                Some(va) => (va.saturating_sub(at) / PAGE_SIZE, run.prot, data),
                None => (end.saturating_sub(at) / PAGE_SIZE, run.prot, data),
            };
            runs.push(at, pages, flags, page)?;
            at = at.saturating_add(pages.saturating_mul(PAGE_SIZE));
            if page != NO_OBJECT_PAGE
            {
                data = data.saturating_add(pages);
            }
        }
    }
    for r in reported
    {
        gaps.absent(&mut runs, r)?;
    }
    runs.finish(data)
}

/// The runs of a layout as they are built, sorted on [`Runs::finish`].
#[derive(Default)]
struct Runs
{
    runs: Vec<Run>,
}

impl Runs
{
    /// Add a run, unless it has no page.
    fn push(
        &mut self,
        va: u64,
        pages: u64,
        flags: u64,
        object_page: u64,
    ) -> Result<(), TryReserveError>
    {
        if pages == 0
        {
            return Ok(());
        }
        self.runs.try_reserve(1)?;
        self.runs.push(Run {
            va,
            pages,
            flags,
            object_page,
        });
        Ok(())
    }

    /// Sort the runs by address, join each to the one before it where it
    /// continues it, and place their bytes after the layout's pages.
    fn finish(mut self, data_pages: u64) -> Result<Layout, TryReserveError>
    {
        self.runs.sort_unstable_by_key(|r| r.va);
        let mut joined: Vec<Run> = Vec::new();
        joined.try_reserve(self.runs.len())?;
        for run in self.runs
        {
            if let Some(last) = joined.last_mut()
                && continues(last, &run)
            {
                last.pages = last.pages.saturating_add(run.pages);
                continue;
            }
            joined.push(run);
        }
        // The heap holds the runs, so their layout's bytes fit a `u64`.
        let layout_pages = layout_pages(joined.len() as u64).unwrap_or(u64::MAX);
        for run in &mut joined
        {
            if run.object_page != NO_OBJECT_PAGE
            {
                run.object_page = run.object_page.saturating_add(layout_pages);
            }
        }
        let complete = joined.iter().all(|r| r.flags & RUN_ABSENT == 0);
        Ok(Layout {
            runs: joined,
            layout_pages,
            data_pages,
            complete,
        })
    }
}

/// Whether `run` continues `last`: it starts where `last` ends, with its
/// flags, and its bytes follow `last`'s in the object, or neither has any.
fn continues(last: &Run, run: &Run) -> bool
{
    let end = last.va.saturating_add(last.pages.saturating_mul(PAGE_SIZE));
    let bytes_follow = if last.object_page == NO_OBJECT_PAGE
    {
        run.object_page == NO_OBJECT_PAGE
    }
    else
    {
        last.object_page.checked_add(last.pages) == Some(run.object_page)
    };
    end == run.va && last.flags == run.flags && bytes_follow
}

/// The parts of reported ranges no listed run covers, found by a walk of the
/// listed runs that only moves forward, as the ranges come in address order.
struct Gaps<'a>
{
    listed: &'a [PageRun],
    /// The first listed run that may end above the next range.
    next: usize,
}

impl Gaps<'_>
{
    /// Add the parts of `r` no listed run covers to `runs`, absent.
    fn absent(&mut self, runs: &mut Runs, r: Reported) -> Result<(), TryReserveError>
    {
        let flags = r.prot | RUN_ABSENT;
        let mut at = r.va;
        while let Some(run) = self.listed.get(self.next)
            && at < r.end
        {
            let end = run.va.saturating_add(run.pages.saturating_mul(PAGE_SIZE));
            if end <= at
            {
                self.next = self.next.saturating_add(1);
                continue;
            }
            if run.va >= r.end
            {
                break;
            }
            if run.va > at
            {
                runs.push(
                    at,
                    run.va.saturating_sub(at) / PAGE_SIZE,
                    flags,
                    NO_OBJECT_PAGE,
                )?;
            }
            at = end;
        }
        if at < r.end
        {
            runs.push(
                at,
                r.end.saturating_sub(at) / PAGE_SIZE,
                flags,
                NO_OBJECT_PAGE,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use syscall_abi::{PAGE_RUN_READ, PAGE_RUN_WRITE};

    const P: u64 = PAGE_SIZE;
    const RW: u64 = PAGE_RUN_READ | PAGE_RUN_WRITE;

    fn listed(va: u64, pages: u64, prot: u64) -> PageRun
    {
        PageRun { va, pages, prot }
    }

    fn run(va: u64, pages: u64, flags: u64, object_page: u64) -> Run
    {
        Run {
            va,
            pages,
            flags,
            object_page,
        }
    }

    #[test]
    fn a_listing_joins_a_run_that_continues_the_last_with_its_protection()
    {
        let mut listing = Listing::default();
        listing
            .push(&[listed(0x1000, 2, RW), listed(0x5000, 1, RW)])
            .unwrap();
        listing
            .push(&[listed(0x6000, 3, RW), listed(0x9000, 1, PAGE_RUN_READ)])
            .unwrap();
        assert_eq!(
            listing.runs(),
            [
                listed(0x1000, 2, RW),
                listed(0x5000, 4, RW),
                listed(0x9000, 1, PAGE_RUN_READ)
            ]
        );
    }

    #[test]
    fn a_listing_holds_as_many_runs_as_the_heap_does()
    {
        // More runs than one layout page's worth many times over: no count
        // bounds a listing, only the heap.
        const RUNS: u64 = 40_000;
        let mut listing = Listing::default();
        let runs: Vec<PageRun> = (0..RUNS).map(|i| listed(i * 2 * P, 1, RW)).collect();
        listing.push(&runs).unwrap();
        // A run that continues the last is joined and needs no entry.
        let last = (RUNS - 1) * 2 * P;
        listing.push(&[listed(last + P, 1, RW)]).unwrap();
        listing.push(&[listed(last + 4 * P, 1, RW)]).unwrap();
        assert_eq!(listing.runs().len() as u64, RUNS + 1);
        assert_eq!(
            listing.runs().iter().rev().nth(1),
            Some(&listed(last, 2, RW))
        );
    }

    #[test]
    fn the_copied_pages_leave_out_no_copy_runs()
    {
        let mut listing = Listing::default();
        listing
            .push(&[
                listed(0x1000, 2, RW),
                listed(0x3000, 5, RW | PAGE_RUN_NO_COPY),
                listed(0x9000, 3, PAGE_RUN_READ),
            ])
            .unwrap();
        assert_eq!(listing.copied_pages(), 5);
    }

    #[test]
    fn a_whole_capture_places_each_run_after_the_layout_in_address_order()
    {
        let l = layout(
            &[listed(0x1000, 2, RW), listed(0x8000, 3, PAGE_RUN_READ)],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            l.runs,
            [run(0x1000, 2, RW, 1), run(0x8000, 3, PAGE_RUN_READ, 3)]
        );
        assert_eq!((l.layout_pages, l.data_pages, l.complete), (1, 5, true));
    }

    #[test]
    fn a_failed_copy_cuts_its_run_and_takes_no_data_page()
    {
        let l = layout(&[listed(0x1000, 4, RW)], &[0x2000, 0x3000], &[]).unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 1, RW, 1),
                run(0x2000, 2, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                run(0x4000, 1, RW, 2)
            ]
        );
        assert_eq!((l.data_pages, l.complete), (2, false));
    }

    #[test]
    fn a_no_copy_run_has_no_bytes_and_leaves_the_capture_complete()
    {
        let l = layout(
            &[
                listed(0x1000, 1, RW),
                listed(0x2000, 4, RW | PAGE_RUN_NO_COPY),
                listed(0x6000, 1, RW),
            ],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 1, RW, 1),
                run(0x2000, 4, RW | PAGE_RUN_NO_COPY, NO_OBJECT_PAGE),
                run(0x6000, 1, RW, 2)
            ]
        );
        assert_eq!((l.data_pages, l.complete), (2, true));
    }

    #[test]
    fn a_reported_range_is_absent_where_no_listed_page_covers_it()
    {
        // The range covers the listed run at 0x3000 and reaches past it; the
        // one at 0x20000 lies above every listed run.
        let l = layout(
            &[listed(0x3000, 1, RW), listed(0x9000, 1, RW)],
            &[],
            &[
                Reported {
                    va: 0x1000,
                    end: 0x5000,
                    prot: RW,
                },
                Reported {
                    va: 0x20000,
                    end: 0x22000,
                    prot: PAGE_RUN_READ,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 2, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                run(0x3000, 1, RW, 1),
                run(0x4000, 1, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                run(0x9000, 1, RW, 2),
                run(0x20000, 2, PAGE_RUN_READ | RUN_ABSENT, NO_OBJECT_PAGE)
            ]
        );
        assert!(!l.complete);
    }

    #[test]
    fn adjacent_absent_runs_of_one_protection_join()
    {
        // Two reported chunks back to back, and a failed page right after
        // the listed run below them.
        let l = layout(
            &[listed(0x1000, 2, RW)],
            &[0x2000],
            &[
                Reported {
                    va: 0x3000,
                    end: 0x5000,
                    prot: RW,
                },
                Reported {
                    va: 0x5000,
                    end: 0x7000,
                    prot: RW,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 1, RW, 1),
                run(0x2000, 5, RW | RUN_ABSENT, NO_OBJECT_PAGE)
            ]
        );
    }

    #[test]
    fn a_layout_past_one_page_places_the_data_after_every_layout_page()
    {
        // 127 runs, alternating protection, need a second layout page.
        let runs: Vec<PageRun> = (0..127u64)
            .map(|i| {
                listed(
                    0x1000 + i * P,
                    1,
                    if i % 2 == 0 { RW } else { PAGE_RUN_READ },
                )
            })
            .collect();
        let l = layout(&runs, &[], &[]).unwrap();
        assert_eq!(l.layout_pages, 2);
        assert_eq!(l.runs.first().map(|r| r.object_page), Some(2));
        assert_eq!(l.runs.last().map(|r| r.object_page), Some(128));
    }

    #[test]
    fn a_layout_of_alternating_failures_takes_a_run_a_page()
    {
        // Every other page failed: one run per page, and a layout sized to
        // them, with no count bounding it.
        const PAGES: u64 = 40_000;
        let failed: Vec<u64> = (0..PAGES).step_by(2).map(|i| 0x1000 + i * P).collect();
        let l = layout(&[listed(0x1000, PAGES, RW)], &failed, &[]).unwrap();
        assert_eq!(l.runs.len() as u64, PAGES);
        assert_eq!(Some(l.layout_pages), layout_pages(PAGES));
        assert_eq!(l.data_pages, PAGES / 2);
        assert!(!l.complete);
        let second = &l.runs[1];
        assert_eq!((second.pages, second.object_page), (1, l.layout_pages));
    }

    #[test]
    fn a_reported_range_is_readable_with_its_regions_write_and_execute_bits()
    {
        use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_RUN_EXECUTE};

        // A heap region registered MAP_WRITABLE alone.
        let r = Reported::new(0x4000, 3 * P, MAP_WRITABLE);
        assert_eq!(r.va, 0x4000);
        assert_eq!(r.end, 0x4000 + 3 * P);
        assert_eq!(r.prot, RW);
        assert_eq!(Reported::new(0x4000, P, MAP_READ).prot, PAGE_RUN_READ);
        assert_eq!(
            Reported::new(0x4000, P, MAP_READ | MAP_EXECUTABLE).prot,
            PAGE_RUN_READ | PAGE_RUN_EXECUTE
        );
        // Bits outside the protection, PAGE_RUN_NO_COPY's among them, are not
        // a region's.
        assert_eq!(
            Reported::new(0x4000, P, PAGE_RUN_NO_COPY | (1 << 9)).prot,
            PAGE_RUN_READ
        );
    }
}
