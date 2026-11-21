// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/snapshot.rs

//! The pure parts of `SNAPSHOT` (`services/procmgr/docs/ipc-interface.md`
//! § Label 33: `SNAPSHOT`): the joining of the runs `SYS_THREAD_LIST_PAGES` lists over
//! several calls, the pages a capture copies, and the layout's runs built from
//! what the capture found.
//!
//! Under the hold, a capture lists the held space's mapped pages ([`Listing`])
//! and has memmgr supply the content of every demand chunk with an entry,
//! wherever memmgr holds it (`memmgr_labels::CAPTURE_CHUNKS`), each chunk
//! described by a [`Chunk`]: the backed pages of the chunks memmgr supplied
//! take the first data pages of the object, in the order memmgr wrote them,
//! with any pages the capture passed over to give memmgr room left unused. It
//! then copies the listed pages outside every chunk ([`outside`]) into the
//! next data pages, in address order, a page whose copy failed taking none.
//! [`layout`] turns the three into the object's runs
//! (`ipc::procmgr_snapshot::Run`): the pages outside the chunks, cut where a
//! copy failed, and the backed pages of each chunk, those memmgr did not
//! supply marked absent.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use ipc::memmgr_capture::{Descriptor, Supply};
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

    /// Pages a copy of the listing takes ([`copied_pages`]).
    #[must_use]
    pub fn copied_pages(&self) -> u64
    {
        copied_pages(&self.runs)
    }
}

/// Pages a copy of `runs` takes: every page but those of `PAGE_RUN_NO_COPY`
/// runs, which `SYS_THREAD_READ_MEM` refuses.
#[must_use]
pub fn copied_pages(runs: &[PageRun]) -> u64
{
    runs.iter()
        .filter(|r| r.prot & PAGE_RUN_NO_COPY == 0)
        .fold(0u64, |n, r| n.saturating_add(r.pages))
}

/// A demand chunk of the held space that memmgr reached
/// (`memmgr_labels::CAPTURE_CHUNKS`): its range, its backed pages, their
/// protection, what memmgr did with it, and where the object holds its pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk
{
    /// The chunk's base, page-aligned.
    pub va: u64,
    /// The chunk's pages.
    pub pages: u64,
    /// The chunk's backed pages, bit `i` for its page `i`.
    pub backed: u16,
    /// The protection of its pages, `PAGE_RUN_*` bits.
    pub prot: u64,
    /// What memmgr did with the chunk. The object holds its pages only when
    /// memmgr supplied them; a chunk still pending when the capture stops
    /// waiting is absent, as an absent one is.
    pub supply: Supply,
    /// The data page of the chunk's first backed page, when supplied: the
    /// others follow it in page order.
    pub data: u64,
}

impl Chunk
{
    /// The chunk memmgr's descriptor `d` names, whose pages, when supplied,
    /// take the data pages from `data`. Every page memmgr maps is readable,
    /// whether or not the region names `MAP_READ` (the kernel lists a resident
    /// page of a region registered `MAP_WRITABLE` alone as
    /// `PAGE_RUN_READ | PAGE_RUN_WRITE`), so the chunk's pages take
    /// `PAGE_RUN_READ` beside the region's write and execute bits (`MAP_*`,
    /// the same bits), as its listed pages would.
    #[must_use]
    pub fn new(d: &Descriptor, data: u64) -> Self
    {
        Self {
            va: d.va,
            pages: d.pages,
            backed: d.backed,
            prot: (d.prot & (PAGE_RUN_WRITE | PAGE_RUN_EXECUTE)) | PAGE_RUN_READ,
            supply: d.supply,
            data,
        }
    }

    /// The chunk's end, exclusive.
    #[must_use]
    pub fn end(&self) -> u64
    {
        self.va.saturating_add(self.pages.saturating_mul(PAGE_SIZE))
    }
}

/// The parts of the listed runs `listed` outside every chunk of `chunks`
/// (ascending, disjoint), in address order: the pages a capture copies from
/// the space itself, since memmgr supplies, or reports, every page of a chunk.
///
/// # Errors
/// The heap's refusal of the runs' memory.
pub fn outside(listed: &[PageRun], chunks: &[Chunk]) -> Result<Vec<PageRun>, TryReserveError>
{
    let mut out = Vec::new();
    let mut next = 0usize;
    for run in listed
    {
        let end = run.va.saturating_add(run.pages.saturating_mul(PAGE_SIZE));
        let mut at = run.va;
        while at < end
        {
            while chunks.get(next).is_some_and(|c| c.end() <= at)
            {
                next = next.saturating_add(1);
            }
            let stop = match chunks.get(next)
            {
                // Inside the chunk: its pages are memmgr's to give.
                Some(c) if c.va <= at =>
                {
                    at = c.end().min(end);
                    continue;
                }
                Some(c) => c.va.min(end),
                None => end,
            };
            out.try_reserve(1)?;
            out.push(PageRun {
                va: at,
                pages: stop.saturating_sub(at) / PAGE_SIZE,
                prot: run.prot,
            });
            at = stop;
        }
    }
    Ok(out)
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

/// The layout of a capture whose listed pages outside every chunk are
/// `outside` ([`outside`]), copied from data page `first_copy` on, whose copy
/// failed for the pages at the addresses `failed` (ascending), and whose
/// demand chunks are `chunks`. Each page of `outside` that is not
/// `PAGE_RUN_NO_COPY` and whose copy held takes the next data page, in
/// address order, as the copy placed it; a run is cut where a copy failed, the
/// failed pages marked [`RUN_ABSENT`] with no object page; a
/// `PAGE_RUN_NO_COPY` run has no object page and is not absent. Each backed
/// page of a chunk memmgr supplied takes its place from the chunk's data
/// page; those of any other chunk are absent. Adjacent runs of one flag word
/// whose bytes follow one another in the object, or which have none, are
/// joined.
///
/// # Errors
/// The heap's refusal of the runs' memory.
pub fn layout(
    outside: &[PageRun],
    first_copy: u64,
    failed: &[u64],
    chunks: &[Chunk],
) -> Result<Layout, TryReserveError>
{
    let mut runs = Runs::default();
    let mut failed = failed.iter().copied().peekable();
    let mut data = first_copy;
    for run in outside
    {
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
    for chunk in chunks
    {
        runs.push_chunk(chunk)?;
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

    /// Add a run for each span of consecutive backed pages of `chunk`: with
    /// their data pages when memmgr supplied it, else absent.
    fn push_chunk(&mut self, chunk: &Chunk) -> Result<(), TryReserveError>
    {
        let supplied = chunk.supply == Supply::Supplied;
        let held = |page: u64| {
            u32::try_from(page)
                .ok()
                .and_then(|p| chunk.backed.checked_shr(p))
                .is_some_and(|b| b & 1 != 0)
        };
        let (mut page, mut rank) = (0u64, 0u64);
        while page < chunk.pages
        {
            if !held(page)
            {
                page = page.saturating_add(1);
                continue;
            }
            let span = (page..chunk.pages).take_while(|&p| held(p)).count() as u64;
            let va = chunk.va.saturating_add(page.saturating_mul(PAGE_SIZE));
            if supplied
            {
                self.push(va, span, chunk.prot, chunk.data.saturating_add(rank))?;
            }
            else
            {
                self.push(va, span, chunk.prot | RUN_ABSENT, NO_OBJECT_PAGE)?;
            }
            rank = rank.saturating_add(span);
            page = page.saturating_add(span);
        }
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

#[cfg(test)]
mod tests
{
    use super::*;
    use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_RUN_READ, PAGE_RUN_WRITE};

    const P: u64 = PAGE_SIZE;
    const RW: u64 = PAGE_RUN_READ | PAGE_RUN_WRITE;

    fn listed(va: u64, pages: u64, prot: u64) -> PageRun
    {
        PageRun { va, pages, prot }
    }

    fn chunk(va: u64, pages: u64, backed: u16, supply: Supply, data: u64) -> Chunk
    {
        Chunk::new(
            &Descriptor {
                va,
                pages,
                backed,
                prot: MAP_READ | MAP_WRITABLE,
                supply,
            },
            data,
        )
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
            0,
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
        let l = layout(&[listed(0x1000, 4, RW)], 0, &[0x2000, 0x3000], &[]).unwrap();
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
            0,
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
    fn the_copy_leaves_out_every_chunks_pages()
    {
        // A run that holds two chunks, one that lies inside a third, and a
        // chunk no listed page covers.
        let chunks = [
            chunk(0x2000, 4, 0xF, Supply::Supplied, 0),
            chunk(0x8000, 2, 0x3, Supply::Absent, 0),
            chunk(0x20000, 16, 0x1, Supply::Supplied, 4),
            chunk(0x40000, 16, 0x1, Supply::Pending, 0),
        ];
        let out = outside(
            &[
                listed(0x1000, 20, RW),
                listed(0x21000, 2, RW),
                listed(0x50000, 1, PAGE_RUN_READ),
            ],
            &chunks,
        )
        .unwrap();
        assert_eq!(
            out,
            [
                listed(0x1000, 1, RW),
                listed(0x6000, 2, RW),
                listed(0xa000, 11, RW),
                listed(0x50000, 1, PAGE_RUN_READ)
            ]
        );
        assert_eq!(copied_pages(&out), 15);
    }

    #[test]
    fn supplied_chunks_take_their_data_pages_and_the_copy_follows_them()
    {
        // memmgr wrote the first chunk's three backed pages to data pages 0
        // to 2 and the second's two to 3 and 4; the copy starts at 5.
        let chunks = [
            chunk(0x10000, 16, 0b1011, Supply::Supplied, 0),
            chunk(0x20000, 4, 0b0110, Supply::Supplied, 3),
        ];
        let out = outside(&[listed(0x1000, 2, RW), listed(0x10000, 2, RW)], &chunks).unwrap();
        let l = layout(&out, 5, &[], &chunks).unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 2, RW, 6),
                run(0x10000, 2, RW, 1),
                run(0x13000, 1, RW, 3),
                run(0x21000, 2, RW, 4)
            ]
        );
        assert_eq!((l.layout_pages, l.data_pages, l.complete), (1, 7, true));
    }

    #[test]
    fn a_chunk_memmgr_did_not_supply_is_absent_over_its_backed_pages()
    {
        // An absent chunk and a pending one back to back join; a failed
        // page and the supplied chunk keep the capture's data pages.
        let chunks = [
            chunk(0x30000, 16, 0xFFFF, Supply::Absent, 0),
            chunk(0x40000, 16, 0x0003, Supply::Pending, 0),
            chunk(0x50000, 16, 0x0004, Supply::Supplied, 0),
        ];
        let l = layout(&[listed(0x1000, 2, RW)], 1, &[0x2000], &chunks).unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 1, RW, 2),
                run(0x2000, 1, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                run(0x30000, 18, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                run(0x52000, 1, RW, 1)
            ]
        );
        assert_eq!((l.data_pages, l.complete), (2, false));
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
        let l = layout(&runs, 0, &[], &[]).unwrap();
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
        let l = layout(&[listed(0x1000, PAGES, RW)], 0, &failed, &[]).unwrap();
        assert_eq!(l.runs.len() as u64, PAGES);
        assert_eq!(Some(l.layout_pages), layout_pages(PAGES));
        assert_eq!(l.data_pages, PAGES / 2);
        assert!(!l.complete);
        let second = &l.runs[1];
        assert_eq!((second.pages, second.object_page), (1, l.layout_pages));
    }

    #[test]
    fn a_chunk_is_readable_with_its_regions_write_and_execute_bits()
    {
        use syscall_abi::PAGE_RUN_EXECUTE;

        let with = |prot: u64| {
            Chunk::new(
                &Descriptor {
                    va: 0x4000,
                    pages: 3,
                    backed: 0b111,
                    prot,
                    supply: Supply::Supplied,
                },
                9,
            )
        };
        // A heap region registered MAP_WRITABLE alone.
        let c = with(MAP_WRITABLE);
        assert_eq!(
            (c.va, c.end(), c.prot, c.data),
            (0x4000, 0x4000 + 3 * P, RW, 9)
        );
        assert_eq!(with(MAP_READ).prot, PAGE_RUN_READ);
        assert_eq!(
            with(MAP_READ | MAP_EXECUTABLE).prot,
            PAGE_RUN_READ | PAGE_RUN_EXECUTE
        );
        // Bits outside the protection, PAGE_RUN_NO_COPY's among them, are not
        // a region's.
        assert_eq!(with(PAGE_RUN_NO_COPY).prot, PAGE_RUN_READ);
    }
}
