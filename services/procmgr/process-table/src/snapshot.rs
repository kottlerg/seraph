// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/snapshot.rs

//! The pure parts of `SNAPSHOT` (`services/procmgr/docs/ipc-interface.md`
//! § Label 33: `SNAPSHOT`): the joining of the runs `SYS_THREAD_LIST_PAGES`
//! lists over several calls, the pages a capture copies, and the layout built
//! from what the capture found.
//!
//! A space's user half has two authorities. memmgr's ledger holds every page
//! of a region the process registered, mapped or not: under the hold, memmgr
//! describes each region and each page of it (`memmgr_labels::CAPTURE_CHUNKS`),
//! gathered here as a [`Described`], and writes the bytes it holds into the
//! first data pages of the object. The kernel's page table holds every page
//! outside the regions, which no pager backs and which is mapped whenever it
//! is in the space: the capture copies the listed pages outside every region
//! ([`outside`]) into the next data pages, in address order, a page whose
//! copy failed taking none. [`layout`] turns both into the object's regions
//! and runs (`ipc::procmgr_snapshot`), and is the model of the layout's
//! invariant: every page of every region and every listed page outside them
//! is covered by exactly one run, no run crosses a region's boundary, a page
//! of a region memmgr described no form of, or of a class this side does not
//! know, is absent, and the capture is complete when no run is.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use ipc::memmgr_capture::{
    Chunk, REGION_COMMITTED, REGION_NO_EVICT, REGION_PRIVATE, Region, RegionClass,
};
use ipc::procmgr_snapshot::{
    self, NO_OBJECT_PAGE, REGION_CLASS_SHIFT, RUN_ABSENT, RUN_IMAGE, RUN_ZERO, RegionEntry, Run,
    layout_pages,
};
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

/// A chunk memmgr described, and the data page of its first written page:
/// its written pages follow in page order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placed
{
    pub chunk: Chunk,
    pub data: u64,
}

/// What memmgr described of the held space's regions
/// (`memmgr_capture::Descriptor`), each list in ascending address order.
#[derive(Debug, Default)]
pub struct Described
{
    /// The regions.
    pub regions: Vec<Region>,
    /// The chunks, with their data pages.
    pub chunks: Vec<Placed>,
    /// The ranges of whole chunks with no entry, as `(va, pages)`.
    pub ranges: Vec<(u64, u64)>,
}

/// The parts of the listed runs `listed` outside every region of `regions`
/// (ascending, disjoint), in address order: the pages a capture copies from
/// the space itself, since memmgr describes every page of a region.
///
/// # Errors
/// The heap's refusal of the runs' memory.
pub fn outside(listed: &[PageRun], regions: &[Region]) -> Result<Vec<PageRun>, TryReserveError>
{
    let mut out = Vec::new();
    let mut next = 0usize;
    for run in listed
    {
        let end = run.va.saturating_add(run.pages.saturating_mul(PAGE_SIZE));
        let mut at = run.va;
        while at < end
        {
            while regions.get(next).is_some_and(|r| r.end() <= at)
            {
                next = next.saturating_add(1);
            }
            let stop = match regions.get(next)
            {
                // Inside the region: its pages are memmgr's to describe.
                Some(r) if r.va <= at =>
                {
                    at = r.end().min(end);
                    continue;
                }
                Some(r) => r.va.min(end),
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

/// The layout of a capture: its regions and runs, in ascending address
/// order, with their object pages, and what the header says of them.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout
{
    /// The regions, as `ipc::procmgr_snapshot::RegionEntry` entries.
    pub regions: Vec<RegionEntry>,
    /// The runs, as `ipc::procmgr_snapshot::Run` entries.
    pub runs: Vec<Run>,
    /// Pages of the layout itself.
    pub layout_pages: u64,
    /// Data pages the runs use, after the layout's.
    pub data_pages: u64,
    /// No run is absent.
    pub complete: bool,
}

/// The layout of a capture whose listed pages outside every region are
/// `outside` ([`outside`]), copied from data page `first_copy` on, whose
/// copy failed for the pages at the addresses `failed` (ascending), and of
/// whose regions memmgr described `described`.
///
/// Outside the regions, each page of `outside` that is not
/// `PAGE_RUN_NO_COPY` and whose copy held takes the next data page, in
/// address order, as the copy placed it; a run is cut where a copy failed,
/// the failed pages [`RUN_ABSENT`]; a `PAGE_RUN_NO_COPY` run has no object
/// page and is not absent.
///
/// Inside a region, every page takes the region's protection, readable, and
/// one form: a written page of a chunk its data page; a backed page memmgr
/// did not write absent; any other page of a chunk or of a range the form the
/// region's class gives, [`RUN_ZERO`] for a demand or zero-object region,
/// [`RUN_IMAGE`] at its object page for the image's, and absent for another
/// object's, whose every page memmgr writes; a page no chunk or range covers
/// absent; and every page of a region of a class this side does not know
/// absent. Adjacent runs of one region, or both outside every region, with
/// one flag word, whose pages follow one another in the object or which have
/// none, are joined.
///
/// # Errors
/// The heap's refusal of the runs' memory.
pub fn layout(
    outside: &[PageRun],
    first_copy: u64,
    failed: &[u64],
    described: &Described,
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
            runs.push(OUTSIDE, run.va, run.pages, run.prot, NO_OBJECT_PAGE)?;
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
            runs.push(OUTSIDE, at, pages, flags, page)?;
            at = at.saturating_add(pages.saturating_mul(PAGE_SIZE));
            if page != NO_OBJECT_PAGE
            {
                data = data.saturating_add(pages);
            }
        }
    }
    let mut regions = Vec::new();
    regions.try_reserve(described.regions.len())?;
    let mut data_end = data;
    for (index, region) in described.regions.iter().enumerate()
    {
        regions.push(entry(region));
        let end = runs.push_region(index as u64, region, described)?;
        data_end = data_end.max(end);
    }
    runs.finish(regions, data_end)
}

/// The layout entry of `region`.
fn entry(region: &Region) -> RegionEntry
{
    let class = match region.class
    {
        RegionClass::Demand => procmgr_snapshot::REGION_DEMAND,
        RegionClass::Image => procmgr_snapshot::REGION_IMAGE,
        RegionClass::Zero => procmgr_snapshot::REGION_ZERO,
        RegionClass::Object => procmgr_snapshot::REGION_OBJECT,
        RegionClass::Unknown(code) => code,
    };
    let mut flags = (region.prot & 0xFF) | ((class & 0xF) << REGION_CLASS_SHIFT);
    for (wire, bit) in [
        (REGION_COMMITTED, procmgr_snapshot::REGION_COMMIT),
        (REGION_NO_EVICT, procmgr_snapshot::REGION_NO_EVICT),
        (REGION_PRIVATE, procmgr_snapshot::REGION_PRIVATE),
    ]
    {
        if region.flags & wire != 0
        {
            flags |= bit;
        }
    }
    RegionEntry {
        va: region.va,
        pages: region.pages,
        flags,
        first_page: region.first_page,
    }
}

/// The region tag of a run outside every region.
const OUTSIDE: u64 = u64::MAX;

/// One run as it is built, and the region it lies in ([`OUTSIDE`] for none),
/// which a join does not cross.
#[derive(Clone, Copy)]
struct Tagged
{
    run: Run,
    region: u64,
}

/// The runs of a layout as they are built, sorted on [`Runs::finish`].
#[derive(Default)]
struct Runs
{
    runs: Vec<Tagged>,
}

/// The form of a page of a region.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form
{
    /// Its bytes, at a data page.
    Bytes(u64),
    /// Zero.
    Zero,
    /// The image's, at an image object page.
    Image(u64),
    /// Absent.
    Absent,
}

impl Runs
{
    /// Add a run of region `region`, unless it has no page.
    fn push(
        &mut self,
        region: u64,
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
        self.runs.push(Tagged {
            run: Run {
                va,
                pages,
                flags,
                object_page,
            },
            region,
        });
        Ok(())
    }

    /// Add the pages `[va, end)` of region `index`, whose pages'
    /// protection is `prot`, of form `form` from their first: bytes or
    /// image pages that follow one another.
    fn push_span(
        &mut self,
        index: u64,
        va: u64,
        end: u64,
        prot: u64,
        form: Form,
    ) -> Result<(), TryReserveError>
    {
        let pages = end.saturating_sub(va) / PAGE_SIZE;
        let (flags, page) = match form
        {
            Form::Bytes(page) => (prot, page),
            Form::Zero => (prot | RUN_ZERO, NO_OBJECT_PAGE),
            Form::Image(page) => (prot | RUN_IMAGE, page),
            Form::Absent => (prot | RUN_ABSENT, NO_OBJECT_PAGE),
        };
        self.push(index, va, pages, flags, page)
    }

    /// Add the runs of region `index`, `region`, from what `described`
    /// says of its pages. Returns the data page past the last its chunks
    /// take.
    fn push_region(
        &mut self,
        index: u64,
        region: &Region,
        described: &Described,
    ) -> Result<u64, TryReserveError>
    {
        let prot = (region.prot & (PAGE_RUN_WRITE | PAGE_RUN_EXECUTE)) | PAGE_RUN_READ;
        let (base, end) = (region.va, region.end());
        let origin = |va: u64| match region.class
        {
            RegionClass::Demand | RegionClass::Zero => Form::Zero,
            RegionClass::Image => Form::Image(
                region
                    .first_page
                    .saturating_add(va.saturating_sub(base) / PAGE_SIZE),
            ),
            RegionClass::Object | RegionClass::Unknown(_) => Form::Absent,
        };
        if matches!(region.class, RegionClass::Unknown(_))
        {
            self.push(index, base, region.pages, prot | RUN_ABSENT, NO_OBJECT_PAGE)?;
            return Ok(0);
        }
        // The chunks and ranges inside the region, merged in address order;
        // one that starts below the page reached, or past the region, is
        // memmgr's error and describes nothing.
        let chunks = described
            .chunks
            .iter()
            .filter(|p| p.chunk.va >= base && p.chunk.va < end);
        let ranges = described
            .ranges
            .iter()
            .filter(|(va, _)| *va >= base && *va < end);
        let mut items: Vec<(u64, Option<&Placed>, u64)> = Vec::new();
        for p in chunks
        {
            items.try_reserve(1)?;
            items.push((p.chunk.va, Some(p), p.chunk.end()));
        }
        for &(va, pages) in ranges
        {
            items.try_reserve(1)?;
            items.push((va, None, va.saturating_add(pages.saturating_mul(PAGE_SIZE))));
        }
        items.sort_unstable_by_key(|(va, _, _)| *va);
        let (mut at, mut data_end) = (base, 0u64);
        for (va, chunk, item_end) in items
        {
            if va < at
            {
                continue;
            }
            self.push_span(index, at, va, prot, Form::Absent)?;
            let item_end = item_end.min(end);
            let Some(p) = chunk
            else
            {
                self.push_span(index, va, item_end, prot, origin(va))?;
                at = at.max(item_end);
                continue;
            };
            let mut rank = 0u64;
            for i in 0..item_end.saturating_sub(va) / PAGE_SIZE
            {
                let page = va.saturating_add(i.saturating_mul(PAGE_SIZE));
                let bit = |mask: u16| i < 16 && (u64::from(mask) >> i) & 1 != 0;
                let form = if bit(p.chunk.written)
                {
                    let at = p.data.saturating_add(rank);
                    rank = rank.saturating_add(1);
                    data_end = data_end.max(at.saturating_add(1));
                    Form::Bytes(at)
                }
                else if bit(p.chunk.backed)
                {
                    Form::Absent
                }
                else
                {
                    origin(page)
                };
                self.push_span(index, page, page.saturating_add(PAGE_SIZE), prot, form)?;
            }
            at = at.max(item_end);
        }
        self.push_span(index, at, end, prot, Form::Absent)?;
        Ok(data_end)
    }

    /// Sort the runs by address, join each to the one before it where it
    /// continues it in its region, and place their bytes after the layout's
    /// pages.
    fn finish(
        mut self,
        regions: Vec<RegionEntry>,
        data_pages: u64,
    ) -> Result<Layout, TryReserveError>
    {
        self.runs.sort_by_key(|t| t.run.va);
        let mut joined: Vec<Tagged> = Vec::new();
        joined.try_reserve(self.runs.len())?;
        for t in self.runs
        {
            if let Some(last) = joined.last_mut()
                && last.region == t.region
                && continues(&last.run, &t.run)
            {
                last.run.pages = last.run.pages.saturating_add(t.run.pages);
                continue;
            }
            joined.push(t);
        }
        let mut runs: Vec<Run> = Vec::new();
        runs.try_reserve(joined.len())?;
        // The heap holds the entries, so their layout's bytes fit a `u64`.
        let entries = (regions.len() as u64).saturating_add(joined.len() as u64);
        let layout_pages = layout_pages(entries).unwrap_or(u64::MAX);
        for t in joined
        {
            let mut run = t.run;
            if run.has_bytes()
            {
                run.object_page = run.object_page.saturating_add(layout_pages);
            }
            runs.push(run);
        }
        let complete = runs.iter().all(|r| r.flags & RUN_ABSENT == 0);
        Ok(Layout {
            regions,
            runs,
            layout_pages,
            data_pages,
            complete,
        })
    }
}

/// Whether `run` continues `last`: it starts where `last` ends, with its
/// flags, and its pages follow `last`'s in the object, or in the image, or
/// neither has any.
fn continues(last: &Run, run: &Run) -> bool
{
    let end = last.va.saturating_add(last.pages.saturating_mul(PAGE_SIZE));
    let pages_follow = if last.object_page == NO_OBJECT_PAGE
    {
        run.object_page == NO_OBJECT_PAGE
    }
    else
    {
        last.object_page.checked_add(last.pages) == Some(run.object_page)
    };
    end == run.va && last.flags == run.flags && pages_follow
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::memmgr_capture::REGION_PRIVATE;
    use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE};

    const P: u64 = PAGE_SIZE;
    const RW: u64 = PAGE_RUN_READ | PAGE_RUN_WRITE;
    const RX: u64 = PAGE_RUN_READ | PAGE_RUN_EXECUTE;
    const NONE: u64 = NO_OBJECT_PAGE;

    fn listed(va: u64, pages: u64, prot: u64) -> PageRun
    {
        PageRun { va, pages, prot }
    }

    fn region(va: u64, pages: u64, class: RegionClass, prot: u64, first_page: u64) -> Region
    {
        Region {
            va,
            pages,
            class,
            prot,
            flags: 0,
            first_page,
        }
    }

    fn placed(va: u64, pages: u64, backed: u16, written: u16, data: u64) -> Placed
    {
        Placed {
            chunk: Chunk {
                va,
                pages,
                backed,
                written,
                pending: false,
            },
            data,
        }
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

    /// The layout of `d` with nothing listed outside its regions.
    fn regions_only(d: &Described) -> Layout
    {
        layout(&[], 0, &[], d).unwrap()
    }

    /// The layout invariant: runs ascending and disjoint, every page of every
    /// region covered by runs of that region alone with its protection, no
    /// run outside the regions but on a listed page, bytes in distinct object
    /// pages, and complete exactly when no run is absent.
    fn check(l: &Layout, listed: &[PageRun])
    {
        for pair in l.runs.windows(2)
        {
            assert!(pair[0].va + pair[0].pages * P <= pair[1].va, "{pair:?}");
        }
        for r in &l.regions
        {
            let end = r.va + r.pages * P;
            let prot = (r.flags & (PAGE_RUN_WRITE | PAGE_RUN_EXECUTE)) | PAGE_RUN_READ;
            let inside: Vec<&Run> = l
                .runs
                .iter()
                .filter(|x| x.va < end && x.va + x.pages * P > r.va)
                .collect();
            let covered: u64 = inside.iter().map(|x| x.pages).sum();
            assert_eq!(covered, r.pages, "region {r:?} not covered once");
            for x in inside
            {
                assert!(
                    x.va >= r.va && x.va + x.pages * P <= end,
                    "{x:?} crosses {r:?}"
                );
                assert_eq!(x.flags & 0b111, prot, "{x:?} in {r:?}");
                let forms = x.flags & (RUN_ABSENT | RUN_ZERO | RUN_IMAGE);
                assert!(forms.count_ones() <= 1, "{x:?}");
            }
        }
        for x in &l.runs
        {
            let in_region = l
                .regions
                .iter()
                .any(|r| x.va >= r.va && x.va < r.va + r.pages * P);
            if !in_region
            {
                assert!(
                    listed
                        .iter()
                        .any(|s| x.va >= s.va && x.va + x.pages * P <= s.va + s.pages * P),
                    "{x:?} outside every region and listing"
                );
            }
        }
        let mut pages: Vec<u64> = l
            .runs
            .iter()
            .filter(|x| x.has_bytes())
            .flat_map(|x| x.object_page..x.object_page + x.pages)
            .collect();
        let n = pages.len();
        pages.sort_unstable();
        pages.dedup();
        assert_eq!(pages.len(), n, "two pages share an object page");
        assert!(
            pages
                .iter()
                .all(|&p| p >= l.layout_pages && p < l.layout_pages + l.data_pages)
        );
        assert_eq!(l.complete, l.runs.iter().all(|x| x.flags & RUN_ABSENT == 0));
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
        assert_eq!(listing.copied_pages(), 7);
    }

    #[test]
    fn the_copy_takes_only_listed_pages_outside_every_region()
    {
        let regions = [
            region(0x4000, 4, RegionClass::Demand, MAP_READ | MAP_WRITABLE, 0),
            region(
                0x20000,
                16,
                RegionClass::Image,
                MAP_READ | MAP_EXECUTABLE,
                0,
            ),
        ];
        let out = outside(
            &[
                listed(0x1000, 10, RW),
                listed(0x21000, 2, RX),
                listed(0x40000, 1, RW | PAGE_RUN_NO_COPY),
            ],
            &regions,
        )
        .unwrap();
        assert_eq!(
            out,
            [
                listed(0x1000, 3, RW),
                listed(0x8000, 3, RW),
                listed(0x40000, 1, RW | PAGE_RUN_NO_COPY)
            ]
        );
        assert_eq!(copied_pages(&out), 6);
    }

    #[test]
    fn outside_the_regions_a_failed_copy_is_absent_and_device_memory_has_no_bytes()
    {
        let listing = [
            listed(0x1000, 4, RW),
            listed(0x5000, 2, RW | PAGE_RUN_NO_COPY),
        ];
        let l = layout(&listing, 0, &[0x2000, 0x3000], &Described::default()).unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 1, RW, 1),
                run(0x2000, 2, RW | RUN_ABSENT, NONE),
                run(0x4000, 1, RW, 2),
                run(0x5000, 2, RW | PAGE_RUN_NO_COPY, NONE)
            ]
        );
        assert_eq!((l.data_pages, l.complete), (2, false));
        check(&l, &listing);
    }

    #[test]
    fn a_demand_region_with_no_entry_reads_zero_whole()
    {
        // A heap reservation of a million pages costs one run.
        let d = Described {
            regions: vec![region(
                0x10_0000,
                1 << 20,
                RegionClass::Demand,
                MAP_WRITABLE,
                0,
            )],
            ranges: vec![(0x10_0000, 1 << 20)],
            ..Described::default()
        };
        let l = regions_only(&d);
        assert_eq!(l.runs, [run(0x10_0000, 1 << 20, RW | RUN_ZERO, NONE)]);
        assert!(l.complete);
        check(&l, &[]);
    }

    #[test]
    fn a_demand_chunk_gives_its_written_pages_and_zero_for_the_unbacked()
    {
        // Chunk 0: pages 0, 1 and 3 backed and written at data 0..3; chunk 1
        // pending (on disk) over pages 16 and 17; chunk 2 lost over page 32;
        // the rest of the region no chunk reached.
        let base = 0x40_0000;
        let mut pending = placed(base + 16 * P, 16, 0b11, 0, 3);
        pending.chunk.pending = true;
        let d = Described {
            regions: vec![region(
                base,
                64,
                RegionClass::Demand,
                MAP_READ | MAP_WRITABLE,
                0,
            )],
            chunks: vec![
                placed(base, 16, 0b1011, 0b1011, 0),
                pending,
                placed(base + 32 * P, 16, 0b1, 0, 3),
            ],
            ranges: vec![(base + 48 * P, 16)],
        };
        let l = regions_only(&d);
        assert_eq!(
            l.runs,
            [
                run(base, 2, RW, 1),
                run(base + 2 * P, 1, RW | RUN_ZERO, NONE),
                run(base + 3 * P, 1, RW, 3),
                run(base + 4 * P, 12, RW | RUN_ZERO, NONE),
                run(base + 16 * P, 2, RW | RUN_ABSENT, NONE),
                run(base + 18 * P, 14, RW | RUN_ZERO, NONE),
                run(base + 32 * P, 1, RW | RUN_ABSENT, NONE),
                run(base + 33 * P, 31, RW | RUN_ZERO, NONE),
            ]
        );
        assert!(!l.complete);
        check(&l, &[]);
    }

    #[test]
    fn an_image_attachment_names_its_object_pages_and_gives_its_own_copies_bytes()
    {
        // The image attached anywhere, from object page 10: page 2 has a copy
        // of its own (a breakpoint), and no fault reached chunk 1.
        let base = 0x7000_0000;
        let d = Described {
            regions: vec![region(
                base,
                20,
                RegionClass::Image,
                MAP_READ | MAP_EXECUTABLE,
                10,
            )],
            chunks: vec![placed(base, 16, 0b100, 0b100, 0)],
            ranges: vec![(base + 16 * P, 4)],
        };
        let l = regions_only(&d);
        assert_eq!(
            l.runs,
            [
                run(base, 2, RX | RUN_IMAGE, 10),
                run(base + 2 * P, 1, RX, 1),
                run(base + 3 * P, 17, RX | RUN_IMAGE, 13),
            ]
        );
        assert_eq!((l.data_pages, l.complete), (1, true));
        assert!(!l.runs[0].has_bytes());
        check(&l, &[]);
    }

    #[test]
    fn a_zero_attachment_reads_zero_but_its_written_pages()
    {
        let base = 0x9000_0000;
        let mut r = region(base, 16, RegionClass::Zero, MAP_READ | MAP_WRITABLE, 0);
        r.flags = REGION_PRIVATE;
        let d = Described {
            regions: vec![r],
            chunks: vec![placed(
                base,
                16,
                0b1000_0000_0000_0000,
                0b1000_0000_0000_0000,
                0,
            )],
            ..Described::default()
        };
        let l = regions_only(&d);
        assert_eq!(
            l.runs,
            [
                run(base, 15, RW | RUN_ZERO, NONE),
                run(base + 15 * P, 1, RW, 1)
            ]
        );
        assert_eq!(
            l.regions[0].flags,
            (MAP_READ | MAP_WRITABLE)
                | (procmgr_snapshot::REGION_ZERO << REGION_CLASS_SHIFT)
                | procmgr_snapshot::REGION_PRIVATE
        );
        check(&l, &[]);
    }

    #[test]
    fn another_objects_attachment_takes_every_page_as_bytes_or_absent()
    {
        // Chunk 0 written whole; a range memmgr should not give such a region
        // is absent, as is a page of a chunk it did not write.
        let base = 0xa000_0000;
        let d = Described {
            regions: vec![region(base, 40, RegionClass::Object, MAP_READ, 3)],
            chunks: vec![
                placed(base, 16, 0, 0xFFFF, 0),
                placed(base + 32 * P, 8, 0, 0b0111_1111, 16),
            ],
            ranges: vec![(base + 16 * P, 16)],
        };
        let l = regions_only(&d);
        assert_eq!(
            l.runs,
            [
                run(base, 16, PAGE_RUN_READ, 1),
                run(base + 16 * P, 16, PAGE_RUN_READ | RUN_ABSENT, NONE),
                run(base + 32 * P, 7, PAGE_RUN_READ, 17),
                run(base + 39 * P, 1, PAGE_RUN_READ | RUN_ABSENT, NONE),
            ]
        );
        check(&l, &[]);
    }

    #[test]
    fn a_region_of_an_unknown_class_is_absent_over_its_extent()
    {
        // Whatever memmgr says of its pages: the class decides nothing here
        // can be read.
        let base = 0xb000_0000;
        let d = Described {
            regions: vec![region(base, 32, RegionClass::Unknown(9), MAP_READ, 0)],
            chunks: vec![placed(base, 16, 0b1, 0b1, 0)],
            ranges: vec![(base + 16 * P, 16)],
        };
        let l = regions_only(&d);
        assert_eq!(l.runs, [run(base, 32, PAGE_RUN_READ | RUN_ABSENT, NONE)]);
        assert!(!l.complete);
        assert_eq!(l.regions[0].class(), 9);
        check(&l, &[]);
    }

    #[test]
    fn a_page_of_a_region_memmgr_described_no_form_of_is_absent()
    {
        // Pages 0 to 15 and 32 to 35 of the region named by nothing.
        let base = 0xc000_0000;
        let d = Described {
            regions: vec![region(base, 36, RegionClass::Demand, MAP_WRITABLE, 0)],
            ranges: vec![(base + 16 * P, 16)],
            ..Described::default()
        };
        let l = regions_only(&d);
        assert_eq!(
            l.runs,
            [
                run(base, 16, RW | RUN_ABSENT, NONE),
                run(base + 16 * P, 16, RW | RUN_ZERO, NONE),
                run(base + 32 * P, 4, RW | RUN_ABSENT, NONE),
            ]
        );
        assert!(!l.complete);
        check(&l, &[]);
    }

    #[test]
    fn runs_of_adjacent_regions_do_not_join()
    {
        let d = Described {
            regions: vec![
                region(0x10000, 16, RegionClass::Demand, MAP_WRITABLE, 0),
                region(0x20000, 16, RegionClass::Demand, MAP_WRITABLE, 0),
            ],
            ranges: vec![(0x10000, 16), (0x20000, 16)],
            ..Described::default()
        };
        let l = regions_only(&d);
        assert_eq!(
            l.runs,
            [
                run(0x10000, 16, RW | RUN_ZERO, NONE),
                run(0x20000, 16, RW | RUN_ZERO, NONE)
            ]
        );
        assert_eq!(l.regions.len(), 2);
        check(&l, &[]);
    }

    #[test]
    fn the_copy_follows_the_chunks_data_pages()
    {
        // memmgr wrote three pages; the copy of the two listed pages outside
        // the region starts at data page 3.
        let d = Described {
            regions: vec![region(0x10000, 16, RegionClass::Demand, MAP_WRITABLE, 0)],
            chunks: vec![placed(0x10000, 16, 0b111, 0b111, 0)],
            ..Described::default()
        };
        let listing = [listed(0x1000, 2, RW), listed(0x10000, 3, RW)];
        let out = outside(&listing, &d.regions).unwrap();
        let l = layout(&out, 3, &[], &d).unwrap();
        assert_eq!(
            l.runs,
            [
                run(0x1000, 2, RW, 4),
                run(0x10000, 3, RW, 1),
                run(0x13000, 13, RW | RUN_ZERO, NONE)
            ]
        );
        assert_eq!((l.layout_pages, l.data_pages), (1, 5));
        check(&l, &listing);
    }

    #[test]
    fn a_layout_past_one_page_places_the_data_after_every_layout_page()
    {
        // 125 runs, alternating protection, need a second layout page.
        let runs: Vec<PageRun> = (0..125u64)
            .map(|i| {
                listed(
                    0x1000 + i * P,
                    1,
                    if i % 2 == 0 { RW } else { PAGE_RUN_READ },
                )
            })
            .collect();
        let l = layout(&runs, 0, &[], &Described::default()).unwrap();
        assert_eq!(l.layout_pages, 2);
        assert_eq!(l.runs.first().map(|r| r.object_page), Some(2));
        assert_eq!(l.runs.last().map(|r| r.object_page), Some(126));
    }

    /// A small linear congruential generator, so the mixes repeat.
    struct Lcg(u64);

    impl Lcg
    {
        fn next(&mut self, below: u64) -> u64
        {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % below
        }
    }

    #[test]
    fn generated_mixes_keep_the_layout_invariant()
    {
        let classes = [
            RegionClass::Demand,
            RegionClass::Image,
            RegionClass::Zero,
            RegionClass::Object,
            RegionClass::Unknown(12),
        ];
        let mut rng = Lcg(0x5eed);
        for _ in 0..500
        {
            let mut d = Described::default();
            let mut listing = Vec::new();
            let (mut va, mut data) = (0x10_0000u64, 0u64);
            for _ in 0..rng.next(6)
            {
                // Listed pages between regions, then a region of up to four
                // chunks, its last short, each chunk described one way or
                // left out.
                let gap = rng.next(4);
                if gap > 0
                {
                    listing.push(listed(va, gap, RW));
                }
                va += (gap + rng.next(3)) * P;
                let pages = 1 + rng.next(64);
                let class = classes[usize::try_from(rng.next(5)).unwrap()];
                d.regions.push(region(
                    va,
                    pages,
                    class,
                    MAP_READ | MAP_WRITABLE,
                    rng.next(100),
                ));
                let mut at = 0;
                while at < pages
                {
                    let n = (pages - at).min(16);
                    let mask = if n == 16 { 0xFFFF } else { (1u16 << n) - 1 };
                    match rng.next(4)
                    {
                        0 => d.ranges.push((va + at * P, n)),
                        1 =>
                        {}
                        _ =>
                        {
                            let backed = u16::try_from(rng.next(1 << 16)).unwrap() & mask;
                            let written = u16::try_from(rng.next(1 << 16)).unwrap() & mask;
                            let mut p = placed(va + at * P, n, backed, written, data);
                            p.chunk.pending = rng.next(2) == 0;
                            data += u64::from(written.count_ones());
                            d.chunks.push(p);
                        }
                    }
                    if rng.next(3) == 0
                    {
                        listing.push(listed(va + at * P, 1, RW));
                    }
                    at += n;
                }
                va += pages * P;
            }
            let out = outside(&listing, &d.regions).unwrap();
            let failed: Vec<u64> = out
                .iter()
                .filter(|_| rng.next(4) == 0)
                .map(|r| r.va)
                .collect();
            let l = layout(&out, data, &failed, &d).unwrap();
            check(&l, &listing);
            let copied = copied_pages(&out) - failed.len() as u64;
            assert_eq!(l.data_pages, data + copied);
        }
    }
}
