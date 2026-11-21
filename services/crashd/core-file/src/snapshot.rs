// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/core-file/src/snapshot.rs

//! A procmgr `SNAPSHOT` object as the source of a core: its layout's runs
//! and thread records, checked before crashd trusts a number in them
//! (`ipc::procmgr_snapshot`; services/procmgr/docs/ipc-interface.md
//! § Snapshot object layout). The regions, which a restore replays, are
//! passed over.
//!
//! A run whose bytes the object holds becomes a [`Run`] of its protection,
//! and a zero run or a `PAGE_RUN_NO_COPY` one becomes one with
//! `PAGE_RUN_NO_COPY` added, which [`crate::layout::plan`] keeps as a
//! `PT_LOAD` with no file bytes, read as zeros. A run of the image's pages or
//! an absent one becomes none: a debugger reads a page no `PT_LOAD` covers
//! from the binary, or reports it unreadable, where a `PT_LOAD` with no file
//! bytes would read as zeros, and `gdb` would find no program headers at the
//! auxiliary vector's `AT_PHDR` to relocate the executable by.

use alloc::vec::Vec;

use ipc::procmgr_snapshot::{
    Header, RUN_ABSENT, RUN_FLAGS, RUN_IMAGE, RUN_ZERO, ThreadRecord, threads_offset,
};
use syscall_abi::{PAGE_RUN_EXECUTE, PAGE_RUN_NO_COPY, PAGE_RUN_READ, PAGE_RUN_WRITE, PAGE_SIZE};

use crate::layout::Run;

/// Why a snapshot's layout is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError
{
    /// The header does not decode, or names more pages than the object has.
    Header,
    /// The layout's bytes end before the runs the header counts.
    Truncated,
    /// Run `n` is malformed: no page, an address off a page boundary or
    /// below the end of the run before it, an unknown flag bit, more than one
    /// of the absent, zero and image bits, or bytes outside the data pages.
    Run(usize),
    /// Thread record `n` does not decode within the bytes the header counts,
    /// or the records do not end where those bytes do.
    Thread(usize),
}

/// A snapshot's layout, checked.
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot
{
    header: Header,
    /// Each run, and the object page of its first page when the object holds
    /// its bytes.
    runs: Vec<(Run, Option<u64>)>,
}

impl Snapshot
{
    /// The layout at the start of `layout`, the object's first
    /// [`Header::layout_pages`] pages or more, of an object of
    /// `object_pages` pages.
    ///
    /// # Errors
    /// The [`SnapshotError`] of the first check that fails.
    pub fn decode(layout: &[u8], object_pages: u64) -> Result<Self, SnapshotError>
    {
        let header = Header::decode(layout).ok_or(SnapshotError::Header)?;
        let pages = header
            .layout_pages
            .checked_add(header.data_pages)
            .ok_or(SnapshotError::Header)?;
        if pages > object_pages
        {
            return Err(SnapshotError::Header);
        }
        let count = usize::try_from(header.run_count).map_err(|_| SnapshotError::Truncated)?;
        let data_end = header.layout_pages.saturating_add(header.data_pages);
        let mut runs = Vec::new();
        runs.try_reserve_exact(count)
            .map_err(|_| SnapshotError::Truncated)?;
        let mut end = 0u64;
        for i in 0..count
        {
            let run = ipc::procmgr_snapshot::Run::decode(layout, header.region_count, i)
                .ok_or(SnapshotError::Truncated)?;
            let forms = run.flags & (RUN_ABSENT | RUN_ZERO | RUN_IMAGE);
            let bytes = run.pages.checked_mul(PAGE_SIZE);
            let run_end = bytes.and_then(|b| run.va.checked_add(b));
            let well_formed = run.pages != 0
                && run.va % PAGE_SIZE == 0
                && run.va >= end
                && run.flags & !RUN_FLAGS == 0
                && forms & forms.wrapping_sub(1) == 0
                && run_end.is_some();
            if !well_formed
            {
                return Err(SnapshotError::Run(i));
            }
            end = run_end.unwrap_or(u64::MAX);
            let object_page = if run.has_bytes()
            {
                // The bytes lie in the data pages, and only a run of no other
                // form has them.
                let inside = run.flags & (forms | PAGE_RUN_NO_COPY) == 0
                    && run.object_page >= header.layout_pages
                    && run
                        .object_page
                        .checked_add(run.pages)
                        .is_some_and(|last| last <= data_end);
                if !inside
                {
                    return Err(SnapshotError::Run(i));
                }
                Some(run.object_page)
            }
            else
            {
                None
            };
            if forms & (RUN_IMAGE | RUN_ABSENT) != 0
            {
                continue;
            }
            let mut prot = run.flags & (PAGE_RUN_READ | PAGE_RUN_WRITE | PAGE_RUN_EXECUTE);
            if object_page.is_none()
            {
                prot |= PAGE_RUN_NO_COPY;
            }
            runs.push((
                Run {
                    va: run.va,
                    pages: run.pages,
                    prot,
                },
                object_page,
            ));
        }
        Ok(Self { header, runs })
    }

    /// The runs, in address order, for [`crate::layout::plan`].
    pub fn runs(&self) -> impl Iterator<Item = Run> + '_
    {
        self.runs.iter().map(|(run, _)| *run)
    }

    /// The object page holding the first page of run `index`; `None` when
    /// the object holds none of its bytes.
    #[must_use]
    pub fn object_page(&self, index: usize) -> Option<u64>
    {
        self.runs.get(index).and_then(|(_, page)| *page)
    }

    /// Whether no run is absent, as the header says.
    #[must_use]
    pub fn complete(&self) -> bool
    {
        self.header.flags & ipc::procmgr_snapshot::SNAPSHOT_COMPLETE != 0
    }

    /// The image's load bias.
    #[must_use]
    pub fn load_bias(&self) -> u64
    {
        self.header.load_bias
    }

    /// Pages of the layout.
    #[must_use]
    pub fn layout_pages(&self) -> u64
    {
        self.header.layout_pages
    }

    /// The thread records of `layout`, the bytes [`Self::decode`] took,
    /// in the layout's order.
    ///
    /// # Errors
    /// [`SnapshotError::Thread`] for the first record that does not decode
    /// within the bytes the header counts, or when the records do not end
    /// where those bytes do.
    pub fn threads<'a>(&self, layout: &'a [u8]) -> Result<Vec<ThreadRecord<'a>>, SnapshotError>
    {
        let count =
            usize::try_from(self.header.thread_count).map_err(|_| SnapshotError::Thread(0))?;
        let start = self
            .header
            .region_count
            .checked_add(self.header.run_count)
            .and_then(threads_offset)
            .ok_or(SnapshotError::Thread(0))?;
        let end = usize::try_from(self.header.thread_bytes)
            .ok()
            .and_then(|n| start.checked_add(n))
            .ok_or(SnapshotError::Thread(0))?;
        let records = layout.get(..end).ok_or(SnapshotError::Thread(0))?;
        let mut out = Vec::new();
        out.try_reserve_exact(count)
            .map_err(|_| SnapshotError::Thread(0))?;
        let mut at = start;
        for i in 0..count
        {
            let (record, next) =
                ThreadRecord::decode(records, at).ok_or(SnapshotError::Thread(i))?;
            out.push(record);
            at = next;
        }
        if at != end
        {
            return Err(SnapshotError::Thread(count));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::procmgr_snapshot::{
        Image, NO_OBJECT_PAGE, REGION_DEMAND, RegionEntry, SNAPSHOT_COMPLETE,
    };

    const P: u64 = PAGE_SIZE;
    const RW: u64 = PAGE_RUN_READ | PAGE_RUN_WRITE;

    fn entry(va: u64, pages: u64, flags: u64, object_page: u64) -> ipc::procmgr_snapshot::Run
    {
        ipc::procmgr_snapshot::Run {
            va,
            pages,
            flags,
            object_page,
        }
    }

    /// The records `(index, regs, ext)` as procmgr writes them.
    fn records(threads: &[(u64, &[u8], &[u8])]) -> Vec<u8>
    {
        let mut out = alloc::vec![0u8; 4096];
        let mut at = 0;
        for &(index, regs, ext) in threads
        {
            at = ThreadRecord {
                index,
                state: syscall_abi::THREAD_REGS_STOPPED,
                regs,
                ext,
            }
            .encode(&mut out, at)
            .unwrap();
        }
        out.truncate(at);
        out
    }

    /// A one-page layout of one demand region, `runs`, and the thread
    /// records `threads`, with `data_pages` data pages.
    fn layout(runs: &[ipc::procmgr_snapshot::Run], data_pages: u64, threads: &[u8]) -> Vec<u8>
    {
        let mut bytes = alloc::vec![0u8; usize::try_from(P).unwrap()];
        Header {
            flags: SNAPSHOT_COMPLETE,
            layout_pages: 1,
            data_pages,
            region_count: 1,
            run_count: runs.len() as u64,
            image: Image {
                hash: [0; 64],
                len: 0,
            },
            load_bias: 0x7000_0000,
            thread_count: 2,
            thread_bytes: threads.len() as u64,
        }
        .encode(&mut bytes)
        .unwrap();
        RegionEntry {
            va: 0x40_0000,
            pages: 4,
            flags: REGION_DEMAND,
            first_page: 0,
        }
        .encode(&mut bytes, 0)
        .unwrap();
        for (i, run) in runs.iter().enumerate()
        {
            run.encode(&mut bytes, 1, i).unwrap();
        }
        let at = threads_offset(1 + runs.len() as u64).unwrap();
        bytes[at..at + threads.len()].copy_from_slice(threads);
        bytes
    }

    #[test]
    fn runs_map_to_core_runs_but_the_images_and_absent_ones()
    {
        let bytes = layout(
            &[
                entry(0x1000, 2, RW, 1),
                entry(0x3000, 1, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                entry(0x8000, 4, PAGE_RUN_READ | PAGE_RUN_NO_COPY, NO_OBJECT_PAGE),
                entry(0x10000, 1, PAGE_RUN_READ | PAGE_RUN_EXECUTE, 3),
                entry(0x20000, 2, PAGE_RUN_READ | PAGE_RUN_EXECUTE | RUN_IMAGE, 0),
                entry(0x40_0000, 4, RW | RUN_ZERO, NO_OBJECT_PAGE),
            ],
            3,
            &[],
        );
        let snap = Snapshot::decode(&bytes, 5).unwrap();
        let runs: Vec<Run> = snap.runs().collect();
        let run = |va, pages, prot| Run { va, pages, prot };
        assert_eq!(
            runs,
            [
                run(0x1000, 2, RW),
                run(0x8000, 4, PAGE_RUN_READ | PAGE_RUN_NO_COPY),
                run(0x10000, 1, PAGE_RUN_READ | PAGE_RUN_EXECUTE),
                run(0x40_0000, 4, RW | PAGE_RUN_NO_COPY),
            ]
        );
        assert_eq!(
            (0..5).map(|i| snap.object_page(i)).collect::<Vec<_>>(),
            [Some(1), None, Some(3), None, None]
        );
        assert!(snap.complete());
        assert_eq!(snap.load_bias(), 0x7000_0000);
        assert_eq!(snap.layout_pages(), 1);
    }

    #[test]
    fn a_header_naming_more_pages_than_the_object_is_refused()
    {
        let bytes = layout(&[], 4, &[]);
        Snapshot::decode(&bytes, 5).unwrap();
        assert_eq!(Snapshot::decode(&bytes, 4), Err(SnapshotError::Header));
        assert_eq!(
            Snapshot::decode(&bytes[..40], 5),
            Err(SnapshotError::Header)
        );
    }

    #[test]
    fn runs_cut_off_by_the_layouts_end_are_refused()
    {
        let mut bytes = layout(&[entry(0x1000, 1, RW, 1), entry(0x2000, 1, RW, 2)], 2, &[]);
        // The bytes end halfway through the second run's entry.
        bytes.truncate(threads_offset(2).unwrap() + 16);
        assert_eq!(Snapshot::decode(&bytes, 3), Err(SnapshotError::Truncated));
    }

    #[test]
    fn malformed_runs_are_refused_by_index()
    {
        let cases = [
            // No page.
            [entry(0x1000, 1, RW, 1), entry(0x2000, 0, RW, 2)],
            // Off a page boundary.
            [entry(0x1000, 1, RW, 1), entry(0x2800, 1, RW, 2)],
            // Below the end of the run before it.
            [entry(0x1000, 2, RW, 1), entry(0x2000, 1, RW, 3)],
            // An unknown flag bit.
            [entry(0x1000, 1, RW, 1), entry(0x2000, 1, RW | (1 << 20), 2)],
            // Two forms at once.
            [
                entry(0x1000, 1, RW, 1),
                entry(0x2000, 1, RW | RUN_ZERO | RUN_ABSENT, NO_OBJECT_PAGE),
            ],
            // Bytes past the data pages.
            [entry(0x1000, 1, RW, 1), entry(0x2000, 3, RW, 2)],
            // Bytes in the layout's page.
            [entry(0x1000, 1, RW, 1), entry(0x2000, 1, RW, 0)],
            // Bytes for an absent run.
            [
                entry(0x1000, 1, RW, 1),
                entry(0x2000, 1, RW | RUN_ABSENT, 2),
            ],
            // Bytes for a run no reader copies.
            [
                entry(0x1000, 1, RW, 1),
                entry(0x2000, 1, RW | PAGE_RUN_NO_COPY, 2),
            ],
            // A run that wraps the address space.
            [entry(0x1000, 1, RW, 1), entry(u64::MAX - 0xfff, 2, RW, 2)],
        ];
        for runs in cases
        {
            let bytes = layout(&runs, 3, &[]);
            assert_eq!(
                Snapshot::decode(&bytes, 4),
                Err(SnapshotError::Run(1)),
                "{runs:?}"
            );
        }
    }

    #[test]
    fn thread_records_decode_in_order_to_their_end()
    {
        let threads = records(&[(0, &[1; 12], &[2; 5]), (3, &[4; 8], &[])]);
        let bytes = layout(&[entry(0x1000, 1, RW, 1)], 1, &threads);
        let snap = Snapshot::decode(&bytes, 2).unwrap();
        let read = snap.threads(&bytes).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(
            (read[0].index, read[0].regs, read[0].ext),
            (0, &[1u8; 12][..], &[2u8; 5][..])
        );
        assert_eq!(
            (read[1].index, read[1].regs.len(), read[1].ext.len()),
            (3, 8, 0)
        );
    }

    #[test]
    fn thread_records_short_of_or_past_their_count_are_refused()
    {
        // The header counts two records.
        let one = records(&[(0, &[1; 8], &[])]);
        let bytes = layout(&[], 1, &one);
        let snap = Snapshot::decode(&bytes, 2).unwrap();
        assert_eq!(snap.threads(&bytes), Err(SnapshotError::Thread(1)));
        let three = records(&[(0, &[1; 8], &[]), (1, &[1; 8], &[]), (2, &[1; 8], &[])]);
        let bytes = layout(&[], 1, &three);
        let snap = Snapshot::decode(&bytes, 2).unwrap();
        assert_eq!(snap.threads(&bytes), Err(SnapshotError::Thread(2)));
    }
}
