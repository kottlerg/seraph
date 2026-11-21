// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/restore.rs

//! The pure parts of a restore creation (`procmgr_labels::CREATE_RESTORE`;
//! docs/checkpoint-restore.md § Restore creation): the checkpoint's layout as
//! procmgr reads it from the object, the checks that bind it to the verified
//! body before anything is created, where each page of a bootstrap surface
//! the restore fills takes its bytes, and the requests that make the
//! checkpoint's regions again on the new process's memmgr record and back
//! their pages (`REGISTER_REGION`, `ATTACH_OBJECT` and `FILL_REGION` of
//! `ipc::memmgr_labels`).

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;
use ipc::memmgr_labels::{self, DEMAND_CHUNK_BYTES, FILL_CHUNKS};
use ipc::procmgr_labels::ArgvEnvHeader;
use ipc::procmgr_snapshot::{
    Checkpoint, Header, Image, REGION_COMMIT, REGION_DEMAND, REGION_NO_EVICT, REGION_PRIVATE,
    REGION_ZERO, RUN_ZERO, RegionEntry, Run, SNAPSHOT_CHECKPOINT, SNAPSHOT_COMPLETE,
    checkpoint_offset,
};
use syscall_abi::{PAGE_RUN_EXECUTE, PAGE_SIZE};

/// Pages of one demand chunk, the unit a `FILL_REGION` mask names pages of.
const CHUNK_PAGES: u64 = DEMAND_CHUNK_BYTES / PAGE_SIZE;

// A chunk's page mask is a `u16`, bit `j` for its page `j`.
const _: () = assert!(CHUNK_PAGES == u16::BITS as u64);

/// The chunks one `FILL_REGION` names at most.
const MAX_CHUNKS: usize = 4;
const _: () = assert!(MAX_CHUNKS as u64 == FILL_CHUNKS);

/// The `MAP_*` protection bits of a [`RegionEntry::flags`].
const REGION_PROT_MASK: u64 = 0xFF;

/// The alignment of a restore stack pointer: the stack alignment both
/// architectures' calling conventions require at a call.
pub const RESTORE_SP_ALIGN: u64 = 16;

/// The header of a checkpoint's layout, from the object's first page
/// `page`: `None` when the header does not decode ([`Header::decode`]) or
/// the layout is not a complete checkpoint ([`SNAPSHOT_COMPLETE`] and
/// [`SNAPSHOT_CHECKPOINT`]).
#[must_use]
pub fn checkpoint_header(page: &[u8]) -> Option<Header>
{
    let header = Header::decode(page)?;
    let needed = SNAPSHOT_COMPLETE | SNAPSHOT_CHECKPOINT;
    (header.flags & needed == needed).then_some(header)
}

/// Why [`Layout::decode`] decoded no layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError
{
    /// An entry or the checkpoint section is not all in the bytes, or a
    /// region or run is empty, off a page, past the address space, or not
    /// above the one before.
    Malformed,
    /// The heap refused the room for the entries.
    OutOfMemory,
}

impl From<TryReserveError> for DecodeError
{
    fn from(_: TryReserveError) -> Self
    {
        Self::OutOfMemory
    }
}

/// A checkpoint's layout, decoded from its layout pages: its header, its
/// checkpoint section, and its regions and runs, each in ascending address
/// order and apart from one another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout
{
    pub header: Header,
    pub checkpoint: Checkpoint,
    pub regions: Vec<RegionEntry>,
    pub runs: Vec<Run>,
}

/// A span of pages a bootstrap surface takes its bytes from
/// ([`Layout::next_span`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span
{
    /// Pages in the span, at least 1.
    pub pages: u64,
    /// The object page holding the span's first page, the others following;
    /// `None` for pages that read zero.
    pub object_page: Option<u64>,
}

/// How a region of the checkpoint is made again on the new process's memmgr
/// record ([`Layout::remake`]): the words of the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remake
{
    /// `REGISTER_REGION`: base, length, protection, flags.
    Register
    {
        va: u64,
        len: u64,
        prot: u64,
        flags: u64,
    },
    /// `ATTACH_OBJECT` of the zero object: base, length, protection, flags.
    AttachZero
    {
        va: u64,
        len: u64,
        prot: u64,
        flags: u64,
    },
}

/// One `FILL_REGION` request: each page its chunks' masks name takes the
/// next object page from [`Fill::first`], in chunk and page order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fill
{
    /// The object page the first named page takes.
    pub first: u64,
    count: usize,
    chunks: [(u64, u16); MAX_CHUNKS],
}

impl Fill
{
    /// The request's chunks, each its base and its page mask, in ascending
    /// order: 1 to `FILL_CHUNKS` of them.
    #[must_use]
    pub fn chunks(&self) -> &[(u64, u16)]
    {
        self.chunks.get(..self.count).unwrap_or(&[])
    }

    /// The object pages the request takes: one per named page.
    #[must_use]
    pub fn pages(&self) -> u64
    {
        self.chunks()
            .iter()
            .map(|&(_, mask)| u64::from(mask.count_ones()))
            .sum()
    }
}

/// The byte after the `pages` pages from `va`; `None` on overflow.
fn end_of(va: u64, pages: u64) -> Option<u64>
{
    va.checked_add(pages.checked_mul(PAGE_SIZE)?)
}

/// Whether the `(va, pages)` spans are nonempty, page-aligned, inside the
/// address space, and ascending apart from one another.
fn ascending(spans: impl Iterator<Item = (u64, u64)>) -> bool
{
    let mut floor = 0u64;
    for (va, pages) in spans
    {
        let Some(end) = end_of(va, pages)
        else
        {
            return false;
        };
        if pages == 0 || !va.is_multiple_of(PAGE_SIZE) || va < floor
        {
            return false;
        }
        floor = end;
    }
    true
}

impl Layout
{
    /// Decode the layout `bytes`, the object's first
    /// [`Header::layout_pages`] pages, whose header is `header`
    /// ([`checkpoint_header`]).
    ///
    /// # Errors
    /// [`DecodeError::Malformed`] when an entry or the checkpoint section is
    /// not all in `bytes`, or the regions or runs are not each ascending
    /// spans apart from one another; [`DecodeError::OutOfMemory`] when the
    /// heap refuses their room.
    pub fn decode(bytes: &[u8], header: Header) -> Result<Self, DecodeError>
    {
        let region_n = usize::try_from(header.region_count).map_err(|_| DecodeError::Malformed)?;
        let run_n = usize::try_from(header.run_count).map_err(|_| DecodeError::Malformed)?;
        let mut regions = Vec::new();
        regions.try_reserve_exact(region_n)?;
        for i in 0..region_n
        {
            regions.push(RegionEntry::decode(bytes, i).ok_or(DecodeError::Malformed)?);
        }
        let mut runs = Vec::new();
        runs.try_reserve_exact(run_n)?;
        for i in 0..run_n
        {
            runs.push(Run::decode(bytes, header.region_count, i).ok_or(DecodeError::Malformed)?);
        }
        let entries = header
            .region_count
            .checked_add(header.run_count)
            .ok_or(DecodeError::Malformed)?;
        let checkpoint = checkpoint_offset(entries, header.thread_bytes)
            .and_then(|at| Checkpoint::decode(bytes, at))
            .ok_or(DecodeError::Malformed)?;
        if !ascending(regions.iter().map(|r| (r.va, r.pages)))
            || !ascending(runs.iter().map(|r| (r.va, r.pages)))
        {
            return Err(DecodeError::Malformed);
        }
        Ok(Self {
            header,
            checkpoint,
            regions,
            runs,
        })
    }

    /// Whether the checkpoint is of the verified body `image` and every
    /// executable run lies in one of the `text` spans (`[start, end)`), the
    /// pages of the image's executable segments at the checkpoint's load
    /// bias, so no executable byte comes from the snapshot.
    #[must_use]
    pub fn binds(&self, image: Image, text: &[(u64, u64)]) -> bool
    {
        self.checkpoint.image == image
            && self
                .runs
                .iter()
                .filter(|run| run.flags & PAGE_RUN_EXECUTE != 0)
                .all(|run| {
                    end_of(run.va, run.pages).is_some_and(|end| {
                        text.iter()
                            .any(|&(start, stop)| start <= run.va && end <= stop)
                    })
                })
    }

    /// The checkpoint's argv and env header, when its bootstrap words are in
    /// the form a create gives them: the `ProcessInfo` page, the IPC buffer
    /// and the stack top page-aligned, a restore stack pointer below the
    /// stack top at [`RESTORE_SP_ALIGN`], and the argv blob at
    /// `region_offset` from the `ProcessInfo` page with the env blob after
    /// it, at most `max_bytes` together, an empty blob recorded as absent.
    #[must_use]
    pub fn argv_env_header(&self, region_offset: u64, max_bytes: u64) -> Option<ArgvEnvHeader>
    {
        let c = &self.checkpoint;
        let pages_aligned = [c.process_info_va, c.ipc_buffer_va, c.stack_top]
            .iter()
            .all(|&va| va != 0 && va.is_multiple_of(PAGE_SIZE));
        let sp_ok = c.restore_sp != 0
            && c.restore_sp < c.stack_top
            && c.restore_sp.is_multiple_of(RESTORE_SP_ALIGN);
        let blob_ok = |offset: u64, bytes: u64, count: u64, at: u64| {
            if bytes == 0
            {
                offset == 0 && count == 0
            }
            else
            {
                offset == at
            }
        };
        let env_at = region_offset.checked_add(c.args_bytes)?;
        let fits = c
            .args_bytes
            .checked_add(c.env_bytes)
            .is_some_and(|total| total <= max_bytes);
        (pages_aligned
            && sp_ok
            && fits
            && blob_ok(c.args_offset, c.args_bytes, c.args_count, region_offset)
            && blob_ok(c.env_offset, c.env_bytes, c.env_count, env_at))
        .then_some(ArgvEnvHeader {
            args_bytes: c.args_bytes,
            args_count: c.args_count,
            env_bytes: c.env_bytes,
            env_count: c.env_count,
        })
    }

    /// The span the page at `va` starts, at most `pages` long, of a
    /// bootstrap surface: the pages of its run from `va` on, when they are
    /// bytes in the object or read zero ([`RUN_ZERO`]). `None` when `pages`
    /// is zero, or `va` is in no run or in one whose pages are neither
    /// (absent, the image's, or device memory): such a page cannot be
    /// restored.
    #[must_use]
    pub fn next_span(&self, va: u64, pages: u64) -> Option<Span>
    {
        if pages == 0
        {
            return None;
        }
        let at = self
            .runs
            .partition_point(|r| end_of(r.va, r.pages).is_some_and(|end| end <= va));
        let run = self.runs.get(at).filter(|run| run.va <= va)?;
        let into = va.checked_sub(run.va)? / PAGE_SIZE;
        let pages = run.pages.checked_sub(into)?.min(pages);
        if run.has_bytes()
        {
            Some(Span {
                pages,
                object_page: Some(run.object_page.checked_add(into)?),
            })
        }
        else if run.flags & RUN_ZERO != 0
        {
            Some(Span {
                pages,
                object_page: None,
            })
        }
        else
        {
            None
        }
    }

    /// How `region` is made again: a demand region by `REGISTER_REGION`
    /// with its commit and no-evict flags, an attachment of the zero object
    /// by `ATTACH_OBJECT` of the zero object, private when it was. `None`
    /// for an attachment of the image, which the new image attachment is,
    /// of another object, which was mapped from a capability, and of a class
    /// this side does not know.
    #[must_use]
    pub fn remake(region: &RegionEntry) -> Option<Remake>
    {
        let va = region.va;
        let len = region.pages.checked_mul(PAGE_SIZE)?;
        let prot = region.flags & REGION_PROT_MASK;
        match region.class()
        {
            REGION_DEMAND =>
            {
                let mut flags = 0;
                if region.flags & REGION_COMMIT != 0
                {
                    flags |= memmgr_labels::REGION_COMMIT;
                }
                if region.flags & REGION_NO_EVICT != 0
                {
                    flags |= memmgr_labels::REGION_NO_EVICT;
                }
                Some(Remake::Register {
                    va,
                    len,
                    prot,
                    flags,
                })
            }
            REGION_ZERO =>
            {
                let flags = if region.flags & REGION_PRIVATE == 0
                {
                    0
                }
                else
                {
                    memmgr_labels::ATTACH_PRIVATE
                };
                Some(Remake::AttachZero {
                    va,
                    len,
                    prot,
                    flags,
                })
            }
            _ => None,
        }
    }

    /// The `FILL_REGION` requests that back every page the snapshot holds
    /// bytes of in a region made again that a fill can back: a demand
    /// region, or a private attachment of the zero object. Each chunk lies
    /// `DEMAND_CHUNK_BYTES` apart from its region's base, a request names at
    /// most `FILL_CHUNKS` in ascending order, and its named pages' object
    /// pages follow one another: a page whose object page does not follow the
    /// one before starts a new request. A zero run stays unbacked.
    ///
    /// # Errors
    /// The heap's refusal of the requests' room.
    pub fn fills(&self) -> Result<Vec<Fill>, TryReserveError>
    {
        let mut out = Fills::default();
        for region in &self.regions
        {
            let fillable = match Self::remake(region)
            {
                Some(Remake::Register { .. }) => true,
                Some(Remake::AttachZero { flags, .. }) =>
                {
                    flags & memmgr_labels::ATTACH_PRIVATE != 0
                }
                None => false,
            };
            let Some(region_end) = end_of(region.va, region.pages)
            else
            {
                continue;
            };
            if !fillable
            {
                continue;
            }
            let first = self.runs.partition_point(|r| r.va < region.va);
            for run in self.runs.get(first..).unwrap_or(&[])
            {
                if run.va >= region_end
                {
                    break;
                }
                if run.has_bytes()
                {
                    out.push_run(region.va, region_end, run)?;
                }
            }
        }
        out.finish()
    }
}

/// The builder of [`Layout::fills`]: the requests made, the one being
/// filled, and the object page its next named page must take.
#[derive(Default)]
struct Fills
{
    done: Vec<Fill>,
    current: Option<Fill>,
    next: u64,
}

impl Fills
{
    /// Name every page of `run`, a run with bytes inside the region
    /// `[base, end)`, in address order.
    fn push_run(&mut self, base: u64, end: u64, run: &Run) -> Result<(), TryReserveError>
    {
        for page in 0..run.pages
        {
            let va = run.va.saturating_add(page.saturating_mul(PAGE_SIZE));
            if va >= end
            {
                break;
            }
            // The run starts at or above the region's base.
            let index = va.saturating_sub(base) / PAGE_SIZE;
            let chunk =
                base.saturating_add((index / CHUNK_PAGES).saturating_mul(DEMAND_CHUNK_BYTES));
            let bit = 1u16 << (index % CHUNK_PAGES);
            self.push(chunk, bit, run.object_page.saturating_add(page))?;
        }
        Ok(())
    }

    /// Name the page `bit` of the chunk at `chunk`, taking object page
    /// `object_page`; pages are pushed in ascending address order.
    fn push(&mut self, chunk: u64, bit: u16, object_page: u64) -> Result<(), TryReserveError>
    {
        if let Some(fill) = self.current.as_mut()
            && self.next == object_page
        {
            let count = fill.count;
            if let Some(last) = count.checked_sub(1).and_then(|i| fill.chunks.get_mut(i))
                && last.0 == chunk
            {
                last.1 |= bit;
                self.next = object_page.saturating_add(1);
                return Ok(());
            }
            if let Some(slot) = fill.chunks.get_mut(count)
            {
                *slot = (chunk, bit);
                fill.count = count.saturating_add(1);
                self.next = object_page.saturating_add(1);
                return Ok(());
            }
        }
        if let Some(fill) = self.current.take()
        {
            self.done.try_reserve(1)?;
            self.done.push(fill);
        }
        let mut chunks = [(0, 0); MAX_CHUNKS];
        if let Some(slot) = chunks.first_mut()
        {
            *slot = (chunk, bit);
        }
        self.current = Some(Fill {
            first: object_page,
            count: 1,
            chunks,
        });
        self.next = object_page.saturating_add(1);
        Ok(())
    }

    /// The requests, the last one included.
    fn finish(mut self) -> Result<Vec<Fill>, TryReserveError>
    {
        if let Some(fill) = self.current.take()
        {
            self.done.try_reserve(1)?;
            self.done.push(fill);
        }
        Ok(self.done)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use alloc::vec;
    use ipc::procmgr_snapshot::{
        CHECKPOINT_BYTES, NO_OBJECT_PAGE, REGION_CLASS_SHIFT, REGION_IMAGE, REGION_OBJECT,
        RUN_ABSENT, RUN_IMAGE, SNAPSHOT_IMAGE,
    };
    use syscall_abi::{PAGE_RUN_NO_COPY, PAGE_RUN_READ, PAGE_RUN_WRITE};

    const P: u64 = PAGE_SIZE;
    const RW: u64 = PAGE_RUN_READ | PAGE_RUN_WRITE;
    const RX: u64 = PAGE_RUN_READ | PAGE_RUN_EXECUTE;
    const REGION_OFFSET: u64 = P;
    const MAX_BYTES: u64 = 64 * P;
    const IMG: Image = Image {
        hash: [7; 64],
        len: 1234,
    };

    fn run(va: u64, pages: u64, flags: u64, object_page: u64) -> Run
    {
        Run {
            va,
            pages,
            flags,
            object_page,
        }
    }

    fn region(va: u64, pages: u64, class: u64, extra: u64) -> RegionEntry
    {
        RegionEntry {
            va,
            pages,
            flags: 0x3 | (class << REGION_CLASS_SHIFT) | extra,
            first_page: 0,
        }
    }

    fn checkpoint() -> Checkpoint
    {
        Checkpoint {
            restore_sp: 0x7000_0000 - 0x100,
            process_info_va: 0x1000_0000,
            ipc_buffer_va: 0x2000_0000,
            stack_top: 0x7000_0000,
            tls_base: 0x3000_0010,
            args_offset: REGION_OFFSET,
            args_bytes: 10,
            args_count: 2,
            env_offset: REGION_OFFSET + 10,
            env_bytes: 6,
            env_count: 1,
            declarations: 0,
            image: IMG,
        }
    }

    fn layout(regions: &[RegionEntry], runs: &[Run]) -> Layout
    {
        Layout {
            header: header(0, 0, SNAPSHOT_COMPLETE | SNAPSHOT_CHECKPOINT),
            checkpoint: checkpoint(),
            regions: regions.to_vec(),
            runs: runs.to_vec(),
        }
    }

    fn header(regions: u64, runs: u64, flags: u64) -> Header
    {
        Header {
            flags,
            layout_pages: 1,
            data_pages: 0,
            region_count: regions,
            run_count: runs,
            image: IMG,
            load_bias: 0x4000_0000,
            thread_count: 0,
            thread_bytes: 0,
        }
    }

    /// The layout page of `regions` and `runs` with the checkpoint section,
    /// under a header with `flags`.
    fn encoded(regions: &[RegionEntry], runs: &[Run], flags: u64) -> (Vec<u8>, Header)
    {
        let h = header(regions.len() as u64, runs.len() as u64, flags);
        let mut bytes = vec![0u8; usize::try_from(P).unwrap()];
        h.encode(&mut bytes).unwrap();
        for (i, r) in regions.iter().enumerate()
        {
            r.encode(&mut bytes, i).unwrap();
        }
        for (i, r) in runs.iter().enumerate()
        {
            r.encode(&mut bytes, regions.len() as u64, i).unwrap();
        }
        let at = checkpoint_offset((regions.len() + runs.len()) as u64, 0).unwrap();
        checkpoint().encode(&mut bytes, at).unwrap();
        (bytes, h)
    }

    // Defect guarded: a restore from a debugger's `SNAPSHOT`, or from a
    // capture with absent pages, whose layout carries no checkpoint section
    // or no bytes of some page.
    #[test]
    fn only_a_complete_checkpoint_header_is_taken()
    {
        let both = SNAPSHOT_COMPLETE | SNAPSHOT_CHECKPOINT;
        let (bytes, _) = encoded(&[], &[], both | SNAPSHOT_IMAGE);
        assert!(checkpoint_header(&bytes).is_some());
        let (bytes, _) = encoded(&[], &[], SNAPSHOT_COMPLETE | SNAPSHOT_IMAGE);
        assert!(checkpoint_header(&bytes).is_none());
        let (bytes, _) = encoded(&[], &[], SNAPSHOT_CHECKPOINT);
        assert!(checkpoint_header(&bytes).is_none());
        assert!(checkpoint_header(&[0; 16]).is_none());
    }

    #[test]
    fn a_layout_decodes_its_entries_and_its_checkpoint_section()
    {
        let regions = [region(0x10_0000, 32, REGION_DEMAND, 0)];
        let runs = [
            run(0x10_0000, 2, RW, 1),
            run(0x10_2000, 30, RW | RUN_ZERO, NO_OBJECT_PAGE),
        ];
        let (bytes, h) = encoded(&regions, &runs, SNAPSHOT_COMPLETE | SNAPSHOT_CHECKPOINT);
        let l = Layout::decode(&bytes, h).unwrap();
        assert_eq!(
            (l.regions.as_slice(), l.runs.as_slice()),
            (&regions[..], &runs[..])
        );
        assert_eq!(l.checkpoint, checkpoint());
        // The checkpoint section must be in the bytes.
        let cut = checkpoint_offset(3, 0).unwrap() + CHECKPOINT_BYTES - 1;
        assert_eq!(
            Layout::decode(&bytes[..cut], h),
            Err(DecodeError::Malformed)
        );
    }

    // Defect guarded: overlapping or unordered runs, which the span lookup's
    // binary search would read wrong, taken as a layout.
    #[test]
    fn runs_or_regions_out_of_order_or_overlapping_are_malformed()
    {
        let flags = SNAPSHOT_COMPLETE | SNAPSHOT_CHECKPOINT;
        let overlapping = [run(0x10_0000, 2, RW, 1), run(0x10_1000, 1, RW, 3)];
        let (bytes, h) = encoded(&[], &overlapping, flags);
        assert_eq!(Layout::decode(&bytes, h), Err(DecodeError::Malformed));
        let unordered = [run(0x20_0000, 1, RW, 1), run(0x10_0000, 1, RW, 2)];
        let (bytes, h) = encoded(&[], &unordered, flags);
        assert_eq!(Layout::decode(&bytes, h), Err(DecodeError::Malformed));
        let empty = [run(0x10_0000, 0, RW, 1)];
        let (bytes, h) = encoded(&[], &empty, flags);
        assert_eq!(Layout::decode(&bytes, h), Err(DecodeError::Malformed));
        let regions = [
            region(0x10_0000, 4, REGION_DEMAND, 0),
            region(0x10_2000, 4, REGION_DEMAND, 0),
        ];
        let (bytes, h) = encoded(&regions, &[], flags);
        assert_eq!(Layout::decode(&bytes, h), Err(DecodeError::Malformed));
    }

    // Defect guarded: a restore that takes an executable byte from the
    // snapshot, or binds the snapshot to another body than the one it was
    // taken of.
    #[test]
    fn a_checkpoint_binds_only_its_own_body_and_its_text()
    {
        let text = [(0x4000_0000, 0x4000_4000)];
        let l = layout(
            &[],
            &[
                run(0x4000_0000, 4, RX | RUN_IMAGE, 0),
                run(0x5000_0000, 2, RW, 1),
            ],
        );
        assert!(l.binds(IMG, &text));
        let other = Image {
            hash: [8; 64],
            len: 1234,
        };
        assert!(!l.binds(other, &text));
        let longer = Image { len: 1235, ..IMG };
        assert!(!l.binds(longer, &text));
        let past = layout(&[], &[run(0x4000_0000, 5, RX, 1)]);
        assert!(!past.binds(IMG, &text));
        let outside = layout(&[], &[run(0x6000_0000, 1, RX, 1)]);
        assert!(!outside.binds(IMG, &text));
    }

    #[test]
    fn the_argv_env_header_is_taken_only_in_the_create_form()
    {
        let l = layout(&[], &[]);
        assert_eq!(
            l.argv_env_header(REGION_OFFSET, MAX_BYTES),
            Some(ArgvEnvHeader {
                args_bytes: 10,
                args_count: 2,
                env_bytes: 6,
                env_count: 1,
            })
        );
        assert_eq!(l.argv_env_header(REGION_OFFSET, 15), None);
        let mut moved = layout(&[], &[]);
        moved.checkpoint.env_offset += 1;
        assert_eq!(moved.argv_env_header(REGION_OFFSET, MAX_BYTES), None);
        let mut none = layout(&[], &[]);
        (none.checkpoint.args_offset, none.checkpoint.args_bytes) = (0, 0);
        none.checkpoint.args_count = 0;
        none.checkpoint.env_offset = REGION_OFFSET;
        assert!(none.argv_env_header(REGION_OFFSET, MAX_BYTES).is_some());
        none.checkpoint.args_count = 1;
        assert_eq!(none.argv_env_header(REGION_OFFSET, MAX_BYTES), None);
        for bad_sp in [0, 0x7000_0000, 0x7000_0000 - 8]
        {
            let mut sp = layout(&[], &[]);
            sp.checkpoint.restore_sp = bad_sp;
            assert_eq!(sp.argv_env_header(REGION_OFFSET, MAX_BYTES), None);
        }
        let mut stack = layout(&[], &[]);
        stack.checkpoint.stack_top += 8;
        assert_eq!(stack.argv_env_header(REGION_OFFSET, MAX_BYTES), None);
    }

    // Defect guarded: a bootstrap page filled from the wrong object page, or
    // from a run whose bytes the object does not hold.
    #[test]
    fn a_span_takes_the_bytes_or_zeros_of_its_run_and_nothing_else()
    {
        let l = layout(
            &[],
            &[
                run(0x10_0000, 4, RW, 10),
                run(0x10_4000, 2, RW | RUN_ZERO, NO_OBJECT_PAGE),
                run(0x10_6000, 1, RW | RUN_ABSENT, NO_OBJECT_PAGE),
                run(0x10_7000, 1, RW | PAGE_RUN_NO_COPY, NO_OBJECT_PAGE),
                run(0x10_8000, 1, RX | RUN_IMAGE, 3),
            ],
        );
        let bytes = |pages, page| Span {
            pages,
            object_page: Some(page),
        };
        assert_eq!(l.next_span(0x10_0000, 9), Some(bytes(4, 10)));
        assert_eq!(l.next_span(0x10_1000, 2), Some(bytes(2, 11)));
        assert_eq!(l.next_span(0x10_3000, 9), Some(bytes(1, 13)));
        assert_eq!(
            l.next_span(0x10_5000, 9),
            Some(Span {
                pages: 1,
                object_page: None
            })
        );
        assert_eq!(l.next_span(0x10_0000, 0), None);
        assert_eq!(l.next_span(0x10_6000, 1), None);
        assert_eq!(l.next_span(0x10_7000, 1), None);
        assert_eq!(l.next_span(0x10_8000, 1), None);
        assert_eq!(l.next_span(0x10_9000, 1), None);
        assert_eq!(l.next_span(0x0F_F000, 1), None);
    }

    // Defect guarded: a region made again with the wrong request or flags,
    // or an attachment of an object remade, which was mapped from a
    // capability the restore does not hold.
    #[test]
    fn regions_are_made_again_by_their_class()
    {
        let demand = region(0x10_0000, 2, REGION_DEMAND, REGION_COMMIT | REGION_NO_EVICT);
        assert_eq!(
            Layout::remake(&demand),
            Some(Remake::Register {
                va: 0x10_0000,
                len: 2 * P,
                prot: 3,
                flags: memmgr_labels::REGION_COMMIT | memmgr_labels::REGION_NO_EVICT,
            })
        );
        let plain = region(0x10_0000, 1, REGION_DEMAND, 0);
        assert!(matches!(
            Layout::remake(&plain),
            Some(Remake::Register { flags: 0, .. })
        ));
        let zero = region(0x20_0000, 3, REGION_ZERO, REGION_PRIVATE);
        assert_eq!(
            Layout::remake(&zero),
            Some(Remake::AttachZero {
                va: 0x20_0000,
                len: 3 * P,
                prot: 3,
                flags: memmgr_labels::ATTACH_PRIVATE,
            })
        );
        assert_eq!(Layout::remake(&region(0, 1, REGION_IMAGE, 0)), None);
        assert_eq!(Layout::remake(&region(0, 1, REGION_OBJECT, 0)), None);
        assert_eq!(Layout::remake(&region(0, 1, 9, 0)), None);
    }

    // Defect guarded: a fill whose named pages take other object pages than
    // the snapshot's, a chunk base off the region's chunk grid, or more
    // chunks than one request names.
    #[test]
    fn fills_name_chunks_from_the_region_base_and_follow_the_object_pages()
    {
        // A region based off a 64 KiB boundary: its chunks start at its base.
        let base = 0x10_3000;
        let regions = [region(base, 80, REGION_DEMAND, 0)];
        let runs = [
            run(base, 2, RW, 5),
            run(base + 2 * P, 14, RW | RUN_ZERO, NO_OBJECT_PAGE),
            run(base + 16 * P, 1, RW, 7),
            run(base + 17 * P, 30, RW | RUN_ZERO, NO_OBJECT_PAGE),
            run(base + 47 * P, 2, RW, 8),
            run(base + 49 * P, 15, RW | RUN_ZERO, NO_OBJECT_PAGE),
            run(base + 64 * P, 1, RW, 10),
            run(base + 65 * P, 1, RW | RUN_ZERO, NO_OBJECT_PAGE),
            run(base + 66 * P, 1, RW, 20),
        ];
        let fills = layout(&regions, &runs).fills().unwrap();
        assert_eq!(fills.len(), 3);
        let chunk = |i: u64| base + i * DEMAND_CHUNK_BYTES;
        // Pages 0-1, 16, 47 and 48 take object pages 5 to 9 in order over
        // four chunks: page 47 is chunk 2's last, page 48 chunk 3's first.
        assert_eq!(fills[0].first, 5);
        assert_eq!(
            fills[0].chunks(),
            &[
                (chunk(0), 0b11),
                (chunk(1), 0b1),
                (chunk(2), 0b1 << 15),
                (chunk(3), 0b1),
            ][..]
        );
        assert_eq!(fills[0].pages(), 5);
        // Page 64, object page 10, is in a fifth chunk: a new request.
        assert_eq!(fills[1].first, 10);
        assert_eq!(fills[1].chunks(), &[(chunk(4), 0b1)][..]);
        // Object page 20 does not follow 10: a new request.
        assert_eq!(fills[2].first, 20);
        assert_eq!(fills[2].chunks(), &[(chunk(4), 0b100)][..]);
    }

    #[test]
    fn a_request_names_at_most_fill_chunks_chunks()
    {
        let regions = [region(0, 16 * 6, REGION_DEMAND, 0)];
        let runs: Vec<Run> = (0..6)
            .map(|i| run(i * DEMAND_CHUNK_BYTES, 1, RW, 100 + i))
            .collect();
        let mut runs_with_gaps = Vec::new();
        for r in &runs
        {
            runs_with_gaps.push(*r);
            runs_with_gaps.push(run(r.va + P, 15, RW | RUN_ZERO, NO_OBJECT_PAGE));
        }
        let fills = layout(&regions, &runs_with_gaps).fills().unwrap();
        assert_eq!(fills.len(), 2);
        assert_eq!(fills[0].chunks().len(), MAX_CHUNKS);
        assert_eq!((fills[1].first, fills[1].chunks().len()), (104, 2));
    }

    // Defect guarded: a fill sent for a region no fill can back (the image's,
    // another object's, a shared zero attachment) or for pages outside every
    // region, which memmgr refuses and which would fail the restore.
    #[test]
    fn only_demand_regions_and_private_zero_attachments_are_filled()
    {
        let regions = [
            region(0x10_0000, 1, REGION_IMAGE, 0),
            region(0x20_0000, 1, REGION_OBJECT, 0),
            region(0x30_0000, 1, REGION_ZERO, 0),
            region(0x40_0000, 1, REGION_ZERO, REGION_PRIVATE),
        ];
        let runs = [
            run(0x10_0000, 1, RW, 1),
            run(0x20_0000, 1, RW, 2),
            run(0x30_0000, 1, RW, 3),
            run(0x40_0000, 1, RW, 4),
            run(0x50_0000, 1, RW, 5),
        ];
        let fills = layout(&regions, &runs).fills().unwrap();
        assert_eq!(fills.len(), 1);
        assert_eq!(
            (fills[0].first, fills[0].chunks()),
            (4, &[(0x40_0000, 1)][..])
        );
    }
}
