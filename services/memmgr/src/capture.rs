// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/src/capture.rs

//! `CAPTURE_CHUNKS`: the content of a process's demand chunks, copied into
//! Memory caps procmgr's request carries, for `SNAPSHOT`
//! (services/memmgr/docs/ipc-interface.md § Label 31: `CAPTURE_CHUNKS`).
//!
//! memmgr reads each chunk where it holds it in this turn
//! ([`free_pool::capture_source`]): from its runs when it is resident, being
//! evicted, or raw ([`evict::read_raw`]), and from its store, decoded, when it
//! is compressed ([`evict::decode_store`]). It maps nothing into the process,
//! draws no frame, and evicts nothing, so a capture of a held process neither
//! changes the process's chunks nor depends on where an eviction meanwhile
//! moves them: each chunk's content has one source, read once. A chunk on disk
//! it posts to the swap service, as `MAKE_RESIDENT` does
//! ([`disk::post_want`]), for procmgr to read again once the swap service has
//! restored it.

use free_pool::{CaptureSource, ChunkState, NodeIdx, capture_source, chunk_for};
use ipc::memmgr_capture::{
    DESCRIPTOR_WORDS, DESCRIPTORS_MAX, Descriptor, REPLY_WORDS, REQUEST_WORDS, Supply, dest_spans,
};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::{MSG_CAP_SLOTS_MAX, PAGE_SIZE};

use crate::{
    MemLedger, SCRUB_VA, delete_caps, disk, evict, ledger_mut, map_self, reply_label, self_aspace,
};

/// Chunks one request supplies at most: a tuning value that bounds the
/// request's turn to as many copies or decodes of a chunk, each at most a
/// chunk's pages, as `MAKE_RESIDENT`'s bound allows restores.
const CAPTURE_SUPPLIED: usize = 4;

/// Chunks with an entry, and regions with none or attached, one request
/// visits at most: a tuning value that bounds the turn's walk over chunks that
/// need nothing.
const CAPTURE_VISITS: u32 = 64;

/// Serve a `CAPTURE_CHUNKS` request whose contract caps are `caps`, and
/// delete them before the reply, whatever it is.
pub(crate) fn handle_capture_chunks(
    req: &IpcMessage,
    caps: &[u64],
    ipc_buf: *mut u64,
    procmgr_badge: u64,
)
{
    let served = serve(req, caps, procmgr_badge);
    delete_caps(caps);
    match served
    {
        Ok(reply) =>
        {
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        Err(label) => reply_label(ipc_buf, label),
    }
}

/// The reply to `req`, or the error label.
fn serve(req: &IpcMessage, caps: &[u64], procmgr_badge: u64) -> Result<IpcMessage, u64>
{
    if req.badge != procmgr_badge
    {
        return Err(memmgr_errors::UNAUTHORIZED);
    }
    let l = ledger_mut();
    let (cursor, end, flags) = (req.word(1), req.word(2), req.word(3));
    let rec = l.find(req.word(0)).ok_or(memmgr_errors::INVALID_ARGUMENT)?;
    if end <= cursor || flags & !memmgr_labels::CAPTURE_COUNT != 0
    {
        return Err(memmgr_errors::INVALID_ARGUMENT);
    }
    if flags & memmgr_labels::CAPTURE_COUNT != 0
    {
        return Ok(count(l, rec, cursor, end));
    }
    if req.word_count() < REQUEST_WORDS.saturating_add(caps.len())
    {
        return Err(memmgr_errors::INVALID_ARGUMENT);
    }
    let mut pages = [0u64; MSG_CAP_SLOTS_MAX];
    for (i, slot) in pages.iter_mut().enumerate().take(caps.len())
    {
        *slot = req.word(REQUEST_WORDS.saturating_add(i));
    }
    let dest = Dest {
        caps,
        offset: req.word(4),
        pages: pages.get(..caps.len()).unwrap_or(&[]),
        used: 0,
    };
    copy(l, rec, cursor, end, dest)
}

/// What a walk's visit of a chunk has it do next ([`walk`]).
enum Step
{
    /// Go on past the chunk.
    Next,
    /// Stop at the chunk, which the next request visits again.
    Before,
    /// Stop past the chunk.
    After,
}

/// A chunk a walk visits: its region, its base, its pages, and its region's
/// protection.
#[derive(Clone, Copy)]
struct Visit
{
    reg: NodeIdx,
    base: u64,
    pages: u32,
    prot: u64,
}

/// Visit each chunk with an entry of `rec`'s demand regions from `at`, below
/// `end`, in address order, passing over attachments, whose chunks no
/// eviction takes and whose pages procmgr reads from the process, and stopping
/// after [`CAPTURE_VISITS`] chunks and regions. Returns where the walk
/// stopped: `end` when it is done, else where the next request goes on from.
fn walk(
    l: &mut MemLedger,
    rec: NodeIdx,
    mut at: u64,
    end: u64,
    mut visit: impl FnMut(&mut MemLedger, Visit) -> Step,
) -> u64
{
    let mut visits = 0u32;
    while at < end
    {
        if visits >= CAPTURE_VISITS
        {
            return at;
        }
        let Some((reg, node)) = l.region_from(rec, at)
        else
        {
            return end;
        };
        if node.region.va_base >= end
        {
            return end;
        }
        visits = visits.saturating_add(1);
        let region_end = node.region.va_base.saturating_add(node.region.len);
        let from = at.max(node.region.va_base);
        let next = if l.attachment(reg).is_some()
        {
            None
        }
        else
        {
            l.next_chunk_with_entry(reg, from)
        };
        let Some(next) = next
        else
        {
            at = region_end;
            continue;
        };
        let (base, pages) = chunk_for(&node.region, next);
        if base >= end
        {
            return end;
        }
        let chunk_end = base.saturating_add(u64::from(pages).saturating_mul(PAGE_SIZE));
        match visit(
            l,
            Visit {
                reg,
                base,
                pages,
                prot: node.region.prot,
            },
        )
        {
            Step::Next => at = chunk_end,
            Step::Before => return base,
            Step::After => return chunk_end.min(end),
        }
    }
    end
}

/// The reply to a `CAPTURE_COUNT` request over `[cursor, end)` of `rec`: the
/// cursor, the backed pages of the evicted chunks walked, lost ones aside, and
/// the chunks on disk walked whose slot word memmgr posted to the swap
/// service.
fn count(l: &mut MemLedger, rec: NodeIdx, cursor: u64, end: u64) -> IpcMessage
{
    let wants = disk::wants_registered();
    let (mut evicted, mut posted) = (0u64, 0u64);
    let reached = walk(l, rec, cursor, end, |l, v| {
        let entry = l.chunk_at(v.reg, v.base);
        let backed = u64::from(entry.backed().count_ones());
        match capture_source(&entry, wants)
        {
            CaptureSource::Skip | CaptureSource::Absent =>
            {}
            // Mapped in the process, so procmgr counts it in its listing.
            CaptureSource::Runs if entry.state() == ChunkState::Resident =>
            {}
            CaptureSource::Runs | CaptureSource::Store => evicted = evicted.saturating_add(backed),
            CaptureSource::Want =>
            {
                evicted = evicted.saturating_add(backed);
                if disk::post_want(l, entry.disk())
                {
                    posted = posted.saturating_add(1);
                }
            }
        }
        Step::Next
    });
    IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, reached)
        .word(1, evicted)
        .word(2, posted)
        .build()
}

/// The reply to a copy request over `[cursor, end)` of `rec` into `dest`, or
/// `OUT_OF_MEMORY_BEST_EFFORT` when a destination page could not be mapped.
fn copy(
    l: &mut MemLedger,
    rec: NodeIdx,
    cursor: u64,
    end: u64,
    mut dest: Dest<'_>,
) -> Result<IpcMessage, u64>
{
    let wants = disk::wants_registered();
    let mut words = [0u64; DESCRIPTORS_MAX * DESCRIPTOR_WORDS];
    let (mut count, mut supplied, mut need, mut unmapped) = (0usize, 0usize, 0u64, false);
    let reached = walk(l, rec, cursor, end, |l, v| {
        let entry = l.chunk_at(v.reg, v.base);
        let source = capture_source(&entry, wants);
        let supply = match source
        {
            CaptureSource::Skip => return Step::Next,
            CaptureSource::Want if disk::post_want(l, entry.disk()) => Supply::Pending,
            CaptureSource::Want | CaptureSource::Absent => Supply::Absent,
            CaptureSource::Runs | CaptureSource::Store =>
            {
                let backed = u64::from(entry.backed().count_ones());
                if !dest.holds(backed)
                {
                    need = backed;
                    return Step::Before;
                }
                let read = dest.fill(l, backed, |l, dst| {
                    if matches!(source, CaptureSource::Runs)
                    {
                        evict::read_raw(l, rec, v.reg, v.base, dst).is_some()
                    }
                    else
                    {
                        evict::decode_store(l, entry, dst)
                    }
                });
                match read
                {
                    None =>
                    {
                        unmapped = true;
                        return Step::Before;
                    }
                    Some(true) =>
                    {
                        dest.used = dest.used.saturating_add(backed);
                        supplied = supplied.saturating_add(1);
                        Supply::Supplied
                    }
                    Some(false) => Supply::Absent,
                }
            }
        };
        let descriptor = Descriptor {
            va: v.base,
            pages: u64::from(v.pages),
            backed: entry.backed(),
            prot: v.prot,
            supply,
        };
        let at = count.saturating_mul(DESCRIPTOR_WORDS);
        if let Some(slot) = words.get_mut(at..at.saturating_add(DESCRIPTOR_WORDS))
        {
            slot.copy_from_slice(&descriptor.encode());
        }
        count = count.saturating_add(1);
        if count >= DESCRIPTORS_MAX || supplied >= CAPTURE_SUPPLIED
        {
            Step::After
        }
        else
        {
            Step::Next
        }
    });
    if unmapped
    {
        return Err(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT);
    }
    Ok(IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, reached)
        .word(1, dest.used)
        .word(2, need)
        .word(3, count as u64)
        .words(
            REPLY_WORDS,
            words
                .get(..count.saturating_mul(DESCRIPTOR_WORDS))
                .unwrap_or(&[]),
        )
        .build())
}

/// A request's destination: its caps, the page offset into the first, the
/// pages each gives, and the pages written so far.
struct Dest<'a>
{
    caps: &'a [u64],
    offset: u64,
    pages: &'a [u64],
    used: u64,
}

impl Dest<'_>
{
    /// Whether `count` more pages fit after those written.
    fn holds(&self, count: u64) -> bool
    {
        dest_spans(self.offset, self.pages, self.used, count).is_some()
    }

    /// Map the `count` pages after those written at the scrub window, run
    /// `read` on their bytes, and unmap them. `None`, nothing left mapped,
    /// when a page cannot be mapped; else what `read` returned.
    fn fill(
        &self,
        l: &mut MemLedger,
        count: u64,
        read: impl FnOnce(&mut MemLedger, &mut [u8]) -> bool,
    ) -> Option<bool>
    {
        let spans = dest_spans(self.offset, self.pages, self.used, count)?;
        let mut mapped = 0u64;
        for (cap, offset, pages) in spans
        {
            let va = SCRUB_VA.saturating_add(mapped.saturating_mul(PAGE_SIZE));
            let cap = self.caps.get(cap).copied().unwrap_or(0);
            // SAFETY: the scrub window is memmgr's own zone, which every use
            // leaves unmapped, and the `count` pages, at most a chunk's, lie
            // in it.
            if unsafe { map_self(l, cap, va, offset, pages) }.is_err()
            {
                unmap_scrub(mapped);
                return None;
            }
            mapped = mapped.saturating_add(pages);
        }
        let len = usize::try_from(count.saturating_mul(PAGE_SIZE)).unwrap_or(0);
        // SAFETY: the `count` pages at the scrub window are mapped read-write
        // above to frames of the request's caps, which nothing in memmgr
        // refers to, and the slice is not used past the unmap below.
        let dst = unsafe { core::slice::from_raw_parts_mut(SCRUB_VA as *mut u8, len) };
        let read = read(l, dst);
        unmap_scrub(mapped);
        Some(read)
    }
}

/// Unmap the first `pages` pages of the scrub window. The unmap is inline
/// assembly without `nomem`, so the stores made to them are made before it.
fn unmap_scrub(pages: u64)
{
    if pages > 0
    {
        // SAFETY: the scrub window is memmgr's own zone.
        let _ = unsafe { syscall::mem_unmap(self_aspace(), SCRUB_VA, pages) };
    }
}
