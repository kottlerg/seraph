// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/src/capture.rs

//! `CAPTURE_CHUNKS`: a description of every page of a process's regions,
//! and the content memmgr holds of them copied into Memory caps procmgr's
//! request carries, for `SNAPSHOT` (services/memmgr/docs/ipc-interface.md
//! § Label 31: `CAPTURE_CHUNKS`).
//!
//! memmgr's ledger is the authority on every page of a region it registered,
//! mapped or not: the walk names each region with the arguments that made it,
//! then each of its chunks, a chunk with an entry by what memmgr holds of each
//! of its pages and the chunks with none as one range. memmgr reads each
//! chunk's own pages where it holds them in this turn
//! ([`free_pool::capture_source`]): from its runs when it is resident, being
//! evicted, or raw ([`evict::read_raw`]), and from its store, decoded, when it
//! is compressed ([`evict::decode_store`]). The pages of an attachment of an
//! object that is neither the process's image, which the request names, nor
//! the zero object, it reads from its own view of the object
//! ([`free_pool::MemObject::runs`]). It maps nothing into the process, draws
//! no frame, and evicts nothing, so a capture of a held process neither
//! changes the process's chunks nor depends on where an eviction meanwhile
//! moves them: each chunk's content has one source, read once. A chunk on disk
//! it posts to the swap service, as `MAKE_RESIDENT` does
//! ([`disk::post_want`]), for procmgr to read again once the swap service has
//! restored it.

use free_pool::{
    Attachment, CaptureSource, ChunkState, Evict, NODE_NULL, NodeIdx, RegionNode, Share,
    capture_source, chunk_for,
};
use ipc::memmgr_capture::{
    Chunk, DESCRIPTOR_WORDS, DESCRIPTORS_MAX, Descriptor, REGION_COMMITTED, REGION_NO_EVICT,
    REGION_PRIVATE, REPLY_WORDS, REQUEST_WORDS, Region, RegionClass, dest_spans,
};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::{MSG_CAP_SLOTS_MAX, PAGE_SIZE};

use crate::{
    Answer, MemLedger, SCRUB_VA, cap_badge, delete_caps, disk, evict, ledger_mut, map_self,
    self_aspace,
};

/// Chunks one request supplies at most: a tuning value that bounds the
/// request's turn to as many copies or decodes of a chunk, each at most a
/// chunk's pages, as `MAKE_RESIDENT`'s bound allows restores.
const CAPTURE_SUPPLIED: usize = 4;

/// Regions, chunks and ranges one request visits at most: a tuning value that
/// bounds the turn's walk over chunks that need nothing.
const CAPTURE_VISITS: u32 = 64;

/// Bytes of a page, as a `usize`.
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// Serve a `CAPTURE_CHUNKS` request whose contract caps are `caps`, and
/// delete them before the reply, whatever it is. With `CAPTURE_IMAGE` the
/// last cap is the image's handle, a SEND on `service_ep`, read and deleted
/// first.
pub(crate) fn handle_capture_chunks(
    req: &IpcMessage,
    caps: &[u64],
    answer: &mut Answer,
    procmgr_badge: u64,
    service_ep: u64,
)
{
    let (dest, image) = if req.word(3) & memmgr_labels::CAPTURE_IMAGE == 0
    {
        (caps, Ok(None))
    }
    else
    {
        match caps.split_last()
        {
            Some((&image, dest)) => (
                dest,
                cap_badge(service_ep, image)
                    .map(Some)
                    .ok_or(memmgr_errors::INVALID_ARGUMENT),
            ),
            None => (caps, Err(memmgr_errors::INVALID_ARGUMENT)),
        }
    };
    let served = serve(req, dest, image, procmgr_badge);
    delete_caps(dest);
    match served
    {
        Ok(reply) =>
        {
            answer.set(reply);
        }
        Err(label) => answer.set_status(label),
    }
}

/// The reply to `req`, whose destination caps are `caps` and whose image
/// handle's badge, with `CAPTURE_IMAGE`, is `image` (an error label for a
/// handle that is missing or no SEND on memmgr), or the error label.
fn serve(
    req: &IpcMessage,
    caps: &[u64],
    image: Result<Option<u64>, u64>,
    procmgr_badge: u64,
) -> Result<IpcMessage, u64>
{
    if req.badge != procmgr_badge
    {
        return Err(memmgr_errors::UNAUTHORIZED);
    }
    let l = ledger_mut();
    let (cursor, end, flags) = (req.word(1), req.word(2), req.word(3));
    let rec = l.find(req.word(0)).ok_or(memmgr_errors::INVALID_ARGUMENT)?;
    let known = memmgr_labels::CAPTURE_COUNT | memmgr_labels::CAPTURE_IMAGE;
    if end <= cursor
        || flags & !known != 0
        || !cursor.is_multiple_of(PAGE_SIZE)
        || !end.is_multiple_of(PAGE_SIZE)
        || !at_boundary(l, rec, cursor)
        || !at_boundary(l, rec, end)
    {
        return Err(memmgr_errors::INVALID_ARGUMENT);
    }
    // The image object, by its handle's badge.
    let image = match image?
    {
        None => None,
        Some(badge) => Some(
            Some(badge)
                .filter(|b| b & memmgr_labels::OBJECT_HANDLE_TAG != 0)
                .and_then(|b| l.find_object(b))
                .ok_or(memmgr_errors::INVALID_ARGUMENT)?,
        ),
    };
    if flags & memmgr_labels::CAPTURE_COUNT != 0
    {
        return Ok(count(l, rec, image, cursor, end));
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
    copy(l, rec, image, cursor, end, dest)
}

/// Whether `va` may bound a walk of `rec`: it lies in no region, or is a
/// chunk's base or a region's end.
fn at_boundary(l: &MemLedger, rec: NodeIdx, va: u64) -> bool
{
    l.region_from(rec, va)
        .is_none_or(|(_, node)| va <= node.region.va_base || chunk_for(&node.region, va).0 == va)
}

/// The class of the region `node`, whose attachment is `att`, with the
/// process's image the object `image`.
fn class_of(l: &MemLedger, att: Option<Attachment>, image: Option<NodeIdx>) -> RegionClass
{
    match att
    {
        None => RegionClass::Demand,
        Some(a) if Some(a.object) == image => RegionClass::Image,
        Some(a) if l.zero_frame(a.object).is_some() => RegionClass::Zero,
        Some(_) => RegionClass::Object,
    }
}

/// The descriptor of the region `node` of class `class`.
fn region_of(node: &RegionNode, att: Option<Attachment>, class: RegionClass) -> Region
{
    let mut flags = 0;
    if node.commit != NODE_NULL
    {
        flags |= REGION_COMMITTED;
    }
    if node.region.evict == Evict::Never
    {
        flags |= REGION_NO_EVICT;
    }
    if att.is_some_and(|a| a.share == Share::Private)
    {
        flags |= REGION_PRIVATE;
    }
    Region {
        va: node.region.va_base,
        pages: node.region.len / PAGE_SIZE,
        class,
        prot: node.region.prot,
        flags,
        first_page: att.map_or(0, |a| a.first_page),
    }
}

/// What a walk reaches: a region at its base, a chunk the walk visits, or the
/// whole chunks with no entry from `va`, `pages` pages.
enum Item
{
    Region(Region),
    Chunk(Visit),
    Range
    {
        va: u64,
        pages: u64,
    },
}

/// What a walk's visit of an item has it do next ([`walk`]).
enum Step
{
    /// Go on past the item.
    Next,
    /// Stop at the item, which the next request visits again.
    Before,
    /// Stop past the item.
    After,
}

/// A chunk a walk visits: its region, its base, its pages, its region's
/// class, and for an attachment the object and the object page at the
/// chunk's base.
#[derive(Clone, Copy)]
struct Visit
{
    reg: NodeIdx,
    base: u64,
    pages: u32,
    class: RegionClass,
    object: Option<(NodeIdx, u64)>,
}

/// Visit what `[at, end)` holds of `rec`'s regions, in address order: each
/// region whose base the walk reaches, then the region's chunks from there,
/// each chunk with an entry, and the chunks with none between as one range;
/// in an attachment of an object neither the image `image` nor the zero
/// object, each chunk. Stops after [`CAPTURE_VISITS`] items, never between a
/// region and its first item: `visit` is told `true` for that item, and a
/// [`Step::Before`] at it stops the walk at the region. Returns where the
/// walk stopped: `end` when it is done, else where the next request goes on
/// from, a region's base, below which its item comes first, or a chunk's.
fn walk(
    l: &mut MemLedger,
    rec: NodeIdx,
    image: Option<NodeIdx>,
    mut at: u64,
    end: u64,
    mut visit: impl FnMut(&mut MemLedger, Item, bool) -> Step,
) -> u64
{
    let mut visits = 0u32;
    // The region whose item this walk visited last, before any of its own.
    let mut opened = false;
    while at < end
    {
        if !opened && visits >= CAPTURE_VISITS
        {
            return at;
        }
        let Some((reg, node)) = l.region_from(rec, at)
        else
        {
            return end;
        };
        let base = node.region.va_base;
        if base >= end
        {
            return end;
        }
        let stop = base.saturating_add(node.region.len).min(end);
        let att = l.attachment(reg);
        let class = class_of(l, att, image);
        visits = visits.saturating_add(1);
        if !opened && at <= base
        {
            match visit(l, Item::Region(region_of(&node, att, class)), false)
            {
                Step::Next =>
                {
                    opened = true;
                    at = base;
                    continue;
                }
                Step::Before | Step::After => return base,
            }
        }
        // `at` is a chunk's base inside the region (`at_boundary`).
        let next = if class == RegionClass::Object
        {
            Some(at)
        }
        else
        {
            l.next_chunk_with_entry(reg, at)
        };
        let (item, past) = match next.filter(|&n| n < stop)
        {
            Some(n) if n == at =>
            {
                let (chunk_base, pages) = chunk_for(&node.region, n);
                let object = att.map(|a| {
                    let offset = chunk_base.saturating_sub(base) / PAGE_SIZE;
                    (a.object, a.first_page.saturating_add(offset))
                });
                let chunk_end =
                    chunk_base.saturating_add(u64::from(pages).saturating_mul(PAGE_SIZE));
                let visit = Visit {
                    reg,
                    base: chunk_base,
                    pages,
                    class,
                    object,
                };
                (Item::Chunk(visit), chunk_end.min(stop))
            }
            next =>
            {
                let past = next.unwrap_or(stop);
                let pages = past.saturating_sub(at) / PAGE_SIZE;
                (Item::Range { va: at, pages }, past)
            }
        };
        let first = core::mem::take(&mut opened);
        match visit(l, item, first)
        {
            Step::Next => at = past,
            Step::Before if first => return base,
            Step::Before => return at,
            Step::After => return past,
        }
    }
    end
}

/// The pages of the visited chunk `v` memmgr reads from the object it
/// attaches, bit `i` for page `i`: in an attachment of an object neither the
/// image nor the zero object, each page with no copy of its own,
/// `backed`, that a frame of the object holds.
fn object_pages(l: &MemLedger, v: &Visit, backed: u16) -> u16
{
    let Some((object, first)) = v.object.filter(|_| v.class == RegionClass::Object)
    else
    {
        return 0;
    };
    let mut mask = 0u16;
    for i in 0..v.pages.min(u16::BITS)
    {
        let bit = 1u16 << i;
        if backed & bit == 0
            && l.object_frame(object, first.saturating_add(u64::from(i)))
                .is_some()
        {
            mask |= bit;
        }
    }
    mask
}

/// The reply to a `CAPTURE_COUNT` request over `[cursor, end)` of `rec`,
/// whose image is `image`: the cursor; the pages memmgr would write that no
/// mapping of the process shows, the backed pages of its evicted chunks, lost
/// ones aside, and the pages of its attachments of objects other than the
/// image and the zero object with no copy of their own; and the chunks on
/// disk walked whose slot word memmgr posted to the swap service.
fn count(
    l: &mut MemLedger,
    rec: NodeIdx,
    image: Option<NodeIdx>,
    cursor: u64,
    end: u64,
) -> IpcMessage
{
    let wants = disk::wants_registered();
    let (mut pages, mut posted) = (0u64, 0u64);
    let reached = walk(l, rec, image, cursor, end, |l, item, _| {
        let Item::Chunk(v) = item
        else
        {
            return Step::Next;
        };
        let entry = l.chunk_at(v.reg, v.base);
        let backed = entry.backed();
        let own = u64::from(backed.count_ones());
        match capture_source(&entry, wants)
        {
            CaptureSource::Skip | CaptureSource::Absent =>
            {}
            // Mapped in the process, so procmgr counts it in its listing.
            CaptureSource::Runs if entry.state() == ChunkState::Resident =>
            {}
            CaptureSource::Runs | CaptureSource::Store => pages = pages.saturating_add(own),
            CaptureSource::Want =>
            {
                pages = pages.saturating_add(own);
                if disk::post_want(l, entry.disk())
                {
                    posted = posted.saturating_add(1);
                }
            }
        }
        let from_object = object_pages(l, &v, backed).count_ones();
        pages = pages.saturating_add(u64::from(from_object));
        Step::Next
    });
    IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, reached)
        .word(1, pages)
        .word(2, posted)
        .build()
}

/// Why a copy stopped at a chunk.
enum Stop
{
    /// The destination does not hold the chunk's pages, this many.
    Need(u64),
    /// A destination page could not be mapped.
    Unmapped,
}

/// The reply to a copy request over `[cursor, end)` of `rec`, whose image is
/// `image`, into `dest`, or `OUT_OF_MEMORY_BEST_EFFORT` when a destination
/// page could not be mapped.
fn copy(
    l: &mut MemLedger,
    rec: NodeIdx,
    image: Option<NodeIdx>,
    cursor: u64,
    end: u64,
    mut dest: Dest<'_>,
) -> Result<IpcMessage, u64>
{
    let wants = disk::wants_registered();
    let mut words = [0u64; DESCRIPTORS_MAX * DESCRIPTOR_WORDS];
    let (mut count, mut supplied, mut need, mut unmapped) = (0usize, 0usize, 0u64, false);
    let reached = walk(l, rec, image, cursor, end, |l, item, first| {
        let descriptor = match item
        {
            // A region's item takes its first item's room too, so no reply
            // ends between them.
            Item::Region(_) if count.saturating_add(2) > DESCRIPTORS_MAX => return Step::Before,
            Item::Region(r) => Descriptor::Region(r),
            Item::Range { va, pages } => Descriptor::Range { va, pages },
            Item::Chunk(v) => match chunk(l, rec, &v, wants, &mut dest)
            {
                Ok(c) =>
                {
                    if c.written != 0
                    {
                        supplied = supplied.saturating_add(1);
                    }
                    Descriptor::Chunk(c)
                }
                Err(stop) =>
                {
                    match stop
                    {
                        Stop::Need(pages) => need = pages,
                        Stop::Unmapped => unmapped = true,
                    }
                    // The walk stops at the region, whose item goes too.
                    if first
                    {
                        count = count.saturating_sub(1);
                    }
                    return Step::Before;
                }
            },
        };
        let at = count.saturating_mul(DESCRIPTOR_WORDS);
        if let Some(slot) = words.get_mut(at..at.saturating_add(DESCRIPTOR_WORDS))
        {
            slot.copy_from_slice(&descriptor.encode());
        }
        count = count.saturating_add(1);
        let region = matches!(descriptor, Descriptor::Region(_));
        if !region && (count >= DESCRIPTORS_MAX || supplied >= CAPTURE_SUPPLIED)
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

/// Write what memmgr holds of the visited chunk `v` of `rec` into `dest`
/// after the pages written, and describe it: its own backed pages where it
/// reads them, and in an attachment of an object neither the image nor the
/// zero object its other pages from the object, in page order. A chunk on
/// disk it posts to the swap service, pending, when it can.
fn chunk(
    l: &mut MemLedger,
    rec: NodeIdx,
    v: &Visit,
    wants: free_pool::disk::Registered,
    dest: &mut Dest<'_>,
) -> Result<Chunk, Stop>
{
    let entry = l.chunk_at(v.reg, v.base);
    let backed = entry.backed();
    let source = capture_source(&entry, wants);
    let mut pending = false;
    let own = match source
    {
        CaptureSource::Want =>
        {
            pending = disk::post_want(l, entry.disk());
            0
        }
        CaptureSource::Skip | CaptureSource::Absent => 0,
        CaptureSource::Runs | CaptureSource::Store => backed,
    };
    let objects = object_pages(l, v, backed);
    let count = u64::from((own | objects).count_ones());
    let mut described = Chunk {
        va: v.base,
        pages: u64::from(v.pages),
        backed,
        written: 0,
        pending,
    };
    if count == 0
    {
        return Ok(described);
    }
    if !dest.holds(count)
    {
        return Err(Stop::Need(count));
    }
    let written = dest
        .fill(l, count, |l, dst| {
            let own_bytes = usize::try_from(own.count_ones())
                .unwrap_or(0)
                .saturating_mul(PAGE_BYTES);
            let read = own != 0
                && dst.get_mut(..own_bytes).is_some_and(|own_dst| {
                    if matches!(source, CaptureSource::Runs)
                    {
                        evict::read_raw(l, rec, v.reg, v.base, own_dst).is_some()
                    }
                    else
                    {
                        evict::decode_store(l, entry, own_dst)
                    }
                });
            let own = if read { own } else { 0 };
            place(l, v, dst, own, objects);
            own | objects
        })
        .ok_or(Stop::Unmapped)?;
    dest.used = dest.used.saturating_add(u64::from(written.count_ones()));
    described.written = written;
    Ok(described)
}

/// Put the pages of the visited chunk `v` that `own | objects` names into
/// `dst` in page order: the `own` pages, read into `dst`'s first pages in
/// page order, moved up to their places, and each `objects` page copied from
/// memmgr's own view of the object.
///
/// It fills `dst` from its last place down: a moved page's place is never
/// below its read place, and every page still to move lies below the place
/// being filled, so no page is overwritten before it moves.
fn place(l: &MemLedger, v: &Visit, dst: &mut [u8], own: u16, objects: u16)
{
    let written = own | objects;
    let mut read = own.count_ones() as usize;
    let mut slot = written.count_ones() as usize;
    for i in (0..v.pages.min(u16::BITS)).rev()
    {
        let bit = 1u16 << i;
        if written & bit == 0
        {
            continue;
        }
        slot = slot.saturating_sub(1);
        let to = slot.saturating_mul(PAGE_BYTES);
        if own & bit != 0
        {
            read = read.saturating_sub(1);
            let from = read.saturating_mul(PAGE_BYTES);
            if from != to
            {
                dst.copy_within(from..from.saturating_add(PAGE_BYTES), to);
            }
            continue;
        }
        let Some((object, first)) = v.object
        else
        {
            continue;
        };
        let Some(page) = dst.get_mut(to..to.saturating_add(PAGE_BYTES))
        else
        {
            continue;
        };
        if let Some((frame, off)) = l.object_frame(object, first.saturating_add(u64::from(i)))
        {
            let src = frame.va.saturating_add(off.saturating_mul(PAGE_SIZE));
            // SAFETY: `frame` is a frame of the object the region attaches,
            // whose `va` is its first page in memmgr's own read-only view and
            // `off` is below its page count, so `src` is a page of the view,
            // mapped until the object retires, which no attached object does
            // this turn; the object is sealed, so nothing writes it, and
            // `page` is a page of the destination, apart from the view.
            unsafe {
                core::ptr::copy_nonoverlapping(src as *const u8, page.as_mut_ptr(), PAGE_BYTES);
            }
        }
    }
}

/// A request's destination: its caps, the page offset into the first, the
/// pages each gives, and the pages written so far.
pub(crate) struct Dest<'a>
{
    pub(crate) caps: &'a [u64],
    pub(crate) offset: u64,
    pub(crate) pages: &'a [u64],
    pub(crate) used: u64,
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
    pub(crate) fn fill<R>(
        &self,
        l: &mut MemLedger,
        count: u64,
        read: impl FnOnce(&mut MemLedger, &mut [u8]) -> R,
    ) -> Option<R>
    {
        let spans = dest_spans(self.offset, self.pages, self.used, count)?;
        let mut mapped = 0u64;
        for (cap, offset, pages) in spans
        {
            let va = SCRUB_VA.saturating_add(mapped.saturating_mul(PAGE_SIZE));
            let cap = self.caps.get(cap).copied().unwrap_or(0);
            // SAFETY: the scrub window is memmgr's own zone, which every use
            // leaves unmapped, and the `count` pages, at most a chunk's here
            // and at most `OBJECT_READ_PAGES` for `OBJECT_READ`, lie in it.
            if unsafe { map_self(l, cap, va, offset, pages) }.is_err()
            {
                // A failed map leaves none of its span mapped: unmap the spans
                // before it.
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
