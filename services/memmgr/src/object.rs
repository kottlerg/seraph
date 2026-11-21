// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/src/object.rs

//! The memory-object labels a checkpoint and its restore use
//! (docs/checkpoint-restore.md § Restore creation): `OBJECT_READ` copies an
//! object's pages into Memory caps its handle's holder presents and reports
//! the object's checkpoint mark, `FILL_REGION` backs pages of the caller's
//! own regions with copies of an object's pages as a write fault backs a
//! page, and procmgr's `MARK_CHECKPOINT` sets the mark
//! (services/memmgr/docs/ipc-interface.md § Label 35 to § Label 37). Each
//! reads the object's pages from memmgr's own read-only view of it
//! ([`free_pool::MemObject::runs`]), which stays mapped while the turn runs.

use free_pool::{FILL_CHUNKS, FillChunk, FillPath, NodeIdx, chunk_for, fill_chunks, fill_path};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::{MSG_CAP_SLOTS_MAX, PAGE_SIZE};

use crate::capture::Dest;
use crate::{
    FaultDecline, MemLedger, SCRUB_VA, SCRUB_WINDOW_PAGES, back_span_with, cap_badge, delete_caps,
    ensure_committed_slots, fault_target, ledger_mut, map_self, release_unmapped_chunk,
    reply_label, self_aspace,
};

const _: () = assert!(FILL_CHUNKS as u64 == memmgr_labels::FILL_CHUNKS);
// An `OBJECT_READ` maps its destination pages at the scrub window at once.
const _: () = assert!(memmgr_labels::OBJECT_READ_PAGES <= SCRUB_WINDOW_PAGES);

/// Bytes of a page, as a `usize`.
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// Words of an `OBJECT_READ` request before the destination page counts.
const READ_WORDS: usize = 2;

/// `OBJECT_READ`, on an object handle: copy the object's pages from
/// `data[0]` on into the Memory caps `caps`, at most
/// `memmgr_labels::OBJECT_READ_PAGES`, and report the object's pages and
/// whether it carries the checkpoint mark. Deletes `caps` before the reply,
/// whatever it is.
pub(crate) fn handle_object_read(req: &IpcMessage, caps: &[u64], ipc_buf: *mut u64)
{
    let served = read(req, caps);
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

/// The reply to the `OBJECT_READ` `req`, whose destination caps are
/// `caps`, or its error label.
fn read(req: &IpcMessage, caps: &[u64]) -> Result<IpcMessage, u64>
{
    let l = ledger_mut();
    let obj = l
        .find_object(req.badge)
        .ok_or(memmgr_errors::INVALID_ARGUMENT)?;
    let marked = l.object(obj).is_some_and(|o| o.checkpoint);
    let total = l.object_pages(obj);
    let first = req.word(0);
    let short = !caps.is_empty() && req.word_count() < READ_WORDS.saturating_add(caps.len());
    if first > total || short
    {
        return Err(memmgr_errors::INVALID_ARGUMENT);
    }
    let mut pages = [0u64; MSG_CAP_SLOTS_MAX];
    for (i, slot) in pages.iter_mut().enumerate().take(caps.len())
    {
        *slot = req.word(READ_WORDS.saturating_add(i));
    }
    let pages = pages.get(..caps.len()).unwrap_or(&[]);
    let held = pages.iter().fold(0u64, |n, &p| n.saturating_add(p));
    let count = held
        .min(total.saturating_sub(first))
        .min(memmgr_labels::OBJECT_READ_PAGES);
    if count != 0
    {
        let dest = Dest {
            caps,
            offset: req.word(1),
            pages,
            used: 0,
        };
        dest.fill(l, count, |l, dst| copy_pages(l, obj, first, dst))
            .ok_or(memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT)?;
    }
    let flags = if marked
    {
        memmgr_labels::OBJECT_CHECKPOINT
    }
    else
    {
        0
    };
    Ok(IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, count)
        .word(1, flags)
        .word(2, total)
        .build())
}

/// Copy pages of the object `obj` from its page `first` on into `dst`, as
/// many as `dst` holds whole, from memmgr's own view of its frames.
fn copy_pages(l: &MemLedger, obj: NodeIdx, first: u64, dst: &mut [u8])
{
    for (i, page) in dst.as_chunks_mut::<PAGE_BYTES>().0.iter_mut().enumerate()
    {
        let at = first.saturating_add(i as u64);
        let Some((frame, off)) = l.object_frame(obj, at)
        else
        {
            page.fill(0);
            continue;
        };
        let src = frame.va.saturating_add(off.saturating_mul(PAGE_SIZE));
        // SAFETY: `frame` is a frame of the live object `obj`, whose `va` is
        // its first page in memmgr's own read-only view and `off` is below
        // its page count, so `src` is a page of the view, mapped until the
        // object retires, which no object does inside a turn; the object is
        // sealed, so nothing writes it, and `page` is a page of the
        // destination, apart from the view.
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, page.as_mut_ptr(), PAGE_BYTES);
        }
    }
}

/// `FILL_REGION`: back the pages the request's masks name in chunks of the
/// caller's own regions with copies of the pages of the object whose handle
/// is `caps[0]`, a SEND on `service_ep` read and deleted first, and reply
/// the pages backed.
pub(crate) fn handle_fill_region(req: &IpcMessage, caps: &[u64], ipc_buf: *mut u64, service_ep: u64)
{
    let handle = caps.first().and_then(|&cap| cap_badge(service_ep, cap));
    match fill_region(req, handle)
    {
        Ok(pages) =>
        {
            let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
                .word(0, pages)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        Err(label) => reply_label(ipc_buf, label),
    }
}

/// A chunk of a `FILL_REGION` request, checked against the caller's
/// region that holds it.
struct Filled
{
    chunk: FillChunk,
    reg: NodeIdx,
    region: free_pool::DemandRegion,
    zero: bool,
}

/// Serve the `FILL_REGION` `req`, whose object handle's badge is `handle`:
/// check every chunk first, then back each named page that holds no data
/// ([`fill_path`]); returns the pages backed, or the error label, the pages
/// backed before a failure staying backed, so a repeat backs the rest.
fn fill_region(req: &IpcMessage, handle: Option<u64>) -> Result<u64, u64>
{
    let l = ledger_mut();
    let rec = l.find(req.badge).ok_or(memmgr_errors::INVALID_ARGUMENT)?;
    let obj = handle
        .filter(|b| b & memmgr_labels::OBJECT_HANDLE_TAG != 0)
        .and_then(|b| l.find_object(b))
        .ok_or(memmgr_errors::INVALID_ARGUMENT)?;
    let mut words = [0u64; FILL_CHUNKS * 2];
    let sent = req.word_count().saturating_sub(2).min(words.len());
    for (i, word) in words.iter_mut().enumerate().take(sent)
    {
        *word = req.word(i.saturating_add(2));
    }
    let first = req.word(0);
    let (chunks, taken) = fill_chunks(first, req.word(1), words.get(..sent).unwrap_or(&[]))
        .ok_or(memmgr_errors::INVALID_ARGUMENT)?;
    let n = usize::try_from(req.word(1)).unwrap_or(0);
    let aspace_cap = l.aspace_cap(rec);
    if aspace_cap == 0 || first.saturating_add(taken) > l.object_pages(obj)
    {
        return Err(memmgr_errors::INVALID_ARGUMENT);
    }
    let mut checked: [Option<Filled>; FILL_CHUNKS] = [None, None, None, None];
    for (slot, chunk) in checked.iter_mut().zip(chunks.iter().take(n))
    {
        let f = check(l, rec, *chunk).ok_or(memmgr_errors::INVALID_ARGUMENT)?;
        if path(l, &f) == FillPath::Refuse
        {
            return Err(memmgr_errors::INVALID_ARGUMENT);
        }
        *slot = Some(f);
    }
    let mut backed = 0u64;
    for f in checked.iter().flatten()
    {
        match path(l, f)
        {
            FillPath::Back =>
            {}
            FillPath::Skip => continue,
            FillPath::Refuse => return Err(memmgr_errors::INVALID_ARGUMENT),
        }
        for (start, end, object_page) in f.chunk.runs()
        {
            let va = f
                .chunk
                .va
                .saturating_add(u64::from(start).saturating_mul(PAGE_SIZE));
            let end = f
                .chunk
                .va
                .saturating_add(u64::from(end).saturating_mul(PAGE_SIZE));
            backed =
                backed.saturating_add(fill_run(l, rec, f, aspace_cap, obj, va, end, object_page)?);
        }
    }
    Ok(backed)
}

/// What the request does with the chunk `f`, by its entry now.
fn path(l: &MemLedger, f: &Filled) -> FillPath
{
    let entry = l.chunk_at(f.reg, f.chunk.va);
    fill_path(entry.state(), entry.backed(), f.chunk.mask)
}

/// `chunk` checked against the region of `rec` holding it: a demand region
/// or a private attachment of the zero object, `chunk.va` a chunk's base in
/// it, and the mask inside the chunk.
fn check(l: &MemLedger, rec: NodeIdx, chunk: FillChunk) -> Option<Filled>
{
    let (reg, region) = l.region_for(rec, chunk.va)?;
    let (base, pages) = chunk_for(&region, chunk.va);
    if base != chunk.va || u32::from(chunk.mask).checked_shr(pages).unwrap_or(0) != 0
    {
        return None;
    }
    let zero = match l.attachment(reg)
    {
        None => false,
        Some(att)
            if att.share == free_pool::Share::Private && l.zero_frame(att.object).is_some() =>
        {
            true
        }
        Some(_) => return None,
    };
    Some(Filled {
        chunk,
        reg,
        region,
        zero,
    })
}

/// Back the pages `[va, end)` of the chunk `f` of `rec`, whose delegated
/// address space is `aspace_cap`, with copies of the pages of `obj` from
/// `object_page` on, as write faults there back them: each run the fault's
/// selection gives ([`back_span_with`]) copied, mapped and recorded on the
/// chunk. A private attachment of the zero object has its span's zero-frame
/// leaves unmapped first, as its write fault does. Returns the pages backed.
///
/// # Errors
/// The label of the fault's decline ([`decline_label`]).
#[expect(
    clippy::too_many_arguments,
    reason = "the run's process, chunk, address space, object and bounds are each a separate fact the fill needs"
)]
fn fill_run(
    l: &mut MemLedger,
    rec: NodeIdx,
    f: &Filled,
    aspace_cap: u64,
    obj: NodeIdx,
    va: u64,
    end: u64,
    object_page: u64,
) -> Result<u64, u64>
{
    let mut at = va;
    let mut backed = 0u64;
    while at < end
    {
        let Some((mut target, _)) =
            fault_target(l, rec, f.reg, &f.region, at, aspace_cap).map_err(decline_label)?
        else
        {
            // The page holds data already, from a fault or an earlier
            // request: it is left as it is.
            at = at.saturating_add(PAGE_SIZE);
            continue;
        };
        target.span = (target.span.0.max(at), target.span.1.min(end));
        let pages = target.span.1.saturating_sub(target.span.0) / PAGE_SIZE;
        // At most a chunk's pages.
        let span_pages = u32::try_from(pages).unwrap_or(1);
        if f.zero
        {
            // SAFETY: `aspace_cap` is a client address space procmgr delegated
            // (`DELEGATE_ASPACE`), never memmgr's own, so the unmap changes
            // nothing memmgr runs on.
            unsafe { syscall::mem_unmap(aspace_cap, target.span.0, pages) }
                .map_err(|_| memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT)?;
        }
        let frame = back_span_with(l, &target, span_pages, |l, cap, run_va, run_pages| {
            let offset = run_va.saturating_sub(va) / PAGE_SIZE;
            copy_run(l, obj, object_page.saturating_add(offset), cap, run_pages)
        })
        .map_err(decline_label)?;
        if !ensure_committed_slots(l, target.held, target.committed)
            || l.back_chunk(rec, f.reg, frame).is_err()
        {
            release_unmapped_chunk(l, rec, aspace_cap, frame);
            return Err(memmgr_errors::QUOTA);
        }
        let run = u64::from(frame.page_count);
        backed = backed.saturating_add(run);
        at = frame.va.saturating_add(run.saturating_mul(PAGE_SIZE));
    }
    Ok(backed)
}

/// Copy the `pages` pages of `obj` from its page `first` into the run of the
/// Memory cap `cap`, mapped read-write at [`SCRUB_VA`] and unmapped again
/// after the copy, as every pass through the window leaves it.
fn copy_run(l: &mut MemLedger, obj: NodeIdx, first: u64, cap: u64, pages: u32) -> Result<(), i64>
{
    let pages = u64::from(pages);
    // SAFETY: the scrub window is memmgr's own zone, which every pass leaves
    // unmapped, and a run of at most a chunk's pages lies in it.
    if let Err(e) = unsafe { map_self(l, cap, SCRUB_VA, 0, pages) }
    {
        // A map that ran out of page tables part way left the pages before
        // the failing one mapped: unmap them, so the run that returns to the
        // pool is mapped nowhere and the window is left unmapped.
        // SAFETY: as for the unmap below.
        let _ = unsafe { syscall::mem_unmap(self_aspace(), SCRUB_VA, pages) };
        return Err(e);
    }
    let len = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
    // SAFETY: the window's `pages` pages are mapped read-write above to the
    // run, which nothing else maps yet, and the slice is not used past the
    // unmap below.
    let dst = unsafe { core::slice::from_raw_parts_mut(SCRUB_VA as *mut u8, len) };
    copy_pages(l, obj, first, dst);
    // SAFETY: the span is the window's pages mapped above. The unmap is inline
    // assembly without `nomem`, so the stores are made before it.
    unsafe { syscall::mem_unmap(self_aspace(), SCRUB_VA, pages) }
}

/// The error label of a `FILL_REGION` whose fault would be declined for
/// `reason`: `LIMIT` at a budget max, `QUOTA` when memmgr's metadata is full,
/// and `OUT_OF_MEMORY_BEST_EFFORT` for every other.
fn decline_label((reason, _): (FaultDecline, u64)) -> u64
{
    match reason
    {
        FaultDecline::BudgetLimit => memmgr_errors::LIMIT,
        FaultDecline::NoArenaSlot | FaultDecline::FrameRecord => memmgr_errors::QUOTA,
        FaultDecline::NoFreePage
        | FaultDecline::MapFailed
        | FaultDecline::CommitOverrun
        | FaultDecline::NotVm
        | FaultDecline::UnknownProcess
        | FaultDecline::NoRegion
        | FaultDecline::AccessRefused
        | FaultDecline::NoAspace
        | FaultDecline::OnDiskChunk => memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT,
    }
}

/// `MARK_CHECKPOINT`, procmgr only: mark the object whose handle is
/// `caps[0]` as a checkpoint when the account `caps[1]` is a SEND on memmgr's
/// endpoint `service_ep` whose badge names the record that sealed it. Both
/// caps are read and deleted first.
pub(crate) fn handle_mark_checkpoint(
    req: &IpcMessage,
    caps: &[u64],
    ipc_buf: *mut u64,
    procmgr_badge: u64,
    service_ep: u64,
)
{
    let handle = caps.first().and_then(|&cap| cap_badge(service_ep, cap));
    let account = caps.get(1).and_then(|&cap| cap_badge(service_ep, cap));
    if req.badge != procmgr_badge
    {
        reply_label(ipc_buf, memmgr_errors::UNAUTHORIZED);
        return;
    }
    let l = ledger_mut();
    let obj = handle
        .filter(|b| b & memmgr_labels::OBJECT_HANDLE_TAG != 0)
        .and_then(|b| l.find_object(b));
    let marked = match (obj, account)
    {
        (Some(obj), Some(account)) => l.mark_checkpoint(obj, account),
        _ => false,
    };
    let label = if marked
    {
        memmgr_errors::SUCCESS
    }
    else
    {
        memmgr_errors::INVALID_ARGUMENT
    };
    reply_label(ipc_buf, label);
}
