// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/snapshot.rs

//! `SNAPSHOT`: capture a live process's mapped pages into a memory object
//! charged to the snapshotter (services/procmgr/docs/ipc-interface.md
//! § Label 33: `SNAPSHOT`).
//!
//! Before the hold, procmgr has memmgr post the target's chunks on disk to the
//! swap service and count its evicted pages (`memmgr_labels::CAPTURE_COUNT`),
//! waits a bounded time while the swap service restores them, lists the
//! target's mapped pages, and requests frames for both on the snapshotter's
//! account. It then holds the target's address space (`SYS_ASPACE_HOLD`), so
//! no thread of it runs, registered or not, and lists the pages again. memmgr
//! writes the content of every demand chunk of the target into the frames
//! (`memmgr_labels::CAPTURE_CHUNKS`), from wherever it holds each chunk in that
//! turn, so no eviction meanwhile can move a chunk's content out of the
//! capture; a chunk still on disk it posts to the swap service, and procmgr
//! asks for it again after a pause, waiting a bounded time while the swap
//! service restores it. procmgr copies every other listed page with
//! `SYS_THREAD_READ_MEM` into the next frames and releases the space. After
//! the release it builds the layout (`process_table::snapshot::layout`),
//! writes it into frames of its own grant, and seals the layout and the data,
//! in that order, into one memory object on the account.
//!
//! The account is the snapshotter's own memmgr SEND, which the request
//! carries: procmgr cannot tell that it names memmgr, so every call on it
//! is bounded ([`ACCOUNT_CALL_TIMEOUT_MS`]), and the first failure fails the
//! capture, releasing the hold and every grant taken. Under the hold procmgr
//! calls only memmgr, on its own endpoint and on the account, waits on the
//! swap service at most [`CAPTURE_STALL_PAUSES`] pauses in a row that restore
//! nothing, and writes no log line, so a held target that serves procmgr
//! (logd among them) or the swap service cannot stall the capture.

use crate::process::CapGuard;
use ipc::memmgr_capture::{
    DESCRIPTOR_WORDS, DESCRIPTORS_MAX, Descriptor, REPLY_WORDS, REQUEST_WORDS, Supply,
};
use ipc::procmgr_snapshot::{Header, SNAPSHOT_COMPLETE};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use process_table::snapshot::{Chunk, Layout, Listing, copied_pages, layout, outside};
use std::collections::TryReserveError;
use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use std::time::Duration;
use syscall_abi::{
    MAX_PAGE_RUNS, MAX_THREAD_MEM_COPY, MSG_CAP_SLOTS_MAX, PAGE_RUN_NO_COPY, PAGE_SIZE, PageRun,
    SyscallError,
};

/// How long procmgr waits, at most, on each call it makes on the
/// snapshotter's account (`REQUEST_MEMORY_CAPS`, `RELEASE_MEMORY_CAPS`,
/// `SEAL_OBJECT`, `OBJECT_RELEASE`): 10 s, as for a caller's file cap. The
/// account is a cap the caller presents, so a server behind it that never
/// answers fails the capture, and releases a held target, once the bound
/// passes, instead of holding the request worker and the target for good.
pub const ACCOUNT_CALL_TIMEOUT_MS: u32 = 10_000;

/// Pages of procmgr's address space through which the copy maps the data
/// frames, a window at a time: 64, 256 KiB. It bounds procmgr's own
/// reservation and page tables for a capture of any size.
const WINDOW_PAGES: u64 = 64;

// `SYS_THREAD_READ_MEM` copies at most `MAX_THREAD_MEM_COPY` bytes a call,
// and the copy reads a page a call.
const _: () = assert!(MAX_THREAD_MEM_COPY as u64 == PAGE_SIZE);

/// Region ids one `RELEASE_MEMORY_CAPS` names: every data word after the count.
const RELEASE_IDS_PER_CALL: usize = syscall_abi::MSG_DATA_WORDS_MAX - 1;

/// Milliseconds procmgr pauses before it asks memmgr again for the target's
/// chunks on disk, whose slot words memmgr posted to the swap service: a
/// tuning value of the order of a swap slot's read and restore.
const CAPTURE_PAUSE_MS: u64 = 10;

/// Pauses in a row that restore no chunk on disk after which procmgr waits
/// no longer for the swap service, the chunks still on disk then absent: 100,
/// a second of [`CAPTURE_PAUSE_MS`]. It bounds how long a swap service that
/// does not answer, or is the held target or waits on it, holds a capture,
/// before the hold and under it.
const CAPTURE_STALL_PAUSES: u32 = 100;

/// What a capture needs of procmgr.
pub struct Context
{
    /// procmgr's own address space, where the frames are mapped to be filled.
    pub self_aspace: u64,
    /// procmgr's SEND on memmgr, for `CAPTURE_CHUNKS`.
    pub memmgr_ep: u64,
    /// The calling worker's IPC buffer.
    pub ipc_buf: *mut u64,
}

/// The target of a capture, its caps derived under the table lock so a
/// teardown meanwhile leaves caps that name the same objects, or that the
/// kernel refuses, never a slot another cap took.
pub struct Target
{
    /// The target's `AddressSpace`, with the Control right the hold takes.
    pub aspace: CapGuard,
    /// The target's main thread, through which its space is listed and read.
    pub thread: CapGuard,
    /// The target's memmgr badge, which names it to `CAPTURE_CHUNKS`.
    pub memmgr_badge: u64,
}

/// A capture's object: its handle, its pages, and whether no run is absent.
pub struct Captured
{
    /// The object handle, in procmgr's `CSpace`.
    pub handle: u64,
    /// The object's pages.
    pub pages: u64,
    /// No run of the layout is absent.
    pub complete: bool,
}

/// Capture `target` into a memory object sealed on `account`, the
/// snapshotter's memmgr SEND, which stays the caller's.
///
/// # Errors
/// `SPACE_HELD` when the target's space is held already or the hold was
/// interrupted; `INVALID_BADGE` when the target ended before or during the
/// capture; `OUT_OF_MEMORY` when the account refused or failed a call,
/// granted a run procmgr refuses, or the object would take more grants than
/// one seal names, when memmgr failed a request, or when procmgr's heap or
/// address space refused the capture's own memory.
pub fn capture(ctx: &Context, target: &Target, account: u64) -> Result<Captured, u64>
{
    let account = Account {
        cap: account,
        ipc_buf: ctx.ipc_buf,
    };
    let top = syscall::user_va_top().map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    // Before the hold: the chunks on disk asked for and waited on, and the
    // frames for what is mapped and what memmgr holds evicted then. Each
    // chunk is read under the hold, wherever memmgr holds it then.
    let evicted = survey(ctx, target.memmgr_badge, top)?;
    let mut data = Grants::new(&account);
    data.cover(
        list(target.thread.cap(), top)?
            .copied_pages()
            .saturating_add(evicted),
    )?;
    let mut window = Window::new(ctx.self_aspace)?;

    let hold = Hold::take(target.aspace.cap())?;
    let listing = list(target.thread.cap(), top)?;
    let mut chunks = Chunks::default();
    chunks.walk(ctx, target.memmgr_badge, (0, top), &mut data)?;
    chunks.await_disk(ctx, target.memmgr_badge, &mut data)?;
    let outside = outside(listing.runs(), &chunks.list).map_err(runs_code)?;
    data.cover(chunks.filled.saturating_add(copied_pages(&outside)))?;
    let failed = copy(
        target.thread.cap(),
        &outside,
        chunks.filled,
        &data,
        &mut window,
    )?;
    drop(hold);
    drop(window);

    let layout = layout(&outside, chunks.filled, &failed, &chunks.list).map_err(runs_code)?;
    data.keep(layout.data_pages);
    let mut head = Grants::new(&account);
    head.cover(layout.layout_pages)?;
    write_layout(ctx.self_aspace, &head, &layout)?;
    let (handle, pages) = seal(&account, head, data)?;
    Ok(Captured {
        handle,
        pages,
        complete: layout.complete,
    })
}

/// The reply code of runs procmgr's heap refused.
fn runs_code(_: TryReserveError) -> u64
{
    procmgr_errors::OUT_OF_MEMORY
}

/// The reply code of a syscall on the target's caps that failed with `err`:
/// a cap the kernel refuses, or a thread or space that ended, means the
/// target ended (`INVALID_BADGE`); anything else, `OUT_OF_MEMORY`.
fn target_code(err: i64) -> u64
{
    if err == SyscallError::InvalidCapability as i64 || err == SyscallError::InvalidState as i64
    {
        procmgr_errors::INVALID_BADGE
    }
    else
    {
        procmgr_errors::OUT_OF_MEMORY
    }
}

/// Call memmgr with `msg` on procmgr's own endpoint: its reply when it
/// succeeded; `INVALID_BADGE` when memmgr knows the target's badge no more,
/// the target torn down; else `OUT_OF_MEMORY`.
fn memmgr_call(ctx: &Context, msg: &IpcMessage) -> Result<IpcMessage, u64>
{
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    match unsafe { ipc::ipc_call(ctx.memmgr_ep, msg, ctx.ipc_buf) }
    {
        Ok(reply) if reply.label == memmgr_errors::SUCCESS => Ok(reply),
        Ok(reply) if reply.label == memmgr_errors::INVALID_ARGUMENT =>
        {
            Err(procmgr_errors::INVALID_BADGE)
        }
        _ => Err(procmgr_errors::OUT_OF_MEMORY),
    }
}

/// Have memmgr post every chunk of the target on disk to the swap service and
/// count its evicted pages (`CAPTURE_COUNT`), over the user half up to `top`,
/// again after each pause of [`CAPTURE_PAUSE_MS`] while chunks on disk
/// remain, until none does or [`CAPTURE_STALL_PAUSES`] pauses in a row leave
/// no fewer. Returns the backed pages of the evicted chunks memmgr counted
/// last, those on disk among them.
fn survey(ctx: &Context, memmgr_badge: u64, top: u64) -> Result<u64, u64>
{
    let (mut fewest, mut stalled) = (u64::MAX, 0u32);
    loop
    {
        let (evicted, on_disk) = count(ctx, memmgr_badge, top)?;
        if on_disk < fewest
        {
            fewest = on_disk;
            stalled = 0;
        }
        else
        {
            stalled = stalled.saturating_add(1);
        }
        if on_disk == 0 || stalled >= CAPTURE_STALL_PAUSES
        {
            return Ok(evicted);
        }
        std::thread::sleep(Duration::from_millis(CAPTURE_PAUSE_MS));
    }
}

/// One `CAPTURE_COUNT` pass over the user half up to `top`: the backed pages
/// of the target's evicted chunks, and its chunks on disk memmgr posted.
fn count(ctx: &Context, memmgr_badge: u64, top: u64) -> Result<(u64, u64), u64>
{
    let (mut evicted, mut on_disk, mut at) = (0u64, 0u64, 0u64);
    while at < top
    {
        let msg = IpcMessage::builder(memmgr_labels::CAPTURE_CHUNKS)
            .word(0, memmgr_badge)
            .word(1, at)
            .word(2, top)
            .word(3, memmgr_labels::CAPTURE_COUNT)
            .build();
        let reply = memmgr_call(ctx, &msg)?;
        evicted = evicted.saturating_add(reply.word(1));
        on_disk = on_disk.saturating_add(reply.word(2));
        // memmgr moves forward on every reply; one that did not would loop.
        if reply.word(0) <= at
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        at = reply.word(0);
    }
    Ok((evicted, on_disk))
}

/// The target's demand chunks memmgr reached under the hold, in address
/// order, and the data pages before the next chunk's: those the supplied
/// chunks took, and any passed over because the grants that held them could
/// not hold a chunk in one request.
#[derive(Default)]
struct Chunks
{
    list: Vec<Chunk>,
    filled: u64,
}

impl Chunks
{
    /// Have memmgr supply every chunk of `range` into the data frames after
    /// those filled (`CAPTURE_CHUNKS`), covering more frames on the account
    /// when memmgr needs them, and add each chunk it names.
    ///
    /// # Errors
    /// As [`memmgr_call`]; `OUT_OF_MEMORY` when the account refuses the
    /// frames, procmgr's heap refuses the chunks, or memmgr's reply names a
    /// chunk out of order, of no descriptor, or pages it did not write.
    fn walk(
        &mut self,
        ctx: &Context,
        memmgr_badge: u64,
        range: (u64, u64),
        data: &mut Grants<'_>,
    ) -> Result<(), u64>
    {
        let (mut at, end) = range;
        while at < end
        {
            let reply = self.request(ctx, memmgr_badge, (at, end), data)?;
            let (next, used, need) = (reply.word(0), reply.word(1), reply.word(2));
            let count = usize::try_from(reply.word(3)).unwrap_or(usize::MAX);
            if count > DESCRIPTORS_MAX
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            self.list
                .try_reserve(count)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            let mut page = self.filled;
            for i in 0..count
            {
                let word = REPLY_WORDS.saturating_add(i.saturating_mul(DESCRIPTOR_WORDS));
                let d = Descriptor::decode([reply.word(word), reply.word(word.saturating_add(1))])
                    .filter(|d| d.va >= self.list.last().map_or(at, Chunk::end))
                    .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
                self.list.push(Chunk::new(&d, page));
                if d.supply == Supply::Supplied
                {
                    page = page.saturating_add(d.backed_pages());
                }
            }
            if page != self.filled.saturating_add(used)
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            self.filled = page;
            if need > 0
            {
                // memmgr stopped at a chunk that needs more frames than the
                // caps it was given hold. One that stopped with room for it,
                // having written nothing, would loop; after chunks it wrote,
                // the next request's caps start further on.
                if used == 0 && data.holds(self.filled, need)
                {
                    return Err(procmgr_errors::OUT_OF_MEMORY);
                }
                self.make_room(need, data)?;
            }
            else if next <= at
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            at = next;
        }
        Ok(())
    }

    /// Cover frames on the account, and pass over the data pages up to the
    /// next grant's first while needed, until the grants one request carries
    /// from the next data page hold `need` pages: a request carries at most
    /// as many caps as a message does, so a chunk can need more pages than the
    /// grants from a page in a short grant hold, its rest passed over and left
    /// unused in the object.
    ///
    /// # Errors
    /// `OUT_OF_MEMORY` when the account refuses the frames, or the grants
    /// would be more than one seal names.
    fn make_room(&mut self, need: u64, data: &mut Grants<'_>) -> Result<(), u64>
    {
        data.cover(self.filled.saturating_add(need))?;
        while !data.holds(self.filled, need)
        {
            self.filled = data.next_grant(self.filled);
            data.cover(self.filled.saturating_add(need))?;
        }
        Ok(())
    }

    /// One `CAPTURE_CHUNKS` request over `[at, end)`, carrying caps derived
    /// from the grants that hold the data pages after those filled, at most
    /// as many as a message carries, and memmgr's reply.
    fn request(
        &self,
        ctx: &Context,
        memmgr_badge: u64,
        (at, end): (u64, u64),
        data: &Grants<'_>,
    ) -> Result<IpcMessage, u64>
    {
        let (grants, offset) = data.at_page(self.filled);
        let mut msg = IpcMessage::builder(memmgr_labels::CAPTURE_CHUNKS)
            .word(0, memmgr_badge)
            .word(1, at)
            .word(2, end)
            .word(3, 0)
            .word(4, offset);
        let mut derived = [0u64; MSG_CAP_SLOTS_MAX];
        for (i, (grant, slot)) in grants.iter().zip(derived.iter_mut()).enumerate()
        {
            let Ok(cap) = syscall::cap_derive(grant.cap, syscall::RIGHTS_MEM_MAP_RW)
            else
            {
                crate::release_caps(&derived);
                return Err(procmgr_errors::OUT_OF_MEMORY);
            };
            *slot = cap;
            let pages = if i == 0
            {
                grant.pages.saturating_sub(offset)
            }
            else
            {
                grant.pages
            };
            msg = msg.word(REQUEST_WORDS.saturating_add(i), pages).cap(cap);
        }
        let reply = memmgr_call(ctx, &msg.build());
        if reply.is_err()
        {
            // A call refused before memmgr received it leaves the caps
            // procmgr's; a handle the call moved is stale, and its delete
            // fails harmlessly.
            crate::release_caps(&derived);
        }
        reply
    }

    /// Ask memmgr again, after each pause of [`CAPTURE_PAUSE_MS`], for each
    /// chunk on disk it posted to the swap service, until none is left or
    /// [`CAPTURE_STALL_PAUSES`] pauses in a row restore none; one still on disk
    /// then is absent.
    fn await_disk(
        &mut self,
        ctx: &Context,
        memmgr_badge: u64,
        data: &mut Grants<'_>,
    ) -> Result<(), u64>
    {
        let mut stalled = 0u32;
        while stalled < CAPTURE_STALL_PAUSES
            && self.list.iter().any(|c| c.supply == Supply::Pending)
        {
            std::thread::sleep(Duration::from_millis(CAPTURE_PAUSE_MS));
            let mut restored = false;
            for i in 0..self.list.len()
            {
                let Some(chunk) = self
                    .list
                    .get(i)
                    .copied()
                    .filter(|c| c.supply == Supply::Pending)
                else
                {
                    continue;
                };
                let mut again = Self {
                    list: Vec::new(),
                    filled: self.filled,
                };
                again.walk(ctx, memmgr_badge, (chunk.va, chunk.end()), data)?;
                self.filled = again.filled;
                // A chunk memmgr names no more holds nothing to capture.
                let now = again
                    .list
                    .into_iter()
                    .find(|c| c.va == chunk.va)
                    .unwrap_or(Chunk {
                        backed: 0,
                        supply: Supply::Absent,
                        ..chunk
                    });
                restored |= now.supply != Supply::Pending;
                if let Some(slot) = self.list.get_mut(i)
                {
                    *slot = now;
                }
            }
            stalled = if restored
            {
                0
            }
            else
            {
                stalled.saturating_add(1)
            };
        }
        Ok(())
    }
}

/// The mapped pages of the space `thread` executes in, below `top`, the top
/// of the user half.
fn list(thread: u64, top: u64) -> Result<Listing, u64>
{
    let mut listing = Listing::default();
    let mut page = Vec::new();
    page.try_reserve_exact(usize::try_from(MAX_PAGE_RUNS).unwrap_or(1))
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    page.resize(page.capacity(), PageRun::default());
    let mut start = 0;
    loop
    {
        let (n, resume) =
            syscall::thread_list_pages(thread, start, &mut page).map_err(target_code)?;
        listing
            .push(page.get(..n).unwrap_or_default())
            .map_err(runs_code)?;
        // The listing is complete at the top of the user half; a call that
        // did not move on would loop.
        if resume >= top || resume <= start
        {
            return Ok(listing);
        }
        start = resume;
    }
}

/// Copy every page of `runs` but those of `PAGE_RUN_NO_COPY` runs into the
/// data frames, in address order, each into the next data page from `first`;
/// a page whose copy fails takes none. Returns the addresses of those pages,
/// ascending.
fn copy(
    thread: u64,
    runs: &[PageRun],
    first: u64,
    data: &Grants<'_>,
    window: &mut Window,
) -> Result<Vec<u64>, u64>
{
    let mut failed = Vec::new();
    let mut dst = first;
    for run in runs.iter().filter(|r| r.prot & PAGE_RUN_NO_COPY == 0)
    {
        for i in 0..run.pages
        {
            let va = run.va.saturating_add(i.saturating_mul(PAGE_SIZE));
            let page = window.page(data, dst)?;
            // SAFETY: `page` is a page of the window, mapped writable to a
            // frame of the capture's grants that procmgr alone holds; no Rust
            // object lives there, and any byte value is valid where the seal
            // hands the frame on.
            match unsafe { syscall::thread_read_mem_raw(thread, va, page, MAX_THREAD_MEM_COPY) }
            {
                Ok(_) => dst = dst.saturating_add(1),
                // A page unmapped since the listing: recorded absent.
                Err(e) if e == SyscallError::InvalidAddress as i64 =>
                {
                    failed
                        .try_reserve(1)
                        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
                    failed.push(va);
                }
                Err(e) => return Err(target_code(e)),
            }
        }
    }
    Ok(failed)
}

/// The target's space held (`SYS_ASPACE_HOLD`) until the value drops,
/// which releases it on every path.
struct Hold
{
    aspace: u64,
}

impl Hold
{
    /// Hold the space `aspace` names.
    fn take(aspace: u64) -> Result<Self, u64>
    {
        match syscall::aspace_hold(aspace)
        {
            Ok(()) => Ok(Self { aspace }),
            Err(e)
                if e == SyscallError::InvalidState as i64
                    || e == SyscallError::Interrupted as i64 =>
            {
                Err(procmgr_errors::SPACE_HELD)
            }
            Err(e) => Err(target_code(e)),
        }
    }
}

impl Drop for Hold
{
    fn drop(&mut self)
    {
        // A space whose teardown began refuses nothing here: its release is a
        // no-op, and a revoked cap fails the call harmlessly.
        let _ = syscall::aspace_release(self.aspace);
    }
}

/// The snapshotter's memmgr SEND, on which every call is bounded.
struct Account
{
    cap: u64,
    ipc_buf: *mut u64,
}

impl Account
{
    /// Call the account with `msg`, waiting at most
    /// [`ACCOUNT_CALL_TIMEOUT_MS`].
    fn call(&self, msg: &IpcMessage) -> Result<IpcMessage, u64>
    {
        bounded_call(self.cap, msg, self.ipc_buf)
    }
}

/// Call `cap` with `msg`, waiting at most [`ACCOUNT_CALL_TIMEOUT_MS`];
/// `OUT_OF_MEMORY` when the call fails or the bound passes.
fn bounded_call(cap: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, u64>
{
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    unsafe { ipc::ipc_call_timeout(cap, msg, ipc_buf, ACCOUNT_CALL_TIMEOUT_MS) }
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)
}

/// One grant of the account: its Memory cap in procmgr's `CSpace`, 0 once
/// deleted, its region id, and its pages.
struct Grant
{
    cap: u64,
    region: u64,
    pages: u64,
}

/// Grants taken on the account, in the order of the object's pages.
///
/// Invariant: every grant received is in `list` from the moment its reply
/// arrives, so [`Drop`] deletes procmgr's caps and returns each to the
/// account whatever step failed.
struct Grants<'a>
{
    account: &'a Account,
    list: Vec<Grant>,
    /// Pages of every grant in `list`.
    pages: u64,
}

impl<'a> Grants<'a>
{
    fn new(account: &'a Account) -> Self
    {
        Self {
            account,
            list: Vec::new(),
            pages: 0,
        }
    }

    /// Request frames on the account until the grants hold at least `pages`
    /// pages, as many runs as memmgr has.
    ///
    /// # Errors
    /// `OUT_OF_MEMORY` when a call fails, memmgr refuses a request, a grant's
    /// cap does not cover the pages its reply names, or the grants would be
    /// more than one seal names.
    fn cover(&mut self, pages: u64) -> Result<(), u64>
    {
        while self.pages < pages
        {
            let want = pages.saturating_sub(self.pages).min(u64::from(u32::MAX));
            let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
                .word(0, want)
                .build();
            let reply = self.account.call(&msg)?;
            let Some((counts, regions)) = ipc::memmgr_grant_layout(&reply)
            else
            {
                crate::release_caps(reply.caps());
                return Err(procmgr_errors::OUT_OF_MEMORY);
            };
            if reply.label != memmgr_errors::SUCCESS
            {
                crate::release_caps(reply.caps());
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            if reply.caps().len() != regions.len() || self.list.try_reserve(regions.len()).is_err()
            {
                // The grants of a reply that is not kept go back at once:
                // none of them is in `list` for `Drop` to return.
                crate::release_caps(reply.caps());
                release_regions(self.account, regions.iter().copied());
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            let mut whole = true;
            for ((&cap, &count), &region) in reply.caps().iter().zip(counts).zip(regions)
            {
                whole &= count != 0
                    && syscall::cap_info(cap, syscall_abi::CAP_INFO_MEMORY_SIZE)
                        .is_ok_and(|size| count.checked_mul(PAGE_SIZE) == Some(size));
                self.list.push(Grant {
                    cap,
                    region,
                    pages: count,
                });
                self.pages = self.pages.saturating_add(count);
            }
            if !whole || self.list.len() as u64 > memmgr_labels::SEAL_OBJECT_MAX_GRANTS
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
        }
        Ok(())
    }

    /// Return to the account every grant past the first `pages` pages, so
    /// the object holds no whole grant it does not use.
    fn keep(&mut self, pages: u64)
    {
        let mut held = 0u64;
        let first = self
            .list
            .iter()
            .position(|g| {
                let past = held >= pages;
                held = held.saturating_add(g.pages);
                past
            })
            .unwrap_or(self.list.len());
        let rest = self.list.get(first..).unwrap_or(&[]);
        self.pages = self
            .pages
            .saturating_sub(rest.iter().fold(0, |n, g| n.saturating_add(g.pages)));
        release(self.account, rest);
        self.list.truncate(first);
    }

    /// The grants from the one holding page `index` of the grants, at most
    /// as many as a message carries, and the page's offset in the first: none
    /// when the grants hold no page `index`.
    fn at_page(&self, index: u64) -> (&[Grant], u64)
    {
        let mut base = 0u64;
        for (i, grant) in self.list.iter().enumerate()
        {
            if index < base.saturating_add(grant.pages)
            {
                let end = i.saturating_add(MSG_CAP_SLOTS_MAX).min(self.list.len());
                return (
                    self.list.get(i..end).unwrap_or(&[]),
                    index.saturating_sub(base),
                );
            }
            base = base.saturating_add(grant.pages);
        }
        (&[], 0)
    }

    /// Whether the grants one request carries from page `index` ([`at_page`])
    /// hold `count` pages from it.
    fn holds(&self, index: u64, count: u64) -> bool
    {
        let (grants, offset) = self.at_page(index);
        grants
            .iter()
            .fold(0u64, |n, g| n.saturating_add(g.pages))
            .saturating_sub(offset)
            >= count
    }

    /// The first page of the grant after the one holding page `index`: the
    /// grants' pages when it is in the last, or past them.
    fn next_grant(&self, index: u64) -> u64
    {
        let mut end = 0u64;
        for grant in &self.list
        {
            end = end.saturating_add(grant.pages);
            if index < end
            {
                return end;
            }
        }
        self.pages.max(index.saturating_add(1))
    }

    /// The grant holding page `index` of the grants, and the page's offset in
    /// it.
    fn locate(&self, index: u64) -> Option<(&Grant, u64)>
    {
        let mut base = 0u64;
        for grant in &self.list
        {
            if index < base.saturating_add(grant.pages)
            {
                return Some((grant, index.saturating_sub(base)));
            }
            base = base.saturating_add(grant.pages);
        }
        None
    }
}

impl Drop for Grants<'_>
{
    fn drop(&mut self)
    {
        release(self.account, &self.list);
    }
}

/// Delete procmgr's caps to `grants` and return them to the account
/// (`RELEASE_MEMORY_CAPS`), which takes each back once no cap names it and
/// nothing maps it.
fn release(account: &Account, grants: &[Grant])
{
    for grant in grants.iter().filter(|g| g.cap != 0)
    {
        let _ = syscall::cap_delete(grant.cap);
    }
    release_regions(account, grants.iter().map(|g| g.region));
}

/// Return the regions `ids` to the account (`RELEASE_MEMORY_CAPS`), as
/// many to a call as one names. It allocates nothing, so it runs after a
/// heap refusal too.
fn release_regions(account: &Account, mut ids: impl Iterator<Item = u64>)
{
    let mut batch = [0u64; RELEASE_IDS_PER_CALL];
    loop
    {
        let n = batch
            .iter_mut()
            .zip(ids.by_ref())
            .map(|(slot, id)| *slot = id)
            .count();
        let Some(ids) = batch.get(..n).filter(|ids| !ids.is_empty())
        else
        {
            return;
        };
        let msg = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
            .word(0, n as u64)
            .words(1, ids)
            .build();
        let _ = account.call(&msg);
    }
}

/// A reservation of procmgr's address space through which the copy maps the
/// data frames, [`WINDOW_PAGES`] at a time.
struct Window
{
    range: Option<ReservedRange>,
    self_aspace: u64,
    /// The data page mapped at the window's first page, and the pages mapped.
    mapped: Option<(u64, u64)>,
}

impl Window
{
    fn new(self_aspace: u64) -> Result<Self, u64>
    {
        let range = reserve_pages(WINDOW_PAGES).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        Ok(Self {
            range: Some(range),
            self_aspace,
            mapped: None,
        })
    }

    fn va(&self) -> u64
    {
        self.range.as_ref().map_or(0, ReservedRange::va_start)
    }

    /// The address in the window of data page `index` of `data`, mapping
    /// the pages of its grant from it, up to the window's size, when they are
    /// not mapped.
    fn page(&mut self, data: &Grants<'_>, index: u64) -> Result<*mut u8, u64>
    {
        if let Some((first, count)) = self.mapped
            && index >= first
            && index < first.saturating_add(count)
        {
            let offset = index.saturating_sub(first).saturating_mul(PAGE_SIZE);
            return Ok(self.va().saturating_add(offset) as *mut u8);
        }
        self.unmap()?;
        let (grant, offset) = data.locate(index).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        let count = grant.pages.saturating_sub(offset).min(WINDOW_PAGES);
        // Recorded before the map, which can fail with pages before the
        // failing one mapped: `unmap` then covers them, and a window that
        // will not unmap them stays reserved.
        self.mapped = Some((index, count));
        // SAFETY: the window's pages are unmapped (`unmap` above) pages of its
        // own reservation, and `count` is at most its size; no Rust object or
        // IPC page occupies them.
        let map = unsafe {
            std::os::seraph::mem_map_funded(
                grant.cap,
                self.self_aspace,
                self.va(),
                offset,
                count,
                syscall::MAP_WRITABLE,
            )
        };
        if map.is_err()
        {
            let _ = self.unmap();
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        Ok(self.va() as *mut u8)
    }

    /// Unmap the window's pages, so a grant mapped through it passes memmgr's
    /// quiescence check.
    fn unmap(&mut self) -> Result<(), u64>
    {
        if let Some((_, count)) = self.mapped
        {
            // SAFETY: the span is the window's own reservation, whose pages
            // hold no Rust object.
            unsafe { syscall::mem_unmap(self.self_aspace, self.va(), count) }
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            self.mapped = None;
        }
        Ok(())
    }
}

impl Drop for Window
{
    fn drop(&mut self)
    {
        // A window that will not unmap stays reserved, so no later
        // reservation lands on a mapped page.
        if self.unmap().is_ok()
            && let Some(range) = self.range.take()
        {
            unreserve_pages(range);
        }
    }
}

/// Write `layout` into the frames of `head`, mapped together for the write.
fn write_layout(self_aspace: u64, head: &Grants<'_>, layout: &Layout) -> Result<(), u64>
{
    let pages = head.pages;
    let range = reserve_pages(pages).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let va = range.va_start();
    let mut mapped = 0u64;
    let mut result = Ok(());
    for grant in &head.list
    {
        let at = va.saturating_add(mapped.saturating_mul(PAGE_SIZE));
        // SAFETY: the grant's pages land on unmapped pages of this
        // reservation, which `head.pages` sized to every grant.
        let map = unsafe {
            std::os::seraph::mem_map_funded(
                grant.cap,
                self_aspace,
                at,
                0,
                grant.pages,
                syscall::MAP_WRITABLE,
            )
        };
        if map.is_err()
        {
            result = Err(procmgr_errors::OUT_OF_MEMORY);
            break;
        }
        mapped = mapped.saturating_add(grant.pages);
    }
    if result.is_ok()
    {
        let len = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
        // SAFETY: the reservation's `pages` pages are mapped writable to frames
        // procmgr alone holds, and the slice ends before they are unmapped.
        let bytes = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };
        result = encode(bytes, layout);
    }
    // SAFETY: the span is this reservation, and the slice over it has ended.
    if unsafe { syscall::mem_unmap(self_aspace, va, pages) }.is_ok()
    {
        unreserve_pages(range);
    }
    else
    {
        result = Err(procmgr_errors::OUT_OF_MEMORY);
    }
    result
}

/// Encode `layout` at the start of `bytes`.
fn encode(bytes: &mut [u8], layout: &Layout) -> Result<(), u64>
{
    let header = Header {
        flags: if layout.complete
        {
            SNAPSHOT_COMPLETE
        }
        else
        {
            0
        },
        layout_pages: layout.layout_pages,
        data_pages: layout.data_pages,
        run_count: layout.runs.len() as u64,
    };
    header.encode(bytes).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    for (i, run) in layout.runs.iter().enumerate()
    {
        run.encode(bytes, i).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    }
    Ok(())
}

/// Seal `head` and `data`, in that order, into one memory object on the
/// account (`memmgr_labels::SEAL_OBJECT`), and return its handle and pages.
/// procmgr's caps are deleted first, so the frames pass memmgr's quiescence
/// check; a seal that fails returns the grants to the account.
fn seal(account: &Account, mut head: Grants<'_>, mut data: Grants<'_>) -> Result<(u64, u64), u64>
{
    let count = head.list.len().saturating_add(data.list.len());
    if count as u64 > memmgr_labels::SEAL_OBJECT_MAX_GRANTS
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }
    let mut msg = IpcMessage::builder(memmgr_labels::SEAL_OBJECT).word(0, count as u64);
    for (i, grant) in head.list.iter_mut().chain(&mut data.list).enumerate()
    {
        // Zeroed once deleted: a slot freed here may hold another worker's cap
        // by the time a failed seal's grants are released.
        let _ = syscall::cap_delete(grant.cap);
        grant.cap = 0;
        // `i` is below `count`, at most `SEAL_OBJECT_MAX_GRANTS`.
        msg = msg.word(i.saturating_add(1), grant.region);
    }
    let reply = account.call(&msg.build())?;
    if reply.label != memmgr_errors::SUCCESS
    {
        crate::release_caps(reply.caps());
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }
    // The grants are the object's now, and their ids name nothing.
    head.list.clear();
    data.list.clear();
    match *reply.caps()
    {
        [handle] => Ok((handle, reply.word(0))),
        ref caps =>
        {
            crate::release_caps(caps);
            Err(procmgr_errors::OUT_OF_MEMORY)
        }
    }
}

/// Drop the object `handle` names (`OBJECT_RELEASE`) and delete the handle:
/// the reply that would have carried it did not reach the snapshotter.
pub fn release_object(handle: u64, ipc_buf: *mut u64)
{
    let _ = bounded_call(
        handle,
        &IpcMessage::builder(memmgr_labels::OBJECT_RELEASE).build(),
        ipc_buf,
    );
    let _ = syscall::cap_delete(handle);
}
