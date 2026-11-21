// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/snapshot.rs

//! `SNAPSHOT`: capture a live process's mapped pages into a memory object
//! charged to the snapshotter (services/procmgr/docs/ipc-interface.md
//! § Label 33: `SNAPSHOT`).
//!
//! procmgr asks memmgr to make the target's evicted pages resident, lists its
//! mapped pages and requests frames for them on the snapshotter's account,
//! all before the hold. It then holds the target's address space
//! (`SYS_ASPACE_HOLD`), so no thread of it runs, registered or not, makes
//! resident what was evicted meanwhile, lists the pages again, requests the
//! frames the second listing adds, copies every page with
//! `SYS_THREAD_READ_MEM` into the frames, and releases the space. After the
//! release it builds the layout (`process_table::snapshot::layout`), writes it
//! into frames of its own grant, and seals the layout and the data, in that
//! order, into one memory object on the account.
//!
//! The account is the snapshotter's own memmgr SEND, which the request
//! carries: procmgr cannot tell that it names memmgr, so every call on it
//! is bounded ([`ACCOUNT_CALL_TIMEOUT_MS`]), and the first failure fails the
//! capture, releasing the hold and every grant taken. Under the hold procmgr
//! calls only memmgr, on its own endpoint and on the account, and writes no
//! log line, so a held target that serves procmgr (logd among them) cannot
//! stall the capture.

use crate::process::CapGuard;
use ipc::procmgr_snapshot::{Header, SNAPSHOT_COMPLETE};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use process_table::snapshot::{Layout, Listing, Reported, layout};
use std::collections::TryReserveError;
use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use syscall_abi::{
    MAX_PAGE_RUNS, MAX_THREAD_MEM_COPY, PAGE_RUN_NO_COPY, PAGE_SIZE, PageRun, SyscallError,
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

/// What a capture needs of procmgr.
pub struct Context
{
    /// procmgr's own address space, where the frames are mapped to be filled.
    pub self_aspace: u64,
    /// procmgr's SEND on memmgr, for `MAKE_RESIDENT`.
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
    /// The target's memmgr badge, which names it to `MAKE_RESIDENT`.
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
/// one seal names, or when procmgr's heap or address space refused the
/// capture's own memory.
pub fn capture(ctx: &Context, target: &Target, account: u64) -> Result<Captured, u64>
{
    let account = Account {
        cap: account,
        ipc_buf: ctx.ipc_buf,
    };
    let top = syscall::user_va_top().map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    // Before the hold: what can be made resident, and the frames for what is
    // mapped then. The reports are taken again under the hold.
    make_resident(ctx, target.memmgr_badge, top)?;
    let mut data = Grants::new(&account);
    data.cover(list(target.thread.cap(), top)?.copied_pages())?;
    let mut window = Window::new(ctx.self_aspace)?;

    let hold = Hold::take(target.aspace.cap())?;
    let reported = make_resident(ctx, target.memmgr_badge, top)?;
    let listing = list(target.thread.cap(), top)?;
    data.cover(listing.copied_pages())?;
    let failed = copy(target.thread.cap(), listing.runs(), &data, &mut window)?;
    drop(hold);
    drop(window);

    let layout = layout(listing.runs(), &failed, &reported).map_err(runs_code)?;
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

/// Have memmgr make every evicted page of the target resident that it can
/// in its turn (`memmgr_labels::RESIDENT_REPORT`), over the user half up to
/// `top`, and return the ranges it reported it could not, in address order.
fn make_resident(ctx: &Context, memmgr_badge: u64, top: u64) -> Result<Vec<Reported>, u64>
{
    let mut reported = Vec::new();
    let mut at = 0u64;
    while at < top
    {
        let msg = IpcMessage::builder(memmgr_labels::MAKE_RESIDENT)
            .word(0, memmgr_badge)
            .word(1, at)
            .word(2, top.saturating_sub(at))
            .word(3, memmgr_labels::RESIDENT_REPORT)
            .build();
        // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
        let reply = match unsafe { ipc::ipc_call(ctx.memmgr_ep, &msg, ctx.ipc_buf) }
        {
            Ok(reply) if reply.label == memmgr_errors::SUCCESS => reply,
            // memmgr knows the badge no more: the target is torn down.
            Ok(reply) if reply.label == memmgr_errors::INVALID_ARGUMENT =>
            {
                return Err(procmgr_errors::INVALID_BADGE);
            }
            _ => return Err(procmgr_errors::OUT_OF_MEMORY),
        };
        let (reached, start, len, prot) =
            (reply.word(2), reply.word(3), reply.word(4), reply.word(5));
        if len != 0
        {
            reported
                .try_reserve(1)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            reported.push(Reported::new(start, len, prot));
        }
        // memmgr moves forward on every reply; one that did not would loop.
        if reached <= at
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        at = reached;
    }
    Ok(reported)
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
/// data frames, in address order, each into the next data page; a page whose
/// copy fails takes none. Returns the addresses of those pages, ascending.
fn copy(
    thread: u64,
    runs: &[PageRun],
    data: &Grants<'_>,
    window: &mut Window,
) -> Result<Vec<u64>, u64>
{
    let mut failed = Vec::new();
    let mut dst = 0u64;
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
                // A page unmapped since the listing, memmgr having evicted it
                // again: recorded absent.
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
