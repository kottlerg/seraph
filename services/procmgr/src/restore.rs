// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/restore.rs

//! Restore creation (`procmgr_labels::CREATE_RESTORE`;
//! docs/checkpoint-restore.md § Restore creation): the reads of a
//! checkpoint's object, the bytes of the new process's bootstrap surfaces,
//! and its regions made again on its memmgr record.
//!
//! Every read is an `OBJECT_READ` sent on procmgr's own memmgr SEND with a
//! copy of the object's handle as a cap, so every answer, the checkpoint
//! mark among them, is memmgr's whoever handed procmgr the handle
//! (services/memmgr/docs/ipc-interface.md § Object Handles). The reads copy
//! into a window of frames on the child's account, which goes back to memmgr
//! before the child's registration settles ([`Source::into_regions`]). The
//! decisions that need no syscall are `process_table::restore`'s.

use crate::image::ImageBuffer;
use crate::process::CapGuard;
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use process_table::restore::{DecodeError, Layout, Remake, checkpoint_header};
use syscall_abi::PAGE_SIZE;

/// Pages one read copies: memmgr's bound on one `OBJECT_READ`.
const WINDOW_PAGES: u64 = memmgr_labels::OBJECT_READ_PAGES;

/// Bytes of a page, as a `usize`.
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// What one `OBJECT_READ` answered.
struct Answer
{
    /// Pages copied into the window.
    copied: u64,
    /// The object's flags (`memmgr_labels::OBJECT_CHECKPOINT`).
    flags: u64,
    /// The object's pages.
    total: u64,
}

/// A copy of `cap` with the send right, or `OUT_OF_MEMORY`.
fn send_copy(cap: u64) -> Result<CapGuard, u64>
{
    syscall::cap_derive(cap, syscall::RIGHTS_EP_SEND)
        .map(CapGuard::new)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)
}

/// A checkpoint being restored: the object's handle, the window its reads
/// copy into, and its decoded layout.
pub struct Source
{
    handle: CapGuard,
    memmgr_ep: u64,
    window: ImageBuffer,
    layout: Layout,
    ipc_buf: *mut u64,
}

/// Copy `pages` pages of the object `handle` names, from its page `first`
/// on, into `window`, with an `OBJECT_READ` on `memmgr_ep`, procmgr's own
/// memmgr SEND.
///
/// # Errors
/// `INVALID_ARGUMENT` when memmgr takes `handle` for no live object
/// handle (a SEND on another endpoint among them) or refuses the page range;
/// `OUT_OF_MEMORY` when a copy cannot be derived, the call fails, or memmgr
/// cannot map the window.
fn read(
    memmgr_ep: u64,
    handle: u64,
    window: &ImageBuffer,
    first: u64,
    pages: u64,
    ipc_buf: *mut u64,
) -> Result<Answer, u64>
{
    let run = window.run_cap().ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    let dest = syscall::cap_derive(run, syscall::RIGHTS_MEM_MAP_RW)
        .map(CapGuard::new)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let handle = send_copy(handle)?;
    let msg = IpcMessage::builder(memmgr_labels::OBJECT_READ)
        .word(0, first)
        .word(1, 0)
        .word(2, pages.min(WINDOW_PAGES))
        .cap(handle.cap())
        .cap(dest.cap())
        .build();
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) };
    // memmgr deletes both copies whatever it answers; a copy the call moved
    // is stale here, and its delete fails harmlessly
    // (docs/capability-model.md).
    drop((handle, dest));
    let reply = reply.map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    match reply.label
    {
        memmgr_errors::SUCCESS => Ok(Answer {
            copied: reply.word(0),
            flags: reply.word(1),
            total: reply.word(2),
        }),
        memmgr_errors::INVALID_ARGUMENT => Err(procmgr_errors::INVALID_ARGUMENT),
        _ => Err(procmgr_errors::OUT_OF_MEMORY),
    }
}

impl Source
{
    /// Open the checkpoint whose object handle procmgr holds in `handle`:
    /// read the object's mark and its layout, through a window of frames on
    /// `child_memmgr`, the child's account.
    ///
    /// # Errors
    /// `INVALID_ARGUMENT` when `handle` is no live object handle on
    /// memmgr's endpoint; `NOT_RESTORABLE` when the object carries no
    /// checkpoint mark, or its layout is not a complete checkpoint's;
    /// `OUT_OF_MEMORY` or `LIMIT` when the window or procmgr's copy of the
    /// layout cannot be had, or a read fails.
    pub fn open(
        handle: CapGuard,
        memmgr_ep: u64,
        self_aspace: u64,
        child_memmgr: u64,
        ipc_buf: *mut u64,
    ) -> Result<Self, u64>
    {
        let window = ImageBuffer::window(self_aspace, child_memmgr, WINDOW_PAGES, ipc_buf)?;
        let first = read(memmgr_ep, handle.cap(), &window, 0, 1, ipc_buf)?;
        if first.flags & memmgr_labels::OBJECT_CHECKPOINT == 0 || first.copied != 1
        {
            return Err(procmgr_errors::NOT_RESTORABLE);
        }
        let header = window
            .bytes()
            .get(..PAGE_BYTES)
            .and_then(checkpoint_header)
            .ok_or(procmgr_errors::NOT_RESTORABLE)?;
        let pages = header.layout_pages;
        let len = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|len| usize::try_from(len).ok())
            .filter(|_| pages != 0 && pages <= first.total)
            .ok_or(procmgr_errors::NOT_RESTORABLE)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let mut at = 0;
        while at < pages
        {
            // The loop condition keeps `at` below `pages`.
            let n = pages.saturating_sub(at).min(WINDOW_PAGES);
            let answer = read(memmgr_ep, handle.cap(), &window, at, n, ipc_buf)?;
            let copied = window.bytes().get(..page_bytes(n)?);
            match copied
            {
                Some(copied) if answer.copied == n => bytes.extend_from_slice(copied),
                _ => return Err(procmgr_errors::NOT_RESTORABLE),
            }
            at = at.saturating_add(n);
        }
        let layout = Layout::decode(&bytes, header).map_err(|e| match e
        {
            DecodeError::Malformed => procmgr_errors::NOT_RESTORABLE,
            DecodeError::OutOfMemory => procmgr_errors::OUT_OF_MEMORY,
        })?;
        Ok(Self {
            handle,
            memmgr_ep,
            window,
            layout,
            ipc_buf,
        })
    }

    /// The checkpoint's decoded layout.
    pub fn layout(&self) -> &Layout
    {
        &self.layout
    }

    /// Whether the checkpoint declares its image private
    /// (`CHECKPOINT_PRIVATE_IMAGE`), so the restored process loads it
    /// private whole, as the checkpointed one did.
    pub fn private_image(&self) -> bool
    {
        self.layout.checkpoint.declarations & ipc::procmgr_snapshot::CHECKPOINT_PRIVATE_IMAGE != 0
    }

    /// The restored process's argv and env, on its account at
    /// `child_memmgr`: the checkpoint's blobs in the argv/env region of its
    /// `ProcessInfo` page ([`crate::process::restored_argv_env`]).
    ///
    /// # Errors
    /// `NOT_RESTORABLE` when the checkpoint's header of them is out of
    /// bounds or its blobs do not hold the strings it counts; the pages' and
    /// the reads' codes.
    pub fn argv_env(
        &self,
        self_aspace: u64,
        child_memmgr: u64,
        ipc_buf: *mut u64,
    ) -> Result<crate::process::ChildArgvEnv, u64>
    {
        let header = self
            .layout
            .argv_env_header(
                process_abi::ARGV_ENV_REGION_OFFSET,
                process_abi::ARGV_ENV_MAX_BYTES,
            )
            .ok_or(procmgr_errors::NOT_RESTORABLE)?;
        let va = self
            .layout
            .checkpoint
            .process_info_va
            .checked_add(process_abi::ARGV_ENV_REGION_OFFSET)
            .ok_or(procmgr_errors::NOT_RESTORABLE)?;
        crate::process::restored_argv_env(self_aspace, child_memmgr, ipc_buf, header, |bytes| {
            self.fill(va, bytes)
        })
    }

    /// Fill `buf`, the bytes of the pages from `va` of a bootstrap surface,
    /// with the checkpoint's: the object's pages for a run that holds bytes,
    /// zeros for one that reads zero
    /// (`process_table::restore::Layout::next_span`).
    ///
    /// # Errors
    /// `NOT_RESTORABLE` when a page is in no run, or in one that is
    /// neither, or the object holds fewer pages than its run names; a
    /// read's code ([`read`]).
    pub fn fill(&self, va: u64, buf: &mut [u8]) -> Result<(), u64>
    {
        let pages = buf.len() as u64 / PAGE_SIZE;
        let mut done = 0;
        while done < pages
        {
            // `done` stays below `pages`, so the page's VA is the surface's.
            let at = va.saturating_add(done.saturating_mul(PAGE_SIZE));
            let span = self
                .layout
                .next_span(at, pages.saturating_sub(done))
                .ok_or(procmgr_errors::NOT_RESTORABLE)?;
            let start = page_bytes(done)?;
            let end = page_bytes(done.saturating_add(span.pages))?;
            let dst = buf
                .get_mut(start..end)
                .ok_or(procmgr_errors::NOT_RESTORABLE)?;
            match span.object_page
            {
                None => dst.fill(0),
                Some(first) => self.copy(first, dst)?,
            }
            done = done.saturating_add(span.pages);
        }
        Ok(())
    }

    /// Copy object pages from `first` on into `dst`, a whole number of
    /// pages, a window at a time.
    fn copy(&self, first: u64, dst: &mut [u8]) -> Result<(), u64>
    {
        for (i, part) in dst.chunks_mut(page_bytes(WINDOW_PAGES)?).enumerate()
        {
            let n = part.len() as u64 / PAGE_SIZE;
            let from = first.saturating_add((i as u64).saturating_mul(WINDOW_PAGES));
            let answer = read(
                self.memmgr_ep,
                self.handle.cap(),
                &self.window,
                from,
                n,
                self.ipc_buf,
            )?;
            let src = self
                .window
                .bytes()
                .get(..part.len())
                .filter(|_| answer.copied == n)
                .ok_or(procmgr_errors::NOT_RESTORABLE)?;
            part.copy_from_slice(src);
        }
        Ok(())
    }

    /// End the reads: the window goes back to memmgr now, before the
    /// child's registration settles, and what remains makes the child's
    /// regions again once it exists ([`Regions::remake`]).
    pub fn into_regions(self) -> Regions
    {
        Regions {
            handle: self.handle,
            layout: self.layout,
        }
    }
}

/// Bytes of `pages` pages, as a `usize`; `NOT_RESTORABLE` past it.
fn page_bytes(pages: u64) -> Result<usize, u64>
{
    pages
        .checked_mul(PAGE_SIZE)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(procmgr_errors::NOT_RESTORABLE)
}

/// The regions of a checkpoint to make again on the restored process's
/// memmgr record, and the object whose pages back them.
pub struct Regions
{
    handle: CapGuard,
    layout: Layout,
}

impl Regions
{
    /// Make the checkpoint's regions again on `child_memmgr`, a SEND on
    /// the restored process's memmgr record, whose address space memmgr has
    /// been delegated: each demand region by `REGISTER_REGION`, each
    /// attachment of the zero object by `ATTACH_OBJECT` without a handle;
    /// then back each page of theirs the checkpoint holds bytes for with
    /// `FILL_REGION` requests. The attachments of the image are the new
    /// image's own, made by the create.
    ///
    /// # Errors
    /// memmgr's refusal of a region, `LIMIT` for a max
    /// ([`process_table::memmgr_refusal`]); `NOT_RESTORABLE` when a
    /// fill is refused or backs fewer pages than it names; `OUT_OF_MEMORY`
    /// when a call fails or procmgr's heap refuses the requests' room.
    pub fn remake(&self, child_memmgr: u64, ipc_buf: *mut u64) -> Result<(), u64>
    {
        for region in &self.layout.regions
        {
            if let Some(remake) = Layout::remake(region)
            {
                make_region(remake, child_memmgr, ipc_buf)?;
            }
        }
        let fills = self
            .layout
            .fills()
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        for fill in &fills
        {
            back_fill(fill, self.handle.cap(), child_memmgr, ipc_buf)?;
        }
        Ok(())
    }
}

/// Make one region again on `child_memmgr` ([`Regions::remake`]).
fn make_region(remake: Remake, child_memmgr: u64, ipc_buf: *mut u64) -> Result<(), u64>
{
    let (label, words) = match remake
    {
        Remake::Register {
            va,
            len,
            prot,
            flags,
        } => (memmgr_labels::REGISTER_REGION, [va, len, prot, flags, 0]),
        // No handle: the zero object.
        Remake::AttachZero {
            va,
            len,
            prot,
            flags,
        } => (memmgr_labels::ATTACH_OBJECT, [va, len, prot, 0, flags]),
    };
    let mut b = IpcMessage::builder(label);
    for (i, word) in words.into_iter().enumerate()
    {
        b = b.word(i, word);
    }
    let msg = b.build();
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(child_memmgr, &msg, ipc_buf) }
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    if reply.label == memmgr_errors::SUCCESS
    {
        Ok(())
    }
    else
    {
        Err(process_table::memmgr_refusal(reply.label))
    }
}

/// Back the pages `fill` names from the object `handle` names, with a
/// `FILL_REGION` on `child_memmgr` ([`Regions::remake`]).
fn back_fill(
    fill: &process_table::restore::Fill,
    handle: u64,
    child_memmgr: u64,
    ipc_buf: *mut u64,
) -> Result<(), u64>
{
    let chunks = fill.chunks();
    let words = [fill.first, chunks.len() as u64].into_iter().chain(
        chunks
            .iter()
            .flat_map(|&(base, mask)| [base, u64::from(mask)]),
    );
    let handle = send_copy(handle)?;
    let mut b = IpcMessage::builder(memmgr_labels::FILL_REGION).cap(handle.cap());
    // At most `FILL_CHUNKS` chunks, so the words stay in the message.
    for (i, word) in words.enumerate()
    {
        b = b.word(i, word);
    }
    let msg = b.build();
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(child_memmgr, &msg, ipc_buf) };
    drop(handle);
    let reply = reply.map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    match reply.label
    {
        memmgr_errors::SUCCESS if reply.word(0) == fill.pages() => Ok(()),
        memmgr_errors::SUCCESS | memmgr_errors::INVALID_ARGUMENT =>
        {
            Err(procmgr_errors::NOT_RESTORABLE)
        }
        label => Err(process_table::memmgr_refusal(label)),
    }
}
