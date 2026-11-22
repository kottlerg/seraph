// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/image.rs

//! The object a create loads: read once, whole, into memory only procmgr
//! maps, and verified there before any byte of it is parsed
//! (docs/signing.md § Verifier Discipline).
//!
//! Both create labels read their object into an [`ImageBuffer`]: a boot
//! module's Memory cap is copied out ([`read_module`]), a file is copied
//! out of its fs driver's cache pages ([`read_file`]). Neither source is
//! verified in place, because each can still be written after the check:
//! a module cap's holder (devmgr holds its modules with write rights) can
//! write it, and an fs driver can rewrite a cache page it lent. The buffer's
//! frames are granted on the child's memmgr account, so a large object is
//! bounded by the child's budget, never procmgr's, and they go back to
//! memmgr when the buffer drops, once the load has copied the segments out.
//! [`verify`] checks the copy against the trust store; the loader then
//! sees only the verified body.
//!
//! `READ_VERIFIED` reads a data file the same way, into one run of frames
//! on its sender's account ([`Shape::Contiguous`]), and once the copy
//! verifies hands the run to the sender read-only
//! ([`ImageBuffer::into_read_only`]).

use crate::loader::{ScratchMapping, map_module};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE};

/// How long procmgr waits, at most, on each call it makes on a
/// caller-supplied file cap (`FS_SESSION`, `FS_OPEN`, `FS_READ_MEMORY`,
/// `FS_RELEASE_MEMORY`, `FS_CLOSE`): 10 s. The cap's server is untrusted,
/// so a server that never answers fails the create with `IO_ERROR` once the
/// bound passes instead of holding the request worker for good
/// (services/procmgr/README.md § Concurrency).
const FILE_CAP_CALL_TIMEOUT_MS: u32 = 10_000;

/// Region ids one `RELEASE_MEMORY_CAPS` names: every data word after the
/// count.
const RELEASE_IDS_PER_CALL: usize = MSG_DATA_WORDS_MAX - 1;

/// The memmgr account a read is granted and charged on.
#[derive(Clone, Copy)]
pub struct Account
{
    /// A memmgr SEND whose badge names the account's process.
    pub memmgr: u64,
    /// Whether that process's budget node is a system-reserve node.
    pub reserve: bool,
}

/// How the frames of an [`ImageBuffer`] are granted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Shape
{
    /// As many runs as memmgr has (`REQUEST_MEMORY_CAPS` best effort): an
    /// image, whose copy stays procmgr's.
    BestEffort,
    /// One run (`REQUIRE_CONTIGUOUS`): a `READ_VERIFIED` copy, which is
    /// handed to its reader as one cap and one region.
    Contiguous,
}

/// The run of a verified `READ_VERIFIED` copy as its reader receives it
/// ([`ImageBuffer::into_read_only`]).
pub struct ReadOnlyRun
{
    /// A Memory cap on the run carrying `RIGHTS_MEM_MAP` alone.
    pub cap: u64,
    /// The run's region id on the account it was granted on.
    pub region: u64,
    /// The run's pages.
    pub pages: u64,
}

/// The bytes of one object, in frames granted on a child's memmgr account and
/// mapped writable in procmgr alone, at one contiguous range of procmgr's
/// address space.
///
/// Invariant: the first `mapped` pages of the reservation are mapped; every
/// cap of a grant taken for the buffer is in `caps`, and its region id in
/// `regions`, from the moment the grant is received, so [`Drop`] returns
/// each grant whatever step failed.
pub struct ImageBuffer
{
    range: Option<ReservedRange>,
    self_aspace: u64,
    /// Pages of the reservation.
    pages: u64,
    /// Pages mapped from the reservation's start.
    mapped: u64,
    /// The object's length in bytes, at most `pages` pages.
    len: usize,
    caps: Vec<u64>,
    regions: Vec<u64>,
    /// The child's memmgr SEND the frames were granted on.
    memmgr: u64,
    ipc_buf: *mut u64,
    shape: Shape,
}

impl ImageBuffer
{
    /// A buffer of `len` bytes, from frames requested on `memmgr` (the
    /// child's account) until they cover it, each grant mapped writable at
    /// the next pages of one reservation; with [`Shape::Contiguous`], one
    /// grant of every page.
    ///
    /// # Errors
    /// `LIMIT` when memmgr refuses a request for the max of the account's
    /// budget node or of an ancestor ([`process_table::memmgr_refusal`]);
    /// `OUT_OF_MEMORY` when `len` is zero or past the address space, no
    /// reservation of its pages is free, memmgr refuses a request otherwise or
    /// answers one with a malformed grant; `MAP_FAILED` when a grant cannot be
    /// mapped. Every grant taken is returned.
    fn new(
        self_aspace: u64,
        memmgr: u64,
        len: u64,
        ipc_buf: *mut u64,
        shape: Shape,
    ) -> Result<Self, u64>
    {
        let pages = len.div_ceil(PAGE_SIZE);
        let byte_len = usize::try_from(len).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        if pages == 0 || memmgr == 0
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        let range = reserve_pages(pages).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let mut buffer = Self {
            range: Some(range),
            self_aspace,
            pages,
            mapped: 0,
            len: byte_len,
            caps: Vec::new(),
            regions: Vec::new(),
            memmgr,
            ipc_buf,
            shape,
        };
        while buffer.mapped < pages
        {
            buffer.grant(pages.saturating_sub(buffer.mapped))?;
        }
        Ok(buffer)
    }

    /// Request up to `want` pages on the child's account and map each cap
    /// of the grant at the next unmapped pages; a best-effort grant may cover
    /// fewer, and the caller asks again for the rest. A contiguous grant is
    /// one cap of every page, or fails.
    fn grant(&mut self, want: u64) -> Result<(), u64>
    {
        let want = want.min(u64::from(u32::MAX));
        let flags = match self.shape
        {
            Shape::BestEffort => 0,
            Shape::Contiguous => u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32,
        };
        let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, want | flags)
            .build();
        // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(self.memmgr, &msg, self.ipc_buf) }
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let Some((counts, regions)) = ipc::memmgr_grant_layout(&reply)
        else
        {
            crate::release_caps(reply.caps());
            if reply.label == memmgr_errors::SUCCESS
            {
                std::os::seraph::log!(warn: "image buffer: malformed memmgr grant");
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            return Err(process_table::memmgr_refusal(reply.label));
        };
        // Every cap and region of the grant is the buffer's to return before
        // any of it is checked or mapped.
        self.caps.extend_from_slice(reply.caps());
        self.regions.extend_from_slice(regions);
        for (&cap, &count) in reply.caps().iter().zip(counts)
        {
            let left = self.pages.saturating_sub(self.mapped);
            let whole = syscall::cap_info(cap, syscall_abi::CAP_INFO_MEMORY_SIZE)
                .is_ok_and(|size| count.checked_mul(PAGE_SIZE) == Some(size));
            if count == 0 || count > left || !whole
            {
                std::os::seraph::log!(warn: "image buffer: memmgr grant of {count} pages refused");
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            // `mapped` is below `pages`, so the offset is inside the
            // reservation.
            let va = self
                .va()
                .saturating_add(self.mapped.saturating_mul(PAGE_SIZE));
            // SAFETY: the `count` pages from `va` are unmapped pages of this
            // buffer's reservation (`count` is at most the pages left), VA
            // no Rust object or IPC page occupies.
            let mapped = unsafe {
                std::os::seraph::mem_map_funded(
                    cap,
                    self.self_aspace,
                    va,
                    0,
                    count,
                    syscall::MAP_WRITABLE,
                )
            };
            if mapped.is_err()
            {
                // A map that stops partway is undone by `Drop`, which unmaps
                // the whole reservation.
                return Err(procmgr_errors::MAP_FAILED);
            }
            self.mapped = self.mapped.saturating_add(count);
        }
        Ok(())
    }

    /// Base address of the buffer in procmgr's address space.
    fn va(&self) -> u64
    {
        self.range.as_ref().map_or(0, ReservedRange::va_start)
    }

    /// The object's bytes.
    pub fn bytes(&self) -> &[u8]
    {
        // SAFETY: the reservation's first `pages` pages are mapped writable
        // (the constructor maps every page before it returns the buffer), and
        // `len` is at most `pages * PAGE_SIZE`; the frames are granted on
        // the child's account to procmgr alone, so no other process writes
        // them, and the slice borrows `self`, so it ends before `Drop`
        // unmaps them.
        unsafe { core::slice::from_raw_parts(self.va() as *const u8, self.len) }
    }

    /// Hand the buffer's run to its reader: derive a cap on it carrying
    /// `RIGHTS_MEM_MAP` alone, unmap the run from procmgr, and delete
    /// procmgr's own cap, so no process but memmgr holds a cap that can
    /// write it; the region is the reader's to release from then on. Only a
    /// [`Shape::Contiguous`] buffer holds the one run this needs.
    ///
    /// # Errors
    /// `OUT_OF_MEMORY` when the buffer is not one run or the derivation
    /// fails; `MAP_FAILED` when procmgr's mapping will not come down. The
    /// buffer then drops, returning the run to memmgr.
    pub fn into_read_only(mut self) -> Result<ReadOnlyRun, u64>
    {
        let (&[cap], &[region]) = (self.caps.as_slice(), self.regions.as_slice())
        else
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        };
        let read_only = syscall::cap_derive(cap, syscall::RIGHTS_MEM_MAP)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        if let Some(range) = self.range.take()
        {
            // SAFETY: the span is this buffer's own reservation, and every
            // slice over it borrows the buffer, which this call owns.
            if unsafe { syscall::mem_unmap(self.self_aspace, range.va_start(), self.pages) }
                .is_err()
            {
                // Put back for `Drop`, which leaves a span that will not
                // unmap reserved.
                self.range = Some(range);
                let _ = syscall::cap_delete(read_only);
                return Err(procmgr_errors::MAP_FAILED);
            }
            unreserve_pages(range);
        }
        let _ = syscall::cap_delete(cap);
        self.caps.clear();
        self.regions.clear();
        Ok(ReadOnlyRun {
            cap: read_only,
            region,
            pages: self.pages,
        })
    }

    /// A buffer of `pages` pages to fill as a memory object, from frames
    /// requested on `memmgr` (the image store's account) as many runs as
    /// memmgr has, for [`Self::seal`].
    ///
    /// # Errors
    /// As the constructor's.
    pub fn for_object(
        self_aspace: u64,
        memmgr: u64,
        pages: u64,
        ipc_buf: *mut u64,
    ) -> Result<Self, u64>
    {
        let len = pages
            .checked_mul(PAGE_SIZE)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        Self::new(self_aspace, memmgr, len, ipc_buf, Shape::BestEffort)
    }

    /// Seal the buffer's frames into a memory object
    /// (`memmgr_labels::SEAL_OBJECT`) on the account they were granted on:
    /// unmap them from procmgr and delete procmgr's caps to them, so they pass
    /// memmgr's quiescence check, then name every grant in the request.
    /// Returns the object handle and the object's pages. The frames are the
    /// object's from then on, charged to the account until memmgr frees the
    /// object.
    ///
    /// # Errors
    /// `OUT_OF_MEMORY` when the buffer is more runs than one seal names
    /// (`memmgr_labels::SEAL_OBJECT_MAX_GRANTS`), or memmgr refuses the seal
    /// or the call fails; `MAP_FAILED` when procmgr's mapping will not come
    /// down. The buffer then drops, returning the grants memmgr still counts
    /// as the account's.
    pub fn seal(mut self) -> Result<(u64, u64), u64>
    {
        if self.regions.is_empty()
            || self.regions.len() as u64 > memmgr_labels::SEAL_OBJECT_MAX_GRANTS
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        if let Some(range) = self.range.take()
        {
            // SAFETY: the span is this buffer's own reservation, and every
            // slice over it borrows the buffer, which this call owns.
            if unsafe { syscall::mem_unmap(self.self_aspace, range.va_start(), self.pages) }
                .is_err()
            {
                // Put back for `Drop`, which leaves a span that will not
                // unmap reserved.
                self.range = Some(range);
                return Err(procmgr_errors::MAP_FAILED);
            }
            unreserve_pages(range);
        }
        crate::release_caps(&self.caps);
        self.caps.clear();
        let msg = IpcMessage::builder(memmgr_labels::SEAL_OBJECT)
            .word(0, self.regions.len() as u64)
            .words(1, &self.regions)
            .build();
        // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(self.memmgr, &msg, self.ipc_buf) }
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        if reply.label != memmgr_errors::SUCCESS
        {
            crate::release_caps(reply.caps());
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        // The grants are the object's now, and their ids name nothing.
        self.regions.clear();
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

    /// A buffer of `pages` pages in one run of frames requested on `memmgr`
    /// (the child's account), for the reads of a restore creation's object
    /// (`crate::restore`), which copy into the run's cap ([`Self::run_cap`]).
    ///
    /// # Errors
    /// As the constructor's.
    pub fn window(self_aspace: u64, memmgr: u64, pages: u64, ipc_buf: *mut u64)
    -> Result<Self, u64>
    {
        let len = pages
            .checked_mul(PAGE_SIZE)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        Self::new(self_aspace, memmgr, len, ipc_buf, Shape::Contiguous)
    }

    /// The Memory cap of the buffer's one run; `None` for a buffer of
    /// several runs.
    pub fn run_cap(&self) -> Option<u64>
    {
        match *self.caps.as_slice()
        {
            [cap] => Some(cap),
            _ => None,
        }
    }

    /// The object's bytes, to fill.
    pub fn bytes_mut(&mut self) -> &mut [u8]
    {
        // SAFETY: as [`Self::bytes`]; the exclusive borrow of `self` makes the
        // slice the only reference into the buffer.
        unsafe { core::slice::from_raw_parts_mut(self.va() as *mut u8, self.len) }
    }
}

impl Drop for ImageBuffer
{
    fn drop(&mut self)
    {
        if let Some(range) = self.range.take()
        {
            // SAFETY: the span is this buffer's own reservation, and every
            // slice over it borrows the buffer, so none is live here.
            // Unmapping a page that was never mapped is harmless; a span that
            // will not unmap stays reserved, so no later reservation lands on
            // a mapped page.
            if unsafe { syscall::mem_unmap(self.self_aspace, range.va_start(), self.pages) }.is_ok()
            {
                unreserve_pages(range);
            }
        }
        crate::release_caps(&self.caps);
        // memmgr takes a region back only once no cap to it is held and it
        // is mapped nowhere, which the two steps above made so.
        for ids in self.regions.chunks(RELEASE_IDS_PER_CALL)
        {
            let msg = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
                .word(0, ids.len() as u64)
                .words(1, ids)
                .build();
            // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(self.memmgr, &msg, self.ipc_buf) };
        }
    }
}

/// Copy the object `len` bytes long at the start of the Memory cap
/// `module_cap` into a buffer granted on `memmgr`. The cap stays the
/// caller's.
///
/// # Errors
/// `INVALID_ARGUMENT` when `len` is zero or past the cap's pages;
/// [`map_module`]'s code when the cap cannot be mapped; [`ImageBuffer`]'s
/// when the buffer cannot be had.
pub fn read_module(
    self_aspace: u64,
    module_cap: u64,
    len: u64,
    memmgr: u64,
    ipc_buf: *mut u64,
) -> Result<ImageBuffer, u64>
{
    let (module, module_pages) = map_module(module_cap, self_aspace)?;
    if len == 0 || len > module_pages.saturating_mul(PAGE_SIZE)
    {
        return Err(procmgr_errors::INVALID_ARGUMENT);
    }
    let mut buffer = ImageBuffer::new(self_aspace, memmgr, len, ipc_buf, Shape::BestEffort)?;
    let dst = buffer.bytes_mut();
    // SAFETY: `module` maps the cap's `module_pages` pages read-only from
    // `va()` and `dst.len()` (`len`) is within them; the cap's holder may
    // write the pages while procmgr reads them, so no Rust reference is
    // formed over them: the bytes are copied by raw pointer into the buffer,
    // which does not overlap them, and `module` drops after the copy.
    unsafe {
        core::ptr::copy_nonoverlapping(module.va() as *const u8, dst.as_mut_ptr(), dst.len());
    }
    drop(module);
    Ok(buffer)
}

/// Copy the `len`-byte file the caller-transferred node cap `node_cap`
/// names into a buffer granted on `memmgr` in `shape`: start a session with
/// the file's server charged to that same account ([`ReadSession`]), open
/// the file in it (`FS_OPEN`), copy each cache page `FS_READ_MEMORY` lends
/// (`FS_RELEASE_MEMORY` right after), delete the session's liveness cap and
/// close the open (`FS_CLOSE`), which ends the session at the server, and
/// release the session's node. The node cap is deleted, the open closed and
/// the session ended, and their caps deleted, on every outcome.
///
/// # Errors
/// `LIMIT` when the max of the account's node, or of an ancestor's, refuses
/// the session or the open; `IO_ERROR` when the session or the open fails
/// otherwise, a read fails, is unanswered, or returns no bytes, ends before
/// `len` bytes, or names a range past the page it lends; [`ImageBuffer`]'s
/// code when the buffer cannot be had, and `OUT_OF_MEMORY` when memmgr
/// cannot make the session's node.
pub fn read_file(
    self_aspace: u64,
    node_cap: u64,
    len: u64,
    account: Account,
    ipc_buf: *mut u64,
    shape: Shape,
) -> Result<ImageBuffer, u64>
{
    let memmgr = account.memmgr;
    // Dropped after the open, which closes first: the session ends with no
    // open in it.
    let (mut session, session_cap) = match ReadSession::start(node_cap, account, ipc_buf)
    {
        Ok(started) => started,
        Err(code) =>
        {
            let _ = syscall::cap_delete(node_cap);
            return Err(code);
        }
    };
    let liveness = session.take_liveness();
    let _session = std::mem::DropGuard::new(session, move |s| s.end(ipc_buf));
    let file = match vfs_open(node_cap, session_cap, ipc_buf)
    {
        Ok(file) => file,
        Err(code) =>
        {
            let _ = syscall::cap_delete(liveness);
            return Err(code);
        }
    };
    let file = std::mem::DropGuard::new(file, move |file| vfs_close(file, ipc_buf));
    // Dropped before the open: the close then finds the session's liveness
    // cap gone and ends the session (fs-driver-protocol.md § Label 3), so its
    // charge has left the account before the read is answered.
    let liveness = std::mem::DropGuard::new(liveness, |cap| {
        let _ = syscall::cap_delete(cap);
    });
    let mut buffer = ImageBuffer::new(self_aspace, memmgr, len, ipc_buf, shape)?;
    let dst = buffer.bytes_mut();
    let mut copied = 0usize;
    while copied < dst.len()
    {
        let chunk = copy_cache_page(self_aspace, *file, ipc_buf, copied as u64, |page| {
            // `copied` is below `dst.len()`.
            let to = dst.get_mut(copied..)?;
            let n = page.len().min(to.len());
            Some((to.as_mut_ptr(), n))
        })?;
        // `chunk` is at most `dst.len() - copied`.
        copied = copied.saturating_add(chunk);
    }
    drop(liveness);
    drop(file);
    Ok(buffer)
}

/// Read the cache page `FS_READ_MEMORY` lends for the file's byte `offset`
/// on the open `file_cap`, and copy its valid bytes to where `target` says:
/// `target` receives the valid range and returns the destination and how
/// many bytes to copy (at most the range's length). Returns the bytes copied,
/// which are never zero.
///
/// # Errors
/// `IO_ERROR` when the read fails or lends no bytes, the page cannot be
/// mapped, the reply's range runs past the page, or `target` has no room.
fn copy_cache_page(
    self_aspace: u64,
    file_cap: u64,
    ipc_buf: *mut u64,
    offset: u64,
    target: impl FnOnce(core::ops::Range<usize>) -> Option<(*mut u8, usize)>,
) -> Result<usize, u64>
{
    let (memory_cap, bytes_valid, data_offset, cookie) =
        vfs_read_memory(file_cap, ipc_buf, offset).ok_or(procmgr_errors::IO_ERROR)?;
    let copied = (|| {
        let mut page = ScratchMapping::map(self_aspace, memory_cap, 1, syscall::MAP_FROM_CAP)
            .map_err(|_| {
                let _ = syscall::cap_delete(memory_cap);
                procmgr_errors::IO_ERROR
            })?;
        page.set_owns_cap(memory_cap);
        // The offset and count come from the fs driver: a range that leaves
        // the one page mapped is refused before any byte is read.
        let range =
            process_table::fs_reads::cache_page_range(data_offset, bytes_valid, PAGE_SIZE as usize)
                .ok_or(procmgr_errors::IO_ERROR)?;
        let start = range.start;
        let (dst, n) = target(range).ok_or(procmgr_errors::IO_ERROR)?;
        if n == 0
        {
            return Err(procmgr_errors::IO_ERROR);
        }
        // `start` is below the one page mapped (`cache_page_range`).
        let src = page.va().saturating_add(start as u64) as *const u8;
        // SAFETY: `page` maps one page read-only from `va()`, and
        // `[start, start + n)` is within it (`n` is at most the checked
        // range's length); `dst` has room for `n` bytes (`target`'s
        // contract). The page is the fs driver's cache page, which the driver
        // may write while procmgr reads it, so no Rust reference is formed
        // over it: the bytes are copied by raw pointer into procmgr's own
        // buffer, which does not overlap it, and `page` drops after the copy.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, n);
        }
        Ok(n)
    })();
    vfs_release_memory(file_cap, ipc_buf, cookie);
    copied
}

/// Verify `object` against procmgr's trust store as the image a creator
/// expects: signed under `name`, with a role set that meets `roles` (the
/// creator's signature policy), for this architecture. The certificate cache is copied
/// out under its lock and written back after, so creates verify at once; the
/// cache is a memo of certificate checks, so an update one create's
/// write-back loses costs a later create one signature check and changes no
/// result. A refusal is logged with the name.
///
/// # Errors
/// The [`objsig::Refusal`] of the object.
pub fn verify<'a>(
    ctx: &crate::ProcmgrCtx,
    object: &'a [u8],
    name: &[u8],
    roles: objsig::RoleSet,
) -> Result<objsig::Verified<'a, 'static>, objsig::Refusal>
{
    let expect = objsig::Expectation {
        roles,
        name,
        arch: crate::arch::current::SIGNED_ARCH,
    };
    let mut cache = *ctx
        .cert_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let verified = objsig::verify_cached(object, &ctx.trust_store, &expect, &mut cache);
    *ctx.cert_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = cache;
    verified.inspect_err(|refusal| {
        std::os::seraph::log!(
            warn: "signature verification refused: {}: {:?}",
            name.escape_ascii(),
            refusal
        );
    })
}

// ── File-cap calls ──────────────────────────────────────────────────────────

/// Call the server of a caller-supplied file cap, bounded by
/// [`FILE_CAP_CALL_TIMEOUT_MS`].
///
/// # Safety
/// `ipc_buf` is the calling thread's registered IPC buffer page.
unsafe fn file_call(cap: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { ipc::ipc_call_timeout(cap, msg, ipc_buf, FILE_CAP_CALL_TIMEOUT_MS) }
}

/// Per-request correlation cookie for `FS_READ_MEMORY`: a random `u64` from
/// the kernel entropy pool, redrawn off the reserved `0` value (fatfs rejects
/// cookie 0 as the `OutstandingPage::None` sentinel). Random rather than
/// monotonic so the read-memory request count/rate it would otherwise leak to
/// the fs stays unguessable; the cookie is opaque and never indexes a table.
/// Its `u64` is the one request word that carries it, so the space never
/// runs out. Returns `None` if the entropy draw fails (a kernel-contract violation).
fn next_memory_cookie() -> Option<u64>
{
    loop
    {
        let c = syscall::random_u64().ok()?;
        if c != 0
        {
            return Some(c);
        }
    }
}

/// Issue `FS_READ_MEMORY` at byte `offset`.
///
/// On success returns `(memory_cap, bytes_valid, memory_data_offset, cookie)`
/// per `fs/docs/fs-driver-protocol.md`: the file's byte at `offset + i` for
/// `i ∈ [0, bytes_valid)` lives in the returned memory cap at byte offset
/// `memory_data_offset + i`, and `cookie` names the request for the
/// `FS_RELEASE_MEMORY` that drops the fs-side cache refcount once the caller
/// has copied the bytes ([`copy_cache_page`] issues it; `FS_CLOSE` drops
/// any the caller missed). The memory cap is a per-call grandchild of the fs
/// cache slot and is owned by the caller; `cap_delete` releases the caller's
/// reference. `bytes_valid` is bounded by file end, cluster boundary, and
/// memory-cap tail — callers must iterate from `offset + bytes_valid` to read
/// past the boundary.
///
/// The file cap is client-supplied, so its server is untrusted: every reply
/// cap other than the returned one is deleted, and on a failed or empty reply
/// every reply cap ([`process_table::fs_reads::read_memory_reply_caps`]).
fn vfs_read_memory(
    file_cap: u64,
    ipc_buf: *mut u64,
    offset: u64,
) -> Option<(u64, usize, usize, u64)>
{
    let cookie = next_memory_cookie()?;
    let msg = IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
        .word(0, offset)
        .word(1, cookie)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { file_call(file_cap, &msg, ipc_buf) }.ok()?;
    let bytes_valid = reply.word(0) as usize;
    let (kept, surplus) =
        process_table::fs_reads::read_memory_reply_caps(reply.label, bytes_valid, reply.caps());
    crate::release_caps(surplus);
    let memory_data_offset = reply.word(2) as usize;
    Some((kept?, bytes_valid, memory_data_offset, cookie))
}

/// The session one file read opens its file in
/// (`fs/docs/fs-driver-protocol.md` § Label 23): charged to a sub-node of the
/// account the read's buffer is granted on, the child's for a create and the
/// sender's for `READ_VERIFIED`, so the creator pays for the server's records
/// of the read as for the buffer, with a max of
/// [`process_table::fs_reads::READ_SESSION_MAX_PAGES`]. It is made on the
/// node cap the read opens, so it is with that file's server by construction,
/// and it lives for the one read: procmgr keeps no session across requests.
struct ReadSession
{
    /// The full handle to the session's sub-node.
    node: u64,
    /// The session's liveness cap.
    liveness: u64,
}

impl ReadSession
{
    /// Make the sub-node on `account` ([`create_node`]), a charge-only handle to it
    /// (`NODE_CHARGE_HANDLE`), and send it in `FS_SESSION` on `node_cap`.
    /// Returns the session and the session cap, which the open moves to the
    /// server. Every cap of a failure is deleted and the sub-node released.
    fn start(node_cap: u64, account: Account, ipc_buf: *mut u64) -> Result<(Self, u64), u64>
    {
        let node = create_node(account, ipc_buf)?;
        let mut session = Self { node, liveness: 0 };
        let Some(charge) = node_call_cap(node, memmgr_labels::NODE_CHARGE_HANDLE, ipc_buf)
        else
        {
            session.end(ipc_buf);
            return Err(procmgr_errors::OUT_OF_MEMORY);
        };
        match request_session(node_cap, charge, ipc_buf)
        {
            Ok((session_cap, liveness)) =>
            {
                session.liveness = liveness;
                Ok((session, session_cap))
            }
            Err(code) =>
            {
                session.end(ipc_buf);
                Err(code)
            }
        }
    }

    /// The session's liveness cap, which the caller now deletes before it
    /// closes the session's open, so the close ends the session.
    fn take_liveness(&mut self) -> u64
    {
        std::mem::take(&mut self.liveness)
    }

    /// End the session: delete its liveness cap, unless the caller took it,
    /// so the server ends it, then release the sub-node (`NODE_RELEASE`),
    /// which tells a server holding a grant charged to it, and delete the
    /// handle. The charge returns to the account when the server ends the
    /// session: at once when the close of its open already did.
    fn end(self, ipc_buf: *mut u64)
    {
        if self.liveness != 0
        {
            let _ = syscall::cap_delete(self.liveness);
        }
        let msg = IpcMessage::new(memmgr_labels::NODE_RELEASE);
        // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
        if let Ok(reply) = unsafe { ipc::ipc_call(self.node, &msg, ipc_buf) }
        {
            crate::release_caps(reply.caps());
        }
        let _ = syscall::cap_delete(self.node);
    }
}

/// Make a sub-node with a max of
/// [`process_table::fs_reads::READ_SESSION_MAX_PAGES`] on `account`
/// (`CREATE_SUB_NODE`), in the system reserve when the account's node is a
/// reserve node (`SUB_NODE_RESERVE`), so a reserve child's create, or a
/// reserve sender's read, is backed from the reserve as its own pages are;
/// its full handle. memmgr's refusal is answered as a refusal of the
/// buffer's pages is.
fn create_node(account: Account, ipc_buf: *mut u64) -> Result<u64, u64>
{
    let flags = if account.reserve
    {
        memmgr_labels::SUB_NODE_RESERVE
    }
    else
    {
        0
    };
    let msg = IpcMessage::builder(memmgr_labels::CREATE_SUB_NODE)
        .word(0, process_table::fs_reads::READ_SESSION_MAX_PAGES)
        .word(1, flags)
        .build();
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(account.memmgr, &msg, ipc_buf) }
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    match (reply.label, reply.caps())
    {
        (memmgr_errors::SUCCESS, &[node]) => Ok(node),
        (label, caps) =>
        {
            crate::release_caps(caps);
            Err(process_table::memmgr_refusal(label))
        }
    }
}

/// Call the node handle `node` with the bare label `label`; the one cap a
/// success carries, `None` on any other reply, whose caps are deleted.
fn node_call_cap(node: u64, label: u64, ipc_buf: *mut u64) -> Option<u64>
{
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(node, &IpcMessage::new(label), ipc_buf) }.ok()?;
    match (reply.label, reply.caps())
    {
        (memmgr_errors::SUCCESS, &[cap]) => Some(cap),
        (_, caps) =>
        {
            crate::release_caps(caps);
            None
        }
    }
}

/// `FS_SESSION` on the caller-supplied node cap `node_cap`, moving the
/// charge-only handle `charge`: the reply's session cap and liveness cap.
/// The handle is deleted when the kernel did not move it, and every surplus
/// reply cap.
///
/// # Errors
/// [`process_table::fs_reads::fs_refusal`] of the server's refusal;
/// `IO_ERROR` when the call fails or a success carries no two caps.
fn request_session(node_cap: u64, charge: u64, ipc_buf: *mut u64) -> Result<(u64, u64), u64>
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_SESSION)
        .cap(charge)
        .build();
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    let reply = unsafe { file_call(node_cap, &msg, ipc_buf) };
    // A handle the kernel did not move (a refused call) is still ours; a
    // moved one's slot is stale, and the delete is refused.
    let _ = syscall::cap_delete(charge);
    let reply = reply.map_err(|_| procmgr_errors::IO_ERROR)?;
    let (kept, surplus) = process_table::fs_reads::session_reply_caps(reply.label, reply.caps());
    // The file cap is client-supplied, so its server is untrusted.
    crate::release_caps(surplus);
    kept.ok_or(process_table::fs_reads::fs_refusal(reply.label))
}

/// Open the file a caller-transferred file node cap names in the read's
/// session (`FS_OPEN`, moving `session_cap` in `caps[0]`, with no release
/// SEND: procmgr releases each page itself right after its copy, so it opts
/// out of cooperative release), and delete the node cap. Returns the open
/// cap every later read and the closing `FS_CLOSE` go to, so procmgr's pages
/// and close touch no other opener's state (`fs/docs/fs-driver-protocol.md`
/// § Label 18); every other reply cap is deleted.
///
/// # Errors
/// `LIMIT` when the session's max refuses the open; `IO_ERROR` when the
/// call fails or the server refuses otherwise, or the reply carries no open
/// cap.
fn vfs_open(node_cap: u64, session_cap: u64, ipc_buf: *mut u64) -> Result<u64, u64>
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_OPEN)
        .cap(session_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { file_call(node_cap, &msg, ipc_buf) };
    // A session cap the kernel did not move is still procmgr's.
    let _ = syscall::cap_delete(session_cap);
    let _ = syscall::cap_delete(node_cap);
    let reply = reply.map_err(|_| procmgr_errors::IO_ERROR)?;
    let (opened, surplus) = process_table::fs_reads::open_reply_caps(reply.label, reply.caps());
    // The file cap is client-supplied, so its server is untrusted.
    crate::release_caps(surplus);
    opened.ok_or(process_table::fs_reads::fs_refusal(reply.label))
}

/// Close an open file via its open cap, then delete the open cap.
fn vfs_close(file_cap: u64, ipc_buf: *mut u64)
{
    let msg = IpcMessage::new(ipc::fs_labels::FS_CLOSE);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Ok(reply) = unsafe { file_call(file_cap, &msg, ipc_buf) }
    {
        // FS_CLOSE replies carry no caps; the untrusted server's are deleted.
        crate::release_caps(reply.caps());
    }
    let _ = syscall::cap_delete(file_cap);
}

/// Issue `FS_RELEASE_MEMORY` on the file-cap to drop the fs-side cache
/// refcount and clear the outstanding-page tracking entry for `cookie`.
/// Failure is non-fatal — the slot will be reclaimed at `FS_CLOSE` time
/// even if the proactive release is lost.
fn vfs_release_memory(file_cap: u64, ipc_buf: *mut u64, cookie: u64)
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_RELEASE_MEMORY)
        .word(0, cookie)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Ok(reply) = unsafe { file_call(file_cap, &msg, ipc_buf) }
    {
        // FS_RELEASE_MEMORY replies carry no caps; the untrusted server's
        // are deleted.
        crate::release_caps(reply.caps());
    }
}
