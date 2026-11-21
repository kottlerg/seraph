// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/session.rs

//! The pages a filesystem session's client pays for, and the memmgr calls
//! that take and return them (services/fs/docs/fs-driver-protocol.md
//! § Label 23).
//!
//! A session keeps its records in pages charged to its client's node. Each
//! page is a one-page grant fatfs asks memmgr for with `REQUEST_CHARGE_NODE`
//! and a copy of the session's charge-only handle ([`request_page`]), maps
//! writable into a window of its own address space ([`SessionPages`]), and
//! gives back with `RELEASE_MEMORY_CAPS` when the session no longer needs it
//! ([`release_page`]), so the charge returns to the node with it. The window
//! is reserved once, at start, for as many pages as the machine has RAM (at
//! most `fat_parse::session_pool::MAX_PAGES`), and holds no page until a
//! session takes one; what fatfs keeps of it is one bit per page up to the
//! highest page in use at once. The layout and lifetimes of the records the
//! pages hold are `fat_parse::session_pool`'s.

use fat_parse::session_pool::{MAX_PAGES, Page, PageStore};
use ipc::{IpcMessage, fs_errors, memmgr_errors, memmgr_labels};
use std::os::seraph::{mem_map_funded, reserve_pages, startup_info};
use syscall_abi::{MAP_WRITABLE, PAGE_SIZE};

/// One page memmgr granted a session: its Memory cap and the region id that
/// gives it back.
#[derive(Clone, Copy)]
pub struct Grant
{
    pub cap: u64,
    pub region_id: u64,
}

impl Grant
{
    /// The two words a session record keeps of the page
    /// (`fat_parse::session_pool::Frame`).
    pub const fn words(self) -> [u64; 2]
    {
        [self.cap, self.region_id]
    }

    /// The grant the two words of a record's frame name.
    pub const fn from_words(words: [u64; 2]) -> Self
    {
        Self {
            cap: words[0],
            region_id: words[1],
        }
    }
}

/// The window of fatfs's address space that maps session pages, by page
/// number: page `n` lies at `base + n * PAGE_SIZE`. Implements
/// [`PageStore`] over the pages it maps.
pub struct SessionPages
{
    /// First VA of the window.
    base: u64,
    /// Pages the window holds.
    capacity: u32,
    /// fatfs's own address space.
    aspace: u64,
    /// One bit per page up to the highest page mapped at once: set while the
    /// page is mapped.
    mapped: Vec<u64>,
    /// The lowest word of `mapped` that may hold a clear bit.
    first_free: usize,
}

impl SessionPages
{
    /// Reserve the window in `aspace`, fatfs's own address space: one page
    /// per page of the machine's `ram_pages` of RAM, at most [`MAX_PAGES`],
    /// halved while the arena cannot give that much. The reservation is held
    /// for the process's life (`ReservedRange` has no `Drop`). A window of
    /// no page, which maps none, when not even one page can be had.
    pub fn reserve(ram_pages: u64, aspace: u64) -> Self
    {
        let mut want = ram_pages.clamp(1, u64::from(MAX_PAGES));
        loop
        {
            if let Ok(range) = reserve_pages(want)
            {
                return Self {
                    base: range.va_start(),
                    capacity: u32::try_from(want).unwrap_or(0),
                    aspace,
                    mapped: Vec::new(),
                    first_free: 0,
                };
            }
            if want == 1
            {
                return Self {
                    base: 0,
                    capacity: 0,
                    aspace,
                    mapped: Vec::new(),
                    first_free: 0,
                };
            }
            want /= 2;
        }
    }

    /// The VA of page `no`, when the window holds it.
    fn va(&self, no: u32) -> Option<u64>
    {
        if no >= self.capacity
        {
            return None;
        }
        self.base.checked_add(u64::from(no).checked_mul(PAGE_SIZE)?)
    }

    /// The word of `mapped` and the bit in it of page `no`.
    fn bit(no: u32) -> (usize, u64)
    {
        let word = usize::try_from(no / 64).unwrap_or(usize::MAX);
        (word, 1u64.wrapping_shl(no % 64))
    }

    fn is_mapped(&self, no: u32) -> bool
    {
        let (word, bit) = Self::bit(no);
        self.mapped.get(word).is_some_and(|w| w & bit != 0)
    }

    /// The lowest page of the window no page maps.
    fn free_page(&mut self) -> Option<u32>
    {
        while let Some(&word) = self.mapped.get(self.first_free)
        {
            if word != u64::MAX
            {
                let no = u32::try_from(self.first_free)
                    .ok()?
                    .checked_mul(64)?
                    .checked_add((!word).trailing_zeros())?;
                return (no < self.capacity).then_some(no);
            }
            self.first_free = self.first_free.saturating_add(1);
        }
        let no = u32::try_from(self.mapped.len()).ok()?.checked_mul(64)?;
        (no < self.capacity).then_some(no)
    }

    /// Map `cap`, a one-page grant, writable at the lowest free page of the
    /// window. Returns its page number, or `None` when the window is full,
    /// the heap cannot grow the page bits, or the map fails; the grant is
    /// then the caller's still.
    pub fn map(&mut self, cap: u64) -> Option<u32>
    {
        let no = self.free_page()?;
        let va = self.va(no)?;
        let (word, bit) = Self::bit(no);
        if word >= self.mapped.len()
        {
            self.mapped.try_reserve(1).ok()?;
            self.mapped.push(0);
        }
        // SAFETY: va is a page of the window reserved at start for session
        // pages, which only this store maps and unmaps; its bit is clear, so
        // no page is mapped there, and no Rust object or IPC buffer lies in
        // it.
        unsafe { mem_map_funded(cap, self.aspace, va, 0, 1, MAP_WRITABLE) }.ok()?;
        let w = self.mapped.get_mut(word)?;
        *w |= bit;
        Some(no)
    }

    /// Unmap page `no`, freeing its place in the window. `false` when it is
    /// not mapped or the unmap fails: the page then stays mapped and keeps its
    /// place.
    pub fn unmap(&mut self, no: u32) -> bool
    {
        if !self.is_mapped(no)
        {
            return false;
        }
        let Some(va) = self.va(no)
        else
        {
            return false;
        };
        // SAFETY: va maps a session page of the window. A reference into it
        // comes only from `page` or `page_mut` and lives no longer than its
        // borrow of the store, which this `&mut self` excludes, so no live
        // Rust object lies in it; no IPC buffer is mapped in the window.
        if unsafe { syscall::mem_unmap(self.aspace, va, 1) }.is_err()
        {
            return false;
        }
        let (word, bit) = Self::bit(no);
        if let Some(w) = self.mapped.get_mut(word)
        {
            *w &= !bit;
        }
        self.first_free = self.first_free.min(word);
        true
    }
}

impl PageStore for SessionPages
{
    fn page(&self, no: u32) -> Option<&Page>
    {
        if !self.is_mapped(no)
        {
            return None;
        }
        let va = self.va(no)?;
        // SAFETY: page `no` of the window is mapped writable (its bit is
        // set) at a page-aligned VA, the size and alignment of a `Page`, and
        // every bit pattern is a valid `Page`. Only this store reaches it,
        // and the borrow of `self` the reference carries keeps `unmap` and
        // `page_mut`, which take `&mut self`, from unmapping or aliasing it
        // while the reference lives.
        Some(unsafe { &*(va as *const Page) })
    }

    fn page_mut(&mut self, no: u32) -> Option<&mut Page>
    {
        if !self.is_mapped(no)
        {
            return None;
        }
        let va = self.va(no)?;
        // SAFETY: as for `page`; the `&mut self` borrow the reference carries
        // makes it the only reference to the page while it lives.
        Some(unsafe { &mut *(va as *mut Page) })
    }
}

/// Ask memmgr for one page charged to the node of `handle`, a session's
/// charge-only handle (`REQUEST_MEMORY_CAPS` with `REQUEST_CHARGE_NODE`
/// and a copy of the handle). The `fs_errors` code the request that needed
/// the page is answered when memmgr gives none: `LIMIT` at the max of the
/// node or an ancestor, `INVALID_ARGUMENT` for a handle memmgr refuses,
/// `TOO_MANY_OPEN` when fatfs's `CSpace` has no slot for the copy, and
/// `IO_ERROR` when memmgr has no page or the call fails.
pub fn request_page(handle: u64, ipc_buf: *mut u64) -> Result<Grant, u64>
{
    let info = startup_info();
    let copy = syscall::cap_copy(handle, info.self_cspace, syscall::RIGHTS_EP_SEND)
        .map_err(|_| fs_errors::TOO_MANY_OPEN)?;
    let flags = memmgr_labels::REQUIRE_CONTIGUOUS | memmgr_labels::REQUEST_CHARGE_NODE;
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1 | (u64::from(flags) << 32))
        .cap(copy)
        .build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(info.memmgr_endpoint, &msg, ipc_buf) })
    else
    {
        // A call that fails moves no cap: the copy is still fatfs's.
        let _ = syscall::cap_delete(copy);
        return Err(fs_errors::IO_ERROR);
    };
    match reply.label
    {
        memmgr_errors::SUCCESS =>
        {}
        memmgr_errors::LIMIT => return Err(fs_errors::LIMIT),
        memmgr_errors::INVALID_ARGUMENT => return Err(fs_errors::INVALID_ARGUMENT),
        _ => return Err(fs_errors::IO_ERROR),
    }
    let cap = reply.caps().first().copied();
    let region_id = match ipc::memmgr_grant_layout(&reply)
    {
        Some((&[1], &[id])) => id,
        _ => 0,
    };
    match (cap, region_id)
    {
        (Some(cap), 1..) => Ok(Grant { cap, region_id }),
        (Some(cap), 0) =>
        {
            // A grant that is not one page with an id cannot be given back
            // by name; drop the cap and take the request as refused.
            let _ = syscall::cap_delete(cap);
            Err(fs_errors::IO_ERROR)
        }
        (None, _) => Err(fs_errors::IO_ERROR),
    }
}

/// Give `grant`, unmapped, back to memmgr, which returns its charge to the
/// node it was charged to. A refused release is logged: the page then stays
/// charged until fatfs exits.
pub fn release_page(grant: Grant)
{
    let _ = syscall::cap_delete(grant.cap);
    let released = crate::cache::release_regions(
        startup_info().memmgr_endpoint,
        &[grant.region_id],
        std::os::seraph::current_ipc_buf(),
    );
    if !released
    {
        std::os::seraph::log!(warn: "session: a page was not given back");
    }
}
