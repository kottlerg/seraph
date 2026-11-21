// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/image_cache.rs

//! The image objects procmgr shares between the instances of one binary
//! (services/procmgr/README.md § Image Sharing).
//!
//! procmgr seals the pages of a binary's segments that are not writable into
//! one memmgr memory object (`memmgr_labels::SEAL_OBJECT`) the first time a
//! demand-paged instance of it is created, and attaches the object shared to
//! that instance and every later one (`memmgr_labels::ATTACH_OBJECT`), each
//! over its own memmgr SEND, so each is charged the pages it attaches. The
//! frames are granted and sealed on the image store, a memmgr record procmgr
//! registers for them alone ([`register_store`]): a top-level budget node
//! outside the system reserve, with no max, so a seal never draws on the
//! reserve, and the object outlives the instance that sealed it. The
//! cache ([`process_table::image_share::ImageCache`]) keeps one object per
//! binary body while an instance attaches it; the last instance's teardown
//! releases it (`memmgr_labels::OBJECT_RELEASE`), and memmgr frees its
//! frames once no region attaches it.

use std::sync::{Mutex, OnceLock};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use process_table::image_share::{ImageCache, ImageKey, ImageRef, Inserted};

use crate::image::ImageBuffer;

/// The cached objects. Its holder makes no IPC call and takes no other lock.
static CACHE: Mutex<ImageCache> = Mutex::new(ImageCache::new());

/// Slot in procmgr's `CSpace` of the image store's memmgr SEND, set once at
/// startup; absent when memmgr refused the registration, and no image is
/// then shared.
static STORE: OnceLock<u64> = OnceLock::new();

/// Register the image store with memmgr over procmgr's own memmgr endpoint
/// `memmgr_ep`: a top-level budget node outside the system reserve, with no
/// max (`memmgr_labels::REGISTER_PROCESS`). Called once, before procmgr
/// serves a request; a refusal is logged, and every image is then loaded
/// private.
pub fn register_store(memmgr_ep: u64, ipc_buf: *mut u64)
{
    let budget = process_table::ChildBudget {
        phys: false,
        reserve: false,
        parent: 0,
        max: None,
        node_handle: false,
        charge: 0,
    };
    let store = crate::register_with_memmgr(memmgr_ep, &budget, ipc_buf);
    if store.cap == 0
    {
        std::os::seraph::log!(warn: "image store not registered; images load private");
        return;
    }
    let _ = STORE.set(store.cap);
}

/// One instance's reference to a cached object. Dropping it releases the
/// reference ([`release`]); [`Self::into_id`] hands it to the instance's
/// process entry, whose teardown releases it.
pub struct ImageGuard
{
    image: ImageRef,
    ipc_buf: *mut u64,
}

impl ImageGuard
{
    /// The reference's id in the cache, which the instance's process entry
    /// records.
    pub fn id(&self) -> u64
    {
        self.image.id
    }

    /// Slot in procmgr's `CSpace` of the object handle.
    pub fn handle(&self) -> u64
    {
        self.image.handle
    }

    /// The reference's id, for the instance's process entry, which now owns
    /// it.
    pub fn into_id(self) -> u64
    {
        core::mem::ManuallyDrop::new(self).image.id
    }
}

impl Drop for ImageGuard
{
    fn drop(&mut self)
    {
        release(self.image.id, self.ipc_buf);
    }
}

/// The object of the binary whose body `key` names, `pages` pages long: the
/// cached one, or else one sealed now on the image store from a buffer that
/// `fill` writes (zeroed first). `None` when no image store is registered,
/// or the object cannot be had: the grants are refused, take more runs than
/// one seal names, or the seal is refused. The caller then loads the image
/// private.
pub fn object_for(
    self_aspace: u64,
    key: &ImageKey,
    pages: u64,
    fill: impl FnOnce(&mut [u8]),
    ipc_buf: *mut u64,
) -> Option<ImageGuard>
{
    let &store = STORE.get()?;
    let cached = crate::lock(&CACHE).acquire(key);
    if let Some(image) = cached
    {
        // One body has one layout at a page-aligned bias; a mismatch drops
        // the reference just taken, and the image loads private.
        let guard = ImageGuard { image, ipc_buf };
        return (guard.image.pages == pages).then_some(guard);
    }
    let mut buffer = ImageBuffer::for_object(self_aspace, store, pages, ipc_buf).ok()?;
    let bytes = buffer.bytes_mut();
    bytes.fill(0);
    fill(bytes);
    let (handle, sealed) = buffer.seal().ok()?;
    if sealed != pages
    {
        release_object(handle, ipc_buf);
        return None;
    }
    let inserted = crate::lock(&CACHE).insert(*key, handle, pages);
    match inserted
    {
        Some(Inserted::New(image)) => Some(ImageGuard { image, ipc_buf }),
        // A concurrent create of the same binary sealed first: take its
        // object and release this one.
        Some(Inserted::Existing(image)) =>
        {
            release_object(handle, ipc_buf);
            Some(ImageGuard { image, ipc_buf })
        }
        None =>
        {
            release_object(handle, ipc_buf);
            None
        }
    }
}

/// A SEND copy of the handle of the object the reference `id` names (`0` for
/// none), taken under the cache's lock so a release meanwhile cannot delete
/// the handle first, and the key of its binary's body: for `SNAPSHOT`, which
/// names the image (`ipc::procmgr_snapshot::Header::image`). `None` when
/// the cache holds no such reference or the copy fails.
pub fn snapshot_image(id: u64) -> Option<(u64, ImageKey)>
{
    if id == 0
    {
        return None;
    }
    let cache = crate::lock(&CACHE);
    let copy = cache.find(id).and_then(|(key, handle)| {
        let copy = syscall::cap_derive(handle, syscall::RIGHTS_EP_SEND).ok()?;
        Some((copy, key))
    });
    drop(cache);
    copy
}

/// Drop the reference `id` (`0` for none): the last reference releases the
/// object.
pub fn release(id: u64, ipc_buf: *mut u64)
{
    if id == 0
    {
        return;
    }
    let last = crate::lock(&CACHE).release(id);
    if let Some(handle) = last
    {
        release_object(handle, ipc_buf);
    }
}

/// Drop the object handle state on memmgr (`OBJECT_RELEASE`, sent on the
/// handle) and delete the handle. memmgr frees the frames once no region
/// attaches the object.
fn release_object(handle: u64, ipc_buf: *mut u64)
{
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    let _ = unsafe {
        ipc::ipc_call(
            handle,
            &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
            ipc_buf,
        )
    };
    let _ = syscall::cap_delete(handle);
}

/// Attach `pages` pages of the object `handle` names, from its page
/// `first_page`, shared at `va` in the child whose memmgr SEND is
/// `child_memmgr` (`memmgr_labels::ATTACH_OBJECT`), executable when
/// `executable` is set and read-only otherwise. The child is charged the
/// pages; nothing is mapped until its first fault there.
///
/// # Errors
/// `OUT_OF_MEMORY` when the handle cannot be copied, or memmgr refuses the
/// attachment for the child's budget, its promise or its metadata (`LIMIT`,
/// `OUT_OF_MEMORY_BEST_EFFORT`, `QUOTA`) or the call fails; `MAP_FAILED`
/// for any other refusal.
pub fn attach(
    child_memmgr: u64,
    handle: u64,
    va: u64,
    pages: u64,
    first_page: u64,
    executable: Executable,
    ipc_buf: *mut u64,
) -> Result<(), u64>
{
    let copy = syscall::cap_derive(handle, syscall::RIGHTS_EP_SEND)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let prot = match executable
    {
        Executable::Yes => syscall::MAP_READ | syscall::MAP_EXECUTABLE,
        Executable::No => syscall::MAP_READ,
    };
    let msg = IpcMessage::builder(memmgr_labels::ATTACH_OBJECT)
        .word(0, va)
        .word(1, pages.saturating_mul(syscall_abi::PAGE_SIZE))
        .word(2, prot)
        .word(3, first_page)
        .word(4, 0)
        .cap(copy)
        .build();
    // SAFETY: `ipc_buf` is the calling thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(child_memmgr, &msg, ipc_buf) };
    // A call that failed before the transfer left the copy here; deleting a
    // moved slot is harmless.
    let _ = syscall::cap_delete(copy);
    match reply.map(|r| r.label)
    {
        Ok(memmgr_errors::SUCCESS) => Ok(()),
        Ok(memmgr_errors::INVALID_ARGUMENT | memmgr_errors::UNAUTHORIZED) =>
        {
            Err(procmgr_errors::MAP_FAILED)
        }
        Ok(_) | Err(_) => Err(procmgr_errors::OUT_OF_MEMORY),
    }
}

/// Whether an attachment is executable: its segment's `PF_X`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Executable
{
    /// Mapped readable and executable.
    Yes,
    /// Mapped read-only.
    No,
}
