// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Per-process release-handler thread for the seraph fs frame protocol.
//!
//! The fs driver evicts cached pages by sending `FS_RELEASE_FRAME` on
//! a tokened SEND derived from the per-process release endpoint owned
//! by this module. The SEND is transferred to the driver in `caps[0]`
//! of the first [`fs_labels::FS_READ_FRAME`] request for each opened
//! file (see [`super::File::read_frame`]); from that point on the
//! driver's eviction worker can route cooperative releases here. The
//! handler removes the matching outstanding mapping from the
//! per-`File` registry (race-safe against the local read path's
//! immediate-release cleanup), unmaps the page, drops the frame cap,
//! returns the VA to the reservation arena, and replies
//! [`fs_labels::FS_RELEASE_ACK`].
//!
//! The endpoint and the handler thread are created lazily on the first
//! [`super::File::open`] call; until then the cost is one
//! `OnceLock<ReleaseState>` load.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::collections::BTreeMap;
use crate::io;
use crate::sync::atomic::{AtomicU64, Ordering};
use crate::sync::{Arc, Mutex, OnceLock, PoisonError};
use crate::thread;
use crate::vec::Vec;

use ipc::{IpcMessage, fs_labels};

use crate::sys::reserve as pal_reserve;
use crate::sys::reserve::ReservedRange;

/// One outstanding cache-page mapping the local read path has obtained
/// from the fs driver via `FS_READ_FRAME`. Carries everything the
/// release path (local or driver-initiated) needs to unmap and free.
pub(super) struct OutstandingMapping
{
    pub cookie: u64,
    pub range: ReservedRange,
    pub frame_cap: u32,
}

/// Per-`File` registration entry held by the release handler under its
/// registry lock. `Arc`-cloned out of the registry by both the handler
/// and the local read/drop paths; the small inner Vec holds the live
/// outstanding mappings keyed by cookie.
pub(super) struct FileEntry
{
    pub mappings: Mutex<Vec<OutstandingMapping>>,
}

/// Process-wide release state. Created exactly once on the first
/// [`super::File::open`] call; held forever for the process lifetime.
pub(super) struct ReleaseState
{
    /// Untokened endpoint cap owned by this process; tokened SENDs
    /// derived from it would live in fs's CSpace once a delivery
    /// channel exists. Revoking this cap (which we never do) would
    /// tear down every fs-side derived child atomically.
    release_ep: u32,
    registry: Mutex<BTreeMap<u64, Arc<FileEntry>>>,
    next_token: AtomicU64,
    /// Process aspace cap, captured at init for the handler's
    /// `mem_unmap` calls. Equal to `StartupInfo::self_aspace`.
    aspace: u32,
}

static STATE: OnceLock<ReleaseState> = OnceLock::new();

/// Lazy-init: ensure the release endpoint exists and the handler thread
/// is running. Returns the singleton state. Subsequent calls hit the
/// `OnceLock` fast path.
pub(super) fn ensure_started() -> io::Result<&'static ReleaseState>
{
    if let Some(s) = STATE.get()
    {
        return Ok(s);
    }

    let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
        io::Error::other("seraph fs: startup info not installed")
    })?;
    let aspace = info.self_aspace;

    let slab = crate::sys::alloc::seraph::object_slab_acquire(88).ok_or_else(|| {
        io::Error::other("seraph fs: object_slab_acquire (release ep) failed")
    })?;
    let release_ep = match syscall::cap_create_endpoint(slab)
    {
        Ok(c) => c,
        Err(_) =>
        {
            return Err(io::Error::other(
                "seraph fs: cap_create_endpoint (release) failed",
            ));
        }
    };

    // get_or_init runs the closure under a mutex, so only one
    // initialiser publishes to STATE. If we lose the race, our endpoint
    // becomes orphaned — drop it before returning.
    let mut won = false;
    let s = STATE.get_or_init(|| {
        won = true;
        ReleaseState {
            release_ep,
            registry: Mutex::new(BTreeMap::new()),
            next_token: AtomicU64::new(1),
            aspace,
        }
    });

    if won
    {
        // Spawn the handler. Do this only on the winning path so we
        // never run two handlers on the same endpoint.
        thread::Builder::new()
            .name("seraph-fs-release".into())
            .spawn(handler_main)
            .map_err(|_| io::Error::other("seraph fs: release-handler spawn failed"))?;
    }
    else
    {
        let _ = syscall::cap_delete(release_ep);
    }

    Ok(s)
}

/// Read the singleton release state if it has been initialised. Used by
/// `File::drop` to avoid spawning the handler if no `File::open` ever
/// ran (e.g. failure during `OpenOptions` validation).
pub(super) fn state() -> Option<&'static ReleaseState>
{
    STATE.get()
}

/// Untokened endpoint cap the per-`File` SEND derivation hangs off.
pub(super) fn release_endpoint(state: &ReleaseState) -> u32
{
    state.release_ep
}

/// Allocate a fresh non-zero per-`File` token.
pub(super) fn allocate_token(state: &ReleaseState) -> u64
{
    let mut t = state.next_token.fetch_add(1, Ordering::Relaxed);
    while t == 0
    {
        t = state.next_token.fetch_add(1, Ordering::Relaxed);
    }
    t
}

/// Register a `File` with the handler, returning its `FileEntry`.
pub(super) fn register(state: &ReleaseState, token: u64) -> Arc<FileEntry>
{
    let entry = Arc::new(FileEntry {
        mappings: Mutex::new(Vec::new()),
    });
    let mut reg = state
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    reg.insert(token, entry.clone());
    entry
}

/// Remove a `File`'s registration. After this call the handler cannot
/// dispatch any further releases to the file; subsequent
/// `FS_RELEASE_FRAME` arrivals look up an empty slot and ack-without-act.
pub(super) fn unregister(state: &ReleaseState, token: u64) -> Option<Arc<FileEntry>>
{
    let mut reg = state
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    reg.remove(&token)
}

/// Add an outstanding mapping to a `FileEntry`. Called by `File::read`
/// after a successful `FS_READ_FRAME` so a forced release can find it.
pub(super) fn add_mapping(entry: &FileEntry, m: OutstandingMapping)
{
    let mut maps = entry.mappings.lock().unwrap_or_else(PoisonError::into_inner);
    maps.push(m);
}

/// Take a mapping by cookie. Returns `Some` to whichever of the local
/// release path or the handler thread observes the entry first; the
/// loser sees `None` and skips its cleanup. Idempotent.
pub(super) fn take_mapping(entry: &FileEntry, cookie: u64) -> Option<OutstandingMapping>
{
    let mut maps = entry.mappings.lock().unwrap_or_else(PoisonError::into_inner);
    let idx = maps.iter().position(|m| m.cookie == cookie)?;
    Some(maps.swap_remove(idx))
}

/// Drain every outstanding mapping at file-close time so `File::drop`
/// can unmap each one. The registry entry is removed separately by the
/// caller via [`unregister`].
pub(super) fn drain_mappings(entry: &FileEntry) -> Vec<OutstandingMapping>
{
    let mut maps = entry.mappings.lock().unwrap_or_else(PoisonError::into_inner);
    core::mem::take(&mut *maps)
}

/// Local cleanup of a single mapping by cookie. Called after a
/// successful synchronous `FS_RELEASE_FRAME` round-trip from
/// `File::read` to release the resources the read held briefly. If the
/// handler thread already cleaned up this cookie (rare but possible
/// during a contended eviction), this is a no-op.
pub(super) fn release_one_local(entry: &FileEntry, aspace: u32, cookie: u64)
{
    let Some(m) = take_mapping(entry, cookie)
    else
    {
        return;
    };
    let _ = syscall::mem_unmap(aspace, m.range.va_start(), m.range.page_count());
    let _ = syscall::cap_delete(m.frame_cap);
    pal_reserve::unreserve_pages(m.range);
}

fn handler_main()
{
    let state = match STATE.get()
    {
        Some(s) => s,
        None => return,
    };
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        // The thread trampoline failed to register an IPC buffer; we
        // cannot service receive-and-reply traffic. Park instead of
        // spinning.
        loop
        {
            let _ = syscall::thread_yield();
        }
    }

    loop
    {
        // SAFETY: `ipc_buf` is the registered IPC buffer for this
        // thread (set by the std::thread trampoline before invoking us).
        let msg = match unsafe { ipc::ipc_recv(state.release_ep, ipc_buf) }
        {
            Ok(m) => m,
            Err(_) => continue,
        };

        if msg.label != fs_labels::FS_RELEASE_FRAME
        {
            // Unknown opcode — reply with label zero (cheap empty ack)
            // so the sender's blocking ipc_call returns and we don't
            // wedge the endpoint queue.
            let reply = IpcMessage::new(0);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            continue;
        }

        let token = msg.token;
        let cookie = msg.word(0);

        // Snapshot the FileEntry under the registry lock, then drop the
        // lock before doing the unmap work — the local release path may
        // need to register a fresh mapping concurrently.
        let entry = {
            let reg = state
                .registry
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            reg.get(&token).cloned()
        };

        if let Some(entry) = entry
        {
            release_one_local(entry.as_ref(), state.aspace, cookie);
        }

        let reply = IpcMessage::new(fs_labels::FS_RELEASE_ACK);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}
