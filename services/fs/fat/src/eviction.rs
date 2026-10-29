// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/eviction.rs

//! Eviction worker for the FAT page cache.
//!
//! When `read_memory_at_slot` cannot acquire a cache slot (every slot
//! has `refcount > 0`), main scans the per-file outstanding-page
//! tables for a page not already queued, marks it queued, enqueues an
//! [`EvictReq`] for it, and replies `IO_ERROR`. The eviction worker
//! pops the request and first checks that the page is still
//! outstanding, skipping it if the client's synchronous release or
//! `FS_CLOSE` already cleaned it up. When the client delivered a
//! release SEND, the worker sends `FS_RELEASE_MEMORY`
//! on its own derived copy of it and waits up to [`RELEASE_TIMEOUT_MS`]
//! for `FS_RELEASE_ACK`; with no SEND, or when it cannot derive the copy
//! or spawn the watchdog, it sends nothing. Either way the worker then
//! takes the per-file outstanding-page entry and, if no other path has
//! cleaned it up meanwhile, `cap_revoke`s the per-cookie ancestor cap,
//! drops it, and decrements the cache slot's refcount. An ack means
//! the client has already unmapped the page. The revoke invalidates
//! the client's derived cap but unmaps nothing, and the released slot
//! may be refilled with other data, so a client that never unmapped
//! keeps reading whatever the cache loads there next (#516).
//!
//! The watchdog is fully userspace. `ipc_call` has no kernel-side
//! timeout, so the worker spawns a child thread to issue the call
//! and uses `Condvar::wait_timeout` to bound the wait. On timeout
//! the orphaned child remains blocked in `ipc_call` until the
//! client eventually replies (or forever, if the client never
//! does); a dedicated channel-state field ensures the late reply
//! is silently discarded rather than racing the parent's cleanup.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use ipc::{IpcMessage, fs_labels};

use crate::cache::PageCache;
use crate::file::{MAX_OPEN_FILES, MAX_OUTSTANDING, OpenFile, find_by_badge};

/// Cooperative release watchdog: how long the worker waits for the
/// client's reply before revoking the ancestor cap anyway. The worker
/// revokes after a reply too; an `FS_RELEASE_ACK` only tells it the
/// client unmapped in time.
pub const RELEASE_TIMEOUT_MS: u64 = 100;

/// Hard upper bound on queued eviction requests. At
/// `MAX_OPEN_FILES * MAX_OUTSTANDING` every outstanding page across
/// the entire fs could be in-flight at once; the cache slot count
/// matches, so the queue cannot overflow under correct accounting.
const MAX_PENDING_EVICTIONS: usize = MAX_OPEN_FILES * MAX_OUTSTANDING;

/// One queued eviction: the outstanding page as it stood when queued.
/// The worker checks it against the open-file table before the
/// cooperative round-trip and again before the cleanup, since the main
/// thread may have cleaned the page up meanwhile.
#[derive(Clone, Copy)]
pub struct EvictReq
{
    /// `OpenFile.badge` identifying which file this entry belongs
    /// to. Used at cleanup time to clear the matching
    /// outstanding-page slot.
    pub file_badge: u64,
    /// Caller-visible cookie originally returned in
    /// `FS_READ_MEMORY`. Carried in `FS_RELEASE_MEMORY`'s `data[0]`
    /// and used to disambiguate cleanup against `file_badge`.
    pub cookie: u64,
    /// Cache slot whose refcount is held by this entry.
    pub slot_idx: usize,
    /// Per-cookie ancestor cap derived under the cache slot's
    /// memory cap. Revoking it kills only the caller's child cap.
    pub ancestor_cap: u32,
}

pub struct EvictionState
{
    queue: Mutex<VecDeque<EvictReq>>,
    cv: Condvar,
}

impl EvictionState
{
    pub fn new() -> Self
    {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(MAX_PENDING_EVICTIONS)),
            cv: Condvar::new(),
        }
    }

    /// Submit `req` to the eviction worker. Wakes the worker.
    ///
    /// On overflow the request is dropped — the queue is sized so
    /// `MAX_PENDING_EVICTIONS` covers every outstanding page across
    /// the fs under correct accounting, so a full queue here means
    /// the per-slot refcount has gone wrong. Log the dropped
    /// request so the invariant violation is observable.
    pub fn enqueue(&self, req: EvictReq)
    {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if q.len() < MAX_PENDING_EVICTIONS
        {
            q.push_back(req);
            self.cv.notify_one();
        }
        else
        {
            std::os::seraph::log!(
                "eviction enqueue overflow: dropped req (badge={}, cookie={}, slot={}, qlen={})",
                req.file_badge,
                req.cookie,
                req.slot_idx,
                q.len()
            );
        }
    }
}

/// Eviction worker entry point. Runs forever.
///
/// The spawning closure owns `Arc` clones of the `EvictionState` and the
/// open-file table and lends them here; since this never returns, they
/// stay alive for the lifetime of the fs process.
pub fn worker_loop(
    state: &EvictionState,
    files: &Mutex<[OpenFile; MAX_OPEN_FILES]>,
    cache: &'static PageCache,
) -> !
{
    loop
    {
        let req = pop_blocking(state);
        // The client's synchronous FS_RELEASE_MEMORY and FS_CLOSE clean an
        // outstanding page up on the main thread, before or during the
        // cooperative round-trip. A page already gone is skipped.
        let Some(endpoint) = live_release_endpoint(files, &req)
        else
        {
            continue;
        };
        let outcome = match endpoint
        {
            Endpoint::Copy(cap) => cooperative_release(cap, req.cookie),
            Endpoint::NoSend => Release::NoEndpoint,
            Endpoint::DeriveFailed => Release::DeriveFailed,
        };
        // Whichever path takes the entry out of the open-file table owns
        // the cleanup: revoke the ancestor (invalidates the client's derived
        // child cap), delete it from fs's CSpace, and drop the cache-slot
        // refcount, once.
        let owned = take_outstanding(files, &req);
        if owned
        {
            let _ = syscall::cap_revoke_all(req.ancestor_cap);
            let _ = syscall::cap_delete(req.ancestor_cap);
            cache.release_slot(req.slot_idx);
        }
        log_outcome(&req, outcome, owned);
    }
}

fn pop_blocking(state: &EvictionState) -> EvictReq
{
    let mut q = state.queue.lock().unwrap_or_else(PoisonError::into_inner);
    loop
    {
        if let Some(req) = q.pop_front()
        {
            return req;
        }
        q = state.cv.wait(q).unwrap_or_else(PoisonError::into_inner);
    }
}

/// Log a non-ack release outcome, and whether the worker revoked the page
/// or found it already cleaned up by the client's release or `FS_CLOSE`.
fn log_outcome(req: &EvictReq, outcome: Release, owned: bool)
{
    let what = match outcome
    {
        Release::Acked => return,
        Release::NoEndpoint => "no release endpoint",
        Release::DeriveFailed => "release SEND derive failed; no FS_RELEASE_MEMORY sent",
        Release::Refused(_) => "FS_RELEASE_MEMORY refused",
        Release::CallFailed => "FS_RELEASE_MEMORY call failed",
        Release::SpawnFailed => "release watchdog spawn failed; no FS_RELEASE_MEMORY sent",
        Release::TimedOut => "FS_RELEASE_MEMORY timeout",
    };
    let label = if let Release::Refused(l) = outcome
    {
        l
    }
    else
    {
        0
    };
    let action = if owned
    {
        "revoked parent cap"
    }
    else
    {
        "page already released"
    };
    std::os::seraph::log!(
        "{} (label={}); {} (badge={}, slot={})",
        what,
        label,
        action,
        req.file_badge,
        req.slot_idx
    );
}

/// How a cooperative release round-trip ended.
#[derive(Clone, Copy)]
enum Release
{
    /// The client replied `FS_RELEASE_ACK` in time: it has unmapped the page.
    Acked,
    /// The client replied in time with another label.
    Refused(u64),
    /// The `ipc_call` to the client's release endpoint failed.
    CallFailed,
    /// No reply within `RELEASE_TIMEOUT_MS`.
    TimedOut,
    /// The watchdog thread could not be spawned, so nothing was sent.
    SpawnFailed,
    /// The client delivered no release endpoint, so none was sent.
    NoEndpoint,
    /// The worker could not derive its copy of the client's release SEND,
    /// so none was sent.
    DeriveFailed,
}

/// Send `FS_RELEASE_MEMORY` for `cookie` on `endpoint`, a derived copy of
/// the client's release SEND that this call consumes, and wait up to
/// `RELEASE_TIMEOUT_MS` for its reply.
///
/// `ipc_call` has no kernel-side timeout, so the synchronous IPC
/// runs on a child thread and the parent waits with
/// `Condvar::wait_timeout`. On timeout the orphaned child is
/// left blocked in `ipc_call`; if the client eventually replies
/// the child observes the channel state already set and discards
/// its own write. A truly hung client leaks the child thread,
/// which is the documented cost of cooperative release without
/// a kernel-side IPC-cancellation primitive.
fn cooperative_release(endpoint: u32, cookie: u64) -> Release
{
    let chan: Arc<(Mutex<Option<Release>>, Condvar)> = Arc::new((Mutex::new(None), Condvar::new()));
    let chan_child = chan.clone();
    let ep = endpoint;

    let spawned = thread::Builder::new()
        .name("fatfs-release-watchdog".into())
        .spawn(move || {
            let ipc_buf = std::os::seraph::current_ipc_buf();
            let msg = IpcMessage::builder(fs_labels::FS_RELEASE_MEMORY)
                .word(0, cookie)
                .build();
            // SAFETY: `ipc_buf` is the registered IPC buffer for this
            // thread (set in `std::thread`'s entry trampoline).
            let result = unsafe { ipc::ipc_call(ep, &msg, ipc_buf) };
            let _ = syscall::cap_delete(ep);
            let outcome = match result
            {
                Ok(reply) if reply.label == fs_labels::FS_RELEASE_ACK => Release::Acked,
                Ok(reply) => Release::Refused(reply.label),
                Err(_) => Release::CallFailed,
            };

            let mut st = chan_child.0.lock().unwrap_or_else(PoisonError::into_inner);
            if st.is_none()
            {
                *st = Some(outcome);
            }
            chan_child.1.notify_all();
        });
    if spawned.is_err()
    {
        let _ = syscall::cap_delete(ep);
        return Release::SpawnFailed;
    }

    let timeout = Duration::from_millis(RELEASE_TIMEOUT_MS);
    let mut st = chan.0.lock().unwrap_or_else(PoisonError::into_inner);
    loop
    {
        if st.is_some()
        {
            break;
        }
        let (next_st, wr) = chan
            .1
            .wait_timeout(st, timeout)
            .unwrap_or_else(PoisonError::into_inner);
        st = next_st;
        if wr.timed_out()
        {
            break;
        }
    }
    // Mark as given up so a late child reply skips its write rather than
    // racing the parent's cleanup.
    *st.get_or_insert(Release::TimedOut)
}

/// The release SEND the worker sends a page's `FS_RELEASE_MEMORY` on.
enum Endpoint
{
    /// The worker's own derived copy of the client's release SEND.
    Copy(u32),
    /// The client delivered no release SEND.
    NoSend,
    /// The client delivered one, but the worker could not derive its copy.
    DeriveFailed,
}

/// Under the open-file lock, check that `req`'s outstanding page is still
/// in the table (same file, cookie, cache slot, and ancestor cap) and return
/// a derived copy of its file's release SEND. The copy is the worker's own,
/// so an `FS_CLOSE` that deletes the slot's SEND meanwhile cannot free or
/// reuse the slot the worker calls on. `None` means the page was already
/// cleaned up.
fn live_release_endpoint(
    files: &Mutex<[OpenFile; MAX_OPEN_FILES]>,
    req: &EvictReq,
) -> Option<Endpoint>
{
    let files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
    let file = &files_g[find_by_badge(&files_g, req.file_badge)?];
    let present = file.outstanding.iter().flatten().any(|e| {
        e.cookie == req.cookie && e.slot_idx == req.slot_idx && e.ancestor_cap == req.ancestor_cap
    });
    if !present
    {
        return None;
    }
    if file.release_endpoint_cap == 0
    {
        return Some(Endpoint::NoSend);
    }
    Some(
        syscall::cap_derive(file.release_endpoint_cap, syscall::RIGHTS_EP_SEND)
            .map_or(Endpoint::DeriveFailed, Endpoint::Copy),
    )
}

/// Take `req`'s outstanding-page entry out of the open-file table, under
/// the table lock the main thread's release and close paths hold. Returns
/// whether the entry was still there (same file, cookie, cache slot, and
/// ancestor cap), in which case the caller owns its cleanup; `false` means
/// another path already cleaned it up.
fn take_outstanding(files: &Mutex<[OpenFile; MAX_OPEN_FILES]>, req: &EvictReq) -> bool
{
    let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(idx) = find_by_badge(&files_g, req.file_badge)
    else
    {
        return false;
    };
    for slot in &mut files_g[idx].outstanding
    {
        if let Some(entry) = slot
            && entry.cookie == req.cookie
            && entry.slot_idx == req.slot_idx
            && entry.ancestor_cap == req.ancestor_cap
        {
            *slot = None;
            return true;
        }
    }
    false
}
