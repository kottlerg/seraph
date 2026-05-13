// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/eviction.rs

//! Eviction worker for the FAT page cache.
//!
//! When `handle_read_frame` cannot acquire a cache slot (every slot
//! has `refcount > 0`), main scans the per-file outstanding-page
//! tables for a candidate, enqueues an [`EvictReq`], and replies
//! `IO_ERROR`. The eviction worker pops the request, sends
//! `FS_RELEASE_FRAME` on the client's release endpoint, and waits
//! up to [`RELEASE_TIMEOUT_MS`] for `FS_RELEASE_ACK`. On ack the
//! cache slot is reclaimed cooperatively; on timeout the worker
//! `cap_revoke`s the per-cookie ancestor cap and the client's
//! mapping is torn down by the kernel — the client takes a
//! `USERSPACE FAULT` on the next access. Either path then drops
//! the ancestor cap, decrements the cache slot's refcount, and
//! clears the per-file outstanding-page entry.
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
use crate::file::{MAX_OPEN_FILES, MAX_OUTSTANDING, OpenFile, find_by_token};

/// Cooperative release watchdog: the client must reply with
/// `FS_RELEASE_ACK` within this many milliseconds, else the worker
/// hard-revokes.
pub const RELEASE_TIMEOUT_MS: u64 = 100;

/// Hard upper bound on queued eviction requests. At
/// `MAX_OPEN_FILES * MAX_OUTSTANDING` every outstanding page across
/// the entire fs could be in-flight at once; the cache slot count
/// matches, so the queue cannot overflow under correct accounting.
const MAX_PENDING_EVICTIONS: usize = MAX_OPEN_FILES * MAX_OUTSTANDING;

/// One queued eviction. Carries everything the worker needs to
/// drive the cooperative round-trip and the cleanup that follows
/// without touching the open-file table for read.
#[derive(Clone, Copy)]
pub struct EvictReq
{
    /// `OpenFile.token` identifying which file this entry belongs
    /// to. Used at cleanup time to clear the matching
    /// outstanding-page slot.
    pub file_token: u64,
    /// Caller-visible cookie originally returned in
    /// `FS_READ_FRAME`. Carried in `FS_RELEASE_FRAME`'s `data[0]`
    /// and used to disambiguate cleanup against `file_token`.
    pub cookie: u64,
    /// Cache slot whose refcount is held by this entry.
    pub slot_idx: usize,
    /// Per-cookie ancestor cap derived under the cache slot's
    /// frame cap. Revoking it kills only the caller's child cap.
    pub ancestor_cap: u32,
    /// SEND cap on the client's release endpoint, addressed by
    /// `FS_RELEASE_FRAME`. Zero means the client did not provide
    /// one, in which case the worker skips straight to hard-revoke.
    pub release_endpoint_cap: u32,
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
                "eviction enqueue overflow: dropped req (token={}, cookie={}, slot={}, qlen={})",
                req.file_token,
                req.cookie,
                req.slot_idx,
                q.len()
            );
        }
    }
}

/// Eviction worker entry point. Runs forever.
///
/// Takes ownership of its `Arc` clones so the worker keeps the
/// `EvictionState` and open-file table alive for as long as it
/// runs (i.e. for the lifetime of the fs process); main hands
/// over its clones at spawn.
#[allow(clippy::needless_pass_by_value)]
pub fn worker_loop(
    state: Arc<EvictionState>,
    files: Arc<Mutex<[OpenFile; MAX_OPEN_FILES]>>,
    cache: &'static PageCache,
) -> !
{
    loop
    {
        let req = pop_blocking(&state);
        let acked = if req.release_endpoint_cap != 0
        {
            cooperative_release(&req)
        }
        else
        {
            // No client release endpoint — go straight to
            // hard-revoke. Plan-documented "skip cooperative"
            // path for clients that elected not to participate.
            false
        };
        if !acked
        {
            std::os::seraph::log!(
                "FS_RELEASE_FRAME timeout, hard-revoking parent cap (token={}, slot={})",
                req.file_token,
                req.slot_idx
            );
        }
        // Cleanup is identical for cooperative and forced paths:
        // revoke the ancestor (kills the client's derived child
        // cap and tears down its mapping), delete the ancestor
        // from fs's CSpace, drop the cache-slot refcount, and
        // clear the per-file outstanding-page entry so a later
        // close does not double-decrement.
        let _ = syscall::cap_revoke(req.ancestor_cap);
        let _ = syscall::cap_delete(req.ancestor_cap);
        cache.release_slot(req.slot_idx);
        clear_outstanding(&files, req.file_token, req.cookie);
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

/// Send `FS_RELEASE_FRAME` to the client and wait up to
/// `RELEASE_TIMEOUT_MS` for the ack. Returns `true` iff the
/// client replied with `FS_RELEASE_ACK` in time.
///
/// `ipc_call` has no kernel-side timeout, so the synchronous IPC
/// runs on a child thread and the parent waits with
/// `Condvar::wait_timeout`. On timeout the orphaned child is
/// left blocked in `ipc_call`; if the client eventually replies
/// the child observes the channel state already set and discards
/// its own write. A truly hung client leaks the child thread,
/// which is the documented cost of cooperative release without
/// a kernel-side IPC-cancellation primitive.
fn cooperative_release(req: &EvictReq) -> bool
{
    let chan: Arc<(Mutex<Option<bool>>, Condvar)> = Arc::new((Mutex::new(None), Condvar::new()));
    let chan_child = chan.clone();
    let ep = req.release_endpoint_cap;
    let cookie = req.cookie;

    let _spawn = thread::Builder::new()
        .name("fatfs-release-watchdog".into())
        .spawn(move || {
            let ipc_buf = std::os::seraph::current_ipc_buf();
            let msg = IpcMessage::builder(fs_labels::FS_RELEASE_FRAME)
                .word(0, cookie)
                .build();
            // SAFETY: `ipc_buf` is the registered IPC buffer for this
            // thread (set in `std::thread`'s entry trampoline).
            let result = unsafe { ipc::ipc_call(ep, &msg, ipc_buf) };
            let acked = matches!(&result, Ok(reply) if reply.label == fs_labels::FS_RELEASE_ACK);

            let mut st = chan_child.0.lock().unwrap_or_else(PoisonError::into_inner);
            if st.is_none()
            {
                *st = Some(acked);
            }
            chan_child.1.notify_all();
        });

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
    let acked = matches!(*st, Some(true));
    if st.is_none()
    {
        // Mark as given up so a late child reply skips its write
        // rather than racing the parent's cleanup.
        *st = Some(false);
    }
    acked
}

fn clear_outstanding(files: &Mutex<[OpenFile; MAX_OPEN_FILES]>, file_token: u64, cookie: u64)
{
    let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(idx) = find_by_token(&files_g, file_token)
    else
    {
        return;
    };
    for slot in &mut files_g[idx].outstanding
    {
        if let Some(entry) = slot
            && entry.cookie == cookie
        {
            *slot = None;
            break;
        }
    }
}
