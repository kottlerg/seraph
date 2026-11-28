// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/eviction.rs

//! Eviction worker for the FAT page cache.
//!
//! When a request cannot acquire a cache slot (every slot has
//! `refcount > 0`), whether for a memory-cap read's page or for a FAT,
//! directory, or inline-read sector, main scans the pages the opens hold
//! for one not already queued, marks it queued, and enqueues an
//! [`EvictReq`] for it (`relieve_pressure`, `Opens::pick_eviction_candidate`);
//! the request is answered `IO_ERROR` and the client retries. The eviction
//! worker pops the request and first checks that the page is still
//! outstanding, skipping it if the client's synchronous release or the
//! release of its open already cleaned it up. An open is released, its
//! pages with it, by `FS_CLOSE`, the removal of the open's node, the sweep
//! of opens whose client is gone, the end of the open's session, and an
//! `FS_OPEN` whose reply failed (`crate::file::Opens`). When the open that read the page
//! carried a release SEND on its `FS_OPEN`, the worker sends
//! `FS_RELEASE_MEMORY` on its own derived copy of that open's SEND, so
//! each page's release reaches the client that read it, and waits up to
//! [`RELEASE_TIMEOUT_MS`]
//! for `FS_RELEASE_ACK`; with no SEND, or when it cannot derive the copy
//! or no watchdog is idle, it sends nothing. Either way the worker then
//! takes the per-open outstanding-page entry and, if no other path has
//! cleaned it up meanwhile, `cap_revoke`s the per-cookie ancestor cap,
//! drops it, and decrements the cache slot's refcount. An ack means
//! the client has already unmapped the page. The revoke invalidates
//! the client's derived cap but unmaps nothing.
//!
//! Releasing the slot does not make it refillable. Every path that drops a
//! handed-out page's slot reference revokes the per-cookie ancestor first:
//! this worker, the client's synchronous `FS_RELEASE_MEMORY`, and the
//! release of the page's open. The order before reuse is revoke, then count, then reuse.
//! The cache's victim pick revokes every derivation of the slot's cap
//! again, so no holder can map the page anew, and only then reads the
//! page's mapping count. It refills the page only when the cache's own
//! mapping is the only one left. A page a client still maps is quarantined
//! instead, never refilled (`cache` module docs § Reuse of a page a client
//! mapped).
//!
//! The watchdog is fully userspace. `ipc_call` has no kernel-side
//! timeout, so the worker hands the call to a watchdog thread and uses
//! `Condvar::wait_timeout_while` to bound the wait. On timeout the watchdog
//! remains blocked in `ipc_call` until the client eventually replies (or
//! forever, if the client never does); its slot's state marks the call
//! given up, so the late reply is silently discarded rather than racing
//! the worker's cleanup. The [`MAX_WATCHDOGS`] watchdog threads are
//! started before the driver serves ([`start_watchdogs`]) and serve one
//! call at a time each, since a release runs when memory is short and a
//! spawn then would take a thread's pages from memmgr: while all of them
//! are still blocked on clients that have not replied, a release sends
//! nothing and goes straight to the revoke, so a client that never replies
//! costs the fs a bounded number of threads. Releasing the blocked calls
//! themselves needs an IPC cancellation the kernel does not offer (#31).

use std::collections::VecDeque;
use std::os::seraph::thread::BuilderExt;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use ipc::{IpcMessage, fs_labels};

use namespace_protocol::OpenRef;

use crate::cache::PageCache;
use crate::file::{Opens, OutstandingPage};

/// Cooperative release watchdog: how long the worker waits for the
/// client's reply before revoking the ancestor cap anyway. The worker
/// revokes after a reply too; an `FS_RELEASE_ACK` only tells it the
/// client unmapped in time.
pub const RELEASE_TIMEOUT_MS: u64 = 100;

/// Cooperative-release watchdog threads, started before the driver serves
/// (module docs). A tuning value that bounds no capacity: with every one of
/// them blocked on a client that has not replied, a release skips the
/// cooperative round trip, which is advisory, and revokes at once.
pub const MAX_WATCHDOGS: usize = 4;

/// One queued eviction: the outstanding page as it stood when queued.
/// The worker checks it against the opens before the
/// cooperative round-trip and again before the cleanup, since the main
/// thread may have cleaned the page up meanwhile.
#[derive(Clone, Copy)]
pub struct EvictReq
{
    /// The open this entry belongs to. Once the open is closed it names no
    /// open, since an open's id is never reused.
    pub open: OpenRef,
    /// Caller-visible cookie originally returned in
    /// `FS_READ_MEMORY`. Carried in `FS_RELEASE_MEMORY`'s `data[0]`
    /// and used to disambiguate cleanup against `open`.
    pub cookie: u64,
    /// Cache slot whose refcount is held by this entry.
    pub slot_idx: usize,
    /// Per-cookie ancestor cap derived under the cache slot's
    /// memory cap. Revoking it kills only the caller's child cap.
    pub ancestor_cap: u64,
}

impl EvictReq
{
    /// The request for `page`, held by `open`.
    pub const fn new(open: OpenRef, page: &OutstandingPage) -> Self
    {
        Self {
            open,
            cookie: page.cookie,
            slot_idx: page.slot_idx,
            ancestor_cap: page.ancestor_cap,
        }
    }
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
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }
    }

    /// Submit `req` to the eviction worker. Wakes the worker.
    ///
    /// The queue holds at most one request per outstanding page: the main
    /// thread marks a page queued before it enqueues it and never queues it
    /// again, so the queue is bounded by the pages clients hold, not by a
    /// constant. A request the heap cannot hold is dropped and logged; its
    /// page stays outstanding until the client releases it or closes.
    pub fn enqueue(&self, req: EvictReq)
    {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        if q.try_reserve(1).is_ok()
        {
            q.push_back(req);
            drop(q);
            self.cv.notify_one();
        }
        else
        {
            drop(q);
            std::os::seraph::log!(
                warn: "eviction enqueue: no memory; dropped req (open={:?}, cookie={}, slot={})",
                req.open,
                req.cookie,
                req.slot_idx
            );
        }
    }
}

/// Eviction worker entry point. Runs forever.
///
/// The spawning closure owns `Arc` clones of the `EvictionState` and the
/// opens and lends them here; since this never returns, they stay alive for
/// the lifetime of the fs process.
pub fn worker_loop(state: &EvictionState, opens: &Mutex<Opens>, cache: &'static PageCache) -> !
{
    loop
    {
        let req = pop_blocking(state);
        // The client's synchronous FS_RELEASE_MEMORY and the release of its
        // open clean an outstanding page up on the main thread, before or during the
        // cooperative round-trip. A page already gone is skipped.
        let Some(endpoint) = live_release_endpoint(opens, &req)
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
        // Whichever path takes the entry off its open owns
        // the cleanup: revoke the ancestor (invalidates the client's derived
        // child cap), delete it from fs's CSpace, and drop the cache-slot
        // refcount, once.
        let owned = take_outstanding(opens, &req);
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
/// or found it already cleaned up by the client's release or its open's
/// release.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`owned` is whether the worker revoked the page, which the line reports"
)]
fn log_outcome(req: &EvictReq, outcome: Release, owned: bool)
{
    let what = match outcome
    {
        Release::Acked => return,
        Release::NoEndpoint => "no release endpoint",
        Release::DeriveFailed => "release SEND derive failed; no FS_RELEASE_MEMORY sent",
        Release::Refused(_) => "FS_RELEASE_MEMORY refused",
        Release::CallFailed => "FS_RELEASE_MEMORY call failed",
        Release::WatchdogsBusy => "release watchdogs all blocked; no FS_RELEASE_MEMORY sent",
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
        warn: "{} (label={}); {} (open={:?}, slot={})",
        what,
        label,
        action,
        req.open,
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
    /// No reply within `RELEASE_TIMEOUT_MS`, or no watchdog took the call
    /// within it, which is then withdrawn unsent.
    TimedOut,
    /// No watchdog was idle: each one started is still blocked on a client
    /// that has not replied, so nothing was sent.
    WatchdogsBusy,
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
/// `ipc_call` has no kernel-side timeout, so the synchronous IPC runs on an
/// idle watchdog thread ([`start_watchdogs`]) and the worker waits with
/// `Condvar::wait_timeout_while`. On timeout the watchdog is left blocked in
/// `ipc_call`; if the client eventually replies the watchdog finds the call
/// given up, discards the outcome, and is idle again. A truly hung client
/// keeps its watchdog blocked, the cost of cooperative release without a
/// kernel-side IPC-cancellation primitive; with every watchdog blocked
/// nothing is sent.
fn cooperative_release(endpoint: u64, cookie: u64) -> Release
{
    let Some(dog) = WATCHDOGS.iter().find(|dog| {
        let mut st = dog.lock();
        let idle = matches!(*st, Watch::Idle);
        if idle
        {
            *st = Watch::Asked { endpoint, cookie };
        }
        idle
    })
    else
    {
        let _ = syscall::cap_delete(endpoint);
        return Release::WatchdogsBusy;
    };
    dog.cv.notify_all();

    let (mut st, _) = dog
        .cv
        .wait_timeout_while(
            dog.lock(),
            Duration::from_millis(RELEASE_TIMEOUT_MS),
            |st| !matches!(*st, Watch::Answered(_)),
        )
        .unwrap_or_else(PoisonError::into_inner);
    match *st
    {
        // The watchdog has not taken the call: withdraw it, so nothing is
        // sent and the watchdog stays idle.
        Watch::Asked { endpoint, .. } =>
        {
            *st = Watch::Idle;
            drop(st);
            let _ = syscall::cap_delete(endpoint);
        }
        // Mark the call given up, so the watchdog discards its outcome when
        // the client replies rather than racing the worker's cleanup.
        Watch::Calling { .. } => *st = Watch::Calling { given_up: true },
        Watch::Answered(outcome) =>
        {
            *st = Watch::Idle;
            return outcome;
        }
        Watch::Absent | Watch::Idle =>
        {}
    }
    Release::TimedOut
}

/// The state of one watchdog slot ([`WATCHDOGS`]).
#[derive(Clone, Copy)]
enum Watch
{
    /// No thread holds the slot: its spawn failed, or has not returned.
    Absent,
    /// Its thread waits for a call.
    Idle,
    /// The worker handed it a call: `FS_RELEASE_MEMORY` of `cookie` on
    /// `endpoint`, a cap the watchdog consumes.
    Asked
    {
        endpoint: u64, cookie: u64
    },
    /// Its thread is in the call; `given_up` once the worker has stopped
    /// waiting for it.
    Calling
    {
        given_up: bool
    },
    /// The call ended with this outcome, which the worker has not taken yet.
    Answered(Release),
}

/// One watchdog slot: its state, and the Condvar both its thread and the
/// worker wait on for the other's change of it.
struct Watchdog
{
    state: Mutex<Watch>,
    cv: Condvar,
}

impl Watchdog
{
    const fn new() -> Self
    {
        Self {
            state: Mutex::new(Watch::Absent),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Watch>
    {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The release watchdogs (module docs), each slot held by one thread
/// [`start_watchdogs`] started.
static WATCHDOGS: [Watchdog; MAX_WATCHDOGS] = [const { Watchdog::new() }; MAX_WATCHDOGS];

/// Start the [`MAX_WATCHDOGS`] release watchdogs, before the driver serves.
/// Each is spawned with its stack touched
/// (`std::os::seraph::thread::BuilderExt::spawn_backed`), so a release, which
/// runs when memory is short, needs no thread, IPC buffer page or stack
/// chunk then (module docs; crate docs, Helper start). A watchdog whose spawn
/// fails leaves its slot empty, logged, and the releases make do with the
/// others.
pub fn start_watchdogs()
{
    let mut started: usize = 0;
    for dog in &WATCHDOGS
    {
        let spawned = thread::Builder::new()
            .name("fatfs-release-watchdog".into())
            .spawn_backed::<{ crate::HELPER_STACK_TOUCH_BYTES }, _, _>(move || watchdog_loop(dog));
        if spawned.is_ok()
        {
            // The thread waits for a call whatever the slot reads, so the
            // slot is opened to the worker here, once the spawn has returned.
            *dog.lock() = Watch::Idle;
            started = started.saturating_add(1);
        }
    }
    if started < MAX_WATCHDOGS
    {
        std::os::seraph::log!(
            warn: "{} of {} release watchdogs started",
            started,
            MAX_WATCHDOGS
        );
    }
}

/// A watchdog's loop: wait for a call on `dog`, make it, and hand the
/// worker its outcome, or discard the outcome of a call the worker gave up
/// on; either way the slot is idle again after.
fn watchdog_loop(dog: &Watchdog) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        let mut st = dog.lock();
        let (endpoint, cookie) = loop
        {
            if let Watch::Asked { endpoint, cookie } = *st
            {
                break (endpoint, cookie);
            }
            st = dog.cv.wait(st).unwrap_or_else(PoisonError::into_inner);
        };
        *st = Watch::Calling { given_up: false };
        drop(st);

        let msg = IpcMessage::builder(fs_labels::FS_RELEASE_MEMORY)
            .word(0, cookie)
            .build();
        // SAFETY: `ipc_buf` is the registered IPC buffer for this thread
        // (set in `std::thread`'s entry trampoline).
        let result = unsafe { ipc::ipc_call(endpoint, &msg, ipc_buf) };
        let _ = syscall::cap_delete(endpoint);
        let outcome = match result
        {
            Ok(reply) if reply.label == fs_labels::FS_RELEASE_ACK => Release::Acked,
            Ok(reply) => Release::Refused(reply.label),
            Err(_) => Release::CallFailed,
        };

        let mut st = dog.lock();
        *st = if let Watch::Calling { given_up: true } = *st
        {
            Watch::Idle
        }
        else
        {
            Watch::Answered(outcome)
        };
        drop(st);
        dog.cv.notify_all();
    }
}

/// The release SEND the worker sends a page's `FS_RELEASE_MEMORY` on.
enum Endpoint
{
    /// The worker's own derived copy of the client's release SEND.
    Copy(u64),
    /// The client delivered no release SEND.
    NoSend,
    /// The client delivered one, but the worker could not derive its copy.
    DeriveFailed,
}

/// Under the opens' lock, check that `req`'s outstanding page is still held
/// by its open (same open, cookie, cache slot, and ancestor cap) and return
/// a derived copy of its open's release SEND. The copy is the worker's own,
/// so an open's release that deletes the slot's SEND meanwhile cannot free or
/// reuse the slot the worker calls on. `None` means the page was already
/// cleaned up.
fn live_release_endpoint(opens: &Mutex<Opens>, req: &EvictReq) -> Option<Endpoint>
{
    let opens_g = opens.lock().unwrap_or_else(PoisonError::into_inner);
    let send = opens_g.release_endpoint_if_held(req)?;
    // The derive runs under the lock, which serialises it against the main
    // thread's release and close paths that delete the SEND.
    let endpoint = if send == 0
    {
        Endpoint::NoSend
    }
    else
    {
        syscall::cap_derive(send, syscall::RIGHTS_EP_SEND)
            .map_or(Endpoint::DeriveFailed, Endpoint::Copy)
    };
    drop(opens_g);
    Some(endpoint)
}

/// Take `req`'s outstanding page off its open, under the lock the main
/// thread's release and close paths hold. Returns whether the page was still
/// held (same open, cookie, cache slot, and ancestor cap), in which case the
/// caller owns its cleanup; `false` means another path already cleaned it
/// up.
fn take_outstanding(opens: &Mutex<Opens>, req: &EvictReq) -> bool
{
    opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take_held(req)
}
