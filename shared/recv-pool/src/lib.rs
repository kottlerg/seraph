// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/recv-pool/src/lib.rs

//! The worker-pool receive helper of multi-threaded std services: several
//! threads receive on one endpoint, each on its own IPC buffer page, and run
//! one handler per request.
//!
//! The rules a server's threads follow (each thread on its own page, a
//! nested call on that page after the request is copied out, a reply before
//! the next receive, no lock held across a nested call whose callee can call
//! back) are `docs/ipc-design.md` § Multi-threaded servers. This crate keeps
//! the first by construction: a handler receives the [`IpcBuf`] of the thread
//! running it, and an `IpcBuf` cannot leave that thread. Each worker's loop
//! is guarded as `docs/ipc-design.md` § Receive-Failure Policy says
//! ([`RecvGuard`]). A worker whose thread has no registered IPC buffer page
//! (the runtime's registration of the page failed) logs it and exits its
//! thread without receiving; the process and the other workers go on, so the
//! hook, whose [`RecvFailureStage::Fatal`] means the process exits, is not
//! told.
//!
//! The crate spawns `std` threads, so it compiles only for seraph.

#![cfg(target_os = "seraph")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use ipc::IpcMessage;
use ipc::recv_guard::{RecvFailureStage, RecvGuard};

/// The calling thread's registered IPC buffer page.
///
/// The only way to get one is [`Self::current`] on the thread it names. The
/// raw pointer it holds makes it neither `Send` nor `Sync`, so it cannot be
/// moved or shared into another thread, nor kept in a `static`: a handler
/// cannot reach any page but its own thread's.
#[derive(Clone, Copy)]
pub struct IpcBuf
{
    ptr: *mut u64,
}

impl IpcBuf
{
    /// The calling thread's registered IPC buffer page, or `None` when the
    /// thread has none.
    #[must_use]
    pub fn current() -> Option<Self>
    {
        let ptr = std::os::seraph::current_ipc_buf();
        if ptr.is_null()
        {
            None
        }
        else
        {
            Some(Self { ptr })
        }
    }

    /// The page, for the `ipc` wrappers, whose safety contract ("the calling
    /// thread's registered IPC buffer page") it meets on the thread that
    /// obtained it, the only thread that can hold it.
    #[must_use]
    pub fn as_ptr(self) -> *mut u64
    {
        self.ptr
    }
}

/// What every worker of a pool shares.
struct Shared<H>
{
    /// RECV on the endpoint the workers receive on.
    endpoint: u64,
    /// The `RecvGuard` diagnostic hook.
    diag: fn(RecvFailureStage, i64),
    handler: H,
    /// `false` until [`RecvPool::open`]; a worker waits for it before its
    /// first receive.
    open: Mutex<bool>,
    /// Signalled, with `open` held, when a worker starts and when the gate
    /// opens.
    changed: Condvar,
}

/// A pool of threads receiving on one endpoint.
///
/// Each worker receives a request and calls the handler with it and the
/// worker's own [`IpcBuf`]. The request is already copied out of the page
/// (`IpcMessage`), so the handler may make nested calls on that page. The
/// handler replies, or deliberately leaves the caller unanswered, before it
/// returns: the worker's next receive releases a caller still pending
/// (`docs/ipc-design.md` § The Call/Reply Model).
///
/// Workers start behind a gate: [`Self::spawn`] starts threads that wait,
/// and [`Self::open`] (or [`Self::serve_on_current`]) lets them receive. A
/// spawned thread's start in the runtime can wait on procmgr (its thread
/// registration, `runtime/ruststd/README.md` § Thread registration), and
/// [`Self::spawn`] returns only once every worker it spawned has started
/// running its code. So a service that procmgr may be waiting on (logd, which
/// serves procmgr's log calls) spawns its workers while something else still
/// serves the endpoint, and opens the gate when it takes the endpoint over.
///
/// The worker count is a concurrency setting of the service. It bounds no
/// capacity: callers beyond it queue on the endpoint.
pub struct RecvPool<H>
{
    shared: Arc<Shared<H>>,
}

/// A failed [`RecvPool::spawn`]: the workers spawned before the failure keep
/// running.
#[derive(Debug)]
pub struct SpawnError
{
    /// Workers this call spawned before the failure.
    pub running: usize,
    /// Why the next one could not be spawned.
    pub error: std::io::Error,
}

impl<H> RecvPool<H>
where
    H: Fn(&IpcMessage, IpcBuf) + Send + Sync + 'static,
{
    /// A pool with no workers and a closed gate, serving `endpoint` (a RECV
    /// capability) with `handler`. `diag` is each worker's `RecvGuard` hook.
    #[must_use]
    pub fn new(endpoint: u64, diag: fn(RecvFailureStage, i64), handler: H) -> Self
    {
        Self {
            shared: Arc::new(Shared {
                endpoint,
                diag,
                handler,
                open: Mutex::new(false),
                changed: Condvar::new(),
            }),
        }
    }

    /// Spawn `count` workers named `<name>-<i>`, and return once each has
    /// started running its code. They receive once the gate is open. Returns
    /// `count`.
    ///
    /// # Errors
    ///
    /// [`SpawnError`] when a thread cannot be spawned, with the number of
    /// workers this call spawned before it, which have also started.
    pub fn spawn(&self, name: &str, count: usize) -> Result<usize, SpawnError>
    {
        let mut failed = None;
        let mut running: usize = 0;
        // This call's own workers count themselves started here, so a spawn
        // on another thread of the same pool neither holds nor releases it.
        let started = Arc::new(AtomicUsize::new(0));
        for i in 0..count
        {
            let shared = Arc::clone(&self.shared);
            let mine = Arc::clone(&started);
            match std::thread::Builder::new()
                .name(format!("{name}-{i}"))
                .spawn(move || serve(&shared, Some(&mine)))
            {
                // Counts this call's threads, at most `count`, so it does
                // not saturate.
                Ok(_) => running = running.saturating_add(1),
                Err(error) =>
                {
                    failed = Some(error);
                    break;
                }
            }
        }
        let mut gate = self.lock_gate();
        // A worker counts itself with `open` held and then signals, so the
        // check under the lock misses no start.
        while started.load(Ordering::Relaxed) < running
        {
            gate = self
                .shared
                .changed
                .wait(gate)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(gate);
        match failed
        {
            None => Ok(count),
            Some(error) => Err(SpawnError { running, error }),
        }
    }

    fn lock_gate(&self) -> MutexGuard<'_, bool>
    {
        self.shared
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Open the gate: every worker, spawned or still to be spawned, receives.
    pub fn open(&self)
    {
        *self.lock_gate() = true;
        self.shared.changed.notify_all();
    }

    /// Open the gate and make the calling thread one more worker.
    pub fn serve_on_current(self) -> !
    {
        self.open();
        serve(&self.shared, None)
    }
}

/// A worker: count itself in `started` (the count of the [`RecvPool::spawn`]
/// call that spawned it, `None` for [`RecvPool::serve_on_current`]), wait for
/// the gate, then receive and handle requests for the life of the process.
fn serve<H>(shared: &Shared<H>, started: Option<&AtomicUsize>) -> !
where
    H: Fn(&IpcMessage, IpcBuf),
{
    let mut gate = shared.open.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(started) = started
    {
        started.fetch_add(1, Ordering::Relaxed);
    }
    shared.changed.notify_all();
    while !*gate
    {
        gate = shared
            .changed
            .wait(gate)
            .unwrap_or_else(PoisonError::into_inner);
    }
    drop(gate);

    let Some(buf) = IpcBuf::current()
    else
    {
        std::os::seraph::log!(
            warn: "receive worker has no IPC buffer page; its thread exits, the other workers serve"
        );
        syscall::thread_exit();
    };

    let mut guard = RecvGuard::new(shared.diag);
    loop
    {
        // SAFETY: `buf` is this thread's registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(shared.endpoint, buf.as_ptr()) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        (shared.handler)(&msg, buf);
    }
}
