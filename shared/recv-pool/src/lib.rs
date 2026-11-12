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
//! ([`RecvGuard`]).
//!
//! The crate spawns `std` threads, so it compiles only for seraph.

#![cfg(target_os = "seraph")]

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use ipc::IpcMessage;
use ipc::recv_guard::{RecvFailureStage, RecvGuard};
use syscall_abi::SyscallError;

/// The error a worker passes its diagnostic hook, at
/// [`RecvFailureStage::Fatal`], when its thread has no registered IPC buffer
/// page (the runtime's registration of the page failed): the worker exits its
/// thread without receiving. The process and the other workers go on.
pub const NO_IPC_BUFFER: i64 = SyscallError::InvalidAddress as i64;

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
    /// The `RecvGuard` diagnostic hook, also told of a worker with no IPC
    /// buffer ([`NO_IPC_BUFFER`]).
    diag: fn(RecvFailureStage, i64),
    handler: H,
    gate: Mutex<Gate>,
    /// Signalled when a worker starts and when the gate opens.
    changed: Condvar,
}

/// The workers' start: how many were spawned and have started, and whether
/// they may receive.
struct Gate
{
    /// Workers spawned so far.
    spawned: usize,
    /// Workers that have started running their code.
    started: usize,
    /// `false` until [`RecvPool::open`]; a worker waits for it before its
    /// first receive.
    open: bool,
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
                gate: Mutex::new(Gate {
                    spawned: 0,
                    started: 0,
                    open: false,
                }),
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
        for i in 0..count
        {
            let shared = Arc::clone(&self.shared);
            match std::thread::Builder::new()
                .name(format!("{name}-{i}"))
                .spawn(move || serve(&shared))
            {
                Ok(_) =>
                {
                    // Both count threads of this one spawn loop, so neither
                    // saturates.
                    running = running.saturating_add(1);
                    let mut gate = self.lock_gate();
                    gate.spawned = gate.spawned.saturating_add(1);
                }
                Err(error) =>
                {
                    failed = Some(error);
                    break;
                }
            }
        }
        let mut gate = self.lock_gate();
        while gate.started < gate.spawned
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

    fn lock_gate(&self) -> MutexGuard<'_, Gate>
    {
        self.shared
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Open the gate: every worker, spawned or still to be spawned, receives.
    pub fn open(&self)
    {
        self.lock_gate().open = true;
        self.shared.changed.notify_all();
    }

    /// Open the gate and make the calling thread one more worker.
    pub fn serve_on_current(self) -> !
    {
        self.open();
        serve(&self.shared)
    }
}

/// A worker: count itself started, wait for the gate, then receive and
/// handle requests for the life of the process.
fn serve<H>(shared: &Shared<H>) -> !
where
    H: Fn(&IpcMessage, IpcBuf),
{
    let mut gate = shared.gate.lock().unwrap_or_else(PoisonError::into_inner);
    // `started` counts the threads of one spawn loop, so it does not
    // saturate.
    gate.started = gate.started.saturating_add(1);
    shared.changed.notify_all();
    while !gate.open
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
        (shared.diag)(RecvFailureStage::Fatal, NO_IPC_BUFFER);
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
