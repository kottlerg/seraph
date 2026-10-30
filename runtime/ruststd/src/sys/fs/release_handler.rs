// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/fs/release_handler.rs

//! Per-process release-handler thread for the seraph fs frame protocol.
//!
//! The fs driver evicts cached pages by sending `FS_RELEASE_MEMORY` on
//! a badged SEND derived from the per-process release endpoint owned
//! by this module. Copies of each opened file's SEND travel to the driver
//! in `caps[0]` of its [`fs_labels::FS_READ_MEMORY`] requests until one
//! is confirmed delivered (see [`super::File::read_frame`]); from the
//! request that allocates the node's driver slot on, the driver's
//! eviction worker can route cooperative releases here. The
//! handler finds the cookie among every registered `File`, not only the one
//! whose badge the release carries: the driver records one release SEND per
//! node, so a release for one `File`'s page can arrive on another `File`'s
//! badge (services/fs/docs/fs-driver-protocol.md § Label 8). It waits out a
//! local copy still reading the cookie's page, for at most [`READ_WAIT`]
//! once per cookie, removes the matching outstanding mapping (race-safe
//! against the local read path's immediate-release cleanup), unmaps the
//! page, drops the memory cap, and replies [`fs_labels::FS_RELEASE_ACK`].
//! The VA returns to the reservation arena only once the unmap succeeds
//! (see [`discard_mapping`]). A failed unmap or a copy still running at the
//! end of the wait is answered with [`fs_errors::IO_ERROR`], no ack. After
//! any reply, or the window with none, the driver revokes the page's caps;
//! the revoke unmaps nothing. The driver never refills a page this client
//! still maps: before reuse it checks that no mapping but its own remains,
//! and quarantines a page that is still mapped (services/fs/docs/
//! fs-driver-protocol.md § Label 8). A copy that outlasts the window
//! therefore reads the page's original bytes. A copy still running when the
//! handler's own wait runs out is marked stalled, and `File::read_frame`
//! discards it as defence in depth. Holding the reply keeps the client's own
//! unmap from racing a copy that ends within the window.
//!
//! The endpoint and the handler thread are created lazily on the first
//! [`super::File::open`] call; until then the cost is one
//! `OnceLock` load. The state is published only once the handler thread
//! is running, so a failed spawn is retried by the next call.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::collections::BTreeMap;
use crate::io;
use crate::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use crate::thread;
use crate::time::Duration;
use crate::vec::Vec;

use ipc::{IpcMessage, fs_errors, fs_labels};

use crate::sys::reserve as pal_reserve;
use crate::sys::reserve::ReservedRange;

/// Longest the handler holds a release for a local copy of the cookie's page:
/// the driver's cooperative-release window (fs-driver-protocol.md § Label 8),
/// past which the driver revokes whatever the reply says. Each cookie gets
/// the wait once: a cookie whose wait ran out is in [`Outstanding::stalled`],
/// and a repeated release of it is refused at once. A driver's hold on the
/// single handler thread, which serves every `File`'s releases, is so
/// bounded by its reads in flight.
const READ_WAIT: Duration = Duration::from_millis(100);

/// One outstanding cache-page mapping the local read path has obtained
/// from the fs driver via `FS_READ_MEMORY`. Carries everything the
/// release path (local or driver-initiated) needs to unmap and free.
pub(super) struct OutstandingMapping
{
    pub cookie: u64,
    pub range: ReservedRange,
    pub memory_cap: u32,
}

/// Per-`File` registration entry held by the release handler under its
/// registry lock. `Arc`-cloned out of the registry by both the handler
/// and the local read/drop paths.
pub(super) struct FileEntry
{
    outstanding: Mutex<Outstanding>,
    /// Signalled whenever a cookie leaves [`Outstanding::reading`].
    read_done: Condvar,
}

/// A `File`'s outstanding pages, keyed by cookie.
struct Outstanding
{
    /// Mappings no local copy is reading; a release may take them.
    idle: Vec<OutstandingMapping>,
    /// Cookies of local reads between their `FS_READ_MEMORY` and the end
    /// of their copy. The driver may send `FS_RELEASE_MEMORY` for such a
    /// cookie before the page is even mapped; the handler waits, up to
    /// [`READ_WAIT`], until the read ends rather than ack a release whose
    /// page is still in use.
    reading: Vec<u64>,
    /// Cookies still in `reading` whose release wait already ran out.
    stalled: Vec<u64>,
}

/// Process-wide release state. Created on the first
/// [`super::File::open`] call whose handler spawn succeeds; held forever
/// for the process lifetime.
pub(super) struct ReleaseState
{
    /// Unbadged endpoint cap owned by this process; badged SENDs
    /// derived from it would live in fs's CSpace once a delivery
    /// channel exists. Revoking this cap (which we never do) would
    /// tear down every fs-side derived child atomically.
    release_ep: u32,
    registry: Mutex<BTreeMap<u64, Arc<FileEntry>>>,
    /// Process aspace cap, captured at init for the handler's
    /// `mem_unmap` calls. Equal to `StartupInfo::self_aspace`.
    aspace: u32,
}

/// Published only after the handler thread serving it has spawned.
static STATE: OnceLock<Arc<ReleaseState>> = OnceLock::new();

/// Serialises initialisers, so at most one endpoint and one handler
/// thread are ever created.
static INIT: Mutex<()> = Mutex::new(());

/// Lazy-init: ensure the release endpoint exists and the handler thread
/// is running. Returns the singleton state. Subsequent calls hit the
/// `OnceLock` fast path. A failed endpoint creation or handler spawn
/// publishes nothing and deletes the endpoint, so the next call retries.
pub(super) fn ensure_started() -> io::Result<&'static ReleaseState>
{
    if let Some(s) = state()
    {
        return Ok(s);
    }
    let _init = INIT.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(s) = state()
    {
        return Ok(s);
    }

    let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
        io::Error::other("seraph fs: startup info not installed")
    })?;
    let aspace = info.self_aspace;

    let release_ep = crate::sys::alloc::seraph::object_slab_retype(88, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .ok_or_else(|| io::Error::other("seraph fs: cap_create_endpoint (release) failed"))?;

    let state = Arc::new(ReleaseState {
        release_ep,
        registry: Mutex::new(BTreeMap::new()),
        aspace,
    });
    let handler_state = Arc::clone(&state);
    if thread::Builder::new()
        .name("seraph-fs-release".into())
        .spawn(move || handler_main(&handler_state))
        .is_err()
    {
        let _ = syscall::cap_delete(release_ep);
        return Err(io::Error::other("seraph fs: release-handler spawn failed"));
    }

    Ok(&**STATE.get_or_init(|| state))
}

/// Read the singleton release state if it has been initialised. Used by
/// `File::drop` to avoid spawning the handler if no `File::open` ever
/// ran (e.g. failure during `OpenOptions` validation).
pub(super) fn state() -> Option<&'static ReleaseState>
{
    STATE.get().map(|s| &**s)
}

/// Unbadged endpoint cap the per-`File` SEND derivation hangs off.
pub(super) fn release_endpoint(state: &ReleaseState) -> u32
{
    state.release_ep
}

/// Allocate a fresh non-zero per-`File` release-endpoint badge: a random `u64`
/// from the kernel entropy pool, redrawn off the reserved `0` value (an
/// unbadged SEND carries badge 0). Random rather than monotonic so the
/// file-open count it would otherwise leak to the fs driver — which receives
/// the badged SEND and echoes the badge in `FS_RELEASE_MEMORY` — stays
/// unguessable; the handler keys its registry by badge value, not index.
/// Returns `None` if the entropy draw fails (a kernel-contract violation).
pub(super) fn allocate_badge() -> Option<u64>
{
    loop
    {
        let t = syscall::random_u64().ok()?;
        if t != 0
        {
            return Some(t);
        }
    }
}

/// Register a `File` with the handler, returning its `FileEntry`.
pub(super) fn register(state: &ReleaseState, badge: u64) -> Arc<FileEntry>
{
    let entry = Arc::new(FileEntry {
        outstanding: Mutex::new(Outstanding {
            idle: Vec::new(),
            reading: Vec::new(),
            stalled: Vec::new(),
        }),
        read_done: Condvar::new(),
    });
    let mut reg = state
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    reg.insert(badge, entry.clone());
    entry
}

/// Remove a `File`'s registration. After this call the handler cannot
/// dispatch any further releases to the file; a later `FS_RELEASE_MEMORY`
/// for one of its cookies finds no entry and is acked without action.
pub(super) fn unregister(state: &ReleaseState, badge: u64) -> Option<Arc<FileEntry>>
{
    let mut reg = state
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    reg.remove(&badge)
}

/// Mark `cookie` as read in progress. Called by `File::read_frame` before
/// its `FS_READ_MEMORY`, so a driver release of the cookie waits, up to
/// [`READ_WAIT`], for the read to end. Every call is paired with one
/// [`end_read`].
pub(super) fn begin_read(entry: &FileEntry, cookie: u64)
{
    let mut out = entry.outstanding.lock().unwrap_or_else(PoisonError::into_inner);
    out.reading.push(cookie);
}

/// End the read of `cookie`, handing over its mapping if one was made, and
/// wake a release waiting on it. The handler thread is the only waiter.
/// Returns whether a driver release's wait for this read ran out first,
/// which means the copy outlasted the driver's window.
pub(super) fn end_read(entry: &FileEntry, cookie: u64, mapping: Option<OutstandingMapping>) -> bool
{
    let mut out = entry.outstanding.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(idx) = out.reading.iter().position(|&c| c == cookie)
    {
        out.reading.swap_remove(idx);
    }
    let stalled = match out.stalled.iter().position(|&c| c == cookie)
    {
        Some(idx) =>
        {
            out.stalled.swap_remove(idx);
            true
        }
        None => false,
    };
    if let Some(m) = mapping
    {
        out.idle.push(m);
    }
    entry.read_done.notify_one();
    stalled
}

/// Take an idle mapping by cookie. Returns `Some` to whichever of the local
/// release path or the handler thread observes the entry first; the
/// loser sees `None` and skips its cleanup. Idempotent.
fn take_mapping(entry: &FileEntry, cookie: u64) -> Option<OutstandingMapping>
{
    let mut out = entry.outstanding.lock().unwrap_or_else(PoisonError::into_inner);
    let idx = out.idle.iter().position(|m| m.cookie == cookie)?;
    Some(out.idle.swap_remove(idx))
}

/// What the handler's take found for a released cookie.
enum Taken
{
    /// The cookie's mapping, now the handler's to discard.
    Mapping(OutstandingMapping),
    /// No mapping: released locally already, or its `File` closed.
    Absent,
    /// A local copy of the page was still running when [`READ_WAIT`] ran
    /// out, now or on an earlier release of the cookie.
    Busy,
}

/// The registered entry holding `cookie`, reading or idle, whichever `File`
/// it belongs to. Cookies are random per read, so at most one entry holds
/// one. Lock order: the registry, then an entry.
fn find_entry(state: &ReleaseState, cookie: u64) -> Option<Arc<FileEntry>>
{
    let reg = state
        .registry
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    reg.values()
        .find(|e| {
            let out = e.outstanding.lock().unwrap_or_else(PoisonError::into_inner);
            out.reading.contains(&cookie) || out.idle.iter().any(|m| m.cookie == cookie)
        })
        .cloned()
}

/// Handler-side take: wait, up to [`READ_WAIT`] and once per cookie, while
/// a local read of `cookie` is in progress, then take its mapping.
fn take_mapping_after_read(entry: &FileEntry, cookie: u64) -> Taken
{
    let out = entry.outstanding.lock().unwrap_or_else(PoisonError::into_inner);
    if out.stalled.contains(&cookie)
    {
        return Taken::Busy;
    }
    let (mut out, _) = entry
        .read_done
        .wait_timeout_while(out, READ_WAIT, |o| o.reading.contains(&cookie))
        .unwrap_or_else(PoisonError::into_inner);
    if out.reading.contains(&cookie)
    {
        out.stalled.push(cookie);
        return Taken::Busy;
    }
    match out.idle.iter().position(|m| m.cookie == cookie)
    {
        Some(idx) => Taken::Mapping(out.idle.swap_remove(idx)),
        None => Taken::Absent,
    }
}

/// Drain every outstanding mapping at file-close time so `File::drop`
/// can unmap each one. The registry entry is removed separately by the
/// caller via [`unregister`].
pub(super) fn drain_mappings(entry: &FileEntry) -> Vec<OutstandingMapping>
{
    let mut out = entry.outstanding.lock().unwrap_or_else(PoisonError::into_inner);
    core::mem::take(&mut out.idle)
}

/// Local cleanup of a single mapping by cookie. Called after a
/// successful synchronous `FS_RELEASE_MEMORY` round-trip from
/// `File::read` to release the resources the read held briefly. If the
/// handler thread already cleaned up this cookie (rare but possible
/// during a contended eviction), this is a no-op.
pub(super) fn release_one_local(entry: &FileEntry, aspace: u32, cookie: u64)
{
    if let Some(m) = take_mapping(entry, cookie)
    {
        discard_mapping(m, aspace);
    }
}

/// Unmap an outstanding mapping and delete its cap. The VA returns to the
/// reservation arena only once the unmap succeeds; a range still mapped
/// stays reserved until this process exits, so no later reservation can
/// land on the driver's page. Returns whether the unmap succeeded.
pub(super) fn discard_mapping(m: OutstandingMapping, aspace: u32) -> bool
{
    // SAFETY: `m` owns its `ReservedRange`, arena VA that holds no Rust
    // object; the read path reads the page only through raw volatile reads,
    // which end before the mapping enters the registry (`ReadMark::finish`),
    // so no Rust reference into it is live.
    let unmapped =
        unsafe { syscall::mem_unmap(aspace, m.range.va_start(), m.range.page_count()) }.is_ok();
    let _ = syscall::cap_delete(m.memory_cap);
    if unmapped
    {
        pal_reserve::unreserve_pages(m.range);
    }
    unmapped
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit. A wedged release endpoint blocks every
/// remote `FS_RELEASE_MEMORY` caller, so the process dies loudly like any
/// other unrecoverable receive loop.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    let msg = match stage
    {
        ipc::recv_guard::RecvFailureStage::First => "failing; backing off",
        ipc::recv_guard::RecvFailureStage::Fatal => "wedged; exiting",
    };
    crate::os::seraph::log::__emit(core::format_args!("fs-release recv loop {msg} (err={err})"));
}

fn handler_main(state: &ReleaseState)
{
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

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: `ipc_buf` is the registered IPC buffer for this
        // thread (set by the std::thread trampoline before invoking us).
        let msg = match unsafe { ipc::ipc_recv(state.release_ep, ipc_buf) }
        {
            Ok(m) => m,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        if msg.label != fs_labels::FS_RELEASE_MEMORY
        {
            // Unknown opcode — reply with label zero (cheap empty ack)
            // so the sender's blocking ipc_call returns and we don't
            // wedge the endpoint queue.
            let reply = IpcMessage::new(0);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            continue;
        }

        let cookie = msg.word(0);

        // The registry lock is dropped before the wait and the unmap, so
        // local reads keep registering mappings meanwhile.
        let taken = find_entry(state, cookie)
            .map_or(Taken::Absent, |e| take_mapping_after_read(e.as_ref(), cookie));

        // A page this process cannot unmap, or one a copy is still reading,
        // is not acknowledged: the ack tells the driver this process unmapped
        // the page, and a page still mapped here costs it a quarantined page.
        let released = match taken
        {
            Taken::Absent => true,
            Taken::Mapping(m) => discard_mapping(m, state.aspace),
            Taken::Busy => false,
        };
        let label = if released { fs_labels::FS_RELEASE_ACK } else { fs_errors::IO_ERROR };
        let reply = IpcMessage::new(label);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}
