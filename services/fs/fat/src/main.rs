// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/main.rs

//! Seraph FAT filesystem driver.
//!
//! Implements read-write FAT16/FAT32 filesystem support. Serves the
//! cap-native namespace protocol (`NS_LOOKUP` / `NS_STAT` /
//! `NS_READDIR`) for directory walks; per-node badged caps carry
//! `FS_SESSION`, `FS_OPEN`, the stateless file labels (`FS_READ`, `FS_WRITE`,
//! `FS_WRITE_MEMORY`, `FS_TRUNCATE`), and directory mutation (`FS_CREATE`,
//! `FS_REMOVE`, `FS_MKDIR`, `FS_RENAME`); per-open caps carry the open's
//! `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, and `FS_CLOSE`, and the stateless
//! file labels.
//! The unbadged service-level requests are vfsd's: `FS_MOUNT`, a
//! BPB-validation probe at mount time, and `FS_UNMOUNT`, after which the
//! driver exits. All disk I/O is performed via the block device IPC endpoint
//! received at creation time; a block call that finds that capability
//! revoked ends the driver once the request in flight is answered
//! ([`cache::block_call`]).
//!
//! Per-node badges are minted by `NS_LOOKUP` (badge = `(NodeId,
//! NamespaceRights)`); per-node ops look the node up in `NodeTable`. Session
//! badges are minted by `FS_SESSION` (badge = the session's id with
//! `namespace_protocol::SESSION` set): each names one session, whose records
//! live in pages charged to the node its client passed (`session`,
//! `file::Opens`). Per-open badges are minted by `FS_OPEN`, which a session
//! cap must accompany (badge = `(open id, NamespaceRights)` with
//! `namespace_protocol::OPEN_INSTANCE` set): each names one open made in that
//! session, which holds that open's read-side memory caps and release SEND, and
//! resolves to its node for the stateless file ops. A session keeps one
//! liveness Notification for all its opens, and ends, with them, once its
//! client holds no copy of it (`file::Opens::sweep_sessions`), at the latest
//! when memmgr signals the end of a donation (module docs, Session end). Write-side metadata patching uses the node's cached
//! `DirEntryLocation`.
//!
//! Memory pressure: a pressure thread waits for a change of memmgr's level
//! (`std::os::seraph::wait_memory_pressure`). Each wake at which the level
//! reads `Low` or `Critical` begins or continues a shortage, whatever the
//! level the last wake read, since a wake can carry a return to `Normal` and
//! a new fall; the thread then marks a release pending and wakes the dispatch
//! loop with an unbadged call on the service endpoint. The loop,
//! at the top of its next turn, gives memmgr back the pages the cache holds
//! idle but the few most recently used, which a miss evicts when memmgr
//! refuses a page ([`cache::PageCache::release_idle_pages`]), and goes on
//! serving; the cache grows again on demand, within what memmgr grants. The
//! loop itself receives on the service endpoint alone, so a revocation of
//! the endpoint ends the driver at its next receive.
//!
//! Session end: the donation-end thread waits on a Notification registered
//! with memmgr (`memmgr_labels::REGISTER_DONATION_END`), which memmgr
//! signals when the handle state of a node fatfs holds a charged grant on
//! ends: the node's release, or its owner's death. The thread marks a sweep
//! pending and wakes the dispatch loop as the pressure thread does; the loop,
//! at the top of its next turn, ends every session whose client holds no
//! copy of its liveness cap any more, with one `CAP_INFO_SOLE_REFERENCE`
//! inquiry per live session, and gives their pages back. Signals that come
//! while a sweep is pending coalesce into it. Sessions are swept too on a
//! schedule of `FS_SESSION` requests (`fat_parse::sweep::SweepSchedule`),
//! and an `FS_CLOSE` that empties a session ends it when its liveness cap is
//! gone (`Opens::close`).
//!
//! Cache coherence: writes go through write-through
//! ([`cache::PageCache::write_sector`]) so any outstanding
//! `FS_READ_MEMORY` cap aliasing the same page observes new bytes
//! immediately. FAT-entry mutations invalidate the per-`FatState`
//! private `cached_fat_sector` to prevent stale FAT chain walks.
//! Crash window discussion lives in
//! `services/fs/fat/docs/crash-safety.md`.

mod alloc;
mod backend;
mod bpb;
mod cache;
mod dir;
mod eviction;
mod fat;
mod file;
mod held;
mod session;

use core::num::NonZeroU64;
use std::os::seraph::{MemoryPressure, StartupInfo, startup_info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use alloc::{FatError, allocate_cluster};
use backend::{FatfsBackend, NodeTable};
use bpb::{FatState, MAX_SECTOR_SIZE, sector_buffer};
use cache::PageCache;
use dir::{
    DeviceSlotState, DirEntryLocation, NewEntryKind, RemovedEntry, directory_is_empty,
    find_in_directory_with_location, free_entry_data, insert_entry, remove_entry,
    update_entry_metadata, write_dot_entries,
};
use eviction::EvictionState;
use fat::{chain_next, next_cluster, read_file_data};
use fat_parse::sweep::SweepSchedule;
use file::{Opens, OutstandingPage, SessionRefusal};
use ipc::{IpcMessage, fs_labels, ns_labels};
use namespace_protocol::{
    GateError, NamespaceRights, NodeId, NodeKind, OpenRef, gate, gate_open, is_open_instance,
    pack as pack_badge, pack_open, pack_session, session_id,
};
use session::SessionPages;
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE, RIGHTS_MEM_MAP};

// A session's ids and the badges that carry them are one width.
const _: () = assert!(fat_parse::session_pool::ID_BITS == namespace_protocol::KIND_ID_BITS);

/// [`PAGE_SIZE`] as a `usize`, for buffer and offset arithmetic.
#[expect(clippy::cast_possible_truncation, reason = "PAGE_SIZE is 4096")]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

// ── Bootstrap ──────────────────────────────────────────────────────────────
//
// Bootstrap round and FS_MOUNT probe: see services/fs/docs/fs-driver-protocol.md
// § Bootstrap caps and § Label 10: FS_MOUNT.

struct FatCaps
{
    block_dev: u64,
    service: u64,
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"fatfs");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is registered by `std::os::seraph::_start` and page-aligned by the \
                  boot protocol; `info.ipc_buffer` carries the same VA as a `*mut u8` we \
                  reinterpret as `*mut u64`"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // A core of a filesystem driver would be written through it, so the
    // crash service must write none: declare it on the core path before it serves
    // (`procmgr_labels::DECLARE_NO_CORE`). A refusal leaves its core to the
    // crash service's dump bound.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_CORE),
            ipc_buf,
        )
    };

    let Some(caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    let cache = match PageCache::init(
        info.memmgr_endpoint,
        info.self_aspace,
        info.self_cspace,
        ipc_buf,
    )
    {
        Ok(c) => c,
        Err(e) =>
        {
            std::os::seraph::log!(error: "page-cache init failed: {e:?}");
            syscall::thread_exit();
        }
    };

    std::os::seraph::log!("starting");

    let mut state = FatState::new();
    let mut nodes = NodeTable::new();

    // The window session pages map into, sized to the machine's RAM.
    let ram_pages = cache::query_system_ram_pages(info.memmgr_endpoint, ipc_buf).unwrap_or(0);
    let pages = SessionPages::reserve(ram_pages, info.self_aspace);
    let opens = Arc::new(Mutex::new(Opens::new(pages)));

    let eviction = Arc::new(EvictionState::new());

    // Spawn the cache-pressure eviction worker. The worker owns
    // outbound `FS_RELEASE_MEMORY` issuance and the cooperative-
    // release watchdog; main only enqueues. Spawn failure is
    // process-fatal — without the worker, cache pressure cannot
    // be relieved and reads degrade to permanent IO_ERROR once
    // every slot is held.
    {
        let ev = eviction.clone();
        let f = opens.clone();
        if std::thread::Builder::new()
            .name("fatfs-eviction-worker".into())
            .spawn(move || eviction::worker_loop(&ev, &f, cache))
            .is_err()
        {
            std::os::seraph::log!(error: "eviction worker spawn failed");
            syscall::thread_exit();
        }
    }

    spawn_pressure_thread(caps.service);
    spawn_donation_end_thread(caps.service, ipc_buf);

    service_loop(
        &caps, &mut state, &mut nodes, &opens, cache, ipc_buf, &eviction,
    );
}

// ── Memory pressure ────────────────────────────────────────────────────────

/// Set by the pressure thread when memmgr's level turns `Low` or
/// `Critical`; the dispatch loop takes it at the top of a turn
/// ([`release_under_pressure`]).
static RELEASE_PENDING: AtomicBool = AtomicBool::new(false);

/// Label of the pressure and donation-end threads' wake call, sent unbadged
/// on the service endpoint. No service-level request uses it, so the
/// dispatch loop refuses it with `UNKNOWN_OPCODE`; the turn the call costs
/// the loop is the wake.
const LOOP_WAKE: u64 = 0;
const _: () = assert!(LOOP_WAKE != fs_labels::FS_MOUNT && LOOP_WAKE != fs_labels::FS_UNMOUNT);

/// Start the pressure thread (module docs, Memory pressure) on an unbadged
/// SEND derived from `service`. Logged and skipped when the process is not
/// registered for pressure or the cap or the thread cannot be had: the cache
/// is then kept whatever the level, since the level is advisory.
fn spawn_pressure_thread(service: u64)
{
    if std::os::seraph::memory_pressure_notification().is_none()
    {
        std::os::seraph::log!(warn: "not registered for memory pressure; cache kept under pressure");
        return;
    }
    let Ok(wake) = syscall::cap_derive(service, syscall::RIGHTS_EP_SEND)
    else
    {
        std::os::seraph::log!(warn: "no wake cap; cache kept under memory pressure");
        return;
    };
    if std::thread::Builder::new()
        .name("fatfs-pressure".into())
        .spawn(move || pressure_thread(wake))
        .is_err()
    {
        std::os::seraph::log!(warn: "pressure thread spawn failed; cache kept under memory pressure");
        let _ = syscall::cap_delete(wake);
    }
}

/// Wait for memmgr's level to change; at `Low` or `Critical`, mark a release
/// pending and wake the dispatch loop ([`wake_loop`]). A wake at the level
/// the last one read is acted on too, since the changes it carries can have
/// passed through `Normal`, the cache growing again meanwhile. Ends when the
/// wait fails, or when the wake fails, as it does once vfsd has revoked the
/// service endpoint: the dispatch loop's receive then fails too and ends the
/// driver.
fn pressure_thread(wake: u64)
{
    loop
    {
        match std::os::seraph::wait_memory_pressure(None)
        {
            Ok(MemoryPressure::Low | MemoryPressure::Critical) =>
            {}
            // `Normal`: no shortage to act on.
            Ok(_) => continue,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "memory-pressure wait failed ({e}); cache kept under pressure");
                break;
            }
        }
        RELEASE_PENDING.store(true, Ordering::Release);
        if !wake_loop(wake)
        {
            break;
        }
    }
    let _ = syscall::cap_delete(wake);
}

/// Wake the dispatch loop with a [`LOOP_WAKE`] call on `wake`, an unbadged
/// SEND on the service endpoint. A call that a stop interrupts is made
/// again, since a second wake costs the loop one more refused request.
/// `false` when the call fails otherwise, as it does once vfsd has revoked
/// the service endpoint.
fn wake_loop(wake: u64) -> bool
{
    let msg = IpcMessage::builder(LOOP_WAKE).build();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer.
        match unsafe { ipc::ipc_call(wake, &msg, ipc_buf) }
        {
            Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
            {}
            result => break result.is_ok(),
        }
    }
}

/// Read memmgr's level again, since it can have recovered since the
/// pressure thread's wake, and at `Low` or `Critical` give memmgr back the
/// cache's idle pages. Run by the dispatch thread between requests
/// ([`PageCache::release_idle_pages`]).
fn release_under_pressure(cache: &PageCache, ipc_buf: *mut u64)
{
    let Some(level @ (MemoryPressure::Low | MemoryPressure::Critical)) =
        std::os::seraph::memory_pressure()
    else
    {
        return;
    };
    let released = cache.release_idle_pages(ipc_buf);
    std::os::seraph::log!("memory pressure {level:?}: {released} cache pages given back");
}

// ── Session end ────────────────────────────────────────────────────────────

/// Set by the donation-end thread when memmgr signals the end of a donation;
/// the dispatch loop takes it at the top of a turn and sweeps the sessions
/// (module docs, Session end).
static SESSION_SWEEP_PENDING: AtomicBool = AtomicBool::new(false);

/// The bit memmgr signals on the donation-end Notification.
const DONATION_END_BIT: u64 = 1;

/// Register a Notification with memmgr for the end of the donations fatfs
/// holds grants on (`memmgr_labels::REGISTER_DONATION_END`), and start the
/// donation-end thread (module docs, Session end) on it and on an unbadged
/// SEND derived from `service`. Logged and skipped when the Notification,
/// the registration, the cap, or the thread cannot be had: sessions whose
/// client is gone are then ended only by the sweeps `FS_SESSION` and
/// `FS_UNMOUNT` make.
fn spawn_donation_end_thread(service: u64, ipc_buf: *mut u64)
{
    let Some(signal) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
    else
    {
        std::os::seraph::log!(warn: "no donation-end Notification; sessions swept on schedule only");
        return;
    };
    if !register_donation_end(signal, ipc_buf)
    {
        std::os::seraph::log!(warn: "donation-end registration refused; sessions swept on schedule only");
        let _ = syscall::cap_delete(signal);
        return;
    }
    let Ok(wake) = syscall::cap_derive(service, syscall::RIGHTS_EP_SEND)
    else
    {
        std::os::seraph::log!(warn: "no wake cap; sessions swept on schedule only");
        let _ = syscall::cap_delete(signal);
        return;
    };
    if std::thread::Builder::new()
        .name("fatfs-donation-end".into())
        .spawn(move || donation_end_thread(signal, wake))
        .is_err()
    {
        std::os::seraph::log!(warn: "donation-end thread spawn failed; sessions swept on schedule only");
        let _ = syscall::cap_delete(wake);
        let _ = syscall::cap_delete(signal);
    }
}

/// Hand memmgr a Notify copy of `signal` to signal [`DONATION_END_BIT`] on.
/// `false` when the copy cannot be had or memmgr refuses it.
fn register_donation_end(signal: u64, ipc_buf: *mut u64) -> bool
{
    let Ok(notify) = syscall::cap_derive(signal, syscall::RIGHTS_NTF_NOTIFY)
    else
    {
        return false;
    };
    let msg = IpcMessage::builder(ipc::memmgr_labels::REGISTER_DONATION_END)
        .word(0, DONATION_END_BIT)
        .cap(notify)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &msg, ipc_buf) })
    else
    {
        // A call that fails moves no cap: the copy is still fatfs's.
        let _ = syscall::cap_delete(notify);
        return false;
    };
    reply.label == ipc::memmgr_errors::SUCCESS
}

/// Wait on `signal`; at each signal, mark a session sweep pending and wake
/// the dispatch loop ([`wake_loop`]). Signals that arrive before the loop
/// takes the mark are one sweep. Ends when the wait or the wake fails.
fn donation_end_thread(signal: u64, wake: u64)
{
    loop
    {
        match syscall::notification_wait(signal)
        {
            Ok(_) =>
            {}
            Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 => continue,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "donation-end wait failed ({e}); sessions swept on schedule only");
                break;
            }
        }
        if !SESSION_SWEEP_PENDING.swap(true, Ordering::AcqRel) && !wake_loop(wake)
        {
            break;
        }
    }
    let _ = syscall::cap_delete(wake);
    let _ = syscall::cap_delete(signal);
}

/// Issue a single bootstrap round against the creator endpoint and assemble
/// [`FatCaps`].
fn bootstrap_caps(info: &StartupInfo, ipc_buf: *mut u64) -> Option<FatCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 2 || !round.done
    {
        return None;
    }
    Some(FatCaps {
        block_dev: round.caps[0],
        service: round.caps[1],
    })
}

/// Validate the BPB by reading sector 0 through the block cap. Updates
/// `state` in place; returns the IPC reply label to use.
///
/// The device's logical block size comes first, from `BLK_GET_GEOMETRY`:
/// the cache addresses one device block per sector, and the BPB's
/// `BytsPerSec` must equal it ([`fat_parse::parse_bpb_geometry`]).
///
/// On a successful FAT32 parse, also loads the `FSInfo` sector (advisory
/// next-free / free-count hints) so the cluster allocator can seed its
/// scan; FAT16 and FAT32 without `FSInfo` leave the hints at the
/// `u32::MAX` sentinel and the allocator scans from cluster 2.
fn validate_bpb(caps: &FatCaps, state: &mut FatState, cache: &PageCache, ipc_buf: *mut u64) -> u64
{
    let Some(block_size) = query_block_size(caps.block_dev, ipc_buf)
    else
    {
        return ipc::fs_errors::IO_ERROR;
    };
    cache.set_sector_size(block_size);
    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
    if !cache.read_sector(0, caps.block_dev, &mut sector_buf, ipc_buf)
    {
        return ipc::fs_errors::IO_ERROR;
    }
    // The BPB lies in the sector's first 512 bytes, whatever its size.
    if !bpb::parse_bpb(&sector_buf, block_size, state)
    {
        return ipc::fs_errors::NOT_FOUND;
    }
    alloc::load_fsinfo(state, cache, caps.block_dev, ipc_buf);
    ipc::fs_errors::SUCCESS
}

/// The block device's logical block size, from `BLK_GET_GEOMETRY` on the
/// partition cap, or `None` when the driver refuses or reports a size that
/// is no FAT sector size ([`fat_parse::is_sector_size`]).
fn query_block_size(block_dev: u64, ipc_buf: *mut u64) -> Option<u32>
{
    let msg = IpcMessage::builder(ipc::blk_labels::BLK_GET_GEOMETRY)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { cache::block_call(block_dev, &msg, ipc_buf) }?;
    drop_caps(reply.caps());
    if reply.label != ipc::blk_errors::SUCCESS
    {
        std::os::seraph::log!(warn: "BLK_GET_GEOMETRY refused (label={})", reply.label);
        return None;
    }
    let size = u32::try_from(reply.word(0)).ok()?;
    if !fat_parse::is_sector_size(size as usize)
    {
        std::os::seraph::log!(warn: "unsupported device block size {size}");
        return None;
    }
    Some(size)
}

// ── Service loop ───────────────────────────────────────────────────────────

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// Main FAT service loop.
///
/// Four request shapes share one endpoint:
/// - `FS_MOUNT` and `FS_UNMOUNT` — unbadged (badge == 0); vfsd's
///   BPB-validation probe and its unmount ([`handle_unmount`]).
/// - `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` — namespace dispatch via
///   the protocol crate.
/// - Per-node `FS_*` requests — badge packs `(NodeId, NamespaceRights)`
///   and the node is resolved through `NodeTable`: `FS_SESSION`, `FS_OPEN`, the stateless
///   file ops (`FS_READ`, `FS_WRITE`, `FS_WRITE_MEMORY`, `FS_TRUNCATE`), and
///   directory mutation (`FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`,
///   `FS_RENAME`).
/// - Per-open `FS_*` requests — badge packs `(open id, NamespaceRights)`
///   with `OPEN_INSTANCE` set and the open is resolved through [`Opens`]:
///   the open's own `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, and `FS_CLOSE`, and
///   the stateless file ops on the open's node. A session cap, whose badge
///   sets `SESSION` alone, carries no request of its own: the gate refuses
///   it, and `FS_OPEN` reads it from the cap it carries.
///
/// A release under memory pressure runs at the top of a turn, once the
/// pressure thread has marked one pending and woken the loop
/// ([`release_under_pressure`]), and so does a session sweep the
/// donation-end thread marked (module docs, Session end). A request held
/// `held::SLOW_REQUEST` or longer, from its receipt to the end of its turn,
/// is logged ([`held::HeldRequest`]).
///
/// The opens are shared with the eviction worker via a `Mutex`. Main takes
/// the lock to resolve an open cap; `FS_SESSION` and `FS_OPEN` take it only
/// around a sweep and their records' update, and release it for each memmgr
/// call that takes a session a page; `FS_READ_MEMORY` releases it the same
/// way before it holds it for the whole dispatch, as `FS_RELEASE_MEMORY` and
/// `FS_CLOSE` do. A session page given back is returned to memmgr under the
/// lock. Lock contention with the worker is only material during
/// cache-pressure releases.
#[expect(
    clippy::too_many_lines,
    reason = "the loop is one dispatch over every label the driver serves, each arm a call into \
              its handler; splitting it would scatter the dispatch table across functions"
)]
fn service_loop(
    caps: &FatCaps,
    state: &mut FatState,
    nodes: &mut NodeTable,
    opens: &Arc<Mutex<Opens>>,
    cache: &'static PageCache,
    ipc_buf: *mut u64,
    eviction: &EvictionState,
) -> !
{
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    let mut session_sweeps = SweepSchedule::new();
    loop
    {
        // The last request found the block device capability revoked and
        // has been answered: the device is gone for good, so the driver
        // ends (fs-driver-protocol.md § Loss of the block device).
        if cache::device_gone()
        {
            std::process::exit(fs_labels::EXIT_DEVICE_GONE.cast_signed());
        }
        // The last request may have met a full cache on a path that does
        // not hold the opens' lock (relieve_pressure).
        if cache.take_pressure()
        {
            let req = opens
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pick_eviction_candidate();
            if let Some(req) = req
            {
                eviction.enqueue(req);
            }
        }
        // The donation-end thread marked a session sweep and woke the loop
        // (module docs, Session end).
        if SESSION_SWEEP_PENDING.swap(false, Ordering::AcqRel)
        {
            sweep_sessions(opens, &mut session_sweeps, cache);
        }
        // The pressure thread marked a release and woke the loop with a
        // call (module docs, Memory pressure).
        if RELEASE_PENDING.swap(false, Ordering::AcqRel)
        {
            release_under_pressure(cache, ipc_buf);
        }
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(caps.service, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        let opcode = msg.label & 0xFFFF;
        // Logs the request when the turn ends, after its reply, if it was
        // held too long (`held` module).
        let held = held::HeldRequest::start(opcode);

        // Unbadged service-level requests: FS_MOUNT and FS_UNMOUNT. Neither
        // carries caps, so none a request carried is kept.
        if msg.badge == 0 && opcode == fs_labels::FS_UNMOUNT
        {
            drop_caps(msg.caps());
            let unmounted = handle_unmount(&msg, state, opens, cache, caps.block_dev, ipc_buf);
            if unmounted
            {
                // The turn ends with the process, which runs no destructor:
                // the held-request check runs first.
                drop(held);
                std::process::exit(fs_labels::EXIT_UNMOUNTED.cast_signed());
            }
            continue;
        }
        if msg.badge == 0
        {
            let code = if opcode == fs_labels::FS_MOUNT
            {
                if msg.word(0) != u64::from(ipc::FS_LABELS_VERSION)
                {
                    ipc::fs_errors::LABEL_VERSION_MISMATCH
                }
                else if state.fat_size == 0
                {
                    validate_bpb(caps, state, cache, ipc_buf)
                }
                else
                {
                    ipc::fs_errors::SUCCESS
                }
            }
            else
            {
                ipc::fs_errors::UNKNOWN_OPCODE
            };
            reply_dropping_caps(&msg, opcode, code, ipc_buf);
            continue;
        }

        // NS_* requests dispatch through the protocol crate, which owns
        // both the wire-code namespace (NsError) and the rights checks
        // for those opcodes.
        if matches!(
            opcode,
            ns_labels::NS_LOOKUP | ns_labels::NS_STAT | ns_labels::NS_READDIR
        )
        {
            // No NS_* request carries a cap; any it does carry is deleted
            // so a caller cannot fill fatfs's CSpace with them.
            drop_caps(msg.caps());
            let mut backend = FatfsBackend::new(state, cache, caps.block_dev, ipc_buf, nodes);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            unsafe {
                namespace_protocol::dispatch_request(&mut backend, &msg, caps.service, ipc_buf);
            }
            continue;
        }

        // FS_* requests: gate on the rights table, replying with
        // fs_errors codes. `parent_rights` is the caller's
        // per-operation rights ceiling — the cap returned by
        // FS_CREATE/FS_MKDIR must not exceed it, or a caller holding
        // a `MUTATE_DIR`-only parent would silently gain `READ` /
        // `WRITE` / `EXEC` on every child they create. An open cap
        // resolves to its open and the open's node; `open_id` is `None`
        // for a node cap. A label sent on the wrong kind of cap is refused
        // before its rights are checked (fs-driver-protocol.md § Label 18).
        let kind = if is_open_instance(msg.badge)
        {
            CapKind::Open
        }
        else
        {
            CapKind::Node
        };
        if !label_accepts(opcode, kind)
        {
            reply_dropping_caps(&msg, opcode, ipc::fs_errors::INVALID_BADGE, ipc_buf);
            continue;
        }
        let gated = if kind == CapKind::Open
        {
            gate_open(msg.label, msg.badge).map(|(open, rights)| (None, rights, Some(open)))
        }
        else
        {
            gate(msg.label, msg.badge).map(|(node, rights)| (Some(node), rights, None))
        };
        let (node_id, parent_rights, open_ref) = match gated
        {
            Ok((node, rights, open)) =>
            {
                let node = node.or_else(|| {
                    let opens_g = opens.lock().unwrap_or_else(PoisonError::into_inner);
                    open.and_then(|open| opens_g.node(open))
                });
                let Some(node) = node
                else
                {
                    reply_dropping_caps(&msg, opcode, ipc::fs_errors::INVALID_BADGE, ipc_buf);
                    continue;
                };
                (node, rights, open)
            }
            Err(err) =>
            {
                let code = match err
                {
                    GateError::UnknownLabel => ipc::fs_errors::UNKNOWN_OPCODE,
                    GateError::PermissionDenied => ipc::fs_errors::PERMISSION_DENIED,
                    GateError::WrongKind => ipc::fs_errors::INVALID_BADGE,
                };
                reply_dropping_caps(&msg, opcode, code, ipc_buf);
                continue;
            }
        };

        // Only FS_SESSION (a charge-only handle), FS_OPEN and FS_CREATE with
        // CREATE_OPEN (a session cap and a release SEND) and FS_WRITE_MEMORY
        // (the source page) take caps; their handlers keep, return, or delete
        // each one. Every other request's caps are deleted here, so no cap a
        // request carries stays in fatfs's CSpace.
        let takes_caps = matches!(
            opcode,
            fs_labels::FS_SESSION | fs_labels::FS_OPEN | fs_labels::FS_WRITE_MEMORY
        ) || (opcode == fs_labels::FS_CREATE
            && msg.label & fs_labels::CREATE_OPEN != 0);
        if !takes_caps
        {
            drop_caps(msg.caps());
        }

        if opcode == fs_labels::FS_READ
        {
            handle_read(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
            continue;
        }

        // Mutation handlers do not need the OpenFile table lock; they
        // operate on the NodeTable + cluster allocator + dir mutation
        // + cache write-through.
        match opcode
        {
            fs_labels::FS_SESSION =>
            {
                // Takes the opens' lock itself, only around a sweep and the
                // session's start: its page request, CSpace top-up, and
                // liveness object's retype call memmgr.
                handle_session_node_cap(
                    node_id,
                    &msg,
                    nodes,
                    opens,
                    &mut session_sweeps,
                    caps,
                    cache,
                    ipc_buf,
                );
                continue;
            }
            fs_labels::FS_OPEN =>
            {
                // Takes the opens' lock itself, only around the records'
                // update: its CSpace top-up and its session's page request
                // may call memmgr.
                handle_open_node_cap(
                    node_id,
                    parent_rights,
                    &msg,
                    nodes,
                    opens,
                    caps,
                    cache,
                    ipc_buf,
                );
                continue;
            }
            fs_labels::FS_WRITE =>
            {
                handle_write(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                continue;
            }
            fs_labels::FS_WRITE_MEMORY =>
            {
                handle_write_memory(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                continue;
            }
            fs_labels::FS_CREATE =>
            {
                // With CREATE_OPEN, takes the opens' lock itself, as FS_OPEN
                // does.
                handle_create_node_cap(
                    node_id,
                    parent_rights,
                    &msg,
                    state,
                    nodes,
                    opens,
                    cache,
                    caps,
                    ipc_buf,
                );
                continue;
            }
            fs_labels::FS_REMOVE =>
            {
                handle_remove_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                release_orphaned_open_files(nodes, opens, cache);
                continue;
            }
            fs_labels::FS_MKDIR =>
            {
                handle_mkdir_node_cap(
                    node_id,
                    parent_rights,
                    &msg,
                    state,
                    nodes,
                    cache,
                    caps,
                    ipc_buf,
                );
                continue;
            }
            fs_labels::FS_RENAME =>
            {
                handle_rename_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                release_orphaned_open_files(nodes, opens, cache);
                continue;
            }
            fs_labels::FS_TRUNCATE =>
            {
                handle_truncate(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                continue;
            }
            _ =>
            {}
        }

        // A memory-cap read takes general slots for its page's ancestor and,
        // in a session, its record's page: top the CSpace up first, as
        // FS_SESSION and FS_OPEN do, since the pages outstanding across opens,
        // each open bounded alone by the slot ceiling, can outnumber the
        // per-slot ancestors the funding counts.
        if opcode == fs_labels::FS_READ_MEMORY
            && !cache.fund_run_time_headroom(startup_info().self_cspace)
        {
            reply_err(ipc::fs_errors::TOO_MANY_OPEN, ipc_buf);
            continue;
        }
        // A memory-cap read in a session first makes room for the record of
        // the page it holds, taking the session a page with the lock released.
        if opcode == fs_labels::FS_READ_MEMORY
            && let Some(open) = open_ref
            && let Err(code) = fund_held_page(open, opens, ipc_buf)
        {
            reply_err(code, ipc_buf);
            continue;
        }
        let mut opens_g = opens.lock().unwrap_or_else(PoisonError::into_inner);
        match (opcode, open_ref)
        {
            (fs_labels::FS_READ_MEMORY, Some(open)) =>
            {
                handle_read_memory_open_cap(
                    node_id,
                    open,
                    &msg,
                    state,
                    nodes,
                    &mut opens_g,
                    caps,
                    cache,
                    ipc_buf,
                    eviction,
                );
            }
            (fs_labels::FS_RELEASE_MEMORY, Some(open)) =>
            {
                handle_release_memory_open_cap(open, &msg, &mut opens_g, cache, ipc_buf);
            }
            (fs_labels::FS_CLOSE, Some(open)) =>
            {
                handle_close_open_cap(open, &mut opens_g, cache, ipc_buf);
            }
            _ =>
            {
                let reply = IpcMessage::new(ipc::fs_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
        }
    }
}

/// The kind of cap a badged request arrived on, told apart by the badge's
/// `OPEN_INSTANCE` bit: a node cap (one `NS_LOOKUP`, `FS_CREATE`, or
/// `FS_MKDIR` minted, or the mount's root cap vfsd derives) or an open cap
/// (one `FS_OPEN` minted).
#[derive(Clone, Copy, PartialEq, Eq)]
enum CapKind
{
    Node,
    Open,
}

/// Whether `opcode` may be sent on a cap of `kind`, per
/// services/fs/docs/fs-driver-protocol.md § Label 18. An open's own labels
/// (`FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, `FS_CLOSE`) need an open cap;
/// `FS_OPEN` and directory mutation need a node cap; the stateless file
/// labels take either. `FS_SESSION` needs a node cap
/// (services/fs/docs/fs-driver-protocol.md § Label 23). Any other opcode
/// passes, so the rights gate answers it `UNKNOWN_OPCODE`. A misdirected
/// label is answered `INVALID_BADGE`.
fn label_accepts(opcode: u64, kind: CapKind) -> bool
{
    match opcode
    {
        fs_labels::FS_READ_MEMORY | fs_labels::FS_RELEASE_MEMORY | fs_labels::FS_CLOSE =>
        {
            kind == CapKind::Open
        }
        fs_labels::FS_SESSION
        | fs_labels::FS_OPEN
        | fs_labels::FS_CREATE
        | fs_labels::FS_REMOVE
        | fs_labels::FS_MKDIR
        | fs_labels::FS_RENAME => kind == CapKind::Node,
        _ => true,
    }
}

/// Delete every cap in `caps` from fatfs's `CSpace`: caps a request carried
/// that its handler neither records nor returns.
fn drop_caps(caps: &[u64])
{
    for &cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
}

// ── Operation handlers ─────────────────────────────────────────────────────

/// `FS_READ` against a node cap or an open cap, `node_id` being the node
/// either names. Resolves `node_id` against the `NodeTable` and reads from
/// the FAT cluster chain. Inline reads touch no open: no outstanding pages,
/// no release bookkeeping.
fn handle_read(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &NodeTable,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let Some(node) = nodes.get(node_id)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_BADGE);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    if node.kind != NodeKind::File
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_BADGE);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let offset = msg.word(0);
    // The reply carries the count in word 0, so the data fits in the
    // remaining MSG_DATA_WORDS_MAX - 1 words.
    let max_len = msg.word(1).min(((MSG_DATA_WORDS_MAX - 1) * 8) as u64);

    let mut out = [0u8; MAX_SECTOR_SIZE];
    let bytes_read = match read_file_data(
        &fat::FileRead {
            start_cluster: node.cluster,
            file_size: node.size,
            offset,
            max_len,
        },
        state,
        cache,
        block_dev,
        ipc_buf,
        &mut out,
    )
    {
        Ok(n) => n,
        Err(e) =>
        {
            reply_err(fat_error_to_wire(e), ipc_buf);
            return;
        }
    };

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, bytes_read as u64)
        .bytes(1, out.get(..bytes_read).unwrap_or_default())
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_READ_MEMORY` body, parameterised by the resolved node and the open
/// the page is read for. `handle_read_memory_open_cap` checks both and
/// delegates here for the cluster walk, cache acquisition, two-step cap
/// derivation, and outstanding-page tracking on that open. The file's size
/// and first cluster come from `node`, the node table's current view, so a
/// write or truncate through any cap on the node is seen at once.
#[expect(
    clippy::too_many_lines,
    reason = "the read is one sequence (validate, resolve the sector, pin a cache page, mint and \
              record the cap, reply) whose steps share the slot state"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the request, its node and open, and each piece of driver state the memory-cap read \
              touches (FAT state, opens, cache, block device, IPC buffer, eviction state)"
)]
#[expect(
    clippy::large_stack_frames,
    reason = "the `reply` `IpcMessage`s (568 B each) of its eight reply paths and the builder's \
              copy; on the 32 KiB main-thread stack of fatfs"
)]
fn read_memory_for_open(
    msg: &IpcMessage,
    node: &backend::FatNode,
    open: OpenRef,
    state: &mut FatState,
    opens: &mut Opens,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
    eviction: &EvictionState,
)
{
    let offset = msg.word(0);
    let cookie = msg.word(1);

    if cookie == 0
    {
        // Cookie 0 collides with the OutstandingPage::None sentinel.
        let reply = IpcMessage::new(ipc::fs_errors::BAD_MEMORY_OFFSET);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let Some(left_in_file) = u64::from(node.size).checked_sub(offset).filter(|&n| n > 0)
    else
    {
        // EOF: zero bytes valid, no cap.
        let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
            .word(0, 0)
            .word(1, cookie)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    // A non-empty file's first cluster comes from its directory entry,
    // untrusted on-disk input; one outside the data region is corrupt.
    let Some(pos) = state
        .file_position(offset)
        .filter(|_| state.is_data_cluster(node.cluster))
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    // Walk the cluster chain to find the sector at `offset`, from the open's
    // cursor when it still serves (storage-layout.md, Open table).
    let (walked, mut cluster) = fat_parse::walk_start(
        opens.cursor(open),
        state.chain_epoch,
        node.cluster,
        pos.cluster_index,
    );
    // `offset` is below the `u32` file size, so the walk ends within
    // `u32::MAX / cluster_size` steps even on a cyclic chain.
    for _ in walked..pos.cluster_index
    {
        if let Some(c) = next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            cluster = c;
        }
        else
        {
            // A FAT sector read that met a full cache fails the walk.
            relieve_pressure(opens, cache, eviction);
            reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
            return;
        }
    }
    let cursor = fat_parse::ChainCursor {
        epoch: state.chain_epoch,
        first_cluster: node.cluster,
        cluster_index: pos.cluster_index,
        cluster,
    };
    let sequential = opens.note_read(open, cursor, offset);
    let sector = u64::from(
        state
            .cluster_to_sector(cluster)
            .saturating_add(pos.sector_in_cluster),
    );
    // The file's byte at `offset` lives at memory-cap offset
    // `sector_offset + offset_in_sector` within the returned slot: the
    // sector's place in its page, then the byte's in its sector. For sector-
    // and page-aligned data areas the sector term folds to zero; for
    // misaligned data areas (data area starting mid-page) it is non-zero on
    // the page boundary. The sector lies inside its page, so the byte does
    // and the page holds at least one byte from it; the check only keeps
    // the arithmetic total.
    let (page_base, sector_offset) = cache.page_of(sector);
    let Some((memory_data_offset, page_left)) = sector_offset
        .checked_add(pos.offset_in_sector as u64)
        .and_then(|off| Some((off, PAGE_SIZE.checked_sub(off).filter(|&n| n > 0)?)))
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };

    // A sequential scan that misses fills a run of the pages it reads next
    // (storage-layout.md, Page cache); sizing the run walks the chain, so
    // only a miss pays for it.
    let run = if sequential && !cache.contains_page(page_base)
    {
        read_run_pages(
            &ReadRun {
                cluster,
                pos: &pos,
                sector,
                page_base,
                left_in_file,
            },
            state,
            cache,
            block_dev,
            ipc_buf,
        )
    }
    else
    {
        1
    };
    let Some(slot_idx) = cache.acquire_page_run(page_base, run, block_dev, ipc_buf)
    else
    {
        // Cache pressure, when every slot is held by an outstanding page:
        // the client retries this read on IO_ERROR.
        relieve_pressure(opens, cache, eviction);
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let slot_cap = cache.slot_memory_cap(slot_idx);
    if slot_cap == 0
    {
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let Ok(ancestor) = syscall::cap_derive(slot_cap, RIGHTS_MEM_MAP)
    else
    {
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let Ok(child) = syscall::cap_derive(ancestor, RIGHTS_MEM_MAP)
    else
    {
        let _ = syscall::cap_delete(ancestor);
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    // From here the client may map the page; the slot is reused only once
    // that mapping is gone (cache module docs § Reuse of a page a client
    // mapped).
    cache.mark_exposed(slot_idx);
    let entry = OutstandingPage {
        cookie,
        slot_idx,
        ancestor_cap: ancestor,
        eviction_queued: false,
    };
    // bytes_valid is bounded by:
    //   - file end:    file_size - offset
    //   - one cluster: cluster_size - offset_in_cluster
    //                  (we only read sectors from one cluster per call)
    //   - memory-cap tail:  PAGE_SIZE - memory_data_offset
    //                  (bytes before memory_data_offset belong to other files
    //                   or the previous cluster's leftover sectors)
    // None bounds a file: the client reads on with further calls.
    let bytes_valid = left_in_file.min(pos.left_in_cluster).min(page_left);
    let ceiling = cache.slot_ceiling();
    // Below the `u32` file size, so it never saturates.
    let next_read = offset.saturating_add(bytes_valid);
    if !opens.track(open, entry, ceiling, next_read)
    {
        let _ = syscall::cap_delete(child);
        let _ = syscall::cap_delete(ancestor);
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::TOO_MANY_OPEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, bytes_valid)
        .word(1, cookie)
        .word(2, memory_data_offset)
        .cap(child)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Where a memory-cap read's sector lies, for sizing its run fill
/// ([`read_run_pages`]).
struct ReadRun<'a>
{
    /// The cluster holding the sector.
    cluster: u32,
    /// The read's place in the file.
    pos: &'a fat_parse::FilePosition,
    /// The sector holding the read's first byte.
    sector: u64,
    /// The first sector of that sector's cache page.
    page_base: u64,
    /// Bytes of the file from the read's first byte.
    left_in_file: u64,
}

/// Pages a memory-cap read's miss fills on a sequential scan
/// (storage-layout.md, Page cache): from the read's page through the
/// sectors the chain holds contiguously from the read's cluster on, up to
/// the file's end and the cache's run capacity; at least 1. A FAT read that
/// fails ends the contiguous span there.
fn read_run_pages(
    read: &ReadRun<'_>,
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> u64
{
    let max_pages = PageCache::run_capacity();
    if max_pages <= 1
    {
        return 1;
    }
    // Mount refuses a zero sector size or cluster size.
    let spc = NonZeroU64::new(u64::from(state.sectors_per_cluster)).unwrap_or(NonZeroU64::MIN);
    let bps = NonZeroU64::new(u64::from(state.bytes_per_sector)).unwrap_or(NonZeroU64::MIN);
    let spp = cache.sectors_per_page();
    let bound = fat_parse::run_cluster_bound(max_pages, spp, read.pos.sector_in_cluster, spc);
    let clusters = fat_parse::contiguous_clusters(read.cluster, bound, |c| {
        next_cluster(state, c, cache, block_dev, ipc_buf)
    });
    let chain_end = u64::from(state.cluster_to_sector(read.cluster))
        .saturating_add(u64::from(clusters).saturating_mul(spc.get()));
    let file_end = fat_parse::file_end_sector(
        read.sector,
        read.pos.offset_in_sector as u64,
        read.left_in_file,
        bps,
    );
    fat_parse::run_pages(read.page_base, chain_end.min(file_end), spp, max_pages)
}

/// When a page acquisition found every cache slot held since the last check
/// ([`PageCache::take_pressure`]), queue one held page for eviction
/// ([`Opens::pick_eviction_candidate`]): the eviction worker frees its slot
/// within `eviction::RELEASE_TIMEOUT_MS`, and the client retries the request
/// it was answered `IO_ERROR`. Called before the reply on the memory-cap read
/// path, and before each receive for every other path that reads through the
/// cache (FAT walks, directory reads, inline reads). `None` from the pick
/// means every held page is queued already, or none is held (then the
/// acquisition's failure is a cache-state bug rather than client-held
/// pressure).
fn relieve_pressure(opens: &mut Opens, cache: &PageCache, eviction: &EvictionState)
{
    if cache.take_pressure()
        && let Some(req) = opens.pick_eviction_candidate()
    {
        eviction.enqueue(req);
    }
}

/// `FS_SESSION` against a node cap (services/fs/docs/fs-driver-protocol.md
/// § Label 23): start a session charged through the charge-only handle
/// `caps[0]` carries (any further cap is deleted), in a first page memmgr
/// charges to that handle's node, which the session keeps for its life; reply
/// with a session cap whose badge names it, carrying `RIGHTS_EP_IDENTIFY`
/// beside `SEND`, and the session's liveness cap.
/// The sessions are swept for those whose client is gone when
/// `session_sweeps` says a sweep is due. A reply the client cannot take moves
/// no cap, so the session is ended at once.
#[expect(
    clippy::too_many_arguments,
    reason = "the request, its node, and the driver state a session touches (node table, opens and \
              their sweep schedule, endpoint caps, cache, IPC buffer)"
)]
fn handle_session_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    nodes: &NodeTable,
    opens: &Mutex<Opens>,
    session_sweeps: &mut SweepSchedule,
    caps: &FatCaps,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let opcode = fs_labels::FS_SESSION;
    // The mount's root cap names `NodeId(0)`, which the node table never
    // holds; any other id names a node the table must still hold.
    if node_id.raw() != 0 && nodes.get(node_id).is_none()
    {
        reply_dropping_caps(msg, opcode, ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    }
    let Some((&handle, rest)) = msg.caps().split_first()
    else
    {
        reply_err(ipc::fs_errors::INVALID_ARGUMENT, ipc_buf);
        return;
    };
    drop_caps(rest);
    let refuse = |code: u64| {
        let _ = syscall::cap_delete(handle);
        reply_err(code, ipc_buf);
    };
    if session_sweeps.note_new()
    {
        sweep_sessions(opens, session_sweeps, cache);
    }
    if !cache.fund_run_time_headroom(startup_info().self_cspace)
    {
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    }
    let grant = match session::request_page(handle, ipc_buf)
    {
        Ok(grant) => grant,
        Err(code) =>
        {
            refuse(code);
            return;
        }
    };
    let Some(liveness) = Liveness::create()
    else
    {
        session::release_page(grant);
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    };
    let started = opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .start_session(grant, handle, liveness.parent);
    let Ok(id) = started
    else
    {
        liveness.discard();
        session::release_page(grant);
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    };
    let end = || {
        opens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .end_session_by_id(id, cache);
    };
    // A session cap carries no namespace rights: it names the session, and
    // FS_OPEN reads it from the cap the open carries. Its endpoint rights add
    // IDENTIFY, so its holder can ask the kernel whether a node cap is on this
    // driver's endpoint (SYS_ENDPOINT_IDENTIFY) and find the session for it.
    let minted = pack_session(id).and_then(|badge| {
        syscall::cap_derive_badge(
            caps.service,
            syscall::RIGHTS_EP_SEND | syscall::RIGHTS_EP_IDENTIFY,
            badge,
        )
        .ok()
    });
    let Some(session_cap) = minted
    else
    {
        // Ending the session revokes the liveness child with its parent.
        end();
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .cap(session_cap)
        .cap(liveness.child)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(session_cap);
        end();
    }
}

/// End every session whose client holds no copy of its liveness cap any
/// more, and restart `session_sweeps` from the sessions left.
fn sweep_sessions(opens: &Mutex<Opens>, session_sweeps: &mut SweepSchedule, cache: &PageCache)
{
    let left = opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .sweep_sessions(cache);
    session_sweeps.swept(left);
}

/// `FS_OPEN` against a file node cap (services/fs/docs/fs-driver-protocol.md
/// § Label 18). The open is made in the session the request's session cap
/// names ([`request_session`], [`open_in_session`]), with the release SEND
/// `caps[1]` carries.
#[expect(
    clippy::too_many_arguments,
    reason = "the request, its node and rights, and the driver state an open touches (node table, \
              opens, endpoint caps, cache, IPC buffer)"
)]
fn handle_open_node_cap(
    node_id: NodeId,
    rights: NamespaceRights,
    msg: &IpcMessage,
    nodes: &NodeTable,
    opens: &Mutex<Opens>,
    caps: &FatCaps,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let opcode = fs_labels::FS_OPEN;
    if nodes.get(node_id).is_none_or(|n| n.kind != NodeKind::File)
    {
        reply_dropping_caps(msg, opcode, ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    }
    let (id, release_send) = match request_session(msg, caps.service)
    {
        Ok(session) => session,
        Err(code) =>
        {
            reply_dropping_caps(msg, opcode, code, ipc_buf);
            return;
        }
    };
    open_in_session(
        id,
        OpenRequest {
            node_id,
            rights,
            service: caps.service,
            release_send,
        },
        opens,
        cache,
        ipc_buf,
    );
}

/// The session a request's `caps[0]` names, and the release SEND its
/// `caps[1]` carries (0 for none): the caps of `FS_OPEN` and of `FS_CREATE`
/// with `CREATE_OPEN`. Every open is made in a session. On success the
/// session cap and every cap past the release SEND are deleted, and the SEND
/// is the caller's. On a refusal every cap is left for
/// [`reply_dropping_caps`], and the error is the `fs_errors` code:
/// `INVALID_ARGUMENT` for no `caps[0]` or one on another endpoint,
/// `INVALID_BADGE` for one on the driver's endpoint that is no session cap.
fn request_session(msg: &IpcMessage, service: u64) -> Result<(u64, u64), u64>
{
    let all = msg.caps();
    // A cap on another endpoint (or none) leaves the badge read refused.
    let session = all
        .first()
        .map(|&cap| syscall::endpoint_badge(service, cap).map(session_id));
    let id = match session
    {
        Some(Ok(Some(id))) => id,
        Some(Ok(None)) => return Err(ipc::fs_errors::INVALID_BADGE),
        _ => return Err(ipc::fs_errors::INVALID_ARGUMENT),
    };
    let (release_send, rest) = match all.get(1..).and_then(<[u64]>::split_first)
    {
        Some((&send, rest)) => (send, rest),
        None => (0, &[][..]),
    };
    let _ = all.first().copied().map(syscall::cap_delete);
    drop_caps(rest);
    Ok((id, release_send))
}

/// What an `FS_OPEN` asks for: the node, the rights the open cap carries,
/// the release SEND the open keeps (0 for none), and the service endpoint the
/// open cap is minted on. The open cap carries the node cap's rights and
/// `SEND_GRANT`, as a node cap does, so `FS_WRITE_MEMORY` can carry its
/// source page on it.
#[derive(Clone, Copy)]
struct OpenRequest
{
    node_id: NodeId,
    rights: NamespaceRights,
    service: u64,
    release_send: u64,
}

impl OpenRequest
{
    /// Delete the release SEND and reply `code`: a refusal before the open
    /// keeps the SEND.
    fn refuse(self, code: u64, ipc_buf: *mut u64)
    {
        if self.release_send != 0
        {
            let _ = syscall::cap_delete(self.release_send);
        }
        reply_err(code, ipc_buf);
    }

    /// Mint the open cap of the open `id`: a badged `SEND_GRANT` whose badge
    /// names the open and carries the request's rights. `None` when the
    /// driver cannot derive it.
    fn mint(self, id: u64) -> Option<u64>
    {
        pack_open(id, self.rights).and_then(|badge| {
            syscall::cap_derive_badge(self.service, syscall::RIGHTS_EP_SEND_GRANT, badge).ok()
        })
    }
}

/// An `FS_OPEN` in the session `session` names: record the open
/// ([`record_open`]) and reply with an open cap whose badge names the open.
/// A reply the client cannot take moves no cap, so the open is closed at
/// once.
fn open_in_session(
    session: u64,
    open: OpenRequest,
    opens: &Mutex<Opens>,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let Some(id) = record_open(session, open, opens, cache, ipc_buf)
    else
    {
        return;
    };
    let close = || {
        opens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .close(OpenRef(id), cache);
    };
    let Some(open_cap) = open.mint(id)
    else
    {
        // Closing the open deletes its release SEND.
        close();
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .cap(open_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(open_cap);
        close();
    }
}

/// Record an open of `open.node_id` in the session `session` names, with
/// its release SEND, taking the session another page when its pages are
/// full, with the opens unlocked, since the request calls memmgr. The open's
/// state lives in pages its client pays for; what stays on fatfs is the
/// release SEND's slot and the open cap's. Returns the open's id. On a
/// refusal the SEND is deleted and the refusal replied, and `None` returned:
/// `TOO_MANY_OPEN` when the `CSpace` cannot be topped up or the driver is
/// spent, `LIMIT` when the page would exceed the max of the session's node or
/// an ancestor's, `INVALID_BADGE` when the session has ended, and memmgr's
/// other refusals as [`session::request_page`] maps them.
fn record_open(
    session: u64,
    open: OpenRequest,
    opens: &Mutex<Opens>,
    cache: &PageCache,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    if !cache.fund_run_time_headroom(startup_info().self_cspace)
    {
        open.refuse(ipc::fs_errors::TOO_MANY_OPEN, ipc_buf);
        return None;
    }
    let room = opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .room_for_open(session);
    if let Err(refusal) = room.or_else(|r| take_page(session, r, opens, ipc_buf))
    {
        open.refuse(refusal_code(refusal), ipc_buf);
        return None;
    }
    let recorded = opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .open_in_session(session, open.node_id, open.release_send);
    match recorded
    {
        Ok(id) => Some(id),
        Err(refusal) =>
        {
            open.refuse(refusal_code(refusal), ipc_buf);
            None
        }
    }
}

/// When `refusal` asks for a page, take the session `session` names one,
/// charged through the handle the refusal carries, with the opens unlocked
/// for the memmgr call, and add it. The `fs_errors` code to answer when no
/// page could be added.
fn take_page(
    session: u64,
    refusal: SessionRefusal,
    opens: &Mutex<Opens>,
    ipc_buf: *mut u64,
) -> Result<(), SessionRefusal>
{
    let SessionRefusal::NeedPage(handle) = refusal
    else
    {
        return Err(refusal);
    };
    // Only this thread ends a session, so the handle outlives the call.
    let grant = session::request_page(handle, ipc_buf).map_err(SessionRefusal::Memmgr)?;
    let added = opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .add_page(session, grant);
    if added.is_err()
    {
        session::release_page(grant);
    }
    added
}

/// The `fs_errors` code a request a session refused is answered.
const fn refusal_code(refusal: SessionRefusal) -> u64
{
    match refusal
    {
        SessionRefusal::Gone => ipc::fs_errors::INVALID_BADGE,
        SessionRefusal::Memmgr(code) => code,
        // A page was just added, or none can be: the driver is spent.
        SessionRefusal::NeedPage(_) | SessionRefusal::Spent => ipc::fs_errors::TOO_MANY_OPEN,
    }
}

/// Before a memory-cap read on `open`, make room in its session for the
/// record of the page the read holds ([`take_page`]). `Ok` for an open that
/// is not live, which the read refuses. The error is
/// the `fs_errors` code to answer.
fn fund_held_page(open: OpenRef, opens: &Mutex<Opens>, ipc_buf: *mut u64) -> Result<(), u64>
{
    let (room, session) = {
        let opens_g = opens.lock().unwrap_or_else(PoisonError::into_inner);
        (opens_g.room_for_held(open), opens_g.session_of(open))
    };
    match (room, session)
    {
        (Err(refusal), Some(session)) =>
        {
            take_page(session, refusal, opens, ipc_buf).map_err(refusal_code)
        }
        _ => Ok(()),
    }
}

/// The two caps of a new session's liveness Notification: the parent fatfs
/// keeps on it, and the zero-rights child the `FS_SESSION` reply hands the
/// client (services/fs/docs/fs-driver-protocol.md § Label 23).
struct Liveness
{
    parent: u64,
    child: u64,
}

impl Liveness
{
    /// Retype a Notification from fatfs's own object slab and derive the
    /// client's copy. `None` when memmgr cannot fund the retype or the
    /// `CSpace` has no slot for either cap.
    fn create() -> Option<Self>
    {
        let parent = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )?;
        // Zero rights: the copy can neither signal nor wait; holding it is
        // its only use.
        if let Ok(child) = syscall::cap_derive(parent, 0)
        {
            Some(Self { parent, child })
        }
        else
        {
            let _ = syscall::cap_delete(parent);
            None
        }
    }

    /// Delete both caps of a liveness object no session or open kept, which
    /// frees the Notification.
    fn discard(self)
    {
        let _ = syscall::cap_delete(self.child);
        let _ = syscall::cap_delete(self.parent);
    }
}

/// `FS_UNMOUNT` (services/fs/docs/fs-driver-protocol.md § Label 19): sweep
/// the sessions whose client is gone, then refuse with `BUSY` and the count
/// of live opens, unless none is left or
/// the request carries `UNMOUNT_FORCE`; a session with no open does not
/// count. Otherwise release every open as `FS_CLOSE` would and end every
/// session, which revokes the client's liveness and page caps and gives the
/// session pages back, write the `FSInfo` hints of a mounted
/// volume, reply, and return `true`, after which the caller ends its turn
/// and exits the process; a refused unmount returns `false`. The single
/// dispatch thread runs this between requests, so no request of this driver
/// is in flight; the eviction worker finds the opens gone when it next takes
/// their lock.
fn handle_unmount(
    msg: &IpcMessage,
    state: &mut FatState,
    opens: &Mutex<Opens>,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> bool
{
    if msg.word(0) != u64::from(ipc::FS_LABELS_VERSION)
    {
        reply_err(ipc::fs_errors::LABEL_VERSION_MISMATCH, ipc_buf);
        return false;
    }
    let mut opens_g = opens.lock().unwrap_or_else(PoisonError::into_inner);
    opens_g.sweep_sessions(cache);
    let live = opens_g.live_opens();
    if live != 0 && msg.label & fs_labels::UNMOUNT_FORCE == 0
    {
        drop(opens_g);
        let reply = IpcMessage::builder(ipc::fs_errors::BUSY)
            .word(0, live as u64)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return false;
    }
    opens_g.release_all(cache);
    drop(opens_g);
    if state.fat_size != 0
    {
        alloc::flush_fsinfo(state, cache, block_dev, ipc_buf);
    }
    std::os::seraph::log!("unmounted ({live} opens released); exiting");
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(ipc::fs_errors::SUCCESS), ipc_buf) };
    true
}

/// `FS_READ_MEMORY` against an open cap: the page is tracked
/// on that open and its cooperative release goes to that open's release SEND. Delegates
/// to [`read_memory_for_open`].
#[expect(
    clippy::too_many_arguments,
    reason = "the request, its node and open, plus the driver state `read_memory_for_open` needs, \
              which this handler forwards"
)]
fn handle_read_memory_open_cap(
    node_id: NodeId,
    open: OpenRef,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &NodeTable,
    opens: &mut Opens,
    caps: &FatCaps,
    cache: &PageCache,
    ipc_buf: *mut u64,
    eviction: &EvictionState,
)
{
    let Some(node) = nodes.get(node_id)
    else
    {
        reply_err(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    };
    if node.kind != NodeKind::File || opens.node(open).is_none()
    {
        reply_err(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    }
    read_memory_for_open(
        msg,
        &node,
        open,
        state,
        opens,
        cache,
        caps.block_dev,
        ipc_buf,
        eviction,
    );
}

/// Reply `code` holding none of the caps the request carried: an
/// `FS_WRITE_MEMORY` source page goes back in the reply, as § Label 12
/// promises in every outcome, and any other cap (an `FS_OPEN` session cap or
/// release SEND, an `FS_SESSION` handle) is deleted. Used for requests refused before any cap they
/// carry is recorded or consumed (the dispatch loop's rights-gate and
/// unknown or unbadged label refusals, the cap-kind refusal, and the
/// `FS_OPEN` handler's refusals before it records the SEND) and for
/// `FS_MOUNT`, which carries no caps.
fn reply_dropping_caps(msg: &IpcMessage, opcode: u64, code: u64, ipc_buf: *mut u64)
{
    let mut builder = IpcMessage::builder(code);
    for &cap in msg.caps()
    {
        if opcode == fs_labels::FS_WRITE_MEMORY
        {
            builder = builder.cap(cap);
        }
        else
        {
            let _ = syscall::cap_delete(cap);
        }
    }
    let reply = builder.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_RELEASE_MEMORY` against an open cap: drop the open's outstanding
/// page `data[0]` names. A cookie matching no page of the open is a no-op
/// success (release is idempotent); a closed open is `INVALID_BADGE`.
fn handle_release_memory_open_cap(
    open: OpenRef,
    msg: &IpcMessage,
    opens: &mut Opens,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let code = if opens.release_held(open, msg.word(0), cache)
    {
        ipc::fs_errors::SUCCESS
    }
    else
    {
        ipc::fs_errors::INVALID_BADGE
    };
    reply_err(code, ipc_buf);
}

/// `FS_CLOSE` against an open cap: remove the open, which retires its
/// identifier, and release its pages and release SEND. Other opens of the
/// node are untouched, and the node lives until its entry is removed
/// ([`NodeTable`]); a session lives on with its other opens. The kernel-side
/// cap reference is dropped by the caller's paired `cap_delete`.
fn handle_close_open_cap(open: OpenRef, opens: &mut Opens, cache: &PageCache, ipc_buf: *mut u64)
{
    let code = if opens.close(open, cache)
    {
        ipc::fs_errors::SUCCESS
    }
    else
    {
        ipc::fs_errors::INVALID_BADGE
    };
    reply_err(code, ipc_buf);
}

/// Release every open of the node an `FS_REMOVE` or
/// `FS_RENAME` freed ([`NodeTable::take_orphaned_node`]), under the opens'
/// lock the eviction worker shares.
fn release_orphaned_open_files(nodes: &mut NodeTable, opens: &Mutex<Opens>, cache: &PageCache)
{
    let Some(node_id) = nodes.take_orphaned_node()
    else
    {
        return;
    };
    opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .close_node(node_id, cache);
}

// ── Write / mutation handlers ──────────────────────────────────────────────

/// Map a [`FatError`] to its wire-side `fs_errors` code.
fn fat_error_to_wire(err: FatError) -> u64
{
    match err
    {
        // I/O and corrupt are both surfaced as IO_ERROR — clients
        // don't distinguish, and "corrupt" without recovery state is
        // an I/O-level failure from their point of view.
        FatError::Io | FatError::Corrupt => ipc::fs_errors::IO_ERROR,
        // A FAT file cannot grow past u32::MAX bytes: no space for it.
        FatError::NoSpace | FatError::FileTooLarge => ipc::fs_errors::NO_SPACE,
        FatError::Exists => ipc::fs_errors::EXISTS,
    }
}

fn reply_err(code: u64, ipc_buf: *mut u64)
{
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Resolve a parent-dir `NodeId` to the directory's cluster number.
/// `NodeId(0)` is the root; FAT16 returns the sentinel cluster 0, FAT32
/// returns `state.root_cluster`.
///
/// # Errors
/// The `fs_errors` code to reply: `INVALID_BADGE` when a non-root id is
/// absent from the table or names a file; `IO_ERROR` when it names a
/// directory whose cluster lies outside the data region. That cluster
/// comes from a corrupt directory entry: cluster 0 would name the FAT16
/// fixed root, so serving it would turn a cap on the subdirectory into
/// one on the root.
fn resolve_dir_cluster(node_id: NodeId, state: &FatState, nodes: &NodeTable) -> Result<u32, u64>
{
    if node_id.raw() == 0
    {
        return Ok(match state.fat_type
        {
            bpb::FatType::Fat32 => state.root_cluster,
            bpb::FatType::Fat16 => 0,
        });
    }
    let node = nodes
        .get(node_id)
        .filter(|n| n.kind == NodeKind::Dir)
        .ok_or(ipc::fs_errors::INVALID_BADGE)?;
    if !state.is_data_cluster(node.cluster)
    {
        return Err(ipc::fs_errors::IO_ERROR);
    }
    Ok(node.cluster)
}

/// Common cluster-walk-and-write engine used by `FS_WRITE` and
/// `FS_WRITE_MEMORY`. Walks the file's cluster chain from `offset`, or
/// from the file's old size when that is lower, allocating new clusters as
/// needed, and writes zeros up to `offset`, then `data`, sector by sector
/// through [`PageCache::write_sector`] (read-modify-write for a sector
/// holding old bytes of the file the write leaves,
/// [`fat_parse::sector_write`]). Returns the file's (possibly-updated)
/// first cluster and its new size.
///
/// The chain is extended only at its end-of-chain marker: a failed FAT
/// read or a corrupt link is an error, never a place to link a new
/// cluster (which would cut the chain's tail off).
///
/// # Errors
/// [`FatError::FileTooLarge`] when the write would end past `u32::MAX`
/// bytes, the largest size a FAT directory entry records, checked before
/// any cluster is allocated; [`FatError::Corrupt`] when the file's first
/// cluster or a chain link lies outside the data region; otherwise the
/// errors of [`allocate_cluster`] and [`FatError::Io`] for a failed FAT or
/// data sector read or write.
#[expect(
    clippy::too_many_arguments,
    reason = "the engine takes the file's extent, the write, and the driver state it writes \
              through (FAT state, cache, block device, IPC buffer), shared by two callers with \
              different request shapes"
)]
fn write_file_bytes(
    start_cluster: u32,
    file_size: u32,
    offset: u64,
    data: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> Result<(u32, u32), FatError>
{
    if data.is_empty()
    {
        return Ok((start_cluster, file_size));
    }
    // The client chooses `offset`: bound the end before the walk below
    // allocates one cluster per index up to it.
    let end = offset
        .checked_add(data.len() as u64)
        .and_then(|end| u32::try_from(end).ok())
        .ok_or(FatError::FileTooLarge)?;

    // Bootstrap: if the file currently holds no chain (size 0 / cluster
    // 0), allocate the first cluster now.
    let mut chain_head = start_cluster;
    if chain_head < 2
    {
        chain_head = allocate_cluster(state, None, cache, block_dev, ipc_buf)?;
    }
    else if !state.is_data_cluster(chain_head)
    {
        // The first cluster comes from the directory entry, untrusted
        // on-disk input.
        return Err(FatError::Corrupt);
    }

    // A write past the file's end writes the gap between the old end and
    // `offset` as zeros, in the same pass as the payload: the clusters and
    // sectors it covers may hold an earlier owner's bytes, and every byte
    // below the new size must read as written or as zero
    // (services/fs/docs/fs-driver-protocol.md § Label 4: `FS_WRITE`).
    let start = offset.min(u64::from(file_size));
    let mut cluster = chain_head;
    let first = state.file_position(start).ok_or(FatError::Corrupt)?;

    // Walk to the cluster holding `start`. When we hit EOC, the current
    // `cluster` is the terminal one — `allocate_cluster(Some(cluster))`
    // links the new cluster after it. (A previous version threaded a
    // separate `prev` that was updated after `cluster`, so on
    // append-past-EOC it linked the new cluster behind the prior
    // terminal, overwriting that terminal's existing forward link and
    // orphaning the original tail.) `end` fits a `u32`, so the walk ends
    // within `u32::MAX / cluster_size` steps even on a cyclic chain.
    for _ in 0..first.cluster_index
    {
        cluster = match chain_next(state, cluster, cache, block_dev, ipc_buf)?
        {
            Some(c) => c,
            None => allocate_cluster(state, Some(cluster), cache, block_dev, ipc_buf)?,
        };
    }

    let mut cluster_index = first.cluster_index;
    let mut rest = data;
    let mut cur_offset = start;
    while cur_offset < u64::from(end)
    {
        let pos = state.file_position(cur_offset).ok_or(FatError::Corrupt)?;
        // The previous sector ended its cluster: move on to the next one.
        if pos.cluster_index != cluster_index
        {
            cluster = match chain_next(state, cluster, cache, block_dev, ipc_buf)?
            {
                Some(c) => c,
                None => allocate_cluster(state, Some(cluster), cache, block_dev, ipc_buf)?,
            };
            cluster_index = pos.cluster_index;
        }
        let sector_lba = state
            .cluster_to_sector(cluster)
            .saturating_add(pos.sector_in_cluster);
        let share = fat_parse::sector_write(
            &pos,
            cur_offset,
            offset,
            u64::from(end),
            u64::from(file_size),
        )
        .ok_or(FatError::Corrupt)?;
        let (chunk, tail) = rest.split_at_checked(share.data).unwrap_or((rest, &[]));

        // Read-modify-write the sector only when it holds old bytes of the
        // file the share leaves; any other sector is written from zeros.
        // Heap-allocated to keep the write-path frame within the default
        // 32 KiB stack envelope when release LTO inlines the nested helpers
        // (`insert_entry → write_dir_slot → ...`).
        let mut sector_buf = sector_buffer()?;
        if share.read_first
            && !cache.read_sector(u64::from(sector_lba), block_dev, &mut *sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }
        // The share ends at or before the sector's end.
        let (gap, payload) = state
            .sector_mut(&mut sector_buf)
            .get_mut(pos.offset_in_sector..)
            .and_then(|dst| dst.split_at_mut_checked(share.zeros))
            .ok_or(FatError::Corrupt)?;
        gap.fill(0);
        for (d, &b) in payload.iter_mut().zip(chunk)
        {
            *d = b;
        }
        if !cache.write_sector(u64::from(sector_lba), block_dev, &*sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }

        rest = tail;
        // Bounded by `end`, a `u32`, so neither step saturates.
        cur_offset = cur_offset
            .saturating_add(share.zeros as u64)
            .saturating_add(chunk.len() as u64);
    }

    debug_assert_eq!(cur_offset, u64::from(end));
    let new_size = file_size.max(end);
    Ok((chain_head, new_size))
}

/// `FS_WRITE` inline write. Badge = file node cap or open cap (must carry
/// `WRITE`), `node_id` the node either names.
/// `label[16..32]` = byte length (≤504), `data[0]` = offset, payload
/// bytes packed from word 1 onward.
fn handle_write(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let Some(node) = nodes.get(node_id)
    else
    {
        reply_err(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    };
    if node.kind != NodeKind::File
    {
        reply_err(ipc::fs_errors::IS_A_DIRECTORY, ipc_buf);
        return;
    }
    let byte_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let offset = msg.word(0);
    // The payload follows the offset word.
    let Some(payload) = msg
        .data_bytes()
        .get(8..)
        .and_then(|bytes| bytes.get(..byte_len))
        .filter(|_| byte_len != 0)
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };

    let (new_cluster, new_size) = match write_file_bytes(
        node.cluster,
        node.size,
        offset,
        payload,
        state,
        cache,
        block_dev,
        ipc_buf,
    )
    {
        Ok(r) => r,
        Err(e) =>
        {
            reply_err(fat_error_to_wire(e), ipc_buf);
            return;
        }
    };

    if (new_cluster != node.cluster || new_size != node.size) && node.loc.sector_lba != 0
    {
        if let Err(e) =
            update_entry_metadata(node.loc, new_cluster, new_size, cache, block_dev, ipc_buf)
        {
            reply_err(fat_error_to_wire(e), ipc_buf);
            return;
        }
        nodes.update_size_and_cluster(node_id, new_cluster, new_size);
    }

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, byte_len as u64)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_WRITE_MEMORY`: caller supplies a source Memory cap; data lives
/// at `memory_data_offset..memory_data_offset + byte_count` in the
/// memory cap. The Memory cap is mapped into fatfs's address space at a
/// process-static scratch VA, copied into a heap buffer, and the
/// scratch VA unmapped before the actual writes. The Memory cap is moved
/// back to the caller in the reply. Badge = file node cap or open cap (must
/// carry `WRITE`), `node_id` the node either names.
#[expect(
    clippy::too_many_lines,
    reason = "the memory-cap write is one sequence (validate the request and the carried cap, map \
              it, copy, unmap, write, patch the entry, reply) whose every exit returns the carried \
              cap to the caller in its reply"
)]
fn handle_write_memory(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let src_cap = msg.caps().first().copied().unwrap_or(0);
    // Only the source page is part of the request; any further cap is
    // deleted rather than kept.
    drop_caps(msg.caps().get(1..).unwrap_or(&[]));

    let reply_with = |code: u64, ipc_buf: *mut u64| {
        let mut builder = IpcMessage::builder(code);
        if src_cap != 0
        {
            builder = builder.cap(src_cap);
        }
        let reply = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    };

    if src_cap == 0
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let Some(node) = nodes.get(node_id)
    else
    {
        reply_with(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    };
    if node.kind != NodeKind::File
    {
        reply_with(ipc::fs_errors::IS_A_DIRECTORY, ipc_buf);
        return;
    }

    let offset = msg.word(0);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "fatfs builds only for 64-bit targets, where `usize` holds every `u64`; both \
                  values are range-checked below"
    )]
    let (byte_count, memory_data_offset) = (msg.word(1) as usize, msg.word(2) as usize);
    if byte_count == 0
        || PAGE_BYTES
            .checked_sub(memory_data_offset)
            .is_none_or(|page_left| byte_count > page_left)
    {
        reply_with(ipc::fs_errors::BAD_MEMORY_OFFSET, ipc_buf);
        return;
    }

    // Validate the source memory cap: Memory cap with at least MAP rights.
    let Ok(tag_rights) = syscall::cap_info(src_cap, syscall::CAP_INFO_TAG_RIGHTS)
    else
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "`CAP_INFO_TAG_RIGHTS` packs the `CapTag` byte above the 32 rights bits \
                  (abi/syscall), so the low byte of the shifted value is the tag"
    )]
    let tag = (tag_rights >> 32) as u8;
    let cap_rights = tag_rights & 0xFFFF_FFFF;
    if u64::from(tag) != u64::from(syscall::CAP_TAG_MEMORY)
        || (cap_rights & RIGHTS_MEM_MAP) != RIGHTS_MEM_MAP
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    let va = write_memory_va();
    if va == 0
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let Some(self_aspace) = self_aspace_cap()
    else
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    // memmgr-issued memory caps carry RIGHTS_ALL (both WRITE and EXECUTE);
    // mem_map with MAP_FROM_CAP (= 0) on such a cap derives both w and
    // x from the cap rights and trips the kernel's W^X check. Derive a
    // sub-cap restricted to RIGHTS_MEM_MAP (no WRITE or EXECUTE) first;
    // delete it after the unmap.
    let Ok(restricted_cap) = syscall::cap_derive(src_cap, RIGHTS_MEM_MAP)
    else
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    // SAFETY: `va` is the page `write_memory_va` reserved from the
    // per-process arena for this handler alone, which runs only on the
    // dispatch thread; nothing else maps it and no Rust object lies in it.
    let mapped = unsafe {
        std::os::seraph::mem_map_funded(
            restricted_cap,
            self_aspace,
            va,
            0,
            1,
            syscall_abi::MAP_FROM_CAP,
        )
    };
    if mapped.is_err()
    {
        let _ = syscall::cap_delete(restricted_cap);
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    // Heap-allocated: a 4 KiB on-stack buffer would push the
    // FS_WRITE_MEMORY path past the default 32 KiB stack envelope
    // once it cascades into `write_file_bytes → insert_entry → …`.
    let mut buf = Box::new([0u8; PAGE_BYTES]);
    // SAFETY: va was just mapped read-only for one page (MAP_FROM_CAP on the
    // Map-only cap); bounds checked above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            va.saturating_add(memory_data_offset as u64) as *const u8,
            buf.as_mut_ptr(),
            byte_count,
        );
    }
    // SAFETY: the same reserved page, read above only through a raw copy; no
    // Rust reference into it is live.
    let _ = unsafe { syscall::mem_unmap(self_aspace, va, 1) };
    // Drop the rights-restricted sub-cap we derived to satisfy W^X
    // at mem_map. The original src_cap is unaffected and returns to
    // the caller in the reply.
    let _ = syscall::cap_delete(restricted_cap);

    let (new_cluster, new_size) = match write_file_bytes(
        node.cluster,
        node.size,
        offset,
        buf.get(..byte_count).unwrap_or_default(),
        state,
        cache,
        block_dev,
        ipc_buf,
    )
    {
        Ok(r) => r,
        Err(e) =>
        {
            reply_with(fat_error_to_wire(e), ipc_buf);
            return;
        }
    };

    if (new_cluster != node.cluster || new_size != node.size) && node.loc.sector_lba != 0
    {
        if let Err(e) =
            update_entry_metadata(node.loc, new_cluster, new_size, cache, block_dev, ipc_buf)
        {
            reply_with(fat_error_to_wire(e), ipc_buf);
            return;
        }
        nodes.update_size_and_cluster(node_id, new_cluster, new_size);
    }

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, byte_count as u64)
        .cap(src_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Lazy process-local VA reservation for `FS_WRITE_MEMORY` source-memory-cap
/// mapping. Returns the VA on success, `0` on reserve failure.
fn write_memory_va() -> u64
{
    use std::sync::OnceLock;
    static VA: OnceLock<u64> = OnceLock::new();
    if let Some(v) = VA.get()
    {
        return *v;
    }
    let Ok(range) = std::os::seraph::reserve_pages(1)
    else
    {
        return 0;
    };
    let va = range.va_start();
    let _ = VA.set(va);
    va
}

/// Locate the current process's `AddressSpace` cap, cached.
fn self_aspace_cap() -> Option<u64>
{
    use std::sync::OnceLock;
    static SELF_ASPACE: OnceLock<u64> = OnceLock::new();
    if let Some(c) = SELF_ASPACE.get()
    {
        return Some(*c);
    }
    let info = startup_info();
    let cap = info.self_aspace;
    if cap != 0
    {
        let _ = SELF_ASPACE.set(cap);
    }
    Some(cap).filter(|&c| c != 0)
}

/// `FS_CREATE`: create a new file in a directory. Badge = parent-dir
/// cap (must carry `MUTATE_DIR`). `label[16..32]` = name length, name
/// from word 0. `parent_rights` is the caller's effective rights on
/// the parent dir; the returned cap is attenuated by it. With
/// `CREATE_OPEN` the file is opened in the same request
/// ([`create_and_open`]); `CREATE_OPEN_EXISTING` without it is refused
/// `INVALID_ARGUMENT`, the caps it carried already deleted.
#[expect(
    clippy::too_many_arguments,
    reason = "an entry point that forwards the request and the driver state to \
              `create_entry_common` or `create_and_open` by the request's flags"
)]
fn handle_create_node_cap(
    node_id: NodeId,
    parent_rights: NamespaceRights,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    opens: &Mutex<Opens>,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
)
{
    let open = msg.label & fs_labels::CREATE_OPEN != 0;
    let existing = msg.label & fs_labels::CREATE_OPEN_EXISTING != 0;
    if open
    {
        create_and_open(
            node_id,
            parent_rights,
            msg,
            state,
            nodes,
            opens,
            cache,
            caps,
            ipc_buf,
        );
    }
    else if existing
    {
        reply_err(ipc::fs_errors::INVALID_ARGUMENT, ipc_buf);
    }
    else
    {
        create_entry_common(
            node_id,
            parent_rights,
            msg,
            NewEntryKind::File,
            state,
            nodes,
            cache,
            caps,
            ipc_buf,
        );
    }
}

/// `FS_MKDIR`: create a new directory in a directory. It takes neither
/// `FS_CREATE` flag: a request carrying one is refused `INVALID_ARGUMENT`.
#[expect(
    clippy::too_many_arguments,
    reason = "a thin entry point that forwards the request and the driver state to \
              `create_entry_common` with the directory kind"
)]
fn handle_mkdir_node_cap(
    node_id: NodeId,
    parent_rights: NamespaceRights,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
)
{
    if msg.label & (fs_labels::CREATE_OPEN | fs_labels::CREATE_OPEN_EXISTING) != 0
    {
        reply_err(ipc::fs_errors::INVALID_ARGUMENT, ipc_buf);
        return;
    }
    create_entry_common(
        node_id,
        parent_rights,
        msg,
        NewEntryKind::Dir,
        state,
        nodes,
        cache,
        caps,
        ipc_buf,
    );
}

/// Rights ceiling of a new entry's cap: `STAT | READ | WRITE | EXEC` for a
/// file, every right for a directory (intermediate-directory composition
/// passes every bit through; per-op gating still checks the leaf).
fn new_entry_rights_ceiling(kind: NewEntryKind) -> NamespaceRights
{
    match kind
    {
        NewEntryKind::Dir => NamespaceRights::ALL,
        NewEntryKind::File => NamespaceRights::from_raw(
            namespace_protocol::rights::STAT
                | namespace_protocol::rights::READ
                | namespace_protocol::rights::WRITE
                | namespace_protocol::rights::EXEC,
        ),
    }
}

/// The name an `FS_CREATE` or `FS_MKDIR` carries: `label[16..32]` bytes
/// from word 0. `None` when it is empty, longer than the message, or not a
/// valid name (`namespace_protocol::validate_name`).
fn create_name(msg: &IpcMessage) -> Option<&[u8]>
{
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    msg.data_bytes()
        .get(..name_len)
        .filter(|name| !name.is_empty() && namespace_protocol::validate_name(name).is_ok())
}

/// Write a new entry `name` of `kind` in the directory at `parent_cluster`:
/// for a directory, first its cluster, holding `.` and `..`. Returns the
/// entry's start cluster (0 for a file, which starts empty) and its on-disk
/// location. A failure leaves no entry and no claimed cluster; the error is
/// the `fs_errors` code.
fn make_entry(
    state: &mut FatState,
    parent_cluster: u32,
    name: &[u8],
    kind: NewEntryKind,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
) -> Result<(u32, DirEntryLocation), u64>
{
    let start_cluster = match kind
    {
        NewEntryKind::File => 0u32,
        NewEntryKind::Dir =>
        {
            // The cluster is written while the FAT still holds it free and
            // only then claimed, as a growing directory's is: a failed write
            // changes no FAT entry, so nothing is left to free, and no
            // claimed cluster ever holds an earlier owner's bytes
            // (services/fs/fat/docs/crash-safety.md § Write ordering).
            alloc::find_free_cluster(state, cache, caps.block_dev, ipc_buf)
                .and_then(|new_cluster| {
                    write_dot_entries(
                        state,
                        new_cluster,
                        parent_cluster,
                        cache,
                        caps.block_dev,
                        ipc_buf,
                    )?;
                    alloc::claim_cluster(state, new_cluster, None, cache, caps.block_dev, ipc_buf)?;
                    Ok(new_cluster)
                })
                .map_err(fat_error_to_wire)?
        }
    };
    insert_entry(
        state,
        parent_cluster,
        name,
        kind,
        start_cluster,
        0,
        cache,
        caps.block_dev,
        ipc_buf,
    )
    .map(|loc| (start_cluster, loc))
    .map_err(|e| {
        if matches!(kind, NewEntryKind::Dir)
        {
            let _ = alloc::free_cluster_chain(state, start_cluster, cache, caps.block_dev, ipc_buf);
        }
        fat_error_to_wire(e)
    })
}

/// A plain `FS_CREATE` or an `FS_MKDIR`: write the entry and reply with a
/// node cap on it.
#[expect(
    clippy::too_many_arguments,
    reason = "the request, the parent node and its rights, the entry kind, and the driver state \
              creation writes through"
)]
fn create_entry_common(
    node_id: NodeId,
    parent_rights: NamespaceRights,
    msg: &IpcMessage,
    kind: NewEntryKind,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
)
{
    // Cap-monotonic attenuation: the child cap carries at most the
    // intersection of the caller's parent rights and the kind ceiling that
    // `backend::lookup` applies on a re-walk. The rights are settled before
    // anything reaches the disk: an empty set (a file created through a
    // parent with none of the file rights) is refused, since a cap with no
    // rights could do nothing (services/fs/docs/fs-driver-protocol.md
    // § Label 13: `FS_CREATE`).
    let child_rights = parent_rights.intersect(new_entry_rights_ceiling(kind));
    if child_rights.is_empty()
    {
        reply_err(ipc::fs_errors::PERMISSION_DENIED, ipc_buf);
        return;
    }
    let parent_cluster = match resolve_dir_cluster(node_id, state, nodes)
    {
        Ok(cluster) => cluster,
        Err(code) =>
        {
            reply_err(code, ipc_buf);
            return;
        }
    };
    let Some(name) = create_name(msg)
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    // The node's slot is taken before the entry is written, so a full node
    // table refuses the create with no entry made.
    if !nodes.reserve()
    {
        reply_err(ipc::fs_errors::TOO_MANY_OPEN, ipc_buf);
        return;
    }
    let (start_cluster, loc) =
        match make_entry(state, parent_cluster, name, kind, cache, caps, ipc_buf)
        {
            Ok(made) => made,
            Err(code) =>
            {
                reply_err(code, ipc_buf);
                return;
            }
        };
    let kind_for_node = match kind
    {
        NewEntryKind::File => NodeKind::File,
        NewEntryKind::Dir => NodeKind::Dir,
    };
    // The reservation leaves room, so the allocation does not fail.
    let Some(new_node_id) = nodes.alloc_for_dispatch(backend::FatNode {
        cluster: start_cluster,
        size: 0,
        kind: kind_for_node,
        loc,
    })
    else
    {
        reply_err(ipc::fs_errors::TOO_MANY_OPEN, ipc_buf);
        return;
    };
    let badge = pack_badge(new_node_id, child_rights);
    let Ok(new_cap) = syscall::cap_derive_badge(caps.service, syscall::RIGHTS_EP_SEND_GRANT, badge)
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, kind_for_node as u64)
        .cap(new_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_CREATE` with `CREATE_OPEN` (services/fs/docs/fs-driver-protocol.md
/// § Label 13): create the file and open it in the session the request's
/// `caps[0]` names, or, with `CREATE_OPEN_EXISTING`, open the file of that
/// name when the directory holds one. Everything that can refuse the open
/// (the session cap, the name, the session's room and page, the open's
/// record, the node table's slot, the open cap) is settled before the entry
/// is written ([`prepare_create_open`]), so a refused open leaves no entry. A
/// failed write closes the open; a reply the client cannot take closes it
/// too, and the entry stays, as after a plain `FS_CREATE` whose client died.
#[expect(
    clippy::too_many_arguments,
    reason = "the request, the parent node and its rights, and the driver state a create and \
              an open touch (FAT state, node table, opens, endpoint caps, cache, IPC buffer)"
)]
fn create_and_open(
    node_id: NodeId,
    parent_rights: NamespaceRights,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    opens: &Mutex<Opens>,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
)
{
    let Some(prepared) = prepare_create_open(
        node_id,
        parent_rights,
        msg,
        state,
        nodes,
        opens,
        cache,
        caps,
        ipc_buf,
    )
    else
    {
        return;
    };
    // Closing the open deletes its release SEND.
    let refuse = |code: u64| {
        let _ = syscall::cap_delete(prepared.open_cap);
        opens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .close(OpenRef(prepared.id), cache);
        reply_err(code, ipc_buf);
    };
    let node = match file_to_open(
        msg,
        prepared.parent_cluster,
        prepared.name,
        state,
        cache,
        caps,
        ipc_buf,
    )
    {
        Ok(node) => node,
        Err(code) =>
        {
            refuse(code);
            return;
        }
    };
    // The reservation leaves room, so the allocation does not fail.
    let Some(file_node) = nodes.alloc_for_dispatch(node)
    else
    {
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    };
    opens
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .set_node(OpenRef(prepared.id), file_node);
    // A file the table already held keeps its node, whose size is the
    // current one; the entry's may predate a write.
    let size = nodes.get(file_node).map_or(node.size, |held| held.size);
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, NodeKind::File as u64)
        .word(1, u64::from(size))
        .cap(prepared.open_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(prepared.open_cap);
        opens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .close(OpenRef(prepared.id), cache);
    }
}

/// What [`prepare_create_open`] settled before a create that opens its file
/// writes anything: the parent directory's cluster, the validated name (in
/// the request), the open's id, and its open cap.
struct PreparedCreateOpen<'a>
{
    parent_cluster: u32,
    name: &'a [u8],
    id: u64,
    open_cap: u64,
}

/// The steps of [`create_and_open`] that can refuse the open, in the order
/// fs-driver-protocol.md § Label 13 lists their refusals: the rights the open
/// cap would carry, the session cap, the parent directory, the name, the
/// open's record in the session ([`record_open`], which names the root until
/// the file's node exists), the node table's slot, and the open cap. On a
/// refusal the request's caps are deleted, an open already recorded is
/// closed, the refusal is replied, and `None` returned.
#[expect(
    clippy::too_many_arguments,
    reason = "the request, the parent node and its rights, and the driver state an open's \
              record touches (FAT state, node table, opens, endpoint caps, cache, IPC buffer)"
)]
fn prepare_create_open<'a>(
    node_id: NodeId,
    parent_rights: NamespaceRights,
    msg: &'a IpcMessage,
    state: &FatState,
    nodes: &mut NodeTable,
    opens: &Mutex<Opens>,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
) -> Option<PreparedCreateOpen<'a>>
{
    let opcode = fs_labels::FS_CREATE;
    // The open cap carries the rights a node cap on the new file would.
    let rights = parent_rights.intersect(new_entry_rights_ceiling(NewEntryKind::File));
    if rights.is_empty()
    {
        reply_dropping_caps(msg, opcode, ipc::fs_errors::PERMISSION_DENIED, ipc_buf);
        return None;
    }
    let (session, release_send) = match request_session(msg, caps.service)
    {
        Ok(session) => session,
        Err(code) =>
        {
            reply_dropping_caps(msg, opcode, code, ipc_buf);
            return None;
        }
    };
    // The open names the root until the file's node exists; no request can
    // reach it before then, since its cap is not handed out yet.
    let open = OpenRequest {
        node_id: NodeId::ROOT,
        rights,
        service: caps.service,
        release_send,
    };
    let parent_cluster = match resolve_dir_cluster(node_id, state, nodes)
    {
        Ok(cluster) => cluster,
        Err(code) =>
        {
            open.refuse(code, ipc_buf);
            return None;
        }
    };
    let Some(name) = create_name(msg)
    else
    {
        open.refuse(ipc::fs_errors::IO_ERROR, ipc_buf);
        return None;
    };
    let id = record_open(session, open, opens, cache, ipc_buf)?;
    let refused = if nodes.reserve()
    {
        open.mint(id).ok_or(ipc::fs_errors::IO_ERROR)
    }
    else
    {
        Err(ipc::fs_errors::TOO_MANY_OPEN)
    };
    match refused
    {
        Ok(open_cap) => Some(PreparedCreateOpen {
            parent_cluster,
            name,
            id,
            open_cap,
        }),
        Err(code) =>
        {
            // Closing the open deletes its release SEND.
            opens
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .close(OpenRef(id), cache);
            reply_err(code, ipc_buf);
            None
        }
    }
}

/// The node a create that opens its file opens: with
/// `CREATE_OPEN_EXISTING`, the file `name` names in the directory at
/// `parent_cluster` when it holds one (`IS_A_DIRECTORY` for a directory);
/// otherwise a new entry, written by [`make_entry`]. The error is the
/// `fs_errors` code to answer.
fn file_to_open(
    msg: &IpcMessage,
    parent_cluster: u32,
    name: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
) -> Result<backend::FatNode, u64>
{
    let found = if msg.label & fs_labels::CREATE_OPEN_EXISTING != 0
    {
        find_in_directory_with_location(parent_cluster, name, state, cache, caps.block_dev, ipc_buf)
    }
    else
    {
        None
    };
    match found
    {
        Some((entry, _)) if FatfsBackend::entry_kind(&entry) == NodeKind::Dir =>
        {
            Err(ipc::fs_errors::IS_A_DIRECTORY)
        }
        Some((entry, loc)) => Ok(backend::FatNode {
            cluster: entry.cluster,
            size: entry.size,
            kind: NodeKind::File,
            loc,
        }),
        None =>
        {
            let (cluster, loc) = make_entry(
                state,
                parent_cluster,
                name,
                NewEntryKind::File,
                cache,
                caps,
                ipc_buf,
            )?;
            Ok(backend::FatNode {
                cluster,
                size: 0,
                kind: NodeKind::File,
                loc,
            })
        }
    }
}

/// `FS_REMOVE`: unlink a file or empty directory. Badge = parent-dir
/// cap (must carry `MUTATE_DIR`). Name in label[16..32] + data bytes.
fn handle_remove_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let parent_cluster = match resolve_dir_cluster(node_id, state, nodes)
    {
        Ok(cluster) => cluster,
        Err(code) =>
        {
            reply_err(code, ipc_buf);
            return;
        }
    };
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let Some(name) = msg.data_bytes().get(..name_len).filter(|_| name_len != 0)
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };

    let Some((entry, removed_loc)) = dir::find_in_directory_with_location(
        parent_cluster,
        name,
        state,
        cache,
        block_dev,
        ipc_buf,
    )
    else
    {
        reply_err(ipc::fs_errors::NOT_FOUND, ipc_buf);
        return;
    };
    let is_dir = entry.attr & 0x10 != 0;
    if is_dir
    {
        match directory_is_empty(state, entry.cluster, cache, block_dev, ipc_buf)
        {
            Ok(true) =>
            {}
            Ok(false) =>
            {
                reply_err(ipc::fs_errors::NOT_EMPTY, ipc_buf);
                return;
            }
            Err(e) =>
            {
                reply_err(fat_error_to_wire(e), ipc_buf);
                return;
            }
        }
    }

    // A failed removal is settled by where it left the 8.3 slot
    // (services/fs/docs/fs-driver-protocol.md § Label 14: `FS_REMOVE`).
    let removed = match remove_entry(state, parent_cluster, name, cache, block_dev, ipc_buf)
    {
        Ok(r) => r,
        Err(failure) =>
        {
            match failed_removal_state(&failure, removed_loc, cache, block_dev, ipc_buf)
            {
                DeviceSlotState::Live =>
                {
                    restore_lfn_slots(&failure, removed_loc, cache, block_dev, ipc_buf);
                    reply_err(fat_error_to_wire(failure.error), ipc_buf);
                    return;
                }
                DeviceSlotState::Deleted => RemovedEntry {
                    start_cluster: entry.cluster,
                },
                DeviceSlotState::Unreadable =>
                {
                    nodes.invalidate_for_loc(removed_loc);
                    reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
                    return;
                }
            }
        }
    };

    if let Err(e) = free_entry_data(state, &removed, cache, block_dev, ipc_buf)
    {
        nodes.invalidate_for_loc(removed_loc);
        reply_err(fat_error_to_wire(e), ipc_buf);
        return;
    }

    // Slot-keyed invalidation: NodeTable now dedupes by
    // `DirEntryLocation`, so a stale node for this slot must be
    // dropped before a later FS_CREATE lands here and reuses the
    // slot's bytes.
    let _ = removed;
    nodes.invalidate_for_loc(removed_loc);

    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Where a failed removal of the entry whose 8.3 slot is `sfn_loc` left
/// that slot. The removal writes the 8.3 slot last and stops at its first
/// failure, so the slot is still live unless its own write was the one that
/// failed; only then is the device read, past the cache, to tell
/// ([`dir::device_slot_state`]).
fn failed_removal_state(
    failure: &dir::RemoveFailure,
    sfn_loc: dir::DirEntryLocation,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
) -> DeviceSlotState
{
    if failure
        .touched
        .last()
        .is_some_and(|slot| slot.loc == sfn_loc)
    {
        dir::device_slot_state(sfn_loc, cache, block_dev, ipc_buf)
    }
    else
    {
        DeviceSlotState::Live
    }
}

/// Put back the LFN slots a failed removal of the entry whose 8.3 slot is
/// `sfn_loc` marked, so an entry the device still holds keeps its long
/// name. The 8.3 slot itself is left as the device holds it. Best-effort:
/// a slot that cannot be restored stays marked, leaving the entry visible
/// only under its short alias (services/fs/fat/docs/crash-safety.md).
fn restore_lfn_slots(
    failure: &dir::RemoveFailure,
    sfn_loc: dir::DirEntryLocation,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let lfn: Vec<dir::SlotFirstByte> = failure
        .touched
        .iter()
        .copied()
        .filter(|slot| slot.loc != sfn_loc)
        .collect();
    if dir::restore_slot_first_bytes(&lfn, cache, block_dev, ipc_buf).is_err()
    {
        std::os::seraph::log!(warn: "could not restore an LFN slot after a failed removal");
    }
}

/// `FS_RENAME`: rename an entry within a single directory.
fn handle_rename_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let parent_cluster = match resolve_dir_cluster(node_id, state, nodes)
    {
        Ok(cluster) => cluster,
        Err(code) =>
        {
            reply_err(code, ipc_buf);
            return;
        }
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "fatfs builds only for 64-bit targets, where `usize` holds every `u64`; both \
                  lengths are bounded below"
    )]
    let (src_len, dst_len) = (msg.word(0) as usize, msg.word(1) as usize);
    // Words 0 and 1 hold the lengths (16 bytes); the names follow from word
    // 2. Both lengths are client words: a name past the data is refused.
    let names = msg.data_bytes().get(16..).unwrap_or_default();
    let Some((src_name, dst_name)) = names.split_at_checked(src_len).and_then(|(src, rest)| {
        (src_len != 0 && dst_len != 0).then_some((src, rest.get(..dst_len)?))
    })
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };

    if namespace_protocol::validate_name(src_name).is_err()
        || namespace_protocol::validate_name(dst_name).is_err()
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    let Some((entry, src_loc)) = dir::find_in_directory_with_location(
        parent_cluster,
        src_name,
        state,
        cache,
        block_dev,
        ipc_buf,
    )
    else
    {
        reply_err(ipc::fs_errors::NOT_FOUND, ipc_buf);
        return;
    };

    let kind = if entry.attr & 0x10 != 0
    {
        NewEntryKind::Dir
    }
    else
    {
        NewEntryKind::File
    };

    // Non-atomic: insert destination first, then unlink source.
    // Documented in services/fs/fat/docs/crash-safety.md.
    if let Err(e) = insert_entry(
        state,
        parent_cluster,
        dst_name,
        kind,
        entry.cluster,
        entry.size,
        cache,
        block_dev,
        ipc_buf,
    )
    {
        reply_err(fat_error_to_wire(e), ipc_buf);
        return;
    }
    if let Err(failure) = remove_entry(state, parent_cluster, src_name, cache, block_dev, ipc_buf)
    {
        // Settled by where the removal left the source's 8.3 slot
        // (services/fs/docs/fs-driver-protocol.md § Label 16: `FS_RENAME`).
        match failed_removal_state(&failure, src_loc, cache, block_dev, ipc_buf)
        {
            DeviceSlotState::Live =>
            {
                // The source survives: undo the rename, the destination's
                // run first, so a failure part-way leaves at worst both
                // names, never neither.
                if remove_entry(state, parent_cluster, dst_name, cache, block_dev, ipc_buf).is_err()
                {
                    std::os::seraph::log!(warn: "could not undo a failed rename's destination");
                }
                restore_lfn_slots(&failure, src_loc, cache, block_dev, ipc_buf);
                reply_err(fat_error_to_wire(failure.error), ipc_buf);
                return;
            }
            DeviceSlotState::Deleted =>
            {}
            DeviceSlotState::Unreadable =>
            {
                nodes.invalidate_for_loc(src_loc);
                reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
                return;
            }
        }
    }

    // Drop any cached node referencing the now-deleted source slot.
    // A later FS_WRITE through a held source cap would otherwise
    // patch a `0xE5`-marked entry.
    nodes.invalidate_for_loc(src_loc);

    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_TRUNCATE`: shrink a file to a new length.
///
/// Badge = file node cap or open cap (must carry `WRITE`), `node_id` the
/// node either names. `data[0]` = new length.
/// v1 supports only `new_len == 0`; non-zero replies `IO_ERROR` so
/// the wire shape is forward-compatible with later extend-with-
/// zero-fill semantics tracked by the `ruststd::fs` completeness-gaps
/// Issue.
fn handle_truncate(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u64,
    ipc_buf: *mut u64,
)
{
    let Some(node) = nodes.get(node_id)
    else
    {
        reply_err(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    };
    if node.kind != NodeKind::File
    {
        reply_err(ipc::fs_errors::IS_A_DIRECTORY, ipc_buf);
        return;
    }
    let new_len = msg.word(0);
    if new_len != 0
    {
        // v1: only size=0 is supported. Non-zero is the extend-with-
        // zero-fill case which needs new allocator work.
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    // Detach the chain before freeing it, as FS_REMOVE does: patch the
    // directory entry and the node to first cluster 0, size 0, then free
    // the old chain. A failed free then leaves only an orphan chain, never
    // a live entry on freed clusters that a later allocation would hand to
    // another file (services/fs/fat/docs/crash-safety.md).
    let old_cluster = node.cluster;
    let entry_loc = node.loc;

    if entry_loc.sector_lba != 0
        && let Err(e) = update_entry_metadata(entry_loc, 0, 0, cache, block_dev, ipc_buf)
    {
        reply_err(fat_error_to_wire(e), ipc_buf);
        return;
    }
    nodes.update_size_and_cluster(node_id, 0, 0);

    if old_cluster >= 2
        && let Err(e) = alloc::free_cluster_chain(state, old_cluster, cache, block_dev, ipc_buf)
    {
        reply_err(fat_error_to_wire(e), ipc_buf);
        return;
    }

    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}
