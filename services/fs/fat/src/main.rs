// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/main.rs

//! Seraph FAT filesystem driver.
//!
//! Implements read-write FAT16/FAT32 filesystem support. Serves the
//! cap-native namespace protocol (`NS_LOOKUP` / `NS_STAT` /
//! `NS_READDIR`) for directory walks; per-node badged caps carry
//! `FS_OPEN`, the stateless file labels (`FS_READ`, `FS_WRITE`,
//! `FS_WRITE_MEMORY`, `FS_TRUNCATE`), and directory mutation (`FS_CREATE`,
//! `FS_REMOVE`, `FS_MKDIR`, `FS_RENAME`); per-open caps carry the open's
//! `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, and `FS_CLOSE`, and the stateless
//! file labels.
//! `FS_MOUNT` is the one unbadged service-level request, used by vfsd
//! as a BPB-validation probe at mount time. All disk I/O is performed via
//! the block device IPC endpoint received at creation time.
//!
//! Per-node badges are minted by `NS_LOOKUP` (badge = `(NodeId,
//! NamespaceRights)`); per-node ops look the node up in `NodeTable`. Per-open
//! badges are minted by `FS_OPEN` (badge = `(open id, NamespaceRights)` with
//! `namespace_protocol::OPEN_INSTANCE` set): each names one `OpenFile` in the
//! `OpenTable`, which holds that open's read-side memory caps, release SEND,
//! and liveness Notification, and resolves to its node for the stateless file
//! ops. An open whose client holds no copy of its liveness cap any more is
//! swept out of the table (`sweep_dead_opens`). Write-side metadata patching
//! uses the node's cached `DirEntryLocation`.
//!
//! Cache coherence: writes go through write-through
//! ([`cache::PageCache::write_sector`]) so any outstanding
//! `FS_READ_MEMORY` cap aliasing the same page observes new bytes
//! immediately. FAT-entry mutations invalidate the per-`FatState`
//! private `cached_fat_sector` to prevent stale FAT chain walks.
//! Crash window discussion lives in
//! `services/fs/fat/docs/crash-safety.md`.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(
    clippy::fn_params_excessive_bools,
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

mod alloc;
mod backend;
mod bpb;
mod cache;
mod dir;
mod eviction;
mod fat;
mod file;

use std::os::seraph::{StartupInfo, startup_info};
use std::sync::{Arc, Mutex, PoisonError};

use alloc::{FatError, allocate_cluster};
use backend::{FatfsBackend, NodeTable};
use bpb::{FatState, MAX_SECTOR_SIZE, sector_buffer};
use cache::PageCache;
use dir::{
    DeviceSlotState, NewEntryKind, RemovedEntry, directory_is_empty, free_entry_data, insert_entry,
    remove_entry, update_entry_metadata, write_dot_entries,
};
use eviction::{EvictReq, EvictionState};
use fat::{chain_next, next_cluster, read_file_data};
use fat_parse::open_slab::SweepSchedule;
use file::{OpenFile, OpenTable, OutstandingPage};
use ipc::{IpcMessage, fs_labels, ns_labels};
use namespace_protocol::{
    GateError, NamespaceRights, NodeId, NodeKind, gate, gate_open, is_open_instance,
    pack as pack_badge, pack_open,
};
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE, RIGHTS_MEM_MAP};

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

    let files = Arc::new(Mutex::new(OpenTable::new()));

    let eviction = Arc::new(EvictionState::new());

    // Spawn the cache-pressure eviction worker. The worker owns
    // outbound `FS_RELEASE_MEMORY` issuance and the cooperative-
    // release watchdog; main only enqueues. Spawn failure is
    // process-fatal — without the worker, cache pressure cannot
    // be relieved and reads degrade to permanent IO_ERROR once
    // every slot is held.
    {
        let ev = eviction.clone();
        let f = files.clone();
        if std::thread::Builder::new()
            .name("fatfs-eviction-worker".into())
            .spawn(move || eviction::worker_loop(&ev, &f, cache))
            .is_err()
        {
            std::os::seraph::log!(error: "eviction worker spawn failed");
            syscall::thread_exit();
        }
    }

    service_loop(
        &caps, &mut state, &mut nodes, &files, cache, ipc_buf, &eviction,
    );
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
    let reply = unsafe { ipc::ipc_call(block_dev, &msg, ipc_buf) }.ok()?;
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
/// Three request shapes share one endpoint:
/// - `FS_MOUNT` — unbadged (badge == 0); vfsd's BPB-validation probe.
/// - `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` — namespace dispatch via
///   the protocol crate.
/// - Per-node `FS_*` requests — badge packs `(NodeId, NamespaceRights)`
///   and the node is resolved through `NodeTable`: `FS_OPEN`, the stateless
///   file ops (`FS_READ`, `FS_WRITE`, `FS_WRITE_MEMORY`, `FS_TRUNCATE`), and
///   directory mutation (`FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`,
///   `FS_RENAME`).
/// - Per-open `FS_*` requests — badge packs `(open id, NamespaceRights)`
///   with `OPEN_INSTANCE` set and the open is resolved through the
///   `OpenTable`: the open's own `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, and
///   `FS_CLOSE`, and the stateless file ops on the open's node.
///
/// The open table is shared with the eviction worker via a `Mutex`. Main
/// takes the lock to resolve an open cap, `FS_OPEN` takes it only around a
/// sweep and its table update, and `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, and `FS_CLOSE`
/// hold it for the whole dispatch. Lock contention with the worker is only material during
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
    files: &Arc<Mutex<OpenTable>>,
    cache: &'static PageCache,
    ipc_buf: *mut u64,
    eviction: &EvictionState,
) -> !
{
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    let mut sweeps = SweepSchedule::new();
    loop
    {
        // The last request may have met a full cache on a path that does
        // not hold the open table's lock (relieve_pressure).
        if cache.take_pressure()
        {
            let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(req) = pick_eviction_candidate(&mut files_g)
            {
                eviction.enqueue(req);
            }
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

        // Unbadged service-level requests: FS_MOUNT only. FS_MOUNT carries
        // no caps, so none a request carried is kept.
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
            gate_open(msg.label, msg.badge).map(|(id, rights)| (None, rights, Some(id)))
        }
        else
        {
            gate(msg.label, msg.badge).map(|(node, rights)| (Some(node), rights, None))
        };
        let (node_id, parent_rights, open_id) = match gated
        {
            Ok((node, rights, open)) =>
            {
                let node = node.or_else(|| {
                    let files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
                    open.and_then(|id| files_g.get(id)).map(|f| f.node_id)
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

        // Only FS_OPEN (a release SEND) and FS_WRITE_MEMORY (the source
        // page) take caps; their handlers keep, return, or delete each one.
        // Every other label's caps are deleted here, so no cap a request
        // carries stays in fatfs's CSpace.
        if opcode != fs_labels::FS_OPEN && opcode != fs_labels::FS_WRITE_MEMORY
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
            fs_labels::FS_OPEN =>
            {
                // Takes the open table's lock itself, only around a sweep
                // and the table update: its CSpace top-up and its liveness
                // object's retype may call memmgr.
                handle_open_node_cap(
                    node_id,
                    parent_rights,
                    &msg,
                    nodes,
                    files,
                    &mut sweeps,
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
                handle_create_node_cap(
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
            fs_labels::FS_REMOVE =>
            {
                handle_remove_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                release_orphaned_open_files(nodes, files, cache);
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
                release_orphaned_open_files(nodes, files, cache);
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

        let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
        match (opcode, open_id)
        {
            (fs_labels::FS_READ_MEMORY, Some(open)) =>
            {
                handle_read_memory_open_cap(
                    node_id,
                    open,
                    &msg,
                    state,
                    nodes,
                    &mut files_g,
                    caps,
                    cache,
                    ipc_buf,
                    eviction,
                );
            }
            (fs_labels::FS_RELEASE_MEMORY, Some(open)) =>
            {
                handle_release_memory_open_cap(open, &msg, &mut files_g, cache, ipc_buf);
            }
            (fs_labels::FS_CLOSE, Some(open)) =>
            {
                handle_close_open_cap(open, &mut files_g, cache, ipc_buf);
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
/// labels take either. Any other opcode passes, so the rights gate answers
/// it `UNKNOWN_OPCODE`. A misdirected label is answered `INVALID_BADGE`.
fn label_accepts(opcode: u64, kind: CapKind) -> bool
{
    match opcode
    {
        fs_labels::FS_READ_MEMORY | fs_labels::FS_RELEASE_MEMORY | fs_labels::FS_CLOSE =>
        {
            kind == CapKind::Open
        }
        fs_labels::FS_OPEN
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
              touches (FAT state, open table, cache, block device, IPC buffer, eviction state)"
)]
fn read_memory_for_open(
    msg: &IpcMessage,
    node: &backend::FatNode,
    open_id: u64,
    state: &mut FatState,
    files: &mut OpenTable,
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
    // Walk the cluster chain to find the sector at `offset`.
    let mut cluster = node.cluster;
    // `offset` is below the `u32` file size, so the walk ends within
    // `u32::MAX / cluster_size` steps even on a cyclic chain.
    for _ in 0..pos.cluster_index
    {
        if let Some(c) = next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            cluster = c;
        }
        else
        {
            // A FAT sector read that met a full cache fails the walk.
            relieve_pressure(files, cache, eviction);
            reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
            return;
        }
    }
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

    let Some(slot_idx) = cache.acquire_page(page_base, block_dev, ipc_buf)
    else
    {
        // Cache pressure, when every slot is held by an outstanding page:
        // the client retries this read on IO_ERROR.
        relieve_pressure(files, cache, eviction);
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
    let ceiling = cache.slot_ceiling();
    if !files
        .get_mut(open_id)
        .is_some_and(|f| f.track_outstanding(entry, ceiling))
    {
        let _ = syscall::cap_delete(child);
        let _ = syscall::cap_delete(ancestor);
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::TOO_MANY_OPEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    // bytes_valid is bounded by:
    //   - file end:    file_size - offset
    //   - one cluster: cluster_size - offset_in_cluster
    //                  (we only read sectors from one cluster per call)
    //   - memory-cap tail:  PAGE_SIZE - memory_data_offset
    //                  (bytes before memory_data_offset belong to other files
    //                   or the previous cluster's leftover sectors)
    // None bounds a file: the client reads on with further calls.
    let bytes_valid = left_in_file.min(pos.left_in_cluster).min(page_left);
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, bytes_valid)
        .word(1, cookie)
        .word(2, memory_data_offset)
        .cap(child)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// When a page acquisition found every cache slot held since the last check
/// ([`PageCache::take_pressure`]), queue one held page for eviction
/// ([`pick_eviction_candidate`]): the eviction worker frees its slot within
/// `eviction::RELEASE_TIMEOUT_MS`, and the client retries the request it was
/// answered `IO_ERROR`. Called before the reply on the memory-cap read path,
/// and before each receive for every other path that reads through the
/// cache (FAT walks, directory reads, inline reads).
fn relieve_pressure(files: &mut OpenTable, cache: &PageCache, eviction: &EvictionState)
{
    if cache.take_pressure()
        && let Some(req) = pick_eviction_candidate(files)
    {
        eviction.enqueue(req);
    }
}

/// Scan the open table for an outstanding cache page not yet queued
/// for eviction, mark it queued, and return it as an [`EvictReq`], so
/// repeated cache misses under pressure queue distinct pages rather than
/// one page many times. `None` when every outstanding page is already
/// queued, or none is outstanding (then `acquire_page` failure is a
/// cache-state bug rather than client-held pressure).
fn pick_eviction_candidate(files: &mut OpenTable) -> Option<EvictReq>
{
    for (open_id, file) in files.iter_mut()
    {
        if let Some(entry) = file
            .outstanding
            .iter_mut()
            .flatten()
            .find(|e| !e.eviction_queued)
        {
            entry.eviction_queued = true;
            return Some(EvictReq {
                open_id,
                cookie: entry.cookie,
                slot_idx: entry.slot_idx,
                ancestor_cap: entry.ancestor_cap,
            });
        }
    }
    None
}

/// `FS_OPEN` against a file node cap: insert a new [`OpenFile`] for the
/// node, recording the release SEND `caps[0]` carries (any further cap is
/// deleted) and the parent of a new liveness cap, and reply with an open cap
/// whose badge names it and the liveness cap
/// (services/fs/docs/fs-driver-protocol.md § Label 18). The open cap
/// carries the node cap's rights and `SEND_GRANT`, as a node cap does, so
/// `FS_WRITE_MEMORY` can carry its source page on it. Before recording the
/// SEND it tops the `CSpace` up ([`PageCache::fund_run_time_headroom`]),
/// with the open table unlocked, since the top-up may call memmgr; the lock
/// is held only to sweep, to insert the open, and to remove it if the mint
/// or the reply fails. The open table is swept for opens whose client is gone
/// ([`sweep_dead_opens`]) when `sweeps` says a sweep is due, and when the
/// `CSpace` cannot grow or the table is full, before that step is retried
/// once. A reply the client cannot take (it died mid-call, or its `CSpace` is
/// full) moves no cap, so the open is released at once.
#[expect(
    clippy::too_many_arguments,
    reason = "the request, its node and rights, and the driver state an open touches (node table, \
              open table and its sweep schedule, endpoint caps, cache, IPC buffer)"
)]
fn handle_open_node_cap(
    node_id: NodeId,
    rights: NamespaceRights,
    msg: &IpcMessage,
    nodes: &NodeTable,
    files: &Mutex<OpenTable>,
    sweeps: &mut SweepSchedule,
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
    let (release_send, rest) = match msg.caps().split_first()
    {
        Some((&send, rest)) => (send, rest),
        None => (0, &[][..]),
    };
    drop_caps(rest);
    let refuse = |code: u64| {
        if release_send != 0
        {
            let _ = syscall::cap_delete(release_send);
        }
        reply_err(code, ipc_buf);
    };
    if !fund_open_slots(files, sweeps, cache)
    {
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    }
    let Some(liveness) = Liveness::create()
    else
    {
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    };
    let inserted = insert_open(files, sweeps, cache, || {
        OpenFile::new(node_id, release_send, liveness.parent)
    });
    let Some(open_id) = inserted
    else
    {
        liveness.discard();
        refuse(ipc::fs_errors::TOO_MANY_OPEN);
        return;
    };
    let minted = pack_open(open_id, rights).and_then(|badge| {
        syscall::cap_derive_badge(caps.service, syscall::RIGHTS_EP_SEND_GRANT, badge).ok()
    });
    let Some(open_cap) = minted
    else
    {
        files
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(open_id);
        liveness.discard();
        refuse(ipc::fs_errors::IO_ERROR);
        return;
    };
    reply_open(open_id, open_cap, liveness.child, files, cache, ipc_buf);
}

/// Count an `FS_OPEN` on `sweeps`, sweeping when one is due, and top the
/// `CSpace` up for the open ([`PageCache::fund_run_time_headroom`]), sweeping
/// and retrying once when it cannot grow. The release SEND and the liveness
/// parent hold slots for the open's lifetime, so the `CSpace` grows with the
/// opens rather than leaving a later read no slot for its page's caps.
/// `false` when the `CSpace` still cannot grow.
fn fund_open_slots(files: &Mutex<OpenTable>, sweeps: &mut SweepSchedule, cache: &PageCache)
-> bool
{
    let sweep = |sweeps: &mut SweepSchedule| {
        let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
        sweep_dead_opens(&mut files_g, sweeps, cache);
    };
    if sweeps.note_open()
    {
        sweep(sweeps);
    }
    let cspace = startup_info().self_cspace;
    if cache.fund_run_time_headroom(cspace)
    {
        return true;
    }
    sweep(sweeps);
    cache.fund_run_time_headroom(cspace)
}

/// Insert the open `open` builds into the table, sweeping and retrying once
/// when the table is full. Returns its identifier, or `None` when the table
/// is still full or the heap cannot grow it.
fn insert_open(
    files: &Mutex<OpenTable>,
    sweeps: &mut SweepSchedule,
    cache: &PageCache,
    open: impl Fn() -> OpenFile,
) -> Option<u64>
{
    let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
    files_g.insert(open()).or_else(|| {
        sweep_dead_opens(&mut files_g, sweeps, cache);
        files_g.insert(open())
    })
}

/// Reply to an `FS_OPEN` with the open cap and the liveness child. A reply
/// the client cannot take moves none of its caps, so both are still fatfs's:
/// the open is then removed and released, which revokes the liveness child
/// with its parent, and the open cap is deleted.
fn reply_open(
    open_id: u64,
    open_cap: u64,
    liveness_child: u64,
    files: &Mutex<OpenTable>,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .cap(open_cap)
        .cap(liveness_child)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_ok()
    {
        return;
    }
    let _ = syscall::cap_delete(open_cap);
    let removed = files
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(open_id);
    if let Some(file) = removed
    {
        release_open_file(&file, cache);
    }
}

/// The two caps of a new open's liveness Notification: the parent fatfs keeps
/// on the open, and the zero-rights child the `FS_OPEN` reply hands the
/// client (services/fs/docs/fs-driver-protocol.md § Label 18).
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

    /// Delete both caps of a liveness object no open kept, which frees the
    /// Notification.
    fn discard(self)
    {
        let _ = syscall::cap_delete(self.child);
        let _ = syscall::cap_delete(self.parent);
    }
}

/// Release every open whose client holds no copy of its liveness cap any more
/// ([`OpenFile::client_gone`]), as `FS_CLOSE` would, and restart `sweeps`
/// from the opens left. Called with the open-table lock held, which the
/// eviction worker shares.
fn sweep_dead_opens(files: &mut OpenTable, sweeps: &mut SweepSchedule, cache: &PageCache)
{
    files.remove_where(OpenFile::client_gone, |f| release_open_file(&f, cache));
    sweeps.swept(files.len());
}

/// `FS_READ_MEMORY` against an open cap: the page is tracked on that open
/// and its cooperative release goes to that open's release SEND. Delegates
/// to [`read_memory_for_open`].
#[expect(
    clippy::too_many_arguments,
    reason = "the request, its node and open, plus the driver state `read_memory_for_open` needs, \
              which this handler forwards"
)]
fn handle_read_memory_open_cap(
    node_id: NodeId,
    open_id: u64,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &NodeTable,
    files: &mut OpenTable,
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
    if node.kind != NodeKind::File || files.get(open_id).is_none()
    {
        reply_err(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    }
    read_memory_for_open(
        msg,
        &node,
        open_id,
        state,
        files,
        cache,
        caps.block_dev,
        ipc_buf,
        eviction,
    );
}

/// Reply `code` holding none of the caps the request carried: an
/// `FS_WRITE_MEMORY` source page goes back in the reply, as § Label 12
/// promises in every outcome, and any other cap (an `FS_OPEN`
/// release SEND) is deleted. Used for requests refused before any cap they
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
    open_id: u64,
    msg: &IpcMessage,
    files: &mut OpenTable,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let cookie = msg.word(0);
    let Some(file) = files.get_mut(open_id)
    else
    {
        reply_err(ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    };
    for slot in &mut file.outstanding
    {
        if let Some(entry) = slot
            && entry.cookie == cookie
        {
            let _ = syscall::cap_revoke_all(entry.ancestor_cap);
            let _ = syscall::cap_delete(entry.ancestor_cap);
            cache.release_slot(entry.slot_idx);
            *slot = None;
            break;
        }
    }
    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_CLOSE` against an open cap: remove the open from the table, which
/// retires its identifier, and release its pages and release SEND. Other
/// opens of the node are untouched, and the node lives until its entry is
/// removed ([`NodeTable`]). The kernel-side cap reference is dropped by the
/// caller's paired `cap_delete`.
fn handle_close_open_cap(open_id: u64, files: &mut OpenTable, cache: &PageCache, ipc_buf: *mut u64)
{
    let code = match files.remove(open_id)
    {
        Some(file) =>
        {
            release_open_file(&file, cache);
            ipc::fs_errors::SUCCESS
        }
        None => ipc::fs_errors::INVALID_BADGE,
    };
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Release an open taken out of the table: revoke and drop each outstanding
/// page, delete the recorded release SEND (leaving it in the `CSpace`
/// would accumulate a stale SEND per open across the fs's lifetime), and
/// revoke the copies of the liveness cap before deleting its parent, so the
/// client's copy dies with the open and the Notification's bytes return to
/// fatfs's object slab. A copy derived from another holder's copy is out of
/// the revoke's reach once a `CSpace` holding a copy on its derivation path
/// is torn down, and holds the bytes until its holder deletes it
/// (services/fs/docs/fs-driver-protocol.md § Label 18).
fn release_open_file(file: &OpenFile, cache: &PageCache)
{
    let _ = syscall::cap_revoke_all(file.liveness_cap);
    let _ = syscall::cap_delete(file.liveness_cap);
    for entry in file.outstanding.iter().flatten()
    {
        let _ = syscall::cap_revoke_all(entry.ancestor_cap);
        let _ = syscall::cap_delete(entry.ancestor_cap);
        cache.release_slot(entry.slot_idx);
    }
    if file.release_endpoint_cap != 0
    {
        let _ = syscall::cap_delete(file.release_endpoint_cap);
    }
}

/// Release every open of the node an `FS_REMOVE` or `FS_RENAME` freed
/// ([`NodeTable::take_orphaned_node`]), under the open-table lock the
/// eviction worker shares.
fn release_orphaned_open_files(nodes: &mut NodeTable, files: &Mutex<OpenTable>, cache: &PageCache)
{
    let Some(node_id) = nodes.take_orphaned_node()
    else
    {
        return;
    };
    let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
    files_g.remove_where(|f| f.node_id == node_id, |f| release_open_file(&f, cache));
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
/// `FS_WRITE_MEMORY`. Walks the file's cluster chain from `offset`,
/// allocating new clusters as needed, and writes `data` sector-by-
/// sector through [`PageCache::write_sector`] (read-modify-write
/// applies for partial-sector writes). Returns the file's
/// (possibly-updated) first cluster and its new size.
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

    let mut cluster = chain_head;
    let first = state.file_position(offset).ok_or(FatError::Corrupt)?;

    // Walk to the cluster containing the target offset, allocating
    // along the way for sparse writes. When we hit EOC, the current
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
    let mut cur_offset = offset;
    while !rest.is_empty()
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
        let (chunk, tail) = rest
            .split_at_checked(pos.left_in_sector)
            .unwrap_or((rest, &[]));

        // Read-modify-write the sector unless we are writing the full
        // sector from offset 0. Heap-allocated to keep the
        // write-path frame within the default 32 KiB stack envelope
        // when release LTO inlines the nested helpers
        // (`insert_entry → write_dir_slot → ...`).
        let mut sector_buf = sector_buffer()?;
        let full_sector_overwrite =
            pos.offset_in_sector == 0 && chunk.len() == state.sector_bytes();
        if !full_sector_overwrite
            && !cache.read_sector(u64::from(sector_lba), block_dev, &mut *sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }
        // The chunk ends at or before the sector's end.
        let dst = state
            .sector_mut(&mut sector_buf)
            .get_mut(pos.offset_in_sector..)
            .unwrap_or_default();
        for (d, &b) in dst.iter_mut().zip(chunk)
        {
            *d = b;
        }
        if !cache.write_sector(u64::from(sector_lba), block_dev, &*sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }

        rest = tail;
        // Bounded by `end`, a `u32`, so this never saturates.
        cur_offset = cur_offset.saturating_add(chunk.len() as u64);
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
        syscall::mem_map(
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
/// the parent dir; the returned child cap is attenuated by it.
#[expect(
    clippy::too_many_arguments,
    reason = "a thin entry point that forwards the request and the driver state to \
              `create_entry_common` with the file kind"
)]
fn handle_create_node_cap(
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

/// `FS_MKDIR`: create a new directory in a directory.
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

#[expect(
    clippy::too_many_arguments,
    reason = "the request, the parent node and its rights, the entry kind, and the driver state \
              creation writes through"
)]
#[expect(
    clippy::too_many_lines,
    reason = "creation is one sequence (settle the child's rights, validate the name, refuse a \
              taken one, allocate, insert the entry, mint the child cap, reply) whose steps share \
              the parent cluster and the new entry's state"
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
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let Some(name) = msg.data_bytes().get(..name_len).filter(|_| name_len != 0)
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    if namespace_protocol::validate_name(name).is_err()
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    let (start_cluster, kind_for_node) = match kind
    {
        NewEntryKind::File => (0u32, NodeKind::File),
        NewEntryKind::Dir =>
        {
            let new_cluster = match allocate_cluster(state, None, cache, caps.block_dev, ipc_buf)
            {
                Ok(c) => c,
                Err(e) =>
                {
                    reply_err(fat_error_to_wire(e), ipc_buf);
                    return;
                }
            };
            if let Err(e) = write_dot_entries(
                state,
                new_cluster,
                parent_cluster,
                cache,
                caps.block_dev,
                ipc_buf,
            )
            {
                reply_err(fat_error_to_wire(e), ipc_buf);
                return;
            }
            (new_cluster, NodeKind::Dir)
        }
    };

    let loc = match insert_entry(
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
    {
        Ok(loc) => loc,
        Err(e) =>
        {
            if matches!(kind, NewEntryKind::Dir)
            {
                let _ =
                    alloc::free_cluster_chain(state, start_cluster, cache, caps.block_dev, ipc_buf);
            }
            reply_err(fat_error_to_wire(e), ipc_buf);
            return;
        }
    };

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
