// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/main.rs

//! Seraph FAT filesystem driver.
//!
//! Implements read-write FAT16/FAT32 filesystem support. Serves the
//! cap-native namespace protocol (`NS_LOOKUP` / `NS_STAT` /
//! `NS_READDIR`) for directory walks; per-node badged caps carry
//! the read side (`FS_READ`, `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`,
//! `FS_CLOSE`) and the write side (`FS_WRITE`, `FS_WRITE_MEMORY`,
//! `FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`, `FS_RENAME`, `FS_TRUNCATE`).
//! `FS_MOUNT` is the one unbadged service-level request, used by vfsd
//! as a BPB-validation probe at mount time. All disk I/O is performed via
//! the block device IPC endpoint received at creation time.
//!
//! Per-node badges are minted by `NS_LOOKUP` (badge = `(NodeId,
//! NamespaceRights)`); per-node ops look the node up in `NodeTable`
//! and act on either the lazily-allocated `OpenFile` slot (read-side
//! memory caps) or the cached `DirEntryLocation` (write-side metadata
//! patching).
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

use std::os::seraph::{StartupInfo, startup_info};
use std::sync::{Arc, Mutex, PoisonError};

use alloc::{FatError, allocate_cluster};
use backend::{FatfsBackend, NO_OPEN_SLOT, NodeTable};
use bpb::{FatState, SECTOR_SIZE};
use cache::PageCache;
use dir::{
    DeviceSlotState, NewEntryKind, RemovedEntry, directory_is_empty, free_entry_data, insert_entry,
    remove_entry, update_entry_metadata, write_dot_entries,
};
use eviction::{EvictReq, EvictionState};
use fat::{chain_next, next_cluster, read_file_data};
use file::{MAX_OPEN_FILES, OpenFile, OutstandingPage};
use ipc::{IpcMessage, fs_labels, ns_labels};
use namespace_protocol::{GateError, NamespaceRights, NodeId, NodeKind, gate, pack as pack_badge};
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE, RIGHTS_MEM_MAP};

/// [`PAGE_SIZE`] as a `usize`, for buffer and offset arithmetic.
// cast_possible_truncation: PAGE_SIZE is 4096.
#[allow(clippy::cast_possible_truncation)]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// Monotonic counter for open-file slot identity. Starts at 1 (0 = unbadged).
///
/// Deliberately kept monotonic (not randomized like the cross-boundary
/// service badges): this value is fat-internal — the eviction worker addresses
/// a slot through `find_by_badge`, but the slot is reached on the cap-native
/// path via `FatNode.open_slot`, so the badge never crosses an IPC boundary
/// (see `file::OpenFile::badge`). With no external observer there is nothing to
/// enumerate, so randomization would add an entropy syscall per open for no
/// anti-enumeration benefit.
static NEXT_BADGE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

// ── Bootstrap ──────────────────────────────────────────────────────────────
//
// Bootstrap round and FS_MOUNT probe: see services/fs/docs/fs-driver-protocol.md
// § Bootstrap caps and § Label 10: FS_MOUNT.

struct FatCaps
{
    block_dev: u32,
    service: u32,
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"fatfs");
    let info = startup_info();

    // IPC buffer is registered by `std::os::seraph::_start` and page-aligned
    // by the boot protocol; `info.ipc_buffer` carries the same VA as a
    // `*mut u8` we reinterpret as `*mut u64`.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    let cache = match PageCache::init(info.memmgr_endpoint, info.self_aspace, ipc_buf)
    {
        Ok(c) => c,
        Err(e) =>
        {
            std::os::seraph::log!("page-cache init failed: {e:?}");
            syscall::thread_exit();
        }
    };

    std::os::seraph::log!("starting");

    let mut state = FatState::new();
    let mut nodes = NodeTable::new();

    let files = Arc::new(Mutex::new([
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
    ]));

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
            std::os::seraph::log!("eviction worker spawn failed");
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
/// On a successful FAT32 parse, also loads the `FSInfo` sector (advisory
/// next-free / free-count hints) so the cluster allocator can seed its
/// scan; FAT16 and FAT32 without `FSInfo` leave the hints at the
/// `u32::MAX` sentinel and the allocator scans from cluster 2.
fn validate_bpb(caps: &FatCaps, state: &mut FatState, cache: &PageCache, ipc_buf: *mut u64) -> u64
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    if !cache.read_sector(0, caps.block_dev, &mut sector_buf, ipc_buf)
    {
        return ipc::fs_errors::IO_ERROR;
    }
    if !bpb::parse_bpb(&sector_buf, state)
    {
        return ipc::fs_errors::NOT_FOUND;
    }
    alloc::load_fsinfo(state, cache, caps.block_dev, ipc_buf);
    ipc::fs_errors::SUCCESS
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
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
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
///   and the node is resolved through `NodeTable`: the read side
///   (`FS_READ`, `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, `FS_CLOSE`), the
///   write side (`FS_WRITE`, `FS_WRITE_MEMORY`, `FS_TRUNCATE`), and
///   directory mutation (`FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`,
///   `FS_RENAME`).
///
/// The open-file table is shared with the eviction worker via a
/// `Mutex`. Only `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, and `FS_CLOSE`
/// use it; main takes the lock for those requests and holds it for the
/// whole dispatch. Lock contention with the worker is only material
/// during cache-pressure releases.
// too_many_lines: the loop is one dispatch over every label the driver serves,
// each arm a call into its handler; splitting it would scatter the dispatch
// table across functions.
#[allow(clippy::too_many_lines)]
fn service_loop(
    caps: &FatCaps,
    state: &mut FatState,
    nodes: &mut NodeTable,
    files: &Arc<Mutex<[OpenFile; MAX_OPEN_FILES]>>,
    cache: &'static PageCache,
    ipc_buf: *mut u64,
    eviction: &EvictionState,
) -> !
{
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
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
        // `WRITE` / `EXEC` on every child they create.
        let (node_id, parent_rights) = match gate(msg.label, msg.badge)
        {
            Ok(pair) => pair,
            Err(err) =>
            {
                let code = match err
                {
                    GateError::UnknownLabel => ipc::fs_errors::UNKNOWN_OPCODE,
                    GateError::PermissionDenied => ipc::fs_errors::PERMISSION_DENIED,
                };
                reply_dropping_caps(&msg, opcode, code, ipc_buf);
                continue;
            }
        };

        // Only FS_READ_MEMORY (a release SEND) and FS_WRITE_MEMORY (the
        // source page) take caps; their handlers keep, return, or delete
        // each one. Every other label's caps are deleted here, so no cap a
        // request carries stays in fatfs's CSpace.
        if opcode != fs_labels::FS_READ_MEMORY && opcode != fs_labels::FS_WRITE_MEMORY
        {
            drop_caps(msg.caps());
        }

        if opcode == fs_labels::FS_READ
        {
            handle_read_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
            continue;
        }

        // Mutation handlers do not need the OpenFile table lock; they
        // operate on the NodeTable + cluster allocator + dir mutation
        // + cache write-through.
        match opcode
        {
            fs_labels::FS_WRITE =>
            {
                handle_write_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                continue;
            }
            fs_labels::FS_WRITE_MEMORY =>
            {
                handle_write_memory_node_cap(
                    node_id,
                    &msg,
                    state,
                    nodes,
                    cache,
                    caps.block_dev,
                    ipc_buf,
                );
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
                continue;
            }
            fs_labels::FS_TRUNCATE =>
            {
                handle_truncate_node_cap(
                    node_id,
                    &msg,
                    state,
                    nodes,
                    cache,
                    caps.block_dev,
                    ipc_buf,
                );
                continue;
            }
            _ =>
            {}
        }

        let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
        match opcode
        {
            fs_labels::FS_READ_MEMORY =>
            {
                handle_read_memory_node_cap(
                    node_id,
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
            fs_labels::FS_RELEASE_MEMORY =>
            {
                handle_release_memory_node_cap(node_id, &msg, nodes, &mut files_g, cache, ipc_buf);
            }
            fs_labels::FS_CLOSE =>
            {
                handle_close_node_cap(node_id, nodes, &mut files_g, cache, ipc_buf);
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

/// Delete every cap in `caps` from fatfs's `CSpace`: caps a request carried
/// that its handler neither records nor returns.
fn drop_caps(caps: &[u32])
{
    for &cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
}

// ── Operation handlers ─────────────────────────────────────────────────────

/// `FS_READ` against a node cap. Resolves `node_id` against the
/// `NodeTable` and reads from the FAT cluster chain. Inline reads
/// allocate no `OpenFile` slot — no outstanding pages, no release
/// bookkeeping.
fn handle_read_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &NodeTable,
    cache: &PageCache,
    block_dev: u32,
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

    let mut out = [0u8; SECTOR_SIZE];
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
        .bytes(1, &out[..bytes_read])
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_READ_MEMORY` body, parameterised by the resolved node and its
/// pre-resolved `OpenFile` slot index. `handle_read_memory_node_cap`
/// resolves the badge via `NodeTable.open_slot` (lazy-allocating on first
/// call) and delegates here for the cluster walk, cache acquisition,
/// two-step cap derivation, and outstanding-page tracking. The file's size
/// and first cluster come from `node`, the node table's current view, so a
/// write or truncate through any cap on the node is seen at once.
// too_many_arguments: the request, its node and open-file slot, and each piece
// of driver state the memory-cap read touches (FAT state, slot table, cache,
// block device, IPC buffer, eviction state). too_many_lines: the read is one
// sequence (validate, resolve the sector, pin a cache page, mint and record
// the cap, reply) whose steps share the slot state.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn read_memory_at_slot(
    msg: &IpcMessage,
    node: &backend::FatNode,
    idx: usize,
    state: &mut FatState,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    block_dev: u32,
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

    let file_size = u64::from(node.size);

    if offset >= file_size
    {
        // EOF: zero bytes valid, no cap.
        let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
            .word(0, 0)
            .word(1, cookie)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    // Walk the cluster chain to find the sector at `offset`.
    let cluster_size = u64::from(state.cluster_size());
    let bytes_per_sector = u64::from(state.bytes_per_sector);
    let cluster_idx = offset / cluster_size;
    let offset_in_cluster = offset % cluster_size;
    // cast_possible_truncation: the quotient is below the cluster's
    // sector count, a `u8` BPB field.
    #[allow(clippy::cast_possible_truncation)]
    let sector_in_cluster = (offset_in_cluster / bytes_per_sector) as u32;
    let byte_in_sector = offset_in_cluster % bytes_per_sector;

    // A non-empty file's first cluster comes from its directory entry,
    // untrusted on-disk input; one outside the data region is corrupt.
    if !state.is_data_cluster(node.cluster)
    {
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }
    let mut cluster = node.cluster;
    for _ in 0..cluster_idx
    {
        if let Some(c) = next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            cluster = c;
        }
        else
        {
            let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            return;
        }
    }
    let sector = u64::from(state.cluster_to_sector(cluster) + sector_in_cluster);
    let page_base = cache::page_base_of(sector);
    // The file's byte at `offset` lives at memory-cap offset
    // `(sector - page_base) * SECTOR_SIZE + byte_in_sector` within the
    // returned slot. For sector- and page-aligned data areas this folds
    // to zero; for misaligned data areas (data area starting mid-page)
    // the sector-position term is non-zero on the page boundary.
    let memory_data_offset = (sector - page_base) * SECTOR_SIZE as u64 + byte_in_sector;

    let Some(slot_idx) = cache.acquire_page(page_base, block_dev, ipc_buf)
    else
    {
        // Cache pressure: every slot is held by an outstanding
        // page elsewhere. Pick one such page and submit it to
        // the eviction worker; the client retries this read on
        // IO_ERROR. Worker may take up to RELEASE_TIMEOUT_MS to
        // free the slot.
        if let Some(req) = pick_eviction_candidate(files)
        {
            eviction.enqueue(req);
        }
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

    let entry = OutstandingPage {
        cookie,
        slot_idx,
        ancestor_cap: ancestor,
        eviction_queued: false,
    };
    if !files[idx].track_outstanding(entry)
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
    let cluster_remaining = cluster_size - offset_in_cluster;
    let bytes_valid = (file_size - offset)
        .min(cluster_remaining)
        .min(PAGE_SIZE - memory_data_offset);
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, bytes_valid)
        .word(1, cookie)
        .word(2, memory_data_offset)
        .cap(child)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Scan the open-file table for an outstanding cache page not yet queued
/// for eviction, mark it queued, and return it as an [`EvictReq`], so
/// repeated cache misses under pressure queue distinct pages rather than
/// one page many times. `None` when every outstanding page is already
/// queued, or none is outstanding (then `acquire_page` failure is a
/// cache-state bug rather than client-held pressure).
fn pick_eviction_candidate(files: &mut [OpenFile; MAX_OPEN_FILES]) -> Option<EvictReq>
{
    for file in files.iter_mut()
    {
        if file.badge == 0
        {
            continue;
        }
        if let Some(entry) = file
            .outstanding
            .iter_mut()
            .flatten()
            .find(|e| !e.eviction_queued)
        {
            entry.eviction_queued = true;
            return Some(EvictReq {
                file_badge: file.badge,
                cookie: entry.cookie,
                slot_idx: entry.slot_idx,
                ancestor_cap: entry.ancestor_cap,
            });
        }
    }
    None
}

/// `FS_READ_MEMORY` against a node cap. Lazily allocates an
/// [`OpenFile`] slot bound to the node on first call (recorded into
/// [`backend::FatNode::open_slot`]) and delegates to
/// [`read_memory_at_slot`]. The slot is reaped at `FS_CLOSE`.
// too_many_arguments: the request and node, plus the driver state
// `read_memory_at_slot` needs, which this handler forwards after binding the
// node's open-file slot.
#[allow(clippy::too_many_arguments)]
fn handle_read_memory_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    caps: &FatCaps,
    cache: &PageCache,
    ipc_buf: *mut u64,
    eviction: &EvictionState,
)
{
    let opcode = fs_labels::FS_READ_MEMORY;
    let Some(node) = nodes.get(node_id)
    else
    {
        reply_dropping_caps(msg, opcode, ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    };
    if node.kind != NodeKind::File
    {
        reply_dropping_caps(msg, opcode, ipc::fs_errors::INVALID_BADGE, ipc_buf);
        return;
    }

    let idx = if node.open_slot == NO_OPEN_SLOT
    {
        let Some(slot_idx) = file::alloc_slot(files)
        else
        {
            reply_dropping_caps(msg, opcode, ipc::fs_errors::TOO_MANY_OPEN, ipc_buf);
            return;
        };
        // Slot identity for the eviction worker's `find_by_badge`
        // lookup. Never seen on the wire — node-cap requests resolve
        // through `FatNode.open_slot`.
        let badge = NEXT_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        files[slot_idx] = OpenFile {
            badge,
            outstanding: [None; file::MAX_OUTSTANDING],
            release_endpoint_cap: 0,
        };
        // cast_possible_truncation: slot_idx < MAX_OPEN_FILES (8).
        #[allow(clippy::cast_possible_truncation)]
        nodes.set_open_slot(node_id, slot_idx as u32);
        slot_idx
    }
    else
    {
        node.open_slot as usize
    };
    record_release_send(&mut files[idx], msg.caps());

    read_memory_at_slot(
        msg,
        &node,
        idx,
        state,
        files,
        cache,
        caps.block_dev,
        ipc_buf,
        eviction,
    );
}

/// Record the release SEND an `FS_READ_MEMORY` carried in `caps[0]` on
/// `file` when the slot holds none yet, and delete every other cap the
/// request carried. The rule is services/fs/docs/fs-driver-protocol.md
/// § Label 7's; `transfer_caps` has already moved each cap into fatfs's
/// `CSpace`, so a cap not stored on the slot here would otherwise stay
/// there for the driver's lifetime.
fn record_release_send(file: &mut OpenFile, caps: &[u32])
{
    let mut rest = caps;
    if file.release_endpoint_cap == 0
        && let Some((&send, tail)) = caps.split_first()
    {
        file.release_endpoint_cap = send;
        rest = tail;
    }
    drop_caps(rest);
}

/// Reply `code` holding none of the caps the request carried: an
/// `FS_WRITE_MEMORY` source page goes back in the reply, as § Label 12
/// promises in every outcome, and any other cap (an `FS_READ_MEMORY`
/// release SEND) is deleted. Used for requests refused before any cap they
/// carry is recorded or consumed (the dispatch loop's rights-gate and
/// unknown or unbadged label refusals, and the `FS_READ_MEMORY` handler's
/// refusals before its slot records the SEND) and for `FS_MOUNT`, which
/// carries no caps.
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

/// `FS_RELEASE_MEMORY` against a node cap. Resolves the lazy
/// [`OpenFile`] slot through [`backend::FatNode::open_slot`] and
/// drops the matching outstanding page. Replies success when the
/// cookie is unknown — release is idempotent.
fn handle_release_memory_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    nodes: &NodeTable,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let cookie = msg.word(0);
    if let Some(node) = nodes.get(node_id)
        && node.open_slot != NO_OPEN_SLOT
    {
        let idx = node.open_slot as usize;
        for slot in &mut files[idx].outstanding
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
    }
    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_CLOSE` against a node cap. Releases any [`OpenFile`] slot
/// bound to the node (revoking outstanding pages, freeing the slot)
/// and clears [`backend::FatNode::open_slot`] back to
/// [`NO_OPEN_SLOT`]. The kernel-side cap reference is dropped by
/// the caller's paired `cap_delete`.
fn handle_close_node_cap(
    node_id: NodeId,
    nodes: &mut NodeTable,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    if let Some(node) = nodes.get(node_id)
        && node.open_slot != NO_OPEN_SLOT
    {
        let idx = node.open_slot as usize;
        for entry in files[idx].outstanding.iter().flatten()
        {
            let _ = syscall::cap_revoke_all(entry.ancestor_cap);
            let _ = syscall::cap_delete(entry.ancestor_cap);
            cache.release_slot(entry.slot_idx);
        }
        // Drop the release SEND recorded on the slot; leaving it in our
        // CSpace would accumulate a stale SEND per opened file across the
        // fs's lifetime.
        if files[idx].release_endpoint_cap != 0
        {
            let _ = syscall::cap_delete(files[idx].release_endpoint_cap);
        }
        files[idx] = OpenFile::empty();
        nodes.set_open_slot(node_id, NO_OPEN_SLOT);
    }
    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
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
// too_many_arguments: the engine takes the file's extent, the write, and the
// driver state it writes through (FAT state, cache, block device, IPC
// buffer), shared by two callers with different request shapes.
#[allow(clippy::too_many_arguments)]
fn write_file_bytes(
    start_cluster: u32,
    file_size: u32,
    offset: u64,
    data: &[u8],
    state: &mut FatState,
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
) -> Result<(u32, u32), FatError>
{
    let cluster_size = u64::from(state.cluster_size());
    let bps = u64::from(state.bytes_per_sector);
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
    let target_cluster_idx = offset / cluster_size;

    // Walk to the cluster containing the target offset, allocating
    // along the way for sparse writes. When we hit EOC, the current
    // `cluster` is the terminal one — `allocate_cluster(Some(cluster))`
    // links the new cluster after it. (A previous version threaded a
    // separate `prev` that was updated after `cluster`, so on
    // append-past-EOC it linked the new cluster behind the prior
    // terminal, overwriting that terminal's existing forward link and
    // orphaning the original tail.)
    for _ in 0..target_cluster_idx
    {
        cluster = match chain_next(state, cluster, cache, block_dev, ipc_buf)?
        {
            Some(c) => c,
            None => allocate_cluster(state, Some(cluster), cache, block_dev, ipc_buf)?,
        };
    }

    let mut written = 0usize;
    let mut cur_offset = offset;
    while written < data.len()
    {
        let cluster_byte_offset = cur_offset % cluster_size;
        // cast_possible_truncation: the quotient is below the cluster's
        // sector count, a `u8` BPB field.
        #[allow(clippy::cast_possible_truncation)]
        let sector_in_cluster = (cluster_byte_offset / bps) as u32;
        // cast_possible_truncation: the remainder is below `bps`, a `u16`.
        #[allow(clippy::cast_possible_truncation)]
        let byte_in_sector = (cluster_byte_offset % bps) as usize;
        let sector_lba = state.cluster_to_sector(cluster) + sector_in_cluster;

        let bytes_avail_in_sector = usize::from(state.bytes_per_sector) - byte_in_sector;
        let bytes_to_write = bytes_avail_in_sector.min(data.len() - written);

        // Read-modify-write the sector unless we are writing the full
        // sector from offset 0. Heap-allocated to keep the
        // write-path frame within the default 32 KiB stack envelope
        // when release LTO inlines the nested helpers
        // (`insert_entry → write_dir_slot → ...`).
        let mut sector_buf = Box::new([0u8; SECTOR_SIZE]);
        let full_sector_overwrite = byte_in_sector == 0 && bytes_to_write == SECTOR_SIZE;
        if !full_sector_overwrite
            && !cache.read_sector(u64::from(sector_lba), block_dev, &mut sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }
        sector_buf[byte_in_sector..byte_in_sector + bytes_to_write]
            .copy_from_slice(&data[written..written + bytes_to_write]);
        if !cache.write_sector(u64::from(sector_lba), block_dev, &sector_buf, ipc_buf)
        {
            return Err(FatError::Io);
        }

        written += bytes_to_write;
        cur_offset += bytes_to_write as u64;

        // Advance to next cluster if we still have data to write and
        // this write touched the cluster tail.
        let new_cluster_offset = cur_offset % cluster_size;
        if new_cluster_offset == 0 && written < data.len()
        {
            cluster = match chain_next(state, cluster, cache, block_dev, ipc_buf)?
            {
                Some(c) => c,
                None => allocate_cluster(state, Some(cluster), cache, block_dev, ipc_buf)?,
            };
        }
    }

    debug_assert_eq!(cur_offset, u64::from(end));
    let new_size = file_size.max(end);
    Ok((chain_head, new_size))
}

/// `FS_WRITE` inline write. Badge = file cap (must carry `WRITE`).
/// `label[16..32]` = byte length (≤504), `data[0]` = offset, payload
/// bytes packed from word 1 onward.
fn handle_write_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u32,
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
    let data_bytes = msg.data_bytes();
    if byte_len == 0 || data_bytes.len() < 8 + byte_len
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let payload = &data_bytes[8..8 + byte_len];

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
/// back to the caller in the reply.
// too_many_lines: the memory-cap write is one sequence (validate the request
// and the carried cap, map it, copy, unmap, write, patch the entry, reply)
// whose every exit returns the carried cap to the caller in its reply.
#[allow(clippy::too_many_lines)]
fn handle_write_memory_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u32,
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
    // cast_possible_truncation: fatfs builds only for 64-bit targets, where
    // `usize` holds every `u64`; both values are range-checked below.
    #[allow(clippy::cast_possible_truncation)]
    let (byte_count, memory_data_offset) = (msg.word(1) as usize, msg.word(2) as usize);
    if byte_count == 0
        || memory_data_offset >= PAGE_BYTES
        || byte_count > PAGE_BYTES - memory_data_offset
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
    // cast_possible_truncation: `CAP_INFO_TAG_RIGHTS` packs the `CapTag` byte
    // above the 32 rights bits (abi/syscall), so the low byte of the shifted
    // value is the tag.
    #[allow(clippy::cast_possible_truncation)]
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
    // mem_map with MAP_READONLY (= 0) on such a cap derives both w and
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
            syscall_abi::MAP_READONLY,
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
    // SAFETY: va just mapped MAP_READONLY for one page; bounds checked
    // above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (va + memory_data_offset as u64) as *const u8,
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
        &buf[..byte_count],
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
fn self_aspace_cap() -> Option<u32>
{
    use std::sync::OnceLock;
    static SELF_ASPACE: OnceLock<u32> = OnceLock::new();
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
// too_many_arguments: a thin entry point that forwards the request and the
// driver state to `create_entry_common` with the file kind.
#[allow(clippy::too_many_arguments)]
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
// too_many_arguments: a thin entry point that forwards the request and the
// driver state to `create_entry_common` with the directory kind.
#[allow(clippy::too_many_arguments)]
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

// too_many_arguments: the request, the parent node and its rights, the entry
// kind, and the driver state creation writes through. too_many_lines: creation
// is one sequence (settle the child's rights, validate the name, refuse a taken
// one, allocate, insert the entry, mint the child cap, reply) whose steps share
// the parent cluster and the new entry's state.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
    let data_bytes = msg.data_bytes();
    if name_len == 0 || data_bytes.len() < name_len
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let name = &data_bytes[..name_len];
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
        open_slot: backend::NO_OPEN_SLOT,
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
    block_dev: u32,
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
    let data_bytes = msg.data_bytes();
    if name_len == 0 || data_bytes.len() < name_len
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let name = &data_bytes[..name_len];

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
    block_dev: u32,
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
    block_dev: u32,
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
        std::os::seraph::log!("WARNING: could not restore an LFN slot after a failed removal");
    }
}

/// `FS_RENAME`: rename an entry within a single directory.
fn handle_rename_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u32,
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
    // cast_possible_truncation: fatfs builds only for 64-bit targets, where
    // `usize` holds every `u64`; both lengths are bounded below.
    #[allow(clippy::cast_possible_truncation)]
    let (src_len, dst_len) = (msg.word(0) as usize, msg.word(1) as usize);
    let data_bytes = msg.data_bytes();
    let name_off: usize = 16; // words 0,1 = lengths (16 bytes), names from word 2
    // Both lengths are client words: bound their sum without overflow
    // before slicing.
    let Some(name_end) = name_off
        .checked_add(src_len)
        .and_then(|end| end.checked_add(dst_len))
        .filter(|&end| src_len != 0 && dst_len != 0 && end <= data_bytes.len())
    else
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    let src_name = &data_bytes[name_off..name_off + src_len];
    let dst_name = &data_bytes[name_off + src_len..name_end];

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
                    std::os::seraph::log!("WARNING: could not undo a failed rename's destination");
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
/// Badge = file cap (must carry `WRITE`). `data[0]` = new length.
/// v1 supports only `new_len == 0`; non-zero replies `IO_ERROR` so
/// the wire shape is forward-compatible with later extend-with-
/// zero-fill semantics tracked by the `ruststd::fs` completeness-gaps
/// Issue.
fn handle_truncate_node_cap(
    node_id: NodeId,
    msg: &IpcMessage,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    block_dev: u32,
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
