// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/main.rs

//! Seraph FAT filesystem driver.
//!
//! Implements read-write FAT16/FAT32 filesystem support. Serves the
//! cap-native namespace protocol (`NS_LOOKUP` / `NS_STAT` /
//! `NS_READDIR`) for directory walks; per-node tokened caps carry
//! the read side (`FS_READ`, `FS_READ_FRAME`, `FS_RELEASE_FRAME`,
//! `FS_CLOSE`) and the write side (`FS_WRITE`, `FS_WRITE_FRAME`,
//! `FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`, `FS_RENAME`). `FS_MOUNT` is
//! the one untokened service-level request, used by vfsd as a
//! BPB-validation probe at mount time. All disk I/O is performed via
//! the block device IPC endpoint received at creation time.
//!
//! Per-node tokens are minted by `NS_LOOKUP` (token = `(NodeId,
//! NamespaceRights)`); per-node ops look the node up in `NodeTable`
//! and act on either the lazily-allocated `OpenFile` slot (read-side
//! frame caps) or the cached `DirEntryLocation` (write-side metadata
//! patching).
//!
//! Cache coherence: writes go through write-through
//! ([`cache::PageCache::write_sector`]) so any outstanding
//! `FS_READ_FRAME` cap aliasing the same page observes new bytes
//! immediately. FAT-entry mutations invalidate the per-`FatState`
//! private `cached_fat_sector` to prevent stale FAT chain walks.
//! Crash window discussion lives in
//! `services/fs/fat/docs/crash-safety.md`.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

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

use alloc::{FatError, allocate_cluster, update_fat_entry};
use backend::{FatfsBackend, NO_OPEN_SLOT, NodeTable};
use bpb::{FatState, SECTOR_SIZE};
use cache::PageCache;
use dir::{
    NewEntryKind, directory_is_empty, free_entry_data, insert_entry, remove_entry,
    update_entry_metadata, write_dot_entries,
};
use eviction::{EvictReq, EvictionState};
use fat::{next_cluster, read_file_data};
use file::{MAX_OPEN_FILES, OpenFile, OutstandingPage};
use ipc::{IpcMessage, fs_labels, ns_labels};
use namespace_protocol::{GateError, NamespaceRights, NodeId, NodeKind, gate, pack as pack_token};
use syscall_abi::{PAGE_SIZE, RIGHTS_MAP_READ};

/// Monotonic counter for token allocation. Starts at 1 (0 = untokened).
static NEXT_TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

// ── Bootstrap ──────────────────────────────────────────────────────────────
//
// vfsd → fatfs bootstrap plan (one round, 2 caps, 0 data words):
//   caps[0]: block device (SEND) — partition-scoped tokened cap on virtio-blk.
//            vfsd registers the partition bound with virtio-blk before
//            delivering this cap; fatfs reads by partition-relative LBA and
//            virtio-blk enforces the bound per-token.
//   caps[1]: fatfs service endpoint (RIGHTS_ALL — receive + derive tokens)
//
// log and procmgr endpoints arrive via `ProcessInfo`/`StartupInfo`.
//
// After bootstrap, vfsd probes fatfs with an empty `FS_MOUNT` so the driver
// can validate the BPB and report mount success/failure before vfsd replies
// to the upstream MOUNT caller.

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
    // outbound `FS_RELEASE_FRAME` issuance and the cooperative-
    // release watchdog; main only enqueues. Spawn failure is
    // process-fatal — without the worker, cache pressure cannot
    // be relieved and reads degrade to permanent IO_ERROR once
    // every slot is held.
    {
        let ev = eviction.clone();
        let f = files.clone();
        if std::thread::Builder::new()
            .name("fatfs-eviction-worker".into())
            .spawn(move || eviction::worker_loop(ev, f, cache))
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

/// Main FAT service loop.
///
/// Three request shapes share one endpoint:
/// - `FS_MOUNT` — untokened (token == 0); vfsd's BPB-validation probe.
/// - `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` — namespace dispatch via
///   the protocol crate.
/// - Per-node `FS_READ` / `FS_READ_FRAME` / `FS_RELEASE_FRAME` /
///   `FS_CLOSE` — token packs `(NodeId, NamespaceRights)`; the slot is
///   resolved through `NodeTable` and the lazily-allocated `OpenFile`.
///
/// The open-file table is shared with the eviction worker via a
/// `Mutex`; main acquires the lock once per request and holds it for
/// the entire dispatch. The hot path is single-client and
/// short-lived; lock contention with the worker is only material
/// during cache-pressure releases.
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
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(caps.service, ipc_buf) })
        else
        {
            continue;
        };

        let opcode = msg.label & 0xFFFF;

        // Untokened service-level requests: FS_MOUNT only.
        if msg.token == 0
        {
            let code = match opcode
            {
                fs_labels::FS_MOUNT =>
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
                _ => ipc::fs_errors::UNKNOWN_OPCODE,
            };
            let reply = IpcMessage::new(code);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
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
            let mut backend = FatfsBackend::new(state, cache, caps.block_dev, ipc_buf, nodes);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            unsafe {
                namespace_protocol::dispatch_request(&mut backend, &msg, caps.service, ipc_buf);
            }
            continue;
        }

        // FS_* requests: gate on the rights table, replying with
        // fs_errors codes.
        let node_id = match gate(msg.label, msg.token)
        {
            Ok((node, _)) => node,
            Err(GateError::UnknownLabel) =>
            {
                let reply = IpcMessage::new(ipc::fs_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                continue;
            }
            Err(GateError::PermissionDenied) =>
            {
                let reply = IpcMessage::new(ipc::fs_errors::PERMISSION_DENIED);
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                continue;
            }
        };

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
            fs_labels::FS_WRITE_FRAME =>
            {
                handle_write_frame_node_cap(
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
                handle_create_node_cap(node_id, &msg, state, nodes, cache, caps, ipc_buf);
                continue;
            }
            fs_labels::FS_REMOVE =>
            {
                handle_remove_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                continue;
            }
            fs_labels::FS_MKDIR =>
            {
                handle_mkdir_node_cap(node_id, &msg, state, nodes, cache, caps, ipc_buf);
                continue;
            }
            fs_labels::FS_RENAME =>
            {
                handle_rename_node_cap(node_id, &msg, state, nodes, cache, caps.block_dev, ipc_buf);
                continue;
            }
            _ =>
            {}
        }

        let mut files_g = files.lock().unwrap_or_else(PoisonError::into_inner);
        match opcode
        {
            fs_labels::FS_READ_FRAME =>
            {
                handle_read_frame_node_cap(
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
            fs_labels::FS_RELEASE_FRAME =>
            {
                handle_release_frame_node_cap(node_id, &msg, nodes, &mut files_g, cache, ipc_buf);
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
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    if node.kind != NodeKind::File
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let offset = msg.word(0);
    let max_len = msg.word(1);

    let mut out = [0u8; SECTOR_SIZE];
    let bytes_read = read_file_data(
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
    );

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, bytes_read as u64)
        .bytes(1, &out[..bytes_read])
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_READ_FRAME` body, parameterised by a pre-resolved `OpenFile`
/// slot index. `handle_read_frame_node_cap` resolves the token via
/// `NodeTable.open_slot` (lazy-allocating on first call) and delegates
/// here for the cluster walk, cache acquisition, two-step cap
/// derivation, and outstanding-page tracking.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn read_frame_at_slot(
    msg: &IpcMessage,
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
        let reply = IpcMessage::new(ipc::fs_errors::BAD_FRAME_OFFSET);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let (file_size, start_cluster) = {
        let f = &files[idx];
        (u64::from(f.file_size), f.start_cluster)
    };

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
    let sector_in_cluster = (offset_in_cluster / bytes_per_sector) as u32;
    let byte_in_sector = offset_in_cluster % bytes_per_sector;

    let mut cluster = start_cluster;
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
    // The file's byte at `offset` lives at frame offset
    // `(sector - page_base) * SECTOR_SIZE + byte_in_sector` within the
    // returned slot. For sector- and page-aligned data areas this folds
    // to zero; for misaligned data areas (data area starting mid-page)
    // the sector-position term is non-zero on the page boundary.
    let frame_data_offset = (sector - page_base) * SECTOR_SIZE as u64 + byte_in_sector;

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
    let slot_cap = cache.slot_frame_cap(slot_idx);
    if slot_cap == 0
    {
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let Ok(ancestor) = syscall::cap_derive(slot_cap, RIGHTS_MAP_READ)
    else
    {
        cache.release_slot(slot_idx);
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let Ok(child) = syscall::cap_derive(ancestor, RIGHTS_MAP_READ)
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
    //   - frame tail:  PAGE_SIZE - frame_data_offset
    //                  (bytes before frame_data_offset belong to other files
    //                   or the previous cluster's leftover sectors)
    let cluster_remaining = cluster_size - offset_in_cluster;
    let bytes_valid = (file_size - offset)
        .min(cluster_remaining)
        .min(PAGE_SIZE - frame_data_offset);
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, bytes_valid)
        .word(1, cookie)
        .word(2, frame_data_offset)
        .cap(child)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Scan the open-file table for any outstanding cache page. Returns
/// the first match as an [`EvictReq`]; `None` only if no file holds
/// any outstanding page (in which case `acquire_page` failure is a
/// cache-state bug rather than client-held pressure).
fn pick_eviction_candidate(files: &[OpenFile; MAX_OPEN_FILES]) -> Option<EvictReq>
{
    for file in files
    {
        if file.token == 0
        {
            continue;
        }
        if let Some(entry) = file.outstanding.iter().flatten().next()
        {
            return Some(EvictReq {
                file_token: file.token,
                cookie: entry.cookie,
                slot_idx: entry.slot_idx,
                ancestor_cap: entry.ancestor_cap,
                release_endpoint_cap: file.release_endpoint_cap,
            });
        }
    }
    None
}

/// `FS_READ_FRAME` against a node cap. Lazily allocates an
/// [`OpenFile`] slot bound to the node on first call (recorded into
/// [`backend::FatNode::open_slot`]) and delegates to
/// [`read_frame_at_slot`]. The slot is reaped at `FS_CLOSE`.
#[allow(clippy::too_many_arguments)]
fn handle_read_frame_node_cap(
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
    let Some(node) = nodes.get(node_id)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    if node.kind != NodeKind::File
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let idx = if node.open_slot == NO_OPEN_SLOT
    {
        let Some(slot_idx) = file::alloc_slot(files)
        else
        {
            let reply = IpcMessage::new(ipc::fs_errors::TOO_MANY_OPEN);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            return;
        };
        // Slot identity for the eviction worker's `find_by_token`
        // lookup. Never seen on the wire — node-cap requests resolve
        // through `FatNode.open_slot`.
        let token = NEXT_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // First FS_READ_FRAME for a (client, node) pair MAY carry the
        // client's per-process release-endpoint SEND in caps[0]. The
        // kernel `transfer_caps` path moved it into our CSpace if
        // present; record it on the slot so the eviction worker can
        // route cooperative `FS_RELEASE_FRAME` back to the client.
        // A zero cap indicates an opt-out client; eviction falls back
        // to the hard-revoke path. Subsequent FS_READ_FRAMEs from
        // the same client carry no caps.
        let release_endpoint_cap = msg.caps().first().copied().unwrap_or(0);
        files[slot_idx] = OpenFile {
            token,
            start_cluster: node.cluster,
            file_size: node.size,
            outstanding: [None; file::MAX_OUTSTANDING],
            release_endpoint_cap,
        };
        // Cast safe: slot_idx ≤ MAX_OPEN_FILES (8) ≪ u32::MAX.
        nodes.set_open_slot(node_id, slot_idx as u32);
        slot_idx
    }
    else
    {
        node.open_slot as usize
    };

    read_frame_at_slot(
        msg,
        idx,
        state,
        files,
        cache,
        caps.block_dev,
        ipc_buf,
        eviction,
    );
}

/// `FS_RELEASE_FRAME` against a node cap. Resolves the lazy
/// [`OpenFile`] slot through [`backend::FatNode::open_slot`] and
/// drops the matching outstanding page. Replies success when the
/// cookie is unknown — release is idempotent.
fn handle_release_frame_node_cap(
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
                let _ = syscall::cap_revoke(entry.ancestor_cap);
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
            let _ = syscall::cap_revoke(entry.ancestor_cap);
            let _ = syscall::cap_delete(entry.ancestor_cap);
            cache.release_slot(entry.slot_idx);
        }
        // Drop the per-File release-endpoint SEND the client transferred
        // on first FS_READ_FRAME — leaving it in our CSpace would
        // accumulate a stale SEND per opened file across the fs's
        // lifetime.
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
        FatError::NoSpace => ipc::fs_errors::NO_SPACE,
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
/// returns `state.root_cluster`. Non-root ids must be present in the
/// table and refer to a directory.
fn resolve_dir_cluster(node_id: NodeId, state: &FatState, nodes: &NodeTable) -> Option<u32>
{
    if node_id.raw() == 0
    {
        return Some(match state.fat_type
        {
            bpb::FatType::Fat32 => state.root_cluster,
            bpb::FatType::Fat16 => 0,
        });
    }
    let node = nodes.get(node_id)?;
    if node.kind != NodeKind::Dir
    {
        return None;
    }
    Some(node.cluster)
}

/// Common cluster-walk-and-write engine used by `FS_WRITE` and
/// `FS_WRITE_FRAME`. Walks the file's cluster chain from `offset`,
/// allocating new clusters as needed, and writes `data` sector-by-
/// sector through [`PageCache::write_sector`] (read-modify-write
/// applies for partial-sector writes). Returns the number of bytes
/// successfully written plus the (possibly-updated) file's first
/// cluster.
#[allow(clippy::too_many_arguments, clippy::single_match_else)]
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

    // Bootstrap: if the file currently holds no chain (size 0 / cluster
    // 0), allocate the first cluster now.
    let mut chain_head = start_cluster;
    if chain_head < 2
    {
        chain_head = allocate_cluster(state, None, cache, block_dev, ipc_buf)?;
    }

    let mut cluster = chain_head;
    let target_cluster_idx = offset / cluster_size;

    // Walk to the cluster containing the target offset, allocating
    // along the way for sparse writes.
    let mut prev = cluster;
    for _ in 0..target_cluster_idx
    {
        cluster = match next_cluster(state, cluster, cache, block_dev, ipc_buf)
        {
            Some(c) =>
            {
                prev = cluster;
                c
            }
            None =>
            {
                let new = allocate_cluster(state, Some(prev), cache, block_dev, ipc_buf)?;
                prev = cluster;
                new
            }
        };
    }

    let mut written = 0usize;
    let mut cur_offset = offset;
    while written < data.len()
    {
        let cluster_byte_offset = cur_offset % cluster_size;
        let sector_in_cluster = (cluster_byte_offset / bps) as u32;
        let byte_in_sector = (cluster_byte_offset % bps) as usize;
        let sector_lba = state.cluster_to_sector(cluster) + sector_in_cluster;

        let bytes_avail_in_sector = (bps as usize) - byte_in_sector;
        let bytes_to_write = bytes_avail_in_sector.min(data.len() - written);

        // Read-modify-write the sector unless we are writing the full
        // sector from offset 0.
        let mut sector_buf = [0u8; SECTOR_SIZE];
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
            prev = cluster;
            cluster = match next_cluster(state, cluster, cache, block_dev, ipc_buf)
            {
                Some(c) => c,
                None => allocate_cluster(state, Some(prev), cache, block_dev, ipc_buf)?,
            };
        }
    }

    // cast_possible_truncation: cur_offset bounded by sector-level
    // arithmetic; FAT file_size field is u32.
    #[allow(clippy::cast_possible_truncation)]
    let new_size = file_size.max(cur_offset as u32);
    Ok((chain_head, new_size))
}

/// `FS_WRITE` inline write. Token = file cap (must carry `WRITE`).
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
        reply_err(ipc::fs_errors::INVALID_TOKEN, ipc_buf);
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
        if let Err(e) = update_entry_metadata(
            state,
            node.loc,
            new_cluster,
            new_size,
            cache,
            block_dev,
            ipc_buf,
        )
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

/// `FS_WRITE_FRAME`: caller supplies a source Frame cap; data lives
/// at `frame_data_offset..frame_data_offset + byte_count` in the
/// frame. The Frame is mapped into fatfs's address space at a
/// process-static scratch VA, copied into a stack buffer, and the
/// scratch VA unmapped before the actual writes. The Frame is moved
/// back to the caller in the reply.
#[allow(clippy::too_many_lines)]
fn handle_write_frame_node_cap(
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
        reply_with(ipc::fs_errors::INVALID_TOKEN, ipc_buf);
        return;
    };
    if node.kind != NodeKind::File
    {
        reply_with(ipc::fs_errors::IS_A_DIRECTORY, ipc_buf);
        return;
    }

    let offset = msg.word(0);
    let byte_count = msg.word(1) as usize;
    let frame_data_offset = msg.word(2) as usize;
    let page_size = PAGE_SIZE as usize;
    if byte_count == 0
        || frame_data_offset >= page_size
        || byte_count > page_size - frame_data_offset
    {
        reply_with(ipc::fs_errors::BAD_FRAME_OFFSET, ipc_buf);
        return;
    }

    // Validate the source frame: Frame cap with at least MAP|READ
    // rights.
    let Ok(tag_rights) = syscall::cap_info(src_cap, syscall::CAP_INFO_TAG_RIGHTS)
    else
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    let tag = (tag_rights >> 32) as u8;
    let cap_rights = tag_rights & 0xFFFF_FFFF;
    if u64::from(tag) != u64::from(syscall::CAP_TAG_FRAME)
        || (cap_rights & RIGHTS_MAP_READ) != RIGHTS_MAP_READ
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    let va = write_frame_va();
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
    // memmgr-issued frames carry RIGHTS_ALL (both WRITE and EXECUTE);
    // mem_map with MAP_READONLY (= 0) on such a cap derives both w and
    // x from the cap rights and trips the kernel's W^X check. Derive a
    // sub-cap restricted to MAP_READ first; delete it after the unmap.
    let Ok(restricted_cap) = syscall::cap_derive(src_cap, RIGHTS_MAP_READ)
    else
    {
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    };
    if syscall::mem_map(
        restricted_cap,
        self_aspace,
        va,
        0,
        1,
        syscall_abi::MAP_READONLY,
    )
    .is_err()
    {
        let _ = syscall::cap_delete(restricted_cap);
        reply_with(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    let mut buf = [0u8; PAGE_SIZE as usize];
    // SAFETY: va just mapped MAP_READONLY for one page; bounds checked
    // above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (va + frame_data_offset as u64) as *const u8,
            buf.as_mut_ptr(),
            byte_count,
        );
    }
    let _ = syscall::mem_unmap(self_aspace, va, 1);
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
        if let Err(e) = update_entry_metadata(
            state,
            node.loc,
            new_cluster,
            new_size,
            cache,
            block_dev,
            ipc_buf,
        )
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

/// Lazy process-local VA reservation for `FS_WRITE_FRAME` source-frame
/// mapping. Returns the VA on success, `0` on reserve failure.
fn write_frame_va() -> u64
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

/// `FS_CREATE`: create a new file in a directory. Token = parent-dir
/// cap (must carry `MUTATE_DIR`). `label[16..32]` = name length, name
/// from word 0.
fn handle_create_node_cap(
    node_id: NodeId,
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
fn handle_mkdir_node_cap(
    node_id: NodeId,
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
        msg,
        NewEntryKind::Dir,
        state,
        nodes,
        cache,
        caps,
        ipc_buf,
    );
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn create_entry_common(
    node_id: NodeId,
    msg: &IpcMessage,
    kind: NewEntryKind,
    state: &mut FatState,
    nodes: &mut NodeTable,
    cache: &PageCache,
    caps: &FatCaps,
    ipc_buf: *mut u64,
)
{
    let Some(parent_cluster) = resolve_dir_cluster(node_id, state, nodes)
    else
    {
        reply_err(ipc::fs_errors::INVALID_TOKEN, ipc_buf);
        return;
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
    let token = pack_token(new_node_id, NamespaceRights::ALL);
    let Ok(new_cap) = syscall::cap_derive_token(caps.service, syscall::RIGHTS_SEND_GRANT, token)
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

/// `FS_REMOVE`: unlink a file or empty directory. Token = parent-dir
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
    let Some(parent_cluster) = resolve_dir_cluster(node_id, state, nodes)
    else
    {
        reply_err(ipc::fs_errors::INVALID_TOKEN, ipc_buf);
        return;
    };
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let data_bytes = msg.data_bytes();
    if name_len == 0 || data_bytes.len() < name_len
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let name = &data_bytes[..name_len];

    let Some((entry, _loc)) = dir::find_in_directory_with_location(
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

    let removed = match remove_entry(state, parent_cluster, name, cache, block_dev, ipc_buf)
    {
        Ok(r) => r,
        Err(e) =>
        {
            reply_err(fat_error_to_wire(e), ipc_buf);
            return;
        }
    };

    if let Err(e) = free_entry_data(state, &removed, cache, block_dev, ipc_buf)
    {
        reply_err(fat_error_to_wire(e), ipc_buf);
        return;
    }

    let kind = if removed.is_dir
    {
        NodeKind::Dir
    }
    else
    {
        NodeKind::File
    };
    nodes.invalidate_for_entry(removed.start_cluster, kind, removed.size);

    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// `FS_RENAME`: rename an entry within a single directory.
#[allow(clippy::too_many_lines)]
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
    let Some(parent_cluster) = resolve_dir_cluster(node_id, state, nodes)
    else
    {
        reply_err(ipc::fs_errors::INVALID_TOKEN, ipc_buf);
        return;
    };
    let src_len = msg.word(0) as usize;
    let dst_len = msg.word(1) as usize;
    let data_bytes = msg.data_bytes();
    let name_off = 16; // words 0,1 = lengths (16 bytes), names from word 2
    if src_len == 0 || dst_len == 0 || data_bytes.len() < name_off + src_len + dst_len
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }
    let src_name = &data_bytes[name_off..name_off + src_len];
    let dst_name = &data_bytes[name_off + src_len..name_off + src_len + dst_len];

    if namespace_protocol::validate_name(src_name).is_err()
        || namespace_protocol::validate_name(dst_name).is_err()
    {
        reply_err(ipc::fs_errors::IO_ERROR, ipc_buf);
        return;
    }

    let Some((entry, _loc)) = dir::find_in_directory_with_location(
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
    if let Err(e) = remove_entry(state, parent_cluster, src_name, cache, block_dev, ipc_buf)
    {
        reply_err(fat_error_to_wire(e), ipc_buf);
        return;
    }

    let _ = update_fat_entry; // silence unused-import lint pending future use
    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}
