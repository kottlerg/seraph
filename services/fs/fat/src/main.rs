// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/main.rs

//! Seraph FAT filesystem driver.
//!
//! Implements read-only FAT16/FAT32 filesystem support. Serves the
//! cap-native namespace protocol (`NS_LOOKUP` / `NS_STAT` /
//! `NS_READDIR`) for directory walks and `FS_READ` / `FS_READ_FRAME` /
//! `FS_RELEASE_FRAME` / `FS_CLOSE` against per-node tokened caps.
//! `FS_MOUNT` is the one untokened service-level request, used by
//! vfsd as a BPB-validation probe at mount time. All disk I/O is
//! performed via the block device IPC endpoint received at creation
//! time.
//!
//! Per-node tokens are minted by `NS_LOOKUP` (token = `(NodeId,
//! NamespaceRights)`); `FS_READ` / `FS_READ_FRAME` / `FS_RELEASE_FRAME`
//! / `FS_CLOSE` look the node up in `NodeTable` and act on the
//! lazily-allocated `OpenFile` slot.

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

use backend::{FatfsBackend, NO_OPEN_SLOT, NodeTable};
use bpb::{FatState, SECTOR_SIZE};
use cache::PageCache;
use eviction::{EvictReq, EvictionState};
use fat::{next_cluster, read_file_data};
use file::{MAX_OPEN_FILES, OpenFile, OutstandingPage};
use ipc::{IpcMessage, fs_labels, ns_labels};
use namespace_protocol::{GateError, NodeId, NodeKind, gate};
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
