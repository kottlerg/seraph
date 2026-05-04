// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// fs/fat/src/main.rs

//! Seraph FAT filesystem driver.
//!
//! Implements read-only FAT16/FAT32 filesystem support. Receives IPC requests
//! from vfsd (mount/open) and directly from clients (read/close/stat/readdir)
//! conforming to `fs/docs/fs-driver-protocol.md`. All disk I/O is performed
//! via the block device IPC endpoint received at creation time.
//!
//! File identification uses capability tokens: `FS_OPEN` derives a tokened
//! send cap from the service endpoint and returns it to the caller. Clients
//! call file operations directly on the tokened cap; the token delivered by
//! `ipc_recv` identifies the open file.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

mod bpb;
mod cache;
mod dir;
mod fat;
mod file;

use std::os::seraph::{StartupInfo, startup_info};

use bpb::{FatState, SECTOR_SIZE};
use cache::PageCache;
use dir::{format_83_name, read_dir_entry_at_index, resolve_path};
use fat::{next_cluster, read_file_data};
use file::{MAX_OPEN_FILES, OpenFile, OutstandingPage};
use ipc::{IpcMessage, fs_labels};
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

    let mut files = [
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
        OpenFile::empty(),
    ];

    service_loop(&caps, &mut state, &mut files, cache, ipc_buf);
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
    ipc::fs_errors::SUCCESS
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Main FAT service loop.
///
/// Dispatches on the token delivered by `ipc_recv`:
/// - token == 0: service-level request from vfsd (`FS_MOUNT`, `FS_OPEN`)
/// - token != 0: per-file request from a client (`FS_READ`, `FS_CLOSE`,
///   `FS_STAT`, `FS_READDIR`), identified by the token
fn service_loop(
    caps: &FatCaps,
    state: &mut FatState,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    ipc_buf: *mut u64,
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

        let label = msg.label;
        let token = msg.token;
        let opcode = label & 0xFFFF;

        if token == 0
        {
            // Service-level request from vfsd (untokened cap).
            match opcode
            {
                fs_labels::FS_MOUNT =>
                {
                    // First FS_MOUNT validates the BPB; subsequent calls are
                    // idempotent. `fat_size == 0` is the pre-mount sentinel
                    // (populated by parse_bpb on success).
                    let code = if state.fat_size == 0
                    {
                        validate_bpb(caps, state, cache, ipc_buf)
                    }
                    else
                    {
                        ipc::fs_errors::SUCCESS
                    };
                    let reply = IpcMessage::new(code);
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
                fs_labels::FS_OPEN =>
                {
                    handle_open(&msg, state, files, caps, cache, ipc_buf);
                }
                _ =>
                {
                    let reply = IpcMessage::new(ipc::fs_errors::UNKNOWN_OPCODE);
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                }
            }
        }
        else
        {
            // Per-file request from client (tokened cap).
            match opcode
            {
                fs_labels::FS_READ =>
                {
                    handle_read(&msg, state, files, cache, caps.block_dev, ipc_buf);
                }
                fs_labels::FS_READ_FRAME =>
                {
                    handle_read_frame(&msg, state, files, cache, caps.block_dev, ipc_buf);
                }
                fs_labels::FS_CLOSE => handle_close(token, files, cache, ipc_buf),
                fs_labels::FS_STAT => handle_stat(token, files, ipc_buf),
                fs_labels::FS_READDIR =>
                {
                    handle_readdir(&msg, state, files, cache, caps.block_dev, ipc_buf);
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
}

// ── Operation handlers ─────────────────────────────────────────────────────

/// Handle `FS_OPEN`: resolve path, allocate file slot, derive a tokened
/// send cap from the service endpoint, and return it in the reply cap slot.
fn handle_open(
    msg: &IpcMessage,
    state: &mut FatState,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    caps: &FatCaps,
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let label = msg.label;
    let path_len = ((label >> 16) & 0xFFFF) as usize;
    if path_len == 0 || path_len > ipc::MAX_PATH_LEN
    {
        let reply = IpcMessage::new(ipc::fs_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let mut path_buf = [0u8; ipc::MAX_PATH_LEN];
    let path_bytes = msg.data_bytes();
    let copy_len = path_len.min(path_bytes.len()).min(ipc::MAX_PATH_LEN);
    path_buf[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
    let path = &path_buf[..path_len];

    let Some(entry) = resolve_path(path, state, cache, caps.block_dev, ipc_buf)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    let Some(slot_idx) = file::alloc_slot(files)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::TOO_MANY_OPEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    let token = NEXT_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Derive a tokened send cap from our service endpoint.
    let Ok(file_cap) = syscall::cap_derive_token(caps.service, syscall_abi::RIGHTS_SEND, token)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    files[slot_idx] = OpenFile {
        token,
        start_cluster: entry.cluster,
        file_size: entry.size,
        is_dir: entry.attr & 0x10 != 0,
        outstanding: [None; file::MAX_OUTSTANDING],
    };

    // Reply with the file cap — no data words needed.
    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .cap(file_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Handle `FS_READ`: token identifies the file. Data layout:
/// request `data[0]` = offset, `data[1]` = `max_len`.
fn handle_read(
    msg: &IpcMessage,
    state: &mut FatState,
    files: &[OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
)
{
    let token = msg.token;
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    let offset = msg.word(0);
    let max_len = msg.word(1);

    let file = &files[idx];
    let mut out = [0u8; SECTOR_SIZE];
    let bytes_read = read_file_data(
        &fat::FileRead {
            start_cluster: file.start_cluster,
            file_size: file.file_size,
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

/// Handle `FS_READ_FRAME`: token identifies the file. Data layout:
/// `data[0]` = page-aligned byte offset, `data[1]` = client-chosen
/// release cookie. Reply: `data[0]` = bytes valid in the returned frame,
/// `data[1]` = the same cookie echoed back, `caps[0]` = a single-page
/// Frame cap with `MAP|READ` rights covering the cached file page.
///
/// V1 caches one sector (512 B) per cache slot, so `bytes_valid` is at
/// most 512 (less near EOF). The wire shape supports widening when the
/// cache evolves to multi-sector-per-slot fills.
///
/// The returned cap is a per-call grandchild of the cache slot's parent
/// cap: the slot cap derives a per-cookie *ancestor* (kept in the fs's
/// `CSpace` for revocation), and the ancestor derives the *child* moved
/// to the caller. `cap_revoke` on the ancestor invalidates only this
/// caller's child without touching the cache slot.
// too_many_lines: handle_read_frame folds parameter validation, file
// resolution, cluster-chain walk, cache acquisition, two-step cap
// derivation, outstanding-page tracking, and reply assembly into one
// flat procedure. The error paths each have to release whatever
// resources the prior step took (refcount, ancestor cap), so extracting
// helpers would still leave the rollback chain wired through main.
#[allow(clippy::too_many_lines)]
fn handle_read_frame(
    msg: &IpcMessage,
    state: &mut FatState,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
)
{
    let token = msg.token;
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let offset = msg.word(0);
    let cookie = msg.word(1);

    if offset & (PAGE_SIZE - 1) != 0
    {
        let reply = IpcMessage::new(ipc::fs_errors::BAD_FRAME_OFFSET);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }
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
    let cluster_idx = offset / cluster_size;
    let offset_in_cluster = offset % cluster_size;
    let sector_in_cluster = (offset_in_cluster / u64::from(state.bytes_per_sector)) as u32;

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
    // `(sector - page_base) * SECTOR_SIZE` within the returned slot. For
    // page-aligned data areas (cluster_size >= PAGE_SIZE and the FS data
    // area page-aligned at format time) this is always 0.
    let frame_data_offset = (sector - page_base) * SECTOR_SIZE as u64;

    let Some(slot_idx) = cache.acquire_page(page_base, block_dev, ipc_buf)
    else
    {
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
    //                  (sectors before frame_data_offset belong to other files)
    let cluster_remaining = u64::from(state.cluster_size()) - offset_in_cluster;
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

/// Handle `FS_CLOSE`: token identifies the file. No data words.
///
/// Outstanding `FS_READ_FRAME` pages are revoked and released here:
/// `cap_revoke` on each per-cookie ancestor cap kills the caller-side
/// derived child cap (the kernel's derivation tree is the authority),
/// and the cache slot's refcount is decremented so the slot becomes
/// eligible for eviction. Phase 9 will add a cooperative round-trip
/// before the hard revoke; Phase 7 hard-revokes unconditionally.
fn handle_close(
    token: u64,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    ipc_buf: *mut u64,
)
{
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    for entry in files[idx].outstanding.iter().flatten()
    {
        let _ = syscall::cap_revoke(entry.ancestor_cap);
        let _ = syscall::cap_delete(entry.ancestor_cap);
        cache.release_slot(entry.slot_idx);
    }

    files[idx] = OpenFile::empty();
    let reply = IpcMessage::new(ipc::fs_errors::SUCCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Handle `FS_STAT`: token identifies the file. No data words in request.
fn handle_stat(token: u64, files: &[OpenFile; MAX_OPEN_FILES], ipc_buf: *mut u64)
{
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    let file = &files[idx];
    let flags: u64 = u64::from(file.is_dir) | 2; // bit 0=dir, bit 1=read-only

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, u64::from(file.file_size))
        .word(1, flags)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Handle `FS_READDIR`: token identifies the directory. `data[0]` = `entry_idx`.
fn handle_readdir(
    msg: &IpcMessage,
    state: &mut FatState,
    files: &[OpenFile; MAX_OPEN_FILES],
    cache: &PageCache,
    block_dev: u32,
    ipc_buf: *mut u64,
)
{
    let token = msg.token;
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    if !files[idx].is_dir
    {
        // InvalidToken: not a directory.
        let reply = IpcMessage::new(ipc::fs_errors::INVALID_TOKEN);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }

    let entry_idx = msg.word(0);
    let dir_cluster = files[idx].start_cluster;

    let Some(entry) =
        read_dir_entry_at_index(dir_cluster, entry_idx, state, cache, block_dev, ipc_buf)
    else
    {
        let reply = IpcMessage::new(fs_labels::END_OF_DIR);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };

    let mut name_buf = [0u8; 12];
    let name_len = format_83_name(&entry.name, &mut name_buf);
    let flags: u64 = u64::from(entry.attr & 0x10 != 0);

    let reply = IpcMessage::builder(ipc::fs_errors::SUCCESS)
        .word(0, name_len as u64)
        .word(1, u64::from(entry.size))
        .word(2, flags)
        .bytes(3, &name_buf[..name_len])
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}
