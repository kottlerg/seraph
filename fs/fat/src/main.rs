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
mod dir;
mod fat;
mod file;

use std::os::seraph::{StartupInfo, startup_info};

use bpb::{FatState, SECTOR_SIZE};
use dir::{format_83_name, read_dir_entry_at_index, resolve_path};
use fat::read_file_data;
use file::{MAX_OPEN_FILES, OpenFile};
use ipc::{IpcBuf, fs_labels};

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
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`; no need to
    // re-register. Build a typed view over the same page for local use.
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    let ipc = unsafe { IpcBuf::from_bytes(info.ipc_buffer) };
    let ipc_buf = ipc.as_ptr();

    let Some(caps) = bootstrap_caps(info, ipc)
    else
    {
        syscall::thread_exit();
    };

    println!("fatfs: starting");

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

    service_loop(&caps, &mut state, &mut files, ipc_buf);
}

/// Issue a single bootstrap round against the creator endpoint and assemble
/// [`FatCaps`].
fn bootstrap_caps(info: &StartupInfo, ipc: IpcBuf) -> Option<FatCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    let round = ipc::bootstrap::request_round(info.creator_endpoint, ipc).ok()?;
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
fn validate_bpb(caps: &FatCaps, state: &mut FatState, ipc_buf: *mut u64) -> u64
{
    let mut sector_buf = [0u8; SECTOR_SIZE];
    if !fat::read_sector(caps.block_dev, 0, &mut sector_buf, ipc_buf)
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
    ipc_buf: *mut u64,
) -> !
{
    loop
    {
        let Ok((label, token)) = syscall::ipc_recv(caps.service)
        else
        {
            continue;
        };

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
                    let reply = if state.fat_size == 0
                    {
                        validate_bpb(caps, state, ipc_buf)
                    }
                    else
                    {
                        ipc::fs_errors::SUCCESS
                    };
                    let _ = syscall::ipc_reply(reply, 0, &[]);
                }
                fs_labels::FS_OPEN =>
                {
                    handle_open(label, state, files, caps, ipc_buf);
                }
                _ =>
                {
                    let _ = syscall::ipc_reply(ipc::fs_errors::UNKNOWN_OPCODE, 0, &[]);
                }
            }
        }
        else
        {
            // Per-file request from client (tokened cap).
            match opcode
            {
                fs_labels::FS_READ => handle_read(token, state, files, caps.block_dev, ipc_buf),
                fs_labels::FS_CLOSE => handle_close(token, files),
                fs_labels::FS_STAT => handle_stat(token, files, ipc_buf),
                fs_labels::FS_READDIR =>
                {
                    handle_readdir(token, state, files, caps.block_dev, ipc_buf);
                }
                _ =>
                {
                    let _ = syscall::ipc_reply(ipc::fs_errors::UNKNOWN_OPCODE, 0, &[]);
                }
            }
        }
    }
}

// ── Operation handlers ─────────────────────────────────────────────────────

/// Handle `FS_OPEN`: resolve path, allocate file slot, derive a tokened
/// send cap from the service endpoint, and return it in the reply cap slot.
fn handle_open(
    label: u64,
    state: &mut FatState,
    files: &mut [OpenFile; MAX_OPEN_FILES],
    caps: &FatCaps,
    ipc_buf: *mut u64,
)
{
    let path_len = ((label >> 16) & 0xFFFF) as usize;
    if path_len == 0 || path_len > ipc::MAX_PATH_LEN
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::NOT_FOUND, 0, &[]);
        return;
    }

    let mut path_buf = [0u8; ipc::MAX_PATH_LEN];
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ipc_ref = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    let _ = ipc::read_path_from_ipc(ipc_ref, path_len, &mut path_buf);
    let path = &path_buf[..path_len];

    let Some(entry) = resolve_path(path, state, caps.block_dev, ipc_buf)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::NOT_FOUND, 0, &[]);
        return;
    };

    let Some(slot_idx) = file::alloc_slot(files)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::TOO_MANY_OPEN, 0, &[]);
        return;
    };

    let token = NEXT_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Derive a tokened send cap from our service endpoint.
    let Ok(file_cap) = syscall::cap_derive_token(caps.service, syscall_abi::RIGHTS_SEND, token)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::IO_ERROR, 0, &[]);
        return;
    };

    files[slot_idx] = OpenFile {
        token,
        start_cluster: entry.cluster,
        file_size: entry.size,
        is_dir: entry.attr & 0x10 != 0,
    };

    // Reply with the file cap — no data words needed.
    let _ = syscall::ipc_reply(ipc::fs_errors::SUCCESS, 0, &[file_cap]);
}

/// Handle `FS_READ`: token identifies the file. Data layout:
/// request `data[0]` = offset, `data[1]` = `max_len`.
fn handle_read(
    token: u64,
    state: &mut FatState,
    files: &[OpenFile; MAX_OPEN_FILES],
    block_dev: u32,
    ipc_buf: *mut u64,
)
{
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::INVALID_TOKEN, 0, &[]);
        return;
    };

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    let offset = ipc.read_word(0);
    let max_len = ipc.read_word(1);

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
        block_dev,
        ipc_buf,
        &mut out,
    );

    ipc.write_word(0, bytes_read as u64);

    let word_count = bytes_read.div_ceil(8);
    for i in 0..word_count
    {
        let base = i * 8;
        let mut word: u64 = 0;
        for j in 0..8
        {
            if base + j < bytes_read
            {
                word |= u64::from(out[base + j]) << (j * 8);
            }
        }
        ipc.write_word(1 + i, word);
    }

    let _ = syscall::ipc_reply(ipc::fs_errors::SUCCESS, 1 + word_count, &[]);
}

/// Handle `FS_CLOSE`: token identifies the file. No data words.
fn handle_close(token: u64, files: &mut [OpenFile; MAX_OPEN_FILES])
{
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::INVALID_TOKEN, 0, &[]);
        return;
    };

    files[idx] = OpenFile::empty();
    let _ = syscall::ipc_reply(ipc::fs_errors::SUCCESS, 0, &[]);
}

/// Handle `FS_STAT`: token identifies the file. No data words in request.
fn handle_stat(token: u64, files: &[OpenFile; MAX_OPEN_FILES], ipc_buf: *mut u64)
{
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::INVALID_TOKEN, 0, &[]);
        return;
    };

    let file = &files[idx];
    let flags: u64 = u64::from(file.is_dir) | 2; // bit 0=dir, bit 1=read-only

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    ipc.write_word(0, u64::from(file.file_size));
    ipc.write_word(1, flags);
    let _ = syscall::ipc_reply(ipc::fs_errors::SUCCESS, 2, &[]);
}

/// Handle `FS_READDIR`: token identifies the directory. `data[0]` = `entry_idx`.
fn handle_readdir(
    token: u64,
    state: &mut FatState,
    files: &[OpenFile; MAX_OPEN_FILES],
    block_dev: u32,
    ipc_buf: *mut u64,
)
{
    let Some(idx) = file::find_by_token(files, token)
    else
    {
        let _ = syscall::ipc_reply(ipc::fs_errors::INVALID_TOKEN, 0, &[]);
        return;
    };

    if !files[idx].is_dir
    {
        // InvalidToken: not a directory.
        let _ = syscall::ipc_reply(ipc::fs_errors::INVALID_TOKEN, 0, &[]);
        return;
    }

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    let entry_idx = ipc.read_word(0);
    let dir_cluster = files[idx].start_cluster;

    let Some(entry) = read_dir_entry_at_index(dir_cluster, entry_idx, state, block_dev, ipc_buf)
    else
    {
        let _ = syscall::ipc_reply(fs_labels::END_OF_DIR, 0, &[]);
        return;
    };

    let mut name_buf = [0u8; 12];
    let name_len = format_83_name(&entry.name, &mut name_buf);
    let flags: u64 = u64::from(entry.attr & 0x10 != 0);

    ipc.write_word(0, name_len as u64);
    ipc.write_word(1, u64::from(entry.size));
    ipc.write_word(2, flags);

    let word_count = name_len.div_ceil(8);
    for i in 0..word_count
    {
        let base = i * 8;
        let mut word: u64 = 0;
        for j in 0..8
        {
            if base + j < name_len
            {
                word |= u64::from(name_buf[base + j]) << (j * 8);
            }
        }
        ipc.write_word(3 + i, word);
    }

    let _ = syscall::ipc_reply(ipc::fs_errors::SUCCESS, 3 + word_count, &[]);
}
