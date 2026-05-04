// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/main.rs

//! Seraph virtual filesystem daemon.
//!
//! vfsd presents a unified virtual filesystem namespace to all other processes.
//! It manages filesystem driver instances and routes `OPEN` requests to the
//! appropriate backing driver based on mount-point resolution. After opening,
//! clients hold a direct per-file capability to the driver and perform
//! read/close/stat/readdir operations without vfsd involvement.
//!
//! See `vfsd/README.md` for the design, `vfsd/docs/vfs-ipc-interface.md` for
//! the client-facing IPC protocol, and `fs/docs/fs-driver-protocol.md` for the
//! driver-side protocol.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
#![allow(clippy::cast_possible_truncation)]

mod driver;
mod gpt;
mod mount;
mod worker;
mod worker_pool;

use gpt::MAX_GPT_PARTS;
use ipc::{IpcMessage, blk_labels};
use mount::{MAX_MOUNTS, MountEntry};
use std::os::seraph::startup_info;
use worker_pool::WorkerPool;

/// Monotonic counter for per-partition block endpoint tokens.
///
/// Each tokened cap derived from the whole-disk block endpoint gets a fresh
/// non-zero token; virtio-blk's partition table keys on this value. Token 0
/// is reserved for the un-tokened (whole-disk) endpoint held by vfsd.
static NEXT_PARTITION_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// ── Data structures ────────────────────────────────────────────────────────

pub struct VfsdCaps
{
    pub procmgr_ep: u32,
    pub registry_ep: u32,
    pub service_ep: u32,
    pub fatfs_module_cap: u32,
    pub self_aspace: u32,
    /// Worker-owned bootstrap endpoint. Populated after the bootstrap worker
    /// thread is spawned. Main derives tokened SEND caps on this slot to hand
    /// to each fatfs child as its creator endpoint.
    pub bootstrap_ep: u32,
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
//
// init → vfsd bootstrap plan:
//   Round 1 (2 caps, 0 data words):
//     caps[0]: service endpoint (vfsd receives on this)
//     caps[1]: devmgr registry endpoint
//   Round 2 (1 cap, 0 data words):
//     caps[0]: fatfs module frame cap
//
// log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`, not through
// this protocol.

fn bootstrap_caps(info: &std::os::seraph::StartupInfo, ipc_buf: *mut u64) -> Option<VfsdCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round1 = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round1.cap_count < 2 || round1.done
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round2 = unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) }.ok()?;
    if round2.cap_count < 1 || !round2.done
    {
        return None;
    }

    Some(VfsdCaps {
        service_ep: round1.caps[0],
        registry_ep: round1.caps[1],
        procmgr_ep: info.procmgr_endpoint,
        fatfs_module_cap: round2.caps[0],
        self_aspace: info.self_aspace,
        bootstrap_ep: 0,
    })
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"vfsd");
    let info = startup_info();

    // IPC buffer is registered by `std::os::seraph::_start` and page-aligned
    // by the boot protocol; `info.ipc_buffer` carries the same VA as a
    // `*mut u8` we reinterpret as `*mut u64` (4 KiB page alignment ≫ u64).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(mut caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("starting");

    if caps.service_ep == 0 || caps.registry_ep == 0
    {
        std::os::seraph::log!("missing required endpoints");
        idle_loop();
    }

    // Spawn the worker pool before any MOUNT can arrive.
    let Some(pool) = WorkerPool::new()
    else
    {
        std::os::seraph::log!("FATAL: worker pool setup failed");
        idle_loop();
    };
    caps.bootstrap_ep = pool.bootstrap_ep();

    // Query devmgr for the block device endpoint.
    std::os::seraph::log!("querying devmgr for block device");
    let query_msg = IpcMessage::new(ipc::devmgr_labels::QUERY_BLOCK_DEVICE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(query_reply) = (unsafe { ipc::ipc_call(caps.registry_ep, &query_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("QUERY_BLOCK_DEVICE ipc_call failed");
        idle_loop();
    };
    if query_reply.label != 0
    {
        std::os::seraph::log!("no block device available");
        idle_loop();
    }

    let reply_caps = query_reply.caps();
    if reply_caps.is_empty()
    {
        std::os::seraph::log!("QUERY_BLOCK_DEVICE returned no caps");
        idle_loop();
    }
    let blk_ep = reply_caps[0];
    std::os::seraph::log!("block device endpoint acquired");

    // Parse GPT partition table — stored for UUID lookups on MOUNT requests.
    let mut gpt_parts = gpt::new_gpt_table();
    match gpt::parse_gpt(blk_ep, ipc_buf, &mut gpt_parts)
    {
        Ok(count) => std::os::seraph::log!("GPT parsed, {count} partitions"),
        Err(gpt::GptError::IoError) => std::os::seraph::log!("GPT parse failed: I/O error"),
        Err(gpt::GptError::InvalidSignature) =>
        {
            std::os::seraph::log!("GPT parse failed: invalid signature");
        }
        Err(gpt::GptError::InvalidEntrySize) =>
        {
            std::os::seraph::log!("GPT parse failed: invalid entry size");
        }
    }

    std::os::seraph::log!("entering service loop");
    let runtime = VfsdRuntime {
        caps: &caps,
        blk_ep,
        gpt_parts: &gpt_parts,
        pool: &pool,
    };
    service_loop(ipc_buf, &runtime);
}

/// Live references the service loop and its handlers need on every request.
pub struct VfsdRuntime<'a>
{
    pub caps: &'a VfsdCaps,
    pub blk_ep: u32,
    pub gpt_parts: &'a [gpt::GptEntry; MAX_GPT_PARTS],
    pub pool: &'a WorkerPool,
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Main VFS service loop — namespace resolution and mount management.
///
/// Handles `OPEN` (resolves mount point, forwards to driver, relays per-file
/// capability to client) and `MOUNT` requests. Clients perform file operations
/// (read/close/stat/readdir) directly on the per-file capability returned by
/// `OPEN`, without further vfsd involvement.
fn service_loop(ipc_buf: *mut u64, rt: &VfsdRuntime) -> !
{
    let mut mounts = mount::new_mount_table();

    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        let Ok(recv) = (unsafe { ipc::ipc_recv(rt.caps.service_ep, ipc_buf) })
        else
        {
            std::os::seraph::log!("ipc_recv failed, retrying");
            continue;
        };

        let label = recv.label;
        let opcode = label & 0xFFFF;

        match opcode
        {
            ipc::vfsd_labels::OPEN => handle_open(&recv, ipc_buf, &mounts),
            ipc::vfsd_labels::MOUNT =>
            {
                handle_mount_request(&recv, ipc_buf, rt, &mut mounts);
            }
            _ =>
            {
                let err = IpcMessage::new(ipc::vfsd_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
            }
        }
    }
}

// ── MOUNT handler ──────────────────────────────────────────────────────────

/// Handle a MOUNT request from init (or any authorized client).
///
/// IPC data layout:
/// - `data[0..2]`: partition UUID (16 bytes, mixed-endian, as stored in GPT)
/// - `data[2]`: mount path length
/// - `data[3..]`: mount path bytes (packed into u64 words)
///
/// Looks up the UUID in the GPT table, spawns a fatfs driver with the
/// partition's LBA offset, and registers a mount entry at the given path.
fn handle_mount_request(
    recv: &IpcMessage,
    ipc_buf: *mut u64,
    rt: &VfsdRuntime,
    mounts: &mut [MountEntry; MAX_MOUNTS],
)
{
    let w0 = recv.word(0);
    let w1 = recv.word(1);
    let mut uuid = [0u8; 16];
    uuid[..8].copy_from_slice(&w0.to_le_bytes());
    uuid[8..].copy_from_slice(&w1.to_le_bytes());

    let path_len = recv.word(2) as usize;
    if path_len == 0 || path_len > 64
    {
        std::os::seraph::log!("MOUNT: invalid path length");
        let err = IpcMessage::new(ipc::vfsd_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    let mut path_buf = [0u8; 64];
    let path_bytes = recv.data_bytes();
    // Path bytes start at word 3 (byte offset 24).
    let path_src_start = 3 * 8;
    let path_src_end = (path_src_start + path_len).min(path_bytes.len());
    let copy_len = path_src_end.saturating_sub(path_src_start).min(path_len);
    if copy_len > 0
    {
        path_buf[..copy_len]
            .copy_from_slice(&path_bytes[path_src_start..path_src_start + copy_len]);
    }

    // Look up UUID in GPT partition table.
    let Some((partition_lba, partition_len)) = gpt::lookup_partition_by_uuid(&uuid, rt.gpt_parts)
    else
    {
        std::os::seraph::log!("MOUNT: partition UUID not found");
        let err = IpcMessage::new(ipc::vfsd_errors::NO_MOUNT);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };
    std::os::seraph::log!(
        "MOUNT: partition LBA={partition_lba:#018x} length={partition_len:#018x}"
    );

    // Spawn fatfs driver for this partition.
    if rt.caps.fatfs_module_cap == 0
    {
        std::os::seraph::log!("MOUNT: no fatfs module cap");
        let err = IpcMessage::new(ipc::vfsd_errors::NO_FS_MODULE);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    // Derive a partition-scoped tokened SEND cap on the whole-disk block
    // endpoint, and register its bound with virtio-blk. fatfs will only
    // ever see this tokened cap; virtio-blk enforces bounds per token.
    let Some(partition_ep) =
        derive_and_register_partition(rt, partition_lba, partition_len, ipc_buf)
    else
    {
        std::os::seraph::log!("MOUNT: partition cap registration failed");
        let err = IpcMessage::new(ipc::vfsd_errors::SPAWN_FAILED);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    let Some(driver_ep) = driver::spawn_fatfs_driver(rt.caps, rt.pool, partition_ep, ipc_buf)
    else
    {
        std::os::seraph::log!("MOUNT: failed to spawn fatfs");
        let err = IpcMessage::new(ipc::vfsd_errors::SPAWN_FAILED);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    // Register mount entry.
    if mount::register_mount(mounts, &path_buf, path_len, driver_ep)
    {
        let ok = IpcMessage::new(ipc::vfsd_errors::SUCCESS);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&ok, ipc_buf) };
        std::os::seraph::log!("MOUNT: registered");
    }
    else
    {
        let err = IpcMessage::new(ipc::vfsd_errors::TABLE_FULL);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        std::os::seraph::log!("MOUNT: mount table full");
    }
}

// ── OPEN handler ──────────────────────────────────────────────────────────

/// Handle an OPEN request: resolve the mount point, forward `FS_OPEN` to the
/// driver, and relay the per-file capability back to the client.
///
/// After this call, the client holds a direct tokened capability to the fs
/// driver for file operations (read/close/stat/readdir).
fn handle_open(recv: &IpcMessage, ipc_buf: *mut u64, mounts: &[MountEntry; MAX_MOUNTS])
{
    let label = recv.label;
    let path_len = ((label >> 16) & 0xFFFF) as usize;
    if path_len == 0 || path_len > ipc::MAX_PATH_LEN
    {
        let err = IpcMessage::new(ipc::vfsd_errors::NOT_FOUND);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    let mut path_buf = [0u8; ipc::MAX_PATH_LEN];
    let recv_bytes = recv.data_bytes();
    let copy_len = path_len.min(recv_bytes.len()).min(ipc::MAX_PATH_LEN);
    path_buf[..copy_len].copy_from_slice(&recv_bytes[..copy_len]);
    let path = &path_buf[..path_len];

    let Some((mount_idx, driver_path)) = mount::resolve_mount(path, mounts)
    else
    {
        let err = IpcMessage::new(ipc::vfsd_errors::NO_MOUNT);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    let driver_ep = mounts[mount_idx].driver_ep;

    // Forward FS_OPEN to driver with the driver-relative path.
    let fwd_path_len = driver_path.len();
    let fwd_label = ipc::fs_labels::FS_OPEN | ((fwd_path_len as u64) << 16);
    let fwd_msg = IpcMessage::builder(fwd_label).bytes(0, driver_path).build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(drv_reply) = (unsafe { ipc::ipc_call(driver_ep, &fwd_msg, ipc_buf) })
    else
    {
        let err = IpcMessage::new(ipc::vfsd_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    if drv_reply.label != 0
    {
        // Driver returned an error — relay it to client.
        let err = IpcMessage::new(drv_reply.label);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    // Read the per-file capability from the driver's reply.
    let drv_caps = drv_reply.caps();
    if drv_caps.is_empty()
    {
        std::os::seraph::log!("OPEN: driver returned no file cap");
        let err = IpcMessage::new(ipc::vfsd_errors::IO_ERROR);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    }

    // Relay the file cap to the client.
    let ok = IpcMessage::builder(ipc::vfsd_errors::SUCCESS)
        .cap(drv_caps[0])
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&ok, ipc_buf) };
}

fn idle_loop() -> !
{
    loop
    {
        let _ = syscall::thread_yield();
    }
}

/// Derive a per-partition tokened SEND cap on the whole-disk block endpoint
/// and register the partition bound with virtio-blk. Returns the tokened cap
/// slot on success.
fn derive_and_register_partition(
    rt: &VfsdRuntime,
    base_lba: u64,
    length_lba: u64,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let token = NEXT_PARTITION_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let partition_ep = syscall::cap_derive_token(rt.blk_ep, syscall::RIGHTS_SEND, token).ok()?;

    // REGISTER_PARTITION on the un-tokened (whole-disk) endpoint.
    let msg = IpcMessage::builder(blk_labels::REGISTER_PARTITION)
        .word(0, token)
        .word(1, base_lba)
        .word(2, length_lba)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(rt.blk_ep, &msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("REGISTER_PARTITION ipc_call failed");
        return None;
    };
    if reply.label != ipc::blk_errors::SUCCESS
    {
        std::os::seraph::log!("REGISTER_PARTITION rejected (code={})", reply.label);
        return None;
    }
    Some(partition_ep)
}
