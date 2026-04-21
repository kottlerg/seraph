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

use gpt::MAX_GPT_PARTS;
use ipc::{IpcBuf, blk_labels};
use mount::{MAX_MOUNTS, MountEntry};
use std::os::seraph::startup_info;
use worker::Channel;

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
    pub self_cspace: u32,
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

fn bootstrap_caps(info: &std::os::seraph::StartupInfo, ipc: IpcBuf) -> Option<VfsdCaps>
{
    if info.creator_endpoint == 0
    {
        return None;
    }
    let round1 = ipc::bootstrap::request_round(info.creator_endpoint, ipc).ok()?;
    if round1.cap_count < 2 || round1.done
    {
        return None;
    }
    let round2 = ipc::bootstrap::request_round(info.creator_endpoint, ipc).ok()?;
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
        self_cspace: info.self_cspace,
        bootstrap_ep: 0,
    })
}

// ── Worker thread setup ────────────────────────────────────────────────────

/// Create the worker's bootstrap endpoint, spawn the worker thread, and
/// return both so main can publish plans into the shared channel and hand
/// tokened SEND caps on the endpoint to each spawned driver.
fn spawn_worker() -> Option<(u32, Channel)>
{
    let bootstrap_ep = syscall::cap_create_endpoint().ok()?;
    let channel = worker::new_channel();

    let worker_channel = channel.clone();
    std::thread::Builder::new()
        .name("vfsd-bootstrap".into())
        .spawn(move || worker::worker_loop(bootstrap_ep, &worker_channel))
        .ok()?;

    Some((bootstrap_ep, channel))
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    // SAFETY: IPC buffer is registered by `std::os::seraph::_start` and
    // page-aligned by the boot protocol.
    let ipc = unsafe { IpcBuf::from_bytes(info.ipc_buffer) };
    let ipc_buf = ipc.as_ptr();

    let Some(mut caps) = bootstrap_caps(info, ipc)
    else
    {
        syscall::thread_exit();
    };

    println!("vfsd: starting");

    if caps.service_ep == 0 || caps.registry_ep == 0
    {
        println!("vfsd: missing required endpoints");
        idle_loop();
    }

    // Spawn the bootstrap worker thread before any MOUNT can arrive.
    let Some((bootstrap_ep, channel)) = spawn_worker()
    else
    {
        println!("vfsd: FATAL: worker thread setup failed");
        idle_loop();
    };
    caps.bootstrap_ep = bootstrap_ep;

    // Query devmgr for the block device endpoint.
    println!("vfsd: querying devmgr for block device");
    let Ok((reply_label, _)) = syscall::ipc_call(
        caps.registry_ep,
        ipc::devmgr_labels::QUERY_BLOCK_DEVICE,
        0,
        &[],
    )
    else
    {
        println!("vfsd: QUERY_BLOCK_DEVICE ipc_call failed");
        idle_loop();
    };
    if reply_label != 0
    {
        println!("vfsd: no block device available");
        idle_loop();
    }

    // SAFETY: ipc_buf is the registered IPC buffer.
    #[allow(clippy::cast_ptr_alignment)]
    let (cap_count, reply_caps) = unsafe { syscall::read_recv_caps(ipc_buf) };
    if cap_count == 0
    {
        println!("vfsd: QUERY_BLOCK_DEVICE returned no caps");
        idle_loop();
    }
    let blk_ep = reply_caps[0];
    println!("vfsd: block device endpoint acquired");

    // Parse GPT partition table — stored for UUID lookups on MOUNT requests.
    let mut gpt_parts = gpt::new_gpt_table();
    match gpt::parse_gpt(blk_ep, ipc_buf, &mut gpt_parts)
    {
        Ok(count) => println!("vfsd: GPT parsed, {count} partitions"),
        Err(gpt::GptError::IoError) => println!("vfsd: GPT parse failed: I/O error"),
        Err(gpt::GptError::InvalidSignature) =>
        {
            println!("vfsd: GPT parse failed: invalid signature");
        }
        Err(gpt::GptError::InvalidEntrySize) =>
        {
            println!("vfsd: GPT parse failed: invalid entry size");
        }
    }

    println!("vfsd: entering service loop");
    let runtime = VfsdRuntime {
        caps: &caps,
        blk_ep,
        gpt_parts: &gpt_parts,
        channel: &channel,
    };
    service_loop(ipc_buf, &runtime);
}

/// Live references the service loop and its handlers need on every request.
pub struct VfsdRuntime<'a>
{
    pub caps: &'a VfsdCaps,
    pub blk_ep: u32,
    pub gpt_parts: &'a [gpt::GptEntry; MAX_GPT_PARTS],
    pub channel: &'a Channel,
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
        let Ok((label, _token)) = syscall::ipc_recv(rt.caps.service_ep)
        else
        {
            println!("vfsd: ipc_recv failed, retrying");
            continue;
        };

        let opcode = label & 0xFFFF;

        match opcode
        {
            ipc::vfsd_labels::OPEN => handle_open(label, ipc_buf, &mounts),
            ipc::vfsd_labels::MOUNT =>
            {
                handle_mount_request(ipc_buf, rt, &mut mounts);
            }
            _ =>
            {
                let _ = syscall::ipc_reply(ipc::vfsd_errors::UNKNOWN_OPCODE, 0, &[]);
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
fn handle_mount_request(ipc_buf: *mut u64, rt: &VfsdRuntime, mounts: &mut [MountEntry; MAX_MOUNTS])
{
    // SAFETY: ipc_buf is the registered IPC buffer page for vfsd.
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    let w0 = ipc.read_word(0);
    let w1 = ipc.read_word(1);
    let mut uuid = [0u8; 16];
    uuid[..8].copy_from_slice(&w0.to_le_bytes());
    uuid[8..].copy_from_slice(&w1.to_le_bytes());

    let path_len = ipc.read_word(2) as usize;
    if path_len == 0 || path_len > 64
    {
        println!("vfsd: MOUNT: invalid path length");
        let _ = syscall::ipc_reply(ipc::vfsd_errors::NOT_FOUND, 0, &[]);
        return;
    }

    let mut path_buf = [0u8; 64];
    let word_count = path_len.div_ceil(8).min(8);
    for i in 0..word_count
    {
        let word = ipc.read_word(3 + i);
        let base = i * 8;
        let bytes = word.to_le_bytes();
        for j in 0..8
        {
            if base + j < path_len
            {
                path_buf[base + j] = bytes[j];
            }
        }
    }

    // Look up UUID in GPT partition table.
    let Some((partition_lba, partition_len)) = gpt::lookup_partition_by_uuid(&uuid, rt.gpt_parts)
    else
    {
        println!("vfsd: MOUNT: partition UUID not found");
        let _ = syscall::ipc_reply(ipc::vfsd_errors::NO_MOUNT, 0, &[]);
        return;
    };
    println!("vfsd: MOUNT: partition LBA={partition_lba:#018x} length={partition_len:#018x}");

    // Spawn fatfs driver for this partition.
    if rt.caps.fatfs_module_cap == 0
    {
        println!("vfsd: MOUNT: no fatfs module cap");
        let _ = syscall::ipc_reply(ipc::vfsd_errors::NO_FS_MODULE, 0, &[]);
        return;
    }

    // Derive a partition-scoped tokened SEND cap on the whole-disk block
    // endpoint, and register its bound with virtio-blk. fatfs will only
    // ever see this tokened cap; virtio-blk enforces bounds per token.
    let Some(partition_ep) =
        derive_and_register_partition(rt, partition_lba, partition_len, ipc_buf)
    else
    {
        println!("vfsd: MOUNT: partition cap registration failed");
        let _ = syscall::ipc_reply(ipc::vfsd_errors::SPAWN_FAILED, 0, &[]);
        return;
    };

    // SAFETY: ipc_buf wraps the registered IPC page.
    let ipc_wrap = unsafe { IpcBuf::from_raw(ipc_buf) };
    let Some(driver_ep) = driver::spawn_fatfs_driver(rt.caps, rt.channel, partition_ep, ipc_wrap)
    else
    {
        println!("vfsd: MOUNT: failed to spawn fatfs");
        let _ = syscall::ipc_reply(ipc::vfsd_errors::SPAWN_FAILED, 0, &[]);
        return;
    };

    // Register mount entry.
    if mount::register_mount(mounts, &path_buf, path_len, driver_ep)
    {
        let _ = syscall::ipc_reply(ipc::vfsd_errors::SUCCESS, 0, &[]);
        println!("vfsd: MOUNT: registered");
    }
    else
    {
        let _ = syscall::ipc_reply(ipc::vfsd_errors::TABLE_FULL, 0, &[]);
        println!("vfsd: MOUNT: mount table full");
    }
}

// ── OPEN handler ──────────────────────────────────────────────────────────

/// Handle an OPEN request: resolve the mount point, forward `FS_OPEN` to the
/// driver, and relay the per-file capability back to the client.
///
/// After this call, the client holds a direct tokened capability to the fs
/// driver for file operations (read/close/stat/readdir).
fn handle_open(label: u64, ipc_buf: *mut u64, mounts: &[MountEntry; MAX_MOUNTS])
{
    let path_len = ((label >> 16) & 0xFFFF) as usize;
    if path_len == 0 || path_len > ipc::MAX_PATH_LEN
    {
        let _ = syscall::ipc_reply(ipc::vfsd_errors::NOT_FOUND, 0, &[]);
        return;
    }

    let mut path_buf = [0u8; ipc::MAX_PATH_LEN];
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ipc_ref = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    let _ = ipc::read_path_from_ipc(ipc_ref, path_len, &mut path_buf);
    let path = &path_buf[..path_len];

    let Some((mount_idx, driver_path)) = mount::resolve_mount(path, mounts)
    else
    {
        let _ = syscall::ipc_reply(ipc::vfsd_errors::NO_MOUNT, 0, &[]);
        return;
    };

    let driver_ep = mounts[mount_idx].driver_ep;

    // Forward FS_OPEN to driver with the driver-relative path.
    let fwd_path_len = driver_path.len();
    let _ = ipc::write_path_to_ipc(ipc_ref, driver_path);

    let fwd_label = ipc::fs_labels::FS_OPEN | ((fwd_path_len as u64) << 16);
    let data_words = fwd_path_len.div_ceil(8).min(6);
    let Ok((drv_reply, _)) = syscall::ipc_call(driver_ep, fwd_label, data_words, &[])
    else
    {
        let _ = syscall::ipc_reply(ipc::vfsd_errors::IO_ERROR, 0, &[]);
        return;
    };

    if drv_reply != 0
    {
        // Driver returned an error — relay it to client.
        let _ = syscall::ipc_reply(drv_reply, 0, &[]);
        return;
    }

    // Read the per-file capability from the driver's reply.
    // SAFETY: ipc_buf is the registered IPC buffer.
    #[allow(clippy::cast_ptr_alignment)]
    let (cap_count, reply_caps) = unsafe { syscall::read_recv_caps(ipc_buf) };
    if cap_count == 0
    {
        println!("vfsd: OPEN: driver returned no file cap");
        let _ = syscall::ipc_reply(ipc::vfsd_errors::IO_ERROR, 0, &[]);
        return;
    }

    // Relay the file cap to the client.
    let _ = syscall::ipc_reply(ipc::vfsd_errors::SUCCESS, 0, &[reply_caps[0]]);
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
    // SAFETY: ipc_buf is the registered IPC buffer.
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    ipc.write_word(0, token);
    ipc.write_word(1, base_lba);
    ipc.write_word(2, length_lba);
    let Ok((reply, _)) = syscall::ipc_call(rt.blk_ep, blk_labels::REGISTER_PARTITION, 3, &[])
    else
    {
        println!("vfsd: REGISTER_PARTITION ipc_call failed");
        return None;
    };
    if reply != ipc::blk_errors::SUCCESS
    {
        println!("vfsd: REGISTER_PARTITION rejected (code={reply})");
        return None;
    }
    Some(partition_ep)
}
