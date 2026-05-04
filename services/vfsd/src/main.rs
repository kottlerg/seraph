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

use std::os::seraph::startup_info;
use std::sync::{Mutex, PoisonError};

use gpt::MAX_GPT_PARTS;
use ipc::{IpcMessage, blk_labels};
use mount::{MAX_MOUNTS, MountEntry};
use worker_pool::WorkerPool;

/// Number of threads that recv on the service endpoint. More than one is
/// required for correctness: when one thread blocks waiting on a worker
/// pool order (e.g. `CREATE_FROM_VFS` for a fatfs respawn), procmgr
/// re-enters vfsd's OPEN to read `/bin/fatfs`; another thread must be
/// available to recv that OPEN and reply, otherwise the system deadlocks.
const SERVICE_THREAD_COUNT: usize = 4;

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
    pub memmgr_ep: u32,
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
        memmgr_ep: info.memmgr_endpoint,
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

    // Allocate a single scratch frame for GPT block reads. The
    // BLK_READ_INTO_FRAME contract requires the caller to supply the DMA
    // target frame; vfsd reuses one scratch page across all GPT reads.
    // The frame and its VA reservation are process-lifetime-leaked.
    let Some((mut scratch_cap, scratch_va)) =
        gpt::alloc_scratch(caps.memmgr_ep, caps.self_aspace, ipc_buf)
    else
    {
        std::os::seraph::log!("FATAL: GPT scratch allocation failed");
        idle_loop();
    };

    // Parse GPT partition table — stored for UUID lookups on MOUNT requests.
    let mut gpt_parts = gpt::new_gpt_table();
    match gpt::parse_gpt(
        blk_ep,
        ipc_buf,
        &mut gpt_parts,
        &mut scratch_cap,
        scratch_va,
    )
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

    let boot_module_cap = caps.fatfs_module_cap;
    let runtime: &'static VfsdRuntime = Box::leak(Box::new(VfsdRuntime {
        caps,
        blk_ep,
        gpt_parts,
        pool,
        mounts: Mutex::new(mount::new_mount_table()),
        boot_module_cap: Mutex::new(boot_module_cap),
    }));

    // Spawn N-1 helper service threads; main becomes the Nth handler. Each
    // thread runs the same recv/dispatch loop on the shared service endpoint.
    for i in 1..SERVICE_THREAD_COUNT
    {
        let name = std::format!("vfsd-service-{i}");
        if std::thread::Builder::new()
            .name(name)
            .spawn(move || service_loop(runtime))
            .is_err()
        {
            std::os::seraph::log!("FATAL: service helper thread spawn failed");
            idle_loop();
        }
    }

    std::os::seraph::log!("entering service loop");
    service_loop(runtime);
}

/// Live state shared by every service-handler thread. `Box::leak`ed at
/// startup so workers and helper threads can reference it as `'static`
/// without per-thread `Arc` clones.
pub struct VfsdRuntime
{
    pub caps: VfsdCaps,
    pub blk_ep: u32,
    pub gpt_parts: [gpt::GptEntry; MAX_GPT_PARTS],
    pub pool: WorkerPool,
    /// Mount table is mutated on MOUNT and read on OPEN, both from any of
    /// the `SERVICE_THREAD_COUNT` handler threads.
    pub mounts: Mutex<[MountEntry; MAX_MOUNTS]>,
    /// Boot-module fatfs cap consumed (and zeroed) by the very first MOUNT.
    /// Mutex-guarded because that MOUNT may land on any handler thread.
    pub boot_module_cap: Mutex<u32>,
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Service-handler entry. One copy of this loop runs per
/// [`SERVICE_THREAD_COUNT`] thread; all share the [`VfsdRuntime`]. Multi-
/// threaded recv on the service endpoint is required so that a handler
/// blocked on a worker pool order (notably `CREATE_FROM_VFS`, which
/// triggers a procmgr → vfsd OPEN re-entry) does not deadlock.
fn service_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("service thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    loop
    {
        // SAFETY: ipc_buf is the thread-registered IPC buffer page.
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
            ipc::vfsd_labels::OPEN => handle_open(&recv, ipc_buf, rt),
            ipc::vfsd_labels::MOUNT => handle_mount_request(&recv, ipc_buf, rt),
            _ =>
            {
                let err = IpcMessage::new(ipc::vfsd_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the thread-registered IPC buffer page.
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
fn handle_mount_request(recv: &IpcMessage, ipc_buf: *mut u64, rt: &VfsdRuntime)
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
    let Some((partition_lba, partition_len)) = gpt::lookup_partition_by_uuid(&uuid, &rt.gpt_parts)
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

    // First MOUNT (root) consumes the boot module cap; later mounts pass 0
    // and the spawn path uses CREATE_FROM_VFS("/bin/fatfs") via a worker.
    // Hold the lock only across the swap so other handlers can read it
    // (and observe 0) immediately.
    let module_cap_for_spawn = {
        let mut bmc = rt
            .boot_module_cap
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let v = *bmc;
        *bmc = 0;
        v
    };

    let Some(driver_ep) = driver::spawn_fatfs_driver(
        &rt.caps,
        &rt.pool,
        partition_ep,
        module_cap_for_spawn,
        ipc_buf,
    )
    else
    {
        std::os::seraph::log!("MOUNT: failed to spawn fatfs");
        if module_cap_for_spawn != 0
        {
            let _ = syscall::cap_delete(module_cap_for_spawn);
        }
        let err = IpcMessage::new(ipc::vfsd_errors::SPAWN_FAILED);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    // Root MOUNT succeeded — drop the boot module cap. The IPC has already
    // transferred a derived child to procmgr; this releases vfsd's outer slot.
    if module_cap_for_spawn != 0
    {
        let _ = syscall::cap_delete(module_cap_for_spawn);
    }

    let registered = {
        let mut mounts = rt.mounts.lock().unwrap_or_else(PoisonError::into_inner);
        mount::register_mount(&mut mounts, &path_buf, path_len, driver_ep)
    };
    if registered
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
fn handle_open(recv: &IpcMessage, ipc_buf: *mut u64, rt: &VfsdRuntime)
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

    // Resolve the mount and capture the driver endpoint and driver-relative
    // path inside the lock; release before issuing the outbound `FS_OPEN`.
    let resolved = {
        let mounts = rt.mounts.lock().unwrap_or_else(PoisonError::into_inner);
        mount::resolve_mount(path, &mounts).map(|(idx, drv_path)| {
            let mut buf = [0u8; ipc::MAX_PATH_LEN];
            let dl = drv_path.len().min(buf.len());
            buf[..dl].copy_from_slice(&drv_path[..dl]);
            (mounts[idx].driver_ep, buf, dl)
        })
    };
    let Some((driver_ep, drv_path_buf, drv_path_len)) = resolved
    else
    {
        let err = IpcMessage::new(ipc::vfsd_errors::NO_MOUNT);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&err, ipc_buf) };
        return;
    };

    // Forward FS_OPEN to driver with the driver-relative path.
    let fwd_label = ipc::fs_labels::FS_OPEN | ((drv_path_len as u64) << 16);
    let fwd_msg = IpcMessage::builder(fwd_label)
        .bytes(0, &drv_path_buf[..drv_path_len])
        .build();

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
    // SEND_GRANT: fatfs sends per-cache-slot Frame caps as caps[0] on
    // BLK_READ_INTO_FRAME, which requires GRANT on the endpoint cap.
    let partition_ep =
        syscall::cap_derive_token(rt.blk_ep, syscall::RIGHTS_SEND_GRANT, token).ok()?;

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
