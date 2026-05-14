// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/driver.rs

//! Filesystem driver process spawning.
//!
//! Creates fatfs driver processes via procmgr. Two spawn paths exist:
//!
//! * **Boot-module path** (root mount only): the very first MOUNT consumes
//!   the boot-module fatfs frame cap delivered to vfsd at bootstrap. This is
//!   the only way to get fatfs running before any filesystem is mounted, so
//!   the cap chain `init → vfsd → procmgr` is unavoidable for the root
//!   mount. After the root MOUNT succeeds, `/bin/fatfs` is reachable through
//!   the just-mounted root filesystem and the boot module is dropped.
//! * **VFS path** (every subsequent mount): vfsd walks its own held
//!   system-root cap to `/bin/fatfs` and asks procmgr to load that
//!   resolved file cap via `procmgr_labels::CREATE_FROM_FILE`.
//!   Procmgr issues `FS_READ` against the file cap, which lands on a
//!   vfs node; the active worker pool absorbs this round so vfsd's
//!   main reply path is not blocked while procmgr re-enters.
//!
//! Both paths route the per-child cap delivery through the bootstrap worker
//! so the main thread's `reply_tcb` is never clobbered while servicing the
//! caller's MOUNT. After the worker signals delivery, main sends a
//! zero-payload `FS_MOUNT` to the new driver as a BPB-validation probe.
//!
//! The `partition_ep` passed in is a tokened SEND cap on virtio-blk's service
//! endpoint, already registered with virtio-blk against a specific LBA range.
//! fatfs is never handed the whole-disk cap and cannot escape the partition
//! regardless of what sector number it computes.

use std::sync::atomic::{AtomicU64, Ordering};

use ipc::{FS_LABELS_VERSION, IpcMessage, fs_labels, procmgr_labels};

use crate::VfsdCaps;
use crate::worker_pool::{BootstrapOrder, CreateFromFileOrder, WorkOrder, WorkerPool};

/// Monotonic counter for fatfs-child bootstrap tokens.
static NEXT_BOOTSTRAP_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Spawn a fatfs driver instance for a partition and return its `SEND_GRANT`
/// service endpoint. `module_cap` is non-zero only for the root mount; pass
/// zero to use the post-boot path that resolves `/bin/fatfs` via vfsd's
/// own held namespace cap (`system_root_cap`) and submits
/// `CREATE_FROM_FILE` to procmgr.
pub fn spawn_fatfs_driver(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    partition_ep: u32,
    module_cap: u32,
    system_root_cap: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    if caps.bootstrap_ep == 0
    {
        std::os::seraph::log!("spawn_fatfs: worker thread not initialised");
        return None;
    }

    // Create fatfs's service endpoint. fatfs receives service calls on
    // this; vfsd holds a SEND_GRANT copy for the FS_MOUNT BPB-validation
    // probe and for `cap_derive_token`-ing the synthetic-root and
    // caller-root caps in `do_mount`.
    let slab = std::os::seraph::object_slab_acquire(88)?;
    let driver_ep = syscall::cap_create_endpoint(slab).ok()?;
    let driver_ep_for_child = syscall::cap_derive(driver_ep, syscall::RIGHTS_ALL).ok()?;
    let driver_send = syscall::cap_derive(driver_ep, syscall::RIGHTS_SEND_GRANT).ok()?;

    // Allocate a bootstrap token and a tokened SEND on the worker-owned
    // bootstrap endpoint. The child receives the tokened cap as its
    // `creator_endpoint` and uses it to fetch its caps via the bootstrap
    // protocol; the bootstrap worker matches by token.
    let token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, Ordering::Relaxed);
    let tokened_creator =
        syscall::cap_derive_token(caps.bootstrap_ep, syscall::RIGHTS_SEND, token).ok()?;
    let bootstrap = BootstrapOrder {
        token,
        blk: partition_ep,
        service: driver_ep_for_child,
    };

    let spawn_ok = if module_cap != 0
    {
        spawn_via_module(caps, pool, bootstrap, module_cap, tokened_creator, ipc_buf)
    }
    else
    {
        spawn_via_vfs(caps, pool, bootstrap, tokened_creator, system_root_cap)
    };

    if !spawn_ok
    {
        return None;
    }

    // Probe the driver with FS_MOUNT: fatfs validates the FS_LABELS_VERSION
    // handshake and the BPB in its handler and replies with
    // fs_errors::SUCCESS or an error label.
    let mount_msg = IpcMessage::builder(fs_labels::FS_MOUNT)
        .word(0, u64::from(FS_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let mount_reply = unsafe { ipc::ipc_call(driver_send, &mount_msg, ipc_buf) }.ok()?;
    if mount_reply.label != 0
    {
        std::os::seraph::log!("fatfs FS_MOUNT probe failed (label={})", mount_reply.label);
        return None;
    }

    std::os::seraph::log!("fatfs driver started");
    Some(driver_send)
}

/// Boot-module spawn path: register the bootstrap order, then issue
/// `CREATE_PROCESS` directly from main and `START_PROCESS`. Used for the
/// root mount only; `/bin/fatfs` is not yet reachable when this runs.
fn spawn_via_module(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    bootstrap: BootstrapOrder,
    module_cap: u32,
    tokened_creator: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let Ok(module_copy) = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL)
    else
    {
        return false;
    };

    let Some(handle) = pool.submit(WorkOrder::Bootstrap(bootstrap))
    else
    {
        let _ = syscall::cap_delete(module_copy);
        let _ = syscall::cap_delete(tokened_creator);
        return false;
    };

    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(module_copy)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(create_reply) = (unsafe { ipc::ipc_call(caps.procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("fatfs CREATE_PROCESS ipc_call failed");
        return false;
    };
    if create_reply.label != 0
    {
        std::os::seraph::log!("fatfs CREATE_PROCESS failed");
        return false;
    }

    let reply_caps = create_reply.caps();
    if reply_caps.is_empty()
    {
        std::os::seraph::log!("fatfs CREATE_PROCESS reply missing caps");
        return false;
    }
    let process_handle = reply_caps[0];

    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let start_ok = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(ref r) if r.label == 0
    );
    if !start_ok
    {
        std::os::seraph::log!("fatfs START_PROCESS failed");
        return false;
    }

    if !handle.wait()
    {
        std::os::seraph::log!("fatfs bootstrap delivery failed");
        return false;
    }

    true
}

/// Post-boot spawn path: resolve `/bin/fatfs` via vfsd's held namespace
/// cap, then hand the resulting file cap plus size hint to an active
/// worker that issues `CREATE_FROM_FILE` and `START_PROCESS` from
/// outside main. The walk runs on the calling thread (cross-thread to
/// vfsd's own namespace dispatcher, so safe); the worker absorbs the
/// procmgr round so a re-entry into vfsd's OPEN does not deadlock the
/// caller's MOUNT reply path.
fn spawn_via_vfs(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    bootstrap: BootstrapOrder,
    tokened_creator: u32,
    system_root_cap: u32,
) -> bool
{
    let (file_cap, file_size) =
        match std::os::seraph::namespace_lookup_file(system_root_cap, "/bin/fatfs")
        {
            Ok(p) => p,
            Err(e) =>
            {
                std::os::seraph::log!("fatfs spawn: NS_LOOKUP /bin/fatfs failed: {e}");
                let _ = syscall::cap_delete(tokened_creator);
                return false;
            }
        };

    let Some(handle) = pool.submit(WorkOrder::CreateFromFile(CreateFromFileOrder {
        procmgr_ep: caps.procmgr_ep,
        file_cap,
        file_size,
        tokened_creator,
        bootstrap,
    }))
    else
    {
        let _ = syscall::cap_delete(file_cap);
        let _ = syscall::cap_delete(tokened_creator);
        return false;
    };

    if !handle.wait()
    {
        std::os::seraph::log!("fatfs spawn failed");
        return false;
    }

    true
}
