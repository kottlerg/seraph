// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/driver.rs

//! Filesystem driver process spawning.
//!
//! Creates fatfs driver processes via procmgr, over the two spawn paths
//! `services/vfsd/README.md` § Responsibilities (Filesystem driver
//! lifecycle) specifies: the root self-mount spawns from the boot-module
//! fatfs cap (`spawn_via_module`), and every later mount (`spawn_via_vfs`)
//! from the file cap vfsd walks to `/services/fs/fatfs` through
//! `CREATE_FROM_FILE`, whose `FS_READ` re-entry the worker pool absorbs so
//! vfsd's main reply path is not blocked.
//!
//! Both paths route the per-child cap delivery through the bootstrap worker
//! so the main thread's `reply_tcb` is never clobbered while servicing the
//! caller's MOUNT. After the worker signals delivery, main sends
//! `FS_MOUNT` (request layout in `services/fs/docs/fs-driver-protocol.md`
//! § Label 10: `FS_MOUNT`) to the new driver as a BPB-validation probe.
//!
//! The `partition_ep` passed in is a badged SEND cap on virtio-blk's service
//! endpoint, already registered with virtio-blk against a specific LBA range.
//! fatfs is never handed the whole-disk cap and cannot escape the partition
//! regardless of what sector number it computes.

use ipc::{FS_LABELS_VERSION, IpcMessage, fs_labels, procmgr_labels};

use crate::VfsdCaps;
use crate::worker_pool::{
    BootstrapOrder, CreateFromFileOrder, WorkOrder, WorkerPool, delete_bootstrap_caps,
};

/// A started fatfs driver instance.
pub struct FatfsDriver
{
    /// The driver's service endpoint as vfsd created it. Every cap on that
    /// endpoint derives from this slot (the child's receive copy, [`Self::send`],
    /// and the badged caps a mount mints from `send`), so [`teardown_driver`]
    /// on it is the kill-the-server shape of `docs/namespace-model.md`
    /// § Revocation. A failed mount tears the driver down through it; a
    /// mount that lands keeps it, unused, for the life of vfsd, since mounts
    /// are permanent (no unmount exists), as the revocation handle an unmount
    /// would use.
    pub endpoint: u32,
    /// `SEND_GRANT` derivation of `endpoint`; the mount transaction probes
    /// the driver and mints its badged caps through it.
    pub send: u32,
}

/// Spawn a fatfs driver instance for a partition and return its endpoint
/// pair. `module_cap` is non-zero only for the root mount; pass zero to use
/// the post-boot path that resolves `/services/fs/fatfs` via vfsd's own held
/// namespace cap (`system_root_cap`) and submits `CREATE_FROM_FILE` to
/// procmgr.
///
/// Takes ownership of `partition_ep`: on success it is the child's, and on
/// `None` it has been released along with every cap vfsd derived for the
/// spawn, and any child that already started has had its service endpoint
/// revoked. `module_cap` stays the caller's.
pub fn spawn_fatfs_driver(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    partition_ep: u32,
    module_cap: u32,
    system_root_cap: u32,
    ipc_buf: *mut u64,
) -> Option<FatfsDriver>
{
    if caps.bootstrap_ep == 0
    {
        std::os::seraph::log!("spawn_fatfs: worker thread not initialised");
        let _ = syscall::cap_delete(partition_ep);
        return None;
    }

    // Create fatfs's service endpoint. fatfs receives service calls on a
    // RIGHTS_ALL derivation of it; vfsd keeps the original for teardown.
    let Some(endpoint) =
        std::os::seraph::object_slab_retype(88, |slab| syscall::cap_create_endpoint(slab).ok())
    else
    {
        let _ = syscall::cap_delete(partition_ep);
        return None;
    };

    let started = start_driver(
        caps,
        pool,
        endpoint,
        partition_ep,
        module_cap,
        system_root_cap,
        ipc_buf,
    );
    if let Some(send) = started
    {
        Some(FatfsDriver { endpoint, send })
    }
    else
    {
        teardown_driver(endpoint);
        None
    }
}

/// Revoke and delete a driver's service endpoint: every cap derived from
/// it (the child's receive copy, vfsd's `SEND_GRANT`, and any badged cap
/// minted from that) is invalidated, so a running driver loses its service
/// endpoint and exits, and an unstarted spawn leaves nothing behind.
pub fn teardown_driver(endpoint: u32)
{
    if let Err(code) = syscall::cap_revoke_all(endpoint)
    {
        std::os::seraph::log!("driver teardown: cap_revoke_all failed: code={code}");
    }
    if let Err(code) = syscall::cap_delete(endpoint)
    {
        std::os::seraph::log!("driver teardown: cap_delete failed: code={code}");
    }
}

/// Spawn the driver behind `endpoint`, deliver its bootstrap caps, and
/// probe it with `FS_MOUNT`. Returns the `SEND_GRANT` derivation of
/// `endpoint` on success. On `None`, `partition_ep` and every cap not
/// derived from `endpoint` are released; the caller revokes `endpoint` to
/// release the rest.
fn start_driver(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    endpoint: u32,
    partition_ep: u32,
    module_cap: u32,
    system_root_cap: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let Some((bootstrap, badged_creator)) = new_bootstrap_order(caps, endpoint, partition_ep)
    else
    {
        let _ = syscall::cap_delete(partition_ep);
        return None;
    };

    // Both paths release the order's caps and `badged_creator` on failure.
    let spawned = if module_cap != 0
    {
        spawn_via_module(caps, pool, bootstrap, module_cap, badged_creator, ipc_buf)
    }
    else
    {
        spawn_via_vfs(caps, pool, bootstrap, badged_creator, system_root_cap)
    };
    if !spawned
    {
        return None;
    }

    // vfsd's SEND_GRANT copy carries the FS_MOUNT BPB-validation probe and
    // the `cap_derive_badge`-ing of the synthetic-root and caller-root caps
    // in `do_mount`.
    let send = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND_GRANT).ok()?;

    // Probe the driver with FS_MOUNT: fatfs validates the FS_LABELS_VERSION
    // handshake and the BPB in its handler and replies with
    // fs_errors::SUCCESS or an error label.
    let mount_msg = IpcMessage::builder(fs_labels::FS_MOUNT)
        .word(0, u64::from(FS_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let mount_reply = unsafe { ipc::ipc_call(send, &mount_msg, ipc_buf) }.ok()?;
    if mount_reply.label != 0
    {
        std::os::seraph::log!("fatfs FS_MOUNT probe failed (label={})", mount_reply.label);
        return None;
    }

    std::os::seraph::log!("fatfs driver started");
    Some(send)
}

/// Build the bootstrap order for one fatfs child and the badged creator
/// endpoint it will REQUEST on. Returns `None` on any derivation or entropy
/// failure; the caller still owns `partition_ep`, and any child endpoint
/// derived here is released by revoking `endpoint`.
fn new_bootstrap_order(
    caps: &VfsdCaps,
    endpoint: u32,
    partition_ep: u32,
) -> Option<(BootstrapOrder, u32)>
{
    let child_endpoint = syscall::cap_derive(endpoint, syscall::RIGHTS_ALL).ok()?;

    // Allocate a bootstrap badge — a random `u64` from the kernel entropy pool,
    // redrawn off the reserved `0` value (an unbadged SEND carries badge 0) — and
    // a badged SEND on the worker-owned bootstrap endpoint. The child receives the
    // badged cap as its `creator_endpoint` and uses it to fetch its caps via the
    // bootstrap protocol; the bootstrap worker matches by badge value, not index,
    // so a random badge keeps the fatfs-spawn count unguessable.
    let mut badge = syscall::random_u64().ok()?;
    while badge == 0
    {
        badge = syscall::random_u64().ok()?;
    }
    let badged_creator =
        syscall::cap_derive_badge(caps.bootstrap_ep, syscall::RIGHTS_EP_SEND, badge).ok()?;
    let bootstrap = BootstrapOrder {
        badge,
        blk: partition_ep,
        service: child_endpoint,
    };
    Some((bootstrap, badged_creator))
}

/// Start a process procmgr created, then release vfsd's caps on it.
///
/// `reply_caps` are the caps of the `CREATE_PROCESS` / `CREATE_FROM_FILE`
/// success reply: `[process_handle, child Thread cap]`. vfsd never addresses
/// a fatfs process or its thread after starting it (the driver is reached
/// through its service endpoint and torn down by revoking it), so both are
/// deleted on either outcome. A process that fails to start is first
/// destroyed (`DESTROY_PROCESS`) so procmgr does not keep it. Returns
/// whether `START_PROCESS` succeeded; `false` without any call when the
/// reply carried no process handle.
pub fn start_and_release(reply_caps: &[u32], ipc_buf: *mut u64) -> bool
{
    for &cap in reply_caps.iter().skip(1)
    {
        let _ = syscall::cap_delete(cap);
    }
    let Some(&process_handle) = reply_caps.first()
    else
    {
        return false;
    };

    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
    let started = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(ref r) if r.label == 0
    );
    if !started
    {
        let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    }
    let _ = syscall::cap_delete(process_handle);
    started
}

/// Boot-module spawn path: register the bootstrap order, then issue
/// `CREATE_PROCESS` directly from main and `START_PROCESS`. Used for the
/// root mount only; `/services/fs/fatfs` is not yet reachable when this runs.
///
/// Returns `true` once the child holds its bootstrap caps. On `false` no cap
/// of `bootstrap` and no `badged_creator` is left in vfsd's `CSpace`.
fn spawn_via_module(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    bootstrap: BootstrapOrder,
    module_cap: u32,
    badged_creator: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let Ok(module_copy) = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL)
    else
    {
        let _ = syscall::cap_delete(badged_creator);
        delete_bootstrap_caps(bootstrap.blk, bootstrap.service);
        return false;
    };

    let badge = bootstrap.badge;
    // A refused order has its caps released by the pool.
    let Some(handle) = pool.submit(WorkOrder::Bootstrap(bootstrap))
    else
    {
        let _ = syscall::cap_delete(module_copy);
        let _ = syscall::cap_delete(badged_creator);
        return false;
    };

    // Same placement as the on-disk fs-driver spawn path (worker.rs): an
    // fs driver runs at vfsd's own level with a matching band ceiling.
    let create_msg = IpcMessage::builder(
        procmgr_labels::CREATE_PROCESS
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::FS_DRIVER_PRIORITY,
                ipc::sched_policy::FS_DRIVER_PRIORITY,
            ),
    )
    .cap(module_copy)
    .cap(badged_creator)
    .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(create_reply) = (unsafe { ipc::ipc_call(caps.procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        // A call refused before delivery transfers no cap, so both are still
        // vfsd's; after delivery the handles are stale and each delete fails
        // closed.
        std::os::seraph::log!("fatfs CREATE_PROCESS ipc_call failed");
        let _ = syscall::cap_delete(module_copy);
        let _ = syscall::cap_delete(badged_creator);
        pool.abandon_bootstrap(badge, handle);
        return false;
    };
    if create_reply.label != 0
    {
        std::os::seraph::log!("fatfs CREATE_PROCESS failed");
        pool.abandon_bootstrap(badge, handle);
        return false;
    }

    if create_reply.caps().is_empty()
    {
        std::os::seraph::log!("fatfs CREATE_PROCESS reply missing caps");
        pool.abandon_bootstrap(badge, handle);
        return false;
    }

    if !start_and_release(create_reply.caps(), ipc_buf)
    {
        std::os::seraph::log!("fatfs START_PROCESS failed");
        pool.abandon_bootstrap(badge, handle);
        return false;
    }

    if !handle.wait()
    {
        std::os::seraph::log!("fatfs bootstrap delivery failed");
        return false;
    }

    true
}

/// Post-boot spawn path: resolve `/services/fs/fatfs` via vfsd's held namespace
/// cap, then hand the resulting file cap plus size hint to an active
/// worker that issues `CREATE_FROM_FILE` and `START_PROCESS` from
/// outside main. The walk runs on the calling thread (cross-thread to
/// vfsd's own namespace dispatcher, so safe); the worker absorbs the
/// procmgr round so a re-entry into vfsd's OPEN does not deadlock the
/// caller's MOUNT reply path.
///
/// Returns `true` once the child holds its bootstrap caps. On `false` no cap
/// of `bootstrap` and no `badged_creator` is left in vfsd's `CSpace`.
fn spawn_via_vfs(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    bootstrap: BootstrapOrder,
    badged_creator: u32,
    system_root_cap: u32,
) -> bool
{
    let (file_cap, file_size) =
        match std::os::seraph::namespace_lookup_file(system_root_cap, "/services/fs/fatfs")
        {
            Ok(p) => p,
            Err(e) =>
            {
                std::os::seraph::log!("fatfs spawn: NS_LOOKUP /services/fs/fatfs failed: {e}");
                let _ = syscall::cap_delete(badged_creator);
                delete_bootstrap_caps(bootstrap.blk, bootstrap.service);
                return false;
            }
        };

    // A refused order has every cap it carries released by the pool, and
    // the worker releases them on each of its failure returns.
    let Some(handle) = pool.submit(WorkOrder::CreateFromFile(CreateFromFileOrder {
        procmgr_ep: caps.procmgr_ep,
        file_cap,
        file_size,
        badged_creator,
        bootstrap,
    }))
    else
    {
        return false;
    };

    if !handle.wait()
    {
        std::os::seraph::log!("fatfs spawn failed");
        return false;
    }

    true
}
