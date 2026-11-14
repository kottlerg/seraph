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
//! The `partition_ep` passed in is a derivation of a badged SEND cap on
//! virtio-blk's service endpoint, already registered with virtio-blk against
//! a specific LBA range; vfsd keeps the registered cap in the mount record.
//! fatfs is never handed the whole-disk cap and cannot escape the partition
//! regardless of what sector number it computes.
//!
//! Each driver gets a death queue its main thread and its address space are
//! bound to before it starts (`docs/namespace-composition.md` § Mount
//! record); both spawn paths return the driver's process handle.

use std::os::seraph::process::ArgvEnvCap;

use ipc::{FS_LABELS_VERSION, IpcMessage, fs_labels, procmgr_labels};

use crate::VfsdCaps;
use crate::worker_pool::{BootstrapOrder, CreateFromFileOrder, WorkerPool, delete_bootstrap_caps};

/// A started fatfs driver instance: what the mount record keeps of it
/// (`root_backend::Mount`, `docs/namespace-composition.md` § Mount record).
pub struct FatfsDriver
{
    /// The driver's service endpoint as vfsd created it. Every cap on that
    /// endpoint derives from this slot (the child's receive copy, [`Self::send`],
    /// and the badged caps a mount mints from `send`), so [`teardown_driver`]
    /// on it is the kill-the-server shape of `docs/namespace-model.md`
    /// § Revocation. A failed mount tears the driver down through it; a
    /// mount that lands keeps it in its record.
    pub endpoint: u64,
    /// `SEND_GRANT` derivation of `endpoint`; the mount transaction probes
    /// the driver and mints its badged caps through it.
    pub send: u64,
    /// procmgr's process handle for the driver.
    pub process: u64,
    /// `RECV` on the driver's death queue ([`new_death_queue`]): the
    /// driver's main thread is bound to it, and procmgr binds the relay
    /// derived from it to the driver's address space, so its main thread's
    /// exit and a terminal fault in any of its threads post to it.
    pub death_queue: u64,
}

/// Entries a driver's death queue holds. The main-thread binding posts once,
/// on the main thread's exit or terminal fault, and procmgr's address-space
/// binding of the relay posts on each terminal fault in any of its threads,
/// so a driver's death usually posts one or two entries. Any one entry
/// reports the death: a post past the capacity, from several threads
/// faulting before procmgr tears the process down, is dropped by the kernel
/// (`QueueFull`) with the death already queued, so the capacity bounds no
/// outcome.
const DEATH_QUEUE_CAPACITY: u32 = 2;

/// Death-observer nodes of a driver's death queue: the main-thread binding
/// and procmgr's address-space binding.
const DEATH_QUEUE_OBSERVERS: u32 = 2;

/// Spawn a fatfs driver instance for a partition and return it.
/// `module_cap` is non-zero only for the root mount; pass zero to use the
/// post-boot path that resolves `/services/fs/fatfs` via vfsd's own held
/// namespace cap (`system_root_cap`) and submits `CREATE_FROM_FILE` to
/// procmgr.
///
/// Takes ownership of `partition_ep`, the driver's partition cap: on
/// success it is the child's, and on `None` it has been released along
/// with every cap vfsd derived or received for the spawn, and any child
/// that already started has had its service endpoint revoked. `module_cap`
/// stays the caller's.
pub fn spawn_fatfs_driver(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    partition_ep: u64,
    module_cap: u64,
    system_root_cap: u64,
    ipc_buf: *mut u64,
) -> Option<FatfsDriver>
{
    if caps.bootstrap_ep == 0
    {
        std::os::seraph::log!(warn: "spawn_fatfs: worker thread not initialised");
        let _ = syscall::cap_delete(partition_ep);
        return None;
    }

    // Create fatfs's service endpoint. fatfs receives service calls on a
    // RIGHTS_ALL derivation of it; vfsd keeps the original for teardown.
    let Some(endpoint) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
    else
    {
        let _ = syscall::cap_delete(partition_ep);
        return None;
    };
    let Some(death_queue) = new_death_queue()
    else
    {
        std::os::seraph::log!(warn: "spawn_fatfs: death queue creation failed");
        let _ = syscall::cap_delete(partition_ep);
        teardown_driver(endpoint);
        return None;
    };

    let started = start_driver(
        caps,
        pool,
        &DriverCaps {
            endpoint,
            death_queue,
            partition_ep,
        },
        module_cap,
        system_root_cap,
        ipc_buf,
    );
    if let Some((send, process)) = started
    {
        Some(FatfsDriver {
            endpoint,
            send,
            process,
            death_queue,
        })
    }
    else
    {
        teardown_driver(endpoint);
        let _ = syscall::cap_delete(death_queue);
        None
    }
}

/// The caps vfsd made or received for one driver before its spawn.
struct DriverCaps
{
    /// The driver's service endpoint, as created.
    endpoint: u64,
    /// `RECV` on the driver's death queue.
    death_queue: u64,
    /// The driver's partition cap, owned by the spawn.
    partition_ep: u64,
}

/// Revoke and delete a driver's service endpoint: every cap derived from
/// it (the child's receive copy, vfsd's `SEND_GRANT`, and any badged cap
/// minted from that) is invalidated, so a running driver loses its service
/// endpoint and exits, and an unstarted spawn leaves nothing behind.
pub fn teardown_driver(endpoint: u64)
{
    if let Err(code) = syscall::cap_revoke_all(endpoint)
    {
        std::os::seraph::log!(warn: "driver teardown: cap_revoke_all failed: code={code}");
    }
    if let Err(code) = syscall::cap_delete(endpoint)
    {
        std::os::seraph::log!(warn: "driver teardown: cap_delete failed: code={code}");
    }
}

/// Spawn the driver behind `driver.endpoint`, deliver its bootstrap caps,
/// and probe it with `FS_MOUNT`. Returns the `SEND_GRANT` derivation of
/// the endpoint and the driver's process handle on success. On `None`,
/// `driver.partition_ep`, the process handle, and every cap not derived
/// from the endpoint or the death queue are released; the caller revokes
/// the endpoint to release the rest, and deletes the death queue.
fn start_driver(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    driver: &DriverCaps,
    module_cap: u64,
    system_root_cap: u64,
    ipc_buf: *mut u64,
) -> Option<(u64, u64)>
{
    let Some((bootstrap, badged_creator)) =
        new_bootstrap_order(caps, driver.endpoint, driver.partition_ep)
    else
    {
        let _ = syscall::cap_delete(driver.partition_ep);
        return None;
    };

    // Both paths release the order's caps and `badged_creator` on failure.
    let process = if module_cap != 0
    {
        spawn_via_module(
            caps,
            pool,
            bootstrap,
            module_cap,
            badged_creator,
            driver.death_queue,
            ipc_buf,
        )
    }
    else
    {
        spawn_via_vfs(
            caps,
            pool,
            bootstrap,
            badged_creator,
            driver.death_queue,
            system_root_cap,
        )
    }?;

    let send = probe_driver(driver.endpoint, ipc_buf);
    if send.is_none()
    {
        let _ = syscall::cap_delete(process);
    }
    Some((send?, process))
}

/// Derive vfsd's `SEND_GRANT` on `endpoint` and probe the driver behind it
/// with `FS_MOUNT`. Returns the derived cap when the driver accepts the
/// probe; on `None` a derived cap is left for the caller's revoke of
/// `endpoint`.
fn probe_driver(endpoint: u64, ipc_buf: *mut u64) -> Option<u64>
{
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
        std::os::seraph::log!(warn: "fatfs FS_MOUNT probe failed (label={})", mount_reply.label);
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
    endpoint: u64,
    partition_ep: u64,
) -> Option<(BootstrapOrder, u64)>
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

/// A driver's death queue: an event queue with room for every post its
/// two bindings can make ([`DEATH_QUEUE_CAPACITY`]) and an observer node
/// for each ([`DEATH_QUEUE_OBSERVERS`]). Returns the original, or `None`
/// when the queue cannot be created.
fn new_death_queue() -> Option<u64>
{
    let bytes = syscall_abi::event_queue_retype_bytes(
        u64::from(DEATH_QUEUE_CAPACITY),
        u64::from(DEATH_QUEUE_OBSERVERS),
    );
    std::os::seraph::object_slab_retype(bytes, |slab| {
        syscall::event_queue_create_observed(slab, DEATH_QUEUE_CAPACITY, DEATH_QUEUE_OBSERVERS).ok()
    })
}

/// A `POST`-only derivation of `death_queue`: the relay a create request
/// carries under `CREATE_DEATH_RELAY` for procmgr to bind to the child's
/// address space.
pub fn derive_death_relay(death_queue: u64) -> Option<u64>
{
    syscall::cap_derive(death_queue, syscall::RIGHTS_EQ_POST).ok()
}

/// Bind a process procmgr created to its death queue and start it.
///
/// `reply_caps` are the caps of the `CREATE_PROCESS` / `CREATE_FROM_FILE`
/// success reply: `[process_handle, child Thread cap]`. The Thread cap binds
/// `death_queue` to the child's main thread (correlator 0: each driver has a
/// queue of its own) before `START_PROCESS`, so no exit precedes the
/// binding, and is then deleted, as is any further cap. The process handle
/// is returned for the mount record. A process that cannot be bound or
/// started is destroyed (`DESTROY_PROCESS`) so procmgr does not keep it,
/// and its handle deleted. Returns `None` without any call when the reply
/// carried no process handle.
pub fn start_child(reply_caps: &[u64], death_queue: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let mut reply = reply_caps.iter().copied();
    let process_handle = reply.next()?;
    let thread = reply.next();
    for cap in reply
    {
        let _ = syscall::cap_delete(cap);
    }
    let bound = thread
        .is_some_and(|thread| syscall::thread_bind_notification(thread, death_queue, 0).is_ok());
    if let Some(thread) = thread
    {
        let _ = syscall::cap_delete(thread);
    }

    let started = bound && {
        let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        let start_reply = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) };
        matches!(start_reply, Ok(ref r) if r.label == 0)
    };
    if started
    {
        return Some(process_handle);
    }
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
    None
}

/// Boot-module spawn path: register the bootstrap order, then issue
/// `CREATE_PROCESS` directly from main and `START_PROCESS`. Used for the
/// root mount only; `/services/fs/fatfs` is not yet reachable when this runs.
///
/// Returns the child's process handle once the child holds its bootstrap
/// caps. On `None` no cap of `bootstrap`, no `badged_creator` and no cap
/// derived from `death_queue` is left in vfsd's `CSpace`.
fn spawn_via_module(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    bootstrap: BootstrapOrder,
    module_cap: u64,
    badged_creator: u64,
    death_queue: u64,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    let module_copy = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL).ok();
    let relay = derive_death_relay(death_queue);
    let (Some(module_copy), Some(relay)) = (module_copy, relay)
    else
    {
        for cap in [module_copy, relay].into_iter().flatten()
        {
            let _ = syscall::cap_delete(cap);
        }
        let _ = syscall::cap_delete(badged_creator);
        delete_bootstrap_caps(bootstrap.blk, bootstrap.service);
        return None;
    };

    let badge = bootstrap.badge;
    // A refused order has its caps released by the pool.
    let Some(handle) = pool.submit_bootstrap(bootstrap)
    else
    {
        let _ = syscall::cap_delete(module_copy);
        let _ = syscall::cap_delete(relay);
        let _ = syscall::cap_delete(badged_creator);
        return None;
    };

    let argv_env = inherited_level_env();
    let argv_env_flag = if argv_env.is_some()
    {
        procmgr_labels::CREATE_ARGV_ENV
    }
    else
    {
        0
    };
    // Same placement as the on-disk fs-driver spawn path (worker.rs): an
    // fs driver runs at vfsd's own level with a matching band ceiling.
    // Caps: [module, creator, argv_env?, relay]; the argv/env header rides
    // in data words 0..4, and the relay is the last cap
    // (`services/procmgr/docs/ipc-interface.md` § Label 1).
    let mut builder = IpcMessage::builder(
        procmgr_labels::CREATE_PROCESS
            | argv_env_flag
            | procmgr_labels::CREATE_DEATH_RELAY
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::FS_DRIVER_PRIORITY,
                ipc::sched_policy::FS_DRIVER_PRIORITY,
            ),
    )
    .cap(module_copy)
    .cap(badged_creator);
    if let Some(env) = &argv_env
    {
        builder = builder.words(0, &env.header_words()).cap(env.cap());
    }
    let create_msg = builder.cap(relay).build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let create_reply = unsafe { ipc::ipc_call(caps.procmgr_ep, &create_msg, ipc_buf) };
    // procmgr has copied the env by now, or refused the request.
    if let Some(env) = argv_env
    {
        env.settle(create_reply.as_ref().map_or(0, |r| r.label));
    }
    let Ok(create_reply) = create_reply
    else
    {
        // A call refused before delivery transfers no cap, so all three are
        // still vfsd's; after delivery the handles are stale and each delete
        // fails closed.
        std::os::seraph::log!(warn: "fatfs CREATE_PROCESS ipc_call failed");
        let _ = syscall::cap_delete(module_copy);
        let _ = syscall::cap_delete(badged_creator);
        let _ = syscall::cap_delete(relay);
        pool.abandon_bootstrap(badge, handle);
        return None;
    };
    if create_reply.label != 0
    {
        std::os::seraph::log!(warn: "fatfs CREATE_PROCESS failed");
        pool.abandon_bootstrap(badge, handle);
        return None;
    }

    if create_reply.caps().is_empty()
    {
        std::os::seraph::log!(warn: "fatfs CREATE_PROCESS reply missing caps");
        pool.abandon_bootstrap(badge, handle);
        return None;
    }

    let Some(process) = start_child(create_reply.caps(), death_queue, ipc_buf)
    else
    {
        std::os::seraph::log!(warn: "fatfs START_PROCESS failed");
        pool.abandon_bootstrap(badge, handle);
        return None;
    };

    if !handle.wait()
    {
        std::os::seraph::log!(warn: "fatfs bootstrap delivery failed");
        let _ = syscall::cap_delete(process);
        return None;
    }

    Some(process)
}

/// The env an fs driver is created with: vfsd's own level, which every fs
/// driver inherits (`std::os::seraph::log::inherited_level_entry`), as its
/// one entry. `None` while vfsd logs at info, and, after a warning, when the
/// cap cannot be built; the driver then logs at info. Both spawn paths use it.
pub fn inherited_level_env() -> Option<ArgvEnvCap>
{
    let entry = std::os::seraph::log::inherited_level_entry()?;
    match ArgvEnvCap::new(&[], 0, &entry, 1)
    {
        Ok(env) => env,
        Err(e) =>
        {
            std::os::seraph::log!(warn: "fatfs spawn: level env not built ({e}); driver logs at info");
            None
        }
    }
}

/// Post-boot spawn path: resolve `/services/fs/fatfs` via vfsd's held namespace
/// cap, then hand the resulting file cap plus size hint to an active
/// worker that issues `CREATE_FROM_FILE` and `START_PROCESS` from
/// outside main. The walk runs on the calling thread (cross-thread to
/// vfsd's own namespace dispatcher, so safe); the worker absorbs the
/// procmgr round so a re-entry into vfsd's OPEN does not deadlock the
/// caller's MOUNT reply path.
///
/// Returns the child's process handle once the child holds its bootstrap
/// caps. On `None` no cap of `bootstrap`, no `badged_creator` and no cap
/// derived from `death_queue` is left in vfsd's `CSpace`.
fn spawn_via_vfs(
    caps: &VfsdCaps,
    pool: &WorkerPool,
    bootstrap: BootstrapOrder,
    badged_creator: u64,
    death_queue: u64,
    system_root_cap: u64,
) -> Option<u64>
{
    let (file_cap, file_size) =
        match std::os::seraph::namespace_lookup_file(system_root_cap, "/services/fs/fatfs")
        {
            Ok(p) => p,
            Err(e) =>
            {
                std::os::seraph::log!(
                    warn: "fatfs spawn: NS_LOOKUP /services/fs/fatfs failed: {e}"
                );
                let _ = syscall::cap_delete(badged_creator);
                delete_bootstrap_caps(bootstrap.blk, bootstrap.service);
                return None;
            }
        };

    // A refused order has every cap it carries released by the pool, and
    // the worker releases them on each of its failure returns.
    let handle = pool.submit_create_from_file(CreateFromFileOrder {
        procmgr_ep: caps.procmgr_ep,
        file_cap,
        file_size,
        badged_creator,
        death_queue,
        bootstrap,
    })?;

    let process = handle.wait();
    if process.is_none()
    {
        std::os::seraph::log!(warn: "fatfs spawn failed");
    }
    process
}
