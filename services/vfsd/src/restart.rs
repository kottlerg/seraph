// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/restart.rs

//! Restart of an fs driver that died
//! (`services/vfsd/docs/namespace-composition.md` § Driver restart).
//!
//! The watch thread begins a mount's restart when its driver dies and the
//! mount's restart budget has room (`watch::driver_died`): the tree holds
//! the mount restarting, visible but crossed by no lookup
//! (`VfsdRootBackend::begin_restart`). [`restart_mount`] then tears the dead
//! instance down on the watch thread, revoking its service endpoint, so every
//! cap a client held through the mount fails closed, and starts the new
//! driver on a thread of its own ([`respawn`]): the new driver is created
//! from the installed `/services/fs/fatfs` through vfsd's own walk, which
//! reads the root filesystem and can block, while the watch thread must stay
//! free to see the root's death and a disk's loss.
//!
//! The new driver serves the same partition through a new grant of it: the
//! dead driver's grant is cut off (`grant::release`: revoke, retire,
//! delete), and the restart registers the partition again with its block
//! driver, under a new badge, and hands the new driver a derivation of the
//! new partition cap, which the mount keeps from then on. The driver runs on
//! a new service endpoint, with a new death queue. Its record replaces the dead one's in the hold that adds its death
//! queue to the watch set (`VfsdRootBackend::finish_restart`), and clients
//! resolve the mount's path again into it. A restart that cannot start the
//! driver, or finds the disk removed, becomes a removal
//! (`VfsdRootBackend::abandon_restart`), after which the path falls through
//! to the root filesystem as after an unmount. The root mount is never
//! restarted: its loss ends vfsd (`watch::root_lost`).

use std::sync::PoisonError;

use root_backend::Mount;

use crate::VfsdRuntime;
use crate::driver;

/// Monotonic time since the first call, in nanoseconds, for the mounts'
/// restart budgets. Saturates rather than wraps.
pub fn now_ns() -> u64
{
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Restart the driver of the mount at node `idx`, whose restart the watch
/// thread began, `dead` being the dead driver's record.
///
/// On the watch thread: cut off the dead driver's partition grant
/// (`grant::release`: revoke its derivations, retire its badge, which ends
/// the block regions registered through it, and delete the partition cap);
/// revoke and delete its service endpoint, which invalidates every cap
/// derived from it, the caps clients hold through the mount among them;
/// destroy what is left of its process; then start [`respawn`] on a thread
/// of its own. A retire that fails for a reason other than the block
/// driver's death, and a thread that cannot be started, abandon the restart
/// here, so no new driver takes the partition while an earlier holder's
/// region may be live.
pub fn restart_mount(rt: &'static VfsdRuntime, idx: u32, dead: &Mount, ipc_buf: *mut u64)
{
    let cut = grant::release(&mut crate::PartitionIo(ipc_buf), dead.partition);
    driver::teardown_driver(dead.endpoint);
    crate::destroy_driver(dead, ipc_buf);
    if cut.is_err()
    {
        std::os::seraph::log!(warn: "restart: partition grant not retired");
        abandon(rt, idx, ipc_buf);
        return;
    }

    let kept = *dead;
    let spawned = std::thread::Builder::new()
        .name("vfsd-restart".into())
        .spawn(move || respawn(rt, idx, &kept));
    if spawned.is_err()
    {
        std::os::seraph::log!(warn: "restart: thread not started; tearing the mount down");
        abandon(rt, idx, ipc_buf);
    }
}

/// Start a new driver for the mount at node `idx` and end its restart; on
/// the restart's own thread. `dead` is the dead driver's record, whose disk
/// and partition the new driver takes over through a new grant. A driver
/// that does not start ([`start_driver`]) abandons the restart.
fn respawn(rt: &'static VfsdRuntime, idx: u32, dead: &Mount)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "restart thread has no registered IPC buffer");
        abandon_without_walk(rt, idx);
        return;
    }
    match start_driver(rt, idx, dead, ipc_buf)
    {
        Some((path, fatfs, partition)) => land(rt, idx, &path, &fatfs, partition, dead, ipc_buf),
        None => abandon(rt, idx, ipc_buf),
    }
}

/// Start the new driver of the mount at node `idx`, at its path, which the
/// driver's `argv` names as a mount's does, from the installed
/// `/services/fs/fatfs` (`driver::spawn_fatfs_driver` with no boot-module
/// cap), on a derivation of a new grant of `dead`'s partition, registered
/// through the disk's whole-disk cap, and probe it with `FS_MOUNT`. Returns
/// the mount's path, the started driver and the new partition cap; `None`,
/// logged, when the disk was removed, the path cannot be built, the
/// partition cannot be registered, or the driver does not start, every cap
/// made for it released and the new grant cut off.
fn start_driver(
    rt: &VfsdRuntime,
    idx: u32,
    dead: &Mount,
    ipc_buf: *mut u64,
) -> Option<(Vec<u8>, driver::FatfsDriver, u64)>
{
    if crate::watch::disk_removed(rt, dead.disk)
    {
        std::os::seraph::log!(warn: "restart: the disk was removed; tearing the mount down");
        return None;
    }
    let path = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .path_of(idx);
    let Some(path) = path
    else
    {
        std::os::seraph::log!(warn: "restart: no memory for the mount's path; tearing it down");
        return None;
    };
    let Some(partition) = crate::held_disk_cap(rt, dead.disk).and_then(|blk_ep| {
        crate::derive_and_register_partition(blk_ep, dead.first_lba, dead.length_lba, ipc_buf)
    })
    else
    {
        std::os::seraph::log!(warn: "restart: partition not registered");
        return None;
    };
    let Ok(partition_ep) = syscall::cap_derive(partition, syscall::RIGHTS_EP_SEND_GRANT)
    else
    {
        std::os::seraph::log!(warn: "restart: partition cap derive failed; tearing the mount down");
        crate::release_partition(partition, ipc_buf);
        return None;
    };
    // `spawn_fatfs_driver` owns `partition_ep` from here.
    let Some(fatfs) = driver::spawn_fatfs_driver(
        &rt.caps,
        &rt.pool,
        &path,
        partition_ep,
        0,
        rt.system_root_cap,
        ipc_buf,
    )
    else
    {
        std::os::seraph::log!(warn: "restart: the driver did not start; tearing the mount down");
        crate::release_partition(partition, ipc_buf);
        return None;
    };
    Some((path, fatfs, partition))
}

/// End the restart of the mount at node `idx`, at `path`, with the started
/// driver `fatfs` on the new grant `partition`: its record, which keeps
/// `partition`, replaces `dead`'s in the hold that adds its
/// death queue to the watch set (the claim rule of `watch`), so lookups
/// cross into it from then on. Then the disk is checked again
/// (`watch::unmount_if_removed`), since the claims of a disk lost during the
/// restart passed the mount. A death queue the set refuses abandons the
/// restart, the new driver torn down and the new grant cut off.
fn land(
    rt: &VfsdRuntime,
    idx: u32,
    path: &[u8],
    fatfs: &driver::FatfsDriver,
    partition: u64,
    dead: &Mount,
    ipc_buf: *mut u64,
)
{
    let shown = core::str::from_utf8(path).unwrap_or("<non-UTF-8>");
    // A terminal mount resolves through the unbadged SEND, as a `MOUNT`
    // installs it (`do_mount_internal`).
    let mount = Mount {
        cap: fatfs.send,
        endpoint: fatfs.endpoint,
        process: fatfs.process,
        death_queue: fatfs.death_queue,
        partition,
        ..*dead
    };
    let landed = {
        let mut backend = rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let observed = rt.watch.add(&backend, mount.death_queue);
        let finished = observed && backend.finish_restart(idx, mount);
        if observed && !finished
        {
            rt.watch.remove(&backend, mount.death_queue);
        }
        drop(backend);
        finished
    };
    if !landed
    {
        // Revoking the new endpoint invalidates `fatfs.send` and stops the
        // driver, which nothing would reach otherwise.
        std::os::seraph::log!(
            warn: "restart of {shown}: the new driver is not observed; tearing the mount down"
        );
        crate::release_partition(partition, ipc_buf);
        driver::teardown_driver(fatfs.endpoint);
        crate::log_cap_delete("restarted driver process handle", fatfs.process);
        crate::log_cap_delete("restarted driver death queue", fatfs.death_queue);
        abandon(rt, idx, ipc_buf);
        return;
    }
    if crate::watch::unmount_if_removed(rt, mount.disk, mount.death_queue, ipc_buf)
    {
        std::os::seraph::log!(warn: "restart of {shown}: the disk was removed during the restart");
        return;
    }
    std::os::seraph::log!("{shown}: fs driver restarted");
}

/// Turn the restart of the mount at node `idx` into its removal: the tree
/// takes it as a mount whose removal has begun
/// (`VfsdRootBackend::abandon_restart`), and the removal ends as an
/// unmount's does (`crate::finish_unmount`), so its path falls through to
/// the root filesystem. The dead driver was torn down, and its partition
/// grant cut off, when the restart began; a new grant is cut off by the step
/// that made it.
fn abandon(rt: &VfsdRuntime, idx: u32, ipc_buf: *mut u64)
{
    if take_abandoned(rt, idx)
    {
        crate::finish_unmount(rt, idx, ipc_buf);
    }
}

/// [`abandon`] on a thread with no IPC buffer: the removal ends without
/// the walk for a fall-through cap that `crate::finish_unmount` makes for a
/// node a mount below keeps visible, which then answers its unmatched
/// lookups `NotFound`.
fn abandon_without_walk(rt: &VfsdRuntime, idx: u32)
{
    if take_abandoned(rt, idx)
        && rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove_mount(idx)
            .is_none()
    {
        std::os::seraph::log!(error: "restart: the abandoned removal was not under way");
    }
}

/// Move the restart of the mount at node `idx` to a removal. `false`,
/// logged, when no restart was under way, which only the restart's own
/// thread ends.
fn take_abandoned(rt: &VfsdRuntime, idx: u32) -> bool
{
    let abandoned = rt
        .root_backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .abandon_restart(idx);
    if abandoned.is_none()
    {
        std::os::seraph::log!(error: "restart: the abandoned restart was not under way");
        return false;
    }
    true
}
