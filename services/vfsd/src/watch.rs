// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/src/watch.rs

//! Observation of the fs drivers and of the disks under the mounts
//! (`services/vfsd/docs/namespace-composition.md` § Driver death and device
//! loss).
//!
//! vfsd's main thread, once it has spawned the service threads, is the watch
//! thread ([`watch_loop`]): it waits on one wait set ([`WatchSet`]) that
//! holds vfsd's watch of devmgr's `block` class and the death queue of every
//! mount lookups cross. It acts on two events:
//!
//! * A driver's death ([`driver_died`]): the mount is torn down without the
//!   driver, its mount point falls through to the root filesystem, and the
//!   disk under it is probed ([`partition::probe`]).
//! * A change of the class ([`class_changed`]): every held disk is probed.
//!
//! A disk devmgr withdrew is marked removed and each mount on it torn down
//! as a forced unmount ([`disk_lost`]). The root mount's death, and its
//! disk's removal, end vfsd ([`root_lost`]).
//!
//! Claim rule. Whoever begins a mount's removal (an `UNMOUNT`, a death, a
//! loss) takes the mount's death queue out of the set in the same hold of
//! the `root_backend` lock as `begin_unmount` ([`claim`]); a refused
//! `UNMOUNT` puts the queue back in the hold that restores the mount, and a
//! `MOUNT` adds it in the hold that installs the mount. So the set holds the
//! queues of the mounts lookups cross and of no other, and the thread acts on
//! a readiness only when, in one hold, the queue belongs to such a mount and
//! yields a death entry: a readiness taken before another thread claimed the
//! mount finds nothing to act on.

use std::sync::PoisonError;

use root_backend::{MAX_MOUNTS, Mount, VfsdRootBackend};
use syscall_abi::WAIT_SET_MAX_MEMBERS;

use crate::VfsdRuntime;
use crate::partition::{self, DiskState};

/// The class watch's badge in the set. A death queue's badge is its own cap
/// handle, whose bit 63 the kernel keeps clear, so no queue's badge is this
/// one.
const CLASS_WATCH_BADGE: u64 = u64::MAX;

/// The root mount's node in the tree (`VfsdRootBackend::find` of `/`).
const ROOT_NODE: u32 = 0;

/// The process exit code vfsd ends with when its root filesystem is lost.
const EXIT_ROOT_LOST: i32 = 1;

// The set holds the class watch and one death queue per mount the tree can
// hold, so an add for a mount the tree accepted is never refused for room.
const _: () = assert!(MAX_MOUNTS + 1 == WAIT_SET_MAX_MEMBERS as usize);

/// The wait set the watch thread waits on, and the class watch in it.
pub struct WatchSet
{
    /// The wait set, of `WAIT_SET_MAX_MEMBERS` members: the class watch and
    /// at most [`MAX_MOUNTS`] death queues, each with its handle as badge.
    set: u64,
    /// The Notification devmgr signals on a change of the `block` class
    /// (`devmgr_labels::WATCH_CLASS`), with the wait right only.
    note: u64,
}

impl WatchSet
{
    /// Register a watch of the class whose SEND is `block_class` and make
    /// the set with the watch as its first member. `None`, logged, when the
    /// watch is refused or the set cannot be made.
    pub fn new(block_class: u64, ipc_buf: *mut u64) -> Option<Self>
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let note = match unsafe { ipc::watch_class(block_class, ipc_buf) }
        {
            Ok(watch) => watch.note,
            Err(e) =>
            {
                std::os::seraph::log!(error: "block class watch refused: {e:?}");
                return None;
            }
        };
        let set = std::os::seraph::object_slab_retype(
            std::os::seraph::wait_set_retype_bytes(u64::from(WAIT_SET_MAX_MEMBERS)),
            |slab| syscall::wait_set_create(slab, WAIT_SET_MAX_MEMBERS).ok(),
        );
        let Some(set) = set
        else
        {
            std::os::seraph::log!(error: "watch set creation failed");
            let _ = syscall::cap_delete(note);
            return None;
        };
        if let Err(code) = syscall::wait_set_add(set, note, CLASS_WATCH_BADGE)
        {
            std::os::seraph::log!(error: "class watch not added to the watch set: code={code}");
            let _ = syscall::cap_delete(set);
            let _ = syscall::cap_delete(note);
            return None;
        }
        Some(Self { set, note })
    }

    /// Add a mount's death queue to the set, in a hold of the `root_backend`
    /// lock, which `_held` is (the claim rule). `false`, logged, when the
    /// kernel refuses it.
    pub fn add(&self, _held: &VfsdRootBackend, death_queue: u64) -> bool
    {
        match syscall::wait_set_add(self.set, death_queue, death_queue)
        {
            Ok(()) => true,
            Err(code) =>
            {
                std::os::seraph::log!(warn: "death queue not added to the watch set: code={code}");
                false
            }
        }
    }

    /// Take a mount's death queue out of the set, in a hold of the
    /// `root_backend` lock, which `_held` is (the claim rule).
    pub fn remove(&self, _held: &VfsdRootBackend, death_queue: u64)
    {
        if let Err(code) = syscall::wait_set_remove(self.set, death_queue)
        {
            std::os::seraph::log!(warn: "death queue not in the watch set: code={code}");
        }
    }
}

/// The watch thread's entry, run by vfsd's main thread: wait on the set and
/// act on each readiness.
pub fn watch_loop(rt: &'static VfsdRuntime) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "watch thread has no registered IPC buffer");
        syscall::thread_exit();
    }

    let mut guard = ipc::recv_guard::RecvGuard::new(crate::recv_diag);
    loop
    {
        let badge = match syscall::wait_set_wait(rt.watch.set)
        {
            Ok(badge) => badge,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        if badge == CLASS_WATCH_BADGE
        {
            class_changed(rt, ipc_buf);
        }
        else
        {
            driver_died(rt, badge, ipc_buf);
        }
    }
}

/// devmgr signalled a change of the `block` class: a driver served or
/// withdrawn. Probe every held disk and handle each one withdrawn. A new
/// driver changes nothing here: a `MOUNT` finds its disk.
fn class_changed(rt: &VfsdRuntime, ipc_buf: *mut u64)
{
    // Clear the bits before the probes, so a change during them signals
    // again.
    let _ = syscall::notification_try_wait(rt.watch.note);
    let count = rt
        .disks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len();
    for disk in 0..count
    {
        probe_disk(rt, disk, ipc_buf);
    }
}

/// Ask devmgr whether it still serves the held disk at `disk`
/// ([`partition::probe`]) and handle its loss when it withdrew it
/// ([`disk_lost`]). A removed disk is not asked again.
pub fn probe_disk(rt: &VfsdRuntime, disk: usize, ipc_buf: *mut u64)
{
    if let Some(ordinal) = held_ordinal(rt, disk)
        && partition::probe(rt.caps.block_class, ordinal, ipc_buf) == DiskState::Withdrawn
    {
        disk_lost(rt, disk, ipc_buf);
    }
}

/// The ordinal of the held disk at `disk`; `None` once it is removed.
fn held_ordinal(rt: &VfsdRuntime, disk: usize) -> Option<u64>
{
    rt.disks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(disk)
        .filter(|d| !d.removed)
        .map(|d| d.ordinal)
}

/// The death queue `queue` is ready. When it belongs to a mount lookups
/// cross and yields the driver's death, tear the mount down without the
/// driver, which no longer answers, and probe its disk: a driver that died
/// of its disk's removal leads to the disk's loss. The root mount's death
/// ends vfsd.
fn driver_died(rt: &VfsdRuntime, queue: u64, ipc_buf: *mut u64)
{
    let taken = take_death(
        rt,
        &mut rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        queue,
    );
    let Some((idx, mount, reason)) = taken
    else
    {
        return;
    };
    std::os::seraph::log!(
        warn: "fs driver of the mount on disk index {} died (reason={reason:#x}); \
         tearing the mount down",
        mount.disk
    );
    crate::teardown_dead_mount(&mount, ipc_buf);
    crate::finish_unmount(rt, idx, ipc_buf);
    probe_disk(rt, mount.disk, ipc_buf);
}

/// In the hold `backend`, take the death `queue` holds when it belongs to a
/// mount lookups cross, and claim that mount ([`begin_claim`]); returns its
/// node, its record and the death's reason. `None` for a readiness with no
/// such mount or no death behind it. The root mount's death ends vfsd.
fn take_death(
    rt: &VfsdRuntime,
    backend: &mut VfsdRootBackend,
    queue: u64,
) -> Option<(u32, Mount, u64)>
{
    let idx = backend.find_mounted(|m| m.death_queue == queue)?;
    let reason = syscall::event_try_recv(queue).ok()?;
    if idx == ROOT_NODE
    {
        root_lost(format_args!("its fs driver died (reason={reason:#x})"));
    }
    begin_claim(rt, backend, idx)
        .ok()
        .map(|mount| (idx, mount, reason))
}

/// devmgr withdrew the held disk at `disk`: mark it removed
/// ([`partition::Disk::remove`]) and tear down each mount on it as a forced
/// unmount. A disk already removed is left as it is. The root mount on it
/// ends vfsd.
fn disk_lost(rt: &VfsdRuntime, disk: usize, ipc_buf: *mut u64)
{
    let newly_removed = rt
        .disks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_mut(disk)
        .and_then(|held| {
            let ordinal = held.ordinal;
            held.remove().then_some(ordinal)
        });
    let Some(ordinal) = newly_removed
    else
    {
        return;
    };
    std::os::seraph::log!(warn: "disk {ordinal}: removed; tearing down its mounts");
    while let Some((idx, mount)) = claim(rt, |m| m.disk == disk)
    {
        crate::force_unmount(rt, idx, &mount, ipc_buf);
    }
}

/// Tear down, as a forced unmount, the mount on the disk at `disk` whose
/// death queue is `death_queue` when that disk is removed; returns whether
/// it is.
///
/// For a mount that became one lookups cross outside the claims of
/// [`disk_lost`]: one a `MOUNT` installed, or one a refused `UNMOUNT`
/// restored, after those claims passed it. The disk is marked removed
/// before the claims, so the claims or this check, which follows the
/// install or the restore, see the mount; when both do, the first claim
/// wins and the other finds nothing to claim.
pub fn unmount_if_removed(
    rt: &VfsdRuntime,
    disk: usize,
    death_queue: u64,
    ipc_buf: *mut u64,
) -> bool
{
    let removed = rt
        .disks
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(disk)
        .is_none_or(|d| d.removed);
    // The disk is matched too: once another remover ended the mount, a later
    // mount's death queue may reuse the handle.
    if removed
        && let Some((idx, mount)) = claim(rt, |m| m.disk == disk && m.death_queue == death_queue)
    {
        crate::force_unmount(rt, idx, &mount, ipc_buf);
    }
    removed
}

/// Claim the first mount lookups cross whose record `matches` ([`begin_claim`]
/// in one hold of the `root_backend` lock). `None` when no such mount is
/// left. The root mount is never claimed: its loss ends vfsd.
pub fn claim(rt: &VfsdRuntime, matches: impl Fn(&Mount) -> bool) -> Option<(u32, Mount)>
{
    claim_in(
        rt,
        &mut rt
            .root_backend
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
        matches,
    )
}

/// [`claim`] in the hold `backend`.
fn claim_in(
    rt: &VfsdRuntime,
    backend: &mut VfsdRootBackend,
    matches: impl Fn(&Mount) -> bool,
) -> Option<(u32, Mount)>
{
    let idx = backend.find_mounted(matches)?;
    if idx == ROOT_NODE
    {
        root_lost(format_args!("its disk was removed"));
    }
    begin_claim(rt, backend, idx).ok().map(|mount| (idx, mount))
}

/// Begin the removal of the mount at node `idx` and take its death queue
/// out of the set, in the hold `backend` of the `root_backend` lock: the
/// claim every remover makes.
pub fn begin_claim(
    rt: &VfsdRuntime,
    backend: &mut VfsdRootBackend,
    idx: u32,
) -> Result<Mount, root_backend::UnmountError>
{
    let mount = backend.begin_unmount(idx)?;
    rt.watch.remove(backend, mount.death_queue);
    Ok(mount)
}

/// Restore the mount at node `idx`, whose removal its claimer abandons, and
/// put its death queue `death_queue` back in the set, in the hold `backend`.
/// Returns whether a removal was under way to restore.
pub fn restore_claim(
    rt: &VfsdRuntime,
    backend: &mut VfsdRootBackend,
    idx: u32,
    death_queue: u64,
) -> bool
{
    let restored = backend.restore_mount(idx);
    if restored && !rt.watch.add(backend, death_queue)
    {
        std::os::seraph::log!(error: "the kept mount's driver is no longer observed");
    }
    restored
}

/// End vfsd: its root filesystem is gone, and with it every path the
/// system-root cap resolves. vfsd is critical and never restarted
/// (`rootfs/config/svcmgr/services/vfsd.svc`), so svcmgr shuts the system
/// down.
///
/// Called on the watch thread, which is vfsd's main thread: the exit
/// syscall ends only the calling thread, and procmgr tears the process down
/// at its main thread's death (`docs/process-lifecycle.md` § Exit reason),
/// which is also the death svcmgr observes.
fn root_lost(why: core::fmt::Arguments<'_>) -> !
{
    std::os::seraph::log!(error: "FATAL: root filesystem lost: {why}; vfsd exits");
    std::process::exit(EXIT_ROOT_LOST)
}
