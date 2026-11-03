// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/settle.rs

//! Driver settle: wait for each spawned driver of a batch to report its device
//! ready or die, before the registry serves the batch's class.
//!
//! devmgr spawns a batch of `VirtIO` PCI drivers (the virtio-blk drivers at
//! boot, the virtio-input drivers after `SET_DRIVERS_DIR`) against one
//! [`SettleBatch`]: a private driver endpoint, a death event queue, and a wait
//! set over both. Each driver's round-2 devmgr query cap is a SEND on the
//! private endpoint badged with its device badge, and devmgr binds a death
//! observer on the driver's thread with that badge as the correlator.
//! [`SettleBatch::settle`] then serves the drivers' `QUERY_DEVICE_INFO` and
//! `DRIVER_READY` calls on the private endpoint and takes their deaths from
//! the event queue until the [`Roster`] is settled. It does not receive on the
//! registry endpoint, so registry callers stay queued until devmgr returns to
//! its registry loop: devmgr replies to a received call before its next
//! receive and holds no saved reply capability, so it cannot serve other
//! labels while a query on the settling class waits. See
//! `services/devmgr/docs/responsibilities.md` § Relationship to drivers.

use firmware::roster::{ReadyReport, Roster};
use ipc::IpcMessage;

use crate::DeviceCatalog;

/// Wait-set badge of the private driver endpoint.
const WS_BADGE_DRIVER: u64 = 1;
/// Wait-set badge of the death event queue.
const WS_BADGE_DEATH: u64 = 2;

/// The kernel objects one spawn batch settles over. Dropping it revokes and
/// deletes the private driver endpoint, so a driver's devmgr query cap stops
/// naming a receiver devmgr no longer serves, and deletes the event queue
/// and the wait set (a death observer still bound keeps the queue object
/// alive until its thread is freed; the kernel frees it then).
pub struct SettleBatch
{
    driver_ep: u32,
    death_eq: u32,
    wait_set: u32,
}

impl SettleBatch
{
    /// Create the objects for a batch of at most `capacity` drivers, the
    /// death event queue holding one post per driver so no death is
    /// dropped. Returns `None`, logging why and releasing what it created,
    /// when `capacity` is 0, exceeds the kernel's event-queue capacity, or an
    /// object cannot be created.
    pub fn new(capacity: usize) -> Option<Self>
    {
        let Some(eq_capacity) = u32::try_from(capacity)
            .ok()
            .filter(|&c| (1..=syscall_abi::EVENT_QUEUE_MAX_CAPACITY).contains(&c))
        else
        {
            std::os::seraph::log!("settle: batch of {} drivers out of range", capacity as u64);
            return None;
        };
        let Some(driver_ep) =
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })
        else
        {
            std::os::seraph::log!("settle: driver endpoint not created");
            return None;
        };
        let eq_bytes = std::os::seraph::event_queue_retype_bytes(u64::from(eq_capacity));
        let Some(death_eq) = std::os::seraph::object_slab_retype(eq_bytes, |slab| {
            syscall::event_queue_create(slab, eq_capacity).ok()
        })
        else
        {
            std::os::seraph::log!("settle: death event queue not created");
            let _ = syscall::cap_delete(driver_ep);
            return None;
        };
        let Some(wait_set) =
            std::os::seraph::object_slab_retype(std::os::seraph::WAIT_SET_RETYPE_BYTES, |slab| {
                syscall::wait_set_create(slab).ok()
            })
        else
        {
            std::os::seraph::log!("settle: wait set not created");
            let _ = syscall::cap_delete(death_eq);
            let _ = syscall::cap_delete(driver_ep);
            return None;
        };
        let batch = Self {
            driver_ep,
            death_eq,
            wait_set,
        };
        if syscall::wait_set_add(wait_set, driver_ep, WS_BADGE_DRIVER).is_err()
            || syscall::wait_set_add(wait_set, death_eq, WS_BADGE_DEATH).is_err()
        {
            std::os::seraph::log!("settle: wait set registration failed");
            return None;
        }
        Some(batch)
    }

    /// The death event queue a driver's death observer posts to.
    #[must_use]
    pub fn death_eq(&self) -> u32
    {
        self.death_eq
    }

    /// The private driver endpoint, from which a driver's devmgr query cap
    /// is derived.
    #[must_use]
    pub fn driver_ep(&self) -> u32
    {
        self.driver_ep
    }

    /// Serve the batch's drivers until `roster` is settled: every driver has
    /// called `DRIVER_READY` or died. A wait-set failure ends the settle
    /// early, logged, and the drivers still pending are not served.
    pub fn settle<T>(&self, roster: &mut Roster<T>, catalog: &DeviceCatalog, ipc_buf: *mut u64)
    {
        let mut guard = ipc::recv_guard::RecvGuard::new(crate::recv_diag);
        while !roster.is_settled()
        {
            match syscall::wait_set_wait(self.wait_set)
            {
                Ok(WS_BADGE_DEATH) => self.drain_deaths(roster),
                Ok(WS_BADGE_DRIVER) =>
                {
                    // SAFETY: ipc_buf is the registered IPC buffer.
                    match unsafe { ipc::ipc_recv(self.driver_ep, ipc_buf) }
                    {
                        Ok(msg) =>
                        {
                            guard.on_success();
                            serve_driver(&msg, roster, catalog, ipc_buf);
                        }
                        Err(e) => guard.on_failure(e),
                    }
                }
                Ok(_) =>
                {}
                Err(e) =>
                {
                    std::os::seraph::log!("settle: wait set failed (err={e}); pending not served");
                    return;
                }
            }
        }
    }

    /// Mark dead every driver whose death the event queue holds. The
    /// correlator, the post's high 32 bits, is the driver's device badge.
    fn drain_deaths<T>(&self, roster: &mut Roster<T>)
    {
        while let Ok(post) = syscall::event_try_recv(self.death_eq)
        {
            let badge = post >> 32;
            if roster.mark_dead(badge)
            {
                std::os::seraph::log!(
                    "settle: driver of device {} died before it was served (reason={:#x})",
                    badge,
                    post & 0xFFFF_FFFF
                );
            }
        }
    }
}

impl Drop for SettleBatch
{
    fn drop(&mut self)
    {
        let _ = syscall::cap_delete(self.wait_set);
        let _ = syscall::cap_delete(self.death_eq);
        let _ = syscall::cap_revoke(self.driver_ep);
        let _ = syscall::cap_delete(self.driver_ep);
    }
}

/// Serve one driver call on the private endpoint: `QUERY_DEVICE_INFO` as on
/// the registry endpoint, `DRIVER_READY` against `roster`.
fn serve_driver<T>(
    msg: &IpcMessage,
    roster: &mut Roster<T>,
    catalog: &DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    match msg.label
    {
        ipc::devmgr_labels::QUERY_DEVICE_INFO =>
        {
            crate::reply_device_info(catalog, msg, ipc_buf);
        }
        ipc::devmgr_labels::DRIVER_READY =>
        {
            if msg.word(0) != u64::from(ipc::DEVMGR_LABELS_VERSION)
            {
                crate::reply_status(ipc::devmgr_errors::LABEL_VERSION_MISMATCH, ipc_buf);
                return;
            }
            let code = match roster.mark_ready(msg.badge)
            {
                ReadyReport::Accepted | ReadyReport::Repeated => ipc::devmgr_errors::SUCCESS,
                ReadyReport::AfterDeath | ReadyReport::Unknown =>
                {
                    ipc::devmgr_errors::INVALID_REQUEST
                }
            };
            crate::reply_status(code, ipc_buf);
        }
        _ => crate::reply_status(ipc::devmgr_errors::UNKNOWN_OPCODE, ipc_buf),
    }
}
