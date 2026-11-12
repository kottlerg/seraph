// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/settle.rs

//! Driver settle and death observation: wait for each spawned driver of a
//! batch to report its device ready, die, or overrun the settle bound before
//! the registry serves the batch's drivers, and observe every driver's death
//! for the rest of the boot.
//!
//! devmgr keeps one [`DriverWatch`] for the boot: a death event queue every
//! driver's death observer posts to, with its device badge as the
//! correlator, a job notification the registry's workers signal when a
//! request leaves work for the control thread (`crate::Registry`), and a
//! wait set over both that devmgr's control thread waits on. devmgr spawns
//! its drivers in batches after the IOMMU batch (at boot, the drivers bound
//! by the boot modules' declarations; after `SET_DRIVERS_DIR`, the drivers
//! bound by the drivers directory's declarations; after each
//! `BIND_DRIVERS`, the drivers bound by the declarations of the directory it
//! names), each against a [`SettleBatch`]: a private driver endpoint on which
//! each driver's devmgr query cap is a SEND badged with its device badge.
//! [`SettleBatch::settle`] takes the job notification out of the wait set,
//! adds the private endpoint and a timer notification, and runs the
//! host-tested [`roster::settle`] loop: it serves the drivers'
//! `QUERY_DEVICE_INFO` and `DRIVER_READY` calls on the private endpoint and
//! takes their deaths until the [`Roster`] is settled or the batch's bound
//! ([`SETTLE_TIMEOUT`]) elapses, then takes every death still queued. A death of a driver an earlier batch settled goes to
//! the caller, which withdraws it. The registry's workers go on serving
//! meanwhile; a query whose answer a batch still unsettled could change
//! waits for it (`crate::Registry`). See
//! `services/devmgr/docs/responsibilities.md` § Responsibilities.

use core::time::Duration;

use firmware::roster::{
    self, DeathPost, DriverLabels, DriverReply, Roster, SettleEnd, SettleEvents, SettleWake,
};
use ipc::IpcMessage;
use ipc::recv_guard::RecvGuard;

use crate::DeviceCatalog;

/// How long a batch's settle waits for its drivers to report ready or die,
/// from the start of the settle (after the batch's last spawn), before the
/// drivers still pending are destroyed and withdrawn.
///
/// Derived from the longest bounded wait a driver's setup makes before its
/// ready report: the `VirtIO` reset, which a virtio-blk or virtio-input
/// driver polls for at most [`virtio_core::pci::RESET_TIMEOUT`] (5 s), once.
/// The bound is twice that, a margin of one further `RESET_TIMEOUT` for the
/// rest of the setup (memmgr grants, mappings, the virtqueue), so the settle
/// never ends before a driver's own timeout has. The serial, framebuffer,
/// and RTC drivers make no bounded wait in their setup. Every driver's
/// setup also makes synchronous IPC calls (memmgr, and devmgr's own
/// `QUERY_DEVICE_INFO`), which are not bounded; a driver blocked in one past
/// the bound is withdrawn like a hung one.
///
/// The registry protocol publishes the bound as
/// `ipc::devmgr_labels::SETTLE_TIMEOUT_MS`, which a client waiting on a settle
/// reads; the two are asserted equal.
pub const SETTLE_TIMEOUT: Duration =
    Duration::from_secs(2 * virtio_core::pci::RESET_TIMEOUT.as_secs());
const _: () = assert!(SETTLE_TIMEOUT.as_millis() == ipc::devmgr_labels::SETTLE_TIMEOUT_MS as u128);

/// Wait-set badge of the job notification.
const WS_BADGE_JOB: u64 = 1;
/// Wait-set badge of a settling batch's private driver endpoint.
const WS_BADGE_DRIVER: u64 = 2;
/// Wait-set badge of the driver death queue.
const WS_BADGE_DEATH: u64 = 3;
/// Wait-set badge of a settling batch's timer notification.
const WS_BADGE_TIMER: u64 = 4;
/// Wait-set member capacity: the death queue, and either the job
/// notification or a settling batch's private endpoint and timer.
const WS_MEMBERS: u32 = 3;

/// What woke the control thread's wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlWake
{
    /// The job notification was signalled; its bits are taken.
    Job,
    /// The death queue holds at least one post.
    Death,
    /// Any other wake; the loop waits again.
    Other,
}

/// devmgr's death observation for the boot: the death event queue every
/// driver's death observer posts to, the job notification, and the wait set
/// the control thread and the settles wait on.
pub struct DriverWatch
{
    death_eq: u64,
    wait_set: u64,
    job_note: u64,
    /// Whether `job_note` is a member of `wait_set`.
    jobs_open: bool,
}

impl DriverWatch
{
    /// Create the watch for a boot that spawns at most `drivers` drivers:
    /// the death queue holds one post and one death-observer node per
    /// driver, since devmgr spawns each at most once and binds one observer
    /// on each, so no death is dropped and every bind is funded. The queue
    /// holds at most the kernel's `EVENT_QUEUE_MAX_CAPACITY`; past it, the
    /// bind of a driver beyond the queue's nodes fails and that driver is not
    /// spawned, logged. The job notification is a member of the wait set
    /// from the start. Returns `None`, logging why and releasing what it
    /// created, when an object cannot be created.
    pub fn new(drivers: usize) -> Option<Self>
    {
        let capacity = u32::try_from(drivers)
            .unwrap_or(u32::MAX)
            .clamp(1, syscall_abi::EVENT_QUEUE_MAX_CAPACITY);
        if usize::try_from(capacity).is_ok_and(|c| c < drivers)
        {
            std::os::seraph::log!(
                "watch: {} drivers past the death queue's capacity {}",
                drivers as u64,
                capacity
            );
        }
        let eq_bytes =
            std::os::seraph::event_queue_retype_bytes(u64::from(capacity), u64::from(capacity));
        let Some(death_eq) = std::os::seraph::object_slab_retype(eq_bytes, |slab| {
            syscall::event_queue_create_observed(slab, capacity, capacity).ok()
        })
        else
        {
            std::os::seraph::log!("watch: death event queue not created");
            return None;
        };
        let Some(wait_set) = std::os::seraph::object_slab_retype(
            std::os::seraph::wait_set_retype_bytes(u64::from(WS_MEMBERS)),
            |slab| syscall::wait_set_create(slab, WS_MEMBERS).ok(),
        )
        else
        {
            std::os::seraph::log!("watch: wait set not created");
            let _ = syscall::cap_delete(death_eq);
            return None;
        };
        let Some(job_note) = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        else
        {
            std::os::seraph::log!("watch: job notification not created");
            let _ = syscall::cap_delete(wait_set);
            let _ = syscall::cap_delete(death_eq);
            return None;
        };
        if syscall::wait_set_add(wait_set, death_eq, WS_BADGE_DEATH).is_err()
            || syscall::wait_set_add(wait_set, job_note, WS_BADGE_JOB).is_err()
        {
            std::os::seraph::log!("watch: wait set registration failed");
            let _ = syscall::cap_delete(job_note);
            let _ = syscall::cap_delete(wait_set);
            let _ = syscall::cap_delete(death_eq);
            return None;
        }
        Some(Self {
            death_eq,
            wait_set,
            job_note,
            jobs_open: true,
        })
    }

    /// The death event queue a driver's death observer posts to.
    #[must_use]
    pub fn death_eq(&self) -> u64
    {
        self.death_eq
    }

    /// The job notification the registry's workers signal when a request
    /// leaves work for the control thread.
    #[must_use]
    pub fn job_note(&self) -> u64
    {
        self.job_note
    }

    /// Add the job notification back to the wait set after a settle took it
    /// out. A no-op when it is already a member.
    ///
    /// # Errors
    /// The `SYS_WAIT_SET_ADD` error when the kernel refuses the membership.
    fn open_jobs(&mut self) -> Result<(), i64>
    {
        if !self.jobs_open
        {
            syscall::wait_set_add(self.wait_set, self.job_note, WS_BADGE_JOB)?;
            self.jobs_open = true;
        }
        Ok(())
    }

    /// Block until the job notification is signalled or a death post is
    /// queued. A signalled notification stays ready on the set until its
    /// bits are taken, so a job wake takes them.
    ///
    /// # Errors
    /// Returns the wait's failure.
    pub fn wait(&self) -> Result<ControlWake, i64>
    {
        Ok(match syscall::wait_set_wait(self.wait_set)?
        {
            WS_BADGE_JOB =>
            {
                let _ = syscall::notification_try_wait(self.job_note);
                ControlWake::Job
            }
            WS_BADGE_DEATH => ControlWake::Death,
            _ => ControlWake::Other,
        })
    }

    /// Take the next death post the queue holds, if any, without blocking.
    #[must_use]
    pub fn take_death(&self) -> Option<DeathPost>
    {
        syscall::event_try_recv_death(self.death_eq)
            .ok()
            .map(|d| DeathPost {
                badge: d.correlator,
                reason: d.exit_reason,
            })
    }
}

/// The private driver endpoint of one spawn batch. Dropping it revokes and
/// deletes the endpoint, so a driver's devmgr query cap stops naming a
/// receiver devmgr no longer serves.
pub struct SettleBatch
{
    driver_ep: u64,
}

impl SettleBatch
{
    /// Create a batch's private driver endpoint. Returns `None`, logged,
    /// when it cannot be created.
    pub fn new() -> Option<Self>
    {
        let Some(driver_ep) =
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })
        else
        {
            std::os::seraph::log!("settle: driver endpoint not created");
            return None;
        };
        Some(Self { driver_ep })
    }

    /// The private driver endpoint, from which a driver's devmgr query cap
    /// is derived.
    #[must_use]
    pub fn driver_ep(&self) -> u64
    {
        self.driver_ep
    }

    /// Serve the batch's drivers until `roster` is settled (every driver
    /// has called `DRIVER_READY` or died) or `bound` elapses ([`SETTLE_TIMEOUT`]
    /// for every production batch), then
    /// take every death still queued; a death post naming no driver of the
    /// batch goes to `on_other_death`. Returns how the settle ended. A
    /// wait-set failure ends the settle early, logged, and the drivers still
    /// pending are not served. When the timer cannot be armed the settle
    /// runs unbounded, logged.
    pub fn settle<T>(
        &self,
        watch: &mut DriverWatch,
        roster: &mut Roster<T>,
        catalog: &DeviceCatalog,
        ipc_buf: *mut u64,
        on_other_death: &mut dyn FnMut(DeathPost),
        bound: Duration,
    ) -> SettleEnd
    {
        // A job signalled during the settle would keep the notification
        // ready on the set and wake every wait of the settle, so it is taken
        // out; its signal stays pending until it is added back.
        let reopen = watch.jobs_open;
        if reopen
        {
            let _ = syscall::wait_set_remove(watch.wait_set, watch.job_note);
            watch.jobs_open = false;
        }
        let end = if syscall::wait_set_add(watch.wait_set, self.driver_ep, WS_BADGE_DRIVER).is_ok()
        {
            let timer = Timer::arm(watch.wait_set, bound);
            let mut events = BatchEvents {
                batch: self,
                watch,
                catalog,
                ipc_buf,
                guard: RecvGuard::new(crate::recv_diag),
                on_other_death,
            };
            let end = roster::settle(&mut events, roster);
            let _ = syscall::wait_set_remove(watch.wait_set, self.driver_ep);
            drop(timer);
            end.unwrap_or_else(|e| {
                std::os::seraph::log!("settle: wait set failed (err={e}); pending not served");
                SettleEnd::Settled
            })
        }
        else
        {
            std::os::seraph::log!("settle: driver endpoint not added to the wait set");
            SettleEnd::Settled
        };
        if reopen && let Err(e) = watch.open_jobs()
        {
            std::os::seraph::log!(
                "settle: job notification not re-added to the wait set (err={e}); \
                 jobs wait for a death to wake the control thread"
            );
        }
        end
    }
}

impl Drop for SettleBatch
{
    fn drop(&mut self)
    {
        let _ = syscall::cap_revoke(self.driver_ep);
        let _ = syscall::cap_delete(self.driver_ep);
    }
}

/// A settle's bound: a notification in the wait set that a timer thread
/// signals once the settle's bound has elapsed. The thread holds its own
/// copy of the notification and deletes it after signalling, so a signal
/// after the settle has ended reaches an object no wait set holds, and the
/// thread never touches a slot devmgr may have reused.
struct Timer
{
    wait_set: u64,
    sig: u64,
}

impl Timer
{
    /// Create the notification, add it to `wait_set`, and start the timer
    /// thread. Returns `None`, logged and with what it created released,
    /// when any step fails; the settle then has no bound.
    fn arm(wait_set: u64, bound: Duration) -> Option<Self>
    {
        let Some(sig) = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        else
        {
            std::os::seraph::log!("settle: timer notification not created; settle unbounded");
            return None;
        };
        if syscall::wait_set_add(wait_set, sig, WS_BADGE_TIMER).is_err()
        {
            std::os::seraph::log!("settle: timer not added to the wait set; settle unbounded");
            let _ = syscall::cap_delete(sig);
            return None;
        }
        let timer = Self { wait_set, sig };
        let Ok(copy) = syscall::cap_derive(sig, syscall::RIGHTS_ALL)
        else
        {
            std::os::seraph::log!("settle: timer cap not derived; settle unbounded");
            return None;
        };
        let spawned = std::thread::Builder::new().spawn(move || {
            std::thread::sleep(bound);
            let _ = syscall::notification_send(copy, 1);
            let _ = syscall::cap_delete(copy);
        });
        if spawned.is_err()
        {
            std::os::seraph::log!("settle: timer thread not started; settle unbounded");
            let _ = syscall::cap_delete(copy);
            return None;
        }
        Some(timer)
    }
}

impl Drop for Timer
{
    fn drop(&mut self)
    {
        let _ = syscall::wait_set_remove(self.wait_set, self.sig);
        let _ = syscall::cap_delete(self.sig);
    }
}

/// A batch's kernel objects as the settle loop drives them.
struct BatchEvents<'a>
{
    batch: &'a SettleBatch,
    watch: &'a DriverWatch,
    catalog: &'a DeviceCatalog,
    ipc_buf: *mut u64,
    guard: RecvGuard,
    on_other_death: &'a mut dyn FnMut(DeathPost),
}

impl<T> SettleEvents<T> for BatchEvents<'_>
{
    type Error = i64;

    fn wait(&mut self) -> Result<SettleWake, i64>
    {
        Ok(match syscall::wait_set_wait(self.watch.wait_set)?
        {
            WS_BADGE_DEATH => SettleWake::Death,
            WS_BADGE_DRIVER => SettleWake::Driver,
            WS_BADGE_TIMER => SettleWake::Timeout,
            _ => SettleWake::Other,
        })
    }

    fn try_death(&mut self) -> Option<DeathPost>
    {
        self.watch.take_death()
    }

    fn serve_driver(&mut self, roster: &mut Roster<T>)
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        match unsafe { ipc::ipc_recv(self.batch.driver_ep, self.ipc_buf) }
        {
            Ok(msg) =>
            {
                self.guard.on_success();
                serve_driver(&msg, roster, self.catalog, self.ipc_buf);
            }
            Err(e) => self.guard.on_failure(e),
        }
    }

    fn on_death(&mut self, badge: u64, reason: u64)
    {
        std::os::seraph::log!(
            "settle: driver of device {} died before the batch settled (reason={:#x})",
            badge,
            reason
        );
    }

    fn on_other_death(&mut self, post: DeathPost)
    {
        (self.on_other_death)(post);
    }
}

/// Serve one driver call on the private endpoint: `QUERY_DEVICE_INFO` from
/// the catalog, `DRIVER_READY` against `roster`, as the host-tested
/// [`roster::answer_driver_call`] decides.
fn serve_driver<T>(
    msg: &IpcMessage,
    roster: &mut Roster<T>,
    catalog: &DeviceCatalog,
    ipc_buf: *mut u64,
)
{
    let labels = DriverLabels {
        device_info: ipc::devmgr_labels::QUERY_DEVICE_INFO,
        ready: ipc::devmgr_labels::DRIVER_READY,
        version: u64::from(ipc::DEVMGR_LABELS_VERSION),
    };
    let code = match roster::answer_driver_call(roster, labels, msg.label, msg.word(0), msg.badge)
    {
        DriverReply::DeviceInfo =>
        {
            crate::reply_device_info(catalog, msg, ipc_buf);
            return;
        }
        DriverReply::VersionMismatch => ipc::devmgr_errors::LABEL_VERSION_MISMATCH,
        DriverReply::ReadyAccepted => ipc::devmgr_errors::SUCCESS,
        DriverReply::ReadyRefused => ipc::devmgr_errors::INVALID_REQUEST,
        DriverReply::UnknownLabel => ipc::devmgr_errors::UNKNOWN_OPCODE,
    };
    crate::reply_status(code, ipc_buf);
}
