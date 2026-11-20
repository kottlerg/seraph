// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/device-tracker/src/lib.rs

//! A device class's current driver, kept across devmgr's restart of it, for
//! the `std` clients of the class (the terminal, gdbstub, debug-echo): one
//! [`Device`] per class a client follows.
//!
//! The contract, which services/devmgr/docs/responsibilities.md § Driver
//! Restart, Clients sets for every client:
//!
//! - **Watch before the first resolve.** devmgr restarts a served driver that
//!   dies and serves the new instance at the class's next ordinal, and
//!   signals the class's `WATCH_CLASS` watches at the withdrawal and again
//!   when the new instance is served. [`Device::start`] registers the watch
//!   before it resolves the class's first live driver, so no change between
//!   the two is missed.
//! - **The look on each signal.** A tracker thread of the device's own waits
//!   on the watch and looks at the class again on each signal
//!   (`ipc::refresh_device`): the held driver is kept while devmgr still
//!   serves its ordinal, and replaced by the first live driver past it once
//!   withdrawn, or none. devmgr's answer at the held ordinal decides, not the
//!   held SEND, which can still work when the signal comes.
//! - **The settle wait is the tracker's.** A `QUERY_DEVICE` past a withdrawn
//!   ordinal waits until the restart's settle ends, which can take as long as
//!   the new instance's start. The tracker thread makes it, so no thread that
//!   calls the driver, or serves anything else, waits on it.
//! - **Generations.** Each driver the tracker resolves takes the next
//!   generation ([`Driver::generation`]). A user reads the current driver
//!   with [`Device::current`] before each call, and tells a new instance from
//!   the one it held by its generation: a thread whose call failed waits for
//!   a newer one ([`Device::await_newer`]), and a client re-registers with a
//!   new instance whatever it registered with the dead one (an RX
//!   notification) when the generation changes.
//! - **The tracker deletes the dead SEND.** When it replaces or loses a
//!   driver it deletes the SEND it held; a call still in flight on it then
//!   fails, and its thread reads the current driver again.
//!
//! The crate spawns `std` threads and logs through `std::os::seraph`, so it
//! compiles only for seraph. Its lines carry the client's log name; `what`
//! names the class in them.

#![cfg(target_os = "seraph")]

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

use ipc::{ClassCallError, Refresh};

/// A driver as the tracker last resolved it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Driver
{
    /// The SEND on the driver's service endpoint. The tracker deletes it when
    /// it replaces the driver; a call through it then fails.
    pub cap: u64,
    /// The driver's instance ordinal in its class.
    pub ordinal: u64,
    /// Counts the drivers the tracker has resolved, so a thread tells a new
    /// instance from the one it held.
    pub generation: u64,
}

/// The tracker's state, which every user reads under its lock.
struct State
{
    /// The current driver; `None` while the class serves none.
    driver: Option<Driver>,
    /// The generation the next resolved driver takes.
    next_generation: u64,
}

/// One class's current driver, shared by the threads that call it.
#[derive(Clone)]
pub struct Device
{
    shared: Arc<(Mutex<State>, Condvar)>,
    /// Whether a tracker thread follows the class; without one the first
    /// resolve stands for the run.
    tracked: bool,
}

impl Device
{
    /// Follow the class whose class SEND is `class_send`, named `what` in
    /// the client's lines: register its watch, resolve its first live
    /// driver, and start the tracker thread. A refused watch, or a tracker
    /// that cannot be spawned, leaves the first resolve for the run, logged.
    ///
    /// # Safety
    /// `ipc_buf` must point to the calling thread's registered IPC buffer
    /// page.
    pub unsafe fn start(class_send: u64, what: &'static str, ipc_buf: *mut u64) -> Self
    {
        // SAFETY: the caller guarantees ipc_buf is the registered IPC buffer.
        let watch = unsafe { ipc::watch_class(class_send, ipc_buf) }
            .inspect_err(|e| {
                std::os::seraph::log!(
                    warn: "{what} class watch refused ({e:?}); resolved once"
                );
            })
            .ok();
        let shared = Arc::new((
            Mutex::new(State {
                driver: None,
                next_generation: 0,
            }),
            Condvar::new(),
        ));
        let mut device = Self {
            shared,
            tracked: false,
        };
        // SAFETY: as above.
        let first = unsafe { ipc::refresh_device(class_send, None, ipc_buf) };
        device.apply(first, what);
        let Some(watch) = watch
        else
        {
            return device;
        };
        let tracker = device.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("{what}-tracker"))
            .spawn(move || tracker.track(class_send, watch.note, what));
        if spawned.is_ok()
        {
            device.tracked = true;
        }
        else
        {
            std::os::seraph::log!(warn: "{what} tracker not spawned; resolved once");
            let _ = syscall::cap_delete(watch.note);
        }
        device
    }

    /// The tracker thread: wait on the class watch `note` and look at the
    /// class again on each signal. Returns only when the wait fails.
    fn track(&self, class_send: u64, note: u64, what: &'static str)
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            std::os::seraph::log!(error: "{what} tracker has no IPC buffer");
            return;
        }
        loop
        {
            match syscall::notification_wait_timeout(note, 0)
            {
                Ok(_) =>
                {}
                Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
                {}
                Err(e) =>
                {
                    std::os::seraph::log!(
                        error: "{what} class watch wait failed ({e}); no longer followed"
                    );
                    return;
                }
            }
            let held = self.current().map(|d| d.ordinal);
            // SAFETY: ipc_buf is this thread's registered IPC buffer.
            let found = unsafe { ipc::refresh_device(class_send, held, ipc_buf) };
            self.apply(found, what);
        }
    }

    /// Record what a look at the class found, wake the threads waiting for a
    /// driver, and delete the SEND it replaces.
    fn apply(&self, found: Result<Refresh, ClassCallError>, what: &'static str)
    {
        let next = match found
        {
            Ok(Refresh::Unchanged) => return,
            Ok(Refresh::Replaced { ordinal, cap }) => Some((ordinal, cap)),
            Ok(Refresh::Lost) => None,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "{what} device query failed ({e:?})");
                return;
            }
        };
        let (lock, changed) = &*self.shared;
        let old = {
            let mut state = lock.lock().unwrap_or_else(PoisonError::into_inner);
            let generation = state.next_generation;
            state.next_generation = generation.wrapping_add(1);
            let driver = next.map(|(ordinal, cap)| Driver {
                cap,
                ordinal,
                generation,
            });
            core::mem::replace(&mut state.driver, driver)
        };
        changed.notify_all();
        match next
        {
            Some((ordinal, _)) =>
            {
                std::os::seraph::log!("{what} driver at ordinal {ordinal}");
            }
            None => std::os::seraph::log!(warn: "{what} driver withdrawn; none served"),
        }
        if let Some(old) = old
        {
            let _ = syscall::cap_delete(old.cap);
        }
    }

    /// The current driver, `None` while the class serves none.
    pub fn current(&self) -> Option<Driver>
    {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap_or_else(PoisonError::into_inner).driver
    }

    /// The first driver, for a class the client cannot run without: the
    /// current one, or, while the class serves none, the first the tracker
    /// resolves, waited for without a bound and logged once as `what`.
    /// `None` when no tracker follows the class and none was resolved.
    #[must_use]
    pub fn await_first(&self, what: &str) -> Option<Driver>
    {
        if let Some(driver) = self.current()
        {
            return Some(driver);
        }
        if !self.tracked
        {
            return None;
        }
        std::os::seraph::log!("no {what} device yet; waiting for devmgr to serve one");
        self.wait_for(|driver| driver.is_some(), None)
    }

    /// A driver other than `held`, a thread's whose call on it failed:
    /// waited for for at most `bound`. `None` when none came in that time,
    /// and the thread calls `held` again; a failure devmgr does not follow
    /// with a withdrawal is retried so.
    #[must_use]
    pub fn await_newer(&self, held: Driver, bound: Duration) -> Option<Driver>
    {
        self.wait_for(
            |driver| driver.is_some_and(|d| d.generation != held.generation),
            Some(bound),
        )
    }

    /// Wait until `ready` accepts the current driver, for at most `bound`
    /// (`None`: without one); that driver, or `None` when the bound passed.
    fn wait_for(
        &self,
        ready: impl Fn(Option<Driver>) -> bool,
        bound: Option<Duration>,
    ) -> Option<Driver>
    {
        let (lock, changed) = &*self.shared;
        let state = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let state = match bound
        {
            None => changed
                .wait_while(state, |s| !ready(s.driver))
                .unwrap_or_else(PoisonError::into_inner),
            Some(bound) =>
            {
                changed
                    .wait_timeout_while(state, bound, |s| !ready(s.driver))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
        };
        if ready(state.driver)
        {
            state.driver
        }
        else
        {
            None
        }
    }
}
