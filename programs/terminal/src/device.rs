// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/terminal/src/device.rs

//! The terminal's drivers, one [`Device`] per class (input, framebuffer,
//! serial), each kept current across a driver's restart.
//!
//! devmgr restarts a served driver that dies and serves the new instance at
//! the class's next ordinal, and signals the class's `WATCH_CLASS` watches at
//! the withdrawal and again when the new instance is served
//! (services/devmgr/docs/responsibilities.md § Driver Restart, Clients). A
//! [`Device`] registers the watch before its first resolve, so no change is
//! missed, and a tracker thread of its own waits on it and looks at the class
//! again on each signal (`ipc::refresh_device`): the held driver is kept while
//! devmgr still serves it, and replaced by the first live driver past it once
//! withdrawn. The look waits for a restart's settle, which no other thread of
//! the terminal does. The threads that call the driver read the current one
//! here, each with its generation, so a thread whose call fails waits for a
//! newer one ([`Device::await_newer`]) and the sink sees a new instance.

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
    /// the terminal's lines: register its watch, resolve its first live
    /// driver, and start the tracker thread. A refused watch, or a tracker
    /// that cannot be spawned, leaves the first resolve for the run, logged.
    pub fn start(class_send: u64, what: &'static str, ipc_buf: *mut u64) -> Self
    {
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer.
        let watch = unsafe { ipc::watch_class(class_send, ipc_buf) }
            .inspect_err(|e| {
                std::os::seraph::log!(
                    warn: "terminal: {what} class watch refused ({e:?}); resolved once"
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
            std::os::seraph::log!(warn: "terminal: {what} tracker not spawned; resolved once");
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
            std::os::seraph::log!(error: "terminal: {what} tracker has no IPC buffer");
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
                        error: "terminal: {what} class watch wait failed ({e}); no longer followed"
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
                std::os::seraph::log!(warn: "terminal: {what} device query failed ({e:?})");
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
                std::os::seraph::log!("terminal: {what} driver at ordinal {ordinal}");
            }
            None => std::os::seraph::log!(warn: "terminal: {what} driver withdrawn; none served"),
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

    /// The first driver, for a class the terminal cannot run without: the
    /// current one, or, while the class serves none, the first the tracker
    /// resolves, waited for without a bound and logged once as `what`.
    /// `None` when no tracker follows the class and none was resolved.
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
        std::os::seraph::log!("terminal: no {what} device yet; waiting for devmgr to serve one");
        self.wait_for(|driver| driver.is_some(), None)
    }

    /// A driver other than `held`, a thread's whose call on it failed:
    /// waited for for at most `bound`. `None` when none came in that time,
    /// and the thread calls `held` again; a failure devmgr does not follow
    /// with a withdrawal is retried so.
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
