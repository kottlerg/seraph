// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/server.rs

//! acpid's service once start-up is done (services/acpid/docs/startup.md
//! § Threads): the evaluation thread's work loop, the receivers that serve
//! the requests of `ipc::acpid_labels` on acpid's service endpoint, and the
//! event thread that takes the SCI.
//!
//! The evaluation thread owns the namespace, so every evaluation runs on
//! it, in turn: it takes [`Work`] from a channel (a power request a
//! receiver forwards, a GPE the event thread found, the power button to
//! enable again once its press was delivered, or the end of devmgr's
//! hotplug job) and blocks on nothing else. After each, it acts on the
//! `Notify` calls the evaluations made: each hotplug event of a slot below
//! a port goes to the hotplug thread, which asks devmgr to run the slot's
//! job and hands its end back, on which the evaluation thread runs the
//! slot's `_EJ0` and `_OST` ([`hotplug`]).
//! The event thread blocks on the SCI's notification alone: on each SCI it
//! disables what fired ([`events::scan`]), hands it on, and acknowledges
//! the interrupt; it runs no AML and makes no IPC. Each receiver blocks in
//! `ipc_recv`, on the evaluation thread's answer to a request it forwarded,
//! or, for `WAIT_EVENT`, on the event mailbox. At most one `WAIT_EVENT`
//! waits at a time, a later one taking its place, so the other receiver is
//! free for `SLEEP` and `RESET`.

use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use acpid::events::{self, Fired, Handled, Handler, Layout, Start};
use acpid::hotplug::{self, Event, Held, HotplugJob, HotplugSlots, Outcome};
use acpid::power::{self, Derived, Request};
use aml::namespace::NodeId;
use aml::{Evaluator, Namespace};
use ipc::{IpcMessage, acpid_errors, acpid_labels, devmgr_errors, devmgr_labels};

use crate::arch::current::{Events, Ports, Power};
use crate::devmgr::{CallError, Devmgr};
use crate::platform::{Platform, path_text};
use crate::startup::path;

/// How long a sleep keeps the events quiesced after its sleep register
/// writes return before it takes the platform to be still running and enables
/// the GPEs again ([`events::resume`]): ACPICA's wait before it takes an S4 or S5 write as not taken. A
/// platform entering the state stops well within it, with only its wake
/// events enabled.
const SLEEP_GRACE: Duration = Duration::from_secs(10);

/// The receiver threads on acpid's endpoint (`docs/limits.md`): one can
/// hold a `WAIT_EVENT` while the other serves `SLEEP` and `RESET`.
const RECEIVERS: usize = 2;

/// Work for the evaluation thread.
enum Work
{
    /// Run the method of the GPE, which fired and is disabled.
    Gpe(u16),
    /// A power request a receiver forwards, and where its status goes.
    Power(Request, SyncSender<u64>),
    /// A `QUERY_SLEEP` of the state a receiver forwards, and where its
    /// answer goes.
    QuerySleep(u8, SyncSender<Result<SleepControl, u64>>),
    /// A power-button press was delivered: clear it and enable the button.
    Rearm,
    /// devmgr's job of the hotplug event of the slot device `.0` ended:
    /// the functions it recorded or removed, or why the call failed.
    Hotplug(NodeId, Result<u64, CallError>),
}

/// A thread whose end ends acpid: its drop, on return or in a panic's
/// unwind, tells `main`, which exits so that svcmgr restarts acpid.
pub struct Watched
{
    name: &'static str,
    ended: Sender<&'static str>,
}

impl Watched
{
    /// The thread `name`, whose end is sent on `ended`.
    pub const fn new(name: &'static str, ended: Sender<&'static str>) -> Self
    {
        Self { name, ended }
    }
}

impl Drop for Watched
{
    fn drop(&mut self)
    {
        let _ = self.ended.send(self.name);
    }
}

/// The event mailbox: the power button is posted to it, and `WAIT_EVENT`
/// waits on it.
struct Mailbox
{
    mail: Mutex<Mail>,
    changed: Condvar,
}

struct Mail
{
    /// Whether there is an event to wait for: the SCI is taken and the
    /// fixed power button enabled. `WAIT_EVENT` replies `NO_DEVICE`
    /// otherwise.
    waitable: bool,
    /// The events not yet delivered, a mask of `acpid_labels::EVENT_*`.
    pending: u64,
    /// The number of the latest `WAIT_EVENT`; an earlier one sees it change
    /// and is superseded.
    waiter: u64,
}

impl Mailbox
{
    fn lock(&self) -> MutexGuard<'_, Mail>
    {
        self.mail.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Post `events` and wake the waiting `WAIT_EVENT`.
    fn post(&self, events: u64)
    {
        self.lock().pending |= events;
        self.changed.notify_all();
    }
}

/// The events start-up acquired: the event blocks and the SCI, and whether
/// the FADT declares the fixed power button.
pub struct EventSource
{
    /// The event blocks and the SCI.
    pub events: Events,
    /// Whether the FADT declares the fixed power button
    /// ([`events::fixed_power_button`]).
    pub power_button: bool,
}

/// What the evaluation thread holds of the events once they are armed.
struct Armed
{
    layout: Layout,
    regs: Arc<Mutex<Ports>>,
    handlers: Vec<Handler>,
    /// The events [`events::arm`] enables, whose GPEs a sleep that returns
    /// enables again ([`events::resume`]).
    handled: Handled,
}

/// Arm the events, start the receivers on `service` and the hotplug
/// thread, and run the evaluation thread's work loop for acpid's lifetime:
/// `ns` is the namespace start-up loaded, `None` when the DSDT could not
/// be; `platform` the evaluator's host; `power` the sleep and reset
/// registers; `events` what start-up acquired of the events;
/// `hotplug_slots` the hotplug slots behind the PCI host bridges start-up
/// found; `ended` where each watched thread's end is sent.
pub fn serve(
    service: u64,
    mut ns: Option<&mut Namespace>,
    platform: &mut Platform<'_>,
    power: &Power,
    events: Option<EventSource>,
    hotplug_slots: HotplugSlots,
    ended: &Sender<&'static str>,
) -> !
{
    let (work, jobs) = mpsc::channel();
    let mut hotplug = start_hotplug(platform.devmgr().clone(), hotplug_slots, &work, ended);
    let mailbox = Arc::new(Mailbox {
        mail: Mutex::new(Mail {
            waitable: false,
            pending: 0,
            waiter: 0,
        }),
        changed: Condvar::new(),
    });
    let armed = events.and_then(|source| arm(source, ns.as_deref(), &mailbox, &work, ended));
    for _ in 0..RECEIVERS
    {
        let (mailbox, work, ended) = (Arc::clone(&mailbox), work.clone(), ended.clone());
        let spawned = std::thread::Builder::new()
            .name("acpid-recv".into())
            .spawn(move || {
                let _watched = Watched::new("receiver", ended);
                receive(service, &mailbox, &work);
            });
        if let Err(e) = spawned
        {
            // A request would wait unanswered behind a held `WAIT_EVENT`, as
            // when a receiver ends: exit, and svcmgr restarts acpid.
            std::os::seraph::log!(error: "receiver not spawned: {e}; exiting");
            syscall::process_exit(1);
        }
    }
    loop
    {
        // The `Notify` calls of start-up's evaluations, then of each work
        // item's.
        if let Some(ns) = ns.as_deref_mut()
        {
            hotplug.route_hotplug_notes(ns, platform);
        }
        // `work`, a sender, lives in this frame, so the receive does not
        // fail.
        let Ok(job) = jobs.recv()
        else
        {
            std::os::seraph::log!(error: "the work channel closed; exiting");
            syscall::process_exit(1);
        };
        match job
        {
            Work::Power(request, status) =>
            {
                let code = match request
                {
                    Request::Sleep(state) =>
                    {
                        let events = armed.as_ref().map(|armed| (armed, &*mailbox, &work));
                        sleep(state, ns.as_deref_mut(), platform, power, events)
                    }
                    Request::Reset => reset(power),
                    Request::QuerySleep(_) | Request::WaitEvent => acpid_errors::INVALID_REQUEST,
                };
                let _ = status.send(code);
            }
            Work::QuerySleep(state, answer) =>
            {
                let control = query_sleep(state, ns.as_deref_mut(), platform, power);
                // A receiver that is gone leaves the derivation here.
                if let Err(mpsc::SendError(Ok(control))) = answer.send(control)
                {
                    let _ = syscall::cap_delete(control.derived.cap);
                }
            }
            Work::Gpe(gpe) =>
            {
                if let Some(armed) = &armed
                {
                    dispatch(gpe, armed, ns.as_deref_mut(), platform);
                }
            }
            Work::Rearm =>
            {
                if let Some(armed) = &armed
                {
                    events::rearm_power_button(&mut *lock(&armed.regs), &armed.layout);
                }
            }
            Work::Hotplug(slot, answer) =>
            {
                hotplug.end_hotplug_job(ns.as_deref_mut(), platform, slot, answer);
            }
        }
    }
}

/// The evaluation thread's side of hotplug: the slots it holds the events
/// of, and the channel the hotplug thread takes the jobs to ask on.
struct HotplugServer
{
    slots: HotplugSlots,
    asks: Sender<HotplugJob>,
}

/// Start the hotplug thread, which asks devmgr, through `devmgr`, for the
/// job of each event it is sent, one at a time, and posts each job's end to
/// `work`; the server of `hotplug_slots` that sends it the events. A
/// thread that cannot start exits acpid, as a receiver's does, and svcmgr
/// restarts it.
fn start_hotplug(
    devmgr: Devmgr,
    hotplug_slots: HotplugSlots,
    work: &Sender<Work>,
    ended: &Sender<&'static str>,
) -> HotplugServer
{
    let (asks, asked) = mpsc::channel::<HotplugJob>();
    let (work, ended) = (work.clone(), ended.clone());
    let spawned = std::thread::Builder::new()
        .name("acpid-hotplug".into())
        .spawn(move || {
            let _watched = Watched::new("hotplug", ended);
            // The evaluation thread holds the sender for acpid's lifetime.
            while let Ok(job) = asked.recv()
            {
                let event = match job.event
                {
                    Event::Check => devmgr_labels::HOTPLUG_ADDED,
                    Event::Eject => devmgr_labels::HOTPLUG_REMOVED,
                };
                let answer = devmgr.acpi_hotplug(event, job.port);
                if work.send(Work::Hotplug(job.slot, answer)).is_err()
                {
                    return;
                }
            }
        });
    if let Err(e) = spawned
    {
        std::os::seraph::log!(error: "hotplug thread not spawned: {e}; exiting");
        syscall::process_exit(1);
    }
    HotplugServer {
        slots: hotplug_slots,
        asks,
    }
}

impl HotplugServer
{
    /// Act on the hotplug `Notify` calls `platform` kept: each Bus Check,
    /// Device Check or Eject Request of a device below a port of one of the
    /// slots' host bridges is held in the slots until its job ends, and sent
    /// to the hotplug thread unless an event of its slot was sent before it,
    /// behind which it waits. An event its slot holds already, the
    /// firmware's repeat of it, is dropped, so each slot holds at most one
    /// event of each kind. A `Notify` of no such device is logged and
    /// dropped.
    fn route_hotplug_notes(&mut self, ns: &mut Namespace, platform: &mut Platform<'_>)
    {
        for (target, value) in platform.take_hotplug_notes()
        {
            let at = path_text(&target);
            // The host keeps only hotplug events (`hotplug::keep`).
            let Some(event) = Event::of(value)
            else
            {
                continue;
            };
            let Some(slot) = hotplug::target(ns, &target)
            else
            {
                std::os::seraph::log!(warn: "Notify({at}, {value:#x}) dropped: no such object");
                continue;
            };
            if self.slots.holds(slot, event)
            {
                std::os::seraph::log!(debug: "Notify({at}, {value:#x}) dropped: its slot holds it");
                continue;
            }
            let route = hotplug::route(
                &mut Evaluator::new(ns, platform),
                self.slots.bridges(),
                slot,
            );
            let port = match &route
            {
                Ok(route) => hotplug::port(route, |f| hotplug::secondary_bus(platform, f)),
                Err(why) =>
                {
                    std::os::seraph::log!(warn: "Notify({at}, {value:#x}) dropped: {why:?}");
                    continue;
                }
            };
            let Some(port) = port
            else
            {
                std::os::seraph::log!(
                    warn: "Notify({at}, {value:#x}) dropped: a bridge above it reads no bus"
                );
                continue;
            };
            std::os::seraph::log!(
                "hotplug: {} of {at} (port {}:{}:{}.{}); asking devmgr",
                event.name(),
                port.segment,
                port.bus,
                port.device,
                port.function
            );
            let job = HotplugJob {
                slot,
                value,
                event,
                port: devmgr_labels::pci_function(
                    port.segment,
                    port.bus,
                    port.device,
                    port.function,
                ),
            };
            match self.slots.hold(job)
            {
                Held::Ask(job) => self.ask_hotplug(job),
                Held::Queued =>
                {}
                Held::NoMemory =>
                {
                    std::os::seraph::log!(warn: "Notify({at}, {value:#x}) dropped: no memory to hold it");
                }
            }
        }
    }

    /// Send `job` to the hotplug thread. The thread takes jobs for acpid's
    /// lifetime, and its end exits acpid, so a failed send, logged, comes only
    /// while acpid exits.
    fn ask_hotplug(&self, job: HotplugJob)
    {
        if self.asks.send(job).is_err()
        {
            std::os::seraph::log!(warn: "hotplug job not asked: the hotplug thread ended");
        }
    }

    /// End the asked hotplug event of `slot` once devmgr's job of it ended
    /// with `answer`: run the slot's methods that end it
    /// ([`run_hotplug_methods`]) when `ns` holds the namespace, then send the
    /// slot's next held event to the hotplug thread.
    fn end_hotplug_job(
        &mut self,
        ns: Option<&mut Namespace>,
        platform: &mut Platform<'_>,
        slot: NodeId,
        answer: Result<u64, CallError>,
    )
    {
        let Some((job, next)) = self.slots.end(slot)
        else
        {
            return;
        };
        if let Some(ns) = ns
        {
            run_hotplug_methods(ns, platform, &job, answer);
        }
        if let Some(next) = next
        {
            self.ask_hotplug(next);
        }
    }
}

/// Run the slot methods that end the hotplug event `job`, whose devmgr job
/// ended with `answer`: for an Eject Request devmgr ran, the slot's
/// `_EJ0`; then, when the slot has one, its `_OST` with the status of the
/// outcome ([`hotplug::ost_status`]).
fn run_hotplug_methods(
    ns: &mut Namespace,
    platform: &mut Platform<'_>,
    job: &HotplugJob,
    answer: Result<u64, CallError>,
)
{
    let at = path(ns, job.slot);
    let what = job.event.name();
    let mut ev = Evaluator::new(ns, platform);
    let outcome = match (answer, job.event)
    {
        (Ok(functions), Event::Check) =>
        {
            std::os::seraph::log!("hotplug: {what} of {at}: devmgr added {functions} functions");
            Outcome::Done
        }
        (Ok(functions), Event::Eject) => match hotplug::eject(&mut ev, job.slot)
        {
            Some(Ok(())) =>
            {
                std::os::seraph::log!(
                    "hotplug: {at} ejected (_EJ0) once devmgr removed {functions} functions"
                );
                Outcome::Done
            }
            Some(Err(fault)) =>
            {
                std::os::seraph::log!(warn: "hotplug: {at}._EJ0 faulted: {fault:?}");
                Outcome::Failed
            }
            None =>
            {
                std::os::seraph::log!(
                    warn: "hotplug: {at} has no _EJ0; devmgr removed {functions} functions"
                );
                Outcome::Failed
            }
        },
        (Err(CallError::Status(devmgr_errors::REFUSED | devmgr_errors::NO_DEVICE)), _) =>
        {
            std::os::seraph::log!(warn: "hotplug: {what} of {at}: devmgr refused it");
            Outcome::Refused
        }
        (Err(e), _) =>
        {
            std::os::seraph::log!(warn: "hotplug: {what} of {at}: devmgr's job failed: {e:?}");
            Outcome::Failed
        }
    };
    let status = hotplug::ost_status(job.event, outcome);
    if let Some(Err(fault)) = hotplug::ost(&mut ev, job.slot, job.value, status)
    {
        std::os::seraph::log!(warn: "hotplug: {at}._OST faulted: {fault:?}");
    }
}

/// Lock the event registers.
fn lock(regs: &Mutex<Ports>) -> MutexGuard<'_, Ports>
{
    regs.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Arm the events of `source`: start the event thread, which binds the
/// blocks to itself and registers the SCI, then set the enables
/// ([`events::arm`]), hand on the events already pending, and let the
/// event thread take the SCI. The GPEs handled are each `\_GPE` method of
/// `ns`. `None`, logged, when the event thread cannot start or take the
/// SCI; every event is then disabled and its status cleared
/// ([`events::clear`]), those a dead acpid of the boot left enabled among
/// them.
fn arm(
    source: EventSource,
    ns: Option<&Namespace>,
    mailbox: &Arc<Mailbox>,
    work: &Sender<Work>,
    ended: &Sender<&'static str>,
) -> Option<Armed>
{
    let EventSource {
        events,
        power_button,
    } = source;
    let layout = events.layout();
    let (handlers, ignored) = ns.map_or_else(Default::default, |ns| {
        events::handlers(ns, layout.gpe_count())
    });
    for name in ignored
    {
        std::os::seraph::log!(
            warn: "\\_GPE.{} not handled: its GPE is past the GPE0 block or has a method already",
            String::from_utf8_lossy(&name)
        );
    }
    let handled = Handled {
        power_button,
        gpes: handlers.iter().map(|h| h.gpe).collect(),
    };
    let (gsi, start) = (events.gsi(), events.start());
    // SAFETY: the evaluation thread bound the blocks at acquisition, and the
    // event thread binds them before it reads or writes a register.
    let regs = Arc::new(Mutex::new(unsafe { events.ports() }));
    let (ready_tx, ready) = mpsc::sync_channel(1);
    let (go, go_rx) = mpsc::sync_channel(1);
    let spawned = {
        let (regs, mailbox, work, ended) = (
            Arc::clone(&regs),
            Arc::clone(mailbox),
            work.clone(),
            ended.clone(),
        );
        std::thread::Builder::new()
            .name("acpid-sci".into())
            .spawn(move || watch(&events, &regs, &mailbox, &work, &ready_tx, &go_rx, ended))
    };
    let taken = match spawned
    {
        Ok(_) => ready.recv().unwrap_or(false),
        Err(e) =>
        {
            std::os::seraph::log!(error: "event thread not spawned: {e}");
            false
        }
    };
    if !taken
    {
        std::os::seraph::log!(warn: "the SCI is not taken; no events");
        events::clear(&mut *lock(&regs), &layout);
        return None;
    }
    let fired = events::arm(&mut *lock(&regs), &layout, &handled);
    mailbox.lock().waitable = power_button;
    std::os::seraph::log!(
        "events armed ({} start, SCI on GSI {gsi}): power button {}, GPEs {:?}",
        match start
        {
            Start::First => "first",
            Start::Restart => "restarted",
        },
        if power_button { "on" } else { "off" },
        handled.gpes
    );
    deliver(&fired, mailbox, work);
    let _ = go.send(());
    Some(Armed {
        layout,
        regs,
        handlers,
        handled,
    })
}

/// The event thread: bind the blocks and register the SCI, and report
/// whether both worked on `ready`; once `go` says the enables are set, take
/// each SCI for acpid's lifetime.
fn watch(
    events: &Events,
    regs: &Mutex<Ports>,
    mailbox: &Mailbox,
    work: &Sender<Work>,
    ready: &SyncSender<bool>,
    go: &Receiver<()>,
    ended: Sender<&'static str>,
)
{
    let thread = std::os::seraph::thread::current_thread_cap();
    let notification =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        });
    let registered = match notification
    {
        None =>
        {
            std::os::seraph::log!(warn: "no notification for the SCI");
            None
        }
        Some(n) => match events
            .bind(thread)
            .and_then(|()| syscall::irq_register(events.sci(), n, events.mode()))
        {
            Ok(()) => Some(n),
            Err(e) =>
            {
                std::os::seraph::log!(
                    warn: "the SCI could not be taken (err={e}, mode {:#x})",
                    events.mode()
                );
                None
            }
        },
    };
    let _ = ready.send(registered.is_some());
    let (Some(notification), Ok(())) = (registered, go.recv())
    else
    {
        return;
    };
    let _watched = Watched::new("event", ended);
    let layout = events.layout();
    loop
    {
        let fired = events::scan(&mut *lock(regs), &layout);
        deliver(&fired, mailbox, work);
        // The registration leaves the line masked until its first
        // acknowledgement, and each later one follows a scan that disabled
        // what fired, so a level-triggered SCI is no longer asserted.
        let _ = syscall::irq_ack(events.sci());
        if let Err(e) = syscall::notification_wait(notification)
        {
            std::os::seraph::log!(error: "waiting for the SCI failed (err={e}); exiting");
            return;
        }
    }
}

/// Hand `fired` on: the power button to the mailbox, each GPE to the
/// evaluation thread.
fn deliver(fired: &Fired, mailbox: &Mailbox, work: &Sender<Work>)
{
    if fired.power_button
    {
        std::os::seraph::log!("power button pressed");
        mailbox.post(acpid_labels::EVENT_POWER_BUTTON);
    }
    for &gpe in &fired.gpes
    {
        let _ = work.send(Work::Gpe(gpe));
    }
}

/// Run GPE `gpe`'s method between [`events::gpe_begin`] and
/// [`events::gpe_end`], which enables the GPE again.
fn dispatch(gpe: u16, armed: &Armed, ns: Option<&mut Namespace>, platform: &mut Platform<'_>)
{
    let Some(handler) = armed.handlers.iter().find(|h| h.gpe == gpe)
    else
    {
        return;
    };
    events::gpe_begin(&mut *lock(&armed.regs), &armed.layout, gpe, handler.trigger);
    if let Some(ns) = ns
    {
        std::os::seraph::log!(debug: "GPE {gpe:#x}: running its method");
        if let Err(fault) = Evaluator::new(ns, platform).evaluate(handler.method, Vec::new())
        {
            std::os::seraph::log!(warn: "GPE {gpe:#x}: its method faulted: {fault:?}");
        }
    }
    events::gpe_end(&mut *lock(&armed.regs), &armed.layout, gpe, handler.trigger);
}

/// A receiver: serve the requests received on `service` for acpid's
/// lifetime. A receive that keeps failing exits acpid
/// (`ipc::recv_guard`), and svcmgr restarts it.
fn receive(service: u64, mailbox: &Mailbox, work: &Sender<Work>) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(service, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        match power::decode(msg.label, msg.badge, msg.word(0), msg.word(1))
        {
            Ok(Request::WaitEvent) => wait_event(mailbox, work, ipc_buf),
            Ok(Request::QuerySleep(state)) => reply_sleep_control(ask_sleep(state, work), ipc_buf),
            Ok(request) => reply(forward(request, work), ipc_buf),
            Err(code) => reply(code, ipc_buf),
        }
    }
}

/// Reply `status` from this thread's IPC buffer `ipc_buf`.
fn reply(status: u64, ipc_buf: *mut u64)
{
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(status), ipc_buf) };
}

/// Forward `request` to the evaluation thread and wait for its status;
/// `NO_DEVICE` when the thread cannot take it.
fn forward(request: Request, work: &Sender<Work>) -> u64
{
    let (status, answer) = mpsc::sync_channel(1);
    if work.send(Work::Power(request, status)).is_err()
    {
        return acpid_errors::NO_DEVICE;
    }
    answer.recv().unwrap_or(acpid_errors::NO_DEVICE)
}

/// Forward a `QUERY_SLEEP` of `state` to the evaluation thread and wait
/// for its answer; `NO_DEVICE` when the thread cannot take it.
fn ask_sleep(state: u8, work: &Sender<Work>) -> Result<SleepControl, u64>
{
    let (answer, answered) = mpsc::sync_channel(1);
    if work.send(Work::QuerySleep(state, answer)).is_err()
    {
        return Err(acpid_errors::NO_DEVICE);
    }
    answered.recv().unwrap_or(Err(acpid_errors::NO_DEVICE))
}

/// Reply to a `QUERY_SLEEP` with `control`: its derivation, its register's
/// port or address, its `SLP_TYPa` and which register it is, or the status
/// of its refusal. A derivation whose reply
/// fails, the caller gone, is deleted.
fn reply_sleep_control(control: Result<SleepControl, u64>, ipc_buf: *mut u64)
{
    let control = match control
    {
        Ok(control) => control,
        Err(status) => return reply(status, ipc_buf),
    };
    let msg = IpcMessage::builder(acpid_errors::SUCCESS)
        .word(0, control.derived.address)
        .word(1, u64::from(control.slp_typ))
        .word(2, control.derived.register)
        .cap(control.derived.cap)
        .build();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
    if unsafe { ipc::ipc_reply(&msg, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(control.derived.cap);
    }
}

/// `WAIT_EVENT`: wait until an event is pending, or a later `WAIT_EVENT`
/// supersedes this one, and reply. A delivered power-button press is
/// cleared and the button enabled again; one whose reply fails, its caller
/// gone, is posted again for the next `WAIT_EVENT`.
fn wait_event(mailbox: &Mailbox, work: &Sender<Work>, ipc_buf: *mut u64)
{
    let mut mail = mailbox.lock();
    if !mail.waitable
    {
        drop(mail);
        return reply(acpid_errors::NO_DEVICE, ipc_buf);
    }
    mail.waiter = mail.waiter.wrapping_add(1);
    let me = mail.waiter;
    mailbox.changed.notify_all();
    let events = loop
    {
        if mail.waiter != me
        {
            break 0;
        }
        if mail.pending != 0
        {
            break core::mem::take(&mut mail.pending);
        }
        mail = mailbox
            .changed
            .wait(mail)
            .unwrap_or_else(PoisonError::into_inner);
    };
    drop(mail);
    if events == 0
    {
        return reply(acpid_errors::SUPERSEDED, ipc_buf);
    }
    let msg = IpcMessage::builder(acpid_errors::SUCCESS)
        .word(0, events)
        .build();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer.
    if unsafe { ipc::ipc_reply(&msg, ipc_buf) }.is_ok()
    {
        if events & acpid_labels::EVENT_POWER_BUTTON != 0
        {
            let _ = work.send(Work::Rearm);
        }
    }
    else
    {
        mailbox.post(events);
    }
}

/// Serve the requests received on `service` for acpid's lifetime without
/// the means to act on any: each request that passes the checks of
/// [`power::decode`] is answered `NO_DEVICE`. acpid's bootstrap round
/// delivered its endpoint but no `devmgr.acpi` seed.
pub fn refuse(service: u64) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(service, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let status = power::decode(msg.label, msg.badge, msg.word(0), msg.word(1))
            .map_or_else(|code| code, |_| acpid_errors::NO_DEVICE);
        reply(status, ipc_buf);
    }
}

/// What a sleep needs of the armed events: the events, the mailbox and the
/// work channel that what fired is handed on to.
type SleepEvents<'a> = (&'a Armed, &'a Mailbox, &'a Sender<Work>);

/// Enter sleep state `state`: its `SLP_TYPa`, then `\_PTS`, then, with the
/// events `armed`, [`events::quiesce`], which hands on each event it takes,
/// then the sleep register writes (`Power::sleep`). When
/// the writes return, the events stay quiesced for [`SLEEP_GRACE`]; when the
/// platform still runs then, the GPEs are enabled again
/// ([`events::resume`]) and what latched is handed on, each event once. The
/// reply status when the platform keeps running.
fn sleep(
    state: u8,
    ns: Option<&mut Namespace>,
    platform: &mut Platform<'_>,
    power: &Power,
    armed: Option<SleepEvents<'_>>,
) -> u64
{
    let (slp_typ, ns) = match sleep_type("SLEEP", state, ns, platform, power)
    {
        Ok(found) => found,
        Err(status) => return status,
    };
    let mut ev = Evaluator::new(ns, platform);
    if let Some(fault) = power::prepare(&mut ev, state)
    {
        std::os::seraph::log!(warn: "\\_PTS({state}) faulted: {fault:?}; sleeping anyway");
    }
    let quiesced = armed.map(|(armed, mailbox, work)| {
        let (taken, quiesced) = events::quiesce(&mut *lock(&armed.regs), &armed.layout);
        deliver(&taken, mailbox, work);
        quiesced
    });
    let entered = power.sleep(state, slp_typ);
    if let (Some((armed, mailbox, work)), Some(quiesced)) = (armed, quiesced)
    {
        if entered
        {
            std::thread::sleep(SLEEP_GRACE);
            std::os::seraph::log!(
                warn: "SLEEP({state}): still running {} s after the writes; GPEs enabled again",
                SLEEP_GRACE.as_secs()
            );
        }
        let fired = events::resume(
            &mut *lock(&armed.regs),
            &armed.layout,
            &armed.handled,
            &quiesced,
        );
        deliver(&fired, mailbox, work);
    }
    if entered
    {
        acpid_errors::SUCCESS
    }
    else
    {
        acpid_errors::NO_DEVICE
    }
}

/// The `SLP_TYPa` of sleep state `state` for the request `request` (its
/// name in the log), read from its `\_Sx_` package in `ns`, and `ns`
/// back. Refused, logged, with `NO_DEVICE` when `power` holds no sleep
/// register, no AML is loaded, or the package is absent or unusable.
fn sleep_type<'n>(
    request: &str,
    state: u8,
    ns: Option<&'n mut Namespace>,
    platform: &mut Platform<'_>,
    power: &Power,
) -> Result<(u16, &'n mut Namespace), u64>
{
    if !power.can_sleep()
    {
        std::os::seraph::log!(warn: "{request}({state}) refused: no PM1a_CNT or SLEEP_CONTROL_REG");
        return Err(acpid_errors::NO_DEVICE);
    }
    let Some(ns) = ns
    else
    {
        std::os::seraph::log!(warn: "{request}({state}) refused: no AML loaded");
        return Err(acpid_errors::NO_DEVICE);
    };
    match power::sleep_type(&mut Evaluator::new(&mut *ns, platform), state)
    {
        Ok(Some(slp_typ)) => Ok((slp_typ, ns)),
        Ok(None) =>
        {
            std::os::seraph::log!(warn: "{request}({state}) refused: no \\_S{state}_ package");
            Err(acpid_errors::NO_DEVICE)
        }
        Err(why) =>
        {
            std::os::seraph::log!(
                warn: "{request}({state}) refused: \\_S{state}_ failed: {why:?}"
            );
            Err(acpid_errors::NO_DEVICE)
        }
    }
}

/// What a `QUERY_SLEEP` hands its caller: the derivation of the register
/// acpid's `SLEEP` writes, with which register it is and its port or
/// address, and the state's `SLP_TYPa`.
struct SleepControl
{
    derived: Derived,
    slp_typ: u16,
}

/// `QUERY_SLEEP` of `state`: its `SLP_TYPa`, as [`sleep`] reads it, and a
/// derivation of the sleep register `power` holds. The status to reply,
/// logged, when [`sleep_type`] refuses or the derivation fails.
fn query_sleep(
    state: u8,
    ns: Option<&mut Namespace>,
    platform: &mut Platform<'_>,
    power: &Power,
) -> Result<SleepControl, u64>
{
    let (slp_typ, _) = sleep_type("QUERY_SLEEP", state, ns, platform, power)?;
    let Some(derived) = power.derive_control()
    else
    {
        std::os::seraph::log!(warn: "QUERY_SLEEP({state}) refused: sleep register not derived");
        return Err(acpid_errors::NO_DEVICE);
    };
    let register = match derived.register
    {
        acpid_labels::SLEEP_REGISTER_PM1A_CNT => "PM1a_CNT",
        acpid_labels::SLEEP_REGISTER_CONTROL_IO => "SLEEP_CONTROL_REG port",
        _ => "SLEEP_CONTROL_REG memory",
    };
    std::os::seraph::log!(
        "QUERY_SLEEP({state}): {register} {:#x}, SLP_TYPa {slp_typ:#x}",
        derived.address
    );
    Ok(SleepControl { derived, slp_typ })
}

/// Reset through `RESET_REG`. The reply status when the platform keeps
/// running.
fn reset(power: &Power) -> u64
{
    if power.reset()
    {
        acpid_errors::SUCCESS
    }
    else
    {
        std::os::seraph::log!(warn: "RESET refused: no RESET_REG");
        acpid_errors::NO_DEVICE
    }
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}
