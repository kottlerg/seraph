// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/src/main.rs

//! Seraph system log daemon — post-mount owner of the master log
//! endpoint, launched and supervised by svcmgr.
//!
//! The bootstrap caps are specified in `services/logd/README.md`
//! § Bootstrap caps; the startup order (death-EQ registration before the
//! first `HANDOVER_PULL`) and the handover itself in
//! `services/logd/docs/handover-protocol.md` § Startup ordering and § Call
//! shape; and why logd cannot use `seraph::log!`, and so routes its own
//! diagnostics and panic output to the serial driver, in the README's
//! § Role and `docs/console-model.md`. `main` follows that order: the
//! core-path declaration (`procmgr_labels::DECLARE_NO_CORE`), bootstrap
//! caps, the panic sink, the dropped `log_send_cap`, the output drivers'
//! class watches and resolution (the serial sink a halt writes to), the
//! death EQ and its registration, the wait set, the receive pool's workers
//! (spawned behind its gate, `services/logd/docs/ipc-interface.md`
//! § Receive pool), the output sinks' writer threads ([`Sink`]), the handover
//! pull, the release of the self-log lines held until init-logd stops writing
//! the UART ([`SELF_LOG_HOLD`]), the kernel log reader's thread
//! ([`read_kernel_log`]), then the gate's opening and the control loop.

mod handover;

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use death_set::OverflowWatch;
use ipc::log_labels::{LOG_QUERY_AUTHORITY, QUERY_HISTORY, QUERY_SLOTS};
use ipc::log_query::{HistoryRequest, QUERY_DENIED, decode_slots_request, refusal};
use ipc::log_record::{RECORD_MAX_BYTES, Record};
use ipc::stream_labels::{
    LEVEL_INFO, LEVEL_WARN, NAME_UNKNOWN, RECORD_ACCEPTED, RECORD_REJECTED, STREAM_BYTES,
    STREAM_RECORD, STREAM_REGISTER_NAME, level_of, sender_named,
};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use logd_codec::hold::HeldLines;
use logd_codec::kernel::{Accept, Cursor, KERNEL_NAME, KernelLine};
use logd_codec::reclaim::{Cause, ReclaimLine};
use logd_codec::record::RENDERED_MAX_BYTES;
use logd_codec::sink::{HEADER_BYTES, Offer, Popped, SINK_QUEUE_BYTES, SINK_STALL_MS, SinkQueue};
use recv_pool::{IpcBuf, RecvPool, SpawnError};
use std::os::seraph::startup_info;
use syscall::RIGHTS_EQ_POST;

use logd_slot_table::{Eviction, History, LINE_BUF_SIZE, MAX_NAME_LEN, Slot, SlotTable};

/// `WaitSet` badge for the death-notification event queue.
const WS_BADGE_DEATH: u64 = 1;
/// `WaitSet` badge for logd's resync notification ([`RESYNC_WALK_DONE`],
/// [`RESYNC_REQUESTED`]).
const WS_BADGE_RESYNC: u64 = 2;
/// `WaitSet` badges for the serial and framebuffer class watches
/// ([`OutputDriver`]), in [`resolve_output_drivers`]'s order.
const WS_BADGE_WATCHES: [u64; 2] = [3, 4];

/// Resync-notification bit the resync helper thread signals when its walk of
/// procmgr's live badges ends.
const RESYNC_WALK_DONE: u64 = 1;
/// Resync-notification bit a death drain signals when it may have followed a
/// dropped post: the main thread then starts a [`Resync`].
const RESYNC_REQUESTED: u64 = 2;

/// Workers receiving on the master log endpoint: a concurrency setting, not
/// a capacity. Senders beyond it queue on the endpoint.
const RECV_WORKERS: usize = 4;

/// Caps real-logd receives from svcmgr's bootstrap round; an absent slot is `0`.
struct BootCaps
{
    /// RECV cap on the master log endpoint. Real-logd is now the
    /// RECV-holder; init-logd has already terminated by the time
    /// this cap is in use.
    log_ep_recv: u64,
    /// SEND cap on the master log endpoint, used only for the
    /// `HANDOVER_PULL` drain and `HANDOVER_RELEASE` rounds with
    /// init-logd. Deleted after handover.
    log_ep_handover_send: u64,
    /// `SEND|GRANT` cap on procmgr carrying `DEATH_EQ_AUTHORITY`, used to
    /// call `REGISTER_DEATH_EQ` at startup and, from the resync helper
    /// thread, `QUERY_LIVE_PROCESSES`. Kept across the lifetime of real-logd.
    procmgr_death_auth_send: u64,
    /// The `serial` class SEND (svcmgr's `devmgr.class.serial`
    /// publication). logd resolves the serial driver's write endpoint
    /// through it via `QUERY_DEVICE`. Zero disables serial output (logd
    /// then buffers received log lines in memory only).
    serial_class: u64,
    /// The `framebuffer` class SEND (svcmgr's `devmgr.class.framebuffer`
    /// publication), through which logd resolves the framebuffer driver
    /// the same way. Zero disables the framebuffer mirror.
    fb_class: u64,
    /// A `KernelLog` cap carrying `Read`, through which logd reads the
    /// kernel's console lines ([`read_kernel_log`]). Zero leaves the kernel
    /// writing its lines itself.
    kernel_log: u64,
}

fn bootstrap_caps(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    // The rounds carry only the present caps and a presence word naming the
    // slot each fills; an absent slot decodes as `0`. Only the RECV is
    // required.
    let [
        log_ep_recv,
        log_ep_handover_send,
        procmgr_death_auth_send,
        serial_class,
        fb_class,
        kernel_log,
    ] = unsafe { ipc::bootstrap::request_slots::<6>(creator_endpoint, ipc_buf) }.ok()?;
    if log_ep_recv == 0
    {
        return None;
    }
    Some(BootCaps {
        log_ep_recv,
        log_ep_handover_send,
        procmgr_death_auth_send,
        serial_class,
        fb_class,
        kernel_log,
    })
}

fn main() -> !
{
    let startup = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is registered by `_start`; reinterpret as `*mut u64`"
    )]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    // A core dump stops every thread of its process but the faulting one, and
    // every process's log output, the crash service's line of the dump's
    // outcome included, waits on logd's receive workers: declare this process
    // on the core path before it spawns a thread, so the crash service reports
    // a fault of logd and writes no core of it
    // (`procmgr_labels::DECLARE_NO_CORE`). A refusal leaves a dump of logd to
    // the policy, and the log calls the dump holds to their bound.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            startup.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_CORE),
            ipc_buf,
        )
    };

    let Some(caps) = bootstrap_caps(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // logd serves the log endpoint, so it must never emit through it. Route
    // panic / alloc-error / precondition output to the serial driver (the
    // path `self_log` already uses) via the std panic sink, and drop the
    // procmgr-seeded badged SEND so no path — panic, alloc-error, or a stray
    // `log!` — can self-IPC into the endpoint logd receives on.
    std::os::seraph::set_panic_sink(panic_to_serial);
    let _ = syscall::cap_delete(startup.log_send_cap);

    // Register the serial and framebuffer class watches and resolve both
    // drivers through devmgr first: a halt on any later step writes its
    // `FATAL` line and the held self-log lines, and the panic sink its
    // output, only to a resolved serial driver. This runs while init-logd
    // still drains the log endpoint: after the release the endpoint has no
    // reader until the receive pool's gate opens, and devmgr may then be
    // logging (`services/devmgr/docs/responsibilities.md`, the on-disk
    // settle). Until a driver is resolved its sink queues the lines, up to
    // its queue, counts those past it, and writes both to the driver resolved
    // next (`Sink::offer`), while history still accrues; the main thread
    // resolves it again when devmgr signals its class's watch.
    let watches = resolve_output_drivers(caps.serial_class, caps.fb_class, ipc_buf);

    let mut table = SlotTable::default();

    // Set up the death-notification queue + wait set and register with procmgr
    // BEFORE pulling the handover. The pull causes init-logd to exit, which
    // triggers procmgr's init-reap; that reap logs, and until logd's receive
    // workers receive there is no other reader on the log endpoint. Registering
    // here — while init's main has already exited but init-logd is still
    // serving, so procmgr is not yet reaping init — keeps logd from blocking on
    // procmgr in that window, which would deadlock against procmgr blocking on
    // the unmanned log endpoint. After the pull, logd opens the receive pool's
    // gate with no further procmgr dependency, so its workers drain the reap's
    // log line.
    let Some(death_eq) = create_death_eq()
    else
    {
        fatal("FATAL: death-EQ create failed; halting");
        syscall::thread_exit();
    };
    register_with_procmgr(caps.procmgr_death_auth_send, death_eq, ipc_buf);
    let Some(resync_note) = create_resync_note()
    else
    {
        fatal("FATAL: resync notification create failed; halting");
        syscall::thread_exit();
    };
    let Some(ws_cap) = create_wait_set(death_eq, resync_note, watches)
    else
    {
        fatal("FATAL: wait_set create failed; halting");
        syscall::thread_exit();
    };
    let logd: &'static Logd = Box::leak(Box::new(Logd {
        state: Mutex::new(LogdState {
            table: SlotTable::default(),
            deaths: OverflowWatch::new(DEATH_EQ_CAPACITY),
        }),
        death_eq,
        resync_note,
    }));

    // Spawn the receive workers now, while init-logd still serves the log
    // endpoint: each one's start in the runtime waits on procmgr, which may
    // be waiting on the log endpoint once the pull below ends
    // (`services/logd/docs/ipc-interface.md` § Receive pool). They receive
    // once the gate opens, after the pull.
    let pool = RecvPool::new(
        caps.log_ep_recv,
        recv_diag,
        move |msg: &IpcMessage, buf: IpcBuf| {
            serve_request(logd, msg, buf);
        },
    );
    match pool.spawn("logd-recv", RECV_WORKERS)
    {
        Ok(_) => (),
        Err(SpawnError { running: 0, .. }) =>
        {
            fatal("FATAL: no receive worker could be spawned; halting");
            syscall::thread_exit();
        }
        Err(SpawnError { running, .. }) =>
        {
            let mut buf = SerialFmt::new();
            let _ = write!(
                buf,
                "{running} of {RECV_WORKERS} receive workers spawned; serving with them"
            );
            self_log(buf.as_str());
        }
    }
    // The sinks' writers, spawned now for the same reason as the receive
    // workers; until each runs, its lines are written inline.
    spawn_writers();

    if caps.log_ep_handover_send != 0
    {
        // First launch, or a restart before procmgr reported init reaped:
        // pull init-logd's accrued boot history, release init-logd, then drop
        // the single-use SEND so logd carries no SEND cap to its own log
        // endpoint. Until the release, init-logd writes the UART beside this
        // logd. Every handover call is bounded, so an init-logd that exited
        // after svcmgr minted the SEND ends the transfer with nothing pulled.
        self_log("started; pulling init-logd handover state");
        // Drain, then the terminal release: init-logd exits on an acknowledged
        // release, not on the drain's DONE, so a dropped data chunk cannot
        // wedge it (and thus cannot block procmgr's reap of init's memory
        // caps).
        // SAFETY: ipc_buf is the registered IPC buffer page.
        unsafe { handover::transfer(caps.log_ep_handover_send, ipc_buf, &mut table) };
        let _ = syscall::cap_delete(caps.log_ep_handover_send);
        // Init-logd has acknowledged the release and writes no more (or no
        // release reached it, and holding longer would only lose the lines):
        // write the held self-log lines.
        open_self_log();

        let mut buf = SerialFmt::new();
        let _ = write!(
            buf,
            "handover complete: {} slots, {} history entries",
            table.slots.len(),
            table.history().len(),
        );
        self_log(buf.as_str());
    }
    else
    {
        // A restart after procmgr reported init reaped: init-logd has exited,
        // so there is no handover source (svcmgr serves `cap[1]` to every
        // restart before that). Serve a fresh table; in-flight history from
        // the prior instance is not recoverable. No init-logd writes the UART,
        // so nothing needs holding.
        open_self_log();
        self_log("started (restart); no handover source, serving fresh");
    }

    logd.lock().table = table;
    start_kernel_reader(caps.kernel_log, logd);
    pool.open();
    let mut resync = Resync::new(caps.procmgr_death_auth_send, resync_note);
    control_loop(ws_cap, logd, &mut resync, watches, ipc_buf);
}

/// The state logd's receive workers and its main thread share.
struct Logd
{
    /// The badge table and the death-drain count, under one lock: every
    /// worker's request and every drain step takes it, and none holds it
    /// across an IPC call (`services/logd/docs/ipc-interface.md` § Receive
    /// pool).
    state: Mutex<LogdState>,
    /// RECV on the death-notification `EventQueue`.
    death_eq: u64,
    /// The resync notification ([`RESYNC_WALK_DONE`], [`RESYNC_REQUESTED`]).
    resync_note: u64,
}

/// What [`Logd::state`] guards.
struct LogdState
{
    table: SlotTable,
    /// The death events taken since a take last found the queue empty, by
    /// any thread, as one thread's drain from a ready queue to an empty one
    /// would take them ([`drain_deaths`]).
    deaths: OverflowWatch,
}

impl Logd
{
    fn lock(&self) -> MutexGuard<'_, LogdState>
    {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Capacity of logd's death-notification `EventQueue`: a tuning value, not
/// a process ceiling. procmgr's post of a death is refused, and dropped,
/// when the queue is full, so a drain that takes this many events or more
/// starts a resync ([`Resync`]), which evicts the slots of senders procmgr no
/// longer lists as live; no process count sizes the queue.
const DEATH_EQ_CAPACITY: u32 = 128;

/// Allocate the slab and create the death-notification `EventQueue` of
/// [`DEATH_EQ_CAPACITY`] entries. It has no death-observer nodes: nothing
/// binds it, since procmgr posts each death to it itself
/// (`services/procmgr/docs/ipc-interface.md` § `REGISTER_DEATH_EQ`).
fn create_death_eq() -> Option<u64>
{
    // The kernel's raw EventQueue debit for that capacity and no nodes.
    let slab_bytes = std::os::seraph::event_queue_retype_bytes(u64::from(DEATH_EQ_CAPACITY), 0);
    std::os::seraph::object_slab_retype(slab_bytes, |slab| {
        syscall::event_queue_create(slab, DEATH_EQ_CAPACITY).ok()
    })
}

/// Create the notification the resync helper thread signals when its walk
/// ends.
fn create_resync_note() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
}

/// Build the main thread's wait set: the death event queue
/// (`WS_BADGE_DEATH`), the resync notification (`WS_BADGE_RESYNC`), and each
/// class watch registered (`WS_BADGE_WATCHES`; 0 for one that is not). The
/// log endpoint is the receive workers', outside the set.
fn create_wait_set(death_eq: u64, resync_note: u64, watches: [u64; 2]) -> Option<u64>
{
    // The set's member capacity: the members above.
    const WS_MEMBERS: u32 = 4;
    let Some(ws) = std::os::seraph::object_slab_retype(
        std::os::seraph::wait_set_retype_bytes(u64::from(WS_MEMBERS)),
        |slab| syscall::wait_set_create(slab, WS_MEMBERS).ok(),
    )
    else
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_create failed");
        self_log(buf.as_str());
        return None;
    };
    if let Err(e) = syscall::wait_set_add(ws, death_eq, WS_BADGE_DEATH)
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_add(death) err={e}");
        self_log(buf.as_str());
        return None;
    }
    if let Err(e) = syscall::wait_set_add(ws, resync_note, WS_BADGE_RESYNC)
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_add(resync) err={e}");
        self_log(buf.as_str());
        return None;
    }
    for (&watch, &badge) in watches.iter().zip(&WS_BADGE_WATCHES)
    {
        // A watch the set cannot hold is never waited on: its driver stays
        // as resolved at start.
        if watch != 0
            && let Err(e) = syscall::wait_set_add(ws, watch, badge)
        {
            let mut buf = SerialFmt::new();
            let _ = write!(buf, "wait_set_add(watch {badge}) err={e}");
            self_log(buf.as_str());
        }
    }
    Some(ws)
}

/// Send `REGISTER_DEATH_EQ` to procmgr.
///
/// `ipc_call` on a message carrying a cap MOVES the cap into the
/// receiver's `CSpace` and clears the sender's slot. logd needs to
/// retain `RECV` on the original event queue so `wait_set_add` and
/// `event_try_recv` keep working, so it first derives a POST-only
/// copy and transfers that. The POST right is what procmgr's
/// `SYS_EVENT_POST` of each death to the queue needs.
fn register_with_procmgr(procmgr_send: u64, death_eq: u64, ipc_buf: *mut u64)
{
    if procmgr_send == 0
    {
        self_log("REGISTER_DEATH_EQ skipped: no procmgr cap");
        return;
    }
    let Ok(post_cap) = syscall::cap_derive(death_eq, RIGHTS_EQ_POST)
    else
    {
        self_log("REGISTER_DEATH_EQ: cap_derive POST failed");
        return;
    };
    let msg = IpcMessage::builder(procmgr_labels::REGISTER_DEATH_EQ)
        .cap(post_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page; the cap
    // transfer moves `post_cap` into procmgr's CSpace.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_send, &msg, ipc_buf) })
    else
    {
        self_log("REGISTER_DEATH_EQ: IPC call failed");
        let _ = syscall::cap_delete(post_cap);
        return;
    };
    if reply.label == procmgr_errors::SUCCESS
    {
        self_log("REGISTER_DEATH_EQ: registered with procmgr");
    }
    else
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "REGISTER_DEATH_EQ: error code {}", reply.label);
        self_log(buf.as_str());
    }
}

/// The main thread's loop: drain deaths when the death queue is ready, so a
/// queue no request wakes a worker for still empties, run the [`Resync`] on
/// its notification's bits, and resolve an output driver again when devmgr
/// signals its class watch ([`OutputDriver::refresh`]; `watches` in
/// [`resolve_output_drivers`]'s order), on `ipc_buf`, the main thread's IPC
/// buffer page.
fn control_loop(
    ws_cap: u64,
    logd: &Logd,
    resync: &mut Resync,
    watches: [u64; 2],
    ipc_buf: *mut u64,
) -> !
{
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        let badge = match syscall::wait_set_wait(ws_cap)
        {
            Ok(badge) => badge,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        match badge
        {
            WS_BADGE_DEATH => drain_deaths(logd),
            WS_BADGE_RESYNC =>
            {
                // Take and clear the signalled bits: the wait set reports the
                // notification ready while any are set. The wake means they
                // are, so this returns at once.
                let bits = syscall::notification_wait_timeout(logd.resync_note, 1).unwrap_or(0);
                if bits & RESYNC_WALK_DONE != 0
                {
                    resync.finish(logd);
                }
                if bits & RESYNC_REQUESTED != 0
                {
                    resync.start(logd);
                }
            }
            badge =>
            {
                for ((output, &watch), &watch_badge) in [&SERIAL.driver, &FB.driver]
                    .into_iter()
                    .zip(&watches)
                    .zip(&WS_BADGE_WATCHES)
                {
                    if badge == watch_badge
                    {
                        // Take and clear the bits, as for the resync
                        // notification above.
                        let _ = syscall::notification_wait_timeout(watch, 1);
                        output.refresh(ipc_buf);
                    }
                }
            }
        }
    }
}

/// logd's death-queue resync (`services/logd/docs/ipc-interface.md`
/// § Death-queue resync): after a drain that may have followed a full queue,
/// evict the slots of children procmgr no longer lists as live.
///
/// The main thread owns it. The walk of procmgr's live badges
/// (`QUERY_LIVE_PROCESSES`) runs on a helper thread, which sends its result
/// over a channel and signals [`RESYNC_WALK_DONE`]; the main thread then
/// evicts from the snapshot it took before the walk began. Why neither the
/// main thread nor a receive worker calls procmgr is
/// `services/logd/docs/ipc-interface.md` § Death-queue resync.
struct Resync
{
    /// `DEATH_EQ_AUTHORITY` SEND on procmgr the helper walks through; zero
    /// disables resync.
    procmgr_send: u64,
    /// Notification in the wait set the helper signals when it is done.
    note: u64,
    /// The walk in flight: the slot snapshot taken before it began and the
    /// channel its live list arrives on (`None` when the walk failed).
    in_flight: Option<(Vec<u64>, LiveReceiver)>,
    /// Whether a walk runs now or is due after the current one.
    gate: logd_codec::resync::WalkGate,
}

/// The channel the resync helper sends its walk's live badges on; `None`
/// when the walk failed.
type LiveReceiver = std::sync::mpsc::Receiver<Option<Vec<u64>>>;

impl Resync
{
    fn new(procmgr_send: u64, note: u64) -> Self
    {
        Self {
            procmgr_send,
            note,
            in_flight: None,
            gate: logd_codec::resync::WalkGate::new(),
        }
    }

    /// Ask for a resync: start the helper's walk now, or, with one already
    /// in flight, mark another due, which [`Self::finish`] starts once the
    /// current walk ends.
    fn start(&mut self, logd: &Logd)
    {
        if self.procmgr_send != 0 && self.gate.request()
        {
            self.begin(logd);
        }
    }

    /// Snapshot the child slots and spawn the helper's walk; the gate has
    /// already counted it in flight, and is told when it cannot begin.
    fn begin(&mut self, logd: &Logd)
    {
        let mut snapshot: Vec<u64> = Vec::new();
        let reserved = {
            let state = logd.lock();
            let reserved = snapshot.try_reserve(state.table.slots.len()).is_ok();
            if reserved
            {
                snapshot.extend(
                    state
                        .table
                        .slots
                        .keys()
                        .copied()
                        .filter(|&b| logd_codec::resync::is_resync_candidate(b)),
                );
            }
            reserved
        };
        if !reserved
        {
            self_log("resync skipped: no memory for the slot snapshot");
            self.gate.abandon();
            return;
        }
        snapshot.sort_unstable();
        let (tx, rx) = std::sync::mpsc::channel();
        let (procmgr_send, note) = (self.procmgr_send, self.note);
        let spawned = std::thread::Builder::new().spawn(move || {
            let _ = tx.send(walk_live_processes(procmgr_send));
            let _ = syscall::notification_send(note, RESYNC_WALK_DONE);
        });
        if spawned.is_ok()
        {
            self.in_flight = Some((snapshot, rx));
        }
        else
        {
            self_log("resync skipped: helper thread spawn failed");
            self.gate.abandon();
        }
    }

    /// On the helper's signal, once its result is in, evict every snapshot
    /// slot the walk did not list, then start the walk a drain marked due
    /// meanwhile.
    fn finish(&mut self, logd: &Logd)
    {
        let Some((snapshot, rx)) = self.in_flight.take()
        else
        {
            return;
        };
        let live = match rx.try_recv()
        {
            Ok(live) => live,
            Err(std::sync::mpsc::TryRecvError::Empty) =>
            {
                // Signalled before the result landed; wait for the next one.
                self.in_flight = Some((snapshot, rx));
                return;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
        };
        match live
        {
            Some(live) => evict_missing(&snapshot, &live, logd),
            None => self_log("resync: live-process walk failed; slots kept"),
        }
        if self.gate.finished()
        {
            self.begin(logd);
        }
    }
}

/// Evict every `snapshot` slot whose badge the walk's ascending `live` list
/// lacks, logging each reclaim line once the lock is released.
fn evict_missing(snapshot: &[u64], live: &[u64], logd: &Logd)
{
    for badge in logd_codec::resync::evictable(snapshot, live)
    {
        let evicted = logd
            .lock()
            .table
            .retire(badge, Eviction::Resync)
            .map(|slot| slot.name.clone());
        if let Some(name) = evicted
        {
            log_reclaim(badge, Cause::Resync, &name);
        }
    }
}

/// Log the reclaim line for the evicted slot of `badge`, named `name`, as a
/// record (`logd_codec::reclaim`), so the name cannot read as a further
/// field.
fn log_reclaim(badge: u64, cause: Cause, name: &[u8])
{
    let w = ReclaimLine { badge, cause, name }.record();
    // A record `RecordWriter` built decodes.
    if let Ok(record) = Record::decode(w.as_bytes())
    {
        let mut out = LineBuf::new();
        out.push_prefix(b"logd", LEVEL_INFO);
        logd_codec::record::render(&record, |b| out.push(b));
        out.push(b'\r');
        out.push(b'\n');
        out.flush();
    }
}

/// Walk procmgr's live badges (`QUERY_LIVE_PROCESSES`) page by page on the
/// calling thread's IPC buffer; runs on the resync helper thread only.
/// `None` when a call fails or a reply does not decode.
fn walk_live_processes(procmgr_send: u64) -> Option<Vec<u64>>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return None;
    }
    let mut live: Vec<u64> = Vec::new();
    let mut after: Option<u64> = None;
    loop
    {
        let msg = IpcMessage::builder(procmgr_labels::QUERY_LIVE_PROCESSES)
            .word(0, u64::from(after.is_some()))
            .word(1, after.unwrap_or(0))
            .build();
        // SAFETY: ipc_buf is this thread's registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(procmgr_send, &msg, ipc_buf) }.ok()?;
        let (page, more) = logd_codec::resync::decode_live_page(&reply, after)?;
        live.try_reserve(page.len()).ok()?;
        live.extend_from_slice(page);
        if !more
        {
            return Some(live);
        }
        after = live.last().copied();
    }
}

/// `RecvGuard` diagnostic hook. logd cannot log through its own IPC
/// endpoint, so this writes via the serial self-log path.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    let mut buf = SerialFmt::new();
    let _ = match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            write!(buf, "recv loop failing (err={err}); backing off")
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            write!(buf, "recv loop wedged (err={err}); exiting")
        }
    };
    self_log(buf.as_str());
}

/// Non-blocking drain of the death event queue, run by a receive worker
/// before each request and by the main thread when the queue is ready. Each
/// death event procmgr posts carries the exit reason and the dead process's
/// full badge as the correlator (`syscall::DeathEvent`); the drain evicts the
/// slot of exactly that badge.
///
/// Each take is made under the state lock, with its eviction, and the reclaim
/// line is written after the lock is released. [`LogdState::deaths`] counts
/// the takes since one last found the queue empty, whichever thread made them
/// (`death_set::OverflowWatch`). When it reaches a full queue's worth, the
/// queue may have filled, and a post to a full queue is dropped, so the drain
/// asks the main thread for a [`Resync`] ([`RESYNC_REQUESTED`]) and counts
/// again from zero.
fn drain_deaths(logd: &Logd)
{
    loop
    {
        let (badge, exit_reason, evicted, full) = {
            let mut state = logd.lock();
            let Ok(death) = syscall::event_try_recv_death(logd.death_eq)
            else
            {
                state.deaths.found_empty();
                return;
            };
            let full = state.deaths.took();
            let exit_reason = death.exit_reason;
            let evicted = state
                .table
                .retire(death.correlator, Eviction::Death { exit_reason })
                .map(|slot| slot.name.clone());
            drop(state);
            (death.correlator, exit_reason, evicted, full)
        };
        if let Some(name) = evicted
        {
            log_reclaim(badge, Cause::Death { exit_reason }, &name);
        }
        if full
        {
            let mut buf = SerialFmt::new();
            let _ = write!(
                buf,
                "death queue gave up {DEATH_EQ_CAPACITY} events (its capacity) since it was last \
                 empty; resyncing"
            );
            self_log(buf.as_str());
            let _ = syscall::notification_send(logd.resync_note, RESYNC_REQUESTED);
        }
    }
}

/// The receive workers' handler (`services/logd/docs/ipc-interface.md`
/// § Receive pool): drain the death queue, then serve `msg` and reply on
/// `buf`, the worker's own IPC buffer page.
fn serve_request(logd: &Logd, msg: &IpcMessage, buf: IpcBuf)
{
    drain_deaths(logd);
    let ipc_buf = buf.as_ptr();
    let label_id = msg.label & 0xFFFF;
    let byte_len = ((msg.label >> 16) & 0xFFFF) as usize;
    if label_id == STREAM_BYTES
    {
        let status = consume_bytes(logd, msg.badge, msg, byte_len);
        // SAFETY: ipc_buf is this worker's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(status), ipc_buf) };
    }
    else if label_id == STREAM_RECORD
    {
        let status = consume_record(logd, msg.badge, msg, byte_len);
        // SAFETY: ipc_buf is this worker's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(status), ipc_buf) };
    }
    else if label_id == STREAM_REGISTER_NAME
    {
        register_name(logd, msg.badge, msg, byte_len);
        reply_ack(ipc_buf);
    }
    else if label_id == QUERY_SLOTS || label_id == QUERY_HISTORY
    {
        let reply = answer_query(&logd.lock().table, msg);
        // SAFETY: ipc_buf is this worker's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
    else
    {
        // Unknown / legacy label (e.g. GET_LOG_CAP from a hypothetical
        // pre-pivot caller). Reply empty so the sender unblocks.
        reply_ack(ipc_buf);
    }
}

/// Answer a `QUERY_SLOTS` or `QUERY_HISTORY` request from the slot table
/// and history logd owns (`services/logd/docs/ipc-interface.md` § Queries),
/// under the state lock the caller holds. It reads only that state and calls
/// no other service, so a query never waits on one. `QUERY_DENIED` for a badge
/// without `LOG_QUERY_AUTHORITY`.
fn answer_query(table: &SlotTable, msg: &IpcMessage) -> IpcMessage
{
    if msg.badge & LOG_QUERY_AUTHORITY == 0
    {
        return refusal(QUERY_DENIED);
    }
    if msg.label & 0xFFFF == QUERY_SLOTS
    {
        match decode_slots_request(msg)
        {
            Ok(after) =>
            {
                let (page, more) = logd_codec::query::slot_page(|| table.slot_rows(), after);
                page.reply(more)
            }
            Err(status) => refusal(status),
        }
    }
    else
    {
        match HistoryRequest::decode(msg)
        {
            Ok(req) =>
            {
                let (page, more) = logd_codec::query::history_page(|| table.history_views(), &req);
                page.reply(more)
            }
            Err(status) => refusal(status),
        }
    }
}

fn reply_ack(ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the calling worker's registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(0), ipc_buf) };
}

/// Append `byte_len` bytes from the IPC payload onto the slot for
/// `badge`, flushing complete lines (`\n`-terminated) to the serial
/// port AND retaining them in logd's history. A line takes
/// the level of the message carrying its first byte
/// ([`Slot::begin_byte`]).
///
/// Accepts up to `STREAM_CHUNK_SIZE = MSG_DATA_WORDS_MAX * 8` bytes
/// per call (the maximum a single `STREAM_BYTES` IPC can carry); the
/// per-line buffer is `LINE_BUF_SIZE` and force-flushes when full,
/// so a chunk longer than `LINE_BUF_SIZE` produces multiple emitted
/// lines rather than truncated output (matches init-logd's behaviour).
///
/// Each line is completed, rendered, and retained under the state lock, and
/// written once the lock is released; the bytes after it are taken under the
/// lock again.
///
/// Returns the reply label: 0, or `NAME_UNKNOWN` for a message that carries
/// `SENDER_NAMED` from a sender whose name logd does not hold
/// ([`SlotTable::name_lost`]), of which nothing is consumed, so its sender
/// registers the name and sends the message again
/// (`services/logd/docs/ipc-interface.md` § `stream_labels::STREAM_REGISTER_NAME`).
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` and the `history` borrow through the guard to the end of the \
              byte loop: the hold serialises the slot's partial line and the history"
)]
fn consume_bytes(logd: &Logd, badge: u64, msg: &IpcMessage, byte_len: usize) -> u64
{
    const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

    if sender_named(msg.label) && logd.lock().table.name_lost(badge)
    {
        return NAME_UNKNOWN;
    }
    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(STREAM_CHUNK_SIZE);
    let level = level_of(msg.label);
    let mut rest = bytes.get(..n).unwrap_or_default();
    while !rest.is_empty()
    {
        let mut out = LineBuf::new();
        let line_done = {
            let mut state = logd.lock();
            let Some((slot, history)) = state.table.sender_slot(badge)
            else
            {
                // An evicted sender's message (`SlotTable::sender_slot`):
                // dropped, and answered as consumed.
                return 0;
            };
            let mut done = false;
            while let Some((&b, tail)) = rest.split_first()
            {
                rest = tail;
                slot.begin_byte(level);
                if b == b'\n'
                {
                    flush_partial(slot, history, badge, &mut out);
                    done = true;
                    break;
                }
                if slot.partial.len() < LINE_BUF_SIZE
                {
                    slot.partial.push(b);
                    if slot.partial.len() == LINE_BUF_SIZE
                    {
                        flush_partial(slot, history, badge, &mut out);
                        done = true;
                        break;
                    }
                }
            }
            done
        };
        if line_done
        {
            out.flush();
        }
    }
    0
}

/// Render one `STREAM_RECORD` message's record as one line and retain it in
/// the slot's history, with its field table, under the state lock, then write
/// the line. The record does not touch the slot's partial text line. Returns
/// the reply label: `RECORD_ACCEPTED`, or `RECORD_REJECTED` for a payload
/// longer than a record or than the message, or one `ipc::log_record` refuses,
/// which is neither rendered nor retained, or `NAME_UNKNOWN` for a record
/// that carries `SENDER_NAMED` from a sender whose name logd does not hold,
/// neither rendered nor retained either, as [`consume_bytes`] answers.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` and the `history` borrow through the guard to the record's \
              retention: the hold serialises the slot's name and the history"
)]
fn consume_record(logd: &Logd, badge: u64, msg: &IpcMessage, byte_len: usize) -> u64
{
    let bytes = msg.data_bytes();
    if byte_len > RECORD_MAX_BYTES || byte_len > bytes.len()
    {
        return RECORD_REJECTED;
    }
    let Some(Ok(record)) = bytes.get(..byte_len).map(Record::decode)
    else
    {
        return RECORD_REJECTED;
    };
    let level = level_of(msg.label);
    let mut out = LineBuf::new();
    {
        let mut state = logd.lock();
        if sender_named(msg.label) && state.table.name_lost(badge)
        {
            return NAME_UNKNOWN;
        }
        let Some((slot, history)) = state.table.sender_slot(badge)
        else
        {
            // An evicted sender's record (`SlotTable::sender_slot`): dropped,
            // and answered as consumed, since nothing is wrong with it.
            return RECORD_ACCEPTED;
        };
        let us = elapsed_us();
        out.push_prefix_at(&slot.name, level, us);
        logd_codec::record::render(&record, |b| out.push(b));
        out.push(b'\r');
        out.push(b'\n');
        history.push_record(slot, badge, us, level, &record);
    }
    out.flush();
    RECORD_ACCEPTED
}

/// Render the in-progress line of `slot`, the slot of sender `badge`, into
/// `out`, retain it in `history`, and clear the partial buffer.
fn flush_partial(slot: &mut Slot, history: &mut History, badge: u64, out: &mut LineBuf)
{
    let line = std::mem::take(&mut slot.partial);
    let level = slot.partial_level;
    let us = elapsed_us();
    out.push_text_line(&slot.name, level, us, &line);
    history.push_text(slot, badge, us, level, &line);
}

/// Bytes of one kernel log read: several records of the longest line, within
/// `KLOG_READ_MAX`.
const KERNEL_READ_BYTES: usize = 4096;

/// The bit the kernel signals the kernel log reader's notification with.
const KERNEL_LOG_BIT: u64 = 1;

/// Name the kernel's slot `kernel`: it holds the kernel's lines init-logd
/// kept and those read from here on. Then start the kernel log reader's
/// thread ([`read_kernel_log`]) through `cap`, a `KernelLog` cap carrying
/// `Read`, with a notification bound as the kernel log's. With no cap, or
/// when the notification, the binding or the thread cannot be had, say so;
/// the kernel then writes its lines itself once the records init-logd left
/// unread stall (`KLOG_STALL_MS`).
fn start_kernel_reader(cap: u64, logd: &'static Logd)
{
    logd.lock()
        .table
        .install_from_handover(ipc::log_badges::LOG_BADGE_KERNEL, KERNEL_NAME);
    if cap == 0
    {
        self_log("no KernelLog capability; the kernel writes its own lines");
        return;
    }
    let Some(ntf) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
    else
    {
        self_log("kernel log notification not created; the kernel writes its own lines");
        return;
    };
    if syscall::kernel_log_bind(cap, ntf, KERNEL_LOG_BIT).is_err()
    {
        let _ = syscall::cap_delete(ntf);
        self_log("kernel log not bound; the kernel writes its own lines");
        return;
    }
    let spawned = std::thread::Builder::new().spawn(move || read_kernel_log(cap, ntf, logd));
    if spawned.is_err()
    {
        // The notification's deletion clears the binding.
        let _ = syscall::cap_delete(ntf);
        self_log("kernel log reader spawn failed; the kernel writes its own lines");
    }
}

/// The kernel log reader (`docs/console-model.md` item 4): read the records
/// the kernel appended, write each as a `[kernel]` line through the sinks
/// as a sender's line is written, and keep it in the kernel's slot
/// (`LOG_BADGE_KERNEL`); then wait for the kernel's signal. Each read
/// acknowledges the records written before it, so a record is acknowledged
/// once its line is written or its sink stalled. A failed read ends the
/// thread, and the kernel writes its lines itself once the records stall.
fn read_kernel_log(cap: u64, ntf: u64, logd: &Logd)
{
    let mut buf = std::vec![0u8; KERNEL_READ_BYTES];
    let mut cursor = Cursor::new();
    loop
    {
        match syscall::kernel_log_read(cap, 0, cursor.ack(), &mut buf)
        {
            Ok(0) =>
            {
                // An append after this read signals the notification at the
                // next tick, so a wait begun after it still wakes.
                let _ = syscall::notification_wait(ntf);
            }
            Ok(n) =>
            {
                for record in syscall_abi::kernel_log_records(buf.get(..n).unwrap_or_default())
                {
                    write_kernel_record(&record, &mut cursor, logd);
                }
            }
            Err(e) =>
            {
                let mut text = SerialFmt::new();
                let _ = write!(
                    text,
                    "kernel log read failed ({e}); the kernel writes its own lines"
                );
                self_log(text.as_str());
                let _ = syscall::cap_delete(ntf);
                return;
            }
        }
    }
}

/// Write `record` as the kernel's line, stamped with its own time, in parts
/// of at most `LINE_BUF_SIZE` bytes, each kept in the kernel's slot and
/// written whole; a gap before it is named in a warning line of logd's.
fn write_kernel_record(record: &syscall_abi::KernelLogRecord<'_>, cursor: &mut Cursor, logd: &Logd)
{
    match cursor.accept(record.seq)
    {
        Accept::Stale => return,
        Accept::InOrder =>
        {}
        Accept::AfterGap { first, last } =>
        {
            let text = logd_codec::kernel::gap_text(first, last);
            let mut out = LineBuf::new();
            out.push_text_line(b"logd", LEVEL_WARN, elapsed_us(), text.as_str().as_bytes());
            out.flush();
        }
    }
    let level = logd_codec::kernel::level(record.level);
    let line = KernelLine::new(record);
    for part in line.parts()
    {
        let mut out = LineBuf::new();
        out.push_text_line(KERNEL_NAME, level, record.us, part);
        keep_kernel_line(logd, record.us, level, part);
        out.flush();
    }
}

/// Keep one kernel line in the kernel's slot.
fn keep_kernel_line(logd: &Logd, us: u64, level: u64, part: &[u8])
{
    let badge = ipc::log_badges::LOG_BADGE_KERNEL;
    let mut state = logd.lock();
    // The kernel's badge is no process's, so no eviction takes it and the
    // slot is always there (`SlotTable::sender_slot`).
    if let Some((slot, history)) = state.table.sender_slot(badge)
    {
        history.push_text(slot, badge, us, level, part);
    }
}

/// Record / update the display name for `badge`. History entries carry
/// no name, only the badge (`QUERY_HISTORY`), so a rename changes the
/// slot's one current name (`QUERY_SLOTS`), which every line of the
/// sender then renders under, earlier ones included.
/// Long names truncated. No collision-suffix policy (procmgr's
/// process badge is unique, so name collisions only happen if two
/// processes intentionally pick the same display name).
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` borrows through the guard to the name's last write: the hold \
              serialises the slot's name"
)]
fn register_name(logd: &Logd, badge: u64, msg: &IpcMessage, byte_len: usize)
{
    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(MAX_NAME_LEN);
    let name = logd_codec::kernel::stored_name(bytes.get(..n).unwrap_or_default());
    let mut state = logd.lock();
    let Some((slot, _)) = state.table.sender_slot(badge)
    else
    {
        // An evicted sender's name (`SlotTable::sender_slot`).
        return;
    };
    slot.name.clear();
    slot.name.extend_from_slice(name);
}

// ── Serial output (driver-mediated) ────────────────────────────────────────

/// An output driver logd writes through, resolved through devmgr: its class
/// SEND and the driver's SEND. Only the main thread resolves
/// ([`Self::start`] before the handover pull, then [`Self::refresh`] from
/// [`control_loop`] when devmgr signals the class's `WATCH_CLASS` watch);
/// the emit path only reads [`Self::cap`], so no receive worker waits on
/// devmgr. A worker blocked on devmgr's reply while devmgr's control thread
/// waits on a log call that worker would serve could deadlock the two: a
/// query devmgr receives during a bind pass, whose answer would name no
/// driver, waits for the pass's settle.
struct OutputDriver
{
    /// The class SEND on devmgr's registry endpoint; 0 when the bootstrap
    /// carried none.
    class: AtomicU64,
    /// The SEND on the driver's service endpoint; 0 while none is resolved,
    /// and the sink then queues its lines for the driver resolved next
    /// ([`Sink::offer`]).
    cap: AtomicU64,
    /// The driver's instance ordinal in its class, while `cap` is nonzero.
    /// Only the main thread reads it.
    ordinal: AtomicU64,
    /// Taken around the writer's look at `cap` and its wait, and by
    /// [`Self::resolve`] before it signals [`Self::served`], so a driver
    /// resolved between the look and the wait is not missed.
    serving: Mutex<()>,
    /// Signalled when [`Self::resolve`] has stored a driver.
    served: Condvar,
}

impl OutputDriver
{
    const fn new() -> Self
    {
        Self {
            class: AtomicU64::new(0),
            cap: AtomicU64::new(0),
            ordinal: AtomicU64::new(0),
            serving: Mutex::new(()),
            served: Condvar::new(),
        }
    }

    /// The driver's SEND, or 0 while none is resolved.
    fn cap(&self) -> u64
    {
        self.cap.load(Ordering::Acquire)
    }

    /// The class SEND the bootstrap carried; 0 when it carried none, and no
    /// driver of the class is ever resolved.
    fn class(&self) -> u64
    {
        self.class.load(Ordering::Acquire)
    }

    /// The driver's SEND, waiting while none is resolved: the writer's wait
    /// for a driver to write its next line to.
    fn await_cap(&self) -> u64
    {
        let mut serving = self.serving.lock().unwrap_or_else(PoisonError::into_inner);
        loop
        {
            let cap = self.cap();
            if cap != 0
            {
                return cap;
            }
            serving = self
                .served
                .wait(serving)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Record `class`, register the class watch, then resolve the driver,
    /// so a change after the resolution signals the watch. Returns the
    /// watch's Notification for the main thread's wait set; 0 when none is
    /// registered (devmgr refused it, logged).
    fn start(&self, class: u64, what: &str, ipc_buf: *mut u64) -> u64
    {
        self.class.store(class, Ordering::Release);
        if class == 0
        {
            return 0;
        }
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        let watch = match unsafe { ipc::watch_class(class, ipc_buf) }
        {
            Ok(watch) => watch.note,
            Err(e) =>
            {
                let mut buf = SerialFmt::new();
                let _ = write!(buf, "{what} class watch refused ({e:?}); resolved once");
                self_log(buf.as_str());
                0
            }
        };
        self.resolve(0, ipc_buf);
        watch
    }

    /// The class watch signalled: ask devmgr whether the held driver's
    /// ordinal is still served, and resolve again from the next ordinal when
    /// devmgr answers `WITHDRAWN`, or from ordinal 0 when none is held.
    /// devmgr's answer decides, not the held SEND: devmgr signals a
    /// withdrawal in the hold that leaves the tombstone, before it revokes
    /// the driver's endpoint, so the SEND can still be valid here.
    fn refresh(&self, ipc_buf: *mut u64)
    {
        let class = self.class.load(Ordering::Acquire);
        if self.cap() == 0
        {
            self.resolve(0, ipc_buf);
            return;
        }
        let ordinal = self.ordinal.load(Ordering::Relaxed);
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        match unsafe { ipc::query_device(class, ordinal, ipc_buf) }
        {
            Ok(copy) =>
            {
                // Still served: keep the held SEND.
                let _ = syscall::cap_delete(copy);
            }
            Err(ipc::ClassCallError::Refused(ipc::devmgr_errors::WITHDRAWN)) =>
            {
                self.resolve(ordinal.saturating_add(1), ipc_buf);
            }
            // devmgr refused or did not answer: keep what is held until the
            // next signal.
            Err(_) =>
            {}
        }
    }

    /// Resolve the class's first live driver from ordinal `start`
    /// (`ipc::first_device_from`), or none, and delete the SEND it replaces.
    /// A replaced SEND that devmgr has revoked is already gone; one an emit
    /// thread still holds fails that thread's call on the slot's generation.
    fn resolve(&self, start: u64, ipc_buf: *mut u64)
    {
        let class = self.class.load(Ordering::Acquire);
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        let (ordinal, cap) =
            unsafe { ipc::first_device_from(class, start, ipc_buf) }.unwrap_or((0, 0));
        self.ordinal.store(ordinal, Ordering::Relaxed);
        let old = self.cap.swap(cap, Ordering::AcqRel);
        if old != 0
        {
            let _ = syscall::cap_delete(old);
        }
        if cap != 0
        {
            // A writer that looked at `cap` before the store waits under the
            // lock, so taking it here orders this signal after its wait began.
            drop(self.serving.lock().unwrap_or_else(PoisonError::into_inner));
            self.served.notify_all();
        }
    }
}

// A sink's queue holds two of the longest rendered lines with their headers,
// so no line logd renders is dropped for its length alone
// (`SinkQueue::offer`), and the writer can hold one while a producer queues
// the next.
const _: () = assert!(SINK_QUEUE_BYTES >= 2 * (LINE_OUT_BYTES + HEADER_BYTES));

/// An output driver and the path every rendered line takes to it: the queue
/// its writer thread drains ([`Sink::run_writer`]), the only thread that
/// calls the driver once it runs, so a driver that is slow, stopped by a
/// debugger, or dead holds that thread alone, and a line's producer for at
/// most [`SINK_STALL_MS`] (`services/logd/docs/ipc-interface.md` § Output
/// sinks).
struct Sink
{
    /// The driver, as resolved through devmgr.
    driver: OutputDriver,
    /// The driver's write opcode (`SERIAL_WRITE_BYTES`, `FB_WRITE_BYTES`).
    op: u64,
    /// The sink's name in logd's lines about it.
    what: &'static str,
    /// Lines waiting for the writer.
    queue: Mutex<SinkQueue<SINK_QUEUE_BYTES>>,
    /// Signalled when a line is queued or the tail's drop count grows.
    queued: Condvar,
    /// Signalled when the writer takes a line, freeing space, and when it
    /// completes a write.
    progress: Condvar,
    /// Whether the writer thread runs; until it does, or when it could not be
    /// spawned, a line is written by its producer ([`Self::write_inline`]).
    writer: AtomicBool,
    /// Whether a producer is writing a line inline, so a line longer than
    /// one call is not split by another thread's. A flag, not a lock held
    /// across the calls: a producer waits for it, and makes its calls, only
    /// until its line's deadline. The panic sink does not take it
    /// ([`panic_to_serial`]).
    inline_busy: Mutex<bool>,
    /// Signalled when an inline write ends and [`Self::inline_busy`] clears.
    inline_free: Condvar,
    /// Lines an inline write did not write whole by its deadline, reported
    /// ahead of the next line an inline write starts.
    inline_dropped: AtomicU32,
}

/// What [`Sink::take_next`] found for the writer.
enum Taken
{
    /// A line, in the writer's buffer.
    Line(Popped),
    /// Lines dropped after every queued one, now written.
    Drops(u32),
}

/// [`SINK_STALL_MS`] from now: the end of one sink's share of a line's
/// producer's time.
fn stall_deadline() -> Instant
{
    let now = Instant::now();
    now.checked_add(Duration::from_millis(u64::from(SINK_STALL_MS)))
        .unwrap_or(now)
}

impl Sink
{
    #[expect(
        clippy::large_stack_frames,
        reason = "evaluated only at compile time, to initialise the SERIAL and FB statics; no \
                  runtime frame holds the queue"
    )]
    const fn new(op: u64, what: &'static str) -> Self
    {
        Self {
            driver: OutputDriver::new(),
            op,
            what,
            queue: Mutex::new(SinkQueue::new()),
            queued: Condvar::new(),
            progress: Condvar::new(),
            writer: AtomicBool::new(false),
            inline_busy: Mutex::new(false),
            inline_free: Condvar::new(),
            inline_dropped: AtomicU32::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SinkQueue<SINK_QUEUE_BYTES>>
    {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hand `line` to the sink: queue it for the writer, waiting while the
    /// queue is full and the writer frees space until `deadline` at most, or
    /// drop it, counted, once the sink is stalled
    /// ([`logd_codec::sink::SinkQueue::offer`]). While no driver is resolved
    /// the sink is unserved: the line is queued for the driver resolved next
    /// without a wait, or dropped and counted when the queue is full
    /// ([`logd_codec::sink::SinkQueue::offer_unserved`]), so a driver that
    /// comes up late, or a restarted one, is written the lines its absence
    /// held back, then their count. The line's number when it is queued to a
    /// served sink that is not stalled, for [`Self::await_written`]; `None`
    /// otherwise. Written here by [`Self::write_inline`], by `deadline`,
    /// while no writer runs. Dropped uncounted when the bootstrap carried no
    /// class SEND, so no driver can ever be resolved.
    fn offer(&self, line: &[u8], deadline: Instant) -> Option<u64>
    {
        if self.driver.class() == 0
        {
            return None;
        }
        if !self.writer.load(Ordering::Acquire)
        {
            self.write_inline(line, deadline);
            return None;
        }
        let mut queue = self.lock();
        loop
        {
            let unserved = self.driver.cap() == 0;
            let left = deadline.saturating_duration_since(Instant::now());
            let offered = if unserved
            {
                queue.offer_unserved(line)
            }
            else
            {
                queue.offer(line, left.is_zero())
            };
            match offered
            {
                Offer::Queued(number) =>
                {
                    let stalled = queue.is_stalled();
                    drop(queue);
                    self.queued.notify_one();
                    return (!stalled && !unserved).then_some(number);
                }
                Offer::Dropped =>
                {
                    drop(queue);
                    // The writer reports the count once its queue drains.
                    self.queued.notify_one();
                    return None;
                }
                Offer::Wait =>
                {
                    queue = self
                        .progress
                        .wait_timeout(queue, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
    }

    /// Wait until the writer has written line `queued` ([`Self::offer`]), the
    /// sink is stalled, or `deadline` passes, which stalls the sink.
    fn await_written(&self, queued: Option<u64>, deadline: Instant)
    {
        let Some(number) = queued
        else
        {
            return;
        };
        let mut queue = self.lock();
        loop
        {
            if queue.is_written(number) || queue.is_stalled()
            {
                return;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero()
            {
                queue.stall();
                return;
            }
            queue = self
                .progress
                .wait_timeout(queue, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Write `line` to the driver from the calling thread, with no other
    /// inline write between its calls ([`Self::inline_busy`]): the wait for
    /// that turn and every call end by `deadline`, so the caller waits on
    /// the sink for [`SINK_STALL_MS`] at most. A line not written whole by
    /// then is counted, and the count is written ahead of the next line an
    /// inline write starts. A line with no driver resolved to write it to is
    /// counted the same way.
    fn write_inline(&self, line: &[u8], deadline: Instant)
    {
        let ipc_buf = emit_ipc_buf();
        let cap = self.driver.cap();
        if ipc_buf.is_null() || cap == 0
        {
            self.inline_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        {
            let mut busy = self
                .inline_busy
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            while *busy
            {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero()
                {
                    self.inline_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                busy = self
                    .inline_free
                    .wait_timeout(busy, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
            *busy = true;
        }
        let mut lost = 0u32;
        let dropped = self.inline_dropped.swap(0, Ordering::Relaxed);
        if dropped > 0
        {
            let report = self.drop_report(dropped);
            if !write_chunks_by(cap, self.op, report.bytes(), ipc_buf, deadline)
            {
                lost = dropped;
            }
        }
        if lost > 0 || !write_chunks_by(cap, self.op, line, ipc_buf, deadline)
        {
            lost = lost.saturating_add(1);
        }
        if lost > 0
        {
            self.inline_dropped.fetch_add(lost, Ordering::Relaxed);
        }
        *self
            .inline_busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = false;
        self.inline_free.notify_one();
    }

    /// Wait for the next line, taken into `buf`, or for drops after every
    /// queued line; wake producers waiting for the space a line frees.
    fn take_next(&self, buf: &mut [u8]) -> Taken
    {
        let mut queue = self.lock();
        loop
        {
            if let Some(popped) = queue.pop(buf)
            {
                drop(queue);
                self.progress.notify_all();
                return Taken::Line(popped);
            }
            let dropped = queue.take_tail_drops();
            if dropped > 0
            {
                return Taken::Drops(dropped);
            }
            queue = self
                .queued
                .wait(queue)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The writer thread: take each line in order and write it to the driver
    /// with calls that have no bound, so a line is written once, when the
    /// driver answers, however long it is stopped; report lines the sink
    /// dropped where they were dropped ([`Self::report_drops`]). While no
    /// driver is resolved it waits for one with the line it took, so the lines
    /// queued meanwhile are written to the next driver resolved. A call that
    /// fails ends the line, and the next line goes to the driver resolved
    /// then; a call to a dead driver fails only once devmgr withdraws
    /// it and revokes its endpoint. Each completed
    /// write releases the producers waiting for it and ends a stall.
    /// `other` is the sink the drop reports are also written to.
    fn run_writer(&self, other: &Sink) -> !
    {
        let ipc_buf = emit_ipc_buf();
        let mut out = LineBuf::new();
        loop
        {
            match self.take_next(&mut out.buf)
            {
                Taken::Line(popped) =>
                {
                    if popped.dropped_before > 0
                    {
                        self.report_drops(popped.dropped_before, other, ipc_buf);
                    }
                    self.write_driver(out.buf.get(..popped.len).unwrap_or_default(), ipc_buf);
                }
                Taken::Drops(dropped) => self.report_drops(dropped, other, ipc_buf),
            }
            self.lock().written();
            self.progress.notify_all();
        }
    }

    /// The writer's write of `bytes` to the driver resolved now, or to the
    /// next one resolved while none is, unbounded.
    fn write_driver(&self, bytes: &[u8], ipc_buf: *mut u64)
    {
        if !ipc_buf.is_null()
        {
            let cap = self.driver.await_cap();
            write_chunks(cap, self.op, bytes, ipc_buf, 0);
        }
    }

    /// Write one logd line naming the `dropped` lines this sink did not
    /// take: to this sink's driver from its writer, and to `other` through its
    /// queue, without waiting for its write.
    fn report_drops(&self, dropped: u32, other: &Sink, ipc_buf: *mut u64)
    {
        let line = self.drop_report(dropped);
        self.write_driver(line.bytes(), ipc_buf);
        let _ = other.offer(line.bytes(), stall_deadline());
    }

    /// logd's warning line naming the `dropped` lines this sink did not
    /// write.
    fn drop_report(&self, dropped: u32) -> LineBuf
    {
        let mut text = SerialFmt::new();
        let _ = write!(
            text,
            "{dropped} lines dropped from the {} output: it had no driver, or its driver \
             took none within {SINK_STALL_MS} ms",
            self.what
        );
        let mut line = LineBuf::new();
        line.push_text_line(b"logd", LEVEL_WARN, elapsed_us(), text.as_str().as_bytes());
        line
    }
}

/// The serial driver logd writes every line to.
static SERIAL: Sink = Sink::new(ipc::serial_labels::SERIAL_WRITE_BYTES, "serial");
/// The framebuffer driver logd mirrors every line to. A headless boot runs
/// none, so the sink stays unserved: it queues lines up to its queue and
/// counts the rest, and nothing is written to a screen ([`Sink::offer`]).
static FB: Sink = Sink::new(ipc::fb_labels::FB_WRITE_BYTES, "framebuffer");

/// Maximum payload bytes per `SERIAL_WRITE_BYTES` or `FB_WRITE_BYTES` (one
/// full IPC data area).
const SERIAL_CHUNK: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// The calling thread's registered IPC buffer, for the sink calls: the main
/// thread, each receive worker, the resync helper and each writer own one, so
/// a call from any thread (the panic sink included) uses its own page
/// (`docs/ipc-design.md` § Multi-threaded servers). Null before the thread has
/// one; the caller then drops the bytes.
fn emit_ipc_buf() -> *mut u64
{
    std::os::seraph::current_ipc_buf()
}

/// Register the serial and framebuffer class watches and resolve both
/// drivers ([`OutputDriver::start`]) on the main thread. Returns the watches'
/// Notifications, 0 for one not registered.
fn resolve_output_drivers(serial_class: u64, fb_class: u64, ipc_buf: *mut u64) -> [u64; 2]
{
    [
        SERIAL.driver.start(serial_class, "serial", ipc_buf),
        FB.driver.start(fb_class, "framebuffer", ipc_buf),
    ]
}

/// Spawn each sink's writer thread ([`Sink::run_writer`]) for a sink whose
/// class the bootstrap carried. A sink whose writer cannot be spawned keeps
/// its lines' producers writing it themselves, bounded
/// ([`Sink::write_inline`]).
fn spawn_writers()
{
    for (sink, other) in [(&SERIAL, &FB), (&FB, &SERIAL)]
    {
        if sink.driver.class.load(Ordering::Acquire) == 0
        {
            continue;
        }
        let spawned = std::thread::Builder::new().spawn(move || {
            sink.run_writer(other);
        });
        if spawned.is_ok()
        {
            sink.writer.store(true, Ordering::Release);
        }
        else
        {
            let mut buf = SerialFmt::new();
            let _ = write!(
                buf,
                "{} writer spawn failed; its lines are written inline",
                sink.what
            );
            self_log(buf.as_str());
        }
    }
}

/// Write `bytes` to the driver behind `cap` with one `op` call per
/// [`SERIAL_CHUNK`] bytes, on the calling thread's page `ipc_buf`, each call
/// bounded by `timeout_ms` (0: no bound). A failed call ends the write.
fn write_chunks(cap: u64, op: u64, bytes: &[u8], ipc_buf: *mut u64, timeout_ms: u32)
{
    for chunk in bytes.chunks(SERIAL_CHUNK)
    {
        if !call_chunk(cap, op, chunk, ipc_buf, timeout_ms)
        {
            return;
        }
    }
}

/// [`write_chunks`] with every call ending by `deadline`; whether all of
/// `bytes` was written.
fn write_chunks_by(cap: u64, op: u64, bytes: &[u8], ipc_buf: *mut u64, deadline: Instant) -> bool
{
    bytes.chunks(SERIAL_CHUNK).all(|chunk| {
        let left = deadline.saturating_duration_since(Instant::now());
        // Round up, so a call is never given the unbounded 0.
        let ms = left.as_micros().div_ceil(1000);
        ms > 0
            && call_chunk(
                cap,
                op,
                chunk,
                ipc_buf,
                u32::try_from(ms).unwrap_or(u32::MAX),
            )
    })
}

/// One `op` call of `chunk` to the driver behind `cap`, bounded by
/// `timeout_ms` (0: no bound); whether it succeeded.
fn call_chunk(cap: u64, op: u64, chunk: &[u8], ipc_buf: *mut u64, timeout_ms: u32) -> bool
{
    let label = op | ((chunk.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, chunk).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer page. A
    // worker calls here (inline) while it serves a request, which was copied
    // out of the page as it was received, and its pending reply stays bound
    // across this call (`docs/ipc-design.md` § Multi-threaded servers).
    unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, timeout_ms) }.is_ok()
}

/// Longest prefix [`LineBuf::push_prefix`] writes, CRLF included: the
/// `[sec.usfrac] ` timestamp (at most 20 + 1 + 6 digits and 3 more bytes), a
/// `[name] ` of at most [`MAX_NAME_LEN`] bytes, the longest level tag and its
/// space (`ERROR `), and the line's `\r\n`.
const LINE_FRAME_MAX: usize = 30 + (MAX_NAME_LEN + 3) + 6 + 2;

/// Bytes of a [`LineBuf`]: the frame of any logd line with its longest body,
/// a rendered record ([`RENDERED_MAX_BYTES`]), which is longer than any text
/// line (`LINE_BUF_SIZE`), so no line is cut.
const LINE_OUT_BYTES: usize = LINE_FRAME_MAX + RENDERED_MAX_BYTES;

const _: () = assert!(RENDERED_MAX_BYTES >= LINE_BUF_SIZE);

/// Fixed-capacity line builder, sized to hold any logd line
/// ([`LINE_OUT_BYTES`]); the serial and framebuffer writes split it into
/// `SERIAL_CHUNK`-byte calls. A push past the capacity is dropped rather
/// than allocated for.
struct LineBuf
{
    buf: [u8; LINE_OUT_BYTES],
    len: usize,
}

impl LineBuf
{
    fn new() -> Self
    {
        Self {
            buf: [0u8; LINE_OUT_BYTES],
            len: 0,
        }
    }

    fn push(&mut self, b: u8)
    {
        if let Some(slot) = self.buf.get_mut(self.len)
        {
            *slot = b;
            // `len` indexed a slot, so it is below the buffer length.
            self.len = self.len.saturating_add(1);
        }
    }

    /// Push a byte, expanding a bare `\n` to `\r\n` for terminal output.
    fn push_escaped(&mut self, b: u8)
    {
        if b == b'\n'
        {
            self.push(b'\r');
        }
        self.push(b);
    }

    fn push_decimal(&mut self, value: u64)
    {
        let mut digits = [0u8; 20];
        let mut n = value;
        let mut idx = digits.len();
        if n == 0
        {
            idx = idx.saturating_sub(1);
            if let Some(d) = digits.get_mut(idx)
            {
                *d = b'0';
            }
        }
        else
        {
            while n > 0
            {
                // A `u64` has at most 20 digits, so `idx` stays in bounds.
                idx = idx.saturating_sub(1);
                if let Some(d) = digits.get_mut(idx)
                {
                    *d = b'0'.saturating_add((n % 10) as u8);
                }
                n /= 10;
            }
        }
        for &d in digits.get(idx..).unwrap_or_default()
        {
            self.push(d);
        }
    }

    fn push_decimal_padded(&mut self, value: u64, width: usize)
    {
        let mut digits = [b'0'; 20];
        let mut n = value;
        let mut idx = digits.len();
        while n > 0 && idx > 0
        {
            // The loop condition keeps `idx` above zero.
            idx = idx.saturating_sub(1);
            if let Some(d) = digits.get_mut(idx)
            {
                *d = b'0'.saturating_add((n % 10) as u8);
            }
            n /= 10;
        }
        let start = digits.len().saturating_sub(width);
        for &d in digits.get(start..).unwrap_or_default()
        {
            self.push(d);
        }
    }

    /// Push `[sec.usfrac] ` for `us` microseconds of the monotonic clock.
    fn push_timestamp(&mut self, us: u64)
    {
        self.push(b'[');
        self.push_decimal(us / 1_000_000);
        self.push(b'.');
        self.push_decimal_padded(us % 1_000_000, 6);
        self.push(b']');
        self.push(b' ');
    }

    /// Push a line's `[sec.usfrac] [name] ` prefix stamped now, `[?]` for an
    /// empty `name`, then the level's tag and a space for any level but info
    /// (`logd_codec::level::tag`).
    fn push_prefix(&mut self, name: &[u8], level: u64)
    {
        self.push_prefix_at(name, level, elapsed_us());
    }

    /// [`Self::push_prefix`], stamped `us` microseconds of the monotonic
    /// clock.
    fn push_prefix_at(&mut self, name: &[u8], level: u64, us: u64)
    {
        self.push_timestamp(us);
        self.push(b'[');
        let name = if name.is_empty()
        {
            logd_codec::reclaim::UNNAMED.as_bytes()
        }
        else
        {
            name
        };
        for &b in name
        {
            self.push(b);
        }
        self.push(b']');
        self.push(b' ');
        if let Some(tag) = logd_codec::level::tag(level)
        {
            for &b in tag.as_bytes()
            {
                self.push(b);
            }
            self.push(b' ');
        }
    }

    /// Push a text line: the prefix stamped `us`, the line's bytes with each
    /// `\n` written `\r\n`, and the closing `\r\n`.
    fn push_text_line(&mut self, name: &[u8], level: u64, us: u64, line: &[u8])
    {
        self.push_prefix_at(name, level, us);
        for &b in line
        {
            self.push_escaped(b);
        }
        self.push(b'\r');
        self.push(b'\n');
    }

    /// The line as pushed so far.
    fn bytes(&self) -> &[u8]
    {
        self.buf.get(..self.len).unwrap_or_default()
    }

    /// Write the line to the serial sink and the framebuffer sink, each whole:
    /// queued to both ([`Sink::offer`]), then awaited
    /// ([`Sink::await_written`]), so the two writes
    /// overlap and each sink holds the caller for [`SINK_STALL_MS`] at most.
    fn flush(&self)
    {
        let line = self.bytes();
        let serial_deadline = stall_deadline();
        let serial = SERIAL.offer(line, serial_deadline);
        let fb_deadline = stall_deadline();
        let fb = FB.offer(line, fb_deadline);
        SERIAL.await_written(serial, serial_deadline);
        FB.await_written(fb, fb_deadline);
    }
}

/// Panic-output sink registered with std via `set_panic_sink`. Routes
/// logd's own panic / alloc-error / precondition output to the serial
/// driver — never through the log endpoint logd serves. Forwards raw bytes
/// (std frames the panic message) straight to the driver, outside the serial
/// sink's queue, each call bounded by [`SINK_STALL_MS`], so a stopped driver
/// delays a panicking thread's end by that bound per call rather than for
/// good; drops them while no driver is resolved. Must stay non-allocating
/// and panic-free: it runs from the panic path, and takes no lock, so a panic
/// on a thread that holds a sink's lock or the state lock still reaches the
/// driver. Its calls use the calling thread's own IPC buffer
/// ([`emit_ipc_buf`]), so a panic or allocation failure on any thread never
/// touches another's.
fn panic_to_serial(bytes: &[u8])
{
    let ipc_buf = emit_ipc_buf();
    if ipc_buf.is_null()
    {
        return;
    }
    let cap = SERIAL.driver.cap();
    if cap != 0
    {
        write_chunks(cap, SERIAL.op, bytes, ipc_buf, SINK_STALL_MS);
    }
}

/// Emit `[sec.usfrac] [logd] <payload>\r\n` to the serial driver, stamped
/// when called. Used for logd's own diagnostics in place of `seraph::log!`
/// (which would self-IPC into the endpoint logd serves). Until
/// [`open_self_log`], the line is held in [`SELF_LOG_HOLD`] instead; a payload
/// longer than `LINE_BUF_SIZE` bytes is cut at a character boundary.
fn self_log(payload: &str)
{
    let mut line = HeldLine {
        us: elapsed_us(),
        payload: SerialFmt::new(),
    };
    let _ = line.payload.write_str(payload);
    let now = SELF_LOG_HOLD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .hold(line);
    if let Some(line) = now
    {
        write_self_log(&line);
    }
}

/// Most self-log lines [`SELF_LOG_HOLD`] keeps until init-logd stops writing
/// the UART. A line past it is dropped and counted, and [`open_self_log`]
/// reports the count in one line. A tuning value: logd self-logs at most nine
/// lines before the release on a start that does not halt (a refused class
/// watch of each output driver, the death-EQ registration's outcome, a failed
/// wait-set add of each watch, a partial receive pool, a failed writer spawn
/// of each sink, and the start of the pull), and a halt writes the held lines
/// before its own.
const SELF_LOG_HELD_MAX: usize = 12;

/// One self-log line: when it was logged, and its text.
struct HeldLine
{
    us: u64,
    payload: SerialFmt,
}

/// logd's self-log lines from its start until init-logd has acknowledged
/// `HANDOVER_RELEASE`. Until then init-logd writes each line it forwards to
/// the UART directly, byte by byte, and the serial driver logd writes through
/// drives the same UART under no lock the two share, so a line of each
/// written at once interleaves byte by byte
/// (`services/logd/docs/handover-protocol.md` § Startup ordering). The
/// panic sink ([`panic_to_serial`]) is not held.
static SELF_LOG_HOLD: Mutex<HeldLines<HeldLine, SELF_LOG_HELD_MAX>> = Mutex::new(HeldLines::new());

/// Write one self-log line to the serial driver, stamped when it was logged.
fn write_self_log(line: &HeldLine)
{
    let mut out = LineBuf::new();
    out.push_text_line(
        b"logd",
        LEVEL_INFO,
        line.us,
        line.payload.as_str().as_bytes(),
    );
    out.flush();
}

/// Stop holding self-log lines: write the held ones in order, then one line
/// for those dropped past [`SELF_LOG_HELD_MAX`], if any. A later call writes
/// nothing.
fn open_self_log()
{
    let dropped = SELF_LOG_HOLD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .open(|line| write_self_log(&line));
    if dropped > 0
    {
        let mut buf = SerialFmt::new();
        let _ = write!(
            buf,
            "{dropped} self-log lines dropped before the handover release (hold of \
             {SELF_LOG_HELD_MAX})"
        );
        self_log(buf.as_str());
    }
}

/// Self-log `payload` on the way to a halt, after the held lines: a halt
/// before the handover release writes them now, since nothing would later.
fn fatal(payload: &str)
{
    open_self_log();
    self_log(payload);
}

/// Stack-buffer `fmt::Write` target for one-shot formatted diagnostics,
/// emitted with `self_log(buf.as_str())`. The 256-byte cap matches
/// `LINE_BUF_SIZE`; over-long formatted output truncates on a character
/// boundary, so the text stays valid UTF-8.
type SerialFmt = logd_codec::BoundedStr<LINE_BUF_SIZE>;

fn elapsed_us() -> u64
{
    syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0)
}
