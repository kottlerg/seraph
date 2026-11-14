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
//! § Role and `docs/console-model.md`. `main` follows that order: bootstrap
//! caps, the serial sink and panic sink, the dropped `log_send_cap`, the
//! death EQ and its registration, the wait set, the receive pool's workers
//! (spawned behind its gate, `services/logd/docs/ipc-interface.md`
//! § Receive pool), the handover pull, the release of the self-log lines held
//! until init-logd stops writing the UART ([`SELF_LOG_HOLD`]), then the
//! gate's opening and the control loop.

#![expect(
    clippy::cast_possible_truncation,
    reason = "targets 64-bit only; u64/usize conversions lossless"
)]

mod handover;
mod slot;

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use ipc::log_labels::{LOG_QUERY_AUTHORITY, QUERY_HISTORY, QUERY_SLOTS};
use ipc::log_query::{HistoryRequest, QUERY_DENIED, decode_slots_request, refusal};
use ipc::log_record::{RECORD_MAX_BYTES, Record};
use ipc::stream_labels::{
    LEVEL_INFO, RECORD_ACCEPTED, RECORD_REJECTED, STREAM_BYTES, STREAM_RECORD,
    STREAM_REGISTER_NAME, level_of,
};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use logd_codec::hold::HeldLines;
use logd_codec::reclaim::{Cause, ReclaimLine};
use logd_codec::record::RENDERED_MAX_BYTES;
use recv_pool::{IpcBuf, RecvPool, SpawnError};
use std::os::seraph::startup_info;
use syscall::RIGHTS_EQ_POST;

use crate::slot::{Eviction, LINE_BUF_SIZE, MAX_NAME_LEN, Slot, SlotTable};

/// `WaitSet` badge for the death-notification event queue.
const WS_BADGE_DEATH: u64 = 1;
/// `WaitSet` badge for logd's resync notification ([`RESYNC_WALK_DONE`],
/// [`RESYNC_REQUESTED`]).
const WS_BADGE_RESYNC: u64 = 2;

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
    ] = unsafe { ipc::bootstrap::request_slots::<5>(creator_endpoint, ipc_buf) }.ok()?;
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

    // Every process's log output, a debug-authority holder's own included,
    // waits on logd, so a holder that stopped it would block on itself:
    // declare this process undebuggable before it spawns a thread
    // (`procmgr_labels::DECLARE_NO_DEBUG`). A refusal leaves it debuggable.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            startup.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    };

    let Some(caps) = bootstrap_caps(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // Record the class SENDs for the emit path. The serial driver is
    // resolved via `QUERY_DEVICE` on the `serial` class SEND before the
    // handover pull (`resolve_output_drivers`), and again on a later emit
    // while it is not resolvable; until then serial output is dropped
    // (init-logd covered the pre-driver window) while history still accrues.
    serial_init(caps.serial_class, caps.fb_class);

    // logd serves the log endpoint, so it must never emit through it. Route
    // panic / alloc-error / precondition output to the serial driver (the
    // path `self_log` already uses) via the std panic sink, and drop the
    // procmgr-seeded badged SEND so no path — panic, alloc-error, or a stray
    // `log!` — can self-IPC into the endpoint logd receives on.
    std::os::seraph::set_panic_sink(panic_to_serial);
    let _ = syscall::cap_delete(startup.log_send_cap);

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
    // Resolve the serial and framebuffer drivers through devmgr now, while
    // init-logd still drains the log endpoint: the first write that would
    // resolve them is held until after the release, when the endpoint has no
    // reader until the receive pool's gate opens, and devmgr may then be logging
    // (`services/devmgr/docs/responsibilities.md`, the on-disk settle).
    resolve_output_drivers(ipc_buf);
    let Some(resync_note) = create_resync_note()
    else
    {
        fatal("FATAL: resync notification create failed; halting");
        syscall::thread_exit();
    };
    let Some(ws_cap) = create_wait_set(death_eq, resync_note)
    else
    {
        fatal("FATAL: wait_set create failed; halting");
        syscall::thread_exit();
    };
    let logd: &'static Logd = Box::leak(Box::new(Logd {
        state: Mutex::new(LogdState::default()),
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

    if caps.log_ep_handover_send != 0
    {
        // First launch: pull init-logd's accrued boot history, release
        // init-logd, then drop the single-use SEND so logd carries no SEND cap
        // to its own log endpoint.
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
            table.slots.values().map(|s| s.history.len()).sum::<usize>(),
        );
        self_log(buf.as_str());
    }
    else
    {
        // A svcmgr restart: there is no handover source (init-logd exited
        // after the first launch). Serve a fresh table; in-flight history
        // from the prior instance is not recoverable. No init-logd writes the
        // UART, so nothing needs holding.
        open_self_log();
        self_log("started (restart); no handover source, serving fresh");
    }

    logd.lock().table = table;
    pool.open();
    let mut resync = Resync::new(caps.procmgr_death_auth_send, resync_note);
    control_loop(ws_cap, logd, &mut resync);
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
#[derive(Default)]
struct LogdState
{
    table: SlotTable,
    /// Death events taken since a take last found the queue empty, by any
    /// thread: a drain's count, as one thread's drain from a ready queue to an
    /// empty one would take them ([`drain_deaths`]).
    drain_run: u32,
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

/// Build the main thread's 2-member wait set: the death event queue
/// (`WS_BADGE_DEATH`) and the resync notification (`WS_BADGE_RESYNC`). The
/// log endpoint is the receive workers', outside the set.
fn create_wait_set(death_eq: u64, resync_note: u64) -> Option<u64>
{
    // The set's member capacity: the two members above.
    const WS_MEMBERS: u32 = 2;
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
/// queue no request wakes a worker for still empties, and run the
/// [`Resync`] on its notification's bits.
fn control_loop(ws_cap: u64, logd: &Logd, resync: &mut Resync) -> !
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
            _ => (),
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
/// line is written after the lock is released. [`LogdState::drain_run`] counts
/// the takes since one last found the queue empty, whichever thread made them.
/// When it reaches a full queue's worth, the queue may have filled, and a post
/// to a full queue is dropped, so the drain asks the main thread for a
/// [`Resync`] ([`RESYNC_REQUESTED`]) and counts again from zero.
fn drain_deaths(logd: &Logd)
{
    loop
    {
        let (badge, exit_reason, evicted, full) = {
            let mut state = logd.lock();
            let Ok(death) = syscall::event_try_recv_death(logd.death_eq)
            else
            {
                state.drain_run = 0;
                return;
            };
            state.drain_run = state.drain_run.saturating_add(1);
            let full = state.drain_run >= DEATH_EQ_CAPACITY;
            if full
            {
                state.drain_run = 0;
            }
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
        consume_bytes(logd, msg.badge, msg, byte_len);
        reply_ack(ipc_buf);
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
/// port AND recording them into the per-slot history ring. A line takes
/// the level of the message carrying its first byte
/// ([`crate::slot::Slot::begin_byte`]).
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
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` and `seq` borrow through the guard to the end of the byte loop: \
              the hold serialises the slot's partial line, its history and the sequence counter"
)]
fn consume_bytes(logd: &Logd, badge: u64, msg: &IpcMessage, byte_len: usize)
{
    const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(STREAM_CHUNK_SIZE);
    let level = level_of(msg.label);
    let mut rest = bytes.get(..n).unwrap_or_default();
    while !rest.is_empty()
    {
        let mut out = LineBuf::new();
        let line_done = {
            let mut state = logd.lock();
            let Some((slot, seq)) = state.table.sender_slot(badge)
            else
            {
                // An evicted sender's message (`SlotTable::sender_slot`).
                return;
            };
            let mut done = false;
            while let Some((&b, tail)) = rest.split_first()
            {
                rest = tail;
                slot.begin_byte(level);
                if b == b'\n'
                {
                    flush_partial(slot, seq, &mut out);
                    done = true;
                    break;
                }
                if slot.partial.len() < LINE_BUF_SIZE
                {
                    slot.partial.push(b);
                    if slot.partial.len() == LINE_BUF_SIZE
                    {
                        flush_partial(slot, seq, &mut out);
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
}

/// Render one `STREAM_RECORD` message's record as one line and retain it in
/// the slot's history, with its field table, under the state lock, then write
/// the line. The record does not touch the slot's partial text line. Returns
/// the reply label: `RECORD_ACCEPTED`, or `RECORD_REJECTED` for a payload
/// longer than a record or than the message, or one `ipc::log_record` refuses,
/// which is neither rendered nor retained.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` and `seq` borrow through the guard to the record's retention: \
              the hold serialises the slot's name, its history and the sequence counter"
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
        let Some((slot, seq)) = state.table.sender_slot(badge)
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
        slot.push_record(SlotTable::next_seq(seq), us, level, &record);
    }
    out.flush();
    RECORD_ACCEPTED
}

/// Render the slot's in-progress line into `out`, append it to the history
/// ring as the next entry of `seq`, and clear the partial buffer.
fn flush_partial(slot: &mut Slot, seq: &mut u64, out: &mut LineBuf)
{
    let line = std::mem::take(&mut slot.partial);
    let level = slot.partial_level;
    let us = elapsed_us();
    out.push_text_line(&slot.name, level, us, &line);
    slot.push_history(SlotTable::next_seq(seq), us, level, &line);
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
    let mut state = logd.lock();
    let Some((slot, _)) = state.table.sender_slot(badge)
    else
    {
        // An evicted sender's name (`SlotTable::sender_slot`).
        return;
    };
    slot.name.clear();
    slot.name
        .extend_from_slice(bytes.get(..n).unwrap_or_default());
}

// ── Serial output (driver-mediated) ────────────────────────────────────────

/// The `serial` class SEND on devmgr's registry endpoint.
static SERIAL_CLASS: AtomicU64 = AtomicU64::new(0);
/// The `framebuffer` class SEND on devmgr's registry endpoint.
static FB_CLASS: AtomicU64 = AtomicU64::new(0);
/// Resolved SEND cap on the serial driver's service endpoint, cached after
/// the first successful `QUERY_DEVICE` on [`SERIAL_CLASS`]. Zero =
/// unresolved.
static SERIAL_CAP: AtomicU64 = AtomicU64::new(0);
/// Resolved SEND cap on the framebuffer driver's service endpoint. `0` =
/// not yet attempted; [`FB_UNAVAILABLE`] = attempted and no driver present
/// (headless boot); any other value = the resolved cap. Once devmgr has
/// answered, the outcome is cached either way, so framebuffer mirroring
/// stays a no-op on a headless boot without re-querying devmgr.
static FB_CAP: AtomicU64 = AtomicU64::new(0);
/// Set while one thread queries devmgr for the serial driver. Another
/// thread that finds it set does not query (its bytes are dropped, as while
/// the driver is not resolvable), so threads never query devmgr at once and
/// no second cap is resolved.
static SERIAL_RESOLVING: AtomicBool = AtomicBool::new(false);
/// [`SERIAL_RESOLVING`] for the framebuffer driver.
static FB_RESOLVING: AtomicBool = AtomicBool::new(false);
/// Held across the `SERIAL_WRITE_BYTES` calls of one line, so a line longer
/// than one call (a record renders to up to `RENDERED_MAX_BYTES`) is not
/// split by another thread's. A lock held across an IPC call departs from
/// `docs/coding-standards.md` § Concurrency: the serial driver never calls
/// logd (it MUST NOT log, `services/drivers/serial/src/main.rs`), so no
/// thread waiting on this lock is one the driver waits on
/// (`docs/ipc-design.md` § Multi-threaded servers). Nothing that calls devmgr
/// runs under it. The panic sink takes no lock ([`panic_to_serial`]).
static SERIAL_EMIT: Mutex<()> = Mutex::new(());
/// [`SERIAL_EMIT`] for the `FB_WRITE_BYTES` calls of one line; the
/// framebuffer driver MUST NOT log either
/// (`services/drivers/framebuffer/src/main.rs`).
static FB_EMIT: Mutex<()> = Mutex::new(());

/// Sentinel stored in [`FB_CAP`] once a resolution attempt finds no
/// framebuffer driver. Repeating the `QUERY_DEVICE` per log line
/// would open a deadlock window against devmgr's own logging — devmgr →
/// `log_ep` → logd, while a logd thread blocks here on devmgr's reply — so
/// the no-driver answer is cached. `u64::MAX` names no cap: no handle sets
/// bit 63.
const FB_UNAVAILABLE: u64 = u64::MAX;
/// Maximum payload bytes per `SERIAL_WRITE_BYTES` or `FB_WRITE_BYTES` (one
/// full IPC data area).
const SERIAL_CHUNK: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// Record the class SENDs for the emit path.
fn serial_init(serial_class: u64, fb_class: u64)
{
    SERIAL_CLASS.store(serial_class, Ordering::Release);
    FB_CLASS.store(fb_class, Ordering::Release);
}

/// The calling thread's registered IPC buffer, for the emit path's
/// `ipc_call`s: the main thread, each receive worker, and the resync helper
/// each own one, so output from any thread (the panic sink included) uses
/// its own page (`docs/ipc-design.md` § Multi-threaded servers). Null before
/// the thread has one; the emit path then drops the bytes.
fn emit_ipc_buf() -> *mut u64
{
    std::os::seraph::current_ipc_buf()
}

/// Resolve (and cache) the serial driver's SEND cap via `QUERY_DEVICE` at
/// ordinal 0 on the `serial` class. Returns 0 while the driver is not yet
/// resolvable (devmgr not reachable, or driver not spawned) or while another
/// thread resolves it ([`SERIAL_RESOLVING`]); the caller then drops the
/// bytes.
fn resolve_serial_cap(ipc_buf: *mut u64) -> u64
{
    let cached = SERIAL_CAP.load(Ordering::Acquire);
    if cached != 0
    {
        return cached;
    }
    let class = SERIAL_CLASS.load(Ordering::Acquire);
    if class == 0
        || SERIAL_RESOLVING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return 0;
    }
    // A thread that resolved it may have finished since the load above.
    let mut cap = SERIAL_CAP.load(Ordering::Acquire);
    if cap == 0
    {
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        if let Ok(resolved) = unsafe { ipc::query_device(class, 0, ipc_buf) }
        {
            SERIAL_CAP.store(resolved, Ordering::Release);
            cap = resolved;
        }
    }
    SERIAL_RESOLVING.store(false, Ordering::Release);
    cap
}

/// Resolve, and cache, the serial driver's and the framebuffer driver's SEND
/// caps without writing anything: [`resolve_serial_cap`] and
/// [`resolve_fb_cap`] on the calling thread's IPC buffer.
fn resolve_output_drivers(ipc_buf: *mut u64)
{
    let _ = resolve_serial_cap(ipc_buf);
    let _ = resolve_fb_cap(ipc_buf);
}

/// Write `bytes` to the driver behind `cap` with one `op` call per
/// [`SERIAL_CHUNK`] bytes, on the calling thread's page `ipc_buf`.
fn write_chunks(cap: u64, op: u64, bytes: &[u8], ipc_buf: *mut u64)
{
    for chunk in bytes.chunks(SERIAL_CHUNK)
    {
        let label = op | ((chunk.len() as u64) << 16);
        let msg = IpcMessage::builder(label).bytes(0, chunk).build();
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        // A worker calls here while it serves a request, which was copied
        // out of the page as it was received, and its pending reply stays
        // bound across this call (`docs/ipc-design.md` § Multi-threaded
        // servers).
        let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
    }
}

/// Write one fully-formatted line to the serial driver under
/// [`SERIAL_EMIT`]. Silently drops the bytes if the driver is
/// not yet resolvable.
fn serial_write(bytes: &[u8])
{
    let ipc_buf = emit_ipc_buf();
    if ipc_buf.is_null()
    {
        return;
    }
    let cap = resolve_serial_cap(ipc_buf);
    if cap == 0
    {
        return;
    }
    let _whole = SERIAL_EMIT.lock().unwrap_or_else(PoisonError::into_inner);
    write_chunks(cap, ipc::serial_labels::SERIAL_WRITE_BYTES, bytes, ipc_buf);
}

/// Resolve (and cache) the framebuffer driver's SEND cap via `QUERY_DEVICE`
/// at ordinal 0 on the `framebuffer` class. Returns 0 while the driver is
/// not yet resolvable (devmgr unreachable, headless boot, or driver not
/// spawned) or while another thread resolves it ([`FB_RESOLVING`]); the
/// caller then skips the framebuffer mirror. Uses the same IPC buffer the
/// serial path resolved through.
fn resolve_fb_cap(ipc_buf: *mut u64) -> u64
{
    let cached = FB_CAP.load(Ordering::Acquire);
    if cached == FB_UNAVAILABLE
    {
        return 0;
    }
    if cached != 0
    {
        return cached;
    }
    let class = FB_CLASS.load(Ordering::Acquire);
    // No class SEND recorded (serial_init sets it before any output, and
    // a boot without the framebuffer class has none): no IPC, so nothing to
    // latch.
    if class == 0
        || FB_RESOLVING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return 0;
    }
    // A thread that resolved it may have finished since the load above.
    let latched = FB_CAP.load(Ordering::Acquire);
    let cap = if latched != 0
    {
        if latched == FB_UNAVAILABLE
        {
            0
        }
        else
        {
            latched
        }
    }
    else
    {
        // SAFETY: ipc_buf is the calling thread's registered IPC buffer page.
        match unsafe { ipc::query_device(class, 0, ipc_buf) }
        {
            // devmgr answered. Latch the outcome so the threads issue no
            // more QUERY_DEVICE: the resolved cap, or FB_UNAVAILABLE when
            // devmgr reports no framebuffer driver (headless boot). The
            // driver, when present, is spawned before svcmgr launches logd,
            // so this resolves it. Latching the no-driver answer is what
            // prevents a per-line re-query, which would open a deadlock
            // window against devmgr's own logging (devmgr → log_ep → logd,
            // while a logd thread blocks here on devmgr's reply).
            Ok(cap) =>
            {
                FB_CAP.store(
                    if cap == 0 { FB_UNAVAILABLE } else { cap },
                    Ordering::Release,
                );
                cap
            }
            // Could not complete the query (transient — the call returned
            // rather than blocking, so this is not the logd↔devmgr deadlock
            // path). Leave the cache unset and retry on the next line,
            // matching resolve_serial_cap; the serial class resolves on the
            // same devmgr endpoint, so a hard failure here does not recur in
            // practice.
            Err(ipc::ClassCallError::Call(_)) => 0,
            // devmgr answered with no driver.
            Err(_) =>
            {
                FB_CAP.store(FB_UNAVAILABLE, Ordering::Release);
                0
            }
        }
    };
    FB_RESOLVING.store(false, Ordering::Release);
    cap
}

/// Mirror a fully-formatted line to the framebuffer driver under [`FB_EMIT`].
/// Silently skips the mirror if the driver is not resolvable, so serial
/// remains the always-present, authoritative channel (CI scrapes serial; the
/// framebuffer is an on-screen convenience).
fn fb_write(bytes: &[u8])
{
    let ipc_buf = emit_ipc_buf();
    if ipc_buf.is_null()
    {
        return;
    }
    let cap = resolve_fb_cap(ipc_buf);
    if cap == 0
    {
        return;
    }
    let _whole = FB_EMIT.lock().unwrap_or_else(PoisonError::into_inner);
    write_chunks(cap, ipc::fb_labels::FB_WRITE_BYTES, bytes, ipc_buf);
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

    /// Write the line to the serial driver and mirror it to the framebuffer
    /// driver, each whole ([`SERIAL_EMIT`], [`FB_EMIT`]).
    fn flush(&self)
    {
        let line = self.buf.get(..self.len).unwrap_or_default();
        serial_write(line);
        fb_write(line);
    }
}

/// Panic-output sink registered with std via `set_panic_sink`. Routes
/// logd's own panic / alloc-error / precondition output to the serial
/// driver — never through the log endpoint logd serves. Forwards raw bytes
/// (std frames the panic message), and drops them until the driver is
/// resolvable. Must stay non-allocating and panic-free: it runs
/// from the panic path, and takes no lock, so a panic on a thread that holds
/// [`SERIAL_EMIT`] or the state lock still reaches the driver. Its calls use
/// the calling thread's own IPC buffer ([`emit_ipc_buf`]), so a panic or
/// allocation failure on any thread never touches another's.
fn panic_to_serial(bytes: &[u8])
{
    let ipc_buf = emit_ipc_buf();
    if ipc_buf.is_null()
    {
        return;
    }
    let cap = resolve_serial_cap(ipc_buf);
    if cap != 0
    {
        write_chunks(cap, ipc::serial_labels::SERIAL_WRITE_BYTES, bytes, ipc_buf);
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
/// reports the count in one line. A tuning value: logd self-logs at most
/// three lines before the release (the death-EQ registration's outcome, a
/// failed wait-set step, and the start of the pull).
const SELF_LOG_HELD_MAX: usize = 8;

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
