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
//! pull, the opening of the sinks once init-logd stops writing the UART
//! ([`open_output`]), the kernel log reader's thread ([`read_kernel_log`]),
//! then the gate's opening and the control loop. logd's journal, its
//! history, is retained from the first line logd logs about itself: the
//! machine's RAM, read from memmgr before it, sizes it ([`history_bounds`]).

mod handover;

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use death_set::OverflowWatch;
use ipc::log_badges::LOG_BADGE_LOGD;
use ipc::log_flush::{FLUSH_DENIED, FlushAnswer};
use ipc::log_labels::{
    LOG_FLUSH, LOG_FLUSH_AUTHORITY, LOG_QUERY_AUTHORITY, QUERY_HISTORY, QUERY_SLOTS,
};
use ipc::log_query::{HistoryRequest, QUERY_DENIED, decode_slots_request, refusal};
use ipc::log_record::{RECORD_MAX_BYTES, Record};
use ipc::serve::Reply;
use ipc::stream_labels::{
    LEVEL_EMERGENCY, LEVEL_INFO, LEVEL_NOTICE, LEVEL_WARN, NAME_UNKNOWN, RECORD_ACCEPTED,
    RECORD_REJECTED, STREAM_BYTES, STREAM_RECORD, STREAM_REGISTER_NAME, WINDOW_FULL, level_of,
    level_or_info, sender_named,
};
use ipc::{IpcMessage, memmgr_labels, procmgr_errors, procmgr_labels};
use logd_codec::history::ENTRY_MAX_BYTES;
use logd_codec::kernel::{Accept, KERNEL_NAME, KernelLine};
use logd_codec::reclaim::{Cause, ReclaimLine};
use logd_codec::record::RENDERED_MAX_BYTES;
use logd_codec::settings::{
    BACKLOG_MAX, Colour, Format, HOSTNAME_ENV, HostName, Pace, Relayed, SinkKind, SinkSettings,
};
use logd_codec::sink::SINK_STALL_MS;
use recv_pool::{IpcBuf, RecvPool, SpawnError};
use std::os::seraph::startup_info;
use syscall::RIGHTS_EQ_POST;

use logd_slot_table::{
    Admit, Bounds, Eviction, History, HistoryEntry, LINE_BUF_SIZE, MARKS, MAX_NAME_LEN, Mark,
    Origin, Slot, SlotTable, admit, lines_completed,
};

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
    /// the same way. Zero disables the framebuffer sink.
    fb_class: u64,
    /// A `KernelLog` cap carrying `Read`, through which logd reads the
    /// kernel's console lines ([`read_kernel_log`]). Zero leaves the kernel
    /// writing its lines itself.
    kernel_log: u64,
    /// The SEND of the `timed` publication, through which logd reads the
    /// wall clock once ([`read_wall_clock`]). Zero leaves the boot wall
    /// offset unknown.
    timed: u64,
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
        timed,
    ] = unsafe { ipc::bootstrap::request_slots::<7>(creator_endpoint, ipc_buf) }.ok()?;
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
        timed,
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

    // The journal's bounds, before the first line logd retains.
    let bounds = history_bounds(startup.memmgr_endpoint, ipc_buf);
    let _ = STATE.set(Mutex::new(LogdState::new(bounds)));
    // Each sink's settings and the host name, from logd's recipe, before a
    // sink writes.
    load_settings();

    // logd serves the log endpoint, so it must never emit through it. Route
    // panic / alloc-error / precondition output to the serial driver (the
    // path `self_log` already uses) via the std panic sink, and drop the
    // procmgr-seeded badged SEND so no path — panic, alloc-error, or a stray
    // `log!` — can self-IPC into the endpoint logd receives on.
    std::os::seraph::set_panic_sink(panic_to_serial);
    let _ = syscall::cap_delete(startup.log_send_cap);

    // Register the serial and framebuffer class watches and resolve both
    // drivers through devmgr first: a halt on any later step writes its
    // `FATAL` line and the lines logd retained before it, and the panic sink
    // its output, only to a resolved serial driver. This runs while init-logd
    // still drains the log endpoint: after the release the endpoint has no
    // reader until the receive pool's gate opens, and devmgr may then be
    // logging (`services/devmgr/docs/responsibilities.md`, the on-disk
    // settle). Until a driver is resolved the journal keeps the lines for its
    // sink's cursor, within the history's bounds; the main thread resolves it
    // again when devmgr signals its class's watch.
    let watches = resolve_output_drivers(caps.serial_class, caps.fb_class, ipc_buf);
    // The sinks' classes are known now: each served sink's cursor is its mark
    // from here, on a restart too, where no handover install sets them.
    state().sync_marks();

    let mut table = SlotTable::with_bounds(bounds);

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
        move |msg: &IpcMessage, _: IpcBuf, reply: &mut Reply| {
            serve_request(logd, msg, reply);
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
    // workers; they write once the sinks open.
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
        let (slots, entries) = (table.slots.len(), table.history().len());
        // The handover's entries go before logd's own lines, which are newer.
        install_table(table);
        // Init-logd has acknowledged the release and writes no more (or no
        // release reached it, and holding longer would only lose the lines):
        // the sinks write the journal from here on.
        open_output();

        let mut buf = SerialFmt::new();
        let _ = write!(
            buf,
            "handover complete: {slots} slots, {entries} history entries"
        );
        self_log(buf.as_str());
    }
    else
    {
        // A restart after procmgr reported init reaped: init-logd has exited,
        // so there is no handover source (svcmgr serves `cap[1]` to every
        // restart before that). Serve a fresh table; in-flight history from
        // the prior instance is not recoverable. No init-logd writes the UART,
        // so the sinks write at once.
        open_output();
        self_log("started (restart); no handover source, serving fresh");
    }

    start_kernel_reader(caps.kernel_log, logd);
    pool.open();
    start_wall_clock_reader(caps.timed);
    let mut resync = Resync::new(caps.procmgr_death_auth_send, resync_note);
    control_loop(ws_cap, logd, &mut resync, watches, ipc_buf);
}

/// The caps logd's receive workers and its main thread share; the state
/// they share is [`STATE`].
struct Logd
{
    /// RECV on the death-notification `EventQueue`.
    death_eq: u64,
    /// The resync notification ([`RESYNC_WALK_DONE`], [`RESYNC_REQUESTED`]).
    resync_note: u64,
}

/// The badge table with the journal, the death-drain count, and the sinks'
/// cursors, under one lock: every worker's request, every drain step and
/// every sink's step takes it, and none holds it across an IPC call
/// (`services/logd/docs/ipc-interface.md` § Receive pool). Set by `main`
/// once the history's bounds are known, before logd retains a line.
static STATE: OnceLock<Mutex<LogdState>> = OnceLock::new();

/// Signalled when an entry is retained and when the sinks open: the writers'
/// wake.
static RETAINED: Condvar = Condvar::new();

/// Signalled when a sink's cursor moves: the kernel log reader's wake
/// ([`await_hold_passed`]).
static PROGRESS: Condvar = Condvar::new();

/// The state lock ([`STATE`]); the floor's bounds when `main` has not set it.
fn state() -> MutexGuard<'static, LogdState>
{
    STATE
        .get_or_init(|| Mutex::new(LogdState::new(Bounds::FLOOR)))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// What [`STATE`] guards.
struct LogdState
{
    table: SlotTable,
    /// The death events taken since a take last found the queue empty, by
    /// any thread, as one thread's drain from a ready queue to an empty one
    /// would take them ([`drain_deaths`]).
    deaths: OverflowWatch,
    /// Each device sink's place in the journal, in [`SINKS`]' order.
    cursors: [Cursor; MARKS],
    /// Each device sink's settings, in [`SINKS`]' order: the one place they
    /// live, which the sink's writer reads under this lock
    /// (`services/logd/docs/sinks.md` § Settings).
    settings: [SinkSettings; MARKS],
    /// Whether the sinks write the journal: set once init-logd writes the
    /// UART no more ([`open_output`]).
    open: bool,
}

impl LogdState
{
    /// The state at start: an empty table whose history keeps `bounds`,
    /// with logd's own slot named.
    fn new(bounds: Bounds) -> Self
    {
        let mut table = SlotTable::with_bounds(bounds);
        table.install_from_handover(LOG_BADGE_LOGD, b"logd");
        let mut state = Self {
            table,
            deaths: OverflowWatch::new(DEATH_EQ_CAPACITY),
            cursors: [Cursor::default(); MARKS],
            settings: SINKS.map(|sink| sink.kind.defaults()),
            open: false,
        };
        state.sync_marks();
        state
    }

    /// Tell the history where each sink's cursor is and what it shows
    /// ([`Mark`]), so its eviction spares what a `hold` sink owes, a
    /// sender's window counts it, and each sink's drops are counted.
    fn sync_marks(&mut self)
    {
        for sink in SINKS
        {
            let mark = self.mark_of(sink);
            self.table.history_mut().set_mark(sink.index, mark);
        }
    }

    /// `sink`'s mark: none for a sink whose class the bootstrap carried
    /// not, or whose level is `off`.
    fn mark_of(&self, sink: &Sink) -> Option<Mark>
    {
        let settings = self.settings.get(sink.index)?;
        let cursor = self.cursors.get(sink.index)?;
        let least = settings.level?;
        (sink.driver.class() != 0).then_some(Mark {
            from: cursor.next,
            taken: cursor.taken,
            least,
            relayed: settings.relayed,
            pace: settings.pace,
        })
    }

    /// Which sinks hold senders, a flush and the kernel reader now
    /// ([`Sink::holding`]), by index.
    fn holding(&self) -> [bool; MARKS]
    {
        SINKS.map(|sink| {
            self.settings
                .get(sink.index)
                .is_some_and(|settings| sink.holding(settings))
        })
    }
}

/// Read each sink's settings and the host name from logd's recipe
/// (`services/logd/docs/sinks.md` § Settings) into the state: a sink's
/// `LOGD_SINK_<NAME>` entry over its defaults, an entry that does not parse
/// leaving them whole and logged at warning, as is a host name that is not
/// one.
fn load_settings()
{
    for sink in SINKS
    {
        let key = sink.kind.env_key();
        let Ok(text) = std::env::var(key)
        else
        {
            continue;
        };
        match sink.kind.defaults().parse_over(sink.kind, &text)
        {
            Ok(settings) =>
            {
                let mut st = state();
                if let Some(slot) = st.settings.get_mut(sink.index)
                {
                    *slot = settings;
                }
                drop(st);
            }
            Err(e) =>
            {
                let mut buf = SerialFmt::new();
                let _ = write!(buf, "{key} refused: {e}");
                retain_own(LEVEL_WARN, buf.as_str().as_bytes());
            }
        }
    }
    if let Ok(text) = std::env::var(HOSTNAME_ENV)
    {
        if let Some(host) = HostName::parse(&text)
        {
            let _ = HOST.set(host);
        }
        else
        {
            let mut buf = SerialFmt::new();
            let _ = write!(buf, "{HOSTNAME_ENV} refused: not a host name");
            retain_own(LEVEL_WARN, buf.as_str().as_bytes());
        }
    }
}

/// The host name the `host` field and the rfc5424 HOSTNAME show, from
/// `LOGD_HOSTNAME`; unset while the recipe sets none.
static HOST: OnceLock<HostName> = OnceLock::new();

impl Logd
{
    #[expect(
        clippy::unused_self,
        reason = "the state is a static, so it exists for the lines logd logs before `Logd`                   does; the method keeps the callers' one way to the lock"
    )]
    fn lock(&self) -> MutexGuard<'static, LogdState>
    {
        state()
    }
}

/// Install `table`, the handover's, as logd's: the entries logd retained
/// before it, which no sink has read since the sinks are not open, are
/// retained after its own ([`SlotTable::absorb`]). A sink that passes
/// `relayed` entries starts after the handover's, every one of which
/// init-logd wrote to its device: the `seq` gaps among them are lines
/// init-logd evicted after writing them, not the sink's drops.
fn install_table(table: SlotTable)
{
    let mut st = state();
    let relayed_end = table.history().next_seq();
    let earlier = core::mem::replace(&mut st.table, table);
    st.table.absorb(earlier);
    let LogdState {
        cursors, settings, ..
    } = &mut *st;
    for (cursor, settings) in cursors.iter_mut().zip(settings.iter())
    {
        if settings.relayed == Relayed::Pass
        {
            cursor.next = cursor.next.max(relayed_end);
        }
    }
    st.sync_marks();
}

/// The history's bounds for the machine's RAM, as memmgr reports it
/// (`QUERY_POOL_STATUS` `data[0]`, `system_ram_bytes`), asked once with a
/// call bounded by [`SINK_STALL_MS`], so logd never waits on memmgr; the
/// floor's bounds when the call is not answered in time or is refused
/// (`services/logd/docs/sinks.md` § The journal).
fn history_bounds(memmgr: u64, ipc_buf: *mut u64) -> Bounds
{
    if memmgr == 0
    {
        return Bounds::FLOOR;
    }
    let msg = IpcMessage::new(memmgr_labels::QUERY_POOL_STATUS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::ipc_call_timeout(memmgr, &msg, ipc_buf, SINK_STALL_MS) }
    {
        Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS => Bounds::for_ram(reply.word(0)),
        _ => Bounds::FLOOR,
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
/// record of logd's (`logd_codec::reclaim`), so the name cannot read as a
/// further field.
fn log_reclaim(badge: u64, cause: Cause, name: &[u8])
{
    let w = ReclaimLine { badge, cause, name }.record();
    // A record `RecordWriter` built decodes.
    if let Ok(record) = Record::decode(w.as_bytes())
    {
        {
            let mut st = state();
            if let Some((slot, history)) = st.table.sender_slot(LOG_BADGE_LOGD)
            {
                let _ =
                    history.push_record(slot, LOG_BADGE_LOGD, elapsed_us(), LEVEL_INFO, &record);
            }
        }
        retained();
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
/// § Receive pool): drain the death queue, then serve `msg` and leave its
/// reply for the worker to send with its next receive.
fn serve_request(logd: &Logd, msg: &IpcMessage, reply: &mut Reply)
{
    drain_deaths(logd);
    let label_id = msg.label & 0xFFFF;
    let byte_len = ((msg.label >> 16) & 0xFFFF) as usize;
    if label_id == STREAM_BYTES
    {
        consume_bytes(logd, msg.badge, msg, byte_len).reply(reply);
    }
    else if label_id == STREAM_RECORD
    {
        consume_record(logd, msg.badge, msg, byte_len).reply(reply);
    }
    else if label_id == STREAM_REGISTER_NAME
    {
        register_name(logd, msg.badge, msg, byte_len);
        reply.set_status(0);
    }
    else if label_id == QUERY_SLOTS || label_id == QUERY_HISTORY
    {
        reply.set(answer_query(&logd.lock().table, msg));
    }
    else if label_id == LOG_FLUSH
    {
        reply.set(answer_flush(msg));
    }
    else
    {
        // Unknown / legacy label (e.g. GET_LOG_CAP from a hypothetical
        // pre-pivot caller). Reply empty so the sender unblocks.
        reply.set_status(0);
    }
}

/// What logd did with a sender's `STREAM_BYTES` or `STREAM_RECORD`
/// message.
enum Consumed
{
    /// Answered with this status label.
    Status(u64),
    /// Refused `WINDOW_FULL`, nothing consumed, with this retry hint in
    /// milliseconds (`services/logd/docs/ipc-interface.md` § Hold window).
    WindowFull(u32),
}

impl Consumed
{
    /// Leave the answer in `reply`.
    fn reply(self, reply: &mut Reply)
    {
        match self
        {
            Self::Status(status) => reply.set_status(status),
            Self::WindowFull(hint) => reply.set(
                IpcMessage::builder(WINDOW_FULL)
                    .word(0, u64::from(hint))
                    .build(),
            ),
        }
    }
}

/// The refusal of a message from `badge` at `level` that completes `lines`
/// lines, read under the state lock `st`: `WINDOW_FULL` with its retry hint
/// when a `hold` sink holds senders and the message would take the sender's
/// entries one of them shows and has not written past its window
/// ([`admit`]); `None` when the message is taken. Allocates nothing and
/// calls nothing, so a refusal costs logd no more than its reply.
fn window_refusal(st: &LogdState, badge: u64, lines: usize, level: u64) -> Option<Consumed>
{
    let holding = st.holding();
    if lines == 0 || !holding.contains(&true)
    {
        return None;
    }
    match admit(st.table.unwritten_of(badge, &holding), lines, level)
    {
        Admit::Accept => None,
        Admit::Refuse { excess } => Some(Consumed::WindowFull(logd_codec::sink::hint_ms(
            excess as u64,
            slowest_entry_us(holding),
        ))),
    }
}

/// The longest time per entry ([`Sink::entry_us`]) of the sinks
/// `holding` names: the pace a retry hint is reckoned at.
fn slowest_entry_us(holding: [bool; MARKS]) -> u64
{
    SINKS
        .iter()
        .zip(holding)
        .filter(|&(_, holds)| holds)
        .map(|(sink, _)| sink.entry_us.load(Ordering::Relaxed))
        .max()
        .unwrap_or(0)
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

/// Answer a `LOG_FLUSH` request (`services/logd/docs/ipc-interface.md`
/// § Flush barrier) from the `hold` sink's cursor, at once, under the state
/// lock, so a flush waits on nothing. `FLUSH_DENIED` for a badge without
/// `LOG_FLUSH_AUTHORITY`.
fn answer_flush(msg: &IpcMessage) -> IpcMessage
{
    if msg.badge & LOG_FLUSH_AUTHORITY == 0
    {
        return ipc::log_flush::refusal(FLUSH_DENIED);
    }
    match ipc::log_flush::decode_request(msg)
    {
        Ok(token) => flush_answer(token).reply(),
        Err(status) => ipc::log_flush::refusal(status),
    }
}

/// The answer to a flush for `token`, or for a new one (`None`): the `seq`
/// the next retained entry takes. Flushed once every `hold` sink's cursor is
/// at or past the token, a sink that holds nobody (stalled, unserved,
/// absent, `off`, or written inline, [`Sink::holding`]) not waited for, and
/// at once for a token past every entry retained, one of an earlier logd
/// instance's; pending otherwise, with the entries' expected time as the
/// retry hint.
fn flush_answer(token: Option<u64>) -> FlushAnswer
{
    let (token, next, behind, holding) = {
        let st = state();
        let next = st.table.history().next_seq();
        let holding = st.holding();
        let behind = SINKS
            .iter()
            .zip(&holding)
            .filter(|&(_, &holds)| holds)
            .filter_map(|(sink, _)| st.cursors.get(sink.index).map(|c| c.next))
            .min();
        drop(st);
        (token.unwrap_or(next), next, behind, holding)
    };
    match behind
    {
        Some(cursor) if cursor < token && token <= next => FlushAnswer::Pending {
            token,
            retry_ms: logd_codec::sink::hint_ms(
                token.saturating_sub(cursor),
                slowest_entry_us(holding),
            ),
        },
        _ => FlushAnswer::Flushed { token },
    }
}

/// Append `byte_len` bytes from the IPC payload onto the slot for
/// `badge`, retaining each line it completes (`\n`-terminated) in logd's
/// journal, from which the sinks write it. A line takes the level of the
/// message carrying its first byte ([`Slot::begin_byte`]).
///
/// Accepts up to `STREAM_CHUNK_SIZE = MSG_DATA_WORDS_MAX * 8` bytes
/// per call (the maximum a single `STREAM_BYTES` IPC can carry); the
/// per-line buffer is `LINE_BUF_SIZE` and force-flushes when full,
/// so a chunk longer than `LINE_BUF_SIZE` produces multiple
/// lines rather than truncated output (matches init-logd's behaviour).
///
/// The message is consumed whole under the state lock, then the writers are
/// woken; no sink's write is waited for (`services/logd/docs/ipc-interface.md`
/// § Receive pool).
///
/// Answers 0; `NAME_UNKNOWN` for a message that carries `SENDER_NAMED` from a
/// sender whose name logd does not hold ([`SlotTable::name_lost`]), so its
/// sender registers the name and sends the message again
/// (`services/logd/docs/ipc-interface.md` § `stream_labels::STREAM_REGISTER_NAME`);
/// or `WINDOW_FULL` for a message past the sender's window
/// ([`window_refusal`]). Nothing is consumed of a refused message.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` and the `history` borrow through the guard to the end of the \
              byte loop: the hold serialises the slot's partial line and the history"
)]
fn consume_bytes(logd: &Logd, badge: u64, msg: &IpcMessage, byte_len: usize) -> Consumed
{
    const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(STREAM_CHUNK_SIZE);
    let level = level_of(msg.label);
    let text = bytes.get(..n).unwrap_or_default();
    {
        let mut st = logd.lock();
        if sender_named(msg.label) && st.table.name_lost(badge)
        {
            return Consumed::Status(NAME_UNKNOWN);
        }
        let lines = lines_completed(st.table.partial_len(badge), text);
        if let Some(refused) = window_refusal(&st, badge, lines, level)
        {
            return refused;
        }
        let Some((slot, history)) = st.table.sender_slot(badge)
        else
        {
            // An evicted sender's message (`SlotTable::sender_slot`):
            // dropped, and answered as consumed.
            return Consumed::Status(0);
        };
        for &b in text
        {
            slot.begin_byte(level);
            if b == b'\n'
            {
                flush_partial(slot, history, badge);
            }
            else if slot.partial.len() < LINE_BUF_SIZE
            {
                slot.partial.push(b);
                if slot.partial.len() == LINE_BUF_SIZE
                {
                    flush_partial(slot, history, badge);
                }
            }
        }
    }
    retained();
    Consumed::Status(0)
}

/// Retain one `STREAM_RECORD` message's record in the slot's history, with
/// its field table, under the state lock, then wake the writers. The record
/// does not touch the slot's partial text line. Answers `RECORD_ACCEPTED`;
/// `RECORD_REJECTED` for a payload longer than a record or than the message,
/// or one `ipc::log_record` refuses, which is not retained; or
/// `NAME_UNKNOWN` or `WINDOW_FULL`, of a record not retained either, as
/// [`consume_bytes`] answers.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the sender's `slot` and the `history` borrow through the guard to the record's \
              retention: the hold serialises the slot's name and the history"
)]
fn consume_record(logd: &Logd, badge: u64, msg: &IpcMessage, byte_len: usize) -> Consumed
{
    let bytes = msg.data_bytes();
    if byte_len > RECORD_MAX_BYTES || byte_len > bytes.len()
    {
        return Consumed::Status(RECORD_REJECTED);
    }
    let Some(Ok(record)) = bytes.get(..byte_len).map(Record::decode)
    else
    {
        return Consumed::Status(RECORD_REJECTED);
    };
    let level = level_of(msg.label);
    {
        let mut st = logd.lock();
        if sender_named(msg.label) && st.table.name_lost(badge)
        {
            return Consumed::Status(NAME_UNKNOWN);
        }
        if let Some(refused) = window_refusal(&st, badge, 1, level)
        {
            return refused;
        }
        let Some((slot, history)) = st.table.sender_slot(badge)
        else
        {
            // An evicted sender's record (`SlotTable::sender_slot`): dropped,
            // and answered as consumed, since nothing is wrong with it.
            return Consumed::Status(RECORD_ACCEPTED);
        };
        let _ = history.push_record(slot, badge, elapsed_us(), level, &record);
    }
    retained();
    Consumed::Status(RECORD_ACCEPTED)
}

/// Retain the in-progress line of `slot`, the slot of sender `badge`, in
/// `history`, and clear the partial buffer.
fn flush_partial(slot: &mut Slot, history: &mut History, badge: u64)
{
    let line = std::mem::take(&mut slot.partial);
    let level = slot.partial_level;
    let _ = history.push_text(slot, badge, elapsed_us(), level, &line);
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
        self_log("klog: no KernelLog capability");
        return;
    }
    let Some(ntf) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
    else
    {
        self_log("klog: notification create failed");
        return;
    };
    if let Err(e) = syscall::kernel_log_bind(cap, ntf, KERNEL_LOG_BIT)
    {
        let _ = syscall::cap_delete(ntf);
        self_log(logd_codec::kernel::failed_text("bind", e).as_str());
        return;
    }
    let spawned = std::thread::Builder::new().spawn(move || read_kernel_log(cap, ntf, logd));
    if spawned.is_err()
    {
        // The notification's deletion clears the binding.
        let _ = syscall::cap_delete(ntf);
        self_log("klog: reader spawn failed");
    }
}

/// The boot wall offset (`services/logd/docs/sinks.md` § Wall time): the
/// wall time, microseconds since 1970-01-01T00:00:00Z, less the uptime of
/// the same instant; `u64::MAX` while it is not known. Set once, by
/// [`read_wall_clock`].
static WALL_OFFSET: AtomicU64 = AtomicU64::new(u64::MAX);

/// The wall time of uptime `us`, `None` while the boot wall offset is not
/// known.
fn wall_of(us: u64) -> Option<u64>
{
    let offset = WALL_OFFSET.load(Ordering::Acquire);
    (offset != u64::MAX).then(|| offset.saturating_add(us))
}

/// Start the thread that reads the wall clock ([`read_wall_clock`])
/// through `timed`, the SEND of the `timed` publication. With no cap, or
/// when the thread cannot be had, the offset stays unknown and the sinks
/// show uptime.
fn start_wall_clock_reader(timed: u64)
{
    if timed == 0
    {
        return;
    }
    let spawned = std::thread::Builder::new().spawn(move || read_wall_clock(timed));
    if spawned.is_err()
    {
        let _ = syscall::cap_delete(timed);
        retain_own(LEVEL_WARN, b"wall clock reader spawn failed");
    }
}

/// Read the wall clock once through `timed` (`timed_labels::GET_WALL_TIME`,
/// with no bound), store the boot wall offset, and retain the notice that
/// names the wall time and its uptime; `WALL_CLOCK_UNAVAILABLE` leaves the
/// offset unknown and is retained at notice too. Its own thread: timed's log
/// calls are served by the receive workers, which wait on no call of
/// logd's, so the call cannot deadlock (`services/logd/docs/sinks.md`
/// § Wall time).
fn read_wall_clock(timed: u64)
{
    let ipc_buf = emit_ipc_buf();
    let msg = IpcMessage::new(ipc::timed_labels::GET_WALL_TIME);
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(timed, &msg, ipc_buf) };
    let uptime = elapsed_us();
    let _ = syscall::cap_delete(timed);
    let mut buf = SerialFmt::new();
    match reply
    {
        Ok(reply) if reply.label == ipc::timed_errors::SUCCESS =>
        {
            let wall = reply.word(0);
            WALL_OFFSET.store(wall.saturating_sub(uptime), Ordering::Release);
            let text = logd_codec::wall::wall_clock_text(wall, uptime);
            retain_own(LEVEL_NOTICE, text.as_str().as_bytes());
        }
        Ok(reply) if reply.label == ipc::timed_errors::WALL_CLOCK_UNAVAILABLE =>
        {
            retain_own(LEVEL_NOTICE, b"wall clock unavailable");
        }
        Ok(reply) =>
        {
            let _ = write!(buf, "wall clock query failed err={:#x}", reply.label);
            retain_own(LEVEL_WARN, buf.as_str().as_bytes());
        }
        Err(e) =>
        {
            let _ = write!(buf, "wall clock query failed err={e:#x}");
            retain_own(LEVEL_WARN, buf.as_str().as_bytes());
        }
    }
}

/// The kernel log reader (`docs/console-model.md` item 4): read the records
/// the kernel appended and retain each as the kernel's lines in the kernel's
/// slot (`LOG_BADGE_KERNEL`), which the sinks write as a sender's; then wait
/// for the kernel's signal. Each read acknowledges the records read before
/// it, so the reader reads again only once the `hold` sink has written their
/// lines or holds nobody ([`await_hold_passed`]): a record is acknowledged
/// once its line is on the wire or its sink stalled. A kernel line is never
/// refused. A failed read ends the thread, and the kernel writes its lines
/// itself once the records stall.
fn read_kernel_log(cap: u64, ntf: u64, logd: &Logd)
{
    let mut buf = std::vec![0u8; KERNEL_READ_BYTES];
    let mut cursor = logd_codec::kernel::Cursor::new();
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
                let mut last = None;
                for record in syscall_abi::kernel_log_records(buf.get(..n).unwrap_or_default())
                {
                    last = keep_kernel_record(&record, &mut cursor, logd).or(last);
                }
                retained();
                if let Some(seq) = last
                {
                    await_hold_passed(seq);
                }
            }
            Err(e) =>
            {
                self_log(logd_codec::kernel::failed_text("read", e).as_str());
                let _ = syscall::cap_delete(ntf);
                return;
            }
        }
    }
}

/// Retain `record` as the kernel's line, stamped with its own time, in parts
/// of at most `LINE_BUF_SIZE` bytes, each kept in the kernel's slot; a gap
/// before it is named in a warning line of logd's. The `seq` of its last
/// part; `None` for a stale record.
fn keep_kernel_record(
    record: &syscall_abi::KernelLogRecord<'_>,
    cursor: &mut logd_codec::kernel::Cursor,
    logd: &Logd,
) -> Option<u64>
{
    match cursor.accept(record.seq)
    {
        Accept::Stale => return None,
        Accept::InOrder =>
        {}
        Accept::AfterGap { first, last } =>
        {
            let text = logd_codec::kernel::gap_text(first, last);
            retain_own(LEVEL_WARN, text.as_str().as_bytes());
        }
    }
    let level = logd_codec::kernel::level(record.level);
    let line = KernelLine::new(record);
    let badge = ipc::log_badges::LOG_BADGE_KERNEL;
    let mut st = logd.lock();
    let mut last = None;
    for part in line.parts()
    {
        // The kernel's badge is no process's, so no eviction takes it and the
        // slot is always there (`SlotTable::sender_slot`).
        if let Some((slot, history)) = st.table.sender_slot(badge)
        {
            last = Some(history.push_text(slot, badge, record.us, level, part));
        }
    }
    last
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
    /// and the journal then keeps the sink's entries for the driver resolved
    /// next ([`Sink::run_writer`]).
    cap: AtomicU64,
    /// The driver's instance ordinal in its class, while `cap` is nonzero.
    /// Only the main thread reads it.
    ordinal: AtomicU64,
    /// Taken around the writer's look at `cap` and its wait, and by
    /// [`Self::resolve`] before it signals [`Self::served`], so a driver
    /// resolved between the look and the wait is not missed.
    serving: Mutex<()>,
    /// Signalled when [`Self::resolve`] has stored a driver, or none.
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

    /// Wait until the resolved SEND is no longer `gone`, whose call failed:
    /// the main thread resolves again when devmgr signals the withdrawal.
    fn await_other(&self, gone: u64)
    {
        let mut serving = self.serving.lock().unwrap_or_else(PoisonError::into_inner);
        loop
        {
            if self.cap() != gone
            {
                return;
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
        // A writer that looked at `cap` before the store waits under the
        // lock, so taking it here orders this signal after its wait began.
        drop(self.serving.lock().unwrap_or_else(PoisonError::into_inner));
        self.served.notify_all();
    }
}

/// A device sink: an output driver and the cursor through which its writer
/// thread reads logd's journal ([`Sink::run_writer`]), the only thread that
/// calls the driver once it runs, so a driver that is slow, stopped by a
/// debugger, or dead holds that thread alone
/// (`services/logd/docs/ipc-interface.md` § Output sinks). Its settings are
/// in [`LogdState::settings`].
struct Sink
{
    /// The driver, as resolved through devmgr.
    driver: OutputDriver,
    /// The driver's write label without its length: the opcode
    /// (`SERIAL_WRITE_BYTES`, `FB_WRITE_BYTES`).
    op: u64,
    /// The flag of the zero-length barrier write that ends each entry, which
    /// the driver answers once the entry has left the device
    /// (`SERIAL_WRITE_SENT`); 0 for a driver that takes none ([`write_line`]).
    sent: u64,
    /// The driver's colour label (`FB_SET_ATTRS`), which a coloured level tag
    /// is written between two calls of ([`write_coloured`]); 0 for a driver
    /// that takes none.
    attrs: u64,
    /// The sink's name in logd's lines about it.
    what: &'static str,
    /// Which sink it is: its settings' defaults and recipe key.
    kind: SinkKind,
    /// The sink's cursor in [`LogdState::cursors`] and its settings in
    /// [`LogdState::settings`].
    index: usize,
    /// Whether the writer thread runs; until it does, or when it could not be
    /// spawned, the entries are written by the thread that retains each
    /// ([`Self::write_inline`]).
    writer: AtomicBool,
    /// Whether a thread is writing the sink's entries inline, so no two
    /// write at once. A flag, not a lock held across the calls: a thread
    /// waits for it, and makes its calls, only until its deadline. The panic
    /// sink does not take it ([`panic_to_serial`]).
    inline_busy: Mutex<bool>,
    /// Signalled when an inline write ends and [`Self::inline_busy`] clears.
    inline_free: Condvar,
    /// When the writer started the entry it is writing, or the wait for the
    /// driver that replaces one whose call failed, on [`elapsed_us`]'s clock;
    /// [`NOT_WRITING`] otherwise ([`Self::holding`]).
    write_started_us: AtomicU64,
    /// How long the writer's last written entry took, in microseconds: the
    /// time per entry of a retry hint.
    entry_us: AtomicU64,
}

/// [`Sink::write_started_us`] while the writer writes nothing.
const NOT_WRITING: u64 = u64::MAX;

/// A sink's place in the journal, under the state lock.
#[derive(Clone, Copy, Default)]
struct Cursor
{
    /// The `seq` of the next entry the sink writes or passes: every entry
    /// before it is written, passed, or dropped.
    next: u64,
    /// The entry the sink's writer has copied and is writing, whose eviction
    /// is no drop of the sink's ([`Mark::taken`]).
    taken: Option<u64>,
    /// The `seq` after the last emergency entry the sink moved past: its next
    /// emergency walk looks back no further, so no entry is walked twice.
    walked: u64,
    /// The [`Self::walked`] the emergency entry being written sets once the
    /// sink moves past it ([`Sink::advance`]); an entry a driver lost with
    /// its endpoint is taken, and walked, again for the next driver.
    walk_end: Option<u64>,
    /// Entries the sink has dropped and not yet reported.
    dropped: u64,
    /// A `skip` sink's drop notice the journal holds and the sink has not
    /// reached: its `seq` and the count it names, which later drops are added
    /// to, so the notices do not multiply.
    notice: Option<(u64, u64)>,
}

/// What a sink's writer does next ([`Sink::next`]).
enum Step
{
    /// Nothing is left above the cursor.
    Idle,
    /// Write the line naming this many dropped entries to the sink's own
    /// output, in these settings: a `hold` sink's drops, before the next
    /// entry it writes.
    Drops(u64, SinkSettings),
    /// Write the entries of the writer's [`Walk`], then the entry of this
    /// `seq`, copied into the writer's [`Taken`].
    Entry(u64),
}

/// An entry a writer copied out of the journal under the state lock, to
/// render outside it, with the settings of its sink at the copy.
struct Taken
{
    us: u64,
    level: u64,
    badge: u64,
    record: bool,
    bytes: [u8; ENTRY_MAX_BYTES],
    len: usize,
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    settings: SinkSettings,
}

impl Taken
{
    const fn new() -> Self
    {
        Self {
            us: 0,
            level: 0,
            badge: 0,
            record: false,
            bytes: [0; ENTRY_MAX_BYTES],
            len: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            settings: SinkKind::Serial.defaults(),
        }
    }

    /// Copy `entry`, to be rendered under `name` in `settings`.
    fn copy(&mut self, entry: &HistoryEntry, name: &[u8], settings: SinkSettings)
    {
        self.us = entry.us;
        self.level = entry.level;
        self.badge = entry.badge;
        self.record = matches!(entry.kind, logd_slot_table::EntryKind::Record { .. });
        self.len = copy_into(&mut self.bytes, &entry.bytes);
        self.name_len = copy_into(&mut self.name, name);
        self.settings = settings;
    }

    /// Render the entry as its sink's line into `out`, in place of what it
    /// held ([`render_line`]).
    fn render(&self, out: &mut LineBuf) -> Option<Tag>
    {
        out.clear();
        let entry = logd_codec::console::Entry {
            us: self.us,
            wall: wall_of(self.us),
            level: self.level,
            badge: self.badge,
            name: self.name.get(..self.name_len).unwrap_or_default(),
            host: HOST.get().map(HostName::as_bytes),
        };
        let bytes = self.bytes.get(..self.len).unwrap_or_default();
        let body = if self.record
        {
            Body::Record(bytes)
        }
        else
        {
            Body::Text(bytes)
        };
        render_line(&self.settings, &entry, body, out)
    }
}

/// The `seq`s of the entries an emergency walk writes before the emergency
/// entry, oldest first (`services/logd/docs/sinks.md` § Device sinks).
struct Walk
{
    seqs: [u64; BACKLOG_MAX as usize],
    len: usize,
}

impl Walk
{
    const fn new() -> Self
    {
        Self {
            seqs: [0; BACKLOG_MAX as usize],
            len: 0,
        }
    }

    /// The walk back from the emergency entry `seq` in `history`: the last
    /// `settings.backlog` entries before it, at or after `walked`, that the
    /// sink in `settings` has not written and writes before it
    /// ([`SinkSettings::walks`]).
    fn collect(&mut self, history: &History, seq: u64, walked: u64, settings: &SinkSettings)
    {
        let backlog = usize::from(settings.backlog).min(self.seqs.len());
        self.len = self.seqs.get_mut(..backlog).map_or(0, |out| {
            history.walk_back(
                seq,
                walked,
                |entry| settings.walks(entry.level, entry.origin == Origin::Relayed),
                out,
            )
        });
    }

    /// The walk's `seq`s, oldest first.
    fn seqs(&self) -> &[u64]
    {
        self.seqs.get(..self.len).unwrap_or_default()
    }
}

/// What a line shows as its message: a text line's bytes or a record's
/// payload.
#[derive(Clone, Copy)]
enum Body<'a>
{
    Text(&'a [u8]),
    Record(&'a [u8]),
}

impl Body<'_>
{
    /// Write the message: a text line's bytes with each `\n` written `\r\n`,
    /// or a record's rendering (`logd_codec::record::render`).
    fn write(self, out: &mut dyn FnMut(u8))
    {
        match self
        {
            Self::Text(bytes) =>
            {
                for &b in bytes
                {
                    if b == b'\n'
                    {
                        out(b'\r');
                    }
                    out(b);
                }
            }
            Self::Record(bytes) =>
            {
                // A record is retained only once it decodes.
                if let Ok(record) = Record::decode(bytes)
                {
                    logd_codec::record::render(&record, out);
                }
            }
        }
    }
}

/// Where a line's level tag is and the colours it is drawn in
/// ([`write_coloured`]).
#[derive(Clone, Copy)]
struct Tag
{
    start: usize,
    end: usize,
    colour: logd_codec::level::TagColour,
}

// The default colours a line is drawn in and a tag's colour is reset to are
// the terminal's, so a log line leaves the terminal's colours as it found them.
const _: () = assert!(
    logd_codec::level::DEFAULT_COLOUR.fg == ansi::DEFAULT_FG
        && logd_codec::level::DEFAULT_COLOUR.bg == ansi::DEFAULT_BG
);

/// Render `entry` with message `body` as one line in `settings`' format
/// (`logd_codec::console`, `logd_codec::rfc5424`) into `out`, ending it with
/// `\r\n`. The level tag to colour, when the settings colour it and its
/// colours are not the default ones.
fn render_line(
    settings: &SinkSettings,
    entry: &logd_codec::console::Entry<'_>,
    body: Body<'_>,
    out: &mut LineBuf,
) -> Option<Tag>
{
    let span = match settings.format
    {
        Format::Console => logd_codec::console::write(
            &settings.fields,
            settings.time,
            entry,
            &mut |b| out.push(b),
            |w| {
                body.write(w);
            },
        ),
        Format::Rfc5424 =>
        {
            logd_codec::rfc5424::write(entry, settings.facility, &mut |b| out.push(b), |w| {
                body.write(w);
            });
            None
        }
    };
    out.push(b'\r');
    out.push(b'\n');
    let colour = logd_codec::level::colour(entry.level);
    span.filter(|_| settings.colour == Colour::On && colour != logd_codec::level::DEFAULT_COLOUR)
        .map(|(start, end)| Tag { start, end, colour })
}

/// Copy as much of `src` as fits into `dst`; the bytes copied.
fn copy_into(dst: &mut [u8], src: &[u8]) -> usize
{
    for (d, s) in dst.iter_mut().zip(src)
    {
        *d = *s;
    }
    src.len().min(dst.len())
}

/// [`SINK_STALL_MS`] from now: the end of an inline write.
fn stall_deadline() -> Instant
{
    let now = Instant::now();
    now.checked_add(Duration::from_millis(u64::from(SINK_STALL_MS)))
        .unwrap_or(now)
}

impl Sink
{
    const fn new(
        op: u64,
        sent: u64,
        attrs: u64,
        what: &'static str,
        kind: SinkKind,
        index: usize,
    ) -> Self
    {
        Self {
            driver: OutputDriver::new(),
            op,
            sent,
            attrs,
            what,
            kind,
            index,
            writer: AtomicBool::new(false),
            inline_busy: Mutex::new(false),
            inline_free: Condvar::new(),
            write_started_us: AtomicU64::new(NOT_WRITING),
            entry_us: AtomicU64::new(0),
        }
    }

    /// Whether the sink holds senders, a flush and the kernel reader now, in
    /// `settings`: a `hold` sink not `off` whose class the bootstrap carried,
    /// whose writer runs and is served, and whose current write is not older
    /// than [`SINK_STALL_MS`]. A sink that is stalled, unserved, absent,
    /// `off`, or written inline holds nobody.
    fn holding(&self, settings: &SinkSettings) -> bool
    {
        if settings.pace != Pace::Hold
            || settings.level.is_none()
            || self.driver.class() == 0
            || !self.writer.load(Ordering::Acquire)
            || self.driver.cap() == 0
        {
            return false;
        }
        let started = self.write_started_us.load(Ordering::Relaxed);
        !logd_codec::sink::write_overdue((started != NOT_WRITING).then_some(started), elapsed_us())
    }

    /// The writer's next step from its cursor, under the state lock `st`
    /// ([`Self::step`]), then the sink's mark moved with the cursor, and the
    /// kernel reader woken when the cursor passed entries.
    fn next(&self, st: &mut LogdState, taken: &mut Taken, walk: &mut Walk) -> Step
    {
        let before = st.cursors.get(self.index).map(|c| c.next);
        let step = self.step(st, taken, walk);
        st.sync_marks();
        if st.cursors.get(self.index).map(|c| c.next) != before
        {
            PROGRESS.notify_all();
        }
        step
    }

    /// The writer's next step from its cursor: take the drops the history
    /// counted for the sink, pass the entries it does not show (below its
    /// level, or `relayed` ones it passes), report drops (a `hold` sink's
    /// before the next entry it writes, a `skip` sink's as its notice in the
    /// journal, [`retain_notice`], which wakes the writers), and copy the
    /// next entry it shows into `taken`, and for an emergency entry the
    /// walk back before it into `walk`. An `off` sink's cursor follows the
    /// newest entry, and it counts no drops.
    fn step(&self, st: &mut LogdState, taken: &mut Taken, walk: &mut Walk) -> Step
    {
        let LogdState {
            table,
            cursors,
            settings,
            ..
        } = st;
        let (Some(cursor), Some(&settings)) =
            (cursors.get_mut(self.index), settings.get(self.index))
        else
        {
            return Step::Idle;
        };
        if settings.level.is_none()
        {
            cursor.next = table.history().next_seq();
            cursor.taken = None;
            cursor.walk_end = None;
            cursor.dropped = 0;
            return Step::Idle;
        }
        cursor.dropped = cursor
            .dropped
            .saturating_add(table.history_mut().take_evicted(self.index));
        let mut found = None;
        while let Some((seq, entry)) = table.history().entry_from(cursor.next)
        {
            cursor.next = seq;
            if cursor.dropped > 0 && settings.pace == Pace::Hold
            {
                return Step::Drops(core::mem::take(&mut cursor.dropped), settings);
            }
            if !settings.shows(entry.level, entry.origin == Origin::Relayed)
            {
                cursor.next = seq.saturating_add(1);
                continue;
            }
            taken.copy(entry, table.name_of(entry.badge), settings);
            found = Some(seq);
            break;
        }
        let Some(seq) = found
        else
        {
            if cursor.dropped > 0 && settings.pace == Pace::Skip
            {
                retain_notice(self.what, cursor, table);
                RETAINED.notify_all();
            }
            return Step::Idle;
        };
        cursor.taken = Some(seq);
        walk.len = 0;
        if level_or_info(taken.level) == LEVEL_EMERGENCY
        {
            walk.collect(table.history(), seq, cursor.walked, &settings);
            cursor.walk_end = Some(seq.saturating_add(1));
        }
        if cursor.dropped > 0
        {
            retain_notice(self.what, cursor, table);
        }
        Step::Entry(seq)
    }

    /// Move the cursor past entry `seq`, counting it as dropped when the
    /// driver did not take it whole (`wrote`), and move the sink's mark with
    /// it.
    fn advance(&self, seq: u64, wrote: Wrote)
    {
        {
            let mut st = state();
            if let Some(cursor) = st.cursors.get_mut(self.index)
            {
                cursor.next = cursor.next.max(seq.saturating_add(1));
                cursor.taken = None;
                if let Some(end) = cursor.walk_end.take()
                {
                    cursor.walked = cursor.walked.max(end);
                }
                cursor.dropped = cursor
                    .dropped
                    .saturating_add(u64::from(wrote != Wrote::All));
            }
            st.sync_marks();
        }
        PROGRESS.notify_all();
    }

    /// Give up the entry the writer copied, which a driver lost with its
    /// endpoint: the writer takes it again from the journal for the next
    /// driver, and its eviction meanwhile is the sink's drop.
    fn release_taken(&self)
    {
        let mut st = state();
        if let Some(cursor) = st.cursors.get_mut(self.index)
        {
            cursor.taken = None;
            cursor.walk_end = None;
        }
        st.sync_marks();
    }

    /// The writer thread: wait until the sinks open and a driver is served,
    /// take each entry above the cursor that the sink shows, in `seq` order,
    /// render it outside every lock, and write it with calls that have no
    /// bound ([`write_line`]), so an entry is written once, when the driver
    /// answers, however long it is stopped. Before an emergency entry it
    /// writes the entries of its walk back ([`Walk`]). A `skip` sink's cursor
    /// starts at most its `backlog` behind the newest entry each time a
    /// driver comes up ([`Self::attach`]). An entry the driver lost with its
    /// endpoint is written again, whole, to the driver resolved next; until
    /// one is, the sink counts as writing it, so it stalls past
    /// [`SINK_STALL_MS`].
    fn run_writer(&self) -> !
    {
        let ipc_buf = emit_ipc_buf();
        let mut taken = Taken::new();
        let mut context = Taken::new();
        let mut walk = Walk::new();
        let mut out = LineBuf::new();
        let mut held = 0u64;
        loop
        {
            let cap = self.driver.await_cap();
            if cap != held
            {
                held = cap;
                self.attach();
            }
            let step = {
                let mut st = state();
                loop
                {
                    if st.open
                    {
                        match self.next(&mut st, &mut taken, &mut walk)
                        {
                            Step::Idle =>
                            {}
                            step @ (Step::Drops(..) | Step::Entry(_)) => break step,
                        }
                    }
                    st = RETAINED.wait(st).unwrap_or_else(PoisonError::into_inner);
                }
            };
            // A drop notice the step retained is another sink's to write.
            RETAINED.notify_all();
            match step
            {
                Step::Idle =>
                {}
                Step::Drops(dropped, settings) =>
                {
                    let tag = drop_line(self.what, dropped, &settings, &mut out);
                    let _ = self.write_driver(cap, &out, tag, ipc_buf);
                }
                Step::Entry(seq) =>
                {
                    let walked = Self::write_walk(
                        &walk,
                        &taken.settings,
                        &mut context,
                        &mut out,
                        |line, tag| self.write_driver(cap, line, tag, ipc_buf),
                    );
                    let wrote = if walked == Wrote::Gone
                    {
                        Wrote::Gone
                    }
                    else
                    {
                        let tag = taken.render(&mut out);
                        self.write_driver(cap, &out, tag, ipc_buf)
                    };
                    match wrote
                    {
                        Wrote::All | Wrote::Lost => self.advance(seq, wrote),
                        Wrote::Gone =>
                        {
                            self.release_taken();
                            self.write_started_us.store(elapsed_us(), Ordering::Relaxed);
                            self.driver.await_other(cap);
                            self.write_started_us.store(NOT_WRITING, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }

    /// Write the entries of `walk` the journal still holds, each copied into
    /// `context` under the state lock and rendered in `settings` into `out`
    /// outside it,
    /// through `write`; `Wrote::Gone` once a write finds the driver gone,
    /// which ends the walk.
    fn write_walk(
        walk: &Walk,
        settings: &SinkSettings,
        context: &mut Taken,
        out: &mut LineBuf,
        mut write: impl FnMut(&LineBuf, Option<Tag>) -> Wrote,
    ) -> Wrote
    {
        for &seq in walk.seqs()
        {
            let held = {
                let st = state();
                match st.table.history().entry_from(seq)
                {
                    Some((at, entry)) if at == seq =>
                    {
                        context.copy(entry, st.table.name_of(entry.badge), *settings);
                        true
                    }
                    _ => false,
                }
            };
            if !held
            {
                continue;
            }
            let tag = context.render(out);
            if write(out, tag) == Wrote::Gone
            {
                return Wrote::Gone;
            }
        }
        Wrote::All
    }

    /// A driver came up: a `skip` sink's cursor starts at most its `backlog`
    /// entries before the newest ([`logd_codec::sink::attach_cursor`]), the
    /// entries passed that it shows counted as dropped.
    fn attach(&self)
    {
        let mut st = state();
        {
            let LogdState {
                table,
                cursors,
                settings,
                ..
            } = &mut *st;
            let (Some(cursor), Some(settings)) =
                (cursors.get_mut(self.index), settings.get(self.index))
            else
            {
                return;
            };
            if settings.pace != Pace::Skip || settings.level.is_none()
            {
                return;
            }
            let next = table.history().next_seq();
            let start =
                logd_codec::sink::attach_cursor(cursor.next, next, u64::from(settings.backlog));
            let passed = table
                .history()
                .between(cursor.next, start)
                .filter(|(_, entry)| settings.shows(entry.level, entry.origin == Origin::Relayed))
                .count();
            cursor.dropped = cursor.dropped.saturating_add(passed as u64);
            cursor.next = cursor.next.max(start);
        }
        st.sync_marks();
    }

    /// The writer's write of `line` to the driver behind `cap`, its level tag
    /// coloured when `tag` says so ([`write_coloured`]), unbounded, timed for
    /// [`Self::holding`] and the retry hint.
    fn write_driver(&self, cap: u64, line: &LineBuf, tag: Option<Tag>, ipc_buf: *mut u64) -> Wrote
    {
        if ipc_buf.is_null()
        {
            return Wrote::Lost;
        }
        let started = elapsed_us();
        self.write_started_us.store(started, Ordering::Relaxed);
        let wrote = self.write_coloured(cap, line.bytes(), tag, ipc_buf, Bound::Unbounded);
        self.write_started_us.store(NOT_WRITING, Ordering::Relaxed);
        if wrote == Wrote::All
        {
            self.entry_us
                .store(elapsed_us().saturating_sub(started), Ordering::Relaxed);
        }
        wrote
    }

    /// Write `bytes`, one line, to the driver behind `cap` ([`write_line`]),
    /// with the level tag `tag` names drawn in its colours on a driver that
    /// takes colour: the bytes before the tag, the colours
    /// ([`Sink::attrs`]), the tag, the default colour, then the rest, so a
    /// terminal's colour is reset by the line
    /// (`services/logd/docs/sinks.md` § Colour). Every call is bounded by
    /// `bound`; the first that does not succeed ends the write.
    fn write_coloured(
        &self,
        cap: u64,
        bytes: &[u8],
        tag: Option<Tag>,
        ipc_buf: *mut u64,
        bound: Bound,
    ) -> Wrote
    {
        let parts = tag.filter(|_| self.attrs != 0).and_then(|tag| {
            Some((
                bytes.get(..tag.start)?,
                bytes.get(tag.start..tag.end)?,
                bytes.get(tag.end..)?,
                tag.colour,
            ))
        });
        let Some((head, text, tail, colour)) = parts
        else
        {
            return write_line(cap, self.op, self.sent, bytes, ipc_buf, bound);
        };
        let attrs = |colour: logd_codec::level::TagColour| {
            let [r, g, b] = ansi::ansi_rgb(colour.fg);
            let [br, bg, bb] = ansi::ansi_rgb(colour.bg);
            [r, g, b, br, bg, bb]
        };
        let steps = [
            write_line(cap, self.op, 0, head, ipc_buf, bound),
            call_step(
                cap,
                self.attrs,
                &attrs(colour),
                ipc_buf,
                bound,
                Step2::Chunk,
            ),
        ];
        if let Some(&failed) = steps.iter().find(|&&w| w != Wrote::All)
        {
            return failed;
        }
        let wrote = write_line(cap, self.op, 0, text, ipc_buf, bound);
        // The default colour is set back whatever became of the tag.
        let reset = call_step(
            cap,
            self.attrs,
            &attrs(logd_codec::level::DEFAULT_COLOUR),
            ipc_buf,
            bound,
            Step2::Chunk,
        );
        if wrote != Wrote::All
        {
            return wrote;
        }
        if reset != Wrote::All
        {
            return reset;
        }
        write_line(cap, self.op, self.sent, tail, ipc_buf, bound)
    }

    /// Write the entries above the cursor from the calling thread, for a sink
    /// with no writer, with no other inline write between its calls
    /// ([`Self::inline_busy`]): the wait for that turn and every call end
    /// [`SINK_STALL_MS`] from now, so the caller waits on the sink for that
    /// long at most. An entry the driver did not take whole is passed and
    /// counted as dropped. Nothing is written before the sinks open, or while
    /// no driver is resolved: the entries wait in the journal for the next
    /// inline write.
    fn write_inline(&self)
    {
        let ipc_buf = emit_ipc_buf();
        if ipc_buf.is_null() || self.driver.class() == 0 || self.writer.load(Ordering::Acquire)
        {
            return;
        }
        let deadline = stall_deadline();
        if !self.take_inline_turn(deadline)
        {
            return;
        }
        let bound = Bound::By(deadline);
        let mut taken = Taken::new();
        let mut context = Taken::new();
        let mut walk = Walk::new();
        let mut out = LineBuf::new();
        while bound.next_ms().is_some()
        {
            let cap = self.driver.cap();
            if cap == 0
            {
                break;
            }
            let step = {
                let mut st = state();
                if !st.open
                {
                    break;
                }
                let step = self.next(&mut st, &mut taken, &mut walk);
                drop(st);
                step
            };
            RETAINED.notify_all();
            match step
            {
                Step::Idle => break,
                Step::Drops(dropped, settings) =>
                {
                    let tag = drop_line(self.what, dropped, &settings, &mut out);
                    let _ = self.write_coloured(cap, out.bytes(), tag, ipc_buf, bound);
                }
                Step::Entry(seq) =>
                {
                    let _ = Self::write_walk(
                        &walk,
                        &taken.settings,
                        &mut context,
                        &mut out,
                        |line, tag| self.write_coloured(cap, line.bytes(), tag, ipc_buf, bound),
                    );
                    let tag = taken.render(&mut out);
                    let wrote = self.write_coloured(cap, out.bytes(), tag, ipc_buf, bound);
                    self.advance(seq, wrote);
                }
            }
        }
        *self
            .inline_busy
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = false;
        self.inline_free.notify_one();
    }

    /// Wait until no other thread writes the sink inline, then take the turn;
    /// `false` when `deadline` passes first.
    fn take_inline_turn(&self, deadline: Instant) -> bool
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
                return false;
            }
            busy = self
                .inline_free
                .wait_timeout(busy, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *busy = true;
        true
    }
}

/// Retain a `skip` sink's drops as a notice line of logd's in the journal,
/// so every sink and the history carry the count: add `cursor`'s count to the
/// sink's notice while the journal still holds it ahead of the cursor, and
/// otherwise retain a new one, carrying the count of a notice evicted before
/// the sink reached it (`services/logd/docs/sinks.md` § Drops).
fn retain_notice(what: &str, cursor: &mut Cursor, table: &mut SlotTable)
{
    let dropped = core::mem::take(&mut cursor.dropped);
    let (pending, total) = match cursor.notice
    {
        Some((seq, count)) if seq >= cursor.next =>
        {
            let held = table
                .history()
                .entry_from(seq)
                .is_some_and(|(at, _)| at == seq);
            (held.then_some(seq), count.saturating_add(dropped))
        }
        _ => (None, dropped),
    };
    let text = logd_codec::sink::drop_text(what, total);
    let seq = if let Some(seq) = pending
    {
        table
            .history_mut()
            .replace_text(seq, text.as_str().as_bytes());
        seq
    }
    else
    {
        let Some((slot, history)) = table.sender_slot(LOG_BADGE_LOGD)
        else
        {
            return;
        };
        history.push_text(
            slot,
            LOG_BADGE_LOGD,
            elapsed_us(),
            LEVEL_NOTICE,
            text.as_str().as_bytes(),
        )
    };
    cursor.notice = Some((seq, total));
}

/// Build in `line` the line naming `dropped` entries sink `what` did not
/// write, as logd's notice, stamped now, in the sink's `settings`; its tag to
/// colour (`services/logd/docs/sinks.md` § Drops).
fn drop_line(what: &str, dropped: u64, settings: &SinkSettings, line: &mut LineBuf) -> Option<Tag>
{
    let text = logd_codec::sink::drop_text(what, dropped);
    line.clear();
    let us = elapsed_us();
    let entry = logd_codec::console::Entry {
        us,
        wall: wall_of(us),
        level: LEVEL_NOTICE,
        badge: LOG_BADGE_LOGD,
        name: b"logd",
        host: HOST.get().map(HostName::as_bytes),
    };
    render_line(settings, &entry, Body::Text(text.as_str().as_bytes()), line)
}

/// The serial driver. Each entry's write ends with a barrier the driver
/// answers once its bytes have left the UART (`SERIAL_WRITE_SENT`,
/// [`write_line`]), so its cursor passes an entry only once the entry is on
/// the wire (`services/logd/docs/sinks.md` § Device sinks). By default a
/// `hold` sink at informational that passes the `relayed` entries
/// init-logd wrote to the UART itself.
static SERIAL: Sink = Sink::new(
    ipc::serial_labels::SERIAL_WRITE_BYTES,
    ipc::serial_labels::SERIAL_WRITE_SENT,
    0,
    "serial",
    SinkKind::Serial,
    0,
);
/// The framebuffer driver, which takes colour (`FB_SET_ATTRS`). By default a
/// `skip` sink at critical that shows `relayed` entries in its backlog. A
/// headless boot runs none, so the sink stays unserved and writes nothing.
static FB: Sink = Sink::new(
    ipc::fb_labels::FB_WRITE_BYTES,
    0,
    ipc::fb_labels::FB_SET_ATTRS,
    "framebuffer",
    SinkKind::Framebuffer,
    1,
);

/// Every device sink, in [`LogdState::cursors`]' order.
static SINKS: [&Sink; MARKS] = [&SERIAL, &FB];

/// Maximum payload bytes per `SERIAL_WRITE_BYTES` or `FB_WRITE_BYTES` (one
/// full IPC data area).
const SERIAL_CHUNK: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// The calling thread's registered IPC buffer, for the sink calls: the main
/// thread, each receive worker, the resync helper, the kernel log reader and
/// each writer own one, so a call from any thread (the panic sink included)
/// uses its own page (`docs/ipc-design.md` § Multi-threaded servers). Null
/// before the thread has one; the caller then drops the bytes.
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
/// class the bootstrap carried. A sink whose writer cannot be spawned is
/// written by the threads that retain entries ([`Sink::write_inline`]).
fn spawn_writers()
{
    for sink in SINKS
    {
        if sink.driver.class() == 0
        {
            continue;
        }
        let spawned = std::thread::Builder::new().spawn(move || {
            sink.run_writer();
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

/// Open the sinks: from now on their writers, or the inline writes, write
/// the journal. Called once init-logd has acknowledged the handover release
/// and writes the UART no more, at once on a restart, and on a halt.
fn open_output()
{
    state().open = true;
    RETAINED.notify_all();
    write_inline_sinks();
}

/// After an entry is retained: wake the writers, and write the sinks that
/// have none inline. Called with the state lock released.
fn retained()
{
    RETAINED.notify_all();
    write_inline_sinks();
}

/// Write each sink that has no writer thread inline ([`Sink::write_inline`]).
fn write_inline_sinks()
{
    for sink in SINKS
    {
        sink.write_inline();
    }
}

/// Wait until every holding `hold` sink's cursor has passed entry `seq`, or
/// the sink stops holding (stalled, unserved, absent, `off`): the kernel log
/// reader's wait before it acknowledges the records it retained
/// (`services/logd/docs/sinks.md` § The kernel's lines).
fn await_hold_passed(seq: u64)
{
    let mut st = state();
    loop
    {
        let holding = st.holding();
        let waiting = SINKS.iter().zip(holding).any(|(sink, holds)| {
            holds
                && st
                    .cursors
                    .get(sink.index)
                    .is_some_and(|cursor| cursor.next <= seq)
        });
        if !waiting
        {
            return;
        }
        // A sink's progress wakes the wait; the bound lets a write that has
        // run past the stall bound since be seen.
        st = PROGRESS
            .wait_timeout(st, Duration::from_millis(u64::from(SINK_STALL_MS)))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// How long each call of a [`write_line`] may wait for its answer.
#[derive(Clone, Copy)]
enum Bound
{
    /// No bound: the writer's calls. A `STALLED` answer is asked again.
    Unbounded,
    /// Each call for this many milliseconds: the panic sink's calls. A
    /// `STALLED` answer ends the write.
    Each(u32),
    /// Every call ending by this instant: an inline write's calls. A
    /// `STALLED` answer is asked again until then.
    By(Instant),
}

impl Bound
{
    /// The next call's bound in milliseconds (0: none), or `None` once a
    /// [`Bound::By`] instant has passed.
    fn next_ms(self) -> Option<u32>
    {
        match self
        {
            Self::Unbounded => Some(0),
            Self::Each(ms) => Some(ms),
            Self::By(deadline) =>
            {
                let left = deadline.saturating_duration_since(Instant::now());
                // Round up, so a call is never given the unbounded 0.
                let ms = left.as_micros().div_ceil(1000);
                (ms > 0).then(|| u32::try_from(ms).unwrap_or(u32::MAX))
            }
        }
    }

    /// Whether a step the driver answered `STALLED` is asked again.
    const fn repeats(self) -> bool
    {
        !matches!(self, Self::Each(_))
    }
}

/// What a driver did with an entry [`write_line`] wrote to it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrote
{
    /// The driver took every byte and, with a barrier, saw them leave the
    /// device: the entry is written.
    All,
    /// The write was given up: a call was refused with anything but
    /// `STALLED`, interrupted after the driver may have taken its bytes, not
    /// answered within its bound, or answered `STALLED` under a bound that
    /// does not ask again. The entry is not written whole, and is counted.
    Lost,
    /// A call failed: the driver's endpoint is gone, and the bytes it took
    /// with it. The entry is written again to the next driver resolved.
    Gone,
}

/// Write `bytes` to the driver behind `cap` with one plain `op` call per
/// [`SERIAL_CHUNK`] bytes, on the calling thread's page `ipc_buf`, each call
/// bounded by `bound`; then, when `sent` is not 0, with one zero-length
/// `op | sent` call, a barrier the driver answers once every byte written
/// before it has left the device. Two steps, so each of the serial driver's
/// `STALLED` answers means one thing: a chunk answered `STALLED` was not
/// appended to the transmit ring, and is written again; a barrier answered
/// `STALLED` was, and is asked again (`services/drivers/serial/README.md`
/// § Label 1). Neither is asked again under [`Bound::Each`].
fn write_line(cap: u64, op: u64, sent: u64, bytes: &[u8], ipc_buf: *mut u64, bound: Bound)
-> Wrote
{
    for chunk in bytes.chunks(SERIAL_CHUNK)
    {
        match call_step(cap, op, chunk, ipc_buf, bound, Step2::Chunk)
        {
            Wrote::All =>
            {}
            other @ (Wrote::Lost | Wrote::Gone) => return other,
        }
    }
    if sent == 0
    {
        return Wrote::All;
    }
    call_step(cap, op | sent, &[], ipc_buf, bound, Step2::Barrier)
}

/// Which step of a [`write_line`] a call is, which decides how an interrupted
/// call is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step2
{
    /// A chunk of the entry's bytes: an interrupted one may have been taken,
    /// so it is not written again.
    Chunk,
    /// The zero-length barrier, which only waits: an interrupted one is asked
    /// again.
    Barrier,
}

/// One step of [`write_line`]: the call of `chunk` with `op`, made again
/// while the driver answers `STALLED` and `bound` repeats, and, for a
/// barrier, while the call is interrupted.
fn call_step(cap: u64, op: u64, chunk: &[u8], ipc_buf: *mut u64, bound: Bound, step: Step2)
-> Wrote
{
    loop
    {
        let Some(ms) = bound.next_ms()
        else
        {
            return Wrote::Lost;
        };
        match call_chunk(cap, op, chunk, ipc_buf, ms)
        {
            Answer::Taken => return Wrote::All,
            Answer::Stalled if bound.repeats() =>
            {}
            Answer::Interrupted if step == Step2::Barrier =>
            {}
            Answer::Stalled | Answer::Refused | Answer::Unanswered | Answer::Interrupted =>
            {
                return Wrote::Lost;
            }
            Answer::Failed => return Wrote::Gone,
        }
    }
}

/// How the driver answered one [`call_chunk`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer
{
    /// Success: the driver took the call's bytes, and for a barrier saw them
    /// leave.
    Taken,
    /// The serial driver's `STALLED`: the transmitter made no progress for its
    /// stall bound.
    Stalled,
    /// Any other answer.
    Refused,
    /// No answer within the call's bound (`WouldBlock`): the driver may
    /// still be serving the call.
    Unanswered,
    /// The call was cancelled before its answer (`Interrupted`): the calling
    /// thread was stopped, or the driver received again before it replied,
    /// or its serving thread was freed. The driver may have taken the call's
    /// bytes, so a chunk interrupted is not written again, and its entry is
    /// counted rather than repeated.
    Interrupted,
    /// The call failed otherwise: the driver's endpoint is gone, which for a
    /// resolved driver means devmgr withdrew it.
    Failed,
}

/// One `op` call of `chunk` to the driver behind `cap`, bounded by
/// `timeout_ms` (0: no bound), and how the driver answered it
/// ([`write_line`] says what each answer means of the bytes).
fn call_chunk(cap: u64, op: u64, chunk: &[u8], ipc_buf: *mut u64, timeout_ms: u32) -> Answer
{
    let label = op | ((chunk.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, chunk).build();
    // SAFETY: ipc_buf is the calling thread's registered IPC buffer page. A
    // worker calls here (inline) after it has served its request, which was
    // copied out of the page as it was received, and its pending reply stays
    // bound across this call (`docs/ipc-design.md` § Multi-threaded servers).
    match unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, timeout_ms) }
    {
        Ok(reply) if reply.label == WRITE_SUCCESS => Answer::Taken,
        Ok(reply) if reply.label == ipc::serial_errors::STALLED => Answer::Stalled,
        Ok(_) => Answer::Refused,
        Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 => Answer::Unanswered,
        Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 => Answer::Interrupted,
        Err(_) => Answer::Failed,
    }
}

/// The answer to a write that the driver took: `SUCCESS` of the serial and
/// the framebuffer driver alike, which both sinks' writes compare against.
const WRITE_SUCCESS: u64 = ipc::serial_errors::SUCCESS;
const _: () = assert!(WRITE_SUCCESS == ipc::fb_errors::SUCCESS);

/// Longest frame of a line: the longer of what the console and the rfc5424
/// formats write around the message, and the line's `\r\n`.
const LINE_FRAME_MAX: usize = if logd_codec::console::FRAME_MAX > logd_codec::rfc5424::HEADER_MAX
{
    logd_codec::console::FRAME_MAX
}
else
{
    logd_codec::rfc5424::HEADER_MAX
} + 2;

/// Bytes of a [`LineBuf`]: the frame of any logd line with its longest
/// message, a rendered record ([`RENDERED_MAX_BYTES`]), which is longer than
/// any text line, its `\n`s written `\r\n` or each of its bytes escaped
/// `\xNN` in the rfc5424 format (four times `LINE_BUF_SIZE`), so no line is
/// cut.
const LINE_OUT_BYTES: usize = LINE_FRAME_MAX + RENDERED_MAX_BYTES;

const _: () = assert!(RENDERED_MAX_BYTES >= 4 * LINE_BUF_SIZE);

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

    /// Empty the line, to build the next in its place.
    fn clear(&mut self)
    {
        self.len = 0;
    }

    /// The line as pushed so far.
    fn bytes(&self) -> &[u8]
    {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

/// Panic-output sink registered with std via `set_panic_sink`. Routes
/// logd's own panic / alloc-error / precondition output to the serial
/// driver — never through the log endpoint logd serves. Forwards raw bytes
/// (std frames the panic message) straight to the driver, outside the
/// journal, each call bounded by [`SINK_STALL_MS`], so a stopped driver
/// delays a panicking thread's end by that bound per call rather than for
/// good; drops them while no driver is resolved. Must stay non-allocating
/// and panic-free: it runs from the panic path, and takes no lock, so a panic
/// on a thread that holds the state lock still reaches the driver. Its calls
/// use the calling thread's own IPC buffer ([`emit_ipc_buf`]), so a panic or
/// allocation failure on any thread never touches another's.
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
        let _ = write_line(
            cap,
            SERIAL.op,
            SERIAL.sent,
            bytes,
            ipc_buf,
            Bound::Each(SINK_STALL_MS),
        );
    }
}

/// Retain `payload` as logd's own informational line, stamped when called,
/// in logd's slot (`LOG_BADGE_LOGD`), so it reaches every sink as a sender's
/// line does. logd's diagnostics take this path in place of `seraph::log!`,
/// which would self-IPC into the endpoint logd serves. A payload longer than
/// `LINE_BUF_SIZE` bytes was cut at a character boundary by its
/// [`SerialFmt`]. Must not be called with the state lock held.
fn self_log(payload: &str)
{
    retain_own(LEVEL_INFO, payload.as_bytes());
}

/// Retain the text line `text` at `level` in logd's slot, then wake the
/// writers ([`retained`]). Never refused: logd's own lines are not held to a
/// window.
fn retain_own(level: u64, text: &[u8])
{
    {
        let mut st = state();
        if let Some((slot, history)) = st.table.sender_slot(LOG_BADGE_LOGD)
        {
            let _ = history.push_text(slot, LOG_BADGE_LOGD, elapsed_us(), level, text);
        }
    }
    retained();
}

/// Self-log `payload` on the way to a halt: open the sinks first, since
/// nothing would later, so the line and those before it are written.
fn fatal(payload: &str)
{
    open_output();
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
