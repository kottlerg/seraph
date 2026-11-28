// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/logd_flood.rs

//! A log flood holds back only the senders that flood
//! (`services/logd/docs/ipc-interface.md` § Hold window).
//!
//! svctest is the probe. Between its `log-flood begin` and `log-flood end`
//! lines it makes [`PROBE_CALLS`] raw `STREAM_BYTES` calls, one every
//! [`QUIET_GAP`], with no flood, and as many again, one every [`FLOODED_GAP`],
//! while two child processes flood logd:
//!
//! - a flooder, whose [`FLOOD_THREADS`] threads, more than logd's four
//!   receive workers (`RECV_WORKERS`), log through `seraph::log!` as fast as
//!   logd takes their lines, the log client waiting out each `WINDOW_FULL`
//!   refusal's hint;
//! - a resender, which sends each line again at once when logd refuses it
//!   `WINDOW_FULL`, and must have been refused.
//!
//! On a boot with a framebuffer driver the phase also stops that driver for
//! the flooded calls: logd's `skip` framebuffer sink holds nobody, so the
//! probe's times hold with it stopped. Its default level, critical, shows
//! none of the flood's lines, so it drops none of them; the `logd_sinks`
//! phase's framebuffer-stopped case checks its drops.
//!
//! The phase requires:
//!
//! - the median of the probe's flooded calls within [`FLOODED_TO_QUIET`]
//!   times the median of its calls with no flood, where a call that waited
//!   on a sink behind the flood's lines would take the time of their writes;
//!   its slowest calls are logged, not bounded: under the flood they meet
//!   the resender's refusals at logd's state lock, whose waiter parks in
//!   steps of a millisecond (`runtime/ruststd/spin-wait`);
//! - no probe call refused: only the flooders' own lines are refused. The
//!   probe keeps within its own window: each of its two runs starts once logd
//!   has written every line it took before it, and before each call the probe
//!   holds at most `HOLD_WINDOW` - 1 lines that logd may not have written,
//!   which it learns through logd's flush barrier (`logd.flush`,
//!   `services/logd/docs/ipc-interface.md` § Flush barrier), trusting a
//!   `FLUSHED` answer only while every `hold` sink is served (`SINK_LIST`
//!   on `logd.control`), and waits for its oldest one otherwise ([`Window`]). A host that slows the serial sink, or a sink left
//!   behind by the phases before, makes the probe wait, and logd refuses a
//!   sender within its window nothing; the waits are logged, not bounded;
//! - both children still flooding when the probe's last call returns: they
//!   flood until the phase closes their stdin, at most [`FLOOD_CAP`].
//!
//! Each probe line is numbered, `log-flood t=0 n=<n> len=<len> <payload>`, and
//! the end line names them all, so the boot's `cargo xtask run --whole-lines
//! log-flood` check requires every probe line on serial whole, in `seq` order,
//! none missing (`xtask/README.md` § `--whole-lines`).

use std::collections::VecDeque;
use std::io::Read;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ipc::IpcMessage;
use ipc::log_control::{SINK_SERVED, decode_list_reply, list_request};
use ipc::log_flush::FlushAnswer;
use ipc::stream_labels::{LEVEL_INFO, STREAM_BYTES, WINDOW_FULL, level_bits};
use logd_slot_table::HOLD_WINDOW;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "logd_flood",
        run: logd_flood_phase,
    }]
}

/// The tag of the phase's whole-lines window.
const TAG: &str = "log-flood";

/// The probe's calls with no flood, and again under it.
const PROBE_CALLS: usize = 200;

/// The probe's pause between its calls with no flood: longer than the serial
/// sink takes to write a line on an idle host, so the probe seldom waits on
/// its window.
const QUIET_GAP: Duration = Duration::from_millis(10);

/// The probe's pause between its flooded calls. The serial sink writes in
/// `seq` order, so each probe line waits behind the flooders' two full
/// windows, `2 * HOLD_WINDOW` lines: with the sink taking `w` a line, the
/// probe holds `2 * HOLD_WINDOW * w / (gap - w)` lines unwritten, within its
/// window while the gap is at least `3 * w`. 30 ms keeps the probe from
/// waiting on its window up to 10 ms a line (about 8 ms on a loaded host's
/// x86_64 boot, 3 ms unloaded); past that it waits.
const FLOODED_GAP: Duration = Duration::from_millis(30);

/// The flooder's threads: logd's four receive workers (`RECV_WORKERS`) and
/// two more.
const FLOOD_THREADS: u64 = 4 + 2;

/// How long a child floods at most, when the phase does not close its stdin
/// before: past the probe's flooded calls, which take [`PROBE_CALLS`] times
/// [`FLOODED_GAP`], 6 s, with their own time and the probe's waits on its
/// window five times over.
const FLOOD_CAP: Duration = Duration::from_secs(30);

/// How long the probe waits, at most, for logd to write a line it took: past
/// logd's stall bound (`SINK_STALL_MS`), after which a stalled sink holds
/// nobody and the wait ends, and past the time a slow sink takes to write the
/// flood's windows and the probe's ahead of the line.
const WRITTEN_WITHIN: Duration = Duration::from_secs(10);

/// The probe's pause before it asks again after a `hold` sink that holds
/// nobody answered its flush: a stalled sink holds nobody for
/// `SINK_STALL_MS` or more, so the pause costs little beside it.
const UNHELD_POLL: Duration = Duration::from_millis(10);

/// How long the phase lets the children start flooding before the probe's
/// flooded calls.
const FLOOD_SETTLE: Duration = Duration::from_millis(300);

/// The median of the probe's flooded calls, at most, in medians of its calls
/// with no flood.
const FLOODED_TO_QUIET: u32 = 10;

/// The flooder's role (`crate::reentry`).
const FLOODER_ROLE: &str = "log-flooder";

/// The resender's role.
const RESENDER_ROLE: &str = "log-resender";

/// The resender's exit code when logd refused none of its lines.
const RESENDER_NEVER_REFUSED: i32 = 3;

/// The shortest numbered line's payload, in letters.
const PAYLOAD_MIN: usize = 8;

/// The payload lengths' spread above [`PAYLOAD_MIN`].
const PAYLOAD_SPREAD: usize = 40;

/// What the probe saw of its calls.
struct Probe
{
    /// Each call's time, in the order made.
    took: Vec<Duration>,
    /// The calls logd refused `WINDOW_FULL`.
    refused: usize,
    /// The wait, before the first call, for logd to write every line it had
    /// taken.
    drained: Duration,
    /// The calls made only after a wait for the probe's oldest line to be
    /// written, and those waits' time.
    waits: usize,
    waited: Duration,
}

/// The probe's lines that logd took and may not have written: before each
/// call the probe holds at most `HOLD_WINDOW` - 1 of them, so that the call
/// keeps it within its window (`services/logd/docs/ipc-interface.md`
/// § Hold window).
///
/// A line counts as written once the flush barrier answers `FLUSHED` for a
/// token taken after it while every `hold` sink not `off` is served, as
/// `SINK_LIST` reports both before and after the answer. A sink that is
/// stalled or unserved holds nobody, so logd answers a flush `FLUSHED` with
/// the sink's cursor where it was, and once it holds again the lines it
/// has not written count against their senders' windows again (§ Flush
/// barrier, Flushed). Such an answer says nothing of the window, and the
/// probe asks again. A stall that begins and ends between the two reads, a
/// few milliseconds apart, is not seen.
struct Window
{
    /// The `logd.flush` SEND.
    flush: u64,
    /// The `logd.control` SEND, which `SINK_LIST` is served on.
    control: u64,
    /// The token of a new flush made right after each such line was taken,
    /// oldest first: past the line.
    unwritten: VecDeque<u64>,
}

impl Window
{
    /// A window on `flush` and `control`, once logd has written every
    /// line it took before: the wait's time, or the failure.
    fn drained(flush: u64, control: u64) -> Result<(Self, Duration), String>
    {
        let window = Self {
            flush,
            control,
            unwritten: VecDeque::with_capacity(HOLD_WINDOW),
        };
        let start_at = Instant::now();
        let token = window.token(None)?.0;
        window.until_written(token)?;
        Ok((window, start_at.elapsed()))
    }

    /// Note a line logd has just taken.
    fn took(&mut self) -> Result<(), String>
    {
        let token = self.token(None)?.0;
        self.unwritten.push_back(token);
        Ok(())
    }

    /// Make room for one more line: while the probe holds `HOLD_WINDOW` lines
    /// that may be unwritten, wait until its oldest is written. The time
    /// waited, zero when the oldest was written already.
    fn room(&mut self) -> Result<Duration, String>
    {
        let start_at = Instant::now();
        let mut waited = false;
        while self.unwritten.len() >= HOLD_WINDOW
        {
            let Some(token) = self.unwritten.pop_front()
            else
            {
                break;
            };
            waited |= self.until_written(token)?;
        }
        Ok(
            if waited
            {
                start_at.elapsed()
            }
            else
            {
                Duration::ZERO
            },
        )
    }

    /// Ask for `token` until the lines before it are written, sleeping a
    /// pending answer's hint, or [`UNHELD_POLL`] after an answer a sink
    /// that holds nobody gave, for at most [`WRITTEN_WITHIN`]: whether it
    /// slept, or the failure.
    fn until_written(&self, token: u64) -> Result<bool, String>
    {
        let start_at = Instant::now();
        let mut slept = false;
        loop
        {
            let held_before = self.hold_sinks_served()?;
            let (_, pending_ms) = self.token(Some(token))?;
            let held_after = self.hold_sinks_served()?;
            let wait = match pending_ms
            {
                None if held_before && held_after => return Ok(slept),
                None => UNHELD_POLL,
                Some(ms) => Duration::from_millis(u64::from(ms.max(1))),
            };
            if start_at.elapsed() > WRITTEN_WITHIN
            {
                return Err(format!(
                    "logd_flood: a probe line not written within {} ms",
                    WRITTEN_WITHIN.as_millis()
                ));
            }
            std::thread::sleep(wait);
            slept = true;
        }
    }

    /// One `LOG_FLUSH` call, a new flush (`None`) or one asked again for
    /// `token`: the answer's token and, when it is pending, its retry hint
    /// in milliseconds; or the failure.
    fn token(&self, token: Option<u64>) -> Result<(u64, Option<u32>), String>
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let msg = ipc::log_flush::request(token);
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let reply =
            unsafe { ipc::ipc_call_timeout(self.flush, &msg, ipc_buf, log::LOG_CALL_TIMEOUT_MS) }
                .map_err(|e| format!("logd_flood: LOG_FLUSH not answered ({e})"))?;
        match FlushAnswer::decode(&reply)
        {
            Ok(FlushAnswer::Flushed { token }) => Ok((token, None)),
            Ok(FlushAnswer::Pending { token, retry_ms }) => Ok((token, Some(retry_ms))),
            Err(status) => Err(format!("logd_flood: LOG_FLUSH refused ({status:#x})")),
        }
    }

    /// Whether every `hold` sink not `off` is served, by one `SINK_LIST`
    /// walk, or the failure.
    fn hold_sinks_served(&self) -> Result<bool, String>
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let mut served = true;
        for index in 0u64..
        {
            let msg = list_request(index);
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            let reply = unsafe {
                ipc::ipc_call_timeout(self.control, &msg, ipc_buf, log::LOG_CALL_TIMEOUT_MS)
            }
            .map_err(|e| format!("logd_flood: SINK_LIST not answered ({e})"))?;
            let Some((sink, more)) = decode_list_reply(&reply)
                .map_err(|status| format!("logd_flood: SINK_LIST refused ({status:#x})"))?
            else
            {
                break;
            };
            let settings = String::from_utf8_lossy(sink.settings);
            let mut words = settings.split_ascii_whitespace();
            let holds = words.clone().any(|w| w == "pace=hold") && !words.any(|w| w == "level=off");
            served &= !holds || sink.state == SINK_SERVED;
            if !more
            {
                break;
            }
        }
        Ok(served)
    }
}

/// Run the probe with no flood and under it (see the module documentation).
fn logd_flood_phase(caps: &Caps)
{
    assert_ne!(caps.logd_flush, 0, "logd_flood: no logd.flush seed");
    assert_ne!(caps.logd_control, 0, "logd_flood: no logd.control seed");
    std::os::seraph::log!("{TAG} begin");
    let quiet = probe(caps, 0, QUIET_GAP).unwrap_or_else(|e| panic!("{e}"));

    let (mut flood_child, flood_stop) = spawn_flooding(FLOODER_ROLE);
    let (mut resend_child, resend_stop) = spawn_flooding(RESENDER_ROLE);
    std::thread::sleep(FLOOD_SETTLE);
    let fb = stop_framebuffer(caps.debug_authority);
    let flooded = probe(caps, PROBE_CALLS, FLOODED_GAP);
    let flooding =
        matches!(flood_child.try_wait(), Ok(None)) && matches!(resend_child.try_wait(), Ok(None));
    drop(flood_stop);
    drop(resend_stop);
    if let Some((process, threads)) = fb
    {
        super::logd_sinks::start(&threads, "framebuffer");
        super::logd_sinks::detach(caps.debug_authority, process, threads, "framebuffer");
    }
    let flooded = flooded.unwrap_or_else(|e| panic!("{e}"));
    let flood_exit = flood_child
        .wait()
        .expect("logd_flood: waiting for the flooder failed");
    let resender = resend_child
        .wait()
        .expect("logd_flood: waiting for the resender failed");
    std::os::seraph::log!(
        "{TAG} end senders=1 lines={}",
        PROBE_CALLS.saturating_mul(2)
    );
    for (seen, flood) in [(&quiet, "no"), (&flooded, "yes")]
    {
        std::os::seraph::log!(
            "logd_flood: probe window waits flood={flood} drain_ms={} waits={} wait_ms={}",
            seen.drained.as_millis(),
            seen.waits,
            seen.waited.as_millis()
        );
    }

    assert_eq!(
        flood_exit.code(),
        Some(0),
        "logd_flood: the flooder failed: {flood_exit}"
    );
    assert_ne!(
        resender.code(),
        Some(RESENDER_NEVER_REFUSED),
        "logd_flood: logd refused none of the resender's lines: no window filled"
    );
    assert_eq!(
        resender.code(),
        Some(0),
        "logd_flood: the resender failed: {resender}"
    );
    assert!(
        flooding,
        "logd_flood: a child stopped flooding before the probe's last call; raise FLOOD_CAP"
    );
    assert_eq!(
        quiet.refused.saturating_add(flooded.refused),
        0,
        "logd_flood: logd refused {} of the probe's lines with no flood and {} under it",
        quiet.refused,
        flooded.refused
    );
    let median = quantile(&quiet.took, 50);
    let slowest = quantile(&flooded.took, 100);
    std::os::seraph::log!(
        "logd_flood: probe calls with no flood: median {} us, 99th percentile {} us, slowest {} \
         us; under {FLOOD_THREADS} flooding threads and a resender: median {} us, 99th \
         percentile {} us, slowest {} us",
        median.as_micros(),
        quantile(&quiet.took, 99).as_micros(),
        quantile(&quiet.took, 100).as_micros(),
        quantile(&flooded.took, 50).as_micros(),
        quantile(&flooded.took, 99).as_micros(),
        slowest.as_micros()
    );
    let flooded_median = quantile(&flooded.took, 50);
    assert!(
        flooded_median <= median.saturating_mul(FLOODED_TO_QUIET),
        "logd_flood: the probe's median flooded call took {} us, past {FLOODED_TO_QUIET} times \
         its median of {} us with no flood",
        flooded_median.as_micros(),
        median.as_micros()
    );
}

/// Stop every thread of the framebuffer driver, when the boot has one: its
/// process and thread caps.
fn stop_framebuffer(authority: u64) -> Option<(u64, Vec<u64>)>
{
    let fb = super::crash::badge_named(authority, super::logd_sinks::FRAMEBUFFER_NAME)?;
    let threads = super::logd_sinks::attach(authority, fb, "framebuffer");
    super::logd_sinks::stop(&threads, "framebuffer");
    Some((fb, threads))
}

/// Spawn svctest in `role`, with its stdin piped: the child, and its
/// stdin, whose close tells it to stop flooding.
fn spawn_flooding(role: &str) -> (Child, ChildStdin)
{
    let mut child = Command::new("/tests/svctest")
        .arg(role)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("logd_flood: spawning the {role} failed ({e})"));
    let stdin = child
        .stdin
        .take()
        .expect("logd_flood: the child's stdin is piped");
    (child, stdin)
}

/// Make [`PROBE_CALLS`] numbered calls from `first`, one every `gap`,
/// within the probe's window, which logd's `logd.flush` and `logd.control`
/// SENDs of `caps` report ([`Window`]): what the probe saw, or the first failure. A refused
/// line is sent again after its hint, so that the console check finds it,
/// and counted. No assertion panics here, since the framebuffer driver may be
/// stopped.
fn probe(caps: &Caps, first: usize, gap: Duration) -> Result<Probe, String>
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let bound = log::LOG_CALL_TIMEOUT_MS;
    let (mut window, drained) = Window::drained(caps.logd_flush, caps.logd_control)?;
    let mut seen = Probe {
        took: Vec::with_capacity(PROBE_CALLS),
        refused: 0,
        drained,
        waits: 0,
        waited: Duration::ZERO,
    };
    for n in first..first.saturating_add(PROBE_CALLS)
    {
        let waited = window.room()?;
        if !waited.is_zero()
        {
            seen.waits = seen.waits.saturating_add(1);
            seen.waited = seen.waited.saturating_add(waited);
        }
        let len = PAYLOAD_MIN.saturating_add(n % PAYLOAD_SPREAD);
        let payload: String = (0..len)
            .map(|i| char::from(b'a'.saturating_add(u8::try_from(i % 26).unwrap_or(0))))
            .collect();
        let line = format!("{TAG} t=0 n={n} len={len} {payload}\n");
        let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
        let msg = IpcMessage::builder(label).bytes(0, line.as_bytes()).build();
        loop
        {
            let start_at = Instant::now();
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            let reply = unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, bound) }
                .map_err(|e| format!("logd_flood: probe call {n} not answered ({e})"))?;
            seen.took.push(start_at.elapsed());
            match reply.label
            {
                0 =>
                {
                    window.took()?;
                    break;
                }
                WINDOW_FULL =>
                {
                    seen.refused = seen.refused.saturating_add(1);
                    std::thread::sleep(Duration::from_millis(reply.word(0)));
                }
                other => return Err(format!("logd_flood: probe call {n} refused ({other:#x})")),
            }
        }
        std::thread::sleep(gap);
    }
    Ok(seen)
}

/// The `percent`th percentile of `took`, by the nearest rank: the median at
/// 50, the slowest at 100.
fn quantile(took: &[Duration], percent: usize) -> Duration
{
    let mut sorted = took.to_vec();
    sorted.sort_unstable();
    let rank = sorted.len().saturating_mul(percent).div_ceil(100);
    sorted
        .get(rank.saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

/// Child-mode dispatch for this module's roles (`crate::reentry`).
pub fn reentry_main(role: &str)
{
    if role == FLOODER_ROLE
    {
        flooder_main();
    }
    if role == RESENDER_ROLE
    {
        resender_main();
    }
}

/// Set once a flooding child's stdin ends, the phase's signal to stop.
static STOP: AtomicBool = AtomicBool::new(false);

/// Read this child's stdin on a thread of its own, and set [`STOP`] at its
/// end.
fn watch_stdin()
{
    std::thread::spawn(|| {
        let mut byte = [0u8; 1];
        while matches!(std::io::stdin().read(&mut byte), Ok(1..))
        {}
        STOP.store(true, Ordering::Release);
    });
}

/// Whether a child flooding since `start_at` floods on: until [`STOP`] is
/// set, for at most [`FLOOD_CAP`].
fn flooding(start_at: Instant) -> bool
{
    !STOP.load(Ordering::Acquire) && start_at.elapsed() < FLOOD_CAP
}

/// The flooder: [`FLOOD_THREADS`] threads log numbered lines through
/// `seraph::log!` while it floods ([`flooding`]).
fn flooder_main() -> !
{
    std::os::seraph::log::register_name(b"logflood");
    watch_stdin();
    let start_at = Instant::now();
    std::thread::scope(|scope| {
        for t in 0..FLOOD_THREADS
        {
            scope.spawn(move || {
                let mut n = 0u64;
                while flooding(start_at)
                {
                    std::os::seraph::log!("flood {t}.{n}");
                    n = n.saturating_add(1);
                }
            });
        }
    });
    std::process::exit(0);
}

/// The resender: while it floods ([`flooding`]), raw `STREAM_BYTES` calls of
/// numbered lines, each sent again at once while logd refuses it
/// `WINDOW_FULL`. Exits 0 once refused at least once,
/// [`RESENDER_NEVER_REFUSED`] if never, 1 on a failed call.
fn resender_main() -> !
{
    std::os::seraph::log::register_name(b"logresend");
    watch_stdin();
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let bound = log::LOG_CALL_TIMEOUT_MS;
    let start_at = Instant::now();
    let mut sent = 0u64;
    let mut refused = 0u64;
    while flooding(start_at)
    {
        let line = format!("resend {sent}\n");
        let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
        let msg = IpcMessage::builder(label).bytes(0, line.as_bytes()).build();
        loop
        {
            // SAFETY: ipc_buf is this thread's registered IPC buffer page.
            match unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, bound) }
            {
                Ok(reply) if reply.label == 0 => break,
                Ok(reply) if reply.label == WINDOW_FULL => refused = refused.saturating_add(1),
                _ => std::process::exit(1),
            }
        }
        sent = sent.saturating_add(1);
    }
    std::os::seraph::log!("{TAG}: the resender sent {sent} lines, refused {refused} times");
    std::process::exit(
        if refused > 0
        {
            0
        }
        else
        {
            RESENDER_NEVER_REFUSED
        },
    );
}
