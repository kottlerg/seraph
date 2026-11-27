// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/logd_sinks.rs

//! logd's output sinks: a sink driver that does not answer holds no log call
//! (`services/logd/docs/ipc-interface.md` § Output sinks, § Hold window), and
//! the serial and framebuffer drivers are debuggable.
//!
//! Through the debug authority svctest holds, the phase attaches to each sink
//! driver it finds by name (`LIST_PROCESSES`, `ATTACH_PROCESS`): the attach
//! must succeed, which it would not for a driver declared undebuggable
//! (`NOT_ATTACHABLE`), must not report the driver on the core path
//! (`ATTACH_FLAG_NO_CORE`), and the driver's main thread must have its
//! exception class bound, the path a fault takes to the crash service.
//!
//! Every line is a raw `STREAM_BYTES` call on svctest's own log cap, and every
//! call must be answered before half the stall bound (`SINK_STALL_MS`) has
//! passed: logd answers a line once it is retained, and no receive worker
//! waits on a sink, where a logd that wrote a line before it answered would
//! hold the call until the write ended or the stall bound passed.
//!
//! - **Serial stopped.** The phase stops every thread of the serial driver,
//!   the `hold` sink's, and sends more lines than logd has receive workers,
//!   each taken. It then sends lines until logd refuses one `WINDOW_FULL`,
//!   which it must do once svctest's lines the stopped sink has not written
//!   pass the hold window (`HOLD_WINDOW`), with a retry hint of 1 ms to the
//!   stall bound. Once the stall bound has passed the sink is stalled and
//!   holds no sender: the refused line, sent again, is taken. The last line
//!   must be in logd's history. The lines stay within svctest's share of the
//!   history (`PER_SLOT_HISTORY_MIN` at the least), so none is dropped from the console CI
//!   reads; they are written once the phase starts the driver again.
//! - **Below serial's level.** A line at debug, below the serial sink's
//!   default level of info, is retained in logd's history, which keeps every
//!   entry whatever the sinks show. The serial sink must not write it, which
//!   the svctest cell's boot checks host-side (`--fail-also` on its text,
//!   [`HIDDEN_LINE`]; `services/logd/docs/sinks.md` § Settings).
//! - **Framebuffer stopped**, on a boot with a framebuffer driver (CI's
//!   release svctest cells and the framebuffer cell; otherwise the case logs
//!   that it skipped). The framebuffer sink is `skip` and holds nobody, and
//!   shows critical and more
//!   severe by default, so the framebuffer cases send their lines at
//!   critical. While its driver is stopped the phase sends more lines than
//!   svctest's share of the history holds at its largest, so the history drops svctest's oldest before the sink
//!   writes them. A line logd refuses for the running serial sink's window
//!   is sent again after its hint, as the log client does. Once the driver
//!   is started again, logd must retain its notice counting the
//!   framebuffer's drops (`framebuffer: <n> lines dropped`,
//!   `services/logd/docs/sinks.md` § Drops) after the last line.
//! - **Framebuffer killed.** The phase then makes the framebuffer driver's main
//!   thread fault at an unmapped address, waits until procmgr no longer lists
//!   the driver and devmgr answers its ordinal `WITHDRAWN`, and sends as many
//!   lines again, under the same bound.
//! - **Framebuffer restarted.** devmgr restarts the killed driver
//!   (services/devmgr/docs/responsibilities.md § Driver Restart): the phase
//!   requires the class's next ordinal to answer with the new instance, and
//!   logd's framebuffer writer to take it up. devmgr can restart the driver
//!   within milliseconds, before the lines sent after the kill, so the
//!   writer may have dropped none of those. The phase therefore stops the new
//!   instance and sends as many lines again, so the history drops svctest's
//!   oldest before the sink writes them, and starts it: logd must retain its
//!   notice of the framebuffer's drops after the last line, which only a
//!   writer serving the new instance retains.
//!
//! The serial driver is only stopped, since a kill would end the console the
//! boot is judged on.
//!
//! A second phase checks logd's flush barrier, `LOG_FLUSH`
//! (`services/logd/docs/ipc-interface.md` § Flush barrier), through the
//! `logd.flush` seed:
//!
//! - **Authority.** `LOG_FLUSH` on `logd.query` is refused `FLUSH_DENIED`,
//!   `QUERY_SLOTS` on `logd.flush` is refused `QUERY_DENIED`, and a request
//!   of another version `FLUSH_VERSION_MISMATCH`.
//! - **Serial running.** After a burst of svctest's lines, a flush is
//!   answered `FLUSH_PENDING`, then `FLUSHED` within the log client's
//!   bound, asked again with its token. The serial sink that the first phase
//!   stalled answers a flush `FLUSHED` at once until its write in flight
//!   returns, so the burst and the flush are repeated until the sink holds the
//!   flush, within twice the stall bound. The flushed sink then holds none of
//!   svctest's lines, so the next case's line is taken within its window.
//! - **Serial stopped.** With every thread of the serial driver stopped, a
//!   line svctest logs is retained and not written, and a flush started then
//!   is answered `FLUSH_PENDING`, with a retry hint of 1 ms to the stall
//!   bound. Asked again with its token, it is answered `FLUSHED` while the
//!   driver is still stopped, once the sink is stalled, within twice the
//!   stall bound: logd does not hold a flush on a sink that writes nothing.

use std::time::{Duration, Instant};

use ipc::log_badges::LOG_BADGE_LOGD;
use ipc::log_flush::{FLUSH_DENIED, FLUSH_VERSION_MISMATCH, FlushAnswer};
use ipc::stream_labels::{
    LEVEL_CRITICAL, LEVEL_DEBUG, LEVEL_INFO, STREAM_BYTES, WINDOW_FULL, level_bits,
};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use logd_codec::sink::SINK_STALL_MS;
use logd_slot_table::{HISTORY_BYTES_MAX, HISTORY_BYTES_MIN, HOLD_WINDOW, PER_SLOT_HISTORY_MIN};
use syscall_abi::FAULT_CLASS_EXCEPTION;

use crate::arch::current::{IP_OFFSET, REGS_SIZE};
use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The logd sink checks; see [`super::all`] for their place.
pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "logd_sinks",
            run: logd_sinks_phase,
        },
        Phase {
            name: "logd_flush",
            run: logd_flush_phase,
        },
    ]
}

/// The serial driver's process name: its bundle entry name, its install
/// path, which devmgr creates it with as its `argv[0]`.
const SERIAL_NAME: &[u8] = b"/services/drivers/serial";

/// The framebuffer driver's process name, as the serial driver's.
pub(super) const FRAMEBUFFER_NAME: &[u8] = b"/services/drivers/framebuffer";

/// The line the phase sends at debug, which the serial sink, at its default
/// level of info, must not write: the svctest cell's boot fails on it
/// (`--fail-also`), so no other line holds this text.
const HIDDEN_LINE: &str = "logd_sinks: a debug line no default sink shows";

/// Lines sent first while the serial driver is stopped: more than logd's four
/// receive workers (`RECV_WORKERS`), each of which would hold one unanswered
/// line if logd wrote a line before replying, and fewer than the hold window.
const SERIAL_STOP_LINES: usize = 9;

/// Lines logged before each flush of the running case: enough that a writing
/// serial sink has not written them all when the flush arrives, and fewer
/// than the hold window, so none is refused.
const RUNNING_BURST: usize = 8;

/// Lines of each framebuffer case: more than a slot's share of the history
/// at its largest, so svctest's oldest are dropped before the stopped
/// framebuffer sink writes them whatever logd's bounds, and more than the
/// sink's backlog on a new driver.
const FLOOD_LINES: usize = PER_SLOT_HISTORY_MIN * (HISTORY_BYTES_MAX / HISTORY_BYTES_MIN) + 1;

/// The log client's bound on a log call.
const LOG_CALL_BOUND: Duration = Duration::from_millis(log::LOG_CALL_TIMEOUT_MS as u64);

/// logd's bound on what one sink costs: the age of a write past which its
/// sink is stalled.
const STALL_BOUND: Duration = Duration::from_millis(SINK_STALL_MS as u64);

/// The longest a line's call may take: half the stall bound. A line answered
/// once retained takes well under a millisecond; one that waited on a
/// stopped sink driver would wait for the stall bound.
const ANSWERED: Duration = Duration::from_millis(SINK_STALL_MS as u64 / 2);

/// An address no process maps (the first page), which the killed thread's
/// instruction pointer is set to.
const UNMAPPED_IP: u64 = 0;

/// How long the phase waits, at most, for the killed driver to be gone, for
/// its restart, and for a notice of logd's.
const DEATH_TIMEOUT: Duration = Duration::from_secs(30);

/// logd's answer to one line ([`send_line`]).
enum Answer
{
    /// Retained.
    Taken,
    /// Refused `WINDOW_FULL`, with this retry hint in milliseconds.
    Refused(u32),
}

/// Check logd's sinks around a stopped serial driver and a stopped, then
/// killed and restarted, framebuffer driver (see the module documentation).
pub fn logd_sinks_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "logd_sinks: no debug authority");
    assert_ne!(caps.logd_query, 0, "logd_sinks: no logd.query seed");

    let serial = super::crash::badge_named(authority, SERIAL_NAME)
        .expect("logd_sinks: LIST_PROCESSES lists no serial driver");
    let threads = attach(authority, serial, "serial");
    stop(&threads, "serial");
    let stopped = serial_stopped(Instant::now());
    start(&threads, "serial");
    detach(authority, serial, threads, "serial");
    let (lines, hint) = stopped.unwrap_or_else(|e| panic!("{e}"));
    retained_seq(caps.logd_query, &lines, "serial stopped");
    std::os::seraph::log!(
        "logd_sinks: {} lines taken while the serial driver was stopped, one refused with a \
         {hint} ms hint and taken once the sink stalled",
        lines.len()
    );

    let hidden = HIDDEN_LINE.as_bytes().to_vec();
    send_taken(&hidden, LEVEL_DEBUG, "below serial's level", 0).unwrap_or_else(|e| panic!("{e}"));
    retained_seq(caps.logd_query, &[hidden], "below serial's level");
    std::os::seraph::log!("logd_sinks: the debug line is in logd's history");

    let Some(fb) = super::crash::badge_named(authority, FRAMEBUFFER_NAME)
    else
    {
        std::os::seraph::log!("logd_sinks: framebuffer case skipped: no framebuffer driver");
        return;
    };
    let threads = attach(authority, fb, "framebuffer");
    stop(&threads, "framebuffer");
    let sent = send_lines("framebuffer stopped", FLOOD_LINES, LEVEL_CRITICAL);
    start(&threads, "framebuffer");
    detach(authority, fb, threads, "framebuffer");
    let lines = sent.unwrap_or_else(|e| panic!("{e}"));
    let last = retained_seq(caps.logd_query, &lines, "framebuffer stopped");
    let dropped = await_fb_notice(caps.logd_query, last, "the stopped driver's start");
    std::os::seraph::log!(
        "logd_sinks: {FLOOD_LINES} lines taken while the framebuffer driver was stopped, \
         {dropped} counted dropped"
    );

    kill(authority, fb, "framebuffer");
    await_gone(authority, fb, FRAMEBUFFER_NAME, "framebuffer");
    await_withdrawn(caps.framebuffer_deny_class);
    let lines = send_lines("framebuffer killed", FLOOD_LINES, LEVEL_CRITICAL)
        .unwrap_or_else(|e| panic!("{e}"));
    retained_seq(caps.logd_query, &lines, "framebuffer killed");
    std::os::seraph::log!(
        "logd_sinks: {FLOOD_LINES} lines taken after the framebuffer driver died"
    );

    await_restarted(caps.framebuffer_deny_class);
    // devmgr can restart the driver before the lines above are sent, so
    // whether the sink dropped any of them depends on that race. Stopping the
    // new instance while lines are sent makes the drops, and the notice that
    // only a writer serving a driver retains, certain.
    let restarted = super::crash::badge_named(authority, FRAMEBUFFER_NAME)
        .unwrap_or_else(|| panic!("logd_sinks: procmgr lists no restarted framebuffer driver"));
    let threads = attach(authority, restarted, "restarted framebuffer");
    stop(&threads, "restarted framebuffer");
    let sent = send_lines("restarted framebuffer stopped", FLOOD_LINES, LEVEL_CRITICAL);
    start(&threads, "restarted framebuffer");
    detach(authority, restarted, threads, "restarted framebuffer");
    let lines = sent.unwrap_or_else(|e| panic!("{e}"));
    let last = retained_seq(caps.logd_query, &lines, "restarted framebuffer stopped");
    let dropped = await_fb_notice(caps.logd_query, last, "the restarted driver's start");
    std::os::seraph::log!(
        "logd_sinks: logd's framebuffer writer took up the restarted driver, {dropped} lines \
         counted dropped"
    );
}

/// With the serial driver stopped since `stopped_at`: send
/// [`SERIAL_STOP_LINES`] lines, each taken, then lines until one is refused
/// `WINDOW_FULL`, within the hold window and before half the stall bound has
/// passed, with a hint within the stall bound; past the stall bound, send it
/// again, to be taken. The lines taken and the hint, or the first failure: no
/// assertion panics here, since a panic's message would wait behind the
/// stopped driver.
fn serial_stopped(stopped_at: Instant) -> Result<(Vec<Vec<u8>>, u32), String>
{
    let case = "serial stopped";
    let mut lines = Vec::new();
    for i in 0..SERIAL_STOP_LINES
    {
        let text = line_text(case, i);
        if let Answer::Refused(_) = send_line(&text, LEVEL_INFO, case, i)?
        {
            return Err(format!(
                "logd_sinks: line {i} with the {case} refused WINDOW_FULL, within the first \
                 {SERIAL_STOP_LINES}"
            ));
        }
        lines.push(text);
    }
    let mut i = SERIAL_STOP_LINES;
    let (text, hint) = loop
    {
        let text = line_text(case, i);
        match send_line(&text, LEVEL_INFO, case, i)?
        {
            Answer::Refused(hint) => break (text, hint),
            Answer::Taken if i < HOLD_WINDOW && stopped_at.elapsed() < ANSWERED =>
            {
                lines.push(text);
                i = i.saturating_add(1);
            }
            Answer::Taken =>
            {
                return Err(format!(
                    "logd_sinks: {} lines taken in {} ms with the {case}, none refused \
                     WINDOW_FULL",
                    i.saturating_add(1),
                    stopped_at.elapsed().as_millis()
                ));
            }
        }
    };
    if !(1..=SINK_STALL_MS).contains(&hint)
    {
        return Err(format!(
            "logd_sinks: retry hint {hint} ms outside 1 to {SINK_STALL_MS} ms"
        ));
    }
    // The writer began its write of a line at or after the stop; past the
    // stall bound from then, the sink is stalled.
    std::thread::sleep(STALL_BOUND.saturating_add(Duration::from_millis(100)));
    if let Answer::Refused(_) = send_line(&text, LEVEL_INFO, case, i)?
    {
        return Err(format!(
            "logd_sinks: line {i} refused WINDOW_FULL again {} ms after the {case}, past the \
             stall bound",
            stopped_at.elapsed().as_millis()
        ));
    }
    lines.push(text);
    Ok((lines, hint))
}

/// Send `count` numbered lines tagged `case` at `level`, each call answered within
/// [`ANSWERED`]; a line refused `WINDOW_FULL` is sent again after its hint,
/// as the log client does, for at most the log client's bound. Each line's
/// text, or the first failure: no assertion panics here, since a sink driver
/// may be stopped.
fn send_lines(case: &str, count: usize, level: u64) -> Result<Vec<Vec<u8>>, String>
{
    let mut sent = Vec::with_capacity(count);
    for i in 0..count
    {
        let text = line_text(case, i);
        send_taken(&text, level, case, i)?;
        sent.push(text);
    }
    Ok(sent)
}

/// Send `text` at `level` as line `i` of `case` ([`send_line`]) until it
/// is taken, sending a line refused `WINDOW_FULL` again after its hint, as
/// the log client does, for at most the log client's bound; the failure
/// otherwise.
fn send_taken(text: &[u8], level: u64, case: &str, i: usize) -> Result<(), String>
{
    let start_at = Instant::now();
    while let Answer::Refused(hint) = send_line(text, level, case, i)?
    {
        if start_at.elapsed() >= LOG_CALL_BOUND
        {
            return Err(format!(
                "logd_sinks: line {i} with the {case} refused WINDOW_FULL for {} ms",
                LOG_CALL_BOUND.as_millis()
            ));
        }
        std::thread::sleep(Duration::from_millis(u64::from(hint)));
    }
    Ok(())
}

/// The text of line `i` of `case`.
fn line_text(case: &str, i: usize) -> Vec<u8>
{
    format!("logd_sinks: line {i} while the {case}").into_bytes()
}

/// One raw `STREAM_BYTES` call of `text` and its newline at `level` on
/// svctest's log cap, line `i` of `case`, which must be answered within
/// [`ANSWERED`]: logd's answer, or the failure.
fn send_line(text: &[u8], level: u64, case: &str, i: usize) -> Result<Answer, String>
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut line = text.to_vec();
    line.push(b'\n');
    let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(level);
    let msg = IpcMessage::builder(label).bytes(0, &line).build();
    let bound = u32::try_from(LOG_CALL_BOUND.as_millis()).unwrap_or(u32::MAX);
    let start_at = Instant::now();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, bound) }.map_err(|e| {
        format!("logd_sinks: line {i} with the {case} not answered within {bound} ms ({e})")
    })?;
    let took = start_at.elapsed();
    if took >= ANSWERED
    {
        return Err(format!(
            "logd_sinks: line {i} with the {case} took {} ms, not under {} ms",
            took.as_millis(),
            ANSWERED.as_millis()
        ));
    }
    match reply.label
    {
        0 => Ok(Answer::Taken),
        WINDOW_FULL => Ok(Answer::Refused(
            u32::try_from(reply.word(0)).unwrap_or(u32::MAX),
        )),
        other => Err(format!(
            "logd_sinks: line {i} with the {case} refused ({other:#x})"
        )),
    }
}

/// Require the last of `lines` in logd's history, read through `query`: its
/// `seq`.
fn retained_seq(query: u64, lines: &[Vec<u8>], case: &str) -> u64
{
    let last = lines.last().expect("logd_sinks: no line sent");
    super::procmgr::logd_history_with(query, None, |entry| {
        (entry.seq, entry.bytes.starts_with(last))
    })
    .into_iter()
    .find_map(|(seq, found)| found.then_some(seq))
    .unwrap_or_else(|| {
        panic!("logd_sinks: the last line sent with the {case} is not in logd's history")
    })
}

/// Wait until logd's history holds its notice counting lines its
/// framebuffer sink dropped, retained after the entry `after`, within
/// [`DEATH_TIMEOUT`]; `what` names the event that lets the sink's writer go
/// on. The count it names.
fn await_fb_notice(query: u64, after: u64, what: &str) -> u64
{
    let start_at = Instant::now();
    loop
    {
        let mut count = None;
        super::procmgr::logd_history_each(query, Some(LOG_BADGE_LOGD), |entry| {
            if entry.seq <= after
            {
                return false;
            }
            count = count.or_else(|| fb_drop_count(entry.bytes));
            count.is_none()
        });
        if let Some(count) = count
        {
            return count;
        }
        assert!(
            start_at.elapsed() < DEATH_TIMEOUT,
            "logd_sinks: logd retained no notice of the framebuffer's drops within {} s of {what}",
            DEATH_TIMEOUT.as_secs()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The count of a notice `framebuffer: <n> lines dropped`, with or without
/// its newline; `None` for any other text.
fn fb_drop_count(text: &[u8]) -> Option<u64>
{
    let text = core::str::from_utf8(text).ok()?;
    let count = text
        .trim_end_matches('\n')
        .strip_prefix("framebuffer: ")?
        .strip_suffix(" lines dropped")?;
    count.parse().ok()
}

/// Check logd's flush barrier, with the serial driver running and stopped
/// (see the module documentation).
pub fn logd_flush_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    let flush = caps.logd_flush;
    assert_ne!(authority, 0, "logd_flush: no debug authority");
    assert_ne!(flush, 0, "logd_flush: no logd.flush seed");
    assert_ne!(caps.logd_query, 0, "logd_flush: no logd.query seed");

    let call = |cap: u64, msg: &IpcMessage| flush_call(cap, msg).unwrap_or_else(|e| panic!("{e}"));
    let denied = call(caps.logd_query, &ipc::log_flush::request(None));
    assert_eq!(
        denied.label, FLUSH_DENIED,
        "logd_flush: LOG_FLUSH on logd.query not refused"
    );
    let denied = call(flush, &ipc::log_query::slots_request(None));
    assert_eq!(
        ipc::log_query::reply_status(denied.label),
        ipc::log_query::QUERY_DENIED,
        "logd_flush: QUERY_SLOTS on logd.flush not refused"
    );
    let stale = IpcMessage::builder(ipc::log_labels::LOG_FLUSH)
        .word(0, u64::from(ipc::LOG_LABELS_VERSION) + 1)
        .build();
    assert_eq!(
        call(flush, &stale).label,
        FLUSH_VERSION_MISMATCH,
        "logd_flush: a stale version not refused"
    );

    let took = flush_while_running(flush).unwrap_or_else(|e| panic!("{e}"));
    std::os::seraph::log!(
        "logd_flush: flushed in {} ms with the serial driver running",
        took.as_millis()
    );

    let serial = super::crash::badge_named(authority, SERIAL_NAME)
        .expect("logd_flush: LIST_PROCESSES lists no serial driver");
    let threads = attach(authority, serial, "serial");
    stop(&threads, "serial");
    // The line is retained at once and its write waits on the stopped driver.
    // No assertion panics until the driver runs again, since its message
    // would wait behind the line.
    std::os::seraph::log!("logd_flush: a line while the serial driver is stopped");
    let answered = flush_while_stopped(flush);
    start(&threads, "serial");
    detach(authority, serial, threads, "serial");
    let (hint, took) = answered.unwrap_or_else(|e| panic!("{e}"));
    std::os::seraph::log!(
        "logd_flush: pending with a {hint} ms hint, then flushed in {} ms with the serial driver \
         stopped",
        took.as_millis()
    );
}

/// With the serial driver running: log [`RUNNING_BURST`] lines and start a
/// flush, until one is pending, then ask again with its token until it is
/// flushed, within the log client's bound. A flush answered `FLUSHED` at once
/// is one the sink did not hold, since it is still stalled from the first
/// phase or wrote the burst before the call (`services/logd/docs/ipc-interface.md`
/// § Flush barrier); the burst is repeated after 10 ms for twice the stall
/// bound. The time from the pending answer to flushed, or the first failure.
fn flush_while_running(flush: u64) -> Result<Duration, String>
{
    let start_at = Instant::now();
    loop
    {
        for i in 0..RUNNING_BURST
        {
            std::os::seraph::log!(
                "logd_flush: line {i} before a flush with the serial driver running"
            );
        }
        let answer = flush_answer(flush, None)?;
        if matches!(answer, FlushAnswer::Pending { .. })
        {
            return await_flushed(flush, answer, LOG_CALL_BOUND);
        }
        if start_at.elapsed() > STALL_BOUND.saturating_mul(2)
        {
            return Err(format!(
                "logd_flush: no flush pending with the serial driver running within {} ms",
                STALL_BOUND.saturating_mul(2).as_millis()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// With the serial driver stopped and a line of svctest's unwritten: start a
/// flush, which must be pending, with a hint within the stall bound, then ask
/// again with its token until it is flushed, within twice the stall bound.
/// The hint and the time to flushed, or the first failure.
fn flush_while_stopped(flush: u64) -> Result<(u32, Duration), String>
{
    let FlushAnswer::Pending { token, retry_ms } = flush_answer(flush, None)?
    else
    {
        return Err(
            "logd_flush: a flush answered FLUSHED with a line unwritten on the stopped serial \
             driver"
                .to_string(),
        );
    };
    if !(1..=SINK_STALL_MS).contains(&retry_ms)
    {
        return Err(format!(
            "logd_flush: retry hint {retry_ms} ms outside 1 to {SINK_STALL_MS} ms"
        ));
    }
    let took = await_flushed(
        flush,
        FlushAnswer::Pending { token, retry_ms },
        STALL_BOUND.saturating_mul(2),
    )?;
    Ok((retry_ms, took))
}

/// Ask again, after each pending answer's hint, until `flush` answers flushed
/// for the token of `answer`, within `within`: the time it took, or the
/// failure.
fn await_flushed(flush: u64, answer: FlushAnswer, within: Duration) -> Result<Duration, String>
{
    let start_at = Instant::now();
    let mut answer = answer;
    loop
    {
        let FlushAnswer::Pending { token, retry_ms } = answer
        else
        {
            return Ok(start_at.elapsed());
        };
        if start_at.elapsed() > within
        {
            return Err(format!(
                "logd_flush: not flushed within {} ms",
                within.as_millis()
            ));
        }
        std::thread::sleep(Duration::from_millis(u64::from(retry_ms)));
        answer = flush_answer(flush, Some(token))?;
    }
}

/// One `LOG_FLUSH` call on `flush`, a new flush (`None`) or one asked again
/// for `token`: logd's answer, or the failure.
fn flush_answer(flush: u64, token: Option<u64>) -> Result<FlushAnswer, String>
{
    let reply = flush_call(flush, &ipc::log_flush::request(token))?;
    FlushAnswer::decode(&reply)
        .map_err(|status| format!("logd_flush: LOG_FLUSH refused ({status:#x})"))
}

/// Call `cap` with `msg`, bounded by the log client's bound, which logd,
/// answering a flush at once, keeps well within: its reply, or the failure.
fn flush_call(cap: u64, msg: &IpcMessage) -> Result<IpcMessage, String>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let bound = u32::try_from(LOG_CALL_BOUND.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call_timeout(cap, msg, ipc_buf, bound) }
        .map_err(|e| format!("logd_flush: call to logd not answered within {bound} ms ({e})"))
}

/// Wait until devmgr serves the framebuffer class's ordinal 1, the restart
/// of the killed driver at ordinal 0, on `class`, a SEND on that class.
/// devmgr posts the restart in the hold that withdraws the dead driver, so a
/// query of the next ordinal received after the `WITHDRAWN` answer waits
/// for the restart's settle and names the new instance, or `NO_DEVICE`
/// when there is none.
fn await_restarted(class: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    match unsafe { ipc::query_device(class, 1, ipc_buf) }
    {
        Ok(copy) =>
        {
            let _ = syscall::cap_delete(copy);
        }
        Err(e) => panic!("logd_sinks: devmgr did not restart the framebuffer driver ({e:?})"),
    }
}

/// Attach to `process`, the driver named `what`, and check that it is
/// debuggable and off the core path; the caps of its threads, main thread
/// first.
pub(super) fn attach(authority: u64, process: u64, what: &str) -> Vec<u64>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("logd_sinks: ATTACH_PROCESS of {what} failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "logd_sinks: ATTACH_PROCESS of the {what} driver refused ({:#x}): it is not debuggable",
        reply.label
    );
    assert_eq!(
        reply.word(procmgr_labels::ATTACH_WORD_FLAGS) & procmgr_labels::ATTACH_FLAG_NO_CORE,
        0,
        "logd_sinks: the {what} driver is on the core path"
    );
    let threads = reply.caps().to_vec();
    let main = *threads
        .first()
        .unwrap_or_else(|| panic!("logd_sinks: the {what} attach returned no thread"));
    let bound = syscall::thread_get_fault_handler(main, FAULT_CLASS_EXCEPTION)
        .unwrap_or_else(|e| panic!("logd_sinks: reading the {what} binding ({e})"));
    assert!(
        bound.is_some(),
        "logd_sinks: the {what} driver's exception class is unbound, so its faults reach no \
         crash service"
    );
    threads
}

/// Stop every thread in `threads`; on a failure, start again those already
/// stopped, so the driver is not left stopped when the phase fails.
pub(super) fn stop(threads: &[u64], what: &str)
{
    for (i, &thread) in threads.iter().enumerate()
    {
        if let Err(e) = syscall::thread_stop(thread)
        {
            start(threads.get(..i).unwrap_or_default(), what);
            panic!("logd_sinks: stopping a {what} thread ({e})");
        }
    }
}

/// Start every thread in `threads` again.
pub(super) fn start(threads: &[u64], what: &str)
{
    for &thread in threads
    {
        syscall::thread_start(thread)
            .unwrap_or_else(|e| panic!("logd_sinks: starting a {what} thread ({e})"));
    }
}

/// Let go of `process` (`DETACH_PROCESS`) and delete its thread caps.
pub(super) fn detach(authority: u64, process: u64, threads: Vec<u64>, what: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
        .word(0, process)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("logd_sinks: DETACH_PROCESS of {what} failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "logd_sinks: DETACH_PROCESS of the {what} driver refused ({:#x})",
        reply.label
    );
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Kill the driver `process`, named `what`: stop its main thread, set its
/// instruction pointer to [`UNMAPPED_IP`], and start it, so it takes a fault
/// no handler resolves, as the `logd_restart` phase kills logd. The attach
/// checks as [`attach`] does.
pub(super) fn kill(authority: u64, process: u64, what: &str)
{
    let threads = attach(authority, process, what);
    let main = *threads
        .first()
        .unwrap_or_else(|| panic!("logd_sinks: the {what} attach returned no thread"));
    syscall::thread_stop(main)
        .unwrap_or_else(|e| panic!("logd_sinks: stopping the {what} main thread ({e})"));
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(main, &mut regs)
        .unwrap_or_else(|e| panic!("logd_sinks: reading the {what} main thread's registers ({e})"));
    regs.get_mut(IP_OFFSET..IP_OFFSET + 8)
        .expect("logd_sinks: the instruction pointer within the register file")
        .copy_from_slice(&UNMAPPED_IP.to_ne_bytes());
    // SAFETY: the thread is the driver's, bound to its address space, so the
    // frame it resumes on touches none of svctest's memory; the write only
    // makes it fault.
    unsafe { syscall::thread_write_regs(main, &regs) }.unwrap_or_else(|e| {
        panic!("logd_sinks: writing the {what} main thread's instruction pointer ({e})")
    });
    syscall::thread_start(main)
        .unwrap_or_else(|e| panic!("logd_sinks: starting the {what} main thread ({e})"));
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Wait until devmgr answers the framebuffer class's ordinal 0, the killed
/// driver's, `WITHDRAWN`, on `class`, a SEND on that class.
fn await_withdrawn(class: u64)
{
    assert_ne!(
        class, 0,
        "logd_sinks: no devmgr.class.framebuffer-deny seed"
    );
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let start_at = Instant::now();
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        match unsafe { ipc::query_device(class, 0, ipc_buf) }
        {
            Ok(copy) =>
            {
                let _ = syscall::cap_delete(copy);
            }
            Err(ipc::ClassCallError::Refused(ipc::devmgr_errors::WITHDRAWN)) => return,
            Err(e) => panic!("logd_sinks: querying the framebuffer class ({e:?})"),
        }
        assert!(
            start_at.elapsed() < DEATH_TIMEOUT,
            "logd_sinks: devmgr has not withdrawn the killed framebuffer driver"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Wait until `LIST_PROCESSES` no longer lists `process`, the driver named
/// `what` whose process name is `name`.
pub(super) fn await_gone(authority: u64, process: u64, name: &[u8], what: &str)
{
    let start_at = Instant::now();
    while super::crash::find_listed(authority, |badge, listed| {
        badge == process && listed == name
    })
    .is_some()
    {
        assert!(
            start_at.elapsed() < DEATH_TIMEOUT,
            "logd_sinks: the killed {what} driver is still listed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
