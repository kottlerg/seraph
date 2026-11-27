// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/logd_sinks.rs

//! logd's output sinks: a sink driver that does not answer holds neither the
//! log stream nor logd's other sink (`services/logd/docs/ipc-interface.md`
//! § Output sinks), and the serial and framebuffer drivers are debuggable.
//!
//! Through the debug authority svctest holds, the phase attaches to each sink
//! driver it finds by name (`LIST_PROCESSES`, `ATTACH_PROCESS`): the attach
//! must succeed, which it would not for a driver declared undebuggable
//! (`NOT_ATTACHABLE`), must not report the driver on the core path
//! (`ATTACH_FLAG_NO_CORE`), and the driver's main thread must have its
//! exception class bound, the path a fault takes to the crash service.
//!
//! - **Serial stopped.** The phase stops every thread of the serial driver and
//!   sends logd lines with raw `STREAM_BYTES` calls on its own log cap, more
//!   lines than logd has receive workers. The first must be answered within
//!   the log client's bound (`log::LOG_CALL_TIMEOUT_MS`): logd waits for its
//!   write for at most its stall bound (`SINK_STALL_MS`), where a logd that
//!   waited on the driver without a bound would answer none. Every later one
//!   must be answered within the stall bound, since the sink is then stalled
//!   and logd waits on it for nothing. The last must be in logd's history. The
//!   lines stay within the serial sink's queue
//!   (`logd_codec::sink::SINK_QUEUE_BYTES`), so none is dropped from the
//!   console CI reads; they are written when the phase starts the threads
//!   again.
//! - **Framebuffer stopped**, on a boot with a framebuffer driver (the
//!   framebuffer cell; otherwise the case logs that it skipped). The lines
//!   sent while the driver is stopped exceed the framebuffer sink's queue, so
//!   the sink stalls and then drops lines, counted, under the same bounds on
//!   the calls; the serial console shows every line, and logd's line
//!   counting the framebuffer's drops once the driver is started again.
//! - **Framebuffer killed.** The phase then makes the framebuffer driver's main
//!   thread fault at an unmapped address, waits until procmgr no longer lists
//!   the driver and devmgr answers its ordinal `WITHDRAWN`, and sends more
//!   than a queue's worth of lines again, under the same bounds as the
//!   serial-stopped case. A call to the dead driver ends only when devmgr
//!   revokes its endpoint, after the `WITHDRAWN` answer, so the first line
//!   can still wait out the stall bound on a writer blocked in such a call.
//! - **Framebuffer restarted.** devmgr restarts the killed driver
//!   (services/devmgr/docs/responsibilities.md § Driver Restart): the phase
//!   requires the class's next ordinal to answer with the new instance, and
//!   logd to write to it. It stops the new instance and sends more than a
//!   queue's worth of lines: once logd has resolved the new instance on its
//!   class watch, its framebuffer writer blocks in a write to it, and a line
//!   that finds the queue full waits out the stall bound, which a sink that
//!   resolved no driver never makes a line do. Until then the phase starts
//!   the instance, waits, and tries again, within a bound. A try that logd's
//!   move to the new instance lands inside, after its first line, can leave
//!   a later line waiting a whole stall bound from its own call, past the
//!   bound on such a line; no later try can meet that move, so such a try is
//!   tried again too, and fails the phase only once the bound has passed.
//!   The lines' calls stay under the serial-stopped case's bounds, the last is in logd's
//!   history, and once the instance is started again logd writes it the
//!   queued lines and the line counting its drops.
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
//! - **Serial running.** After a line of svctest's, a flush is answered
//!   `FLUSHED` within the log client's bound, asked again with its token.
//! - **Serial stopped.** With every thread of the serial driver stopped, a
//!   line logged from another thread is queued and not written, and a flush
//!   started meanwhile is answered `FLUSH_PENDING`, with a retry hint of
//!   1 ms to the stall bound, before the stall bound has passed. Asked again
//!   with its token, it is answered `FLUSHED` while the driver is still
//!   stopped, once the sink is stalled, within twice the stall bound: logd
//!   does not hold a flush on a sink that writes nothing. A stop that cuts
//!   off a write in flight makes logd's writer give it up, which stalls the
//!   sink at once, and every flush is then answered `FLUSHED`; the phase
//!   starts the driver, lets a write end the stall, and stops it again, at
//!   most three stops in all.

use std::time::{Duration, Instant};

use ipc::log_flush::{FLUSH_DENIED, FLUSH_VERSION_MISMATCH, FlushAnswer};
use ipc::stream_labels::{LEVEL_INFO, STREAM_BYTES, level_bits};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use logd_codec::sink::{SINK_QUEUE_BYTES, SINK_STALL_MS};
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
const FRAMEBUFFER_NAME: &[u8] = b"/services/drivers/framebuffer";

/// Lines sent while the serial driver is stopped: more than logd's four
/// receive workers (`RECV_WORKERS`), each of which would hold one unanswered
/// line if logd wrote a line before replying.
const SERIAL_STOP_LINES: usize = 9;

/// Body bytes of each line of the framebuffer cases, newline included: one
/// `STREAM_BYTES` call's payload, below its 512 bytes.
const FLOOD_LINE_BYTES: usize = 400;

/// Lines of each framebuffer case: their bodies alone exceed the sink's
/// queue by half again, so the queue fills whatever logd's prefix adds.
const FLOOD_LINES: usize = SINK_QUEUE_BYTES * 3 / 2 / FLOOD_LINE_BYTES + 1;

/// The log client's bound on a log call.
const LOG_CALL_BOUND: Duration = Duration::from_millis(log::LOG_CALL_TIMEOUT_MS as u64);

/// logd's bound on what one sink costs a line's producer.
const STALL_BOUND: Duration = Duration::from_millis(SINK_STALL_MS as u64);

/// An address no process maps (the first page), which the killed thread's
/// instruction pointer is set to.
const UNMAPPED_IP: u64 = 0;

/// How long the phase waits, at most, for the killed driver to be gone, and
/// for logd to write to the restarted one.
const DEATH_TIMEOUT: Duration = Duration::from_secs(30);

/// The shortest call that counts as a line waiting out the stall bound: half
/// of it. A line dropped by a sink that resolved no driver is answered in
/// well under a millisecond, and one that waits on a blocked writer waits
/// until the bound from the writer's call, sent a few milliseconds earlier.
const STALL_SEEN: Duration = Duration::from_millis(SINK_STALL_MS as u64 / 2);

/// How many times the flush phase stops the serial driver, at most, for a
/// stop that finds logd's serial writer not stalled: a stop that cuts off a
/// write in flight (logd's own, or a kernel line's) makes the writer give it
/// up, which stalls the sink, and a flush then rightly reads it as flushed.
const STOP_ATTEMPTS: u32 = 3;

/// How long the flush phase lets the restarted serial driver run before it
/// stops it again: time for logd's writer to complete a write, which ends
/// the sink's stall.
const STALL_CLEAR: Duration = Duration::from_millis(100);

/// How long the phase waits between tries for logd to resolve the restarted
/// framebuffer driver.
const RESOLVE_RETRY: Duration = Duration::from_millis(200);

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
    let lines = send_lines("serial stopped", SERIAL_STOP_LINES, 0, LOG_CALL_BOUND);
    start(&threads, "serial");
    detach(authority, serial, threads, "serial");
    let (lines, _) = lines.unwrap_or_else(|e| panic!("{e}"));
    check_retained(caps.logd_query, &lines, "serial stopped");
    std::os::seraph::log!(
        "logd_sinks: {SERIAL_STOP_LINES} lines answered while the serial driver was stopped"
    );

    let Some(fb) = super::crash::badge_named(authority, FRAMEBUFFER_NAME)
    else
    {
        std::os::seraph::log!("logd_sinks: framebuffer case skipped: no framebuffer driver");
        return;
    };
    let threads = attach(authority, fb, "framebuffer");
    stop(&threads, "framebuffer");
    let start_at = Instant::now();
    let lines = send_lines(
        "framebuffer stopped",
        FLOOD_LINES,
        FLOOD_LINE_BYTES,
        LOG_CALL_BOUND,
    );
    let took = start_at.elapsed().as_millis();
    start(&threads, "framebuffer");
    detach(authority, fb, threads, "framebuffer");
    let (lines, _) = lines.unwrap_or_else(|e| panic!("{e}"));
    check_retained(caps.logd_query, &lines, "framebuffer stopped");
    std::os::seraph::log!(
        "logd_sinks: {FLOOD_LINES} lines answered in {took} ms while the framebuffer driver was \
         stopped"
    );

    kill(authority, fb, "framebuffer");
    await_gone(authority, fb, FRAMEBUFFER_NAME, "framebuffer");
    await_withdrawn(caps.framebuffer_deny_class);
    let start_at = Instant::now();
    if let Err(e) = send_lines(
        "framebuffer killed",
        FLOOD_LINES,
        FLOOD_LINE_BYTES,
        LOG_CALL_BOUND,
    )
    {
        panic!("{e}");
    }
    let took = start_at.elapsed().as_millis();
    std::os::seraph::log!(
        "logd_sinks: {FLOOD_LINES} lines answered in {took} ms after the framebuffer driver died"
    );

    await_restarted(caps.framebuffer_deny_class);
    let restarted = super::crash::badge_named(authority, FRAMEBUFFER_NAME)
        .expect("logd_sinks: LIST_PROCESSES lists no restarted framebuffer driver");
    let longest = await_stall_on(caps.logd_query, authority, restarted);
    std::os::seraph::log!(
        "logd_sinks: logd writes to the restarted framebuffer driver (a line waited {} ms on it)",
        longest.as_millis()
    );
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

    std::os::seraph::log!("logd_flush: a line before a flush with the serial driver running");
    let first = flush_answer(flush, None).unwrap_or_else(|e| panic!("{e}"));
    let took = await_flushed(flush, first, LOG_CALL_BOUND).unwrap_or_else(|e| panic!("{e}"));
    std::os::seraph::log!(
        "logd_flush: flushed in {} ms with the serial driver running",
        took.as_millis()
    );

    let serial = super::crash::badge_named(authority, SERIAL_NAME)
        .expect("logd_flush: LIST_PROCESSES lists no serial driver");
    let threads = attach(authority, serial, "serial");
    let mut stopped = None;
    for attempt in 1..=STOP_ATTEMPTS
    {
        stop(&threads, "serial");
        // The line's call waits on the stopped driver up to the stall bound,
        // so another thread makes it while this one flushes. No assertion
        // panics until the driver runs again, since its message would wait
        // behind it.
        let line = std::thread::spawn(|| {
            std::os::seraph::log!("logd_flush: a line while the serial driver is stopped");
        });
        let answered = flush_while_stopped(flush);
        start(&threads, "serial");
        let _ = line.join();
        if matches!(answered, Ok(None)) && attempt < STOP_ATTEMPTS
        {
            std::os::seraph::log!(
                "logd_flush: the serial sink was stalled at the driver's stop (attempt \
                 {attempt} of {STOP_ATTEMPTS}); stopping it again"
            );
            // The line above returns once queued on the stalled sink; the
            // writer's next completed write ends the stall.
            std::thread::sleep(STALL_CLEAR);
            continue;
        }
        stopped = Some(answered);
        break;
    }
    detach(authority, serial, threads, "serial");
    let (hint, took) = match stopped
    {
        Some(Ok(Some(answer))) => answer,
        Some(Err(e)) => panic!("{e}"),
        Some(Ok(None)) | None => panic!(
            "logd_flush: no flush pending within {} ms of the serial driver's stop, in \
             {STOP_ATTEMPTS} stops",
            STALL_SEEN.as_millis()
        ),
    };
    std::os::seraph::log!(
        "logd_flush: pending with a {hint} ms hint, then flushed in {} ms with the serial driver \
         stopped",
        took.as_millis()
    );
}

/// With the serial driver stopped: start flushes until one is pending, which
/// must happen before [`STALL_SEEN`] passes, with a hint within the stall
/// bound, then ask again with its token until it is flushed, within twice the
/// stall bound. The hint and the time to flushed; `None` when no flush was
/// pending, since the sink was stalled from the stop on (a write the stop cut
/// off); or the first failure.
fn flush_while_stopped(flush: u64) -> Result<Option<(u32, Duration)>, String>
{
    let start_at = Instant::now();
    let (token, hint) = loop
    {
        match flush_answer(flush, None)?
        {
            FlushAnswer::Pending { token, retry_ms } => break (token, retry_ms),
            FlushAnswer::Flushed { .. } if start_at.elapsed() < STALL_SEEN =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            FlushAnswer::Flushed { .. } => return Ok(None),
        }
    };
    if !(1..=SINK_STALL_MS).contains(&hint)
    {
        return Err(format!(
            "logd_flush: retry hint {hint} ms outside 1 to {SINK_STALL_MS} ms"
        ));
    }
    let took = await_flushed(
        flush,
        FlushAnswer::Pending {
            token,
            retry_ms: hint,
        },
        STALL_BOUND.saturating_mul(2),
    )?;
    Ok(Some((hint, took)))
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

/// Stop the restarted framebuffer driver `process` and flood logd until a
/// line waits out the stall bound on it (see the module documentation),
/// starting the driver again after each try; the longest call of that try.
/// The try's calls must stay under the flood's bounds, a failed try being
/// tried again until [`DEATH_TIMEOUT`] (see the module documentation), and
/// the last line sent must be in logd's history, read through `query`.
fn await_stall_on(query: u64, authority: u64, process: u64) -> Duration
{
    let start_at = Instant::now();
    loop
    {
        let threads = attach(authority, process, "restarted framebuffer");
        stop(&threads, "restarted framebuffer");
        let sent = send_lines(
            "restarted framebuffer stopped",
            FLOOD_LINES,
            FLOOD_LINE_BYTES,
            LOG_CALL_BOUND,
        );
        start(&threads, "restarted framebuffer");
        detach(authority, process, threads, "restarted framebuffer");
        let in_time = start_at.elapsed() < DEATH_TIMEOUT;
        match sent
        {
            Ok((lines, longest)) if longest >= STALL_SEEN =>
            {
                check_retained(query, &lines, "restarted framebuffer stopped");
                return longest;
            }
            Ok(_) => assert!(
                in_time,
                "logd_sinks: logd's framebuffer writer did not reach the restarted driver"
            ),
            Err(e) => assert!(in_time, "{e}"),
        }
        std::thread::sleep(RESOLVE_RETRY);
    }
}

/// Attach to `process`, the driver named `what`, and check that it is
/// debuggable and off the core path; the caps of its threads, main thread
/// first.
fn attach(authority: u64, process: u64, what: &str) -> Vec<u64>
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
fn stop(threads: &[u64], what: &str)
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
fn start(threads: &[u64], what: &str)
{
    for &thread in threads
    {
        syscall::thread_start(thread)
            .unwrap_or_else(|e| panic!("logd_sinks: starting a {what} thread ({e})"));
    }
}

/// Let go of `process` (`DETACH_PROCESS`) and delete its thread caps.
fn detach(authority: u64, process: u64, threads: Vec<u64>, what: &str)
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

/// Send `count` numbered lines tagged `case`, each padded to `pad_to` bytes
/// (newline included) when longer than its text, one raw `STREAM_BYTES` call
/// each on svctest's log cap. The first must be answered within `first`,
/// every later one within [`STALL_BOUND`]. Each line's text before its
/// padding, with the longest call, or the first failure: no assertion panics
/// here, since a sink driver may be stopped, and a panic's message would
/// wait behind it.
fn send_lines(
    case: &str,
    count: usize,
    pad_to: usize,
    first: Duration,
) -> Result<(Vec<Vec<u8>>, Duration), String>
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut sent = Vec::with_capacity(count);
    let mut longest = Duration::ZERO;
    for i in 0..count
    {
        let within = if i == 0 { first } else { STALL_BOUND };
        let bound = u32::try_from(within.as_millis()).unwrap_or(u32::MAX);
        let head = format!("logd_sinks: line {i} of {count} while the {case}").into_bytes();
        let mut line = head.clone();
        line.resize(line.len().max(pad_to.saturating_sub(1)), b'.');
        line.push(b'\n');
        let label = STREAM_BYTES | ((line.len() as u64) << 16) | level_bits(LEVEL_INFO);
        let msg = IpcMessage::builder(label).bytes(0, &line).build();
        let start_at = Instant::now();
        // SAFETY: ipc_buf is this thread's registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call_timeout(cap, &msg, ipc_buf, bound) }.map_err(|e| {
            format!("logd_sinks: line {i} with the {case} not answered within {bound} ms ({e})")
        })?;
        let took = start_at.elapsed();
        if reply.label != 0
        {
            return Err(format!(
                "logd_sinks: line {i} with the {case} refused ({:#x})",
                reply.label
            ));
        }
        if took >= within
        {
            return Err(format!(
                "logd_sinks: line {i} with the {case} took {} ms, not under {bound} ms",
                took.as_millis()
            ));
        }
        longest = longest.max(took);
        sent.push(head);
    }
    Ok((sent, longest))
}

/// Require a line that starts with the last of `lines` in logd's history.
fn check_retained(query: u64, lines: &[Vec<u8>], case: &str)
{
    let last = lines.last().expect("logd_sinks: no line sent");
    let history = super::procmgr::logd_history(query, None);
    assert!(
        history.iter().any(|(_, bytes)| bytes.starts_with(last)),
        "logd_sinks: the last line sent with the {case} is not in logd's history"
    );
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
