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
//!
//! No driver restarts a killed one yet, so the case ends with the framebuffer
//! sink resolving no driver; the serial driver is only stopped, since a kill
//! would end the console the boot is judged on.

use std::time::{Duration, Instant};

use ipc::stream_labels::{LEVEL_INFO, LEVEL_SHIFT, STREAM_BYTES};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use logd_codec::sink::{SINK_QUEUE_BYTES, SINK_STALL_MS};
use syscall_abi::FAULT_CLASS_EXCEPTION;

use crate::arch::current::{IP_OFFSET, REGS_SIZE};
use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The logd sink checks; see [`super::all`] for their place.
pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "logd_sinks",
        run: logd_sinks_phase,
    }]
}

/// The serial driver's process name: its bundle entry name, which devmgr
/// creates it with as its `argv[0]`.
const SERIAL_NAME: &[u8] = b"serial";

/// The framebuffer driver's process name, as the serial driver's.
const FRAMEBUFFER_NAME: &[u8] = b"framebuffer";

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

/// How long the phase waits, at most, for the killed driver to be gone.
const DEATH_TIMEOUT: Duration = Duration::from_secs(30);

/// Check logd's sinks around a stopped serial driver and a stopped, then
/// killed, framebuffer driver (see the module documentation).
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
    let lines = lines.unwrap_or_else(|e| panic!("{e}"));
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
    let lines = lines.unwrap_or_else(|e| panic!("{e}"));
    check_retained(caps.logd_query, &lines, "framebuffer stopped");
    std::os::seraph::log!(
        "logd_sinks: {FLOOD_LINES} lines answered in {took} ms while the framebuffer driver was \
         stopped"
    );

    kill(authority, fb);
    await_gone(authority, fb);
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
/// padding, or the first failure: no assertion panics here, since a sink
/// driver may be stopped, and a panic's message would wait behind it.
fn send_lines(
    case: &str,
    count: usize,
    pad_to: usize,
    first: Duration,
) -> Result<Vec<Vec<u8>>, String>
{
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut sent = Vec::with_capacity(count);
    for i in 0..count
    {
        let within = if i == 0 { first } else { STALL_BOUND };
        let bound = u32::try_from(within.as_millis()).unwrap_or(u32::MAX);
        let head = format!("logd_sinks: line {i} of {count} while the {case}").into_bytes();
        let mut line = head.clone();
        line.resize(line.len().max(pad_to.saturating_sub(1)), b'.');
        line.push(b'\n');
        let label = STREAM_BYTES | ((line.len() as u64) << 16) | (LEVEL_INFO << LEVEL_SHIFT);
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
        sent.push(head);
    }
    Ok(sent)
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

/// Kill the driver `process`: stop its main thread, set its instruction
/// pointer to [`UNMAPPED_IP`], and start it, so it takes a fault no handler
/// resolves, as the `logd_restart` phase kills logd.
fn kill(authority: u64, process: u64)
{
    let threads = attach(authority, process, "framebuffer");
    let main = *threads
        .first()
        .expect("logd_sinks: the framebuffer attach returned no thread");
    syscall::thread_stop(main).expect("logd_sinks: stopping the framebuffer main thread");
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(main, &mut regs)
        .expect("logd_sinks: reading the framebuffer main thread's registers");
    regs.get_mut(IP_OFFSET..IP_OFFSET + 8)
        .expect("logd_sinks: the instruction pointer within the register file")
        .copy_from_slice(&UNMAPPED_IP.to_ne_bytes());
    // SAFETY: the thread is the framebuffer driver's, bound to its address
    // space, so the frame it resumes on touches none of svctest's memory; the
    // write only makes it fault.
    unsafe { syscall::thread_write_regs(main, &regs) }
        .expect("logd_sinks: writing the framebuffer main thread's instruction pointer");
    syscall::thread_start(main).expect("logd_sinks: starting the framebuffer main thread");
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

/// Wait until `LIST_PROCESSES` no longer lists `process`.
fn await_gone(authority: u64, process: u64)
{
    let start_at = Instant::now();
    while super::crash::badge_named(authority, FRAMEBUFFER_NAME) == Some(process)
    {
        assert!(
            start_at.elapsed() < DEATH_TIMEOUT,
            "logd_sinks: the killed framebuffer driver is still listed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
