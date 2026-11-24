// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/logd_restart.rs

//! logd's restart end to end (`docs/supervision.md` § Restart Shapes).
//!
//! The phase kills logd through the debug authority svctest holds: it finds
//! logd by name (`LIST_PROCESSES`), attaches to it (`ATTACH_PROCESS`), checks
//! that the attach reports logd on the core path (`ATTACH_FLAG_NO_CORE`), so
//! the crash service writes no core of it
//! (`services/crashd/docs/operation.md` § Core Dump), stops its main thread, points the thread's instruction pointer at an unmapped
//! address, and starts it. The thread faults there, and the fault takes the
//! path any fault of logd takes: memmgr forwards it to the exception class,
//! which procmgr bound to its crash endpoint, where crashd, when the boot
//! stages it, reports it and declines it, and procmgr's own receiver declines
//! it otherwise. logd dies of the fault, and svcmgr restarts it under its
//! recipe's `restart = on_failure`. The phase waits until the new instance's
//! history holds svcmgr's lines about the death, which it holds only when
//! svcmgr writes them after the respawn, since a line written while no logd
//! receives is dropped, and logs how long the restart took. It then runs the
//! `logd_death_forward` check again against the new instance: a child's line
//! arrives, and its death, which procmgr forwards to the death queue the new
//! instance registered, retires its slot. That check finds exactly one slot
//! of the child's name, so the instance it reads holds a fresh table, not the
//! one the earlier run of the check left a retired slot in.
//!
//! The phase writes no log line between the kill and the new instance's
//! service: a line written while no logd receives waits out its bound. The
//! new instance's table holds no sender's name, and svctest registered its
//! own once, at startup. Its first line after the restart carries
//! `SENDER_NAMED`, which the new instance refuses with `NAME_UNKNOWN` until
//! the name is sent again, so the phase checks that the line is retained once,
//! in a slot named `svctest`
//! (`services/logd/docs/ipc-interface.md` § `stream_labels::STREAM_REGISTER_NAME`).
//! A child then sends the new instance raw stream messages. It first registers
//! an empty name, so its live slot holds none, as a slot a sender created
//! before registering does; then a line without the bit, which no receiver
//! refuses; then a line and a record with the bit, which must be refused and
//! not retained; then, once it has registered a name, a line with the bit,
//! which is accepted.
//!
//! The `logd_reserve` phase before it requires logd's budget node to be a
//! system-reserve node (`services/svcmgr/docs/service-definitions.md`
//! § `reserve`), on the running instance and on the next: each attach must
//! report `ATTACH_FLAG_RESERVE`, so the phase fails whenever logd's recipe
//! leaves it outside the reserve. Between the two it kills logd in the same way
//! while the `memhog` fixture holds memory at the system reserve, and requires
//! the next instance to run and serve before the level falls. While the
//! fixture holds the pool there, memmgr refuses every page to a budget node
//! outside the reserve (`services/memmgr/docs/memory-pool.md` § Distribution
//! policy), and the create of a new process and every first touch of its heap
//! and stacks take fresh pages. The kill frees the old instance's frames,
//! though, and the fixture takes back what others free only at its next tick
//! (`mem_fill::TICK_MS`), so a create that falls in that gap is served from
//! them whatever its node: the restart check shows that a logd in the reserve
//! restarts while memory is critical, and the attach flags are what fail for a
//! logd outside it. The phase attaches to logd before the fill, faults it once
//! the level reads `CRITICAL`, and, once the level has fallen, requires
//! svcmgr's restart line in the new instance's history to be stamped before
//! svcmgr's line for its stop of the fixture, the first of each after the
//! kill. svcmgr writes the stop line once procmgr has destroyed the fixture,
//! which frees the memory, and it serves a stop and restarts a service on one
//! event loop (`services/svcmgr/docs/restart-protocol.md` § Death detection),
//! so a stop asked for while it restarts logd waits for the restart. logd
//! stamps each line while svcmgr's call of it waits, so the order of the two
//! stamps is the order of the restart and the destroy, however long the
//! restart takes and whether oomd or svctest asks for the stop.
//!
//! The kill comes first in the window: oomd stops the fixture its grace after
//! the level reads `CRITICAL`, and the restart has to come before that stop,
//! though logd's death reaches svcmgr only once the crash service, when the
//! boot stages it, has reported the fault. After the kill, in the same window,
//! the phase makes the creates of `super::critical_creates` (svctest's own,
//! refused `OUT_OF_MEMORY`, and a reserve creator's, which succeeds), and
//! faults the `crasher-worker` fixture's worker, whose restart must be held
//! until the level falls and then made; the window is shared because svcmgr
//! restarts memhog at most three times a window and the boot's other memhog
//! windows spend them. A create of svctest's own that the old instance's freed
//! frames serve before the fixture's next tick takes them back is destroyed and
//! made again (`super::critical_creates`).

use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

use crate::arch::current::{IP_OFFSET, REGS_SIZE};
use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The logd restart checks, in memory critical and not; see [`super::all`]
/// for their place.
pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "logd_reserve",
            run: logd_reserve_phase,
        },
        Phase {
            name: "logd_restart",
            run: logd_restart_phase,
        },
    ]
}

/// logd's process name: the first word of its recipe's `argv`.
const LOGD_NAME: &[u8] = b"logd";

/// An address no process maps (the first page), which the killed thread's
/// instruction pointer is set to.
const UNMAPPED_IP: u64 = 0;

/// How long the phase waits, at most, for svcmgr to restart logd and write
/// its lines about it.
const RESTART_TIMEOUT: Duration = Duration::from_secs(30);

/// The interval at which the phase looks for the restart.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// svcmgr's first and last lines about the death, which it writes once the
/// next instance runs (`services/svcmgr/src/restart.rs` `handle_death`).
const SVCMGR_LINES: [&[u8]; 2] = [b"service died: logd", b"service restarted: logd"];

/// svcmgr's line for its stop of the `memhog` fixture, which it writes once
/// procmgr has destroyed the fixture's process, and with it freed the memory
/// the fixture held (`services/svcmgr/src/stop.rs` `handle_stop_candidate`).
const MEMHOG_STOP_LINE: &[u8] = b"stop memhog: stopped for a stop-authority holder";

/// How long the `logd_reserve` phase holds memory critical when no oomd stops
/// the `memhog` fixture, and svctest stops it. svcmgr serves the stop only
/// once it has restarted logd, so the hold need not outlast the restart. A test
/// wait bound.
const RESERVE_HOLD: Duration = Duration::from_secs(5);

/// Kill logd while memory is critical and require its next instance to run
/// and serve before the level falls (see the module documentation).
pub fn logd_reserve_phase(caps: &Caps)
{
    let phase = "logd_reserve";
    if !super::fixtures::staged(svctest_fixtures::Fixture::Memhog)
    {
        super::fixtures::skip(phase, svctest_fixtures::Fixture::Memhog);
        return;
    }
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "{phase}: no debug authority");
    assert_ne!(caps.logd_query, 0, "{phase}: no logd.query seed");
    let killed = super::crash::badge_named(authority, LOGD_NAME)
        .unwrap_or_else(|| panic!("{phase}: LIST_PROCESSES lists no logd"));
    let (threads, flags) = attach(authority, killed, phase);
    require_reserve(flags, phase, "the running");
    let mut creates = super::critical_creates::Checks::prepare(phase);
    let mut killed_us = 0;
    super::oom::critical_window(caps, phase, RESERVE_HOLD, || {
        killed_us = super::oom::elapsed_us();
        fault_main(&threads, phase);
        creates.creates();
        creates.fault_worker();
    });
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
    await_restart(caps.logd_query, authority, killed, phase);
    let restarted_us = await_line_after(caps.logd_query, SVCMGR_LINES[1], killed_us, phase);
    let stopped_us = await_line_after(caps.logd_query, MEMHOG_STOP_LINE, killed_us, phase);
    let next = super::crash::badge_named(authority, LOGD_NAME)
        .filter(|&badge| badge != killed)
        .unwrap_or_else(|| panic!("{phase}: LIST_PROCESSES lists no next logd"));
    let (threads, flags) = attach(authority, next, phase);
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
    require_reserve(flags, phase, "the restarted");
    assert!(
        restarted_us < stopped_us,
        "{phase}: logd's next instance took svcmgr's restart line at {restarted_us} us, after \
         svcmgr's stop of memhog at {stopped_us} us: logd restarted only once memory was freed"
    );
    let took = restarted_us.saturating_sub(killed_us) / 1000;
    let lead = stopped_us.saturating_sub(restarted_us) / 1000;
    std::os::seraph::log!(
        "logd_reserve phase passed (logd killed while memory was critical, and restarted and \
         serving {took} ms later, {lead} ms before svcmgr stopped memhog)"
    );
    creates.finish(phase);
}

/// Kill logd, wait for its next instance, and check the new instance's
/// history and its death forward (see the module documentation).
pub fn logd_restart_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "logd_restart: no debug authority");
    assert_ne!(caps.logd_query, 0, "logd_restart: no logd.query seed");
    let killed = super::crash::badge_named(authority, LOGD_NAME)
        .expect("logd_restart: LIST_PROCESSES lists no logd");
    let start = Instant::now();
    kill(authority, killed, "logd_restart: logd");
    await_restart(caps.logd_query, authority, killed, "logd_restart");
    let took = start.elapsed().as_millis();
    std::os::seraph::log!("logd_restart: logd restarted in {took} ms");
    check_first_line_named(caps.logd_query);
    check_name_probe(caps.logd_query);
    super::procmgr::logd_death_forward_phase(caps);
}

/// The start of svctest's first line after the restart.
const FIRST_LINE: &[u8] = b"logd_restart: logd restarted in ";

/// svctest's own display name, which it registered at startup.
const SVCTEST_NAME: &[u8] = b"svctest";

/// Check that svctest's first line after the restart ([`FIRST_LINE`]), sent
/// with `SENDER_NAMED` to a table that held no name for svctest, is retained
/// once, in the history of svctest's live slot, which holds svctest's name: the
/// new instance refused the line until svctest's log client sent the name
/// again, and retained it once resent.
fn check_first_line_named(query: u64)
{
    use ipc::log_query::SLOT_LIVE;

    let first_lines = |history: Vec<(u8, Vec<u8>)>| {
        history
            .iter()
            .filter(|(_, bytes)| bytes.starts_with(FIRST_LINE))
            .count()
    };
    let retained = first_lines(super::procmgr::logd_history(query, None));
    assert_eq!(
        retained, 1,
        "logd_restart: the first line after the restart is retained {retained} times, not once"
    );
    let named: Vec<u64> = super::procmgr::logd_slots(query)
        .into_iter()
        .filter(|(_, state, _, name)| *state == SLOT_LIVE && name == SVCTEST_NAME)
        .map(|(badge, _, _, _)| badge)
        .collect();
    let &[badge] = named.as_slice()
    else
    {
        panic!(
            "logd_restart: {} live slots named svctest, not one",
            named.len()
        );
    };
    assert_eq!(
        first_lines(super::procmgr::logd_history(query, Some(badge))),
        1,
        "logd_restart: the first line after the restart is not in svctest's named slot"
    );
}

/// Role token of [`name_probe_child_main`].
const NAME_PROBE_ROLE: &str = "logd-name-probe-child";

/// The name [`name_probe_child_main`] registers once its refused messages are
/// sent.
const NAME_PROBE_NAME: &[u8] = b"svctest-logd-name-probe";

/// The probe child's exit code once every reply was the one expected; a
/// failed check panics, so the exit code differs.
const NAME_PROBE_EXIT_CODE: i32 = 0x2b;

/// The probe child's line without `SENDER_NAMED`, which logd accepts.
const PROBE_UNNAMED: &[u8] = b"name probe: a line without the named-sender bit\n";

/// The probe child's line with `SENDER_NAMED` and no name registered, which
/// logd refuses.
const PROBE_REFUSED: &[u8] = b"name probe: a refused line\n";

/// The probe child's line with `SENDER_NAMED` once its name is registered,
/// which logd accepts.
const PROBE_NAMED: &[u8] = b"name probe: a line after the registration\n";

/// Child mode of the [`logd_restart_phase`]: send logd raw stream messages and
/// require each reply (see the module documentation), then exit with
/// [`NAME_PROBE_EXIT_CODE`].
fn name_probe_child_main() -> !
{
    use ipc::stream_labels::{
        LEVEL_INFO, LEVEL_SHIFT, NAME_UNKNOWN, SENDER_NAMED, STREAM_BYTES, STREAM_RECORD,
        STREAM_REGISTER_NAME,
    };

    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let send = |id: u64, bytes: &[u8]| {
        let label = id | ((bytes.len() as u64) << 16) | (LEVEL_INFO << LEVEL_SHIFT);
        let msg = ipc::IpcMessage::builder(label).bytes(0, bytes).build();
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
            .expect("logd name probe: log send failed")
            .label
    };
    // svctest's `main` registered `svctest` for this child before the role
    // dispatch: an empty name leaves its slot holding none.
    assert_eq!(
        send(STREAM_REGISTER_NAME, b""),
        0,
        "logd name probe: the empty name was not acknowledged"
    );
    assert_eq!(
        send(STREAM_BYTES, PROBE_UNNAMED),
        0,
        "logd name probe: a line without the named-sender bit was not accepted"
    );
    assert_eq!(
        send(STREAM_BYTES | SENDER_NAMED, PROBE_REFUSED),
        NAME_UNKNOWN,
        "logd name probe: a named line from a sender with no name held was not refused"
    );
    let record = log::build_record(format_args!("name probe: a refused record"), &[]);
    assert_eq!(
        send(STREAM_RECORD | SENDER_NAMED, record.as_bytes()),
        NAME_UNKNOWN,
        "logd name probe: a named record from a sender with no name held was not refused"
    );
    std::os::seraph::log::register_name(NAME_PROBE_NAME);
    assert_eq!(
        send(STREAM_BYTES | SENDER_NAMED, PROBE_NAMED),
        0,
        "logd name probe: a named line after the registration was not accepted"
    );
    std::process::exit(NAME_PROBE_EXIT_CODE)
}

/// Run [`name_probe_child_main`] and check its exit code, then that logd
/// retained exactly its two accepted lines, newest first, under the badge of
/// the slot named [`NAME_PROBE_NAME`].
fn check_name_probe(query: u64)
{
    let status = std::process::Command::new("/tests/svctest")
        .arg(NAME_PROBE_ROLE)
        .status()
        .expect("logd_restart: spawning the name probe failed");
    assert_eq!(
        status.code(),
        Some(NAME_PROBE_EXIT_CODE),
        "logd_restart: the name probe failed: {status}"
    );
    let badge = super::procmgr::logd_slots(query)
        .into_iter()
        .find(|(_, _, _, name)| name == NAME_PROBE_NAME)
        .map(|(badge, _, _, _)| badge)
        .expect("logd_restart: no slot holds the name probe's name");
    let lines: Vec<Vec<u8>> = super::procmgr::logd_history(query, Some(badge))
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    let line = |text: &[u8]| text.strip_suffix(b"\n").unwrap_or(text).to_vec();
    assert_eq!(
        lines,
        [line(PROBE_NAMED), line(PROBE_UNNAMED)],
        "logd_restart: logd retained other than the name probe's two accepted lines"
    );
    std::os::seraph::log!("logd_restart: named-sender refusals and resends checked");
}

/// Child-mode dispatch for this module's role ([`crate::reentry`]).
pub fn reentry_main(role: &str)
{
    if role == NAME_PROBE_ROLE
    {
        name_probe_child_main();
    }
}

/// Kill the process `process` through an attach, which must report it on the
/// core path: stop its main thread, set its instruction pointer to
/// [`UNMAPPED_IP`], and start it, so it takes a fault no handler resolves
/// (see the module documentation). `what` names the phase and the process in
/// a failure.
pub(crate) fn kill(authority: u64, process: u64, what: &str)
{
    let (threads, _) = attach(authority, process, what);
    fault_main(&threads, what);
    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Attach to the process `process`, which must report it on the core path:
/// its thread caps, its main thread's first, which the caller deletes, and the
/// reply's `ATTACH_WORD_FLAGS`. `what` names the phase and the process in a
/// failure.
fn attach(authority: u64, process: u64, what: &str) -> (Vec<u64>, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let attach = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &attach, ipc_buf) }
        .unwrap_or_else(|e| panic!("{what}: ATTACH_PROCESS ipc_call failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "{what}: ATTACH_PROCESS refused ({:#x})",
        reply.label
    );
    let flags = reply.word(procmgr_labels::ATTACH_WORD_FLAGS);
    assert_ne!(
        flags & procmgr_labels::ATTACH_FLAG_NO_CORE,
        0,
        "{what}: the process is not on the core path (no DECLARE_NO_CORE)"
    );
    let threads = reply.caps().to_vec();
    assert!(
        !threads.is_empty(),
        "{what}: the attach returned no main thread"
    );
    (threads, flags)
}

/// Require the attach `flags` of the logd instance `which` names to report
/// a system-reserve budget node (`ATTACH_FLAG_RESERVE`).
fn require_reserve(flags: u64, phase: &str, which: &str)
{
    assert_ne!(
        flags & procmgr_labels::ATTACH_FLAG_RESERVE,
        0,
        "{phase}: {which} logd's budget node is outside the system reserve (reserve = yes)"
    );
}

/// Stop the main thread of an attached process, the first of `threads`, set
/// its instruction pointer to [`UNMAPPED_IP`], and start it. Allocates
/// nothing until it fails.
fn fault_main(threads: &[u64], what: &str)
{
    let Some(&main) = threads.first()
    else
    {
        panic!("{what}: the attach returned no main thread");
    };
    syscall::thread_stop(main).unwrap_or_else(|e| panic!("{what}: stopping the main thread ({e})"));
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(main, &mut regs)
        .unwrap_or_else(|e| panic!("{what}: reading its registers ({e})"));
    regs.get_mut(IP_OFFSET..IP_OFFSET + 8)
        .unwrap_or_else(|| panic!("{what}: the instruction pointer within the register file"))
        .copy_from_slice(&UNMAPPED_IP.to_ne_bytes());
    // SAFETY: the thread is the attached process's, bound to its address
    // space, so the frame it resumes on touches none of svctest's memory; the
    // write only makes it fault.
    unsafe { syscall::thread_write_regs(main, &regs) }
        .unwrap_or_else(|e| panic!("{what}: writing its instruction pointer ({e})"));
    syscall::thread_start(main)
        .unwrap_or_else(|e| panic!("{what}: starting the main thread ({e})"));
}

/// Wait until the history of logd's instance after `killed` holds every line
/// of [`SVCMGR_LINES`], which svcmgr writes once it has restarted logd.
/// `phase` names the phase in a failure.
fn await_restart(query: u64, authority: u64, killed: u64, phase: &str)
{
    let start = Instant::now();
    loop
    {
        let next = super::crash::badge_named(authority, LOGD_NAME).filter(|&b| b != killed);
        if next.is_some()
        {
            let history = super::procmgr::logd_history(query, None);
            if SVCMGR_LINES
                .iter()
                .all(|line| history.iter().any(|(_, bytes)| contains(bytes, line)))
            {
                return;
            }
        }
        assert!(
            start.elapsed() < RESTART_TIMEOUT,
            "{phase}: no next logd instance holding svcmgr's restart lines"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The stamp of the oldest entry of logd's history, through `query`, that is
/// stamped at or after `after_us` and holds `line`, read every
/// [`POLL_INTERVAL`] until one is there, for up to [`RESTART_TIMEOUT`].
/// `phase` names the phase in a failure.
pub(super) fn await_line_after(query: u64, line: &[u8], after_us: u64, phase: &str) -> u64
{
    let start = Instant::now();
    loop
    {
        // Newest first: the last match read is the oldest.
        let oldest = super::procmgr::logd_history_with(query, None, |entry| {
            (entry.us >= after_us && contains(entry.bytes, line)).then_some(entry.us)
        })
        .into_iter()
        .rev()
        .flatten()
        .next();
        if let Some(us) = oldest
        {
            return us;
        }
        assert!(
            start.elapsed() < RESTART_TIMEOUT,
            "{phase}: logd's history holds no {:?} line stamped after {after_us} us",
            String::from_utf8_lossy(line)
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool
{
    haystack.windows(needle.len()).any(|w| w == needle)
}
