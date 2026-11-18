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
//! own once, at startup, so the phase registers it again before its next
//! line; otherwise every later svctest line, the terminal marker included,
//! would carry `[?]` (`services/logd/docs/handover-protocol.md`, the
//! restart paragraph).

use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

use crate::arch::current::{IP_OFFSET, REGS_SIZE};
use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The logd restart check; see [`super::all`] for its place.
pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "logd_restart",
        run: logd_restart_phase,
    }]
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
    kill(authority, killed);
    await_restart(caps.logd_query, authority, killed);
    let took = start.elapsed().as_millis();
    std::os::seraph::log::register_name(b"svctest");
    super::procmgr::logd_death_forward_phase(caps);
    std::os::seraph::log!("logd_restart: logd restarted in {took} ms");
}

/// Kill the process `process` (logd) through an attach, which must report it
/// on the core path: stop its main thread, set its instruction pointer to [`UNMAPPED_IP`], and start it, so
/// it takes a fault no handler resolves (see the module documentation).
fn kill(authority: u64, process: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let attach = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &attach, ipc_buf) }
        .unwrap_or_else(|e| panic!("logd_restart: ATTACH_PROCESS ipc_call failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "logd_restart: ATTACH_PROCESS of logd refused ({:#x})",
        reply.label
    );
    assert_ne!(
        reply.word(procmgr_labels::ATTACH_WORD_FLAGS) & procmgr_labels::ATTACH_FLAG_NO_CORE,
        0,
        "logd_restart: logd is not on the core path (no DECLARE_NO_CORE)"
    );
    let threads = reply.caps().to_vec();
    let main = *threads
        .first()
        .expect("logd_restart: the attach returned no main thread");

    syscall::thread_stop(main).expect("logd_restart: stopping logd's main thread");
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(main, &mut regs).expect("logd_restart: reading its registers");
    regs.get_mut(IP_OFFSET..IP_OFFSET + 8)
        .expect("logd_restart: the instruction pointer within the register file")
        .copy_from_slice(&UNMAPPED_IP.to_ne_bytes());
    // SAFETY: the thread is logd's, bound to logd's address space, so the
    // frame it resumes on touches none of svctest's memory; the write only
    // makes it fault.
    unsafe { syscall::thread_write_regs(main, &regs) }
        .expect("logd_restart: writing its instruction pointer");
    syscall::thread_start(main).expect("logd_restart: starting logd's main thread");

    for cap in threads
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Wait until the history of logd's instance after `killed` holds every line
/// of [`SVCMGR_LINES`], which svcmgr writes once it has restarted logd.
fn await_restart(query: u64, authority: u64, killed: u64)
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
            "logd_restart: no next logd instance holding svcmgr's restart lines"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Whether `needle` occurs in `haystack`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool
{
    haystack.windows(needle.len()).any(|w| w == needle)
}
