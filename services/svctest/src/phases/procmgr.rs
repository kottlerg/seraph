// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/procmgr.rs

//! procmgr / `std::process::Command` surface.
//!
//! Hosts the child-mode entries `cwd_child_main` (spawned by
//! `command_cwd_inherit_phase`), `blobs_large_child_main` (spawned by
//! `command_blobs_large_phase`), `park_child_main` (spawned by
//! `command_from_spawned_thread_phase`), `undeliverable_reply_child_main`
//! (spawned by `procmgr_refusals_phase`), and `logd_reclaim_child_main`
//! (spawned by `logd_death_forward_phase`).

use std::os::seraph::process::ChildExt;
use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// `spawn_phase` runs before the namespace cluster.
pub fn spawn_only() -> &'static [Phase]
{
    &[Phase {
        name: "spawn",
        run: spawn_phase,
    }]
}

/// The logd death-forward check, run just after [`spawn_only`].
pub fn logd_forward() -> &'static [Phase]
{
    &[Phase {
        name: "logd_death_forward",
        run: logd_death_forward_phase,
    }]
}

/// The log name [`logd_death_forward_phase`]'s child registers, by which the
/// phase finds the child's slot. No other process registers it. It holds a
/// forged `exit_reason` field, which logd's `reclaim:` line must carry inside
/// the quoted name, never as a field of its own.
const LOGD_RECLAIM_NAME: &[u8] = b"svctest-logd-reclaim exit_reason=0x0";

/// The code [`logd_death_forward_phase`]'s child exits with, which logd
/// reports as the exit reason of the child's retired slot. Nonzero, so the
/// check also sees that the forward carries the exit reason, not only the
/// badge.
const LOGD_RECLAIM_EXIT_CODE: i32 = 0x17;

/// Role token of [`logd_death_forward_phase`]'s child.
const LOGD_RECLAIM_ROLE: &str = "logd-reclaim-child";

/// Register [`LOGD_RECLAIM_NAME`], log under it, and exit with
/// [`LOGD_RECLAIM_EXIT_CODE`]. The registration is a synchronous call, so
/// logd holds the named slot before the child can exit.
///
/// Between the halves of one text line, [`LOGD_PARTIAL_TEXT`] then
/// [`LOGD_RESUMED_TEXT`], the child sends a malformed record, which logd must
/// refuse, and a record with a `code` field of [`LOGD_RECLAIM_EXIT_CODE`].
/// The phase reads the record from logd's history, and the text line whole
/// after it: a record leaves a sender's pending text line as it was. A
/// refused record or a failed send panics, so the exit code differs.
fn logd_reclaim_child_main() -> !
{
    use ipc::stream_labels::{
        LEVEL_INFO, LEVEL_SHIFT, RECORD_REJECTED, STREAM_BYTES, STREAM_RECORD,
    };

    std::os::seraph::log::register_name(LOGD_RECLAIM_NAME);
    let cap = std::os::seraph::log::acquire();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let send = |id: u64, bytes: &[u8]| {
        let label = id | ((bytes.len() as u64) << 16) | (LEVEL_INFO << LEVEL_SHIFT);
        let msg = ipc::IpcMessage::builder(label).bytes(0, bytes).build();
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        unsafe { ipc::ipc_call(cap, &msg, ipc_buf) }
            .expect("logd_reclaim child: log send failed")
            .label
    };
    send(STREAM_BYTES, LOGD_PARTIAL_TEXT);
    // A message length of 5 with no message bytes after it.
    assert_eq!(
        send(STREAM_RECORD, &[5, 0]),
        RECORD_REJECTED,
        "logd_reclaim child: logd accepted a malformed record"
    );
    std::os::seraph::log!("logd-reclaim child exiting"; code = LOGD_RECLAIM_EXIT_CODE);
    send(STREAM_BYTES, LOGD_RESUMED_TEXT);
    std::process::exit(LOGD_RECLAIM_EXIT_CODE)
}

/// The first half of the text line [`logd_reclaim_child_main`] splits around
/// its records; the phase reads the line whole ([`LOGD_WHOLE_TEXT`]).
const LOGD_PARTIAL_TEXT: &[u8] = b"partial text ";

/// The second half, which ends the line.
const LOGD_RESUMED_TEXT: &[u8] = b"line resumed\n";

/// The text line logd retains from the two halves, without its newline.
const LOGD_WHOLE_TEXT: &[u8] = b"partial text line resumed";

/// The message of the child's record.
const LOGD_RECORD_MESSAGE: &[u8] = b"logd-reclaim child exiting";

/// Spawn a child that registers [`LOGD_RECLAIM_NAME`] with logd and exits
/// with [`LOGD_RECLAIM_EXIT_CODE`], and assert that code. procmgr's teardown
/// forwards the death to logd's death queue (`forward_death_to_logd`), and
/// logd evicts the child's slot into its retired slots
/// (`services/logd/docs/ipc-interface.md` § Retired slots). Through the
/// `logd.query` seed the phase reads logd's slots (`QUERY_SLOTS`) until the
/// child's slot is retired by a death, then checks that it is retired once,
/// with exit reason [`LOGD_RECLAIM_EXIT_CODE`], and that no live slot keeps
/// its name. It reads the child's history (`QUERY_HISTORY`), newest first:
/// the whole text line [`LOGD_WHOLE_TEXT`], then the record with its `code`
/// field, and nothing older, so logd retained neither the malformed record
/// nor a part of the split line. Last, a query on svctest's own log cap,
/// whose process badge carries no `LOG_QUERY_AUTHORITY`, must be refused
/// `QUERY_DENIED`; it runs after the eviction is seen, when logd, not
/// init-logd, holds the endpoint.
pub fn logd_death_forward_phase(caps: &Caps)
{
    use ipc::log_query::{QUERY_DENIED, reply_status, slots_request};

    assert_ne!(caps.logd_query, 0, "logd_death_forward: no logd.query seed");
    let status = std::process::Command::new("/tests/svctest")
        .arg(LOGD_RECLAIM_ROLE)
        .status()
        .expect("logd_death_forward: spawn failed");
    assert_eq!(
        status.code(),
        Some(LOGD_RECLAIM_EXIT_CODE),
        "logd_death_forward: child exit code not propagated: {status}"
    );

    let badge = logd_await_retired(caps.logd_query);
    check_logd_history(&logd_history(caps.logd_query, badge));

    let own = std::os::seraph::log::acquire();
    let denied = logd_query_call(own, &slots_request(None));
    assert_eq!(
        reply_status(denied.label),
        QUERY_DENIED,
        "logd_death_forward: a query without LOG_QUERY_AUTHORITY was not refused ({:#x})",
        denied.label
    );
    std::os::seraph::log!("logd_death_forward: child's slot retired with its history: {status}");
}

/// One logd query call on `cap`; a failed call panics.
pub(crate) fn logd_query_call(cap: u64, msg: &ipc::IpcMessage) -> ipc::IpcMessage
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("logd_death_forward: query ipc_call failed ({e})"))
}

/// Every slot named [`LOGD_RECLAIM_NAME`], live or retired, as (badge, state,
/// exit reason), read across every `QUERY_SLOTS` page.
fn logd_named_slots(query: u64) -> Vec<(u64, u8, u64)>
{
    use ipc::log_query::{QUERY_OK, reply_more, reply_status, slot_entry, slots_request};

    let mut found = Vec::new();
    let mut after = None;
    loop
    {
        let reply = logd_query_call(query, &slots_request(after));
        assert_eq!(
            reply_status(reply.label),
            QUERY_OK,
            "logd_death_forward: QUERY_SLOTS refused ({:#x})",
            reply.label
        );
        let mut index = 0;
        while let Some(entry) = slot_entry(&reply, index)
        {
            if entry.name() == LOGD_RECLAIM_NAME
            {
                found.push((entry.badge, entry.state, entry.exit_reason));
            }
            after = Some(entry.cursor());
            index += 1;
        }
        if !reply_more(reply.label)
        {
            return found;
        }
        assert!(
            index > 0,
            "logd_death_forward: QUERY_SLOTS page empty but more"
        );
    }
}

/// Poll logd's slots until the child's slot is retired by a death, check that
/// it is the one slot of that name, retired with [`LOGD_RECLAIM_EXIT_CODE`],
/// and return its badge.
fn logd_await_retired(query: u64) -> u64
{
    use ipc::log_query::{SLOT_EVICTED_DEATH, SLOT_LIVE};

    const POLL_INTERVAL_MS: u64 = 10;
    // 30 s, as `init_cspace_released` polls: procmgr posts the death after
    // its teardown, and logd drains it on its next wake.
    const MAX_POLLS: u32 = 3000;

    let mut retired = false;
    for _ in 0..MAX_POLLS
    {
        if logd_named_slots(query)
            .iter()
            .any(|&(_, state, _)| state == SLOT_EVICTED_DEATH)
        {
            retired = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
    }
    assert!(
        retired,
        "logd_death_forward: child's slot not evicted within the poll budget"
    );
    // A walk is no snapshot: the one that saw the retired slot may have read
    // the live slot on an earlier page, before logd retired it. Once retired,
    // the dead child's badge sends nothing more, so a fresh walk is stable.
    let found = logd_named_slots(query);
    let [(badge, _, exit_reason)] = found[..]
    else
    {
        panic!("logd_death_forward: expected the child's one retired slot, found {found:?}");
    };
    assert_eq!(
        exit_reason,
        u64::from(LOGD_RECLAIM_EXIT_CODE.unsigned_abs()),
        "logd_death_forward: retired slot carries exit reason {exit_reason:#x}"
    );
    assert!(
        !found.iter().any(|&(_, state, _)| state == SLOT_LIVE),
        "logd_death_forward: a live slot keeps the child's name"
    );
    badge
}

/// The history of `badge`, newest first, as (kind, bytes), read across every
/// `QUERY_HISTORY` page.
pub(crate) fn logd_history(query: u64, badge: u64) -> Vec<(u8, Vec<u8>)>
{
    use ipc::log_query::{HistoryEntries, HistoryRequest, QUERY_OK, reply_more, reply_status};

    let mut history = Vec::new();
    let mut req = HistoryRequest {
        badge: Some(badge),
        before: None,
    };
    loop
    {
        let reply = logd_query_call(query, &req.message());
        assert_eq!(
            reply_status(reply.label),
            QUERY_OK,
            "logd_death_forward: QUERY_HISTORY refused ({:#x})",
            reply.label
        );
        let read_before = history.len();
        for entry in HistoryEntries::new(&reply)
        {
            assert_eq!(
                entry.badge, badge,
                "logd_death_forward: another badge's entry"
            );
            history.push((entry.kind, entry.bytes.to_vec()));
            req.before = Some(entry.seq);
        }
        if !reply_more(reply.label)
        {
            return history;
        }
        assert!(
            history.len() > read_before,
            "logd_death_forward: QUERY_HISTORY page empty but more"
        );
    }
}

/// Check the child's history, newest first: exactly the whole text line
/// [`LOGD_WHOLE_TEXT`], then the record [`LOGD_RECORD_MESSAGE`] with its
/// `code` field.
fn check_logd_history(history: &[(u8, Vec<u8>)])
{
    use ipc::log_query::{ENTRY_RECORD, ENTRY_TEXT};

    let [(text_kind, text), (record_kind, record)] = history
    else
    {
        panic!(
            "logd_death_forward: expected the child's text line and record, found {} entries",
            history.len()
        );
    };
    assert_eq!(
        *text_kind, ENTRY_TEXT,
        "logd_death_forward: newest entry is not text"
    );
    assert_eq!(
        text.as_slice(),
        LOGD_WHOLE_TEXT,
        "logd_death_forward: text line not retained whole"
    );
    assert_eq!(
        *record_kind, ENTRY_RECORD,
        "logd_death_forward: older entry is not a record"
    );
    let record = ipc::log_record::Record::decode(record)
        .unwrap_or_else(|e| panic!("logd_death_forward: retained record does not decode ({e:?})"));
    assert_eq!(
        record.message(),
        LOGD_RECORD_MESSAGE,
        "logd_death_forward: record message"
    );
    let fields: Vec<(&[u8], &[u8])> = record.fields().map(|f| (f.key, f.value)).collect();
    assert_eq!(
        fields,
        [(&b"code"[..], &b"23"[..])],
        "logd_death_forward: record fields"
    );
}

/// The init-reap release check. Registered late (see [`super::all`]) so
/// init's reap has almost always run; the phase polls for it in any case.
pub fn init_reap() -> &'static [Phase]
{
    &[Phase {
        name: "init_cspace_released",
        run: init_cspace_released_phase,
    }]
}

/// Wait for init's reap, then assert that it released init's `CSpace`:
/// procmgr's release probe, an endpoint it moved into init's `CSpace` just
/// before deleting its last cap on that `CSpace`, must have been freed with
/// it (`QUERY_INIT_REAP` reports `INIT_REAP_PROBE_RELEASED`; see
/// `services/procmgr/docs/ipc-interface.md` § `QUERY_INIT_REAP`). A kernel
/// that kept init's `CSpace` alive past its last capability reports
/// `INIT_REAP_PROBE_HELD`. The reap waits for init-logd's exit after
/// real-logd's handover, which races svctest's startup, so the phase polls.
pub fn init_cspace_released_phase(_: &Caps)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    const POLL_INTERVAL_MS: u64 = 10;
    // 30 s: far past the handover on every CI cell, short enough to fail
    // rather than hang when the reap never runs.
    const MAX_POLLS: u32 = 3000;

    let procmgr = startup_info().procmgr_endpoint;
    let query = IpcMessage::builder(procmgr_labels::QUERY_INIT_REAP).build();
    for _ in 0..MAX_POLLS
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(procmgr, &query, std::os::seraph::current_ipc_buf()) }
            .unwrap_or_else(|e| panic!("QUERY_INIT_REAP: ipc_call failed ({e})"));
        assert_eq!(
            reply.label,
            procmgr_errors::SUCCESS,
            "QUERY_INIT_REAP: procmgr replied {}",
            reply.label
        );
        if reply.word(0) != 0
        {
            assert_eq!(
                reply.word(1),
                procmgr_labels::INIT_REAP_PROBE_RELEASED,
                "init's CSpace was not released at its reap (probe outcome {})",
                reply.word(1)
            );
            std::os::seraph::log!("init_cspace_released passed");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
    }
    panic!("init_cspace_released: init's reap did not run within the poll budget");
}

/// `command_*`, `stdio_file_unsupported`, `procmgr_refusals`, `procmgr_concurrent_spawn`,
/// `crash_endpoint`,
/// `procmgr_dma_hold`, and `death_queue_growth` run after the namespace cluster has established
/// attenuation invariants.
pub fn command_phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "command_cwd_inherit",
            run: command_cwd_inherit_phase,
        },
        Phase {
            name: "command_cwd_missing",
            run: command_cwd_missing_phase,
        },
        Phase {
            name: "command_invalid_elf_loop",
            run: command_invalid_elf_loop_phase,
        },
        Phase {
            name: "command_blobs_large",
            run: command_blobs_large_phase,
        },
        Phase {
            name: "command_non_utf8_refused",
            run: command_non_utf8_refused_phase,
        },
        Phase {
            name: "command_from_spawned_thread",
            run: command_from_spawned_thread_phase,
        },
        Phase {
            name: "stdio_file_unsupported",
            run: stdio_file_unsupported_phase,
        },
        Phase {
            name: "procmgr_refusals",
            run: procmgr_refusals_phase,
        },
        Phase {
            name: "procmgr_concurrent_spawn",
            run: procmgr_concurrent_spawn_phase,
        },
        Phase {
            name: "crash_endpoint",
            run: super::crash::crash_endpoint_phase,
        },
        Phase {
            name: "procmgr_dma_hold",
            run: procmgr_dma_hold_phase,
        },
        Phase {
            name: "death_queue_growth",
            run: death_queue_growth_phase,
        },
    ]
}

/// Child-mode dispatch for argv tokens this module owns. Matching
/// arms diverge: each child function exits through `std::process::exit`,
/// except `park-child`'s, which parks until its spawner tears it down. On
/// a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == "cwd-child"
    {
        cwd_child_main();
    }
    if role == BLOBS_LARGE_ROLE
    {
        blobs_large_child_main();
    }
    if role == PARK_ROLE
    {
        park_child_main();
    }
    if role == UNDELIVERABLE_ROLE
    {
        undeliverable_reply_child_main();
    }
    if role == LOGD_RECLAIM_ROLE
    {
        logd_reclaim_child_main();
    }
}

/// Children [`death_queue_growth_phase`] holds alive at once. procmgr binds
/// two death observers per live process on its death queues, the first of
/// which holds `FIRST_POOL_OBSERVERS` nodes: half that many children take the
/// whole pool, and svctest's own two nodes, live while the phase runs, push
/// the binds into a further queue whatever else is live.
const GROWTH_CHILDREN: usize = process_table::death_queues::FIRST_POOL_OBSERVERS as usize / 2;

/// Hold [`GROWTH_CHILDREN`] children alive at once, so procmgr's death
/// binds outgrow its first death queue's pool, then let each exit and check
/// its clean exit and procmgr's `QUERY_PROCESS` answer (`EXITED`, reason 0).
/// Each child is `/programs/stdiotest`, blocked on its piped stdin until the
/// phase writes a line to it. A procmgr whose pool did not grow refuses the
/// spawns past it. The phase cannot observe which queue a bind landed on, so
/// it tests growth only while [`GROWTH_CHILDREN`] follows procmgr's pool.
pub fn death_queue_growth_phase(_: &Caps)
{
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let mut children = Vec::with_capacity(GROWTH_CHILDREN);
    for i in 0..GROWTH_CHILDREN
    {
        let child = Command::new("/programs/stdiotest")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!("death_queue_growth: spawn {i} of {GROWTH_CHILDREN} failed: {e}")
            });
        children.push(child);
    }
    for child in &mut children
    {
        assert!(
            child
                .try_wait()
                .expect("death_queue_growth: try_wait failed")
                .is_none(),
            "death_queue_growth: a child exited before its stdin was written"
        );
    }
    std::os::seraph::log!("death_queue_growth: {GROWTH_CHILDREN} children alive at once");

    for mut child in children
    {
        child
            .stdin
            .take()
            .expect("piped child must have stdin handle")
            .write_all(b"x\n")
            .expect("death_queue_growth: write to stdin failed");
        let mut out = String::new();
        child
            .stdout
            .take()
            .expect("piped child must have stdout handle")
            .read_to_string(&mut out)
            .expect("death_queue_growth: read stdout failed");
        assert!(
            out.contains("PASS"),
            "death_queue_growth: child stdout missing PASS: {out:?}"
        );
        let status = child.wait().expect("death_queue_growth: wait failed");
        assert!(
            status.success(),
            "death_queue_growth: child did not exit cleanly: {status}"
        );
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
        let reply = unsafe {
            ipc::ipc_call(
                child.process_handle(),
                &query,
                std::os::seraph::current_ipc_buf(),
            )
        }
        .expect("death_queue_growth: QUERY_PROCESS call failed");
        assert_eq!(
            (reply.label, reply.word(0), reply.word(1)),
            (
                ipc::procmgr_errors::SUCCESS,
                ipc::procmgr_process_state::EXITED,
                0
            ),
            "death_queue_growth: QUERY_PROCESS after wait"
        );
    }
    std::os::seraph::log!("death_queue_growth: every child exited cleanly");
}

/// argv[1] of a child that parks until it is torn down; the
/// `command_from_spawned_thread` cells kill and drop it.
const PARK_ROLE: &str = "park-child";

fn park_child_main() -> !
{
    loop
    {
        std::thread::park();
    }
}

fn cwd_child_main() -> !
{
    if std::os::seraph::current_dir_cap() == 0
    {
        std::process::exit(4);
    }
    match std::fs::File::open("test.txt")
    {
        Ok(_) => std::process::exit(0),
        Err(_) => std::process::exit(5),
    }
}

pub fn spawn_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/hello")
        .arg("one")
        .arg("two")
        .env("SPAWNED_BY", "svctest")
        .spawn()
        .expect("spawn /programs/hello failed");

    let id = child.process_handle();
    std::os::seraph::log!("spawned /programs/hello handle={id:#x}");

    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let id = child.process_handle();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply =
            unsafe { ipc::ipc_call(id, &query, ipc_buf) }.expect("QUERY_PROCESS call failed");
        assert_eq!(
            reply.label,
            ipc::procmgr_errors::SUCCESS,
            "QUERY_PROCESS non-success label"
        );
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        match state
        {
            s if s == ipc::procmgr_process_state::ALIVE =>
            {
                assert_eq!(exit_reason, 0, "ALIVE process must report exit_reason=0");
            }
            s if s == ipc::procmgr_process_state::EXITED =>
            {
                assert_eq!(
                    exit_reason, 0,
                    "clean child must report exit_reason=0, got {exit_reason:#x}"
                );
            }
            other => panic!("expected ALIVE or EXITED, got {other}"),
        }
        std::os::seraph::log!("query_process pre-wait passed (state={state})");
    }

    let status = child.wait().expect("child wait failed");
    std::os::seraph::log!("child exited: {status}");
    assert!(
        status.success(),
        "child /programs/hello did not exit cleanly: {status}"
    );

    let again = child.try_wait().expect("try_wait after wait failed");
    assert!(
        again.is_some(),
        "try_wait after wait must surface cached status"
    );
    std::os::seraph::log!("try_wait phase passed");

    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply =
            unsafe { ipc::ipc_call(id, &query, ipc_buf) }.expect("QUERY_PROCESS call failed");
        assert_eq!(
            reply.label,
            ipc::procmgr_errors::SUCCESS,
            "QUERY_PROCESS non-success label after auto-reap"
        );
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED after auto-reap, got {state}"
        );
        assert_eq!(
            exit_reason, 0,
            "clean child must report exit_reason=0, got {exit_reason:#x}"
        );
        std::os::seraph::log!("auto_reap (EXITED) passed");
    }

    std::os::seraph::log!("spawn phase passed");
}

pub fn command_cwd_inherit_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/tests/svctest")
        .arg("cwd-child")
        .current_dir("/data")
        .spawn()
        .expect("Command::cwd(/data) must spawn cleanly");
    let status = child.wait().expect("wait on cwd-inherit child failed");
    let code = status.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "cwd-inherit child exit code {code}: \
         4=current_dir_cap zero, 5=relative open failed (see cwd_child_main)"
    );
    std::os::seraph::log!("command_cwd_inherit phase passed");
}

pub fn command_cwd_missing_phase(_: &Caps)
{
    use std::process::Command;

    let err = Command::new("/tests/svctest")
        .arg("cwd-child")
        .current_dir("/this/does/not/exist")
        .spawn()
        .expect_err("Command::cwd on unreachable path must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected NotFound from cwd walk failure, got {err:?}",
    );
    std::os::seraph::log!("command_cwd_missing phase passed");
}

pub fn command_invalid_elf_loop_phase(_: &Caps)
{
    use std::process::Command;

    for i in 0..16
    {
        let err = Command::new("/data/test.txt")
            .spawn()
            .expect_err("spawning a non-ELF path must fail");
        let _ = i;
        let _ = err;
    }

    let mut child = Command::new("/programs/hello")
        .spawn()
        .expect("legitimate spawn after invalid-ELF loop failed");
    let status = child.wait().expect("wait on hello after loop failed");
    assert_eq!(
        status.code().unwrap_or(-1),
        0,
        "hello after invalid-ELF loop exited non-zero",
    );
    std::os::seraph::log!("command_invalid_elf_loop phase passed");
}

/// Fixture the blob cells spawn: svctest itself, re-entered through
/// [`reentry_main`] as [`BLOBS_LARGE_ROLE`] so the child can check what
/// reached it. Its path is argv[0] on the wire.
const BLOB_FIXTURE: &str = "/tests/svctest";
/// argv[1] of the large-blob cell's child; dispatches to
/// `blobs_large_child_main`.
const BLOBS_LARGE_ROLE: &str = "blobs-large-child";
/// Bytes of the one long argv token, 3 MiB: past the 512 pages a child's
/// seed page-table pool covers (so procmgr funds the child's page tables for
/// the region), across many of procmgr's and the spawner's 64-page copy
/// windows, and far past the 256 B a whole argv blob once had.
const BLOBS_FILLER_BYTES: usize = 3 << 20;
/// Short argv tokens after the long one, past the 255 an 8-bit count field
/// once held.
const BLOBS_EXTRA_ARGS: usize = 300;
/// Bytes of the value of the long env entry, `K`.
const BLOBS_ENV_VALUE_BYTES: usize = 5000;
/// Short env entries beside `K`, past the 255 an 8-bit count field once held.
const BLOBS_EXTRA_ENVS: usize = 260;
/// Exit code of the large-blob child when argv is not what the parent packed.
const BLOBS_CHILD_BAD_ARGV: i32 = 6;
/// Exit code of the large-blob child when env is not what the parent packed.
const BLOBS_CHILD_BAD_ENV: i32 = 7;

/// The argv the large-blob child must see, argv[0] first: about 3 MiB in
/// 303 strings.
fn blobs_large_args() -> Vec<String>
{
    let mut args = vec![
        String::from(BLOB_FIXTURE),
        String::from(BLOBS_LARGE_ROLE),
        "a".repeat(BLOBS_FILLER_BYTES),
    ];
    args.extend((0..BLOBS_EXTRA_ARGS).map(|i| format!("t{i}")));
    args
}

/// The env the large-blob child must see, sorted by key: about 7 KiB in 261
/// entries.
fn blobs_large_env() -> Vec<(String, String)>
{
    let mut env: Vec<(String, String)> = (0..BLOBS_EXTRA_ENVS)
        .map(|i| (format!("E{i:03}"), i.to_string()))
        .collect();
    env.push((String::from("K"), "v".repeat(BLOBS_ENV_VALUE_BYTES)));
    env.sort();
    env
}

/// Child main of the large-blob cell. Exits `0` only when argv and env
/// reproduce, entry for entry, what [`command_blobs_large_phase`] packed; a
/// blob procmgr truncated or degraded would otherwise still look like a
/// clean exit to the parent.
fn blobs_large_child_main() -> !
{
    let args: Vec<String> = std::env::args().collect();
    if args != blobs_large_args()
    {
        let lens: Vec<usize> = args.iter().map(String::len).take(4).collect();
        std::os::seraph::log!(
            "blobs-large-child: argv mismatch, {} tokens, first lengths {lens:?}",
            args.len()
        );
        std::process::exit(BLOBS_CHILD_BAD_ARGV);
    }
    let mut vars: Vec<(String, String)> = std::env::vars().collect();
    vars.sort();
    if vars != blobs_large_env()
    {
        std::os::seraph::log!("blobs-large-child: env mismatch, {} entries", vars.len());
        std::process::exit(BLOBS_CHILD_BAD_ENV);
    }
    std::process::exit(0);
}

/// argv and env far past the 256 B per blob and 255 strings per count that
/// once rode inline in the create message: `Command::spawn` packs them into a
/// Memory cap, procmgr copies them into the child's argv/env region, and the
/// child (`blobs_large_child_main`) must see both intact — it exits
/// [`BLOBS_CHILD_BAD_ARGV`] or [`BLOBS_CHILD_BAD_ENV`] when either was
/// degraded or truncated on the way. `env_clear` keeps svctest's own
/// `SERAPH_*` entries out of the comparison.
pub fn command_blobs_large_phase(_: &Caps)
{
    let mut child = std::process::Command::new(BLOB_FIXTURE)
        .args(&blobs_large_args()[1..])
        .env_clear()
        .envs(blobs_large_env())
        .spawn()
        .expect("argv and env past the former inline limits must spawn");
    let status = child.wait().expect("wait on the large-blob child failed");
    assert_eq!(
        status.code(),
        Some(0),
        "large-blob child exit {status}: {BLOBS_CHILD_BAD_ARGV}=argv mismatch, \
         {BLOBS_CHILD_BAD_ENV}=env mismatch (see blobs_large_child_main)"
    );
    std::os::seraph::log!("command_blobs_large phase passed");
}

/// The process ABI defines argv and env as UTF-8 strings, so std refuses a
/// non-UTF-8 argument or env value with `InvalidInput` before any child is
/// created.
pub fn command_non_utf8_refused_phase(_: &Caps)
{
    // SAFETY: safe Rust cannot build a non-UTF-8 `OsString` here, since
    // `std::os::seraph` offers no `OsStringExt::from_vec`. This target's
    // `OsStr` uses std's byte-string encoding, which accepts every byte
    // sequence, so `[0xFF]` is a validly encoded `OsStr` on it.
    let invalid = unsafe { std::ffi::OsString::from_encoded_bytes_unchecked(vec![0xFF]) };

    let err = std::process::Command::new(BLOB_FIXTURE)
        .arg(&invalid)
        .spawn()
        .expect_err("a non-UTF-8 argument must not spawn");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a non-UTF-8 argument must surface as InvalidInput, got {err:?}"
    );

    let err = std::process::Command::new(BLOB_FIXTURE)
        .env("SVCTEST_NON_UTF8", &invalid)
        .spawn()
        .expect_err("a non-UTF-8 env value must not spawn");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a non-UTF-8 env value must surface as InvalidInput, got {err:?}"
    );
    std::os::seraph::log!("command_non_utf8_refused phase passed");
}

/// `Command::spawn`, `Child::kill`, and dropping an unwaited `Child` each
/// call procmgr through the calling thread's IPC buffer, so all three must
/// work from a spawned thread as from main. The kill and drop cells use an
/// unpiped child, which has no death bridge to tear it down instead, and
/// check through procmgr that the child is gone.
pub fn command_from_spawned_thread_phase(_: &Caps)
{
    use ipc::procmgr_process_state::EXITED;
    use std::process::Command;

    let spawner = std::thread::Builder::new()
        .name("command_spawner".into())
        .spawn(|| {
            let output = Command::new("/programs/hello")
                .output()
                .expect("Command::output from a spawned thread failed");
            assert!(
                output.status.success(),
                "hello spawned from a thread did not exit cleanly: {}",
                output.status
            );
            assert!(
                !output.stdout.is_empty(),
                "hello spawned from a thread produced no stdout"
            );

            let mut child = Command::new("/tests/svctest")
                .arg(PARK_ROLE)
                .spawn()
                .expect("spawning the park child to kill failed");
            child
                .kill()
                .expect("Child::kill from a spawned thread failed");
            let status = child.wait().expect("wait on the killed park child failed");
            assert_eq!(
                status.to_string(),
                "killed",
                "a killed child must report killed, got {status}"
            );
            // `Child::kill` sends `DESTROY_PROCESS`, which records the exit:
            // the parked child answers `EXITED` with `EXIT_KILLED`.
            let (state, reason) = process_state_and_reason(child.process_handle());
            assert_eq!(
                (state, reason),
                (EXITED, syscall_abi::EXIT_KILLED),
                "Child::kill from a spawned thread left the child in state {state} (reason {reason:#x})"
            );

            let unwaited = Command::new("/tests/svctest")
                .arg(PARK_ROLE)
                .spawn()
                .expect("spawning the park child to drop failed");
            let handle = syscall::cap_derive(unwaited.process_handle(), syscall::RIGHTS_ALL)
                .expect("copying the unwaited child's process handle failed");
            // Dropping an unwaited `Child` destroys it (`DESTROY_PROCESS`),
            // which records the exit as the kill cell's does.
            drop(unwaited);
            let (state, reason) = process_state_and_reason(handle);
            let _ = syscall::cap_delete(handle);
            assert_eq!(
                (state, reason),
                (EXITED, syscall_abi::EXIT_KILLED),
                "dropping an unwaited Child on a spawned thread left the child in state {state} (reason {reason:#x})"
            );
        })
        .expect("command_from_spawned_thread spawn failed");
    spawner
        .join()
        .expect("command_from_spawned_thread child panicked");
    std::os::seraph::log!("command_from_spawned_thread phase passed");
}

/// The `procmgr_process_state` value and exit reason procmgr reports for the
/// process behind `handle`, asked through the calling thread's IPC buffer.
/// After a destroy or reap procmgr still answers on the handle, with
/// `EXITED` while it holds the exit record (the recent-exit window, best
/// effort) and `UNKNOWN` after, so a failed call or a refusal is a test
/// failure, not a sign the process is gone.
fn process_state_and_reason(handle: u64) -> (u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(handle, &query, ipc_buf) }
        .expect("QUERY_PROCESS on the child's process handle failed");
    assert_eq!(
        reply.label,
        ipc::procmgr_errors::SUCCESS,
        "QUERY_PROCESS refused the child's process handle"
    );
    (reply.word(0), reply.word(1))
}

pub fn stdio_file_unsupported_phase(_: &Caps)
{
    use std::fs::File;
    use std::io::ErrorKind;
    use std::process::{Command, Stdio};

    let file = File::open("/data/test.txt").expect("open /data/test.txt for stdio probe");
    let err = Command::new("/programs/hello")
        .stdout(Stdio::from(file))
        .spawn()
        .expect_err("Stdio::from(File) must surface as Unsupported on seraph");
    assert_eq!(
        err.kind(),
        ErrorKind::Unsupported,
        "Stdio::from(File) spawn error must be Unsupported, got {err:?}"
    );
    std::os::seraph::log!("stdio_file_unsupported phase passed");
}

/// Rounds of each refused request in [`procmgr_refusals_phase`]: the phase
/// repeats every request, as a client flooding procmgr would.
const REFUSAL_ROUNDS: usize = 16;

/// Threads that spawn at once in [`procmgr_concurrent_spawn_phase`].
const CONCURRENT_SPAWNERS: usize = 4;

/// Spawns each of those threads makes, one after another.
const SPAWNS_PER_THREAD: usize = 3;

/// The size the stalled create names for its file: any nonzero size, since
/// procmgr opens the file before it reads the size.
const STALLED_FILE_SIZE: u64 = 4096;

/// procmgr serves a create on one request worker while others serve the
/// rest (services/procmgr/README.md § Concurrency). A thread of svctest
/// serves an endpoint whose SEND cap is the file cap of a `CREATE_FROM_FILE`
/// another thread makes, and holds procmgr's `FS_OPEN` unanswered. While
/// it is held, [`CONCURRENT_SPAWNERS`] threads each spawn `/programs/hello`
/// [`SPAWNS_PER_THREAD`] times, at once, and every child must exit cleanly.
/// The server never answers, and the stalled create must fail with
/// `IO_ERROR` once procmgr's bound on the call passes
/// (`FILE_CAP_CALL_TIMEOUT_MS`, services/procmgr/docs/ipc-interface.md
/// § Label 13).
pub fn procmgr_concurrent_spawn_phase(_: &Caps)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
    use std::sync::mpsc;

    let endpoint =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
        .expect("procmgr_concurrent_spawn: endpoint creation failed");
    let file = syscall::cap_derive(endpoint, syscall::RIGHTS_EP_SEND)
        .expect("procmgr_concurrent_spawn: deriving the file cap failed");

    // The stalled file server: receive procmgr's FS_OPEN, report its label,
    // and never answer it; the thread ends when told to.
    let (opened_tx, opened_rx) = mpsc::channel::<u64>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let server = std::thread::Builder::new()
        .name("stalled-fs".into())
        .spawn(move || {
            let ipc_buf = std::os::seraph::current_ipc_buf();
            // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
            let req = unsafe { ipc::ipc_recv(endpoint, ipc_buf) }
                .expect("stalled file server: receive failed");
            for &cap in req.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            opened_tx
                .send(req.label)
                .expect("stalled file server: report failed");
            release_rx
                .recv()
                .expect("stalled file server: release failed");
        })
        .expect("procmgr_concurrent_spawn: server thread spawn failed");

    let stalled = std::thread::Builder::new()
        .name("stalled-create".into())
        .spawn(move || {
            let create = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
                .word(0, STALLED_FILE_SIZE)
                .cap(file)
                .build();
            // SAFETY: `current_ipc_buf` is this thread's registered IPC
            // buffer page.
            unsafe {
                ipc::ipc_call(
                    startup_info().procmgr_endpoint,
                    &create,
                    std::os::seraph::current_ipc_buf(),
                )
            }
            .expect("stalled CREATE_FROM_FILE call failed")
            .label
        })
        .expect("procmgr_concurrent_spawn: create thread spawn failed");

    let label = opened_rx
        .recv()
        .expect("procmgr_concurrent_spawn: the stalled server never reported");
    assert_eq!(
        label,
        ipc::fs_labels::FS_OPEN,
        "the stalled file server received label {label}, not FS_OPEN"
    );

    let spawners: Vec<_> = (0..CONCURRENT_SPAWNERS)
        .map(|i| {
            std::thread::Builder::new()
                .name(format!("spawner-{i}"))
                .spawn(move || {
                    for n in 0..SPAWNS_PER_THREAD
                    {
                        let status = std::process::Command::new("/programs/hello")
                            .status()
                            .unwrap_or_else(|e| {
                                panic!("spawner {i}: spawn {n} beside a stalled create failed: {e}")
                            });
                        assert!(
                            status.success(),
                            "spawner {i}: hello {n} beside a stalled create exited {status}"
                        );
                    }
                })
                .expect("procmgr_concurrent_spawn: spawner thread spawn failed")
        })
        .collect();
    for spawner in spawners
    {
        spawner
            .join()
            .expect("procmgr_concurrent_spawn: a spawner panicked");
    }

    let code = stalled
        .join()
        .expect("procmgr_concurrent_spawn: the stalled create panicked");
    assert_eq!(
        code,
        procmgr_errors::IO_ERROR,
        "a create whose FS_OPEN went unanswered replied {code}, not IO_ERROR"
    );
    release_tx
        .send(())
        .expect("procmgr_concurrent_spawn: releasing the server failed");
    server
        .join()
        .expect("procmgr_concurrent_spawn: the stalled server panicked");
    let _ = syscall::cap_delete(endpoint);
}

/// A cap to attach to a request: a SEND copy of svctest's own procmgr cap,
/// which the call moves into procmgr's `CSpace`.
fn spare_cap() -> u64
{
    syscall::cap_derive(startup_info().procmgr_endpoint, syscall::RIGHTS_EP_SEND)
        .expect("deriving a spare cap to attach failed")
}

/// Call `target` with `msg` and assert procmgr replies `want`.
fn expect_reply(target: u64, msg: &ipc::IpcMessage, want: u64, what: &str)
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(target, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"));
    assert_eq!(reply.label, want, "{what}: procmgr replied {}", reply.label);
}

/// procmgr refuses a `CREATE_FROM_FILE` asking `CREATE_PHYS_ACCESS` from
/// svctest, which is not phys-class, with `INVALID_ARGUMENT`
/// (`services/procmgr/docs/ipc-interface.md` § Label 1, **Physical-address
/// flag**).
fn phys_access_refused(procmgr: u64)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let (file, size) = hello_file();
    expect_reply(
        procmgr,
        &IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_PHYS_ACCESS)
            .word(0, size)
            .cap(file)
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_FROM_FILE with CREATE_PHYS_ACCESS from a creator that is not phys-class",
    );
}

/// procmgr refuses `ATTACH_PROCESS`, `DETACH_PROCESS`, `LIST_PROCESSES`, and
/// `REGISTER_CRASH_SERVICE` from svctest, whose procmgr cap carries no
/// `DEBUG_AUTHORITY`, with `UNAUTHORIZED`, whatever badge the request names:
/// the authority check precedes the target lookup
/// (`services/procmgr/docs/ipc-interface.md` § `ATTACH_PROCESS`).
fn debug_authority_refused(procmgr: u64)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    for target in [0, u64::MAX >> 4]
    {
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
                .word(0, target)
                .word(1, 0)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "ATTACH_PROCESS without DEBUG_AUTHORITY",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::DETACH_PROCESS)
                .word(0, target)
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "DETACH_PROCESS without DEBUG_AUTHORITY",
        );
    }
    expect_reply(
        procmgr,
        &IpcMessage::builder(procmgr_labels::LIST_PROCESSES)
            .word(0, 0)
            .build(),
        procmgr_errors::UNAUTHORIZED,
        "LIST_PROCESSES without DEBUG_AUTHORITY",
    );
    let thread = syscall::cap_derive(
        std::os::seraph::thread::current_thread_cap(),
        syscall::RIGHTS_THREAD_OBSERVE,
    )
    .expect("deriving a thread cap to register failed");
    expect_reply(
        procmgr,
        &IpcMessage::builder(procmgr_labels::REGISTER_CRASH_SERVICE)
            .cap(thread)
            .build(),
        procmgr_errors::UNAUTHORIZED,
        "REGISTER_CRASH_SERVICE without DEBUG_AUTHORITY",
    );
}

/// Look up `/programs/hello` and return `(file_cap, size)`.
fn hello_file() -> (u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let root = std::os::seraph::root_dir_cap();
    let (programs, _, _) = crate::ipc_util::ns::ns_lookup(root, b"programs", 0xFFFF, ipc_buf)
        .expect("ns_lookup /programs failed");
    let (file, _, size) = crate::ipc_util::ns::ns_lookup(programs, b"hello", 0xFFFF, ipc_buf)
        .expect("ns_lookup /programs/hello failed");
    let _ = syscall::cap_delete(programs);
    (file, size)
}

/// procmgr refuses requests whose sender or shape its wire contract does not
/// admit, and deletes every cap they carried (see
/// `services/procmgr/docs/ipc-interface.md` § Capability Transfer):
/// `REGISTER_DEATH_EQ` and `QUERY_LIVE_PROCESSES` (whose badge list names
/// process handles) from a sender without the `DEATH_EQ_AUTHORITY` badge,
/// the init-reap labels (`REGISTER_INIT_TEARDOWN`, `INIT_TEARDOWN_DONE`) from
/// any badged sender, an unknown opcode, a `CREATE_FROM_FILE` that sets
/// `CREATE_DEATH_RELAY` on a message whose only cap is the file cap, a
/// `CREATE_FROM_FILE` asking `CREATE_PHYS_ACCESS` (a phys-class child) from
/// svctest, which is not phys-class, `ATTACH_PROCESS` and
/// `REGISTER_CRASH_SERVICE` from a sender without the `DEBUG_AUTHORITY` badge,
/// and a `CONFIGURE_PIPE` with an unknown
/// direction or for a direction already configured. Each refused request
/// carries caps. procmgr's slot count is not observable from a client, so
/// each cell asserts the refusal reply, and a
/// spawn afterwards shows procmgr still serves. The phase then checks that
/// procmgr destroys a child whose create reply it cannot deliver
/// ([`undeliverable_reply_child_main`]).
pub fn procmgr_refusals_phase(_: &Caps)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let procmgr = startup_info().procmgr_endpoint;
    for _ in 0..REFUSAL_ROUNDS
    {
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::REGISTER_DEATH_EQ)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "REGISTER_DEATH_EQ without DEATH_EQ_AUTHORITY",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::QUERY_LIVE_PROCESSES)
                .word(0, 0)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "QUERY_LIVE_PROCESSES without DEATH_EQ_AUTHORITY",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN)
                .word(0, 1)
                .cap(spare_cap())
                .cap(spare_cap())
                .cap(spare_cap())
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "REGISTER_INIT_TEARDOWN first round from a badged sender",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN)
                .word(0, 0)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "REGISTER_INIT_TEARDOWN donation round from a badged sender",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(procmgr_labels::INIT_TEARDOWN_DONE)
                .cap(spare_cap())
                .build(),
            procmgr_errors::UNAUTHORIZED,
            "INIT_TEARDOWN_DONE from a badged sender",
        );
        expect_reply(
            procmgr,
            &IpcMessage::builder(4).cap(spare_cap()).build(),
            procmgr_errors::UNKNOWN_OPCODE,
            "unassigned label 4",
        );
        let (file, size) = hello_file();
        expect_reply(
            procmgr,
            &IpcMessage::builder(
                procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_DEATH_RELAY,
            )
            .word(0, size)
            .cap(file)
            .build(),
            procmgr_errors::INVALID_ARGUMENT,
            "CREATE_FROM_FILE with the relay flag and only the file cap",
        );
        phys_access_refused(procmgr);
        debug_authority_refused(procmgr);
    }

    configure_pipe_refusals();
    argv_env_refusals();

    let status = std::process::Command::new("/programs/hello")
        .status()
        .expect("spawn after the refused requests failed");
    assert!(
        status.success(),
        "hello after the refused requests exited {status}"
    );

    let status = std::process::Command::new("/tests/svctest")
        .arg(UNDELIVERABLE_ROLE)
        .status()
        .expect("spawning the undeliverable-reply child failed");
    assert_eq!(
        status.code(),
        Some(0),
        "undeliverable-reply child exit {status}: {UNDELIVERABLE_LOOKUP_FAILED}=lookup failed, \
         {UNDELIVERABLE_REPLY_DELIVERED}=create reply delivered or not refused, \
         {UNDELIVERABLE_POOL_QUERY_FAILED}=pool query failed, \
         {UNDELIVERABLE_NEVER_RECLAIMED}=the child's pages were never reclaimed, \
         {UNDELIVERABLE_CALL_FAILED}=the create call failed, \
         {UNDELIVERABLE_GRANT_FAILED}=a reserve-spending grant failed"
    );
    std::os::seraph::log!("procmgr_refusals phase passed");
}

/// procmgr refuses, with `INVALID_ARGUMENT`, a `CREATE_FROM_FILE` whose argv
/// and env it cannot deliver intact (see
/// `services/procmgr/docs/ipc-interface.md` § Label 1: `CREATE_PROCESS`,
/// **argv and env**). Before it acquires anything for the child: a header
/// longer than its cap, an argv/env cap that is not a Memory cap, the flag
/// without the cap, and a label still carrying the former inline argv fields
/// in bits `[32..64]`. During the copy, after it registers the child with
/// memmgr: a Memory cap the kernel will not map for it, and, on the child's
/// copy, a blob whose NULs disagree with its count or that lacks its final
/// NUL. [`create_process_argv_env_refusals`] covers the `CREATE_PROCESS`
/// side. A spawn afterwards in [`procmgr_refusals_phase`] shows procmgr still
/// serves.
fn argv_env_refusals()
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
    use std::os::seraph::process::ArgvEnvCap;

    let procmgr = startup_info().procmgr_endpoint;
    let label = procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_ARGV_ENV;
    let blob = b"/programs/hello\0";
    let len = blob.len() as u64;
    let page = syscall_abi::PAGE_SIZE;
    let cells: [(&str, [u64; 4]); 3] = [
        ("a header longer than its one-page cap", [page + 1, 1, 0, 0]),
        ("an argv count its NULs disagree with", [len, 2, 0, 0]),
        ("an argv blob without its final NUL", [len - 1, 1, 0, 0]),
    ];
    for (what, header) in cells
    {
        let argv_env = ArgvEnvCap::new(blob, 1, b"", 0)
            .expect("building the argv/env cap failed")
            .expect("a nonempty argv builds a cap");
        let (file, size) = hello_file();
        expect_reply(
            procmgr,
            &IpcMessage::builder(label)
                .word(0, size)
                .words(1, &header)
                .cap(file)
                .cap(argv_env.cap())
                .build(),
            procmgr_errors::INVALID_ARGUMENT,
            what,
        );
    }

    let (file, size) = hello_file();
    expect_reply(
        procmgr,
        &IpcMessage::builder(label)
            .word(0, size)
            .words(1, &[len, 1, 0, 0])
            .cap(file)
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_ARGV_ENV with only the file cap",
    );

    let (file, size) = hello_file();
    expect_reply(
        procmgr,
        &IpcMessage::builder(label)
            .word(0, size)
            .words(1, &[len, 1, 0, 0])
            .cap(file)
            .cap(spare_cap())
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_ARGV_ENV with an endpoint cap as the argv/env cap",
    );

    // A Memory cap with no rights passes the size check (`cap_info` needs
    // none), and the kernel then refuses procmgr's map of it.
    let argv_env = ArgvEnvCap::new(blob, 1, b"", 0)
        .expect("building the argv/env cap failed")
        .expect("a nonempty argv builds a cap");
    let no_rights =
        syscall::cap_derive(argv_env.cap(), 0).expect("deriving a rights-free argv/env cap failed");
    let (file, size) = hello_file();
    expect_reply(
        procmgr,
        &IpcMessage::builder(label)
            .word(0, size)
            .words(1, &[len, 1, 0, 0])
            .cap(file)
            .cap(no_rights)
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_ARGV_ENV with a Memory cap that has no map right",
    );

    let (file, size) = hello_file();
    expect_reply(
        procmgr,
        &IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | (len << 32) | (1 << 48))
            .word(0, size)
            .bytes(1, blob)
            .cap(file)
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "a create label with the former inline argv fields",
    );

    create_process_argv_env_refusals();
}

/// The `CREATE_PROCESS` side of [`argv_env_refusals`]: the same split and
/// header checks, with the header at data word 0. Each refusal comes before
/// procmgr maps the module, so a spare cap stands in for it; svctest holds no
/// boot-module Memory cap, so no cell here spawns a child through
/// `CREATE_PROCESS`.
fn create_process_argv_env_refusals()
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
    use std::os::seraph::process::ArgvEnvCap;

    let procmgr = startup_info().procmgr_endpoint;
    let label = procmgr_labels::CREATE_PROCESS | procmgr_labels::CREATE_ARGV_ENV;
    let blob = b"/programs/hello\0";
    let len = blob.len() as u64;
    let page = syscall_abi::PAGE_SIZE;
    let cells: [(&str, [u64; 4]); 2] = [
        (
            "CREATE_PROCESS with a header longer than its cap",
            [page + 1, 1, 0, 0],
        ),
        (
            "CREATE_PROCESS with an argv count its NULs disagree with",
            [len, 2, 0, 0],
        ),
    ];
    for (what, header) in cells
    {
        let argv_env = ArgvEnvCap::new(blob, 1, b"", 0)
            .expect("building the argv/env cap failed")
            .expect("a nonempty argv builds a cap");
        expect_reply(
            procmgr,
            &IpcMessage::builder(label)
                .words(0, &header)
                .cap(spare_cap())
                .cap(argv_env.cap())
                .build(),
            procmgr_errors::INVALID_ARGUMENT,
            what,
        );
    }
    expect_reply(
        procmgr,
        &IpcMessage::builder(label)
            .words(0, &[len, 1, 0, 0])
            .cap(spare_cap())
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_PROCESS with CREATE_ARGV_ENV and only the module cap",
    );
}

/// Sample windows [`procmgr_dma_hold_phase`] retries: memmgr's free-pool size
/// is system-wide, and other processes (crasher shares the boot) can move it
/// inside one.
const DMA_HOLD_WINDOWS: u32 = 8;
/// Pool queries per window: while the held child's pages must stay out of
/// the pool, and after the release until they are back. A test wait bound: it
/// limits only how long a window polls.
const DMA_HOLD_POLLS: u32 = 256;
/// `QUERY_PROCESS` polls for the held child's exit. A test wait bound.
const DMA_HOLD_EXIT_POLLS: u32 = 100_000;

/// The caps the create reply of a `CREATE_DMA_HOLD` child carries.
struct HeldHello
{
    handle: u64,
    thread: u64,
    /// The release token, the only cap `RELEASE_HOLD` releases on.
    token: u64,
}

impl HeldHello
{
    /// Delete the three caps.
    fn delete(&self)
    {
        for cap in [self.thread, self.handle, self.token]
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// Create `/programs/hello` through raw `CREATE_FROM_FILE` with
/// `CREATE_DMA_HOLD` and return its reply caps, the release token among them.
fn create_held_hello() -> HeldHello
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let (file, size) = hello_file();
    let create =
        IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_DMA_HOLD)
            .word(0, size)
            .cap(file)
            .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().procmgr_endpoint,
            &create,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .expect("CREATE_FROM_FILE with CREATE_DMA_HOLD call failed");
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "CREATE_FROM_FILE with CREATE_DMA_HOLD refused"
    );
    match reply.caps()
    {
        &[handle, thread, token] => HeldHello {
            handle,
            thread,
            token,
        },
        other => panic!(
            "CREATE_FROM_FILE with CREATE_DMA_HOLD replied {} caps",
            other.len()
        ),
    }
}

/// memmgr's free-pool size, asserting the query succeeds.
fn pool_free() -> u64
{
    std::os::seraph::memmgr_pool_free_bytes().expect("memmgr QUERY_POOL_STATUS failed")
}

/// Whether memmgr's free pool reads `level` within [`DMA_HOLD_POLLS`] polls.
fn pool_returns_to(level: u64) -> bool
{
    for _ in 0..DMA_HOLD_POLLS
    {
        if pool_free() == level
        {
            return true;
        }
        std::thread::yield_now();
    }
    false
}

/// Start the held child behind `handle`, wait for it to exit, and destroy it,
/// so procmgr has torn it down before the call returns.
fn run_held_child_to_teardown(handle: u64)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels, procmgr_process_state};

    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::START_PROCESS),
        procmgr_errors::SUCCESS,
        "START_PROCESS of the held child",
    );
    let exited = (0..DMA_HOLD_EXIT_POLLS).any(|_| {
        let exited = process_state_and_reason(handle).0 == procmgr_process_state::EXITED;
        if !exited
        {
            std::thread::yield_now();
        }
        exited
    });
    assert!(exited, "the held child did not exit");
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        procmgr_errors::SUCCESS,
        "DESTROY_PROCESS of the exited held child",
    );
}

/// procmgr's held reclaim (`CREATE_DMA_HOLD`, `RELEASE_HOLD`;
/// `services/procmgr/docs/ipc-interface.md` § Label 1 and § Label 3): a held
/// child that was started keeps its pages out of memmgr's free pool after its
/// teardown, until its creator's `RELEASE_HOLD` on the release token, which
/// returns them, and a second release finds nothing; `RELEASE_HOLD` on the
/// process handle, whose badge lacks `HOLD_RELEASE_AUTHORITY` as every copy
/// of the child's own procmgr cap's does, is refused and the hold stays;
/// `RELEASE_HOLD` on a live child, or on one never started, finds nothing to
/// release; and a held child destroyed before its start is reclaimed at
/// once. This is the procmgr
/// side of devmgr's order for a DMA-capable driver (docs/process-lifecycle.md
/// § Process Death); no boot can kill a `VirtIO` driver with a request in
/// flight and observe its frames reused
/// (services/devmgr/docs/responsibilities.md § Responsibilities).
pub fn procmgr_dma_hold_phase(_: &Caps)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let release = IpcMessage::new(procmgr_labels::RELEASE_HOLD);

    // Never started: no hold, reclaimed at its destroy.
    let unstarted = (0..DMA_HOLD_WINDOWS).any(|_| {
        let before = pool_free();
        let child = create_held_hello();
        expect_reply(
            child.token,
            &release,
            procmgr_errors::INVALID_BADGE,
            "RELEASE_HOLD on a live held child",
        );
        expect_reply(
            child.handle,
            &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
            procmgr_errors::SUCCESS,
            "DESTROY_PROCESS of the never-started held child",
        );
        expect_reply(
            child.token,
            &release,
            procmgr_errors::INVALID_BADGE,
            "RELEASE_HOLD on a never-started held child",
        );
        child.delete();
        pool_returns_to(before)
    });
    assert!(
        unstarted,
        "a held child destroyed before its start was not reclaimed in {DMA_HOLD_WINDOWS} windows"
    );

    // Started: held across the teardown until the release on the token.
    let mut held_seen = false;
    let started = (0..DMA_HOLD_WINDOWS).any(|_| {
        let before = pool_free();
        let child = create_held_hello();
        run_held_child_to_teardown(child.handle);
        let held = !pool_returns_to(before);
        expect_reply(
            child.handle,
            &release,
            procmgr_errors::UNAUTHORIZED,
            "RELEASE_HOLD on the held child's process handle",
        );
        let still_held = !pool_returns_to(before);
        expect_reply(
            child.token,
            &release,
            procmgr_errors::SUCCESS,
            "RELEASE_HOLD on the torn-down held child's token",
        );
        expect_reply(
            child.token,
            &release,
            procmgr_errors::INVALID_BADGE,
            "second RELEASE_HOLD on the released child's token",
        );
        child.delete();
        held_seen |= held && still_held;
        held && still_held && pool_returns_to(before)
    });
    assert!(
        held_seen,
        "a started held child's pages returned to the pool before the release on its token in \
         every window"
    );
    assert!(
        started,
        "a held child's pages were not back in the pool after RELEASE_HOLD in any of \
         {DMA_HOLD_WINDOWS} windows"
    );
    std::os::seraph::log!("procmgr_dma_hold phase passed");
}

/// `CONFIGURE_PIPE` cells on a child created (and never started) through raw
/// `CREATE_FROM_FILE`: an unknown direction is refused, the first stdout
/// configuration succeeds, and a second one for stdout is refused, since an
/// installed triple cannot be replaced. procmgr does not check the caps'
/// types, so spare caps stand in for the shmem page and notifications.
fn configure_pipe_refusals()
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let (file, size) = hello_file();
    let create = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, size)
        .cap(file)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().procmgr_endpoint,
            &create,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .expect("raw CREATE_FROM_FILE call failed");
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "raw CREATE_FROM_FILE refused"
    );
    let (handle, thread) = match reply.caps()
    {
        &[handle, thread] => (handle, thread),
        other => panic!("CREATE_FROM_FILE replied {} caps", other.len()),
    };
    let pipe = |direction: u64| {
        IpcMessage::builder(procmgr_labels::CONFIGURE_PIPE)
            .word(0, direction)
            .word(1, 0)
            .cap(spare_cap())
            .cap(spare_cap())
            .cap(spare_cap())
            .build()
    };
    expect_reply(
        handle,
        &pipe(7),
        procmgr_errors::INVALID_ARGUMENT,
        "CONFIGURE_PIPE with an unknown direction",
    );
    expect_reply(
        handle,
        &pipe(procmgr_labels::PIPE_DIR_STDOUT),
        procmgr_errors::SUCCESS,
        "first CONFIGURE_PIPE for stdout",
    );
    expect_reply(
        handle,
        &pipe(procmgr_labels::PIPE_DIR_STDOUT),
        procmgr_errors::INVALID_ARGUMENT,
        "second CONFIGURE_PIPE for stdout",
    );
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        procmgr_errors::SUCCESS,
        "DESTROY_PROCESS of the never-started child",
    );
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
}

/// argv[1] of the child that checks procmgr destroys a child whose create
/// reply it cannot deliver; see [`undeliverable_reply_child_main`].
const UNDELIVERABLE_ROLE: &str = "undeliverable-reply-child";
/// Exit code: a namespace lookup failed.
const UNDELIVERABLE_LOOKUP_FAILED: i32 = 2;
/// Exit code: the create reply reached the child, or procmgr refused the
/// create, instead of the reply transfer failing.
const UNDELIVERABLE_REPLY_DELIVERED: i32 = 3;
/// Exit code: a `QUERY_POOL_STATUS` call to memmgr failed.
const UNDELIVERABLE_POOL_QUERY_FAILED: i32 = 4;
/// Exit code: memmgr's free pool never returned to its level before the
/// create, in any window, so the created child's pages stayed accounted.
const UNDELIVERABLE_NEVER_RECLAIMED: i32 = 5;
/// Exit code: the `CREATE_FROM_FILE` call itself failed.
const UNDELIVERABLE_CALL_FAILED: i32 = 6;
/// Exit code: a memmgr grant spending the IPC receive reserve neither landed
/// nor failed its transfer.
const UNDELIVERABLE_GRANT_FAILED: i32 = 7;
/// Sample windows the child retries: memmgr's free-pool size is system-wide,
/// and other processes (crasher shares the boot) can move it inside one.
const UNDELIVERABLE_WINDOWS: u32 = 8;
/// Pool queries per window while procmgr's teardown of the created child
/// reaches memmgr. A test wait bound: it limits only how long a window polls.
const UNDELIVERABLE_POLLS: u32 = 256;

/// Child role: exhaust this process's `CSpace`, its IPC receive reserve
/// included, so procmgr's two-cap create reply cannot land, issue
/// `CREATE_FROM_FILE`, and check that the reply transfer fails and that
/// procmgr then destroys the child it created —
/// memmgr's free pool returns to its level before the create, which it does
/// not while the suspended child holds its pages. Runs without heap
/// allocation after the exhaustion, since a heap refill needs a free slot.
fn undeliverable_reply_child_main() -> !
{
    use ipc::{IpcMessage, procmgr_labels};

    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let lookup = |dir: u64, name: &[u8]| {
        crate::ipc_util::ns::ns_lookup(dir, name, 0xFFFF, ipc_buf)
            .unwrap_or_else(|_| std::process::exit(UNDELIVERABLE_LOOKUP_FAILED))
    };
    let (programs, _, _) = lookup(std::os::seraph::root_dir_cap(), b"programs");
    let (mut file, _, size) = lookup(programs, b"hello");

    // Fill every general slot, then spend the IPC receive reserve, which
    // general allocations leave free, on one-page memmgr grants: each lands
    // until the reserve is gone. The create call then moves the file cap
    // out, freeing one slot, and the reply's two caps cannot both land.
    while syscall::cap_derive(info.procmgr_endpoint, syscall::RIGHTS_EP_SEND).is_ok()
    {}
    for _ in 0..=syscall_abi::CSPACE_IPC_RECV_RESERVE
    {
        let grant = IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
            .word(0, 1)
            .build();
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        match unsafe { ipc::ipc_call(info.memmgr_endpoint, &grant, ipc_buf) }
        {
            Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED => break,
            Ok(reply) if reply.label == ipc::memmgr_errors::SUCCESS && !reply.caps().is_empty() =>
            {
            }
            _ => std::process::exit(UNDELIVERABLE_GRANT_FAILED),
        }
    }

    for window in 0..UNDELIVERABLE_WINDOWS
    {
        if window > 0
        {
            // The slot the previous create freed takes the new file cap.
            file = lookup(programs, b"hello").0;
        }
        let Some(before) = std::os::seraph::memmgr_pool_free_bytes()
        else
        {
            std::process::exit(UNDELIVERABLE_POOL_QUERY_FAILED);
        };
        let create = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
            .word(0, size)
            .cap(file)
            .build();
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        match unsafe { ipc::ipc_call(info.procmgr_endpoint, &create, ipc_buf) }
        {
            Ok(reply) if reply.label == syscall::IPC_REPLY_TRANSFER_FAILED =>
            {}
            Ok(_) => std::process::exit(UNDELIVERABLE_REPLY_DELIVERED),
            Err(_) => std::process::exit(UNDELIVERABLE_CALL_FAILED),
        }
        for _ in 0..UNDELIVERABLE_POLLS
        {
            match std::os::seraph::memmgr_pool_free_bytes()
            {
                Some(now) if now == before => std::process::exit(0),
                Some(_) => std::thread::yield_now(),
                None => std::process::exit(UNDELIVERABLE_POOL_QUERY_FAILED),
            }
        }
    }
    std::process::exit(UNDELIVERABLE_NEVER_RECLAIMED);
}
