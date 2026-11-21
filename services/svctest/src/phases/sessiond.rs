// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/sessiond.rs

//! sessiond in operator mode (services/sessiond/docs/ipc-interface.md):
//! svctest as an interface, opening sessions through its `sessiond.operator`
//! seed, and as a holder of svcmgr's stop authority, listing and stopping
//! them through the stop SEND svcmgr hands it for sessiond.
//!
//! [`Session`] is shared with the [`oom`](super::oom) phase, which opens a
//! session whose job oomd stops.

use std::io::{Read, Write};
use std::os::seraph::process::SessionStdio;
use std::process::{ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels, sessiond_labels as sl, stop_labels};
use syscall::EXIT_KILLED;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The marker the session phase has the shell echo.
const ECHO_MARKER: &str = "sessiond-echo-ok";

/// The shell's prompt.
pub(super) const PROMPT: &str = "$ ";

/// The pages the session phase's job holds.
const PHASE_JOB_PAGES: u64 = 16;

/// The path procmgr names a job of the shell by: the first word of the
/// argv the shell creates it with.
pub(super) const CRASHME_PATH: &str = "/programs/crashme";

/// The end queue svctest registered with procmgr; 0 until it has.
static END_QUEUE: AtomicU64 = AtomicU64::new(0);

/// The nonce sessiond knows svctest by; 0 until it has registered.
static NONCE: AtomicU64 = AtomicU64::new(0);

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "sessiond_operator",
        run: sessiond_phase,
    }]
}

/// Whether the image stages sessiond and svctest holds its operator SEND.
pub(super) fn staged(caps: &Caps, phase: &str) -> bool
{
    super::svcmgr::recipe_staged(super::svcmgr::SESSIOND_RECIPE, phase)
        && caps.sessiond_operator != 0
}

/// sessiond's stop SEND, from svcmgr's `LIST_STOP_SOURCES` through the stop
/// authority; the caller deletes it.
pub(super) fn stop_send(caps: &Caps, phase: &str) -> u64
{
    let mut found = 0;
    for (name, _, send) in super::svcmgr::list_stop_sources(caps.stop_authority, phase)
    {
        if name == "sessiond" && found == 0
        {
            found = send;
        }
        else
        {
            let _ = syscall::cap_delete(send);
        }
    }
    assert_ne!(found, 0, "{phase}: svcmgr lists no stop SEND for sessiond");
    found
}

/// The number of candidates the first `LIST_CANDIDATES` page through
/// `send` holds. Allocates nothing, so a phase can poll it while memory is
/// critical.
pub(super) fn candidate_count(send: u64, phase: &str) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = IpcMessage::builder(stop_labels::LIST_CANDIDATES)
        .word(0, 0)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(send, &msg, ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: LIST_CANDIDATES call failed: {e:?}"));
    assert_eq!(
        reply.label,
        stop_labels::SUCCESS,
        "{phase}: LIST_CANDIDATES through sessiond's stop SEND replied {:#x}",
        reply.label
    );
    reply.word(0)
}

/// Call `label` on `cap` with the data words `words` and the caps `caps`:
/// the reply's label and first data word. Its own frame holds the message.
#[inline(never)]
fn call(cap: u64, label: u64, words: &[u64], caps: &[u64], phase: &str) -> (u64, u64)
{
    let mut builder = IpcMessage::builder(label).words(0, words);
    for &held in caps
    {
        builder = builder.cap(held);
    }
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(cap, &builder.build(), ipc_buf) }
        .unwrap_or_else(|e| panic!("{phase}: call of label {label} failed: {e:?}"));
    (reply.label, reply.word(0))
}

/// The nonce svctest is registered with sessiond under, registering an end
/// queue with procmgr, and the interface with sessiond, on the first call.
fn nonce(operator: u64, phase: &str) -> u64
{
    let nonce = NONCE.load(Ordering::Relaxed);
    if nonce != 0
    {
        return nonce;
    }
    if END_QUEUE.load(Ordering::Relaxed) == 0
    {
        let queue = std::os::seraph::object_slab_retype(
            std::os::seraph::event_queue_retype_bytes(1, 0),
            |slab| syscall::event_queue_create(slab, 1).ok(),
        )
        .unwrap_or_else(|| panic!("{phase}: end queue creation failed"));
        let post = syscall::cap_derive(queue, syscall::RIGHTS_EQ_POST)
            .unwrap_or_else(|e| panic!("{phase}: POST derivation failed: {e}"));
        let (label, _) = call(
            std::os::seraph::startup_info().procmgr_endpoint,
            procmgr_labels::REGISTER_END_QUEUE,
            &[0],
            &[post],
            phase,
        );
        assert_eq!(
            label,
            procmgr_errors::SUCCESS,
            "{phase}: REGISTER_END_QUEUE replied {label:#x}"
        );
        END_QUEUE.store(queue, Ordering::Relaxed);
    }
    let queue = END_QUEUE.load(Ordering::Relaxed);
    let register = |nonce: u64, version: u64| {
        let recv = syscall::cap_derive(queue, syscall::RIGHTS_EQ_RECV)
            .unwrap_or_else(|e| panic!("{phase}: RECV derivation failed: {e}"));
        call(
            operator,
            sl::REGISTER_INTERFACE,
            &[nonce, version],
            &[recv],
            phase,
        )
        .0
    };
    let nonce = fresh_nonce(phase);
    let version = u64::from(ipc::SESSIOND_LABELS_VERSION);
    let label = register(nonce, version.wrapping_add(1));
    assert_eq!(
        label,
        sl::VERSION_MISMATCH,
        "{phase}: REGISTER_INTERFACE of another version replied {label:#x}"
    );
    let label = register(nonce, version);
    assert_eq!(
        label,
        sl::SUCCESS,
        "{phase}: REGISTER_INTERFACE replied {label:#x}"
    );
    let label = register(nonce, version);
    assert_eq!(
        label,
        sl::INVALID_ARGUMENT,
        "{phase}: a second REGISTER_INTERFACE under one nonce replied {label:#x}"
    );
    NONCE.store(nonce, Ordering::Relaxed);
    nonce
}

/// A nonzero random nonce.
fn fresh_nonce(phase: &str) -> u64
{
    loop
    {
        let nonce =
            syscall::random_u64().unwrap_or_else(|e| panic!("{phase}: random_u64 failed: {e}"));
        if nonce != 0
        {
            return nonce;
        }
    }
}

/// A session svctest opened and started, and its leader's streams.
pub(super) struct Session
{
    pub(super) key: u64,
    streams: SessionStdio,
    stdin: ChildStdin,
    stdout: ChildStdout,
    _stderr: ChildStderr,
    /// What the leader's stdout gave since the last [`Self::expect`] matched.
    seen: Vec<u8>,
}

impl Session
{
    /// Open, hand over the streams of, and start a session through the
    /// operator SEND `operator`; fails `phase` on any refusal.
    pub(super) fn open(operator: u64, phase: &str) -> Self
    {
        let nonce = nonce(operator, phase);
        let mut streams =
            SessionStdio::new().unwrap_or_else(|e| panic!("{phase}: SessionStdio::new: {e}"));
        let relay = streams
            .relay()
            .unwrap_or_else(|e| panic!("{phase}: relay derivation: {e}"));
        let (label, key) = call(operator, sl::OPEN_SESSION, &[nonce], &[relay], phase);
        assert_eq!(
            label,
            sl::SUCCESS,
            "{phase}: OPEN_SESSION replied {label:#x} ({key})"
        );
        for direction in [
            procmgr_labels::PIPE_DIR_STDIN,
            procmgr_labels::PIPE_DIR_STDOUT,
            procmgr_labels::PIPE_DIR_STDERR,
        ]
        {
            let ring = streams
                .handoff(direction)
                .unwrap_or_else(|| panic!("{phase}: no stream caps for direction {direction}"));
            let words = [nonce, key, direction, streams.ring_capacity()];
            let (label, code) = call(operator, sl::SESSION_STDIO, &words, &ring, phase);
            assert_eq!(
                label,
                sl::SUCCESS,
                "{phase}: SESSION_STDIO({direction}) replied {label:#x} ({code})"
            );
        }
        let (label, code) = call(operator, sl::START_SESSION, &[nonce, key], &[], phase);
        assert_eq!(
            label,
            sl::SUCCESS,
            "{phase}: START_SESSION replied {label:#x} ({code})"
        );
        let stdin = streams.take_stdin().expect("the leader's stdin end");
        let stdout = streams.take_stdout().expect("the leader's stdout end");
        let stderr = streams.take_stderr().expect("the leader's stderr end");
        Self {
            key,
            streams,
            stdin,
            stdout,
            _stderr: stderr,
            seen: Vec::with_capacity(1024),
        }
    }

    /// Write `line` and a newline to the leader's stdin.
    pub(super) fn send(&mut self, line: &str, phase: &str)
    {
        let written = self
            .stdin
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush());
        written.unwrap_or_else(|e| panic!("{phase}: write to the session's leader: {e}"));
    }

    /// Read the leader's stdout until it has given `text`, and drop what it
    /// gave up to it.
    pub(super) fn expect(&mut self, text: &str, phase: &str)
    {
        let needle = text.as_bytes();
        let mut buf = [0u8; 256];
        loop
        {
            if let Some(at) = self.seen.windows(needle.len()).position(|w| w == needle)
            {
                self.seen.drain(..at.saturating_add(needle.len()));
                return;
            }
            let n = self
                .stdout
                .read(&mut buf)
                .unwrap_or_else(|e| panic!("{phase}: read of the session's stdout: {e}"));
            assert_ne!(
                n,
                0,
                "{phase}: the session's stdout ended before {text:?}; it gave {:?}",
                String::from_utf8_lossy(&self.seen)
            );
            self.seen
                .extend_from_slice(buf.get(..n).unwrap_or_default());
        }
    }

    /// Wait for the leader's end through the relay.
    pub(super) fn wait(mut self, phase: &str) -> ExitStatus
    {
        self.streams
            .wait()
            .unwrap_or_else(|e| panic!("{phase}: the session's relay was not read: {e}"))
    }
}

/// sessiond's gates, a session's life through the relay, and the list and
/// stop of its candidates through svcmgr's stop authority. The phase passes
/// without sessiond's recipe, or without its operator seed.
///
/// - The operator labels through sessiond's stop SEND, and the stop labels
///   through the operator SEND, reply `UNAUTHORIZED`.
/// - `OPEN_SESSION` under a nonce sessiond never registered replies
///   `UNKNOWN_INTERFACE`; `REGISTER_INTERFACE` of another version replies
///   `VERSION_MISMATCH`, and a second one under the same nonce
///   `INVALID_ARGUMENT`.
/// - A cap of the wrong type or rights replies `INVALID_ARGUMENT`: a POST
///   cap as `REGISTER_INTERFACE`'s end queue, a RECV cap as
///   `OPEN_SESSION`'s relay, and a notification in `SESSION_STDIO`'s
///   memory slot, which also ends the session, so its relay is posted.
/// - A session opened and started runs its leader, the shell: it echoes a
///   line. The session is listed with `RANK_SESSION` under the key
///   `OPEN_SESSION` gave, and the job the shell runs
///   (`crashme oom-hold`) with `RANK_JOB`, under the path it was created
///   from and with at least the pages it holds. `STOP_CANDIDATE` of the job
///   leaves the shell answering; the shell's `exit` ends the session, whose
///   relay gives status 0, and its key is no candidate after.
/// - `STOP_CANDIDATE` of a second session's key ends it, and its relay
///   gives `EXIT_KILLED`.
fn sessiond_phase(caps: &Caps)
{
    let phase = "sessiond_operator";
    if !staged(caps, phase)
    {
        std::os::seraph::log!("sessiond phase passed (sessiond.svc not staged)");
        return;
    }
    let operator = caps.sessiond_operator;
    let send = stop_send(caps, phase);
    gates(operator, send, phase);
    cap_checks(operator, phase);
    session_life(operator, send, phase);
    session_stop(operator, send, phase);
    let _ = syscall::cap_delete(send);
    std::os::seraph::log!(
        "sessiond phase passed (gates; caps checked; a session ran, its job was stopped, its \
         leader exited; a second session was stopped)"
    );
}

/// The badge gates, and the refusal of an open under an unregistered nonce.
fn gates(operator: u64, send: u64, phase: &str)
{
    for label in [
        sl::REGISTER_INTERFACE,
        sl::OPEN_SESSION,
        sl::SESSION_STDIO,
        sl::START_SESSION,
    ]
    {
        let (got, _) = call(send, label, &[], &[], phase);
        assert_eq!(
            got,
            sl::UNAUTHORIZED,
            "{phase}: operator label {label} through the stop SEND replied {got:#x}"
        );
    }
    for label in [stop_labels::LIST_CANDIDATES, stop_labels::STOP_CANDIDATE]
    {
        let (got, _) = call(operator, label, &[], &[], phase);
        assert_eq!(
            got,
            stop_labels::UNAUTHORIZED,
            "{phase}: stop label {label} through the operator SEND replied {got:#x}"
        );
    }
    let stray = SessionStdio::new().unwrap_or_else(|e| panic!("{phase}: SessionStdio::new: {e}"));
    let relay = stray
        .relay()
        .unwrap_or_else(|e| panic!("{phase}: relay derivation: {e}"));
    let (got, _) = call(
        operator,
        sl::OPEN_SESSION,
        &[fresh_nonce(phase)],
        &[relay],
        phase,
    );
    stray.refused();
    assert_eq!(
        got,
        sl::UNKNOWN_INTERFACE,
        "{phase}: OPEN_SESSION under an unregistered nonce replied {got:#x}"
    );
}

/// The checks sessiond makes of each cap an interface hands it: one of the
/// wrong rights or type is refused before sessiond keeps or forwards it.
fn cap_checks(operator: u64, phase: &str)
{
    let nonce = nonce(operator, phase);
    let queue = END_QUEUE.load(Ordering::Relaxed);
    let derive = |rights: u64| {
        syscall::cap_derive(queue, rights)
            .unwrap_or_else(|e| panic!("{phase}: derivation of rights {rights:#x} failed: {e}"))
    };
    let version = u64::from(ipc::SESSIOND_LABELS_VERSION);
    let (got, _) = call(
        operator,
        sl::REGISTER_INTERFACE,
        &[fresh_nonce(phase), version],
        &[derive(syscall::RIGHTS_EQ_POST)],
        phase,
    );
    assert_eq!(
        got,
        sl::INVALID_ARGUMENT,
        "{phase}: REGISTER_INTERFACE with a POST cap replied {got:#x}"
    );
    let (got, _) = call(
        operator,
        sl::OPEN_SESSION,
        &[nonce],
        &[derive(syscall::RIGHTS_EQ_RECV)],
        phase,
    );
    assert_eq!(
        got,
        sl::INVALID_ARGUMENT,
        "{phase}: OPEN_SESSION with a RECV cap replied {got:#x}"
    );
    let mut streams =
        SessionStdio::new().unwrap_or_else(|e| panic!("{phase}: SessionStdio::new: {e}"));
    let relay = streams
        .relay()
        .unwrap_or_else(|e| panic!("{phase}: relay derivation: {e}"));
    let (label, key) = call(operator, sl::OPEN_SESSION, &[nonce], &[relay], phase);
    assert_eq!(
        label,
        sl::SUCCESS,
        "{phase}: OPEN_SESSION replied {label:#x} ({key})"
    );
    let direction = procmgr_labels::PIPE_DIR_STDIN;
    let [memory, data, space] = streams
        .handoff(direction)
        .unwrap_or_else(|| panic!("{phase}: no stream caps for direction {direction}"));
    let words = [nonce, key, direction, streams.ring_capacity()];
    let (got, _) = call(
        operator,
        sl::SESSION_STDIO,
        &words,
        &[data, memory, space],
        phase,
    );
    assert_eq!(
        got,
        sl::INVALID_ARGUMENT,
        "{phase}: SESSION_STDIO with a notification as its memory cap replied {got:#x}"
    );
    // The refusal ended the session: its relay is posted.
    let _ = streams
        .wait()
        .unwrap_or_else(|e| panic!("{phase}: the refused session's relay was not read: {e}"));
}

/// A session's life: it runs, it and its job are listed, the job is stopped,
/// and the leader's exit ends it.
fn session_life(operator: u64, send: u64, phase: &str)
{
    let mut session = Session::open(operator, phase);
    session.send(&format!("echo {ECHO_MARKER}"), phase);
    session.expect(ECHO_MARKER, phase);
    session.send(&format!("crashme oom-hold {PHASE_JOB_PAGES}"), phase);
    session.expect(&format!("holding {PHASE_JOB_PAGES}"), phase);
    let listed = super::svcmgr::list_candidates(send, phase);
    assert!(
        listed
            .iter()
            .any(|c| c.key == session.key && c.rank == stop_labels::RANK_SESSION),
        "{phase}: the session {:#x} is not listed: {listed:?}",
        session.key
    );
    let job = listed
        .iter()
        .find(|c| c.rank == stop_labels::RANK_JOB && c.name == CRASHME_PATH)
        .unwrap_or_else(|| panic!("{phase}: the session's job is not listed: {listed:?}"));
    assert!(
        job.pages >= PHASE_JOB_PAGES,
        "{phase}: the job lists {} pages, under the {PHASE_JOB_PAGES} it holds",
        job.pages
    );
    let label = super::svcmgr::stop_candidate(send, job.key);
    assert_eq!(
        label,
        stop_labels::SUCCESS,
        "{phase}: STOP_CANDIDATE(job) replied {label:#x}"
    );
    // The shell forwards a line to its job until it has seen the job end, and
    // prompts once it has.
    session.expect(PROMPT, phase);
    session.send(&format!("echo {ECHO_MARKER}"), phase);
    session.expect(ECHO_MARKER, phase);
    session.send("exit", phase);
    let key = session.key;
    let status = session.wait(phase);
    assert!(status.success(), "{phase}: the leader's exit gave {status}");
    let label = super::svcmgr::stop_candidate(send, key);
    assert_eq!(
        label,
        stop_labels::NO_CANDIDATE,
        "{phase}: STOP_CANDIDATE of the ended session replied {label:#x}"
    );
}

/// A session stopped through the stop SEND: its relay gives `EXIT_KILLED`.
fn session_stop(operator: u64, send: u64, phase: &str)
{
    let mut stopped = Session::open(operator, phase);
    stopped.send(&format!("echo {ECHO_MARKER}"), phase);
    stopped.expect(ECHO_MARKER, phase);
    let label = super::svcmgr::stop_candidate(send, stopped.key);
    assert_eq!(
        label,
        stop_labels::SUCCESS,
        "{phase}: STOP_CANDIDATE(session) replied {label:#x}"
    );
    let status = stopped.wait(phase);
    assert_eq!(
        status.code().and_then(|c| u64::try_from(c).ok()),
        Some(EXIT_KILLED),
        "{phase}: the stopped session's relay gave {status}"
    );
}
