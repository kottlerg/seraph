// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/critical_creates.rs

//! Process creation while memory is critical (`services/procmgr/docs/ipc-interface.md` § Label 13,
//! `services/svcmgr/docs/restart-protocol.md`).
//!
//! Three checks the `logd_reserve` phase makes in its window
//! (`super::logd_restart`), while the `memhog` fixture holds the pool at the
//! system reserve ([`super::oom::critical_window`]). They share that window
//! because svcmgr restarts memhog at most three times a window
//! (`services/svcmgr/docs/service-definitions.md` § `restart`), and the boot's
//! other memhog windows spend them.
//!
//! 1. svctest's own `CREATE_FROM_FILE` of `/programs/hello`, which is outside
//!    the reserve, is refused with `OUT_OF_MEMORY`, and no other label:
//!    svcmgr's memory wait for a restart holds only that label, so a create
//!    outside the reserve that failed otherwise would be a hard failure there.
//!    The checks destroy each child they manage to create and wait for
//!    memhog's next tick to take back the frames the destroy freed, and try
//!    up to [`ATTEMPTS`] times.
//! 2. A reserve creator's `CREATE_FROM_FILE | CREATE_RESERVE`, made by the
//!    `reserve-creator` fixture (`reserve-creator.svc`, a service in the
//!    system reserve), succeeds while memory is critical.
//! 3. The `crasher-worker` fixture's service restart, started by its worker's
//!    fault inside the window, is held and made: its next instance answers
//!    after the window with a new nonce.
//!
//! Check 2 runs when the staged fixture set declares `reserve-creator`,
//! check 3 when it declares `crasher-worker` ([`super::fixtures`]); each
//! check left out logs the skip line. Everything the window needs is allocated before it
//! ([`Checks::prepare`]), and the window's steps ([`Checks::creates`],
//! [`Checks::fault_worker`]) allocate nothing and log nothing.

use ipc::{IpcMessage, procmgr_errors, procmgr_labels, restart_probe_labels as probe};
use svctest_fixtures::Fixture;

use super::fixtures;

/// The name the reserve-creator fixture provides.
const RESERVE_NAME: &[u8] = b"svctest.reserve";

/// Role token of the reserve-creator fixture ([`reentry_main`]).
const FIXTURE_ROLE: &str = "reserve-creator";

/// The fixture's request that looks up its file caps, replied 0.
const PREPARE: u64 = 1;

/// The fixture's request that makes a reserve create, replied with procmgr's
/// reply label (0, `SUCCESS`, for a child made).
const CREATE: u64 = 2;

/// The fixture's reply when it holds no file cap to create from.
const NO_FILE: u64 = 0xFE;

/// The fixture's reply to a request it does not know, or when procmgr returned
/// no reply.
const CREATE_FAILED: u64 = 0xFF;

/// The label recorded for a call that returned no reply.
const NO_REPLY: u64 = u64::MAX;

/// The file caps of `/programs/hello` each side looks up before the window,
/// and so the most creates it makes in one.
const ATTEMPTS: usize = 4;

/// The ticks of memhog (`mem_fill::TICK_MS`) the phase sleeps after a destroy,
/// so memhog takes back what the destroy freed.
const TAKE_BACK_TICKS: u64 = 3;

/// The file caps of `/programs/hello` and their sizes, as `hello_file` returns
/// them; `(0, 0)` for a cap spent or deleted.
type Files = [(u64, u64); ATTEMPTS];

/// Look up [`ATTEMPTS`] file caps of `/programs/hello`.
fn lookup_files() -> Files
{
    let mut files = [(0, 0); ATTEMPTS];
    for slot in &mut files
    {
        *slot = super::procmgr::hello_file();
    }
    files
}

/// A raw `CREATE_FROM_FILE` of `/programs/hello` with `flags` added to the
/// label, from `file` of `size` bytes: procmgr's reply, or `None` when the
/// call returned none. Allocates nothing.
fn create_hello(file: u64, size: u64, flags: u64) -> Option<IpcMessage>
{
    super::procmgr::create_call(
        std::os::seraph::startup_info().procmgr_endpoint,
        procmgr_labels::CREATE_FROM_FILE | flags,
        &[size],
        super::procmgr::HELLO_PATH,
        &[file],
    )
    .ok()
}

/// Destroy the unstarted child a `SUCCESS` create `reply` carries, through
/// its process handle, and delete the reply's caps. Allocates nothing.
fn discard_child(reply: &IpcMessage)
{
    if let Some(&process) = reply.caps().first()
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe {
            ipc::ipc_call(
                process,
                &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
                ipc_buf,
            )
        };
    }
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Call `fixture` with `label` and no data: the reply's label, or
/// [`NO_REPLY`]. Allocates nothing.
fn call_label(fixture: u64, label: u64) -> u64
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // SAFETY: ipc_buf is the registered IPC buffer.
    unsafe { ipc::ipc_call(fixture, &IpcMessage::new(label), ipc_buf) }
        .map_or(NO_REPLY, |reply| reply.label)
}

/// Make up to [`ATTEMPTS`] creates of svctest's own, one from each of `files`,
/// recording each reply label in `labels`, and stop at the first that is not
/// `SUCCESS`: the creates made. Destroys each child a create makes, and
/// sleeps so memhog takes back what the destroy freed. Allocates nothing.
fn own_creates(files: &Files, labels: &mut [u64; ATTEMPTS]) -> usize
{
    let mut made: usize = 0;
    for (&(file, size), slot) in files.iter().zip(labels.iter_mut())
    {
        made = made.saturating_add(1);
        let label = match create_hello(file, size, 0)
        {
            Some(reply) =>
            {
                if reply.label == procmgr_errors::SUCCESS
                {
                    discard_child(&reply);
                    // memhog takes back what the destroy freed.
                    let _ = syscall::thread_sleep(TAKE_BACK_TICKS * mem_fill::TICK_MS);
                }
                reply.label
            }
            None => NO_REPLY,
        };
        *slot = label;
        if label != procmgr_errors::SUCCESS
        {
            break;
        }
    }
    made
}

/// What the checks hold from before the window to after it.
pub(super) struct Checks
{
    /// The file caps of svctest's own creates.
    files: Files,
    /// The reserve-creator fixture's endpoint, when it is staged.
    creator: Option<u64>,
    /// The worker-fault fixture's endpoint and its first instance's nonce,
    /// when it is staged.
    worker: Option<(u64, u64)>,
    /// The reply label of each of svctest's own creates.
    labels: [u64; ATTEMPTS],
    /// How many of svctest's own creates were made.
    attempts: usize,
    /// The reserve creator's reply label.
    creator_label: Option<u64>,
    /// The worker-fault fixture's reply to `PROBE_FAULT_WORKER`.
    worker_label: Option<u64>,
}

impl Checks
{
    /// Look up the file caps, and reach each staged fixture, before the
    /// window.
    pub(super) fn prepare(phase: &str) -> Self
    {
        let files = lookup_files();
        let creator = fixtures::staged(Fixture::ReserveCreator).then(|| {
            let fixture = super::svcmgr::provided_endpoint(RESERVE_NAME, phase);
            let label = call_label(fixture, PREPARE);
            assert_eq!(
                label, 0,
                "{phase}: the reserve creator's PREPARE replied {label:#x}"
            );
            fixture
        });
        let worker = fixtures::staged(Fixture::CrasherWorker).then(|| {
            let fixture = super::svcmgr::worker_fixture(phase);
            let nonce = super::svcmgr::probe_nonce(fixture, phase, "first PROBE_INSTANCE");
            (fixture, nonce)
        });
        Self {
            files,
            creator,
            worker,
            labels: [NO_REPLY; ATTEMPTS],
            attempts: 0,
            creator_label: None,
            worker_label: None,
        }
    }

    /// Checks 1 and 2, inside the window. Allocates nothing and logs nothing.
    pub(super) fn creates(&mut self)
    {
        self.attempts = own_creates(&self.files, &mut self.labels);
        if let Some(fixture) = self.creator
        {
            self.creator_label = Some(call_label(fixture, CREATE));
        }
    }

    /// Check 3's fault, inside the window. Allocates nothing and logs nothing.
    pub(super) fn fault_worker(&mut self)
    {
        if let Some((fixture, _)) = self.worker
        {
            self.worker_label = Some(call_label(fixture, probe::PROBE_FAULT_WORKER));
        }
    }

    /// Judge the three checks after the window, awaiting the worker-fault
    /// fixture's next instance, and log the outcome.
    pub(super) fn finish(self, phase: &str)
    {
        for &(file, _) in self.files.iter().skip(self.attempts)
        {
            let _ = syscall::cap_delete(file);
        }
        let attempts = self.attempts;
        let last = self
            .labels
            .get(attempts.saturating_sub(1))
            .copied()
            .unwrap_or(NO_REPLY);
        assert_ne!(
            last,
            procmgr_errors::SUCCESS,
            "{phase}: memory never ran short of svctest's create ({attempts} created)"
        );
        assert_eq!(
            last,
            procmgr_errors::OUT_OF_MEMORY,
            "{phase}: CREATE_FROM_FILE outside the reserve while memory was critical replied \
             {last:#x}, not OUT_OF_MEMORY (svcmgr's memory wait holds only OUT_OF_MEMORY)"
        );
        if let Some(label) = self.creator_label
        {
            assert_eq!(
                label, 0,
                "{phase}: a reserve creator's CREATE_FROM_FILE | CREATE_RESERVE while memory was \
                 critical replied {label:#x}"
            );
        }
        if let (Some((fixture, first)), Some(label)) = (self.worker, self.worker_label)
        {
            assert_eq!(
                label,
                probe::SUCCESS,
                "{phase}: PROBE_FAULT_WORKER replied {label:#x}"
            );
            std::os::seraph::log!("{phase}: awaiting crasher-worker's restart");
            let next =
                super::svcmgr::probe_nonce(fixture, phase, "PROBE_INSTANCE after the window");
            assert_ne!(
                next, first,
                "{phase}: the same crasher-worker instance answered after its worker faulted"
            );
        }
        if let Some(fixture) = self.creator
        {
            let _ = syscall::cap_delete(fixture);
        }
        if let Some((fixture, _)) = self.worker
        {
            let _ = syscall::cap_delete(fixture);
        }
        let shown = |staged: bool| if staged { "ok" } else { "not staged" };
        std::os::seraph::log!(
            "{phase}: creates while memory was critical passed (own create refused OUT_OF_MEMORY \
             after {attempts} attempts; reserve create: {}; worker restart after the window: {})",
            shown(self.creator.is_some()),
            shown(self.worker.is_some())
        );
        if self.creator.is_none()
        {
            fixtures::skip(phase, Fixture::ReserveCreator);
        }
        if self.worker.is_none()
        {
            fixtures::skip(phase, Fixture::CrasherWorker);
        }
    }
}

/// Child-mode dispatch for this module's role ([`crate::reentry`]).
pub fn reentry_main(role: &str)
{
    if role == FIXTURE_ROLE
    {
        fixture_main();
    }
}

/// [`ipc::recv_guard::RecvGuard`] hook of the fixture's receive loop.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// The reserve-creator fixture: serve [`PREPARE`] and [`CREATE`] on the
/// endpoint its recipe provides, which svcmgr delivers in bootstrap slot 0.
/// Its node is a reserve node, so it may allocate.
fn fixture_main() -> !
{
    // svctest's main registered svctest's own name before the role dispatch;
    // the fixture's lines carry a name of their own, so the phases that count
    // the live log slots named `svctest` find svctest's alone.
    std::os::seraph::log::register_name(FIXTURE_ROLE.as_bytes());
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let service = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
        .map_or(0, |[cap]| cap);
    if service == 0
    {
        std::os::seraph::log!(error: "no service endpoint");
        syscall::thread_exit();
    }
    std::os::seraph::log!("serving");
    let mut files: Files = [(0, 0); ATTEMPTS];
    let mut next = 0;
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv_timeout(service, ipc_buf, 0) }
        {
            Ok(msg) =>
            {
                guard.on_success();
                msg
            }
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let label = match msg.label
        {
            PREPARE =>
            {
                for &(file, _) in &files
                {
                    if file != 0
                    {
                        let _ = syscall::cap_delete(file);
                    }
                }
                files = lookup_files();
                next = 0;
                0
            }
            CREATE => reserve_create(&mut files, &mut next),
            _ => CREATE_FAILED,
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(label), ipc_buf) };
    }
}

/// Make a reserve create from the next held file cap, destroy the unstarted
/// child, and return the fixture's reply label: procmgr's, [`NO_FILE`] with no
/// file cap held, [`CREATE_FAILED`] when the call returned no reply.
fn reserve_create(files: &mut Files, next: &mut usize) -> u64
{
    let Some(slot) = files.get_mut(*next).filter(|slot| slot.0 != 0)
    else
    {
        return NO_FILE;
    };
    let (file, size) = core::mem::take(slot);
    *next = next.saturating_add(1);
    let Some(reply) = create_hello(file, size, procmgr_labels::CREATE_RESERVE)
    else
    {
        std::os::seraph::log!(warn: "CREATE_FROM_FILE | CREATE_RESERVE returned no reply");
        return CREATE_FAILED;
    };
    if reply.label == procmgr_errors::SUCCESS
    {
        discard_child(&reply);
    }
    reply.label
}
