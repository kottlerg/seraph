// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/critical_creates.rs

//! Process creation while memory is critical (`services/procmgr/docs/ipc-interface.md` § Label 13,
//! `services/svcmgr/docs/restart-protocol.md`).
//!
//! The `memhog` fixture holds the pool at the system reserve for the window of
//! [`super::oom::critical_window`], and the phase makes three checks inside it:
//!
//! 1. svctest's own `CREATE_FROM_FILE` of `/programs/hello`, which is outside
//!    the reserve, is refused with `OUT_OF_MEMORY`, and no other label:
//!    svcmgr's memory wait for a restart holds only that label, so a create
//!    outside the reserve that failed otherwise would be a hard failure there.
//!    The phase destroys each child it manages to create and waits for
//!    memhog's next tick to take back the frames the destroy freed, and tries
//!    up to [`ATTEMPTS`] times.
//! 2. A reserve creator's `CREATE_FROM_FILE | CREATE_RESERVE`, made by the
//!    `reserve-creator` fixture (`reserve-creator.svc`, a service in the
//!    system reserve), succeeds while memory is critical.
//! 3. The `crasher-worker` fixture's service restart, started by its worker's
//!    fault inside the window, is held and made: its next instance answers
//!    after the window with a new nonce.
//!
//! Check 2 runs when `reserve-creator.svc` is staged, check 3 when
//! `crasher-worker.svc` is, and the phase as a whole when `memhog.svc` is.
//! Everything the window needs is allocated before it, and the window logs
//! nothing.

use std::time::Duration;

use ipc::{IpcMessage, procmgr_errors, procmgr_labels, restart_probe_labels as probe};

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The phase.
pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "critical_creates",
        run: critical_creates_phase,
    }]
}

/// The recipe that starts the reserve-creator fixture, when it is staged.
const RESERVE_RECIPE: &str = "/config/svcmgr/services/reserve-creator.svc";

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

/// How long the window holds memory critical when no oomd stops memhog. A test
/// wait bound.
const CRITICAL_HOLD: Duration = Duration::from_secs(5);

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

/// Run the three checks (see the module documentation).
fn critical_creates_phase(caps: &Caps)
{
    let phase = "critical_creates";
    if !super::svcmgr::recipe_staged(super::oom::MEMHOG_RECIPE, phase)
    {
        std::os::seraph::log!("critical_creates phase passed (memhog.svc not staged)");
        return;
    }
    let files = lookup_files();
    let creator = super::svcmgr::recipe_staged(RESERVE_RECIPE, phase).then(|| {
        let fixture = super::svcmgr::provided_endpoint(RESERVE_NAME, phase);
        let label = call_label(fixture, PREPARE);
        assert_eq!(
            label, 0,
            "{phase}: the reserve creator's PREPARE replied {label:#x}"
        );
        fixture
    });
    let worker = super::svcmgr::worker_fixture_staged(phase).then(|| {
        let fixture = super::svcmgr::worker_fixture(phase);
        let nonce = super::svcmgr::probe_nonce(fixture, phase, "first PROBE_INSTANCE");
        (fixture, nonce)
    });

    let mut labels = [NO_REPLY; ATTEMPTS];
    let mut attempts = 0;
    let mut creator_label = None;
    let mut worker_label = None;
    super::oom::critical_window(caps, phase, CRITICAL_HOLD, || {
        attempts = own_creates(&files, &mut labels);
        if let Some(fixture) = creator
        {
            creator_label = Some(call_label(fixture, CREATE));
        }
        if let Some((fixture, _)) = worker
        {
            worker_label = Some(call_label(fixture, probe::PROBE_FAULT_WORKER));
        }
    });
    for &(file, _) in files.iter().skip(attempts)
    {
        let _ = syscall::cap_delete(file);
    }

    let last = labels
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
    if let Some(label) = creator_label
    {
        assert_eq!(
            label, 0,
            "{phase}: a reserve creator's CREATE_FROM_FILE | CREATE_RESERVE while memory was \
             critical replied {label:#x}"
        );
    }
    if let (Some((fixture, first)), Some(label)) = (worker, worker_label)
    {
        assert_eq!(
            label,
            probe::SUCCESS,
            "{phase}: PROBE_FAULT_WORKER replied {label:#x}"
        );
        std::os::seraph::log!("critical_creates: awaiting crasher-worker's restart");
        let next = super::svcmgr::probe_nonce(fixture, phase, "PROBE_INSTANCE after the window");
        assert_ne!(
            next, first,
            "{phase}: the same crasher-worker instance answered after its worker faulted"
        );
    }
    if let Some(fixture) = creator
    {
        let _ = syscall::cap_delete(fixture);
    }
    if let Some((fixture, _)) = worker
    {
        let _ = syscall::cap_delete(fixture);
    }
    let shown = |staged: bool| if staged { "ok" } else { "not staged" };
    std::os::seraph::log!(
        "critical_creates phase passed (own create refused OUT_OF_MEMORY after {attempts} \
         attempts; reserve create: {}; worker restart after the window: {})",
        shown(creator.is_some()),
        shown(worker.is_some())
    );
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
