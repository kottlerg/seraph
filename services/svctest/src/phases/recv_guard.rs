// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/recv_guard.rs

//! Shared recv-loop failure policy (`RecvGuard`) surface: a wedged receive
//! loop ends its process with `EXIT_RECV_WEDGE`, on the main thread
//! (`recv_wedge`, the capexhaust fixture) and on a spawned one
//! (`recv_wedge_thread`, the `recv-wedge-thread` child mode hosted here).

use std::os::seraph::process::ChildExt;
use std::time::Duration;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "recv_wedge",
            run: recv_wedge_phase,
        },
        Phase {
            name: "recv_wedge_thread",
            run: recv_wedge_thread_phase,
        },
    ]
}

/// Code the `recv-wedge-thread` child's main thread exits with once
/// [`MAIN_BOUND`] passes: the parent sees it only when the guard's fatal exit
/// on the spawned thread ended that thread alone.
const MAIN_CODE: i32 = 45;

/// Correlator of the supervisor's observer `recv_wedge_thread` binds.
const SUPERVISOR_CORR: u64 = 0x00C0_FFEE;

/// How long `recv_wedge_thread` waits for the supervisor's post after the
/// child's `ExitStatus` arrived: far past the one walk that posts both.
const SUPERVISOR_WAIT_MS: u64 = 5000;

/// How long the `recv-wedge-thread` child's main thread sleeps before it
/// exits: far past the guard's escalation (its fatal streak with the backoff
/// capped, a few seconds) and procmgr's teardown after it.
const MAIN_BOUND: Duration = Duration::from_secs(30);

/// Child-mode dispatch for argv tokens this module owns. The matching arm
/// diverges via `std::process::exit`; on a miss control returns.
pub fn reentry_main(role: &str)
{
    if role != "recv-wedge-thread"
    {
        return;
    }
    let _worker = std::thread::spawn(|| wedge());
    std::thread::sleep(MAIN_BOUND);
    std::process::exit(MAIN_CODE);
}

/// A guarded receive loop on the null cap (slot 0, permanently null), so
/// every receive fails alike and the guard escalates to its fatal exit.
fn wedge() -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        match unsafe { ipc::ipc_recv(0, ipc_buf) }
        {
            Ok(_) => guard.on_success(),
            Err(e) => guard.on_failure(e),
        }
    }
}

/// Spawn the capexhaust fixture, which exhausts its own `CSpace`'s general
/// slots, spends the IPC receive reserve on memmgr grants (which must land),
/// and enters a guarded blocking receive loop. With the reserve spent, the
/// kernel fails every `ipc_recv` at the `MSG_CAP_SLOTS_MAX` pre-allocate; the
/// fixture's `RecvGuard` must escalate to a loud `EXIT_RECV_WEDGE` death
/// instead of spinning silently. A failed reserve check panics the fixture,
/// whose fault exit code fails the assertion below.
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() returns i32; exit_reason is always non-negative (voluntary codes \
              < 0x1000). Casting to u64 is safe"
)]
fn recv_wedge_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/tests/fixtures/programs/capexhaust")
        .spawn()
        .expect("spawn /tests/fixtures/programs/capexhaust failed");

    let id = child.process_handle();
    std::os::seraph::log!("spawned /tests/fixtures/programs/capexhaust handle={id:#x}");

    let status = child.wait().expect("capexhaust wait failed");
    std::os::seraph::log!("capexhaust exited: {status}");

    assert!(
        !status.success(),
        "capexhaust child must not exit cleanly: {status}"
    );

    let raw = status
        .code()
        .expect("capexhaust ExitStatus must carry a code") as u64;
    assert_eq!(
        raw,
        u64::from(ipc::recv_guard::EXIT_RECV_WEDGE),
        "expected EXIT_RECV_WEDGE ({:#x}), got {raw:#x}",
        ipc::recv_guard::EXIT_RECV_WEDGE
    );

    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(id, &query, ipc_buf) }
            .expect("QUERY_PROCESS call after exit failed");
        assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED for wedged child, got {state}"
        );
        assert_eq!(
            exit_reason, raw,
            "auto-reap exit_reason {exit_reason:#x} does not match spawner-observed {raw:#x}"
        );
    }

    std::os::seraph::log!("recv_wedge phase passed (exit_reason={raw:#x})");
}

/// Spawn the `recv-wedge-thread` child, whose `RecvGuard` escalates on a
/// spawned thread while its main thread sleeps [`MAIN_BOUND`]: the guard's
/// fatal exit ends the process, so the parent's `ExitStatus`,
/// `QUERY_PROCESS`, and a supervisor's observer bound through procmgr carry
/// `EXIT_RECV_WEDGE`, not the main thread's [`MAIN_CODE`].
#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() returns i32; exit_reason is always non-negative (voluntary codes \
              < 0x1000). Casting to u64 is safe"
)]
fn recv_wedge_thread_phase(_: &Caps)
{
    let mut child = spawn_recv_wedge_thread();
    let id = child.process_handle();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    // A supervisor's observer, bound through procmgr on the child's address
    // space as svcmgr binds one (`BIND_DEATH_OBSERVER`), well before the
    // guard's streak escalates.
    let queue =
        std::os::seraph::object_slab_retype(syscall_abi::event_queue_retype_bytes(1, 1), |slab| {
            syscall::event_queue_create_observed(slab, 1, 1).ok()
        })
        .expect("supervisor queue creation failed");
    let post = syscall::cap_derive(queue, syscall::RIGHTS_EQ_POST)
        .expect("deriving a POST cap on the supervisor queue failed");
    let bind = ipc::IpcMessage::builder(ipc::procmgr_labels::BIND_DEATH_OBSERVER)
        .word(0, SUPERVISOR_CORR)
        .cap(post)
        .build();
    // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(id, &bind, ipc_buf) }.expect("BIND_DEATH_OBSERVER failed");
    assert_eq!(
        reply.label,
        ipc::procmgr_errors::SUCCESS,
        "BIND_DEATH_OBSERVER on the child refused"
    );
    let status = child.wait().expect("recv-wedge-thread wait failed");
    std::os::seraph::log!("recv-wedge-thread exited: {status}");
    let raw = status
        .code()
        .expect("recv-wedge-thread ExitStatus must carry a code") as u64;
    assert_eq!(
        raw,
        u64::from(ipc::recv_guard::EXIT_RECV_WEDGE),
        "a spawned thread's wedge did not end the process with EXIT_RECV_WEDGE ({:#x}): got {raw:#x}",
        ipc::recv_guard::EXIT_RECV_WEDGE
    );
    let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
    // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
    let reply =
        unsafe { ipc::ipc_call(id, &query, ipc_buf) }.expect("QUERY_PROCESS after exit failed");
    assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
    assert_eq!(
        (reply.word(0), reply.word(1)),
        (ipc::procmgr_process_state::EXITED, raw),
        "procmgr's record of the wedged child is not EXITED with the spawner-observed reason"
    );
    // The space's end posts every observer of it in one walk, which procmgr's
    // reap may overtake, so the supervisor's post is awaited.
    let death = syscall::event_recv_entry(queue, SUPERVISOR_WAIT_MS)
        .map(syscall::DeathEvent::from_entry)
        .expect("the supervisor's observer received no post");
    assert_eq!(
        (death.correlator, death.exit_reason),
        (SUPERVISOR_CORR, raw),
        "the supervisor's observer did not receive the wedge's reason"
    );
    let _ = syscall::cap_delete(queue);
    drop(child);

    std::os::seraph::log!("recv_wedge_thread phase passed (exit_reason={raw:#x})");
}

/// Spawn the `recv-wedge-thread` child. A function of its own, so the
/// `Command` and its stdio configuration take no room in the phase's frame.
fn spawn_recv_wedge_thread() -> std::process::Child
{
    std::process::Command::new("/tests/svctest")
        .arg("recv-wedge-thread")
        .spawn()
        .expect("spawn /tests/svctest recv-wedge-thread failed")
}
