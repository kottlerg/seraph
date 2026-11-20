// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/exit_code.rs

//! Process exit-code propagation surface (#302).
//!
//! A child spawned via `std::process::Command` that calls
//! `std::process::exit(code)` must surface `code` to the parent's
//! `ExitStatus`: `success()` reflects the zero/non-zero verdict and
//! `code()` carries the value. A spawned thread's `std::process::exit` ends
//! the whole process with its code, though the main thread runs on
//! (docs/process-lifecycle.md § Exit reason). Hosts the child-mode entries
//! spawned by `exit_code_phase` and `exit_code_thread_phase`.

use std::os::seraph::process::ChildExt;
use std::time::Duration;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// Non-zero exit code the `exit-code-nonzero` child reports; the parent
/// asserts it survives end to end.
const NONZERO_CODE: i32 = 42;

/// Code the `exit-code-thread` child's spawned thread exits the process with.
const THREAD_CODE: i32 = 43;

/// Code the `exit-code-thread` child's main thread exits with once
/// [`MAIN_BOUND`] passes: the parent sees it only when the spawned thread's
/// exit ended that thread alone.
const MAIN_CODE: i32 = 44;

/// How long the `exit-code-thread` child's main thread sleeps before it
/// exits: far past procmgr's teardown of a process one of whose threads
/// exited it.
const MAIN_BOUND: Duration = Duration::from_secs(10);

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "exit_code",
            run: exit_code_phase,
        },
        Phase {
            name: "exit_code_thread",
            run: exit_code_thread_phase,
        },
    ]
}

/// Child-mode dispatch for argv tokens this module owns. Matching arms
/// diverge via `std::process::exit`; on a miss control returns.
pub fn reentry_main(role: &str)
{
    match role
    {
        "exit-code-nonzero" => std::process::exit(NONZERO_CODE),
        "exit-code-zero" => std::process::exit(0),
        "exit-code-thread" =>
        {
            let _worker = std::thread::spawn(|| std::process::exit(THREAD_CODE));
            std::thread::sleep(MAIN_BOUND);
            std::process::exit(MAIN_CODE);
        }
        _ =>
        {}
    }
}

pub fn exit_code_phase(_: &Caps)
{
    use std::process::Command;

    // Non-zero voluntary exit: success() is false and code() carries the value.
    let mut child = Command::new("/tests/svctest")
        .arg("exit-code-nonzero")
        .spawn()
        .expect("spawn /tests/svctest exit-code-nonzero failed");
    let id = child.process_handle();
    let status = child.wait().expect("exit-code-nonzero wait failed");
    std::os::seraph::log!("exit-code-nonzero exited: {status}");
    assert!(
        !status.success(),
        "exit({NONZERO_CODE}) child must not report success: {status}"
    );
    assert_eq!(
        status.code(),
        Some(NONZERO_CODE),
        "exit({NONZERO_CODE}) code not propagated: {status:?}"
    );

    // procmgr's death observers reap the process and record the reason;
    // QUERY_PROCESS confirms the kernel→procmgr path agrees with the
    // spawner-observed code.
    assert_reaped_with(id, NONZERO_CODE);
    drop(child);

    // Clean voluntary exit: success() is true, code() is 0.
    let zero = Command::new("/tests/svctest")
        .arg("exit-code-zero")
        .status()
        .expect("spawn /tests/svctest exit-code-zero failed");
    assert!(zero.success(), "exit(0) child must report success: {zero}");
    assert_eq!(zero.code(), Some(0), "exit(0) code mismatch: {zero:?}");

    std::os::seraph::log!("exit_code phase passed (code={NONZERO_CODE})");
}

/// Spawn the `exit-code-thread` child, whose spawned thread calls
/// `std::process::exit(THREAD_CODE)` while its main thread sleeps
/// [`MAIN_BOUND`]: the exit ends the address space, procmgr reaps the
/// process on the space's end, and the parent's `ExitStatus` and
/// `QUERY_PROCESS` both carry [`THREAD_CODE`], not the main thread's
/// [`MAIN_CODE`].
pub fn exit_code_thread_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/tests/svctest")
        .arg("exit-code-thread")
        .spawn()
        .expect("spawn /tests/svctest exit-code-thread failed");
    let id = child.process_handle();
    let status = child.wait().expect("exit-code-thread wait failed");
    std::os::seraph::log!("exit-code-thread exited: {status}");
    assert_eq!(
        status.code(),
        Some(THREAD_CODE),
        "a spawned thread's exit({THREAD_CODE}) did not end the process: {status:?}"
    );
    assert_reaped_with(id, THREAD_CODE);
    drop(child);

    std::os::seraph::log!("exit_code_thread phase passed (code={THREAD_CODE})");
}

/// Assert procmgr answers `QUERY_PROCESS` on the exited child `id` names
/// with `EXITED` and the reason of a voluntary exit with `code`.
fn assert_reaped_with(id: u64, code: i32)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
    // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
    let reply =
        unsafe { ipc::ipc_call(id, &query, ipc_buf) }.expect("QUERY_PROCESS after exit failed");
    assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
    let state = reply.word(0);
    let exit_reason = reply.word(1);
    assert_eq!(
        state,
        ipc::procmgr_process_state::EXITED,
        "expected EXITED for an exited child, got {state}"
    );
    let expected = u64::from(code.unsigned_abs());
    assert_eq!(
        exit_reason, expected,
        "auto-reap exit_reason {exit_reason:#x} != spawner-observed {expected:#x}"
    );
}
