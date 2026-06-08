// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Process exit-code propagation surface (#302).
//!
//! A child spawned via `std::process::Command` that calls
//! `std::process::exit(code)` must surface `code` to the parent's
//! `ExitStatus`: `success()` reflects the zero/non-zero verdict and
//! `code()` carries the value. Hosts the child-mode entries spawned by
//! `exit_code_phase`.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// Non-zero exit code the `exit-code-nonzero` child reports; the parent
/// asserts it survives end to end.
const NONZERO_CODE: i32 = 42;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "exit_code",
        run: exit_code_phase,
    }]
}

/// Child-mode dispatch for argv tokens this module owns. Matching arms
/// diverge via `std::process::exit`; on a miss control returns.
pub fn reentry_main(role: &str)
{
    match role
    {
        "exit-code-nonzero" => std::process::exit(NONZERO_CODE),
        "exit-code-zero" => std::process::exit(0),
        _ =>
        {}
    }
}

// cast_sign_loss: ExitStatus::code() is i32 but a voluntary exit reason is
// non-negative (the encoded code in `[0, EXIT_FAULT_BASE)`); the u64 cast is safe.
#[allow(clippy::cast_sign_loss)]
pub fn exit_code_phase(_: &Caps)
{
    use std::process::Command;

    // Non-zero voluntary exit: success() is false and code() carries the value.
    let mut child = Command::new("/tests/svctest")
        .arg("exit-code-nonzero")
        .spawn()
        .expect("spawn /tests/svctest exit-code-nonzero failed");
    let id = child.id();
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

    // procmgr's per-thread death observer reaps the process and records the
    // reason; QUERY_PROCESS confirms the kernel→procmgr path agrees with the
    // spawner-observed code.
    {
        let info = startup_info();
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(id, &query, ipc_buf) }
            .expect("QUERY_PROCESS after voluntary exit failed");
        assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED for voluntarily-exited child, got {state}"
        );
        assert_eq!(
            exit_reason, NONZERO_CODE as u64,
            "auto-reap exit_reason {exit_reason:#x} != spawner-observed {NONZERO_CODE:#x}"
        );
    }
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
