// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Shared recv-loop failure policy (`RecvGuard`) surface.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "recv_wedge",
        run: recv_wedge_phase,
    }]
}

/// Spawn the capexhaust fixture, which exhausts its own `CSpace` and enters a
/// guarded blocking receive loop. The kernel fails every `ipc_recv` at the
/// `MSG_CAP_SLOTS_MAX` pre-allocate; the fixture's `RecvGuard` must escalate
/// to a loud `EXIT_RECV_WEDGE` death instead of spinning silently.
// cast_sign_loss: ExitStatus::code() returns i32; exit_reason is always
// non-negative (voluntary codes < 0x1000). Casting to u64 is safe.
#[allow(clippy::cast_sign_loss)]
fn recv_wedge_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/capexhaust")
        .spawn()
        .expect("spawn /programs/capexhaust failed");

    let id = child.id();
    std::os::seraph::log!("spawned /programs/capexhaust handle={id:#x}");

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
        let info = startup_info();
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
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
