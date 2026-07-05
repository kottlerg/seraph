// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Kernel process-fault surfaces (stack guard, RELRO seal, future
//! notification paths).

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "stack_overflow",
            run: stack_overflow_phase,
        },
        Phase {
            name: "relro_write",
            run: relro_write_phase,
        },
    ]
}

// cast_sign_loss: ExitStatus::code() returns i32; exit_reason is always
// non-negative in practice (kernel-set 0, clean-exit 0, fault 0x1000+vec,
// killed 0x2000). Casting to u64 is safe.
#[allow(clippy::cast_sign_loss)]
pub fn stack_overflow_phase(_: &Caps)
{
    use std::process::Command;
    use syscall::{EXIT_FAULT_BASE, EXIT_KILLED};

    let mut child = Command::new("/programs/stackoverflow")
        .spawn()
        .expect("spawn /programs/stackoverflow failed");

    let id = child.id();
    std::os::seraph::log!("spawned /programs/stackoverflow handle={id:#x}");

    let status = child.wait().expect("stackoverflow wait failed");
    std::os::seraph::log!("stackoverflow exited: {status}");

    assert!(
        !status.success(),
        "stackoverflow child must not exit cleanly: {status}"
    );

    let raw = status
        .code()
        .expect("stackoverflow ExitStatus must carry a code") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&raw),
        "expected fault exit_reason in 0x1000..0x2000, got {raw:#x}"
    );

    {
        let info = startup_info();
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(id, &query, ipc_buf) }
            .expect("QUERY_PROCESS call after fault failed");
        assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED for faulted child, got {state}"
        );
        assert_eq!(
            exit_reason, raw,
            "auto-reap exit_reason {exit_reason:#x} does not match spawner-observed {raw:#x}"
        );
        std::os::seraph::log!("auto_reap_fault (EXITED) passed");
    }

    std::os::seraph::log!("stack_overflow phase passed (exit_reason={raw:#x})");
}

/// `PT_GNU_RELRO` enforcement (#39): a write into `.data.rel.ro` must fault.
/// The fixture writes through a pointer to a relocated static; a clean exit
/// means the loader left the RELRO pages writable.
// cast_sign_loss: see stack_overflow_phase.
#[allow(clippy::cast_sign_loss)]
pub fn relro_write_phase(_: &Caps)
{
    use std::process::Command;
    use syscall::{EXIT_FAULT_BASE, EXIT_KILLED};

    let mut child = Command::new("/programs/relrofault")
        .spawn()
        .expect("spawn /programs/relrofault failed");

    let status = child.wait().expect("relrofault wait failed");
    std::os::seraph::log!("relrofault exited: {status}");

    assert!(
        !status.success(),
        "relrofault child exited cleanly — RELRO pages are writable: {status}"
    );
    let raw = status
        .code()
        .expect("relrofault ExitStatus must carry a code") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&raw),
        "expected fault exit_reason in 0x1000..0x2000, got {raw:#x}"
    );

    std::os::seraph::log!("relro_write phase passed (exit_reason={raw:#x})");
}
