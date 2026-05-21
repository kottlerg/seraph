// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! procmgr / `std::process::Command` surface.
//!
//! Hosts the child-mode entry `cwd_child_main` spawned by
//! `command_cwd_inherit_phase`.

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

/// `command_*` and `stdio_file_unsupported` run after the namespace
/// cluster has established attenuation invariants.
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
            name: "stdio_file_unsupported",
            run: stdio_file_unsupported_phase,
        },
    ]
}

/// Child-mode dispatch for argv tokens this module owns. Matching
/// arms diverge via the child function's `std::process::exit`; on a
/// miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == "cwd-child"
    {
        cwd_child_main();
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

    let mut child = Command::new("/bin/hello")
        .arg("one")
        .arg("two")
        .env("SPAWNED_BY", "svctest")
        .spawn()
        .expect("spawn /bin/hello failed");

    let id = child.id();
    std::os::seraph::log!("spawned /bin/hello handle={id:#x}");

    {
        let info = startup_info();
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let id = child.id();
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
        "child /bin/hello did not exit cleanly: {status}"
    );

    let again = child.try_wait().expect("try_wait after wait failed");
    assert!(
        again.is_some(),
        "try_wait after wait must surface cached status"
    );
    std::os::seraph::log!("try_wait phase passed");

    {
        let info = startup_info();
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
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
        .current_dir("/srv")
        .spawn()
        .expect("Command::cwd(/srv) must spawn cleanly");
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
        let err = Command::new("/srv/test.txt")
            .spawn()
            .expect_err("spawning a non-ELF path must fail");
        let _ = i;
        let _ = err;
    }

    let mut child = Command::new("/bin/hello")
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

pub fn stdio_file_unsupported_phase(_: &Caps)
{
    use std::fs::File;
    use std::io::ErrorKind;
    use std::process::{Command, Stdio};

    let file = File::open("/srv/test.txt").expect("open /srv/test.txt for stdio probe");
    let err = Command::new("/bin/hello")
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
