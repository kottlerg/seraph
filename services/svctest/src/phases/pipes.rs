// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Kernel pipe object surface (Stdio piped, death-bridge EOF).

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "pipes",
            run: pipes_phase,
        },
        Phase {
            name: "pipe_fault_eof",
            run: pipe_fault_eof_phase,
        },
    ]
}

#[allow(clippy::too_many_lines)]
pub fn pipes_phase(_: &Caps)
{
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    // ── (1) hello capture ─────────────────────────────────────────────
    {
        let mut child = Command::new("/programs/hello")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn /programs/hello (piped) failed");
        let mut stdout_bytes = Vec::new();
        {
            let mut out = child
                .stdout
                .take()
                .expect("piped child must have stdout handle");
            out.read_to_end(&mut stdout_bytes)
                .expect("read_to_end on hello stdout failed");
        }
        let body = String::from_utf8_lossy(&stdout_bytes);
        for line in body.lines()
        {
            std::os::seraph::log!("hello: {line}");
        }
        assert!(
            !stdout_bytes.is_empty(),
            "hello produced no stdout bytes — pipe wiring broken"
        );
        let status = child.wait().expect("hello wait failed");
        assert!(status.success(), "hello did not exit cleanly: {status}");
        std::os::seraph::log!("pipes: hello capture ok ({} bytes)", stdout_bytes.len());
    }

    // ── (2) stdiotest round-trip ──────────────────────────────────────
    {
        let mut child = Command::new("/programs/stdiotest")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn /programs/stdiotest (piped) failed");

        {
            let mut stdin = child
                .stdin
                .take()
                .expect("piped child must have stdin handle");
            stdin
                .write_all(b"hello\n")
                .expect("write to stdiotest stdin failed");
        }

        let mut stdout_bytes = Vec::new();
        {
            let mut out = child
                .stdout
                .take()
                .expect("piped child must have stdout handle");
            out.read_to_end(&mut stdout_bytes)
                .expect("read_to_end on stdiotest stdout failed");
        }
        let body = String::from_utf8_lossy(&stdout_bytes);
        for line in body.lines()
        {
            std::os::seraph::log!("stdiotest: {line}");
        }
        assert!(
            body.contains("got 6 bytes"),
            "stdiotest stdout missing byte-count line: {body:?}"
        );
        assert!(
            body.contains("shouted: HELLO"),
            "stdiotest stdout missing shout line: {body:?}"
        );
        assert!(
            body.contains("PASS"),
            "stdiotest stdout missing PASS marker: {body:?}"
        );

        if let Some(mut err) = child.stderr.take()
        {
            let mut stderr_bytes = Vec::new();
            err.read_to_end(&mut stderr_bytes)
                .expect("read_to_end on stdiotest stderr failed");
            if !stderr_bytes.is_empty()
            {
                let body = String::from_utf8_lossy(&stderr_bytes);
                for line in body.lines()
                {
                    std::os::seraph::log!("stdiotest.err: {line}");
                }
            }
        }

        let status = child.wait().expect("stdiotest wait failed");
        assert!(status.success(), "stdiotest did not exit cleanly: {status}");
        std::os::seraph::log!("pipes: stdiotest round-trip ok");
    }

    // ── (3) Command::output() round-trip ──────────────────────────────
    {
        let output = Command::new("/programs/hello")
            .output()
            .expect("Command::output on hello failed");
        assert!(
            output.status.success(),
            "hello via output() did not exit cleanly: {}",
            output.status
        );
        assert!(
            !output.stdout.is_empty(),
            "Command::output captured zero stdout bytes"
        );
        std::os::seraph::log!(
            "pipes: Command::output ok ({} stdout, {} stderr)",
            output.stdout.len(),
            output.stderr.len(),
        );
    }

    std::os::seraph::log!("pipes phase passed");
}

// cast_sign_loss: ExitStatus::code() returns i32; exit_reason is always
// non-negative in practice.
#[allow(clippy::cast_sign_loss)]
pub fn pipe_fault_eof_phase(_: &Caps)
{
    use std::io::Read;
    use std::process::{Command, Stdio};
    use syscall::{EXIT_FAULT_BASE, EXIT_KILLED};

    let mut child = Command::new("/programs/pipefault")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/pipefault failed");

    let id = child.id();
    std::os::seraph::log!("spawned /programs/pipefault handle={id:#x}");

    let mut stdout = child.stdout.take().expect("piped stdout missing");
    let mut bytes = Vec::new();
    let n = stdout
        .read_to_end(&mut bytes)
        .expect("read_to_end on pipefault stdout failed");
    assert_eq!(
        n,
        bytes.len(),
        "read_to_end length mismatch ({n} vs {})",
        bytes.len()
    );
    assert!(
        bytes.starts_with(b"prefix\n"),
        "pipefault stdout missing prefix: {:?}",
        String::from_utf8_lossy(&bytes)
    );
    std::os::seraph::log!(
        "pipe_fault_eof: drained {} bytes, EOF observed without hang",
        bytes.len()
    );

    let status = child.wait().expect("pipefault wait failed");
    let raw = status
        .code()
        .expect("pipefault ExitStatus must carry a code") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&raw),
        "expected pipefault fault exit_reason in 0x1000..0x2000, got {raw:#x}"
    );

    {
        let info = startup_info();
        #[allow(clippy::cast_ptr_alignment)]
        let ipc_buf = info.ipc_buffer.cast::<u64>();
        let query = ipc::IpcMessage::new(ipc::procmgr_labels::QUERY_PROCESS);
        // SAFETY: `ipc_buf` is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(id, &query, ipc_buf) }
            .expect("QUERY_PROCESS for pipefault failed");
        assert_eq!(reply.label, ipc::procmgr_errors::SUCCESS);
        let state = reply.word(0);
        let exit_reason = reply.word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::EXITED,
            "expected EXITED for faulted piped child, got {state}"
        );
        assert_eq!(
            exit_reason, raw,
            "auto-reap exit_reason {exit_reason:#x} disagrees with spawner-observed {raw:#x}"
        );
    }

    std::os::seraph::log!("pipe_fault_eof phase passed (exit_reason={raw:#x})");
}
