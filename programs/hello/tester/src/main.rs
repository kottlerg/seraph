// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/hello/tester/src/main.rs

//! Per-program tester for `/programs/hello`. Spawns it with a piped stdout,
//! asserts the expected line appears, and asserts a clean exit. Then, as a
//! program, which may start programs only (docs/signing.md § Signature Policy
//! in procmgr), asserts that starting a service is refused. Before all that,
//! it checks the seed usertest's recipe declares for it, `pwrmgr.deny`: it
//! takes the cap over the bootstrap protocol, which usertest's spawn waits
//! on, and pwrmgr refuses it `SHUTDOWN`. See
//! [docs/testing.md](../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::io::Read;
use std::process::{Command, Stdio};

const EXPECTED_LINE: &str = "hello from seraph userspace";

/// A service image a program may not start: the restart-path fixture,
/// which only crashes if it does start.
const SERVICE_IMAGE: &str = "/tests/fixtures/crasher";

fn main()
{
    check_declared_seed();

    let mut child = Command::new("/programs/hello")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/hello");

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /programs/hello stdout");

    let status = child.wait().expect("wait /programs/hello");
    let out = String::from_utf8_lossy(&bytes);

    let line_present = out.lines().any(|l| l.contains(EXPECTED_LINE));
    if !line_present
    {
        println!("[hello-tester] FAIL expected line missing: {EXPECTED_LINE:?}");
        println!("[hello-tester] captured stdout: {out:?}");
        std::process::exit(1);
    }
    if !status.success()
    {
        println!("[hello-tester] FAIL non-zero exit: {:?}", status.code());
        std::process::exit(2);
    }

    // Defect guarded: a program starting an image in a role its creator's
    // signature policy does not admit, a service here.
    match Command::new(SERVICE_IMAGE).spawn()
    {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {}
        Err(e) =>
        {
            println!("[hello-tester] FAIL starting {SERVICE_IMAGE}: {e}, not PermissionDenied");
            std::process::exit(3);
        }
        Ok(mut started) =>
        {
            let _ = started.kill();
            println!("[hello-tester] FAIL a program started the service {SERVICE_IMAGE}");
            std::process::exit(4);
        }
    }

    println!("[hello-tester] PASS");
}

/// Take the one seed usertest's recipe declares for this tester
/// (`TESTER_SEEDS=hello:1`, `pwrmgr.deny`) over the bootstrap protocol and
/// check it is that cap: pwrmgr answers its `SHUTDOWN` `UNAUTHORIZED`.
/// Defect guarded: a declared seed that does not reach its tester, or one
/// that reaches it as another seed's cap.
fn check_declared_seed()
{
    let info = std::os::seraph::startup_info();
    if info.creator_endpoint == 0
    {
        println!("[hello-tester] FAIL no creator endpoint for the declared seed");
        std::process::exit(5);
    }
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: the IPC buffer is registered by `_start` and page-aligned.
    let slots = unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) };
    let deny = match slots
    {
        Ok([cap]) if cap != 0 => cap,
        other =>
        {
            println!("[hello-tester] FAIL declared seed not delivered: {other:?}");
            std::process::exit(6);
        }
    };
    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    match unsafe { ipc::ipc_call(deny, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == ipc::pwrmgr_errors::UNAUTHORIZED =>
        {}
        Ok(reply) =>
        {
            println!(
                "[hello-tester] FAIL the declared seed's SHUTDOWN answered {:#x}, not UNAUTHORIZED",
                reply.label
            );
            std::process::exit(7);
        }
        Err(e) =>
        {
            println!("[hello-tester] FAIL the declared seed's SHUTDOWN call failed: {e}");
            std::process::exit(8);
        }
    }
}
