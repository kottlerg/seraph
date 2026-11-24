// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/hello/tester/src/main.rs

//! Per-program tester for `/programs/hello`. Spawns it with a piped stdout,
//! asserts the expected line appears, and asserts a clean exit. Before that,
//! it checks the seed usertest's recipe declares for it, `pwrmgr.deny`: it
//! takes the cap over the bootstrap protocol, which usertest's spawn waits
//! on, and pwrmgr refuses it `SHUTDOWN`. See
//! [docs/testing.md](../../../docs/testing.md) for the protocol.
//!
//! After taking the seed it writes [`STDERR_BLOCK_BYTES`] to its own stderr while its stdout
//! is open, which the usertest orchestrator must drain while it waits on
//! stdout (programs/usertest/README.md); an orchestrator that does not leaves
//! this tester blocked on a full pipe ring and the run hangs.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

const EXPECTED_LINE: &str = "hello from seraph userspace";

/// Bytes written to stderr before the stdout check: twice the 2048-byte pipe
/// ring (`RING_CAPACITY` in `runtime/ruststd/src/sys/pipe/seraph.rs`), so
/// the writes cannot complete unless the reader drains them.
const STDERR_BLOCK_BYTES: usize = 4096;

/// Length of each stderr line, its newline included.
const STDERR_LINE_BYTES: usize = 1024;

fn main()
{
    // The seed is taken before the first write to stdout or stderr: usertest's
    // spawn returns, and it drains the tester's streams, only once the seed
    // request has come (docs/testing.md § Per-program tester protocol).
    check_declared_seed();

    // Defect guarded: an orchestrator that reads a tester's stdout to its end
    // before it drains the tester's stderr, so a tester whose stderr fills its
    // pipe ring blocks and the run hangs.
    let line = "e".repeat(STDERR_LINE_BYTES - 1);
    let mut stderr = std::io::stderr().lock();
    for _ in 0..STDERR_BLOCK_BYTES / STDERR_LINE_BYTES
    {
        writeln!(stderr, "{line}").expect("write the stderr block");
    }
    drop(stderr);

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
