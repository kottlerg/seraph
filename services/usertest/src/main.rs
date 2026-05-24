// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/usertest/src/main.rs

//! Programs-surface test orchestrator.
//!
//! Walks `/tests/programs/`, spawns each entry as a child process, and
//! reports a pass/fail verdict from the child's exit status. Each child
//! (per-program tester) drives its target `/programs/<name>` through that
//! program's real I/O surface; see [docs/testing.md](../../../docs/testing.md)
//! for the protocol.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. RUSTC_BOOTSTRAP=1 (set by
// xtask for StdUser builds) lets the attribute compile without a
// nightly-tagged toolchain.
#![feature(restricted_std)]
// usertest is an integration test harness: panics on protocol violation
// so faults surface in the log. `expect`/`unwrap` are the intended idiom
// here (coding-standards §D permits them in test code).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::seraph::startup_info;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TESTERS_DIR: &str = "/tests/programs";

fn main()
{
    std::os::seraph::log::register_name(b"usertest");

    let pwrmgr_auth = bootstrap_pwrmgr_auth();

    std::os::seraph::log!("starting");

    let testers = discover_testers();
    if testers.is_empty()
    {
        std::os::seraph::log!("no testers found under {TESTERS_DIR}");
    }

    let mut passed: usize = 0;
    let mut failed: usize = 0;

    for path in &testers
    {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<unnamed>");
        std::os::seraph::log!("running {}", path.display());

        match run_one(path)
        {
            Ok(()) =>
            {
                std::os::seraph::log!("  {name}: PASS");
                passed += 1;
            }
            Err(reason) =>
            {
                std::os::seraph::log!("  {name}: FAIL ({reason})");
                failed += 1;
            }
        }
    }

    std::os::seraph::log!("passed={passed} failed={failed}");
    if failed == 0
    {
        std::os::seraph::log!("ALL TESTS PASSED");
    }
    else
    {
        std::os::seraph::log!("SOME TESTS FAILED");
    }

    shutdown(pwrmgr_auth);
}

/// Enumerate `/tests/programs/`. Stable sort by filename for deterministic
/// output across boots. Empty list on any I/O error (the run then reports
/// "no testers found"); that surfaces a sysroot-misconfiguration as a
/// visible empty run rather than a hidden zero-test pass.
fn discover_testers() -> Vec<PathBuf>
{
    let mut out: Vec<PathBuf> = match std::fs::read_dir(TESTERS_DIR)
    {
        Ok(it) => it
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// Spawn one tester, forward its stdout/stderr to the boot log under a
/// per-tester prefix, and turn the exit status into a pass/fail.
fn run_one(path: &Path) -> Result<(), String>
{
    let path_str = path.to_str().ok_or_else(|| "non-utf8 path".to_string())?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("<unnamed>")
        .to_string();

    let mut child = Command::new(path_str)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    if let Some(s) = stdout
    {
        forward_lines(&name, "out", s);
    }
    if let Some(s) = stderr
    {
        forward_lines(&name, "err", s);
    }

    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    if status.success()
    {
        Ok(())
    }
    else
    {
        Err(match status.code()
        {
            Some(c) => format!("exit={c}"),
            None => "killed by signal".to_string(),
        })
    }
}

/// Drain a child stream and emit each line through the log under
/// `[<tester>:<stream>]`. Truncates lines at the log buffer; binary
/// output is silently dropped past the first NUL.
fn forward_lines<R: std::io::Read>(tester: &str, stream: &str, mut r: R)
{
    let mut buf = [0u8; 512];
    let mut line: Vec<u8> = Vec::with_capacity(512);
    loop
    {
        match r.read(&mut buf)
        {
            Ok(0) | Err(_) => break,
            Ok(n) =>
            {
                for &b in &buf[..n]
                {
                    if b == b'\n'
                    {
                        let s = String::from_utf8_lossy(&line);
                        std::os::seraph::log!("  [{tester}:{stream}] {s}");
                        line.clear();
                    }
                    else
                    {
                        line.push(b);
                    }
                }
            }
        }
    }
    if !line.is_empty()
    {
        let s = String::from_utf8_lossy(&line);
        std::os::seraph::log!("  [{tester}:{stream}] {s}");
    }
}

/// Bootstrap one cap from the creator-endpoint round: pwrmgr's SHUTDOWN-
/// tokened SEND (slot 0). The recipe seeds `pwrmgr.shutdown` first; absent
/// caps come back as zero and the shutdown step logs a skip instead of
/// powering off (boot stays up for inspection).
fn bootstrap_pwrmgr_auth() -> u32
{
    let info = startup_info();
    if info.creator_endpoint == 0
    {
        return 0;
    }
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(info.creator_endpoint, ipc_buf) })
    else
    {
        return 0;
    };
    if round.cap_count >= 1
    {
        round.caps[0]
    }
    else
    {
        0
    }
}

/// Terminal — pwrmgr powers off and QEMU exits. A reply arrives only on
/// failure (cap missing the authority token or pwrmgr cannot power off);
/// in that case the log records the symptom and the process falls through
/// to its normal exit, leaving the system idle.
fn shutdown(pwrmgr_auth: u32)
{
    if pwrmgr_auth == 0
    {
        std::os::seraph::log!("pwrmgr shutdown skipped: no authority cap");
        return;
    }
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(pwrmgr_auth, &msg, ipc_buf) };
    match reply
    {
        Ok(r) => std::os::seraph::log!(
            "pwrmgr SHUTDOWN returned unexpectedly (label={:#x})",
            r.label
        ),
        Err(_) => std::os::seraph::log!("pwrmgr SHUTDOWN ipc_call failed"),
    }
}
