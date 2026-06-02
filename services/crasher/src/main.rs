// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crasher/src/main.rs

//! Deliberate-crash fixture validating svcmgr's restart path.
//!
//! Gated, opt-in: its recipe lives in `/config/svcmgr/tests/`, co-staged
//! with svctest in CI and never launched on a normal boot. On every spawn
//! it asserts the recipe surfaces survived — argv, env, cwd, and bootstrap
//! seeds — logs `<surface> ok` for each, then deliberately faults (NULL
//! write) so svcmgr respawns it under `restart = always`. A surface that
//! fails to round-trip (notably one dropped on restart) is logged with a
//! `FATAL:` prefix, which run-parallel's fail regex catches and fails the
//! run; the deliberate `USERSPACE FAULT` itself is not a fail token.
//!
//! Capabilities: the bootstrap round delivers the recipe's two seeds —
//! `caps[0]` = svcmgr service endpoint, `caps[1]` = pwrmgr deny twin —
//! re-resolved on every (re)spawn. Log and procmgr endpoints arrive via
//! `ProcessInfo`, so they need no bootstrap round.

use std::os::seraph::startup_info;
use std::thread;
use std::time::Duration;

fn main()
{
    std::os::seraph::log::register_name(b"crasher");
    let info = startup_info();

    // Assert the recipe surfaces are present on THIS spawn — first launch
    // and every restart. Each logs `<surface> ok` or a `FATAL:` mismatch.
    check_argv();
    check_env();
    check_cwd();

    let (svcmgr_cap, second_cap, cap_count) =
        bootstrap_caps(info.creator_endpoint, info.ipc_buffer);
    check_seeds(svcmgr_cap, second_cap, cap_count);

    std::os::seraph::log!("alive (bootstrap caps={cap_count})");

    if svcmgr_cap != 0
    {
        probe_svcmgr(svcmgr_cap, info.ipc_buffer);
    }

    // Brief settle so the surface assertions land before the fault report;
    // kept well under the 3 s softlockup-watchdog idle window. Co-staged
    // with svctest, crasher's bounded faults finish long before svctest's
    // terminal marker, so the kernel fault dump never clobbers it.
    thread::sleep(Duration::from_millis(500));

    std::os::seraph::log!("triggering fault");

    // Trigger a fault: write to null pointer.
    // x86-64: #PF (vector 14) for unmapped page.
    // RISC-V: store page fault (scause 15).
    // SAFETY: deliberately invalid — this is the point.
    unsafe {
        core::ptr::write_volatile(core::ptr::null_mut::<u8>(), 0x42);
    }

    // SAFETY: unreachable — the write above faults and the kernel kills this thread.
    unsafe { core::hint::unreachable_unchecked() }
}

/// Assert argv survived the (re)spawn: the recipe declares
/// `argv = crasher selftest`.
fn check_argv()
{
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[0] == "crasher" && args[1] == "selftest"
    {
        std::os::seraph::log!("argv ok ({args:?})");
    }
    else
    {
        std::os::seraph::log!("FATAL: argv mismatch {args:?} (want [crasher, selftest])");
    }
}

/// Assert env survived the (re)spawn: the recipe declares
/// `env = CRASHER_MARKER=107`.
fn check_env()
{
    match std::env::var("CRASHER_MARKER")
    {
        Ok(v) if v == "107" => std::os::seraph::log!("env ok (CRASHER_MARKER={v})"),
        Ok(v) => std::os::seraph::log!("FATAL: env CRASHER_MARKER={v:?} (want \"107\")"),
        Err(e) => std::os::seraph::log!("FATAL: env CRASHER_MARKER unset: {e}"),
    }
}

/// Assert cwd survived the (re)spawn: the recipe declares `cwd = /tests`,
/// where crasher's own binary lives. A **relative** lookup of `crasher`
/// resolves through the child's `current_dir_cap`; if cwd were dropped on
/// restart that cap is zero and the lookup fails. The path is relative (no
/// leading `/`, no `.` component) so it routes through cwd, not the
/// namespace root. `std::env::current_dir()` is deliberately NOT used — the
/// spawner installs the cwd cap without a path string, so it reports
/// `Unsupported` until a process calls `set_current_dir`.
fn check_cwd()
{
    match std::fs::metadata("crasher")
    {
        Ok(_) => std::os::seraph::log!("cwd ok (relative lookup of \"crasher\" resolved)"),
        Err(e) => std::os::seraph::log!("FATAL: cwd relative lookup failed: {e}"),
    }
}

/// Assert the bootstrap seeds survived the (re)spawn: the recipe declares
/// `seed = svcmgr pwrmgr.deny`, so both slots must be present and non-zero.
fn check_seeds(svcmgr_cap: u32, second_cap: u32, cap_count: usize)
{
    if cap_count == 2 && svcmgr_cap != 0 && second_cap != 0
    {
        std::os::seraph::log!("seed ok (cap_count=2, both non-zero)");
    }
    else
    {
        std::os::seraph::log!(
            "FATAL: seed mismatch cap_count={cap_count} svcmgr={svcmgr_cap} \
             pwrmgr_deny={second_cap} (want 2 non-zero)"
        );
    }
}

/// Request the generic bootstrap round, returning `(svcmgr_cap, second_cap,
/// cap_count)`. Missing caps are zero.
fn bootstrap_caps(creator_ep: u32, ipc_buffer: *mut u8) -> (u32, u32, usize)
{
    if creator_ep == 0
    {
        return (0, 0, 0);
    }
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) })
    else
    {
        return (0, 0, 0);
    };
    let cap0 = if round.cap_count >= 1
    {
        round.caps[0]
    }
    else
    {
        0
    };
    let cap1 = if round.cap_count >= 2
    {
        round.caps[1]
    }
    else
    {
        0
    };
    (cap0, cap1, round.cap_count)
}

/// Liveness probe: call `QUERY_ENDPOINT` on the svcmgr cap for a name that
/// does not exist. A successful round-trip (any reply, including
/// `UNKNOWN_NAME`) proves the cap is live. A crash here would indicate the
/// seed cap was not re-injected after restart.
fn probe_svcmgr(svcmgr_cap: u32, ipc_buffer: *mut u8)
{
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = ipc_buffer.cast::<u64>();
    let probe_name = b"__probe__";
    let name_len = probe_name.len();
    let label = ipc::svcmgr_labels::QUERY_ENDPOINT | ((name_len as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, probe_name).build();
    // SAFETY: `ipc_buf` is the kernel-registered, page-aligned IPC buffer
    // page installed by `_start`.
    match unsafe { ipc::ipc_call(svcmgr_cap, &msg, ipc_buf) }
    {
        Ok(reply) => std::os::seraph::log!("svcmgr probe reply={}", reply.label),
        Err(_) => std::os::seraph::log!("svcmgr probe ipc_call failed"),
    }
}
