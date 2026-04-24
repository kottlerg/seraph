// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/crasher/src/main.rs

//! Deliberate-crash test service for svcmgr monitoring validation.
//!
//! Bootstraps one cap from its creator (init on first start, svcmgr on
//! restarts): `caps[0]` = optional tokened SEND cap on svcmgr's service
//! endpoint (registered at init-time under the bundle name "svcmgr"). Log
//! endpoint and procmgr endpoint arrive via `ProcessInfo`, so they are
//! available from `std::os::seraph::startup_info()` without a bootstrap round.
//!
//! Logs its bootstrap state, exercises the bundle cap with a harmless
//! `QUERY_ENDPOINT` probe, sleeps for 5 seconds, then triggers a fault.
//! The 5 s window lets other tests (usertest threading/mutex)
//! complete cleanly before the kernel's fault report interleaves with
//! their log output.
//!
//! Also validates svcmgr's restart path: if cap re-injection regresses,
//! the post-restart bootstrap reports `cap_count < 1` and the
//! `QUERY_ENDPOINT` probe is skipped, making the regression visible in the
//! log.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble; RUSTC_BOOTSTRAP=1 (set by xtask for StdUser
// builds) lets the attribute compile without a nightly-tagged toolchain.
#![feature(restricted_std)]

use std::os::seraph::startup_info;
use std::thread;
use std::time::Duration;

fn main()
{
    std::os::seraph::register_log_name(b"crasher");
    let info = startup_info();

    let (svcmgr_cap, cap_count) = bootstrap_caps(info.creator_endpoint, info.ipc_buffer);

    println!("alive (bootstrap caps={cap_count})");

    if svcmgr_cap != 0
    {
        probe_svcmgr(svcmgr_cap, info.ipc_buffer);
    }

    thread::sleep(Duration::from_secs(5));

    println!("triggering fault");

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

/// Request the generic bootstrap round, returning `(svcmgr_cap, cap_count)`.
/// Missing cap is zero.
fn bootstrap_caps(creator_ep: u32, ipc_buffer: *mut u8) -> (u32, usize)
{
    if creator_ep == 0
    {
        return (0, 0);
    }
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB), satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    let Ok(round) = (unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) })
    else
    {
        return (0, 0);
    };
    let svcmgr_cap = if round.cap_count >= 1
    {
        round.caps[0]
    }
    else
    {
        0
    };
    (svcmgr_cap, round.cap_count)
}

/// Liveness probe: call `QUERY_ENDPOINT` on the svcmgr cap for a name that
/// does not exist. A successful round-trip (any reply, including
/// `UNKNOWN_NAME`) proves the cap is live. A crash here would indicate the
/// bundle cap was not re-injected after restart.
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
        Ok(reply) => println!("svcmgr probe reply={}", reply.label),
        Err(_) => println!("svcmgr probe ipc_call failed"),
    }
}
