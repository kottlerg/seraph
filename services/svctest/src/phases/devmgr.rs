// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! devmgr surface — driver-spawn orphan teardown (#176).
//!
//! Drives devmgr's temporary `TEST_SPAWN_ORPHAN` shim to force a round-2
//! bootstrap failure in a fault-injection driver that hangs (never exits),
//! then asserts both that devmgr reports the spawn failed and that the
//! child's reserved pages return to memmgr's free pool. Free-pool recovery is
//! the observable that distinguishes #176's `DESTROY_PROCESS` teardown from a
//! leak: a hung child is never reaped by procmgr's exit path, so without
//! teardown its pages stay pinned and `free` never recovers.
//!
//! TODO(#165): retire with the devmgr enumeration redesign and its shim.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "devmgr_orphan_teardown",
        run: orphan_teardown_phase,
    }]
}

/// Read memmgr's current free-pool total (`QUERY_POOL_STATUS` `data[3]`).
fn free_bytes(memmgr_ep: u32, ipc_buf: *mut u64) -> u64
{
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }
        .expect("memmgr QUERY_POOL_STATUS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status"
    );
    reply.word(3)
}

fn orphan_teardown_phase(caps: &Caps)
{
    // The child reserves ~1 MiB before hanging; the margin absorbs unrelated
    // allocator noise in the sampling window.
    const MARGIN_BYTES: u64 = 128 * 1024;
    const MAX_POLL: u32 = 4096;

    let devmgr = caps.devmgr_registry;
    assert!(devmgr != 0, "devmgr_orphan: no devmgr registry cap seeded");

    let info = startup_info();
    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB).
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let memmgr = info.memmgr_endpoint;

    let free_before = free_bytes(memmgr, ipc_buf);

    // Trigger the forced-failure spawn. devmgr acks immediately, then runs the
    // spawn (which fails, unwinds, and DESTROYs the child) before it services
    // the result query below.
    let trigger = ipc::IpcMessage::new(ipc::devmgr_labels::TEST_SPAWN_ORPHAN);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let ack = unsafe { ipc::ipc_call(devmgr, &trigger, ipc_buf) }
        .expect("TEST_SPAWN_ORPHAN ipc_call failed");
    assert_eq!(
        ack.label,
        ipc::devmgr_errors::SUCCESS,
        "TEST_SPAWN_ORPHAN ack"
    );

    // Serviced only after devmgr returns to its loop — i.e. after the spawn and
    // its synchronous teardown completed.
    let query = ipc::IpcMessage::new(ipc::devmgr_labels::TEST_ORPHAN_RESULT);
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let res = unsafe { ipc::ipc_call(devmgr, &query, ipc_buf) }
        .expect("TEST_ORPHAN_RESULT ipc_call failed");
    assert_eq!(
        res.label,
        ipc::devmgr_errors::SUCCESS,
        "TEST_ORPHAN_RESULT status"
    );
    let outcome = res.word(0);
    assert_eq!(
        outcome, 1,
        "devmgr_orphan: expected spawn-failed/unwind (1), got outcome={outcome} \
         (2=unexpected success, 3=shim setup error)"
    );

    // With #176's teardown the child's reserved pages are reclaimed
    // synchronously, so `free` returns to baseline; without it the hung child
    // stays pinned and `free` stays ~1 MiB low. Poll to bound any incidental lag.
    let mut free_after = free_bytes(memmgr, ipc_buf);
    for _ in 0..MAX_POLL
    {
        if free_after + MARGIN_BYTES >= free_before
        {
            break;
        }
        let _ = syscall::thread_yield();
        free_after = free_bytes(memmgr, ipc_buf);
    }
    assert!(
        free_after + MARGIN_BYTES >= free_before,
        "devmgr_orphan: orphan pages not reclaimed: free_before={free_before} free_after={free_after}"
    );

    std::os::seraph::log!(
        "devmgr_orphan_teardown passed: spawn unwound, free reclaimed (before={free_before} after={free_after})"
    );
}
