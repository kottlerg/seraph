// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/test-fault/src/main.rs

//! Test-only fault-injection driver for devmgr's driver settle and
//! withdrawal.
//!
//! Spawned on demand by devmgr's `TEST_SPAWN_FAULT_DRIVERS` shim through the
//! simple-device path: round 1 carries `[service_ep, hw_cap]` with the mode
//! word (`ipc::test_fault_labels`) in `data[0]`, round 2 the devmgr query
//! cap. In `MODE_READY` it reports `DRIVER_READY` and serves `FAULT_PING`
//! and `FAULT_EXIT`; `FAULT_EXIT` replies and then exits without receiving
//! again, so a call queued after it reaches a dead driver. In
//! `MODE_NEVER_READY` it holds `NEVER_READY_RESERVE_BYTES` of touched memory
//! and neither reports ready nor exits, so devmgr's settle ends at its bound
//! and destroys it; svctest watches the memory return to memmgr.
//!
//! TODO(#165): remove with the devmgr enumeration redesign.

use ipc::{IpcMessage, test_fault_labels};
use std::os::seraph::startup_info;

/// The caps and mode word the two bootstrap rounds deliver.
struct BootCaps
{
    service_ep: u64,
    devmgr_query_ep: u64,
    mode: u64,
}

fn bootstrap_caps(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let r1 = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if r1.cap_count < 2 || r1.done || r1.data_words < 1
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let r2 = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if r2.cap_count < 1 || !r2.done
    {
        return None;
    }
    Some(BootCaps {
        service_ep: r1.caps[0],
        devmgr_query_ep: r2.caps[0],
        mode: r1.data[0],
    })
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"test-fault");
    let info = startup_info();
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "test-fault: bootstrap caps missing");
        syscall::thread_exit();
    };

    if caps.mode == test_fault_labels::MODE_NEVER_READY
    {
        hang();
    }

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { ipc::report_driver_ready(caps.devmgr_query_ep, ipc_buf) }
    {
        std::os::seraph::log!(error: "test-fault: DRIVER_READY failed ({:?}); exiting", e);
        syscall::thread_exit();
    }
    serve(caps.service_ep, ipc_buf);
}

/// Hang in "setup": hold [`test_fault_labels::NEVER_READY_RESERVE_BYTES`]
/// of touched memory and neither report ready nor exit. Only devmgr's
/// `DESTROY_PROCESS` at the end of the settle ends this process, and only
/// that returns the reserved pages to memmgr, which the harness observes.
fn hang() -> !
{
    // `vec!` writes every byte, faulting the pages in; `black_box` below keeps
    // the buffer observable, so the stores are not elided.
    let reserved = std::vec![0xA5u8; test_fault_labels::NEVER_READY_RESERVE_BYTES];
    std::os::seraph::log!(
        "test-fault: holding {} bytes, never reporting ready",
        test_fault_labels::NEVER_READY_RESERVE_BYTES
    );
    loop
    {
        core::hint::black_box(&reserved);
        let _ = syscall::thread_sleep(u64::from(u32::MAX));
    }
}

/// Serve `FAULT_PING` until a `FAULT_EXIT`, then exit after its delay
/// without receiving again.
fn serve(service_ep: u64, ipc_buf: *mut u64) -> !
{
    let mut guard = ipc::recv_guard::RecvGuard::new(|_, _| {});
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        let reply = match msg.label
        {
            test_fault_labels::FAULT_PING | test_fault_labels::FAULT_EXIT =>
            {
                IpcMessage::new(ipc::devmgr_errors::SUCCESS)
            }
            _ => IpcMessage::new(ipc::devmgr_errors::UNKNOWN_OPCODE),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if msg.label == test_fault_labels::FAULT_EXIT
        {
            let _ = syscall::thread_sleep(test_fault_labels::FAULT_EXIT_DELAY_MS);
            std::os::seraph::log!("test-fault: exiting on FAULT_EXIT");
            syscall::thread_exit();
        }
    }
}
