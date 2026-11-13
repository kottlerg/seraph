// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/test-fault/src/main.rs

//! Test-only fault-injection driver for devmgr's on-demand bind, driver
//! settle, mid-bootstrap teardown, and withdrawal.
//!
//! It declares QEMU's `pci-testdev` (PCI `1b36:0005`), which only the test
//! launches attach (`cargo xtask run --test-devices`), and is installed in
//! `/tests/drivers/`, which no drivers-directory pass of the boot lists:
//! devmgr binds it only when svctest sends `BIND_DRIVERS` with a cap on that
//! directory. devmgr delivers each instance the resource list of
//! `driver_binding::resources`, from which the instance takes its role
//! (`ipc::test_fault_labels`):
//!
//! - a function with no BAR 2 reports `DRIVER_READY` and serves `FAULT_PING`
//!   and `FAULT_EXIT`; `FAULT_EXIT` replies and then exits without receiving
//!   again, so a call queued after it reaches a dead driver, which devmgr
//!   withdraws;
//! - a function whose BAR 2 is `HANG_BAR_BYTES` long takes the whole list,
//!   then holds `HOLD_BYTES` of touched memory and neither reports ready nor
//!   exits, so devmgr's settle ends at its bound and destroys it;
//! - a function whose BAR 2 is `ORPHAN_BAR_BYTES` long holds `HOLD_BYTES`
//!   once that BAR's round arrives and answers the next round with a request
//!   devmgr's bootstrap server refuses, so devmgr destroys it before its
//!   bootstrap ends.
//!
//! svctest watches the held memory return to memmgr in both fault cases.

#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]

use driver_binding::decl::{Declaration, Interrupt, Match, Reset, Tier};
use driver_binding::resources::{Resource, ResourceList};
use ipc::{IpcMessage, test_fault_labels};
use std::os::seraph::startup_info;

driver_binding::driver_declaration!(Declaration {
    name: "test-fault",
    class: Some("test-fault"),
    matches: &[Match::PciId {
        vendor: 0x1b36,
        device: 0x0005,
    }],
    instance_limit: None,
    interrupt: Interrupt::NONE,
    dma: false,
    dma_width: None,
    phys_access: false,
    reset: Reset::None,
    tier: Tier::Auxiliary,
});

/// A round request whose low 16 label bits are not `bootstrap::REQUEST`
/// (`1`), so devmgr's `serve_round` rejects it with `INVALID` and the spawn
/// fails mid-bootstrap.
const BAD_ROUND_LABEL: u64 = 0x7E57_0000;

/// The PCI index of the BAR whose length selects the role.
const ROLE_BAR: u8 = 2;

/// The BAR 2 length of a resource round, if the round delivers BAR 2.
fn role_bar_bytes(list: &ResourceList) -> Option<u64>
{
    list.resources().iter().find_map(|r| match *r
    {
        Resource::Mmio {
            bar: Some(ROLE_BAR),
            bytes,
            ..
        } => Some(bytes),
        Resource::Mmio { .. } | Resource::IoPort { .. } | Resource::Interrupt { .. } => None,
    })
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"test-fault");
    let info = startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let creator = info.creator_endpoint;
    if creator == 0
    {
        std::os::seraph::log!("test-fault: no creator endpoint");
        syscall::thread_exit();
    }

    // Request the rounds one at a time, so the orphan role can refuse the
    // round after its BAR 2 arrives instead of finishing the list.
    let mut list = ResourceList::new();
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(round) = (unsafe { ipc::bootstrap::request_round(creator, ipc_buf) })
        else
        {
            std::os::seraph::log!("test-fault: bootstrap round failed");
            syscall::thread_exit();
        };
        match list.absorb(&round)
        {
            Ok(true) => break,
            Ok(false) =>
            {
                if role_bar_bytes(&list) == Some(test_fault_labels::ORPHAN_BAR_BYTES)
                {
                    orphan(creator, ipc_buf);
                }
            }
            Err(_) =>
            {
                std::os::seraph::log!("test-fault: resource list does not decode");
                syscall::thread_exit();
            }
        }
    }
    let Some(eps) = list.endpoints()
    else
    {
        syscall::thread_exit();
    };
    if role_bar_bytes(&list) == Some(test_fault_labels::HANG_BAR_BYTES)
    {
        hang();
    }

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { ipc::report_driver_ready(eps.devmgr_query, ipc_buf) }
    {
        std::os::seraph::log!("test-fault: DRIVER_READY failed ({:?}); exiting", e);
        syscall::thread_exit();
    }
    serve(eps.service, ipc_buf);
}

/// Touch [`test_fault_labels::HOLD_BYTES`] of memory: `vec!` writes every
/// byte, faulting the pages in.
fn touch(why: &str) -> Vec<u8>
{
    let held = std::vec![0xA5u8; test_fault_labels::HOLD_BYTES];
    std::os::seraph::log!(
        "test-fault: holding {} bytes, {}",
        test_fault_labels::HOLD_BYTES,
        why
    );
    held
}

/// Hold `held` for the rest of the process's life; `black_box` keeps the
/// buffer observable, so the stores are not elided. Only devmgr's
/// `DESTROY_PROCESS` ends the process, and only that returns the pages to
/// memmgr, which the harness observes.
fn hold(held: &[u8]) -> !
{
    loop
    {
        core::hint::black_box(held);
        let _ = syscall::thread_sleep(u64::from(u32::MAX));
    }
}

/// The hang role: never report ready.
fn hang() -> !
{
    hold(&touch("never reporting ready"))
}

/// The orphan role: touch the memory first, so it is held whether or not
/// devmgr replies to the refused request, then answer the next round with a
/// request devmgr refuses, and hold the memory until devmgr destroys the
/// process.
fn orphan(creator: u64, ipc_buf: *mut u64) -> !
{
    let held = touch("refusing the bootstrap");
    let bad = IpcMessage::new(BAD_ROUND_LABEL);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(creator, &bad, ipc_buf) };
    hold(&held)
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
        for &c in msg.caps()
        {
            let _ = syscall::cap_delete(c);
        }
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
