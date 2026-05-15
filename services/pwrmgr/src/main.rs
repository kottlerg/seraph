// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// pwrmgr/src/main.rs

//! Seraph power manager — userspace authority for platform shutdown and
//! reboot.
//!
//! pwrmgr owns the raw platform caps that drive a clean power-off:
//! `AcpiReclaimable` Frame caps plus the `IoPortRange` cap on x86-64
//! (ACPI S5), and the `SbiControl` cap on RISC-V (SBI SRST). Init
//! transfers those caps to pwrmgr during Phase 3 bootstrap and hands a
//! `SHUTDOWN_AUTHORITY`-tokened SEND cap on pwrmgr's service endpoint to
//! the consumers permitted to invoke shutdown (today: usertest, plus a
//! reserved copy held by svcmgr for future escalation policy).
//!
//! See `services/pwrmgr/README.md` for the design and future-scope
//! sketch.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod caps;

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64.rs"]
mod arch;

use ipc::{IpcMessage, pwrmgr_errors, pwrmgr_labels};
use std::os::seraph::startup_info;

fn main() -> !
{
    std::os::seraph::log::register_name(b"pwrmgr");
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer is page-aligned (4 KiB) by the boot
    // protocol, satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = caps::bootstrap_caps(info, ipc_buf)
    else
    {
        std::os::seraph::log!("bootstrap failed, exiting");
        syscall::thread_exit();
    };

    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint, exiting");
        syscall::thread_exit();
    }

    std::os::seraph::log!(
        "ready (arch_cap={:#x}, acpi_regions={})",
        u64::from(caps.arch_cap),
        caps.acpi_region_count as u64
    );

    let self_thread = info.self_thread;

    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        let Ok(msg) = (unsafe { ipc::ipc_recv(caps.service_ep, ipc_buf) })
        else
        {
            continue;
        };

        let authorized = msg.token & pwrmgr_labels::SHUTDOWN_AUTHORITY != 0;
        match msg.label
        {
            pwrmgr_labels::SHUTDOWN =>
            {
                if !authorized
                {
                    reject(pwrmgr_errors::UNAUTHORIZED, ipc_buf);
                    continue;
                }
                std::os::seraph::log!("SHUTDOWN requested");
                arch::shutdown(self_thread, &caps);
                // Returned → shutdown failed. Reply so the caller does
                // not hang on its ipc_call.
                reject(pwrmgr_errors::INVALID_REQUEST, ipc_buf);
            }
            pwrmgr_labels::REBOOT =>
            {
                if !authorized
                {
                    reject(pwrmgr_errors::UNAUTHORIZED, ipc_buf);
                    continue;
                }
                std::os::seraph::log!("REBOOT requested");
                arch::reboot(self_thread, &caps);
                reject(pwrmgr_errors::INVALID_REQUEST, ipc_buf);
            }
            _ => reject(pwrmgr_errors::UNKNOWN_OPCODE, ipc_buf),
        }
    }
}

fn reject(code: u64, ipc_buf: *mut u64)
{
    let reply = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}
