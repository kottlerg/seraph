// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/serial/src/main.rs

//! Seraph userspace serial (UART) device driver.
//!
//! Spawned by devmgr with the platform UART authority cap — an
//! `IoPort` covering COM1 on x86-64, an `Mmio` covering the
//! ACPI-SPCR-reported NS16550 on RISC-V — plus a RECV cap on its service
//! endpoint. Owns the UART end-to-end and is the sole driver-mediated sink
//! for userspace serial bytes: real-logd and every other writer reach it
//! via [`serial_labels::SERIAL_WRITE_BYTES`].
//!
//! Unlike the sibling RTC drivers, this driver MUST NOT call
//! `std::os::seraph::log!`. logd routes its own output here, so a log call
//! would deadlock (driver → log endpoint → logd → driver). Diagnostics are
//! therefore dropped; fatal bootstrap failures `thread_exit` silently. The
//! pre-driver boot window is covered by init-logd's direct-UART path (see
//! `docs/console-model.md`).

#![allow(clippy::cast_possible_truncation)]

mod arch;

use ipc::{IpcMessage, serial_errors, serial_labels};
use std::os::seraph::startup_info;

// ── Bootstrap ──────────────────────────────────────────────────────────────

struct BootCaps
{
    service_ep: u32,
    hw_cap: u32,
}

fn bootstrap_caps(creator_endpoint: u32, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 2 || !round.done
    {
        return None;
    }
    Some(BootCaps {
        service_ep: round.caps[0],
        hw_cap: round.caps[1],
    })
}

// ── Service loop ───────────────────────────────────────────────────────────

fn handle_request(msg: &IpcMessage, ipc_buf: *mut u64)
{
    // Label encoding mirrors `stream_labels::STREAM_BYTES`: opcode in bits
    // 0-15, payload byte length in bits 16-31.
    let reply = if msg.label & 0xFFFF == serial_labels::SERIAL_WRITE_BYTES
    {
        let byte_len = ((msg.label >> 16) & 0xFFFF) as usize;
        let bytes = msg.data_bytes();
        let n = byte_len.min(bytes.len());
        for &b in &bytes[..n]
        {
            arch::current::serial_write_byte(b);
        }
        IpcMessage::new(serial_errors::SUCCESS)
    }
    else
    {
        IpcMessage::new(serial_errors::UNKNOWN_OPCODE)
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn service_loop(service_ep: u32, ipc_buf: *mut u64) -> !
{
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
        else
        {
            continue;
        };
        handle_request(&msg, ipc_buf);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    if caps.service_ep == 0 || caps.hw_cap == 0
    {
        syscall::thread_exit();
    }

    if !arch::current::serial_init(info.self_thread, info.self_aspace, caps.hw_cap)
    {
        syscall::thread_exit();
    }

    service_loop(caps.service_ep, ipc_buf);
}
