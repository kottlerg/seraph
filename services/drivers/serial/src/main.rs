// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/serial/src/main.rs

//! Seraph userspace serial (UART) device driver.
//!
//! Spawned by devmgr with the platform UART authority cap — an
//! `IoPort` covering COM1 on x86-64, an `Mmio` covering the
//! ACPI-SPCR-reported NS16550 on RISC-V — a RECV cap on its service endpoint,
//! and (optionally) the UART interrupt cap. Owns the UART end-to-end and is
//! the sole driver-mediated path for userspace serial bytes in both
//! directions: real-logd and every other writer reach it via
//! [`serial_labels::SERIAL_WRITE_BYTES`]; the terminal reads input via
//! [`serial_labels::SERIAL_READ_BYTES`], waking on an interrupt registered
//! through [`serial_labels::SERIAL_REGISTER_RX_NOTIFY`]. The service loop never
//! blocks (reads drain and return at once), so a pending read never starves
//! writers.
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
    /// UART interrupt cap (x86 ISA IRQ4, riscv NS16550 PLIC source). Zero when
    /// devmgr delivered no IRQ: RX then degrades to timeout polling on the
    /// client side, and `SERIAL_REGISTER_RX_NOTIFY` reports `REGISTER_FAILED`.
    irq_cap: u32,
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
        irq_cap: if round.cap_count >= 3
        {
            round.caps[2]
        }
        else
        {
            0
        },
    })
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Maximum bytes drained per `SERIAL_READ_BYTES`, matching the write path's
/// `0..=512` payload bound.
const MAX_READ_BYTES: usize = 512;

fn handle_request(msg: &IpcMessage, irq_cap: u32, ipc_buf: *mut u64)
{
    // Label encoding mirrors `stream_labels::STREAM_BYTES`: opcode in bits
    // 0-15, payload byte length in bits 16-31.
    let op = msg.label & 0xFFFF;
    let reply = if op == serial_labels::SERIAL_WRITE_BYTES
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
    else if op == serial_labels::SERIAL_READ_BYTES
    {
        let mut buf = [0u8; MAX_READ_BYTES];
        let mut n = 0;
        while n < buf.len()
        {
            let Some(b) = arch::current::serial_read_byte()
            else
            {
                break;
            };
            buf[n] = b;
            n += 1;
        }
        // Re-arm the receive interrupt: the kernel masks the line on each fire,
        // and the ack unmasks it for the next byte. Idempotent, so it is also
        // safe on a poll-driven read where no IRQ was pending.
        if irq_cap != 0
        {
            let _ = syscall::irq_ack(irq_cap);
        }
        IpcMessage::builder(serial_errors::SUCCESS | ((n as u64) << 16))
            .bytes(0, &buf[..n])
            .build()
    }
    else if op == serial_labels::SERIAL_REGISTER_RX_NOTIFY
    {
        let notif = msg.caps().first().copied().unwrap_or(0);
        if irq_cap != 0 && notif != 0 && syscall::irq_register(irq_cap, notif).is_ok()
        {
            // irq_register leaves the line masked; the first ack arms it.
            let _ = syscall::irq_ack(irq_cap);
            IpcMessage::new(serial_errors::SUCCESS)
        }
        else
        {
            IpcMessage::new(serial_errors::REGISTER_FAILED)
        }
    }
    else
    {
        IpcMessage::new(serial_errors::UNKNOWN_OPCODE)
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

fn service_loop(service_ep: u32, irq_cap: u32, ipc_buf: *mut u64) -> !
{
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
        else
        {
            continue;
        };
        handle_request(&msg, irq_cap, ipc_buf);
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

    service_loop(caps.service_ep, caps.irq_cap, ipc_buf);
}
