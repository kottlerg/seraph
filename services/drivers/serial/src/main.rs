// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/main.rs

//! Seraph userspace serial (UART) device driver.
//!
//! Bound by devmgr to the UART's platform device record, it receives the
//! resource list (`driver_binding::resources`): the UART's register window
//! (an `IoPort` range on x86-64, an `Mmio` range on RISC-V), its wired line
//! when the record has one, a RECV cap on its service endpoint, and its
//! devmgr query cap. Once the UART
//! is set up it reports ready (`devmgr_labels::DRIVER_READY`) on the query
//! cap, immediately before its service loop: devmgr serves the driver's
//! endpoint only after that report, and the driver exits when devmgr refuses
//! it. Owns the UART
//! end-to-end and is the sole driver-mediated path for userspace serial
//! bytes in both directions: real-logd and every other writer reach it via
//! [`serial_labels::SERIAL_WRITE_BYTES`]; the terminal reads input via
//! [`serial_labels::SERIAL_READ_BYTES`], waking on an interrupt registered
//! through [`serial_labels::SERIAL_REGISTER_RX_NOTIFY`]. The service loop
//! never blocks (reads drain and return at once), so a pending read never
//! starves writers.
//!
//! Unlike the sibling RTC drivers, this driver MUST NOT call
//! `std::os::seraph::log!`; the rule and its deadlock chain are in
//! `docs/console-model.md` § Logging constraint on the serial and framebuffer
//! drivers. Diagnostics are dropped; fatal bootstrap failures `thread_exit`
//! silently.

mod arch;

use driver_binding::resources::{self, PlatformDelivery};
use ipc::{IpcMessage, serial_errors, serial_labels};
use std::os::seraph::startup_info;

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations): the console UART the SPCR
// names, or an ACPI namespace device of `_HID` `PNP0501`.
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "serial",
    class: Some("serial"),
    matches: &[
        driver_binding::decl::Match::Spcr(0x00),
        driver_binding::decl::Match::Spcr(0x12),
        driver_binding::decl::Match::AcpiHid("PNP0501")
    ],
    instance_limit: Some(1),
    interrupt: driver_binding::decl::Interrupt::OPTIONAL,
    dma: false,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::None,
    tier: driver_binding::decl::Tier::Boot,
});

// ── Bootstrap ──────────────────────────────────────────────────────────────

/// The UART's interrupt: its cap (zero when devmgr delivered no line, so RX
/// degrades to timeout polling on the client side, and
/// `SERIAL_REGISTER_RX_NOTIFY` reports `REGISTER_FAILED`) and the mode the
/// record gives it.
#[derive(Clone, Copy)]
struct Irq
{
    cap: u64,
    mode: u64,
}

/// Receive the resource list (`driver_binding::resources`): the UART's
/// register window, an `IoPort` or `Mmio` range, its wired line if the
/// record has one, and the endpoints.
fn bootstrap(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<PlatformDelivery>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let list = unsafe { resources::receive(creator_endpoint, ipc_buf) }.ok()?;
    PlatformDelivery::from_list(&list)
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Maximum bytes drained per `SERIAL_READ_BYTES`, matching the write path's
/// `0..=512` payload bound: `MSG_DATA_WORDS_MAX` words of 8 bytes, the most
/// one reply carries. A caller drains more input with further reads.
const MAX_READ_BYTES: usize = 512;

/// Serve one request. Every cap the request carries and the driver does not
/// keep (all of them but an accepted RX notification) is deleted before the
/// reply, so no request leaves a slot of the driver's `CSpace` taken.
/// `rx_notify` is the notification the UART interrupt is bound to (0 when
/// none is).
fn handle_request(msg: &IpcMessage, irq: Irq, rx_notify: &mut u64, ipc_buf: *mut u64)
{
    // Label encoding mirrors `stream_labels::STREAM_BYTES`: opcode in bits
    // 0-15, payload byte length in bits 16-31.
    let op = msg.label & 0xFFFF;
    // Verb-bit gate (docs/capability-model.md): writes need WRITE_AUTHORITY,
    // reads and RX-notify need READ_AUTHORITY. Unknown opcodes carry no gate
    // and fall through to the UNKNOWN_OPCODE arm.
    let required_authority = match op
    {
        serial_labels::SERIAL_WRITE_BYTES => serial_labels::WRITE_AUTHORITY,
        serial_labels::SERIAL_READ_BYTES | serial_labels::SERIAL_REGISTER_RX_NOTIFY =>
        {
            serial_labels::READ_AUTHORITY
        }
        _ => 0,
    };
    let authorized = required_authority == 0 || msg.badge & required_authority != 0;
    // Only an authorized RX-notify request keeps a cap, its first one, which
    // `register_rx_notify` keeps or deletes. No client delivers a cap on an
    // unauthorized request today: devmgr mints its test-deny SENDs without
    // GRANT, and every SEND it grants carries all of this driver's verb bits.
    // The `authorized` term keeps a future partial-authority SEND from
    // leaving its notification here.
    let kept = usize::from(authorized && op == serial_labels::SERIAL_REGISTER_RX_NOTIFY);
    for &cap in msg.caps().iter().skip(kept)
    {
        let _ = syscall::cap_delete(cap);
    }
    let reply = if !authorized
    {
        IpcMessage::new(serial_errors::UNAUTHORIZED)
    }
    else if op == serial_labels::SERIAL_WRITE_BYTES
    {
        // The mask bounds the length to 16 bits, so the conversion cannot fail.
        // 16 label bits exceed the 512 bytes one message's data words carry,
        // and `n` clamps to those bytes.
        let byte_len = usize::try_from((msg.label >> 16) & 0xFFFF).unwrap_or(0);
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
        if irq.cap != 0
        {
            let _ = syscall::irq_ack(irq.cap);
        }
        IpcMessage::builder(serial_errors::SUCCESS | ((n as u64) << 16))
            .bytes(0, &buf[..n])
            .build()
    }
    else if op == serial_labels::SERIAL_REGISTER_RX_NOTIFY
    {
        register_rx_notify(irq, msg.caps().first().copied().unwrap_or(0), rx_notify)
    }
    else
    {
        IpcMessage::new(serial_errors::UNKNOWN_OPCODE)
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Bind the UART interrupt to `notification` and arm it, replacing the
/// notification bound before, whose cap is then deleted. A refused
/// registration (no IRQ cap held, no notification supplied, or a cap
/// `SYS_IRQ_REGISTER` rejects) deletes `notification` and leaves the earlier
/// binding in place.
fn register_rx_notify(irq: Irq, notification: u64, rx_notify: &mut u64) -> IpcMessage
{
    // The mode the device record gives the line, as devmgr delivered it.
    // devmgr keeps the line exclusive, so no other binding has recorded
    // another mode on it.
    let irq_cap = irq.cap;
    if irq_cap == 0
        || notification == 0
        || syscall::irq_register(irq_cap, notification, irq.mode).is_err()
    {
        if notification != 0
        {
            let _ = syscall::cap_delete(notification);
        }
        return IpcMessage::new(serial_errors::REGISTER_FAILED);
    }
    // A registration through the bound Interrupt cap rebinds it, and returns
    // once no delivery to the replaced notification is in flight, so the
    // replaced cap is free to delete.
    let old = core::mem::replace(rx_notify, notification);
    if old != 0
    {
        let _ = syscall::cap_delete(old);
    }
    // irq_register leaves a first binding masked; the first ack arms it.
    let _ = syscall::irq_ack(irq_cap);
    IpcMessage::new(serial_errors::SUCCESS)
}

fn service_loop(service_ep: u64, irq: Irq, ipc_buf: *mut u64) -> !
{
    let mut rx_notify = 0;
    // No diagnostic hook: a `log!` here is a blocking call into logd, which
    // may itself be blocked calling this driver (see the module doc). The
    // kernel's rate-limited recv-failure line and the guard's exit remain
    // the signal.
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
        handle_request(&msg, irq, &mut rx_notify, ipc_buf);
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // logd writes every log line through this driver, so a debug-authority
    // holder that stopped it would block on its own log output: declare this
    // process undebuggable before it spawns a thread
    // (`procmgr_labels::DECLARE_NO_DEBUG`). A refusal leaves it debuggable.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    };

    let Some(device) = bootstrap(info.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };
    let (cap, mode) = device.wired.unwrap_or((0, 0));
    let irq = Irq { cap, mode };

    // SAFETY: `info.self_aspace` is this process's address space, and
    // `device.registers` is the register window devmgr delivered, whose cap
    // the call maps (riscv64) or binds (x86-64) only after checking its kind
    // and size.
    if !unsafe {
        arch::current::serial_init(
            info.self_thread,
            info.self_aspace,
            &device.registers,
            irq.cap != 0,
        )
    }
    {
        syscall::thread_exit();
    }

    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::report_driver_ready(device.endpoints.devmgr_query, ipc_buf) }.is_err()
    {
        syscall::thread_exit();
    }
    service_loop(device.endpoints.service, irq, ipc_buf);
}
