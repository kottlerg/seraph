// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/serial_labels.rs

//! IPC labels of the serial protocol: byte write, byte read, and RX-notify
//! registration on a byte transport.
//!
//! Two drivers serve it. The serial (UART) driver (`services/drivers/serial`)
//! owns the platform UART hardware authority (an `IoPort` for COM1 on x86-64,
//! an `Mmio` for the QEMU `virt` NS16550 at its platform-static address on
//! RISC-V) and is the sole driver-mediated path for userspace console serial
//! bytes in both directions; devmgr hands clients a cap on it badged with
//! [`serial_labels::WRITE_AUTHORITY`](crate::serial_labels::WRITE_AUTHORITY) | [`serial_labels::READ_AUTHORITY`](crate::serial_labels::READ_AUTHORITY) via
//! [`devmgr_labels::QUERY_DEVICE`](crate::devmgr_labels::QUERY_DEVICE) on the `serial` class. The virtio-console
//! driver (`services/drivers/virtio/console`) serves the debug port, handed
//! out the same way on the `debug-port` class. Line-control and flow-control
//! surfaces are planned but unimplemented (see the driver `README.md`); they
//! are not on the wire.

/// Write bytes to the transport (the UART, or the debug port).
///
/// Wire format mirrors [`stream_labels::STREAM_BYTES`]: the payload byte
/// length rides bits 16-31 of the label, the bytes are packed via
/// `.bytes(0, …)` into the data words, and the receiver reads
/// `byte_len.div_ceil(8)` words. The caller's badge must carry
/// [`WRITE_AUTHORITY`]. Reply: empty body, status code in the reply label.
///
/// # Label encoding
/// - Bits 0-15: label ID (`SERIAL_WRITE_BYTES`)
/// - Bits 16-31: byte length of the payload in this call (0..=512).
///
/// 512 is the whole data area (`MSG_DATA_WORDS_MAX * 8`); callers split a
/// longer write over more calls.
pub const SERIAL_WRITE_BYTES: u64 = 1;

/// Read the bytes currently received: the UART receive FIFO, or the debug
/// port's received bytes.
///
/// Non-blocking: the driver drains whatever is ready and replies at once,
/// possibly with zero bytes. Callers that want to sleep until input arrives
/// register a notification via [`SERIAL_REGISTER_RX_NOTIFY`] and wait on it
/// between reads. Request: empty body; the caller's badge must carry
/// [`READ_AUTHORITY`].
///
/// Reply ([`super::serial_errors::SUCCESS`]): the byte count rides bits
/// 16-31 of the reply label (0..=512), the bytes are packed via
/// `.bytes(0, …)` into the data words (the same wire shape as
/// [`SERIAL_WRITE_BYTES`], in the reply direction).
pub const SERIAL_READ_BYTES: u64 = 2;

/// Register a notification kicked when receive data becomes ready.
///
/// Request: the client's notification cap in cap slot 0; the caller's badge
/// must carry [`READ_AUTHORITY`]. The serial (UART) driver binds the UART
/// interrupt to that notification and arms it; the IRQ is masked on each
/// fire and re-armed by the next [`SERIAL_READ_BYTES`]. The virtio-console
/// driver instead signals the notification from its interrupt-service
/// thread on each interrupt of its device. Either way a client loops:
/// drain with `SERIAL_READ_BYTES`, then wait on its notification with a
/// bounded timeout, so a byte racing the re-arm (the serial driver
/// registers the x86 UART line edge-triggered, mode 0) or a lost
/// interrupt is recovered by the timeout-driven re-drain. Reply: empty
/// body, status in the reply label
/// ([`super::serial_errors::REGISTER_FAILED`] if the driver holds no IRQ
/// cap or the binding fails).
pub const SERIAL_REGISTER_RX_NOTIFY: u64 = 3;

/// Authority bit in the serial-service-endpoint badge's high u64 bit.
/// Set on caps devmgr mints in response to [`devmgr_labels::QUERY_DEVICE`]
/// on the `serial` and `debug-port` classes; gates [`SERIAL_WRITE_BYTES`].
/// A verb ("may write"), not an identity.
pub const WRITE_AUTHORITY: u64 = 1u64 << 63;

/// Authority bit gating [`SERIAL_READ_BYTES`] and
/// [`SERIAL_REGISTER_RX_NOTIFY`]. Set alongside [`WRITE_AUTHORITY`] on caps
/// devmgr mints for [`devmgr_labels::QUERY_DEVICE`] on the `serial` and
/// `debug-port` classes. A verb ("may
/// read"), not an identity.
pub const READ_AUTHORITY: u64 = 1u64 << 62;
