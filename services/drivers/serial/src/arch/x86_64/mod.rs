// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/arch/x86_64/mod.rs

//! x86-64 serial I/O via an I/O-port 16550 UART.
//!
//! The driver binds the `IoPort` cap devmgr delivered (the range the UART's
//! device record names: `0x3F8`, eight ports, for COM1 on QEMU) to its
//! thread, then writes the transmit register and drains the receive
//! register after polling the line status register. The UART was programmed by
//! an earlier boot stage and that state persists; the one piece that must be
//! re-enabled here is the receive-data interrupt (every boot stage left
//! `IER = 0`), so RX raises the IRQ the driver routes to its client.

use core::sync::atomic::{AtomicU16, Ordering};

use driver_binding::resources::Resource;

/// Interrupt Enable Register offset; bit 0 (ERBFI) enables the
/// received-data-available interrupt.
const UART_IER: u16 = 1;
/// Line Status Register offset; bit 0 (DR) signals a byte is ready to read.
const UART_LSR: u16 = 5;
/// Ports a 16550's register file spans.
const UART_PORTS: u64 = 8;

/// The UART's first port, set once by [`serial_init`]; 0 until then.
static UART_PORT: AtomicU16 = AtomicU16::new(0);

/// Bind the UART's `IoPort` range, `registers`, to `self_thread` so
/// `out`/`in` against it do not fault, then enable the receive-data
/// interrupt when `enable_rx_irq` is set. `self_aspace` is unused on x86-64.
/// Returns `false` if `registers` is not an `IoPort` range of at least the
/// eight ports a 16550 spans, or the bind fails.
///
/// # Safety
/// None on x86-64: the UART is reached through I/O ports and nothing is
/// mapped. The function is `unsafe` for the arch-dispatch surface, whose
/// riscv64 implementation maps the cap it is handed.
pub unsafe fn serial_init(
    self_thread: u64,
    _self_aspace: u64,
    registers: &Resource,
    enable_rx_irq: bool,
) -> bool
{
    let Resource::IoPort { cap, base, count } = *registers
    else
    {
        return false;
    };
    let Ok(port) = u16::try_from(base)
    else
    {
        return false;
    };
    if port == 0 || count < UART_PORTS || syscall::ioport_bind(self_thread, cap).is_err()
    {
        return false;
    }
    if enable_rx_irq
    {
        // Enable Received Data Available interrupt (ERBFI). Earlier boot stages
        // left IER cleared; without this the 16550 never asserts its IRQ line.
        // Skipped when the driver holds no IRQ cap (RX then relies on polling).
        // SAFETY: the UART's eight ports are bound to this thread by the
        // ioport_bind above.
        unsafe { outb(register(port, UART_IER), 0x01) };
    }
    UART_PORT.store(port, Ordering::Release);
    true
}

/// Read one byte from the UART if the receive register holds data, else
/// `None`. No-ops to `None` if [`serial_init`] never bound the UART.
pub fn serial_read_byte() -> Option<u8>
{
    let port = UART_PORT.load(Ordering::Acquire);
    if port == 0
    {
        return None;
    }
    // SAFETY: `port` is the UART's range bound by `serial_init`; reading the
    // LSR is side-effect-free.
    if unsafe { inb(register(port, UART_LSR)) } & 0x01 == 0
    {
        return None;
    }
    // SAFETY: the same range; reading the RBR returns the next received byte
    // and clears the data-ready bit.
    Some(unsafe { inb(port) })
}

/// Write one byte to the UART, spinning until the transmit holding register
/// is empty (LSR bit `0x20`). No-ops if [`serial_init`] never bound the
/// UART.
pub fn serial_write_byte(byte: u8)
{
    let port = UART_PORT.load(Ordering::Acquire);
    if port == 0
    {
        return;
    }
    // SAFETY: `port` is the UART's range bound by `serial_init`; reading the
    // LSR is side-effect-free.
    while unsafe { inb(register(port, UART_LSR)) } & 0x20 == 0
    {}
    // SAFETY: writing one byte to the UART's transmit register.
    unsafe { outb(port, byte) };
}

/// The port of the UART register at `offset` from the UART's first port,
/// `port`. The `IoPort` range [`serial_init`] bound holds the eight ports
/// from `port` within the 16-bit port space, so the sum never saturates.
fn register(port: u16, offset: u16) -> u16
{
    port.saturating_add(offset)
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port is bound to this thread.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val,
            options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: caller guarantees port is bound to this thread.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val,
            options(nomem, nostack, preserves_flags));
    }
    val
}
