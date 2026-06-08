// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/serial/src/arch/x86_64/mod.rs

//! x86-64 serial I/O via COM1.
//!
//! The driver binds the `IoPort` cap devmgr delegated (COM1, `0x3F8`)
//! to its thread, then writes the transmit register and drains the receive
//! register after polling the line status register. The UART was programmed by
//! an earlier boot stage and that state persists; the one piece that must be
//! re-enabled here is the receive-data interrupt (every boot stage left
//! `IER = 0`), so RX raises the IRQ the driver routes to its client.

const COM1: u16 = 0x3F8;
/// Interrupt Enable Register offset; bit 0 (ERBFI) enables the
/// received-data-available interrupt.
const UART_IER: u16 = 1;
/// Line Status Register offset; bit 0 (DR) signals a byte is ready to read.
const UART_LSR: u16 = 5;

/// Bind the COM1 `IoPort` cap to `self_thread` so `out`/`in` against the UART
/// do not fault, then enable the receive-data interrupt. `self_aspace` is
/// unused on x86-64. Returns `false` if the bind fails.
pub fn serial_init(self_thread: u32, _self_aspace: u32, ioport_cap: u32) -> bool
{
    if syscall::ioport_bind(self_thread, ioport_cap).is_err()
    {
        return false;
    }
    // Enable Received Data Available interrupt (ERBFI). Earlier boot stages
    // left IER cleared; without this the 16550 never asserts its IRQ line.
    // SAFETY: COM1 is bound to this thread by the ioport_bind above.
    unsafe { outb(COM1 + UART_IER, 0x01) };
    true
}

/// Read one byte from COM1 if the receive register holds data, else `None`.
pub fn serial_read_byte() -> Option<u8>
{
    // SAFETY: COM1 is within the IoPort bound by `serial_init`; reading the
    // LSR is side-effect-free.
    if unsafe { inb(COM1 + UART_LSR) } & 0x01 == 0
    {
        return None;
    }
    // SAFETY: COM1 is within the IoPort bound by `serial_init`; reading the RBR
    // returns the next received byte and clears the data-ready bit.
    Some(unsafe { inb(COM1) })
}

/// Write one byte to COM1, spinning until the transmit holding register is
/// empty (LSR bit `0x20`).
pub fn serial_write_byte(byte: u8)
{
    // SAFETY: COM1 is within the IoPort bound by `serial_init`; reading
    // the LSR is side-effect-free.
    while unsafe { inb(COM1 + UART_LSR) } & 0x20 == 0
    {}
    // SAFETY: writing one byte to the COM1 transmit register.
    unsafe { outb(COM1, byte) };
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
