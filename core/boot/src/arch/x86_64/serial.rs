// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/arch/x86_64/serial.rs

//! COM1 serial backend for x86-64 (UART 16550, I/O port 0x3F8, 115200 8N1).

/// COM1 base I/O port.
const COM1: u16 = 0x3F8;

/// Initialize COM1 at 115200 baud, 8-N-1.
///
/// Sequence: disable interrupts → set DLAB → write divisor 1 (115200) →
/// clear DLAB, set 8N1 → enable FIFO → enable modem control.
///
/// # Safety
/// Caller must ensure this is called at most once before any `serial_write_byte`
/// call, and that I/O port access is permitted in the current privilege level.
pub unsafe fn serial_init()
{
    // SAFETY: caller guarantees ring 0 and at-most-once serial_init invocation.
    unsafe {
        outb(COM1 + 1, 0x00); // disable all interrupts
        outb(COM1 + 3, 0x80); // DLAB = 1 (access divisor latch)
        outb(COM1, 0x01); // divisor low  byte = 1 → 115200 baud
        outb(COM1 + 1, 0x00); // divisor high byte = 0
        outb(COM1 + 3, 0x03); // DLAB = 0, 8 bits, no parity, 1 stop (8N1)
        outb(COM1 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2 (enable IRQs on modem)
    }
}

/// Write a single byte to COM1, spinning until the transmit buffer is empty.
///
/// # Safety
/// `serial_init` must have been called before this function.
pub unsafe fn serial_write_byte(byte: u8)
{
    // Spin on LSR bit 5 (THRE — Transmit Holding Register Empty).
    // SAFETY: I/O port read; serial_init has prepared COM1.
    while unsafe { inb(COM1 + 5) } & 0x20 == 0
    {}
    // SAFETY: THRE is set; writing to the data register is safe.
    unsafe {
        outb(COM1, byte);
    }
}

/// Write one byte to an I/O port.
///
/// # Safety
/// Caller must ensure the port is valid and I/O access is permitted.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port validity and access rights.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read one byte from an I/O port.
///
/// # Safety
/// Caller must ensure the port is valid and I/O access is permitted.
#[inline]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: caller guarantees port validity and access rights.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}
