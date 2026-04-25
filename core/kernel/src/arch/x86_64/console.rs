// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/console.rs

//! COM1 serial backend for x86-64 (UART 16550, I/O port 0x3F8, 115200 8N1).
//!
//! COM1 is accessed via I/O ports (`in`/`out` instructions), not MMIO, so it
//! is unaffected by page table changes. [`rebase_serial`] is a no-op here and
//! [`uart_phys_base`] always returns 0.

/// COM1 base I/O port.
const COM1: u16 = 0x3F8;

/// Physical base address of the serial device.
///
/// Always 0 on x86-64 because COM1 is I/O-mapped (no physical MMIO address).
/// The top-level console module checks this to decide whether `rebase_serial`
/// is meaningful after Phase 3.
#[must_use]
pub fn uart_phys_base() -> u64
{
    0
}

/// No-op on x86-64: COM1 is accessed via I/O ports, not MMIO.
///
/// Present to satisfy the cross-architecture call site in `main.rs`.
///
/// # Safety
/// No preconditions; always safe to call.
pub unsafe fn rebase_serial(_new_base: u64) {}

/// Initialize COM1 at 115200 baud, 8-N-1.
///
/// Sequence: disable interrupts → set DLAB → write divisor 1 (115200) →
/// clear DLAB, set 8N1 → enable FIFO → enable modem control.
///
/// `_phys_base` is ignored; COM1 is always at I/O port 0x3F8 on x86.
///
/// # Safety
/// Caller must ensure this is called at most once before any `serial_write_byte`
/// call, and that I/O port access is permitted in the current privilege level.
pub unsafe fn serial_init(_phys_base: u64)
{
    // SAFETY: caller guarantees ring 0 and at-most-once initialization.
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

/// Write `val` to x86 I/O port `port`.
///
/// # Safety
/// Caller must ensure the port is valid and accessible at the current privilege
/// level (ring 0 or with appropriate IOPL/IOPB).
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: x86 I/O port instruction; caller meets the precondition.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, nomem),
        );
    }
}

/// Read a byte from x86 I/O port `port`.
///
/// # Safety
/// Same as [`outb`].
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: x86 I/O port instruction; caller meets the precondition.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, nomem),
        );
    }
    val
}
