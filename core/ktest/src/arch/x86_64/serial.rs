// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/serial.rs

//! x86-64 serial UART for ktest: COM1 (I/O port 0x3F8) through an `IoPort` cap
//! and `ioport_bind`. `crate::serial` owns the ready flag and the line framing.

use init_protocol::InitInfo;

/// COM1 base I/O port.
const COM1: u16 = 0x3F8;

/// COM1 register width — 8 ports starting at [`COM1`].
const COM1_PORTS: u16 = 8;

/// Initialise COM1 serial output; returns whether the UART is ready.
///
/// Carves a narrow `IoPort` cap covering exactly COM1's 8 ports from the root
/// cap (via [`super::ioport::bind_port_range`]) and binds it to the thread
/// `thread_cap` names, then programs the UART to 115200 8N1. `InitInfo` is
/// consumed centrally by [`super::ioport::init`]; serial only needs the narrow
/// COM1 bind, so `_info` and `_aspace_cap` are unused here.
///
/// # Safety
/// Must be called once, from the main thread, after `InitInfo` is mapped and
/// [`super::init_io_ports`] has run.
pub unsafe fn init(_info: &InitInfo, _aspace_cap: u32, thread_cap: u32) -> bool
{
    if !super::ioport::bind_port_range(thread_cap, COM1, COM1_PORTS)
    {
        return false; // no IoPort cap, or carve/bind failed
    }

    // SAFETY: bind_port_range succeeded; I/O port access for [COM1,
    // COM1+COM1_PORTS) is permitted on this thread.
    unsafe { serial_hw_init() };
    true
}

/// Program COM1 to 115200 baud, 8N1.
///
/// # Safety
/// I/O port access to COM1 must be permitted (via `ioport_bind`).
unsafe fn serial_hw_init()
{
    // SAFETY: COM1 port range bound to this thread.
    unsafe {
        outb(COM1 + 1, 0x00); // disable all interrupts
        outb(COM1 + 3, 0x80); // DLAB = 1
        outb(COM1, 0x01); // divisor low  = 1 → 115200 baud
        outb(COM1 + 1, 0x00); // divisor high = 0
        outb(COM1 + 3, 0x03); // DLAB = 0, 8N1
        outb(COM1 + 2, 0xC7); // enable FIFO, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2
    }
}

/// Write a single byte, spinning until the transmit buffer is empty.
///
/// Called only once [`init`] has returned `true`.
pub fn write_byte(byte: u8)
{
    // Spin on LSR bit 5 (THRE — Transmit Holding Register Empty).
    // SAFETY: serial_hw_init completed; I/O port access permitted.
    while unsafe { inb(COM1 + 5) } & 0x20 == 0
    {}
    // SAFETY: THRE set; writing to data register transmits the byte.
    unsafe { outb(COM1, byte) };
}

/// Write `val` to I/O port `port` (`out dx, al`; reads dx and al, clobbers
/// nothing, touches no memory or flag).
///
/// # Safety
/// The calling thread must hold an `ioport_bind` grant covering `port`.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port access is permitted.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a byte from I/O port `port` (`in al, dx`; reads dx, writes al only,
/// touches no memory or flag).
///
/// # Safety
/// The calling thread must hold an `ioport_bind` grant covering `port`.
#[inline]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: caller guarantees port access is permitted.
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
