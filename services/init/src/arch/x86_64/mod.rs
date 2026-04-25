// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/arch/x86_64.rs

//! x86-64 serial output via COM1 and architecture constants.

use init_protocol::InitInfo;

/// ELF machine type for x86-64.
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_X86_64;

const COM1: u16 = 0x3F8;

/// Initialise COM1 serial output at 115200 8N1.
pub fn serial_init(info: &InitInfo, thread_cap: u32)
{
    let Some(slot) = crate::find_cap_by_type(info, init_protocol::CapType::IoPortRange)
    else
    {
        return;
    };
    if syscall::ioport_bind(thread_cap, slot).is_err()
    {
        return;
    }
    // SAFETY: single-threaded init; COM1 hardware programming sequence.
    // Ports are bound to this thread via ioport_bind above.
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // DLAB = 1
        outb(COM1, 0x01); // divisor low = 1 → 115200 baud
        outb(COM1 + 1, 0x00); // divisor high = 0
        outb(COM1 + 3, 0x03); // 8N1, DLAB = 0
        outb(COM1 + 2, 0xC7); // FIFO enable
        outb(COM1 + 4, 0x0B); // DTR + RTS + OUT2
    }
}

/// Write one byte to COM1, spinning until the transmit register is ready.
pub fn serial_write_byte(byte: u8)
{
    // SAFETY: reading LSR is a side-effect-free I/O port read on COM1.
    while unsafe { inb(COM1 + 5) } & 0x20 == 0
    {}
    // SAFETY: writing one byte to the COM1 data register.
    unsafe { outb(COM1, byte) };
}

/// # Safety
///
/// `port` must be a valid I/O port bound to the calling thread.
#[inline]
unsafe fn outb(port: u16, val: u8)
{
    // SAFETY: caller guarantees port is a valid I/O port bound to this thread.
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
    // SAFETY: caller guarantees port is a valid I/O port bound to this thread.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val,
            options(nomem, nostack, preserves_flags));
    }
    val
}
