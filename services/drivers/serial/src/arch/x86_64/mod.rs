// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/serial/src/arch/x86_64/mod.rs

//! x86-64 serial output via COM1.
//!
//! The driver binds the `IoPortRange` cap devmgr delegated (COM1, `0x3F8`)
//! to its thread, then writes the transmit register after polling the line
//! status register. The UART was programmed by an earlier boot stage and
//! that state persists, so no re-initialization is required here.

const COM1: u16 = 0x3F8;

/// Bind the COM1 `IoPortRange` cap to `self_thread` so `out`/`in` against
/// the UART do not fault. `self_aspace` is unused on x86-64. Returns
/// `false` if the bind fails.
pub fn serial_init(self_thread: u32, _self_aspace: u32, ioport_cap: u32) -> bool
{
    syscall::ioport_bind(self_thread, ioport_cap).is_ok()
}

/// Write one byte to COM1, spinning until the transmit holding register is
/// empty (LSR bit `0x20`).
pub fn serial_write_byte(byte: u8)
{
    // SAFETY: COM1 is within the IoPortRange bound by `serial_init`; reading
    // the LSR is side-effect-free.
    while unsafe { inb(COM1 + 5) } & 0x20 == 0
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
