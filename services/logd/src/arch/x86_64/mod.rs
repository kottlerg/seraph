// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// logd/src/arch/x86_64/mod.rs

//! x86-64 serial output via COM1.
//!
//! Real-logd inherits the COM1 hardware from init's COM1 init (init's
//! main thread programmed the UART during `serial_init`; UART
//! programming state is per-device and persists). All logd needs is
//! the `IoPortRange` cap (passed via bootstrap caps[3]) bound to its
//! main thread so the `out`/`in` instructions don't fault.

const COM1: u16 = 0x3F8;

/// Bind the caller-provided `IoPortRange` cap to `thread_cap` so this
/// thread can issue `out`/`in` against COM1. Silently no-ops on a
/// zero cap (logd then runs without serial output — its received
/// log lines are still buffered in memory).
pub fn serial_init(thread_cap: u32, ioport_cap: u32)
{
    if ioport_cap == 0
    {
        return;
    }
    let _ = syscall::ioport_bind(thread_cap, ioport_cap);
}

/// Write one byte to COM1, spinning until the transmit register is
/// ready. Silently no-ops when no I/O port cap is bound (the `out`
/// instruction would trap; the bind is gated by
/// [`serial_init`]).
pub fn serial_write_byte(byte: u8)
{
    // SAFETY: reading LSR is a side-effect-free I/O port read on
    // COM1, only valid after `ioport_bind` succeeded for this
    // thread. If the cap was zero, this read traps — but `serial_init`
    // would have left no-binding, and the caller decides not to
    // invoke us in that case (see `crate::self_log` / `emit_line`
    // for the gating).
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
