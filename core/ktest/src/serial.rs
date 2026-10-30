// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/serial.rs

//! Direct serial output for ktest.
//!
//! Drives the serial port from userspace using capabilities received via the
//! init protocol; the kernel offers no debug-print syscall. The UART itself is
//! reached through `crate::arch::serial`:
//!
//! - **x86-64**: COM1 (I/O port 0x3F8) via `IoPort` cap + `ioport_bind`.
//! - **RISC-V**: MMIO 16550 (`0x1000_0000`) via `Mmio` cap + `mmio_map`.
//!
//! Call [`init`] once during early startup (after `InitInfo` is available, before
//! any logging). After that, [`write_str`] and [`write_byte`] are available.

use init_protocol::InitInfo;

use crate::arch::serial as uart;

/// Whether serial has been successfully initialised.
///
/// `write_byte` / `write_str` silently no-op when false.
// SAFETY: ktest is single-threaded on the serial output path.
static mut SERIAL_READY: bool = false;

/// Initialise the serial port using capabilities from the init protocol.
///
/// On x86-64, binds the COM1 `IoPort` cap to `thread_cap`.
/// On RISC-V, maps the UART `Mmio` cap into `aspace_cap`.
///
/// # Safety
/// Must be called once during early ktest startup, before any `write_str`
/// or `write_byte` call, and after `crate::arch::init_io_ports`.
pub unsafe fn init(info: &InitInfo, aspace_cap: u32, thread_cap: u32)
{
    // SAFETY: caller guarantees at-most-once, single-threaded, after the I/O
    // port seed.
    let ready = unsafe { uart::init(info, aspace_cap, thread_cap) };
    // SAFETY: single-threaded; the flag is written only here.
    unsafe { SERIAL_READY = ready };
}

/// Whether the UART is initialised, so its registers may be programmed
/// (`crate::arch::serial::raise_tx_interrupt` and its sibling).
pub fn is_ready() -> bool
{
    // SAFETY: single-threaded read of flag set during init.
    unsafe { SERIAL_READY }
}

/// Write a single byte to the serial port.
///
/// No-op if serial has not been initialised.
#[inline]
pub fn write_byte(byte: u8)
{
    // SAFETY: single-threaded read of flag set during init.
    if unsafe { !SERIAL_READY }
    {
        return;
    }
    uart::write_byte(byte);
}

/// Write a string to the serial port, inserting `\r` before each `\n`.
///
/// No-op if serial has not been initialised.
pub fn write_str(s: &str)
{
    // SAFETY: single-threaded read of flag set during init.
    if unsafe { !SERIAL_READY }
    {
        return;
    }
    for &b in s.as_bytes()
    {
        if b == b'\n'
        {
            uart::write_byte(b'\r');
        }
        uart::write_byte(b);
    }
}
