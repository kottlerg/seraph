// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/console.rs

//! Boot console: dual serial + framebuffer output.
//!
//! Provides `init_serial()`, `init_framebuffer()`, and `console_write_str()`
//! used by the `bprint!`/`bprintln!` macros. Output goes to both the serial
//! port and the framebuffer (when available). All state is static; the
//! bootloader is single-threaded and never runs concurrent code.

use crate::arch::current::serial::{serial_init, serial_write_byte};
use crate::framebuffer::FramebufferWriter;
use boot_protocol::FramebufferInfo;

/// Static console state. Single-threaded bootloader: no locking required.
static mut CONSOLE: Console = Console {
    serial_ready: false,
    fb: None,
};

/// Internal console state.
struct Console
{
    serial_ready: bool,
    fb: Option<FramebufferWriter>,
}

/// Initialize the serial backend.
///
/// Must be called once, before any `bprint!` usage. Safe to call before
/// GOP/framebuffer initialization.
///
/// # Safety
/// Must be called at most once, before any concurrent or interrupt-driven
/// use of the serial port.
pub unsafe fn init_serial()
{
    // SAFETY: serial_init is called exactly once at bootloader entry.
    unsafe {
        serial_init();
    }
    // SAFETY: CONSOLE is only accessed from the single boot thread.
    unsafe {
        CONSOLE.serial_ready = true;
    }
}

/// Initialize the framebuffer backend.
///
/// Called after GOP query in Step 1. If `fb.physical_base == 0`, the
/// framebuffer backend is silently skipped.
///
/// # Safety
/// `fb` must describe a valid, accessible framebuffer. Must be called at
/// most once, from the single boot thread.
pub unsafe fn init_framebuffer(fb: &FramebufferInfo)
{
    // SAFETY: FramebufferWriter::new requires a valid framebuffer; caller ensures this.
    let writer = unsafe { FramebufferWriter::new(fb) };
    // SAFETY: CONSOLE is only accessed from the single boot thread.
    unsafe {
        CONSOLE.fb = writer;
    }
}

/// Write a string to both serial and framebuffer backends.
///
/// This is the low-level sink used by `bprint!`/`bprintln!`. Inserts `\r`
/// before each `\n` on the serial path so terminals show correct line endings.
///
/// # Safety
/// Backends must have been initialized before calling this function.
pub unsafe fn console_write_str(s: &str)
{
    // SAFETY: CONSOLE is only accessed from the single boot thread.
    // SAFETY: raw pointer avoids the static_mut_refs lint; single-threaded bootloader.
    let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };

    for byte in s.bytes()
    {
        if console.serial_ready
        {
            if byte == b'\n'
            {
                // SAFETY: serial_init was called during init_serial.
                unsafe {
                    serial_write_byte(b'\r');
                }
            }
            // SAFETY: serial_init was called during init_serial.
            unsafe {
                serial_write_byte(byte);
            }
        }

        if let Some(ref mut fb) = console.fb
        {
            // SAFETY: fb was constructed from a valid FramebufferInfo.
            unsafe {
                fb.write_byte(byte);
            }
        }
    }
}

/// Write a u64 as a 0x-prefixed 16-digit lowercase hex string.
///
/// All 16 hex digits are always emitted (zero-padded). No vtable dispatch;
/// bytes are written directly through `console_write_str`.
///
/// # Safety
/// Serial backend must be initialized before calling.
pub unsafe fn console_write_hex64(n: u64)
{
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 18]; // "0x" + 16 hex digits
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16usize
    {
        buf[2 + i] = HEX[((n >> (60 - i * 4)) & 0xF) as usize];
    }
    // SAFETY: buf contains only ASCII hex characters; valid UTF-8.
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    // SAFETY: caller ensures serial initialized.
    unsafe {
        console_write_str(s);
    }
}

/// Write a u32 as a decimal string with no padding or prefix.
///
/// Writes "0" for zero. No vtable dispatch.
///
/// # Safety
/// Serial backend must be initialized before calling.
pub unsafe fn console_write_dec32(n: u32)
{
    if n == 0
    {
        // SAFETY: caller ensures serial initialized.
        unsafe {
            console_write_str("0");
        }
        return;
    }
    let mut buf = [0u8; 10]; // max 10 decimal digits for u32
    let mut pos = 10usize;
    let mut v = n;
    while v > 0
    {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // SAFETY: buf[pos..] contains only ASCII digit characters; valid UTF-8.
    let s = unsafe { core::str::from_utf8_unchecked(&buf[pos..]) };
    // SAFETY: caller ensures serial initialized.
    unsafe {
        console_write_str(s);
    }
}

/// Print a literal string to the boot console.
///
/// Accepts a single `&str` expression (including `concat!(...)` for compile-time
/// string concatenation). Never uses `core::fmt::Write` or creates trait objects,
/// so no vtable entries are emitted — required for RISC-V UEFI where the PE
/// `.reloc` section is empty and absolute addresses are never patched.
///
/// To add: extend with another `bprint!("...")` call immediately after.
#[macro_export]
macro_rules! bprint {
    ($s:expr) => {{
        let s: &str = $s;
        // SAFETY: console is initialized before any macro usage.
        unsafe {
            $crate::console::console_write_str(s);
        }
    }};
}

/// Print a literal string followed by `\r\n` to the boot console.
///
/// Accepts a single `&str` expression or no argument (bare newline). Never
/// uses `core::fmt::Write`; see `bprint!` for the rationale.
#[macro_export]
macro_rules! bprintln {
    ($s:expr) => {{
        let s: &str = $s;
        // SAFETY: console is initialized before any macro usage.
        unsafe {
            $crate::console::console_write_str(s);
            $crate::console::console_write_str("\r\n");
        }
    }};
    () => {{
        // SAFETY: console is initialized before any macro usage.
        unsafe {
            $crate::console::console_write_str("\r\n");
        }
    }};
}
