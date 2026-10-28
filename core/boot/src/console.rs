// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/console.rs

//! Boot console: dual serial + framebuffer output.
//!
//! Provides `init_serial()`, `init_framebuffer()`, and `console_write_fmt()` /
//! `console_write_str()` used by the `bprint!`/`bprintln!` macros. Output goes
//! to both the serial port and the framebuffer (when available). All state is
//! static and unlocked; see `core/boot/docs/console.md` § Scope.

use crate::arch::current::serial::{serial_init, serial_write_byte};
use crate::framebuffer::FramebufferWriter;
use boot_protocol::FramebufferInfo;

/// Static console state; unlocked (see `core/boot/docs/console.md` § Scope).
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
/// Must be called only from the single boot thread (no concurrent access to
/// `CONSOLE`). Backends need not be initialized: output to a backend that is
/// not live is dropped (the `unsafe` qualifier is stale, #442).
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

/// `core::fmt::Write` sink over the dual serial + framebuffer console.
///
/// Zero-sized; each write forwards to `console_write_str`, which performs the
/// `\n` → `\r\n` serial translation. Backs the `bprint!` / `bprintln!` macros.
struct ConsoleWriter;

impl core::fmt::Write for ConsoleWriter
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        // SAFETY: single-threaded bootloader; output before init is dropped.
        unsafe {
            console_write_str(s);
        }
        Ok(())
    }
}

/// Render `core::fmt` arguments to both console backends.
///
/// Backs the `bprint!`/`bprintln!` macros. `core::fmt` dispatches through
/// vtables and fn-pointer tables, which are valid because the image's absolute
/// pointers are fixed up before any Rust code runs: by the UEFI PE loader on
/// x86-64, and by the `_start` self-relocation on RISC-V (see
/// `core/boot/docs/riscv-uefi-boot.md` § Relocation: static-PIE self-relocation).
/// Output before `init_serial`/`init_framebuffer` is silently dropped, so this
/// function is safe to call at any point.
pub fn console_write_fmt(args: core::fmt::Arguments)
{
    use core::fmt::Write;
    // ConsoleWriter::write_str is infallible, so the Result is always Ok.
    let _ = ConsoleWriter.write_fmt(args);
}

/// Print formatted output to the boot console.
///
/// Accepts `core::fmt` formatting syntax (`bprint!("base={:#x}", addr)`), a
/// bare string literal, or `concat!(...)`. Output is rendered through
/// `core::fmt` into the dual serial + framebuffer sink.
#[macro_export]
macro_rules! bprint {
    ($($arg:tt)*) => {
        $crate::console::console_write_fmt(::core::format_args!($($arg)*))
    };
}

/// Print formatted output followed by `\r\n` to the boot console.
///
/// Accepts `core::fmt` formatting syntax or no argument (bare newline).
#[macro_export]
macro_rules! bprintln {
    () => {{
        // SAFETY: single-threaded bootloader; output before init is dropped.
        unsafe {
            $crate::console::console_write_str("\r\n");
        }
    }};
    ($($arg:tt)*) => {{
        $crate::console::console_write_fmt(::core::format_args!($($arg)*));
        // SAFETY: single-threaded bootloader; output before init is dropped.
        unsafe {
            $crate::console::console_write_str("\r\n");
        }
    }};
}
