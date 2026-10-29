// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/console.rs

//! Boot console: dual serial + framebuffer output.
//!
//! Provides `init_serial()`, `init_framebuffer()`, and `console_write_fmt()` /
//! `console_write_str()` used by the `bprint!`/`bprintln!` macros. Output goes
//! to both the serial port and the framebuffer (when available). The
//! framebuffer state sits behind a busy-flag cell that turns away panic
//! re-entry; see `core/boot/docs/console.md` § Scope.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::current::serial::{serial_init, serial_write_byte};
use crate::framebuffer::FramebufferWriter;
use boot_protocol::FramebufferInfo;

/// Framebuffer console state, reached only through [`ConsoleCell::try_with`].
static CONSOLE: ConsoleCell = ConsoleCell {
    busy: AtomicBool::new(false),
    state: UnsafeCell::new(Console { fb: None }),
};

/// Set by [`init_serial`] once the UART is programmed. Kept outside
/// [`CONSOLE`] so a re-entered write can reach serial without touching it.
static SERIAL_READY: AtomicBool = AtomicBool::new(false);

/// Internal console state.
struct Console
{
    fb: Option<FramebufferWriter>,
}

/// The console state together with the flag that marks it in use, so the
/// state is reachable only while the flag is held.
struct ConsoleCell
{
    busy: AtomicBool,
    state: UnsafeCell<Console>,
}

// SAFETY: the bootloader runs on a single boot thread with no console-touching
// interrupt handlers. The one overlapping access is the panic handler
// re-entering a console write on that same thread, which `try_with`'s busy
// flag turns away before it forms a reference to `state`.
unsafe impl Sync for ConsoleCell {}

impl ConsoleCell
{
    /// Run `f` on the console state, or return `None` without running it when
    /// a call is already in progress (a panic raised inside `f` whose handler
    /// writes to the console). A panic inside `f` leaves the flag held, so
    /// later output stays serial-only; the bootloader halts on panic.
    fn try_with<R>(&self, f: impl FnOnce(&mut Console) -> R) -> Option<R>
    {
        if self.busy.swap(true, Ordering::Acquire)
        {
            return None;
        }
        // SAFETY: `busy` was clear and this call set it, so no other
        // reference into `state` is live: every access goes through
        // `try_with`, and an overlapping call returned above.
        let result = f(unsafe { &mut *self.state.get() });
        self.busy.store(false, Ordering::Release);
        Some(result)
    }
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
    SERIAL_READY.store(true, Ordering::Release);
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
    // Called from step 1, never inside a console write, so the cell is free.
    let installed = CONSOLE.try_with(|console| console.fb = writer);
    debug_assert!(
        installed.is_some(),
        "init_framebuffer ran inside a console write"
    );
}

/// Write a string to both serial and framebuffer backends.
///
/// This is the low-level sink used by `bprint!`/`bprintln!`. Inserts `\r`
/// before each `\n` on the serial path so terminals show correct line endings.
///
/// Safe to call at any point: output to a backend that is not yet
/// initialized is dropped. A call made while another is in progress (the
/// panic handler reporting a panic raised inside a write) goes to serial
/// only, since the framebuffer state is still in use by the outer call.
pub fn console_write_str(s: &str)
{
    write_serial(s);
    // A re-entered call finds the cell busy and skips the framebuffer.
    let _ = CONSOLE.try_with(|console| {
        if let Some(fb) = console.fb.as_mut()
        {
            for byte in s.bytes()
            {
                // SAFETY: fb was constructed from a valid FramebufferInfo.
                unsafe {
                    fb.write_byte(byte);
                }
            }
        }
    });
}

/// Write `s` to the serial backend, if initialized, inserting `\r` before
/// each `\n`. Touches no shared console state but [`SERIAL_READY`].
fn write_serial(s: &str)
{
    if !SERIAL_READY.load(Ordering::Acquire)
    {
        return;
    }
    for byte in s.bytes()
    {
        if byte == b'\n'
        {
            // SAFETY: SERIAL_READY is set only after init_serial ran serial_init.
            unsafe {
                serial_write_byte(b'\r');
            }
        }
        // SAFETY: SERIAL_READY is set only after init_serial ran serial_init.
        unsafe {
            serial_write_byte(byte);
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
        console_write_str(s);
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
        $crate::console::console_write_str("\r\n");
    }};
    ($($arg:tt)*) => {{
        $crate::console::console_write_fmt(::core::format_args!($($arg)*));
        $crate::console::console_write_str("\r\n");
    }};
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn cell() -> ConsoleCell
    {
        ConsoleCell {
            busy: AtomicBool::new(false),
            state: UnsafeCell::new(Console { fb: None }),
        }
    }

    /// A call made while another holds the cell (panic re-entry) is turned
    /// away without running, and the cell is free again once the outer call
    /// returns.
    #[test]
    fn nested_call_is_turned_away_and_the_cell_is_released_after()
    {
        let console = cell();
        let mut inner_ran = false;
        let outer = console.try_with(|_| {
            let inner = console.try_with(|_| inner_ran = true);
            assert!(inner.is_none());
        });
        assert!(outer.is_some());
        assert!(!inner_ran);
        assert_eq!(console.try_with(|_| 7), Some(7));
    }
}
