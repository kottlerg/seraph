// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/console.rs

//! Kernel early console: dual serial + framebuffer output.
//!
//! Provides `init()` and the `kprint!`/`kprintln!` macros. Output goes to both
//! the serial port and the framebuffer (when available). All state is static;
//! the kernel is single-threaded during early boot and never runs concurrent
//! code before SMP is initialized.
//!
//! Unlike the bootloader console, the kernel is a native ELF, so `core::fmt`
//! trait objects and vtable dispatch work on all architectures. The macros
//! accept full format arguments.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::current::console::{serial_init, serial_write_byte};
use crate::framebuffer::FramebufferWriter;
use crate::mm::paging::phys_to_virt;
use boot_protocol::BootInfo;

/// Spinlock protecting `CONSOLE`. Acquired by every `console_write_fmt` call
/// so concurrent writes from multiple CPUs (SMP) do not race on the
/// framebuffer cursor position. Uses a plain `AtomicBool` (test-and-set) rather
/// than the ticket `Spinlock` to avoid disabling interrupts — callers may already
/// be in an interrupt handler, and timer ISRs do not call `kprintln!`.
static CONSOLE_LOCK: AtomicBool = AtomicBool::new(false);

/// Static console state.
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

impl core::fmt::Write for Console
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        for byte in s.bytes()
        {
            if self.serial_ready
            {
                if byte == b'\n'
                {
                    // Insert CR before LF for serial terminals.
                    // SAFETY: serial_init was called during console::init.
                    unsafe {
                        serial_write_byte(b'\r');
                    }
                }
                // SAFETY: serial_init was called during console::init.
                unsafe {
                    serial_write_byte(byte);
                }
            }

            if let Some(ref mut fb) = self.fb
            {
                // SAFETY: fb was constructed from a valid FramebufferInfo.
                unsafe {
                    fb.write_byte(byte);
                }
            }
        }
        Ok(())
    }
}

/// Initialize the kernel early console.
///
/// Initializes the serial backend and, if a framebuffer is present in
/// `boot_info`, the framebuffer backend. Must be called once during Phase 1
/// before any `kprint!` usage.
///
/// # Safety
/// Must be called at most once, from the single kernel boot thread, with a
/// valid `boot_info` pointer (Phase 0 validation must have passed).
pub unsafe fn init(boot_info: &BootInfo)
{
    // Resolve the UART physical base for this architecture. RISC-V reads it
    // from `BootInfo.kernel_mmio.uart_base` (with a default fallback);
    // x86-64 ignores the value because COM1 is I/O-mapped.
    let uart_phys = crate::arch::current::platform::uart_base_for_boot_info(&boot_info.kernel_mmio);
    // SAFETY: serial_init is called exactly once at kernel entry.
    unsafe {
        serial_init(uart_phys);
    }
    // SAFETY: CONSOLE is only accessed from the single boot thread.
    unsafe {
        (*core::ptr::addr_of_mut!(CONSOLE)).serial_ready = true;
    }

    // Initialize framebuffer if present.
    // SAFETY: boot_info.framebuffer describes a valid, accessible region (or
    // physical_base == 0, which FramebufferWriter::new handles gracefully).
    let writer = unsafe { FramebufferWriter::new(&boot_info.framebuffer) };
    // SAFETY: CONSOLE is only accessed from the single boot thread.
    unsafe {
        (*core::ptr::addr_of_mut!(CONSOLE)).fb = writer;
    }
}

/// Repoint the framebuffer to its direct-map virtual address.
///
/// Called after Phase 3 activates the kernel's page tables. Converts
/// `fb_phys` to `DIRECT_MAP_BASE + fb_phys` and calls `FramebufferWriter::rebase`
/// so subsequent output writes to the correct virtual address.
///
/// Does nothing if no framebuffer is present (`fb_phys == 0`).
///
/// # Safety
/// Must be called only after `init_kernel_page_tables` has returned
/// successfully and the direct physical map is active.
pub unsafe fn rebase_framebuffer(fb_phys: u64)
{
    if fb_phys == 0
    {
        return;
    }
    // SAFETY: CONSOLE is only accessed from the single boot thread.
    let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
    if let Some(ref mut fb) = console.fb
    {
        let new_base = phys_to_virt(fb_phys) as *mut u8;
        // SAFETY: new_base is the direct-map VA of the framebuffer physical memory,
        // which is now mapped R/W by the kernel's page tables.
        unsafe {
            fb.rebase(new_base);
        }
    }
}

/// Write a formatted string to the kernel console.
///
/// Serialised via `CONSOLE_LOCK` so concurrent calls from multiple CPUs
/// (after SMP bringup) do not race on the framebuffer cursor state.
/// Each call acquires the lock, writes, then releases.
///
/// # Safety
/// `console::init` must have been called before this function.
pub unsafe fn console_write_fmt(args: core::fmt::Arguments)
{
    use core::fmt::Write;

    // Acquire spin-lock (test-and-set, non-disabling).
    while CONSOLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    // SAFETY: we hold CONSOLE_LOCK; no other CPU is in this block.
    let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
    let _ = console.write_fmt(args);

    CONSOLE_LOCK.store(false, Ordering::Release);
}

/// Write a formatted string to the serial port only.
///
/// Acquires `CONSOLE_LOCK` normally (spin-waits) but writes only to serial,
/// skipping the framebuffer. Used for userspace fault diagnostics that should
/// not overwrite whatever is on the display.
///
/// # Safety
/// `console::init` must have been called before this function.
#[cfg(not(test))]
pub unsafe fn serial_write_fmt(args: core::fmt::Arguments)
{
    use core::fmt::Write;

    struct SerialWriter;
    impl core::fmt::Write for SerialWriter
    {
        fn write_str(&mut self, s: &str) -> core::fmt::Result
        {
            // SAFETY: serial was initialised by console::init.
            unsafe {
                for byte in s.bytes()
                {
                    if byte == b'\n'
                    {
                        serial_write_byte(b'\r');
                    }
                    serial_write_byte(byte);
                }
            }
            Ok(())
        }
    }

    while CONSOLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    let _ = SerialWriter.write_fmt(args);

    CONSOLE_LOCK.store(false, Ordering::Release);
}

/// No-op stub for test builds.
#[cfg(test)]
pub unsafe fn serial_write_fmt(_args: core::fmt::Arguments) {}

/// Write a formatted string to the serial port only, for use inside panic handlers.
///
/// Unlike `console_write_fmt`, this function:
/// - Force-claims `CONSOLE_LOCK` with a store (no spin-wait, avoids deadlock if
///   this CPU already holds the lock or if the lock is stuck on a halted CPU).
/// - Writes only to the serial port; skips the framebuffer to avoid touching
///   any mutable cursor state that might be in an inconsistent state mid-panic.
/// - Does not release the lock (the caller is about to halt anyway).
///
/// # Safety
/// `console::init` must have been called before this function. May be called
/// even while `CONSOLE_LOCK` is held by the same CPU (re-entrant panic).
#[cfg(not(test))]
pub unsafe fn panic_write_fmt(args: core::fmt::Arguments)
{
    use core::fmt::Write;

    /// A `fmt::Write` sink that writes bytes only to the serial port.
    struct SerialWriter;
    impl core::fmt::Write for SerialWriter
    {
        fn write_str(&mut self, s: &str) -> core::fmt::Result
        {
            // SAFETY: serial was initialised by console::init before any kprint! use.
            unsafe {
                for byte in s.bytes()
                {
                    if byte == b'\n'
                    {
                        serial_write_byte(b'\r');
                    }
                    serial_write_byte(byte);
                }
            }
            Ok(())
        }
    }

    // Force-claim: store true unconditionally. Stops other CPUs from writing
    // (best-effort) without risking a spin-wait deadlock on re-entrant panics.
    CONSOLE_LOCK.store(true, Ordering::Relaxed);

    let _ = SerialWriter.write_fmt(args);
    // Lock intentionally not released — caller halts immediately after.
}

/// No-op stub for test builds.
#[cfg(test)]
pub unsafe fn panic_write_fmt(_args: core::fmt::Arguments) {}

/// Write a `[S.NNNNNN] ` timestamp prefix to the kernel console before each line.
///
/// Format: `[S.NNNNNN] ` where S is whole seconds (variable width) and NNNNNN
/// is zero-padded microseconds (6 digits). Source: TSC on x86-64,
/// the `time` CSR on RISC-V — both are interrupt-independent and give
/// sub-microsecond raw resolution.
///
/// Before the timer is calibrated (pre-Phase 5), prints `[--------] ` — 8
/// dashes inside brackets to match the width of `[0.000000]`.
///
/// Called by `kprintln!` at the start of every line. The bare `kprint!` macro
/// does not prepend a timestamp (it is for partial-line writes only).
///
/// No effect in test builds (no hardware timer available).
///
/// # Modification notes
/// - To add nanosecond resolution: change the `elapsed_us` call to an
///   `elapsed_ns` variant and update the format field to `{:09}`.
/// - To change the width of the fallback: match the inner char count of the
///   format string (currently 8: one digit + dot + six digits).
#[cfg(not(test))]
pub fn print_timestamp()
{
    use crate::arch::current::timer;

    let Some(us) = timer::elapsed_us()
    else
    {
        // Timer not yet calibrated (pre-Phase 5). Fixed-width placeholder so
        // pre-boot lines are visually distinct from timed lines.
        // Width matches "[0.000000]": 8 inner chars → 8 dashes.
        // SAFETY: console is initialised before kprintln! is used.
        unsafe {
            console_write_fmt(format_args!("[--------] "));
        }
        return;
    };

    let sec = us / 1_000_000;
    let us_frac = us % 1_000_000;

    // Format seconds into a small stack buffer (no heap, no float).
    // Handles up to u64::MAX seconds without overflow.
    let mut sec_buf = [0u8; 20]; // 20 ASCII digits covers u64::MAX
    let sec_str = {
        let mut n = sec;
        let mut len = 0usize;
        if n == 0
        {
            sec_buf[0] = b'0';
            len = 1;
        }
        else
        {
            while n > 0
            {
                sec_buf[len] = b'0' + (n % 10) as u8;
                n /= 10;
                len += 1;
            }
            sec_buf[..len].reverse();
        }
        // SAFETY: buf contains only ASCII digit bytes.
        unsafe { core::str::from_utf8_unchecked(&sec_buf[..len]) }
    };

    // SAFETY: console is initialised before kprintln! is used.
    unsafe {
        console_write_fmt(format_args!("[{sec_str}.{us_frac:06}] "));
    }
}

/// No-op stub for test builds (no hardware timer).
#[cfg(test)]
pub fn print_timestamp() {}

/// Serial-only variant of [`print_timestamp`].
#[cfg(not(test))]
pub fn print_serial_timestamp()
{
    use crate::arch::current::timer;

    let Some(us) = timer::elapsed_us()
    else
    {
        // SAFETY: console is initialised.
        unsafe {
            serial_write_fmt(format_args!("[--------] "));
        }
        return;
    };

    let sec = us / 1_000_000;
    let us_frac = us % 1_000_000;

    let mut sec_buf = [0u8; 20];
    let sec_str = {
        let mut n = sec;
        let mut len = 0usize;
        if n == 0
        {
            sec_buf[0] = b'0';
            len = 1;
        }
        else
        {
            while n > 0
            {
                sec_buf[len] = b'0' + (n % 10) as u8;
                n /= 10;
                len += 1;
            }
            sec_buf[..len].reverse();
        }
        // SAFETY: buf contains only ASCII digit bytes.
        unsafe { core::str::from_utf8_unchecked(&sec_buf[..len]) }
    };

    // SAFETY: console is initialised.
    unsafe {
        serial_write_fmt(format_args!("[{sec_str}.{us_frac:06}] "));
    }
}

/// No-op stub for test builds.
#[cfg(test)]
pub fn print_serial_timestamp() {}

/// Print a formatted string to the kernel console.
///
/// Accepts the same format arguments as `std::print!`. Requires
/// `console::init()` to have been called.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        // Capture format_args! outside the unsafe block to avoid expanding
        // metavariables inside unsafe (clippy::macro_metavariable_expr_dep).
        let _args = format_args!($($arg)*);
        // SAFETY: console is initialized before any macro usage.
        unsafe {
            $crate::console::console_write_fmt(_args);
        }
    }};
}

/// Print a formatted string to serial only (no framebuffer).
///
/// Used for userspace fault diagnostics that should not disturb the display.
#[macro_export]
macro_rules! kprint_serial {
    ($($arg:tt)*) => {{
        let _args = format_args!($($arg)*);
        // SAFETY: console is initialized before any macro usage.
        unsafe {
            $crate::console::serial_write_fmt(_args);
        }
    }};
}

/// Print a formatted string followed by `\n` to serial only.
///
/// Prepends a `[S.NNNNNN] kernel: ` timestamp prefix (via serial only).
/// Used for userspace fault diagnostics.
#[macro_export]
macro_rules! kprintln_serial {
    () => {
        $crate::kprint_serial!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::console::print_serial_timestamp();
        $crate::kprint_serial!("kernel: {}\n", format_args!($($arg)*))
    }};
}

/// Print a formatted string followed by `\n` to the kernel console.
///
/// Prepends a `[S.NNNNNN] kernel: ` prefix before each line: timestamp
/// (seconds elapsed since timer calibration) followed by the component
/// identifier `kernel: `. Pre-Phase 5 lines show `[--------] kernel: ` instead.
/// Accepts the same format arguments as `std::println!`. Requires
/// `console::init()` to have been called.
///
/// Use `kprint!` (without the `ln`) for partial-line writes where the
/// timestamp should not be inserted mid-line.
#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::console::print_timestamp();
        $crate::kprint!("kernel: {}\n", format_args!($($arg)*))
    }};
}
