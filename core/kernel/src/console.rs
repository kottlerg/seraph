// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/console.rs

//! Kernel direct console: serial and framebuffer output, and the print macros.
//!
//! Provides `init()` and the `kprintln!` family. A line written here goes
//! straight to the serial port, and to the framebuffer when the line's sink
//! includes it. While a reader is attached to the kernel log, `kprintln!` and
//! `kprintln_fault!` lines become log records instead (`crate::klog`); the
//! other macros always write here. Which macro a line takes is in
//! `core/kernel/docs/kernel-log.md` § Print classes.
//!
//! The kernel is a native ELF, so `core::fmt` trait objects and vtable dispatch
//! work on all architectures. The macros accept full format arguments.
//!
//! This console is retained permanently for early boot and failure windows;
//! steady-state serial output is owned by the userspace serial driver. See
//! `docs/console-model.md`.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::current::console::{serial_init, serial_write_byte};
use crate::framebuffer::FramebufferWriter;
use crate::mm::paging::phys_to_virt;
use boot_protocol::BootInfo;

/// Spinlock protecting `CONSOLE`. Acquired by every [`write_line`]
/// call so concurrent writes from multiple CPUs (SMP) do not
/// race on the framebuffer cursor position. A plain `AtomicBool`
/// (test-and-set) rather than the ticket `Spinlock`, so the crash and NMI paths
/// below can claim it without queueing. The acquiring writer disables
/// interrupts before it spins and restores them only after the release, so the
/// lock is never held with interrupts enabled: an interrupt-context print
/// (`timer_tick`'s vmgenid log, BSP stall check, and softlockup watchdog dump)
/// cannot interrupt a holder on its own CPU and spin on it forever.
///
/// The kernel log's lock (`klog::KLOG_LOCK`) is taken before it, never after:
/// a line printed while no reader is attached is written under both. No holder
/// of `CONSOLE_LOCK` takes the kernel log's lock.
///
/// Two non-acquiring exceptions exist for crash and NMI paths where
/// spin-waiting would deadlock against a halted or interrupted lock-
/// holder: `panic_write_fmt` force-claims the lock and never releases
/// it (caller halts), and `nmi_write_fmt` swap-and-restores the lock
/// (caller resumes the interrupted code).
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
/// before any line is printed.
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
/// `fb_phys` to `phys_to_virt(fb_phys)` and calls `FramebufferWriter::rebase`
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

/// Where a directly written line goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sink
{
    /// The serial port and the framebuffer.
    Console,
    /// The serial port only: a line no framebuffer reader may see
    /// (`core/kernel/docs/cross-boundary-disclosure.md` § Kernel console
    /// diagnostics).
    Serial,
}

/// A line's timestamp, `[S.NNNNNN]`: whole seconds (variable width) and
/// zero-padded microseconds since timer calibration, or `[--------]` before
/// it (8 dashes, the width of `[0.000000]`).
pub struct Stamp(pub Option<u64>);

impl core::fmt::Display for Stamp
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self.0
        {
            None => f.write_str("[--------]"),
            Some(us) => write!(f, "[{}.{:06}]", us / 1_000_000, us % 1_000_000),
        }
    }
}

/// The kernel's time for a line written now: `None` before the timer is
/// calibrated (pre-Phase 5), and in host tests.
pub fn now_us() -> Option<u64>
{
    #[cfg(not(test))]
    {
        crate::arch::current::timer::elapsed_us()
    }
    #[cfg(test)]
    {
        None
    }
}

/// Write one kernel line to `sink`: the timestamp, `kernel: `, the text and
/// a newline, under one hold of `CONSOLE_LOCK`, so no other CPU's line falls
/// inside it. Each call disables interrupts, acquires the lock, writes,
/// releases, and restores the caller's interrupt state (see `CONSOLE_LOCK`).
///
/// # Safety
/// `console::init` must have been called before this function.
#[cfg(not(test))]
pub unsafe fn write_line(sink: Sink, us: Option<u64>, args: core::fmt::Arguments)
{
    use core::fmt::Write;

    let saved = console_lock_acquire();
    let line = format_args!("{} kernel: {}\n", Stamp(us), args);
    match sink
    {
        Sink::Console =>
        {
            // SAFETY: we hold CONSOLE_LOCK; no other CPU is in this block.
            let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
            let _ = console.write_fmt(line);
        }
        Sink::Serial =>
        {
            let _ = SerialWriter.write_fmt(line);
        }
    }
    console_lock_release(saved);
}

/// Write one kernel line to the serial port only, never as a log record: the
/// path of `kprintln_serial!`, as a function a register dump shared with
/// userspace faults can take.
pub fn print_serial(args: core::fmt::Arguments)
{
    // SAFETY: the console is initialised before any line is printed.
    unsafe { write_line(Sink::Serial, now_us(), args) };
}

/// No-op stub for test builds.
#[cfg(test)]
pub unsafe fn write_line(_sink: Sink, _us: Option<u64>, _args: core::fmt::Arguments) {}

/// Disable interrupts, then spin until `CONSOLE_LOCK` is claimed. Returns the
/// saved interrupt state for [`console_lock_release`].
///
/// Interrupts go off before the spin so the lock is never held, or waited on,
/// with interrupts enabled (see `CONSOLE_LOCK`).
#[cfg(not(test))]
fn console_lock_acquire() -> u64
{
    // SAFETY: kernel context; the saved state is restored by
    // console_lock_release on the same CPU.
    let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    while CONSOLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    saved
}

/// Release `CONSOLE_LOCK`, then restore the interrupt state
/// [`console_lock_acquire`] saved.
#[cfg(not(test))]
fn console_lock_release(saved: u64)
{
    CONSOLE_LOCK.store(false, Ordering::Release);
    // SAFETY: `saved` came from console_lock_acquire on this CPU.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved) };
}

/// Host-test variant: no interrupts exist off-target.
#[cfg(test)]
fn console_lock_acquire() -> u64
{
    while CONSOLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    0
}

/// Host-test variant: no interrupts exist off-target.
#[cfg(test)]
fn console_lock_release(_saved: u64)
{
    CONSOLE_LOCK.store(false, Ordering::Release);
}

/// A `fmt::Write` sink that writes bytes only to the serial port, inserting a
/// CR before each LF. Shared by [`write_line`], [`panic_write_fmt`], and
/// [`nmi_write_fmt`], which differ only in how they claim `CONSOLE_LOCK`.
///
/// Construct it only after `console::init` has initialised the serial port
/// (each of those writers requires that as its safety contract); writing
/// through it is sound only then.
#[cfg(not(test))]
struct SerialWriter;

#[cfg(not(test))]
impl core::fmt::Write for SerialWriter
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        for byte in s.bytes()
        {
            if byte == b'\n'
            {
                // SAFETY: a `SerialWriter` is constructed only after
                // `console::init` (see the type's rustdoc); writing a byte to an
                // initialised port has no other precondition.
                unsafe { serial_write_byte(b'\r') };
            }
            // SAFETY: as for the `\r` above: the port is initialised.
            unsafe { serial_write_byte(byte) };
        }
        Ok(())
    }
}

/// Write a formatted string to the serial port only, for use inside panic handlers.
///
/// Unlike [`write_line`], this function:
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

    // Force-claim: store true unconditionally. Stops other CPUs from writing
    // (best-effort) without risking a spin-wait deadlock on re-entrant panics.
    CONSOLE_LOCK.store(true, Ordering::Relaxed);

    let _ = SerialWriter.write_fmt(args);
    // Lock intentionally not released — caller halts immediately after.
}

/// Write a formatted string to the serial port from an NMI handler.
///
/// Unlike [`write_line`], this function does NOT spin-wait on
/// `CONSOLE_LOCK` — an NMI can interrupt a CPU that already holds the
/// lock, and spinning would deadlock. Instead it swaps the lock,
/// writes, and restores the prior lock state so the interrupted
/// critical section resumes cleanly.
///
/// Output may interleave with another CPU mid-write; the diagnostic
/// content (RIP, RSP, GPRs from the saved frame) is intelligible
/// line-by-line even when interleaved.
///
/// # Safety
/// `console::init` must have been called before this function. Safe
/// to call from inside an NMI handler regardless of whether
/// `CONSOLE_LOCK` is held by the interrupted code.
#[cfg_attr(
    target_arch = "riscv64",
    expect(
        dead_code,
        reason = "only the x86-64 NMI handler calls this; RISC-V has no S-mode NMI surface"
    )
)]
#[cfg(not(test))]
pub unsafe fn nmi_write_fmt(args: core::fmt::Arguments)
{
    use core::fmt::Write;

    // Atomic swap: take the lock (forcibly), remember the prior state.
    let prior = CONSOLE_LOCK.swap(true, Ordering::Acquire);

    let _ = SerialWriter.write_fmt(args);

    // If the interrupted code was holding the lock, leave it held so
    // its critical section resumes uninterrupted. Otherwise release.
    if !prior
    {
        CONSOLE_LOCK.store(false, Ordering::Release);
    }
}

/// No-op stub for test builds.
#[cfg(test)]
pub unsafe fn nmi_write_fmt(_args: core::fmt::Arguments) {}

/// No-op stub for test builds.
#[cfg(test)]
pub unsafe fn panic_write_fmt(_args: core::fmt::Arguments) {}

/// Print one line to the kernel console, or, while a reader is attached to
/// the kernel log, append it as a log record (`crate::klog::print`).
///
/// For an address-free kernel line: it carries no kernel virtual address, no
/// KASLR-derived value and no physical address, since a log record reaches
/// userspace (`core/kernel/docs/kernel-log.md` § Print classes). Accepts the
/// same format arguments as `std::println!`. Written directly, the line is
/// `[S.NNNNNN] kernel: <text>` on the serial port and the framebuffer.
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {
        $crate::klog::print($crate::console::Sink::Console, format_args!($($arg)*))
    };
}

/// [`kprintln!`] for a diagnostic of a userspace thread's fault: what the
/// kernel's fault message to a handler carries, and the thread's own user
/// registers. Written directly, the line goes to the serial port only.
#[macro_export]
macro_rules! kprintln_fault {
    ($($arg:tt)*) => {
        $crate::klog::print($crate::console::Sink::Serial, format_args!($($arg)*))
    };
}

/// Print one line to the serial port only, never as a log record.
///
/// The path for a line carrying a kernel virtual address, a KASLR-derived
/// value or a physical address; see
/// `core/kernel/docs/cross-boundary-disclosure.md` § Kernel console diagnostics.
#[macro_export]
macro_rules! kprintln_serial {
    ($($arg:tt)*) => {{
        let _args = format_args!($($arg)*);
        // SAFETY: console is initialized before any macro usage.
        unsafe {
            $crate::console::write_line(
                $crate::console::Sink::Serial,
                $crate::console::now_us(),
                _args,
            );
        }
    }};
}

/// Print one line to the kernel console whether or not a reader is attached:
/// a report of a failure in which the reader may not run (the watchdog, a
/// fatal error). First prints the log records no reader has acknowledged
/// (`crate::klog::flush`), so the lines before the failure come out ahead of
/// it.
#[macro_export]
macro_rules! kprintln_direct {
    ($($arg:tt)*) => {
        $crate::klog::print_direct(format_args!($($arg)*))
    };
}

/// NMI-safe variant of [`kprintln_serial!`]: swap-and-restore on
/// `CONSOLE_LOCK` instead of spin-waiting, so an NMI that interrupts
/// the lock-holder does not deadlock. Output may interleave with
/// another CPU mid-write; the diagnostic content is intelligible
/// line-by-line.
#[macro_export]
macro_rules! kprintln_nmi {
    ($($arg:tt)*) => {{
        let _args = format_args!("kernel-nmi: {}\n", format_args!($($arg)*));
        // SAFETY: console is initialised before any NMI dispatch.
        unsafe {
            $crate::console::nmi_write_fmt(_args);
        }
    }};
}
