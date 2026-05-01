// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/main.rs

//! ktest — Seraph kernel test binary.
//!
//! Loaded by the kernel in place of real init (set `init=ktest` in boot.conf).
//! Receives the same initial capability set that init would, then:
//!
//! 1. **Tier 1** (`unit/`)        — exercises every kernel syscall in isolation.
//! 2. **Tier 2** (`integration/`) — cross-subsystem scenario tests.
//! 3. **Tier 3** (`bench/`)       — placeholder for future timing/profiling.
//!
//! Results are printed directly to the serial console via hardware I/O.
//! Each test prints `PASS` or `FAIL`. A summary follows. ktest then exits.
//!
//! See `ktest/README.md` for the full test structure and output format.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

mod bench;
mod cmdline;
mod frame_pool;
mod framebuffer;
mod integration;
mod serial;
mod stress;
mod unit;

#[cfg(target_arch = "x86_64")]
mod acpi_shutdown;
#[cfg(target_arch = "riscv64")]
mod sbi_shutdown;

// ── Test infrastructure ───────────────────────────────────────────────────────

/// Return type for every test function.
///
/// On failure the `Err` string is a static reason message logged immediately
/// after the test name.
pub type TestResult = Result<(), &'static str>;

/// Counts tests that returned `Ok(())`.
pub static PASS_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Counts tests that returned `Err(...)`.
pub static FAIL_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Run a named unit test and update the global pass/fail counters.
///
/// `$name` must be a string literal (used with `concat!` for zero-cost
/// log messages). `$body` is an expression evaluating to [`TestResult`].
///
/// Prints one line per test: `ktest: PASS <name>` or `ktest: FAIL <name>`
/// followed by the failure reason. Tests always continue past failures.
///
/// To add a new unit test: write a function returning `TestResult`, then
/// call `run_test!("subsystem::test_name", fn_name(ctx))` in the relevant
/// `run_all` function.
#[macro_export]
macro_rules! run_test {
    ($name:literal, $body:expr) => {{
        let result: $crate::TestResult = { $body };
        match result
        {
            Ok(()) =>
            {
                $crate::log(concat!("ktest: PASS ", $name));
                $crate::PASS_COUNT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            }
            Err(reason) =>
            {
                $crate::log(concat!("ktest: FAIL ", $name));
                $crate::log(reason);
                $crate::FAIL_COUNT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            }
        }
    }};
}

/// Run a named integration test and update the global pass/fail counters.
///
/// Like [`run_test!`] but emits a `"ktest: <name> starting"` line before
/// running the test body. Integration tests typically emit step-by-step
/// progress logs from within their body; the starting line marks their
/// beginning and the PASS/FAIL line marks their end.
///
/// To add a new integration test: implement it in `integration/`, declare
/// it with `pub mod`, then call `run_integration_test!` in `run_all`.
#[macro_export]
macro_rules! run_integration_test {
    ($name:literal, $body:expr) => {{
        $crate::log(concat!("ktest: ", $name, " starting"));
        let result: $crate::TestResult = { $body };
        match result
        {
            Ok(()) =>
            {
                $crate::log(concat!("ktest: PASS ", $name));
                $crate::PASS_COUNT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            }
            Err(reason) =>
            {
                $crate::log(concat!("ktest: FAIL ", $name));
                $crate::log(reason);
                $crate::FAIL_COUNT.fetch_add(1, ::core::sync::atomic::Ordering::Relaxed);
            }
        }
    }};
}

/// Context passed to all test functions.
///
/// Carries the two resources that many tests need: the ktest `AddressSpace` cap
/// and the IPC buffer pointer. Pass by shared reference to test functions.
pub struct TestContext
{
    /// ktest's own `AddressSpace` capability slot, provided by the kernel.
    ///
    /// Used for memory management tests, thread creation (threads must be
    /// bound to an address space), and hardware access tests.
    pub aspace_cap: u32,

    /// Pointer to the registered IPC buffer page (4 KiB, page-aligned).
    ///
    /// Registered with `ipc_buffer_set` before any tests run. Passed into
    /// `ipc::ipc_call` / `ipc::ipc_recv` / `ipc::ipc_reply` as the buffer
    /// for the snapshot copy. The returned `IpcMessage` owns data words
    /// and received cap-slot indices.
    pub ipc_buf: *mut u64,

    /// First RAM Frame cap slot in ktest's `CSpace`, kernel-minted at
    /// Phase 7. ktest is loaded as init and inherits the RAM Frame caps
    /// directly (the same caps init forwards to memmgr). Used by tests
    /// that need to inspect the rights/state of an actual RAM cap; the
    /// `frame_pool` slots elsewhere are derived from a segment cap and
    /// therefore lack the RETYPE right.
    pub memory_frame_base: u32,
}

/// 16 KiB stack for a child thread, aligned per the System V ABI.
///
/// Declare one as `static mut CHILD_STACK: ChildStack = ChildStack::ZERO` in
/// any test module that spawns a child thread. Pass `ChildStack::top(ptr)` to
/// `thread_configure` as the initial stack pointer.
///
/// Each test file that needs a child thread declares its own static stack so
/// stacks never alias across concurrent (or sequential) test boundaries.
#[allow(dead_code)] // Field is CPU stack memory; only the hardware stack pointer accesses it, not Rust code.
#[repr(align(16))]
pub struct ChildStack([u8; 16384]);

impl ChildStack
{
    pub const ZERO: ChildStack = ChildStack([0u8; 16384]);

    /// Virtual address of the top of the stack at `ptr` (one past the last byte).
    ///
    /// Thread stacks grow downward; this is the value to pass as the initial
    /// stack pointer. Takes a raw pointer to avoid creating a reference to a
    /// `static mut` — pass `core::ptr::addr_of!(STACK)` as the argument.
    #[must_use]
    pub fn top(ptr: *const Self) -> u64
    {
        ptr as u64 + 16384
    }
}

// ── IPC buffer ────────────────────────────────────────────────────────────────

/// Static IPC buffer — 4 KiB, page-aligned.
///
/// Registered once in `run()` via `ipc_buffer_set`. The kernel writes received
/// message data and capability slot indices here; the `ipc::IpcMessage`
/// wrappers snapshot those values into a stack-owned message before returning,
/// so tests read from the returned `IpcMessage` rather than from the buffer
/// directly.
#[repr(C, align(4096))]
struct IpcBuf([u64; 512]);

// SAFETY: ktest is single-threaded on the main test path. Child threads that
// need IPC data transfer must register this buffer via ipc_buffer_set.
pub(crate) static mut IPC_BUF: IpcBuf = IpcBuf([0u64; 512]);

// ── Entry point ───────────────────────────────────────────────────────────────

/// Kernel entry point for ktest.
///
/// `info_ptr` — virtual address of the read-only [`InitInfo`](init_protocol::InitInfo)
/// page mapped by the kernel. Provided as the initial argument (same as for real init).
#[unsafe(no_mangle)]
pub extern "C" fn _start(info_ptr: u64) -> !
{
    run(info_ptr)
}

fn run(info_ptr: u64) -> !
{
    // Read InitInfo from the kernel-mapped page.
    // SAFETY: info_ptr is a valid page-aligned virtual address mapped by the
    // kernel in Phase 9; the page contains a valid InitInfo struct.
    let info: &init_protocol::InitInfo = unsafe { &*(info_ptr as *const init_protocol::InitInfo) };

    if info.version != init_protocol::INIT_PROTOCOL_VERSION
    {
        // Version mismatch: kernel and ktest disagree on InitInfo layout.
        // Cannot log (serial not initialised yet). Halt immediately.
        halt();
    }

    // Initialise direct serial output before any logging.
    // SAFETY: called once, single-threaded, InitInfo is valid.
    unsafe { serial::init(info, info.aspace_cap, info.thread_cap) };

    // Initialise framebuffer output (best-effort; no-op if unavailable).
    // SAFETY: called once, single-threaded, InitInfo is valid.
    unsafe { framebuffer::init(info, info.aspace_cap) };

    log("ktest: starting");

    let aspace_cap = info.aspace_cap;

    // Register the IPC buffer before any IPC syscall. All Tier 1 IPC tests
    // and integration tests depend on this.
    // SAFETY: IPC_BUF is a page-aligned static in ktest's BSS; single-threaded here.
    let ipc_buf_ptr = core::ptr::addr_of_mut!(IPC_BUF).cast::<u64>();
    syscall::ipc_buffer_set(ipc_buf_ptr as u64).unwrap_or_else(|_| {
        log("ktest: FATAL: ipc_buffer_set failed");
        halt()
    });

    // Initialize the frame pool before running tests. Tests consume frame caps
    // via splits; without pooling, resources are exhausted after ~10 tests.
    // SAFETY: Called once before any tests run; no concurrent access yet.
    unsafe {
        frame_pool::init(info);
    }

    let ctx = TestContext {
        aspace_cap,
        ipc_buf: ipc_buf_ptr,
        memory_frame_base: info.memory_frame_base,
    };

    // Parse config early so we can gate tier execution and pass bench_iters.
    // SAFETY: info is valid for the lifetime of the process (kernel-mapped page).
    let config = cmdline::parse(unsafe { init_protocol::cmdline_bytes(info) });

    // ── Tier 1: per-syscall isolation ─────────────────────────────────────────
    if config.run_unit
    {
        log("ktest: --- Tier 1: syscall isolation ---");
        unit::run_all(&ctx);
    }

    // ── Tier 2: cross-subsystem integration ───────────────────────────────────
    if config.run_integration
    {
        log("ktest: --- Tier 2: integration ---");
        integration::run_all(&ctx);
    }

    // ── Tier S: stress tests ─────────────────────────────────────────────────
    if config.run_stress
    {
        log("ktest: --- Tier S: stress ---");
        stress::run_all(&ctx);
    }

    // ── Tier 3: benchmarks ────────────────────────────────────────────────────
    if config.run_bench
    {
        log("ktest: --- Tier 3: benchmarks ---");
        bench::run_all(&ctx, config.bench_iters);
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    let passed = PASS_COUNT.load(Ordering::Relaxed);
    let failed = FAIL_COUNT.load(Ordering::Relaxed);
    log_u64("ktest: passed=", passed as u64);
    log_u64("ktest: failed=", failed as u64);
    if failed == 0
    {
        log("ktest: ALL TESTS PASSED");
    }
    else
    {
        log("ktest: SOME TESTS FAILED");
    }

    // ── Shutdown ─────────────────────────────────────────────────────────────
    let all_passed = failed == 0;
    let should_shutdown = match config.shutdown_policy
    {
        cmdline::ShutdownPolicy::Always => true,
        cmdline::ShutdownPolicy::Pass => all_passed,
        cmdline::ShutdownPolicy::Never => false,
    };

    if should_shutdown
    {
        if config.timeout_secs > 0
        {
            log_u64("ktest: shutdown in ", u64::from(config.timeout_secs));
            wait_seconds(config.timeout_secs);
        }

        log("ktest: shutdown");
        #[cfg(target_arch = "x86_64")]
        acpi_shutdown::shutdown(info);
        #[cfg(target_arch = "riscv64")]
        sbi_shutdown::shutdown(info);

        // Shutdown failed; fall through to thread_exit.
        log("ktest: shutdown failed, halting");
    }

    syscall::thread_exit()
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Write a `[S.NNNNNN] ` timestamp prefix to all output channels.
///
/// Format matches the kernel console: `[S.NNNNNN] ` where S is whole seconds
/// (variable width) and NNNNNN is zero-padded microseconds (6 digits).
/// Source: `SYS_SYSTEM_INFO(ElapsedUs)` — microseconds since kernel timer init.
fn write_timestamp()
{
    let us = syscall::system_info(6).unwrap_or(0);
    let sec = us / 1_000_000;
    let us_frac = us % 1_000_000;

    // Format "[sec.uuuuuu] " into a stack buffer. Max seconds digits = 20 (u64),
    // plus '[', '.', 6 fractional digits, ']', ' ' = 30 bytes max.
    let mut buf = [0u8; 30];
    let mut pos = 0usize;

    buf[pos] = b'[';
    pos += 1;

    // Seconds (variable width, at least one digit).
    let mut sec_buf = [0u8; 20];
    let mut sec_len = 0usize;
    let mut n = sec;
    if n == 0
    {
        sec_buf[0] = b'0';
        sec_len = 1;
    }
    else
    {
        while n > 0
        {
            sec_buf[sec_len] = b'0' + (n % 10) as u8;
            n /= 10;
            sec_len += 1;
        }
        sec_buf[..sec_len].reverse();
    }
    buf[pos..pos + sec_len].copy_from_slice(&sec_buf[..sec_len]);
    pos += sec_len;

    buf[pos] = b'.';
    pos += 1;

    // Microseconds (zero-padded to 6 digits).
    let mut frac = us_frac;
    for i in (0..6).rev()
    {
        buf[pos + i] = b'0' + (frac % 10) as u8;
        frac /= 10;
    }
    pos += 6;

    buf[pos] = b']';
    pos += 1;
    buf[pos] = b' ';
    pos += 1;

    if let Ok(s) = core::str::from_utf8(&buf[..pos])
    {
        serial::write_str(s);
        framebuffer::write_str(s);
    }
}

/// Write a string to all available output channels (serial + framebuffer).
///
/// Each line is prefixed with a `[S.NNNNNN] ` timestamp matching the kernel
/// console format. Each channel is best-effort: no-op if its initialisation
/// failed.
#[inline]
pub fn log(msg: &str)
{
    write_timestamp();
    serial::write_str(msg);
    serial::write_byte(b'\n');
    framebuffer::write_str(msg);
    framebuffer::newline();
}

/// Log a decimal `u64` value prefixed by a static string.
///
/// Uses a fixed 24-byte stack buffer — no heap required.
pub fn log_u64(prefix: &str, value: u64)
{
    let mut buf = [0u8; 24];
    let mut n = value;
    let mut len = 0usize;
    if n == 0
    {
        buf[0] = b'0';
        len = 1;
    }
    else
    {
        while n > 0
        {
            buf[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
        buf[..len].reverse();
    }

    let num_str = core::str::from_utf8(&buf[..len]).unwrap_or("?");
    let mut msg = [0u8; 128];
    let pb = prefix.as_bytes();
    let plen = pb.len().min(msg.len());
    msg[..plen].copy_from_slice(&pb[..plen]);
    let nlen = num_str.len().min(msg.len() - plen);
    msg[plen..plen + nlen].copy_from_slice(&num_str.as_bytes()[..nlen]);
    let total = plen + nlen;
    if let Ok(s) = core::str::from_utf8(&msg[..total])
    {
        log(s);
    }
}

/// Log a kernel version packed as a `u64` in `MAJOR.MINOR.PATCH` encoding.
///
/// Prints `prefix` followed by `"vMAJOR.MINOR.PATCH"` (e.g. `"v0.0.1"`).
/// Uses the same shift/mask encoding as `syscall_abi::KERNEL_VERSION`:
/// `major = ver >> 32`, `minor = (ver >> 16) & 0xFFFF`, `patch = ver & 0xFFFF`.
pub fn log_version(prefix: &str, ver: u64)
{
    // Write a u64 as decimal into buf starting at pos; returns new pos.
    fn write_num(buf: &mut [u8], pos: usize, mut n: u64) -> usize
    {
        if n == 0
        {
            if pos < buf.len()
            {
                buf[pos] = b'0';
                return pos + 1;
            }
            return pos;
        }
        let start = pos;
        let mut end = pos;
        while n > 0 && end < buf.len()
        {
            buf[end] = b'0' + (n % 10) as u8;
            n /= 10;
            end += 1;
        }
        buf[start..end].reverse();
        end
    }

    let major = ver >> 32;
    let minor = (ver >> 16) & 0xFFFF;
    let patch = ver & 0xFFFF;
    let mut buf = [0u8; 128];
    let pb = prefix.as_bytes();
    let plen = pb.len().min(buf.len());
    buf[..plen].copy_from_slice(&pb[..plen]);
    let mut pos = plen;

    if pos < buf.len()
    {
        buf[pos] = b'v';
        pos += 1;
    }
    pos = write_num(&mut buf, pos, major);
    if pos < buf.len()
    {
        buf[pos] = b'.';
        pos += 1;
    }
    pos = write_num(&mut buf, pos, minor);
    if pos < buf.len()
    {
        buf[pos] = b'.';
        pos += 1;
    }
    pos = write_num(&mut buf, pos, patch);

    if let Ok(s) = core::str::from_utf8(&buf[..pos])
    {
        log(s);
    }
}

/// Wait for `secs` seconds using the kernel timer via `system_info(ElapsedUs)`.
///
/// Yields the CPU between polls so the scheduler can run other threads.
fn wait_seconds(secs: u32)
{
    let target_us = u64::from(secs) * 1_000_000;
    let start = syscall::system_info(6).unwrap_or(0); // ElapsedUs = 6
    loop
    {
        let now = syscall::system_info(6).unwrap_or(0);
        if now.wrapping_sub(start) >= target_us
        {
            break;
        }
        let _ = syscall::thread_yield();
    }
}

/// Spin forever. Used for fatal errors where ktest cannot continue.
pub fn halt() -> !
{
    loop
    {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> !
{
    // Only the main thread has IOPB access for serial output. Child threads
    // that panic must not call log (outb would GP-fault without IOPB).
    // Exit the thread instead.
    syscall::thread_exit()
}
