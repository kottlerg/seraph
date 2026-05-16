// seraph-overlay: std::sys::stdio::seraph
//
// Stdin/Stdout/Stderr for Seraph userspace, backed by shmem SPSC rings
// + signal caps (Phase 3 of LOGGING_STDIO_ROADMAP). Each direction is
// an independent `sys::pipe::seraph::Pipe` end attached at child
// startup from the (frame, data_signal, space_signal) triple the
// spawner installed via `procmgr_labels::CONFIGURE_PIPE`.
//
// Cap topology per direction:
//   * stdin:  child = Reader (parent writes into the ring).
//   * stdout: child = Writer (child writes out; parent reads).
//   * stderr: child = Writer.
//
// Frame cap zero in any direction means "no pipe attached":
//   * stdout/stderr write returns Ok(buf.len()) (silent drop).
//   * stdin read returns Ok(0) (immediate EOF).
//
// Panic output continues to route through the system log endpoint
// (pre-seeded tokened SEND cap in `ProcessInfo.log_send_cap`); this
// file does NOT touch the log.

use crate::cell::UnsafeCell;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sys::pipe::seraph::{Pipe, Role};

use crate::os::seraph::current_ipc_buf;

// ── Child-side ring VAs ────────────────────────────────────────────────────
//
// One fixed VA per direction. Above PROCESS_MAIN_TLS_VADDR + max TLS pages
// (0x7FFF_FFFD_4000) and below PROCMGR_IPC_BUF_VA (0x7FFF_FFFE_0000).

const STDIN_RING_VA: u64 = 0x0000_7FFF_FFFD_5000;
const STDOUT_RING_VA: u64 = 0x0000_7FFF_FFFD_6000;
const STDERR_RING_VA: u64 = 0x0000_7FFF_FFFD_7000;

// Process-global stdio Pipe ends. UnsafeCell behind a one-shot guard
// flag — `_start` is the unique writer; subsequent reads happen only
// after `STDIO_READY` flips to true, with Acquire ordering.

struct StdioCell(UnsafeCell<[Option<Pipe>; 3]>);

// SAFETY: written exactly once from `_start` before any other thread
// runs; subsequent accesses go through the `STDIO_READY` Acquire load.
unsafe impl Sync for StdioCell {}

static STDIO: StdioCell = StdioCell(UnsafeCell::new([None, None, None]));
static STDIO_READY: AtomicBool = AtomicBool::new(false);

const IDX_STDIN: usize = 0;
const IDX_STDOUT: usize = 1;
const IDX_STDERR: usize = 2;

fn pipe_for(idx: usize) -> Option<&'static Pipe> {
    if !STDIO_READY.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: STDIO_READY = true means `stdio_init` finished writing
    // the slots before flipping the flag (Release). We hold a shared
    // reference that lasts the process lifetime; no further writes
    // occur after init.
    let slots = unsafe { &*STDIO.0.get() };
    slots.get(idx).and_then(|s| s.as_ref())
}

/// Install one direction's pipe if a frame cap was provided. Helper
/// for `stdio_init`.
fn try_attach(
    frame: u32,
    data_signal: u32,
    space_signal: u32,
    role: Role,
    aspace: u32,
    child_va: u64,
) -> Option<Pipe> {
    if frame == 0 {
        return None;
    }
    Pipe::attach_from_caps(frame, data_signal, space_signal, role, aspace, child_va).ok()
}

/// Install the stdio pipe ends from `ProcessInfo` cap triples. Called
/// once from `_start` after the IPC buffer is registered. Each direction
/// is independent: any combination of zero/non-zero frame caps is
/// tolerated.
#[allow(clippy::too_many_arguments)]
pub fn stdio_init(
    stdin_frame: u32,
    stdin_data_sig: u32,
    stdin_space_sig: u32,
    stdout_frame: u32,
    stdout_data_sig: u32,
    stdout_space_sig: u32,
    stderr_frame: u32,
    stderr_data_sig: u32,
    stderr_space_sig: u32,
    aspace: u32,
) {
    // SAFETY: single writer; runs before `STDIO_READY` is observed by
    // any other code path.
    unsafe {
        let slots = &mut *STDIO.0.get();
        slots[IDX_STDIN] = try_attach(
            stdin_frame,
            stdin_data_sig,
            stdin_space_sig,
            Role::Reader,
            aspace,
            STDIN_RING_VA,
        );
        slots[IDX_STDOUT] = try_attach(
            stdout_frame,
            stdout_data_sig,
            stdout_space_sig,
            Role::Writer,
            aspace,
            STDOUT_RING_VA,
        );
        slots[IDX_STDERR] = try_attach(
            stderr_frame,
            stderr_data_sig,
            stderr_space_sig,
            Role::Writer,
            aspace,
            STDERR_RING_VA,
        );
    }
    STDIO_READY.store(true, Ordering::Release);
}

// ── Stdin ──────────────────────────────────────────────────────────────────

pub struct Stdin;

impl Stdin {
    pub const fn new() -> Stdin {
        Stdin
    }
}

impl io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match pipe_for(IDX_STDIN) {
            Some(p) => p.read(buf),
            None => Ok(0),
        }
    }

    fn read_buf(&mut self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        match pipe_for(IDX_STDIN) {
            Some(p) => p.read_buf(cursor),
            None => Ok(()),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match pipe_for(IDX_STDIN) {
            Some(p) => p.read_vectored(bufs),
            None => Ok(0),
        }
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        false
    }
}

// ── Stdout ──────────────────────────────────────────────────────────────────

pub struct Stdout;

impl Stdout {
    pub const fn new() -> Stdout {
        Stdout
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match pipe_for(IDX_STDOUT) {
            Some(p) => p.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match pipe_for(IDX_STDOUT) {
            Some(p) => p.write_vectored(bufs),
            None => Ok(bufs.iter().map(|b| b.len()).sum()),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── Stderr ──────────────────────────────────────────────────────────────────

pub struct Stderr;

impl Stderr {
    pub const fn new() -> Stderr {
        Stderr
    }
}

impl io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match pipe_for(IDX_STDERR) {
            Some(p) => p.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match pipe_for(IDX_STDERR) {
            Some(p) => p.write_vectored(bufs),
            None => Ok(bufs.iter().map(|b| b.len()).sum()),
        }
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── Module API expected by std::io::stdio ──────────────────────────────────

pub const STDIN_BUF_SIZE: usize = 512;

pub fn is_ebadf(_err: &io::Error) -> bool {
    true
}

/// Tear down all stdio pipe ends. Called from the process-exit path
/// (`sys::exit::exit` and the post-`main` epilogue in `os::seraph::
/// _start`) so the close protocol fires (header `closed = 1` + signal
/// kick) before the kernel destroys this aspace and the parent's
/// blocking read/write would otherwise hang. Idempotent — second call
/// is a no-op.
pub fn close_all() {
    if !STDIO_READY.swap(false, Ordering::AcqRel) {
        return;
    }
    // SAFETY: STDIO_READY just toggled off; no concurrent reader past
    // the Acquire load in `pipe_for`. Drop runs on each Pipe end and
    // marks closed + sends one final signal kick to wake the peer.
    unsafe {
        let slots = &mut *STDIO.0.get();
        drop(slots[IDX_STDIN].take());
        drop(slots[IDX_STDOUT].take());
        drop(slots[IDX_STDERR].take());
    }
}

/// Panic-output sink that emits through the system log endpoint.
///
/// Uses the process's pre-seeded tokened SEND cap from
/// `ProcessInfo.log_send_cap` (installed by `_start`) and sends each
/// `write` as `STREAM_BYTES` chunks. Non-allocating — `log::write_bytes`
/// stages bytes into the per-thread IPC buffer, so panics survive
/// allocator failure. Silent-drops on a zero cap or any IPC error.
pub struct LogPanicWriter;

impl io::Write for LogPanicWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ipc_ptr = current_ipc_buf();
        let cap = ::log::ensure_tokened_cap(ipc_ptr);
        if cap == 0 || ipc_ptr.is_null() {
            return Ok(buf.len());
        }
        ::log::write_bytes(cap, ipc_ptr, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn panic_output() -> Option<impl io::Write> {
    if current_ipc_buf().is_null() {
        return None;
    }
    Some(LogPanicWriter)
}
