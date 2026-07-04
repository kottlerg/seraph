// seraph-overlay: std::sys::stdio::seraph
//
// Stdin/Stdout/Stderr for Seraph userspace, backed by shmem SPSC rings
// + notification caps (Phase 3 of LOGGING_STDIO_ROADMAP). Each direction is
// an independent `sys::pipe::seraph::Pipe` end attached at child
// startup from the (memory, data_notification, space_notification) triple the
// spawner installed via `procmgr_labels::CONFIGURE_PIPE`.
//
// Cap topology per direction:
//   * stdin:  child = Reader (parent writes into the ring).
//   * stdout: child = Writer (child writes out; parent reads).
//   * stderr: child = Writer.
//
// Memory cap zero in any direction means "no pipe attached":
//   * stdout/stderr write returns Ok(buf.len()) (silent drop).
//   * stdin read returns Ok(0) (immediate EOF).
//
// Panic output defaults to the system log endpoint (pre-seeded badged
// SEND cap in `ProcessInfo.log_send_cap`); the stdio rings here do NOT
// touch the log. A process that serves the log endpoint registers a
// sink via `set_panic_sink` so its own panic / alloc-error output routes
// elsewhere (logd → serial driver) rather than self-IPCing into the
// endpoint it serves.

use crate::cell::UnsafeCell;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::sys::pipe::seraph::{Pipe, Role};

use crate::os::seraph::current_ipc_buf;

// ── Child-side ring VAs ────────────────────────────────────────────────────
//
// One page per attached direction, drawn from the process's page-reservation
// arena (`sys::reserve::seraph`) so the rings inherit the arena's
// per-process randomised base (ASLR, #39). Reserving is pure VA bookkeeping
// (no syscall beyond the arena's one-time base draw), so it is safe this
// early in `_start`, before the heap exists.

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

/// Install one direction's pipe if a memory cap was provided, reserving
/// its ring VA from the arena. Helper for `stdio_init`.
fn try_attach(
    memory: u32,
    data_notification: u32,
    space_notification: u32,
    role: Role,
    aspace: u32,
) -> Option<Pipe> {
    if memory == 0 {
        return None;
    }
    let reserved = crate::sys::reserve::reserve_pages(1).ok()?;
    Pipe::attach_from_caps(memory, data_notification, space_notification, role, aspace, reserved)
        .ok()
}

/// Install the stdio pipe ends from `ProcessInfo` cap triples. Called
/// once from `_start` after the IPC buffer is registered. Each direction
/// is independent: any combination of zero/non-zero memory caps is
/// tolerated.
#[allow(clippy::too_many_arguments)]
pub fn stdio_init(
    stdin_memory: u32,
    stdin_data_sig: u32,
    stdin_space_sig: u32,
    stdout_memory: u32,
    stdout_data_sig: u32,
    stdout_space_sig: u32,
    stderr_memory: u32,
    stderr_data_sig: u32,
    stderr_space_sig: u32,
    aspace: u32,
) {
    // SAFETY: single writer; runs before `STDIO_READY` is observed by
    // any other code path.
    unsafe {
        let slots = &mut *STDIO.0.get();
        slots[IDX_STDIN] = try_attach(
            stdin_memory,
            stdin_data_sig,
            stdin_space_sig,
            Role::Reader,
            aspace,
        );
        slots[IDX_STDOUT] = try_attach(
            stdout_memory,
            stdout_data_sig,
            stdout_space_sig,
            Role::Writer,
            aspace,
        );
        slots[IDX_STDERR] = try_attach(
            stderr_memory,
            stderr_data_sig,
            stderr_space_sig,
            Role::Writer,
            aspace,
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
/// _start`) so the close protocol fires (header `closed = 1` + notification
/// kick) before the kernel destroys this aspace and the parent's
/// blocking read/write would otherwise hang. Idempotent — second call
/// is a no-op.
pub fn close_all() {
    if !STDIO_READY.swap(false, Ordering::AcqRel) {
        return;
    }
    // SAFETY: STDIO_READY just toggled off; no concurrent reader past
    // the Acquire load in `pipe_for`. Drop runs on each Pipe end and
    // marks closed + sends one final notification kick to wake the peer.
    unsafe {
        let slots = &mut *STDIO.0.get();
        drop(slots[IDX_STDIN].take());
        drop(slots[IDX_STDOUT].take());
        drop(slots[IDX_STDERR].take());
    }
}

/// Optional process-global panic-output sink. `0` means unset — panic
/// output then takes the default log-endpoint path. A non-zero value is a
/// `fn(&[u8])` pointer registered via [`set_panic_sink`]; panic output is
/// forwarded to it instead. A process that serves the log endpoint (logd)
/// registers a serial-driver sink so its own faults never self-IPC into
/// the endpoint it serves.
static PANIC_SINK: AtomicUsize = AtomicUsize::new(0);

/// Register `sink` as this process's panic-output sink. `sink` must be
/// non-allocating and must not itself panic: it runs from the panic hook
/// and from the non-unwinding `handle_alloc_error` / precondition paths,
/// which all share the [`panic_output`] chokepoint. Last writer wins.
pub fn set_panic_sink(sink: fn(&[u8])) {
    PANIC_SINK.store(sink as usize, Ordering::Release);
}

/// Panic-output sink. Prefers a registered [`set_panic_sink`] sink; absent
/// one, falls back to the system log endpoint via the process's pre-seeded
/// badged SEND cap from `ProcessInfo.log_send_cap` (installed by `_start`),
/// sending each `write` as `STREAM_BYTES` chunks. Non-allocating —
/// `log::write_bytes` stages bytes into the per-thread IPC buffer, so
/// panics survive allocator failure. Silent-drops on a zero cap or any IPC
/// error.
pub struct PanicWriter;

impl io::Write for PanicWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let raw = PANIC_SINK.load(Ordering::Acquire);
        if raw != 0 {
            // SAFETY: the `raw != 0` guard is what licenses the *call*:
            // `set_panic_sink` only ever stores a valid `fn(&[u8])` (never a
            // null/dangling value), and a usize and a thin fn pointer are the
            // same width on this target, so the round-trip reproduces a live,
            // callable function.
            let sink: fn(&[u8]) = unsafe { crate::mem::transmute::<usize, fn(&[u8])>(raw) };
            sink(buf);
            return Ok(buf.len());
        }
        let ipc_ptr = current_ipc_buf();
        let cap = ::log::ensure_badged_cap(ipc_ptr);
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
    // A registered sink needs no IPC buffer; the log fallback does.
    if PANIC_SINK.load(Ordering::Acquire) == 0 && current_ipc_buf().is_null() {
        return None;
    }
    Some(PanicWriter)
}
