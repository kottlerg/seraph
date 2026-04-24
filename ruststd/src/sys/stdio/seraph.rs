// seraph-overlay: std::sys::stdio::seraph
//
// Stdin/Stdout/Stderr for Seraph userspace. Each stream is backed by an
// IPC capability the spawner installed in the child's `ProcessInfo`.
// Core userspace has no opinion on what the receiver does — current
// spawners point stdout/stderr at a logging sink with a per-service token,
// but a future shell or terminal service can point them anywhere.
//
// Wire protocol (stdout/stderr):
//   Producer issues `ipc_call(cap, label = STREAM_BYTES | (byte_len << 16),
//   data_words = byte_len.div_ceil(8), caps = []) -> empty reply`.
//   Bytes are packed little-endian into the IPC buffer data words. Writes
//   larger than the per-call payload (`MSG_DATA_WORDS_MAX * 8 = 512` bytes)
//   loop with one ipc_call per chunk; the receiver concatenates each call's
//   bytes in order. No continuation flag, no total-length envelope — line
//   buffering or stream framing is the receiver's concern.
//
// Wire protocol (stdin):
//   Spawner (or its delegate) calls into the child's stdin endpoint with the
//   same STREAM_BYTES label. Child's `read(buf)` performs `ipc_recv` on its
//   stdin cap, copies up to `buf.len()` bytes out of the IPC buffer, then
//   `ipc_reply`s empty to unblock the sender.
//
// Caps with slot index 0 mean "no stream attached":
//   * stdout/stderr write returns `Ok(buf.len())` (silent drop).
//   * stdin read returns `Ok(0)` (immediate EOF).

use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::os::seraph::current_ipc_buf;
use crate::sync::atomic::{AtomicU32, Ordering};

use ipc::{IpcMessage, stream_labels::STREAM_BYTES};
use syscall_abi::MSG_DATA_WORDS_MAX;

/// Maximum bytes per IPC chunk (one full IPC data area).
const CHUNK_SIZE: usize = MSG_DATA_WORDS_MAX * 8;

static STDIN_CAP: AtomicU32 = AtomicU32::new(0);
static STDOUT_CAP: AtomicU32 = AtomicU32::new(0);
static STDERR_CAP: AtomicU32 = AtomicU32::new(0);

/// Install the three stdio cap slots.
///
/// Called from `_start` once the `ProcessInfo` page has been read. The IPC
/// buffer pointer is not stored here: every send/recv site reads the
/// current thread's registered buffer from the TLS slot populated by
/// `_start` (main thread) or the thread trampoline (spawned threads) via
/// [`crate::os::seraph::current_ipc_buf`]. A process-global buffer VA
/// would silently target the main thread's page from spawned threads,
/// while the kernel reads the calling thread's `tcb.ipc_buffer`.
///
/// Each cap slot may be zero, in which case operations on that stream
/// silently drop (writes) or return EOF (reads).
pub fn stdio_init(stdin: u32, stdout: u32, stderr: u32) {
    STDIN_CAP.store(stdin, Ordering::Release);
    STDOUT_CAP.store(stdout, Ordering::Release);
    STDERR_CAP.store(stderr, Ordering::Release);
}

/// Best-effort raw write to the stderr cap, used by panic / pre-heap
/// diagnostic paths that cannot afford a `LineWriter` allocation. Silently
/// drops if the current thread's IPC buffer is not yet registered or the
/// stderr slot is zero. Does not fall back to stdout — a process without
/// stderr was created that way intentionally, and cross-stream
/// redirection crosses the semantics the spawner set.
pub(crate) fn diag_write_raw(bytes: &[u8]) {
    let ipc_ptr = current_ipc_buf();
    if ipc_ptr.is_null() {
        return;
    }
    let cap = STDERR_CAP.load(Ordering::Acquire);
    if cap != 0 {
        let _ = send_bytes(cap, ipc_ptr, bytes);
    }
}

/// Send raw bytes on `cap`, splitting across multiple IPC calls if the
/// payload exceeds `CHUNK_SIZE`.
fn send_bytes(ep: u32, ipc_ptr: *mut u64, bytes: &[u8]) -> io::Result<usize> {
    let total_len = bytes.len();
    if total_len == 0 {
        return Ok(0);
    }

    let mut offset = 0;
    while offset < total_len {
        let remaining = total_len - offset;
        let chunk_len = remaining.min(CHUNK_SIZE);
        let label = STREAM_BYTES | ((chunk_len as u64 & 0xFFFF) << 16);
        let msg = IpcMessage::builder(label)
            .bytes(0, &bytes[offset..offset + chunk_len])
            .build();
        // SAFETY: `ipc_ptr` was just loaded from the per-thread TLS slot
        // populated by `_start` / the thread trampoline immediately after
        // `syscall::ipc_buffer_set`, so it is the kernel-registered
        // (page-aligned) IPC buffer for the current thread.
        if unsafe { ipc::ipc_call(ep, &msg, ipc_ptr) }.is_err() {
            return Err(io::const_error!(
                io::ErrorKind::BrokenPipe,
                "seraph stdio ipc_call failed",
            ));
        }
        offset += chunk_len;
    }
    Ok(total_len)
}

/// Receive up to `buf.len()` bytes on the stdin cap. Replies empty to unblock
/// the sender. Returns the number of bytes read; `Ok(0)` indicates EOF or no
/// stdin attached.
fn recv_bytes(ep: u32, ipc_ptr: *mut u64, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: `ipc_ptr` is the calling thread's kernel-registered IPC
    // buffer (TLS slot populated before any user code runs).
    let msg = match unsafe { ipc::ipc_recv(ep, ipc_ptr) } {
        Ok(m) => m,
        Err(_) => {
            return Err(io::const_error!(
                io::ErrorKind::BrokenPipe,
                "seraph stdin ipc_recv failed",
            ));
        }
    };

    let empty_reply = IpcMessage::new(0);
    let label_id = msg.label & 0xFFFF;
    if label_id != STREAM_BYTES {
        // Unexpected label — reply with empty so the sender unblocks, then
        // surface as EOF. A protocol mismatch is not actionable here.
        // SAFETY: `ipc_ptr` is the calling thread's kernel-registered buffer.
        let _ = unsafe { ipc::ipc_reply(&empty_reply, ipc_ptr) };
        return Ok(0);
    }
    let byte_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let n = byte_len.min(buf.len()).min(msg.data_bytes().len());
    buf[..n].copy_from_slice(&msg.data_bytes()[..n]);

    // SAFETY: `ipc_ptr` is the calling thread's kernel-registered buffer.
    let _ = unsafe { ipc::ipc_reply(&empty_reply, ipc_ptr) };
    Ok(n)
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
        let cap = STDIN_CAP.load(Ordering::Acquire);
        let ipc_ptr = current_ipc_buf();
        if ipc_ptr.is_null() || cap == 0 {
            return Ok(0);
        }
        recv_bytes(cap, ipc_ptr, buf)
    }

    fn read_buf(&mut self, mut cursor: BorrowedCursor<'_>) -> io::Result<()> {
        let cap = STDIN_CAP.load(Ordering::Acquire);
        let ipc_ptr = current_ipc_buf();
        if ipc_ptr.is_null() || cap == 0 {
            return Ok(());
        }
        // SAFETY: BorrowedCursor exposes only initialised bytes after the
        // appropriate advance; we allocate a small temporary on the stack to
        // bridge to the byte-slice based recv.
        let mut tmp = [0u8; CHUNK_SIZE];
        let cap_len = cursor.capacity().min(tmp.len());
        let n = recv_bytes(cap, ipc_ptr, &mut tmp[..cap_len])?;
        cursor.append(&tmp[..n]);
        Ok(())
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        for b in bufs.iter_mut() {
            if !b.is_empty() {
                return self.read(b);
            }
        }
        Ok(0)
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
        let cap = STDOUT_CAP.load(Ordering::Acquire);
        let ipc_ptr = current_ipc_buf();
        if ipc_ptr.is_null() || cap == 0 {
            return Ok(buf.len());
        }
        send_bytes(cap, ipc_ptr, buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let cap = STDOUT_CAP.load(Ordering::Acquire);
        let ipc_ptr = current_ipc_buf();
        if ipc_ptr.is_null() || cap == 0 {
            return Ok(bufs.iter().map(|b| b.len()).sum());
        }
        let mut total = 0;
        for b in bufs {
            let n = send_bytes(cap, ipc_ptr, b)?;
            total += n;
            if n < b.len() {
                break;
            }
        }
        Ok(total)
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
        let cap = STDERR_CAP.load(Ordering::Acquire);
        let ipc_ptr = current_ipc_buf();
        if ipc_ptr.is_null() || cap == 0 {
            return Ok(buf.len());
        }
        send_bytes(cap, ipc_ptr, buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let cap = STDERR_CAP.load(Ordering::Acquire);
        let ipc_ptr = current_ipc_buf();
        if ipc_ptr.is_null() || cap == 0 {
            return Ok(bufs.iter().map(|b| b.len()).sum());
        }
        let mut total = 0;
        for b in bufs {
            let n = send_bytes(cap, ipc_ptr, b)?;
            total += n;
            if n < b.len() {
                break;
            }
        }
        Ok(total)
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

pub const STDIN_BUF_SIZE: usize = CHUNK_SIZE;

pub fn is_ebadf(_err: &io::Error) -> bool {
    true
}

pub fn panic_output() -> Option<impl io::Write> {
    // Panic diagnostics go to stderr exclusively. A process whose stderr is
    // unwired was deliberately created without one, and stdout is not a
    // substitute — silently redirecting panic text to stdout crosses the
    // stream semantics the spawner set. Returning `None` when stderr is
    // absent makes the default panic hook drop the message; callers that
    // want a visible panic must wire stderr.
    let cap = STDERR_CAP.load(Ordering::Acquire);
    if current_ipc_buf().is_null() || cap == 0 {
        return None;
    }
    Some(Stderr::new())
}
