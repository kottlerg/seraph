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
use crate::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use ipc::IpcBuf;
use ipc::stream_labels::STREAM_BYTES;
use syscall_abi::MSG_DATA_WORDS_MAX;

/// Maximum bytes per IPC chunk (one full IPC data area).
const CHUNK_SIZE: usize = MSG_DATA_WORDS_MAX * 8;

static STDIN_CAP: AtomicU32 = AtomicU32::new(0);
static STDOUT_CAP: AtomicU32 = AtomicU32::new(0);
static STDERR_CAP: AtomicU32 = AtomicU32::new(0);
static IPC_BUF: AtomicPtr<u64> = AtomicPtr::new(core::ptr::null_mut());

/// Install the three stdio cap slots and the IPC buffer pointer.
///
/// Called from `_start` once the `ProcessInfo` page has been read. The IPC
/// buffer pointer must be the same address registered with
/// `syscall::ipc_buffer_set` and must remain valid for the process lifetime.
/// Each cap slot may be zero, in which case operations on that stream silently
/// drop (writes) or return EOF (reads).
pub fn stdio_init(stdin: u32, stdout: u32, stderr: u32, ipc_buf: *mut u8) {
    STDIN_CAP.store(stdin, Ordering::Release);
    STDOUT_CAP.store(stdout, Ordering::Release);
    STDERR_CAP.store(stderr, Ordering::Release);
    // cast_ptr_alignment: the IPC buffer is page-aligned (4096 bytes),
    // satisfying u64 alignment.
    #[allow(clippy::cast_ptr_alignment)]
    IPC_BUF.store(ipc_buf.cast::<u64>(), Ordering::Release);
}

/// Snapshot the IPC buffer pointer. Returns `None` until `stdio_init` runs.
fn ipc_ptr() -> Option<*mut u64> {
    let buf = IPC_BUF.load(Ordering::Acquire);
    if buf.is_null() { None } else { Some(buf) }
}

/// Best-effort raw write to the stderr cap, used by panic / pre-heap
/// diagnostic paths that cannot afford a `LineWriter` allocation. Silently
/// drops if `stdio_init` has not been called or the stderr slot is zero.
/// Does not fall back to stdout — a process without stderr was created
/// that way intentionally, and cross-stream redirection crosses the
/// semantics the spawner set.
pub(crate) fn diag_write_raw(bytes: &[u8]) {
    let Some(ipc_ptr) = ipc_ptr() else {
        return;
    };
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
    // SAFETY: `ipc_ptr` came from `stdio_init`, which requires it to be the
    // kernel-registered (page-aligned, u64-aligned) IPC buffer.
    let ipc = unsafe { IpcBuf::from_raw(ipc_ptr) };

    let mut offset = 0;
    while offset < total_len {
        let remaining = total_len - offset;
        let chunk_len = remaining.min(CHUNK_SIZE);

        let label = STREAM_BYTES | ((chunk_len as u64 & 0xFFFF) << 16);

        let word_count = chunk_len.div_ceil(8);
        for i in 0..MSG_DATA_WORDS_MAX {
            let mut word: u64 = 0;
            if i < word_count {
                let start = offset + i * 8;
                for j in 0..8 {
                    let idx = start + j;
                    if idx < offset + chunk_len {
                        word |= (bytes[idx] as u64) << (j * 8);
                    }
                }
            }
            ipc.write_word(i, word);
        }

        if syscall::ipc_call(ep, label, word_count, &[]).is_err() {
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
    let (label, _token) = match syscall::ipc_recv(ep) {
        Ok(v) => v,
        Err(_) => {
            return Err(io::const_error!(
                io::ErrorKind::BrokenPipe,
                "seraph stdin ipc_recv failed",
            ));
        }
    };

    let label_id = label & 0xFFFF;
    if label_id != STREAM_BYTES {
        // Unexpected label — reply with empty so the sender unblocks, then
        // surface as EOF. A protocol mismatch is not actionable here.
        let _ = syscall::ipc_reply(0, 0, &[]);
        return Ok(0);
    }
    let byte_len = ((label >> 16) & 0xFFFF) as usize;

    // SAFETY: stdin's IPC buffer is the same page registered with
    // `ipc_buffer_set` (via stdio_init). u64-aligned by virtue of being
    // page-aligned.
    let ipc = unsafe { IpcBuf::from_raw(ipc_ptr) };

    let n = byte_len.min(buf.len());
    let word_count = n.div_ceil(8);
    for i in 0..word_count {
        let word = ipc.read_word(i);
        let base = i * 8;
        for j in 0..8 {
            let idx = base + j;
            if idx < n {
                buf[idx] = ((word >> (j * 8)) & 0xFF) as u8;
            }
        }
    }

    let _ = syscall::ipc_reply(0, 0, &[]);
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
        let Some(ipc_ptr) = ipc_ptr() else {
            return Ok(0);
        };
        if cap == 0 {
            return Ok(0);
        }
        recv_bytes(cap, ipc_ptr, buf)
    }

    fn read_buf(&mut self, mut cursor: BorrowedCursor<'_>) -> io::Result<()> {
        let cap = STDIN_CAP.load(Ordering::Acquire);
        let Some(ipc_ptr) = ipc_ptr() else {
            return Ok(());
        };
        if cap == 0 {
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
        let Some(ipc_ptr) = ipc_ptr() else {
            return Ok(buf.len());
        };
        if cap == 0 {
            return Ok(buf.len());
        }
        send_bytes(cap, ipc_ptr, buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let cap = STDOUT_CAP.load(Ordering::Acquire);
        let Some(ipc_ptr) = ipc_ptr() else {
            return Ok(bufs.iter().map(|b| b.len()).sum());
        };
        if cap == 0 {
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
        let Some(ipc_ptr) = ipc_ptr() else {
            return Ok(buf.len());
        };
        if cap == 0 {
            return Ok(buf.len());
        }
        send_bytes(cap, ipc_ptr, buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let cap = STDERR_CAP.load(Ordering::Acquire);
        let Some(ipc_ptr) = ipc_ptr() else {
            return Ok(bufs.iter().map(|b| b.len()).sum());
        };
        if cap == 0 {
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
    let ipc = IPC_BUF.load(Ordering::Acquire);
    if ipc.is_null() || cap == 0 {
        return None;
    }
    Some(Stderr::new())
}
