// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/logging.rs

//! Logging subsystem for init.
//!
//! Two halves:
//!
//! * **Sender side (init's own log line emission):** early boot writes
//!   directly to the serial port; once the log thread is up, init's main
//!   thread switches to the same `STREAM_BYTES` IPC path that std-built
//!   services use, with a tokened SEND cap carrying `b"init"` so the
//!   receiver attributes init's lines correctly.
//!
//! * **Receiver side (`log_receive_loop`):** the dedicated log thread
//!   loops on `ipc_recv` over the master log endpoint. Each message
//!   carries a `STREAM_BYTES` label, the sender's token (delivered by the
//!   kernel from the tokened SEND cap they hold), and a length-prefixed
//!   payload. The thread maintains a small per-token line buffer; on
//!   `\n` it emits `[name] <line>\r\n` to the serial port.

use crate::arch;
use crate::{FrameAlloc, PAGE_SIZE};
use init_protocol::InitInfo;

use ipc::stream_labels::STREAM_BYTES;

// ── Constants ────────────────────────────────────────────────────────────────

use va_layout::{
    INIT_LOG_THREAD_IPC_BUF_VA as LOG_THREAD_IPC_BUF_VA,
    INIT_LOG_THREAD_STACK_VA as LOG_THREAD_STACK_VA,
};

/// Number of stack pages for the log thread (16 KiB).
const LOG_THREAD_STACK_PAGES: u64 = 4;

/// Max bytes per IPC chunk. Must match `MSG_DATA_WORDS_MAX * 8` from `syscall_abi`.
const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// Per-sender line-buffer size in the log receiver. Lines longer than this
/// are flushed without a trailing newline.
const LINE_BUF_SIZE: usize = 256;

/// Maximum number of distinct sender tokens the log receiver tracks at once.
const MAX_SENDERS: usize = 16;

// ── Mutable state (sender side, main-thread bound) ──────────────────────────

/// Tokened SEND cap on the log endpoint that init's own `log()` writes to.
/// Set after the log thread is up. Zero before then; falls back to direct
/// serial output.
static mut INIT_LOG_SEND: u32 = 0;

/// IPC buffer pointer for the main thread (set after IPC buffer is mapped).
static mut MAIN_IPC_BUF: *mut u64 = core::ptr::null_mut();

// ── Public interface ─────────────────────────────────────────────────────────

/// Log a message. Uses direct serial before the log thread is running,
/// then switches to IPC-based logging through the log thread.
pub fn log(s: &str)
{
    // SAFETY: INIT_LOG_SEND and MAIN_IPC_BUF are written once by the main
    // thread before any IPC log call; log thread only reads its own argument.
    let cap = unsafe { INIT_LOG_SEND };
    // SAFETY: see above.
    let ipc_buf = unsafe { MAIN_IPC_BUF };

    if cap != 0 && !ipc_buf.is_null()
    {
        ipc_log(cap, ipc_buf, s.as_bytes());
        // Append a newline so the receiver flushes the line.
        ipc_log(cap, ipc_buf, b"\n");
    }
    else
    {
        serial_log(s);
    }
}

/// Switch the main thread from direct serial to IPC-based logging.
///
/// Must be called exactly once after the log thread has started. `cap` must
/// be a tokened SEND cap on the log endpoint with the token identifying the
/// sender (`pack_name(b"init")` for init's own diagnostics).
pub fn set_ipc_logging(cap: u32, ipc_buf: *mut u64)
{
    // SAFETY: single main thread; log thread only reads its own argument.
    unsafe {
        INIT_LOG_SEND = cap;
        MAIN_IPC_BUF = ipc_buf;
    }
}

// ── Serial output ────────────────────────────────────────────────────────────

/// Direct serial output (early boot, before log thread exists).
pub(crate) fn serial_log(s: &str)
{
    for &b in s.as_bytes()
    {
        if b == b'\n'
        {
            arch::current::serial_write_byte(b'\r');
        }
        arch::current::serial_write_byte(b);
    }
    arch::current::serial_write_byte(b'\r');
    arch::current::serial_write_byte(b'\n');
}

// ── Stream byte sender (matches ruststd's stdio path) ──────────────────────

/// Send up to `STREAM_CHUNK_SIZE` bytes per IPC call on `cap` using the
/// `STREAM_BYTES` label. Sends multiple calls if `bytes` exceeds the chunk
/// size; the receiver concatenates each call's payload in order.
fn ipc_log(cap: u32, ipc_buf: *mut u64, bytes: &[u8])
{
    if bytes.is_empty()
    {
        return;
    }
    // SAFETY: ipc_buf was registered by the caller (init main thread).
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };

    let mut offset = 0;
    while offset < bytes.len()
    {
        let chunk_len = (bytes.len() - offset).min(STREAM_CHUNK_SIZE);
        let label = STREAM_BYTES | ((chunk_len as u64 & 0xFFFF) << 16);
        let word_count = chunk_len.div_ceil(8);

        for i in 0..syscall_abi::MSG_DATA_WORDS_MAX
        {
            let mut word: u64 = 0;
            if i < word_count
            {
                let base = offset + i * 8;
                for j in 0..8
                {
                    let idx = base + j;
                    if idx < offset + chunk_len
                    {
                        word |= u64::from(bytes[idx]) << (j * 8);
                    }
                }
            }
            ipc.write_word(i, word);
        }

        let _ = syscall::ipc_call(cap, label, word_count, &[]);
        offset += chunk_len;
    }
}

// ── Token packing helpers (also used by service.rs) ─────────────────────────

/// Pack up to 8 ASCII bytes into a u64. Used as the `cap_derive_token` value
/// for per-service stdio attribution. Truncates names longer than 8 bytes.
#[must_use]
pub fn pack_name(name: &[u8]) -> u64
{
    let mut buf = [0u8; 8];
    let n = name.len().min(8);
    buf[..n].copy_from_slice(&name[..n]);
    u64::from_le_bytes(buf)
}

// ── Log thread ───────────────────────────────────────────────────────────────

/// Spawn a dedicated log-receiving thread so the main thread can continue
/// bootstrap orchestration (making IPC calls to vfsd etc.) without blocking
/// service log output.
pub fn spawn_log_thread(info: &InitInfo, alloc: &mut FrameAlloc, log_ep: u32, ioport_cap: u32)
{
    // Allocate stack pages for the log thread.
    for i in 0..LOG_THREAD_STACK_PAGES
    {
        let Some(frame) = alloc.alloc_page()
        else
        {
            log("init: FATAL: cannot allocate log thread stack");
            syscall::thread_exit();
        };
        let Ok(rw_cap) = syscall::cap_derive(frame, syscall::RIGHTS_MAP_RW)
        else
        {
            log("init: FATAL: cannot derive log thread stack cap");
            syscall::thread_exit();
        };
        if syscall::mem_map(
            rw_cap,
            info.aspace_cap,
            LOG_THREAD_STACK_VA + i * PAGE_SIZE,
            0,
            1,
            0,
        )
        .is_err()
        {
            log("init: FATAL: cannot map log thread stack");
            syscall::thread_exit();
        }
    }

    // Allocate IPC buffer page for the log thread.
    let Some(ipc_frame) = alloc.alloc_page()
    else
    {
        log("init: FATAL: cannot allocate log thread IPC buffer");
        syscall::thread_exit();
    };
    let Ok(ipc_rw_cap) = syscall::cap_derive(ipc_frame, syscall::RIGHTS_MAP_RW)
    else
    {
        log("init: FATAL: cannot derive log thread IPC cap");
        syscall::thread_exit();
    };
    if syscall::mem_map(ipc_rw_cap, info.aspace_cap, LOG_THREAD_IPC_BUF_VA, 0, 1, 0).is_err()
    {
        log("init: FATAL: cannot map log thread IPC buffer");
        syscall::thread_exit();
    }
    // Zero the IPC buffer.
    // SAFETY: LOG_THREAD_IPC_BUF_VA is mapped writable and covers one page.
    unsafe { core::ptr::write_bytes(LOG_THREAD_IPC_BUF_VA as *mut u8, 0, PAGE_SIZE as usize) };

    // Create the thread bound to init's address space and CSpace.
    let Ok(thread_cap) = syscall::cap_create_thread(info.aspace_cap, info.cspace_cap)
    else
    {
        log("init: FATAL: cannot create log thread");
        syscall::thread_exit();
    };

    // Bind I/O ports to the log thread so it can write to the serial port.
    // On x86-64, I/O port access is per-thread via the TSS IOPB.
    if ioport_cap != 0 && syscall::ioport_bind(thread_cap, ioport_cap).is_err()
    {
        log("init: log thread: ioport_bind failed");
    }

    let stack_top = LOG_THREAD_STACK_VA + LOG_THREAD_STACK_PAGES * PAGE_SIZE;

    // Pack log_ep (u32) into the arg passed to the thread.
    let arg = u64::from(log_ep);

    if syscall::thread_configure(
        thread_cap,
        log_thread_entry as *const () as u64,
        stack_top,
        arg,
    )
    .is_err()
    {
        log("init: FATAL: cannot configure log thread");
        syscall::thread_exit();
    }
    if syscall::thread_start(thread_cap).is_err()
    {
        log("init: FATAL: cannot start log thread");
        syscall::thread_exit();
    }
}

/// Entry point for the log thread. Registers its own IPC buffer then enters
/// the log receive loop. Never returns.
///
/// Called via `thread_configure` with `arg` = log endpoint cap slot (RECV).
extern "C" fn log_thread_entry(arg: u64) -> !
{
    // Register this thread's IPC buffer.
    if syscall::ipc_buffer_set(LOG_THREAD_IPC_BUF_VA).is_err()
    {
        serial_log("init: log thread: ipc_buffer_set failed");
        syscall::thread_exit();
    }

    let log_ep = arg as u32;

    // SAFETY: LOG_THREAD_IPC_BUF_VA is the registered IPC buffer, page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = LOG_THREAD_IPC_BUF_VA as *mut u64;

    log_receive_loop(log_ep, ipc_buf);
}

// ── Log receive loop ─────────────────────────────────────────────────────────

/// Per-sender state: the sender's token (== identity, packed name) and a
/// short buffer of bytes accumulated since the last newline.
#[derive(Clone, Copy)]
struct SenderSlot
{
    token: u64,
    buf: [u8; LINE_BUF_SIZE],
    used: usize,
}

impl SenderSlot
{
    const fn empty() -> Self
    {
        Self {
            token: 0,
            buf: [0u8; LINE_BUF_SIZE],
            used: 0,
        }
    }
}

/// Receive byte-stream messages from services and write them to the serial
/// port, prefixing each line with the sender's `[name]` (extracted from the
/// per-message kernel-delivered token).
fn log_receive_loop(log_ep: u32, ipc_buf_raw: *mut u64) -> !
{
    // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
    let ipc = unsafe { ipc::IpcBuf::from_raw(ipc_buf_raw) };
    let mut slots: [SenderSlot; MAX_SENDERS] = [SenderSlot::empty(); MAX_SENDERS];
    // Round-robin pointer used to evict when all slots are in use.
    let mut next_evict: usize = 0;

    loop
    {
        let Ok((label, token)) = syscall::ipc_recv(log_ep)
        else
        {
            continue;
        };

        let label_id = label & 0xFFFF;
        if label_id == STREAM_BYTES
        {
            let byte_len = ((label >> 16) & 0xFFFF) as usize;
            consume_bytes(&mut slots, &mut next_evict, ipc, token, byte_len);
        }

        // Reply to unblock the sender (call/reply protocol; payload empty).
        let _ = syscall::ipc_reply(0, 0, &[]);
    }
}

/// Append `byte_len` bytes from the IPC buffer onto the slot for `token`,
/// flushing complete lines (`\n`-terminated) to the serial port as `[name] <line>\r\n`.
fn consume_bytes(
    slots: &mut [SenderSlot; MAX_SENDERS],
    next_evict: &mut usize,
    ipc: ipc::IpcBuf,
    token: u64,
    byte_len: usize,
)
{
    let len = byte_len.min(STREAM_CHUNK_SIZE);
    let word_count = len.div_ceil(8);
    // Stack temporary so we can iterate after extracting from IPC words.
    let mut tmp = [0u8; STREAM_CHUNK_SIZE];
    for i in 0..word_count
    {
        let word = ipc.read_word(i);
        let base = i * 8;
        for j in 0..8
        {
            let idx = base + j;
            if idx < len
            {
                tmp[idx] = ((word >> (j * 8)) & 0xFF) as u8;
            }
        }
    }

    let slot_idx = find_or_alloc_slot(slots, next_evict, token);
    for &b in &tmp[..len]
    {
        if b == b'\n'
        {
            flush_line(&slots[slot_idx]);
            slots[slot_idx].used = 0;
        }
        else if slots[slot_idx].used < LINE_BUF_SIZE
        {
            let used = slots[slot_idx].used;
            slots[slot_idx].buf[used] = b;
            slots[slot_idx].used += 1;
            // Buffer full — flush to keep the prefix visible.
            if slots[slot_idx].used == LINE_BUF_SIZE
            {
                flush_line(&slots[slot_idx]);
                slots[slot_idx].used = 0;
            }
        }
    }
}

/// Find the slot for `token`, or claim a free one. If all slots are used,
/// evict the round-robin victim (its partial line is dropped).
fn find_or_alloc_slot(
    slots: &mut [SenderSlot; MAX_SENDERS],
    next_evict: &mut usize,
    token: u64,
) -> usize
{
    for (i, s) in slots.iter().enumerate()
    {
        if s.token == token && s.token != 0
        {
            return i;
        }
    }
    for (i, s) in slots.iter_mut().enumerate()
    {
        if s.token == 0
        {
            s.token = token;
            s.used = 0;
            return i;
        }
    }
    // Eviction.
    let victim = *next_evict % MAX_SENDERS;
    *next_evict = (victim + 1) % MAX_SENDERS;
    slots[victim].token = token;
    slots[victim].used = 0;
    victim
}

/// Emit `[name] <buffered bytes>\r\n` to the serial port. `name` is unpacked
/// from `slot.token` (trailing zeros stripped). Anonymous senders (token = 0)
/// get `[?]`.
fn flush_line(slot: &SenderSlot)
{
    arch::current::serial_write_byte(b'[');
    if slot.token == 0
    {
        arch::current::serial_write_byte(b'?');
    }
    else
    {
        let name_bytes = slot.token.to_le_bytes();
        for &b in &name_bytes
        {
            if b == 0
            {
                break;
            }
            arch::current::serial_write_byte(b);
        }
    }
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    for &b in &slot.buf[..slot.used]
    {
        if b == b'\n'
        {
            arch::current::serial_write_byte(b'\r');
        }
        arch::current::serial_write_byte(b);
    }
    arch::current::serial_write_byte(b'\r');
    arch::current::serial_write_byte(b'\n');
}
