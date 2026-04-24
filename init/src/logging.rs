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

/// Maximum per-slot display-name length in bytes. Sized for typical
/// contextual names like `"fatfs /some/deeply/nested/mount"`. Longer names
/// are truncated.
const MAX_NAME_LEN: usize = 48;

// ── Mutable state (sender side, main-thread bound) ──────────────────────────

/// Tokened SEND cap on the log endpoint that init's own `log()` writes to.
/// Set after the log thread is up. Zero before then; falls back to direct
/// serial output.
static mut INIT_LOG_SEND: u32 = 0;

/// IPC buffer pointer for the main thread (set after IPC buffer is mapped).
static mut MAIN_IPC_BUF: *mut u64 = core::ptr::null_mut();

/// Init's full-rights cap on the system log endpoint, retained as the
/// source for deriving tokened SEND caps for the handful of services init
/// spawns directly during early boot (procmgr, devmgr, vfsd, svcmgr,
/// crasher, usertest, ...). Zero until `set_log_ep` is called right after
/// the log thread starts.
static mut INIT_LOG_EP: u32 = 0;

/// Init's own `CSpace` cap, stashed at startup so `derive_log_stdio_pair`
/// can `cap_copy` within init's `CSpace` to produce a second slot pointing
/// at the same tokened endpoint. Zero until `set_cspace_cap` is called.
static mut INIT_CSPACE: u32 = 0;

/// Monotonic counter for init-reserved log stream tokens. Range 2..=16 is
/// reserved for services init spawns directly; procmgr's `NEXT_LOG_TOKEN`
/// starts at 1024 to guarantee no overlap. Token 1 is init's own self-cap.
static INIT_NEXT_LOG_TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(2);

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
/// sender (token `1` — init's self-identity — for init's own diagnostics).
pub fn set_ipc_logging(cap: u32, ipc_buf: *mut u64)
{
    // SAFETY: single main thread; log thread only reads its own argument.
    unsafe {
        INIT_LOG_SEND = cap;
        MAIN_IPC_BUF = ipc_buf;
    }
}

/// Install the init-retained log endpoint cap so [`derive_log_output_cap`]
/// can mint per-child tokened SEND caps for direct spawns.
pub fn set_log_ep(log_ep: u32)
{
    // SAFETY: single main thread; only main reads this.
    unsafe {
        INIT_LOG_EP = log_ep;
    }
}

/// Install init's own `CSpace` cap so the log-stdio pair helpers can
/// `cap_copy` within init's `CSpace`.
pub fn set_cspace_cap(cspace: u32)
{
    // SAFETY: single main thread; only main reads this.
    unsafe {
        INIT_CSPACE = cspace;
    }
}

/// Derive a tokened SEND cap on init's log endpoint for a child process's
/// stdout/stderr. Token is drawn from init's reserved range (2..=16) so it
/// does not collide with procmgr-minted tokens (starting at 1024).
///
/// Returns zero on failure (`log_ep` not installed, `cap_derive_token`
/// refused, or reserved range exhausted). Callers typically use
/// [`derive_log_stdio_pair`] instead — it returns two slots that both
/// refer to the same tokened endpoint and are ready to hand to
/// `CONFIGURE_STDIO` as stdout + stderr.
pub fn derive_log_output_cap() -> u32
{
    use core::sync::atomic::Ordering;
    // SAFETY: see above — single main thread reads INIT_LOG_EP.
    let log_ep = unsafe { INIT_LOG_EP };
    if log_ep == 0
    {
        return 0;
    }
    let token = INIT_NEXT_LOG_TOKEN.fetch_add(1, Ordering::Relaxed);
    if token > 16
    {
        // Reserved range exhausted — refuse rather than collide with
        // procmgr's range. Caller logs the failure.
        return 0;
    }
    syscall::cap_derive_token(log_ep, syscall::RIGHTS_SEND, token).unwrap_or(0)
}

/// Derive a pair of tokened SEND caps on init's log endpoint that both
/// refer to the same underlying cap (same endpoint + same token). Meant
/// for `CONFIGURE_STDIO`: one slot used for `stdout_cap`, the other for
/// `stderr_cap`, so the mediator attributes both writes to the same
/// registered display name.
///
/// Returns `(stdout_slot, stderr_slot)`. Either is zero on failure.
pub fn derive_log_stdio_pair() -> (u32, u32)
{
    let stdout = derive_log_output_cap();
    if stdout == 0
    {
        return (0, 0);
    }
    // SAFETY: single main thread; INIT_CSPACE is written once at startup.
    let cspace = unsafe { INIT_CSPACE };
    if cspace == 0
    {
        return (stdout, 0);
    }
    let stderr = syscall::cap_copy(stdout, cspace, syscall::RIGHTS_SEND).unwrap_or(0);
    (stdout, stderr)
}

/// Send a `STREAM_REGISTER_NAME` message on init's own log SEND cap so the
/// mediator labels `[init]` lines correctly. Must be called exactly once
/// after `set_ipc_logging`.
pub fn register_name(name: &[u8])
{
    // SAFETY: INIT_LOG_SEND and MAIN_IPC_BUF are written once by the main
    // thread; log thread only reads its own argument.
    let cap = unsafe { INIT_LOG_SEND };
    // SAFETY: see above.
    let ipc_buf = unsafe { MAIN_IPC_BUF };
    if cap == 0 || ipc_buf.is_null() || name.is_empty()
    {
        return;
    }
    let len = name.len().min(STREAM_CHUNK_SIZE);
    let label = ipc::stream_labels::STREAM_REGISTER_NAME | ((len as u64 & 0xFFFF) << 16);
    let msg = ipc::IpcMessage::builder(label)
        .bytes(0, &name[..len])
        .build();
    // SAFETY: ipc_buf registered by main thread.
    let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
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

    let mut offset = 0;
    while offset < bytes.len()
    {
        let chunk_len = (bytes.len() - offset).min(STREAM_CHUNK_SIZE);
        let label = STREAM_BYTES | ((chunk_len as u64 & 0xFFFF) << 16);
        let msg = ipc::IpcMessage::builder(label)
            .bytes(0, &bytes[offset..offset + chunk_len])
            .build();
        // SAFETY: ipc_buf was registered by the caller (init main thread).
        let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
        offset += chunk_len;
    }
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

/// Per-sender state: the sender's token (opaque u64 identity), the display
/// name registered via `STREAM_REGISTER_NAME`, and the bytes accumulated
/// since the last newline.
#[derive(Clone, Copy)]
struct SenderSlot
{
    token: u64,
    name: [u8; MAX_NAME_LEN],
    name_used: usize,
    buf: [u8; LINE_BUF_SIZE],
    used: usize,
}

impl SenderSlot
{
    const fn empty() -> Self
    {
        Self {
            token: 0,
            name: [0u8; MAX_NAME_LEN],
            name_used: 0,
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
    let mut slots: [SenderSlot; MAX_SENDERS] = [SenderSlot::empty(); MAX_SENDERS];
    // Round-robin pointer used to evict when all slots are in use.
    let mut next_evict: usize = 0;

    loop
    {
        // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
        let Ok(recv) = (unsafe { ipc::ipc_recv(log_ep, ipc_buf_raw) })
        else
        {
            continue;
        };

        let label_id = recv.label & 0xFFFF;
        let byte_len = ((recv.label >> 16) & 0xFFFF) as usize;
        if label_id == STREAM_BYTES
        {
            consume_bytes(&mut slots, &mut next_evict, &recv, recv.token, byte_len);
        }
        else if label_id == ipc::stream_labels::STREAM_REGISTER_NAME
        {
            register_sender_name(&mut slots, &mut next_evict, &recv, recv.token, byte_len);
        }

        // Reply to unblock the sender (call/reply protocol; payload empty).
        // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(0), ipc_buf_raw) };
    }
}

/// Record a display name for the sender identified by `token`. Called from
/// `log_receive_loop` when a `STREAM_REGISTER_NAME` message arrives.
/// Idempotent — later registrations replace earlier.
fn register_sender_name(
    slots: &mut [SenderSlot; MAX_SENDERS],
    next_evict: &mut usize,
    msg: &ipc::IpcMessage,
    token: u64,
    byte_len: usize,
)
{
    let bytes = msg.data_bytes();
    let len = byte_len.min(bytes.len()).min(MAX_NAME_LEN);
    let slot_idx = find_or_alloc_slot(slots, next_evict, token);
    slots[slot_idx].name[..len].copy_from_slice(&bytes[..len]);
    slots[slot_idx].name_used = len;
}

/// Append `byte_len` bytes from the IPC buffer onto the slot for `token`,
/// flushing complete lines (`\n`-terminated) to the serial port as `[name] <line>\r\n`.
fn consume_bytes(
    slots: &mut [SenderSlot; MAX_SENDERS],
    next_evict: &mut usize,
    msg: &ipc::IpcMessage,
    token: u64,
    byte_len: usize,
)
{
    let len = byte_len.min(STREAM_CHUNK_SIZE);
    let bytes = msg.data_bytes();
    let copy_len = len.min(bytes.len());
    let mut tmp = [0u8; STREAM_CHUNK_SIZE];
    tmp[..copy_len].copy_from_slice(&bytes[..copy_len]);
    let len = copy_len;

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

/// Emit `[sec.usfrac] [name] <buffered bytes>\r\n` to the serial port.
/// `[name]` uses the display name registered via `STREAM_REGISTER_NAME`;
/// senders that have not registered yet render as `[?]`.
fn flush_line(slot: &SenderSlot)
{
    // ── Timestamp: [sec.usfrac:06] ─────────────────────────────────────
    //
    // Source: `SYS_SYSTEM_INFO(ElapsedUs)` — kernel handler returns
    // `unwrap_or(0)` and never errors. Format matches the kernel's
    // `[sec.usfrac:06] ` prefix in `kernel/src/console.rs`.
    let us = syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let sec = us / 1_000_000;
    let usfrac = (us % 1_000_000) as u32;

    arch::current::serial_write_byte(b'[');
    write_decimal(sec);
    arch::current::serial_write_byte(b'.');
    write_decimal_padded(u64::from(usfrac), 6);
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    // ── Name: [<registered name>] or [?] ───────────────────────────────
    arch::current::serial_write_byte(b'[');
    if slot.name_used == 0
    {
        arch::current::serial_write_byte(b'?');
    }
    else
    {
        for &b in &slot.name[..slot.name_used]
        {
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

/// Write `value` as base-10 ASCII to the serial port with no padding.
fn write_decimal(value: u64)
{
    let mut buf = [0u8; 20];
    let mut n = value;
    let mut idx = buf.len();
    if n == 0
    {
        idx -= 1;
        buf[idx] = b'0';
    }
    else
    {
        while n > 0
        {
            idx -= 1;
            buf[idx] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    for &b in &buf[idx..]
    {
        arch::current::serial_write_byte(b);
    }
}

/// Write `value` as zero-padded base-10 ASCII of exactly `width` digits.
/// `width` must be <= 20 (max decimal digits in a u64).
fn write_decimal_padded(value: u64, width: usize)
{
    let mut buf = [b'0'; 20];
    let mut n = value;
    let mut idx = buf.len();
    while n > 0 && idx > 0
    {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let start = buf.len().saturating_sub(width);
    for &b in &buf[start..]
    {
        arch::current::serial_write_byte(b);
    }
}
