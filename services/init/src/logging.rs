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

use ipc::log_labels::GET_LOG_CAP;
use ipc::stream_labels::STREAM_BYTES;

// ── Constants ────────────────────────────────────────────────────────────────
//
// init's log-thread VAs sit one page above its main IPC buffer to keep
// the two adjacent for human readability of address dumps; both live in
// init's private no_std VA space (init does not use the std page-
// reservation allocator).

/// init log-thread IPC buffer (one page above the main IPC buffer).
const LOG_THREAD_IPC_BUF_VA: u64 = crate::INIT_IPC_BUF_VA + crate::PAGE_SIZE;

/// init log-thread stack base.
const LOG_THREAD_STACK_VA: u64 = 0x0000_0000_D000_0000;

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

/// Monotonic counter for tokens minted on the `GET_LOG_CAP` discovery
/// path. Token 0 is reserved for the untokened sentinel; token 1 is
/// reserved for init's self-identity cap, derived directly from the
/// log endpoint init owns; every other process gets its token from
/// this counter.
static INIT_DISCOVERY_NEXT_TOKEN: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(2);

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

    // Reserve a Thread-retype slab and create the log thread bound to
    // init's address space and CSpace.
    let Some(thread_slab) = alloc.alloc_pages(crate::THREAD_RETYPE_PAGES)
    else
    {
        log("init: FATAL: cannot allocate log thread frame slab");
        syscall::thread_exit();
    };
    let Ok(thread_cap) = syscall::cap_create_thread(thread_slab, info.aspace_cap, info.cspace_cap)
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
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(0), ipc_buf_raw) };
        }
        else if label_id == ipc::stream_labels::STREAM_REGISTER_NAME
        {
            register_sender_name(&mut slots, &mut next_evict, &recv, recv.token, byte_len);
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(0), ipc_buf_raw) };
        }
        else if label_id == GET_LOG_CAP
        {
            if recv.word(0) == u64::from(ipc::LOG_LABELS_VERSION)
            {
                handle_get_log_cap(log_ep, ipc_buf_raw);
                // handle_get_log_cap performs its own ipc_reply (with the
                // minted cap or an error code), so we do not double-reply
                // here.
            }
            else
            {
                // Caller built against a different `shared/ipc` revision;
                // reject before minting a token. Reply code 3 is local to
                // GET_LOG_CAP's reply vocabulary (0=success, 1=token
                // counter wrap, 2=cap_derive failure, 3=version mismatch).
                // SAFETY: ipc_buf_raw is the log thread's registered IPC
                // buffer page.
                let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(3), ipc_buf_raw) };
            }
        }
        else
        {
            // Unknown label — reply empty so the sender unblocks.
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(0), ipc_buf_raw) };
        }
    }
}

/// Handler for `log_labels::GET_LOG_CAP`. Mints a fresh tokened SEND cap
/// on the system log endpoint (token=0 reserved as the untokened sentinel,
/// token=1 reserved for init's self-identity), transfers it back to the
/// caller in the reply, and frees our local slot when the kernel performs
/// the transfer.
fn handle_get_log_cap(log_ep: u32, ipc_buf: *mut u64)
{
    use core::sync::atomic::Ordering;

    let token = INIT_DISCOVERY_NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    if token == 0
    {
        // Counter wrapped — vanishingly unlikely (u64), but bail rather
        // than mint a token that aliases the untokened sentinel.
        flush_synthetic_logd_line(b"GET_LOG_CAP: token counter wrapped");
        // SAFETY: ipc_buf is the log thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(1), ipc_buf) };
        return;
    }

    let Ok(cap) = syscall::cap_derive_token(log_ep, syscall::RIGHTS_SEND, token)
    else
    {
        // SAFETY: ipc_buf is the log thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(2), ipc_buf) };
        return;
    };

    let reply = ipc::IpcMessage::builder(0).cap(cap).build();
    // SAFETY: ipc_buf is the log thread's registered IPC buffer page;
    // the kernel transfers the cap from init's CSpace to the caller's
    // CSpace, so the local slot is released.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Record a display name for the sender identified by `token`. Called
/// from `log_receive_loop` when a `STREAM_REGISTER_NAME` message
/// arrives. Implements the roadmap collision-suffix policy:
///
/// * Re-registration by the same token with its own current name is a
///   silent no-op (no map mutation, no synthetic line).
/// * Otherwise the sender's previous name slot is freed first, then the
///   requested name is resolved against the rest of the table — if
///   another active token holds the bare name, the applicant is stored
///   as `name.2`, `name.3`, …; the first free suffix wins.
/// * Every non-no-op registration emits a synthetic
///   `[init-logd] token=<N> registered name='<stored-name>'` line so the
///   full `token → name` history is reconstructable from log output
///   alone.
fn register_sender_name(
    slots: &mut [SenderSlot; MAX_SENDERS],
    next_evict: &mut usize,
    msg: &ipc::IpcMessage,
    token: u64,
    byte_len: usize,
)
{
    let bytes = msg.data_bytes();
    let requested_len = byte_len.min(bytes.len()).min(MAX_NAME_LEN);
    if requested_len == 0
    {
        return;
    }
    let requested = &bytes[..requested_len];

    let slot_idx = find_or_alloc_slot(slots, next_evict, token);

    // Same token, same current name — silent no-op.
    if slots[slot_idx].name_used == requested_len
        && &slots[slot_idx].name[..slots[slot_idx].name_used] == requested
    {
        return;
    }

    // Free this token's current name before resolving collisions, so a
    // rename liberates the previous slot for the new applicant.
    slots[slot_idx].name_used = 0;
    slots[slot_idx].name = [0u8; MAX_NAME_LEN];

    let mut stored = [0u8; MAX_NAME_LEN];
    let stored_len = resolve_unique_name(slots, requested, &mut stored);

    slots[slot_idx].name[..stored_len].copy_from_slice(&stored[..stored_len]);
    slots[slot_idx].name_used = stored_len;

    emit_registration_event(token, &stored[..stored_len]);
}

/// Try the bare `requested` name first; if any other active slot
/// already holds that exact name, append `.2`, `.3`, … until a free
/// candidate is found. Writes the chosen bytes into `out` and returns
/// the byte count. If every suffix collides the bare name is returned
/// (collision is preserved rather than dropped — the synthetic line
/// will still reflect what was stored).
fn resolve_unique_name(
    slots: &[SenderSlot; MAX_SENDERS],
    requested: &[u8],
    out: &mut [u8; MAX_NAME_LEN],
) -> usize
{
    if !name_in_use(slots, requested)
    {
        let n = requested.len().min(out.len());
        out[..n].copy_from_slice(&requested[..n]);
        return n;
    }
    let max_suffix = (MAX_SENDERS as u32) + 1;
    let mut suffix: u32 = 2;
    while suffix <= max_suffix
    {
        let n = compose_suffixed(requested, suffix, out);
        if !name_in_use(slots, &out[..n])
        {
            return n;
        }
        suffix += 1;
    }
    let n = requested.len().min(out.len());
    out[..n].copy_from_slice(&requested[..n]);
    n
}

/// Return `true` if any active slot already stores `name` verbatim.
fn name_in_use(slots: &[SenderSlot; MAX_SENDERS], name: &[u8]) -> bool
{
    slots
        .iter()
        .any(|s| s.token != 0 && s.name_used == name.len() && &s.name[..s.name_used] == name)
}

/// Write `name` followed by `.<n>` into `out`, return the total byte
/// count. Truncates if the composed form exceeds [`MAX_NAME_LEN`].
fn compose_suffixed(name: &[u8], n: u32, out: &mut [u8; MAX_NAME_LEN]) -> usize
{
    let copy_len = name.len().min(out.len());
    out[..copy_len].copy_from_slice(&name[..copy_len]);
    let mut idx = copy_len;
    if idx < out.len()
    {
        out[idx] = b'.';
        idx += 1;
    }
    let mut digits = [0u8; 10];
    let mut dlen = 0;
    let mut value = n;
    if value == 0
    {
        digits[0] = b'0';
        dlen = 1;
    }
    else
    {
        while value > 0 && dlen < digits.len()
        {
            digits[dlen] = b'0' + (value % 10) as u8;
            dlen += 1;
            value /= 10;
        }
    }
    while dlen > 0 && idx < out.len()
    {
        dlen -= 1;
        out[idx] = digits[dlen];
        idx += 1;
    }
    idx
}

/// Emit a synthetic registration-event line attributed to the receiver
/// itself: `[sec.usfrac] [init-logd] token=<N> registered name='<name>'`.
/// Bypasses the slot machinery so it does not interfere with active
/// senders' line buffers.
fn emit_registration_event(token: u64, name: &[u8])
{
    let mut payload = [0u8; LINE_BUF_SIZE];
    let mut idx = 0usize;

    let prefix = b"token=";
    for &b in prefix
    {
        if idx < payload.len()
        {
            payload[idx] = b;
            idx += 1;
        }
    }
    idx = write_decimal_into(token, &mut payload, idx);
    let middle = b" registered name='";
    for &b in middle
    {
        if idx < payload.len()
        {
            payload[idx] = b;
            idx += 1;
        }
    }
    let name_room = payload.len().saturating_sub(idx + 1);
    let name_len = name.len().min(name_room);
    if name_len > 0
    {
        payload[idx..idx + name_len].copy_from_slice(&name[..name_len]);
        idx += name_len;
    }
    if idx < payload.len()
    {
        payload[idx] = b'\'';
        idx += 1;
    }

    flush_synthetic_logd_line(&payload[..idx]);
}

/// Write `value` as base-10 ASCII into `buf` starting at `start`,
/// returning the new write index. Caps at `buf.len()`.
fn write_decimal_into(value: u64, buf: &mut [u8; LINE_BUF_SIZE], start: usize) -> usize
{
    let mut digits = [0u8; 20];
    let mut dlen = 0;
    let mut n = value;
    if n == 0
    {
        digits[0] = b'0';
        dlen = 1;
    }
    else
    {
        while n > 0 && dlen < digits.len()
        {
            digits[dlen] = b'0' + (n % 10) as u8;
            dlen += 1;
            n /= 10;
        }
    }
    let mut idx = start;
    while dlen > 0 && idx < buf.len()
    {
        dlen -= 1;
        buf[idx] = digits[dlen];
        idx += 1;
    }
    idx
}

/// Emit `[sec.usfrac] [init-logd] <payload>\r\n` directly to the
/// serial port. Used for synthetic registration-event lines and
/// saturation warnings; bypasses the per-token slot/buffer machinery
/// so it does not collide with in-flight log streams. The `init-`
/// prefix marks the receiver as init's interim log thread; a future
/// real `logd` service will emit the same line shape under bare
/// `[logd]`.
fn flush_synthetic_logd_line(payload: &[u8])
{
    let us = syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    let sec = us / 1_000_000;
    let usfrac = (us % 1_000_000) as u32;

    arch::current::serial_write_byte(b'[');
    write_decimal(sec);
    arch::current::serial_write_byte(b'.');
    write_decimal_padded(u64::from(usfrac), 6);
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    arch::current::serial_write_byte(b'[');
    for &b in b"init-logd"
    {
        arch::current::serial_write_byte(b);
    }
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    for &b in payload
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
    // Eviction. Clear the prior occupant's name so the new owner does not
    // inherit it — otherwise unregistered byte writes would render under the
    // evicted sender's display name.
    let victim = *next_evict % MAX_SENDERS;
    *next_evict = (victim + 1) % MAX_SENDERS;
    slots[victim].token = token;
    slots[victim].used = 0;
    slots[victim].name = [0u8; MAX_NAME_LEN];
    slots[victim].name_used = 0;
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
