// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/src/logging.rs

//! Logging subsystem for init — the system's *interim* log mediator.
//!
//! Init owns the master log endpoint at boot and runs a dedicated thread
//! ("init-logd") that drains it until the svcmgr-launched real-logd takes it
//! over; init-logd's console role is specified in `docs/console-model.md`
//! (item 3) and the takeover in `services/logd/docs/handover-protocol.md`.
//!
//! Three halves:
//!
//! * **Sender side (init's own log line emission):** early boot writes
//!   directly to the serial port; once the log thread is up, init's main
//!   thread switches to the same `STREAM_BYTES` IPC path that std-built
//!   services use, with a badged SEND cap carrying badge
//!   `LOG_BADGE_INIT` so the receiver attributes init's lines correctly.
//!
//! * **Receiver side (`log_receive_loop`):** the dedicated log thread
//!   loops on `ipc_recv` over the master log endpoint. Each
//!   `STREAM_BYTES` message carries a badge (delivered by the kernel
//!   from the badged SEND cap they hold) and a length-prefixed payload.
//!   The thread maintains a per-badge line buffer; on `\n` it emits
//!   `[name] <line>\r\n` to the serial port AND records the line in a
//!   bounded history ring for handover to real-logd.
//!
//! * **Handover (`HANDOVER_PULL` + `HANDOVER_RELEASE`):** the receiver
//!   serves real-logd's drain of the badge table and history ring, and
//!   exits on the release, as `services/logd/docs/handover-protocol.md`
//!   § Call shape and § Termination specify; the wire contract is
//!   `logd_codec::handover` (`services/logd/codec`).

use crate::PAGE_SIZE;
use crate::arch;
use crate::bootstrap::BootArena;
use init_protocol::InitInfo;
use init_sender_table::{SenderSlot, SenderTable};

use ipc::log_labels::{HANDOVER_PULL, HANDOVER_RELEASE};
use ipc::stream_labels::STREAM_BYTES;
use logd_codec::LINE_BUF_SIZE;
use logd_codec::handover::{self, NameResend};
use logd_codec::history::{HistoryCursor, HistoryRing};

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

/// Number of stack pages for the log thread (16 KiB). It bounds no log
/// capacity: [`SENDERS`] and [`HISTORY`] live in BSS, not on this stack.
pub(crate) const LOG_THREAD_STACK_PAGES: u64 = 4;

/// Max bytes per IPC chunk. Must match `MSG_DATA_WORDS_MAX * 8` from `syscall_abi`.
const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// Maximum number of distinct sender badges the log receiver tracks at once.
/// Every process that logs before real-logd takes over the endpoint holds a
/// slot (boots peak at about 15), and each registers its name once, so a
/// table smaller than that count evicts named senders, which then log as
/// `[?]` for the rest of the boot. Twice the observed peak leaves room for
/// new boot-time services.
const MAX_SENDERS: usize = 32;

/// Bytes of init-logd's captured-history ring. Lines are packed by length
/// (`logd_codec::history`), so the ring holds about 160 lines of the 80-odd
/// bytes boot lines run to, against a pre-handover peak of about 50, and
/// still more than 50 lines at the full `LINE_BUF_SIZE`. A full ring drops
/// its oldest lines (FIFO), losing only boot history real-logd would
/// otherwise inherit, never a sender or a live line.
const HISTORY_RING_BYTES: usize = 16 * 1024;

// ── Mutable state (sender side, main-thread bound) ──────────────────────────

/// Badged SEND cap on the log endpoint that init's own `log()` writes to.
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
/// be a badged SEND cap on the log endpoint with the badge identifying the
/// sender (badge `1` — init's self-identity — for init's own diagnostics).
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

/// Direct serial output for the main thread before init-logd is up, and for
/// the log thread's setup-failure diagnostic; see `docs/console-model.md`
/// § Ownership across the boot lifecycle (init-logd direct-UART fallback).
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
///
/// Returns the init-logd Thread cap slot so the main thread can include it
/// in the post-Phase-3 reap-handoff (`procmgr.REGISTER_INIT_TEARDOWN`).
/// The cap survives init-logd's `sys_thread_exit` — the kernel marks the
/// TCB Exited but does not reclaim it until `cap_delete` drops the cap's
/// last reference.
///
/// # Safety
/// Called at most once, on init's main thread: it maps the log thread's stack
/// and IPC page at the fixed `LOG_THREAD_STACK_VA` and `LOG_THREAD_IPC_BUF_VA`
/// in init's own address space and starts the thread on them, so a second
/// call would remap a running thread's memory.
pub unsafe fn spawn_log_thread(
    info: &InitInfo,
    arena: &mut BootArena,
    log_ep: u32,
    ioport_cap: u32,
) -> u32
{
    // Offset-map the log thread's stack pages from init's arena into init's
    // address space, writable (W^X: not executable). `place_page` maps the
    // full-rights arena cap directly with explicit protection, so no per-page
    // derived child cap is needed.
    for i in 0..LOG_THREAD_STACK_PAGES
    {
        // SAFETY: the log-thread stack pages are fixed VAs of init's private
        // plan (below the kernel-chosen windows of `process-layout`), which
        // only this once-only call maps.
        let placed = unsafe {
            arena.place_page(
                info.aspace_cap,
                LOG_THREAD_STACK_VA + i * PAGE_SIZE,
                syscall::MAP_WRITABLE,
                |_| {},
            )
        };
        if placed.is_none()
        {
            log("init: FATAL: cannot place log thread stack");
            syscall::thread_exit();
        }
    }

    // Offset-map the log thread's IPC buffer (zeroed by `place_page`).
    // SAFETY: LOG_THREAD_IPC_BUF_VA is a fixed page of init's private plan,
    // which only this once-only call maps.
    let placed = unsafe {
        arena.place_page(
            info.aspace_cap,
            LOG_THREAD_IPC_BUF_VA,
            syscall::MAP_WRITABLE,
            |_| {},
        )
    };
    if placed.is_none()
    {
        log("init: FATAL: cannot place log thread IPC buffer");
        syscall::thread_exit();
    }

    // Create the log thread by retyping from the arena front, bound to init's
    // own address space and CSpace. The retype holds an ancestor reference on
    // the arena's MemoryObject, pinning it for the thread's life. Placed at
    // the init-logd level via the still-unsplit root SchedControl —
    // `spawn_log_thread` runs before init's baseline split consumes that
    // slot in `run()`.
    let Ok(thread_cap) = syscall::cap_create_thread(
        arena.cap,
        info.aspace_cap,
        info.cspace_cap,
        info.sched_control_cap,
        ipc::sched_policy::INIT_LOGD_PRIORITY,
    )
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

    // SAFETY: `log_thread_entry` is an `extern "C" fn(u64) -> !`; `stack_top`
    // tops the stack pages placed above for this thread alone, which nothing
    // else uses for the thread's life; no TLS block is set.
    let configured = unsafe {
        syscall::thread_configure(
            thread_cap,
            log_thread_entry as *const () as u64,
            stack_top,
            arg,
        )
    };
    if configured.is_err()
    {
        log("init: FATAL: cannot configure log thread");
        syscall::thread_exit();
    }
    if crate::start_thread(thread_cap).is_err()
    {
        log("init: FATAL: cannot start log thread");
        syscall::thread_exit();
    }
    thread_cap
}

/// Entry point for the log thread. Registers its own IPC buffer then enters
/// the log receive loop. Never returns.
///
/// Called via `thread_configure` with `arg` = log endpoint cap slot (RECV).
extern "C" fn log_thread_entry(arg: u64) -> !
{
    // Register this thread's IPC buffer.
    // SAFETY: LOG_THREAD_IPC_BUF_VA is the page `spawn_log_thread` placed for
    // this thread alone; no Rust object lives in it, and the thread reaches
    // it only through the raw `ipc_buf` pointer below.
    if unsafe { syscall::ipc_buffer_set(LOG_THREAD_IPC_BUF_VA) }.is_err()
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

/// Per-sender state, keyed by the kernel-delivered badge: the display name
/// registered via `STREAM_REGISTER_NAME` and the bytes accumulated since the
/// last newline. Too large for the log thread's 16 KiB stack (about 10 KiB
/// at [`MAX_SENDERS`]), so it sits in init's BSS like [`HISTORY`]. The log
/// thread is its only user; `log_receive_loop` takes the one reference to it.
static mut SENDERS: SenderTable<MAX_SENDERS> = SenderTable::new();

/// Captured history: the completed log lines `consume_bytes` records for
/// handover to real-logd, oldest dropped first when full. Too large for the
/// log thread's 16 KiB stack, so it sits in init's BSS like [`SENDERS`]. The
/// log thread is its only user; `log_receive_loop` takes the one reference
/// to it.
static mut HISTORY: HistoryRing<HISTORY_RING_BYTES> = HistoryRing::new();

/// Set when init-logd acknowledges real-logd's `HANDOVER_RELEASE`. The
/// receive loop checks this on the next iteration and exits cleanly via
/// `sys_thread_exit`, terminating the init-logd thread.
static HANDOVER_COMPLETE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Record a completed line in the history ring. Called from `consume_bytes`
/// for every newline-terminated or buffer-full payload.
fn history_push(history: &mut HistoryRing<HISTORY_RING_BYTES>, slot: &SenderSlot)
{
    let us = syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0);
    history.push(slot.badge(), us, slot.line());
}

/// `RecvGuard` diagnostic hook. Init's serial sink is direct, so emit
/// synthetic logd lines; the error code is dropped (the kernel's recv
/// diagnostic carries the cause).
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, _err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            flush_synthetic_logd_line(b"log recv loop failing; backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            flush_synthetic_logd_line(b"log recv loop wedged; exiting");
        }
    }
}

/// Receive byte-stream messages from services and write them to the serial
/// port, prefixing each line with the sender's `[name]` (extracted from the
/// per-message kernel-delivered badge). Also services real-logd's
/// `HANDOVER_PULL` data drain and its terminal `HANDOVER_RELEASE`; an
/// acknowledged release sets `HANDOVER_COMPLETE`, and the next loop
/// iteration self-terminates the thread.
fn log_receive_loop(log_ep: u32, ipc_buf_raw: *mut u64) -> !
{
    // SAFETY: the log thread runs this loop once and never returns from it,
    // and nothing else names SENDERS, so this is the only reference to it.
    let senders = unsafe { &mut *core::ptr::addr_of_mut!(SENDERS) };
    // SAFETY: as for SENDERS: nothing else names HISTORY.
    let history = unsafe { &mut *core::ptr::addr_of_mut!(HISTORY) };
    let mut drain = HandoverDrain::new();

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        if HANDOVER_COMPLETE.load(core::sync::atomic::Ordering::Acquire)
        {
            flush_synthetic_logd_line(b"handover complete; init-logd thread exiting");
            arch::current::serial_release();
            syscall::thread_exit();
        }

        // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
        let recv = match unsafe { ipc::ipc_recv(log_ep, ipc_buf_raw) }
        {
            Ok(recv) => recv,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        let label_id = recv.label & 0xFFFF;
        let byte_len = ((recv.label >> 16) & 0xFFFF) as usize;
        if label_id == STREAM_BYTES
        {
            consume_bytes(senders, history, &recv, recv.badge, byte_len);
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(0), ipc_buf_raw) };
        }
        else if label_id == ipc::stream_labels::STREAM_REGISTER_NAME
        {
            if let Some(slot_idx) = register_sender_name(senders, &recv, recv.badge, byte_len)
            {
                drain.name_resend.note_name_change(slot_idx);
            }
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(0), ipc_buf_raw) };
        }
        else if label_id == HANDOVER_PULL
        {
            let reply = drain.next_chunk(senders.slots(), history);
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf_raw) };
        }
        else if label_id == HANDOVER_RELEASE
        {
            // Real-logd's terminal release: the sole init-logd exit trigger,
            // independent of the data drain's progress. A name that changed
            // after its slot was sent defers it (a bounded number of times):
            // real-logd pulls again and the drain sends that slot. Otherwise
            // ack and set the flag; the next loop iteration self-terminates
            // the thread.
            let status = drain.name_resend.release_status();
            // SAFETY: ipc_buf_raw is the log thread's registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(status), ipc_buf_raw) };
            if status == handover::RELEASE_ACK
            {
                HANDOVER_COMPLETE.store(true, core::sync::atomic::Ordering::Release);
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

/// init-logd's progress through real-logd's `HANDOVER_PULL` drain, kept
/// across pulls so each returns a fresh chunk.
struct HandoverDrain
{
    /// Whether the `HEADER` chunk has been sent.
    header_sent: bool,
    /// The next slot-table index the slot pass sends.
    slot_idx: usize,
    /// The next history line to send.
    history: HistoryCursor,
    /// Slots whose name changed after the slot pass began; the drain sends
    /// them again before it reports `DONE` or acks the release.
    name_resend: NameResend<MAX_SENDERS>,
}

impl HandoverDrain
{
    const fn new() -> Self
    {
        Self {
            header_sent: false,
            slot_idx: 0,
            history: HistoryCursor::new(),
            name_resend: NameResend::new(),
        }
    }

    /// Build the next `HANDOVER_PULL` reply chunk and advance past it: the
    /// header, every occupied slot, every slot whose name changed after the
    /// slot pass began, then the history lines. On the last entry, the reply
    /// is `DONE`, meaning only "no more data": the init-logd thread
    /// terminates on a separate acknowledged [`HANDOVER_RELEASE`], not on
    /// this `DONE`, so a dropped data chunk cannot wedge init-logd (which
    /// would block procmgr's reap of init's memory caps).
    fn next_chunk(
        &mut self,
        slots: &[SenderSlot; MAX_SENDERS],
        history: &HistoryRing<HISTORY_RING_BYTES>,
    ) -> ipc::IpcMessage
    {
        if !self.header_sent
        {
            let active = slots.iter().filter(|s| s.badge() != 0).count() as u64;
            self.header_sent = true;
            // From here a name change can land behind the slot pass; record
            // it so the drain sends that slot again.
            self.name_resend.start();
            return handover::encode_header(history.total(), active);
        }

        while self.slot_idx < MAX_SENDERS
        {
            let slot = &slots[self.slot_idx];
            self.slot_idx += 1;
            if slot.badge() != 0
            {
                return slot_chunk(slot);
            }
        }
        while let Some(i) = self.name_resend.take_next()
        {
            if slots[i].badge() != 0
            {
                return slot_chunk(&slots[i]);
            }
        }

        // History, by absolute push sequence: a line evicted before it was
        // sent is skipped, and lines pushed after the drain caught up are
        // sent by a later pull (a deferred release's further drain).
        let mut line = [0u8; LINE_BUF_SIZE];
        if let Some(entry) = history.read_next(&mut self.history, &mut line)
        {
            return handover::encode_line(entry.badge, entry.us, &line[..entry.len]);
        }
        handover::encode_done()
    }
}

/// The `SLOT` handover chunk carrying `slot`'s badge and display name.
fn slot_chunk(slot: &SenderSlot) -> ipc::IpcMessage
{
    handover::encode_slot(slot.badge(), slot.name())
}

/// Record a display name for the sender identified by `badge`. Called
/// from `log_receive_loop` when a `STREAM_REGISTER_NAME` message
/// arrives. The name is stored under the collision-suffix policy of
/// [`SenderTable::register_name`]:
///
/// * Re-registration by the same badge with its own current name is a
///   silent no-op (no map mutation, no synthetic line).
/// * Otherwise the sender's previous name is freed first, then the
///   requested name is resolved against the rest of the table — if
///   another active badge holds the bare name, the applicant is stored
///   as `name.2`, `name.3`, …; the first free suffix wins.
/// * Every non-no-op registration emits a synthetic
///   `[init-logd] badge=<N> registered name='<stored-name>'` line so the
///   full `badge → name` history is reconstructable from log output
///   alone.
///
/// Returns the index of the slot whose stored name changed, or `None` for a
/// no-op (empty request or unchanged name), so the caller can schedule the
/// slot to be sent again to real-logd if the handover is in progress.
fn register_sender_name(
    senders: &mut SenderTable<MAX_SENDERS>,
    msg: &ipc::IpcMessage,
    badge: u64,
    byte_len: usize,
) -> Option<usize>
{
    let bytes = msg.data_bytes();
    let requested = &bytes[..byte_len.min(bytes.len())];
    let slot_idx = senders.register_name(badge, requested)?;
    emit_registration_event(badge, senders.slots()[slot_idx].name());
    Some(slot_idx)
}

/// Emit a synthetic registration-event line attributed to the receiver
/// itself: `[sec.usfrac] [init-logd] badge=<N> registered name='<name>'`.
/// Bypasses the slot machinery so it does not interfere with active
/// senders' line buffers.
fn emit_registration_event(badge: u64, name: &[u8])
{
    let mut payload = [0u8; LINE_BUF_SIZE];
    let mut idx = 0usize;

    let prefix = b"badge=";
    for &b in prefix
    {
        if idx < payload.len()
        {
            payload[idx] = b;
            idx += 1;
        }
    }
    idx = write_decimal_into(badge, &mut payload, idx);
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
/// saturation warnings; bypasses the per-badge slot/buffer machinery
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

/// Append `byte_len` bytes from the IPC buffer onto the slot for `badge`,
/// flushing complete lines (`\n`-terminated) to the serial port as `[name] <line>\r\n`.
/// A sender new to a full table takes an evicted slot
/// ([`SenderTable::find_or_alloc`]), whose partial line is dropped.
fn consume_bytes(
    senders: &mut SenderTable<MAX_SENDERS>,
    history: &mut HistoryRing<HISTORY_RING_BYTES>,
    msg: &ipc::IpcMessage,
    badge: u64,
    byte_len: usize,
)
{
    let len = byte_len.min(STREAM_CHUNK_SIZE);
    let bytes = msg.data_bytes();
    let copy_len = len.min(bytes.len());
    let mut tmp = [0u8; STREAM_CHUNK_SIZE];
    tmp[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let slot_idx = senders.find_or_alloc(badge);
    let slot = senders.slot_mut(slot_idx);
    for &b in &tmp[..copy_len]
    {
        // A newline ends the line; a full buffer is flushed too, to keep the
        // prefix visible.
        if b == b'\n' || slot.push_byte(b)
        {
            history_push(history, slot);
            flush_line(slot);
            slot.clear_line();
        }
    }
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
    if slot.name().is_empty()
    {
        arch::current::serial_write_byte(b'?');
    }
    else
    {
        for &b in slot.name()
        {
            arch::current::serial_write_byte(b);
        }
    }
    arch::current::serial_write_byte(b']');
    arch::current::serial_write_byte(b' ');

    for &b in slot.line()
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
