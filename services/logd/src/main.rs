// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// logd/src/main.rs

//! Seraph system log daemon — post-mount owner of the master log
//! endpoint.
//!
//! Launched and supervised by svcmgr, real-logd:
//!
//! 1. Receives via bootstrap protocol a RECV cap on the master log
//!    endpoint, a SEND cap on the same endpoint (single-use, for the
//!    `HANDOVER_PULL` IPC to init-logd), a SEND cap on procmgr
//!    carrying `DEATH_EQ_AUTHORITY` (for `REGISTER_DEATH_EQ`), and a
//!    SEND cap on devmgr's registry endpoint carrying
//!    `REGISTRY_QUERY_AUTHORITY` (to resolve the serial driver via
//!    `QUERY_SERIAL_DEVICE`).
//! 2. Drains init-logd's captured state via `HANDOVER_PULL` until
//!    `DONE`. Init-logd self-terminates immediately after replying
//!    `DONE`.
//! 3. Creates an `EventQueue` for procmgr-routed death notifications.
//! 4. Registers the EQ with procmgr via `REGISTER_DEATH_EQ`. Procmgr
//!    retroactively binds it on every existing thread and on every
//!    future spawn (correlator = process badge, equal to the log
//!    badge logd sees on `STREAM_BYTES`).
//! 5. Enters the main wait loop, draining death notifications first
//!    then servicing log endpoint messages.
//!
//! Logd does NOT use `seraph::log!` for its own diagnostics — it IS
//! the log receiver, so a `log!` call would self-IPC into the
//! endpoint it serves and deadlock once init-logd has terminated.
//! Diagnostics + received log lines are emitted through the userspace
//! serial driver (resolved once via devmgr's `QUERY_SERIAL_DEVICE`)
//! using `serial_labels::SERIAL_WRITE_BYTES`. Until the driver is
//! resolvable, serial output is dropped but received lines stay in the
//! per-slot history ring; the pre-driver boot window is covered by
//! init-logd's direct-UART fallback (see `docs/console-model.md`).
//!
//! Logd's *panic / alloc-error / precondition* output must not ride the
//! log endpoint either. `main` registers a `std::os::seraph::set_panic_sink`
//! sink (`panic_to_serial`) that routes that output to the serial driver,
//! and drops the procmgr-seeded badged SEND on the log endpoint
//! (`ProcessInfo.log_send_cap`) so no path can self-IPC into the endpoint
//! logd receives on.
//!
//! The pre-existing badged SEND caps held by memmgr, procmgr,
//! tier-1 services, and every Phase-3 child remain valid across the
//! handover — same kernel endpoint object, only the RECV-holder
//! changes.

// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod handover;
mod slot;

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ipc::stream_labels::{STREAM_BYTES, STREAM_REGISTER_NAME};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use std::os::seraph::startup_info;

use crate::slot::{LINE_BUF_SIZE, MAX_NAME_LEN, SlotTable};

/// `WaitSet` badge for the master log endpoint.
const WS_BADGE_LOG: u64 = 0;
/// `WaitSet` badge for the death-notification event queue.
const WS_BADGE_DEATH: u64 = 1;

/// Caps real-logd receives from init's bootstrap round.
struct BootCaps
{
    /// RECV cap on the master log endpoint. Real-logd is now the
    /// RECV-holder; init-logd has already terminated by the time
    /// this cap is in use.
    log_ep_recv: u32,
    /// SEND cap on the master log endpoint, used only for the
    /// `HANDOVER_PULL` IPC to init-logd. Deleted after handover.
    log_ep_handover_send: u32,
    /// SEND cap on procmgr carrying `DEATH_EQ_AUTHORITY`, used to
    /// call `REGISTER_DEATH_EQ`. Kept across the lifetime of
    /// real-logd in case re-registration is ever needed.
    procmgr_death_auth_send: u32,
    /// SEND cap on devmgr's registry endpoint carrying
    /// `REGISTRY_QUERY_AUTHORITY`. logd resolves the serial driver's
    /// write endpoint through it via `QUERY_SERIAL_DEVICE`. Zero
    /// disables serial output (logd then buffers received log lines in
    /// memory only).
    devmgr_registry_ep: u32,
}

fn bootstrap_caps(creator_endpoint: u32, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_endpoint, ipc_buf) }.ok()?;
    if round.cap_count < 4 || !round.done
    {
        return None;
    }
    Some(BootCaps {
        log_ep_recv: round.caps[0],
        log_ep_handover_send: round.caps[1],
        procmgr_death_auth_send: round.caps[2],
        devmgr_registry_ep: round.caps[3],
    })
}

fn main() -> !
{
    let startup = startup_info();

    // IPC buffer is registered by `_start`; reinterpret as `*mut u64`.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // Record the devmgr-registry cap + IPC buffer for the emit path. The
    // serial driver is resolved lazily on first emit via
    // `QUERY_SERIAL_DEVICE`; until then serial output is dropped (init-logd
    // covered the pre-driver window) while history still accrues.
    serial_init(caps.devmgr_registry_ep, ipc_buf);

    // logd serves the log endpoint, so it must never emit through it. Route
    // panic / alloc-error / precondition output to the serial driver (the
    // path `self_log` already uses) via the std panic sink, and drop the
    // procmgr-seeded badged SEND so no path — panic, alloc-error, or a stray
    // `log!` — can self-IPC into the endpoint logd receives on.
    std::os::seraph::set_panic_sink(panic_to_serial);
    let _ = syscall::cap_delete(startup.log_send_cap);

    let mut table = SlotTable::default();

    // Set up the death-notification queue + wait set and register with procmgr
    // BEFORE pulling the handover. The pull causes init-logd to exit, which
    // triggers procmgr's init-reap; that reap logs, and until logd reaches its
    // draining loop there is no other reader on the log endpoint. Registering
    // here — while init's main has already exited but init-logd is still
    // serving, so procmgr is not yet reaping init — keeps logd from blocking on
    // procmgr in that window, which would deadlock against procmgr blocking on
    // the unmanned log endpoint. After the pull, logd reaches `event_loop` with
    // no further procmgr dependency, so it drains the reap's log line itself.
    let Some(death_eq) = create_death_eq()
    else
    {
        self_log("FATAL: death-EQ create failed; halting");
        syscall::thread_exit();
    };
    register_with_procmgr(caps.procmgr_death_auth_send, death_eq, ipc_buf);
    let Some(ws_cap) = create_wait_set(caps.log_ep_recv, death_eq)
    else
    {
        self_log("FATAL: wait_set create failed; halting");
        syscall::thread_exit();
    };

    if caps.log_ep_handover_send != 0
    {
        // First launch: pull init-logd's accrued boot history, release
        // init-logd, then drop the single-use SEND so logd carries no SEND cap
        // to its own log endpoint.
        self_log("started; pulling init-logd handover state");
        // SAFETY: ipc_buf is the registered IPC buffer page.
        unsafe { handover::pull_all(caps.log_ep_handover_send, ipc_buf, &mut table) };
        // Terminal release: init-logd exits on this, not on the drain's DONE,
        // so a dropped data chunk cannot wedge it (and thus cannot block
        // procmgr's reap of init's memory caps).
        // SAFETY: ipc_buf is the registered IPC buffer page.
        unsafe { handover::send_release(caps.log_ep_handover_send, ipc_buf) };
        let _ = syscall::cap_delete(caps.log_ep_handover_send);

        let mut buf = SerialFmt::new();
        let _ = write!(
            buf,
            "handover complete: {} slots, {} history lines",
            table.slots.len(),
            table.slots.values().map(|s| s.history.len()).sum::<usize>(),
        );
        buf.flush_self_log();
    }
    else
    {
        // A svcmgr restart: there is no handover source (init-logd exited
        // after the first launch). Serve a fresh table; in-flight history
        // from the prior instance is not recoverable.
        self_log("started (restart); no handover source, serving fresh");
    }

    event_loop(ws_cap, death_eq, caps.log_ep_recv, ipc_buf, &mut table);
}

/// Allocate the slab and create the death-notification `EventQueue`.
/// Capacity sized so a burst of simultaneous child deaths fits before
/// logd's next drain (`MAX_DEATHS_PER_BURST`).
fn create_death_eq() -> Option<u32>
{
    const MAX_DEATHS_PER_BURST: u32 = 64;
    // Bytes: 24 wrapper + 56 state + (capacity + 1) * 8 ring.
    let slab_bytes: u64 = 24 + 56 + (u64::from(MAX_DEATHS_PER_BURST) + 1) * 8;
    let slab = std::os::seraph::object_slab_acquire(slab_bytes)?;
    syscall::event_queue_create(slab, MAX_DEATHS_PER_BURST).ok()
}

/// Build a 2-member wait set: the log endpoint (`WS_BADGE_LOG`) and
/// the death event queue (`WS_BADGE_DEATH`).
fn create_wait_set(log_ep_recv: u32, death_eq: u32) -> Option<u32>
{
    let slab = std::os::seraph::object_slab_acquire(4096)?;
    let ws = match syscall::wait_set_create(slab)
    {
        Ok(c) => c,
        Err(e) =>
        {
            let mut buf = SerialFmt::new();
            let _ = write!(buf, "wait_set_create err={e} slab={slab}");
            buf.flush_self_log();
            return None;
        }
    };
    if let Err(e) = syscall::wait_set_add(ws, log_ep_recv, WS_BADGE_LOG)
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_add(log) err={e}");
        buf.flush_self_log();
        return None;
    }
    if let Err(e) = syscall::wait_set_add(ws, death_eq, WS_BADGE_DEATH)
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "wait_set_add(death) err={e}");
        buf.flush_self_log();
        return None;
    }
    Some(ws)
}

/// POST = bit 9 (matches `core::cap::slot::Rights::POST` =
/// `1 << 9`). Construct directly; `shared/syscall` does not expose
/// a `RIGHTS_POST` helper yet.
const RIGHTS_POST: u64 = 1 << 9;

/// Send `REGISTER_DEATH_EQ` to procmgr.
///
/// `ipc_call` on a message carrying a cap MOVES the cap into the
/// receiver's `CSpace` and clears the sender's slot. logd needs to
/// retain `RECV` on the original event queue so `wait_set_add` and
/// `event_try_recv` keep working, so it first derives a POST-only
/// copy and transfers that. Procmgr's `REGISTER_DEATH_EQ` handler
/// gates on the POST right (`sys_thread_bind_notification`'s lookup
/// already requires it).
fn register_with_procmgr(procmgr_send: u32, death_eq: u32, ipc_buf: *mut u64)
{
    if procmgr_send == 0
    {
        self_log("REGISTER_DEATH_EQ skipped: no procmgr cap");
        return;
    }
    let Ok(post_cap) = syscall::cap_derive(death_eq, RIGHTS_POST)
    else
    {
        self_log("REGISTER_DEATH_EQ: cap_derive POST failed");
        return;
    };
    let msg = IpcMessage::builder(procmgr_labels::REGISTER_DEATH_EQ)
        .cap(post_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page; the cap
    // transfer moves `post_cap` into procmgr's CSpace.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_send, &msg, ipc_buf) })
    else
    {
        self_log("REGISTER_DEATH_EQ: IPC call failed");
        let _ = syscall::cap_delete(post_cap);
        return;
    };
    if reply.label == procmgr_errors::SUCCESS
    {
        self_log("REGISTER_DEATH_EQ: bound on procmgr");
    }
    else
    {
        let mut buf = SerialFmt::new();
        let _ = write!(buf, "REGISTER_DEATH_EQ: error code {}", reply.label);
        buf.flush_self_log();
    }
}

/// Main wait loop. Drains death notifications before each log-EP
/// dispatch so a recently-died sender's slot is evicted before we
/// process its in-flight messages (matches procmgr's drain-deaths-
/// first pattern).
fn event_loop(
    ws_cap: u32,
    death_eq: u32,
    log_ep_recv: u32,
    ipc_buf: *mut u64,
    table: &mut SlotTable,
) -> !
{
    // One guard covers both spin shapes: a failing wait_set_wait, and a
    // level-triggered wait set that keeps reporting ready while the recv in
    // dispatch_log keeps failing. Only a successful recv counts as progress.
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        let badge = match syscall::wait_set_wait(ws_cap)
        {
            Ok(badge) => badge,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        drain_deaths(death_eq, table);
        // Only WS_BADGE_LOG warrants service action; deaths were
        // already drained above. WS_BADGE_DEATH and unknown badges
        // fall through silently.
        if badge == WS_BADGE_LOG
        {
            dispatch_log(log_ep_recv, ipc_buf, table, &mut guard);
        }
    }
}

/// `RecvGuard` diagnostic hook. logd cannot log through its own IPC
/// endpoint, so this writes via the serial self-log path.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    let mut buf = SerialFmt::new();
    let _ = match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            write!(buf, "recv loop failing (err={err}); backing off")
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            write!(buf, "recv loop wedged (err={err}); exiting")
        }
    };
    buf.flush_self_log();
}

/// Non-blocking drain of the death event queue. Each payload encodes
/// `(process_badge as u32) << 32 | exit_reason`. We evict the
/// matching slot from the badge table.
fn drain_deaths(death_eq: u32, table: &mut SlotTable)
{
    loop
    {
        let Ok(payload) = syscall::event_try_recv(death_eq)
        else
        {
            return;
        };
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload as u32;
        // Badge in logd's slot map is the full u64; the correlator
        // procmgr binds is `process_badge as u32`. Match against the
        // low 32 bits.
        let dead: Vec<u64> = table
            .slots
            .keys()
            .copied()
            .filter(|&t| (t as u32) == correlator)
            .collect();
        for badge in dead
        {
            if table.evict(badge)
            {
                let mut buf = SerialFmt::new();
                let _ = write!(buf, "reclaim: badge={badge} exit_reason=0x{exit_reason:x}");
                buf.flush_self_log();
            }
        }
    }
}

fn dispatch_log(
    log_ep_recv: u32,
    ipc_buf: *mut u64,
    table: &mut SlotTable,
    guard: &mut ipc::recv_guard::RecvGuard,
)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let recv = match unsafe { ipc::ipc_recv(log_ep_recv, ipc_buf) }
    {
        Ok(recv) => recv,
        Err(e) =>
        {
            guard.on_failure(e);
            return;
        }
    };
    guard.on_success();
    let label_id = recv.label & 0xFFFF;
    let byte_len = ((recv.label >> 16) & 0xFFFF) as usize;
    if label_id == STREAM_BYTES
    {
        consume_bytes(table, recv.badge, &recv, byte_len);
        reply_ack(ipc_buf);
    }
    else if label_id == STREAM_REGISTER_NAME
    {
        register_name(table, recv.badge, &recv, byte_len);
        reply_ack(ipc_buf);
    }
    else
    {
        // Unknown / legacy label (e.g. GET_LOG_CAP from a hypothetical
        // pre-pivot caller). Reply empty so the sender unblocks.
        reply_ack(ipc_buf);
    }
}

fn reply_ack(ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(0), ipc_buf) };
}

/// Append `byte_len` bytes from the IPC payload onto the slot for
/// `badge`, flushing complete lines (`\n`-terminated) to the serial
/// port AND recording them into the per-slot history ring.
///
/// Accepts up to `STREAM_CHUNK_SIZE = MSG_DATA_WORDS_MAX * 8` bytes
/// per call (the maximum a single `STREAM_BYTES` IPC can carry); the
/// per-line buffer is `LINE_BUF_SIZE` and force-flushes when full,
/// so a chunk longer than `LINE_BUF_SIZE` produces multiple emitted
/// lines rather than truncated output (matches init-logd's behaviour).
fn consume_bytes(table: &mut SlotTable, badge: u64, msg: &IpcMessage, byte_len: usize)
{
    const STREAM_CHUNK_SIZE: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(STREAM_CHUNK_SIZE);
    // Stage the bytes in a stack buffer so we can borrow the slot
    // mutably without aliasing the IPC buffer.
    let mut staged = [0u8; STREAM_CHUNK_SIZE];
    staged[..n].copy_from_slice(&bytes[..n]);
    let slot = table.get_or_create(badge);
    for &b in &staged[..n]
    {
        if b == b'\n'
        {
            flush_partial(badge, slot);
        }
        else if slot.partial.len() < LINE_BUF_SIZE
        {
            slot.partial.push(b);
            if slot.partial.len() == LINE_BUF_SIZE
            {
                flush_partial(badge, slot);
            }
        }
    }
}

/// Snapshot the slot's in-progress line, emit it to serial, append
/// it to the history ring, clear the partial buffer. Separated so
/// the `&slot.name`/`&slot.partial` borrows don't alias the
/// subsequent `&mut slot` calls.
fn flush_partial(badge: u64, slot: &mut crate::slot::Slot)
{
    let name = slot.name.clone();
    let line: Vec<u8> = slot.partial.drain(..).collect();
    emit_line(badge, &name, &line);
    let us = elapsed_us();
    slot.push_history(us, &line);
}

/// Record / update the display name for `badge`. Lines emitted with
/// the old name remain attributed to the old name in history (those
/// are immutable); subsequent emissions render under the new name.
/// Long names truncated. No collision-suffix policy (procmgr's
/// process badge is unique, so name collisions only happen if two
/// processes intentionally pick the same display name).
fn register_name(table: &mut SlotTable, badge: u64, msg: &IpcMessage, byte_len: usize)
{
    let bytes = msg.data_bytes();
    let n = byte_len.min(bytes.len()).min(MAX_NAME_LEN);
    let slot = table.get_or_create(badge);
    slot.name.clear();
    slot.name.extend_from_slice(&bytes[..n]);
}

// ── Serial output (driver-mediated) ────────────────────────────────────────

/// SEND cap on devmgr's registry endpoint (`REGISTRY_QUERY_AUTHORITY`).
static DEVMGR_REGISTRY_EP: AtomicU32 = AtomicU32::new(0);
/// Resolved SEND cap on the serial driver's service endpoint, cached after
/// the first successful `QUERY_SERIAL_DEVICE`. Zero = unresolved.
static SERIAL_CAP: AtomicU32 = AtomicU32::new(0);
/// Resolved SEND cap on the framebuffer driver's service endpoint. `0` =
/// not yet attempted; [`FB_UNAVAILABLE`] = attempted and no driver present
/// (headless boot); any other value = the resolved cap. The resolve runs at
/// most once, caching its outcome either way so framebuffer mirroring stays a
/// no-op on a headless boot without re-querying devmgr.
static FB_CAP: AtomicU32 = AtomicU32::new(0);

/// Sentinel stored in [`FB_CAP`] once a resolution attempt finds no
/// framebuffer driver. Repeating the `QUERY_FRAMEBUFFER_DEVICE` per log line
/// would open a deadlock window against devmgr's own logging — devmgr →
/// `log_ep` → logd, while logd blocks here on devmgr's reply — so the attempt
/// is made exactly once. `u32::MAX` is never a valid `CSpace` slot.
const FB_UNAVAILABLE: u32 = u32::MAX;
/// logd's registered IPC buffer pointer, stashed so the emit path can issue
/// the serial `ipc_call` without threading it through every formatter.
static IPC_BUF_PTR: AtomicU64 = AtomicU64::new(0);

/// Maximum payload bytes per `SERIAL_WRITE_BYTES` (one full IPC data area).
const SERIAL_CHUNK: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;

/// Record the devmgr-registry cap and IPC buffer for the emit path.
fn serial_init(devmgr_registry_ep: u32, ipc_buf: *mut u64)
{
    DEVMGR_REGISTRY_EP.store(devmgr_registry_ep, Ordering::Release);
    IPC_BUF_PTR.store(ipc_buf as u64, Ordering::Release);
}

/// Resolve (and cache) the serial driver's SEND cap via devmgr's
/// `QUERY_SERIAL_DEVICE`. Returns 0 while the driver is not yet resolvable
/// (devmgr not reachable, or driver not spawned); the caller then drops the
/// bytes.
fn resolve_serial_cap(ipc_buf: *mut u64) -> u32
{
    let cached = SERIAL_CAP.load(Ordering::Acquire);
    if cached != 0
    {
        return cached;
    }
    let registry = DEVMGR_REGISTRY_EP.load(Ordering::Acquire);
    if registry == 0
    {
        return 0;
    }
    let msg = IpcMessage::builder(ipc::devmgr_labels::QUERY_SERIAL_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(registry, &msg, ipc_buf) })
    else
    {
        return 0;
    };
    if reply.label != ipc::devmgr_errors::SUCCESS
    {
        return 0;
    }
    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        return 0;
    }
    let cap = reply_caps[0];
    SERIAL_CAP.store(cap, Ordering::Release);
    cap
}

/// Write a fully-formatted line to the serial driver via one or more
/// `SERIAL_WRITE_BYTES` calls. Silently drops the bytes if the driver is
/// not yet resolvable.
fn serial_write(bytes: &[u8])
{
    let ipc_buf = IPC_BUF_PTR.load(Ordering::Acquire) as *mut u64;
    if ipc_buf.is_null()
    {
        return;
    }
    let cap = resolve_serial_cap(ipc_buf);
    if cap == 0
    {
        return;
    }
    let mut off = 0;
    while off < bytes.len()
    {
        let end = (off + SERIAL_CHUNK).min(bytes.len());
        let chunk = &bytes[off..end];
        let label = ipc::serial_labels::SERIAL_WRITE_BYTES | ((chunk.len() as u64) << 16);
        let msg = IpcMessage::builder(label).bytes(0, chunk).build();
        // SAFETY: ipc_buf is the registered IPC buffer page. Nested IPC is
        // safe here: a received `STREAM_BYTES` is already snapshotted into a
        // stack `IpcMessage`, and the kernel preserves the pending reply to
        // the log sender across this call (same pattern as vfsd → blk).
        let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
        off = end;
    }
}

/// Resolve (and cache) the framebuffer driver's SEND cap via devmgr's
/// `QUERY_FRAMEBUFFER_DEVICE`. Returns 0 while the driver is not yet
/// resolvable (devmgr unreachable, headless boot, or driver not spawned);
/// the caller then skips the framebuffer mirror. Reuses the same registry
/// cap and IPC buffer the serial path resolved through.
fn resolve_fb_cap(ipc_buf: *mut u64) -> u32
{
    let cached = FB_CAP.load(Ordering::Acquire);
    if cached == FB_UNAVAILABLE
    {
        return 0;
    }
    if cached != 0
    {
        return cached;
    }
    let registry = DEVMGR_REGISTRY_EP.load(Ordering::Acquire);
    if registry == 0
    {
        // Registry not recorded yet (serial_init sets it before the drain
        // loop); retry once it is.
        return 0;
    }
    let msg = IpcMessage::builder(ipc::devmgr_labels::QUERY_FRAMEBUFFER_DEVICE)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(registry, &msg, ipc_buf) })
    else
    {
        // Could not complete the query (transient — the call returned rather
        // than blocking, so this is not the logd↔devmgr deadlock path). Leave
        // the cache unset and retry on the next line, matching
        // resolve_serial_cap; the serial cap resolves on this same registry
        // endpoint, so a hard failure here does not recur in practice.
        return 0;
    };
    // devmgr answered. Latch the outcome so the drain loop issues at most one
    // more QUERY_FRAMEBUFFER_DEVICE: the resolved cap, or FB_UNAVAILABLE when
    // devmgr reports no framebuffer driver (headless boot). The driver, when
    // present, is spawned before svcmgr launches logd, so this resolves it.
    // Latching the no-driver answer is what prevents a per-line re-query, which
    // would open a deadlock window against devmgr's own logging (devmgr →
    // log_ep → logd, while logd blocks here on devmgr's reply).
    let cap = if reply.label == ipc::devmgr_errors::SUCCESS
    {
        reply.caps().first().copied().unwrap_or(0)
    }
    else
    {
        0
    };
    FB_CAP.store(
        if cap == 0 { FB_UNAVAILABLE } else { cap },
        Ordering::Release,
    );
    cap
}

/// Mirror a fully-formatted line to the framebuffer driver via one or more
/// `FB_WRITE_BYTES` calls. Silently skips the mirror if the driver is not
/// resolvable, so serial remains the always-present, authoritative channel
/// (CI scrapes serial; the framebuffer is an on-screen convenience).
fn fb_write(bytes: &[u8])
{
    let ipc_buf = IPC_BUF_PTR.load(Ordering::Acquire) as *mut u64;
    if ipc_buf.is_null()
    {
        return;
    }
    let cap = resolve_fb_cap(ipc_buf);
    if cap == 0
    {
        return;
    }
    let mut off = 0;
    while off < bytes.len()
    {
        let end = (off + SERIAL_CHUNK).min(bytes.len());
        let chunk = &bytes[off..end];
        let label = ipc::fb_labels::FB_WRITE_BYTES | ((chunk.len() as u64) << 16);
        let msg = IpcMessage::builder(label).bytes(0, chunk).build();
        // SAFETY: ipc_buf is the registered IPC buffer page. Same nested-IPC
        // reasoning as serial_write: the received STREAM_BYTES is already
        // snapshotted and the kernel preserves the pending reply to the log
        // sender across this call.
        let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
        off = end;
    }
}

/// Fixed-capacity line builder. 512 bytes holds any logd line
/// (`LINE_BUF_SIZE` content plus timestamp and name framing) in a single
/// `SERIAL_WRITE_BYTES`; over-long lines truncate rather than allocate.
struct LineBuf
{
    buf: [u8; 512],
    len: usize,
}

impl LineBuf
{
    fn new() -> Self
    {
        Self {
            buf: [0u8; 512],
            len: 0,
        }
    }

    fn push(&mut self, b: u8)
    {
        if self.len < self.buf.len()
        {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    /// Push a byte, expanding a bare `\n` to `\r\n` for terminal output.
    fn push_escaped(&mut self, b: u8)
    {
        if b == b'\n'
        {
            self.push(b'\r');
        }
        self.push(b);
    }

    fn push_decimal(&mut self, value: u64)
    {
        let mut digits = [0u8; 20];
        let mut n = value;
        let mut idx = digits.len();
        if n == 0
        {
            idx -= 1;
            digits[idx] = b'0';
        }
        else
        {
            while n > 0
            {
                idx -= 1;
                digits[idx] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        for &d in &digits[idx..]
        {
            self.push(d);
        }
    }

    fn push_decimal_padded(&mut self, value: u64, width: usize)
    {
        let mut digits = [b'0'; 20];
        let mut n = value;
        let mut idx = digits.len();
        while n > 0 && idx > 0
        {
            idx -= 1;
            digits[idx] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        let start = digits.len().saturating_sub(width);
        for &d in &digits[start..]
        {
            self.push(d);
        }
    }

    /// Push `[sec.usfrac] ` from the current monotonic clock.
    fn push_timestamp(&mut self)
    {
        let us = elapsed_us();
        self.push(b'[');
        self.push_decimal(us / 1_000_000);
        self.push(b'.');
        self.push_decimal_padded(us % 1_000_000, 6);
        self.push(b']');
        self.push(b' ');
    }

    fn flush(&self)
    {
        serial_write(&self.buf[..self.len]);
        fb_write(&self.buf[..self.len]);
    }
}

/// Emit `[sec.usfrac] [name] <bytes>\r\n` to the serial driver. Mirrors
/// init-logd's `flush_line` shape so the post-handover output stream looks
/// identical to the pre-handover output.
fn emit_line(_badge: u64, name: &[u8], line: &[u8])
{
    let mut out = LineBuf::new();
    out.push_timestamp();
    out.push(b'[');
    if name.is_empty()
    {
        out.push(b'?');
    }
    else
    {
        for &b in name
        {
            out.push(b);
        }
    }
    out.push(b']');
    out.push(b' ');
    for &b in line
    {
        out.push_escaped(b);
    }
    out.push(b'\r');
    out.push(b'\n');
    out.flush();
}

/// Panic-output sink registered with std via `set_panic_sink`. Routes
/// logd's own panic / alloc-error / precondition output to the serial
/// driver — never through the log endpoint logd serves. Forwards raw bytes
/// (std frames the panic message); `serial_write` silent-drops until the
/// driver is resolvable. Must stay non-allocating and panic-free: it runs
/// from the panic path. Correct only while logd is single-threaded:
/// `serial_write` issues its `ipc_call` against the cached `IPC_BUF_PTR`
/// (logd's main-thread IPC buffer), so a panic on a future worker thread
/// would target the wrong IPC page.
fn panic_to_serial(bytes: &[u8])
{
    serial_write(bytes);
}

/// Emit `[sec.usfrac] [logd] <payload>\r\n` to the serial driver. Used for
/// logd's own diagnostics in place of `seraph::log!` (which would self-IPC
/// into the endpoint logd serves).
fn self_log(payload: &str)
{
    let mut out = LineBuf::new();
    out.push_timestamp();
    out.push(b'[');
    for &b in b"logd"
    {
        out.push(b);
    }
    out.push(b']');
    out.push(b' ');
    for b in payload.bytes()
    {
        out.push_escaped(b);
    }
    out.push(b'\r');
    out.push(b'\n');
    out.flush();
}

/// Stack-buffer `fmt::Write` adapter for one-shot formatted
/// diagnostics. 256-byte cap matches `LINE_BUF_SIZE`; over-long
/// formatted output truncates.
struct SerialFmt
{
    buf: [u8; 256],
    used: usize,
}

impl SerialFmt
{
    fn new() -> Self
    {
        Self {
            buf: [0u8; 256],
            used: 0,
        }
    }

    fn flush_self_log(&self)
    {
        // SAFETY: SerialFmt only ever receives UTF-8 from
        // `core::fmt::write`.
        let s = unsafe { core::str::from_utf8_unchecked(&self.buf[..self.used]) };
        self_log(s);
    }
}

impl Write for SerialFmt
{
    fn write_str(&mut self, s: &str) -> core::fmt::Result
    {
        let bytes = s.as_bytes();
        let cap = self.buf.len() - self.used;
        let n = bytes.len().min(cap);
        self.buf[self.used..self.used + n].copy_from_slice(&bytes[..n]);
        self.used += n;
        Ok(())
    }
}

fn elapsed_us() -> u64
{
    syscall::system_info(syscall_abi::SystemInfoType::ElapsedUs as u64).unwrap_or(0)
}
