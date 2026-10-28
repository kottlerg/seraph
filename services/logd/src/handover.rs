// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/src/handover.rs

//! Real-logd → init-logd handover client.
//!
//! Sends `log_labels::HANDOVER_PULL` repeatedly on a SEND cap to the
//! shared log endpoint until init-logd replies with the `DONE`
//! status, ingesting the (slot table, history ring) payload along the
//! way into logd's [`SlotTable`], then releases init-logd with
//! `log_labels::HANDOVER_RELEASE`. A release init-logd defers (a name
//! changed after its slot was sent) sends logd back to pulling.
//!
//! The wire contract (reply, chunk-kind, and release-status codes, and
//! the chunk decoder) lives in [`logd_codec::handover`], shared with
//! init-logd's sender side in `services/init/src/logging.rs`. See
//! `services/logd/docs/handover-protocol.md`.

use ipc::IpcMessage;
use ipc::log_labels::{HANDOVER_PULL, HANDOVER_RELEASE};
use logd_codec::handover::{self as wire, Chunk};

use crate::slot::SlotTable;

/// Outcome of [`send_release`].
enum Release
{
    /// Init-logd acknowledged and exits.
    Acked,
    /// Init-logd has names to send again and keeps serving; pull again.
    Pending,
    /// No attempt was delivered; init-logd keeps serving.
    Unreached,
}

/// Run the whole handover: drain init-logd's state into `table`, then
/// release it, pulling again each time init-logd defers the release.
///
/// Init-logd defers at most [`wire::MAX_RELEASE_DEFERRALS`] times and
/// acknowledges the release after that, so the
/// `MAX_RELEASE_DEFERRALS + 1` rounds here end with init-logd released
/// unless no release attempt reaches it at all.
///
/// # Safety
/// `ipc_buf` must be the calling thread's registered IPC buffer.
pub unsafe fn transfer(handover_send_cap: u32, ipc_buf: *mut u64, table: &mut SlotTable)
{
    for _ in 0..=wire::MAX_RELEASE_DEFERRALS
    {
        // SAFETY: caller's invariant — ipc_buf is the registered IPC buffer.
        unsafe { pull_all(handover_send_cap, ipc_buf, table) };
        // SAFETY: caller's invariant — ipc_buf is the registered IPC buffer.
        let outcome = unsafe { send_release(handover_send_cap, ipc_buf) };
        if !matches!(outcome, Release::Pending)
        {
            return;
        }
    }
}

/// Drain init-logd's handover state into `table`, best-effort. Returns
/// on the `DONE` reply (no more data), on an `ipc_call` error (drain
/// aborted), or at the iteration cap. `DONE` means only "no more data" —
/// init-logd's thread does NOT terminate here; the caller must follow
/// with [`send_release`], which is what actually releases init-logd. A
/// dropped data chunk therefore loses at most some boot history; it
/// cannot wedge init-logd.
///
/// # Safety
/// `ipc_buf` must be the calling thread's registered IPC buffer.
unsafe fn pull_all(handover_send_cap: u32, ipc_buf: *mut u64, table: &mut SlotTable)
{
    // Bound on chunks per drain. A first drain sends 1 header + up to
    // MAX_SENDERS (16) slots + up to HISTORY_RING_LEN (512) lines + 1
    // DONE, about 530 chunks; slots resent after a rename and lines pushed
    // during the drain add to that only while senders keep renaming or
    // logging. 2048 leaves ample headroom for both, and also ends a
    // malformed reply stream that never sends DONE.
    const MAX_ITERS: usize = 2048;

    for _ in 0..MAX_ITERS
    {
        let req = IpcMessage::new(HANDOVER_PULL);
        // SAFETY: caller's invariant — ipc_buf is the registered IPC
        // buffer page.
        let Ok(reply) = (unsafe { ipc::ipc_call(handover_send_cap, &req, ipc_buf) })
        else
        {
            // Drain aborted (e.g. a kernel IPC rendezvous race on the shared
            // log endpoint dropped this call). Non-fatal: the caller still
            // issues HANDOVER_RELEASE, so init-logd is released regardless —
            // at most some boot history is not transferred.
            return;
        };
        match wire::decode(&reply)
        {
            Chunk::Slot { badge, name } => table.install_from_handover(badge, name),
            Chunk::Line { badge, us, bytes } => table.install_history_line(badge, us, bytes),
            // The header is informational; an unknown kind is skipped.
            Chunk::Header | Chunk::Skip =>
            {}
        }
        // Any status other than DONE continues the drain; MAX_ITERS bounds
        // a peer that never sends DONE.
        if wire::is_done(reply.label)
        {
            return;
        }
    }
}

/// Ask init-logd to terminate, retrying until a call is delivered.
///
/// Issued once [`pull_all`] settles (DONE, abort, or iteration cap).
/// Init-logd's thread terminates on an acknowledged release — not on the
/// data drain's `DONE` chunk — so a dropped data chunk (a kernel IPC
/// rendezvous race on the shared, multi-sender log endpoint) cannot leave
/// init-logd running and block procmgr's reap of init's memory caps.
///
/// Init-logd is alive until it acknowledges a release, so the first
/// *delivered* call returns `Ok`: [`Release::Acked`], or
/// [`Release::Pending`] when init-logd defers the release because a name
/// changed after its slot was sent. The retry recovers a release whose
/// request was dropped (init-logd never saw it, so it is still serving).
/// The cap bounds the loop; a genuinely unreachable init-logd is left
/// serving (procmgr reaps init only on init-logd's natural exit), never
/// wedged by an unbounded spin here.
///
/// # Safety
/// `ipc_buf` must be the calling thread's registered IPC buffer.
unsafe fn send_release(handover_send_cap: u32, ipc_buf: *mut u64) -> Release
{
    const MAX_RETRIES: usize = 64;
    let req = IpcMessage::new(HANDOVER_RELEASE);
    for _ in 0..MAX_RETRIES
    {
        // SAFETY: caller's invariant — ipc_buf is the registered IPC buffer.
        if let Ok(reply) = unsafe { ipc::ipc_call(handover_send_cap, &req, ipc_buf) }
        {
            return if wire::is_release_pending(reply.label)
            {
                Release::Pending
            }
            else
            {
                Release::Acked
            };
        }
        let _ = syscall::thread_yield();
    }
    Release::Unreached
}
