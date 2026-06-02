// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// logd/src/handover.rs

//! Real-logd → init-logd handover client.
//!
//! Sends `log_labels::HANDOVER_PULL` repeatedly on a SEND cap to the
//! shared log endpoint until init-logd replies with the `DONE`
//! status. Ingests the (slot table, history ring) payload along the
//! way and merges it into logd's [`SlotTable`].
//!
//! Wire format mirrors `services/init/src/logging.rs`:
//!
//! * Reply label = `MORE` (0) or `DONE` (1).
//! * `word(0)` = chunk kind: `HEADER` (1), `SLOT` (2), `LINE` (3).
//! * `HEADER`: `word(1)` = total history-entry count, `word(2)` =
//!   active slot count.
//! * `SLOT`: `word(1)` = badge, `word(2)` = name length;
//!   `bytes(3, ...)` = name payload.
//! * `LINE`: `word(1)` = badge, `word(2)` = receipt microseconds,
//!   `word(3)` = byte length; `bytes(4, ...)` = line payload.
//!
//! See `services/logd/docs/handover-protocol.md`.

use ipc::IpcMessage;
use ipc::log_labels::{HANDOVER_PULL, HANDOVER_RELEASE};

use crate::slot::SlotTable;

/// Reply codes mirror `services/init/src/logging.rs::handover_reply`.
const REPLY_MORE: u64 = 0;
const REPLY_DONE: u64 = 1;

/// Chunk-kind codes mirror `services/init/src/logging.rs::handover_kind`.
const KIND_HEADER: u64 = 1;
const KIND_SLOT: u64 = 2;
const KIND_LINE: u64 = 3;

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
pub unsafe fn pull_all(handover_send_cap: u32, ipc_buf: *mut u64, table: &mut SlotTable)
{
    // Bound: 1 header + MAX_SENDERS slots + HISTORY_RING_LEN lines +
    // 1 DONE. init-logd's HISTORY_RING_LEN is 512, MAX_SENDERS is 16
    // — 1024 is comfortable headroom for both. A malformed reply
    // sequence is unreachable in the in-tree init-logd; the bound is
    // a defence against a future protocol drift.
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
        // Init-logd packs SLOT/LINE byte lengths into label bits
        // 16-31 (mirrors the stream-protocol convention). The status
        // (MORE / DONE) lives in the bottom 16 bits.
        let status = reply.label & 0xFFFF;
        match reply.word(0)
        {
            KIND_HEADER =>
            {
                // Header is informational; nothing to install yet.
                let _total = reply.word(1);
                let _active = reply.word(2);
            }
            KIND_SLOT =>
            {
                let badge = reply.word(1);
                let name_len = reply.word(2) as usize;
                let bytes = reply.data_bytes();
                // Inline bytes start at data word 3. Mirror init-logd's
                // `.bytes(3, ...)` packing offset (3 * 8 = 24 bytes).
                let start = 3 * 8;
                let end = (start + name_len).min(bytes.len());
                if start < bytes.len()
                {
                    table.install_from_handover(badge, &bytes[start..end]);
                }
            }
            KIND_LINE =>
            {
                let badge = reply.word(1);
                let us = reply.word(2);
                let byte_len = reply.word(3) as usize;
                let bytes = reply.data_bytes();
                // Inline bytes start at data word 4. Mirror init-logd's
                // `.bytes(4, ...)` packing offset (4 * 8 = 32 bytes).
                let start = 4 * 8;
                let end = (start + byte_len).min(bytes.len());
                if start < bytes.len()
                {
                    table.install_history_line(badge, us, &bytes[start..end]);
                }
            }
            _ =>
            {}
        }
        if status == REPLY_DONE
        {
            return;
        }
        debug_assert_eq!(status, REPLY_MORE);
    }
}

/// Tell init-logd to terminate, retrying until the call is acknowledged.
///
/// Issued once [`pull_all`] settles (DONE, abort, or iteration cap).
/// Init-logd's thread terminates on this message — not on the data drain's
/// `DONE` chunk — so a dropped data chunk (a kernel IPC rendezvous race on
/// the shared, multi-sender log endpoint) cannot leave init-logd running and
/// block procmgr's reap of init's memory caps.
///
/// Init-logd is alive until it processes a RELEASE, so the first *delivered*
/// call is acknowledged and returns `Ok`. The retry recovers a `RELEASE`
/// whose request was dropped (init-logd never saw it, so it is still
/// serving). The cap bounds the loop; a genuinely unreachable init-logd is
/// covered by procmgr's reap backstop, never by an unbounded spin here.
///
/// # Safety
/// `ipc_buf` must be the calling thread's registered IPC buffer.
pub unsafe fn send_release(handover_send_cap: u32, ipc_buf: *mut u64)
{
    const MAX_RETRIES: usize = 64;
    let req = IpcMessage::new(HANDOVER_RELEASE);
    for _ in 0..MAX_RETRIES
    {
        // SAFETY: caller's invariant — ipc_buf is the registered IPC buffer.
        if (unsafe { ipc::ipc_call(handover_send_cap, &req, ipc_buf) }).is_ok()
        {
            return;
        }
        let _ = syscall::thread_yield();
    }
}
