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
//! * `SLOT`: `word(1)` = token, `word(2)` = name length;
//!   `bytes(3, ...)` = name payload.
//! * `LINE`: `word(1)` = token, `word(2)` = receipt microseconds,
//!   `word(3)` = byte length; `bytes(4, ...)` = line payload.
//!
//! See `services/logd/docs/handover-protocol.md`.

use ipc::IpcMessage;
use ipc::log_labels::HANDOVER_PULL;

use crate::slot::SlotTable;

/// Reply codes mirror `services/init/src/logging.rs::handover_reply`.
const REPLY_MORE: u64 = 0;
const REPLY_DONE: u64 = 1;

/// Chunk-kind codes mirror `services/init/src/logging.rs::handover_kind`.
const KIND_HEADER: u64 = 1;
const KIND_SLOT: u64 = 2;
const KIND_LINE: u64 = 3;

/// Drain init-logd's handover state into `table`. Returns on the
/// first `DONE` reply (init-logd has at that point set its
/// handover-complete flag and will self-terminate on its next loop
/// iteration). Caps the loop at a generous iteration bound to
/// guarantee termination on a malformed init-logd reply.
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
                let token = reply.word(1);
                let name_len = reply.word(2) as usize;
                let bytes = reply.data_bytes();
                // Inline bytes start at data word 3. Mirror init-logd's
                // `.bytes(3, ...)` packing offset (3 * 8 = 24 bytes).
                let start = 3 * 8;
                let end = (start + name_len).min(bytes.len());
                if start < bytes.len()
                {
                    table.install_from_handover(token, &bytes[start..end]);
                }
            }
            KIND_LINE =>
            {
                let token = reply.word(1);
                let us = reply.word(2);
                let byte_len = reply.word(3) as usize;
                let bytes = reply.data_bytes();
                // Inline bytes start at data word 4. Mirror init-logd's
                // `.bytes(4, ...)` packing offset (4 * 8 = 32 bytes).
                let start = 4 * 8;
                let end = (start + byte_len).min(bytes.len());
                if start < bytes.len()
                {
                    table.install_history_line(token, us, &bytes[start..end]);
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
