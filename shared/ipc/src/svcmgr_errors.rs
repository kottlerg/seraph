// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/svcmgr_errors.rs

//! Error replies from svcmgr.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// Reserved; not emitted by the current svcmgr.
pub const TABLE_FULL: u64 = 1;
/// Invalid service name (too long / malformed).
pub const INVALID_NAME: u64 = 2;
/// A required cap is missing: `PUBLISH_ENDPOINT` carried no `caps[0]`,
/// or `QUERY_ENDPOINT` could not derive from the stored cap (its
/// publisher is gone; the entry is evicted).
pub const INSUFFICIENT_CAPS: u64 = 3;
/// Reserved; not emitted by the current svcmgr.
pub const EVENT_QUEUE_FAILED: u64 = 4;
/// Discovery registry lookup: name is not published.
pub const UNKNOWN_NAME: u64 = 5;
/// Discovery registry publish: table full or duplicate name.
pub const REGISTER_REJECTED: u64 = 6;
/// Reserved; not emitted by the current svcmgr. Each handover-endowment
/// `CAPS` round carries the caller's `SVCMGR_LABELS_VERSION` in `data[1]`
/// (after the `svcmgr_endowment::kind::CAPS` round kind in `data[0]`); on
/// a mismatch svcmgr's bootstrap fails without replying this code.
pub const LABEL_VERSION_MISMATCH: u64 = 7;
/// Caller's badge lacks [`svcmgr_labels::PUBLISH_AUTHORITY`] on a
/// `PUBLISH_ENDPOINT` request, [`svcmgr_labels::HANDOVER_AUTHORITY`] on
/// a `HANDOVER_COMPLETE`, or [`crate::stop_labels::STOP_AUTHORITY`] on
/// a `LIST_STOP_SOURCES`, or the handover has already run. The stop labels
/// svcmgr serves reply in [`crate::stop_labels`]'s codes.
pub const UNAUTHORIZED: u64 = 8;
/// Client-side: the underlying `ipc_call` returned `Err` (no reply
/// from svcmgr, transport-level failure), for a client that reports it
/// in the svcmgr status space. Never emitted by svcmgr itself; no
/// in-tree client synthesises it.
pub const IPC_FAILED: u64 = 9;
/// Unknown opcode on svcmgr endpoint.
pub const UNKNOWN_OPCODE: u64 = 0xFFFF;
