// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memmgr_errors.rs

//! Error replies from memmgr.
//!
//! memmgr never panics on allocation failure; the caller decides whether
//! to retry, fall back, or propagate the OOM upstream.

/// Request handled.
pub const SUCCESS: u64 = 0;
/// `REQUIRE_CONTIGUOUS` was set and no free run satisfies `want_pages`.
/// Caller may retry without the flag, or fail.
pub const OUT_OF_MEMORY_CONTIGUOUS: u64 = 1;
/// Pool cannot cover `want_pages` even fragmented. System-wide RAM
/// exhaustion.
pub const OUT_OF_MEMORY_BEST_EFFORT: u64 = 2;
/// memmgr could not allocate per-process tracking metadata for a frame or
/// region: the self-hosted node arena could not grow because system RAM is
/// exhausted. Per-process region and frame counts are otherwise RAM-bound,
/// not capped by a constant.
pub const QUOTA: u64 = 3;
/// A malformed request: the per-label cases are listed in
/// `services/memmgr/docs/ipc-interface.md` (for example `want_pages == 0`
/// or reserved flag bits on `REQUEST_MEMORY_CAPS`, an unregistered badge,
/// or a bad region on `REGISTER_REGION`).
pub const INVALID_ARGUMENT: u64 = 4;
/// Procmgr-only label called over a non-procmgr badge, a node label
/// called over a badge that is no node handle, or another label called
/// over a node handle.
pub const UNAUTHORIZED: u64 = 5;
/// `REGISTER_PROCESS` could not complete: the tracking table could not
/// take a new entry, the badge draw failed, or the reply cap could not
/// be derived. Procmgr handles this as a process-creation failure.
pub const TOO_MANY_PROCESSES: u64 = 6;
/// Caller's compiled `MEMMGR_LABELS_VERSION` does not match the receiver's.
/// `REGISTER_PROCESS` is the handshake entry point and carries the
/// caller's version as `data[0]`; mismatch here means the caller was
/// built against a different revision of `shared/ipc`.
pub const LABEL_VERSION_MISMATCH: u64 = 7;
/// The request would take the subtree of the caller's budget node, or of
/// an ancestor, over its max. Distinct from the out-of-memory codes: the
/// RAM may exist, and the caller's budget refuses it.
pub const LIMIT: u64 = 8;
/// `SWAP_TAKE`: memmgr's walk found no evicted chunk to take within its bound;
/// a later call goes on from where it stopped.
pub const NOTHING_TO_TAKE: u64 = 9;
/// `SWAP_TAKE`: every registered swap slot is taken.
pub const SWAP_FULL: u64 = 10;
/// `SWAP_RESTORE`: memmgr could not make the slot's chunk resident; the
/// reply's `data[0]` is the fault decline word the swap service forwards the
/// held fault with.
pub const RESTORE_DECLINED: u64 = 11;
