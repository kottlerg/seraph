// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_process_state.rs

//! Process-state codes returned by `procmgr_labels::QUERY_PROCESS`.
//!
//! Populated in data word 0 of the reply. Word 1 carries an accompanying
//! exit reason (encoded as `docs/process-lifecycle.md` § Exit reason
//! defines); it is zero for states in which the exit reason is not
//! meaningful (ALIVE, CREATED, UNKNOWN).

/// Entry exists and the process has been started. Running or blocked.
pub const ALIVE: u64 = 0;
/// Entry exists but the process has not yet been started (still in the
/// suspended post-CREATE state). Rare for external queriers to see.
pub const CREATED: u64 = 1;
/// No entry for this badge — reaped or destroyed more than the
/// recent-exit window ago (30 s), or within it but no longer recorded
/// (retention is best-effort: when procmgr's heap cannot hold a new
/// record, the oldest record makes room, or the new one is dropped), or
/// the badge was never valid. Equivalent to `ESRCH`.
pub const UNKNOWN: u64 = 2;
/// The process has exited: its address space has ended or its main thread
/// is already `Exited` (before procmgr's death-event drain reaps it), or
/// procmgr reaped or destroyed (`DESTROY_PROCESS`) it within the
/// recent-exit window (30 s) and still holds its record (best-effort; see
/// [`UNKNOWN`]). Reply word 1 carries the kernel-encoded `exit_reason`:
/// the address space's first terminal end, else the main thread's retained
/// reason; for a destroyed process that had not ended, `EXIT_KILLED`.
/// After the window, queries on the same badge return `UNKNOWN`.
pub const EXITED: u64 = 3;
