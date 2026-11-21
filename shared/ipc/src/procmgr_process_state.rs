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
/// reason, read at the first `EXITED` answer, which fixes it for later
/// answers and for the teardown, or else at the reap or destroy; for a
/// destroyed process that had not ended, `EXIT_KILLED`.
/// After the window, queries on the same badge return `UNKNOWN`.
pub const EXITED: u64 = 3;

/// The exit reason a holder of an ended process's handle states the end by:
/// the one procmgr gives the process, from its `QUERY_PROCESS` answer,
/// `answer` (word 0, the state, and word 1, the reason; `None` for a failed
/// or refused call), when procmgr answers [`EXITED`]; else `posted`, the
/// reason of the death post that reported the end.
///
/// The post can come from the observer of the process's main thread, whose
/// own end is the process's end only when it is the first terminal end of
/// any of its threads (`docs/process-lifecycle.md` § Exit reason): a worker
/// thread's end after the main thread's own exit, before procmgr fixes the
/// process's reason, is the process's reason, which procmgr gives and the
/// post does not. An answer other than `EXITED` gives no reason: an
/// [`ALIVE`] or [`CREATED`] process has not ended, and [`UNKNOWN`] (no
/// record) leaves the post's reason the best one the holder has.
#[must_use]
pub fn process_reason(answer: core::option::Option<(u64, u64)>, posted: u64) -> u64
{
    match answer
    {
        core::option::Option::Some((EXITED, reason)) => reason,
        _ => posted,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A fault reason, as the kernel encodes one.
    const FAULT: u64 = syscall_abi::EXIT_FAULT_BASE + 14;

    #[test]
    fn process_reason_takes_procmgrs_exited_reason()
    {
        // The main thread's own exit posted 0; a worker's fault ended the
        // process.
        assert_eq!(process_reason(Some((EXITED, FAULT)), 0), FAULT);
        assert_eq!(process_reason(Some((EXITED, 0)), FAULT), 0);
    }

    #[test]
    fn process_reason_keeps_the_post_without_an_exited_answer()
    {
        for state in [ALIVE, CREATED, UNKNOWN]
        {
            assert_eq!(process_reason(Some((state, 0)), FAULT), FAULT);
            assert_eq!(process_reason(Some((state, FAULT)), 0), 0);
        }
        assert_eq!(process_reason(None, FAULT), FAULT);
    }
}
