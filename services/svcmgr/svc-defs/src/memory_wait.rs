// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/memory_wait.rs

//! What svcmgr does with a restart whose `CREATE_FROM_FILE` failed, and when a
//! restart that waits for memory is retried
//! (`services/svcmgr/docs/restart-protocol.md` § Decision tree).
//!
//! memmgr refuses a grant to a budget node outside the system reserve while
//! its pressure level reads `CRITICAL` (`services/memmgr/docs/memory-pool.md`
//! § Memory pressure), so procmgr's create of such a service then replies
//! `OUT_OF_MEMORY`. That refusal lasts only while the level stays there, and
//! memmgr signals each change of level on the Notification the std runtime
//! registers for every process; svcmgr waits on it rather than leave the
//! service down.

use ipc::memmgr_labels::PRESSURE_CRITICAL;

/// Why a restart's create failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CreateFailure
{
    /// procmgr replied `OUT_OF_MEMORY`.
    OutOfMemory,
    /// Any other failure: a walk, a badge mint, a transport error, another
    /// procmgr refusal, a short reply.
    Other,
}

/// What follows a restart's failed create.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AfterCreateFailure
{
    /// The service is permanently down: its `critical` key decides the rest.
    Permanent,
    /// Decide the restart again at once, charging the budget again: the level
    /// had already left `CRITICAL` when svcmgr read it.
    RetryNow,
    /// The restart waits for memmgr's level to leave `CRITICAL`.
    WaitForMemory,
}

/// What follows a restart whose create failed with `failure`.
///
/// `reserve_path` is whether the service keeps the permanent path whatever
/// the failure: a service created in the system reserve (`reserve = yes`),
/// whose refusal means the reserve itself is spent, and the log sink, whose
/// death's lines svcmgr holds until a next instance runs. `registered` is
/// whether svcmgr has the pressure Notification to wait on. `level` is
/// memmgr's pressure level read after the refusal (`PRESSURE_*`), `None`
/// when memmgr did not answer.
///
/// An `OUT_OF_MEMORY` refusal of any other service waits while the level
/// reads `CRITICAL`, or cannot be read, since memmgr's next change of level
/// wakes svcmgr; read below `CRITICAL`, the level fell between the refusal and
/// the read, and the restart is decided again at once. Without a
/// registration nothing would wake the wait, so the service is down.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`reserve_path` and `registered` are the two facts besides the failure and the \
              level that the decision reads"
)]
pub fn after_create_failure(
    failure: CreateFailure,
    reserve_path: bool,
    registered: bool,
    level: Option<u64>,
) -> AfterCreateFailure
{
    if failure != CreateFailure::OutOfMemory || reserve_path || !registered
    {
        return AfterCreateFailure::Permanent;
    }
    match level
    {
        Some(level) if level != PRESSURE_CRITICAL => AfterCreateFailure::RetryNow,
        _ => AfterCreateFailure::WaitForMemory,
    }
}

/// Whether a restart that waits for memory is retried, given memmgr's level
/// read after a signal of its pressure Notification: once it reads below
/// `CRITICAL`. An unanswered read keeps the wait.
#[must_use]
pub fn retry_due(level: Option<u64>) -> bool
{
    matches!(level, Some(level) if level != PRESSURE_CRITICAL)
}

#[cfg(test)]
mod tests
{
    use ipc::memmgr_labels::{PRESSURE_CRITICAL, PRESSURE_LOW, PRESSURE_NORMAL};

    use super::AfterCreateFailure::{Permanent, RetryNow, WaitForMemory};
    use super::CreateFailure::{Other, OutOfMemory};
    use super::{after_create_failure, retry_due};

    // The case the wait is for: a non-reserve service refused while the level
    // reads CRITICAL, as when oomd stops a service that is not the one holding
    // the memory and svcmgr restarts it at once.
    #[test]
    fn a_refusal_for_memory_at_critical_waits()
    {
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_CRITICAL)),
            WaitForMemory
        );
    }

    // The refusal was made at CRITICAL and the level fell before svcmgr read
    // it: no signal of a later change need come, so waiting would leave the
    // service down; the restart is decided again at once.
    #[test]
    fn a_refusal_for_memory_read_below_critical_retries_at_once()
    {
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_LOW)),
            RetryNow
        );
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_NORMAL)),
            RetryNow
        );
    }

    #[test]
    fn an_unread_level_waits_for_memmgrs_signal()
    {
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, None),
            WaitForMemory
        );
    }

    #[test]
    fn a_reserve_service_or_the_log_sink_is_down_at_once()
    {
        for level in [None, Some(PRESSURE_CRITICAL), Some(PRESSURE_NORMAL)]
        {
            assert_eq!(
                after_create_failure(OutOfMemory, true, true, level),
                Permanent
            );
        }
    }

    #[test]
    fn without_a_pressure_registration_nothing_wakes_a_wait()
    {
        for level in [None, Some(PRESSURE_CRITICAL), Some(PRESSURE_NORMAL)]
        {
            assert_eq!(
                after_create_failure(OutOfMemory, false, false, level),
                Permanent
            );
        }
    }

    #[test]
    fn every_other_failure_is_permanent()
    {
        for level in [None, Some(PRESSURE_CRITICAL), Some(PRESSURE_NORMAL)]
        {
            assert_eq!(after_create_failure(Other, false, true, level), Permanent);
        }
    }

    #[test]
    fn a_wait_ends_once_the_level_reads_below_critical()
    {
        assert!(retry_due(Some(PRESSURE_LOW)));
        assert!(retry_due(Some(PRESSURE_NORMAL)));
        assert!(!retry_due(Some(PRESSURE_CRITICAL)));
        assert!(!retry_due(None));
    }
}
