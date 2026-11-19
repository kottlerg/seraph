// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/memory_wait.rs

//! What svcmgr does with a restart whose `CREATE_FROM_FILE` failed, and when a
//! restart that waits for memory is retried
//! (`services/svcmgr/docs/restart-protocol.md` § Decision tree).
//!
//! memmgr refuses a request from a budget node outside the system reserve
//! that would leave fewer free pages outside `promised` than the growth floor
//! (`services/memmgr/docs/memory-pool.md` § Allocation), and procmgr's create
//! of such a service then replies `OUT_OF_MEMORY`. Its pressure level reads
//! `CRITICAL` at or below that floor, and leaves it only once the free pool
//! clears the floor by a hysteresis band (§ Memory pressure), so a create
//! needing more than the margin above the floor is refused below `CRITICAL`
//! too, as is one needing a contiguous run memmgr cannot find. Only memory
//! coming free ends such a refusal, and memmgr signals each change of level on
//! the Notification the std runtime registers for every process; svcmgr waits
//! on it rather than leave the service down.

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
    /// read below `CRITICAL` after the refusal, and the decision had made no
    /// such retry yet.
    RetryNow,
    /// The restart waits for memmgr's next change of level to below
    /// `CRITICAL` ([`retry_due`]).
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
/// when memmgr did not answer. `retried` is whether this decision has already
/// retried at once ([`AfterCreateFailure::RetryNow`]).
///
/// An `OUT_OF_MEMORY` refusal of any other service waits while the level
/// reads `CRITICAL`, or cannot be read, since memmgr's next change of level
/// wakes svcmgr. Read below `CRITICAL`, the level may have fallen between the
/// refusal and the read, so the restart is decided again at once, once: a
/// second refusal read below `CRITICAL` is one memmgr makes at that level (a
/// create larger than the margin above the floor), which no retry before memory
/// comes free ends, so it waits too, and the budget is not spent on it. Without
/// a registration nothing would wake the wait, so the service is down.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`reserve_path`, `registered` and `retried` are the facts besides the failure \
              and the level that the decision reads"
)]
pub fn after_create_failure(
    failure: CreateFailure,
    reserve_path: bool,
    registered: bool,
    level: Option<u64>,
    retried: bool,
) -> AfterCreateFailure
{
    if failure != CreateFailure::OutOfMemory || reserve_path || !registered
    {
        return AfterCreateFailure::Permanent;
    }
    match level
    {
        Some(level) if level != PRESSURE_CRITICAL && !retried => AfterCreateFailure::RetryNow,
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
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_CRITICAL), false),
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
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_LOW), false),
            RetryNow
        );
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_NORMAL), false),
            RetryNow
        );
    }

    // memmgr also refuses below CRITICAL a create larger than the margin above
    // the growth floor: the one retry at once is refused again, and the restart
    // then waits for memory to come free rather than spend the budget.
    #[test]
    fn a_second_refusal_read_below_critical_waits()
    {
        for level in [PRESSURE_LOW, PRESSURE_NORMAL]
        {
            assert_eq!(
                after_create_failure(OutOfMemory, false, true, Some(level), true),
                WaitForMemory
            );
        }
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, Some(PRESSURE_CRITICAL), true),
            WaitForMemory
        );
        assert_eq!(
            after_create_failure(OutOfMemory, true, true, Some(PRESSURE_LOW), true),
            Permanent
        );
        assert_eq!(
            after_create_failure(Other, false, true, Some(PRESSURE_LOW), true),
            Permanent
        );
    }

    #[test]
    fn an_unread_level_waits_for_memmgrs_signal()
    {
        assert_eq!(
            after_create_failure(OutOfMemory, false, true, None, false),
            WaitForMemory
        );
    }

    #[test]
    fn a_reserve_service_or_the_log_sink_is_down_at_once()
    {
        for level in [None, Some(PRESSURE_CRITICAL), Some(PRESSURE_NORMAL)]
        {
            assert_eq!(
                after_create_failure(OutOfMemory, true, true, level, false),
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
                after_create_failure(OutOfMemory, false, false, level, false),
                Permanent
            );
        }
    }

    #[test]
    fn every_other_failure_is_permanent()
    {
        for level in [None, Some(PRESSURE_CRITICAL), Some(PRESSURE_NORMAL)]
        {
            assert_eq!(
                after_create_failure(Other, false, true, level, false),
                Permanent
            );
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
