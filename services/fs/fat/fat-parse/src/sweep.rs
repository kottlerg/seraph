// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/sweep.rs

//! When `fatfs` sweeps its sessions for those whose client is gone.
//!
//! A session lives while its client holds a copy of its liveness cap
//! (services/fs/docs/fs-driver-protocol.md § Label 23). `fatfs` ends the
//! sessions whose client holds none when memmgr signals the end of a donation,
//! and also on the schedule [`SweepSchedule`] keeps, counted in `FS_SESSION`
//! requests, so a client that drops its liveness cap without releasing its
//! node still has its session ended.

/// Fewest sessions started between two scheduled sweeps. It bounds no
/// capacity: past it the interval follows the sessions a sweep leaves live
/// ([`SweepSchedule`]). Below that it sets what a small table holds dead
/// before a sweep, at most twice it: 128 sessions, each with three `CSpace`
/// slots and a Notification in fatfs, about 45 KiB, and a first page charged
/// to its client's node, against one sweep's lock hold per 64 sessions.
pub const SWEEP_FLOOR: usize = 64;

/// When the next scheduled sweep falls due: once the sessions started since
/// the last sweep reach the larger of [`SWEEP_FLOOR`] and the live sessions
/// that sweep left. A sweep reads every live session once: at most the
/// sessions the last sweep left plus those started since, each count at most
/// the interval, so a sweep costs at most two reads per session started since
/// the last, and the table holds at most twice the interval, live and dead,
/// until the next sweep.
pub struct SweepSchedule
{
    /// Sessions started since the last sweep.
    since: usize,
    /// Sessions after which the next sweep is due.
    interval: usize,
}

impl Default for SweepSchedule
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl SweepSchedule
{
    /// A schedule with no session counted yet, whose first sweep falls due
    /// after [`SWEEP_FLOOR`] sessions.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            since: 0,
            interval: SWEEP_FLOOR,
        }
    }

    /// Count one session; `true` when a sweep is due before it is started.
    pub fn note_new(&mut self) -> bool
    {
        self.since = self.since.saturating_add(1);
        self.since >= self.interval
    }

    /// Record a sweep that left `live` sessions: the next falls due after
    /// the larger of [`SWEEP_FLOOR`] and `live` further sessions.
    pub fn swept(&mut self, live: usize)
    {
        self.since = 0;
        self.interval = live.max(SWEEP_FLOOR);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Sessions counted until `schedule` reports a sweep due, at most
    /// `bound`.
    fn sessions_until_due(schedule: &mut SweepSchedule, bound: usize) -> Option<usize>
    {
        (1..=bound).find(|_| schedule.note_new())
    }

    #[test]
    fn a_sweep_falls_due_after_the_floor_while_few_sessions_live()
    {
        let mut schedule = SweepSchedule::new();
        assert_eq!(sessions_until_due(&mut schedule, 1000), Some(SWEEP_FLOOR));
        schedule.swept(3);
        assert_eq!(sessions_until_due(&mut schedule, 1000), Some(SWEEP_FLOOR));
    }

    #[test]
    fn a_sweep_that_leaves_many_live_sessions_waits_for_as_many_more()
    {
        let mut schedule = SweepSchedule::new();
        schedule.swept(SWEEP_FLOOR * 5);
        assert_eq!(
            sessions_until_due(&mut schedule, SWEEP_FLOOR * 10),
            Some(SWEEP_FLOOR * 5)
        );
    }
}
