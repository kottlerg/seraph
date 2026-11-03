// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/roster.rs

//! Settle bookkeeping for one batch of spawned drivers.
//!
//! devmgr serves a driver's service endpoint through the registry only once
//! the driver has reported its device ready. It spawns a batch of drivers,
//! then settles the batch: each driver either reports ready (`DRIVER_READY`)
//! or dies, and devmgr observes the death through a death observer bound on
//! the driver's thread. [`Roster`] records each driver of the batch under its
//! device badge, takes those two events, says when the batch is settled, and
//! yields each driver's outcome in spawn order, so the served drivers keep
//! that order for the registry's instance ordinals. [`settle`] is devmgr's
//! settle loop over those events; the kernel objects behind them (the wait
//! set, the death event queue, the private driver endpoint) reach it through
//! [`SettleEvents`], which keeps this module free of syscalls and
//! host-testable.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

/// Where one driver of the batch stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverState
{
    /// Spawned; neither a ready report nor a death observed yet.
    Pending,
    /// Reported its device ready, and no death observed since.
    Ready,
    /// Died. Terminal: a later ready report does not revive it.
    Dead,
}

/// What [`Roster::mark_ready`] made of a ready report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyReport
{
    /// The driver was pending and is now ready.
    Accepted,
    /// The driver had already reported ready; nothing changed.
    Repeated,
    /// The driver's death was already observed; it stays dead.
    AfterDeath,
    /// No driver of the batch carries that badge.
    Unknown,
}

impl ReadyReport
{
    /// Whether the report is answered as accepted: the driver is ready
    /// after it. A report after the driver's death, or from a badge the batch
    /// does not hold, is refused, and the driver exits on the refusal.
    #[must_use]
    pub fn is_accepted(self) -> bool
    {
        matches!(self, Self::Accepted | Self::Repeated)
    }
}

/// What woke a settle loop's wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettleWake
{
    /// The death event queue holds at least one post.
    Death,
    /// A driver call is queued on the batch's private endpoint.
    Driver,
    /// Any other wake; the loop waits again.
    Other,
}

/// The kernel objects one batch settles over, as [`settle`] drives them.
pub trait SettleEvents<T>
{
    /// Why a wait failed.
    type Error;

    /// Block until the batch's wait set reports a source.
    ///
    /// # Errors
    /// Returns the wait's failure; [`settle`] then ends early.
    fn wait(&mut self) -> Result<SettleWake, Self::Error>;

    /// Take the next death post the event queue holds, if any, without
    /// blocking.
    fn try_death(&mut self) -> Option<u64>;

    /// Receive one driver call on the private endpoint and answer it,
    /// taking a ready report into `roster`.
    fn serve_driver(&mut self, roster: &mut Roster<T>);

    /// A death post named the driver under `badge` (`reason` is the post's
    /// low half), and `roster` now holds it dead.
    fn on_death(&mut self, badge: u64, reason: u64);
}

/// Split a death post into the driver's device badge (the correlator, the
/// high 32 bits) and the exit reason (the low 32 bits).
#[must_use]
pub fn death_post_parts(post: u64) -> (u64, u64)
{
    (post >> 32, post & 0xFFFF_FFFF)
}

/// Settle `roster`: serve the drivers' calls and take their deaths until
/// every driver has reported ready or died, then take every death still
/// queued, so a driver that died after reporting ready, with its death
/// queued when the last report settled the batch, is not served.
///
/// # Errors
/// Returns the wait's failure, after taking the queued deaths; the drivers
/// still pending are then not served.
pub fn settle<T, E: SettleEvents<T>>(events: &mut E, roster: &mut Roster<T>)
-> Result<(), E::Error>
{
    let mut result = Ok(());
    while !roster.is_settled()
    {
        match events.wait()
        {
            Ok(SettleWake::Death) => drain_deaths(events, roster),
            Ok(SettleWake::Driver) => events.serve_driver(roster),
            Ok(SettleWake::Other) =>
            {}
            Err(e) =>
            {
                result = Err(e);
                break;
            }
        }
    }
    drain_deaths(events, roster);
    result
}

/// Mark dead every driver whose death the event queue holds.
fn drain_deaths<T, E: SettleEvents<T>>(events: &mut E, roster: &mut Roster<T>)
{
    while let Some(post) = events.try_death()
    {
        let (badge, reason) = death_post_parts(post);
        if roster.mark_dead(badge)
        {
            events.on_death(badge, reason);
        }
    }
}

/// One driver of the batch: its device badge, the caller's record of it,
/// and its state.
struct Entry<T>
{
    badge: u64,
    driver: T,
    state: DriverState,
}

/// The drivers of one spawn batch, in spawn order.
pub struct Roster<T>
{
    entries: Vec<Entry<T>>,
}

impl<T> Default for Roster<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> Roster<T>
{
    /// An empty roster.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
        }
    }

    /// Reserve room for one more driver, so a spawn is attempted only when
    /// its driver can be recorded.
    ///
    /// # Errors
    /// Returns the allocation error when the roster cannot grow.
    pub fn try_reserve_one(&mut self) -> Result<(), TryReserveError>
    {
        self.entries.try_reserve(1)
    }

    /// Record a spawned driver as pending under its device `badge`. Returns
    /// the driver back when the roster has no reserved room for it (call
    /// [`try_reserve_one`](Self::try_reserve_one) first) or already holds
    /// that badge, which device badges never repeat.
    ///
    /// # Errors
    /// Returns `driver` unrecorded in either case.
    pub fn add(&mut self, badge: u64, driver: T) -> Result<(), T>
    {
        if self.entries.len() == self.entries.capacity()
            || self.entries.iter().any(|e| e.badge == badge)
        {
            return Err(driver);
        }
        self.entries.push(Entry {
            badge,
            driver,
            state: DriverState::Pending,
        });
        Ok(())
    }

    /// The number of drivers recorded.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.entries.len()
    }

    /// Whether no driver is recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.entries.is_empty()
    }

    /// The state of the driver under `badge`, if the batch holds one.
    #[must_use]
    pub fn state(&self, badge: u64) -> Option<DriverState>
    {
        self.entries
            .iter()
            .find(|e| e.badge == badge)
            .map(|e| e.state)
    }

    /// Take a ready report from the driver under `badge`.
    pub fn mark_ready(&mut self, badge: u64) -> ReadyReport
    {
        let Some(entry) = self.entries.iter_mut().find(|e| e.badge == badge)
        else
        {
            return ReadyReport::Unknown;
        };
        match entry.state
        {
            DriverState::Pending =>
            {
                entry.state = DriverState::Ready;
                ReadyReport::Accepted
            }
            DriverState::Ready => ReadyReport::Repeated,
            DriverState::Dead => ReadyReport::AfterDeath,
        }
    }

    /// Take the death of the driver under `badge`, whatever it reported
    /// before. Returns `false` when no driver of the batch carries that
    /// badge.
    pub fn mark_dead(&mut self, badge: u64) -> bool
    {
        let Some(entry) = self.entries.iter_mut().find(|e| e.badge == badge)
        else
        {
            return false;
        };
        entry.state = DriverState::Dead;
        true
    }

    /// Whether every driver has reported ready or died. An empty roster is
    /// settled.
    #[must_use]
    pub fn is_settled(&self) -> bool
    {
        self.entries.iter().all(|e| e.state != DriverState::Pending)
    }

    /// Consume the roster, yielding each driver with whether the registry
    /// serves it, in spawn order. A driver is served when it reported ready
    /// and was not seen to die; one still pending is not served, so a caller
    /// that stops settling early serves only the drivers known ready.
    pub fn into_outcomes(self) -> impl Iterator<Item = (bool, T)>
    {
        self.entries
            .into_iter()
            .map(|e| (e.state == DriverState::Ready, e.driver))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A roster of `badges.len()` pending drivers, each recorded as its own
    /// badge.
    fn roster_of(badges: &[u64]) -> Roster<u64>
    {
        let mut r = Roster::new();
        for &b in badges
        {
            r.try_reserve_one().unwrap();
            r.add(b, b).unwrap();
        }
        r
    }

    fn served(r: Roster<u64>) -> Vec<u64>
    {
        r.into_outcomes()
            .filter_map(|(served, d)| served.then_some(d))
            .collect()
    }

    #[test]
    fn empty_roster_is_settled_and_serves_nothing()
    {
        let r: Roster<u64> = Roster::new();
        assert!(r.is_settled());
        assert!(r.is_empty());
        assert!(served(r).is_empty());
    }

    #[test]
    fn batch_settles_only_once_every_driver_is_resolved()
    {
        let mut r = roster_of(&[1, 2, 3]);
        assert!(!r.is_settled());
        assert_eq!(r.mark_ready(1), ReadyReport::Accepted);
        assert!(!r.is_settled());
        assert!(r.mark_dead(2));
        assert!(!r.is_settled());
        assert_eq!(r.mark_ready(3), ReadyReport::Accepted);
        assert!(r.is_settled());
    }

    #[test]
    fn driver_dying_in_setup_is_not_served_and_later_ordinals_close_up()
    {
        // The first of three disks' drivers exits in its device setup: the
        // other two are served at ordinals 0 and 1, in spawn order.
        let mut r = roster_of(&[1, 2, 3]);
        assert!(r.mark_dead(1));
        assert_eq!(r.mark_ready(3), ReadyReport::Accepted);
        assert_eq!(r.mark_ready(2), ReadyReport::Accepted);
        assert!(r.is_settled());
        assert_eq!(served(r), [2, 3]);
    }

    #[test]
    fn death_after_ready_withdraws_the_driver()
    {
        let mut r = roster_of(&[1, 2]);
        assert_eq!(r.mark_ready(1), ReadyReport::Accepted);
        assert_eq!(r.mark_ready(2), ReadyReport::Accepted);
        assert!(r.mark_dead(1));
        assert_eq!(r.state(1), Some(DriverState::Dead));
        assert_eq!(served(r), [2]);
    }

    #[test]
    fn ready_report_after_death_does_not_revive()
    {
        let mut r = roster_of(&[1]);
        assert!(r.mark_dead(1));
        assert_eq!(r.mark_ready(1), ReadyReport::AfterDeath);
        assert_eq!(r.state(1), Some(DriverState::Dead));
        assert!(served(r).is_empty());
    }

    #[test]
    fn repeated_and_unknown_reports_change_nothing()
    {
        let mut r = roster_of(&[1, 2]);
        assert_eq!(r.mark_ready(1), ReadyReport::Accepted);
        assert_eq!(r.mark_ready(1), ReadyReport::Repeated);
        assert_eq!(r.mark_ready(9), ReadyReport::Unknown);
        assert!(!r.mark_dead(9));
        assert_eq!(r.state(2), Some(DriverState::Pending));
        assert_eq!(r.state(9), None);
        assert!(!r.is_settled());
    }

    #[test]
    fn pending_driver_is_not_served()
    {
        let mut r = roster_of(&[1, 2]);
        assert_eq!(r.mark_ready(2), ReadyReport::Accepted);
        assert_eq!(served(r), [2]);
    }

    /// A scripted settle source: `wakes` in order, a death queue the
    /// script fills as it goes, and the badge each driver call reports ready.
    #[derive(Default)]
    struct Script
    {
        /// Each wake, with the death posts queued just before it reports.
        wakes: Vec<(Result<SettleWake, ()>, Vec<u64>)>,
        /// The ready-report badge of each driver call, in order.
        calls: Vec<u64>,
        queue: Vec<u64>,
        replies: Vec<bool>,
        deaths: Vec<(u64, u64)>,
    }

    impl SettleEvents<u64> for Script
    {
        type Error = ();

        fn wait(&mut self) -> Result<SettleWake, ()>
        {
            let (wake, posts) = self.wakes.remove(0);
            self.queue.extend(posts);
            wake
        }

        fn try_death(&mut self) -> Option<u64>
        {
            (!self.queue.is_empty()).then(|| self.queue.remove(0))
        }

        fn serve_driver(&mut self, roster: &mut Roster<u64>)
        {
            let badge = self.calls.remove(0);
            self.replies.push(roster.mark_ready(badge).is_accepted());
        }

        fn on_death(&mut self, badge: u64, reason: u64)
        {
            self.deaths.push((badge, reason));
        }
    }

    fn post(badge: u64, reason: u64) -> u64
    {
        (badge << 32) | reason
    }

    #[test]
    fn death_queued_when_the_last_report_settles_is_taken()
    {
        // Driver 1 reports ready, then dies; its death is queued when the
        // wait reports driver 2's ready call first, which settles the batch.
        let mut r = roster_of(&[1, 2]);
        let mut s = Script {
            wakes: vec![
                (Ok(SettleWake::Driver), vec![]),
                (Ok(SettleWake::Driver), vec![post(1, 7)]),
            ],
            calls: vec![1, 2],
            ..Script::default()
        };
        assert_eq!(settle(&mut s, &mut r), Ok(()));
        assert_eq!(s.deaths, [(1, 7)]);
        assert_eq!(served(r), [2]);
    }

    #[test]
    fn settle_serves_reports_and_takes_deaths_until_settled()
    {
        let mut r = roster_of(&[1, 2, 3]);
        let mut s = Script {
            wakes: vec![
                (Ok(SettleWake::Other), vec![]),
                (Ok(SettleWake::Death), vec![post(2, 1), post(9, 1)]),
                (Ok(SettleWake::Driver), vec![]),
                (Ok(SettleWake::Driver), vec![]),
                (Ok(SettleWake::Driver), vec![]),
            ],
            calls: vec![3, 2, 1],
            ..Script::default()
        };
        assert_eq!(settle(&mut s, &mut r), Ok(()));
        // Driver 2's report after its death is refused; the post for a badge
        // the batch does not hold changes nothing; the loop stops once settled.
        assert_eq!(s.replies, [true, false, true]);
        assert_eq!(s.deaths, [(2, 1)]);
        assert!(s.wakes.is_empty());
        assert_eq!(served(r), [1, 3]);
    }

    #[test]
    fn wait_failure_ends_the_settle_with_pending_not_served()
    {
        let mut r = roster_of(&[1, 2, 3]);
        let mut s = Script {
            wakes: vec![
                (Ok(SettleWake::Driver), vec![]),
                (Err(()), vec![post(2, 3)]),
            ],
            calls: vec![1],
            ..Script::default()
        };
        assert_eq!(settle(&mut s, &mut r), Err(()));
        assert_eq!(s.deaths, [(2, 3)]);
        assert_eq!(served(r), [1]);
    }

    #[test]
    fn death_post_splits_into_badge_and_reason()
    {
        assert_eq!(
            death_post_parts(post(0xFFFF_FFFF, 0x8000_0001)),
            (0xFFFF_FFFF, 0x8000_0001)
        );
        assert_eq!(death_post_parts(0), (0, 0));
    }

    #[test]
    fn only_accepted_and_repeated_reports_are_answered_as_accepted()
    {
        assert!(ReadyReport::Accepted.is_accepted());
        assert!(ReadyReport::Repeated.is_accepted());
        assert!(!ReadyReport::AfterDeath.is_accepted());
        assert!(!ReadyReport::Unknown.is_accepted());
    }

    #[test]
    fn add_refuses_without_reserved_room_or_for_a_repeated_badge()
    {
        let mut r = Roster::new();
        assert_eq!(r.add(1, 10), Err(10));
        r.try_reserve_one().unwrap();
        assert_eq!(r.add(1, 10), Ok(()));
        r.try_reserve_one().unwrap();
        assert_eq!(r.add(1, 11), Err(11));
        assert_eq!(r.len(), 1);
    }
}
