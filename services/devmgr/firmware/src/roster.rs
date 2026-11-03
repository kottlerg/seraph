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
//! that order for the registry's instance ordinals. The events reach it from
//! devmgr's settle loop, which keeps this module free of syscalls and
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
