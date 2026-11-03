// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/served.rs

//! The drivers the registry serves for one device class, by instance
//! ordinal.
//!
//! devmgr fills a class's [`Served`] list once, when the class's settle batch
//! settles, with the drivers that reported their device ready, in spawn
//! (PCI segment, bus, device, function) order: ordinal `i` names the `i`-th
//! of them for the rest of the boot. A served driver that dies later is
//! withdrawn ([`Served::withdraw`]) and leaves a tombstone at its ordinal, so
//! the ordinals after it keep their drivers and a client probing ordinals
//! `0, 1, ...` (vfsd) skips no live disk. The single-instance classes (serial,
//! framebuffer, RTC) use the same list with at most one entry, at ordinal 0.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

/// What an instance ordinal names.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a, T>
{
    /// A served driver.
    Live(&'a T),
    /// A driver that was served and has since been withdrawn.
    Withdrawn,
    /// Past the last driver the class served.
    Absent,
}

// A lookup holds only a reference, so it copies whatever `T` is; a derive
// would require `T: Copy`.
impl<T> Clone for Lookup<'_, T>
{
    fn clone(&self) -> Self
    {
        *self
    }
}

impl<T> Copy for Lookup<'_, T> {}

/// One ordinal: the driver's device badge, and its record while it is
/// served.
struct Slot<T>
{
    badge: u64,
    driver: Option<T>,
}

/// The served drivers of one class, in ordinal order.
pub struct Served<T>
{
    slots: Vec<Slot<T>>,
}

impl<T> Default for Served<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> Served<T>
{
    /// A class that serves no driver.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { slots: Vec::new() }
    }

    /// Reserve room for `additional` more drivers, so a settled batch's
    /// drivers are all recorded.
    ///
    /// # Errors
    /// Returns the allocation error when the list cannot grow.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    {
        self.slots.try_reserve(additional)
    }

    /// Serve `driver`, under its device `badge`, at the next ordinal.
    ///
    /// # Errors
    /// Returns `driver` unrecorded when no room is reserved for it
    /// ([`try_reserve`](Self::try_reserve)).
    pub fn push(&mut self, badge: u64, driver: T) -> Result<(), T>
    {
        if self.slots.len() == self.slots.capacity()
        {
            return Err(driver);
        }
        self.slots.push(Slot {
            badge,
            driver: Some(driver),
        });
        Ok(())
    }

    /// What `ordinal` names.
    #[must_use]
    pub fn get(&self, ordinal: usize) -> Lookup<'_, T>
    {
        match self.slots.get(ordinal)
        {
            Some(Slot {
                driver: Some(d), ..
            }) => Lookup::Live(d),
            Some(Slot { driver: None, .. }) => Lookup::Withdrawn,
            None => Lookup::Absent,
        }
    }

    /// The served driver at the lowest ordinal that is not withdrawn, if
    /// any.
    #[must_use]
    pub fn first_live(&self) -> Option<&T>
    {
        self.slots.iter().find_map(|s| s.driver.as_ref())
    }

    /// Withdraw the served driver under `badge`, leaving a tombstone at its
    /// ordinal, and return its record for the caller to release. Returns
    /// `None` when the class serves no driver under `badge`: another class's
    /// badge, or one already withdrawn.
    pub fn withdraw(&mut self, badge: u64) -> Option<T>
    {
        self.slots
            .iter_mut()
            .find(|s| s.badge == badge)
            .and_then(|s| s.driver.take())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A class serving `badges`, each recorded as its own badge.
    fn serving(badges: &[u64]) -> Served<u64>
    {
        let mut s = Served::new();
        s.try_reserve(badges.len()).unwrap();
        for &b in badges
        {
            s.push(b, b).unwrap();
        }
        s
    }

    #[test]
    fn ordinals_name_the_drivers_in_push_order()
    {
        let s = serving(&[7, 3, 9]);
        assert_eq!(s.get(0), Lookup::Live(&7));
        assert_eq!(s.get(1), Lookup::Live(&3));
        assert_eq!(s.get(2), Lookup::Live(&9));
        assert_eq!(s.get(3), Lookup::Absent);
    }

    #[test]
    fn withdrawal_leaves_a_tombstone_and_keeps_later_ordinals()
    {
        // The first of three disks dies after it was served: a probe of
        // ordinals 0, 1, 2 still reaches the other two at their ordinals.
        let mut s = serving(&[1, 2, 3]);
        assert_eq!(s.withdraw(1), Some(1));
        assert_eq!(s.get(0), Lookup::Withdrawn);
        assert_eq!(s.get(1), Lookup::Live(&2));
        assert_eq!(s.get(2), Lookup::Live(&3));
        assert_eq!(s.get(3), Lookup::Absent);
        assert_eq!(s.first_live(), Some(&2));
        assert_eq!(s.withdraw(2), Some(2));
        assert_eq!(s.withdraw(3), Some(3));
        assert_eq!(s.first_live(), None);
    }

    #[test]
    fn withdrawal_of_an_unknown_or_withdrawn_badge_changes_nothing()
    {
        let mut s = serving(&[1, 2]);
        assert_eq!(s.withdraw(5), None);
        assert_eq!(s.withdraw(2), Some(2));
        assert_eq!(s.withdraw(2), None);
        assert_eq!(s.get(0), Lookup::Live(&1));
        assert_eq!(s.get(1), Lookup::Withdrawn);
    }

    #[test]
    fn push_refuses_without_reserved_room()
    {
        let mut s: Served<u64> = Served::new();
        assert_eq!(s.push(1, 10), Err(10));
        s.try_reserve(1).unwrap();
        assert_eq!(s.push(1, 10), Ok(()));
        assert_eq!(s.get(0), Lookup::Live(&10));
    }
}
