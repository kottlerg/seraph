// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/classes.rs

//! The device classes devmgr knows, each a [`Served`] list keyed by its
//! class name, with what the class requests configured for it
//! ([docs/driver-binding.md](../../../../docs/driver-binding.md)
//! § Device Classes).
//!
//! devmgr does not interpret a class name: it interns each name into this
//! bounded table the first time a class request (`MINT_CLASS_SEND`) names it
//! or it serves a driver of that class, and a class keeps its slot, the
//! index a class SEND's badge carries, for the boot, since the table only
//! grows. No source lists the classes. Each class holds the watchers devmgr
//! signals when the class changes ([`Watchers`]).

extern crate alloc;

use alloc::vec::Vec;

use driver_binding::decl::ClassName;

use crate::served::{Lookup, Served};
use crate::watchers::{WatchError, Watchers};

/// The most device classes the table holds; past it [`Classes::intern`]
/// finds no room, so a class request for a new class is refused and the
/// ready driver of a new class is withdrawn, logged.
pub const MAX_CLASSES: usize = 64;

/// One class: its name, its served drivers, its watchers, and its
/// configuration.
struct Entry<T>
{
    name: ClassName,
    served: Served<T>,
    watchers: Watchers,
    /// A class request named it.
    configured: bool,
}

/// Why [`Classes::configure`] refused a class request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigureError
{
    /// The class is new and the table holds [`MAX_CLASSES`] classes or
    /// cannot grow.
    Full,
}

/// What [`Classes::mismatches`] reports of a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mismatch
{
    /// A class request configured it, and no driver of it is served.
    NoDriver,
    /// A driver of it is served, and no class request configured it, so no
    /// consumer reaches the driver.
    NotConfigured,
}

/// The served drivers of every class, by class name and slot.
pub struct Classes<T>
{
    entries: Vec<Entry<T>>,
}

impl<T> Default for Classes<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> Classes<T>
{
    /// A table of no class.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
        }
    }

    /// The slot of class `name`, interning the name when it is new. `None`
    /// when the name is new and the table holds [`MAX_CLASSES`] classes or
    /// cannot grow.
    fn slot(&mut self, name: &ClassName) -> Option<usize>
    {
        if let Some(index) = self.entries.iter().position(|e| e.name == *name)
        {
            return Some(index);
        }
        if self.entries.len() >= MAX_CLASSES || self.entries.try_reserve(1).is_err()
        {
            return None;
        }
        let index = self.entries.len();
        self.entries.push(Entry {
            name: *name,
            served: Served::new(),
            watchers: Watchers::new(),
            configured: false,
        });
        Some(index)
    }

    /// The served list of class `name`, interning the name when it is new.
    /// `None` when the name is new and the table holds [`MAX_CLASSES`]
    /// classes or cannot grow.
    pub fn intern(&mut self, name: &ClassName) -> Option<&mut Served<T>>
    {
        let slot = self.slot(name)?;
        self.entries.get_mut(slot).map(|e| &mut e.served)
    }

    /// Record a class request for `name`: intern it and mark it configured.
    /// Returns the class's slot.
    ///
    /// # Errors
    /// [`ConfigureError`].
    pub fn configure(&mut self, name: &ClassName) -> Result<usize, ConfigureError>
    {
        let slot = self.slot(name).ok_or(ConfigureError::Full)?;
        if let Some(entry) = self.entries.get_mut(slot)
        {
            entry.configured = true;
        }
        Ok(slot)
    }

    /// The served list of the class named `name`; `None` when the class is
    /// not in the table.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Served<T>>
    {
        self.find(name).map(|e| &e.served)
    }

    /// The served list of the class at `slot`; `None` past the table.
    #[must_use]
    pub fn get_slot(&self, slot: usize) -> Option<&Served<T>>
    {
        self.entries.get(slot).map(|e| &e.served)
    }

    /// Add the watcher `cap` to the class at `slot` ([`Watchers::add`],
    /// which drops the watchers `gone` holds for when the class is full),
    /// and return the ordinals the class has served
    /// ([`Served::ordinals`]), read with the registration.
    ///
    /// # Errors
    /// [`WatchError`]; `cap` then stays the caller's.
    pub fn watch(
        &mut self,
        slot: usize,
        cap: u64,
        gone: impl FnMut(u64) -> bool,
    ) -> Result<usize, WatchError>
    {
        let entry = self.entries.get_mut(slot).ok_or(WatchError::NoClass)?;
        entry.watchers.add(cap, gone)?;
        Ok(entry.served.ordinals())
    }

    /// Signal the watchers of class `name`, when it is in the table
    /// ([`Watchers::signal`]).
    pub fn signal(&mut self, name: &ClassName, signal: impl FnMut(u64) -> bool)
    {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.name == *name)
        {
            entry.watchers.signal(signal);
        }
    }

    /// Every class's served list, in the order the classes were interned.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&ClassName, &mut Served<T>)>
    {
        self.entries.iter_mut().map(|e| (&e.name, &mut e.served))
    }

    /// Every class configured without a served driver, or with one but not
    /// configured, in slot order.
    pub fn mismatches(&self) -> impl Iterator<Item = (&ClassName, Mismatch)>
    {
        self.entries.iter().filter_map(|e| {
            let served = !matches!(e.served.get(0), Lookup::Absent);
            match (e.configured, served)
            {
                (true, false) => Some((&e.name, Mismatch::NoDriver)),
                (false, true) => Some((&e.name, Mismatch::NotConfigured)),
                _ => None,
            }
        })
    }

    fn find(&self, name: &str) -> Option<&Entry<T>>
    {
        self.entries
            .iter()
            .find(|e| e.name.as_bytes() == name.as_bytes())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn class(name: &str) -> ClassName
    {
        ClassName::class(name.as_bytes()).unwrap()
    }

    #[test]
    fn a_class_is_interned_once_and_found_by_name()
    {
        let mut classes = Classes::new();
        let block = classes.intern(&class("block")).unwrap();
        block.try_reserve(1).unwrap();
        block.push(7, "disk0").unwrap();
        let again = classes.intern(&class("block")).unwrap();
        again.try_reserve(1).unwrap();
        again.push(8, "disk1").unwrap();
        let served = classes.get("block").unwrap();
        assert_eq!(served.get(0), Lookup::Live(&"disk0"));
        assert_eq!(served.get(1), Lookup::Live(&"disk1"));
        assert!(classes.get("input").is_none());
        assert_eq!(classes.iter_mut().count(), 1);
    }

    #[test]
    fn the_table_holds_at_most_max_classes()
    {
        let mut classes = Classes::<()>::new();
        for i in 0..MAX_CLASSES
        {
            let name = alloc::format!("c{i}");
            assert!(classes.intern(&class(&name)).is_some());
        }
        assert!(classes.intern(&class("one-more")).is_none());
        assert_eq!(
            classes.configure(&class("one-more")),
            Err(ConfigureError::Full)
        );
        // A class already held is still found, and configured.
        assert!(classes.intern(&class("c0")).is_some());
        assert_eq!(classes.configure(&class("c0")), Ok(0));
    }

    #[test]
    fn a_configured_class_keeps_its_slot_and_the_served_list_it_names()
    {
        let mut classes = Classes::new();
        assert_eq!(classes.configure(&class("serial")), Ok(0));
        assert_eq!(classes.configure(&class("input")), Ok(1));
        let input = classes.intern(&class("input")).unwrap();
        input.try_reserve(1).unwrap();
        input.push(3, "kbd").unwrap();
        // A repeated request names the same slot.
        assert_eq!(classes.configure(&class("input")), Ok(1));
        assert_eq!(classes.get_slot(1).unwrap().get(0), Lookup::Live(&"kbd"));
        assert_eq!(classes.get_slot(0).unwrap().get(0), Lookup::Absent);
        assert!(classes.get_slot(2).is_none());
    }

    #[test]
    fn a_watch_reads_the_ordinals_with_the_registration_and_a_signal_reaches_its_class()
    {
        let mut classes = Classes::new();
        assert_eq!(classes.configure(&class("block")), Ok(0));
        assert_eq!(classes.configure(&class("input")), Ok(1));
        assert_eq!(classes.watch(0, 10, |_| false), Ok(0));
        let block = classes.intern(&class("block")).unwrap();
        block.try_reserve(2).unwrap();
        block.push(1, "disk0").unwrap();
        block.push(2, "disk1").unwrap();
        block.withdraw(1);
        // A withdrawn ordinal still counts: the next driver takes ordinal 2.
        assert_eq!(classes.watch(0, 11, |_| false), Ok(2));
        assert_eq!(classes.watch(1, 20, |_| false), Ok(0));
        assert_eq!(classes.watch(2, 30, |_| false), Err(WatchError::NoClass));

        let mut signalled = Vec::new();
        classes.signal(&class("block"), |cap| {
            signalled.push(cap);
            true
        });
        assert_eq!(signalled, [10, 11]);
        signalled.clear();
        classes.signal(&class("rtc"), |cap| {
            signalled.push(cap);
            true
        });
        assert_eq!(signalled, Vec::<u64>::new());
    }

    #[test]
    fn a_full_class_refuses_a_watcher_and_others_are_unaffected()
    {
        let mut classes = Classes::<()>::new();
        classes.configure(&class("serial")).unwrap();
        classes.configure(&class("input")).unwrap();
        for cap in 0..crate::watchers::MAX_CLASS_WATCHERS as u64
        {
            assert_eq!(classes.watch(0, cap, |_| false), Ok(0));
        }
        assert_eq!(classes.watch(0, 99, |_| false), Err(WatchError::Full));
        assert_eq!(classes.watch(1, 99, |_| false), Ok(0));
        // A watcher found gone makes room.
        assert_eq!(classes.watch(0, 100, |cap| cap == 3), Ok(0));
    }

    #[test]
    fn mismatches_name_a_configured_class_without_a_driver_and_the_reverse()
    {
        let mut classes = Classes::new();
        classes.configure(&class("serial")).unwrap();
        classes.configure(&class("rtc")).unwrap();
        for name in ["serial", "test-dma"]
        {
            let served = classes.intern(&class(name)).unwrap();
            served.try_reserve(1).unwrap();
            served.push(1, ()).unwrap();
        }
        let found: Vec<(&str, Mismatch)> =
            classes.mismatches().map(|(n, m)| (n.as_str(), m)).collect();
        assert_eq!(
            found,
            [
                ("rtc", Mismatch::NoDriver),
                ("test-dma", Mismatch::NotConfigured)
            ]
        );
    }
}
