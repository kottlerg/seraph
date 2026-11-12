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
//! grows. No source lists the classes.

extern crate alloc;

use alloc::vec::Vec;

use driver_binding::decl::ClassName;

use crate::served::{Lookup, Served};

/// The most device classes the table holds; past it [`Classes::intern`]
/// finds no room, so a class request for a new class is refused and the
/// ready driver of a new class is withdrawn, logged.
pub const MAX_CLASSES: usize = 64;

/// One class: its name, its served drivers, and its configuration.
struct Entry<T>
{
    name: ClassName,
    served: Served<T>,
    /// A class request named it.
    configured: bool,
    /// A class request marked its drivers boot-bundle only.
    boot_only: bool,
}

/// Why [`Classes::configure`] refused a class request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigureError
{
    /// The class is new and the table holds [`MAX_CLASSES`] classes or
    /// cannot grow.
    Full,
    /// A boot-only mark once the drivers-directory pass has begun, which
    /// could no longer keep that pass's drivers of the class out.
    BootOnlyTooLate,
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
            configured: false,
            boot_only: false,
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

    /// Record a class request for `name`: intern it, mark it configured,
    /// and boot-only when `boot_only` is set (a mark that stays for the
    /// boot). Returns the class's slot. A boot-only mark is refused once
    /// `pass_begun`, the drivers-directory pass having begun.
    ///
    /// # Errors
    /// [`ConfigureError`].
    pub fn configure(
        &mut self,
        name: &ClassName,
        boot_only: bool,
        pass_begun: bool,
    ) -> Result<usize, ConfigureError>
    {
        if boot_only && pass_begun && !self.is_boot_only(name.as_str())
        {
            return Err(ConfigureError::BootOnlyTooLate);
        }
        let slot = self.slot(name).ok_or(ConfigureError::Full)?;
        if let Some(entry) = self.entries.get_mut(slot)
        {
            entry.configured = true;
            entry.boot_only |= boot_only;
        }
        Ok(slot)
    }

    /// Whether a class request marked class `name` boot-only.
    #[must_use]
    pub fn is_boot_only(&self, name: &str) -> bool
    {
        self.find(name).is_some_and(|e| e.boot_only)
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
            classes.configure(&class("one-more"), false, false),
            Err(ConfigureError::Full)
        );
        // A class already held is still found, and configured.
        assert!(classes.intern(&class("c0")).is_some());
        assert_eq!(classes.configure(&class("c0"), false, false), Ok(0));
    }

    #[test]
    fn a_configured_class_keeps_its_slot_and_the_served_list_it_names()
    {
        let mut classes = Classes::new();
        assert_eq!(classes.configure(&class("serial"), false, false), Ok(0));
        assert_eq!(classes.configure(&class("input"), false, false), Ok(1));
        let input = classes.intern(&class("input")).unwrap();
        input.try_reserve(1).unwrap();
        input.push(3, "kbd").unwrap();
        // A repeated request names the same slot.
        assert_eq!(classes.configure(&class("input"), false, true), Ok(1));
        assert_eq!(classes.get_slot(1).unwrap().get(0), Lookup::Live(&"kbd"));
        assert_eq!(classes.get_slot(0).unwrap().get(0), Lookup::Absent);
        assert!(classes.get_slot(2).is_none());
    }

    #[test]
    fn a_boot_only_mark_is_sticky_and_refused_once_the_pass_began()
    {
        let mut classes = Classes::<()>::new();
        assert!(!classes.is_boot_only("block"));
        assert_eq!(classes.configure(&class("block"), true, false), Ok(0));
        assert!(classes.is_boot_only("block"));
        // A later request without the mark does not clear it, and one with
        // it after the pass began is admitted for a class already marked.
        assert_eq!(classes.configure(&class("block"), false, true), Ok(0));
        assert!(classes.is_boot_only("block"));
        assert_eq!(classes.configure(&class("block"), true, true), Ok(0));
        assert_eq!(
            classes.configure(&class("rtc"), true, true),
            Err(ConfigureError::BootOnlyTooLate)
        );
        assert!(!classes.is_boot_only("rtc"));
        assert!(classes.get("rtc").is_none());
    }

    #[test]
    fn mismatches_name_a_configured_class_without_a_driver_and_the_reverse()
    {
        let mut classes = Classes::new();
        classes.configure(&class("serial"), false, false).unwrap();
        classes.configure(&class("rtc"), false, false).unwrap();
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
