// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/classes.rs

//! The device classes devmgr serves, each a [`Served`] list keyed by its
//! class name ([docs/driver-binding.md](../../../../docs/driver-binding.md)
//! § Device Classes).
//!
//! devmgr does not interpret a class name: it interns each name a
//! declaration gives it into this bounded table the first time it serves a
//! driver of that class, and looks a class up by name. No source lists the
//! classes.

extern crate alloc;

use alloc::vec::Vec;

use driver_binding::decl::ClassName;

use crate::served::Served;

/// The most device classes the table holds; a declaration naming a class
/// past it is served under no class, and logged.
pub const MAX_CLASSES: usize = 64;

/// The served drivers of every class, by class name.
pub struct Classes<T>
{
    entries: Vec<(ClassName, Served<T>)>,
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

    /// The served list of class `name`, interning the name when it is new.
    /// `None` when the name is new and the table holds [`MAX_CLASSES`]
    /// classes or cannot grow.
    pub fn intern(&mut self, name: &ClassName) -> Option<&mut Served<T>>
    {
        if let Some(index) = self.entries.iter().position(|(n, _)| n == name)
        {
            return self.entries.get_mut(index).map(|(_, served)| served);
        }
        if self.entries.len() >= MAX_CLASSES || self.entries.try_reserve(1).is_err()
        {
            return None;
        }
        self.entries.push((*name, Served::new()));
        self.entries.last_mut().map(|(_, served)| served)
    }

    /// The served list of the class named `name`; `None` when no driver of
    /// that class has been served.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Served<T>>
    {
        self.entries
            .iter()
            .find(|(n, _)| n.as_bytes() == name.as_bytes())
            .map(|(_, served)| served)
    }

    /// Every class's served list, in the order the classes were interned.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&ClassName, &mut Served<T>)>
    {
        self.entries.iter_mut().map(|(n, served)| (&*n, served))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::served::Lookup;

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
        // A class already held is still found.
        assert!(classes.intern(&class("c0")).is_some());
    }
}
