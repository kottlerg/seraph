// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/registry/src/lib.rs

//! Growable name→endpoint-cap registry for supervisor services.
//!
//! Each supervisor (svcmgr today) holds a [`Registry`] that maps
//! short byte-string names to capability-slot indices in its own `CSpace`. Callers
//! query via `QUERY_ENDPOINT` (reply semantics: `services/svcmgr/docs/ipc-interface.md`
//! § Label 4); the supervisor resolves the name with [`Registry::lookup`]. Each
//! entry carries a [`Visibility`]: a [`Visibility::SeedOnly`] entry resolves
//! only for the supervisor's own resolution ([`Resolver::Seed`]), never for
//! a `QUERY_ENDPOINT` caller ([`Resolver::Query`]).
//!
//! Entries live on the heap and the table grows with what is published, so
//! it holds no fixed count; a publish fails only when the heap cannot grow
//! it. Names are at most [`NAME_MAX`] bytes. A full bytewise match is
//! required — no prefix or glob matching.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// Maximum registered name length in bytes: the svcmgr protocol's one name
/// limit, shared with every client and the `.svc` parser.
pub const NAME_MAX: usize = ipc::svcmgr_labels::NAME_MAX;

/// Which resolvers an entry answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility
{
    /// Resolved for every [`Resolver`].
    Public,
    /// Resolved only for [`Resolver::Seed`]; a [`Resolver::Query`] lookup
    /// finds no entry. For names whose cap carries authority that only the
    /// recipes seeding the name may hold.
    SeedOnly,
}

/// Who is resolving a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolver
{
    /// A `QUERY_ENDPOINT` caller: any process holding a registry SEND.
    Query,
    /// The supervisor itself: the seed lists of the recipes it launches and
    /// its own lookups.
    Seed,
}

/// One entry in the registry: a short name → capability slot mapping.
#[derive(Clone, Copy)]
pub struct Entry
{
    /// Name bytes, zero-padded to `NAME_MAX`.
    pub name: [u8; NAME_MAX],
    /// Active length of `name`. At most `NAME_MAX`, so the `u8` never
    /// truncates.
    pub name_len: u8,
    /// Capability slot index in the supervisor's `CSpace`; `u32` is the cap
    /// handle width of the syscall ABI.
    pub cap: u32,
    /// Which resolvers see this entry.
    pub visibility: Visibility,
}

impl Entry
{
    const fn empty() -> Self
    {
        Self {
            name: [0; NAME_MAX],
            name_len: 0,
            cap: 0,
            visibility: Visibility::Public,
        }
    }

    /// Bytewise comparison of this entry's name against `name`.
    fn name_matches(&self, name: &[u8]) -> bool
    {
        name.len() == self.name_len as usize
            && name.len() <= NAME_MAX
            && self.name[..name.len()] == *name
    }
}

/// Growable name→cap registry, one heap entry per published name.
pub struct Registry
{
    entries: Vec<Entry>,
}

impl Registry
{
    /// Create an empty registry.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
        }
    }

    /// Resolve `name` to its registered cap for `resolver`. Returns `None`
    /// if not found, if `name` is empty or exceeds `NAME_MAX` bytes, or if
    /// the entry is [`Visibility::SeedOnly`] and `resolver` is
    /// [`Resolver::Query`].
    #[must_use]
    pub fn lookup(&self, name: &[u8], resolver: Resolver) -> Option<u32>
    {
        if name.is_empty() || name.len() > NAME_MAX
        {
            return None;
        }
        let entry = self.entries.iter().find(|e| e.name_matches(name))?;
        if entry.visibility == Visibility::SeedOnly && resolver == Resolver::Query
        {
            return None;
        }
        Some(entry.cap)
    }

    /// Publish `name → cap` with `visibility`.
    ///
    /// `cap == 0`, the null slot, is rejected.
    ///
    /// # Errors
    /// Returns `Err(())` if the heap cannot grow the table, `name` is empty
    /// or exceeds [`NAME_MAX`], the cap is zero, or the name is already
    /// registered (at either visibility).
    // A unit error: every rejection gets the same reply on the wire
    // (`REGISTER_REJECTED`), so the cause carries no information.
    #[allow(clippy::result_unit_err)]
    pub fn publish(&mut self, name: &[u8], cap: u32, visibility: Visibility) -> Result<(), ()>
    {
        if cap == 0 || name.is_empty() || name.len() > NAME_MAX
        {
            return Err(());
        }
        if self.entries.iter().any(|e| e.name_matches(name))
        {
            return Err(());
        }
        let name_len = u8::try_from(name.len()).map_err(|_| ())?;
        self.entries.try_reserve(1).map_err(|_| ())?;
        let mut entry = Entry::empty();
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name_len;
        entry.cap = cap;
        entry.visibility = visibility;
        self.entries.push(entry);
        Ok(())
    }

    /// Remove an entry by name. Returns the removed cap slot, or `None` if
    /// the name was not registered.
    pub fn remove(&mut self, name: &[u8]) -> Option<u32>
    {
        if name.is_empty() || name.len() > NAME_MAX
        {
            return None;
        }
        let idx = self.entries.iter().position(|e| e.name_matches(name))?;
        Some(self.entries.swap_remove(idx).cap)
    }
}

impl Default for Registry
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(test)]
mod tests
{
    use super::{NAME_MAX, Registry, Resolver, Visibility};

    #[test]
    fn public_entry_resolves_for_query_and_seed()
    {
        let mut r = Registry::new();
        r.publish(b"timed", 7, Visibility::Public).unwrap();
        assert_eq!(r.lookup(b"timed", Resolver::Query), Some(7));
        assert_eq!(r.lookup(b"timed", Resolver::Seed), Some(7));
    }

    #[test]
    fn seed_only_entry_resolves_for_seed_but_not_query()
    {
        let mut r = Registry::new();
        r.publish(b"devmgr.shutdown", 9, Visibility::SeedOnly)
            .unwrap();
        assert_eq!(r.lookup(b"devmgr.shutdown", Resolver::Query), None);
        assert_eq!(r.lookup(b"devmgr.shutdown", Resolver::Seed), Some(9));
    }

    #[test]
    fn unknown_empty_and_overlong_names_resolve_to_none()
    {
        let mut r = Registry::new();
        r.publish(b"a", 1, Visibility::Public).unwrap();
        assert_eq!(r.lookup(b"b", Resolver::Seed), None);
        assert_eq!(r.lookup(b"", Resolver::Seed), None);
        assert_eq!(r.lookup(&[b'a'; NAME_MAX + 1], Resolver::Seed), None);
    }

    #[test]
    fn name_of_exactly_name_max_bytes_is_published_resolved_and_removed()
    {
        let name = [b'a'; NAME_MAX];
        let mut r = Registry::new();
        r.publish(&name, 7, Visibility::Public).unwrap();
        assert_eq!(r.lookup(&name, Resolver::Query), Some(7));
        assert_eq!(r.remove(&name), Some(7));
        assert!(
            r.publish(&[b'a'; NAME_MAX + 1], 8, Visibility::Public)
                .is_err()
        );
    }

    #[test]
    fn publish_rejects_zero_cap_and_invalid_names()
    {
        let mut r = Registry::new();
        assert!(r.publish(b"a", 0, Visibility::Public).is_err());
        assert!(r.publish(b"", 1, Visibility::Public).is_err());
        assert!(
            r.publish(&[b'a'; NAME_MAX + 1], 1, Visibility::Public)
                .is_err()
        );
    }

    #[test]
    fn publish_rejects_a_name_registered_at_either_visibility()
    {
        let mut r = Registry::new();
        r.publish(b"a", 1, Visibility::SeedOnly).unwrap();
        assert!(r.publish(b"a", 2, Visibility::Public).is_err());
        r.publish(b"b", 3, Visibility::Public).unwrap();
        assert!(r.publish(b"b", 4, Visibility::SeedOnly).is_err());
    }

    #[test]
    fn registry_grows_past_any_fixed_count_and_resolves_every_name()
    {
        let mut r = Registry::new();
        let names: Vec<[u8; 3]> = (0..300u16)
            .map(|i| [b'n', b'a' + (i / 26) as u8, b'a' + (i % 26) as u8])
            .collect();
        for (i, name) in names.iter().enumerate()
        {
            r.publish(name, i as u32 + 1, Visibility::Public).unwrap();
        }
        for (i, name) in names.iter().enumerate()
        {
            assert_eq!(r.lookup(name, Resolver::Query), Some(i as u32 + 1));
        }
    }

    #[test]
    fn remove_frees_the_slot_and_returns_the_cap()
    {
        let mut r = Registry::new();
        r.publish(b"a", 5, Visibility::SeedOnly).unwrap();
        assert_eq!(r.remove(b"a"), Some(5));
        assert_eq!(r.remove(b"a"), None);
        assert_eq!(r.remove(b""), None);
        assert_eq!(r.lookup(b"a", Resolver::Seed), None);
        r.publish(b"b", 6, Visibility::Public).unwrap();
        assert_eq!(r.lookup(b"b", Resolver::Query), Some(6));
    }
}
