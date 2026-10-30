// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/registry/src/lib.rs

//! Fixed-capacity name→endpoint-cap registry for supervisor services.
//!
//! Each supervisor (svcmgr today) holds a [`Registry`] that maps
//! short byte-string names to capability-slot indices in its own `CSpace`. Callers
//! query via `QUERY_ENDPOINT` (reply semantics: `services/svcmgr/docs/ipc-interface.md`
//! § Label 4); the supervisor resolves the name with [`Registry::lookup`]. Each
//! entry carries a [`Visibility`]: a [`Visibility::SeedOnly`] entry resolves
//! only for the supervisor's own resolution ([`Resolver::Seed`]), never for
//! a `QUERY_ENDPOINT` caller ([`Resolver::Query`]).
//!
//! Storage is statically sized (`N` entries, `NAME_MAX`-byte names) and the crate
//! needs no allocator. A full bytewise match is
//! required — no prefix or glob matching.

#![cfg_attr(not(test), no_std)]

/// Maximum registered name length in bytes.
pub const NAME_MAX: usize = 16;

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
    /// Active length of `name` (the entry is in use iff `cap != 0`). At most
    /// `NAME_MAX`, so the `u8` never truncates.
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

/// Fixed-capacity name→cap registry. `N` caps the table size.
pub struct Registry<const N: usize>
{
    entries: [Entry; N],
}

impl<const N: usize> Registry<N>
{
    /// Create an empty registry.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: [Entry::empty(); N],
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
        let entry = self
            .entries
            .iter()
            .find(|e| e.cap != 0 && e.name_matches(name))?;
        if entry.visibility == Visibility::SeedOnly && resolver == Resolver::Query
        {
            return None;
        }
        Some(entry.cap)
    }

    /// Publish `name → cap` with `visibility`.
    ///
    /// `cap == 0` is rejected — the zero slot marks an empty entry.
    ///
    /// # Errors
    /// Returns `Err(())` if the table is full, `name` is empty or exceeds
    /// [`NAME_MAX`], the cap is zero, or the name is already registered
    /// (at either visibility).
    // A unit error: every rejection gets the same reply on the wire
    // (`REGISTER_REJECTED`), so the cause carries no information.
    #[allow(clippy::result_unit_err)]
    pub fn publish(&mut self, name: &[u8], cap: u32, visibility: Visibility) -> Result<(), ()>
    {
        if cap == 0 || name.is_empty() || name.len() > NAME_MAX
        {
            return Err(());
        }
        let mut empty_idx: Option<usize> = None;
        for (i, e) in self.entries.iter().enumerate()
        {
            if e.cap == 0
            {
                if empty_idx.is_none()
                {
                    empty_idx = Some(i);
                }
                continue;
            }
            if e.name_matches(name)
            {
                return Err(());
            }
        }
        let idx = empty_idx.ok_or(())?;
        let name_len = u8::try_from(name.len()).map_err(|_| ())?;
        let mut entry = Entry::empty();
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name_len;
        entry.cap = cap;
        entry.visibility = visibility;
        self.entries[idx] = entry;
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
        for e in &mut self.entries
        {
            if e.cap != 0 && e.name_matches(name)
            {
                let cap = e.cap;
                *e = Entry::empty();
                return Some(cap);
            }
        }
        None
    }
}

impl<const N: usize> Default for Registry<N>
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
        let mut r = Registry::<4>::new();
        r.publish(b"timed", 7, Visibility::Public).unwrap();
        assert_eq!(r.lookup(b"timed", Resolver::Query), Some(7));
        assert_eq!(r.lookup(b"timed", Resolver::Seed), Some(7));
    }

    #[test]
    fn seed_only_entry_resolves_for_seed_but_not_query()
    {
        let mut r = Registry::<4>::new();
        r.publish(b"devmgr.shutdown", 9, Visibility::SeedOnly)
            .unwrap();
        assert_eq!(r.lookup(b"devmgr.shutdown", Resolver::Query), None);
        assert_eq!(r.lookup(b"devmgr.shutdown", Resolver::Seed), Some(9));
    }

    #[test]
    fn unknown_empty_and_overlong_names_resolve_to_none()
    {
        let mut r = Registry::<4>::new();
        r.publish(b"a", 1, Visibility::Public).unwrap();
        assert_eq!(r.lookup(b"b", Resolver::Seed), None);
        assert_eq!(r.lookup(b"", Resolver::Seed), None);
        assert_eq!(r.lookup(&[b'a'; NAME_MAX + 1], Resolver::Seed), None);
    }

    #[test]
    fn name_of_exactly_name_max_bytes_is_published_resolved_and_removed()
    {
        let name = [b'a'; NAME_MAX];
        let mut r = Registry::<1>::new();
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
        let mut r = Registry::<2>::new();
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
        let mut r = Registry::<4>::new();
        r.publish(b"a", 1, Visibility::SeedOnly).unwrap();
        assert!(r.publish(b"a", 2, Visibility::Public).is_err());
        r.publish(b"b", 3, Visibility::Public).unwrap();
        assert!(r.publish(b"b", 4, Visibility::SeedOnly).is_err());
    }

    #[test]
    fn publish_fails_when_the_table_is_full()
    {
        let mut r = Registry::<2>::new();
        r.publish(b"a", 1, Visibility::Public).unwrap();
        r.publish(b"b", 2, Visibility::SeedOnly).unwrap();
        assert!(r.publish(b"c", 3, Visibility::Public).is_err());
    }

    #[test]
    fn remove_frees_the_slot_and_returns_the_cap()
    {
        let mut r = Registry::<1>::new();
        r.publish(b"a", 5, Visibility::SeedOnly).unwrap();
        assert_eq!(r.remove(b"a"), Some(5));
        assert_eq!(r.remove(b"a"), None);
        assert_eq!(r.remove(b""), None);
        assert_eq!(r.lookup(b"a", Resolver::Seed), None);
        r.publish(b"b", 6, Visibility::Public).unwrap();
        assert_eq!(r.lookup(b"b", Resolver::Query), Some(6));
    }
}
