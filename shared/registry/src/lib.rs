// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/registry/src/lib.rs

//! Fixed-capacity name→endpoint-cap registry for supervisor services.
//!
//! Each supervisor (svcmgr today) holds a [`Registry`] that maps
//! short byte-string names to capability-slot indices in its own `CSpace`. Callers
//! query via `QUERY_ENDPOINT` (reply semantics: `services/svcmgr/docs/ipc-interface.md`
//! § Label 4); the supervisor resolves the name with [`Registry::lookup`].
//!
//! Storage is statically sized (`N` entries, `NAME_MAX`-byte names) and the crate
//! needs no allocator. A full bytewise match is
//! required — no prefix or glob matching.

#![no_std]
#![allow(clippy::cast_possible_truncation)]

/// Maximum registered name length in bytes.
pub const NAME_MAX: usize = 16;

/// One entry in the registry: a short name → capability slot mapping.
#[derive(Clone, Copy)]
pub struct Entry
{
    /// Name bytes, zero-padded to `NAME_MAX`.
    pub name: [u8; NAME_MAX],
    /// Active length of `name` (the entry is in use iff `cap != 0`).
    pub name_len: u8,
    /// Capability slot index in the supervisor's `CSpace`.
    pub cap: u32,
}

impl Entry
{
    const fn empty() -> Self
    {
        Self {
            name: [0; NAME_MAX],
            name_len: 0,
            cap: 0,
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

    /// Resolve `name` to its registered cap. Returns `None` if not found or
    /// if `name` exceeds `NAME_MAX` bytes.
    #[must_use]
    pub fn lookup(&self, name: &[u8]) -> Option<u32>
    {
        if name.is_empty() || name.len() > NAME_MAX
        {
            return None;
        }
        for e in &self.entries
        {
            if e.cap != 0 && e.name_matches(name)
            {
                return Some(e.cap);
            }
        }
        None
    }

    /// Publish `name → cap`.
    ///
    /// `cap == 0` is rejected — the zero slot marks an empty entry.
    ///
    /// # Errors
    /// Returns `Err(())` if the table is full, `name` is empty or exceeds
    /// [`NAME_MAX`], the cap is zero, or the name is already registered.
    #[allow(clippy::result_unit_err)]
    pub fn publish(&mut self, name: &[u8], cap: u32) -> Result<(), ()>
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
        let mut entry = Entry::empty();
        entry.name[..name.len()].copy_from_slice(name);
        entry.name_len = name.len() as u8;
        entry.cap = cap;
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
