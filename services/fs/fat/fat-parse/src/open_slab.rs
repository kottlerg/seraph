// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/open_slab.rs

//! Recycling, generation-checked table of `fatfs` open instances.
//!
//! An [`OpenSlab`] holds one entry per `FS_OPEN` and hands out a 40-bit
//! identifier for it, in the shape [`crate::node_slab`] uses: a 24-bit index
//! into the slab (plus one) and a 16-bit generation. The identifier is the low
//! 40 bits of the open cap's badge (services/fs/docs/fs-driver-protocol.md
//! § Label 18). Unlike a node, an open has no key: every insert is a new
//! entry. Removing an entry bumps its index's generation, so an identifier
//! issued before the removal never resolves again: a cap kept past its
//! `FS_CLOSE` names no open, never the open that later reuses the index. An
//! index whose generation would wrap is retired instead of reused. The table
//! grows on the heap with the live entries, every growth fallible.

use alloc::vec::Vec;

use crate::node_slab::{INDEX_BITS, INDEX_MASK, MAX_ENTRIES, identifier};

struct Slot<T>
{
    entry: Option<T>,
    generation: u16,
}

/// A recycling, generation-checked table of `T`; see the module docs.
pub struct OpenSlab<T>
{
    slots: Vec<Slot<T>>,
    /// Indices of freed slots whose generation has not wrapped. Its capacity
    /// is kept at least `slots.len()`, so a removal never allocates.
    free: Vec<u32>,
    /// Live entries.
    len: usize,
}

impl<T> Default for OpenSlab<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> OpenSlab<T>
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    /// Insert `value` as a new entry and return its identifier, never 0.
    ///
    /// Returns `None`, leaving `value` dropped, when the slab already holds
    /// [`MAX_ENTRIES`] entries with every freed index retired, or the heap
    /// cannot grow the table.
    pub fn insert(&mut self, value: T) -> Option<u64>
    {
        let idx = if let Some(idx) = self.free.pop()
        {
            idx
        }
        else
        {
            if self.slots.len() >= MAX_ENTRIES
            {
                return None;
            }
            self.slots.try_reserve(1).ok()?;
            self.free.try_reserve(self.slots.len() + 1).ok()?;
            self.slots.push(Slot {
                entry: None,
                generation: 0,
            });
            // Cast is range-safe: the length is at most MAX_ENTRIES < 2^24.
            #[allow(clippy::cast_possible_truncation)]
            let idx = (self.slots.len() - 1) as u32;
            idx
        };
        let slot = &mut self.slots[idx as usize];
        slot.entry = Some(value);
        self.len += 1;
        Some(identifier(idx, slot.generation))
    }

    /// The entry `id` names, while it is live.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&T>
    {
        let idx = self.live_index(id)?;
        self.slots[idx].entry.as_ref()
    }

    /// Mutable access to the entry `id` names; `None` as [`Self::get`].
    pub fn get_mut(&mut self, id: u64) -> Option<&mut T>
    {
        let idx = self.live_index(id)?;
        self.slots[idx].entry.as_mut()
    }

    /// Remove the entry `id` names and return it: `id` stops resolving.
    pub fn remove(&mut self, id: u64) -> Option<T>
    {
        let idx = self.live_index(id)?;
        self.take_at(idx)
    }

    /// Remove every live entry for which `pred` holds, handing each to
    /// `release`.
    pub fn remove_where(&mut self, mut pred: impl FnMut(&T) -> bool, mut release: impl FnMut(T))
    {
        for idx in 0..self.slots.len()
        {
            if self.slots[idx].entry.as_ref().is_some_and(&mut pred)
                && let Some(value) = self.take_at(idx)
            {
                release(value);
            }
        }
    }

    /// Every live entry with its identifier, in index order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, &mut T)>
    {
        self.slots.iter_mut().enumerate().filter_map(|(idx, slot)| {
            let generation = slot.generation;
            // Cast is range-safe: the index is below MAX_ENTRIES < 2^24.
            #[allow(clippy::cast_possible_truncation)]
            let id = identifier(idx as u32, generation);
            slot.entry.as_mut().map(|v| (id, v))
        })
    }

    /// Live entries.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the slab holds no live entry.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// Empty live slot `idx`, bump its generation or retire it, and return
    /// its entry.
    fn take_at(&mut self, idx: usize) -> Option<T>
    {
        let slot = &mut self.slots[idx];
        let value = slot.entry.take()?;
        self.len -= 1;
        // Retire an index whose generation would wrap: reissuing generation 0
        // would let an identifier from the first lifetime resolve again.
        if let Some(next) = slot.generation.checked_add(1)
        {
            slot.generation = next;
            // Never allocates: `free` holds at least `slots.len()` capacity.
            // Cast is range-safe: the index is below MAX_ENTRIES < 2^24.
            #[allow(clippy::cast_possible_truncation)]
            self.free.push(idx as u32);
        }
        Some(value)
    }

    /// The slot index `id` names, when its generation is the slot's current
    /// one and the slot is live.
    fn live_index(&self, id: u64) -> Option<usize>
    {
        let idx = usize::try_from((id & INDEX_MASK).checked_sub(1)?).ok()?;
        let generation = id >> INDEX_BITS;
        let slot = self.slots.get(idx)?;
        (u64::from(slot.generation) == generation && slot.entry.is_some()).then_some(idx)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn two_inserts_of_equal_values_get_distinct_identifiers()
    {
        let mut slab: OpenSlab<&str> = OpenSlab::new();
        let a = slab.insert("node 7").expect("room");
        let b = slab.insert("node 7").expect("room");
        assert_ne!(a, b);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.remove(a), Some("node 7"));
        assert_eq!(slab.get(b), Some(&"node 7"));
    }

    #[test]
    fn a_removed_then_reused_index_never_resolves_the_old_identifier()
    {
        let mut slab: OpenSlab<&str> = OpenSlab::new();
        let a = slab.insert("open A").expect("room");
        assert_eq!(slab.remove(a), Some("open A"));
        assert_eq!(slab.remove(a), None);
        // B takes A's index; A's identifier names it at an older generation
        // and must reach neither B nor its removal.
        let b = slab.insert("open B").expect("room");
        assert_eq!(a & INDEX_MASK, b & INDEX_MASK);
        assert_ne!(a, b);
        assert_eq!(slab.get(a), None);
        assert_eq!(slab.remove(a), None);
        assert_eq!(slab.get(b), Some(&"open B"));
    }

    #[test]
    fn an_index_is_retired_when_its_generation_would_wrap()
    {
        let mut slab: OpenSlab<u8> = OpenSlab::new();
        let first = slab.insert(0).expect("room");
        slab.slots[0].generation = u16::MAX;
        let last = first | (u64::from(u16::MAX) << INDEX_BITS);
        assert_eq!(slab.remove(last), Some(0));
        let next = slab.insert(1).expect("room");
        assert_ne!(next & INDEX_MASK, first & INDEX_MASK);
        assert_eq!(slab.get(first), None);
    }

    #[test]
    fn identifiers_that_name_no_issued_slot_resolve_nothing()
    {
        let mut slab: OpenSlab<u8> = OpenSlab::new();
        let id = slab.insert(3).expect("room");
        assert_ne!(id, 0);
        assert_eq!(slab.get(0), None);
        assert_eq!(slab.get(id + 1), None);
        assert_eq!(slab.get(u64::MAX), None);
    }

    #[test]
    fn remove_where_takes_only_the_matching_entries()
    {
        let mut slab: OpenSlab<u32> = OpenSlab::new();
        let ids: Vec<u64> = (0..6).map(|v| slab.insert(v % 2).expect("room")).collect();
        let mut released = Vec::new();
        slab.remove_where(|v| *v == 1, |v| released.push(v));
        assert_eq!(released, [1, 1, 1]);
        assert_eq!(slab.len(), 3);
        for (i, id) in ids.iter().enumerate()
        {
            assert_eq!(slab.get(*id).is_some(), i % 2 == 0, "entry {i}");
        }
    }

    #[test]
    fn iter_mut_yields_each_live_entry_under_its_identifier()
    {
        let mut slab: OpenSlab<u32> = OpenSlab::new();
        let a = slab.insert(10).expect("room");
        let b = slab.insert(20).expect("room");
        let c = slab.insert(30).expect("room");
        slab.remove(b);
        let seen: Vec<(u64, u32)> = slab.iter_mut().map(|(id, v)| (id, *v)).collect();
        assert_eq!(seen, [(a, 10), (c, 30)]);
    }
}
