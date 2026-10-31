// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/node_slab.rs

//! Recycling, generation-checked identifier table for `fatfs` nodes.
//!
//! A [`NodeSlab`] maps a node key (the on-disk slot of a directory entry) to
//! a value and hands out a 40-bit identifier for it: a 24-bit index into the
//! slab and a 16-bit generation. Every lookup of one key returns the same
//! identifier while its entry lives. An entry is freed when its on-disk entry
//! is removed ([`NodeSlab::remove_key`]); freeing bumps the index's
//! generation, so an identifier issued before the free never resolves again:
//! a client that keeps using a cap after its file was removed gets "no such
//! node", never the node that later reuses the index. An index whose
//! generation would wrap is retired instead of reused. The table grows on
//! the heap with the live entries, and every growth is fallible.

use alloc::vec::Vec;

/// Bits of a node identifier holding the slab index plus one (0 is the
/// root's identifier, which the slab never issues).
pub const INDEX_BITS: u32 = 24;

/// Bits of a node identifier holding the index's generation. With
/// [`INDEX_BITS`] they fill the 40-bit `NodeId` of the namespace protocol's
/// badge.
pub const GENERATION_BITS: u32 = 16;

/// Most live entries a slab holds: every index the identifier's index field
/// can name, about 16.7 million nodes.
pub const MAX_ENTRIES: usize = (1 << INDEX_BITS) - 1;

const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;

struct Slot<K, T>
{
    entry: Option<(K, T)>,
    generation: u16,
}

/// A recycling, generation-checked table of `T` keyed by `K`; see the module
/// docs.
pub struct NodeSlab<K, T>
{
    slots: Vec<Slot<K, T>>,
    /// Indices of freed slots whose generation has not wrapped. Its capacity
    /// is kept at least `slots.len()`, so a free never allocates.
    free: Vec<u32>,
    /// Live entries as `(key, index)`, sorted by key, for deduplication.
    by_key: Vec<(K, u32)>,
}

impl<K: Ord + Copy, T> Default for NodeSlab<K, T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<K: Ord + Copy, T> NodeSlab<K, T>
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            by_key: Vec::new(),
        }
    }

    /// The identifier of the entry for `key`, inserting `make()` when the key
    /// has none.
    ///
    /// Returns `None` when a new entry is needed and either the slab already
    /// holds [`MAX_ENTRIES`] entries with every freed index retired, or the
    /// heap cannot grow the table.
    pub fn acquire(&mut self, key: K, make: impl FnOnce() -> T) -> Option<u64>
    {
        let pos = match self.by_key.binary_search_by(|(k, _)| k.cmp(&key))
        {
            Ok(pos) =>
            {
                let idx = self.by_key[pos].1;
                return Some(identifier(idx, self.slots[idx as usize].generation));
            }
            Err(pos) => pos,
        };
        self.by_key.try_reserve(1).ok()?;
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
        slot.entry = Some((key, make()));
        self.by_key.insert(pos, (key, idx));
        Some(identifier(idx, slot.generation))
    }

    /// The value `id` names, while the entry it was issued for is live.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&T>
    {
        let idx = self.live_index(id)?;
        self.slots[idx].entry.as_ref().map(|(_, v)| v)
    }

    /// Mutable access to the value `id` names; `None` as [`Self::get`].
    pub fn get_mut(&mut self, id: u64) -> Option<&mut T>
    {
        let idx = self.live_index(id)?;
        self.slots[idx].entry.as_mut().map(|(_, v)| v)
    }

    /// Free the entry for `key`, returning its value: every identifier
    /// issued for it stops resolving.
    pub fn remove_key(&mut self, key: &K) -> Option<T>
    {
        let pos = self.by_key.binary_search_by(|(k, _)| k.cmp(key)).ok()?;
        let (_, idx) = self.by_key.remove(pos);
        let slot = &mut self.slots[idx as usize];
        let (_, value) = slot.entry.take()?;
        // Retire an index whose generation would wrap: reissuing generation 0
        // would let an identifier from the first lifetime resolve again.
        if let Some(next) = slot.generation.checked_add(1)
        {
            slot.generation = next;
            // Never allocates: `free` holds at least `slots.len()` capacity.
            self.free.push(idx);
        }
        Some(value)
    }

    /// Live entries.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.by_key.len()
    }

    /// Whether the slab holds no live entry.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.by_key.is_empty()
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

/// The identifier of slab index `idx` at `generation`: never 0, the root's.
fn identifier(idx: u32, generation: u16) -> u64
{
    (u64::from(generation) << INDEX_BITS) | (u64::from(idx) + 1)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_removed_then_reused_index_never_resolves_the_old_identifier()
    {
        let mut slab: NodeSlab<u32, &str> = NodeSlab::new();
        let a = slab.acquire(1, || "file A").expect("room");
        assert_eq!(slab.remove_key(&1), Some("file A"));
        // B takes A's index; A's identifier names B's slot at an older
        // generation and must not return B's content.
        let b = slab.acquire(2, || "file B").expect("room");
        assert_eq!(a & INDEX_MASK, b & INDEX_MASK);
        assert_ne!(a, b);
        assert_eq!(slab.get(a), None);
        assert_eq!(slab.get(b), Some(&"file B"));
    }

    #[test]
    fn every_lookup_of_a_key_returns_its_one_live_identifier()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let first = slab.acquire(7, || 1).expect("room");
        let second = slab.acquire(7, || 2).expect("room");
        assert_eq!(first, second);
        assert_eq!(slab.get(first), Some(&1));
        assert_eq!(slab.len(), 1);
        // Keys inserted out of order still dedupe.
        let other = slab.acquire(3, || 3).expect("room");
        assert_eq!(slab.acquire(3, || 4), Some(other));
        assert_eq!(slab.acquire(7, || 5), Some(first));
    }

    #[test]
    fn a_removed_key_is_looked_up_afresh_under_a_new_identifier()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let id = slab.acquire(3, || 9).expect("room");
        assert_eq!(slab.remove_key(&3), Some(9));
        assert!(slab.is_empty());
        assert_eq!(slab.remove_key(&3), None);
        let again = slab.acquire(3, || 10).expect("room");
        assert_ne!(again, id);
        assert_eq!(slab.get(again), Some(&10));
        assert_eq!(slab.get(id), None);
    }

    #[test]
    fn an_index_is_retired_when_its_generation_would_wrap()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let first = slab.acquire(0, || 0).expect("room");
        slab.slots[0].generation = u16::MAX;
        assert_eq!(slab.remove_key(&0), Some(0));
        // Index 0 is not reissued: the next entry takes a new index, so the
        // generation-0 identifier `first` can never name a live entry again.
        let next = slab.acquire(1, || 1).expect("room");
        assert_ne!(next & INDEX_MASK, first & INDEX_MASK);
        assert_eq!(slab.get(first), None);
    }

    #[test]
    fn the_first_index_is_never_issued_as_the_root_identifier()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let id = slab.acquire(0, || 0).expect("room");
        assert_ne!(id, 0);
        assert_eq!(slab.get(0), None);
    }
}
