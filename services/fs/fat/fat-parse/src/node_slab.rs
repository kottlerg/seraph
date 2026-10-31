// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/node_slab.rs

//! Recycling, generation-checked identifier table for `fatfs` nodes.
//!
//! A [`NodeSlab`] maps a node key (the on-disk slot of a directory entry) to
//! a value and hands out a 40-bit identifier for it: a 24-bit index into the
//! slab and a 16-bit generation. An entry counts the references the driver
//! has minted on it (one per lookup or create that returned a cap) and is
//! freed when the last is released, or at once when its on-disk entry is
//! removed. Freeing bumps the index's generation, so an identifier minted
//! before the free never resolves again: a client that keeps using a cap
//! after closing it, or after the file was removed, gets "no such node",
//! never the node that later reuses the index. An index whose generation
//! would wrap is retired instead of reused. The table grows on the heap with
//! the live nodes; nothing in it is fixed-size.

use alloc::collections::BTreeMap;
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
    refs: u32,
}

/// A recycling, generation-checked table of `T` keyed by `K`; see the module
/// docs.
pub struct NodeSlab<K, T>
{
    slots: Vec<Slot<K, T>>,
    /// Indices of freed slots whose generation has not wrapped.
    free: Vec<u32>,
    /// Live entries by key, for deduplication.
    by_key: BTreeMap<K, u32>,
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
            by_key: BTreeMap::new(),
        }
    }

    /// Take a reference on the entry for `key`, inserting `make()` when the
    /// key has none, and return the entry's identifier.
    ///
    /// Returns `None` when a new entry is needed and the slab already holds
    /// [`MAX_ENTRIES`] live entries (with every freed index retired), or the
    /// existing entry's reference count is at `u32::MAX`.
    pub fn acquire(&mut self, key: K, make: impl FnOnce() -> T) -> Option<u64>
    {
        if let Some(&idx) = self.by_key.get(&key)
        {
            let slot = &mut self.slots[idx as usize];
            slot.refs = slot.refs.checked_add(1)?;
            return Some(identifier(idx, slot.generation));
        }
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
            self.slots.push(Slot {
                entry: None,
                generation: 0,
                refs: 0,
            });
            // Cast is range-safe: the length is below MAX_ENTRIES < 2^24.
            #[allow(clippy::cast_possible_truncation)]
            let idx = (self.slots.len() - 1) as u32;
            idx
        };
        let slot = &mut self.slots[idx as usize];
        slot.entry = Some((key, make()));
        slot.refs = 1;
        self.by_key.insert(key, idx);
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

    /// Drop one reference on the entry `id` names, freeing it when that was
    /// the last; the freed value is returned. `None` when `id` names no live
    /// entry or the entry keeps other references.
    pub fn release(&mut self, id: u64) -> Option<T>
    {
        let idx = self.live_index(id)?;
        let slot = &mut self.slots[idx];
        slot.refs = slot.refs.saturating_sub(1);
        if slot.refs > 0
        {
            return None;
        }
        self.free_index(idx)
    }

    /// Free the entry for `key` whatever its references, returning its value:
    /// every identifier issued for it stops resolving.
    pub fn remove_key(&mut self, key: &K) -> Option<T>
    {
        let idx = *self.by_key.get(key)?;
        self.free_index(idx as usize)
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

    fn free_index(&mut self, idx: usize) -> Option<T>
    {
        let slot = &mut self.slots[idx];
        let (key, value) = slot.entry.take()?;
        slot.refs = 0;
        self.by_key.remove(&key);
        // Retire an index whose generation would wrap: reissuing generation 0
        // would let an identifier from the first lifetime resolve again.
        if let Some(next) = slot.generation.checked_add(1)
        {
            slot.generation = next;
            // Cast is range-safe: indices are below MAX_ENTRIES < 2^24.
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
    fn a_closed_then_reused_index_never_resolves_the_old_identifier()
    {
        let mut slab: NodeSlab<u32, &str> = NodeSlab::new();
        let a = slab.acquire(1, || "file A").expect("room");
        assert_eq!(slab.release(a), Some("file A"));
        // B takes A's index; A's identifier names B's slot at an older
        // generation and must not return B's content.
        let b = slab.acquire(2, || "file B").expect("room");
        assert_eq!(a & INDEX_MASK, b & INDEX_MASK);
        assert_ne!(a, b);
        assert_eq!(slab.get(a), None);
        assert_eq!(slab.get(b), Some(&"file B"));
    }

    #[test]
    fn a_key_looked_up_twice_is_freed_only_after_both_releases()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let first = slab.acquire(7, || 1).expect("room");
        let second = slab.acquire(7, || 2).expect("room");
        assert_eq!(first, second);
        assert_eq!(slab.release(first), None);
        assert_eq!(slab.get(first), Some(&1));
        assert_eq!(slab.release(first), Some(1));
        assert_eq!(slab.get(first), None);
        // A further release of the dead identifier changes nothing.
        assert_eq!(slab.release(first), None);
    }

    #[test]
    fn removing_a_key_invalidates_every_identifier_whatever_its_references()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let id = slab.acquire(3, || 9).expect("room");
        slab.acquire(3, || 9).expect("room");
        assert_eq!(slab.remove_key(&3), Some(9));
        assert_eq!(slab.get(id), None);
        assert!(slab.is_empty());
        // The key can be looked up afresh, under a new identifier.
        let again = slab.acquire(3, || 10).expect("room");
        assert_ne!(again, id);
        assert_eq!(slab.get(again), Some(&10));
    }

    #[test]
    fn an_index_is_retired_when_its_generation_would_wrap()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        let first = slab.acquire(0, || 0).expect("room");
        slab.slots[0].generation = u16::MAX;
        let last = identifier(0, u16::MAX);
        assert_eq!(slab.release(last), Some(0));
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
