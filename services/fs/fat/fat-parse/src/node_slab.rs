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
//! the heap with the live entries, every growth fallible, and finds a key
//! through a hash index in O(1) expected time.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

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

pub(crate) const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;

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
    /// Key index for deduplication: an open-addressing hash table (linear
    /// probing, backward-shift deletion) of slot indices, [`EMPTY`] in an
    /// unused bucket. Its length is zero or a power of two, at least twice
    /// the live entries, so a lookup or insert costs O(1) expected.
    buckets: Vec<u32>,
    /// Live entries.
    len: usize,
}

/// An unused bucket of [`NodeSlab::buckets`].
const EMPTY: u32 = u32::MAX;

/// Buckets of the first key index the slab allocates.
const MIN_BUCKETS: usize = 16;

impl<K: Hash + Eq + Copy, T> Default for NodeSlab<K, T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<K: Hash + Eq + Copy, T> NodeSlab<K, T>
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            buckets: Vec::new(),
            len: 0,
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
        if let Some((_, idx)) = self.find(&key)
        {
            return self.live_identifier(idx);
        }
        // The key index stays at least twice the live entries.
        if self.len >= self.buckets.len() / 2
        {
            self.grow()?;
        }
        let idx = if let Some(idx) = self.free.pop()
        {
            idx
        }
        else
        {
            let (idx, new_len) = new_index(self.slots.len(), MAX_ENTRIES)?;
            self.slots.try_reserve(1).ok()?;
            self.free.try_reserve(new_len).ok()?;
            self.slots.push(Slot {
                entry: None,
                generation: 0,
            });
            idx
        };
        // `idx` is a freed or a just-pushed slot, so the slot exists.
        let slot = self.slots.get_mut(idx as usize)?;
        slot.entry = Some((key, make()));
        let generation = slot.generation;
        self.place(&key, idx);
        // At most one live entry per slot, and at most `MAX_ENTRIES` slots, so
        // this never saturates.
        self.len = self.len.saturating_add(1);
        Some(identifier(idx, generation))
    }

    /// The identifier of `key`'s live entry, without inserting one.
    #[must_use]
    pub fn id_of(&self, key: &K) -> Option<u64>
    {
        let (_, idx) = self.find(key)?;
        self.live_identifier(idx)
    }

    /// The value `id` names, while the entry it was issued for is live.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&T>
    {
        let idx = self.live_index(id)?;
        self.slots.get(idx)?.entry.as_ref().map(|(_, v)| v)
    }

    /// Mutable access to the value `id` names; `None` as [`Self::get`].
    pub fn get_mut(&mut self, id: u64) -> Option<&mut T>
    {
        let idx = self.live_index(id)?;
        self.slots.get_mut(idx)?.entry.as_mut().map(|(_, v)| v)
    }

    /// Free the entry for `key`, returning its value: every identifier
    /// issued for it stops resolving.
    pub fn remove_key(&mut self, key: &K) -> Option<T>
    {
        let (bucket, idx) = self.find(key)?;
        self.unplace(bucket);
        // A key the index finds is live, so `len` is at least 1.
        self.len = self.len.saturating_sub(1);
        let slot = self.slots.get_mut(idx as usize)?;
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
        self.len
    }

    /// Whether the slab holds no live entry.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The key of the live slot `idx`.
    fn key_of(&self, idx: u32) -> Option<&K>
    {
        self.slots.get(idx as usize)?.entry.as_ref().map(|(k, _)| k)
    }

    /// The identifier of slot `idx` at its current generation.
    fn live_identifier(&self, idx: u32) -> Option<u64>
    {
        let slot = self.slots.get(idx as usize)?;
        Some(identifier(idx, slot.generation))
    }

    /// The bucket `key` hashes to in a table of `mask + 1` buckets.
    fn home(key: &K, mask: usize) -> usize
    {
        let mut h = Fnv1a(FNV_OFFSET);
        key.hash(&mut h);
        // Cast is range-safe: the result is masked to a bucket index.
        #[allow(clippy::cast_possible_truncation)]
        let home = h.finish() as usize & mask;
        home
    }

    /// The bucket holding `key`'s slot index, and that index, if `key` is
    /// live.
    fn find(&self, key: &K) -> Option<(usize, u32)>
    {
        let mask = self.buckets.len().checked_sub(1)?;
        let mut b = Self::home(key, mask);
        loop
        {
            let idx = *self.buckets.get(b)?;
            if idx == EMPTY
            {
                return None;
            }
            if self.key_of(idx) == Some(key)
            {
                return Some((b, idx));
            }
            b = next_bucket(b, mask);
        }
    }

    /// Record live slot `idx` under `key` in the first free bucket of its
    /// probe run. The table has room: it is at least twice the live entries.
    fn place(&mut self, key: &K, idx: u32)
    {
        let Some(mask) = self.buckets.len().checked_sub(1)
        else
        {
            return;
        };
        let mut b = Self::home(key, mask);
        while let Some(bucket) = self.buckets.get_mut(b)
        {
            if *bucket == EMPTY
            {
                *bucket = idx;
                return;
            }
            b = next_bucket(b, mask);
        }
    }

    /// Empty bucket `hole`, shifting each later entry of its probe run back
    /// into it when the entry's home does not lie between the hole and it, so
    /// every live key stays reachable from its home without tombstones.
    fn unplace(&mut self, mut hole: usize)
    {
        let Some(mask) = self.buckets.len().checked_sub(1)
        else
        {
            return;
        };
        self.set_bucket(hole, EMPTY);
        let mut b = next_bucket(hole, mask);
        while let Some(&idx) = self.buckets.get(b)
        {
            if idx == EMPTY
            {
                return;
            }
            let start = self.key_of(idx).map_or(b, |k| Self::home(k, mask));
            // Distance from home to b, and from home to the hole, along the
            // probe direction.
            let from_home = b.wrapping_sub(start) & mask;
            let to_hole = hole.wrapping_sub(start) & mask;
            if to_hole <= from_home
            {
                self.set_bucket(hole, idx);
                self.set_bucket(b, EMPTY);
                hole = b;
            }
            b = next_bucket(b, mask);
        }
    }

    /// Store `idx` in bucket `b`, a bucket of the table.
    fn set_bucket(&mut self, b: usize, idx: u32)
    {
        if let Some(bucket) = self.buckets.get_mut(b)
        {
            *bucket = idx;
        }
    }

    /// Double the key index (or allocate its first [`MIN_BUCKETS`]) and
    /// rehash the live entries into it; `None` when the heap cannot hold it.
    fn grow(&mut self) -> Option<()>
    {
        let size = self.buckets.len().checked_mul(2)?.max(MIN_BUCKETS);
        let mut table = Vec::new();
        table.try_reserve_exact(size).ok()?;
        table.resize(size, EMPTY);
        let old = core::mem::replace(&mut self.buckets, table);
        for idx in old.into_iter().filter(|&i| i != EMPTY)
        {
            if let Some(key) = self.key_of(idx).copied()
            {
                self.place(&key, idx);
            }
        }
        Some(())
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

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a over the key's bytes: the key index's hash. The fat driver's keys
/// are on-disk slots, `(sector_lba, offset_in_sector)`. A client holding
/// `MUTATE_DIR` chooses which slots stay live, by creating entries and
/// removing the ones it does not want, but never sees the `sector_lba` an
/// entry lands at, so it cannot aim its entries at one probe run, and the
/// hash needs no keying against collision floods.
struct Fnv1a(u64);

impl Hasher for Fnv1a
{
    fn finish(&self) -> u64
    {
        self.0
    }

    fn write(&mut self, bytes: &[u8])
    {
        for &b in bytes
        {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(FNV_PRIME);
        }
    }
}

/// The bucket after `b` in the probe order of a table of `mask + 1` buckets,
/// wrapping to the first.
fn next_bucket(b: usize, mask: usize) -> usize
{
    b.wrapping_add(1) & mask
}

/// The index of the slot a slab of `len` slots pushes next, and its length
/// after that push; `None` when the push would take it past `max` slots.
/// [`crate::open_slab::OpenSlab`] grows the same way.
pub(crate) fn new_index(len: usize, max: usize) -> Option<(u32, usize)>
{
    let new_len = len.checked_add(1).filter(|&n| n <= max)?;
    Some((u32::try_from(len).ok()?, new_len))
}

/// The identifier of slab index `idx` at `generation`: never 0, the root's.
/// [`crate::open_slab::OpenSlab`] issues its identifiers in the same shape.
pub(crate) fn identifier(idx: u32, generation: u16) -> u64
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
    fn interleaved_inserts_and_removals_keep_every_live_key_reachable()
    {
        // Enough keys to grow the index several times and to wrap probe runs;
        // removals in a scattered order exercise the backward shift.
        let mut slab: NodeSlab<(u32, usize), u32> = NodeSlab::new();
        let mut live = std::collections::BTreeMap::new();
        for i in 0..2000u32
        {
            let key = (i.wrapping_mul(2_654_435_761) % 997, (i % 16) as usize * 32);
            let id = slab.acquire(key, || i).expect("room");
            live.entry(key).or_insert((id, i));
            if i % 3 == 0
            {
                let gone = (i.wrapping_mul(40_503) % 997, (i % 7) as usize * 32);
                if let Some((gid, _)) = live.remove(&gone)
                {
                    assert!(slab.remove_key(&gone).is_some());
                    assert_eq!(slab.get(gid), None);
                }
            }
        }
        assert_eq!(slab.len(), live.len());
        for (key, (id, v)) in &live
        {
            assert_eq!(slab.get(*id), Some(v), "key {key:?}");
            assert_eq!(slab.acquire(*key, || u32::MAX), Some(*id));
        }
    }

    #[test]
    fn id_of_names_a_live_key_without_inserting_one()
    {
        let mut slab: NodeSlab<u32, u8> = NodeSlab::new();
        assert_eq!(slab.id_of(&4), None);
        let id = slab.acquire(4, || 1).expect("room");
        assert_eq!(slab.id_of(&4), Some(id));
        assert_eq!(slab.id_of(&5), None);
        assert_eq!(slab.len(), 1);
        slab.remove_key(&4);
        assert_eq!(slab.id_of(&4), None);
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
