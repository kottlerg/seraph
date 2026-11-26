// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/page_index.rs

//! The `fatfs` page cache's index from a cached page to the slot holding it.
//!
//! A [`PageIndex`] keeps the page-aligned LBA-base of every cached page with
//! its slot index, sorted by LBA-base in an array sized at init to the cache's
//! slot ceiling and padded to a power of two with [`PageIndex::EMPTY`] keys.
//! A lookup is a binary search of a fixed number of steps, the logarithm of
//! the padded length, each step choosing its half by arithmetic rather than a
//! branch: its instructions depend on the slot ceiling alone, not on the key,
//! on what else the cache holds, or on the order the pages were filled in.
//! That order follows the order of the requests the filesystem served before,
//! which the machine's timing decides, so a search whose cost depended on the
//! position of the page (a scan of the slots that stops at the hit) would give
//! one request different costs in different boots. An insert and a removal
//! shift the entries above the key's place, O(n) in the pages cached; the cache
//! makes them only when a page is filled or leaves, each beside a block-device
//! request or a release that costs far more.
//!
//! The arrays are allocated once, by [`PageIndex::with_capacity`], so no
//! insert or removal allocates: the cache changes the index on its miss and
//! release paths, which run when memory is short.

use alloc::boxed::Box;
use alloc::vec::Vec;

/// A sorted index from a cached page's LBA-base to its slot; see the module
/// docs.
pub struct PageIndex
{
    /// LBA-bases, ascending; every entry from `len` on is [`Self::EMPTY`].
    /// The length is a power of two.
    keys: Box<[u64]>,
    /// The slot of each key, at the key's position; unused past `len`.
    slots: Box<[usize]>,
    /// Entries in use.
    len: usize,
    /// Most entries the index holds: the capacity it was made with.
    capacity: usize,
}

impl PageIndex
{
    /// The key of an unused entry, above every LBA-base: a page-aligned
    /// LBA-base is a multiple of the sectors per page, which `u64::MAX` is
    /// not for any page of more than one sector, and the cache uses it as
    /// its own mark of a slot holding no page.
    pub const EMPTY: u64 = u64::MAX;

    /// An empty index for at most `capacity` pages, or `None` when the heap
    /// cannot hold its arrays.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Option<Self>
    {
        let padded = capacity.max(1).checked_next_power_of_two()?;
        let mut keys = Vec::new();
        keys.try_reserve_exact(padded).ok()?;
        keys.resize(padded, Self::EMPTY);
        let mut slots = Vec::new();
        slots.try_reserve_exact(padded).ok()?;
        slots.resize(padded, 0);
        Some(Self {
            keys: keys.into_boxed_slice(),
            slots: slots.into_boxed_slice(),
            len: 0,
            capacity,
        })
    }

    /// Pages the index holds.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the index holds no page.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The slot holding the page at `key`, or `None` when the index holds no
    /// such page. Runs the same instructions for every key and every content
    /// of an index of one capacity (module docs).
    #[must_use]
    pub fn lookup(&self, key: u64) -> Option<usize>
    {
        let at = self.position(key);
        let found = self.keys.get(at).copied() == Some(key) && key != Self::EMPTY;
        found.then(|| self.slots.get(at).copied()).flatten()
    }

    /// Record that slot `slot` holds the page at `key`, replacing the slot an
    /// entry for `key` named. `false`, the index unchanged, when `key` is
    /// [`Self::EMPTY`], or the index is full and holds no entry for `key`.
    pub fn insert(&mut self, key: u64, slot: usize) -> bool
    {
        if key == Self::EMPTY
        {
            return false;
        }
        let at = self.lower_bound(key);
        if self.keys.get(at).copied() == Some(key)
        {
            if let Some(entry) = self.slots.get_mut(at)
            {
                *entry = slot;
            }
            return true;
        }
        if self.len >= self.capacity
        {
            return false;
        }
        // `at` is at most `len`, below `capacity`, so both ranges lie within
        // the arrays, whose length is at least `capacity`.
        let end = self.len.saturating_add(1);
        let (Some(keys), Some(slots)) = (self.keys.get_mut(at..end), self.slots.get_mut(at..end))
        else
        {
            return false;
        };
        keys.rotate_right(1);
        slots.rotate_right(1);
        if let (Some(k), Some(s)) = (keys.first_mut(), slots.first_mut())
        {
            *k = key;
            *s = slot;
        }
        self.len = end;
        true
    }

    /// Drop the entry for `key`, returning the slot it named, or `None` when
    /// the index holds no entry for `key`.
    pub fn remove(&mut self, key: u64) -> Option<usize>
    {
        if key == Self::EMPTY
        {
            return None;
        }
        let at = self.lower_bound(key);
        if self.keys.get(at).copied() != Some(key)
        {
            return None;
        }
        let slot = self.slots.get(at).copied();
        // An entry was found at `at`, below `len`.
        let keys = self.keys.get_mut(at..self.len)?;
        let slots = self.slots.get_mut(at..self.len)?;
        keys.rotate_left(1);
        slots.rotate_left(1);
        if let Some(last) = keys.last_mut()
        {
            *last = Self::EMPTY;
        }
        self.len = self.len.saturating_sub(1);
        slot
    }

    /// The first position whose key is not below `key` (the padded length's
    /// last position when every key is below it), found in the logarithm of the
    /// padded length steps whatever the keys are: each step adds the half it
    /// skips through a mask of the comparison, so no step branches on a key.
    fn position(&self, key: u64) -> usize
    {
        let mut at: usize = 0;
        let mut half = self.keys.len() / 2;
        while half > 0
        {
            // `at` is a sum of the larger halves, each a power of two above
            // `half`, so `at | (half - 1)` is `at + half - 1`, the last
            // position of the lower half, below the padded length.
            let probe = self
                .keys
                .get(at | half.wrapping_sub(1))
                .copied()
                .unwrap_or(Self::EMPTY);
            at |= half & usize::from(probe < key).wrapping_neg();
            half /= 2;
        }
        at
    }

    /// The first position below `len` whose key is not below `key`, or `len`:
    /// where an insert places `key`. Off the lookup path, so a plain binary
    /// search.
    fn lower_bound(&self, key: u64) -> usize
    {
        self.keys
            .get(..self.len)
            .map_or(0, |keys| keys.partition_point(|&k| k < key))
    }
}

#[cfg(test)]
mod tests
{
    use super::PageIndex;

    /// The entries of `index` as (key, slot) pairs, in order.
    fn entries(index: &PageIndex) -> Vec<(u64, usize)>
    {
        index
            .keys
            .iter()
            .zip(index.slots.iter())
            .take(index.len())
            .map(|(&k, &s)| (k, s))
            .collect()
    }

    #[test]
    fn a_lookup_finds_every_page_inserted_in_any_order_and_no_other()
    {
        for capacity in [1, 2, 3, 7, 8, 9, 256, 300]
        {
            let mut index = PageIndex::with_capacity(capacity).expect("heap");
            // Keys inserted out of order: every 8th LBA, scrambled by a stride
            // coprime to every capacity tried (313 is a prime above them).
            let keys: Vec<u64> = (0..capacity)
                .map(|i| ((i * 313 + 3) % capacity) as u64 * 8)
                .collect();
            for (slot, &key) in keys.iter().enumerate()
            {
                assert!(index.insert(key, slot));
            }
            assert_eq!(index.len(), capacity);
            for (slot, &key) in keys.iter().enumerate()
            {
                assert_eq!(
                    index.lookup(key),
                    Some(slot),
                    "capacity {capacity}, key {key}"
                );
                assert_eq!(index.lookup(key + 1), None);
            }
            assert_eq!(index.lookup(capacity as u64 * 8), None);
            assert_eq!(index.lookup(PageIndex::EMPTY), None);
            let sorted = entries(&index);
            assert!(sorted.windows(2).all(|w| w[0].0 < w[1].0));
        }
    }

    #[test]
    fn a_full_index_refuses_a_new_page_and_replaces_a_held_one()
    {
        let mut index = PageIndex::with_capacity(3).expect("heap");
        assert!(index.insert(16, 0));
        assert!(index.insert(0, 1));
        assert!(index.insert(8, 2));
        assert!(!index.insert(24, 3));
        assert_eq!(index.lookup(24), None);
        assert!(index.insert(8, 5));
        assert_eq!(index.lookup(8), Some(5));
        assert_eq!(entries(&index), vec![(0, 1), (8, 5), (16, 0)]);
    }

    #[test]
    fn a_removal_frees_its_place_and_leaves_the_others_found()
    {
        let mut index = PageIndex::with_capacity(4).expect("heap");
        for (slot, key) in [40, 8, 24, 0].into_iter().enumerate()
        {
            assert!(index.insert(key, slot));
        }
        assert_eq!(index.remove(24), Some(2));
        assert_eq!(index.remove(24), None);
        assert_eq!(index.lookup(24), None);
        assert_eq!(index.lookup(0), Some(3));
        assert_eq!(index.lookup(8), Some(1));
        assert_eq!(index.lookup(40), Some(0));
        assert_eq!(index.len(), 3);
        assert!(index.insert(32, 7));
        assert_eq!(entries(&index), vec![(0, 3), (8, 1), (32, 7), (40, 0)]);
        for key in [0, 8, 32, 40]
        {
            assert!(index.remove(key).is_some());
        }
        assert!(index.is_empty());
        assert!(index.keys.iter().all(|&k| k == PageIndex::EMPTY));
    }

    #[test]
    fn the_empty_key_is_never_held()
    {
        let mut index = PageIndex::with_capacity(2).expect("heap");
        assert!(!index.insert(PageIndex::EMPTY, 0));
        assert_eq!(index.remove(PageIndex::EMPTY), None);
        assert_eq!(index.lookup(PageIndex::EMPTY), None);
        assert!(index.is_empty());
    }
}
