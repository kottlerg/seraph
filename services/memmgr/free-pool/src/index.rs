// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/index.rs

//! Badge-keyed process index: a linear hash over arena-resident records.
//!
//! Records are [`Node::Process`] slots in the [`Arena`], chained per bucket
//! through their slot `next` link. The bucket array is a [`WordStore`] of
//! bucket heads that only grows, one page of buckets at a time; linear
//! hashing splits one bucket per step, so growth never rehashes the whole
//! table and the array stays append-only. When the owner cannot add bucket
//! storage the table keeps working with longer chains: bucket storage tunes
//! lookup cost and bounds no capacity. See
//! `services/memmgr/docs/memory-pool.md` § Per-Process Tracking.

use syscall_abi::PAGE_SIZE;

use crate::arena::{Arena, NODE_NULL, Node, NodeIdx, SlotStore};

/// Bucket heads per page of bucket storage.
pub const BUCKETS_PER_PAGE: u64 = PAGE_SIZE / 8;

/// Mean chain length past which the index splits a bucket.
const MAX_LOAD: u64 = 2;

/// Backing storage for bucket heads.
pub trait WordStore
{
    /// Read word `i`.
    ///
    /// # Safety
    /// `i` MUST lie below the capacity the owning [`ProcessIndex`] has been
    /// given through [`ProcessIndex::add_page`].
    unsafe fn read(&self, i: u64) -> u64;

    /// Write word `i`.
    ///
    /// # Safety
    /// As [`WordStore::read`].
    unsafe fn write(&mut self, i: u64, v: u64);
}

/// Spread a badge over the bucket bits. Badges are random draws already; the
/// multiply keeps the reserved badges (all-ones and its neighbour) and any
/// creator-chosen bootstrap badge from clustering in the low bits.
const fn hash(badge: u64) -> u64
{
    badge.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(32)
}

/// The index state: bucket storage plus the linear-hash split state.
pub struct ProcessIndex<W>
{
    words: W,
    /// Buckets the storage holds.
    capacity: u64,
    /// Power-of-two bucket count at the start of the current round.
    level: u64,
    /// Next bucket to split in this round; live buckets are `level + split`.
    split: u64,
    count: u64,
}

impl<W: WordStore> ProcessIndex<W>
{
    /// An index with no bucket storage over `words`. Inserts fail until
    /// [`ProcessIndex::add_page`] gives it the first page.
    pub const fn new(words: W) -> Self
    {
        Self {
            words,
            capacity: 0,
            level: 1,
            split: 0,
            count: 0,
        }
    }

    /// Records indexed.
    #[must_use]
    pub const fn len(&self) -> u64
    {
        self.count
    }

    /// Whether no record is indexed.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.count == 0
    }

    /// Live buckets.
    #[must_use]
    pub const fn buckets(&self) -> u64
    {
        self.level + self.split
    }

    /// Bucket pages given so far; the next [`ProcessIndex::add_page`] covers
    /// page `pages()`.
    #[must_use]
    pub const fn pages(&self) -> u64
    {
        self.capacity / BUCKETS_PER_PAGE
    }

    /// Whether the next insert would want more bucket storage: none yet, or
    /// every bucket in use and the load past [`MAX_LOAD`].
    #[must_use]
    pub const fn wants_page(&self) -> bool
    {
        self.capacity == 0
            || (self.buckets() >= self.capacity && self.count + 1 > MAX_LOAD * self.buckets())
    }

    /// Give the index the next page of bucket storage (words `[capacity,
    /// capacity + BUCKETS_PER_PAGE)`), then split any buckets the load
    /// already calls for.
    ///
    /// # Safety
    /// The store MUST accept [`WordStore::read`] and [`WordStore::write`] for
    /// every word in that range for the index's life.
    pub unsafe fn add_page<S: SlotStore>(&mut self, arena: &mut Arena<S>)
    {
        for i in self.capacity..self.capacity + BUCKETS_PER_PAGE
        {
            // SAFETY: the caller's contract covers word `i`.
            unsafe { self.words.write(i, NODE_NULL) };
        }
        self.capacity += BUCKETS_PER_PAGE;
        self.grow(arena);
    }

    fn head(&self, bucket: u64) -> NodeIdx
    {
        debug_assert!(bucket < self.capacity);
        if bucket >= self.capacity
        {
            return NODE_NULL;
        }
        // SAFETY: `bucket < capacity`, which `add_page`'s contract made valid.
        unsafe { self.words.read(bucket) }
    }

    fn set_head(&mut self, bucket: u64, idx: NodeIdx)
    {
        debug_assert!(bucket < self.capacity);
        if bucket < self.capacity
        {
            // SAFETY: as in `head`.
            unsafe { self.words.write(bucket, idx) };
        }
    }

    fn bucket_of(&self, badge: u64) -> u64
    {
        let h = hash(badge);
        let b = h & (self.level - 1);
        if b < self.split
        {
            h & (2 * self.level - 1)
        }
        else
        {
            b
        }
    }

    /// The record slot keyed by `badge`.
    #[must_use]
    pub fn find<S: SlotStore>(&self, arena: &Arena<S>, badge: u64) -> Option<NodeIdx>
    {
        if self.capacity == 0
        {
            return None;
        }
        let mut cur = self.head(self.bucket_of(badge));
        while cur != NODE_NULL
        {
            let slot = arena.get(cur);
            match slot.node
            {
                Node::Process(rec) if rec.badge == badge => return Some(cur),
                Node::Process(_) => cur = slot.next,
                _ => return None,
            }
        }
        None
    }

    /// Index the record slot `idx` (which holds a [`Node::Process`] whose
    /// badge no indexed record shares). Returns `false`, indexing nothing,
    /// when the index has no bucket storage or the slot holds no record.
    pub fn insert<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx) -> bool
    {
        let Node::Process(rec) = arena.get(idx).node
        else
        {
            return false;
        };
        if self.capacity == 0
        {
            return false;
        }
        let b = self.bucket_of(rec.badge);
        arena.set_next(idx, self.head(b));
        self.set_head(b, idx);
        self.count += 1;
        self.grow(arena);
        true
    }

    /// Unindex the record keyed by `badge`, returning its slot (still holding
    /// the record; the caller frees it).
    pub fn remove<S: SlotStore>(&mut self, arena: &mut Arena<S>, badge: u64) -> Option<NodeIdx>
    {
        if self.capacity == 0
        {
            return None;
        }
        let b = self.bucket_of(badge);
        let mut prev = NODE_NULL;
        let mut cur = self.head(b);
        while cur != NODE_NULL
        {
            let slot = arena.get(cur);
            let Node::Process(rec) = slot.node
            else
            {
                return None;
            };
            if rec.badge == badge
            {
                if prev == NODE_NULL
                {
                    self.set_head(b, slot.next);
                }
                else
                {
                    arena.set_next(prev, slot.next);
                }
                arena.set_next(cur, NODE_NULL);
                self.count -= 1;
                return Some(cur);
            }
            prev = cur;
            cur = slot.next;
        }
        None
    }

    /// Split buckets while the load exceeds [`MAX_LOAD`] and storage allows.
    fn grow<S: SlotStore>(&mut self, arena: &mut Arena<S>)
    {
        while self.count > MAX_LOAD * self.buckets() && self.buckets() < self.capacity
        {
            self.split_one(arena);
        }
    }

    /// Split bucket `split` into itself and bucket `level + split` by the
    /// next hash bit, then advance the split pointer.
    fn split_one<S: SlotStore>(&mut self, arena: &mut Arena<S>)
    {
        let old = self.split;
        let new = self.level + self.split;
        let mask = 2 * self.level - 1;
        let mut keep = NODE_NULL;
        let mut moved = NODE_NULL;
        let mut cur = self.head(old);
        while cur != NODE_NULL
        {
            let slot = arena.get(cur);
            let Node::Process(rec) = slot.node
            else
            {
                break;
            };
            if hash(rec.badge) & mask == new
            {
                arena.set_next(cur, moved);
                moved = cur;
            }
            else
            {
                arena.set_next(cur, keep);
                keep = cur;
            }
            cur = slot.next;
        }
        self.set_head(old, keep);
        self.set_head(new, moved);
        self.split += 1;
        if self.split == self.level
        {
            self.level *= 2;
            self.split = 0;
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::ProcessRecord;
    use crate::arena::test_store::VecStore;

    #[derive(Default)]
    struct VecWords(Vec<u64>);

    impl WordStore for VecWords
    {
        unsafe fn read(&self, i: u64) -> u64
        {
            self.0[i as usize]
        }

        unsafe fn write(&mut self, i: u64, v: u64)
        {
            let i = i as usize;
            if self.0.len() <= i
            {
                self.0.resize(i + 1, NODE_NULL);
            }
            self.0[i] = v;
        }
    }

    fn record(badge: u64) -> Node
    {
        Node::Process(ProcessRecord {
            badge,
            frame_head: NODE_NULL,
            region_head: NODE_NULL,
            aspace_cap: 0,
        })
    }

    fn setup() -> (Arena<VecStore>, ProcessIndex<VecWords>)
    {
        (
            Arena::new(VecStore::default()),
            ProcessIndex::new(VecWords::default()),
        )
    }

    fn insert(a: &mut Arena<VecStore>, ix: &mut ProcessIndex<VecWords>, badge: u64) -> NodeIdx
    {
        if a.free_count() == 0
        {
            // SAFETY: VecStore grows on write.
            unsafe { a.add_page() };
        }
        if ix.wants_page()
        {
            // SAFETY: VecWords grows on write.
            unsafe { ix.add_page(a) };
        }
        let idx = a.alloc(record(badge), NODE_NULL).unwrap();
        assert!(ix.insert(a, idx));
        idx
    }

    #[test]
    fn insert_fails_without_bucket_storage()
    {
        let (mut a, mut ix) = setup();
        // SAFETY: VecStore grows on write.
        unsafe { a.add_page() };
        let idx = a.alloc(record(5), NODE_NULL).unwrap();
        assert!(!ix.insert(&mut a, idx));
        assert!(ix.find(&a, 5).is_none());
    }

    #[test]
    fn every_record_stays_findable_across_bucket_splits()
    {
        let (mut a, mut ix) = setup();
        // Enough records to split past the first page of buckets.
        let n = BUCKETS_PER_PAGE * MAX_LOAD * 3;
        let badges: Vec<u64> = (1..=n)
            .map(|i| i.wrapping_mul(0x2545_F491_4F6C_DD1D))
            .collect();
        let slots: Vec<NodeIdx> = badges.iter().map(|&b| insert(&mut a, &mut ix, b)).collect();
        assert!(ix.buckets() > BUCKETS_PER_PAGE);
        assert_eq!(ix.len(), n);
        for (&b, &s) in badges.iter().zip(&slots)
        {
            assert_eq!(ix.find(&a, b), Some(s));
        }
        assert!(ix.find(&a, 0xDEAD).is_none());
    }

    #[test]
    fn remove_unindexes_only_the_named_record()
    {
        let (mut a, mut ix) = setup();
        let badges = [u64::MAX, u64::MAX - 1, 7, 9];
        let slots: Vec<NodeIdx> = badges.iter().map(|&b| insert(&mut a, &mut ix, b)).collect();
        assert_eq!(ix.remove(&mut a, 7), Some(slots[2]));
        assert!(ix.remove(&mut a, 7).is_none());
        assert!(ix.find(&a, 7).is_none());
        for i in [0, 1, 3]
        {
            assert_eq!(ix.find(&a, badges[i]), Some(slots[i]));
        }
        assert_eq!(ix.len(), 3);
    }

    #[test]
    fn a_full_bucket_store_lengthens_chains_instead_of_refusing()
    {
        let (mut a, mut ix) = setup();
        // SAFETY: VecWords grows on write.
        unsafe { ix.add_page(&mut a) };
        let n = BUCKETS_PER_PAGE * MAX_LOAD * 2;
        let mut found = Vec::new();
        for i in 1..=n
        {
            if a.free_count() == 0
            {
                // SAFETY: VecStore grows on write.
                unsafe { a.add_page() };
            }
            let idx = a.alloc(record(i), NODE_NULL).unwrap();
            assert!(ix.insert(&mut a, idx));
            found.push((i, idx));
        }
        assert_eq!(ix.buckets(), BUCKETS_PER_PAGE);
        assert!(found.iter().all(|&(b, s)| ix.find(&a, b) == Some(s)));
    }
}
