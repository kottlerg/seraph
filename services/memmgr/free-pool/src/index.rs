// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/index.rs

//! Badge-keyed process index: a linear hash over arena-resident records,
//! budget-node handle states and live memory objects.
//!
//! Records are [`Node::Process`] slots in the [`Arena`], keyed by their
//! badge, handle states [`Node::Handle`] slots, keyed by the badge their
//! node handles carry, and live memory objects [`Node::Object`] slots, keyed by
//! the badge their object handles carry ([`key_of`]); each is chained per bucket through its
//! slot `next` link. The bucket array is a [`WordStore`] of
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

/// The key the index files a slot under: a record's badge, the badge a
/// handle state's node handles carry, or the badge a memory object's handles
/// carry; `None` for any other payload. One key
/// names one slot: the owner draws each new key off every key in use.
#[must_use]
pub const fn key_of(node: &Node) -> Option<u64>
{
    match node
    {
        Node::Process(rec) => Some(rec.badge),
        Node::Handle(h) => Some(h.key),
        Node::Object(o) => Some(o.key),
        Node::Free
        | Node::ZeroFrame(_)
        | Node::Reclaim(_)
        | Node::Holder(_)
        | Node::Run(_)
        | Node::Pooled(_)
        | Node::Deferred(_)
        | Node::Budget(_)
        | Node::Region(_)
        | Node::Frame(_)
        | Node::ChunkDir(_)
        | Node::Chunk(_)
        | Node::Caps(_)
        | Node::Commit(_)
        | Node::Limit(_)
        | Node::Disk(_) => None,
    }
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

    /// Slots indexed: records and handle states.
    #[must_use]
    pub const fn len(&self) -> u64
    {
        self.count
    }

    /// Whether no slot is indexed.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.count == 0
    }

    /// Live buckets.
    #[must_use]
    pub const fn buckets(&self) -> u64
    {
        self.level.saturating_add(self.split)
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
            || (self.buckets() >= self.capacity
                && self.count.saturating_add(1) > MAX_LOAD.saturating_mul(self.buckets()))
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
        for i in self.capacity..self.capacity.saturating_add(BUCKETS_PER_PAGE)
        {
            // SAFETY: the caller's contract covers word `i`.
            unsafe { self.words.write(i, NODE_NULL) };
        }
        self.capacity = self.capacity.saturating_add(BUCKETS_PER_PAGE);
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

    /// The live bucket of `badge`: its bucket at this round's level, or at
    /// the next level once that bucket is split. Chosen by mask, so the steps
    /// do not follow whether the badge's bucket has split.
    fn bucket_of(&self, badge: u64) -> u64
    {
        let h = hash(badge);
        let b = h & self.level.saturating_sub(1);
        let wide = h & self.level.saturating_mul(2).saturating_sub(1);
        let split = u64::from(b < self.split).wrapping_neg();
        (wide & split) | (b & !split)
    }

    /// The slot keyed by `badge`: a record or a handle state ([`key_of`]).
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
            match key_of(&slot.node)
            {
                Some(key) if key == badge => return Some(cur),
                Some(_) => cur = slot.next,
                None => return None,
            }
        }
        None
    }

    /// The slot keyed by `badge`, as [`ProcessIndex::find`], moved to the
    /// head of its bucket's chain, so a later lookup of the same key reads
    /// one slot of the chain whatever keys collided with it before. For the
    /// lookups a process repeats on its hot paths (a fault, a grant), whose
    /// cost then does not follow where the random badges placed its slot.
    pub fn find_front<S: SlotStore>(&mut self, arena: &mut Arena<S>, badge: u64)
    -> Option<NodeIdx>
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
            match key_of(&slot.node)
            {
                Some(key) if key == badge =>
                {
                    if prev != NODE_NULL
                    {
                        arena.set_next(prev, slot.next);
                        arena.set_next(cur, self.head(b));
                        self.set_head(b, cur);
                    }
                    return Some(cur);
                }
                Some(_) =>
                {
                    prev = cur;
                    cur = slot.next;
                }
                None => return None,
            }
        }
        None
    }

    /// Call `f` with every indexed slot (record or handle state), bucket by
    /// bucket.
    pub fn for_each<S: SlotStore>(&self, arena: &Arena<S>, mut f: impl FnMut(NodeIdx))
    {
        for bucket in 0..self.buckets().min(self.capacity)
        {
            let mut cur = self.head(bucket);
            while cur != NODE_NULL
            {
                f(cur);
                cur = arena.get(cur).next;
            }
        }
    }

    /// Index the keyed slot `idx` (a record or a handle state, [`key_of`],
    /// whose key no indexed slot shares). Returns `false`, indexing nothing,
    /// when the index has no bucket storage or the slot holds no key.
    pub fn insert<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx) -> bool
    {
        let Some(key) = key_of(&arena.get(idx).node)
        else
        {
            return false;
        };
        if self.capacity == 0
        {
            return false;
        }
        let b = self.bucket_of(key);
        arena.set_next(idx, self.head(b));
        self.set_head(b, idx);
        // Each indexed slot is its own, so the count stays below the slot count.
        self.count = self.count.saturating_add(1);
        self.grow(arena);
        true
    }

    /// Unindex the slot keyed by `badge`, returning it (still holding its
    /// record or handle state; the caller frees it).
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
            let key = key_of(&slot.node)?;
            if key == badge
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
                // The slot being unlinked was counted, so `count` is above zero.
                self.count = self.count.saturating_sub(1);
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
        while self.count > MAX_LOAD.saturating_mul(self.buckets()) && self.buckets() < self.capacity
        {
            self.split_one(arena);
        }
    }

    /// Split bucket `split` into itself and bucket `level + split` by the
    /// next hash bit, then advance the split pointer.
    fn split_one<S: SlotStore>(&mut self, arena: &mut Arena<S>)
    {
        let old = self.split;
        let new = self.level.saturating_add(self.split);
        let mask = self.level.saturating_mul(2).saturating_sub(1);
        let mut keep = NODE_NULL;
        let mut moved = NODE_NULL;
        let mut cur = self.head(old);
        while cur != NODE_NULL
        {
            let slot = arena.get(cur);
            let Some(key) = key_of(&slot.node)
            else
            {
                break;
            };
            if hash(key) & mask == new
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
        // `split` is below `level`, so the increment stays within `level`.
        self.split = self.split.saturating_add(1);
        if self.split == self.level
        {
            self.level = self.level.saturating_mul(2);
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
            self.0[usize::try_from(i).unwrap()]
        }

        unsafe fn write(&mut self, i: u64, v: u64)
        {
            let i = usize::try_from(i).unwrap();
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
            caps: NODE_NULL,
            next_region_id: 1,
            budget: NODE_NULL,
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
    fn find_front_moves_the_found_slot_to_its_chain_head_and_keeps_the_rest()
    {
        // Three keys of one hash parity share a bucket while there are two.
        let (mut a, mut ix) = setup();
        let badges: Vec<u64> = (1u64..).filter(|&b| hash(b) & 1 == 0).take(3).collect();
        let slots: Vec<NodeIdx> = badges.iter().map(|&b| insert(&mut a, &mut ix, b)).collect();
        assert_eq!(ix.buckets(), 2);
        let bucket = ix.bucket_of(badges[0]);
        // The chain's last slot, whatever order the inserts and splits left.
        let mut last = ix.head(bucket);
        while a.get(last).next != NODE_NULL
        {
            last = a.get(last).next;
        }
        assert_ne!(ix.head(bucket), last);
        let key = badges[slots.iter().position(|&s| s == last).unwrap()];
        assert_eq!(ix.find_front(&mut a, key), Some(last));
        assert_eq!(ix.head(bucket), last);
        // A miss changes nothing.
        assert_eq!(ix.find_front(&mut a, 0xDEAD), None);
        assert_eq!(ix.head(bucket), last);
        for (&b, &s) in badges.iter().zip(&slots)
        {
            assert_eq!(ix.find(&a, b), Some(s));
        }
        let mut seen = 0;
        ix.for_each(&a, |_| seen += 1);
        assert_eq!(seen, 3);
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
    fn for_each_visits_every_record_once_across_bucket_splits()
    {
        let (mut a, mut ix) = setup();
        let n = BUCKETS_PER_PAGE * MAX_LOAD * 3;
        let mut slots: Vec<NodeIdx> = (1..=n).map(|b| insert(&mut a, &mut ix, b)).collect();
        assert!(ix.buckets() > BUCKETS_PER_PAGE);
        let gone = ix.remove(&mut a, 5).unwrap();
        slots.retain(|&s| s != gone);
        let mut seen = Vec::new();
        ix.for_each(&a, |idx| seen.push(idx));
        seen.sort_unstable();
        slots.sort_unstable();
        assert_eq!(seen, slots);
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
