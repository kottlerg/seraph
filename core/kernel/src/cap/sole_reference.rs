// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/sole_reference.rs

//! Sole-reference observers: the table that finds the observer nodes bound to
//! an object by `SYS_CAP_BIND_SOLE_REFERENCE`, the claims that fire them, and
//! the drain that posts them.
//!
//! An object with a bound observer carries [`REF_OBSERVED`] in its count word.
//! A binding posts once: the first time the drain finds its object at one
//! reference after the bind, or at the object's death. The decrement that
//! leaves one reference only marks the object's bucket pending, from the
//! address alone, since it may have released the decrementer's last hold on
//! the object; the drain claims the object under the table lock. The decrement
//! that leaves none owns the object, and fires its observers under the lock
//! before the word is reused.
//!
//! The table lock is a leaf: nothing is acquired under it, and no reference is
//! released under it. It serialises every change to the flag and to the
//! chains, so the flag is set exactly while the object's group of nodes is on
//! its bucket's chain. That is what lets the drain dereference a chained
//! object: the decrement to 0 takes the group off the chain under the lock
//! before the object's memory can be reused.
//!
//! Design: [capability-internals.md](../../docs/capability-internals.md)
//! § Sole-Reference Observers.

use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::object::{KernelObjectHeader, REF_OBSERVED};
use crate::ipc::event_queue::ObserverNode;
use crate::sync::Spinlock;

/// Number of chains in the table, keyed by a hash of the object address.
pub const BUCKETS: usize = 256;

/// The most nodes one drain pass posts. A death can fire any number of
/// nodes, each funded by its binder's queue; the drain posts them a pass at a
/// time, so one pass bounds the work a syscall return or an idle-loop
/// iteration does for observers it did not bind.
pub const POST_BUDGET: usize = 64;

/// Number of 64-bit words in the pending-bucket mask.
const PENDING_WORDS: usize = BUCKETS / 64;

/// The summary bit that says the fired list is not empty; the bits below it
/// say which pending words have a bit set.
const SUMMARY_FIRED: u64 = 1 << PENDING_WORDS;

/// The chains and the fired list, owned by the table lock.
///
/// A bucket's chain links one primary node per observed object, through the
/// node's `death.next`; the primary names the object in `object`, and the
/// object's other nodes hang off it through `group`. The fired list links the
/// primaries of the groups the claims and deaths took off their chains, the
/// same way, until the drain has taken every node of them.
struct Chains
{
    heads: [*mut ObserverNode; BUCKETS],
    fired: *mut ObserverNode,
}

impl Chains
{
    /// The head of `bucket`'s chain, as a place.
    #[expect(
        clippy::indexing_slicing,
        reason = "every bucket comes from bucket_of, the top eight bits of a u64, so below \
                  BUCKETS (256)"
    )]
    fn heads_at_mut(&mut self, bucket: usize) -> &mut *mut ObserverNode
    {
        &mut self.heads[bucket]
    }
}

/// The word of `pending` holding `bucket`'s bit.
#[expect(
    clippy::indexing_slicing,
    reason = "every bucket comes from bucket_of, below BUCKETS, so its word is below PENDING_WORDS"
)]
fn pending_word(pending: &[AtomicU64; PENDING_WORDS], bucket: usize) -> &AtomicU64
{
    &pending[bucket / 64]
}

/// The sole-reference table: the chains, under a leaf lock, and the
/// pending-bucket mask that the decrements set without it.
pub struct SoleReferenceTable
{
    lock: Spinlock,
    chains: UnsafeCell<Chains>,
    /// One bit per bucket whose objects the drain checks for one reference.
    pending: [AtomicU64; PENDING_WORDS],
    /// One bit per word of `pending` with a bit set, and [`SUMMARY_FIRED`].
    /// The drain's fast path reads this word alone.
    summary: AtomicU64,
}

// SAFETY: `chains` is read and written only under `lock`; the other fields
// are atomics.
unsafe impl Sync for SoleReferenceTable {}

/// The kernel's sole-reference table.
pub static TABLE: SoleReferenceTable = SoleReferenceTable::new();

/// The bucket of the object at `addr`: the top eight bits of a multiplicative
/// hash, which spreads the slab-aligned header addresses over every bucket.
fn bucket_of(addr: usize) -> usize
{
    let hash = (addr as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    // The top eight bits: below BUCKETS (256).
    (hash >> 56) as usize
}

impl SoleReferenceTable
{
    /// An empty table.
    #[expect(
        clippy::large_stack_frames,
        reason = "the kernel's one table is a static, built at compile time; only the host tests \
                  build a table at run time, on the stack of an unoptimised build"
    )]
    pub const fn new() -> Self
    {
        Self {
            lock: Spinlock::new(),
            chains: UnsafeCell::new(Chains {
                heads: [null_mut(); BUCKETS],
                fired: null_mut(),
            }),
            pending: [const { AtomicU64::new(0) }; PENDING_WORDS],
            summary: AtomicU64::new(0),
        }
    }

    /// Mark the bucket of the object at `addr` pending, for the drain to check
    /// its objects for one reference. Reads nothing at `addr`: the decrement
    /// that calls this may have released the caller's last hold on it.
    pub fn mark_pending(&self, addr: usize)
    {
        let bucket = bucket_of(addr);
        // Release, and the summary after the bucket bit: a drain whose summary
        // swap reads this bit sees the bucket bit and, through it, the
        // decrement before it.
        pending_word(&self.pending, bucket).fetch_or(1 << (bucket % 64), Ordering::Release);
        self.summary.fetch_or(1 << (bucket / 64), Ordering::Release);
    }

    /// Bind `node` to `object`: link it into the object's group, or start the
    /// group on the object's chain, and set [`REF_OBSERVED`] in the object's
    /// count word.
    ///
    /// # Safety
    /// `node` is an observer node taken from its queue's pool, on no list,
    /// with its `death.eq` and `death.correlator` set, and lives until the
    /// drain hands it back. The caller holds a reference on `object` across
    /// the call and holds no lock.
    pub unsafe fn link(&self, node: *mut ObserverNode, object: &KernelObjectHeader)
    {
        let addr = core::ptr::from_ref(object);
        let bucket = bucket_of(addr.addr());
        // SAFETY: paired with the unlock_raw below.
        let saved = unsafe { self.lock.lock_raw() };
        // SAFETY: the held lock gives this thread the chains alone.
        let chains = unsafe { &mut *self.chains.get() };
        // The flag changes only under this lock, so it says whether the
        // object's group is on the chain.
        let primary = if object.ref_count.load(Ordering::Relaxed) & REF_OBSERVED == 0
        {
            null_mut()
        }
        else
        {
            // SAFETY: the held lock; every primary on a chain is a live node.
            unsafe { find_primary(*chains.heads_at_mut(bucket), addr) }
        };
        debug_assert!(
            object.ref_count.load(Ordering::Relaxed) & REF_OBSERVED == 0 || !primary.is_null(),
            "sole reference: an observed object has no group on its chain"
        );
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a field of node, which is on no list, or of primary, \
                      a chained node the held lock owns"
        )]
        // SAFETY: node is on no list (contract), so only this thread reaches
        // it; primary, when non-null, is on the chain the held lock owns.
        unsafe {
            (*node).object = addr;
            if primary.is_null()
            {
                (*node).group = null_mut();
                (*node).death.next = chains.heads_at_mut(bucket).cast();
                *chains.heads_at_mut(bucket) = node;
            }
            else
            {
                (*node).death.next = null_mut();
                (*node).group = (*primary).group;
                (*primary).group = node;
            }
        }
        // Relaxed: a decrement that reads the flag only marks a bucket or
        // takes this lock, which orders the rest.
        object.ref_count.fetch_or(REF_OBSERVED, Ordering::Relaxed);
        // SAFETY: paired with the lock_raw above.
        unsafe { self.lock.unlock_raw(saved) };
    }

    /// Fire the observers of `object`, whose last reference the caller just
    /// released, and clear its count word: take its group off its chain onto
    /// the fired list, for the drain to post.
    ///
    /// Called by [`KernelObjectHeader::dec_ref`] on the decrement from
    /// `REF_OBSERVED | 1`, whose caller owns the object; the word clears before
    /// the caller can reuse it for a dealloc cascade.
    pub fn fire_dying(&self, object: &KernelObjectHeader)
    {
        let addr = core::ptr::from_ref(object);
        let bucket = bucket_of(addr.addr());
        // SAFETY: paired with the unlock_raw below.
        let saved = unsafe { self.lock.lock_raw() };
        // SAFETY: the held lock gives this thread the chains alone.
        let chains = unsafe { &mut *self.chains.get() };
        let mut link: *mut *mut ObserverNode = chains.heads_at_mut(bucket);
        // SAFETY: link points at a chain head or a chained node's link, which
        // the held lock owns.
        while !unsafe { *link }.is_null()
        {
            // SAFETY: as above.
            let node = unsafe { *link };
            // SAFETY: node is a chained primary the held lock owns.
            if unsafe { (*node).object } == addr
            {
                #[expect(
                    clippy::multiple_unsafe_ops_per_block,
                    reason = "every access is to a chain link or a field of node, which the held \
                              lock owns"
                )]
                // SAFETY: as above; node leaves the chain for the fired list,
                // both owned by the held lock.
                unsafe {
                    *link = (*node).death.next.cast();
                    (*node).death.next = chains.fired.cast();
                }
                chains.fired = node;
                break;
            }
            // SAFETY: node is a chained primary the held lock owns.
            link = unsafe { &raw mut (*node).death.next }.cast::<*mut ObserverNode>();
        }
        debug_assert!(
            !chains.fired.is_null(),
            "sole reference: a dying observed object has no group on its chain"
        );
        self.summary.fetch_or(SUMMARY_FIRED, Ordering::Release);
        // The word read REF_OBSERVED (the decrement left 0 references); clear
        // the flag before the caller's cascade reuses the word as a link.
        object.ref_count.store(0, Ordering::Relaxed);
        // SAFETY: paired with the lock_raw above.
        unsafe { self.lock.unlock_raw(saved) };
    }

    /// Whether a drain has work: a bucket marked pending, or fired nodes a
    /// pass left.
    pub fn work_pending(&self) -> bool
    {
        self.summary.load(Ordering::Acquire) != 0
    }

    /// Claim every object of a pending bucket that holds one reference, and
    /// take at most `budget` nodes off the fired list: the nodes to post,
    /// linked through `group` (null when nothing fired). The caller owns
    /// every node it takes. Nodes that remain
    /// stay on the fired list, with [`SUMMARY_FIRED`] set, for the next drain
    /// on any CPU.
    ///
    /// Reads one word when nothing is pending.
    pub fn collect(&self, budget: usize) -> *mut ObserverNode
    {
        if self.summary.load(Ordering::Acquire) == 0
        {
            return null_mut();
        }
        let summary = self.summary.swap(0, Ordering::AcqRel);
        // SAFETY: paired with the unlock_raw below.
        let saved = unsafe { self.lock.lock_raw() };
        // SAFETY: the held lock gives this thread the chains alone.
        let chains = unsafe { &mut *self.chains.get() };
        for (word, pending) in self.pending.iter().enumerate()
        {
            if summary & (1 << word) == 0
            {
                continue;
            }
            let mut bits = pending.swap(0, Ordering::AcqRel);
            while bits != 0
            {
                let bucket = word
                    .wrapping_mul(64)
                    .wrapping_add(bits.trailing_zeros() as usize);
                bits &= bits.wrapping_sub(1);
                claim_bucket(chains, bucket);
            }
        }
        let mut taken: *mut ObserverNode = null_mut();
        let mut count = 0;
        while count < budget && !chains.fired.is_null()
        {
            let primary = chains.fired;
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to a field of primary or of its group's first member, \
                          both on the fired list the held lock owns"
            )]
            // SAFETY: primary heads the fired list and member, when non-null,
            // hangs off it; the held lock owns both. The node taken leaves the
            // list for the caller's, which only this thread reaches.
            unsafe {
                let member = (*primary).group;
                let node = if member.is_null()
                {
                    chains.fired = (*primary).death.next.cast();
                    primary
                }
                else
                {
                    (*primary).group = (*member).group;
                    member
                };
                (*node).group = taken;
                taken = node;
            }
            count = count.wrapping_add(1);
        }
        if !chains.fired.is_null()
        {
            self.summary.fetch_or(SUMMARY_FIRED, Ordering::Release);
        }
        // SAFETY: paired with the lock_raw above.
        unsafe { self.lock.unlock_raw(saved) };
        taken
    }
}

/// The primary node of the object at `addr` on the chain from `head`, or
/// null.
///
/// # Safety
/// The caller holds the table lock that owns the chain.
unsafe fn find_primary(
    head: *mut ObserverNode,
    addr: *const KernelObjectHeader,
) -> *mut ObserverNode
{
    let mut node = head;
    while !node.is_null()
    {
        // SAFETY: node is on the chain the caller's lock owns.
        if unsafe { (*node).object } == addr
        {
            return node;
        }
        // SAFETY: as above.
        node = unsafe { (*node).death.next }.cast();
    }
    null_mut()
}

/// Claim every object on `bucket`'s chain whose count word is
/// `REF_OBSERVED | 1`: clear the flag and move its group to the fired list.
///
/// A chained object is live: its group leaves the chain under the table lock,
/// held here, before its word or its memory can be reused
/// ([`SoleReferenceTable::fire_dying`]). A compare-and-swap that races an
/// increment either fails, and the object stays on the chain, or wins, and
/// the count was one.
fn claim_bucket(chains: &mut Chains, bucket: usize)
{
    let mut link: *mut *mut ObserverNode = chains.heads_at_mut(bucket);
    // SAFETY: link points at a chain head or a chained node's link, which the
    // caller's held lock owns.
    while !unsafe { *link }.is_null()
    {
        // SAFETY: as above.
        let node = unsafe { *link };
        // SAFETY: node is a chained primary the caller's lock owns.
        let object = unsafe { (*node).object };
        // SAFETY: a chained primary names a live object (see above).
        let claimed = unsafe { &*object }
            .ref_count
            .compare_exchange(REF_OBSERVED | 1, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok();
        if claimed
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to a chain link or a field of node, which the held lock \
                          owns"
            )]
            // SAFETY: node leaves the chain for the fired list, both owned by
            // the caller's held lock.
            unsafe {
                *link = (*node).death.next.cast();
                (*node).death.next = chains.fired.cast();
            }
            chains.fired = node;
        }
        else
        {
            // SAFETY: node is a chained primary the caller's lock owns.
            link = unsafe { &raw mut (*node).death.next }.cast::<*mut ObserverNode>();
        }
    }
}

/// Post at most [`POST_BUDGET`] of the sole-reference observers the table
/// has fired: each node back to its pool, then `(0, correlator)` to its
/// queue, then the queue's reference the binding held released.
///
/// Called by `drain_deferred_reclaim` after its reclaim, on the syscall
/// epilogue and in the idle loop, and by the idle loop again while
/// [`work_pending`] holds and its run queues are empty, with no lock held.
/// Reads one word when nothing is pending. The fired nodes a pass leaves stay
/// marked for the next drain on any CPU.
///
/// # Safety
/// No lock is held, and the context is one [`release_ref`] allows: syscall
/// context with interrupts disabled, or the idle thread.
///
/// [`release_ref`]: crate::cap::object::release_ref
#[cfg(not(test))]
pub unsafe fn drain()
{
    let mut node = TABLE.collect(POST_BUDGET);
    while !node.is_null()
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a field of node, which collect handed this thread"
        )]
        // SAFETY: collect handed this thread node; it lives in its queue,
        // which the binding's reference keeps live until the release below.
        let (next, eq, correlator) = unsafe {
            let fields = ((*node).group, (*node).death.eq, (*node).death.correlator);
            (*node).object = core::ptr::null();
            (*node).group = null_mut();
            (*node).death.next = null_mut();
            fields
        };
        // The node goes back to its pool before the post, so a binder that
        // receives the post and binds again finds it free; its fields are
        // read above and it is not touched again.
        // SAFETY: the binding's reference keeps eq live.
        let eq_state = unsafe { (*eq).state };
        // SAFETY: node came from this queue's pool and is on no list; the
        // binding's reference keeps eq live; no lock is held.
        unsafe {
            crate::ipc::event_queue::event_queue_return_observer(
                eq_state,
                node.cast::<crate::sched::thread::DeathObserver>(),
            );
        }
        // SAFETY: the binding's reference keeps eq live; no lock is held.
        unsafe { crate::sched::post_one_death_event(eq, correlator, 0) };
        if let Some(eq) = core::ptr::NonNull::new(eq.cast::<KernelObjectHeader>())
        {
            // SAFETY: the binding's reference, which this consumes; the
            // context is one release_ref allows (contract).
            unsafe { crate::cap::object::release_ref(eq) };
        }
        node = next;
    }
}

/// Whether a drain has work: a bucket marked pending, or fired nodes a pass
/// left. One load; the idle loop reads it to keep draining before it halts.
pub fn work_pending() -> bool
{
    TABLE.work_pending()
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cap::object::{ObjectType, REF_COUNT_LIMIT};
    use crate::sched::thread::DeathObserver;

    /// An object held by one capability slot (count 1, no flag).
    fn object() -> KernelObjectHeader
    {
        KernelObjectHeader::new(ObjectType::Notification)
    }

    /// Free observer nodes whose correlators are `first..first + n`.
    fn nodes(first: u64, n: u64) -> Vec<ObserverNode>
    {
        (first..first + n)
            .map(|correlator| ObserverNode {
                death: DeathObserver {
                    next: null_mut(),
                    eq: null_mut(),
                    correlator,
                },
                object: core::ptr::null(),
                group: null_mut(),
            })
            .collect()
    }

    /// The word of `obj`'s count.
    fn word(obj: &KernelObjectHeader) -> u32
    {
        obj.ref_count.load(Ordering::Relaxed)
    }

    /// Bind `node` to `obj` as the syscall does: pin, link, release the pin.
    fn bind(table: &SoleReferenceTable, node: &mut ObserverNode, obj: &KernelObjectHeader)
    {
        obj.inc_ref();
        // SAFETY: node is a free node the test owns, outliving the table's use
        // of it; the pin above holds obj; no lock is held.
        unsafe { table.link(node, obj) };
        obj.dec_ref_in(table);
    }

    /// The correlators of the nodes one collect of `budget` takes, sorted,
    /// and whether the table still has work for a drain.
    fn pass(table: &SoleReferenceTable, budget: usize) -> (Vec<u64>, bool)
    {
        let mut out = Vec::new();
        let mut node = table.collect(budget);
        while !node.is_null()
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "both reads are of fields of node, which collect handed the test"
            )]
            // SAFETY: collect handed the test every node of the list; each is
            // a node of a test vector still live.
            unsafe {
                out.push((*node).death.correlator);
                node = (*node).group;
            }
        }
        out.sort_unstable();
        (out, table.work_pending())
    }

    /// The correlators the drain would post now, over as many passes as it
    /// takes, sorted.
    fn posted(table: &SoleReferenceTable) -> Vec<u64>
    {
        let (mut out, mut more) = pass(table, POST_BUDGET);
        while more
        {
            let (next, again) = pass(table, POST_BUDGET);
            out.extend(next);
            more = again;
        }
        out.sort_unstable();
        out
    }

    // Defect guarded: a bind whose own pin release leaves the object at one
    // reference must post at once; a missed post leaves the lease unseen.
    #[test]
    fn bind_on_a_sole_holder_posts_at_the_next_drain()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        let mut n = nodes(7, 1);
        bind(&table, &mut n[0], &obj);
        assert_eq!(word(&obj), REF_OBSERVED | 1);
        assert_eq!(posted(&table), [7]);
        assert_eq!(word(&obj), 1, "the claim clears the flag");
        assert!(posted(&table).is_empty(), "the binding posts once");
    }

    // Defect guarded: the decrement that leaves one reference must post the
    // binding, once, and not before.
    #[test]
    fn release_of_the_other_copy_posts_once()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        obj.inc_ref();
        let mut n = nodes(1, 1);
        bind(&table, &mut n[0], &obj);
        assert_eq!(word(&obj), REF_OBSERVED | 2);
        assert!(posted(&table).is_empty(), "two references: no post");
        assert_eq!(obj.dec_ref_in(&table), 1);
        assert_eq!(posted(&table), [1]);
        assert_eq!(word(&obj), 1);
        assert_eq!(
            obj.dec_ref_in(&table),
            0,
            "an unflagged object dies as before"
        );
        assert_eq!(posted(&table), Vec::<u64>::new());
    }

    // Defect guarded: a count that falls to one and rises again before the
    // drain must neither post at two references nor lose the binding; it posts
    // at the next fall to one.
    #[test]
    fn count_that_rises_before_the_drain_posts_at_its_next_fall()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        obj.inc_ref();
        let mut n = nodes(3, 1);
        bind(&table, &mut n[0], &obj);
        obj.dec_ref_in(&table);
        obj.inc_ref();
        assert_eq!(posted(&table), Vec::<u64>::new());
        assert_eq!(
            word(&obj),
            REF_OBSERVED | 2,
            "the flag stays for the next fall"
        );
        obj.dec_ref_in(&table);
        assert_eq!(posted(&table), [3]);
    }

    // Defect guarded: a bind made while the count is back at two must not be
    // posted for a fall to one before it; both bindings post at the next fall.
    #[test]
    fn later_bind_posts_only_for_a_fall_after_it()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        obj.inc_ref();
        let mut n = nodes(1, 2);
        bind(&table, &mut n[0], &obj);
        obj.dec_ref_in(&table);
        obj.inc_ref();
        bind(&table, &mut n[1], &obj);
        assert_eq!(posted(&table), Vec::<u64>::new());
        obj.dec_ref_in(&table);
        assert_eq!(posted(&table), [1, 2]);
    }

    // Defect guarded: an object whose last two references go before the drain
    // must post its binding and clear its word before the cascade reuses it.
    #[test]
    fn death_before_the_drain_posts_once_and_clears_the_word()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        obj.inc_ref();
        let mut n = nodes(9, 2);
        bind(&table, &mut n[0], &obj);
        bind(&table, &mut n[1], &obj);
        assert_eq!(obj.dec_ref_in(&table), 1);
        assert_eq!(obj.dec_ref_in(&table), 0);
        assert_eq!(word(&obj), 0, "the cascade finds a clear word");
        assert_eq!(posted(&table), [9, 10]);
        assert_eq!(posted(&table), Vec::<u64>::new());
    }

    // Defect guarded: two bindings on one object must each post once.
    #[test]
    fn two_bindings_on_one_object_each_post_once()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        obj.inc_ref();
        let mut n = nodes(4, 2);
        bind(&table, &mut n[0], &obj);
        bind(&table, &mut n[1], &obj);
        obj.dec_ref_in(&table);
        assert_eq!(posted(&table), [4, 5]);
        obj.dec_ref_in(&table);
        assert_eq!(posted(&table), Vec::<u64>::new());
    }

    // Defect guarded: a claim must take only the object at one reference off
    // a shared chain, and leave the others for their own fall or death.
    #[test]
    fn claim_leaves_the_other_objects_of_its_bucket()
    {
        let table = SoleReferenceTable::new();
        let mut objs: Vec<Box<KernelObjectHeader>> = Vec::new();
        let (a, b) = loop
        {
            let next = Box::new(object());
            let bucket = bucket_of(core::ptr::from_ref(&*next).addr());
            if let Some(i) = objs
                .iter()
                .position(|o| bucket_of(core::ptr::from_ref(&**o).addr()) == bucket)
            {
                break (objs.swap_remove(i), next);
            }
            objs.push(next);
        };
        a.inc_ref();
        b.inc_ref();
        let mut n = nodes(1, 2);
        bind(&table, &mut n[0], &a);
        bind(&table, &mut n[1], &b);
        a.dec_ref_in(&table);
        assert_eq!(posted(&table), [1]);
        assert_eq!(word(&b), REF_OBSERVED | 2);
        b.dec_ref_in(&table);
        b.dec_ref_in(&table);
        assert_eq!(posted(&table), [2]);
    }

    // Defect guarded: an object with no binding must not reach the table, so
    // its decrements and increments cost what they did.
    #[test]
    fn unobserved_counts_never_touch_the_table()
    {
        let table = SoleReferenceTable::new();
        let obj = object();
        obj.inc_ref();
        obj.inc_ref();
        obj.dec_ref_in(&table);
        obj.dec_ref_in(&table);
        assert_eq!(obj.dec_ref_in(&table), 0);
        assert_eq!(table.summary.load(Ordering::Relaxed), 0);
        assert!(table.collect(POST_BUDGET).is_null());
    }

    // Defect guarded: one pass must post no more than its budget, however many
    // nodes a death fires, and must leave the rest marked for the next pass, so
    // no drain does unbounded work for observers it did not bind.
    #[test]
    fn a_pass_posts_at_most_its_budget_and_leaves_the_rest_marked()
    {
        let table = SoleReferenceTable::new();
        let a = object();
        let b = object();
        a.inc_ref();
        let mut n = nodes(1, 4);
        let (first, rest) = n.split_at_mut(3);
        for node in first
        {
            bind(&table, node, &a);
        }
        bind(&table, &mut rest[0], &b);
        assert_eq!(b.dec_ref_in(&table), 0);
        assert_eq!(a.dec_ref_in(&table), 1);
        assert_eq!(a.dec_ref_in(&table), 0);
        let (one, more) = pass(&table, 3);
        assert_eq!(one.len(), 3);
        assert!(more, "a fired node remains");
        assert_ne!(table.summary.load(Ordering::Relaxed) & SUMMARY_FIRED, 0);
        let (two, more) = pass(&table, 3);
        assert_eq!(two.len(), 1);
        assert!(!more);
        let mut all = [one, two].concat();
        all.sort_unstable();
        assert_eq!(all, [1, 2, 3, 4], "every node posts once");
        assert_eq!(table.summary.load(Ordering::Relaxed), 0);
    }

    // Defect guarded: the limit and the live tests must read the count without
    // the flag, and a refused increment must leave the flag in place.
    #[test]
    fn checked_increments_mask_the_flag()
    {
        let obj = object();
        obj.ref_count
            .store(REF_OBSERVED | (REF_COUNT_LIMIT - 1), Ordering::Relaxed);
        assert_eq!(obj.try_inc_ref(), Ok(()));
        assert_eq!(word(&obj), REF_OBSERVED | REF_COUNT_LIMIT);
        assert_eq!(obj.try_inc_ref(), Err(syscall::SyscallError::QuotaExceeded));
        assert_eq!(
            word(&obj),
            REF_OBSERVED | REF_COUNT_LIMIT,
            "the flag survives"
        );
        obj.ref_count.store(REF_OBSERVED, Ordering::Relaxed);
        assert!(
            !obj.inc_ref_if_live(),
            "a dying observed object is not live"
        );
        obj.ref_count.store(REF_OBSERVED | 1, Ordering::Relaxed);
        assert!(obj.inc_ref_if_live());
        assert_eq!(word(&obj), REF_OBSERVED | 2);
    }
}
