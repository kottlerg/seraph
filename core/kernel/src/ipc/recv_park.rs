// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/recv_park.rs

//! The endpoint receive queue ([`RecvQueue`]) and the per-CPU parked-receiver
//! table ([`RecvParkTable`]) through which a call prefers a receiver parked on
//! the caller's CPU.
//!
//! A receiver that parks on an endpoint records itself in the table of the CPU
//! it parks on; a call from a CPU that queues no thread but its idle thread
//! takes the receiver that CPU's table records for the endpoint, and any other
//! call the longest-waiting receiver. The receiver order and the table's
//! protocol are specified in core/kernel/docs/ipc-internals.md § Wait Queues.
//!
//! ## Ordering
//!
//! Every slot word is an atomic accessed `Relaxed`. The table has no lock of
//! its own: each access that decides an outcome holds the lock of the endpoint
//! the slot names, which orders it. The owning CPU records and looks up under
//! the lock of the endpoint it parks on or calls, with interrupts off, so no
//! other access of its own interleaves with either. A remover on any CPU clears
//! a slot by a compare-and-swap of its receiver word from the removed receiver
//! to null, never a plain store, under the lock of the endpoint it removes the
//! receiver from. A slot naming that endpoint has no other writer meanwhile,
//! since its owner records into it only under the same lock.
//!
//! A slot the owner has since given to another endpoint, under that
//! endpoint's lock, is the one place accesses under different locks meet: the
//! swap races the owner's store of the new receiver, on that single word,
//! whose coherence settles the race. A swap that lands first clears the old
//! receiver and the store then names the new one; a swap that lands after the
//! store fails and changes nothing. Either way the slot names the new
//! receiver.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering::Relaxed};

use super::WaitQueue;
use crate::sched::thread::ThreadControlBlock;

/// Slots in each CPU's [`RecvParkTable`]: the endpoints a CPU keeps a parked
/// receiver for at once. A lookup compares at most this many words.
pub const RECV_PARK_SLOTS: usize = 4;

/// One slot of a [`RecvParkTable`]: a receive queue, the receiver last parked
/// on it from the owning CPU, and when that park was recorded.
struct RecvParkSlot
{
    /// The receive queue the slot names (its address, compared, never
    /// dereferenced), or null for a slot never used. Written only by the
    /// owning CPU.
    queue: AtomicPtr<RecvQueue>,
    /// The receiver, or null once it has left the queue or before any park.
    /// Non-null only while that receiver is on `queue`: every removal from a
    /// receive queue clears the slot that names the removed receiver
    /// ([`RecvQueue`]). Written by the owning CPU at a record, and cleared by
    /// any CPU's removal.
    receiver: AtomicPtr<ThreadControlBlock>,
    /// The owning CPU's stamp at the slot's last record; 0 for a slot never
    /// used. Written only by the owning CPU.
    stamp: AtomicU64,
}

impl RecvParkSlot
{
    const fn new() -> Self
    {
        Self {
            queue: AtomicPtr::new(core::ptr::null_mut()),
            receiver: AtomicPtr::new(core::ptr::null_mut()),
            stamp: AtomicU64::new(0),
        }
    }
}

/// One CPU's parked-receiver table: for up to [`RECV_PARK_SLOTS`] endpoints,
/// the receiver most recently parked on the endpoint from this CPU, while it is
/// still parked. Held in the CPU's `PerCpuData` and written by its own records
/// and by any CPU's removals (see the module's § Ordering).
pub struct RecvParkTable
{
    slots: [RecvParkSlot; RECV_PARK_SLOTS],
    /// The stamp of this CPU's last record. A `u64` counting records does not
    /// wrap in the system's life.
    last_stamp: AtomicU64,
}

impl RecvParkTable
{
    /// An empty table.
    pub const fn new() -> Self
    {
        Self {
            slots: [const { RecvParkSlot::new() }; RECV_PARK_SLOTS],
            last_stamp: AtomicU64::new(0),
        }
    }

    /// Record `receiver`, parking on `queue` from this table's CPU, and return
    /// the receiver word of the slot it took: the slot naming `queue` when one
    /// does (its earlier receiver, if still parked, stays queued and is no
    /// longer recorded), else a slot holding no receiver, else the slot
    /// recorded longest ago.
    ///
    /// The caller is this table's CPU and holds the lock of the endpoint that
    /// owns `queue`, with interrupts off.
    fn record(
        &self,
        queue: *const RecvQueue,
        receiver: *mut ThreadControlBlock,
    ) -> &AtomicPtr<ThreadControlBlock>
    {
        let slot = self.slot_for(queue);
        let stamp = self.last_stamp.load(Relaxed).wrapping_add(1);
        self.last_stamp.store(stamp, Relaxed);
        slot.queue.store(queue.cast_mut(), Relaxed);
        slot.stamp.store(stamp, Relaxed);
        slot.receiver.store(receiver, Relaxed);
        &slot.receiver
    }

    /// The slot a record for `queue` takes ([`Self::record`]).
    fn slot_for(&self, queue: *const RecvQueue) -> &RecvParkSlot
    {
        let named = self
            .slots
            .iter()
            .find(|slot| core::ptr::eq(slot.queue.load(Relaxed), queue));
        let free = || {
            self.slots
                .iter()
                .find(|slot| slot.receiver.load(Relaxed).is_null())
        };
        let [first, rest @ ..] = &self.slots;
        let oldest = || {
            rest.iter().fold(first, |oldest, slot| {
                if slot.stamp.load(Relaxed) < oldest.stamp.load(Relaxed)
                {
                    slot
                }
                else
                {
                    oldest
                }
            })
        };
        named.or_else(free).unwrap_or_else(oldest)
    }

    /// The receiver this table records for `queue`, or null. Compares only
    /// the slots' queue words, and loads a receiver word only on a match.
    ///
    /// The caller is this table's CPU and holds the lock of the endpoint that
    /// owns `queue`, with interrupts off.
    fn lookup(&self, queue: *const RecvQueue) -> *mut ThreadControlBlock
    {
        self.slots
            .iter()
            .find(|slot| core::ptr::eq(slot.queue.load(Relaxed), queue))
            .map_or(core::ptr::null_mut(), |slot| slot.receiver.load(Relaxed))
    }
}

/// An endpoint's receive queue: the receivers parked on it, longest-waiting
/// first, with each park recorded in the parking CPU's [`RecvParkTable`]. A
/// call takes the receiver its CPU's table records for this queue when it
/// passes that table, and otherwise the head ([`Self::take`]).
///
/// Every removal clears the removed receiver's slot, and only this type's
/// methods reach the inner queue, so no removal path leaves a slot naming a
/// receiver that has left the queue. That keeps a slot's receiver word, read
/// under this queue's endpoint lock, a thread still parked here.
///
/// Every method runs under the owning endpoint's `ep.lock`. The queue must
/// not move while a thread is on it: the TCBs' queue tags and the tables'
/// slots hold its address.
pub struct RecvQueue
{
    waiting: WaitQueue,
}

impl RecvQueue
{
    /// An empty queue.
    pub const fn new() -> Self
    {
        Self {
            waiting: WaitQueue::new(),
        }
    }

    /// Whether no receiver is parked.
    pub fn is_empty(&self) -> bool
    {
        self.waiting.is_empty()
    }

    /// The longest-waiting receiver, or null when empty.
    ///
    /// # Safety
    /// The endpoint's lock is held.
    pub unsafe fn head(&self) -> *mut ThreadControlBlock
    {
        // SAFETY: forwarded caller contract.
        unsafe { self.waiting.head() }
    }

    /// Append `tcb`, a receiver parking from the CPU that owns `table`, and
    /// record the park in `table`.
    ///
    /// # Safety
    /// `tcb` is a valid TCB on no wait queue; the endpoint's lock is held, by
    /// the CPU that owns `table`, with interrupts off.
    pub unsafe fn push(&mut self, tcb: *mut ThreadControlBlock, table: &RecvParkTable)
    {
        // SAFETY: forwarded caller contract.
        unsafe { self.waiting.push(tcb) };
        let word = table.record(core::ptr::from_ref(self), tcb);
        // SAFETY: tcb is valid (contract); its recv_park_slot is owned by the
        // held lock of the endpoint whose queue now links it.
        unsafe { (*tcb).recv_park_slot = core::ptr::from_ref(word) };
    }

    /// Remove and return the receiver a call takes: the one `local`, the
    /// calling CPU's table, records for this queue, or, when `local` is
    /// `None` or records none, the longest-waiting. Null when empty.
    ///
    /// # Safety
    /// The endpoint's lock is held; `local`, when `Some`, is the table of
    /// the CPU that holds it, with interrupts off.
    pub unsafe fn take(&mut self, local: Option<&RecvParkTable>) -> *mut ThreadControlBlock
    {
        let recorded = local.map_or(core::ptr::null_mut(), |table| {
            table.lookup(core::ptr::from_ref(self))
        });
        // A recorded receiver is on this queue (above), so its removal holds;
        // the head is taken if it ever did not.
        // SAFETY: a non-null slot receiver is a live TCB parked on this queue,
        // whose removal clears the slot; the lock is held (contract).
        if !recorded.is_null() && unsafe { self.remove(recorded) }
        {
            return recorded;
        }
        debug_assert!(
            recorded.is_null(),
            "RecvQueue::take: a recorded receiver was not on its queue"
        );
        // SAFETY: the lock is held (contract).
        let head = unsafe { self.waiting.pop() };
        if !head.is_null()
        {
            // SAFETY: head was just removed from this queue under the lock.
            unsafe { forget_park(head) };
        }
        head
    }

    /// Remove and return the longest-waiting receiver, or null when empty.
    ///
    /// # Safety
    /// The endpoint's lock is held.
    pub unsafe fn pop(&mut self) -> *mut ThreadControlBlock
    {
        // SAFETY: forwarded caller contract.
        unsafe { self.take(None) }
    }

    /// Remove `tcb` if it is on this queue; returns whether it was.
    ///
    /// # Safety
    /// `tcb` is a valid TCB; the endpoint's lock is held.
    pub unsafe fn remove(&mut self, tcb: *mut ThreadControlBlock) -> bool
    {
        // SAFETY: forwarded caller contract.
        if !unsafe { self.waiting.remove(tcb) }
        {
            return false;
        }
        // SAFETY: tcb was just removed from this queue under the lock.
        unsafe { forget_park(tcb) };
        true
    }
}

/// Clear the table slot that recorded `tcb`'s park, if it still names `tcb`,
/// and the TCB's pointer to it.
///
/// # Safety
/// `tcb` is a valid TCB just removed from a [`RecvQueue`], under the lock of
/// the endpoint that owns that queue.
unsafe fn forget_park(tcb: *mut ThreadControlBlock)
{
    // SAFETY: tcb is valid; recv_park_slot is owned by the held endpoint lock
    // (contract).
    let word = unsafe { core::mem::replace(&mut (*tcb).recv_park_slot, core::ptr::null()) };
    // SAFETY: a non-null word is a slot of a table that outlives every
    // receiver it records: a CPU's, in the per-CPU slab, which is never freed.
    if let Some(word) = unsafe { word.as_ref() }
    {
        // A failed swap leaves a slot a later park has taken.
        let _ = word.compare_exchange(tcb, core::ptr::null_mut(), Relaxed, Relaxed);
    }
}

#[cfg(test)]
mod tests
{
    use core::sync::atomic::Ordering::Relaxed;

    use super::{RecvParkTable, RecvQueue};
    use crate::sched::thread::ThreadControlBlock;

    /// The TCBs, receive queues and tables of one test, used only on the
    /// test's thread, so every operation runs as under the endpoint lock and
    /// on the table's CPU. Each TCB is a heap allocation, and the queues and
    /// tables are held in vectors that are never resized, so none moves; all
    /// are freed only when the fixture drops, after every queue is emptied.
    /// The methods name each by index.
    struct Fixture
    {
        tcbs: Vec<*mut ThreadControlBlock>,
        queues: Vec<RecvQueue>,
        tables: Vec<RecvParkTable>,
    }

    impl Fixture
    {
        fn new(tcbs: usize, queues: usize, tables: usize) -> Self
        {
            Self {
                tcbs: (0..tcbs)
                    .map(|_| {
                        // SAFETY: an all-zero TCB is a valid inert value for
                        // queue-link tests (no link, tag or slot pointer).
                        Box::into_raw(Box::new(unsafe {
                            core::mem::zeroed::<ThreadControlBlock>()
                        }))
                    })
                    .collect(),
                queues: (0..queues).map(|_| RecvQueue::new()).collect(),
                tables: (0..tables).map(|_| RecvParkTable::new()).collect(),
            }
        }

        /// Park TCB `t` on queue `q` from the CPU of table `cpu`.
        fn park(&mut self, q: usize, t: usize, cpu: usize)
        {
            let tcb = self.tcbs[t];
            // SAFETY: tcb is a live TCB of the fixture, on no queue (each test
            // parks a TCB once until it is removed).
            unsafe { self.queues[q].push(tcb, &self.tables[cpu]) };
        }

        /// Take from queue `q` for a call from the CPU of table `cpu`, or
        /// with no table; the index of the TCB taken.
        fn take(&mut self, q: usize, cpu: Option<usize>) -> Option<usize>
        {
            let table = cpu.map(|c| &self.tables[c]);
            // SAFETY: as under the endpoint lock (above).
            let tcb = unsafe { self.queues[q].take(table) };
            self.index_of(tcb)
        }

        fn pop(&mut self, q: usize) -> Option<usize>
        {
            // SAFETY: as under the endpoint lock (above).
            let tcb = unsafe { self.queues[q].pop() };
            self.index_of(tcb)
        }

        fn remove(&mut self, q: usize, t: usize) -> bool
        {
            let tcb = self.tcbs[t];
            // SAFETY: tcb is a live TCB of the fixture; as under the lock.
            unsafe { self.queues[q].remove(tcb) }
        }

        /// The TCB index table `cpu` records for queue `q`.
        fn recorded(&self, cpu: usize, q: usize) -> Option<usize>
        {
            let tcb = self.tables[cpu].lookup(core::ptr::from_ref(&self.queues[q]));
            self.index_of(tcb)
        }

        /// Whether TCB `t` points at no slot.
        fn slotless(&self, t: usize) -> bool
        {
            // SAFETY: a live TCB of the fixture, read on the test's thread.
            unsafe { (*self.tcbs[t]).recv_park_slot.is_null() }
        }

        fn index_of(&self, p: *mut ThreadControlBlock) -> Option<usize>
        {
            if p.is_null()
            {
                return None;
            }
            let i = self.tcbs.iter().position(|&t| core::ptr::eq(t, p));
            assert!(
                i.is_some(),
                "a queue returned a TCB the fixture does not own"
            );
            i
        }
    }

    impl Drop for Fixture
    {
        fn drop(&mut self)
        {
            for q in 0..self.queues.len()
            {
                while self.pop(q).is_some()
                {}
            }
            for &tcb in &self.tcbs
            {
                // SAFETY: each pointer came from Box::into_raw in new, and no
                // queue links it any more.
                drop(unsafe { Box::from_raw(tcb) });
            }
        }
    }

    #[test]
    fn a_call_takes_the_receiver_parked_on_its_cpu_and_keeps_the_others_in_order()
    {
        let mut f = Fixture::new(3, 1, 3);
        f.park(0, 0, 0);
        f.park(0, 1, 1);
        f.park(0, 2, 2);
        assert_eq!(f.take(0, Some(1)), Some(1));
        assert_eq!(f.pop(0), Some(0));
        assert_eq!(f.pop(0), Some(2));
        assert_eq!(f.pop(0), None);
    }

    #[test]
    fn a_call_with_no_receiver_recorded_on_its_cpu_takes_the_longest_waiting()
    {
        let mut f = Fixture::new(2, 1, 3);
        f.park(0, 0, 0);
        f.park(0, 1, 1);
        assert_eq!(f.take(0, Some(2)), Some(0));
        assert_eq!(f.take(0, None), Some(1));
    }

    #[test]
    fn the_latest_park_on_a_cpu_is_the_one_its_calls_take()
    {
        let mut f = Fixture::new(3, 1, 2);
        f.park(0, 0, 1);
        f.park(0, 1, 0);
        f.park(0, 2, 0);
        assert_eq!(f.take(0, Some(0)), Some(2));
        // The receiver it displaced from the slot is no longer recorded: the
        // next call from that CPU takes the longest-waiting.
        assert_eq!(f.take(0, Some(0)), Some(0));
        assert_eq!(f.take(0, Some(0)), Some(1));
    }

    #[test]
    fn removing_a_displaced_receiver_leaves_the_slot_that_replaced_it()
    {
        let mut f = Fixture::new(3, 1, 2);
        f.park(0, 0, 1);
        f.park(0, 1, 0);
        f.park(0, 2, 0);
        assert!(f.remove(0, 1));
        assert!(f.slotless(1));
        assert_eq!(f.recorded(0, 0), Some(2));
        assert_eq!(f.take(0, Some(0)), Some(2));
    }

    #[test]
    fn a_full_table_gives_the_slot_recorded_longest_ago_to_a_new_endpoint()
    {
        // Queue i has a head parked from CPU 1 (TCB i) and a receiver parked
        // from CPU 0 (TCB 5 + i), recorded in queue order.
        let mut f = Fixture::new(10, 5, 2);
        for q in 0..5
        {
            f.park(q, q, 1);
            f.park(q, 5 + q, 0);
        }
        assert_eq!(f.recorded(0, 0), None);
        assert_eq!(f.take(0, Some(0)), Some(0));
        for q in 1..5
        {
            assert_eq!(f.take(q, Some(0)), Some(5 + q));
        }
    }

    #[test]
    fn a_slot_whose_receiver_left_is_taken_before_the_oldest()
    {
        let mut f = Fixture::new(9, 5, 2);
        for q in 0..4
        {
            f.park(q, q, 1);
            f.park(q, 4 + q, 0);
        }
        // Queue 1's recorded receiver leaves, freeing its slot.
        assert!(f.remove(1, 5));
        f.park(4, 8, 0);
        assert_eq!(f.recorded(0, 4), Some(8));
        assert_eq!(f.recorded(0, 0), Some(4));
        assert_eq!(f.take(0, Some(0)), Some(4));
    }

    #[test]
    fn every_removal_clears_the_removed_receivers_slot()
    {
        // Each removal path: the head's pop, a removal from the middle, and a
        // call's take of a recorded receiver.
        let mut f = Fixture::new(3, 3, 3);
        f.park(0, 0, 0);
        assert_eq!(f.pop(0), Some(0));
        f.park(1, 1, 1);
        assert!(f.remove(1, 1));
        f.park(2, 2, 2);
        assert_eq!(f.take(2, Some(2)), Some(2));
        for t in 0..3
        {
            assert_eq!(f.recorded(t, t), None);
            assert!(f.slotless(t));
        }
    }

    #[test]
    fn a_clear_before_its_slot_is_recorded_again_leaves_the_new_record()
    {
        // CPU 0's table is full (queues 0 to 3, TCBs 0 to 3, TCB 0 oldest);
        // TCB 0 leaves queue 0, clearing its slot, before a park on queue 4,
        // another endpoint, records into that slot.
        let mut f = Fixture::new(6, 5, 2);
        f.park(4, 5, 1);
        for q in 0..4
        {
            f.park(q, q, 0);
        }
        assert!(f.remove(0, 0));
        assert!(f.slotless(0));
        f.park(4, 4, 0);
        assert_eq!(f.recorded(0, 4), Some(4));
        for q in 1..4
        {
            assert_eq!(f.recorded(0, q), Some(q));
        }
        // The head of queue 4 is TCB 5; the call from CPU 0 takes the record.
        assert_eq!(f.take(4, Some(0)), Some(4));
    }

    #[test]
    fn a_stale_clear_after_its_slot_is_recorded_again_changes_nothing()
    {
        // As above, but the park on queue 4 evicts TCB 0's slot while TCB 0
        // is still parked on queue 0, and TCB 0 leaves afterwards: its clear,
        // under queue 0's lock, finds the slot naming queue 4 and TCB 4.
        let mut f = Fixture::new(6, 5, 2);
        f.park(4, 5, 1);
        for q in 0..4
        {
            f.park(q, q, 0);
        }
        f.park(4, 4, 0);
        assert_eq!(f.recorded(0, 0), None);
        assert!(f.remove(0, 0));
        assert!(f.slotless(0));
        assert_eq!(f.recorded(0, 4), Some(4));
        assert_eq!(f.take(4, Some(0)), Some(4));
        assert_eq!(f.take(4, Some(0)), Some(5));
    }

    #[test]
    fn a_clear_between_a_records_queue_and_receiver_stores_leaves_the_new_record()
    {
        // The owner's record of TCB 4 on queue 4 into the slot of TCB 0
        // (queue 0) is interrupted, between its queue store and its receiver
        // store, by TCB 0's removal on another CPU under queue 0's lock: the
        // clear succeeds on the slot's old receiver, and the receiver store
        // that follows leaves the slot naming queue 4 and TCB 4.
        let mut f = Fixture::new(5, 5, 1);
        for q in 0..4
        {
            f.park(q, q, 0);
        }
        let queue4 = core::ptr::from_ref(&f.queues[4]);
        let slot_ptr = core::ptr::from_ref(f.tables[0].slot_for(queue4));
        // SAFETY: the slot lives in the heap buffer of the tables vector, which
        // is never resized and outlives this test's uses; the fixture's methods
        // touch only the queues and TCBs.
        let slot = unsafe { &*slot_ptr };
        assert_eq!(f.index_of(slot.receiver.load(Relaxed)), Some(0));
        slot.queue.store(queue4.cast_mut(), Relaxed);
        assert!(f.remove(0, 0));
        assert!(f.slotless(0));
        assert!(slot.receiver.load(Relaxed).is_null());
        let tcb = f.tcbs[4];
        // SAFETY: TCB 4 is a live TCB of the fixture on no queue; as under
        // queue 4's lock, on the table's CPU.
        unsafe { f.queues[4].waiting.push(tcb) };
        // SAFETY: as above; the field is owned by queue 4's lock.
        unsafe { (*tcb).recv_park_slot = core::ptr::from_ref(&slot.receiver) };
        slot.receiver.store(tcb, Relaxed);
        assert_eq!(f.recorded(0, 4), Some(4));
        assert_eq!(f.take(4, Some(0)), Some(4));
        assert!(f.slotless(4));
    }
}
