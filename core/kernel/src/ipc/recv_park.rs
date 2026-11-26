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
//! call the longest-waiting receiver. A CPU below [`RECV_PARK_HINT_CPUS`] finds
//! the endpoint's slot through the two bits the receive queue keeps for it; a
//! CPU above compares every slot. The receiver order and the table's protocol
//! are specified in core/kernel/docs/ipc-internals.md § Wait Queues.
//!
//! ## Ordering
//!
//! Every slot word is an atomic accessed `Relaxed`, but for the owning CPU's
//! plain reads of its queue words, which no other CPU reads or writes, so no
//! access runs beside such a read; a cross-CPU access of a queue word would
//! need `RecvParkTable::names` and `RecvParkTable::scan` back on atomic
//! loads. A receive queue's hints are plain bytes, read and written only under
//! the lock of the endpoint that owns the queue. The table has no lock of its
//! own: each access that decides an outcome holds the lock of the endpoint the
//! slot names, which orders it. The owning CPU records and looks up under the
//! lock of the endpoint it parks on or calls, with interrupts off, so no other
//! access of its own interleaves with either. A remover on any CPU clears a
//! slot by a compare-and-swap of its receiver word from the removed receiver to
//! null, never a plain store, under the lock of the endpoint it removes the
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
/// receiver for at once. A CPU without a hint compares this many words.
pub const RECV_PARK_SLOTS: usize = 4;

/// Bytes of slot hints in each [`RecvQueue`]: what is left of the endpoint's
/// 128-byte retype slot after its wrapper and the rest of its state, asserted
/// in `ipc::endpoint`. A hint is two bits, since a table has four slots.
pub const RECV_PARK_HINT_BYTES: usize = 56;

/// CPUs whose slot a [`RecvQueue`] keeps a hint for: CPU indices below this
/// find an endpoint's slot through its hint, and those above by comparing
/// every slot.
pub const RECV_PARK_HINT_CPUS: usize = RECV_PARK_HINT_BYTES * 4;

/// A receive queue's slot hints: CPU `c`'s is bits `2 * (c % 4)` and up of
/// byte `c / 4`.
type Hints = [u8; RECV_PARK_HINT_BYTES];

/// The [`RecvParkTable::hint_byte_end`] of a table with no hint, zero so that
/// an all-zero table, which the zero-filled per-CPU slab holds until
/// [`RecvParkTable::bind`] runs, is one.
const NO_HINT: usize = 0;

/// One slot of a [`RecvParkTable`]: a receive queue, the receiver last parked
/// on it from the owning CPU, and when that park was recorded.
struct RecvParkSlot
{
    /// The receive queue the slot names (its address, compared, never
    /// dereferenced), or null for a slot never used. Written and read only by
    /// the owning CPU.
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
    /// One past the index of the byte of a receive queue's hints that holds
    /// this CPU's hint, or [`NO_HINT`] for a CPU at or above
    /// [`RECV_PARK_HINT_CPUS`]. Written once, by [`Self::bind`] before the CPU
    /// runs, and read only by this CPU.
    hint_byte_end: usize,
    /// The shift of this CPU's two bits in that byte.
    hint_shift: u32,
}

impl RecvParkTable
{
    /// An empty table with no hint, until [`Self::bind`] names its CPU.
    pub const fn new() -> Self
    {
        Self {
            slots: [const { RecvParkSlot::new() }; RECV_PARK_SLOTS],
            last_stamp: AtomicU64::new(0),
            hint_byte_end: NO_HINT,
            hint_shift: 0,
        }
    }

    /// Bind the table to logical CPU `cpu`: a CPU below
    /// [`RECV_PARK_HINT_CPUS`] finds a queue's slot through its hint, and any
    /// other by comparing every slot. Runs once, at the CPU's per-CPU init,
    /// before any park or call on it.
    pub fn bind(&mut self, cpu: u32)
    {
        let cpu = cpu as usize;
        if cpu < RECV_PARK_HINT_CPUS
        {
            self.hint_byte_end = (cpu / 4).wrapping_add(1);
            #[expect(clippy::cast_possible_truncation, reason = "(cpu & 3) * 2 is below 8")]
            {
                self.hint_shift = (cpu & 3).wrapping_mul(2) as u32;
            }
        }
        else
        {
            self.hint_byte_end = NO_HINT;
            self.hint_shift = 0;
        }
    }

    /// The index of this CPU's byte of a receive queue's hints, past the last
    /// byte when the CPU has no hint.
    fn hint_byte(&self) -> usize
    {
        self.hint_byte_end.wrapping_sub(1)
    }

    /// Slot `index`, which is below [`RECV_PARK_SLOTS`]: a hint's two bits or
    /// a slot's position.
    fn slot(&self, index: usize) -> &RecvParkSlot
    {
        let [first, ..] = &self.slots;
        self.slots.get(index).unwrap_or(first)
    }

    /// Whether slot `index` names `queue`.
    ///
    /// The caller is this table's CPU, with interrupts off.
    fn names(&self, index: usize, queue: *const RecvQueue) -> bool
    {
        // SAFETY: only this table's CPU writes a queue word (`record`), and
        // the caller is that CPU with interrupts off, so no write runs beside
        // this read.
        let named = unsafe { self.slot(index).queue.as_ptr().read() };
        core::ptr::eq(named, queue)
    }

    /// The index of the slot naming `queue`, or `None` when none does.
    ///
    /// A CPU with a hint loads its two bits of `hints` and checks the slot
    /// they name, and no other: its records keep the hint on the slot that
    /// records a receiver for `queue` ([`RecvQueue`]), so a slot the hint
    /// does not name holds no receiver for `queue`, and a hint whose slot was
    /// given to another endpoint since fails the check, as a table with no
    /// slot for `queue` does. A CPU without one compares every slot
    /// ([`Self::scan`]). Either way the cost is the same whichever slot names
    /// `queue`, and hit and miss follow only what the table holds.
    ///
    /// The caller is this table's CPU and holds the lock of the endpoint that
    /// owns `queue` and `hints`, with interrupts off.
    fn find(&self, queue: *const RecvQueue, hints: &Hints) -> Option<usize>
    {
        match hints.get(self.hint_byte())
        {
            Some(&byte) =>
            {
                let index = usize::from((byte >> self.hint_shift) & 3);
                self.names(index, queue).then_some(index)
            }
            None => self.scan(queue),
        }
    }

    /// The index of the slot naming `queue`, or `None`, found by comparing
    /// every slot's queue word: the search of a CPU with no hint. At most one
    /// slot names a queue in such a table, since its records take the slot
    /// naming their queue when one does.
    ///
    /// Every slot is compared, whichever one names `queue`, so the search
    /// runs the same instructions whichever slot that is. The slot is set by
    /// the order of the CPU's earlier parks on other endpoints, which the
    /// machine's timing decides, and a search that stopped at the match would
    /// make the cost of every round trip through the endpoint depend on it.
    ///
    /// The caller is this table's CPU, with interrupts off.
    fn scan(&self, queue: *const RecvQueue) -> Option<usize>
    {
        // One more than the index of the slot naming `queue`, or 0: each
        // slot ORs in its own number masked by whether it matches, and at most
        // one matches. The compiler makes each step a select of the number or
        // zero, which both targets build without a branch (a conditional move
        // on x86_64, a negated set-if-equal and an AND on riscv64), so every
        // slot runs the same instructions. A select between two slots instead
        // becomes branches on riscv64, which has no conditional move, and its
        // instruction count then follows the slot that matched.
        let mut number: usize = 0;
        for (slot, index) in self.slots.iter().zip(1usize..)
        {
            // SAFETY: only this table's CPU writes a queue word (`record`),
            // and the caller is that CPU with interrupts off, so no write runs
            // beside this read. A plain read lets the compiler fold it into
            // the comparison, which an atomic load does not.
            let named = unsafe { slot.queue.as_ptr().read() };
            let matches = usize::from(core::ptr::eq(named, queue)).wrapping_neg();
            number |= index & matches;
        }
        // Whether some slot matched, never which, decides this one branch.
        number.checked_sub(1)
    }

    /// Record `receiver`, parking on `queue` from this table's CPU, and return
    /// the receiver word of the slot it took: the slot naming `queue` when one
    /// does ([`Self::find`]; its earlier receiver, if still parked, stays
    /// queued and is no longer recorded), else a slot holding no receiver, else
    /// the slot recorded longest ago, whose receiver stays queued unrecorded.
    /// A slot newly taken for `queue` gets this CPU's hint in `hints`.
    ///
    /// The caller is this table's CPU and holds the lock of the endpoint that
    /// owns `queue` and `hints`, with interrupts off.
    fn record(
        &self,
        queue: *const RecvQueue,
        hints: &mut Hints,
        receiver: *mut ThreadControlBlock,
    ) -> &AtomicPtr<ThreadControlBlock>
    {
        let found = self.find(queue, hints);
        let index = found.unwrap_or_else(|| self.free_or_oldest());
        if found.is_none()
            && let Some(byte) = hints.get_mut(self.hint_byte())
        {
            #[expect(clippy::cast_possible_truncation, reason = "a slot index is below 4")]
            let bits = (index as u8) << self.hint_shift;
            *byte = (*byte & !(3u8 << self.hint_shift)) | bits;
        }
        let slot = self.slot(index);
        let stamp = self.last_stamp.load(Relaxed).wrapping_add(1);
        self.last_stamp.store(stamp, Relaxed);
        slot.queue.store(queue.cast_mut(), Relaxed);
        slot.stamp.store(stamp, Relaxed);
        slot.receiver.store(receiver, Relaxed);
        &slot.receiver
    }

    /// The slot a record takes when none names its queue: the first holding
    /// no receiver, else the one recorded longest ago.
    fn free_or_oldest(&self) -> usize
    {
        self.slots
            .iter()
            .position(|slot| slot.receiver.load(Relaxed).is_null())
            .unwrap_or_else(|| {
                let stamps = self.slots.iter().map(|slot| slot.stamp.load(Relaxed));
                stamps
                    .enumerate()
                    .min_by_key(|&(_, stamp)| stamp)
                    .map_or(0, |(index, _)| index)
            })
    }

    /// The receiver this table records for `queue`, or null: the receiver
    /// word of the slot [`Self::find`] returns. Reads no TCB.
    ///
    /// The caller is this table's CPU and holds the lock of the endpoint that
    /// owns `queue` and `hints`, with interrupts off.
    fn lookup(&self, queue: *const RecvQueue, hints: &Hints) -> *mut ThreadControlBlock
    {
        self.find(queue, hints)
            .map_or(core::ptr::null_mut(), |index| {
                self.slot(index).receiver.load(Relaxed)
            })
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
/// `hints` keeps, for each CPU below [`RECV_PARK_HINT_CPUS`], the index of
/// the slot that CPU's table last took for this queue. A record that finds no
/// slot naming the queue writes the hint of the slot it takes, so a slot of
/// that CPU's table that names this queue and holds a receiver is always the
/// one the hint names; a slot naming the queue that the hint does not name
/// holds no receiver (one left behind by an endpoint freed at the same
/// address), and a hint whose slot was given to another endpoint fails the
/// check of its queue word. A zero hint is a slot index like any other, so a
/// new queue's hints need no state for none.
///
/// Every method runs under the owning endpoint's `ep.lock`. The queue must
/// not move while a thread is on it: the TCBs' queue tags and the tables'
/// slots hold its address. `repr(C)` keeps `hints` after `waiting`, where
/// `EndpointState`'s layout puts its first bytes in the endpoint's first
/// cache line (`ipc::endpoint`).
#[repr(C)]
pub struct RecvQueue
{
    waiting: WaitQueue,
    /// Per CPU below [`RECV_PARK_HINT_CPUS`], two bits: the slot that CPU's
    /// table last took for this queue.
    pub(super) hints: Hints,
}

impl RecvQueue
{
    /// An empty queue.
    pub const fn new() -> Self
    {
        Self {
            waiting: WaitQueue::new(),
            hints: [0; RECV_PARK_HINT_BYTES],
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
        let queue = core::ptr::from_ref(self);
        let word = table.record(queue, &mut self.hints, tcb);
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
            table.lookup(core::ptr::from_ref(self), &self.hints)
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

    use super::{RECV_PARK_HINT_CPUS, RecvParkTable, RecvQueue};
    use crate::sched::thread::ThreadControlBlock;

    /// The first CPU index of a fixture's tables, for each test that runs on
    /// both searches: every table hinted; CPUs 222 and 223 hinted beside a
    /// CPU 224 that scans (the boundary); every table scanning.
    const BASES: [u32; 3] = [0, 222, 224];

    /// The TCBs, receive queues and tables of one test, used only on the
    /// test's thread, so every operation runs as under the endpoint lock and
    /// on the table's CPU. Each TCB is a heap allocation, and the queues and
    /// tables are held in vectors that are never resized, so none moves; all
    /// are freed only when the fixture drops, after every queue is emptied.
    /// The methods name each by index; table `i` is bound to CPU `base + i`.
    struct Fixture
    {
        tcbs: Vec<*mut ThreadControlBlock>,
        queues: Vec<RecvQueue>,
        tables: Vec<RecvParkTable>,
    }

    impl Fixture
    {
        fn new(tcbs: usize, queues: usize, tables: u32, base: u32) -> Self
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
                tables: (0..tables)
                    .map(|i| {
                        let mut table = RecvParkTable::new();
                        table.bind(base + i);
                        table
                    })
                    .collect(),
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
            let queue = &self.queues[q];
            let tcb = self.tables[cpu].lookup(core::ptr::from_ref(queue), &queue.hints);
            self.index_of(tcb)
        }

        /// The index of the slot table `cpu` finds queue `q` in.
        fn named_slot(&self, cpu: usize, q: usize) -> Option<usize>
        {
            let queue = &self.queues[q];
            self.tables[cpu].find(core::ptr::from_ref(queue), &queue.hints)
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
        for base in BASES
        {
            let mut f = Fixture::new(3, 1, 3, base);
            f.park(0, 0, 0);
            f.park(0, 1, 1);
            f.park(0, 2, 2);
            assert_eq!(f.take(0, Some(1)), Some(1));
            assert_eq!(f.pop(0), Some(0));
            assert_eq!(f.pop(0), Some(2));
            assert_eq!(f.pop(0), None);
        }
    }

    #[test]
    fn a_call_with_no_receiver_recorded_on_its_cpu_takes_the_longest_waiting()
    {
        for base in BASES
        {
            let mut f = Fixture::new(2, 1, 3, base);
            f.park(0, 0, 0);
            f.park(0, 1, 1);
            assert_eq!(f.take(0, Some(2)), Some(0));
            assert_eq!(f.take(0, None), Some(1));
        }
    }

    #[test]
    fn the_latest_park_on_a_cpu_is_the_one_its_calls_take()
    {
        for base in BASES
        {
            let mut f = Fixture::new(3, 1, 2, base);
            f.park(0, 0, 1);
            f.park(0, 1, 0);
            f.park(0, 2, 0);
            assert_eq!(f.take(0, Some(0)), Some(2));
            // The receiver it displaced from the slot is no longer recorded:
            // the next call from that CPU takes the longest-waiting.
            assert_eq!(f.take(0, Some(0)), Some(0));
            assert_eq!(f.take(0, Some(0)), Some(1));
        }
    }

    #[test]
    fn removing_a_displaced_receiver_leaves_the_slot_that_replaced_it()
    {
        for base in BASES
        {
            let mut f = Fixture::new(3, 1, 2, base);
            f.park(0, 0, 1);
            f.park(0, 1, 0);
            f.park(0, 2, 0);
            assert!(f.remove(0, 1));
            assert!(f.slotless(1));
            assert_eq!(f.recorded(0, 0), Some(2));
            assert_eq!(f.take(0, Some(0)), Some(2));
        }
    }

    #[test]
    fn a_lookup_finds_its_endpoint_in_every_slot_and_no_other()
    {
        for base in BASES
        {
            // Table 0 names queues 0 to 3, in slots 0 to 3; queue 4 is parked
            // on from table 1's CPU only.
            let mut f = Fixture::new(5, 5, 2, base);
            for q in 0..4
            {
                f.park(q, q, 0);
            }
            f.park(4, 4, 1);
            for q in 0..4
            {
                assert_eq!(f.named_slot(0, q), Some(q));
                assert_eq!(f.recorded(0, q), Some(q));
            }
            assert_eq!(f.named_slot(0, 4), None);
            assert_eq!(f.recorded(0, 4), None);
            // A park on an endpoint the table names takes its slot again, here
            // after its receiver left, which keeps the slot's queue word.
            assert!(f.remove(2, 2));
            f.park(2, 2, 0);
            assert_eq!(f.named_slot(0, 2), Some(2));
            assert_eq!(f.recorded(0, 2), Some(2));
        }
    }

    #[test]
    fn a_full_table_gives_the_slot_recorded_longest_ago_to_a_new_endpoint()
    {
        for base in BASES
        {
            // Queue i has a head parked from table 1's CPU (TCB i) and a
            // receiver parked from table 0's (TCB 5 + i), recorded in queue
            // order.
            let mut f = Fixture::new(10, 5, 2, base);
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
    }

    #[test]
    fn a_slot_whose_receiver_left_is_taken_before_the_oldest()
    {
        for base in BASES
        {
            let mut f = Fixture::new(9, 5, 2, base);
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
    }

    #[test]
    fn every_removal_clears_the_removed_receivers_slot()
    {
        for base in BASES
        {
            // Each removal path: the head's pop, a removal from the middle,
            // and a call's take of a recorded receiver.
            let mut f = Fixture::new(3, 3, 3, base);
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
    }

    #[test]
    fn a_clear_before_its_slot_is_recorded_again_leaves_the_new_record()
    {
        for base in BASES
        {
            // Table 0 is full (queues 0 to 3, TCBs 0 to 3, TCB 0 oldest); TCB 0
            // leaves queue 0, clearing its slot, before a park on queue 4,
            // another endpoint, records into that slot.
            let mut f = Fixture::new(6, 5, 2, base);
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
            // The head of queue 4 is TCB 5; the call from table 0's CPU takes
            // the record.
            assert_eq!(f.take(4, Some(0)), Some(4));
        }
    }

    #[test]
    fn a_stale_clear_after_its_slot_is_recorded_again_changes_nothing()
    {
        for base in BASES
        {
            // As above, but the park on queue 4 evicts TCB 0's slot while TCB
            // 0 is still parked on queue 0, and TCB 0 leaves afterwards: its
            // clear, under queue 0's lock, finds the slot naming queue 4 and
            // TCB 4.
            let mut f = Fixture::new(6, 5, 2, base);
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
    }

    #[test]
    fn a_clear_between_a_records_queue_and_receiver_stores_leaves_the_new_record()
    {
        for base in BASES
        {
            // The owner's record of TCB 4 on queue 4 into the slot of TCB 0
            // (queue 0) is interrupted, between its queue store and its
            // receiver store, by TCB 0's removal on another CPU under queue
            // 0's lock: the clear succeeds on the slot's old receiver, and the
            // receiver store that follows leaves the slot naming queue 4 and
            // TCB 4.
            let mut f = Fixture::new(5, 5, 1, base);
            for q in 0..4
            {
                f.park(q, q, 0);
            }
            let queue4 = core::ptr::from_ref(&f.queues[4]);
            let table = &f.tables[0];
            assert_eq!(table.find(queue4, &f.queues[4].hints), None);
            let index = table.free_or_oldest();
            let slot_ptr = core::ptr::from_ref(table.slot(index));
            // SAFETY: the slot lives in the heap buffer of the tables vector,
            // which is never resized and outlives this test's uses; the
            // fixture's methods touch only the queues and TCBs.
            let slot = unsafe { &*slot_ptr };
            assert_eq!(f.index_of(slot.receiver.load(Relaxed)), Some(0));
            // Slot 0, which a CPU with a hint finds queue 4's zero hint
            // already naming, so the record would leave the hint as it is.
            assert_eq!(index, 0);
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

    #[test]
    fn a_stale_hint_finds_no_slot_and_the_next_park_repoints_it()
    {
        // CPU 223 is the last with a hint (byte 55, bits 6 and 7), CPU 0 the
        // first.
        for cpu in [0, 223]
        {
            // The table records queues 0 to 3 in slots 0 to 3; a park on
            // queue 4 takes slot 0, the oldest, while TCB 0 stays parked on
            // queue 0 unrecorded, so queue 0's hint names a slot that now
            // names queue 4.
            let mut f = Fixture::new(6, 5, 1, cpu);
            for q in 0..4
            {
                f.park(q, q, 0);
            }
            f.park(4, 4, 0);
            assert_eq!(f.named_slot(0, 4), Some(0));
            assert_eq!(f.named_slot(0, 0), None);
            assert_eq!(f.recorded(0, 0), None);
            // A new park on queue 0 misses its stale hint, takes the oldest
            // slot left, slot 1 (queue 1's), and points the hint at it.
            f.park(0, 5, 0);
            assert_eq!(f.named_slot(0, 0), Some(1));
            assert_eq!(f.recorded(0, 0), Some(5));
            assert_eq!(f.recorded(0, 1), None);
            assert_eq!(f.recorded(0, 4), Some(4));
            let byte = f.queues[0].hints[(cpu / 4) as usize];
            assert_eq!((byte >> ((cpu % 4) * 2)) & 3, 1);
            assert_eq!(f.take(0, Some(0)), Some(5));
            assert_eq!(f.take(0, Some(0)), Some(0));
        }
    }

    #[test]
    fn a_slot_left_naming_a_queues_address_beside_its_hint_is_harmless()
    {
        // A slot that names queue 2's address and holds no receiver, as one
        // left by an endpoint freed at that address, while the queue's hint
        // names another slot (a new queue's hints are zero): the next park
        // takes the first free slot, before the one left behind, and points
        // the hint at it, and calls find the receiver there.
        let mut f = Fixture::new(5, 4, 1, 0);
        f.park(0, 0, 0);
        f.park(1, 1, 0);
        f.park(3, 2, 0);
        f.park(2, 3, 0);
        assert_eq!(f.named_slot(0, 2), Some(3));
        assert!(f.remove(1, 1));
        assert!(f.remove(2, 3));
        f.queues[2].hints = [0; super::RECV_PARK_HINT_BYTES];
        assert_eq!(f.named_slot(0, 2), None);
        f.park(2, 4, 0);
        assert_eq!(f.named_slot(0, 2), Some(1));
        assert_eq!(f.recorded(0, 2), Some(4));
        assert_eq!(f.take(2, Some(0)), Some(4));
        // The next park on it takes the hinted slot again.
        f.park(2, 4, 0);
        assert_eq!(f.named_slot(0, 2), Some(1));
        assert_eq!(f.recorded(0, 0), Some(0));
        assert_eq!(f.recorded(0, 3), Some(2));
    }

    #[test]
    fn cpus_sharing_a_hint_byte_keep_their_own_hints()
    {
        // CPUs 220 to 223 share the queue's last hint byte; each records the
        // queue in a different slot of its own table (table c's slots 0 to
        // c - 1 hold other queues first).
        let mut f = Fixture::new(10, 4, 4, 220);
        for cpu in 0..4
        {
            for q in 0..cpu
            {
                f.park(q, 4 + cpu * (cpu - 1) / 2 + q, cpu);
            }
            f.park(3, cpu, cpu);
        }
        for cpu in 0..4
        {
            assert_eq!(f.named_slot(cpu, 3), Some(cpu));
            assert_eq!(f.recorded(cpu, 3), Some(cpu));
        }
        assert_eq!(f.take(3, Some(2)), Some(2));
        assert_eq!(f.take(3, Some(0)), Some(0));
    }

    #[test]
    fn a_cpu_at_or_above_the_hinted_range_scans_and_writes_no_hint()
    {
        assert_eq!(RECV_PARK_HINT_CPUS, 224);
        for cpu in [224, u32::MAX]
        {
            let mut f = Fixture::new(4, 4, 1, cpu);
            for q in 0..4
            {
                f.park(q, q, 0);
            }
            for q in 0..4
            {
                assert_eq!(f.named_slot(0, q), Some(q));
                assert_eq!(f.queues[q].hints, [0; super::RECV_PARK_HINT_BYTES]);
            }
            assert_eq!(f.take(3, Some(0)), Some(3));
        }
    }

    #[test]
    fn an_all_zero_table_scans_and_writes_no_hint_until_bound()
    {
        // The per-CPU slab is zero-filled before `bind` runs: an all-zero
        // table is `RecvParkTable::new()`, and keeps no hint.
        // SAFETY: every field of a table (atomics, a pointer, integers) is
        // valid at zero.
        let zeroed: RecvParkTable = unsafe { core::mem::zeroed() };
        let new = RecvParkTable::new();
        assert_eq!(zeroed.hint_byte_end, new.hint_byte_end);
        assert_eq!(zeroed.hint_shift, new.hint_shift);
        let mut f = Fixture::new(4, 4, 1, 0);
        f.tables[0] = zeroed;
        for q in 0..4
        {
            f.park(q, q, 0);
        }
        for q in 0..4
        {
            assert_eq!(f.named_slot(0, q), Some(q));
            assert_eq!(f.queues[q].hints, [0; super::RECV_PARK_HINT_BYTES]);
        }
        assert_eq!(f.take(2, Some(0)), Some(2));
    }
}
