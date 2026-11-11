// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/wait_set.rs

//! Wait set — multiplexed blocking on multiple IPC sources.
//!
//! A wait set aggregates up to its creator-chosen capacity of IPC sources
//! (endpoints, notifications, event queues). A caller blocks on the wait set and is woken when
//! any member becomes ready. The caller receives the opaque `badge` it chose
//! at `sys_wait_set_add` time, then reads from the source normally.
//!
//! # Readiness model
//! - **Endpoint**: has at least one pending sender.
//! - **Notification**: has non-zero bits.
//! - **`EventQueue`**: has at least one entry.
//!
//! # Ready ring
//! `ready_ring` is a circular buffer of member indices, at most one per
//! member. Every arrival of work on a member queues it there unless it is
//! already queued, whether or not the arrival also wakes a waiting thread;
//! `waitset_wait` pops from it, and queues a member it returns again behind
//! the others, so every ready member is queued and ready members are returned
//! in turn. An entry is a hint: one whose source is no longer ready when it
//! is popped is skipped and dropped. The states and invariants are those of
//! core/kernel/docs/ipc-internals.md § Wait Set Readiness Model, which the
//! host tests below check on generated sequences.
//!
//! # One wait set per source
//! A source can be in at most one wait set at a time. `sys_wait_set_add`
//! returns `InvalidArgument` if the source's `wait_set` pointer is non-null.
//! This is a design choice, not a capacity bound: each source carries one
//! `wait_set` pointer and member index, a fixed cost per source.
//!
//! # Lifetime — wait-set membership refcount
//! Each member holds a +1 reference on its source's `KernelObjectHeader`, per
//! core/kernel/docs/capability-internals.md § Kernel Object Reference Counting
//! and core/kernel/docs/ipc-internals.md § Wait Set Add/Remove. See
//! [`source_header`] for the member-to-header mapping.
//!
//! # Thread safety
//! Every operation serialises on the set's own `lock`; a notifying source's
//! lock is outer to it (see [`WaitSetState::lock`]).
//!
//! # Member capacity
//! The caller sizes the set at `SYS_CAP_CREATE_WAIT_SET` (`1..=
//! WAIT_SET_MAX_MEMBERS`) and pays for it: the member array and the ready
//! ring live inline after [`WaitSetState`] in the set's retype slot
//! (`cap::retype::wait_set_dispatch`), as an `EventQueue`'s ring does.

use crate::sched::thread::{IpcThreadState, ThreadControlBlock};

/// Largest member capacity a wait set can be created with; the ABI's
/// `WAIT_SET_MAX_MEMBERS`. The set is caller-funded, so the ceiling protects
/// no shared pool. It bounds the level-readiness walk `waitset_wait` makes
/// over every member under the set's lock, with interrupts off. A server with
/// more sources splits them across sets and waiting threads.
pub const WAIT_SET_MAX_MEMBERS: usize = syscall::WAIT_SET_MAX_MEMBERS as usize;

// A member index travels as a `u16` (`wait_set_member_idx` on every source,
// the ready ring's entries), and the ring holds `capacity + 1` of them.
const _: () = assert!(WAIT_SET_MAX_MEMBERS < u16::MAX as usize);

// ── Member tag ────────────────────────────────────────────────────────────────

/// Discriminant for the kind of source in a `WaitSetMember`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitSetSourceTag
{
    Endpoint = 0,
    Notification = 1,
    EventQueue = 2,
}

// ── Source wrapper layout ─────────────────────────────────────────────────────

/// Byte distance from the start of an Endpoint/Notification/EventQueue retype slot
/// (where the wrapper carrying `KernelObjectHeader` lives) to the embedded
/// state body. Equals `size_of::<EndpointObject>() == size_of::<NotificationObject>()
/// == size_of::<EventQueueObject>() == 24` — see
/// `cap::retype::EVENT_QUEUE_WRAPPER_BYTES` and the `dispatch_for` entries in
/// `core/kernel/src/cap/retype.rs`. The wrapper structs themselves are defined
/// in `core/kernel/src/cap/object.rs`.
const SOURCE_WRAPPER_BYTES: usize = 24;

// `source_header` subtracts SOURCE_WRAPPER_BYTES from a state pointer and then
// `dec_ref`s through the result, and each construction site places the state at
// `size_of::<Wrapper>()`; a wrapper that grew without this constant would land
// the subtraction inside the wrapper. Anchor the constant to all three wrappers.
const _: () = {
    assert!(SOURCE_WRAPPER_BYTES == core::mem::size_of::<crate::cap::object::EndpointObject>());
    assert!(SOURCE_WRAPPER_BYTES == core::mem::size_of::<crate::cap::object::NotificationObject>());
    assert!(SOURCE_WRAPPER_BYTES == core::mem::size_of::<crate::cap::object::EventQueueObject>());
};

/// Derive the `KernelObjectHeader` pointer from a registered source state
/// pointer.
///
/// Wait-set membership holds a +1 reference on this header (see
/// [`waitset_add`] / [`waitset_remove`] / [`wait_set_drop`]).
///
/// # Safety
/// `state_ptr` must be the state pointer registered by `waitset_add` and must
/// point into a retype-backed source slot (Endpoint/Notification/EventQueue). The
/// production paths in `sys_cap_create_*` always retype-back these objects,
/// and the dealloc arms in `cap::object::dealloc_object_one` assert
/// a non-null `ancestor`; there is no other construction path.
unsafe fn source_header(state_ptr: *mut u8) -> *mut crate::cap::object::KernelObjectHeader
{
    // SAFETY: state_ptr is the inner-body pointer; the wrapper (with header at
    // offset 0) precedes it by SOURCE_WRAPPER_BYTES inside the same retype slot.
    // cast_ptr_alignment: the retype slot is allocated to the alignment of its
    // wrapper (`EndpointObject` / `NotificationObject` / `EventQueueObject`), each of
    // which begins with a `KernelObjectHeader` (8-byte aligned); the state body
    // is 24 bytes past that start so subtracting 24 lands on the wrapper start.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        state_ptr
            .sub(SOURCE_WRAPPER_BYTES)
            .cast::<crate::cap::object::KernelObjectHeader>()
    }
}

// ── WaitSetMember ─────────────────────────────────────────────────────────────

/// A single registered source within a wait set.
///
/// `source_ptr.is_null()` marks the slot as vacant. Folding the vacancy
/// flag into the pointer keeps the struct at 24 B aligned and the
/// member array at `N * 24` rather than `N * 32` (the size an outer
/// `Option<WaitSetMember>` would need without a niche). This is what
/// keeps the per-member debit `wait_set_retype_bytes` charges at 24 B.
pub struct WaitSetMember
{
    /// Raw pointer to the source's state struct (`EndpointState` / `NotificationState` /
    /// `EventQueueState`). Null when the slot is vacant; otherwise used as a
    /// key for removal and for ready-at-add-time checks. Cast to the concrete
    /// type via `source_tag`.
    pub source_ptr: *mut u8,
    /// Kind of source, determines how `source_ptr` is interpreted.
    /// Meaningful only when `source_ptr` is non-null.
    pub source_tag: WaitSetSourceTag,
    /// Whether the ready ring holds an entry for this member. A member has at
    /// most one entry, so the ring, which holds `capacity` entries, never
    /// fills; see [`WaitSetState::push_ready`]. Sits in the padding after
    /// `source_tag`, so the member stays 24 B.
    pub queued: bool,
    /// Caller-chosen opaque badge returned by `sys_wait_set_wait`.
    pub badge: u64,
}

impl WaitSetMember
{
    /// Construct a vacant slot. Used by `WaitSetState::new` to initialise
    /// the member array without invoking `Default`.
    const fn vacant() -> Self
    {
        Self {
            source_ptr: core::ptr::null_mut(),
            source_tag: WaitSetSourceTag::Endpoint,
            queued: false,
            badge: 0,
        }
    }

    /// Whether this slot currently holds a registered source.
    #[inline]
    fn is_occupied(&self) -> bool
    {
        !self.source_ptr.is_null()
    }
}

// ── WaitSetState ─────────────────────────────────────────────────────────────

/// Kernel state backing a `WaitSet` capability.
///
/// The member array (`capacity` entries) and the ready ring (`capacity + 1`
/// `u16` member indices) live inline after this struct in the same retype
/// slot, which the cap-create path sizes from the caller's capacity and
/// constructs in place; nothing else is allocated. `lock` serialises every
/// field that changes after construction, and the inline arrays (the
/// bare-field exception of docs/coding-standards.md § Concurrency).
pub struct WaitSetState
{
    /// Per-`WaitSetState` spinlock. Serialises every mutation of the
    /// fields below — the members, `member_count`, the ready ring, `waiters`,
    /// and the read/write pointers. Acquired by `waitset_wait`, `waitset_notify`,
    /// `waitset_add`, `waitset_remove`, and `wait_set_drop`.
    ///
    /// Lock order: `<source>.lock` OUTER, `WaitSetState.lock` INNER, per
    /// core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 2;
    /// `wait_set_drop` clears source back-pointers before taking this lock.
    ///
    /// Source liveness during member dispatch is guaranteed by the
    /// membership refcount (see module docs); the lock-order discipline
    /// continues to govern back-pointer consistency and the side channels
    /// between `notification_send`/`event_queue_post`/`endpoint_call` and
    /// `waitset_notify`.
    pub lock: crate::sync::Spinlock,
    /// Inline member array of `capacity` slots. A slot with
    /// `source_ptr.is_null()` is vacant. Fixed at construction.
    members: *mut WaitSetMember,
    /// Inline circular buffer of `capacity + 1` pending member indices; one
    /// slot stays empty to tell full from empty, so it holds up to `capacity`
    /// entries. Each names a distinct occupied member (`WaitSetMember::queued`).
    /// An entry whose source is no longer ready is skipped during pop.
    /// Fixed at construction.
    ready_ring: *mut u16,
    /// Member capacity, chosen by the creator. Fixed at construction.
    capacity: u16,
    /// Number of occupied member slots.
    member_count: u16,
    /// Read pointer into the ready ring (next index to pop).
    ready_head: u16,
    /// Write pointer into the ready ring (next index to push).
    ready_tail: u16,
    /// The threads blocked in `sys_wait_set_wait`, in arrival order. Any
    /// number may wait; each readiness notification wakes the head. A
    /// [`WaitQueue`](crate::ipc::WaitQueue), so its claims share the
    /// notification and event-queue code.
    pub waiters: crate::ipc::WaitQueue,
}

// SAFETY: WaitSetState is internally synchronised by `WaitSetState.lock`; the
// inline arrays it points at belong to the same retype slot.
unsafe impl Send for WaitSetState {}
// SAFETY: WaitSetState is internally synchronised by `WaitSetState.lock`.
unsafe impl Sync for WaitSetState {}

// A WaitSetMember stays 24 B (3 × usize; the vacancy flag folds into the
// pointer), which the ABI's `wait_set_retype_bytes` charges per member, and
// the state is the size `cap::retype::WAIT_SET_STATE_BYTES` declares; both are
// pinned against the ABI formula in core/kernel/src/cap/retype.rs.
const _: () = {
    assert!(core::mem::size_of::<WaitSetMember>() == 24);
    assert!(
        core::mem::size_of::<WaitSetState>() as u64 == crate::cap::retype::WAIT_SET_STATE_BYTES
    );
};

impl WaitSetState
{
    /// Create a new, empty wait set of `capacity` members over the inline
    /// arrays at `members` and `ready_ring`, initialising both.
    ///
    /// # Safety
    /// `capacity` is in `1..=WAIT_SET_MAX_MEMBERS`. `members` must point to
    /// writable, 8-byte-aligned memory for `capacity` `WaitSetMember`s and
    /// `ready_ring` to writable memory for `capacity + 1` `u16`s, both inside
    /// the set's retype slot, unaliased, and outliving the state.
    pub unsafe fn new(capacity: u16, members: *mut WaitSetMember, ready_ring: *mut u16) -> Self
    {
        for i in 0..usize::from(capacity)
        {
            // SAFETY: i < capacity; the slot lies in the array (contract).
            unsafe { core::ptr::write(members.add(i), WaitSetMember::vacant()) };
        }
        // SAFETY: the ring has capacity + 1 u16 slots (contract).
        unsafe { core::ptr::write_bytes(ready_ring, 0, usize::from(capacity) + 1) };
        Self {
            lock: crate::sync::Spinlock::new(),
            members,
            ready_ring,
            capacity,
            member_count: 0,
            ready_head: 0,
            ready_tail: 0,
            waiters: crate::ipc::WaitQueue::new(),
        }
    }

    /// Member capacity the set was created with.
    pub fn capacity(&self) -> u16
    {
        self.capacity
    }

    /// The inline member array.
    fn members(&self) -> &[WaitSetMember]
    {
        // SAFETY: members points at `capacity` initialised slots that live as
        // long as the state (`new`'s contract); `&self` excludes a writer.
        unsafe { core::slice::from_raw_parts(self.members, usize::from(self.capacity)) }
    }

    /// The inline member array, mutably.
    fn members_mut(&mut self) -> &mut [WaitSetMember]
    {
        // SAFETY: as `members`; `&mut self` makes the borrow exclusive.
        unsafe { core::slice::from_raw_parts_mut(self.members, usize::from(self.capacity)) }
    }

    /// Ring length: `capacity + 1` slots.
    fn ring_len(&self) -> u16
    {
        self.capacity + 1
    }

    /// Return true if the ready ring has pending entries.
    #[inline]
    fn has_ready(&self) -> bool
    {
        self.ready_head != self.ready_tail
    }

    /// Queue `member_idx` on the ready ring, unless it already has an entry
    /// or its slot is vacant.
    ///
    /// A member holds at most one entry, so a member that stays busy cannot
    /// fill the ring past the other members' entries, and the ring, which
    /// holds `capacity` entries, never fills: the full check below cannot
    /// fire while every entry names a distinct occupied member, which
    /// [`Self::vacate_member`] keeps. A member a wait returns keeps its entry
    /// ([`Self::pop_ready`] queues it again), per
    /// core/kernel/docs/ipc-internals.md § Multiple Ready Sources.
    #[inline]
    fn push_ready(&mut self, member_idx: u16)
    {
        let m = &self.members()[usize::from(member_idx)];
        if m.queued || !m.is_occupied()
        {
            return;
        }
        let next = (self.ready_tail + 1) % self.ring_len();
        debug_assert!(next != self.ready_head, "wait set ready ring full");
        if next != self.ready_head
        {
            // SAFETY: ready_tail < ring_len; the ring has ring_len slots.
            unsafe { *self.ready_ring.add(usize::from(self.ready_tail)) = member_idx };
            self.ready_tail = next;
            self.members_mut()[usize::from(member_idx)].queued = true;
        }
    }

    /// Pop from the ready ring, skipping stale entries: those of a member whose
    /// source `ready` reports no longer ready (an endpoint whose queued sender
    /// was stopped or destroyed after its call pushed the entry, or a
    /// notification a direct waiter drained), and any that names a vacant
    /// slot. A skipped member's `queued` flag is cleared, so its next arrival
    /// queues it again.
    ///
    /// The member returned is queued again at the tail, behind every other
    /// queued member, so a member with work left after this return is served
    /// again in turn, after the others, and a member whose arrivals keep
    /// landing cannot hold the ring's head while another member's backlog
    /// waits. If the caller drains it, its entry is skipped at its next pop.
    ///
    /// Returns `Some(badge)` for the first entry whose member is present and
    /// ready, `None` if the ring is empty or every remaining entry is stale.
    fn pop_ready(&mut self, ready: impl Fn(&WaitSetMember) -> bool) -> Option<u64>
    {
        while self.has_ready()
        {
            // SAFETY: ready_head < ring_len; the ring has ring_len slots.
            let entry = unsafe { *self.ready_ring.add(usize::from(self.ready_head)) };
            self.ready_head = (self.ready_head + 1) % self.ring_len();
            let m = &mut self.members_mut()[usize::from(entry)];
            if m.is_occupied() && ready(m)
            {
                let badge = m.badge;
                // The pop above freed a slot, so the re-queue always fits; the
                // member keeps its one entry and its `queued` flag.
                // SAFETY: ready_tail < ring_len; the ring has ring_len slots.
                unsafe { *self.ready_ring.add(usize::from(self.ready_tail)) = entry };
                self.ready_tail = (self.ready_tail + 1) % self.ring_len();
                return Some(badge);
            }
            m.queued = false;
        }
        None
    }

    /// Vacate member `idx` and drop its ready-ring entry, if it has one, so a
    /// member added later at the same index starts with no entry and every
    /// entry names a distinct occupied member.
    fn vacate_member(&mut self, idx: usize)
    {
        if self.members()[idx].queued
        {
            let len = self.ring_len();
            let (mut read, mut write) = (self.ready_head, self.ready_head);
            while read != self.ready_tail
            {
                // SAFETY: read and write are < ring_len; the ring has ring_len
                // slots.
                unsafe {
                    let entry = *self.ready_ring.add(usize::from(read));
                    if usize::from(entry) != idx
                    {
                        *self.ready_ring.add(usize::from(write)) = entry;
                        write = (write + 1) % len;
                    }
                }
                read = (read + 1) % len;
            }
            self.ready_tail = write;
        }
        self.members_mut()[idx] = WaitSetMember::vacant();
    }

    // ── Readiness model ───────────────────────────────────────────────────
    //
    // The transitions of core/kernel/docs/ipc-internals.md § Wait Set
    // Readiness Model, as pure functions over the members and the ring, under
    // `lock`. The kernel entry points below add only the lock and the waiter
    // queue; the host tests drive these directly.

    /// Arrival of work on member `member_idx` (its source raised its level
    /// just before): queue the member unless it is already queued, and, if
    /// `threads_parked`, return the badge to wake the longest-waiting thread
    /// with.
    fn on_arrival(&mut self, member_idx: u16, threads_parked: bool) -> Option<u64>
    {
        self.push_ready(member_idx);
        let m = &self.members()[usize::from(member_idx)];
        threads_parked.then_some(if m.is_occupied() { m.badge } else { 0 })
    }

    /// Install `member` in the first vacant slot. If `ready` reports its
    /// source ready, queue it, and, if `threads_parked`, also return the badge
    /// to wake the longest-waiting thread with. Returns the slot index and that
    /// wake, or `None` when every slot is occupied.
    fn install(
        &mut self,
        member: &WaitSetMember,
        ready: impl Fn(&WaitSetMember) -> bool,
        threads_parked: bool,
    ) -> Option<(u16, Option<u64>)>
    {
        let idx = self.members().iter().position(|m| !m.is_occupied())?;
        self.members_mut()[idx] = WaitSetMember {
            source_ptr: member.source_ptr,
            source_tag: member.source_tag,
            queued: false,
            badge: member.badge,
        };
        self.member_count += 1;
        // cast_possible_truncation: idx < capacity, a u16.
        #[allow(clippy::cast_possible_truncation)]
        let idx = idx as u16;
        let m = &self.members()[usize::from(idx)];
        let (badge, is_ready) = (m.badge, ready(m));
        if !is_ready
        {
            return Some((idx, None));
        }
        self.push_ready(idx);
        Some((idx, threads_parked.then_some(badge)))
    }

    /// Remove the member at `idx` and its ring entry.
    fn remove_member(&mut self, idx: usize)
    {
        self.vacate_member(idx);
        self.member_count -= 1;
    }

    /// The badge a wait returns without parking, or `None` when no member is
    /// ready and the caller parks: the next ready entry of the ring
    /// ([`Self::pop_ready`]), else the first ready member the backstop walk
    /// finds, which it queues behind the others.
    fn next_ready(&mut self, ready: impl Fn(&WaitSetMember) -> bool) -> Option<u64>
    {
        if let Some(badge) = self.pop_ready(&ready)
        {
            return Some(badge);
        }
        let idx = (0..usize::from(self.capacity)).find(|&i| {
            let m = &self.members()[i];
            m.is_occupied() && ready(m)
        })?;
        // cast_possible_truncation: idx < capacity, a u16.
        #[allow(clippy::cast_possible_truncation)]
        self.push_ready(idx as u16);
        Some(self.members()[idx].badge)
    }
}

// ── Public operations ─────────────────────────────────────────────────────────

/// Notify the wait set that member `member_idx` is ready.
///
/// Called once per arrival of work on a registered source: from
/// `endpoint_call` for every call it queues, from `event_queue_post` for every
/// entry it rings, and from `notification_send` on every send that finds no
/// blocked waiter.
///
/// The member is queued on the ready ring unless it is already queued, and, if
/// threads are blocked in `waitset_wait`, the longest-waiting one is woken
/// with the member's badge and the others stay parked (transition 2 of
/// core/kernel/docs/ipc-internals.md § Wait Set Readiness Model).
///
/// # Safety
/// `ws_opaque` must be a valid `*mut WaitSetState` cast to `*mut u8`.
/// Acquires the wait set's internal `Spinlock` for the duration; the
/// source's lock is expected to already be held by the caller (see the
/// lock-ordering note on [`WaitSetState::lock`]).
#[cfg(not(test))]
pub unsafe fn waitset_notify(ws_opaque: *mut u8, member_idx: u16)
{
    // SAFETY: caller guarantees ws_opaque is a valid *mut WaitSetState.
    // cast_ptr_alignment: WaitSetState lives 24 B (the WaitSetObject wrapper)
    // past an 8-aligned retype slot base, so it is 8-aligned, which covers its
    // largest field alignment (`*mut ThreadControlBlock`, `u64`).
    #[allow(clippy::cast_ptr_alignment)]
    let ws = unsafe { &mut *ws_opaque.cast::<WaitSetState>() };

    // SAFETY: lock is owned by ws; matched unlock_raw at every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    let parked = !ws.waiters.is_empty();
    let Some(badge) = ws.on_arrival(member_idx, parked)
    else
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return;
    };

    // Snapshot under ws.lock, release, then enqueue_and_wake — see
    // core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5.
    // Claim the head waiter for wake before releasing ws.lock; dealloc's
    // BlockedOnWaitSet unlink takes ws.lock and spins on wake_in_flight
    // (#160), cleared by enqueue_and_wake.
    // SAFETY: ws.lock held; the popped waiter is a valid parked TCB.
    let (waiter, target_cpu) = unsafe {
        let waiter = ws.waiters.pop();
        crate::ipc::claim_waiter(waiter, badge);
        (waiter, crate::sched::select_target_cpu(waiter))
    };

    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };

    // SAFETY: waiter remains valid; enqueue_and_wake commits state under sched.lock.
    unsafe { crate::sched::enqueue_and_wake(waiter, target_cpu) };
}

/// Block `caller` until any member becomes ready, or return the next pending badge.
///
/// - If the ready ring holds a ready member, returns `Some(badge)` for it
///   without blocking, and queues it again behind the others.
/// - Else, if a registered member's source is level-ready, queues it and
///   returns `Some(badge)` for it without blocking
///   (core/kernel/docs/ipc-internals.md § Wait Path, Wait Set, step 3).
/// - Otherwise queues `caller` behind any threads already waiting, commits
///   the park (a refused commit dequeues it again), and returns `None`: the
///   caller went through the park commit and must reach `schedule()`, then
///   read `caller.wakeup_value`.
///
/// # Safety
/// `ws` must be a valid pointer. Acquires the wait set's internal
/// `Spinlock` for the duration; no caller-side locks are required.
#[cfg(not(test))]
pub unsafe fn waitset_wait(ws: *mut WaitSetState, caller: *mut ThreadControlBlock) -> Option<u64>
{
    // SAFETY: caller guarantees ws is valid for &mut access for the
    // duration of this call (the cap holding ws remains alive).
    let ws = unsafe { &mut *ws };

    // SAFETY: lock is owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    // An entry is a hint: the member's source is re-checked as it is popped,
    // so a readiness that lapsed since the push is skipped, and the backstop
    // walk follows an empty ring; see core/kernel/docs/ipc-internals.md
    // § Wait Path (Wait Set) steps 2 and 3.
    // SAFETY: an occupied member's source is pinned alive by the +1 reference
    // the member holds on its header (module docs); the reads are lock-free
    // atomic loads, with no source lock (which would invert the
    // source.lock -> ws.lock order).
    if let Some(badge) = ws.next_ready(|m| unsafe { source_is_ready(m.source_ptr, m.source_tag) })
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Some(badge);
    }

    // Nothing ready — block caller.
    //
    // Clear context_saved before making the thread visible as a waiter.
    // See core/kernel/docs/scheduling-internals.md § Atomic Ordering
    // Invariants (`context_saved`).
    // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: caller is a valid TCB on no queue; ws.lock held.
    unsafe { ws.waiters.push(caller) };
    let blocked_on = core::ptr::addr_of_mut!(*ws).cast::<u8>();
    // SAFETY: caller is a valid TCB; ws.lock held excludes other waiter writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            caller,
            IpcThreadState::BlockedOnWaitSet,
            blocked_on,
        )
    };
    if committed != crate::sched::ParkCommit::Committed
    {
        // Refused park; dequeue the caller again (ws.lock held since publish).
        // Stamping per core/kernel/docs/ipc-internals.md § Park Dispositions
        // and Episodes (refused-commit rollbacks).
        // SAFETY: caller was pushed above; ws.lock held throughout.
        unsafe { ws.waiters.remove(caller) };
        if committed == crate::sched::ParkCommit::RefusedStop
        {
            // SAFETY: caller is a valid TCB; episode owned per the above.
            unsafe {
                crate::sched::thread::stamp_park_deposit(
                    caller,
                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                );
            }
        }
        // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
        unsafe {
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };
    None
}

/// Register a source in the wait set.
///
/// Returns `Ok(member_idx)` on success, `Err(())` if the wait set is full.
///
/// Also checks whether the source is already ready at add time; if so, queues
/// it on `ready_ring` and wakes the longest-waiting thread, if any.
///
/// # Safety
/// `ws` and `source_ptr` (the source's state struct) must be valid. The caller
/// holds the source's lock, which is outer to the `ws.lock` taken here, and no
/// scheduler lock (a ready-at-add wake runs under the source lock). The caller
/// is responsible for setting the source's `wait_set` back-pointer.
#[cfg(not(test))]
pub unsafe fn waitset_add(
    ws: *mut WaitSetState,
    source_ptr: *mut u8,
    source_tag: WaitSetSourceTag,
    badge: u64,
) -> Result<u16, ()>
{
    // SAFETY: ws valid for &mut access for the duration; cap pins it.
    let ws = unsafe { &mut *ws };

    // SAFETY: lock owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    // Install, then check ready-at-add-time so notifications are not missed.
    let member = WaitSetMember {
        source_ptr,
        source_tag,
        queued: false,
        badge,
    };
    let parked = !ws.waiters.is_empty();
    // SAFETY: source_ptr is a valid pointer to the source's state struct; tag
    // determines concrete type.
    let installed = ws.install(
        &member,
        |m| unsafe { source_is_ready(m.source_ptr, m.source_tag) },
        parked,
    );
    let Some((idx, wake)) = installed
    else
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Err(());
    };
    // Snapshot the wake; enqueue_and_wake runs after unlock per
    // core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5.
    // SAFETY: ws.lock held; claim the head waiter for wake (#160).
    let deferred_wake = wake.map(|badge| unsafe {
        let waiter = ws.waiters.pop();
        crate::ipc::claim_waiter(waiter, badge);
        (waiter, crate::sched::select_target_cpu(waiter))
    });

    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };

    if let Some((waiter, target_cpu)) = deferred_wake
    {
        // SAFETY: waiter remains valid.
        unsafe { crate::sched::enqueue_and_wake(waiter, target_cpu) };
    }
    Ok(idx)
}

/// Remove a source from the wait set by its raw state pointer.
///
/// Clears the member slot and drops its `ready_ring` entry. Does NOT clear the
/// source's back-pointer —
/// the caller (syscall handler) must do that.
///
/// Returns `Ok(())` if found, `Err(())` if not present.
///
/// # Safety
/// `ws` must be valid. The caller holds the source's lock, which is outer to
/// the `ws.lock` taken here, and no scheduler lock.
#[cfg(not(test))]
pub unsafe fn waitset_remove(ws: *mut WaitSetState, source_ptr: *mut u8) -> Result<(), ()>
{
    // SAFETY: ws valid for &mut access for the duration; cap pins it.
    let ws = unsafe { &mut *ws };

    // SAFETY: lock owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    let Some(idx) = ws
        .members()
        .iter()
        .position(|m| m.is_occupied() && m.source_ptr == source_ptr)
    else
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Err(());
    };

    ws.remove_member(idx);
    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };
    Ok(())
}

/// Free all resources of `ws` and wake every blocked waiter.
///
/// Clears back-pointers on all registered sources so they stop notifying,
/// then `dec_ref`s the +1 cap-level reference that wait-set membership held
/// on each source, handing each source whose count reaches 0 (the member's
/// +1 was the last cap-level reference) to `on_zero`. Finally wakes every
/// blocked waiter with its park stamped `PARK_DISPOSITION_INTERRUPTED`.
///
/// The caller — the `WaitSet` arm of `cap::object::dealloc_object_one` —
/// reclaims each source `on_zero` receives. `on_zero` runs with no lock held,
/// once per zeroed source, in member order.
///
/// # Safety
/// `ws` must be a valid pointer. After this call `ws` itself is NOT freed —
/// the caller drops the outer `WaitSetObject` storage.
///
/// Lock discipline: clears each source's back-pointer FIRST under the
/// source's own lock — this is the inverse of the `notification_send →
/// waitset_notify` direction (`source.lock` → `ws.lock`), and walking the
/// members under `ws.lock` while taking source locks would invert that
/// order. By clearing back-pointers first we guarantee no future
/// `waitset_notify` call references this ws; we then take `ws.lock` only
/// to wake the blocked waiters. The `dec_ref` calls, and `on_zero`, happen
/// after `clear_source_backpointer` returns, so they hold no source IPC
/// lock.
#[cfg(not(test))]
pub unsafe fn wait_set_drop(
    ws: *mut WaitSetState,
    mut on_zero: impl FnMut(core::ptr::NonNull<crate::cap::object::KernelObjectHeader>),
)
{
    // SAFETY: ws valid for &mut access for the duration; the caller is
    // dealloc_object on a refcount==0 cap, no other syscall path can hold
    // ws_state at this point.
    let ws_ref = unsafe { &mut *ws };

    // Walk the occupied members without ws.lock: the back-pointer clears
    // below take each source's lock, and holding ws.lock across them would
    // invert the source.lock → ws.lock order. Once cleared, no concurrent
    // notification_send / event_queue_post / endpoint_call can reach
    // waitset_notify for this wait set; nothing else writes the members of a
    // set whose refcount is 0.
    for idx in 0..usize::from(ws_ref.capacity)
    {
        let slot = &ws_ref.members()[idx];
        if !slot.is_occupied()
        {
            continue;
        }
        let (source_ptr, source_tag) = (slot.source_ptr, slot.source_tag);
        // SAFETY: source_ptr is a valid pointer to the source's state
        // struct; clear_source_backpointer takes the source's own lock.
        unsafe { clear_source_backpointer(source_ptr, source_tag) };

        // Drop the +1 cap-level ref the membership held on its source. A
        // source whose refcount reaches 0 here goes to `on_zero` (the wait set
        // was its last referent).
        // SAFETY: source is retype-backed (production invariant — see
        // source_header docstring); header sits at `source_ptr - 24`.
        let header_ptr = unsafe { source_header(source_ptr) };
        // SAFETY: header_ptr points to the wrapper's KernelObjectHeader,
        // pinned alive by the +1 ref we are now releasing.
        if unsafe { (*header_ptr).dec_ref() } == 0
        {
            // SAFETY: header_ptr is non-null (computed from a non-null
            // state_ptr); refcount reached 0.
            on_zero(unsafe { core::ptr::NonNull::new_unchecked(header_ptr) });
        }
    }

    // Under ws.lock, claim and wake every blocked waiter with its park stamped
    // INTERRUPTED (the destroyed wait set cancels the wait;
    // `SYS_WAIT_SET_WAIT` returns Interrupted).
    // SAFETY: lock owned by ws; matched unlock_raw below.
    let saved = unsafe { ws_ref.lock.lock_raw() };
    // SAFETY: ws.lock held; no scheduler or sleep-list lock held.
    unsafe { crate::ipc::interrupt_all_waiters(&mut ws_ref.waiters) };
    for slot in ws_ref.members_mut()
    {
        *slot = WaitSetMember::vacant();
    }
    ws_ref.member_count = 0;
    // SAFETY: paired with lock_raw above.
    unsafe { ws_ref.lock.unlock_raw(saved) };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Check whether a source is already ready (has pending data).
///
/// # Safety
/// `source_ptr` must be a valid pointer to the appropriate state struct.
unsafe fn source_is_ready(source_ptr: *mut u8, tag: WaitSetSourceTag) -> bool
{
    use core::sync::atomic::Ordering;
    // cast_ptr_alignment: each source_ptr addresses a ConcreteType constructed
    // 24 B (the wrapper size) past a size-class-aligned retype slot base, so it
    // is 8-aligned, which covers align_of::<ConcreteType>(). The casts below
    // restore that type.
    #[allow(clippy::cast_ptr_alignment)]
    match tag
    {
        WaitSetSourceTag::Endpoint =>
        {
            let ep = source_ptr.cast::<crate::ipc::endpoint::EndpointState>();
            // Lockless Acquire-load of the `send_nonempty` shadow, per
            // core/kernel/docs/scheduling-internals.md § Atomic Ordering
            // Invariants. SAFETY: ep is a valid EndpointState.
            unsafe { (*ep).send_nonempty.load(Ordering::Acquire) != 0 }
        }
        WaitSetSourceTag::Notification =>
        {
            let sig = source_ptr.cast::<crate::ipc::notification::NotificationState>();
            // SAFETY: sig is a valid NotificationState.
            unsafe { (*sig).bits.load(Ordering::Acquire) != 0 }
        }
        WaitSetSourceTag::EventQueue =>
        {
            let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
            // Acquire-load pairs with the Release count mutations in
            // event_queue_post/recv so this lockless check never sees a stale
            // level (see the field doc on `EventQueueState::count`).
            // SAFETY: eq is a valid EventQueueState.
            unsafe { (*eq).count.load(Ordering::Acquire) > 0 }
        }
    }
}

/// Clear the back-pointer on a source so it stops notifying this wait set.
///
/// Acquires the source's own lock to serialise against any concurrent
/// `notification_send` / `event_queue_post` / `endpoint_call` that is reading
/// `source.wait_set` to dispatch a notification. Without this lock the
/// reader could see a non-null pointer, then release its read of the
/// pointer's target after we've torn down the wait set — UAF.
///
/// # Safety
/// `source_ptr` must be a valid pointer to the appropriate state struct.
unsafe fn clear_source_backpointer(source_ptr: *mut u8, tag: WaitSetSourceTag)
{
    // cast_ptr_alignment: each source_ptr addresses a ConcreteType constructed
    // 24 B (the wrapper size) past a size-class-aligned retype slot base, so it
    // is 8-aligned, which covers align_of::<ConcreteType>(). The casts below
    // restore that type.
    #[allow(clippy::cast_ptr_alignment)]
    match tag
    {
        WaitSetSourceTag::Endpoint =>
        {
            let ep = source_ptr.cast::<crate::ipc::endpoint::EndpointState>();
            // SAFETY: ep is valid; acquire its lock for the back-pointer write.
            unsafe {
                let saved = (*ep).lock.lock_raw();
                (*ep).wait_set = core::ptr::null_mut();
                (*ep).wait_set_member_idx = 0;
                (*ep).lock.unlock_raw(saved);
            }
        }
        WaitSetSourceTag::Notification =>
        {
            let sig = source_ptr.cast::<crate::ipc::notification::NotificationState>();
            // SAFETY: sig is valid; acquire its lock for the back-pointer write.
            unsafe {
                let saved = (*sig).lock.lock_raw();
                (*sig).wait_set = core::ptr::null_mut();
                (*sig).wait_set_member_idx = 0;
                // Keep has_observer set only while a waiter is still queued.
                (*sig).refresh_observer();
                (*sig).lock.unlock_raw(saved);
            }
        }
        WaitSetSourceTag::EventQueue =>
        {
            let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
            // SAFETY: eq is valid; acquire its lock for the back-pointer write.
            unsafe {
                let saved = (*eq).lock.lock_raw();
                (*eq).wait_set = core::ptr::null_mut();
                (*eq).wait_set_member_idx = 0;
                (*eq).lock.unlock_raw(saved);
            }
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A set of `CAP` members over local arrays, every member occupied with
    /// badge `100 + index`. The source pointers are never dereferenced by the
    /// ring operations under test.
    struct Fixture<const CAP: usize, const RING: usize>
    {
        members: [WaitSetMember; CAP],
        ring: [u16; RING],
    }

    impl<const CAP: usize, const RING: usize> Fixture<CAP, RING>
    {
        fn new() -> Self
        {
            // The ring holds capacity + 1 slots, as `WaitSetState::new` requires.
            const { assert!(RING == CAP + 1) };
            Self {
                members: [const { WaitSetMember::vacant() }; CAP],
                ring: [0; RING],
            }
        }

        fn set(&mut self) -> WaitSetState
        {
            // SAFETY: the arrays hold CAP members and CAP + 1 ring slots and
            // outlive the state within each test.
            let mut ws = unsafe {
                WaitSetState::new(
                    CAP as u16,
                    self.members.as_mut_ptr(),
                    self.ring.as_mut_ptr(),
                )
            };
            for (i, m) in ws.members_mut().iter_mut().enumerate()
            {
                *m = WaitSetMember {
                    source_ptr: core::ptr::NonNull::<u8>::dangling().as_ptr(),
                    source_tag: WaitSetSourceTag::Notification,
                    queued: false,
                    badge: 100 + i as u64,
                };
            }
            ws
        }
    }

    // Defect guarded: a ring that holds one entry fewer than its capacity, or
    // loses order across the wrap, drops or reorders ready members of a
    // caller-sized set.
    #[test]
    fn ring_holds_capacity_entries_and_pops_in_order_across_the_wrap()
    {
        let mut fx = Fixture::<3, 4>::new();
        let mut ws = fx.set();
        for idx in [0, 1, 2]
        {
            ws.push_ready(idx);
        }
        ws.push_ready(0);
        assert_eq!(ws.pop_ready(always_ready), Some(100));
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        assert_eq!(ws.pop_ready(always_ready), Some(102));
        drain(&mut ws);
        // The indices now wrap past the ring's end.
        ws.push_ready(2);
        ws.push_ready(0);
        ws.push_ready(1);
        assert_eq!(ws.pop_ready(always_ready), Some(102));
        assert_eq!(ws.pop_ready(always_ready), Some(100));
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        drain(&mut ws);
    }

    /// The readiness predicate of a set whose every source is ready.
    fn always_ready(_: &WaitSetMember) -> bool
    {
        true
    }

    /// Pop with every source drained, which skips and clears every entry, and
    /// require that nothing was returned and the ring is now empty.
    fn drain(ws: &mut WaitSetState)
    {
        assert_eq!(ws.pop_ready(|_| false), None);
        assert!(!ws.has_ready());
        assert!(ws.members().iter().all(|m| !m.queued));
    }

    // Defect guarded: a member that stays ready and keeps receiving work (an
    // endpoint with a stream of calls) filled the ring with its own entries, so
    // another member's arrival was dropped and that member was not returned
    // while the busy one stayed ready.
    #[test]
    fn a_busy_member_holds_one_entry_and_does_not_crowd_out_another()
    {
        let mut fx = Fixture::<2, 3>::new();
        let mut ws = fx.set();
        for _ in 0..3
        {
            ws.push_ready(0);
        }
        ws.push_ready(1);
        assert_eq!(ws.pop_ready(always_ready), Some(100));
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        drain(&mut ws);
        // A drained member queues again on its next arrival, behind the
        // members already queued.
        ws.push_ready(1);
        ws.push_ready(0);
        ws.push_ready(1);
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        assert_eq!(ws.pop_ready(always_ready), Some(100));
        drain(&mut ws);
    }

    // Defect guarded: a member returned by a wait lost its entry, so the rest
    // of its backlog was reachable only through the level walk, which runs
    // only when the ring holds no ready entry and favours the lowest index; a
    // lower-indexed member whose arrivals kept landing between the waits was
    // returned every time and the other member's backlog waited.
    #[test]
    fn a_returned_member_is_queued_again_behind_the_others()
    {
        let mut fx = Fixture::<2, 3>::new();
        let mut ws = fx.set();
        ws.push_ready(1);
        ws.push_ready(0);
        let mut returned = [0u64; 4];
        for badge in &mut returned
        {
            *badge = ws.pop_ready(always_ready).unwrap();
            ws.push_ready(0);
        }
        assert_eq!(returned, [101, 100, 101, 100]);
    }

    // Defect guarded: a removed member's entry left in the ring, followed by a
    // member added at the same index, gave that index two entries, so the ring
    // filled and another member's arrival was dropped.
    #[test]
    fn vacating_a_member_drops_its_entry()
    {
        let mut fx = Fixture::<3, 4>::new();
        let mut ws = fx.set();
        ws.push_ready(2);
        ws.push_ready(0);
        ws.push_ready(1);
        ws.vacate_member(0);
        assert!(!ws.members()[0].queued);
        ws.members_mut()[0] = WaitSetMember {
            source_ptr: core::ptr::NonNull::<u8>::dangling().as_ptr(),
            source_tag: WaitSetSourceTag::Notification,
            queued: false,
            badge: 200,
        };
        ws.push_ready(0);
        assert_eq!(ws.pop_ready(always_ready), Some(102));
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        assert_eq!(ws.pop_ready(always_ready), Some(200));
        drain(&mut ws);
        // A vacant slot takes no entry.
        ws.vacate_member(1);
        ws.push_ready(1);
        assert!(!ws.has_ready());
    }

    // Defect guarded: a pop that returned a removed member's badge would wake
    // the waiter for a source no longer in the set.
    #[test]
    fn pop_skips_entries_of_removed_members()
    {
        let mut fx = Fixture::<2, 3>::new();
        let mut ws = fx.set();
        ws.push_ready(0);
        ws.push_ready(1);
        ws.members_mut()[0] = WaitSetMember::vacant();
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        assert_eq!(ws.pop_ready(always_ready), Some(101));
        drain(&mut ws);
    }

    // Defect guarded: a pop that returned the badge of a member whose source
    // stopped being ready after its entry was pushed (an endpoint whose queued
    // sender was stopped) would send the waiter to a receive that blocks, past
    // a member that is ready.
    #[test]
    fn pop_skips_entries_whose_source_is_no_longer_ready()
    {
        let mut fx = Fixture::<3, 4>::new();
        let mut ws = fx.set();
        ws.push_ready(0);
        ws.push_ready(1);
        ws.push_ready(2);
        let ready = |m: &WaitSetMember| m.badge != 100;
        assert_eq!(ws.pop_ready(ready), Some(101));
        assert_eq!(ws.pop_ready(ready), Some(102));
        assert_eq!(ws.pop_ready(ready), Some(101));
        assert!(!ws.members()[0].queued);
        drain(&mut ws);
        ws.push_ready(0);
        assert_eq!(ws.pop_ready(|_| false), None);
        assert_eq!(ws.pop_ready(always_ready), None);
    }

    // Defect guarded: a set constructed with leftover member contents would
    // report phantom members before any add.
    #[test]
    fn a_new_set_has_every_member_vacant_and_nothing_ready()
    {
        let mut stale = [const { WaitSetMember::vacant() }; 4];
        for m in &mut stale
        {
            m.source_ptr = core::ptr::NonNull::<u8>::dangling().as_ptr();
        }
        let mut ring = [9u16; 5];
        // SAFETY: the arrays hold 4 members and 5 ring slots and outlive ws.
        let mut ws = unsafe { WaitSetState::new(4, stale.as_mut_ptr(), ring.as_mut_ptr()) };
        assert!(ws.members().iter().all(|m| !m.is_occupied()));
        assert_eq!(ws.pop_ready(always_ready), None);
        assert_eq!(ws.capacity(), 4);
    }

    // ── Readiness model on generated sequences ───────────────────────────────

    /// Largest member capacity the model runs with.
    const MODEL_CAP: usize = 6;
    /// Most threads the model runs with.
    const MODEL_THREADS: usize = 4;
    /// Steps per generated sequence.
    const MODEL_STEPS: usize = 400;
    /// Generated sequences.
    const MODEL_SEEDS: u64 = 400;

    /// xorshift64: a deterministic generator, so a failing seed replays.
    struct Rng(u64);

    impl Rng
    {
        fn below(&mut self, n: usize) -> usize
        {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            usize::try_from(self.0 % n as u64).unwrap()
        }
    }

    /// A thread of the modelled pool.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Thread
    {
        /// Running, about to wait on the set.
        Free,
        /// Handed member `idx` of source epoch `epoch`, by a wake or a
        /// wait's return; it next takes one unit of work from it, or
        /// abandons it.
        Holding
        {
            idx: usize, epoch: u32
        },
        /// Parked on the set.
        Parked,
    }

    /// The modelled world around one set: each slot's source and its units of
    /// work, the pool's threads, and the parked threads in FIFO order.
    struct World
    {
        cap: usize,
        work: [u32; MODEL_CAP],
        epoch: [u32; MODEL_CAP],
        threads: [Thread; MODEL_THREADS],
        nthreads: usize,
        parked: std::collections::VecDeque<usize>,
        /// Per member: successful waits since it was last returned, counted
        /// while it holds work.
        starve: [usize; MODEL_CAP],
    }

    /// Badge of slot `idx` in the model.
    fn model_badge(idx: usize) -> u64
    {
        100 + idx as u64
    }

    /// Slot of a model badge.
    fn model_slot(badge: u64) -> usize
    {
        usize::try_from(badge - 100).unwrap()
    }

    impl World
    {
        /// Hand the head parked thread the member `badge` names (a wake).
        fn wake(&mut self, badge: u64)
        {
            let t = self
                .parked
                .pop_front()
                .expect("a wake with no thread parked");
            assert_eq!(self.threads[t], Thread::Parked);
            let idx = model_slot(badge);
            self.threads[t] = Thread::Holding {
                idx,
                epoch: self.epoch[idx],
            };
        }

        fn arrive(&mut self, ws: &mut WaitSetState, idx: usize)
        {
            self.work[idx] += 1;
            let parked = !self.parked.is_empty();
            let wake = ws.on_arrival(u16::try_from(idx).unwrap(), parked);
            // I4: while threads are parked, every arrival wakes one.
            assert_eq!(wake.is_some(), parked);
            if let Some(badge) = wake
            {
                assert_eq!(badge, model_badge(idx));
                self.wake(badge);
            }
        }

        fn wait(&mut self, ws: &mut WaitSetState, t: usize)
        {
            let work = self.work;
            let returned = ws.next_ready(|m| work[model_slot(m.badge)] > 0);
            let Some(badge) = returned
            else
            {
                // I4: a thread parks only when no member holds work.
                assert!(self.work.iter().all(|&w| w == 0), "parked beside work");
                self.threads[t] = Thread::Parked;
                self.parked.push_back(t);
                return;
            };
            let idx = model_slot(badge);
            assert!(ws.members()[idx].is_occupied() && self.work[idx] > 0);
            self.threads[t] = Thread::Holding {
                idx,
                epoch: self.epoch[idx],
            };
            // I3: every other member with work waits fewer than `cap`
            // successful waits for its turn.
            for j in 0..self.cap
            {
                self.starve[j] = if j == idx || self.work[j] == 0
                {
                    0
                }
                else
                {
                    self.starve[j] + 1
                };
                assert!(self.starve[j] < self.cap, "member {j} passed over");
            }
        }

        fn add(&mut self, ws: &mut WaitSetState, work: u32)
        {
            let parked = !self.parked.is_empty();
            let Some(vacant) = ws.members().iter().position(|m| !m.is_occupied())
            else
            {
                return;
            };
            self.epoch[vacant] += 1;
            self.work[vacant] = work;
            self.starve[vacant] = 0;
            let member = WaitSetMember {
                source_ptr: core::ptr::NonNull::<u8>::dangling().as_ptr(),
                source_tag: WaitSetSourceTag::EventQueue,
                queued: false,
                badge: model_badge(vacant),
            };
            let (idx, wake) = ws.install(&member, |_| work > 0, parked).unwrap();
            assert_eq!(usize::from(idx), vacant);
            assert_eq!(wake.is_some(), parked && work > 0);
            if let Some(badge) = wake
            {
                self.wake(badge);
            }
        }

        fn remove(&mut self, ws: &mut WaitSetState, idx: usize)
        {
            ws.remove_member(idx);
            self.work[idx] = 0;
            self.starve[idx] = 0;
        }

        /// I1 and I2, after every step.
        fn check(&self, ws: &WaitSetState)
        {
            let mut in_ring = [0usize; MODEL_CAP];
            let mut at = ws.ready_head;
            while at != ws.ready_tail
            {
                // SAFETY: at < ring_len; the ring has ring_len slots.
                let idx = usize::from(unsafe { *ws.ready_ring.add(usize::from(at)) });
                in_ring[idx] += 1;
                at = (at + 1) % ws.ring_len();
            }
            let occupied = ws.members().iter().filter(|m| m.is_occupied()).count();
            assert_eq!(usize::from(ws.member_count), occupied);
            for (idx, m) in ws.members().iter().enumerate()
            {
                // I1: a queued member has exactly one entry, and only an
                // occupied member is queued.
                assert_eq!(in_ring[idx], usize::from(m.queued), "slot {idx} entries");
                assert!(!m.queued || m.is_occupied());
                // I2: a member with work is queued.
                assert!(
                    !m.is_occupied() || self.work[idx] == 0 || m.queued,
                    "slot {idx} holds work and is not queued"
                );
            }
            // I4: with the whole pool parked, no work waits: each arrival
            // since the last park woke a thread.
            if self.threads[..self.nthreads]
                .iter()
                .all(|&t| t == Thread::Parked)
            {
                assert!(
                    self.work.iter().all(|&w| w == 0),
                    "the pool parked beside work"
                );
            }
        }
    }

    /// Run one generated sequence of arrivals, waits, takes, abandoned
    /// handouts, removes, and adds against a set of a generated capacity and
    /// pool size.
    fn run_model(seed: u64)
    {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let cap = 1 + rng.below(MODEL_CAP);
        let mut members = [const { WaitSetMember::vacant() }; MODEL_CAP];
        let mut ring = [0u16; MODEL_CAP + 1];
        // SAFETY: the arrays hold MODEL_CAP >= cap members and cap + 1 ring
        // slots, and outlive ws.
        let mut ws = unsafe {
            WaitSetState::new(
                u16::try_from(cap).unwrap(),
                members.as_mut_ptr(),
                ring.as_mut_ptr(),
            )
        };
        let mut w = World {
            cap,
            work: [0; MODEL_CAP],
            epoch: [0; MODEL_CAP],
            threads: [Thread::Free; MODEL_THREADS],
            nthreads: 1 + rng.below(MODEL_THREADS),
            parked: std::collections::VecDeque::new(),
            starve: [0; MODEL_CAP],
        };
        for _ in 0..cap
        {
            w.add(&mut ws, 0);
        }
        for _ in 0..MODEL_STEPS
        {
            let t = rng.below(w.nthreads);
            let idx = rng.below(cap);
            match rng.below(10)
            {
                0..=2 if ws.members()[idx].is_occupied() && w.work[idx] < 8 =>
                {
                    w.arrive(&mut ws, idx);
                }
                3..=5 if w.threads[t] == Thread::Free => w.wait(&mut ws, t),
                6 | 7 =>
                {
                    // Take one unit of what the thread holds, if its source
                    // is still the member it was handed.
                    if let Thread::Holding { idx, epoch } = w.threads[t]
                    {
                        if epoch == w.epoch[idx] && w.work[idx] > 0
                        {
                            w.work[idx] -= 1;
                        }
                        w.threads[t] = Thread::Free;
                    }
                }
                8 if matches!(w.threads[t], Thread::Holding { .. }) =>
                {
                    // Abandon: the thread takes nothing from what it holds.
                    w.threads[t] = Thread::Free;
                }
                9 if ws.members()[idx].is_occupied() => w.remove(&mut ws, idx),
                9 =>
                {
                    let work = u32::try_from(rng.below(3)).unwrap();
                    w.add(&mut ws, work);
                }
                _ =>
                {}
            }
            w.check(&ws);
        }
    }

    // Defect guarded: an ordering or coverage gap in the ready ring (a member
    // with work and no entry, two entries for one member, a member passed over
    // for `capacity` or more turns while it holds work, a thread parked beside
    // work, or an arrival with threads parked that wakes none) over any
    // interleaving of arrivals, waits, takes, abandoned handouts, removes, and
    // adds, per core/kernel/docs/ipc-internals.md § Wait Set Readiness Model.
    #[test]
    fn generated_sequences_keep_the_readiness_invariants()
    {
        for seed in 1..=MODEL_SEEDS
        {
            run_model(seed);
        }
    }
}
