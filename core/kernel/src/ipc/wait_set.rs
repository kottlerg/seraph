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
//! `ready_ring` is a circular buffer of member indices. Notifications push to
//! it; `waitset_wait` pops from it. Stale entries (for removed members) are
//! silently skipped on pop.
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
    /// entries. Stale entries (after removal) are silently skipped during pop.
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
    /// The thread blocked on `sys_wait_set_wait`, if any. At most one: a wait
    /// while another thread waits is refused (`WaitSetPending::Occupied`).
    /// Held as a [`WaitQueue`](crate::ipc::WaitQueue) so its claims share the
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

    /// Push `member_idx` onto the ready ring.
    ///
    /// A push to a full ring (`capacity` pending entries) is dropped; the lost
    /// edge is recovered by `waitset_wait`'s level-readiness walk, per
    /// core/kernel/docs/ipc-internals.md § Multiple Ready Sources.
    #[inline]
    fn push_ready(&mut self, member_idx: u16)
    {
        let next = (self.ready_tail + 1) % self.ring_len();
        if next != self.ready_head
        {
            // SAFETY: ready_tail < ring_len; the ring has ring_len slots.
            unsafe { *self.ready_ring.add(usize::from(self.ready_tail)) = member_idx };
            self.ready_tail = next;
        }
    }

    /// Pop from the ready ring, skipping stale (removed) entries.
    ///
    /// Returns `Some(badge)` for the first live member found, `None` if empty
    /// or all remaining entries are stale.
    fn pop_ready(&mut self) -> Option<u64>
    {
        while self.has_ready()
        {
            // SAFETY: ready_head < ring_len; the ring has ring_len slots.
            let idx = usize::from(unsafe { *self.ready_ring.add(usize::from(self.ready_head)) });
            self.ready_head = (self.ready_head + 1) % self.ring_len();
            let m = &self.members()[idx];
            if m.is_occupied()
            {
                return Some(m.badge);
            }
            // Entry is stale (member was removed) — skip.
        }
        None
    }
}

// ── Public operations ─────────────────────────────────────────────────────────

/// Notify the wait set that member `member_idx` is ready.
///
/// Called from `endpoint_call` and `event_queue_post` on their empty→non-empty
/// transitions, and from `notification_send` on every send that finds no
/// blocked waiter while a wait set is registered.
///
/// If a thread is blocked in `waitset_wait`, it is woken immediately.
/// Otherwise the member index is pushed to the ready ring for the next caller.
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

    if ws.waiters.is_empty()
    {
        ws.push_ready(member_idx);
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return;
    }

    // Snapshot under ws.lock, release, then enqueue_and_wake — see
    // core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5.
    let badge = {
        let m = &ws.members()[usize::from(member_idx)];
        if m.is_occupied() { m.badge } else { 0 }
    };
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

/// Why [`waitset_wait`] returned without a badge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitSetPending
{
    /// The caller went through the park commit (committed, or refused and
    /// rolled back); it must reach `schedule()` and then read its deposit.
    Parked,
    /// Another thread already waits on the set; the caller did not park and
    /// the syscall returns `InvalidState`.
    Occupied,
}

/// Block `caller` until any member becomes ready, or return the next pending badge.
///
/// - If another thread already waits on the set, returns
///   `Err(WaitSetPending::Occupied)` without parking: a wait set takes one
///   waiter (any number of member sources).
/// - If the ready ring is non-empty, pops and returns `Ok(badge)` without blocking.
/// - Else, if a registered member's source is level-ready, returns
///   `Ok(badge)` for it without blocking (core/kernel/docs/ipc-internals.md
///   § Wait Path, Wait Set, step 3).
/// - Otherwise makes `caller` the waiter, commits the park (a refused commit
///   rolls the waiter back), and returns `Err(WaitSetPending::Parked)`.
///   The syscall handler calls `schedule()`, then reads `caller.wakeup_value`.
///
/// # Safety
/// `ws` must be a valid pointer. Acquires the wait set's internal
/// `Spinlock` for the duration; no caller-side locks are required.
#[cfg(not(test))]
pub unsafe fn waitset_wait(
    ws: *mut WaitSetState,
    caller: *mut ThreadControlBlock,
) -> Result<u64, WaitSetPending>
{
    // SAFETY: caller guarantees ws is valid for &mut access for the
    // duration of this call (the cap holding ws remains alive).
    let ws = unsafe { &mut *ws };

    // SAFETY: lock is owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    if !ws.waiters.is_empty()
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Err(WaitSetPending::Occupied);
    }

    if let Some(badge) = ws.pop_ready()
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Ok(badge);
    }

    // Level-state self-heal: return the first member whose source is
    // level-ready now; see core/kernel/docs/ipc-internals.md § Wait Path
    // (Wait Set) step 3.
    for idx in 0..usize::from(ws.capacity)
    {
        let m = &ws.members()[idx];
        if !m.is_occupied()
        {
            continue;
        }
        let (source_ptr, source_tag, badge) = (m.source_ptr, m.source_tag, m.badge);
        // SAFETY: source_ptr is pinned alive by the +1 cap-level ref this
        // member holds on its source's `KernelObjectHeader` (see module
        // docs). Reads use atomic loads where appropriate; no source-side
        // lock required.
        if unsafe { source_is_ready(source_ptr, source_tag) }
        {
            // SAFETY: paired with lock_raw above.
            unsafe { ws.lock.unlock_raw(saved) };
            return Ok(badge);
        }
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
    Err(WaitSetPending::Parked)
}

/// Register a source in the wait set.
///
/// Returns `Ok(member_idx)` on success, `Err(())` if the wait set is full.
///
/// Also checks whether the source is already ready at add time; if so,
/// pushes to `ready_ring` immediately.
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

    // Find a free slot.
    let Some(idx) = ws.members().iter().position(|m| !m.is_occupied())
    else
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Err(());
    };
    ws.members_mut()[idx] = WaitSetMember {
        source_ptr,
        source_tag,
        badge,
    };
    ws.member_count += 1;

    // Check ready-at-add-time so notifications are not missed.
    // SAFETY: source_ptr is a valid pointer to the source's state struct; tag determines concrete type.
    let already_ready = unsafe { source_is_ready(source_ptr, source_tag) };
    let mut deferred_wake: Option<(*mut ThreadControlBlock, usize)> = None;
    if already_ready
    {
        // cast_possible_truncation: idx < capacity, a u16.
        #[allow(clippy::cast_possible_truncation)]
        ws.push_ready(idx as u16);
        // Snapshot the wake; enqueue_and_wake runs after unlock per
        // core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5.
        if !ws.waiters.is_empty()
        {
            // SAFETY: ws.lock held; claim the head waiter for wake (#160).
            deferred_wake = Some(unsafe {
                let waiter = ws.waiters.pop();
                crate::ipc::claim_waiter(waiter, badge);
                (waiter, crate::sched::select_target_cpu(waiter))
            });
        }
    }

    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };

    if let Some((waiter, target_cpu)) = deferred_wake
    {
        // SAFETY: waiter remains valid.
        unsafe { crate::sched::enqueue_and_wake(waiter, target_cpu) };
    }

    // cast_possible_truncation: idx < capacity, a u16.
    #[allow(clippy::cast_possible_truncation)]
    Ok(idx as u16)
}

/// Remove a source from the wait set by its raw state pointer.
///
/// Clears the member slot; stale `ready_ring` entries for this slot are skipped
/// automatically during pop. Does NOT clear the source's back-pointer —
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

    ws.members_mut()[idx] = WaitSetMember::vacant();
    ws.member_count -= 1;
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

    // Under ws.lock, claim and wake the blocked waiter with its park stamped
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
                    badge: 100 + i as u64,
                };
            }
            ws
        }
    }

    // Defect guarded: a ring that holds one entry fewer than its capacity, or
    // overwrites at full, or loses order across the wrap, drops or reorders
    // ready members of a caller-sized set.
    #[test]
    fn ring_holds_capacity_entries_drops_the_next_and_pops_in_order_across_the_wrap()
    {
        let mut fx = Fixture::<3, 4>::new();
        let mut ws = fx.set();
        for idx in [0, 1, 2]
        {
            ws.push_ready(idx);
        }
        ws.push_ready(0);
        assert_eq!(ws.pop_ready(), Some(100));
        assert_eq!(ws.pop_ready(), Some(101));
        assert_eq!(ws.pop_ready(), Some(102));
        assert_eq!(ws.pop_ready(), None);
        // The indices now wrap past the ring's end.
        ws.push_ready(2);
        ws.push_ready(0);
        ws.push_ready(1);
        assert_eq!(ws.pop_ready(), Some(102));
        assert_eq!(ws.pop_ready(), Some(100));
        assert_eq!(ws.pop_ready(), Some(101));
        assert_eq!(ws.pop_ready(), None);
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
        assert_eq!(ws.pop_ready(), Some(101));
        assert_eq!(ws.pop_ready(), None);
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
        assert_eq!(ws.pop_ready(), None);
        assert_eq!(ws.capacity(), 4);
    }
}
