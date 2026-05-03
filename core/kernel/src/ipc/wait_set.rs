// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/wait_set.rs

//! Wait set — multiplexed blocking on multiple IPC sources.
//!
//! A wait set aggregates up to `WAIT_SET_MAX_MEMBERS` IPC sources (endpoints,
//! signals, event queues). A caller blocks on the wait set and is woken when
//! any member becomes ready. The caller receives the opaque `token` it chose
//! at `sys_wait_set_add` time, then reads from the source normally.
//!
//! # Readiness model
//! - **Endpoint**: has at least one pending sender.
//! - **Signal**: has non-zero bits.
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
//!
//! # Thread safety
//! All operations must be called with the scheduler lock held.
//!
//! # Extending member capacity
//! Increase `WAIT_SET_MAX_MEMBERS` and the fixed-size arrays. `WAIT_SET_MAX_MEMBERS`
//! must fit in a u8 index.

// cast_possible_truncation: member indices are bounded by WAIT_SET_MAX_MEMBERS (16),
// which fits in u8. WAIT_SET_MAX_MEMBERS itself (usize) fits in u8. All truncations safe.
#![allow(clippy::cast_possible_truncation)]

use crate::sched::thread::{IpcThreadState, ThreadControlBlock};

/// Maximum number of sources a wait set can monitor simultaneously.
/// Must be ≤ 255 (`member_idx` is u8). Both procmgr and svcmgr
/// multiplex per-child death notifications onto a single shared
/// `EventQueue` (correlator-routed in payload), so wait-set width is
/// bounded by the number of distinct sources, not the number of
/// monitored entities. The current ceiling is the IPC service
/// endpoint plus a handful of `EventQueue`s.
pub const WAIT_SET_MAX_MEMBERS: usize = 16;

// ── Member tag ────────────────────────────────────────────────────────────────

/// Discriminant for the kind of source in a `WaitSetMember`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitSetSourceTag
{
    Endpoint = 0,
    Signal = 1,
    EventQueue = 2,
}

// ── WaitSetMember ─────────────────────────────────────────────────────────────

/// A single registered source within a wait set.
///
/// `source_ptr.is_null()` marks the slot as vacant. Folding the vacancy
/// flag into the pointer keeps the struct at 24 B aligned and the
/// member array at `N * 24` rather than `N * 32` (the size an outer
/// `Option<WaitSetMember>` would need without a niche). This is what
/// lets `WaitSetState` fit inside the 512 B retype bin alongside its
/// fixed metadata.
pub struct WaitSetMember
{
    /// Raw pointer to the source's state struct (`EndpointState` / `SignalState` /
    /// `EventQueueState`). Null when the slot is vacant; otherwise used as a
    /// key for removal and for ready-at-add-time checks. Cast to the concrete
    /// type via `source_tag`.
    pub source_ptr: *mut u8,
    /// Kind of source, determines how `source_ptr` is interpreted.
    /// Meaningful only when `source_ptr` is non-null.
    pub source_tag: WaitSetSourceTag,
    /// Caller-chosen opaque token returned by `sys_wait_set_wait`.
    pub token: u64,
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
            token: 0,
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
/// Sized to fit, together with the 24 B `WaitSetObject` wrapper, inside
/// the 512 B retype bin (≈ 440 B: 16 × 24 B members, plus ready ring,
/// waiter pointer, and bookkeeping). The cap-create path constructs
/// both objects in place inside the source `Frame` cap's region;
/// nothing is heap-allocated.
pub struct WaitSetState
{
    /// Per-`WaitSetState` spinlock. Serialises every mutation of the
    /// fields below — `members`, `ready_ring`, `waiter`, and the read/write
    /// pointers. Acquired by `waitset_wait`, `waitset_notify`,
    /// `waitset_add`, `waitset_remove`, and `wait_set_drop`.
    ///
    /// Lock order: `<source>.lock` (Signal/Endpoint/EventQueue) is OUTER,
    /// `WaitSetState.lock` is INNER. `signal_send` already holds `sig.lock`
    /// when it calls into `waitset_notify`; the registration and removal
    /// paths in `sys_wait_set_add` / `sys_wait_set_remove` take the
    /// source's lock before calling `waitset_add` / `waitset_remove`.
    /// `wait_set_drop` clears every source's back-pointer first (under
    /// each source's own lock) and only then takes its own lock, so no
    /// nesting reverses the order.
    pub lock: crate::sync::Spinlock,
    /// Registered members. A slot with `source_ptr.is_null()` is vacant.
    pub members: [WaitSetMember; WAIT_SET_MAX_MEMBERS],
    /// Number of occupied member slots.
    pub member_count: u8,
    /// Circular buffer of pending member indices.
    ///
    /// Entries are member indices `[0, WAIT_SET_MAX_MEMBERS)`. Stale entries
    /// (after removal) are silently skipped during pop.
    pub ready_ring: [u8; WAIT_SET_MAX_MEMBERS],
    /// Read pointer into `ready_ring` (next index to pop).
    pub ready_head: u8,
    /// Write pointer into `ready_ring` (next index to push).
    pub ready_tail: u8,
    /// Single thread blocked on `sys_wait_set_wait`, or null.
    pub waiter: *mut ThreadControlBlock,
}

// SAFETY: WaitSetState is internally synchronised by `WaitSetState.lock`.
unsafe impl Send for WaitSetState {}
// SAFETY: WaitSetState is internally synchronised by `WaitSetState.lock`.
unsafe impl Sync for WaitSetState {}

// Hold the niche-packing invariant: a WaitSetMember must remain 24 B
// (3 × usize) so the 16-slot member array is 384 B and the full state
// fits, with the 24 B WaitSetObject wrapper, in the 512 B retype bin.
// `cap::retype::dispatch_for(WaitSet)` declares 24 + 440 raw bytes;
// regressions here must be matched there or rerouted to a larger bin.
const _: () = {
    assert!(core::mem::size_of::<WaitSetMember>() == 24);
    assert!(core::mem::size_of::<WaitSetState>() <= 440);
};

impl WaitSetState
{
    /// Create a new, empty wait set with no members and no waiter.
    pub fn new() -> Self
    {
        Self {
            lock: crate::sync::Spinlock::new(),
            members: [const { WaitSetMember::vacant() }; WAIT_SET_MAX_MEMBERS],
            member_count: 0,
            ready_ring: [0u8; WAIT_SET_MAX_MEMBERS],
            ready_head: 0,
            ready_tail: 0,
            waiter: core::ptr::null_mut(),
        }
    }

    /// Return true if the ready ring has pending entries.
    #[inline]
    fn has_ready(&self) -> bool
    {
        self.ready_head != self.ready_tail
    }

    /// Push `member_idx` onto the ready ring.
    ///
    /// If the ring is full (all slots occupied with stale entries the consumer
    /// hasn't popped), the push is silently dropped — the source remains
    /// registered but its notification is lost until the consumer calls wait
    /// again. This is safe in the single-CPU boot model where consumers drain
    /// the ring promptly.
    #[inline]
    fn push_ready(&mut self, member_idx: u8)
    {
        let next = (self.ready_tail + 1) % WAIT_SET_MAX_MEMBERS as u8;
        if next != self.ready_head
        {
            self.ready_ring[self.ready_tail as usize] = member_idx;
            self.ready_tail = next;
        }
    }

    /// Pop from the ready ring, skipping stale (removed) entries.
    ///
    /// Returns `Some(token)` for the first live member found, `None` if empty
    /// or all remaining entries are stale.
    fn pop_ready(&mut self) -> Option<u64>
    {
        while self.has_ready()
        {
            let idx = self.ready_ring[self.ready_head as usize] as usize;
            self.ready_head = (self.ready_head + 1) % WAIT_SET_MAX_MEMBERS as u8;
            let m = &self.members[idx];
            if m.is_occupied()
            {
                return Some(m.token);
            }
            // Entry is stale (member was removed) — skip.
        }
        None
    }
}

// ── Public operations ─────────────────────────────────────────────────────────

/// Notify the wait set that member `member_idx` is ready.
///
/// Called from source objects (`signal_send`, `endpoint_call`, `event_queue_post`)
/// when they transition from not-ready to ready.
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
pub unsafe fn waitset_notify(ws_opaque: *mut u8, member_idx: u8)
{
    // SAFETY: caller guarantees ws_opaque is a valid *mut WaitSetState.
    // cast_ptr_alignment: WaitSetState now lives at the start of a retype
    // slot whose alignment is the slot's natural 8 B; `*mut TCB` is the
    // largest field and aligns to 8.
    #[allow(clippy::cast_ptr_alignment)]
    let ws = unsafe { &mut *ws_opaque.cast::<WaitSetState>() };

    // SAFETY: lock is owned by ws; matched unlock_raw at every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    if ws.waiter.is_null()
    {
        ws.push_ready(member_idx);
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return;
    }

    // Snapshot under ws.lock, release, then enqueue_and_wake — see
    // docs/scheduling-internals.md § Lock Hierarchy rule 5.
    let waiter = ws.waiter;
    ws.waiter = core::ptr::null_mut();

    let token = {
        let m = &ws.members[member_idx as usize];
        if m.is_occupied() { m.token } else { 0 }
    };

    // SAFETY: waiter is a valid TCB placed by waitset_wait.
    let (prio, target_cpu) = unsafe {
        (*waiter).wakeup_value = token;
        let prio = (*waiter).priority;
        let target_cpu = crate::sched::select_target_cpu(waiter);
        (prio, target_cpu)
    };

    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };

    // SAFETY: waiter remains valid; enqueue_and_wake commits state under sched.lock.
    unsafe { crate::sched::enqueue_and_wake(waiter, target_cpu, prio) };
}

/// Block `caller` until any member becomes ready, or return the next pending token.
///
/// - If the ready ring is non-empty, pops and returns `Ok(token)` without blocking.
/// - If empty, sets `caller` as waiter and returns `Err(())`.
///   The syscall handler calls `schedule()`, then reads `caller.wakeup_value`.
///
/// # Safety
/// `ws` must be a valid pointer. Acquires the wait set's internal
/// `Spinlock` for the duration; no caller-side locks are required.
#[cfg(not(test))]
pub unsafe fn waitset_wait(
    ws: *mut WaitSetState,
    caller: *mut ThreadControlBlock,
) -> Result<u64, ()>
{
    // SAFETY: caller guarantees ws is valid for &mut access for the
    // duration of this call (the cap holding ws remains alive).
    let ws = unsafe { &mut *ws };

    // SAFETY: lock is owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    if let Some(token) = ws.pop_ready()
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Ok(token);
    }

    // Level-state self-heal. Source notifications are edge-triggered:
    // `endpoint_call` fires `waitset_notify` only on the empty→non-empty
    // send-queue transition, and `event_queue_post` only on the
    // empty→non-empty count transition. A second event arriving while a
    // first is still queued does NOT fire a notify, and would otherwise
    // be invisible to a consumer that processes one item per wakeup and
    // returns here. Walk the registered members and return the first
    // source that is level-ready right now; symmetric with the level
    // check already performed in `waitset_add`.
    for idx in 0..ws.members.len()
    {
        let m = &ws.members[idx];
        if !m.is_occupied()
        {
            continue;
        }
        let (source_ptr, source_tag, token) = (m.source_ptr, m.source_tag, m.token);
        // SAFETY: source_ptr was registered via waitset_add and outlives
        // the wait set (caller's CSpace still holds the cap). Read uses
        // atomic loads where appropriate; no source-side lock required.
        if unsafe { source_is_ready(source_ptr, source_tag) }
        {
            // SAFETY: paired with lock_raw above.
            unsafe { ws.lock.unlock_raw(saved) };
            return Ok(token);
        }
    }

    // Nothing ready — block caller.
    //
    // Clear context_saved before making the thread visible as a waiter.
    // See signal.rs signal_wait for the full rationale.
    // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    ws.waiter = caller;
    let blocked_on = core::ptr::addr_of_mut!(*ws).cast::<u8>();
    // SAFETY: caller is a valid TCB; ws.lock held excludes other waiter writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            caller,
            IpcThreadState::BlockedOnWaitSet,
            blocked_on,
        )
    };
    if !committed
    {
        // Concurrent stop won; roll back the waiter slot.
        ws.waiter = core::ptr::null_mut();
        // SAFETY: caller is a valid TCB; context_saved is AtomicU32.
        unsafe {
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };
    Err(())
}

/// Register a source in the wait set.
///
/// Returns `Ok(member_idx)` on success, `Err(())` if the wait set is full.
///
/// Also checks whether the source is already ready at add time; if so,
/// pushes to `ready_ring` immediately.
///
/// # Safety
/// Must be called with the scheduler lock held.
/// `source_ptr` must be a valid pointer to the source's state struct.
/// The caller is responsible for setting the source's `wait_set` back-pointer.
#[cfg(not(test))]
pub unsafe fn waitset_add(
    ws: *mut WaitSetState,
    source_ptr: *mut u8,
    source_tag: WaitSetSourceTag,
    token: u64,
) -> Result<u8, ()>
{
    // SAFETY: ws valid for &mut access for the duration; cap pins it.
    let ws = unsafe { &mut *ws };

    // SAFETY: lock owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    // Find a free slot.
    let Some(idx) = ws.members.iter().position(|m| !m.is_occupied())
    else
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Err(());
    };
    ws.members[idx] = WaitSetMember {
        source_ptr,
        source_tag,
        token,
    };
    ws.member_count += 1;

    // Check ready-at-add-time so notifications are not missed.
    // SAFETY: source_ptr is a valid pointer to the source's state struct; tag determines concrete type.
    let already_ready = unsafe { source_is_ready(source_ptr, source_tag) };
    let mut deferred_wake: Option<(*mut ThreadControlBlock, u8, usize)> = None;
    if already_ready
    {
        // cast_possible_truncation: WAIT_SET_MAX_MEMBERS = 16; idx fits in u8.
        #[allow(clippy::cast_possible_truncation)]
        ws.push_ready(idx as u8);
        // Snapshot the wake; enqueue_and_wake runs after unlock per
        // docs/scheduling-internals.md § Lock Hierarchy rule 5.
        if !ws.waiter.is_null()
        {
            let waiter = ws.waiter;
            ws.waiter = core::ptr::null_mut();
            // SAFETY: waiter is a valid TCB.
            let (prio, target_cpu) = unsafe {
                (*waiter).wakeup_value = token;
                let prio = (*waiter).priority;
                let target_cpu = crate::sched::select_target_cpu(waiter);
                (prio, target_cpu)
            };
            deferred_wake = Some((waiter, prio, target_cpu));
        }
    }

    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };

    if let Some((waiter, prio, target_cpu)) = deferred_wake
    {
        // SAFETY: waiter remains valid.
        unsafe { crate::sched::enqueue_and_wake(waiter, target_cpu, prio) };
    }

    // cast_possible_truncation: idx < WAIT_SET_MAX_MEMBERS = 16.
    #[allow(clippy::cast_possible_truncation)]
    Ok(idx as u8)
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
/// Must be called with the scheduler lock held.
#[cfg(not(test))]
pub unsafe fn waitset_remove(ws: *mut WaitSetState, source_ptr: *mut u8) -> Result<(), ()>
{
    // SAFETY: ws valid for &mut access for the duration; cap pins it.
    let ws = unsafe { &mut *ws };

    // SAFETY: lock owned by ws; matched unlock_raw on every return path.
    let saved = unsafe { ws.lock.lock_raw() };

    let Some(idx) = ws
        .members
        .iter()
        .position(|m| m.is_occupied() && m.source_ptr == source_ptr)
    else
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ws.lock.unlock_raw(saved) };
        return Err(());
    };

    ws.members[idx] = WaitSetMember::vacant();
    ws.member_count -= 1;
    // SAFETY: paired with lock_raw above.
    unsafe { ws.lock.unlock_raw(saved) };
    Ok(())
}

/// Free all resources of `ws` and wake any blocked waiter.
///
/// Clears back-pointers on all registered sources so they stop notifying,
/// then wakes any blocked waiter.
///
/// # Safety
/// `ws` must be a valid pointer. After this call `ws` itself is NOT freed —
/// the caller drops the outer `WaitSetObject` storage.
///
/// Lock discipline: clears each source's back-pointer FIRST under the
/// source's own lock — this is the inverse of the `signal_send →
/// waitset_notify` direction (`source.lock` → `ws.lock`), and walking the
/// members under `ws.lock` while taking source locks would invert that
/// order. By clearing back-pointers first we guarantee no future
/// `waitset_notify` call references this ws; we then take `ws.lock` only
/// to wake the blocked waiter (if any).
#[cfg(not(test))]
pub unsafe fn wait_set_drop(ws: *mut WaitSetState)
{
    // SAFETY: ws valid for &mut access for the duration; the caller is
    // dealloc_object on a refcount==0 cap, no other syscall path can hold
    // ws_state at this point.
    let ws_ref = unsafe { &mut *ws };

    // Step 1: clear back-pointers under each source's own lock so no
    // concurrent signal_send / event_post / endpoint_call can call back
    // into waitset_notify after this point. We snapshot member info into
    // a stack array first because we cannot hold ws.lock while taking
    // source locks (that would invert the lock order).
    let mut snap: [Option<(*mut u8, WaitSetSourceTag)>; WAIT_SET_MAX_MEMBERS] =
        [None; WAIT_SET_MAX_MEMBERS];
    for (i, slot) in ws_ref.members.iter().enumerate()
    {
        if slot.is_occupied()
        {
            snap[i] = Some((slot.source_ptr, slot.source_tag));
        }
    }
    for entry in snap.iter().flatten()
    {
        let (source_ptr, source_tag) = *entry;
        // SAFETY: source_ptr is a valid pointer to the source's state
        // struct; clear_source_backpointer takes the source's own lock.
        unsafe { clear_source_backpointer(source_ptr, source_tag) };
    }

    // Step 2: detach any blocked waiter under ws.lock; defer the wake
    // until after unlock per § Lock Hierarchy rule 5.
    // SAFETY: lock owned by ws; matched unlock_raw below.
    let saved = unsafe { ws_ref.lock.lock_raw() };
    let deferred_wake: Option<(*mut ThreadControlBlock, u8, usize)> = if ws_ref.waiter.is_null()
    {
        None
    }
    else
    {
        let waiter = ws_ref.waiter;
        ws_ref.waiter = core::ptr::null_mut();
        // SAFETY: waiter is a valid TCB; wakeup_value=0 = drop semantics.
        let (prio, target_cpu) = unsafe {
            (*waiter).wakeup_value = 0;
            let prio = (*waiter).priority;
            let target_cpu = crate::sched::select_target_cpu(waiter);
            (prio, target_cpu)
        };
        Some((waiter, prio, target_cpu))
    };
    for slot in &mut ws_ref.members
    {
        *slot = WaitSetMember::vacant();
    }
    ws_ref.member_count = 0;
    // SAFETY: paired with lock_raw above.
    unsafe { ws_ref.lock.unlock_raw(saved) };

    if let Some((waiter, prio, target_cpu)) = deferred_wake
    {
        // SAFETY: waiter remains valid.
        unsafe { crate::sched::enqueue_and_wake(waiter, target_cpu, prio) };
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Check whether a source is already ready (has pending data).
///
/// # Safety
/// `source_ptr` must be a valid pointer to the appropriate state struct.
unsafe fn source_is_ready(source_ptr: *mut u8, tag: WaitSetSourceTag) -> bool
{
    use core::sync::atomic::Ordering;
    // cast_ptr_alignment: each source_ptr was created from a Box<ConcreteType>, so it
    // is aligned to align_of::<ConcreteType>(). The casts below restore that type.
    #[allow(clippy::cast_ptr_alignment)]
    match tag
    {
        WaitSetSourceTag::Endpoint =>
        {
            let ep = source_ptr.cast::<crate::ipc::endpoint::EndpointState>();
            // SAFETY: ep is a valid EndpointState.
            !unsafe { (*ep).send_head.is_null() }
        }
        WaitSetSourceTag::Signal =>
        {
            let sig = source_ptr.cast::<crate::ipc::signal::SignalState>();
            // SAFETY: sig is a valid SignalState.
            unsafe { (*sig).bits.load(Ordering::Acquire) != 0 }
        }
        WaitSetSourceTag::EventQueue =>
        {
            let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
            // SAFETY: eq is a valid EventQueueState.
            unsafe { (*eq).count > 0 }
        }
    }
}

/// Clear the back-pointer on a source so it stops notifying this wait set.
///
/// Acquires the source's own lock to serialise against any concurrent
/// `signal_send` / `event_post` / `endpoint_call` that is reading
/// `source.wait_set` to dispatch a notification. Without this lock the
/// reader could see a non-null pointer, then release its read of the
/// pointer's target after we've torn down the wait set — UAF.
///
/// # Safety
/// `source_ptr` must be a valid pointer to the appropriate state struct.
unsafe fn clear_source_backpointer(source_ptr: *mut u8, tag: WaitSetSourceTag)
{
    // cast_ptr_alignment: each source_ptr was created from a Box<ConcreteType>, so it
    // is aligned to align_of::<ConcreteType>(). The casts below restore that type.
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
        WaitSetSourceTag::Signal =>
        {
            let sig = source_ptr.cast::<crate::ipc::signal::SignalState>();
            // SAFETY: sig is valid; acquire its lock for the back-pointer write.
            unsafe {
                let saved = (*sig).lock.lock_raw();
                (*sig).wait_set = core::ptr::null_mut();
                (*sig).wait_set_member_idx = 0;
                // Update has_observer: keep 1 only if a waiter is still registered.
                (*sig).has_observer.store(
                    u8::from(!(*sig).waiter.is_null()),
                    core::sync::atomic::Ordering::Relaxed,
                );
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
