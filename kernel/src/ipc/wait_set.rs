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

// cast_possible_truncation: member indices are bounded by WAIT_SET_MAX_MEMBERS (64),
// which fits in u8. WAIT_SET_MAX_MEMBERS itself (usize) fits in u8. All truncations safe.
#![allow(clippy::cast_possible_truncation)]

use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};

/// Maximum number of sources a wait set can monitor simultaneously.
/// Must be ≤ 255 (`member_idx` is u8). Sized to fit procmgr's
/// `MAX_PROCESSES` (32) + service endpoint + headroom, and svcmgr's
/// `MAX_SERVICES` (16) + service endpoint + headroom.
pub const WAIT_SET_MAX_MEMBERS: usize = 64;

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
pub struct WaitSetMember
{
    /// Raw pointer to the source's state struct (`EndpointState` / `SignalState` /
    /// `EventQueueState`). Used as a key for removal and for ready-at-add-time
    /// checks. Cast to the concrete type via `source_tag`.
    pub source_ptr: *mut u8,
    /// Kind of source, determines how `source_ptr` is interpreted.
    pub source_tag: WaitSetSourceTag,
    /// Caller-chosen opaque token returned by `sys_wait_set_wait`.
    pub token: u64,
}

// ── WaitSetState ─────────────────────────────────────────────────────────────

/// Kernel state backing a `WaitSet` capability.
///
/// `WaitSetState` is ~480 bytes; it is heap-allocated via `Box`.
/// The `WaitSetObject` wrapper (16 B) holds a pointer to it.
pub struct WaitSetState
{
    /// Registered members. `None` means the slot is free.
    pub members: [Option<WaitSetMember>; WAIT_SET_MAX_MEMBERS],
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

// SAFETY: WaitSetState is accessed only under the scheduler lock.
unsafe impl Send for WaitSetState {}
// SAFETY: WaitSetState is accessed only under the scheduler lock; no Sync violation.
unsafe impl Sync for WaitSetState {}

impl WaitSetState
{
    /// Create a new, empty wait set with no members and no waiter.
    pub fn new() -> Self
    {
        // Members must be initialised individually because WaitSetMember is not
        // Copy. Use a const-style macro-free approach: construct each array slot.
        // SAFETY: Option<WaitSetMember>::None is valid for all-zero bytes since
        // None has discriminant 0 and raw pointers may be null.
        // Use MaybeUninit to satisfy the compiler.
        use core::mem::MaybeUninit;
        let members = {
            // SAFETY: MaybeUninit<T> has no validity invariants; assume_init is valid for uninitialized memory.
            let mut arr: [MaybeUninit<Option<WaitSetMember>>; WAIT_SET_MAX_MEMBERS] =
                unsafe { MaybeUninit::uninit().assume_init() };
            for slot in &mut arr
            {
                slot.write(None);
            }
            // SAFETY: all slots initialised above.
            unsafe {
                core::mem::transmute::<
                    [MaybeUninit<Option<WaitSetMember>>; WAIT_SET_MAX_MEMBERS],
                    [Option<WaitSetMember>; WAIT_SET_MAX_MEMBERS],
                >(arr)
            }
        };
        Self {
            members,
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
            if let Some(ref m) = self.members[idx]
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
/// Must be called with the scheduler lock held.
/// `ws_opaque` must be a valid `*mut WaitSetState` cast to `*mut u8`.
#[cfg(not(test))]
pub unsafe fn waitset_notify(ws_opaque: *mut u8, member_idx: u8)
{
    // SAFETY: caller guarantees ws_opaque is a valid *mut WaitSetState.
    // cast_ptr_alignment: WaitSetState is heap-allocated via Box, which guarantees
    // alignment to align_of::<WaitSetState>().
    #[allow(clippy::cast_ptr_alignment)]
    let ws = unsafe { &mut *ws_opaque.cast::<WaitSetState>() };

    if ws.waiter.is_null()
    {
        ws.push_ready(member_idx);
    }
    else
    {
        // Wake the blocked thread; deliver the token via wakeup_value.
        let waiter = ws.waiter;
        ws.waiter = core::ptr::null_mut();

        let token = ws.members[member_idx as usize]
            .as_ref()
            .map_or(0, |m| m.token);

        // SAFETY: waiter is a valid TCB placed by waitset_wait.
        unsafe {
            (*waiter).wakeup_value = token;
            (*waiter).state = ThreadState::Ready;
            (*waiter).ipc_state = IpcThreadState::None;
            (*waiter).blocked_on_object = core::ptr::null_mut();
            let prio = (*waiter).priority;
            let target_cpu = crate::sched::select_target_cpu(waiter);
            crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
        }
    }
}

/// Block `caller` until any member becomes ready, or return the next pending token.
///
/// - If the ready ring is non-empty, pops and returns `Ok(token)` without blocking.
/// - If empty, sets `caller` as waiter and returns `Err(())`.
///   The syscall handler calls `schedule()`, then reads `caller.wakeup_value`.
///
/// # Safety
/// Must be called with the scheduler lock held.
#[cfg(not(test))]
pub unsafe fn waitset_wait(
    ws: *mut WaitSetState,
    caller: *mut ThreadControlBlock,
) -> Result<u64, ()>
{
    // SAFETY: caller guarantees lock held and ws is valid.
    let ws = unsafe { &mut *ws };

    if let Some(token) = ws.pop_ready()
    {
        return Ok(token);
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
    // SAFETY: caller is a valid TCB.
    unsafe {
        (*caller).state = ThreadState::Blocked;
        (*caller).ipc_state = IpcThreadState::BlockedOnWaitSet;
        (*caller).blocked_on_object = core::ptr::addr_of_mut!(*ws).cast::<u8>();
    }
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
    // SAFETY: lock held and ws is valid.
    let ws = unsafe { &mut *ws };

    // Find a free slot.
    let idx = ws.members.iter().position(Option::is_none).ok_or(())?;
    ws.members[idx] = Some(WaitSetMember {
        source_ptr,
        source_tag,
        token,
    });
    ws.member_count += 1;

    // Check ready-at-add-time so notifications are not missed.
    // SAFETY: source_ptr is a valid pointer to the source's state struct; tag determines concrete type.
    let already_ready = unsafe { source_is_ready(source_ptr, source_tag) };
    if already_ready
    {
        ws.push_ready(idx as u8);
        // If a thread is already blocked, wake it immediately.
        if !ws.waiter.is_null()
        {
            let waiter = ws.waiter;
            ws.waiter = core::ptr::null_mut();
            // SAFETY: waiter is a valid TCB.
            unsafe {
                (*waiter).wakeup_value = token;
                (*waiter).state = ThreadState::Ready;
                (*waiter).ipc_state = IpcThreadState::None;
                let prio = (*waiter).priority;
                let target_cpu = crate::sched::select_target_cpu(waiter);
                crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
            }
        }
    }

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
    // SAFETY: lock held and ws is valid.
    let ws = unsafe { &mut *ws };

    let idx = ws
        .members
        .iter()
        .position(|m| m.as_ref().is_some_and(|m| m.source_ptr == source_ptr))
        .ok_or(())?;

    ws.members[idx] = None;
    ws.member_count -= 1;
    Ok(())
}

/// Free all resources of `ws` and wake any blocked waiter.
///
/// Clears back-pointers on all registered sources so they stop notifying.
/// Called from `dealloc_object` when the `WaitSet` cap's ref count reaches zero.
///
/// # Safety
/// Must be called with the scheduler lock held. `ws` must be a valid pointer.
/// After this call `ws` itself is NOT freed — the caller drops the outer
/// `WaitSetObject` box.
#[cfg(not(test))]
pub unsafe fn wait_set_drop(ws: *mut WaitSetState)
{
    // SAFETY: ws is valid and lock is held.
    let ws = unsafe { &mut *ws };

    // Wake blocked waiter.
    if !ws.waiter.is_null()
    {
        let waiter = ws.waiter;
        ws.waiter = core::ptr::null_mut();
        // SAFETY: waiter is a valid TCB.
        unsafe {
            (*waiter).wakeup_value = 0;
            (*waiter).state = ThreadState::Ready;
            (*waiter).ipc_state = IpcThreadState::None;
            let prio = (*waiter).priority;
            let target_cpu = crate::sched::select_target_cpu(waiter);
            crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
        }
    }

    // Clear back-pointers on all registered sources.
    for slot in &mut ws.members
    {
        if let Some(m) = slot.as_ref()
        {
            // SAFETY: source_ptr is a valid pointer to the source's state struct; tag determines concrete type.
            unsafe { clear_source_backpointer(m.source_ptr, m.source_tag) };
        }
        *slot = None;
    }
    ws.member_count = 0;
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
            // SAFETY: ep is valid.
            unsafe {
                (*ep).wait_set = core::ptr::null_mut();
                (*ep).wait_set_member_idx = 0;
            }
        }
        WaitSetSourceTag::Signal =>
        {
            let sig = source_ptr.cast::<crate::ipc::signal::SignalState>();
            // SAFETY: sig is valid.
            unsafe {
                (*sig).wait_set = core::ptr::null_mut();
                (*sig).wait_set_member_idx = 0;
                // Update has_observer: keep 1 only if a waiter is still registered.
                (*sig).has_observer.store(
                    u8::from(!(*sig).waiter.is_null()),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
        WaitSetSourceTag::EventQueue =>
        {
            let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
            // SAFETY: eq is valid.
            unsafe {
                (*eq).wait_set = core::ptr::null_mut();
                (*eq).wait_set_member_idx = 0;
            }
        }
    }
}
