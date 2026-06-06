// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/ipc/endpoint.rs

//! Endpoint IPC — synchronous call / receive / reply.
//!
//! An endpoint has two intrusive FIFO queues:
//! - `send_queue`: callers blocked waiting for a server to `recv`.
//! - `recv_queue`: servers blocked waiting for a caller to `call`.
//!
//! ## Protocol
//! 1. Caller: `call(ep, msg)` — if a server is waiting → transfer message,
//!    mint reply capability, wake server, block caller on reply.
//!    Otherwise → enqueue caller on `send_queue`.
//! 2. Server: `recv(ep)` — if a caller is waiting → dequeue, transfer message,
//!    mint reply cap, return to server. Otherwise → block on `recv_queue`.
//! 3. Server: `reply(reply_cap, msg)` — transfer reply, wake caller, consume cap.
//!
//! ## Reply capability
//! Phase 9 uses a simple approach: the "reply cap" is stored directly in the
//! caller's TCB (`reply_tcb` field). The server's `reply_cap_slot` points at the
//! caller's TCB. Full derivation-tree reply caps are deferred to a future phase.
//!
//! ## Thread safety
//! All operations must be called with the relevant scheduler lock held.

use super::message::Message;
use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};

// ── EndpointState ─────────────────────────────────────────────────────────────

/// Kernel state backing an Endpoint capability.
///
/// The send/recv queues are intrusive singly-linked lists through `ipc_wait_next`
/// in each TCB. Both queues have FIFO ordering.
pub struct EndpointState
{
    /// Head of the blocked-senders queue (callers waiting for a receiver).
    pub send_head: *mut ThreadControlBlock,
    /// Tail of the blocked-senders queue.
    pub send_tail: *mut ThreadControlBlock,
    /// Head of the blocked-receivers queue (servers waiting for a caller).
    pub recv_head: *mut ThreadControlBlock,
    /// Tail of the blocked-receivers queue.
    pub recv_tail: *mut ThreadControlBlock,
    /// Opaque pointer to the `WaitSetState` this endpoint is registered with,
    /// or null if not in any wait set. Type-erased to avoid a circular import.
    /// Cast to `*mut WaitSetState` only inside `wait_set.rs`.
    pub wait_set: *mut u8,
    /// Index of this endpoint's entry in `WaitSetState::members`.
    pub wait_set_member_idx: u8,
    /// Serialises call/recv/reply across CPUs (see notification.rs for rationale).
    pub lock: crate::sync::Spinlock,
}

// SAFETY: EndpointState is accessed only under the relevant scheduler lock.
unsafe impl Send for EndpointState {}
// SAFETY: EndpointState is accessed only under the relevant scheduler lock.
unsafe impl Sync for EndpointState {}

impl EndpointState
{
    /// Create a new, empty endpoint with no waiting threads.
    pub fn new() -> Self
    {
        Self {
            send_head: core::ptr::null_mut(),
            send_tail: core::ptr::null_mut(),
            recv_head: core::ptr::null_mut(),
            recv_tail: core::ptr::null_mut(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            lock: crate::sync::Spinlock::new(),
        }
    }
}

// ── Queue helpers ─────────────────────────────────────────────────────────────

/// Append `tcb` to the tail of a FIFO queue (head, tail pointers).
///
/// # Safety
/// The TCB must not already be on any queue.
unsafe fn enqueue(
    head: &mut *mut ThreadControlBlock,
    tail: &mut *mut ThreadControlBlock,
    tcb: *mut ThreadControlBlock,
)
{
    // SAFETY: tcb validated by caller; ipc_wait_next field always valid in TCB.
    unsafe {
        (*tcb).ipc_wait_next = None;
    }
    if tail.is_null()
    {
        *head = tcb;
        *tail = tcb;
    }
    else
    {
        // SAFETY: tail validated non-null; ipc_wait_next field always valid in TCB.
        unsafe {
            (**tail).ipc_wait_next = Some(tcb);
        }
        *tail = tcb;
    }
}

/// Remove and return the head of the queue, or null if empty.
///
/// # Safety
/// Head/tail pointers must be consistent.
unsafe fn dequeue(
    head: &mut *mut ThreadControlBlock,
    tail: &mut *mut ThreadControlBlock,
) -> *mut ThreadControlBlock
{
    if head.is_null()
    {
        return core::ptr::null_mut();
    }
    let tcb = *head;
    // SAFETY: tcb validated non-null; ipc_wait_next field always valid in TCB.
    let next = unsafe { (*tcb).ipc_wait_next };
    *head = next.unwrap_or_default();
    if head.is_null()
    {
        *tail = core::ptr::null_mut();
    }
    // SAFETY: tcb validated non-null; ipc_wait_next field always valid in TCB.
    unsafe {
        (*tcb).ipc_wait_next = None;
    }
    tcb
}

// ── Endpoint operations ───────────────────────────────────────────────────────

/// Attempt an IPC call on `ep` from `caller` with `msg`.
///
/// Returns `Ok(woken_server)` if a receiver was waiting and was woken (caller
/// is now blocked awaiting reply). Returns `Err(())` if no receiver was
/// available (caller is now blocked on the send queue).
///
/// `parked_state` is the blocked state the caller commits when a receiver was
/// waiting: [`IpcThreadState::BlockedOnReply`] for a normal `SYS_IPC_CALL`, or
/// [`IpcThreadState::BlockedOnFault`] for kernel-synthesized fault delivery
/// (see [`crate::ipc::fault`]). On the send-queue path the caller commits
/// `BlockedOnSend` regardless; the fault discriminator carried on the caller's
/// `in_fault_delivery` flag tells a later [`endpoint_recv`] which awaiting-reply
/// state to transition it to.
///
/// # Safety
/// Must be called with the scheduler lock held.
#[cfg(not(test))]
pub unsafe fn endpoint_call(
    ep: *mut EndpointState,
    caller: *mut ThreadControlBlock,
    msg: &Message,
    parked_state: IpcThreadState,
) -> Result<*mut ThreadControlBlock, ()>
{
    // SAFETY: ep validated by caller.
    let ep = unsafe { &mut *ep };

    // SAFETY: lock serialises call/recv/reply; paired with unlock_raw below.
    let saved = unsafe { ep.lock.lock_raw() };

    // Is a server waiting?
    // SAFETY: recv_head/recv_tail maintained by enqueue/dequeue operations.
    let server = unsafe { dequeue(&mut ep.recv_head, &mut ep.recv_tail) };
    if !server.is_null()
    {
        // SAFETY: server dequeued from recv_head; validate before use.
        #[allow(clippy::undocumented_unsafe_blocks)]
        {
            debug_assert!(
                unsafe { (*server).magic == crate::sched::thread::TCB_MAGIC },
                "endpoint_call: server TCB magic corrupt — use-after-free?"
            );
            debug_assert!(
                unsafe { (*server).state == ThreadState::Blocked },
                "endpoint_call: server not Blocked"
            );
        }
        // SAFETY: server dequeued from recv_head; ipc_msg / reply_tcb are
        // data fields written under ep.lock. State transitions are
        // committed by enqueue_and_wake.
        unsafe {
            (*server).ipc_msg = *msg;
            // Clear context_saved BEFORE the caller becomes wakeable. Every
            // reply-wake claimant reaches the caller through `reply_tcb`
            // (endpoint_reply, dealloc's BlockedOnReply detach,
            // cancel_ipc_block, the sleep-list timer arm), Acquire-loading it.
            // Ordering this Relaxed clear before the `reply_tcb` Release makes
            // the Release carry it, so no claimant can observe the stale
            // context_saved==1 left by the caller's previous switch-in and
            // dispatch it onto a stack its switch() has not yet vacated.
            // Mirrors notification_wait's clear-before-register ordering (notification.rs).
            (*caller)
                .context_saved
                .store(0, core::sync::atomic::Ordering::Relaxed);
            // The caller is becoming BlockedOnReply: claim it for the eventual
            // reply wake BEFORE publishing reply_tcb. dealloc_object(Thread)'s
            // BlockedOnReply detach Acquire-loads reply_tcb, so this store is
            // visible to it (release/acquire via reply_tcb), and it spins on
            // the flag before retype_free. On reply, enqueue_and_wake clears
            // it; on dealloc cancel, the detach clears it (#160). See
            // docs/scheduling-internals.md § Cross-CPU TCB Ownership.
            (*caller)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
            (*server)
                .reply_tcb
                .store(caller, core::sync::atomic::Ordering::Release);
            // Claim the server for wake before releasing ep.lock. dealloc's
            // BlockedOnRecv unlink takes ep.lock and then spins on this flag,
            // so it cannot free the server in the window between this dequeue
            // and the caller's enqueue_and_wake. Cleared by enqueue_and_wake.
            (*server)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
        }
        // SAFETY: caller validated; held ep.lock excludes recv-queue writes.
        let committed = unsafe {
            crate::sched::commit_blocked_under_local_lock(caller, parked_state, server.cast::<u8>())
        };
        if !committed
        {
            // Concurrent stop won; tear down the reply linkage.
            // SAFETY: caller / server validated.
            unsafe {
                let cleared = (*server)
                    .reply_tcb
                    .compare_exchange(
                        caller,
                        core::ptr::null_mut(),
                        core::sync::atomic::Ordering::AcqRel,
                        core::sync::atomic::Ordering::Acquire,
                    )
                    .is_ok();
                // If we tore down the reply binding, the reply wake will never
                // fire, so release the wake-in-flight claim set above (#160).
                // If the CAS failed, another claimant owns the wake and will
                // clear it.
                if cleared
                {
                    (*caller)
                        .wake_in_flight
                        .store(0, core::sync::atomic::Ordering::Release);
                }
                (*caller)
                    .context_saved
                    .store(1, core::sync::atomic::Ordering::Relaxed);
            }
        }
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        return Ok(server);
    }

    // No server available — block caller on send queue.
    let was_empty = ep.send_head.is_null();
    // Clear context_saved before enqueuing on the send queue.
    // See notification.rs notification_wait for the full rationale.
    // SAFETY: caller validated by syscall layer; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: caller validated by syscall layer.
    unsafe {
        (*caller).ipc_msg = *msg;
        enqueue(&mut ep.send_head, &mut ep.send_tail, caller);
    }
    #[allow(clippy::cast_ptr_alignment)]
    let blocked_on = core::ptr::from_mut::<EndpointState>(ep).cast::<u8>();
    // SAFETY: caller validated; held ep.lock excludes send-queue writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            caller,
            IpcThreadState::BlockedOnSend,
            blocked_on,
        )
    };
    if !committed
    {
        // Concurrent stop won; unlink from the send queue.
        // SAFETY: ep.lock held.
        unsafe {
            unlink_from_wait_queue(caller, &mut ep.send_head, &mut ep.send_tail);
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    if was_empty && committed && !ep.wait_set.is_null()
    {
        // SAFETY: wait_set validated non-null.
        unsafe { crate::ipc::wait_set::waitset_notify(ep.wait_set, ep.wait_set_member_idx) };
    }
    // SAFETY: paired with lock_raw above.
    unsafe { ep.lock.unlock_raw(saved) };
    Err(())
}

/// Attempt to receive on `ep` as `server`.
///
/// Returns `Ok(caller, msg)` if a sender was waiting (server continues running;
/// sender remains blocked on reply). Returns `Err(())` if no sender was available
/// (server is now blocked on the recv queue).
///
/// # Safety
/// Must be called with the scheduler lock held.
#[cfg(not(test))]
pub unsafe fn endpoint_recv(
    ep: *mut EndpointState,
    server: *mut ThreadControlBlock,
) -> Result<(*mut ThreadControlBlock, Message), ()>
{
    // SAFETY: ep validated by caller.
    let ep = unsafe { &mut *ep };

    // SAFETY: lock serialises call/recv/reply; paired with unlock_raw below.
    let saved = unsafe { ep.lock.lock_raw() };

    // Dequeue successive senders, skipping any that died / were stopped
    // mid-rebind. The BlockedOnSend → BlockedOnReply transition publishes the
    // reply binding (`server.reply_tcb`, the caller's `ipc_state` /
    // `blocked_on_object`), and `dealloc_object(Thread)` uses the caller's
    // `(ipc_state, blocked_on_object)` to find and clear that binding when the
    // caller dies. `endpoint_call` keeps the two consistent by committing the
    // transition under the scheduler lock (`commit_blocked_under_local_lock`);
    // this path must do the same via `commit_reply_rebind_under_local_lock`. If
    // the caller died concurrently the commit fails: tear the binding down so no
    // stale `reply_tcb` survives to fire against the freed/reused slot
    // (#289 use-after-free / double-enqueue; #284 TCB-field corruption), then
    // skip to the next queued sender.
    loop
    {
        // SAFETY: send_head/send_tail maintained by enqueue/dequeue operations.
        let caller = unsafe { dequeue(&mut ep.send_head, &mut ep.send_tail) };
        if caller.is_null()
        {
            break;
        }
        // SAFETY: caller dequeued from send_head.
        let msg = unsafe { (*caller).ipc_msg };
        // A fault sender (kernel-synthesized delivery) parks as BlockedOnFault
        // so its resume re-executes the faulting instruction and its
        // cancellation kills it; a normal call sender parks as BlockedOnReply.
        // SAFETY: caller dequeued from send_head; in_fault_delivery always valid.
        let parked = if unsafe { (*caller).in_fault_delivery }
        {
            IpcThreadState::BlockedOnFault
        }
        else
        {
            IpcThreadState::BlockedOnReply
        };
        // SAFETY: server validated by syscall layer.
        unsafe {
            // Caller transitions BlockedOnSend → BlockedOnReply: claim it for
            // the eventual reply wake BEFORE publishing reply_tcb, so dealloc's
            // BlockedOnReply detach (which Acquire-loads reply_tcb) sees the
            // flag and gates on it before retype_free (#160).
            (*caller)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
            (*server)
                .reply_tcb
                .store(caller, core::sync::atomic::Ordering::Release);
        }
        // Commit the rebind under the caller's scheduler lock so the
        // (ipc_state, blocked_on_object) publication is serialised with
        // dealloc_object(Thread)'s all-CPU-locks Exited mark and SYS_THREAD_STOP.
        // SAFETY: caller is a valid Blocked TCB dequeued from the send queue.
        let committed = unsafe {
            crate::sched::commit_reply_rebind_under_local_lock(caller, parked, server.cast::<u8>())
        };
        if committed
        {
            // SAFETY: paired with lock_raw above.
            unsafe { ep.lock.unlock_raw(saved) };
            return Ok((caller, msg));
        }
        // Rollback: the caller is dying. CAS the reply binding back to null
        // (the caller's own dealloc may have beaten us; if so it owns the
        // teardown) and release the wake-in-flight claim so its dealloc can
        // proceed past the #160 gate. Then skip this dead sender.
        // SAFETY: server / caller validated.
        unsafe {
            let cleared = (*server)
                .reply_tcb
                .compare_exchange(
                    caller,
                    core::ptr::null_mut(),
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok();
            if cleared
            {
                (*caller)
                    .wake_in_flight
                    .store(0, core::sync::atomic::Ordering::Release);
            }
        }
    }

    // No sender — block server on recv queue.
    // Clear context_saved before enqueuing on the recv queue.
    // See notification.rs notification_wait for the full rationale.
    // SAFETY: server validated by syscall layer; context_saved is AtomicU32.
    unsafe {
        (*server)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: server validated by syscall layer.
    unsafe {
        enqueue(&mut ep.recv_head, &mut ep.recv_tail, server);
    }
    #[allow(clippy::cast_ptr_alignment)]
    let blocked_on = core::ptr::from_mut::<EndpointState>(ep).cast::<u8>();
    // SAFETY: server validated; held ep.lock excludes recv-queue writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            server,
            IpcThreadState::BlockedOnRecv,
            blocked_on,
        )
    };
    if !committed
    {
        // Concurrent stop won; unlink from the recv queue.
        // SAFETY: ep.lock held.
        unsafe {
            unlink_from_wait_queue(server, &mut ep.recv_head, &mut ep.recv_tail);
            (*server)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { ep.lock.unlock_raw(saved) };
    Err(())
}

/// Reply to the thread stored in `server.reply_tcb` with `msg`.
///
/// Wakes the caller (moves it to Ready) and clears the reply target.
/// Returns `Some(caller)` if a caller was woken, `None` if the reply target
/// was null (i.e., server was not in a call context).
///
/// # Safety
/// Must be called with the scheduler lock held.
#[cfg(not(test))]
pub unsafe fn endpoint_reply(
    server: *mut ThreadControlBlock,
    msg: &Message,
) -> Option<*mut ThreadControlBlock>
{
    // SAFETY: server validated by syscall layer; reply_tcb field always valid in TCB.
    let caller = unsafe {
        (*server)
            .reply_tcb
            .load(core::sync::atomic::Ordering::Acquire)
    };
    if caller.is_null()
    {
        return None;
    }
    // CAS-claim the reply slot: `cancel_ipc_block`, the
    // `dealloc_object_one(Thread)` reply-bound waker, and the timer
    // `BlockedOnReply` arm in `sleep_check_wakeups` all CAS this slot
    // independently of `ep.lock`. A plain load+store would let one of
    // them clear `reply_tcb` between our load and store while we still
    // proceed to wake `caller` — yielding two `enqueue_and_wake` calls
    // on the same client and a double-enqueue. See issue #117.
    // SAFETY: server validated.
    if unsafe {
        (*server)
            .reply_tcb
            .compare_exchange(
                caller,
                core::ptr::null_mut(),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_err()
    }
    {
        // A concurrent canceller / dealloc / timer already cleared the
        // slot; they own the wake (and the client may already be
        // Stopped or Exited).
        return None;
    }

    // SAFETY: caller stored by endpoint_call/recv. State transitions
    // committed by enqueue_and_wake at the call site. `caller.wake_in_flight`
    // was set to 1 when the caller became BlockedOnReply (in endpoint_call /
    // endpoint_recv, before publishing `reply_tcb`); enqueue_and_wake clears it
    // once the wake commits. We won the reply_tcb CAS above, so no other
    // claimant (dealloc / cancel) will touch the caller. See
    // docs/scheduling-internals.md § Cross-CPU TCB Ownership.
    unsafe {
        (*caller).ipc_msg = *msg;
    }
    Some(caller)
}

// ── IPC block cancellation helper ────────────────────────────────────────────

/// Remove `tcb` from a singly-linked IPC wait queue (chained through
/// `ipc_wait_next`). Updates `head`/`tail` as needed.
///
/// Returns `true` if the TCB was found and removed, `false` if not present.
///
/// Used by `SYS_THREAD_STOP` to cancel a `BlockedOnSend` or `BlockedOnRecv`.
///
/// # Safety
/// Must be called with the scheduler lock held. All pointers must be valid.
pub unsafe fn unlink_from_wait_queue(
    tcb: *mut ThreadControlBlock,
    head: &mut *mut ThreadControlBlock,
    tail: &mut *mut ThreadControlBlock,
) -> bool
{
    let mut prev: *mut ThreadControlBlock = core::ptr::null_mut();
    let mut cur = *head;

    while !cur.is_null()
    {
        if core::ptr::eq(cur, tcb)
        {
            // SAFETY: cur validated non-null; ipc_wait_next field always valid in TCB.
            let next = unsafe { (*cur).ipc_wait_next.unwrap_or_default() };

            if prev.is_null()
            {
                *head = next;
            }
            else
            {
                // SAFETY: prev validated non-null; ipc_wait_next field always valid in TCB.
                unsafe {
                    (*prev).ipc_wait_next = if next.is_null() { None } else { Some(next) };
                }
            }

            if core::ptr::eq(cur, *tail)
            {
                *tail = prev;
            }

            // SAFETY: cur validated non-null; ipc_wait_next field always valid in TCB.
            unsafe {
                (*cur).ipc_wait_next = None;
            }
            return true;
        }

        prev = cur;
        // SAFETY: cur validated non-null; ipc_wait_next field always valid in TCB.
        cur = unsafe { (*cur).ipc_wait_next.unwrap_or_default() };
    }

    false
}
