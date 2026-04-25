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
    /// Serialises call/recv/reply across CPUs (see signal.rs for rationale).
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
/// is now blocked on reply). Returns `Err(())` if no receiver was available
/// (caller is now blocked on the send queue).
///
/// # Safety
/// Must be called with the scheduler lock held.
#[cfg(not(test))]
pub unsafe fn endpoint_call(
    ep: *mut EndpointState,
    caller: *mut ThreadControlBlock,
    msg: &Message,
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
        // SAFETY: server dequeued from recv_head.
        unsafe {
            (*server).ipc_msg = *msg;
            (*server).reply_tcb = caller;
            (*server).state = ThreadState::Ready;
            (*server).ipc_state = IpcThreadState::None;
            (*server).blocked_on_object = core::ptr::null_mut();
        }
        // Clear context_saved before making the caller visible as blocked.
        // See signal.rs signal_wait for the full rationale.
        // SAFETY: caller validated by syscall layer; context_saved is AtomicU32.
        unsafe {
            (*caller)
                .context_saved
                .store(0, core::sync::atomic::Ordering::Relaxed);
        }
        // SAFETY: caller validated by syscall layer.
        unsafe {
            (*caller).state = ThreadState::Blocked;
            (*caller).ipc_state = IpcThreadState::BlockedOnReply;
            (*caller).blocked_on_object = server.cast::<u8>();
        }
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        return Ok(server);
    }

    // No server available — block caller on send queue.
    let was_empty = ep.send_head.is_null();
    // Clear context_saved before enqueuing on the send queue.
    // See signal.rs signal_wait for the full rationale.
    // SAFETY: caller validated by syscall layer; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: caller validated by syscall layer.
    unsafe {
        (*caller).ipc_msg = *msg;
        (*caller).state = ThreadState::Blocked;
        (*caller).ipc_state = IpcThreadState::BlockedOnSend;
        #[allow(clippy::cast_ptr_alignment)]
        {
            (*caller).blocked_on_object = core::ptr::from_mut::<EndpointState>(ep).cast::<u8>();
        }
        enqueue(&mut ep.send_head, &mut ep.send_tail, caller);
    }
    if was_empty && !ep.wait_set.is_null()
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

    // SAFETY: send_head/send_tail maintained by enqueue/dequeue operations.
    let caller = unsafe { dequeue(&mut ep.send_head, &mut ep.send_tail) };
    if !caller.is_null()
    {
        // SAFETY: caller dequeued from send_head.
        let msg = unsafe { (*caller).ipc_msg };
        // SAFETY: server validated by syscall layer.
        unsafe {
            (*server).reply_tcb = caller;
        }
        // SAFETY: caller dequeued from send_head.
        unsafe {
            (*caller).ipc_state = IpcThreadState::BlockedOnReply;
            (*caller).blocked_on_object = server.cast::<u8>();
        }
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        return Ok((caller, msg));
    }

    // No sender — block server on recv queue.
    // Clear context_saved before enqueuing on the recv queue.
    // See signal.rs signal_wait for the full rationale.
    // SAFETY: server validated by syscall layer; context_saved is AtomicU32.
    unsafe {
        (*server)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: server validated by syscall layer.
    unsafe {
        (*server).state = ThreadState::Blocked;
        (*server).ipc_state = IpcThreadState::BlockedOnRecv;
        #[allow(clippy::cast_ptr_alignment)]
        {
            (*server).blocked_on_object = core::ptr::from_mut::<EndpointState>(ep).cast::<u8>();
        }
        enqueue(&mut ep.recv_head, &mut ep.recv_tail, server);
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
    let caller = unsafe { (*server).reply_tcb };
    if caller.is_null()
    {
        return None;
    }
    // Clear the reply target.
    // SAFETY: server validated by syscall layer; reply_tcb field always valid in TCB.
    unsafe {
        (*server).reply_tcb = core::ptr::null_mut();
    }

    // Deliver reply to caller.
    // SAFETY: caller stored by endpoint_call/recv; scheduler lock held; ensures exclusive
    // access to thread state.
    unsafe {
        (*caller).ipc_msg = *msg;
        (*caller).state = ThreadState::Ready;
        (*caller).ipc_state = IpcThreadState::None;
        (*caller).blocked_on_object = core::ptr::null_mut();
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
