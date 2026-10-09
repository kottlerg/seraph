// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/endpoint.rs

//! Endpoint IPC — synchronous call / receive / reply.
//!
//! An endpoint has two intrusive FIFO queues:
//! - `send_queue`: callers blocked waiting for a server to `recv`.
//! - `recv_queue`: servers blocked waiting for a caller to `call`.
//!
//! ## Protocol
//! The call, receive, and reply paths (`endpoint_call`, `endpoint_recv`,
//! `endpoint_reply`) are specified in core/kernel/docs/ipc-internals.md
//! § Call Path (Sender), § Receive Path (Server), and § Reply Path; the
//! call/reply model is docs/ipc-design.md § The Call/Reply Model.
//!
//! ## Reply capability
//! The reply capability is the implicit, single-use caller binding that
//! docs/ipc-design.md § The Call/Reply Model defines: the server TCB's
//! `reply_tcb` field points at the bound caller's TCB. It occupies no `CSpace`
//! slot.
//!
//! ## Thread safety
//! `endpoint_call` and `endpoint_recv` take `EndpointState::lock` (`ep.lock`)
//! themselves; it serialises the send/recv queues and the call/recv rendezvous.
//! `endpoint_reply` takes no lock and serialises through the `reply_tcb` claim.
//! `unlink_from_wait_queue` requires the caller to hold the owning endpoint's
//! `ep.lock`. Callers enter with no scheduler lock held (lock order:
//! core/kernel/docs/scheduling-internals.md § Lock Hierarchy). A server's `reply_tcb` is
//! claimed by compare-exchange (`endpoint_reply`, cancel, teardown) or by an
//! atomic swap (the `SYS_IPC_REPLY` failure path); the claim protocol is in
//! core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership, and the swap claim
//! in core/kernel/docs/ipc-internals.md § Park Dispositions and Episodes.

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
    /// `1` iff `send_head != null`: the lockless readiness signal that
    /// `wait_set::source_is_ready` reads, Release-stored under `lock` by
    /// [`EndpointState::refresh_send_ready`] at every `send_head` mutation
    /// (core/kernel/docs/ipc-internals.md § Wait Path).
    pub send_nonempty: core::sync::atomic::AtomicU32,
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
    /// Serialises the send/recv queues and the call/recv rendezvous; reply is
    /// serialised by the `reply_tcb` claim, not this lock.
    pub lock: crate::sync::Spinlock,
}

// SAFETY: every mutation of the raw queue pointers (`send_*`, `recv_*`) and of
// the wait-set back-pointer fields happens under `EndpointState::lock`, and
// `send_nonempty` is an atomic, so moving the state between CPUs exposes no
// unsynchronised write.
unsafe impl Send for EndpointState {}
// SAFETY: concurrent shared access writes the raw-pointer fields only under
// `EndpointState::lock`; the lock-free readiness check
// (`wait_set::source_is_ready`) reads only the atomic `send_nonempty`.
unsafe impl Sync for EndpointState {}

// Pins the retype-slot budget assumed by `cap::retype::dispatch_for(Endpoint)`:
// the 24 B `EndpointObject` wrapper plus this state must fit BIN_128 (128 B).
// Catches a future field addition that would overflow the bin.
const _: () = {
    assert!(24 + core::mem::size_of::<EndpointState>() <= 128);
};

impl EndpointState
{
    /// Create a new, empty endpoint with no waiting threads.
    pub fn new() -> Self
    {
        Self {
            send_head: core::ptr::null_mut(),
            send_tail: core::ptr::null_mut(),
            send_nonempty: core::sync::atomic::AtomicU32::new(0),
            recv_head: core::ptr::null_mut(),
            recv_tail: core::ptr::null_mut(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            lock: crate::sync::Spinlock::new(),
        }
    }

    /// Republish the `send_nonempty` shadow from the current `send_head`.
    ///
    /// MUST be called under `lock` after every `send_head` mutation so the
    /// lockless `Acquire` reader in `wait_set::source_is_ready` observes the
    /// current level. `Release` pairs with that `Acquire`.
    ///
    /// # Safety
    /// Caller holds `self.lock` (serialises with all `send_head` writers).
    pub unsafe fn refresh_send_ready(&self)
    {
        self.send_nonempty.store(
            u32::from(!self.send_head.is_null()),
            core::sync::atomic::Ordering::Release,
        );
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

/// Tear down a rendezvous reply linkage whose park commit was refused
/// (`ParkCommit::RefusedStop`: a concurrent stop or exit; or
/// `ParkCommit::RefusedWake`: a coalesced wake; either refusal cancels the
/// call): CAS the server's `reply_tcb` back to null (the caller's own dealloc
/// may have beaten us; if so it owns the teardown). On the CAS win (the
/// episode claim), stamp the cancelled disposition so the caller's resume
/// takes the error path, and release the wake-in-flight claim so its dealloc
/// can proceed (#160). On a loss, another claimant owns the wake and will
/// clear it. Either way, republish `context_saved` (the park never happened).
///
/// # Safety
/// `server` and `caller` must be valid TCBs; the lock of the endpoint that
/// published the linkage must be held.
#[cfg(not(test))]
unsafe fn rollback_uncommitted_call(
    server: *mut ThreadControlBlock,
    caller: *mut ThreadControlBlock,
    parked_state: IpcThreadState,
)
{
    // SAFETY: server / caller valid per caller contract.
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
            crate::sched::thread::stamp_cancelled_deposit(
                caller,
                parked_state == IpcThreadState::BlockedOnFault,
            );
            (*caller)
                .wake_in_flight
                .store(0, core::sync::atomic::Ordering::Release);
        }
        (*caller)
            .context_saved
            .store(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Attempt an IPC call on `ep` from `caller` with `msg`.
///
/// Returns `Ok(server)` if a receiver was waiting. The server is dequeued and
/// bound, and its wake is claimed by `wake_in_flight`. The caller MUST wake it
/// with `enqueue_and_wake` after moving any caps. The calling thread is
/// committed to `parked_state`, unless the park is refused, in which case the
/// reply linkage is rolled back. Returns `Err(())` if no receiver was
/// available: the calling thread is committed `BlockedOnSend` on the send
/// queue, unless the park is refused, in which case it is unlinked and the
/// call is stamped cancelled.
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
/// `ep` and `caller` must be valid, and `caller` must be the running thread.
/// Call with no scheduler lock and no `ep.lock` held.
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

    // SAFETY: lock serialises the send/recv queues and the call/recv rendezvous
    // (reply is serialised by the `reply_tcb` claim); paired with unlock_raw below.
    let saved = unsafe { ep.lock.lock_raw() };

    // Is a server waiting?
    // SAFETY: recv_head/recv_tail maintained by enqueue/dequeue operations.
    let server = unsafe { dequeue(&mut ep.recv_head, &mut ep.recv_tail) };
    if !server.is_null()
    {
        // undocumented_unsafe_blocks: the two unsafe reads sit inside debug_assert!
        // arguments, where a per-block SAFETY comment cannot be placed. Both are
        // sound: server was just dequeued from recv_head under ep.lock and is a live
        // TCB.
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
            // (endpoint_reply, the SYS_IPC_REPLY failure-path swap, dealloc_object(Thread)'s
            // dying-server reply-bound wake, cancel_ipc_block, the sleep-list timer arm),
            // Acquire-loading it.
            // Ordering this Relaxed clear before the `reply_tcb` Release makes
            // the Release carry it, so no claimant can observe the stale
            // context_saved==1 left by the caller's previous switch-in and
            // dispatch it onto a stack its switch() has not yet vacated.
            // Mirrors notification_wait's clear-before-register ordering (notification.rs).
            (*caller)
                .context_saved
                .store(0, core::sync::atomic::Ordering::Relaxed);
            // The caller is becoming `parked_state` (BlockedOnReply, or BlockedOnFault
            // for fault delivery): claim it for the eventual reply wake BEFORE publishing
            // reply_tcb. dealloc_object(Thread)'s BlockedOnReply / BlockedOnFault detach
            // Acquire-loads reply_tcb, so this store is visible to it
            // (release/acquire via reply_tcb), and it spins on
            // the flag before retype_free. On reply, enqueue_and_wake clears
            // it; on dealloc cancel, the detach clears it (#160). See
            // core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership.
            (*caller)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
            // Known defect (#443): this unconditional store overwrites any
            // binding still pending on the server, stranding the displaced
            // caller with wake_in_flight set and no claimant able to win its
            // reply_tcb CAS.
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
        // SAFETY: caller is the current CPU's running thread (this fn's contract);
        // held ep.lock excludes recv-queue writes.
        let committed = unsafe {
            crate::sched::commit_blocked_under_local_lock(caller, parked_state, server.cast::<u8>())
        };
        if committed != crate::sched::ParkCommit::Committed
        {
            // Refused park (stop won, or a stray coalesced wake); tear down
            // the reply linkage. Either refusal cancels the call.
            // SAFETY: caller / server validated; ep.lock held.
            unsafe { rollback_uncommitted_call(server, caller, parked_state) };
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
        // Publish the send-queue level before the wait-set notify below.
        ep.refresh_send_ready();
    }
    // cast_ptr_alignment: the cast is to `*mut u8` (alignment 1), so it cannot
    // misalign; `blocked_on_object` is restored to `EndpointState` only by readers
    // keyed on `ipc_state`.
    #[allow(clippy::cast_ptr_alignment)]
    let blocked_on = core::ptr::from_mut::<EndpointState>(ep).cast::<u8>();
    // SAFETY: caller is the current CPU's running thread (this fn's contract);
    // held ep.lock excludes send-queue writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            caller,
            IpcThreadState::BlockedOnSend,
            blocked_on,
        )
    };
    if committed != crate::sched::ParkCommit::Committed
    {
        // Refused park (stop won, or a stray coalesced wake — either cancels
        // the call); unlink from the send queue.
        // SAFETY: ep.lock held.
        unsafe {
            let _ = unlink_from_wait_queue(caller, &mut ep.send_head, &mut ep.send_tail);
            ep.refresh_send_ready();
            // ep.lock has been held continuously since the enqueue above, so
            // this teardown is the episode's sole owner: stamp so the stopped
            // caller's restart resumes via the disposition.
            crate::sched::thread::stamp_cancelled_deposit(caller, (*caller).in_fault_delivery);
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    if was_empty && committed == crate::sched::ParkCommit::Committed && !ep.wait_set.is_null()
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
/// (the server is committed `BlockedOnRecv` on the recv queue, unless the park
/// is refused, in which case it is unlinked and, on a stop-won refusal, its
/// park is stamped INTERRUPTED).
///
/// # Safety
/// `ep` and `server` must be valid, and `server` must be the running thread.
/// Call with no scheduler lock and no `ep.lock` held.
#[cfg(not(test))]
pub unsafe fn endpoint_recv(
    ep: *mut EndpointState,
    server: *mut ThreadControlBlock,
) -> Result<(*mut ThreadControlBlock, Message), ()>
{
    // SAFETY: ep validated by caller.
    let ep = unsafe { &mut *ep };

    // SAFETY: lock serialises the send/recv queues and the call/recv rendezvous
    // (reply is serialised by the `reply_tcb` claim); paired with unlock_raw below.
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
        // Republish the send-queue level after each dequeue (the queue may now be
        // empty) for the lockless wait-set level self-heal (#285).
        // SAFETY: ep.lock held.
        unsafe { ep.refresh_send_ready() };
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
            // Caller transitions BlockedOnSend → `parked` (BlockedOnReply, or
            // BlockedOnFault for a fault sender): claim it for the eventual reply wake
            // BEFORE publishing reply_tcb, so dealloc's BlockedOnReply / BlockedOnFault
            // detach (which Acquire-loads reply_tcb) sees the flag and gates on it before
            // retype_free (#160).
            (*caller)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
            // Known defect (#443): this unconditional store overwrites any
            // binding still pending on the server (a second recv without a
            // reply), stranding the displaced caller with wake_in_flight set
            // and no claimant able to win its reply_tcb CAS.
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
        // Rollback: the caller is dying or stopped. CAS the reply binding back
        // to null (the caller's own dealloc may have beaten us; if so it owns
        // the teardown) and release the wake-in-flight claim so its dealloc
        // can proceed past the #160 gate. Then skip this dead sender.
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
                // Teardown CAS win = episode claim. The send-queue dequeue
                // above is also why a concurrent cancel_ipc_block's unlink
                // lost and did not stamp: a STOPPED caller resumes on restart
                // via this disposition. Stamp before releasing the
                // wake-in-flight gate — after the release a dying caller's
                // dealloc may free the TCB.
                crate::sched::thread::stamp_cancelled_deposit(
                    caller,
                    parked == IpcThreadState::BlockedOnFault,
                );
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
    // cast_ptr_alignment: the cast is to `*mut u8` (alignment 1), so it cannot
    // misalign; `blocked_on_object` is restored to `EndpointState` only by readers
    // keyed on `ipc_state`.
    #[allow(clippy::cast_ptr_alignment)]
    let blocked_on = core::ptr::from_mut::<EndpointState>(ep).cast::<u8>();
    // SAFETY: server is the current CPU's running thread (this fn's contract);
    // held ep.lock excludes recv-queue writes.
    let committed = unsafe {
        crate::sched::commit_blocked_under_local_lock(
            server,
            IpcThreadState::BlockedOnRecv,
            blocked_on,
        )
    };
    if committed != crate::sched::ParkCommit::Committed
    {
        // Refused park; unlink from the recv queue. ep.lock has been held
        // across enqueue/commit/rollback, so the rollback owns the episode.
        // A stop-won refusal stamps INTERRUPTED so the restarted server's
        // resume reports the cancellation instead of publishing a stale
        // ipc_msg; a coalesced-wake refusal leaves the deposit standing.
        // SAFETY: ep.lock held.
        unsafe {
            unlink_from_wait_queue(server, &mut ep.recv_head, &mut ep.recv_tail);
            if committed == crate::sched::ParkCommit::RefusedStop
            {
                crate::sched::thread::stamp_park_deposit(
                    server,
                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                );
            }
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
/// Claims the reply binding (CAS `server.reply_tcb` from the bound caller to
/// null) and stages `msg` in the caller's `ipc_msg`. Returns the claimed
/// caller; the CAS win makes the syscall layer the episode's sole depositor,
/// so it MUST finish the deposit (cap results), stamp the disposition (REPLY,
/// or `fault_outcome` and the episode for a `BlockedOnFault` caller), and then
/// wake it with `enqueue_and_wake`. Returns `None` if no binding exists or a
/// concurrent claimant won.
///
/// # Safety
/// `server` must be the calling thread's valid TCB. Call with no scheduler or
/// endpoint lock held.
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
    // core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership.
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
/// Used by `cancel_ipc_block` (the `SYS_THREAD_STOP` and object-teardown
/// cancel path), by `dealloc_object(Thread)`'s `BlockedOnSend` /
/// `BlockedOnRecv` unlink, and by the refused-park rollbacks in
/// `endpoint_call` and `endpoint_recv`.
///
/// # Safety
/// Caller must hold the owning endpoint's `ep.lock`. All pointers must be valid.
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
