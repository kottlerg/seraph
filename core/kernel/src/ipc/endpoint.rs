// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/ipc/endpoint.rs

//! Endpoint IPC — synchronous call / receive / reply.
//!
//! An endpoint has two intrusive queues:
//! - `send`: callers blocked waiting for a server to `recv`, a FIFO
//!   ([`WaitQueue`]): a receive binds the longest-waiting caller.
//! - `recv`: servers blocked waiting for a caller to `call` ([`RecvQueue`]):
//!   a call takes a receiver parked on the caller's CPU when that CPU queues
//!   no thread but its idle thread and its parked-receiver table records one
//!   for this endpoint, and otherwise the longest-waiting receiver
//!   (core/kernel/docs/ipc-internals.md § Wait Queues).
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
//! Every other access to a queue (a canceller's or a dying thread's removal)
//! holds the owning endpoint's `ep.lock`. Callers enter with no scheduler lock held (lock order:
//! core/kernel/docs/scheduling-internals.md § Lock Hierarchy). A server's `reply_tcb` is
//! claimed by compare-exchange (`endpoint_reply`, cancel, teardown) or by an
//! atomic swap (the `SYS_IPC_REPLY` failure path, the release of an unreplied
//! caller at receive entry, and the receive's rebind, which displaces the
//! earlier binding as it publishes the next); the claim protocol is in
//! core/kernel/docs/scheduling-internals.md § Cross-CPU TCB Ownership, and the swap claim
//! in core/kernel/docs/ipc-internals.md § Park Dispositions and Episodes.

use super::WaitQueue;
use super::recv_park::RecvQueue;
use crate::sched::thread::{IpcThreadState, ThreadControlBlock, ThreadState};

// ── EndpointState ─────────────────────────────────────────────────────────────

/// Kernel state backing an Endpoint capability.
///
/// The send queue is a [`WaitQueue`] and the receive queue a [`RecvQueue`]
/// over one: each O(1) to remove any thread from, which a canceller, a dying
/// thread, a refused park's rollback and a call's take of a receiver parked on
/// its CPU do. Callers are bound in arrival order; a call takes the receiver
/// parked on its CPU when [`RecvQueue::take`] finds one, and otherwise the
/// longest-waiting. `lock` serialises every non-atomic field that changes after
/// construction (the bare-field exception of docs/coding-standards.md
/// § Concurrency).
pub struct EndpointState
{
    /// The blocked senders (callers waiting for a receiver).
    pub send: WaitQueue,
    /// `1` iff `send` is not empty: the lockless readiness signal that
    /// `wait_set::source_is_ready` reads, Release-stored under `lock` by
    /// [`EndpointState::refresh_send_ready`] at every `send` mutation
    /// (core/kernel/docs/ipc-internals.md § Wait Path).
    pub send_nonempty: core::sync::atomic::AtomicU32,
    /// The blocked receivers (servers waiting for a caller).
    pub recv: RecvQueue,
    /// Opaque pointer to the `WaitSetState` this endpoint is registered with,
    /// or null if not in any wait set. Type-erased to avoid a circular import.
    /// Cast to `*mut WaitSetState` only inside `wait_set.rs`.
    pub wait_set: *mut u8,
    /// Index of this endpoint's entry in `WaitSetState::members`.
    pub wait_set_member_idx: u16,
    /// Serialises the send/recv queues and the call/recv rendezvous; reply is
    /// serialised by the `reply_tcb` claim, not this lock.
    pub lock: crate::sync::Spinlock,
    /// Number of capability slots, in every `CSpace`, that name this endpoint
    /// with the Receive right: raised when such a slot is filled and lowered
    /// when it is freed or its dying `CSpace` releases it
    /// (`cap::object::note_slot_filled`, `cap::object::note_slot_released`).
    /// Zero is final: a slot with the Receive right is filled only from
    /// another one (a derive, copy, or move) or at creation, so once none is
    /// left no thread can receive on the endpoint again. A call or receive
    /// reads it under `lock` and fails with `NoReceiver` at zero; the release
    /// that made it zero then drains the queues ([`release_if_unreceivable`]).
    pub receivers: core::sync::atomic::AtomicU32,
}

#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the fields that are not `Send`, the wait queues and the wait-set back-pointer, \
              are read and written only under the endpoint's `lock`"
)]
// SAFETY: every access to the queues (`send`, `recv`) and to the wait-set
// back-pointer fields happens under `EndpointState::lock`, and
// `send_nonempty` and `receivers` are atomics, so moving the state between
// CPUs exposes no unsynchronised write.
unsafe impl Send for EndpointState {}
// SAFETY: concurrent shared access writes the queues and raw-pointer fields only under
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
            send: WaitQueue::new(),
            send_nonempty: core::sync::atomic::AtomicU32::new(0),
            recv: RecvQueue::new(),
            wait_set: core::ptr::null_mut(),
            wait_set_member_idx: 0,
            lock: crate::sync::Spinlock::new(),
            receivers: core::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Count a capability slot just filled with this endpoint and the Receive
    /// right ([`EndpointState::receivers`]).
    pub fn note_receiver_filled(&self)
    {
        self.receivers
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }

    /// Uncount a slot with the Receive right on this endpoint that is being
    /// freed, or whose dying `CSpace` releases it
    /// ([`EndpointState::receivers`]).
    pub fn note_receiver_released(&self)
    {
        let before = self
            .receivers
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
        debug_assert!(before > 0, "EndpointState receivers underflow");
    }

    /// Whether a capability slot with the Receive right on this endpoint is
    /// left ([`EndpointState::receivers`]). Read under `lock` by a call or a
    /// receive, which then fails at zero.
    pub fn has_receiver(&self) -> bool
    {
        self.receivers.load(core::sync::atomic::Ordering::Acquire) != 0
    }

    /// Republish the `send_nonempty` shadow from the current `send` queue.
    ///
    /// MUST be called under `lock` after every `send` mutation so the
    /// lockless `Acquire` reader in `wait_set::source_is_ready` observes the
    /// current level. `Release` pairs with that `Acquire`.
    ///
    /// # Safety
    /// Caller holds `self.lock` (serialises with all `send` writers).
    pub unsafe fn refresh_send_ready(&self)
    {
        self.send_nonempty.store(
            u32::from(!self.send.is_empty()),
            core::sync::atomic::Ordering::Release,
        );
    }
}

// ── Endpoint operations ───────────────────────────────────────────────────────

/// Tear down a rendezvous reply linkage whose park commit was refused
/// (`ParkCommit::RefusedStop`: a concurrent stop or exit, never a pending
/// upcall, which a call's park waits out; or `ParkCommit::RefusedWake`: a
/// coalesced wake; either refusal cancels the call): CAS the server's `reply_tcb` back to null (the caller's own dealloc
/// may have beaten us; if so it owns the teardown). On the CAS win (the
/// episode claim), stamp the cancelled disposition so the caller's resume
/// takes the error path, clear a timed call's deadline, which its sleep-list
/// add then refuses, and release the wake-in-flight claim so its dealloc can
/// proceed (#160). On a loss, another claimant owns the wake and the deadline,
/// and will clear both. Either way, republish `context_saved` (the park never
/// happened).
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
    // SAFETY: server is a valid TCB per the caller contract.
    let cleared = unsafe {
        (*server)
            .reply_tcb
            .compare_exchange(
                caller,
                core::ptr::null_mut(),
                core::sync::atomic::Ordering::AcqRel,
                core::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    };
    if cleared
    {
        // SAFETY: caller is a valid TCB per the caller contract, and the CAS
        // win is its episode's exclusive claim.
        unsafe {
            crate::sched::thread::stamp_cancelled_deposit(
                caller,
                crate::sched::thread::ParkKind::of_blocked(parked_state),
            );
        }
        // SAFETY: the CAS just claimed caller's park episode, which has not
        // woken; the sleep-list lock nests under the held endpoint lock.
        unsafe { crate::ipc::cancel_timed_entry(caller) };
        // SAFETY: caller is a valid TCB per the caller contract.
        unsafe {
            (*caller)
                .wake_in_flight
                .store(0, core::sync::atomic::Ordering::Release);
        }
    }
    // SAFETY: caller is a valid TCB per the caller contract.
    unsafe {
        (*caller)
            .context_saved
            .store(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Copy the message staged in `src`'s `ipc_msg` into `dst`'s: its header,
/// its `data_count` data words, and its `cap_count` handles, never the whole
/// [`Message`](super::message::Message).
///
/// # Safety
/// `src` and `dst` must be distinct valid TCBs; the caller holds `dst`'s
/// park claim, which owns its `ipc_msg`, and no thread writes `src`'s
/// `ipc_msg` during the copy.
#[cfg(not(test))]
unsafe fn copy_message(src: *const ThreadControlBlock, dst: *mut ThreadControlBlock)
{
    // SAFETY: src is valid and its ipc_msg is not written meanwhile
    // (contract).
    let msg = unsafe { &(*src).ipc_msg };
    // SAFETY: dst is valid, not src, and its ipc_msg is the caller's (contract).
    unsafe { (*dst).ipc_msg.copy_from(msg) };
}

/// This CPU's parked-receiver table when this CPU queues no thread but its
/// idle thread, the occupancy condition of the synchronous wake rule
/// ([`WakeHint::Sync`](crate::sched::WakeHint::Sync)), else `None`: a call
/// from a CPU with other work queued takes the longest-waiting receiver.
///
/// # Safety
/// Interrupts are off, so the CPU stays this one while the table is used.
#[cfg(not(test))]
unsafe fn local_receiver_table() -> Option<&'static super::recv_park::RecvParkTable>
{
    // SAFETY: the per-CPU pointer is installed before any thread runs.
    let scheduler = unsafe { crate::percpu::current_scheduler() };
    // Relaxed, a local read, as the synchronous wake rule reads it: it only
    // chooses a receiver, and every link this CPU made precedes it.
    if scheduler.has_queued_thread()
    {
        return None;
    }
    // SAFETY: as above, and interrupts are off (contract).
    Some(unsafe { crate::percpu::this_cpu_recv_parked() })
}

/// What [`endpoint_call`] did with a call.
#[cfg(not(test))]
pub enum CallRendezvous
{
    /// A receiver was waiting: it is dequeued and bound, and its wake is
    /// claimed by `wake_in_flight`. The caller MUST wake it with
    /// `enqueue_and_wake` after moving any caps, on the CPU
    /// `select_target_cpu` chooses under `hint`.
    Bound
    {
        /// The bound receiver.
        server: *mut ThreadControlBlock,
        /// [`WakeHint::Sync`](crate::sched::WakeHint::Sync) when the caller's
        /// park committed, so its `schedule()` follows before any return to
        /// user mode; [`WakeHint::None`](crate::sched::WakeHint::None) when
        /// the park was refused and the caller runs on.
        hint: crate::sched::WakeHint,
    },
    /// No receiver was waiting: the call is queued on the send queue.
    Queued,
    /// The endpoint has no receiver left ([`EndpointState::receivers`]): the
    /// call is refused, and nothing of the caller changed.
    NoReceiver,
}

/// Attempt an IPC call on `ep` from `caller`, whose message is staged in its
/// own `ipc_msg`.
///
/// Returns [`CallRendezvous::Bound`] if a receiver was waiting: the message is
/// copied into the receiver's `ipc_msg` ([`copy_message`]), and the calling
/// thread is committed to `parked_state`, unless the park is refused, in
/// which case the reply linkage is rolled back. Returns
/// [`CallRendezvous::Queued`] if no receiver was waiting: the calling thread,
/// its message left in its `ipc_msg` for the receive that binds it, is
/// committed `BlockedOnSend` on the send queue, unless the park is refused,
/// in which case it is unlinked and the call is stamped cancelled.
/// Returns [`CallRendezvous::NoReceiver`], before touching the caller or
/// either queue, when no capability with the Receive right on the endpoint is
/// left.
///
/// `parked_state` is the blocked state the caller commits when a receiver was
/// waiting: [`IpcThreadState::BlockedOnReply`] for a normal `SYS_IPC_CALL`, or
/// [`IpcThreadState::BlockedOnFault`] for kernel-synthesized fault delivery
/// (see [`crate::ipc::fault`]). On the send-queue path the caller commits
/// `BlockedOnSend` regardless; the fault discriminator carried on the caller's
/// `in_fault_delivery` flag tells a later [`endpoint_recv`] which awaiting-reply
/// state to transition it to.
///
/// `deadline` is the tick at which a timed call expires, or `0` for an untimed
/// one (a fault delivery is never timed). The one sleep-list entry it arms
/// bounds the whole call, its send park and its reply park
/// (core/kernel/docs/ipc-internals.md § Call Path (Sender)).
///
/// # Safety
/// `ep` and `caller` must be valid, and `caller` must be the running thread,
/// its message staged in its `ipc_msg`. Call with no scheduler lock and no
/// `ep.lock` held.
// too_many_lines: one rendezvous under one ep.lock hold, whose two arms (bind
// a waiting server, or park on the send queue) each commit the caller's park
// before the lock is released; the TCB accesses take one unsafe operation per
// block (docs/coding-standards.md § Unsafe Code).
#[expect(
    clippy::too_many_lines,
    reason = "one rendezvous whose arms commit the caller's park under one ep.lock hold"
)]
#[cfg(not(test))]
pub unsafe fn endpoint_call(
    ep: *mut EndpointState,
    caller: *mut ThreadControlBlock,
    parked_state: IpcThreadState,
    deadline: u64,
) -> CallRendezvous
{
    // SAFETY: ep validated by caller.
    let ep = unsafe { &mut *ep };

    // SAFETY: lock serialises the send/recv queues and the call/recv rendezvous
    // (reply is serialised by the `reply_tcb` claim); paired with unlock_raw below.
    let saved = unsafe { ep.lock.lock_raw() };

    // Read under ep.lock: the release that took the count to zero takes this
    // lock after its decrement to drain the queues, so a call either sees zero
    // here or queues before that drain, which releases it.
    if !ep.has_receiver()
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        return CallRendezvous::NoReceiver;
    }

    // Is a server waiting? A call from a CPU that queues no thread but its
    // idle thread takes the receiver its parked-receiver table records for
    // this endpoint, if any; any other call takes the longest-waiting
    // (core/kernel/docs/ipc-internals.md § Wait Queues).
    // SAFETY: ep.lock is held, with interrupts off, so the CPU stays this one.
    let local = unsafe { local_receiver_table() };
    // SAFETY: ep.lock is held, and `local` is this CPU's table for the hold.
    let server = unsafe { ep.recv.take(local) };
    if !server.is_null()
    {
        // The dequeue claimed the server's receive, so a timed receive's
        // entry goes with it, under ep.lock.
        // SAFETY: server was just dequeued under ep.lock.
        unsafe { crate::ipc::cancel_timed_entry(server) };
        #[expect(
            clippy::undocumented_unsafe_blocks,
            reason = "the two unsafe reads sit inside debug_assert! arguments, where a per-block \
                      SAFETY comment cannot be placed. Both are sound: server was just dequeued \
                      from the recv queue under ep.lock and is a live TCB"
        )]
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
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to an atomic field of caller, the running thread's valid TCB \
                      by this function's contract"
        )]
        // SAFETY: caller is the running thread's valid TCB (this function's
        // contract), and each field written is an atomic.
        unsafe {
            // Clear context_saved BEFORE the caller becomes wakeable. Every
            // reply-wake claimant reaches the caller through `reply_tcb`
            // (endpoint_reply, dealloc's BlockedOnReply detach and server arm,
            // cancel_ipc_block, the SYS_IPC_REPLY failure-path swap, and the
            // receive-entry release_unreplied_caller swap), Acquire-loading it.
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
            // A timed call's deadline, too, before reply_tcb is published:
            // the Release carries it to every claimant, which clears it with
            // its claim, and the sleep-list add after the commit below then
            // refuses rather than list a claimed park.
            (*caller)
                .sleep_deadline
                .store(deadline, core::sync::atomic::Ordering::Relaxed);
        }
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to an atomic field of server, a live TCB dequeued under the \
                      held ep.lock"
        )]
        // SAFETY: server was dequeued from the recv queue under the held ep.lock,
        // so it is a live TCB this call has claimed; each field is an atomic.
        unsafe {
            // The server reached the recv queue through endpoint_recv, which
            // released any binding it still held, so the slot is empty.
            debug_assert!(
                (*server)
                    .reply_tcb
                    .load(core::sync::atomic::Ordering::Relaxed)
                    .is_null(),
                "endpoint_call: server already holds a reply binding"
            );
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
        let hint = if committed == crate::sched::ParkCommit::Committed
        {
            crate::sched::WakeHint::Sync
        }
        else
        {
            crate::sched::WakeHint::None
        };
        if committed != crate::sched::ParkCommit::Committed
        {
            // Refused park (a stop won, or a stray coalesced wake; a pending
            // upcall refuses neither a call's park nor a fault delivery's);
            // tear down the reply linkage. Every refusal cancels the call.
            // SAFETY: caller / server validated; ep.lock held.
            unsafe { rollback_uncommitted_call(server, caller, parked_state) };
        }
        else if deadline != 0
        {
            // A claimant may already have cleared the deadline (the server
            // replied, or a stop cancelled the reply park, since the commit);
            // the add then refuses, and the claim owns the episode.
            // SAFETY: caller is the running thread, committed Blocked;
            // SLEEP_LIST_LOCK nests under ep.lock as a leaf.
            let _ = unsafe { crate::sched::sleep_list_add(caller) };
        }
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        // The message goes to the server after the lock: the dequeue claimed
        // the server, and its wake_in_flight pin, which only the caller's
        // enqueue_and_wake clears, owns its ipc_msg until that wake.
        // SAFETY: caller is the running thread, whose staged ipc_msg only the
        // server's reply writes, and the server cannot run before the wake;
        // server is the live TCB the dequeue claimed, not yet woken, and not
        // the caller (a running thread is on no receive queue).
        unsafe { copy_message(caller, server) };
        return CallRendezvous::Bound { server, hint };
    }

    // No server available — block caller on send queue.
    // Clear context_saved before enqueuing on the send queue.
    // See notification.rs notification_wait for the full rationale.
    // SAFETY: caller validated by syscall layer; context_saved is AtomicU32.
    unsafe {
        (*caller)
            .context_saved
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }
    // The message stays in caller.ipc_msg, which the queue's ep.lock owns from
    // the push below, for the receive that binds it.
    // SAFETY: caller is the running thread, on no wait queue; ep.lock held.
    unsafe {
        ep.send.push(caller);
    }
    // Publish the send-queue level before the wait-set notify below.
    // SAFETY: ep.lock held.
    unsafe { ep.refresh_send_ready() };
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
        // Refused park (a stop won, or a stray coalesced wake — each cancels
        // the call; a pending upcall refuses neither a call's park nor a fault
        // delivery's); unlink from the send queue.
        // SAFETY: ep.lock held; caller is a valid TCB.
        unsafe {
            let _ = ep.send.remove(caller);
        }
        // SAFETY: ep.lock held.
        unsafe { ep.refresh_send_ready() };
        // ep.lock has been held continuously since the enqueue above, so
        // this teardown is the episode's sole owner: stamp so the stopped
        // caller's restart resumes via the disposition.
        // SAFETY: caller is the running thread, which owns its own
        // in_fault_delivery, and this teardown holds its park claim.
        let kind = unsafe { crate::sched::thread::ParkKind::of_sender(caller) };
        // SAFETY: as above, this teardown is the episode's exclusive claimant
        // (a failed park commit's binding teardown under the held ep.lock).
        unsafe { crate::sched::thread::stamp_cancelled_deposit(caller, kind) };
        // SAFETY: caller is a valid TCB; context_saved is an atomic.
        unsafe {
            (*caller)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    else if deadline != 0
    {
        // SAFETY: caller is the running thread, committed Blocked and queued
        // under the ep.lock held since its push.
        unsafe { crate::ipc::arm_timed_park(caller, deadline, "endpoint_call") };
    }
    // Notify a registered wait set of every call queued, not only the one
    // that made the send queue non-empty: each arrival wakes one of the
    // threads waiting on the set (core/kernel/docs/ipc-internals.md
    // § Readiness Notification).
    if committed == crate::sched::ParkCommit::Committed && !ep.wait_set.is_null()
    {
        // SAFETY: wait_set validated non-null.
        unsafe { crate::ipc::wait_set::waitset_notify(ep.wait_set, ep.wait_set_member_idx) };
    }
    // SAFETY: paired with lock_raw above.
    unsafe { ep.lock.unlock_raw(saved) };
    CallRendezvous::Queued
}

/// Release the caller still bound to `server` by an earlier receive that was
/// never replied to.
///
/// The swap of `reply_tcb` to null is the episode claim, competing as any
/// reply-slot claim does with `cancel_ipc_block`, a timed call's expiry, and
/// the `dealloc_object(Thread)` client and server arms. The other claimants
/// cannot run meanwhile: `endpoint_reply`, the `SYS_IPC_REPLY` failure-path
/// swap and the receive's rebind run on this thread, and `endpoint_call`'s
/// rollback only while this server is parked. On a win the caller is
/// released as [`release_displaced_caller`] describes.
///
/// # Safety
/// `server` must be the running thread's valid TCB. Call with no scheduler
/// or endpoint lock held.
#[cfg(not(test))]
unsafe fn release_unreplied_caller(server: *mut ThreadControlBlock)
{
    // SAFETY: server valid per contract; reply_tcb is AtomicPtr.
    let caller = unsafe {
        (*server)
            .reply_tcb
            .swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel)
    };
    // SAFETY: a non-null caller is the binding the swap claimed; no lock held.
    unsafe { release_displaced_caller(caller) };
}

/// Release `caller`, a reply binding whose episode a swap of the server's
/// `reply_tcb` just claimed (at receive entry, or by the rebind of the next
/// caller); a null `caller` is no binding. The caller's call fails with
/// `Interrupted`, a fault-blocked caller is killed (one blocked on its
/// restartable syscall's user copy has that syscall fail with
/// `InvalidAddress`), or a caller blocked in an upcall delivery has the upcall
/// dropped and resumes; a timed call's sleep-list entry is removed; and the
/// caller is woken. The `wake_in_flight` pin set at bind keeps it alive until
/// that wake clears it.
///
/// # Safety
/// `caller` is null, or the valid TCB of a binding the caller's swap claimed.
/// Call with no scheduler or endpoint lock held.
#[cfg(not(test))]
unsafe fn release_displaced_caller(caller: *mut ThreadControlBlock)
{
    if caller.is_null()
    {
        return;
    }
    // SAFETY: the swap won the caller's episode, so this thread holds its park
    // claim, and its wake_in_flight pin keeps the TCB allocated until
    // enqueue_and_wake clears it.
    let kind = unsafe { crate::sched::thread::ParkKind::of_sender(caller) };
    // SAFETY: the swap is the episode's exclusive claim; the pin keeps caller
    // allocated.
    unsafe { crate::sched::thread::stamp_cancelled_deposit(caller, kind) };
    // SAFETY: the swap just claimed caller's park episode, which has not
    // woken; no sleep-list lock is held (contract).
    unsafe { crate::ipc::cancel_timed_entry(caller) };
    // SAFETY: the wake_in_flight pin keeps caller a valid TCB.
    let target_cpu =
        unsafe { crate::sched::select_target_cpu(caller, crate::sched::WakeHint::None) };
    // SAFETY: caller is valid (pinned), target_cpu came from
    // select_target_cpu, and no scheduler lock is held (contract).
    unsafe { crate::sched::enqueue_and_wake(caller, target_cpu) };
}

/// What a receive keeps of a sender it bound for its reply
/// (`bind_next_sender`): `cspace`, its `CSpace` identity, copied under
/// `ep.lock` as its message is copied into the receiver's `ipc_msg`. It
/// carries no pointer to the sender: once the receive drops the lock, a
/// canceller can claim the reply binding and wake the sender, which can exit
/// and be freed. The capability transfer resolves the source `CSpace` from
/// `cspace`.
#[cfg(not(test))]
pub struct BoundSender
{
    pub cspace: crate::cap::CSpaceIdentity,
}

/// Dequeue the first live sender on `ep` and bind it to `server` for the
/// reply, under `ep.lock`, which the caller holds, copying its message into
/// `server`'s `ipc_msg`.
///
/// Returns `Some((bound, displaced))` when a sender was bound: `displaced` is
/// the binding the rebind's swap displaced (null when the slot was empty),
/// which the caller MUST release with [`release_displaced_caller`] once it has
/// dropped `ep.lock`. Returns `None` when the send queue holds no live sender,
/// and `server`'s binding is then unchanged and its `ipc_msg` holds no word of
/// a skipped sender's message.
///
/// # Safety
/// `server` must be the running thread's valid TCB, and `ep.lock` held.
#[cfg(not(test))]
unsafe fn bind_next_sender(
    ep: &mut EndpointState,
    server: *mut ThreadControlBlock,
) -> Option<(BoundSender, *mut ThreadControlBlock)>
{
    // Dequeue successive senders, skipping any that died / were stopped
    // mid-rebind. The BlockedOnSend → BlockedOnReply transition publishes the
    // reply binding (`server.reply_tcb`, the caller's `ipc_state` /
    // `blocked_on_object`), and `dealloc_object(Thread)` uses the caller's
    // `(ipc_state, blocked_on_object)` to find and clear that binding when the
    // caller dies. `endpoint_call` keeps the two consistent by committing the
    // transition under the scheduler lock (`commit_blocked_under_local_lock`);
    // this path does the same via `commit_reply_rebind_under_local_lock`, which
    // publishes `reply_tcb` inside that hold. If the caller died or was stopped
    // concurrently the commit refuses and publishes nothing, so no stale
    // `reply_tcb` survives to fire against the freed/reused slot (#289
    // use-after-free / double-enqueue; #284 TCB-field corruption); this path
    // then retires the dequeued sender's episode and skips to the next.
    loop
    {
        // SAFETY: ep.lock is held.
        let caller = unsafe { ep.send.pop() };
        // Republish the send-queue level after each dequeue (the queue may now be
        // empty) for the lockless wait-set level self-heal (#285).
        // SAFETY: ep.lock held.
        unsafe { ep.refresh_send_ready() };
        if caller.is_null()
        {
            return None;
        }
        // The message is copied now, before the commit publishes the binding,
        // as the CSpace identity below is.
        // SAFETY: caller was dequeued under the held ep.lock, which owns its
        // queued ipc_msg; server is the running thread, which owns its own and
        // is on no send queue, so it is not caller.
        unsafe { copy_message(caller, server) };
        // The sender's CSpace identity is copied now, before the commit
        // publishes the binding: from that publication a canceller (a stop,
        // a timed call's expiry, a teardown) can claim the binding and wake
        // the caller, which can then exit and be freed while the receive's
        // capability transfer is still to run.
        // SAFETY: caller dequeued from the send queue under ep.lock, which a stop
        // or dealloc of a BlockedOnSend thread takes to unlink it, so it is
        // live.
        let cspace = unsafe { crate::cap::CSpaceIdentity::of_thread(caller) };
        // A fault sender (kernel-synthesized delivery) parks as BlockedOnFault
        // so its reply and its cancellation take the fault outcomes
        // (docs/fault-handling.md § Delivery, Resume, and Kill, § Kernel
        // Copies, § Asynchronous Upcalls); a normal call sender parks as
        // BlockedOnReply.
        // SAFETY: caller dequeued from the send queue; in_fault_delivery always valid.
        let parked = if unsafe { (*caller).in_fault_delivery }
        {
            IpcThreadState::BlockedOnFault
        }
        else
        {
            IpcThreadState::BlockedOnReply
        };
        // Caller transitions BlockedOnSend → `parked` (BlockedOnReply, or
        // BlockedOnFault for a fault sender): claim it for the eventual reply
        // wake BEFORE the rebind publishes reply_tcb, so dealloc's
        // BlockedOnReply / BlockedOnFault detach (which Acquire-loads
        // reply_tcb) sees the flag and gates on it before retype_free (#160).
        // SAFETY: caller dequeued from the send queue under ep.lock.
        unsafe {
            (*caller)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
        }
        // Commit the rebind under the caller's scheduler lock so the
        // (ipc_state, blocked_on_object) publication is serialised with
        // dealloc_object(Thread)'s all-CPU-locks Exited mark and SYS_THREAD_STOP.
        // A timed call keeps its sleep-list entry: the timeout bounds the
        // reply park too.
        // SAFETY: caller is a valid Blocked TCB dequeued from the send queue;
        // server is the running thread.
        let committed =
            unsafe { crate::sched::commit_reply_rebind_under_local_lock(caller, parked, server) };
        if let Some(displaced) = committed
        {
            return Some((BoundSender { cspace }, displaced));
        }
        // Refused: the caller is dying or stopped, and nothing was published.
        // The send-queue dequeue above is the episode claim (and why a
        // concurrent cancel_ipc_block's unlink lost and did not stamp): a
        // STOPPED caller resumes on restart via this disposition. Stamp
        // before releasing the wake-in-flight gate — after the release a
        // dying caller's dealloc may free the TCB. The refusal already
        // removed a timed call's entry. Then skip this dead sender.
        // SAFETY: caller validated; ep.lock held, and the send-queue dequeue
        // is the episode's exclusive claim.
        unsafe {
            crate::sched::thread::stamp_cancelled_deposit(
                caller,
                crate::sched::thread::ParkKind::of_blocked(parked),
            );
        }
        // SAFETY: caller is a valid TCB dequeued under ep.lock;
        // wake_in_flight is an atomic.
        unsafe {
            (*caller)
                .wake_in_flight
                .store(0, core::sync::atomic::Ordering::Release);
        }
        // The skipped sender's message leaves the receiver, whose resume
        // could otherwise publish it on a fail-open path.
        // SAFETY: server is the running thread, which owns its ipc_msg.
        unsafe { (*server).ipc_msg.begin(0, 0) };
    }
}

/// Why a receive bound no sender.
#[cfg(not(test))]
pub enum RecvMiss
{
    /// No sender was waiting. From [`endpoint_recv`], the server's park
    /// committed: it blocks at its `schedule()`.
    NoSender,
    /// No sender was waiting and [`endpoint_recv`]'s park was refused: the
    /// server is off the recv queue and runs on past its `schedule()`.
    ParkRefused,
    /// The endpoint has no receiver left ([`EndpointState::receivers`]): the
    /// receive's own capability was freed after its lookup. Nothing of the
    /// server changed under `ep.lock`.
    NoReceiver,
}

/// Attempt to receive on `ep` as `server`.
///
/// First releases a caller still bound from an earlier unreplied receive
/// (`release_unreplied_caller`). Returns `Ok(bound)` if a sender was waiting
/// (server continues running with the sender's message in its `ipc_msg`;
/// sender remains blocked on reply, and [`BoundSender`] holds what the
/// receive keeps of it).
/// Returns [`RecvMiss::NoSender`] if no sender was available and the server is
/// committed `BlockedOnRecv` on the recv queue, and [`RecvMiss::ParkRefused`]
/// if none was and the park was refused, in which case the server is unlinked
/// and, on a stop-won or upcall refusal, its park is stamped INTERRUPTED.
/// Returns [`RecvMiss::NoReceiver`], without parking,
/// when no capability with the Receive right on the endpoint is left.
///
/// `deadline` is the tick at which a timed receive's park expires, or `0` for
/// an untimed one.
///
/// # Safety
/// `ep` and `server` must be valid, and `server` must be the running thread.
/// Call with no scheduler lock and no `ep.lock` held.
#[cfg(not(test))]
#[expect(
    clippy::inline_always,
    reason = "the receive of SYS_IPC_RECV and SYS_IPC_REPLY_RECV is the one caller; out of \
              line, every round trip pays a frame and the callee-saved spills of this body"
)]
#[inline(always)]
pub unsafe fn endpoint_recv(
    ep: *mut EndpointState,
    server: *mut ThreadControlBlock,
    deadline: u64,
) -> Result<BoundSender, RecvMiss>
{
    // SAFETY: server is the running thread; no lock held (contract).
    unsafe { release_unreplied_caller(server) };

    // SAFETY: ep validated by caller.
    let ep = unsafe { &mut *ep };

    // SAFETY: lock serialises the send/recv queues and the call/recv rendezvous
    // (reply is serialised by the `reply_tcb` claim); paired with unlock_raw below.
    let saved = unsafe { ep.lock.lock_raw() };

    // Read under ep.lock, as `endpoint_call` reads it: a receiver parked after
    // the drain that followed the count's last decrement would never be woken.
    if !ep.has_receiver()
    {
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        return Err(RecvMiss::NoReceiver);
    }

    // SAFETY: server is the running thread; ep.lock held.
    if let Some((bound, displaced)) = unsafe { bind_next_sender(ep, server) }
    {
        // Entry released any earlier binding, and only this thread binds.
        debug_assert!(
            displaced.is_null(),
            "endpoint_recv: server already held a reply binding"
        );
        // SAFETY: paired with lock_raw above.
        unsafe { ep.lock.unlock_raw(saved) };
        return Ok(bound);
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
    // The push records the park in this CPU's parked-receiver table, where a
    // call from this CPU looks for it.
    // SAFETY: ep.lock is held, with interrupts off, so the CPU stays this one.
    let table = unsafe { crate::percpu::this_cpu_recv_parked() };
    // SAFETY: server is the running thread, on no wait queue; ep.lock is held,
    // and `table` is this CPU's for the hold.
    unsafe { ep.recv.push(server, table) };
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
    let parked = committed == crate::sched::ParkCommit::Committed;
    if !parked
    {
        // Refused park; unlink from the recv queue. ep.lock has been held
        // across enqueue/commit/rollback, so the rollback owns the episode.
        // A stop-won or upcall refusal stamps INTERRUPTED so the server's
        // resume reports the cancellation instead of publishing a stale
        // ipc_msg; a coalesced-wake refusal leaves the deposit standing.
        // SAFETY: ep.lock held; server is a valid TCB.
        unsafe {
            let _ = ep.recv.remove(server);
        }
        if committed == crate::sched::ParkCommit::RefusedStop
        {
            // SAFETY: the rollback under the continuously held ep.lock is
            // the episode's exclusive claimant.
            unsafe {
                crate::sched::thread::stamp_park_deposit(
                    server,
                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                );
            }
        }
        // SAFETY: server is a valid TCB; context_saved is an atomic.
        unsafe {
            (*server)
                .context_saved
                .store(1, core::sync::atomic::Ordering::Relaxed);
        }
    }
    else if deadline != 0
    {
        // SAFETY: server is the running thread, committed Blocked and queued
        // under the ep.lock held since its push.
        unsafe { crate::ipc::arm_timed_park(server, deadline, "endpoint_recv") };
    }
    // SAFETY: paired with lock_raw above.
    unsafe { ep.lock.unlock_raw(saved) };
    Err(
        if parked
        {
            RecvMiss::NoSender
        }
        else
        {
            RecvMiss::ParkRefused
        },
    )
}

/// Receive on `ep` as `server` without parking (`SYS_IPC_RECV` try-once).
///
/// Returns `Ok(bound)` when a sender was waiting, bound as
/// [`endpoint_recv`] binds it; the caller this binding displaced (one still
/// bound from an earlier unreplied receive) is released only then, after
/// `ep.lock` drops. Returns [`RecvMiss::NoSender`] when no sender was
/// waiting, and [`RecvMiss::NoReceiver`] when no capability with the Receive
/// right on the endpoint is left; either leaves `server`'s earlier binding in
/// place, so a later `SYS_IPC_REPLY` still reaches that caller.
///
/// # Safety
/// `ep` and `server` must be valid, and `server` must be the running thread.
/// Call with no scheduler lock and no `ep.lock` held.
#[cfg(not(test))]
pub unsafe fn endpoint_try_recv(
    ep: *mut EndpointState,
    server: *mut ThreadControlBlock,
) -> Result<BoundSender, RecvMiss>
{
    // SAFETY: ep validated by caller.
    let ep = unsafe { &mut *ep };
    // SAFETY: paired with unlock_raw below.
    let saved = unsafe { ep.lock.lock_raw() };
    let bound = if ep.has_receiver()
    {
        // SAFETY: server is the running thread; ep.lock held.
        unsafe { bind_next_sender(ep, server) }.ok_or(RecvMiss::NoSender)
    }
    else
    {
        Err(RecvMiss::NoReceiver)
    };
    // SAFETY: paired with lock_raw above.
    unsafe { ep.lock.unlock_raw(saved) };
    let (bound, displaced) = bound?;
    // SAFETY: the rebind's swap claimed `displaced`; no lock held.
    unsafe { release_displaced_caller(displaced) };
    Ok(bound)
}

/// Claim the caller bound in `server.reply_tcb` for a reply.
///
/// Claims the reply binding (CAS `server.reply_tcb` from the bound caller to
/// null) and returns the claimed caller, before anything reads it: the claim
/// is what keeps the caller live, because its `wake_in_flight` pin, set when
/// its park published the binding, now waits for this claimant's wake, and a
/// `dealloc_object(Thread)` of the caller waits for that pin before it frees
/// the TCB. The CAS win makes the syscall layer the episode's sole depositor,
/// so it MUST stage the reply (or the `IPC_REPLY_TRANSFER_FAILED` sentinel)
/// in the caller's `ipc_msg`, stamp the disposition (REPLY, or
/// `fault_outcome` and the episode for a `BlockedOnFault` caller), and then
/// wake it with `enqueue_and_wake`. Returns `None` if no binding exists or a
/// concurrent claimant won.
///
/// # Safety
/// `server` must be the calling thread's valid TCB. Call with no scheduler or
/// endpoint lock held.
#[cfg(not(test))]
pub unsafe fn endpoint_reply(server: *mut ThreadControlBlock) -> Option<*mut ThreadControlBlock>
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
    // CAS-claim the reply slot: `cancel_ipc_block` and the
    // `dealloc_object_one(Thread)` client and server arms CAS this slot
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
        // A concurrent `cancel_ipc_block`, timed call's expiry, or dealloc
        // arm already cleared the slot; it owns the wake (and the client may
        // already be Stopped or Exited).
        return None;
    }
    // The CAS win ends the call's episode, so a timed call's entry goes now,
    // before the wake: a later timed park of the caller arms a new one.
    // SAFETY: the CAS claimed caller, whose wake_in_flight pin keeps it live.
    unsafe { crate::ipc::cancel_timed_entry(caller) };

    // `caller.wake_in_flight` was set to 1 when the caller became
    // BlockedOnReply or BlockedOnFault (in endpoint_call / endpoint_recv,
    // before publishing `reply_tcb`); the claimant's enqueue_and_wake clears
    // it once the wake commits. We won the reply_tcb CAS above, so no other
    // claimant (dealloc / cancel) touches the caller, and its dealloc waits
    // for that wake. See core/kernel/docs/scheduling-internals.md § Cross-CPU
    // TCB Ownership.
    Some(caller)
}

// ── Release when no receiver is left ─────────────────────────────────────────

/// Release the waiters of the endpoint `obj` when no capability with the
/// Receive right on it is left ([`EndpointState::receivers`]); a no-op for
/// any other object, or an endpoint that still has one.
///
/// Called before the release of the reference a freed capability slot held
/// (`SYS_CAP_DELETE`, a revoke's `dealloc_revoked`, a move's source release,
/// and a dying `CSpace`'s release of its slots), after the slot was uncounted.
/// The release whose decrement made the count zero reads it here, after its
/// own decrement, so it drains the queues ([`release_waiters`]). A later one
/// drains, alongside it, the waiters its batches have not yet released, if
/// any: a call or receive that reads zero under `ep.lock` queues nothing, so
/// every release returns with both queues empty.
///
/// # Safety
/// `obj` must carry a reference the caller owns. Call with no
/// `DERIVATION_LOCK`, `CSpace`, IPC, scheduler, or sleep-list lock held, where
/// interrupts may be taken (the drain opens interrupt windows).
#[cfg(not(test))]
pub unsafe fn release_if_unreceivable(
    obj: core::ptr::NonNull<crate::cap::object::KernelObjectHeader>,
)
{
    // SAFETY: the caller's reference keeps obj live.
    if unsafe { obj.as_ref() }.obj_type != crate::cap::object::ObjectType::Endpoint
    {
        return;
    }
    // SAFETY: an Endpoint header is at offset 0 of its EndpointObject, live by
    // the caller's reference.
    let state = unsafe { (*obj.as_ptr().cast::<crate::cap::object::EndpointObject>()).state };
    // SAFETY: a non-null state is the endpoint's, live with it.
    if state.is_null() || unsafe { (*state).has_receiver() }
    {
        return;
    }
    // SAFETY: state is live (above); the lock preconditions are the caller's.
    unsafe { release_waiters(state) };
}

/// Release every thread queued on `ep`, which no thread can receive on
/// again: each queued caller with its park stamped
/// [`PARK_DISPOSITION_NO_RECEIVER`](crate::sched::thread::PARK_DISPOSITION_NO_RECEIVER)
/// (a queued fault delivery with `FAULT_OUTCOME_NO_RECEIVER`, so the fault is
/// unhandled), and each parked receiver the same way; a timed park's sleep-list
/// entry goes with it, and `send_nonempty` is republished. The senders go
/// first, then the receivers, each queue in its order.
///
/// Run by [`release_if_unreceivable`] and by the endpoint's dealloc, where no
/// slot names the endpoint, so none with the Receive right does.
///
/// Each waiter is popped from its queue under `ep.lock` (its episode claim),
/// pinned (`wake_in_flight = 1`, the #160 discipline, so a
/// `dealloc_object(Thread)` that finds it gone from the queue waits at its
/// wake-in-flight gate for this drain's `enqueue_and_wake` rather than free
/// the TCB under it), stamped, and woken, all in one hold of the lock, as
/// core/kernel/docs/scheduling-internals.md § Lock Hierarchy rule 5 allows.
/// The drain holds the lock for [`super::DRAIN_BATCH_WAITERS`] waiters at a
/// time and opens an interrupt window between batches
/// ([`super::drain_in_batches`]): the waiters it has not reached stay queued
/// and unclaimed meanwhile, so a canceller, a timed park's expiry or the
/// waiter's own dealloc claims one by its usual removal under `ep.lock`, and
/// no thread joins either queue, since a call or a receive reads
/// [`EndpointState::receivers`] under the lock and that count's zero is
/// final. Two drains of one endpoint (two releases that each read zero) take
/// turns at the queues; each pop is one claim.
///
/// # Safety
/// `ep` must be a live `EndpointState` with no receiver left, live until
/// this returns. Call with no `DERIVATION_LOCK`, `CSpace`, IPC, scheduler,
/// or sleep-list lock held, where interrupts may be taken.
#[cfg(not(test))]
pub unsafe fn release_waiters(ep: *mut EndpointState)
{
    // SAFETY: ep is live (contract).
    let lock = unsafe { &(*ep).lock };
    debug_assert!(
        // SAFETY: ep is live (contract); receivers is atomic.
        !unsafe { (*ep).has_receiver() },
        "release_waiters: the endpoint still has a receiver"
    );
    // SAFETY: the returned flags are passed, through the drain, to the
    // unlock_raw below.
    let mut saved = unsafe { lock.lock_raw() };
    let has_waiter = || {
        // SAFETY: ep is live; ep.lock is held while the drain calls this.
        let state = unsafe { &*ep };
        !state.send.is_empty() || !state.recv.is_empty()
    };
    // A queued fault sender (its handler never received) takes the
    // no-receiver kill outcome when woken (its copy fault fails the syscall,
    // its upcall is dropped): its resume runs the fault helper, which reads
    // `fault_outcome`. A caller or a receiver gets NO_RECEIVER, so its
    // syscall's resume returns the error instead of reading the deposit.
    let release_next = || {
        // SAFETY: ep is live; ep.lock is held while the drain calls this, and
        // the drain calls it only while a queue holds a waiter.
        let state = unsafe { &mut *ep };
        let sender = !state.send.is_empty();
        let tcb = if sender
        {
            // SAFETY: as above.
            let tcb = unsafe { state.send.pop() };
            // SAFETY: as above; ep.lock serialises every send-queue writer.
            unsafe { state.refresh_send_ready() };
            tcb
        }
        else
        {
            // SAFETY: as above.
            unsafe { state.recv.pop() }
        };
        let kind = if sender
        {
            // SAFETY: tcb is a valid TCB whose park this drain has claimed by
            // popping it under ep.lock.
            unsafe { crate::sched::thread::ParkKind::of_sender(tcb) }
        }
        else
        {
            crate::sched::thread::ParkKind::Call
        };
        // SAFETY: tcb is a valid TCB whose park episode this drain has
        // claimed under ep.lock; exactly one stamp per episode.
        unsafe { crate::sched::thread::stamp_no_receiver_deposit(tcb, kind) };
        // A timed park's entry ends with its episode.
        // SAFETY: tcb's park episode was just claimed under ep.lock and is
        // not yet woken; no sleep-list lock is held.
        unsafe { crate::ipc::cancel_timed_entry(tcb) };
        // Claim for wake under ep.lock (#160); cleared by enqueue_and_wake.
        // SAFETY: tcb is a valid TCB; ep.lock held.
        unsafe {
            (*tcb)
                .wake_in_flight
                .store(1, core::sync::atomic::Ordering::Release);
        }
        // SAFETY: tcb is a valid, initialised TCB.
        let target_cpu =
            unsafe { crate::sched::select_target_cpu(tcb, crate::sched::WakeHint::None) };
        // SAFETY: tcb is a valid TCB; target_cpu came from
        // select_target_cpu.
        unsafe { crate::sched::enqueue_and_wake(tcb, target_cpu) };
    };
    // SAFETY: ep.lock is held with flags `saved` and no other lock; no waiter
    // joins either queue (above); interrupts may be taken (contract).
    unsafe { super::drain_in_batches(lock, &mut saved, has_waiter, release_next) };
    // SAFETY: `saved` is the flags of the drain's last hold of this lock.
    unsafe { lock.unlock_raw(saved) };
}
