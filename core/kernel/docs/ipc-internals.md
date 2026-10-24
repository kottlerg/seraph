# IPC Subsystem Internals

This document covers the implementation of the IPC subsystem. IPC semantics —
the call/reply model, notifications, event queues, wait sets, and capability transfer —
are specified in [docs/ipc-design.md](../../../docs/ipc-design.md). This document
describes how those semantics are implemented in the kernel.

The IPC subsystem comprises four kernel object types:

1. **Endpoint** — synchronous call/reply rendezvous point
2. **Notification** — coalescing asynchronous bitmask notification
3. **EventQueue** — ordered asynchronous ring buffer
4. **WaitSet** — multi-source aggregation for multiplexed waiting

---

## Endpoint (`ipc/endpoint.rs`)

### Object Structure

```rust
pub struct EndpointState
{
    /// Threads waiting to send (callers blocked in SYS_IPC_CALL), FIFO.
    send_head: *mut ThreadControlBlock,
    send_tail: *mut ThreadControlBlock,

    /// 1 iff send_head is non-null: the atomic shadow the wait-set readiness
    /// check reads without the lock.
    send_nonempty: AtomicU32,

    /// Threads waiting to receive (servers blocked in SYS_IPC_RECV), FIFO.
    recv_head: *mut ThreadControlBlock,
    recv_tail: *mut ThreadControlBlock,

    /// Wait-set back-pointer (null if not in any wait set) and this
    /// endpoint's member index in that set.
    wait_set: *mut u8,
    wait_set_member_idx: u8,

    /// Lock protecting the queues and the call/recv rendezvous.
    lock: Spinlock,
}
```

The endpoint keeps no state field: the pseudo-code below tests the queues directly (a waiting
receiver is a non-empty receive queue, a waiting sender a non-empty send queue).

### Wait Queues

Every blocked thread is linked into its object's queue through intrusive link fields in the TCB,
used only while the thread is blocked on an IPC object (a blocked thread waits on one object, so
one set of links suffices). No separate allocation. Threads are served in arrival order.

- An endpoint keeps a linear send queue and a linear receive queue, each a head and tail pointer,
  chained through `tcb.ipc_wait_next`.
- A notification, event queue, or wait set keeps an `ipc::WaitQueue`: a circular doubly linked
  list through `tcb.ipc_wait_next` and `tcb.ipc_wait_prev` storing only its tail (the head is the
  tail's successor), so it is pointer-sized. Each queued TCB's `ipc_wait_queue` tag names the
  queue, so push, pop, removal of any waiter, and the membership test are O(1) and touch only the
  TCBs they link or unlink. A wait set holds at most one waiter (§ Wait Path).

### Call Path (Sender)

`SYS_IPC_CALL` execution on the sender's thread:

```
1. Resolve endpoint_cap → verify Send rights
2. Validate message arguments (data_count, cap_slots)
3. Acquire endpoint lock
4. if the recv queue is non-empty:
   // Fast path: receiver is already waiting
   a. recv_tcb = head of the endpoint's recv queue (dequeued)
   b. Stage the message in recv_tcb.ipc_msg: label/counts/badge from the
      sender's saved register state, data words read from the sender's IPC
      buffer page (the receiver writes them to its own page when it resumes)
   c. Pin current_tcb for its eventual reply wake (wake_in_flight = 1),
      publish the caller binding (the server's reply capability):
      recv_tcb.reply_tcb = current_tcb (Release store into an empty slot;
      the server's receive released any earlier binding), then claim
      recv_tcb for its wake (recv_tcb.wake_in_flight = 1)
   d. commit_blocked_under_local_lock(current_tcb, BlockedOnReply or
      BlockedOnFault, recv_tcb); on a refusal, roll the binding back
      (rollback_uncommitted_call)
   e. Release endpoint lock
   f. Transfer capability slots (see capability-internals.md)
   g. enqueue_and_wake(recv_tcb) on its selected CPU
   h. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then
      return through the disposition

5. else (no receiver yet):
   // Slow path, all under the endpoint lock until step e
   a. Store the message in current_tcb.ipc_msg
   b. Append current_tcb to the endpoint's send queue (send_nonempty = 1)
   c. commit_blocked_under_local_lock(current_tcb, BlockedOnSend, ep);
      on a refusal, unlink current_tcb from the send queue and stamp the
      call cancelled (INTERRUPTED, or KILL for a fault delivery)
   d. If the park committed and made the send queue non-empty, notify the
      endpoint's wait set (waitset_notify)
   e. Release endpoint lock
   f. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then
      return through the disposition
```

**Message copy:** The label, counts, badge, and packed cap handles travel in
saved register state (message format per
[docs/ipc-design.md § Message Format](../../../docs/ipc-design.md#message-format)).
Data words travel through the per-thread IPC buffer pages: when `data_count` > 0
the kernel reads the words from the sender's registered page and writes them
into the receiver's registered page; the delivered cap-transfer result block is
likewise written into the receiver's page. The error surface is read-side only,
per [syscalls.md § `SYS_IPC_BUFFER_SET`](syscalls.md#sys_ipc_buffer_set-42): a
sender (or replier) with no registered page fails with `InvalidArgument`, and a
sender page unmapped at copy time surfaces the copy fault (`InvalidAddress`),
while delivery-side writes are best-effort — an unregistered or unmapped
receiver page silently drops the data words and cap results; the drop fails no
syscall on either side. Nothing is allocated on the path.

### Receive Path (Server)

`SYS_IPC_RECV` execution on the server's thread:

```
1. Resolve endpoint_cap → verify Receive rights, and pre-allocate the
   worst-case cap-slot headroom in the server's CSpace; a failure returns
   here and leaves any earlier binding in place
2. Release an unreplied caller (release_unreplied_caller, no lock held):
   swap current_tcb.reply_tcb to null; if it held a caller bound by an
   earlier receive the server never replied to, stamp that caller's call
   cancelled (INTERRUPTED, or KILL for a fault-blocked caller) and
   enqueue_and_wake it. The binding published below therefore never
   overwrites another.
3. Acquire endpoint lock
4. if the send queue is non-empty:
   // Fast path: a sender is waiting
   a. sender_tcb = head of the send queue (dequeued)
   b. if the send queue is now empty: send_nonempty = 0
   c. Claim sender_tcb for the reply wake (wake_in_flight = 1), then publish
      the caller binding (the server's reply capability):
      current_tcb.reply_tcb = sender_tcb (Release store)
   d. commit_reply_rebind_under_local_lock(sender_tcb, BlockedOnReply or
      BlockedOnFault); if the sender died or was stopped meanwhile, CAS the
      binding back to null, stamp the sender cancelled on a win, and retry
      from a with the next sender
   e. Release endpoint lock
   f. Copy the staged message from sender_tcb.ipc_msg (label/counts plus the
      data words read at call time) into the server's trap frame and IPC
      buffer page, and transfer capability slots
   g. Return to server with message (no blocking)

5. else (no sender yet):
   // Slow path, all under the endpoint lock until step c
   a. Append current_tcb to the endpoint's recv queue
   b. commit_blocked_under_local_lock(current_tcb, BlockedOnRecv, ep); on a
      refusal, unlink current_tcb from the recv queue, and stamp INTERRUPTED
      if the refusal was a stop (RefusedStop)
   c. Release endpoint lock
   d. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then
      return through the disposition
```

### Reply Path

`SYS_IPC_REPLY` execution on the server's thread:

```
1. Peek caller_tcb = current_tcb.reply_tcb (Acquire load)
   (the reply capability is this caller binding, a per-thread field outside
   the CSpace; the peeked caller is read before the step-3 claim and is not
   pinned, so a concurrent dealloc can free it first, #443)
2. Unless caller_tcb is BlockedOnFault (a fault reply, whose data words and
   caps the kernel ignores): read the data words and pre-validate the reply
   cap slots; when caps are attached, return InvalidCapability if no caller
   is bound (no swap), then pre-allocate the slots in the caller's CSpace
   (resolved through the registry); on any of these failures, swap
   current_tcb.reply_tcb to null and, if it held a caller, wake that caller
   with the IPC_REPLY_TRANSFER_FAILED label
3. Claim and clear the binding: CAS current_tcb.reply_tcb from caller_tcb
   to null; a lost CAS means a concurrent canceller owns the caller's wake;
   a null binding or a lost CAS → InvalidCapability
4. Stage the reply in caller_tcb.ipc_msg: label/count for the caller's
   return registers, data words for the caller to write to its own IPC
   buffer page when it resumes
5. If caller_tcb is BlockedOnFault: skip step 6, record RESUME/KILL from
   the label in caller_tcb.fault_outcome, stamp the episode, and go to step 7
6. Transfer reply capability slots; stamp REPLY. If the transfer fails after
   the claim, deposit the IPC_REPLY_TRANSFER_FAILED reply instead, wake the
   caller (step 7), and return the error to the server
7. enqueue_and_wake(caller_tcb) on its selected CPU; return to the server
```

### Park Dispositions and Episodes

Every park is an **episode**. The TCB carries `park_disposition`
(`NONE`/`REPLY`/`INTERRUPTED`); debug builds add
`park_episode`/`deposit_episode` counters for the call/fault protocol's
tripwire. A `sys_ipc_call` episode has exactly one deposit (fail-closed,
below); the non-call parking surfaces (`sys_notification_wait`,
`sys_event_recv`, `sys_ipc_recv`, `sys_wait_set_wait`, `sys_thread_sleep`)
use the disposition only as a cancellation channel (fail-open, below).

**Episode start (ownership window).** Every parking syscall resets `park_disposition = NONE`
*before* its source-side registration publishes any claimable state (`reply_tcb`, a wait-queue link
— an endpoint queue or a source's waiter queue — or the Blocked commit for a plain sleep) —
`sys_ipc_call` via `open_call_episode` (which also bumps `park_episode`), the non-call surfaces via
`open_park_episode` (no bump: their genuine wakers deliberately do not stamp, so the open/stamp
counter pairing holds only for call/fault episodes). Until that publication the parking thread
exclusively owns its wake fields, so the reset cannot race a deposit. `fault_dispatch` bumps the
episode the same way next to its `fault_outcome = Pending` reset.

**Claim-then-stamp rule.** A site may stamp the episode only after winning
the episode's exclusive wake claim. Per the DEPOSIT model (rule 8 /
[sched-ipc-redesign.md](sched-ipc-redesign.md) § 2.1) every deposit now carries a disposition;
the resume remains deposit-read, never re-check. Stamps are Release-ordered after
the payload write; the resume's Acquire load orders the payload reads after
it. The wake chain (stamp → `enqueue_and_wake`'s `sched_lock`/run-queue
Release → dispatch Acquire → resume) carries the stamp; for the
wake-before-park refusal, `wake_pending` is written and consumed under the
same `(*tcb).sched_lock`, which carries it to the refusing parker (see
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 8).

| Deposit site | Exclusive claim | Stamp |
|---|---|---|
| `sys_ipc_reply` normal arm | `reply_tcb` CAS won in `endpoint_reply` | episode + REPLY (after cap-result writes) |
| `sys_ipc_reply` cap-transfer refusal arm (`deposit_transfer_failed_reply`) | same CAS | episode + REPLY (the synthetic `IPC_REPLY_TRANSFER_FAILED` message replaces the staged reply wholesale; the server receives the transfer error) |
| `sys_ipc_reply` fault-RESUME arm | same CAS | episode only (`fault_outcome` carries RESUME/KILL) |
| `fail_reply_and_wake_caller` (via `deposit_transfer_failed_reply`) | `reply_tcb.swap(null)` non-null | episode + REPLY (synthetic failure reply) |
| `release_unreplied_caller` (`SYS_IPC_RECV` entry, a caller bound by an earlier unreplied receive) | `reply_tcb.swap(null)` non-null | episode + INTERRUPTED (faulter: episode + KILL) |
| `cancel_ipc_block` BlockedOnReply / BlockedOnFault arms | `reply_tcb` CAS | episode + INTERRUPTED / episode + KILL |
| `cancel_ipc_block` BlockedOnSend arm | send-queue unlink of the snapshotted park (`park_seq` equal to the cancel's snapshot) under `ep.lock` (a lost unlink hands the episode to the racing rebind chain, to the endpoint's dealloc drain, or to a concurrent cancel that already claimed it; or the thread's own `dealloc_object(Thread)` unlinked it, unstamped, as it dies) | episode + INTERRUPTED (faulter: episode + KILL) |
| `dealloc_object(Thread)` reply-bound wake | `reply_tcb` CAS under all-CPU locks | episode + INTERRUPTED (faulter: episode + KILL) |
| `endpoint_call` rendezvous commit-fail teardown | teardown `reply_tcb` CAS win | episode + INTERRUPTED / KILL — without it a legitimate stop→start resume has no deposit |
| `endpoint_call` send-queue commit-fail teardown | `ep.lock` held continuously from link to unlink | episode + INTERRUPTED / KILL |
| `endpoint_recv` rebind-fail teardown | teardown `reply_tcb` CAS win (stamped before the wake-in-flight release — a dying caller's dealloc may free the TCB after it) | episode + INTERRUPTED / KILL |
| `dealloc_object(Thread)` dying-client detach arms | `reply_tcb` CAS | **no stamp** — the claimed thread is the one being freed; it never resumes |
| `cancel_ipc_block` BlockedOnRecv arm | recv-queue unlink of the snapshotted park (`park_seq` equal to the cancel's snapshot) under `ep.lock` (a lost unlink means one of: a caller already deposited into `ipc_msg` (its delivery stands); the endpoint's dealloc drain stamped the park `INTERRUPTED`; a concurrent cancel already claimed it; or the thread's own `dealloc_object(Thread)` unlinked it, unstamped, as it dies) | INTERRUPTED |
| `cancel_ipc_block` BlockedOnNotification / EventQueue / WaitSet arms | removal of the snapshotted park (`park_seq` equal to the cancel's snapshot) from the source's waiter queue under the source lock (every genuine waker claims under the same lock) | INTERRUPTED |
| `cancel_ipc_block` plain-sleep cleanup | `sleep_list_remove` returning `true` under the target's `sched_lock` (the deadline was still pending; the timer pop clears it under the same `SLEEP_LIST_LOCK`, and a commit→add window cancel makes the later add refuse; on a full list the sleeper's own withdrawal makes the same `sleep_list_remove` claim, so a cancel that wins leaves the sleeper descheduled with the stamp, which a stopped sleeper returns as `Interrupted` when restarted) | INTERRUPTED |
| `dealloc_object(Notification)` wake of every waiter (`interrupt_all_waiters`) | removal from the waiter queue under `sig.lock` | INTERRUPTED |
| `event_queue_drop` (`dealloc_object(EventQueue)`) wake of every waiter | removal from the waiter queue under `eq.lock` | INTERRUPTED |
| `wait_set_drop` (`dealloc_object(WaitSet)`) wake of every waiter | removal from the waiter queue under `ws.lock` | INTERRUPTED |
| `dealloc_object(Endpoint)` send-queue drain | whole-queue detach under `ep.lock` | episode + INTERRUPTED (faulter: episode + KILL) |
| `dealloc_object(Endpoint)` recv-queue drain | whole-queue detach under `ep.lock` | INTERRUPTED |
| park-helper refused-commit rollbacks (`notification_wait`, `event_queue_recv`, `waitset_wait`, `endpoint_recv`) | source lock held continuously from publish to rollback — no waker ever saw the queued entry | INTERRUPTED on `ParkCommit::RefusedStop` only; a `RefusedWake` rollback must leave the coalesced deposit deliverable |

**Resume (call/fault episodes — fail-closed).** `sys_ipc_call` consumes the
disposition: REPLY reads `ipc_msg`; INTERRUPTED returns `Interrupted` without
touching `ipc_msg`; NONE is a protocol violation: debug builds assert (naming
tid/park-episode/deposit-episode — the #352-class spurious-resume tripwire,
also checked in `fault_dispatch`'s resume), release builds fail closed with
`Interrupted` rather than surfacing stale `ipc_msg` bytes as a success.
`fault_dispatch`'s resume fails closed the same way: any `fault_outcome` other
than RESUME, a PENDING left by an unstamped wake included, kills the thread
(the `fault_outcome` row of
[scheduling-internals.md § Atomic Ordering Invariants](scheduling-internals.md#atomic-ordering-invariants)).

**Resume (non-call parks — fail-open).** Each non-call parking syscall
consumes the disposition via `consume_park_interrupted` before reading its
wake deposit: INTERRUPTED returns `Interrupted` without touching
`wakeup_value`/`timed_out`/`ipc_msg` (clearing the per-surface leftovers);
NONE proceeds on the normal deposit-read path. Fail-open is required, not a
convenience: genuine wakers for these surfaces do not stamp, because a
coalesced wake-before-park deposit (`ParkCommit::RefusedWake`) has no
claimable episode to stamp, and a recv whose cancel lost the unlink race to a
concurrent `endpoint_call` must still publish the already-deposited message —
its caller is parked `BlockedOnReply` on it and would otherwise be stranded.
A fail-closed consume here would turn every unstamped genuine wake into a
lost wakeup. The cancellation claims are exclusive against all genuine wakers
(same source lock / `SLEEP_LIST_LOCK`), so INTERRUPTED-stamped episodes are
exactly the cancelled ones. The pre-#363 trap-frame `Interrupted` pokes are
gone: every resume rewrites the return registers, so a poke never survived —
the disposition is the only cancellation channel.

### Waking the Recipient

The kernel performs no direct thread switch on IPC. Every call rendezvous and
every reply wakes the recipient through `enqueue_and_wake` on the CPU
`select_target_cpu` chooses, after the endpoint lock is released (call) or the
`reply_tcb` claim is won (reply, which takes no endpoint lock); the run queue
decides when it runs. A receive first wakes any caller it releases from an
earlier unreplied binding (its call returns `Interrupted`, or a faulter is
killed; § Receive Path step 2). Beyond that, a receive that finds a waiting
sender wakes no thread: the server continues and the sender stays parked
awaiting the reply (`BlockedOnReply`, or `BlockedOnFault` for a fault sender). The call path then
parks the caller through `schedule`; the reply path returns to the server.

---

## Notification (`ipc/notification.rs`)

### Object Structure

```rust
pub struct NotificationState
{
    /// Atomic bitmask: set bits represent pending events.
    pub bits: AtomicU64,

    /// Threads waiting in SYS_NOTIFICATION_WAIT, in arrival order (a
    /// WaitQueue: a circular FIFO through each TCB's ipc_wait_next and
    /// ipc_wait_prev storing only its tail; see § Wait Queues).
    /// Protected by `lock` (see scheduling-internals.md § Lock Hierarchy).
    pub waiters: WaitQueue,

    /// Optional wait-set back-pointer (null if not in any wait set).
    pub wait_set: *mut u8,
    pub wait_set_member_idx: u8,

    /// Lock-free fast-path flag: non-zero iff a waiter or wait-set is registered.
    /// Read with a SeqCst fence in the notification_send fast path; the Dekker pair
    /// is documented in scheduling-internals.md § Atomic Ordering Invariants.
    pub has_observer: AtomicU8,

    /// Spinlock serialising slow-path send/wait and waiter-queue mutations.
    pub lock: Spinlock,
}
```

### Send Path

`SYS_NOTIFICATION_SEND`:

```
1. bits.fetch_or(bits_arg, Ordering::Relaxed)
2. SeqCst fence (Dekker pair with notification_wait)
3. if has_observer == 0: return None      // lock-free fast path
4. Acquire sig.lock
5. if waiters is non-empty:
   a. delivered = bits.swap(0, Ordering::Relaxed)
   b. if delivered == 0: release sig.lock; return None
      (between steps 1 and 4 our bits were claimed, by a newly arriving
       notification_wait that found them pending and returned without
       blocking, or by a concurrent send's step a; the queued waiters
       were already waiting and none is touched, else one receives
       wakeup_value=0 — a spurious wake, since 0-bit sends are rejected
       before step 1)
   c. tcb = waiters.pop() (the longest-waiting thread);
      has_observer = (waiters non-empty || wait_set != null)
   d. claim_waiter(tcb, delivered): wake_in_flight = 1,
      tcb.wakeup_value = delivered, and if tcb.sleep_deadline != 0
      sleep_list_remove(tcb) (clears the deadline with the entry)
   e. Release sig.lock
   f. enqueue_and_wake(tcb, target_cpu)        // outside the lock
6. else if wait_set is Some(ws): waitset_notify(ws); release; return None
7. else: release; return None                  // observer disappeared
```

The atomic OR in step 1 is the only operation on the hot path when no waiter is
present. Setting an already-set bit is idempotent — this is the defined coalescing
behaviour (per [docs/ipc-design.md § Notifications](../../../docs/ipc-design.md#notifications)).

### Wait Path

`SYS_NOTIFICATION_WAIT`:

```
1. Acquire sig.lock; context_saved = 0
2. waiters.push(current_tcb) (the tail); has_observer = 1
3. SeqCst fence (Dekker pair with notification_send)
4. acquired = bits.swap(0, Ordering::Relaxed)
5. if acquired != 0:
   // Bits were set; undo the registration and return without blocking
   waiters.remove(current_tcb); recompute has_observer; context_saved = 1
   Release sig.lock;
   tf.set_ipc_return(primary = 0, secondary = acquired); return Ok(0)
6. commit_blocked_under_local_lock(tcb, BlockedOnNotification, sig)
   (a refusal dequeues the caller again, under the same sig.lock hold);
   on a committed timed wait, arm_timed_park(tcb, deadline): set
   sleep_deadline and sleep_list_add, still under sig.lock
7. Release sig.lock
8. Block current thread; return when woken
9. On wakeup: if the park is INTERRUPTED (a stop, or the notification
   destroyed under the waiter), return Interrupted. Otherwise the sender has
   already performed bits.swap(0) and stored the result in
   current_tcb.wakeup_value (0 for a timer wake);
   tf.set_ipc_return(primary = 0, secondary = wakeup_value); return Ok(0)
```

The acquired bitmask is delivered in the secondary return register
(rdx / a1), matching `SYS_EVENT_RECV`'s register layout, per
[syscalls.md § `SYS_NOTIFICATION_WAIT`](syscalls.md#sys_notification_wait-4). An in-band
encoding via the dispatcher's `cast_signed()` of the primary would alias
bit-63-set bitmasks with negative-Err codes.

---

## Event Queue (`ipc/event_queue.rs`)

### Object Structure

```rust
pub struct EventQueueState
{
    pub lock: Spinlock,

    /// Capacity of the ring (fixed at creation).
    pub capacity: u32,

    /// Write index (producer position, modulo capacity).
    pub write_idx: u32,

    /// Read index (consumer position, modulo capacity).
    pub read_idx: u32,

    /// Receivers blocked in SYS_EVENT_RECV, in arrival order.
    pub waiters: WaitQueue,

    // ... additional bookkeeping fields ...
}
```

When the user requests capacity N, the kernel reserves a ring buffer of N+1
entries laid out **inline within the same retype slot** that holds the
`EventQueueState` (see the typed-memory cap design and
[scheduling-internals.md](scheduling-internals.md)). The one-slot gap between
`write_idx` and `read_idx` (used to distinguish full from empty) is internal;
the user observes exactly N usable slots. The ring is reclaimed wholesale with
the wrapper on `dealloc_object(EventQueue)`.

### Post Path

`SYS_EVENT_POST`:

```
1. Acquire eq.lock
2. if waiters is non-empty:
   // Deliver directly to the longest-waiting receiver, bypassing the ring
   a. tcb = waiters.pop()
   b. claim_waiter(tcb, payload): wake_in_flight = 1,
      tcb.wakeup_value = payload, and if tcb.sleep_deadline != 0
      sleep_list_remove(tcb) (clears the deadline with the entry)
   c. Release eq.lock
   d. Syscall handler: select_target_cpu + enqueue_and_wake(tcb)
3. if count >= capacity:
   Release eq.lock; return QueueFull
4. ring[write_idx] = payload; write_idx = (write_idx + 1) % (capacity + 1)
5. count += 1 (Release); on the 0 -> 1 transition, waitset_notify
6. Release eq.lock
```

The ring has `capacity + 1` slots internally (one-slot-gap full detection);
the user observes exactly N usable slots as requested. `count` tracks
occupancy and doubles as the lockless wait-set level-readiness witness.

### Recv Path

`SYS_EVENT_RECV` branches on arg1 (`timeout_ms`) before anything can park:

```
1. if timeout_ms == u64::MAX:
   // Non-blocking try-once: a pure peek (event_queue_try_recv).
   // Acquire eq.lock; pop the ring head if count > 0, else release and
   // return WouldBlock. Never queues the caller; the caller is never
   // wakeable and never enters the scheduler.
2. Acquire eq.lock (event_queue_recv)
3. if count > 0:
   a. payload = ring[read_idx]; read_idx = (read_idx + 1) % (capacity + 1)
   b. count -= 1 (Release)
   c. Release eq.lock; return payload
4. else, still under eq.lock:
   // Queue the caller at the tail of eq.waiters
   a. context_saved = 0; waiters.push(current_tcb)
   b. commit_blocked_under_local_lock(tcb, BlockedOnEventQueue)
      (eq.lock outer -> sched_lock inner; a refusal dequeues the caller)
   c. if committed and timeout_ms in 1..=MAX-1: arm_timed_park(tcb,
      deadline): set sleep_deadline and sleep_list_add, still under eq.lock
   d. Release eq.lock
5. schedule(); on resume:
   if the park is INTERRUPTED -> return Interrupted (a stop, or the queue
                                 destroyed under the waiter),
   else if tcb.timed_out      -> return WouldBlock,
   else                       -> return payload from wakeup_value
```

The try-once mode never takes the park path, per
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 8.

The `tcb.timed_out` flag is the out-of-band timeout marker — required
because event-queue payloads may be any `u64` (including 0), so an
in-band sentinel on `wakeup_value` is unavailable. The flag is set by
the `BlockedOnEventQueue` arm of `sleep_check_wakeups` when the timer
arbitrates against `event_queue_post` and wins; cleared by the resuming
syscall (protocol per
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#timed_out-cross-cpu-protocol)).

Lock order: `eq.lock → SLEEP_LIST_LOCK` (the post, the timed-recv arm, and the cancel and destroy
claims), per
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 3.
`SLEEP_LIST_LOCK` is released before `eq.lock` is taken on the timer
path — sequential, not nested, so no cycle.

---

## Wait Set (`ipc/wait_set.rs`)

### Object Structure

```rust
/// Maximum number of sources a single wait set may contain.
pub const WAIT_SET_MAX_MEMBERS: usize = 16;

pub struct WaitSetState
{
    lock: Spinlock,

    /// Registered members. A slot whose `source_ptr` is null is vacant.
    /// Fixed capacity; SYS_WAIT_SET_ADD returns InvalidArgument when full.
    members: [WaitSetMember; WAIT_SET_MAX_MEMBERS],

    /// Number of occupied member slots.
    member_count: u8,

    /// Ring buffer of pending member indices. One slot stays empty to tell
    /// full from empty, so it holds at most WAIT_SET_MAX_MEMBERS - 1 entries.
    ready_ring: [u8; WAIT_SET_MAX_MEMBERS],
    ready_head: u8,
    ready_tail: u8,

    /// The thread blocked in SYS_WAIT_SET_WAIT, if any (at most one; a second
    /// wait is refused). A WaitQueue so its claims share the source code.
    waiters: WaitQueue,
}

struct WaitSetMember
{
    /// The source's state struct (`EndpointState` / `NotificationState` /
    /// `EventQueueState`), interpreted per `source_tag`. Null when vacant.
    source_ptr: *mut u8,

    /// Kind of source; meaningful only when `source_ptr` is non-null.
    source_tag: WaitSetSourceTag,

    /// Opaque badge returned to the caller when this source is ready.
    badge: u64,
}

#[repr(u8)]
enum WaitSetSourceTag
{
    Endpoint = 0,
    Notification = 1,
    EventQueue = 2,
}
```

Folding vacancy into a null `source_ptr` keeps each `WaitSetMember` at 24 B, so
the 16-slot member array is 384 B and `WaitSetState` (at most 440 B) fits,
with its 24 B `WaitSetObject` wrapper, in the 512 B retype bin; `wait_set.rs`
asserts both sizes at compile time.

The arrays are fixed-capacity because the kernel runs no allocator (see
§ Kernel Object Memory in
[memory-internals.md](memory-internals.md#kernel-object-memory-capretypers)): a
wait set's membership storage is part of the object carved at creation, and
`waitset_notify`, under the source object lock, only walks it. A full wait set
refuses `SYS_WAIT_SET_ADD` with `InvalidArgument`, per
[syscalls.md § `SYS_WAIT_SET_ADD`](syscalls.md#sys_wait_set_add-26).

### Readiness Notification

Each IPC object type is extended with a "wait set registration" — a pointer back to
the `WaitSetState` and the member index. When an object becomes ready (a sender calls an
endpoint, a notification has bits set, an event is posted), it calls into the wait set:

```
waitset_notify(wait_set, member_idx):
    Acquire wait_set.lock
    if waiters is non-empty:
        tcb = waiters.pop()            // the longest-waiting thread
        claim_waiter(tcb, members[member_idx].badge)
        Release lock
        enqueue_and_wake(tcb)
    else:
        ready_ring.push(member_idx)   // dropped if the ring is full
        Release lock
```

### Wait Path

`SYS_WAIT_SET_WAIT`:

```
1. Acquire lock; if a thread already waits, Release lock and return
   InvalidState (a wait set takes one waiter)
2. while ready_ring is non-empty:
   a. member_idx = ready_ring.pop()
   b. if members[member_idx] is vacant (removed): skip it
   c. Release lock; return members[member_idx].badge
3. Level-readiness self-heal: for each member, if source_is_ready(source)
   right now, Release lock and return its badge.
4. else:
   a. waiters.push(current_tcb)
   b. commit_blocked_under_local_lock(current_tcb, BlockedOnWaitSet, ws);
      on a refusal, remove current_tcb from waiters, and stamp INTERRUPTED
      if the refusal was a stop (RefusedStop)
   c. Release lock
   d. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then return
      Interrupted if the park is INTERRUPTED (a stop, or the wait set
      destroyed under the waiter), else return wakeup_value
```

**Why step 3 exists, and its memory-ordering requirement.** Readiness
notifications (`waitset_notify`) are *edge-triggered*: `event_queue_post` fires
only on the empty→non-empty `count` transition and `endpoint_call` only on the
empty→non-empty send-queue transition. A second item that arrives while a first
is still queued therefore fires no notify, and — for a consumer that handles one
item per wakeup — would be invisible without the level re-check in step 3.

The self-heal reads source readiness **without taking the source lock**: taking
it here would acquire `source.lock` while holding `ws.lock`, inverting the
`source.lock → ws.lock` order `waitset_notify` uses (it runs under the source
lock and acquires `ws.lock`) and deadlocking (rule 2 of
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy)).
Because the read is lockless, each source's readiness signal MUST be an atomic
that the self-heal reads with `Acquire`, paired with `Release` mutations under
the source lock — otherwise a weak-memory target (riscv64) can observe a stale
not-ready and strand a queued sender/event whose enqueue fired no edge notify
(lost wakeup). The readiness signals are: `NotificationState::bits`
(`AtomicU64`), `EventQueueState::count` (`AtomicU32`), and
`EndpointState::send_nonempty` (`AtomicU32`, a shadow of `send_head != null`
republished under `ep.lock` at every send-queue mutation); their pairings are tabulated in
[scheduling-internals.md](scheduling-internals.md#atomic-ordering-invariants) § Atomic Ordering
Invariants.

### Wait Set Add/Remove

`SYS_WAIT_SET_ADD` acquires the wait set lock, appends a new `WaitSetMember`,
registers the wait set back-pointer on the source object, and `inc_ref`s the
source's `KernelObjectHeader` — wait-set membership is a +1 cap-level
reference on the source. The source object must be modified atomically to
avoid lost readiness notifications — if the source is already ready at add
time, the wait set is immediately notified.

`SYS_WAIT_SET_REMOVE` acquires both the wait set lock and the source object lock,
removes the member, clears the back-pointer, and `dec_ref`s the source's
`KernelObjectHeader` to release the +1 held by membership. The lock pairing
prevents a concurrent notification from referencing a removed member. The
caller still holds a cap to the source while issuing the syscall, so this
`dec_ref` cannot drain the refcount to zero.

When the wait set itself is dropped (last cap released), `wait_set_drop`
clears every member's back-pointer and `dec_ref`s each source's header; any
source whose refcount reaches zero at that point is reclaimed via the
standard `dealloc_object` cascade. The source's dealloc arm therefore never
runs while a wait-set member references it; each source's dealloc arm
carries a `debug_assert!(state.wait_set.is_null())` invariant check (refcount
ownership per § Kernel Object Reference Counting in
[capability-internals.md](capability-internals.md#kernel-object-reference-counting)).

Every waiter parked on the dropped wait set is woken with its park stamped
INTERRUPTED (§ Park Dispositions and Episodes), so its `SYS_WAIT_SET_WAIT`
returns `Interrupted`.

### Multiple Ready Sources

If multiple members become ready before `SYS_WAIT_SET_WAIT` is called, `ready_ring`
buffers their member indices in arrival order, up to `WAIT_SET_MAX_MEMBERS - 1`
entries; it does not deduplicate, and a push to a full ring is dropped.
Subsequent `SYS_WAIT_SET_WAIT` calls drain the ring without blocking until it is
empty, per [syscalls.md § `SYS_WAIT_SET_WAIT`](syscalls.md#sys_wait_set_wait-28).
An edge lost to a full ring is recovered by the level-readiness self-heal
(§ Wait Path step 3), which returns any member whose source is still ready.

---

## Per-CPU Considerations

### Lock Ordering

The lock hierarchy that applies to IPC primitives, the cross-CPU TCB ownership
rules, and the wake-protocol invariants are specified in
[scheduling-internals.md](scheduling-internals.md). That document is
authoritative for all cross-cutting concurrency rules touched by IPC.

The capability-revocation deferred-cleanup pattern remains specified in
[capability-internals.md](capability-internals.md).

### Cross-CPU Wakeup

The wake protocol — producer-side enqueue plus RESCHEDULE_PENDING set, IPI
delivery, consumer-side atomic check-and-halt — is specified in
[scheduling-internals.md § Wake Protocol Invariants](scheduling-internals.md#wake-protocol-invariants).
The wake-one primitives invoke `enqueue_and_wake` after releasing their source IPC lock;
`waitset_notify` and `waitset_add`'s ready-at-add wake release `ws.lock` but wake while the
notifying or registering source's lock is still held. The multi-waiter drains — the endpoint
dealloc drain and the Notification, EventQueue, and WaitSet destroy wakes
(`interrupt_all_waiters`) — hold the source lock across their walks. All are per
[§ Lock Hierarchy rule 5](scheduling-internals.md#lock-hierarchy).

### Lock-Free Notification Fast Path

Notification delivery (OR bits) uses an atomic operation and avoids acquiring the waiter
lock in the common case of no waiter. Only after the atomic OR, if a waiter is
suspected, is the lock acquired. This makes the notification send path essentially one
atomic instruction in the no-waiter case.

---

## IPC Scheduling Interaction

The IPC paths interact with the scheduler only through its park and wake
primitives: `commit_blocked_under_local_lock` to park,
`commit_reply_rebind_under_local_lock` to rebind an already parked sender to its
reply, `select_target_cpu` and `enqueue_and_wake` to wake, `schedule` to switch
away, and `sleep_list_add` and `sleep_list_remove` for timed waits (see
§ Waking the Recipient). The scheduler itself does not need to know about IPC.

The scheduler's preemption timer does not interrupt the IPC fast path. Syscall entry
masks interrupts, and every IPC object lock is an IRQ-disabling
`crate::sync::Spinlock`, so the endpoint-lock critical section that performs the
send/receive runs with interrupts disabled. A timer interrupt that arrives
meanwhile stays pending for the rest of that critical section. Syscall context
re-enables interrupts only in preempt-disabled windows, or when the CPU returns to
userspace or switches to the next thread, so the tick never preempts the IPC path;
kernel-mode preemption exists only at a slice expiry with preemption enabled (see
the "Lock primitive" and "Bare spin locks" paragraphs of
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy)).

---

## Summarized By

[core/kernel/README.md](../README.md), [Capability Subsystem Internals](capability-internals.md),
[Scheduler Internals](scheduler.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md),
[Thread Lifecycle and Sleep List Invariants](thread-lifecycle-and-sleep.md),
[IPC Design](../../../docs/ipc-design.md)
