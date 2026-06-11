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
pub struct Endpoint
{
    /// Lock protecting all fields of this endpoint.
    lock: Spinlock,

    /// State of the endpoint.
    state: EndpointState,

    /// Threads waiting to send (callers blocked in SYS_IPC_CALL).
    send_queue: WaitQueue,

    /// Thread waiting to receive (server blocked in SYS_IPC_RECV).
    /// At most one thread may wait to receive at a time.
    recv_waiter: Option<*mut ThreadControlBlock>,

    /// Reference count (from KernelObjectHeader).
    header: KernelObjectHeader,
}

#[repr(u8)]
enum EndpointState
{
    /// No waiters on either side.
    Idle,
    /// One or more senders are queued waiting for a receiver.
    SendWait,
    /// A receiver is waiting for a sender.
    RecvWait,
}
```

### Wait Queue

```rust
struct WaitQueue
{
    /// Intrusive FIFO queue of TCB pointers. Threads are served in arrival order.
    head: Option<*mut ThreadControlBlock>,
    tail: Option<*mut ThreadControlBlock>,
}
```

Threads are linked through `tcb.ipc_wait_next` — an intrusive pointer field in the
TCB used only while the thread is blocked on an IPC object. No separate allocation.

### Call Path (Sender)

`SYS_IPC_CALL` execution on the sender's thread:

```
1. Resolve endpoint_cap → verify Send rights
2. Validate message arguments (data_count, cap_slots)
3. Acquire endpoint lock
4. if endpoint.state == RecvWait:
   // Fast path: receiver is already waiting
   a. recv_tcb = endpoint.recv_waiter
   b. Copy message (label + data words) directly from sender's saved register state
      into recv_tcb's trap frame / message buffer
   c. Transfer capability slots (see capability-internals.md)
   d. Create reply capability in recv_tcb.reply_cap_slot
   e. Mark recv_tcb as Ready; set result to success
   f. Release endpoint lock
   g. Direct thread switch: if recv_tcb.priority > current_tcb.priority:
      enqueue current_tcb, switch to recv_tcb immediately (fast path optimization)
      else: enqueue recv_tcb, continue on current_tcb
   h. Current thread blocks (if not switched): state = BlockedOnReply

5. else (endpoint.state == Idle or SendWait):
   // Slow path: no receiver yet
   a. Enqueue current_tcb in endpoint.send_queue
   b. endpoint.state = SendWait
   c. Store message in current_tcb.pending_send (on-stack or in-TCB buffer)
   d. Release endpoint lock
   e. Block current thread: state = BlockedOnSend, call scheduler
```

**Message copy — small messages (fast path):** Label and up to the register-capacity
data words pass entirely through saved register state. No user memory is accessed
after argument validation; no heap allocation occurs.

**Message copy — extended payloads:** When `data_count` exceeds the register
capacity (flagged via the `flags` argument bit 0 in `SYS_IPC_CALL`), the kernel
reads the additional data words from the sender's per-thread IPC buffer page at the
registered virtual address. The kernel writes the extended words into the receiver's
IPC buffer page. If either IPC buffer page is unmapped, the syscall returns
`InvalidArgument`. Capability slots always travel in registers regardless of payload
size.

### Receive Path (Server)

`SYS_IPC_RECV` execution on the server's thread:

```
1. Resolve endpoint_cap → verify Receive rights
2. Acquire endpoint lock
3. if endpoint.state == SendWait:
   // Fast path: a sender is waiting
   a. sender_tcb = endpoint.send_queue.dequeue()
   b. if send_queue is now empty: endpoint.state = Idle
   c. Copy message from sender_tcb.pending_send into server's trap frame
   d. Transfer capability slots
   e. Create reply capability in current_tcb.reply_cap_slot
   f. Mark sender_tcb as BlockedOnReply (was already enqueued as BlockedOnSend)
   g. Release endpoint lock
   h. Return to server with message (no blocking)

4. else (endpoint.state == Idle):
   // Slow path: no sender yet
   a. endpoint.recv_waiter = current_tcb
   b. endpoint.state = RecvWait
   c. Release endpoint lock
   d. Block current thread: state = BlockedOnRecv, call scheduler
```

### Reply Path

`SYS_IPC_REPLY` execution on the server's thread:

```
1. Resolve reply_cap from current_tcb.reply_cap_slot
   (the reply cap is not in the CSpace; it is in a dedicated per-thread field)
2. Validate: reply_cap must be present and unconsumed
3. caller_tcb = reply_cap.caller
4. Copy reply message into caller_tcb's trap frame (return registers)
5. Transfer reply capability slots
6. Consume (clear) current_tcb.reply_cap_slot
7. Mark caller_tcb as Ready; enqueue
8. If caller_tcb.priority > current_tcb.priority: direct switch
```

### Park Dispositions and Episodes

Every park is an **episode**. The TCB carries `park_disposition`
(`NONE`/`REPLY`/`INTERRUPTED`); debug builds add
`park_episode`/`deposit_episode` counters for the call/fault protocol's
tripwire. A `sys_ipc_call` episode has exactly one deposit (fail-closed,
below); the non-call parking surfaces (`sys_notification_wait`,
`sys_event_recv`, `sys_ipc_recv`, `sys_wait_set_wait`, `sys_thread_sleep`)
use the disposition only as a cancellation channel (fail-open, below).

**Episode start (ownership window).** Every parking syscall resets
`park_disposition = NONE` *before* its source-side registration publishes any
claimable state (`reply_tcb`, a wait-queue link, a waiter slot, or the
Blocked commit for a plain sleep) — `sys_ipc_call` via `open_call_episode`
(which also bumps `park_episode`), the non-call surfaces via
`open_park_episode` (no bump: their genuine wakers deliberately do not stamp,
so the open/stamp counter pairing holds only for call/fault episodes). Until
that publication the parking thread exclusively owns its wake fields, so the
reset cannot race a deposit. `fault_dispatch` bumps the episode the same way
next to its `fault_outcome = Pending` reset.

**Claim-then-stamp rule.** A site may stamp the episode only after winning
the episode's exclusive wake claim. Per the DEPOSIT model (rule 8 /
sched-ipc-redesign.md §2.1) every deposit now carries a disposition; the
resume remains deposit-read, never re-check. Stamps are Release-ordered after
the payload write; the resume's Acquire load orders the payload reads after
it. The wake chain (stamp → `enqueue_and_wake`'s `sched_lock`/run-queue
Release → dispatch Acquire → resume) carries the stamp; for the
wake-before-park refusal, `wake_pending` is written and consumed under the
same `(*tcb).sched_lock`, which carries it to the refusing parker.

| Deposit site | Exclusive claim | Stamp |
|---|---|---|
| `sys_ipc_reply` normal arm | `reply_tcb` CAS won in `endpoint_reply` | episode + REPLY (after cap-result writes) |
| `sys_ipc_reply` fault-RESUME arm | same CAS | episode only (`fault_outcome` carries RESUME/KILL) |
| `fail_reply_and_wake_caller` | `reply_tcb.swap(null)` non-null | episode + REPLY (synthetic failure reply) |
| `cancel_ipc_block` BlockedOnReply / BlockedOnFault arms | `reply_tcb` CAS | episode + INTERRUPTED / episode + KILL |
| `cancel_ipc_block` BlockedOnSend arm | send-queue unlink win under `ep.lock` (a lost unlink hands the episode to the racing rebind chain) | episode + INTERRUPTED (faulter: episode + KILL) |
| `dealloc_object(Thread)` reply-bound wake | `reply_tcb` CAS under all-CPU locks | episode + INTERRUPTED (faulter: episode + KILL) |
| sleep-list timer BlockedOnReply / BlockedOnFault arms (defensive, unreachable today) | `reply_tcb` CAS | episode + INTERRUPTED / episode + KILL |
| `endpoint_call` rendezvous commit-fail teardown | teardown `reply_tcb` CAS win | episode + INTERRUPTED / KILL — without it a legitimate stop→start resume has no deposit |
| `endpoint_call` send-queue commit-fail teardown | `ep.lock` held continuously from link to unlink | episode + INTERRUPTED / KILL |
| `endpoint_recv` rebind-fail teardown | teardown `reply_tcb` CAS win (stamped before the wake-in-flight release — a dying caller's dealloc may free the TCB after it) | episode + INTERRUPTED / KILL |
| `dealloc_object(Thread)` dying-client detach arms | `reply_tcb` CAS | **no stamp** — the claimed thread is the one being freed; it never resumes |
| `cancel_ipc_block` BlockedOnRecv arm | recv-queue unlink win under `ep.lock` (a lost unlink means a caller already deposited into `ipc_msg`; that delivery stands) | INTERRUPTED |
| `cancel_ipc_block` BlockedOnNotification / EventQueue / WaitSet arms | waiter-slot clear under the source lock (every genuine waker claims under the same lock) | INTERRUPTED |
| `cancel_ipc_block` plain-sleep cleanup | the Blocked + `ipc_state == None` snapshot itself — a plain sleeper has no competing depositor (the timer's claim deposits nothing), and gating on the `sleep_list_remove` win would miss the commit→add window | INTERRUPTED |
| `dealloc_object(Endpoint)` send-queue drain | whole-queue detach under `ep.lock` | episode + INTERRUPTED (faulter: episode + KILL) |
| `dealloc_object(Endpoint)` recv-queue drain | whole-queue detach under `ep.lock` | INTERRUPTED |
| park-helper refused-commit rollbacks (`notification_wait`, `event_queue_recv`, `waitset_wait`, `endpoint_recv`) | source lock held continuously from publish to rollback — no waker ever saw the slot | INTERRUPTED on `ParkCommit::RefusedStop` only; a `RefusedWake` rollback must leave the coalesced deposit deliverable |

**Resume (call/fault episodes — fail-closed).** `sys_ipc_call` consumes the
disposition: REPLY reads `ipc_msg`; INTERRUPTED returns `Interrupted` without
touching `ipc_msg`; NONE is a protocol violation: debug builds assert (naming
tid/park-episode/deposit-episode — the #352-class spurious-resume tripwire,
also checked in `fault_dispatch`'s resume), release builds fail closed with
`Interrupted` rather than surfacing stale `ipc_msg` bytes as a success.

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

### Direct Thread Switch (Fast Path Optimization)

When a synchronous IPC completes and the recipient has higher priority than the
sender, the kernel performs a direct context switch to the recipient rather than
going through the run queue. This eliminates a round-trip through the scheduler
and is the primary mechanism that keeps synchronous IPC latency low.

The direct switch is only valid when:
- The recipient is on the same CPU (or will be scheduled there — determined by
  affinity)
- The IPC completes atomically (while the endpoint lock is held, preventing
  concurrent modification)
- The resulting switch is to a higher-priority thread (otherwise, queue normally)

---

## Notification (`ipc/notification.rs`)

### Object Structure

```rust
pub struct NotificationState
{
    /// Atomic bitmask: set bits represent pending events.
    pub bits: AtomicU64,

    /// Waiter waiting in SYS_NOTIFICATION_WAIT, or null.
    /// Protected by `lock` (see scheduling-internals.md § Lock Hierarchy).
    pub waiter: *mut ThreadControlBlock,

    /// Optional wait-set back-pointer (null if not in any wait set).
    pub wait_set: *mut u8,
    pub wait_set_member_idx: u8,

    /// Lock-free fast-path flag: non-zero iff a waiter or wait-set is registered.
    /// Read with a SeqCst fence in the notification_send fast path; the Dekker pair
    /// is documented in scheduling-internals.md § Atomic Ordering Invariants.
    pub has_observer: AtomicU8,

    /// Spinlock serialising slow-path send/wait and waiter-slot mutations.
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
5. if waiter is Some(tcb):
   a. delivered = bits.swap(0, Ordering::Relaxed)
   b. if delivered == 0: release sig.lock; return None
      (a fast-path notification_wait between steps 1 and 4 consumed our
       bits; the current sig.waiter is a *new* waiter who must NOT
       be touched, else they receive wakeup_value=0 — a spurious
       wake, since 0-bit sends are rejected at step 1)
   c. waiter = None; has_observer = (wait_set != null)
   d. tcb.wakeup_value = delivered
   e. if tcb.sleep_deadline != 0: clear it and sleep_list_remove(tcb)
   f. Release sig.lock
   g. enqueue_and_wake(tcb, target_cpu)        // outside the lock
6. else if wait_set is Some(ws): waitset_notify(ws); release; return None
7. else: release; return None                  // observer disappeared
```

The atomic OR in step 1 is the only operation on the hot path when no waiter is
present. Setting an already-set bit is idempotent — this is the defined coalescing
behaviour.

### Wait Path

`SYS_NOTIFICATION_WAIT`:

```
1. acquired = bits.swap(0, Ordering::Acquire)
   // Atomically read and clear all bits
2. if acquired != 0:
   // Bits were set; return immediately without blocking
   tf.set_ipc_return(primary = 0, secondary = acquired); return Ok(0)
3. Acquire waiter_lock
4. Re-check: acquired = bits.swap(0, Ordering::Acquire)
   // Must re-check after acquiring lock to prevent lost-wakeup race:
   // a sender may have set bits between step 1 and step 3
5. if acquired != 0:
   Release waiter_lock;
   tf.set_ipc_return(primary = 0, secondary = acquired); return Ok(0)
6. waiter = current_tcb
7. Release waiter_lock
8. Block current thread; return when woken
9. On wakeup: the sender has already performed bits.swap(0) and stored the
   result in current_tcb.wakeup_value;
   tf.set_ipc_return(primary = 0, secondary = wakeup_value); return Ok(0)
```

The acquired bitmask is delivered in the secondary return register
(rdx / a1), matching `SYS_EVENT_RECV`'s register layout. An in-band
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

    /// Waiter blocked in SYS_EVENT_RECV, or null.
    pub waiter: *mut ThreadControlBlock,

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
2. if waiter is Some(tcb):
   // Deliver directly, bypassing the ring
   a. waiter = None; tcb.wakeup_value = payload; tcb.wake_in_flight = 1
   b. if tcb.sleep_deadline != 0: sleep_list_remove(tcb); clear deadline
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
   // return WouldBlock. Never registers eq.waiter; the caller is never
   // wakeable and never enters the scheduler.
2. Acquire eq.lock (event_queue_recv)
3. if count > 0:
   a. payload = ring[read_idx]; read_idx = (read_idx + 1) % (capacity + 1)
   b. count -= 1 (Release)
   c. Release eq.lock; return payload
4. else, still under eq.lock:
   // Park the caller as eq.waiter
   a. context_saved = 0; waiter = current_tcb
   b. commit_blocked_under_local_lock(tcb, BlockedOnEventQueue)
      (eq.lock outer -> sched_lock inner; a refusal rolls the waiter back)
   c. Release eq.lock
5. if timeout_ms in 1..=MAX-1:
   re-acquire eq.lock; if still eq.waiter, set sleep_deadline and
   sleep_list_add(tcb); release eq.lock
6. schedule(); on resume:
   if tcb.timed_out -> return WouldBlock,
   else             -> return payload from wakeup_value
```

The `tcb.timed_out` flag is the out-of-band timeout marker — required
because event-queue payloads may be any `u64` (including 0), so an
in-band sentinel on `wakeup_value` is unavailable. The flag is set by
the `BlockedOnEventQueue` arm of `sleep_check_wakeups` when the timer
arbitrates against `event_queue_post` and wins; cleared by the resuming
syscall.

Lock order: `eq.lock → SLEEP_LIST_LOCK` (post path).
`SLEEP_LIST_LOCK` is released before `eq.lock` is taken on the timer
path — sequential, not nested, so no cycle.

---

## Wait Set (`ipc/wait_set.rs`)

### Object Structure

```rust
/// Maximum number of sources a single WaitSet may contain.
/// Chosen so the WaitSet fits in the sub-page in-place retype slot
/// (per scheduling-internals.md and the typed-memory cap design).
pub const WAIT_SET_MAX_MEMBERS: usize = 16;

pub struct WaitSet
{
    lock: Spinlock,

    /// Members of this wait set. Each entry pairs a source with its badge.
    /// Fixed capacity; SYS_WAIT_SET_ADD returns OutOfMemory when full.
    members: [Option<WaitSetMember>; WAIT_SET_MAX_MEMBERS],

    /// Count of valid entries in `members`.
    member_count: usize,

    /// Ring buffer of member indices that are currently ready.
    /// Fixed capacity: at most WAIT_SET_MAX_MEMBERS entries can be ready.
    ready_ring: [u8; WAIT_SET_MAX_MEMBERS],
    ready_head: usize,
    ready_tail: usize,

    /// Thread blocked in SYS_WAIT_SET_WAIT, or None.
    waiter: Option<*mut ThreadControlBlock>,

    header: KernelObjectHeader,
}

struct WaitSetMember
{
    /// The IPC object being watched.
    source: WaitSetSource,

    /// Opaque badge returned to the caller when this source is ready.
    badge: u64,

    /// Whether this source currently has pending readiness (to handle
    /// readiness arriving before the waiter blocks).
    pending: bool,
}

enum WaitSetSource
{
    Endpoint(NonNull<Endpoint>),
    Notification(NonNull<Notification>),
    EventQueue(NonNull<EventQueueHeader>),
}
```

The fixed-capacity arrays avoid heap allocation on the notification hot path.
`waitset_notify` runs under the source object lock; heap allocation there would
require a second lock (the allocator lock) and create a lock-ordering hazard.

### Readiness Notification

Each IPC object type is extended with a "wait set registration" — a pointer back to
the `WaitSet` and the member index. When an object becomes ready (a sender calls an
endpoint, a notification has bits set, an event is posted), it calls into the wait set:

```
waitset_notify(wait_set, member_idx):
    Acquire wait_set.lock
    if waiter is Some(tcb):
        waiter = None
        tcb.wakeup_badge = members[member_idx].badge
        Release lock
        Mark tcb as Ready; enqueue
    else:
        members[member_idx].pending = true
        ready_queue.push_back(member_idx)
        Release lock
```

### Wait Path

`SYS_WAIT_SET_WAIT`:

```
1. Acquire lock
2. if ready_queue is non-empty:
   a. member_idx = ready_queue.pop_front()
   b. members[member_idx].pending = false
   c. badge = members[member_idx].badge
   d. Release lock; return badge
3. Level-readiness self-heal: for each member, if source_is_ready(source)
   right now, Release lock and return its badge.
4. else:
   a. waiter = current_tcb
   b. Release lock
   c. Block current thread; return wakeup_badge when woken
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
lock and acquires `ws.lock`) and deadlocking. Because the read is lockless, each
source's readiness signal MUST be an atomic that the self-heal reads with
`Acquire`, paired with `Release` mutations under the source lock — otherwise a
weak-memory target (riscv64) can observe a stale not-ready and strand a queued
sender/event whose enqueue fired no edge notify (lost wakeup). The readiness
signals are: `NotificationState::bits` (`AtomicU64`), `EventQueueState::count`
(`AtomicU32`), and `EndpointState::send_nonempty` (`AtomicU32`, a shadow of
`send_head != null` republished under `ep.lock` at every send-queue mutation).

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
carries a `debug_assert!(state.wait_set.is_null())` invariant check.

### Multiple Ready Sources

If multiple members become ready before `SYS_WAIT_SET_WAIT` is called, `ready_queue`
accumulates all of them in order. Subsequent `SYS_WAIT_SET_WAIT` calls drain the
queue without blocking until it is empty. This prevents readiness loss — any number
of readiness events are remembered.

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
IPC primitives invoke `enqueue_and_wake` after releasing their source IPC lock
per [§ Lock Hierarchy rule 5](scheduling-internals.md#lock-hierarchy).

### Lock-Free Notification Fast Path

Notification delivery (OR bits) uses an atomic operation and avoids acquiring the waiter
lock in the common case of no waiter. Only after the atomic OR, if a waiter is
suspected, is the lock acquired. This makes the notification send path essentially one
atomic instruction in the no-waiter case.

---

## IPC Scheduling Interaction

The direct thread switch on synchronous IPC (described in the Endpoint section) is
the primary scheduling interaction. The scheduler itself does not need to know about
IPC — the IPC path directly manipulates TCB state and, when appropriate, calls the
low-level context switch primitive.

The scheduler's preemption timer is irrelevant during IPC fast-path execution — the
entire send/receive/switch sequence executes atomically with interrupts enabled but
within the endpoint lock. The timer interrupt may fire during this sequence; the
interrupt handler will observe that the current thread is in kernel mode (not
preemptible at the scheduler level) and defer preemption until the thread returns
to userspace.

---

## Summarized By

[kernel/README.md](../README.md)
