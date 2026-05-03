# IPC Subsystem Internals

This document covers the implementation of the IPC subsystem. IPC semantics —
the call/reply model, signals, event queues, wait sets, and capability transfer —
are specified in [docs/ipc-design.md](../../../docs/ipc-design.md). This document
describes how those semantics are implemented in the kernel.

The IPC subsystem comprises four kernel object types:

1. **Endpoint** — synchronous call/reply rendezvous point
2. **Signal** — coalescing asynchronous bitmask notification
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

## Signal (`ipc/signal.rs`)

### Object Structure

```rust
pub struct SignalState
{
    /// Atomic bitmask: set bits represent pending events.
    pub bits: AtomicU64,

    /// Waiter waiting in SYS_SIGNAL_WAIT, or null.
    /// Protected by `lock` (see scheduling-internals.md § Lock Hierarchy).
    pub waiter: *mut ThreadControlBlock,

    /// Optional wait-set back-pointer (null if not in any wait set).
    pub wait_set: *mut u8,
    pub wait_set_member_idx: u8,

    /// Lock-free fast-path flag: non-zero iff a waiter or wait-set is registered.
    /// Read with a SeqCst fence in the signal_send fast path; the Dekker pair
    /// is documented in scheduling-internals.md § Atomic Ordering Invariants.
    pub has_observer: AtomicU8,

    /// Spinlock serialising slow-path send/wait and waiter-slot mutations.
    pub lock: Spinlock,
}
```

### Send Path

`SYS_SIGNAL_SEND`:

```
1. bits.fetch_or(bits_arg, Ordering::Relaxed)
2. SeqCst fence (Dekker pair with signal_wait)
3. if has_observer == 0: return None      // lock-free fast path
4. Acquire sig.lock
5. if waiter is Some(tcb):
   a. delivered = bits.swap(0, Ordering::Relaxed)
   b. if delivered == 0: release sig.lock; return None
      (a fast-path signal_wait between steps 1 and 4 consumed our
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

`SYS_SIGNAL_WAIT`:

```
1. acquired = bits.swap(0, Ordering::Acquire)
   // Atomically read and clear all bits
2. if acquired != 0:
   // Bits were set; return immediately without blocking
   return acquired
3. Acquire waiter_lock
4. Re-check: acquired = bits.swap(0, Ordering::Acquire)
   // Must re-check after acquiring lock to prevent lost-wakeup race:
   // a sender may have set bits between step 1 and step 3
5. if acquired != 0:
   Release waiter_lock; return acquired
6. waiter = current_tcb
7. Release waiter_lock
8. Block current thread; return when woken
9. On wakeup: the sender has already performed bits.swap(0) and stored the
   result in current_tcb.wakeup_value; return that value
```

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
1. Acquire lock
2. used = (write_idx - read_idx + capacity) % capacity
   (modulo arithmetic; wraps correctly; capacity is the allocated N+1 size)
3. if used == capacity - 1:
   // Ring is full (N usable slots exhausted); reject
   Release lock; return QueueFull
4. ring[write_idx % capacity] = payload
5. write_idx = (write_idx + 1) % capacity
6. if waiter is Some(tcb):
   a. waiter = None
   b. Release lock
   c. Mark tcb as Ready; enqueue
7. else:
   Release lock
```

The ring buffer uses a one-slot gap between `write_idx` and `read_idx` to distinguish
full from empty. The kernel allocates N+1 entries internally so the user observes
exactly N usable slots as requested.

### Recv Path

`SYS_EVENT_RECV`:

```
1. Acquire lock
2. if write_idx != read_idx:
   // Entry available
   a. payload = ring[read_idx % capacity]
   b. read_idx = (read_idx + 1) % capacity
   c. Release lock; return payload
3. else:
   // Queue empty; park the caller as eq.waiter
   a. waiter = current_tcb
   b. Release lock
   c. Branch on arg1 (`timeout_ms`):
      - `u64::MAX`     -> roll back the park; return WouldBlock
      - `0`            -> schedule(); resume reads payload from wakeup_value
      - 1..=MAX-1      -> set sleep_deadline = now + ms*tps/1000;
                          sleep_list_add(tcb); schedule(); on resume,
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

    /// Members of this wait set. Each entry pairs a source with its token.
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

    /// Opaque token returned to the caller when this source is ready.
    token: u64,

    /// Whether this source currently has pending readiness (to handle
    /// readiness arriving before the waiter blocks).
    pending: bool,
}

enum WaitSetSource
{
    Endpoint(NonNull<Endpoint>),
    Signal(NonNull<Signal>),
    EventQueue(NonNull<EventQueueHeader>),
}
```

The fixed-capacity arrays avoid heap allocation on the notification hot path.
`waitset_notify` runs under the source object lock; heap allocation there would
require a second lock (the allocator lock) and create a lock-ordering hazard.

### Readiness Notification

Each IPC object type is extended with a "wait set registration" — a pointer back to
the `WaitSet` and the member index. When an object becomes ready (a sender calls an
endpoint, a signal has bits set, an event is posted), it calls into the wait set:

```
waitset_notify(wait_set, member_idx):
    Acquire wait_set.lock
    if waiter is Some(tcb):
        waiter = None
        tcb.wakeup_token = members[member_idx].token
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
   c. token = members[member_idx].token
   d. Release lock; return token
3. else:
   a. waiter = current_tcb
   b. Release lock
   c. Block current thread; return wakeup_token when woken
```

### Wait Set Add/Remove

`SYS_WAIT_SET_ADD` acquires the wait set lock, appends a new `WaitSetMember`, and
registers the wait set back-pointer on the source object. The source object must
be modified atomically to avoid lost readiness notifications — if the source is
already ready at add time, the wait set is immediately notified.

`SYS_WAIT_SET_REMOVE` acquires both the wait set lock and the source object lock,
removes the member, and clears the back-pointer. This must be done under both locks
to prevent a concurrent notification from referencing a removed member.

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

### Lock-Free Signal Fast Path

Signal delivery (OR bits) uses an atomic operation and avoids acquiring the waiter
lock in the common case of no waiter. Only after the atomic OR, if a waiter is
suspected, is the lock acquired. This makes the signal send path essentially one
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

None
