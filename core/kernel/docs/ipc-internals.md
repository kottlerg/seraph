# IPC Subsystem Internals

This document covers the implementation of the IPC subsystem. IPC semantics —
the call/reply model, signals, event queues, wait sets, and capability transfer —
are specified in [docs/ipc-design.md](../../docs/ipc-design.md). This document
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
pub struct Signal
{
    /// Atomic bitmask: set bits represent pending events.
    bits: AtomicU64,

    /// Waiter waiting in SYS_SIGNAL_WAIT, or None.
    /// Protected by `waiter_lock` to prevent the common case of racing
    /// between a send and a wait.
    waiter: Mutex<Option<*mut ThreadControlBlock>>,

    header: KernelObjectHeader,
}
```

### Send Path

`SYS_SIGNAL_SEND`:

```
1. bits.fetch_or(bits_arg, Ordering::Release)
2. Acquire waiter_lock
3. if waiter is Some(tcb):
   a. waiter = None
   a2. acquired = bits.swap(0, Ordering::Acquire)
       // Atomically read and clear the bits for the waking thread
   a3. tcb.wakeup_value = acquired
   b. Release waiter_lock
   c. Mark tcb as Ready; enqueue
4. else:
   Release waiter_lock
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
pub struct EventQueueHeader
{
    lock: Spinlock,

    /// Ring buffer stored separately (allocated from size-class allocator).
    ring: NonNull<u64>,

    /// Capacity of the ring (fixed at creation).
    capacity: u32,

    /// Write index (producer position, modulo capacity).
    write_idx: u32,

    /// Read index (consumer position, modulo capacity).
    read_idx: u32,

    /// Waiter blocked in SYS_EVENT_RECV, or None.
    waiter: Option<*mut ThreadControlBlock>,

    header: KernelObjectHeader,
}
```

When the user requests capacity N, the kernel allocates a ring buffer of N+1 entries.
The one-slot gap between `write_idx` and `read_idx` (used to distinguish full from
empty) is thus internal. The user observes exactly N usable slots, matching the
requested capacity. The ring buffer body is allocated from the size-class allocator
at creation time. The `EventQueueHeader` is allocated from a slab cache.

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
   // Queue empty; block
   a. waiter = current_tcb
   b. Release lock
   c. Block current thread; return payload from wakeup_value when woken
```

---

## Wait Set (`ipc/wait_set.rs`)

### Object Structure

```rust
/// Maximum number of sources a single WaitSet may contain.
/// Chosen so the WaitSet fits in a fixed-size slab allocation.
const WAIT_SET_MAX_MEMBERS: usize = 64;

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

The following global ordering must be observed everywhere in the kernel. Acquiring
locks in the reverse order, or skipping levels, risks deadlock.

```
Global lock ordering (acquire in this order; never reverse):

1. Per-CPU scheduler lock
   — when acquiring scheduler locks on two CPUs, always acquire the lower
     CPU ID's lock first (prevents deadlock during load balancing)

2. IPC object lock (endpoint / signal / event queue)
   — one lock per object; never hold two IPC object locks simultaneously
     except on a defined path that documents the ordering explicitly

3. Wait set lock
   — always acquired after the source IPC object lock that triggered the
     notification (waitset_notify: source lock → wait set lock)
   — SYS_WAIT_SET_REMOVE acquires in the same order: source lock first

4. Buddy allocator lock

5. Derivation tree lock (reader or writer)
   — ordered after IPC object locks; SYS_CAP_REVOKE must NOT acquire IPC
     object locks while holding the derivation tree write lock
```

**Deferred cleanup during revocation:** Because the derivation tree lock is ordered
after IPC object locks, `SYS_CAP_REVOKE` cannot directly acquire IPC object locks
while traversing the tree. Instead, revocation uses a two-phase approach:

1. Hold the derivation tree write lock; collect a list of IPC objects that
   reference any slot being revoked (e.g. endpoints with registered waitsets).
2. Release the derivation tree write lock.
3. For each collected object, acquire its IPC object lock and perform cleanup
   (unregister wait set back-pointers, cancel blocked sends, etc.).

This "deferred cleanup" pattern keeps lock ordering consistent at the cost of a
second pass during revocation. Revocation is expected to be rare.

### Cross-CPU Wakeup

When the kernel marks a TCB as `Ready` and enqueues it on a run queue, the TCB may
belong to a different CPU's run queue (based on affinity). In this case:

1. Enqueue the TCB on the target CPU's run queue (under the run queue lock)
2. Send an IPI to the target CPU if it is idle (in the idle thread)

The IPI wakes the target CPU's idle thread, which then picks up the newly ready TCB
through the normal scheduler path.

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
