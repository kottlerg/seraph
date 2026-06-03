# IPC Design

All communication between processes goes through the kernel's IPC mechanism.

---

## Overview

Two processes that do not share an IPC capability cannot communicate.

- **Synchronous calls** for structured request/reply between services.
- **Asynchronous primitives** for event delivery: notifications (coalescing
  bitmask) and event queues (ordered ring).

---

## Synchronous IPC

### Endpoints

An endpoint is a kernel object through which synchronous IPC occurs. It is created by
a server and referenced by capability. Holding a send capability to an endpoint allows
a process to call the server; only the process holding the receive capability can accept
calls on it.

Endpoints are stateless rendezvous points.

### The Call/Reply Model

Synchronous IPC follows a strict call/reply pattern:

1. **Caller** invokes `call(endpoint_cap, message)` and blocks.
2. **Server** invokes `recv(endpoint_cap)`, which returns the message and a
   single-use **reply capability**.
3. **Server** processes the request and invokes `reply(reply_cap, message)`.
4. **Caller** is unblocked and receives the reply.

The reply capability is valid for exactly one use; it cannot be stored, delegated,
or reused.

A server that needs to delegate work may save its reply capability and reply after
receiving the downstream result.

### Message Format

A message consists of:

- **Label** — one word. Interpreted by the receiver as a message type or opcode.
  The kernel does not inspect or validate the label.
- **Data words** — up to `MSG_DATA_WORDS_MAX` words carrying the message payload.
- **Capability slots** — up to `MSG_CAP_SLOTS_MAX` capability references.
  Capabilities in these slots are transferred from sender to receiver atomically
  with the message. The sender loses access to transferred capabilities.

**Small messages (fast path):** When data fits within `MSG_REGS_DATA_MAX` words,
the entire message passes through register state. No memory access or dynamic
allocation occurs after argument validation.

**Extended payloads:** When a message exceeds the register budget, the additional data
words spill to a per-thread **IPC buffer page**. Each thread registers its IPC buffer
page once via `SYS_IPC_BUFFER_SET`. The kernel reads from the sender's page and writes
to the receiver's page directly — no arbitrary user pointer dereference, no heap
allocation. If the IPC buffer page is not registered or is unmapped at the time of an
extended IPC, the syscall fails with `InvalidArgument`. Capability slots always travel
in registers regardless of payload size.

For bulk data, pass a shared memory capability instead.

### Large Data Transfers

Fixed-size messages are intentionally small. For large payloads — bulk data, file
contents, frame buffers — the correct approach is to pass a shared memory capability
rather than embedding data in the message.

The sender maps a region, writes data, and passes a capability to the receiver. No
kernel copy occurs. The capability controls access rights (read-only, read-write).

---

## Asynchronous Primitives

Two primitives handle non-blocking event delivery:

### Notifications

A notification is a kernel object containing a single machine word used as a bitmask. Each
bit represents a distinct event type, defined by the service using the notification.

**Delivery:** The sender ORs one or more bits into the notification word. This is O(1) and
never blocks. If the receiver is already waiting, it is woken immediately. If not,
the bits accumulate until the receiver next waits.

**Coalescing:** Setting an already-set bit is idempotent.

**Receipt:** The receiver waits on the notification object and receives the full bitmask,
which is atomically cleared on read. The receiver then inspects each set bit and
acts accordingly.

Notifications are appropriate for: hardware interrupt delivery, timer expiry, IPC endpoint
readiness, DMA completion, and any event where what matters is that something happened,
not how many times or in what order.

### Event Queues

An event queue is a fixed-capacity ring buffer. Each entry carries a word-sized payload.
The capacity is chosen at creation time and does not change.

**Delivery:** The sender appends an entry to the ring. If the ring is full, the send
returns an error — it is the sender's responsibility to handle backpressure. Delivery
is otherwise O(1) and non-blocking.

**Ordering:** Entries are delivered to the receiver in the order they were posted.
Events are not coalesced. "Process A exited, then process B exited" is preserved
as two distinct entries in order.

**Receipt:** The receiver waits on the queue and receives the next available entry.
If multiple entries are available, subsequent receives return them in order without
blocking.

Event queues are appropriate for: process lifecycle events (exit, notification delivery),
anything where ordering or count of events matters, and cases where coalescing would
cause correctness problems.

---

## Waiting on Multiple Sources

A **wait set** aggregates any combination of endpoints, notifications, and event queues.
A process waits on the set and is woken when any member becomes ready; the result
identifies which source triggered the wake.

---

## Capability Semantics in IPC

IPC capabilities carry three rights — Send (call the endpoint), Receive (accept calls), and Grant
(pass capabilities in messages) — with scoping rules defined in [capability-model.md#ipc-endpoint](capability-model.md#ipc-endpoint).
Capabilities passed in IPC messages are moved, not copied; see [capability-model.md#transfer](capability-model.md#transfer).

---

## Fault Delivery

Under the fault-handler protocol ([Fault Handling](fault-handling.md); not yet
implemented), a userspace thread fault the kernel cannot resolve is delivered to the
thread's bound fault-handler endpoint as a kernel-originated synchronous message,
suspending the thread until the handler replies to resume (or the binding is severed and
the thread is killed).
This reuses the call/reply machinery above — the suspended thread occupies the caller's
role and the handler services it with the ordinary receive/reply cycle. See
[Fault Handling](fault-handling.md).

---

## Kernel Role

The kernel delivers messages, manages endpoint queuing, and transfers capability
references atomically with messages. It has no opinion on message content, service
protocols, or what capabilities mean to the receiving process.

The kernel does not provide:
- Service discovery — endpoint capabilities are delegated by init or a parent
- Protocol versioning or negotiation
- Broadcast or multicast — one sender, one receiver per endpoint call

---

## Summarized By

[README.md](../README.md),
[Architecture Overview](architecture.md),
[devmgr/README.md](../services/devmgr/README.md),
[logd/README.md](../services/logd/README.md),
[memmgr/README.md](../services/memmgr/README.md),
[procmgr/README.md](../services/procmgr/README.md),
[vfsd/README.md](../services/vfsd/README.md)
