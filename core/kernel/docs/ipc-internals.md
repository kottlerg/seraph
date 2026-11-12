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

## Endpoint (`core/kernel/src/ipc/endpoint.rs`)

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
    wait_set_member_idx: u16,

    /// Serialises every non-atomic field that changes after construction:
    /// the two queues, the call/recv rendezvous, and the wait-set
    /// back-pointer pair.
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
  TCBs they link or unlink.

### Call Path (Sender)

`SYS_IPC_CALL` execution on the sender's thread:

```
1. Resolve endpoint_cap → verify Send rights
2. Read the data words from the sender's IPC buffer page (data_count > 0),
   pre-validate the cap slots, open the park episode (open_call_episode);
   a non-zero timeout_ms (arg 2's high half) gives the call's deadline
3. Acquire endpoint lock
4. if the recv queue is non-empty:
   // Fast path: receiver is already waiting
   a. recv_tcb = head of the endpoint's recv queue (dequeued); the dequeue
      claims its receive, so a timed receive's sleep-list entry is removed
      (cancel_timed_entry)
   b. Stage the message in recv_tcb.ipc_msg: label/counts/badge from the
      sender's saved register state, data words read from the sender's IPC
      buffer page (the receiver writes them to its own page when it resumes)
   c. Pin current_tcb for its eventual reply wake (wake_in_flight = 1),
      store a timed call's sleep_deadline, publish the caller binding (the
      server's reply capability): recv_tcb.reply_tcb = current_tcb (Release
      store into an empty slot; the server's receive released any earlier
      binding), then claim recv_tcb for its wake (recv_tcb.wake_in_flight = 1)
   d. commit_blocked_under_local_lock(current_tcb, BlockedOnReply or
      BlockedOnFault, recv_tcb); on a refusal, roll the binding back
      (rollback_uncommitted_call, which clears the deadline on its win); on
      a commit of a timed call, sleep_list_add, which refuses when a claim
      of the binding since the publish already cleared the deadline
      (thread-lifecycle-and-sleep.md § Sleep List Invariants, invariant 8)
   e. Release endpoint lock
   f. Transfer capability slots in the caller's context (deliver_call_caps; a
      refusal delivers zero caps; see capability-internals.md)
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
      call cancelled (INTERRUPTED, or KILL for a fault delivery); on a
      commit of a timed call, arm its sleep-list entry (arm_timed_park),
      which then bounds the reply park too
   d. If the park committed, notify the endpoint's wait set (waitset_notify),
      for every call queued, not only the first
      (§ Wait Set, Readiness Notification)
   e. Release endpoint lock
   f. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then
      return through the disposition
```

**Message copy:** The label, counts, and badge travel in saved register state
(message format per
[docs/ipc-design.md § Message Format](../../../docs/ipc-design.md#message-format)).
Data words and the sender's cap handles travel through the per-thread IPC buffer
pages: when `data_count` > 0 the kernel reads the words from the sender's
registered page and writes them into the receiver's registered page, and when
`cap_count` > 0 it reads the handles from the sender's cap block; the delivered
cap-transfer result block is likewise written into the receiver's page. The error
surface is read-side only,
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
   worst-case cap-slot headroom in the server's CSpace (a failure returns
   here and leaves any earlier binding in place); open the park episode
2. Release an unreplied caller (release_unreplied_caller, no lock held):
   swap current_tcb.reply_tcb to null; if it held a caller bound by an
   earlier receive the server never replied to, stamp that caller's call
   cancelled (INTERRUPTED, or KILL for a fault-blocked caller) and
   enqueue_and_wake it. The binding published below therefore never
   overwrites another.
3. Acquire endpoint lock
4. if the send queue is non-empty (bind_next_sender):
   // Fast path: a sender is waiting
   a. sender_tcb = head of the send queue (dequeued)
   b. if the send queue is now empty: send_nonempty = 0
   c. Claim sender_tcb for the reply wake (wake_in_flight = 1)
   d. commit_reply_rebind_under_local_lock(sender_tcb, BlockedOnReply or
      BlockedOnFault, current_tcb): under sender_tcb's sched_lock, publish
      the caller binding (the server's reply capability) by
      current_tcb.reply_tcb.swap(sender_tcb) and commit the transition; a
      timed call keeps its sleep-list entry, which bounds the reply park
      too. If the sender died or was stopped meanwhile, nothing is
      published: the commit removes a timed call's entry, and the receive,
      whose dequeue claimed the episode, stamps the sender cancelled,
      clears its wake_in_flight, and retries from a with the next sender
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
      if the refusal was a stop or a pending upcall (RefusedStop); on a
      commit of a bounded receive, arm its sleep-list entry (arm_timed_park)
   c. Release endpoint lock
   d. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then
      return through the disposition (consume_park_cancel: TIMED_OUT
      returns WouldBlock, INTERRUPTED returns Interrupted)
```

**Try-once receive** (`timeout_ms == WAIT_TRY_ONCE`, `endpoint_try_recv`). Step 1 runs as above;
step 2 does not. Under the endpoint lock the receive runs step 4 (`bind_next_sender`), and when no
live sender is queued it returns `WouldBlock` without parking, leaving `reply_tcb` as it was, so a
reply the server still owes reaches its caller. When it binds a sender, the rebind's swap returns
the binding it displaced, a caller of an earlier unreplied receive whose episode the swap claimed,
and the receive releases it as step 2 would (`release_displaced_caller`) once the endpoint lock is
released.

### Reply Path

`SYS_IPC_REPLY` execution on the server's thread:

```
1. Claim the binding before anything reads the caller (endpoint_reply):
   load current_tcb.reply_tcb (Acquire) and CAS it from the loaded caller
   to null (the reply capability is this caller binding, a per-thread field
   outside the CSpace). The won claim keeps caller_tcb live: its
   wake_in_flight pin, set when its park published the binding, waits for
   this reply's wake, and the caller's dealloc_object(Thread) waits for
   that pin. On the win, remove a timed call's sleep-list entry
   (cancel_timed_entry). A null binding or a lost CAS (a concurrent
   canceller, or the timer's expiry, owns the caller's wake) means no
   caller: still read the data words and pre-validate the reply cap slots,
   return the first error they raise, else InvalidCapability
2. If caller_tcb is BlockedOnFault (a fault reply, whose caps the kernel
   ignores): record RESUME, DECLINED for a FAULT_REPLY_KILL label, or,
   for a FAULT_REPLY_FORWARD label, FORWARDED when caller_tcb's delivery
   is of the VM class and DECLINED otherwise, in caller_tcb.fault_outcome;
   for DECLINED or FORWARDED, deposit the label and data word 0 (the
   decline reason, when sent and readable) in caller_tcb's ipc_msg; stamp
   the episode, and go to step 6
3. Read the data words and pre-validate the reply cap slots; when caps are
   attached, pre-allocate the slots in the caller's CSpace (resolved
   through the registry from caller_tcb's cspace_id/epoch); on any of these
   failures, deposit the IPC_REPLY_TRANSFER_FAILED reply instead, wake the
   caller (step 6), and return the error to the server
4. Transfer reply capability slots; if the transfer fails, deposit the
   IPC_REPLY_TRANSFER_FAILED reply instead, wake the caller (step 6), and
   return the error to the server
5. Stage the reply in caller_tcb.ipc_msg (label/count for the caller's
   return registers, data words for the caller to write to its own IPC
   buffer page when it resumes, cap results) and stamp REPLY
6. enqueue_and_wake(caller_tcb) on its selected CPU; return to the server
```

### Park Dispositions and Episodes

Every park is an **episode**. The TCB carries `park_disposition`
(`NONE`/`REPLY`/`INTERRUPTED`/`TIMED_OUT`, the last stamped only by the
sleep-list timer's expiry of a timed endpoint or wait-set park); debug builds add
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
exclusively owns its wake fields, so the reset cannot race a deposit. Each fault delivery
(`deliver_once` in `ipc::fault`) bumps the episode the same way, after its `fault_outcome =
Pending` reset, which `pin_binding` makes under the thread's `sched_lock` with the binding read
that opens the delivery.

**Claim-then-stamp rule.** A site may stamp the episode only after winning
the episode's exclusive wake claim. Per the DEPOSIT model
([scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 8 /
[sched-ipc-redesign.md](sched-ipc-redesign.md) § 2.1) every call/fault-episode deposit carries
a disposition, while the non-call surfaces stamp only on cancellation (below);
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
| `sys_ipc_reply` payload, cap-validation, pre-allocation, or cap-transfer refusal arm (`deposit_transfer_failed_reply`) | same CAS | episode + REPLY (the synthetic `IPC_REPLY_TRANSFER_FAILED` message, with no reply staged; the server receives the error) |
| `sys_ipc_reply` fault arm | same CAS | episode only (`fault_outcome` carries RESUME, DECLINED, or FORWARDED; a DECLINED or FORWARDED reply's label and reason word go to `ipc_msg`) |
| `release_unreplied_caller` (`SYS_IPC_RECV` entry, a caller bound by an earlier unreplied receive) | `reply_tcb.swap(null)` non-null | episode + INTERRUPTED (faulter: episode + KILL) |
| `release_displaced_caller` after a try-once receive's rebind (`endpoint_try_recv`, a caller bound by an earlier unreplied receive) | the rebind's `reply_tcb.swap(sender)` returning non-null | episode + INTERRUPTED (faulter: episode + KILL) |
| `cancel_for_timeout` (the sleep-list timer's expiry of a timed `SYS_IPC_CALL`, `SYS_IPC_RECV`, or `SYS_WAIT_SET_WAIT` park): the `cancel_ipc_block` BlockedOnSend, BlockedOnReply, BlockedOnRecv, and WaitSet arms, never a fault park | the claim of the same arm, gated on the popped park (`ipc_state` and `park_seq` unchanged; for a call, the same `call_episode` in its send or reply park) | episode + TIMED_OUT, with `wake_in_flight = 1` set in the claim's hold (kept, on the BlockedOnReply arm) for the timer's own `enqueue_and_wake`; the woken syscall returns `WouldBlock` ([thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § Sleep List Invariants, invariant 6) |
| `cancel_ipc_block` BlockedOnReply / BlockedOnFault arms | `reply_tcb` CAS | episode + INTERRUPTED / episode + KILL |
| `ipc::fault::claim_fault_park` (a fault-handler binding change, `redeliver_in_flight`), received arm | `reply_tcb` CAS under the faulter's `sched_lock` behind a `blocked_on_object` re-read | episode only (`fault_outcome` carries REDELIVER) |
| `ipc::fault::claim_fault_park`, queued arm | send-queue unlink of the snapshotted park (`park_seq` equal to the binder's snapshot) under `ep.lock` | episode only (`fault_outcome` carries REDELIVER) |
| `cancel_ipc_block` BlockedOnSend arm | send-queue unlink of the snapshotted park (`park_seq` equal to the cancel's snapshot) under `ep.lock` (a lost unlink hands the episode to the racing rebind chain, to the endpoint's dealloc drain, or to a concurrent cancel that already claimed it; or the thread's own `dealloc_object(Thread)` unlinked it, unstamped, as it dies) | episode + INTERRUPTED (faulter: episode + KILL) |
| `dealloc_object(Thread)` reply-bound wake | `reply_tcb` CAS under all-CPU locks | episode + INTERRUPTED (faulter: episode + KILL) |
| `endpoint_call` rendezvous commit-fail teardown | teardown `reply_tcb` CAS win | episode + INTERRUPTED / KILL — without it a legitimate stop→start resume has no deposit |
| `endpoint_call` send-queue commit-fail teardown | `ep.lock` held continuously from link to unlink | episode + INTERRUPTED / KILL |
| `bind_next_sender` refused-rebind teardown (`endpoint_recv`, `endpoint_try_recv`) | the send-queue dequeue under `ep.lock`; the refused rebind published nothing (stamped before the wake-in-flight release — a dying caller's dealloc may free the TCB after it) | episode + INTERRUPTED / KILL |
| `dealloc_object(Thread)` dying-client detach arms | `reply_tcb` CAS | **no stamp** — the claimed thread is the one being freed; it never resumes |
| `cancel_ipc_block` BlockedOnRecv arm | recv-queue unlink of the snapshotted park (`park_seq` equal to the cancel's snapshot) under `ep.lock` (a lost unlink means one of: a caller already deposited into `ipc_msg` (its delivery stands); the endpoint's dealloc drain stamped the park `INTERRUPTED`; a concurrent cancel already claimed it; or the thread's own `dealloc_object(Thread)` unlinked it, unstamped, as it dies) | INTERRUPTED |
| `cancel_ipc_block` BlockedOnNotification / EventQueue / WaitSet arms | removal of the snapshotted park (`park_seq` equal to the cancel's snapshot) from the source's waiter queue under the source lock (every genuine waker claims under the same lock) | INTERRUPTED |
| `cancel_ipc_block` plain-sleep cleanup | `sleep_list_remove` returning `true` under the target's `sched_lock` (the deadline was still pending; the timer pop clears it under the same `SLEEP_LIST_LOCK`, and a commit→add window cancel makes the later add refuse) | INTERRUPTED |
| `cancel_for_upcall` (a posted upcall, `ipc::upcall::post`): the `cancel_ipc_block` arms but BlockedOnFault and a fault sender's BlockedOnSend, which its snapshot refuses, as does a masked or delivering thread | the claim of the same arm, the BlockedOnReply arm's gated for an upcall on the snapshotted `park_seq` as the source arms' are | episode + INTERRUPTED, with `wake_in_flight = 1` set in the claim's hold (kept, on the BlockedOnReply arm) for the poster's own `enqueue_and_wake`; the woken syscall returns `Interrupted` ([thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § Upcall Cancel-and-Wake Protocol) |
| `dealloc_object(Notification)` wake of every waiter (`interrupt_all_waiters`) | removal from the waiter queue under `sig.lock` | INTERRUPTED |
| `event_queue_drop` (`dealloc_object(EventQueue)`) wake of every waiter | removal from the waiter queue under `eq.lock` | INTERRUPTED |
| `wait_set_drop` (`dealloc_object(WaitSet)`) wake of every waiter | removal from the waiter queue under `ws.lock` | INTERRUPTED |
| `dealloc_object(Endpoint)` send-queue drain | whole-queue detach under `ep.lock` | episode + INTERRUPTED (faulter: episode + KILL) |
| `dealloc_object(Endpoint)` recv-queue drain | whole-queue detach under `ep.lock` | INTERRUPTED |
| park-helper refused-commit rollbacks (`notification_wait`, `event_queue_recv`, `waitset_wait`, `endpoint_recv`) | source lock held continuously from publish to rollback — no waker ever saw the queued entry | INTERRUPTED on `ParkCommit::RefusedStop` only; a `RefusedWake` rollback must leave the coalesced deposit deliverable |

**Resume (call/fault episodes — fail-closed).** `sys_ipc_call` consumes the
disposition: REPLY reads `ipc_msg`; INTERRUPTED returns `Interrupted` and
TIMED_OUT returns `WouldBlock`, neither touching `ipc_msg`; NONE is a protocol
violation: debug builds assert (naming tid/park-episode/deposit-episode — the
#352-class spurious-resume tripwire, also checked in `fault_dispatch`'s
resume), release builds fail closed with
`Interrupted` rather than surfacing stale `ipc_msg` bytes as a success.
`fault_dispatch`'s resume fails closed the same way: REDELIVER makes the delivery again under the
binding current then, FORWARDED makes it again through the exception class (a decline for a
kernel copy's fault), and any other `fault_outcome` than RESUME, a PENDING left by an unstamped
wake included, is the unhandled outcome: it kills the thread, or, for the fault of a restartable
syscall's user copy (`copy_fault_dispatch`), fails that syscall with `InvalidAddress`, or, for an
upcall delivery, drops the upcall and resumes the thread (the `fault_outcome` row of
[scheduling-internals.md § Atomic Ordering Invariants](scheduling-internals.md#atomic-ordering-invariants)).

**Resume (non-call parks — fail-open).** Each non-call parking syscall
consumes the disposition before reading its wake deposit, via
`consume_park_interrupted`, or `consume_park_cancel` for the parks the timer
expires as a cancel (`sys_ipc_recv`, `sys_wait_set_wait`): INTERRUPTED returns
`Interrupted`, and TIMED_OUT `WouldBlock`, without reading
`wakeup_value`/`timed_out`/`ipc_msg` (it clears the per-surface leftovers instead);
NONE proceeds on the normal deposit-read path. Fail-open is required, not a
convenience: genuine wakers for these surfaces do not stamp, because a
coalesced wake-before-park deposit (`ParkCommit::RefusedWake`) has no
claimable episode to stamp, and a recv whose cancel lost the unlink race to a
concurrent `endpoint_call` must still publish the already-deposited message —
its caller is parked `BlockedOnReply` on it and would otherwise be stranded.
A fail-closed consume here would turn every unstamped genuine wake into a
lost wakeup. The cancellation claims are exclusive against all genuine wakers
(same source lock / `SLEEP_LIST_LOCK`), so INTERRUPTED-stamped episodes are
exactly the cancelled ones, and TIMED_OUT-stamped ones exactly the expired
ones. The pre-#363 trap-frame `Interrupted` pokes are gone: every resume
rewrites the return registers, so a poke never survived — the disposition is
the only cancellation channel.

### Waking the Recipient

The kernel performs no direct thread switch on IPC. Every call rendezvous and
every reply wakes the recipient through `enqueue_and_wake` on the CPU
`select_target_cpu` chooses, after the endpoint lock is released (call) or the
`reply_tcb` claim is won (reply, which takes no endpoint lock); the run queue
decides when it runs. A receive first wakes any caller it releases from an
earlier unreplied binding (its call returns `Interrupted`, a faulter is
killed, or, on its restartable syscall's user copy, has that syscall fail with
`InvalidAddress`, and a caller blocked in an upcall delivery has the upcall
dropped and resumes; § Receive Path step 2). Beyond that, a receive that finds a waiting
sender wakes no thread: the server continues and the sender stays parked
awaiting the reply (`BlockedOnReply`, or `BlockedOnFault` for a fault sender). The call path then
parks the caller through `schedule`; the reply path returns to the server.

---

## Notification (`core/kernel/src/ipc/notification.rs`)

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
    pub wait_set_member_idx: u16,

    /// Lock-free fast-path flag: non-zero iff a waiter or wait-set is registered.
    /// Read with a SeqCst fence in the notification_send fast path; the Dekker pair
    /// is documented in scheduling-internals.md § Atomic Ordering Invariants.
    pub has_observer: AtomicU8,

    /// Spinlock serialising every non-atomic field that changes after
    /// construction: the waiter queue, the slow-path send/wait, and the
    /// wait-set back-pointer pair.
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

Steps 1-3 (the OR, the SeqCst fence, and the `has_observer` load) are the only
operations on the hot path when no waiter or wait set is registered.
Setting an already-set bit is idempotent — this is the defined coalescing
behaviour (per [docs/ipc-design.md § Notifications](../../../docs/ipc-design.md#notifications)).

**Device IRQ delivery.** A source `SYS_IRQ_REGISTER` bound to notifications reaches the send path
from interrupt context (`irq::dispatch_device_irq`), with no capability and no reference of its
own: it reads the entry of the delivery slot the interrupt arrived through (`irq::SlotEntry`, in
the executing CPU's row of x86-64 device vectors or riscv64 IMSIC identities), then walks a wired
line's bindings, or reads a message-signaled target's one binding, and signals each bound
notification. A bound binding holds a reference on its notification's object, taken by
`SYS_IRQ_REGISTER` and given up only by the change that takes the notification from the binding (a
rebind to another notification, or the binding's removal when its Interrupt object is freed). A
notification a binding names is therefore never freed, and the Notification teardown
(`dealloc_object`, Notification arm) makes no IRQ change: deleting a notification's capabilities
leaves its bindings in place until their Interrupt capabilities unbind, rebind or go.

Every delivery runs under its CPU's delivery gate (`irq::DeliveryGate`, one per CPU): a count the
delivery raises to odd before its first read of the slot's entry and drops to even after its last
access to a binding, a state, and the waiter it woke (step f above). A source is delivered only
through its slot, on the slot's CPU. Every binding change runs under the routing lock, and a change
that removes a binding from a slot or a line, or a notification from a binding, makes the removal
with a `SeqCst` store and then waits out that CPU's gate before it releases the lock (spin site
`irq:route-drain`): when the gate's count is odd it waits until the count changes. Only then is the
binding's object freed or the notification's reference dropped, outside the lock. In the single
total order of the `SeqCst` operations, a delivery whose raise precedes the change's store is seen
odd by the wait, which lasts until its drop (a `Release` the wait's `Acquire` load pairs with), and
a delivery whose raise follows the store reads the changed state. No delivery on any CPU, then,
reaches a binding no slot or line links or a notification no binding names. A line's release also
clears its slot's entry and waits out its CPU, so no delivery that read the line from that slot
outlives it; a line's first binding waits out its CPU once linked, since an interrupt latched for
the slot's previous owner can find the line with no binding and mask it, and the wait lands that
mask before the receiver's first `SYS_IRQ_ACK` can unmask it. The wait is bounded at one delivery:
a later delivery on that CPU began after the store, the waiter holds the routing lock with
interrupts disabled, so it is in no delivery itself, and a delivery takes no routing lock.

### Wait Path

`SYS_NOTIFICATION_WAIT`:

```
1. Open the park episode; acquire sig.lock; context_saved = 0
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
   sleep_deadline and sleep_list_add, still under sig.lock (the list has
   no capacity to refuse it; thread-lifecycle-and-sleep.md § Sleep List
   Invariants, invariant 4)
7. Release sig.lock
8. Block current thread; return when woken
9. On wakeup: if the park is INTERRUPTED (a stop, an upcall, or the
   notification destroyed under the waiter), return Interrupted. Otherwise the
   sender has already performed bits.swap(0) and stored the result in
   current_tcb.wakeup_value (0 for a timer wake);
   tf.set_ipc_return(primary = 0, secondary = wakeup_value); return Ok(0)
```

A try-once wait (`timeout_ms == WAIT_TRY_ONCE`, `notification_try_wait`) takes
`bits.swap(0)` under `sig.lock` and returns the bits, or `WouldBlock` when they were
0; it opens no park episode and joins neither the waiter queue nor the sleep list,
so no waker or canceller can reach it.

The acquired bitmask is delivered in the secondary return register
(rdx / a1), matching `SYS_EVENT_RECV`'s register layout, per
[syscalls.md § `SYS_NOTIFICATION_WAIT`](syscalls.md#sys_notification_wait-4). An in-band
encoding via the dispatcher's `cast_signed()` of the primary would alias
bit-63-set bitmasks with negative-Err codes.

---

## Event Queue (`core/kernel/src/ipc/event_queue.rs`)

### Object Structure

```rust
/// One entry: the two words SYS_EVENT_POST takes and SYS_EVENT_RECV returns.
pub struct EventEntry
{
    pub payload: u64,
    pub tag: u64,
}

pub struct EventQueueState
{
    /// Ring body, inline after this struct in the retype slot (set at
    /// construction).
    pub ring: *mut EventEntry,

    /// Capacity of the ring (fixed at creation).
    pub capacity: u32,

    /// Entry count: atomic so the wait-set readiness check reads it without
    /// the lock; every mutation is under `lock`.
    pub count: AtomicU32,

    /// Write index (producer position, modulo capacity + 1).
    pub write_idx: u32,

    /// Read index (consumer position, modulo capacity + 1).
    pub read_idx: u32,

    /// Receivers blocked in SYS_EVENT_RECV, in arrival order.
    pub waiters: WaitQueue,

    /// Wait-set back-pointer (null if not in any wait set) and this queue's
    /// member index in that set.
    pub wait_set: *mut u8,
    pub wait_set_member_idx: u16,

    /// Free death-observer nodes (the pool inline after the ring) and the
    /// pool's size, fixed at creation.
    pub observer_free: *mut DeathObserver,
    pub observer_count: u32,

    /// Serialises every non-atomic field that changes after construction:
    /// the ring contents, `write_idx`, `read_idx`, `waiters`, the
    /// wait-set back-pointer pair, and the observer free list.
    pub lock: Spinlock,
}
```

When the user requests capacity N, the kernel reserves a ring buffer of N+1
two-word entries laid out **inline within the same retype slot** that holds the
`EventQueueState` (layout: `cap::retype::event_queue_raw_bytes` and
`EVENT_QUEUE_RING_OFFSET`; see
[memory-internals.md § Kernel Object Memory](memory-internals.md#kernel-object-memory-capretypers)).
Full and empty are detected from `count` (also the lockless wait-set readiness
witness), not from the gap between `write_idx` and `read_idx`. Both indices
advance modulo N+1, so every slot is written in rotation, but at most N slots
are occupied at any time (the extra slot is never needed for full/empty
detection) and the user observes exactly N usable slots. The ring is reclaimed
wholesale with the wrapper on `dealloc_object(EventQueue)`.

The queue's death-observer nodes follow the ring in the same slot
(`cap::retype::event_queue_observer_offset`), as many as `SYS_CAP_CREATE_EVENT_Q` argument 2
asks for, all on `observer_free` at creation. A thread or address-space bind takes one under
`eq.lock` alone (`event_queue_take_observer`) before it takes the owner's lock, links it into the
owner's chain, and takes a checked reference on the queue (`try_inc_ref`); the owner's teardown
returns the node under `eq.lock` (`event_queue_return_observer`) and only then drops that
reference. `eq.lock` is therefore never held with a thread's `sched_lock` or an address space's
`death_lock`, and a queue whose count reaches zero has every node back on its free list. A node's
`next` and `correlator` are bare fields owned by the lock of the list that holds the node: the
queue's `lock` while it is free, the owner thread's `sched_lock` or the owner address space's
`death_lock` while it is bound (the bare-field exception of
[coding-standards.md § Concurrency](../../../docs/coding-standards.md#concurrency)); a death walk
reads a bound node's links without the lock, after reading the chain head under it, because a
linked node's links never change until the owner's teardown takes the chain. `eq` is fixed at
creation.

### Post Path

`SYS_EVENT_POST`:

```
1. Acquire eq.lock
2. if waiters is non-empty:
   // Deliver directly to the longest-waiting receiver, bypassing the ring
   a. tcb = waiters.pop()
   b. claim_waiter(tcb, entry.payload): wake_in_flight = 1,
      tcb.wakeup_value = entry.payload, and if tcb.sleep_deadline != 0
      sleep_list_remove(tcb) (clears the deadline with the entry);
      tcb.wakeup_tag = entry.tag
   c. Release eq.lock; return the woken tcb (ring untouched)
   d. Syscall handler: select_target_cpu + enqueue_and_wake(tcb)
3. if count >= capacity:
   Release eq.lock; return QueueFull
4. ring[write_idx] = entry; write_idx = (write_idx + 1) % (capacity + 1)
5. count += 1 (Release); if a wait set is registered, waitset_notify (on
   every entry rung, not only the 0 -> 1 transition)
6. Release eq.lock
```

The ring has `capacity + 1` slots internally; full and empty are detected from
`count`, not the index gap, and the user observes exactly N usable slots as
requested. `count` tracks occupancy and doubles as the lockless wait-set
level-readiness witness.

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
   a. entry = ring[read_idx]; read_idx = (read_idx + 1) % (capacity + 1)
   b. count -= 1 (Release)
   c. Release eq.lock; return entry
4. else, still under eq.lock:
   // Queue the caller at the tail of eq.waiters
   a. context_saved = 0; waiters.push(current_tcb)
   b. commit_blocked_under_local_lock(tcb, BlockedOnEventQueue)
      (eq.lock outer -> sched_lock inner; a refusal dequeues the caller)
   c. if committed and timeout_ms in 1..=MAX-1: arm_timed_park(tcb,
      deadline): set sleep_deadline and sleep_list_add, still under eq.lock
   d. Release eq.lock
5. schedule(); on resume:
   if the park is INTERRUPTED -> return Interrupted (a stop, an upcall, or
                                 the queue destroyed under the waiter),
   else if tcb.timed_out      -> return WouldBlock,
   else                       -> return the entry from wakeup_value and
                                 wakeup_tag
```

The try-once mode never takes the park path, per
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 8.

The `tcb.timed_out` flag is the out-of-band timeout marker — required
because event-queue entry words may be any `u64` (including 0), so an
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

## Wait Set (`core/kernel/src/ipc/wait_set.rs`)

### Object Structure

```rust
/// Largest member capacity a wait set may be created with (the ABI's).
pub const WAIT_SET_MAX_MEMBERS: usize = 1024;

pub struct WaitSetState
{
    /// Serialises every field that changes after construction: the members,
    /// `member_count`, the ready ring, `ready_head`, `ready_tail`, and
    /// `waiters`. Inner to every source's lock (see § Lock Ordering).
    lock: Spinlock,

    /// Registered members, `capacity` slots inline after this struct. A slot
    /// whose `source_ptr` is null is vacant. SYS_WAIT_SET_ADD returns
    /// InvalidArgument when every slot is occupied.
    members: *mut WaitSetMember,

    /// Ring buffer of pending member indices, `capacity + 1` slots inline
    /// after the members. One slot stays empty to tell full from empty, so it
    /// holds at most `capacity` entries; each names a distinct member.
    ready_ring: *mut u16,

    /// Member capacity, fixed at creation; occupied member slots.
    capacity: u16,
    member_count: u16,

    ready_head: u16,
    ready_tail: u16,

    /// Threads blocked in SYS_WAIT_SET_WAIT, in arrival order. A WaitQueue,
    /// so its claims share the source code.
    waiters: WaitQueue,
}

struct WaitSetMember
{
    /// The source's state struct (`EndpointState` / `NotificationState` /
    /// `EventQueueState`), interpreted per `source_tag`. Null when vacant.
    source_ptr: *mut u8,

    /// Kind of source; meaningful only when `source_ptr` is non-null.
    source_tag: WaitSetSourceTag,

    /// Whether `ready_ring` holds an entry for this member (at most one).
    queued: bool,

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

Folding vacancy into a null `source_ptr`, and placing `queued` in the padding after
`source_tag`, keeps each `WaitSetMember` at 24 B, the per-member debit of
`wait_set_retype_bytes`; `wait_set.rs` asserts the member and state
sizes at compile time, and `cap/retype.rs` pins the layout to the ABI formula.

The member array and the ready ring are sized by the capacity the creator passes to
`SYS_CAP_CREATE_WAIT_SET` (`1..=WAIT_SET_MAX_MEMBERS`, 1024) and live inline after the
state in the set's retype slot, because the kernel runs no heap (see § Kernel Object Memory in
[memory-internals.md](memory-internals.md#kernel-object-memory-capretypers)): a
wait set's membership storage is part of the object carved at creation, and
`waitset_notify`, under the source object lock, touches only the member it is given and
allocates nothing. A full wait set
refuses `SYS_WAIT_SET_ADD` with `InvalidArgument`, per
[syscalls.md § `SYS_WAIT_SET_ADD`](syscalls.md#sys_wait_set_add-26).

### Readiness Notification

Each IPC object type is extended with a "wait set registration" — a pointer back to
the `WaitSetState` and the member index. On every arrival of work on the object (a call
queued on an endpoint, a send to a notification that wakes no direct waiter, an entry rung
on an event queue), not only on the one that makes it ready, it calls into the wait set, so
that each arrival queues the member and wakes one of the threads waiting on the set:

```
waitset_notify(wait_set, member_idx):
    Acquire wait_set.lock
    if members[member_idx] is occupied and not queued:
        ready_ring.push(member_idx)
        members[member_idx].queued = true
    if waiters is non-empty:
        tcb = waiters.pop()            // the longest-waiting thread
        claim_waiter(tcb, members[member_idx].badge)
        Release lock
        enqueue_and_wake(tcb)
    else:
        Release lock
```

A member holds at most one ring entry, however many arrivals it takes, so the ring never
holds more entries than the set has members and never fills, and a member that keeps
receiving work cannot crowd another member's entry out of it. An arrival that wakes a
thread queues the member too, so work that the woken thread does not take stays visible to
later waits. A member a wait returns keeps its entry, queued again behind the others
(§ Wait Path step 2c). § Wait Set Readiness Model states the states and invariants these
rules keep.

### Wait Path

`SYS_WAIT_SET_WAIT`:

```
1. Acquire lock
2. while ready_ring is non-empty:
   a. member_idx = ready_ring.pop()
   b. if members[member_idx] is vacant, or its source is not
      source_is_ready right now: members[member_idx].queued = false; skip it
   c. ready_ring.push(member_idx) (queued stays set: the member is queued
      again behind the others); Release lock; return members[member_idx].badge
3. Level-readiness self-heal (the ring is now empty): for each member, if
   source_is_ready(source) right now, queue it (ready_ring.push, queued =
   true), Release lock, and return its badge.
4. else, still under the lock (a try-once instead releases the lock and
   returns WouldBlock):
   a. context_saved = 0; waiters.push(current_tcb) (the tail, behind any
      threads already waiting)
   b. commit_blocked_under_local_lock(current_tcb, BlockedOnWaitSet, ws);
      on a refusal, remove current_tcb from waiters, and stamp INTERRUPTED
      if the refusal was a stop or a pending upcall (RefusedStop); on a
      commit of a bounded wait, arm its sleep-list entry (arm_timed_park)
   c. Release lock
   d. Call the scheduler whether the park committed or was refused (a
      refused park that left the thread runnable is requeued), then return
      Interrupted if the park is INTERRUPTED (a stop, an upcall, or the wait
      set destroyed under the waiter), WouldBlock if it is TIMED_OUT (the
      timer's expiry, which removed it from waiters under the lock), else
      wakeup_value
```

A try-once wait (`timeout_ms == WAIT_TRY_ONCE`, `waitset_try_wait`) runs steps 1 to 3
and never parks, so it joins neither `waiters` nor the sleep list.

**What a returned badge means.** A ring entry is a hint that the member became
ready, not a reservation of what made it ready: the queued sender that pushed an
endpoint's entry can be stopped or destroyed before the waiter runs, which
leaves the send queue empty, and a direct `SYS_NOTIFICATION_WAIT` can drain the
bits that pushed a notification's. Step 2b therefore re-checks the source as it
pops the entry, with the same lockless reads as step 3, and skips an entry whose
readiness lapsed. An entry is pushed only after its source's readiness signal is
stored, and the push and the pop both hold the wait set's lock, so the re-check
never drops a live edge. A returned badge names a source that was ready when the wait
returned (step 2 or 3), or when its readiness woke the waiter. That readiness can
still lapse before the caller's own receive on the source, for the same reasons,
so that receive can find nothing to take.

**Several waiters.** Any number of threads may wait on one set, queued in arrival
order on `waiters`. Each `waitset_notify` wakes the head and leaves the rest
parked, and the set's destruction wakes them all. A thread parks only after steps 2
and 3 found nothing ready under the lock, so no member's readiness is stranded
while a thread waits: every readiness after that point reaches `waitset_notify`.
The badge a wake deposits reserves nothing. A member handed to one thread, by a wake or
by a wait's return, stays queued while its source is ready, so any thread that enters
the wait before the first one receives can be returned the same member by step 2 (or,
should its entry be missing, step 3) and take what made it ready; the first thread's
receive then finds nothing. A thread that shares a set with others therefore receives
with the source's try-once mode (`WAIT_TRY_ONCE` on `SYS_IPC_RECV`,
`SYS_NOTIFICATION_WAIT`, or `SYS_EVENT_RECV`) and returns to the set on `WouldBlock`, or
accepts that its blocking receive waits for the source's next arrival.

A wake hands one arrival to one thread, and the set does not wake another for it. If the
woken thread does not take the work (it is stopped or destroyed after the wake, or it
receives from another source first), the work stays queued: the next thread to enter the
wait is returned it, and so is the thread the next arrival on any member wakes. A pool
whose every other thread is parked therefore leaves that work untaken until a thread
enters the wait or another arrival wakes one; § Wait Set Readiness Model states this as
property P1.

**Why step 3 exists, and its memory-ordering requirement.** Every arrival of work
on a member queues it (§ Readiness Notification), a member leaves the ring only when a
wait finds it drained at the head (step 2b), and a member ready when it is added is
queued at the add (§ Wait Set Add/Remove), so a ready member always has an entry
(invariant I2 of § Wait Set Readiness Model). The self-heal of step 3 is the backstop
behind that bookkeeping: before a thread parks, a ready member that no entry names is returned and
queued rather than left beside the parked thread. Run only when the ring is empty, it
costs one walk over the members per park.

Steps 2b and 3 read source readiness **without taking the source lock**: taking
it here would acquire `source.lock` while holding `ws.lock`, inverting the
`source.lock → ws.lock` order `waitset_notify` uses (it runs under the source
lock and acquires `ws.lock`) and deadlocking (rule 2 of
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy)).
Because the read is lockless, each source's readiness signal is an atomic that
they read with `Acquire`. `EventQueueState::count` and
`EndpointState::send_nonempty` MUST be mutated with `Release` under the source lock,
and the `Acquire` load pairs with those stores. Without that pairing, a weak-memory
target (riscv64) can observe a stale not-ready and strand a queued sender or event
that no ring entry names (lost wakeup). `NotificationState::bits` is the
exception. `notification_send` sets it with a lock-free `Relaxed` `fetch_or` that
the SeqCst Dekker fence pair orders against `notification_wait`, so their
`Acquire` load of `bits` has no `Release` partner (`bits` carries no dependent
payload). The readiness signals are: `NotificationState::bits`
(`AtomicU64`), `EventQueueState::count` (`AtomicU32`), and
`EndpointState::send_nonempty` (`AtomicU32`, a shadow of `send_head != null`
republished under `ep.lock` at every send-queue mutation); their pairings are tabulated in
[scheduling-internals.md](scheduling-internals.md#atomic-ordering-invariants) § Atomic Ordering
Invariants.

### Wait Set Add/Remove

`SYS_WAIT_SET_ADD` holds the source object's lock across the whole registration.
Under it, `waitset_add` takes the wait set lock (inner) and fills the first vacant
`WaitSetMember` slot. The handler then registers the wait set back-pointer on the
source object and `inc_ref`s the source's `KernelObjectHeader`: wait-set membership
is a +1 cap-level reference on the source. Holding the source lock makes the
registration atomic from the source's side for every path that raises the level under
that lock. A notification's bits rise outside it (§ Send Path step 1), so the Notification
arm also stores `has_observer = 1` and runs a SeqCst fence before `waitset_add` reads the
bits, and recomputes `has_observer` if the add fails. That fence pairs with the send's
(§ Send Path step 2): a send that overlaps the add either has its bits seen by the add's
readiness check, or reads `has_observer == 1`, waits on the lock until the
registration is complete, and reaches `waitset_notify`. No readiness notification is
therefore lost. If the source is already ready at add time, `waitset_add` queues the
member and wakes the longest-waiting thread, if any, immediately.

`SYS_WAIT_SET_REMOVE` acquires both the wait set lock and the source object lock,
removes the member and its ring entry, if it has one (so a member later added at the
same index starts with none), clears the back-pointer, and `dec_ref`s the source's
`KernelObjectHeader` to release the +1 held by membership. The lock pairing
prevents a concurrent notification from referencing a removed member. Both handlers
resolve the source capability through `syscall::pin_slot`, which pins the source for
the call (see
[capability-internals.md § Storage: Hybrid Radix Directory](capability-internals.md#storage-hybrid-radix-directory)),
so a concurrent delete or ancestor revoke of that capability mid-call never makes the
membership's `dec_ref` the last: the source is freed, if at all, when the handler drops
its pin after releasing the locks.

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
buffers their member indices in the order they were queued, one entry per member
(§ Readiness Notification), so it holds every ready member and never fills. A member a
wait returns is queued again at the tail while its source stays ready (§ Wait Path step
2c), so subsequent `SYS_WAIT_SET_WAIT` calls return the ready members in turn without
blocking, and a member whose arrivals keep landing does not hold back another member's
backlog, per [syscalls.md § `SYS_WAIT_SET_WAIT`](syscalls.md#sys_wait_set_wait-28). An
entry whose source is no longer ready is skipped and dropped (§ Wait Path step 2b); the
member's next arrival queues it again.

### Wait Set Readiness Model

A member's source has a level, `ready(m)`: a queued call, a posted entry, or pending
bits. The level rises just before the source calls `waitset_notify`, and it falls when a
thread receives from the source, which the set does not observe. Every rise reaches
`waitset_notify`. An endpoint's send queue grows only in `endpoint_call`, which
kernel-synthesized fault messages also go through. An event queue's count rises only in
`event_queue_post`. Both raise the level under the source's lock. A notification's bits
rise only in `notification_send`, by a lock-free `fetch_or` before it takes the lock, and
it notifies the set on every send that no direct waiter takes. A send skips the lock, and
the notify, only when it reads `has_observer` as 0 after its SeqCst fence. The Notification
arm of `SYS_WAIT_SET_ADD` stores `has_observer = 1` and runs a SeqCst fence before
`waitset_add` reads `bits`, the add half of that Dekker pair (§ Wait Set Add/Remove). A
send that overlaps the add is therefore either seen by the add's readiness check or takes
the slow path, which waits on the lock until the registration is complete.
A post or call handed straight to a blocked receiver, and bits a direct waiter takes,
leave the level where it was. The set's own state, under `ws.lock`, is the ring of
queued members and the FIFO queue of parked threads.

**Member states.**

- **Vacant**: the slot holds no source.
- **Idle**: occupied, with no ring entry (`queued` clear).
- **Queued**: occupied, with exactly one ring entry (`queued` set). The source may be
  ready, a live entry, or drained, a stale entry dropped when it reaches the head.

A member handed to a thread, by a wake or by a wait's return, is Queued. It stays
Queued while its source is ready, and becomes Idle when a later wait finds it drained
at the head.

**Transitions**, each under `ws.lock`, as `WaitSetState`'s methods implement them:

| Event | Transition | Method |
|---|---|---|
| add | Vacant to Idle; to Queued at the tail if the source is ready at the add, then the longest-parked thread, if any, is woken with the member's badge | `install` |
| arrival | Idle to Queued at the tail; a Queued member keeps its place; then the longest-parked thread, if any, is woken with the member's badge | `on_arrival` |
| wait, step 2 | the head entry is popped; a ready member is Queued again at the tail and returned; a drained one becomes Idle and the next entry is popped | `pop_ready` |
| wait, step 3 | with the ring empty, the first ready Idle member is Queued at the tail and returned | `next_ready` |
| park | with no member returned by steps 2 and 3, the thread joins the tail of `waiters` | `waitset_wait` |
| remove | any state to Vacant, the member's entry leaving the ring | `remove_member` |
| destroy | every parked thread is woken with `Interrupted` | `wait_set_drop` |
| drain | outside the set: the level falls, and the member's state is unchanged | none |

**Invariants.**

- **I1, one entry:** a member is Queued exactly when the ring holds its index, once. The
  ring names occupied members only, so it holds at most `member_count` entries, within
  its `capacity`, and a push always fits.
- **I2, coverage:** a member whose source is ready is Queued, except between the level's
  rise and the `waitset_notify` of the same arrival. A member is queued by every arrival,
  and it leaves the ring only when a wait finds it drained.
- **I3, bounded turns:** a ready Queued member is returned by one of the next `L`
  successful waits, where `L` is the ring's length, at most `member_count`. Each
  successful wait returns the head entry and queues it behind the rest, or drops a
  drained head. An arrival never moves a Queued member, and a newly queued member joins
  behind it.
- **I4, no lost wake:** a thread parks only when steps 2 and 3, under `ws.lock`, found
  no ready member. Every later arrival takes `ws.lock` and wakes the longest-parked
  thread, so while threads are parked each arrival wakes exactly one of them, in arrival
  order. Arrivals beyond the number parked leave the member Queued for the next wait.
  With the whole pool parked, no work waits.

**Properties of the contract** (`SYS_WAIT_SET_WAIT` states both):

- **P1, a wake hands one arrival to one thread.** The set wakes no other thread for that
  arrival. If the woken thread does not take the work (it is stopped or destroyed after
  the wake, or receives from another source first), the work stays Queued (I2). The next
  thread to enter the wait is returned it, and so is the thread the next arrival on any
  member wakes. A pool whose other threads are all parked leaves the work untaken until
  one of those events, so a pool that can lose a woken thread runs a thread that keeps
  waiting, or re-arms the pool when it loses one.
- **P2, a badge reserves nothing.** A member handed to one thread stays Queued while its
  source is ready, so another thread's wait can be returned the same member before the
  first thread receives, through the ring (step 2) and not only through the self-heal
  (step 3). One of the two then finds nothing to take.

The host test `generated_sequences_keep_the_readiness_invariants` in `wait_set.rs`
drives these methods through generated sequences of arrivals, waits, takes, abandoned
handouts, removes and adds, over capacities of 1 to 6 members and pools of 1 to 4
threads. It checks I1 to I4 after every step.

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
(`interrupt_all_waiters`) — hold the source lock across their walks. All are per rule 5 of
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy).

### Lock-Free Notification Fast Path

Notification delivery (OR bits) avoids acquiring `lock` when no observer is
registered. `notification_send` performs a `Relaxed` `fetch_or`, the SeqCst Dekker
fence, and a `Relaxed` load of `has_observer`. It takes `lock` only when
`has_observer` is non-zero (a waiter or a wait set is registered). The no-observer
send path is therefore one atomic read-modify-write, one fence, and one load
(§ Send Path steps 1-3).

---

## IPC Scheduling Interaction

The IPC paths interact with the scheduler through its park and wake primitives:
`commit_blocked_under_local_lock` to park, `commit_reply_rebind_under_local_lock` to rebind an
already parked sender to its reply, `select_target_cpu` and `enqueue_and_wake` to wake, `schedule`
to switch away, and `sleep_list_add` and `sleep_list_remove` for timed waits (see § Waking the
Recipient). The IPC paths also use the `sched::thread` park-episode helpers `open_park_episode`,
`stamp_park_deposit`, `stamp_cancelled_deposit` and `consume_park_interrupted` (see § Park
Dispositions and Episodes). The dependency is not one-way: the scheduler's timer path
`sleep_check_wakeups` dispatches on `IpcThreadState` and claims timed notification and event-queue
waiters under the source lock, and `post_one_death_event` posts death payloads through
`event_queue_post`.

The scheduler's preemption timer does not interrupt the IPC fast path. Syscall entry
masks interrupts, and every IPC object lock is an IRQ-disabling
`crate::sync::Spinlock`, so the endpoint-lock critical section that performs the
send/receive runs with interrupts disabled. A timer interrupt that arrives
meanwhile stays pending for the rest of that critical section. Syscall context
re-enables interrupts only in preempt-disabled windows, or when the CPU returns to
userspace or switches to the next thread, so the tick never preempts the IPC path;
kernel-mode preemption exists only at a tick that decides a reschedule with preemption enabled
([scheduler.md § Kernel-Mode Preemption Points](scheduler.md#kernel-mode-preemption-points); see
the "Lock primitive" and "Bare spin locks" paragraphs of
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy)).

---

## Summarized By

[core/kernel/README.md](../README.md), [Capability Subsystem Internals](capability-internals.md),
[Scheduler Internals](scheduler.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md),
[Thread Lifecycle and Sleep List Invariants](thread-lifecycle-and-sleep.md),
[Coding Standards](../../../docs/coding-standards.md), [IPC Design](../../../docs/ipc-design.md)
