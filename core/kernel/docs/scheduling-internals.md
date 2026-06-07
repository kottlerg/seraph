# SMP Scheduling and Locking Invariants

This document specifies the cross-cutting SMP invariants the kernel's scheduler and IPC subsystems MUST hold: lock hierarchy, cross-CPU TCB ownership, wake protocol, atomic ordering, BSP boot transient, and IPI taxonomy. It is the authoritative reference consulted before any change that touches concurrency in `core/kernel/src/sched/`, `core/kernel/src/ipc/`, `core/kernel/src/percpu.rs`, or the syscall paths that block or wake threads.

---

## Document Boundary

This document is sibling to two existing kernel-internal docs and supersedes the cross-cutting concurrency claims either of them makes:

| Doc | Owns |
|---|---|
| [scheduler.md](scheduler.md) | Scheduling algorithm: priority levels, FIFO-within-priority, time-slice policy, SMT topology preference, hard/soft affinity, idle-thread role, preemption decisions. |
| [ipc-internals.md](ipc-internals.md) | IPC primitive object layouts, syscall paths (call/reply/recv/send/wait/post), message copy mechanism, fast-path direct-switch optimisation. |
| **This document** | Lock hierarchy, cross-CPU TCB ownership, wake protocol invariants, BSP boot transient, IPI taxonomy, atomic ordering invariants, ThreadState transition table, process-death and parked-thread protocol. |

Where a sibling doc currently states a cross-cutting concurrency rule, this document is authoritative; the sibling MUST be updated to summarize and link here rather than restate.

---

## Subsystem Surface

In scope:

- `core/kernel/src/sched/{mod,run_queue,thread}.rs`
- `core/kernel/src/percpu.rs`
- `core/kernel/src/ipc/{endpoint,notification,event_queue,wait_set}.rs`
- `core/kernel/src/syscall/{thread,ipc}.rs`
- `core/kernel/src/arch/{x86_64,riscv64}/{interrupts,timer,context,cpu}.rs`
- `core/kernel/src/arch/x86_64/{gdt,ap_trampoline}.rs` (per-CPU storage; riscv64 uses `tp` and SBI HSM)

---

## Lock Hierarchy

The following ordering MUST be observed everywhere in the kernel. Acquiring locks in reverse, or skipping levels, risks deadlock.

```
                    per-CPU scheduler.lock      (outer)
                              │
              ┌───────────────┼───────────────┐
              │                               │
       source IPC lock                derivation tree lock
   (sig.lock | ep.lock |             (cap revocation;
    eq.lock | ws.lock)                see capability-internals.md)
              │
        SLEEP_LIST_LOCK                (leaf-only)
```

**Acquisition rules (MUST):**

1. **scheduler.lock is outermost on the IPC-blocking path.** Every IPC syscall handler (`sys_endpoint_call`, `sys_notification_wait`, `sys_event_recv`, `sys_wait_set_wait`, etc.) acquires the calling CPU's `scheduler.lock` before entering the IPC primitive's code. The IPC primitive is then permitted to acquire its own source lock under that scheduler lock.

2. **At most one source IPC lock at a time.** A code path holding `sig.lock` MUST NOT acquire `ep.lock`, `eq.lock`, or `ws.lock`. The single exception is `waitset_notify`, which is invoked from within a source lock (the source notifying the wait set) and acquires `ws.lock` as the inner lock — order `source.lock → ws.lock` only.

3. **`SLEEP_LIST_LOCK` is leaf-only.** It MAY be acquired from inside any source IPC lock. It MUST NOT contain calls that re-enter IPC or scheduler code while held.

4. **Cross-CPU scheduler-lock acquisition rule.** When a code path needs two CPU's `scheduler.lock`s simultaneously, the lower-numbered CPU's lock MUST be acquired first. Live production sites: `sched::migrate_ready_thread` (used by `sys_thread_set_affinity` active migration and the periodic load balancer), `dealloc_object(Thread)` (all-CPU walk in ascending order), `sched::set_state_under_all_locks` (lifecycle state writes), and `sys_thread_set_priority` (priority writes plus locate-and-relocate of the Ready TCB's queue entry — all-CPU walk in ascending order).

5. **`enqueue_and_wake` MUST be invoked with no IPC source lock held.** A primitive that wakes a TCB (e.g. `notification_send`, `event_queue_post`, `waitset_notify`, `endpoint_call`'s server-wake branch, `endpoint_reply`) snapshots the wake parameters under its source lock, releases the source lock, then calls `enqueue_and_wake`. `enqueue_and_wake` acquires the *target CPU*'s scheduler.lock and dispatches an IPI; holding any source lock across that call would introduce a `source.lock → scheduler.lock` ordering that does not exist in the hierarchy. The same rule governs `dec_ref → dealloc_object` from a wait-set path: `wait_set_drop` releases its source/ws locks before reporting any zero-refcount source back to `dealloc_object_one`'s cascade worklist.

6. **Derivation tree lock is ordered after IPC object locks.** `SYS_CAP_REVOKE` MUST NOT acquire IPC object locks while holding the derivation tree write lock — see [capability-internals.md](capability-internals.md) for the deferred-cleanup pattern.

7. **`cancel_ipc_block` MUST acquire the source lock matching `tcb.ipc_state`.** Every read or write of `source.waiter` (or the equivalent intrusive-queue field) requires the source lock; reads from non-owning CPUs without the source lock are races. The dealloc paths in `core/kernel/src/cap/object.rs` (Endpoint, Notification, EventQueue, WaitSet, and Thread arms) follow the same rule.

8. **Blocking commit MUST go through `commit_blocked_under_local_lock`.** A primitive that parks the calling thread (`notification_wait`, `event_queue_recv`, `endpoint_call`, `endpoint_recv`, `waitset_wait`) MUST commit the `Running → Blocked` transition via `crate::sched::commit_blocked_under_local_lock(tcb, ipc_state, blocked_on)`. The helper acquires the *current CPU*'s scheduler.lock, reads `state`, and only writes `Blocked` if `state ∈ {Running, Ready}`. On a `false` return (a concurrent `set_state_under_all_locks(Stopped)` has already won) the caller MUST roll back the source-side waiter registration before releasing the source IPC lock. Direct writes to `(*tcb).state = Blocked` from outside the local sched.lock are forbidden — they race the all-locks `Stopped` write in `sys_thread_stop` and silently clobber it. Lock order: source IPC lock (outer, held by the IPC primitive) → current CPU's scheduler.lock (inner, acquired by `commit_blocked_under_local_lock`).

9. **Wake commit MUST go through `enqueue_and_wake`.** Wake primitives MUST NOT write `(*tcb).state = Ready`, `ipc_state = None`, or `blocked_on_object = null` themselves under the source IPC lock; they MUST snapshot the wakeup payload (`wakeup_value`, `timed_out`) under the source lock and delegate the state writes to `enqueue_and_wake`, which performs them under the target CPU's scheduler.lock. The function reads `state` first; if `Stopped` or `Exited` the enqueue is *skipped* entirely (preventing UAF when a concurrent `dealloc_object(Thread)` is racing the wake). This rule applies equally to dealloc-time wake walks (`endpoint_dealloc` send/recv heads, `notification_dealloc` waiter, `event_queue_drop`, `wait_set_drop`).

**Lock primitive.** All locks above are `crate::sync::Spinlock` (IRQ-disabling). Hold-time MUST be bounded (target ~10 µs on x86_64); no page-table walks, buddy allocations, IPC syscalls, or other long-latency operations under any spinlock.

---

## ThreadState Transitions

Thread lifecycle is `Created → Ready ↔ Running ↔ Blocked → Exited`, with `Stopped` as a terminal-pending sub-state of either `Running` or `Blocked`.

The transition table below pins every ThreadState write to a syscall/event, the CPU performing the write, and the canonical helper / locks held. Deviations from this table are bugs.

| From | To | Trigger | Performing CPU | Locks / canonical helper |
|---|---|---|---|---|
| (uninit) | `Created` | `sys_cap_create_thread` | calling CPU | none (TCB not yet visible) |
| `Created` | `Ready` | `sys_thread_start` (first start) | calling CPU | `set_state_under_all_locks(Ready)` then `enqueue_and_wake(target_cpu)` |
| `Stopped` | `Ready` | `sys_thread_start` (resume from stop) | calling CPU | `set_state_under_all_locks(Ready)` then `enqueue_and_wake(target_cpu)` |
| `Ready` | `Running` | `schedule()` selecting next | running CPU | running CPU's scheduler.lock |
| `Running` | `Ready` | `schedule(requeue_current=true)` (yield, preempt) | running CPU | running CPU's scheduler.lock; if `cpu_affinity` excludes the running CPU the requeue is routed cross-CPU via `enqueue_and_wake(target_cpu)` after dropping the local lock |
| `Ready` (on CPU A) | `Ready` (on CPU B) | `sys_thread_set_affinity` (active migration) or periodic load balancer | calling CPU | `migrate_ready_thread(tcb, A, B)`; both scheduler.locks held in ascending-CPU order |
| `Running` | `Blocked` | IPC blocking entry (`endpoint_call/recv`, `notification_wait`, `event_queue_recv`, `waitset_wait`) | running CPU | `commit_blocked_under_local_lock(tcb, ipc, blocked_on)`; on `false` the IPC primitive rolls back its waiter registration |
| `Blocked` | `Ready` | IPC wake (`notification_send`, `event_queue_post`, `endpoint_reply`, `endpoint_call` server-wake, `waitset_notify`) | wake-issuing CPU | source IPC lock to snapshot wakeup payload, *released*, then `enqueue_and_wake(target_cpu)` |
| `Blocked` | `Ready` | timeout from sleep list | timer-firing CPU | `SLEEP_LIST_LOCK` to drain expired entries (released first), then source IPC lock to arbitrate `(*src).waiter == tcb` and write the wake payload, then `enqueue_and_wake(target_cpu)` |
| `Blocked` | `Ready` | `cancel_ipc_block` (called from `sys_thread_stop` on a blocked target) | calling CPU | scheduler.lock (already held by caller) + source IPC lock matching `tcb.ipc_state` |
| `Running` | `Blocked` (`BlockedOnFault`) | fault redirection — `ipc::fault::fault_dispatch` delivering a kernel-unresolvable fault to the thread's bound handler endpoint | running CPU (arch fault handler) | `commit_blocked_under_local_lock(tcb, BlockedOnFault, handler)`; kernel-synthesized, the faulter takes the caller role in the endpoint call/reply machinery |
| `Blocked` (`BlockedOnFault`) | `Ready` | fault reply (`sys_ipc_reply`) or cancellation (handler death via `server_reply_wake`, `cancel_ipc_block`, `dealloc_object(Thread)` unlink, endpoint-dealloc send-drain) | wake-issuing CPU | the wake-claim winner records `fault_outcome` (`Resume`/`Kill`) then `enqueue_and_wake(target_cpu)`; the faulter resumes inside `fault_dispatch` (re-executing its faulting instruction or running the kill path) rather than returning a syscall value |
| `Running` | `Stopped` | `sys_thread_stop` on running target | calling CPU | `set_state_under_all_locks(Stopped)`; if running on a remote CPU, `prod_remote_cpu(run_cpu)` and spin until `sched_remote.current != tcb` |
| `Ready` | `Stopped` | `sys_thread_stop` on a Ready target | calling CPU | `set_state_under_all_locks(Stopped)`; the helper also walks every CPU's run queue and calls `remove_from_queue` inside the all-locks region. See § *Stopped/Exited drain* below. |
| `Blocked` | `Stopped` | `sys_thread_stop` on blocked target | calling CPU | `cancel_ipc_block` first (acquires the source IPC lock and unlinks the waiter), then `set_state_under_all_locks(Stopped)` |
| `*` | `Exited` | `sys_thread_exit` (self) or fault handler | running CPU | `set_state_under_all_locks(Exited)` (on the dying CPU), then `schedule(false)` |
| `*` | `Exited` | `dealloc_object(Thread)` (refcount → 0) | calling CPU | acquires every CPU's scheduler.lock in ascending order, writes `Exited`, walks `remove_from_queue` for every CPU, releases all; then waits unconditionally for `sched.current != tcb` on *every* CPU *and* `tcb.context_saved == 1` (see Cross-CPU TCB Ownership) before freeing |

All `Running→Blocked` parks MUST route through `commit_blocked_under_local_lock`; all `Blocked→Ready` wakes MUST route through `enqueue_and_wake`. Direct `(*tcb).state` writes from an IPC primitive — under the source lock or otherwise — are forbidden; they race `set_state_under_all_locks(Stopped)` and silently clobber Stopped.

**Sleep-list coordination (issue #117).** When a wake source (`notification_send`,
`event_queue_post`, `cancel_ipc_block`) wakes a waiter that was registered with
a timeout, the sleep-list entry MUST be dropped *before* `(*waiter).sleep_deadline`
is cleared, not after. The timer path (`sleep_check_wakeups`) walks `SLEEP_LIST`
under `SLEEP_LIST_LOCK` and treats `(*tcb).sleep_deadline <= now` as expired.
Clearing the deadline before removing from the list creates a window where the
entry is still on the list with `deadline == 0 <= now`, letting the timer
claim a wake concurrently with the IPC source. Both then call
`enqueue_and_wake`, producing a double-enqueue and an intrusive-list self-cycle
(`tail.next = Some(tail)`).

**Stopped/Exited drain (issue #117).** `set_state_under_all_locks(Stopped|Exited)`
MUST also walk every CPU's run queue and call `remove_from_queue(tcb, priority)`
inside the all-locks region — leaving the stale `Ready` entry for the
dispatch-side skip loop to drain (the previous design) is unsound: a subsequent
Stopped→Ready transition followed by `enqueue_and_wake` could race the drain
and produce two list entries for the same TCB. The skip loop at
`sched/mod.rs:1967-1976` remains as defence-in-depth and as the drain mechanism for
legitimate paths that bypass `set_state_under_all_locks` (none currently). The
priority snapshot uses `(*tcb).priority` read under all-CPU locks; this is
consistent with the matching reads in `dealloc_object(Thread)` and
`sys_thread_set_priority`, which all read/write the Scheduling field group
under the same all-CPU-locks discipline.

**Priority change of a Ready TCB (issue #122).** `sys_thread_set_priority`
writes `(*tcb).priority` and, when the target is `Ready`, relocates its
queue entry under every CPU's `scheduler.lock` acquired in ascending order.
Identifying the home CPU is itself a read of the Scheduling field group, so
the syscall scans each scheduler with `remove_from_queue(tcb, old_prio)`
and re-enqueues on the same scheduler at the new priority via
`PerCpuScheduler::enqueue`. The all-locks region serialises this against
`migrate_ready_thread`, `dealloc_object(Thread)`, and
`set_state_under_all_locks`.

The "Ready ⇒ linked on exactly one queue" invariant has a transient
exception during any window where a caller publishes `state = Ready` on
a TCB but the matching `enqueue_and_wake` has not yet acquired the
destination scheduler's lock. The known sites are:

- `schedule()`'s cross-CPU outgoing branch
  (`core/kernel/src/sched/mod.rs`), which writes `state = Ready` under
  the local sched.lock, releases that lock, and only then calls
  `enqueue_and_wake` on the destination CPU's lock.
- `sys_thread_start` (`core/kernel/src/syscall/thread.rs`), which calls
  `set_state_under_all_locks(target, Ready)` to commit the state
  transition and then a separate `enqueue_and_wake(target_cpu)` to
  commit the queue link.
- `dealloc_object(Thread)`'s server-side reply wake
  (`core/kernel/src/cap/object.rs`), which writes `state = Ready` on
  the bound client under all-CPU locks and defers the matching
  `enqueue_and_wake(bound)` until after the all-locks region releases
  (the enqueue itself acquires a sched.lock, so it cannot run under
  the outer all-locks region — see Lock Hierarchy rule 5).

In each window the TCB is observably `Ready` with no queue link. A
racing `sys_thread_set_priority` taking the all-CPU-locks region sees
no scheduler claim the TCB in its locate scan; it writes the new
priority and falls through without relocating. The pending
`enqueue_and_wake` then reads `(*tcb).priority` under the destination
lock — `enqueue_and_wake` takes no caller-supplied priority — and links
the TCB at whichever value was last committed under lock. No desync
results.

`migrate_ready_thread` (`core/kernel/src/sched/mod.rs`) is the other
known consumer of this transient. Under both source and destination
scheduler locks it re-reads `state` and `preferred_cpu` and proceeds
only if `state == Ready && preferred_cpu == src_cpu`; the cross-CPU
outgoing branch updates `preferred_cpu` inside the pending
`enqueue_and_wake` (under the destination's lock), so during the
transient the function still observes the stale `preferred_cpu`
naming `src_cpu` and walks `src_cpu`'s priority queue. The walk finds
nothing (the TCB is unlinked). `migrate_ready_thread` returns `false`
and leaves the pending `enqueue_and_wake` to place the TCB; the next
caller of `migrate_ready_thread` (or the load balancer) re-runs the
migration if still warranted.

`PerCpuScheduler::enqueue` (not `change_priority`) is the correct primitive
for the syscall's re-enqueue half: `change_priority`'s enqueue is
unconditional, so calling it on a scheduler whose `remove_from_queue`
returned `false` (the wrong-home race) would double-link the TCB; the
function is therefore unused by the post-fix code.

Note that the re-enqueue does not re-route via `select_target_cpu`, so a
concurrent narrowing `sys_thread_set_affinity` that lands between this
syscall and the next dispatch may leave the TCB transiently linked on a
scheduler its `cpu_affinity` now forbids. `schedule()`'s outgoing
cross-CPU branch and `migrate_ready_thread` heal this on the next
dispatch tick (the dispatch-side skip loop at `sched/mod.rs` does not
consult affinity, so the re-route happens via the outgoing branch's
affinity recheck rather than at dispatch). This is the same eventual-
consistency window as for any other `enqueue_and_wake` racing
`sys_thread_set_affinity`; see issue #116.

**Enqueue-chokepoint enforcement (issue #244).** Every run-queue insertion —
`enqueue_and_wake`, `schedule()`'s outgoing requeue, `sys_thread_set_priority`'s
re-enqueue, and `migrate_ready_thread`'s destination link — funnels through
`PerCpuScheduler::enqueue`. That chokepoint refuses a double-link: if `tcb` is
already linked on a run queue (`run_queue_next.is_some()`, or it is the target
priority queue's tail), re-linking it would self-cycle the intrusive list
(`tail.next = Some(tail)`, the `head=tail=tcb` corruption #244 reported). The
condition is read under the owning `scheduler.lock` — the same state and lock
the `RunQueue::enqueue` tripwire asserts on, so it identifies only genuine
double-links. Debug builds panic via that tripwire, naming the racing call
sites through the debug-only `last_enqueue` breadcrumb; release builds skip the
redundant link so the "Ready ⇒ linked on exactly one queue" invariant holds by
construction rather than corrupting. The skip is lossless: the target TCB is
already `Ready` and linked, so it is dispatched and consumes its wakeup payload
from where it is already queued. The guard precedes `increment_load`, so a
skipped link leaves the load counter exact. The legitimate Ready-on-entry
callers (the cross-CPU outgoing branch, `sys_thread_start`) reach
`PerCpuScheduler::enqueue` with the TCB *unlinked* (it was just `current`, or
`Created`/`Stopped`), so the guard never fires on them. This makes the
invariant self-enforcing at the single insertion chokepoint, closing the
double-link class (#22/#116/#117/#122/#142/#144/#244) against any residual
racing path.

---

## Cross-CPU TCB Ownership

The TCB is owned in pieces. Different field groups have different lock disciplines. Cross-CPU access to any field MUST hold the lock specified for that field's group.

| Field group | Fields | Owning lock | Cross-CPU access rule |
|---|---|---|---|
| **Scheduling** | `state`, `priority`, `slice_remaining`, `cpu_affinity`, `preferred_cpu`, `run_queue_next` | The scheduler.lock of whichever CPU's run queue currently links the TCB. For threads not on any run queue (blocked or running), the *home* CPU's scheduler.lock — the one that would re-enqueue on wake. | Cross-CPU writers MUST acquire the home CPU's scheduler.lock. |
| **IPC blocking** | `ipc_state`, `blocked_on_object`, `ipc_msg`, `ipc_wait_next`, `wakeup_value`, `timed_out` | The source IPC lock matching `ipc_state` (or `None` if not blocked). | Cross-CPU writers MUST acquire the matching source lock; reads from another CPU MUST do the same. |
| **Reply slot** | `reply_tcb` | `AtomicPtr<ThreadControlBlock>`; lock-free with `Acquire`/`Release` ordering, and `compare_exchange` for cancel. | Endpoint paths set/clear it under `ep.lock`; cancel/dealloc paths on a remote CPU use `compare_exchange(client, null)` so they never clobber a different client's binding. `reply_tcb` is the one TCB field with no single owning lock — multiple lock domains write it (the various `endpoint_*` paths under `ep.lock`, plus `cancel_ipc_block`, the `dealloc_object(Thread)` reply-bound waker, and the fault-redirection reply/cancel paths, from outside any lock), which is why it is atomic. The fault redirection (`BlockedOnFault`) reuses this slot identically: `fault_dispatch` parks the faulter exactly as a caller, so every CAS claimant arbitrates over the same slot. |
| **Context save/restore** | `saved_state`, `kernel_stack_top`, `trap_frame`, `context_saved` | Owning-CPU's scheduler.lock for read; the running CPU writes `saved_state` during `context::switch` (no lock; write is serialised with the next reader by `context_saved` Acquire/Release). | A remote CPU dequeueing this TCB MUST spin-wait on `context_saved` (Acquire load) before reading any other context field. |
| **Address-space / capability** | `address_space`, `cspace`, `iopb` | Set once at create-time / configure-time; treated as read-only after `sys_thread_start`. | No cross-CPU write is permitted; reads need no lock. |
| **Identity** | `thread_id`, `magic` | Immutable after construction. | Read freely. |
| **IPC buffer** | `ipc_buffer` | Set by `SYS_IPC_BUFFER_SET`; logically owned by the thread itself. | The thread reads it under no lock from its own kernel-mode syscall path; other CPUs MUST NOT read it. |
| **Death observers** | `death_observers`, `death_observer_count`, `sleep_deadline` | Owning-CPU's scheduler.lock for `death_observers`/`death_observer_count`; for `sleep_deadline`, the source IPC lock that initiated the timed wait + `SLEEP_LIST_LOCK`. | Cross-CPU writes follow the per-field rule above. |

**Magic-cookie discipline.** `magic == TCB_MAGIC` MUST be read on every dereference of a TCB pointer that crossed a CPU boundary or came from an intrusive list (run queue, IPC wait queue, sleep list, death observer). `core/kernel/src/sched/run_queue.rs:223,272` already does this for run-queue ops; the same pattern applies anywhere a stale pointer might be observed.

**`cpu_affinity` enforcement invariant.** A thread with `cpu_affinity = X` (X ≠ `AFFINITY_ANY`) MUST NOT be linked on CPU Y's run queue, nor dispatched out of `schedule()` on CPU Y, for any Y ≠ X. The enforcement points are:

- `select_target_cpu` + `enqueue_and_wake` (`core/kernel/src/sched/mod.rs`) honour `cpu_affinity` on every placement.
- `migrate_ready_thread` is the active-relocation primitive.
- `schedule()`'s outgoing-thread re-enqueue branch (`core/kernel/src/sched/mod.rs:1918-1953`) routes the requeue cross-CPU when the *outgoing* thread's affinity no longer permits the current CPU.

The dispatch-side skip loop in `schedule()` (`core/kernel/src/sched/mod.rs:1967-1976`) only filters `Stopped` / `Exited` — it does **NOT** consult `cpu_affinity` on the *incoming* dequeued thread. A `cpu_affinity` write that lands between an `enqueue_and_wake` and the matching `migrate_ready_thread` is therefore a window in which `schedule()` on the source CPU can still dispatch the target locally in violation of the new affinity. Syscalls that mutate `cpu_affinity` and then dispatch on an unlocked state read (`sys_thread_set_affinity`) MUST bracket the read-and-act sequence with `percpu::preempt_disable` / `preempt_enable` so a local timer-driven `schedule()` cannot dispatch the target on the source CPU during the in-flight migration. See issue #116.

Userspace that pins a thread to one CPU then re-pins it to another (the `affinity_migrate_ready_queued` ktest pattern) has an analogous *inter-syscall* race window that no kernel guard closes: the target is legitimately Ready and on the source CPU's queue with a matching `cpu_affinity` for that CPU, so a timer-driven `schedule()` between the two syscalls correctly dispatches it locally. Tests that publish state derived from the running CPU MUST encode that state in a non-zero form (e.g. `1u64 << cpu` rather than `cpu`) so wake primitives never reject the wake on a stale-CPU run; otherwise a stale dispatch silently swallows the wake and the parent's wait parks indefinitely. See issue #116.

**`context_saved` protocol (`core/kernel/src/sched/thread.rs`).** This is the load-bearing cross-CPU synchronisation for context-switch correctness on RVWMO *and* the publication barrier protecting TCB lifetime against `dealloc_object(Thread)`:

```
Outgoing CPU (in schedule()):
  1. context_saved.store(0, Relaxed)               // before unlock
  2. sched.set_current(next)                       // sched.current = next
  3. sched.lock.release_lock_only()                // remote dequeue / dealloc can now observe
  3.5. while next.context_saved.load(Acquire) == 0 { spin_loop() }   // LOCKLESS
  4. arch::current::context::switch(&out.saved_state, &in.saved_state)
  5. context_saved.store(1, Release)               // after switch completes

Remote dequeue (after dequeue_highest returns this TCB):
  6. while context_saved.load(Acquire) == 0 { spin_loop() }
  7. // saved_state is now safe to read on this CPU

dealloc_object(Thread) (after the all-locks region releases):
  8. loop { scan every cpu under its sched.lock; if some cpu.current == tcb,
            spin on that cpu until cpu.current != tcb, then re-scan }  // unconditional, all-CPU
  9. while context_saved.load(Acquire) == 0 { spin_loop() }    // unconditional
 10. // safe to free TCB body and kernel stack
```

Step 3.5 is the outgoing CPU's cross-CPU dispatch barrier: when this CPU is about to switch INTO `next`, it must observe `next.context_saved == 1` from the CPU that previously ran `next`. Step 3.5 MUST run with the local `sched.lock` already released (step 3). Holding the lock across the spin re-introduces issue #144's cross-CPU deadlock: a peer CPU's cross-CPU `enqueue_and_wake` (e.g. its own outgoing-branch re-enqueue) targets this CPU's lock; if this CPU is spinning on `next.context_saved` under the lock while waiting on the peer to publish, the peer cannot reach its own `switch()` and the cycle never breaks. Step 3.5 runs lockless on both arches.

The Release in step 5 pairs with both the Acquire in step 6 (cross-CPU dequeue), the Acquire in step 3.5 (outgoing-CPU dispatch barrier), and the Acquire in step 9 (TCB free). Step 8 is the prerequisite: it scans *every* CPU and will not let the free proceed while any CPU still names `tcb` as `current`, so it does not rely on an all-locks `running_on` snapshot (which names at most one CPU and can be stale once the locks drop). Step 9 then closes the residual window step 8 cannot see: the lock release at step 3 lets a peer observe `sched.current = next` (set at step 2) *while step 4 is still writing into `tcb.saved_state`* — a CPU that has just switched *away* passes step 8 but its register save may still be in flight, and freeing the TCB there lets the next allocation reuse the memory while `switch()` corrupts it. Step 9 is unconditional; new TCBs initialise `context_saved = 1`, so the wait is bounded for threads that never ran.

**`context_saved = 1` and `popfq` ordering inside `context::switch` (issue #117).** Step 5 above hides a finer-grained ordering invariant inside the `switch()` asm itself. Both the `context_saved = 1` publication AND the `popfq` that restores `next.saved_state.rflags` (which may set `IF = 1`) MUST happen AFTER `mov rsp, [rsi + 8]` (the rsp swap to the next thread's kstack), not before it. Doing either earlier opens this window:
1. `popfq` before the rsp swap re-enables interrupts while this CPU is still executing on the OUTGOING thread's kstack. A trap taken in that window pushes its iretq frame onto the outgoing kstack.
2. Publishing `current.context_saved = 1` before the rsp swap satisfies step 6's Acquire spin for any peer CPU that just dequeued `current`. That peer's own `switch()` then executes its own rsp swap onto the SAME outgoing kstack, and any push/pop the peer does collides with the iretq frame from (1).
The collision overwrites the trap return address, so `iretq` on this CPU returns to a wild RIP (typically `0` because the corruption zeroes the slot). The `stress::concurrent_ipc` ktest surfaces this as a kernel `#PF` at `rip = 0, cr2 = 0, err = 0x10` at ~0.2 % per run on x86_64 TCG with the racy ordering. Keeping both the publication and `popfq` below the rsp swap closes the window.

**RISC-V analogue inside `arch::riscv64::context::switch` (issue #133).** The same invariant holds: `*save_flag = 1` (the `context_saved` Release publication) MUST happen AFTER `ld sp, 0(a1)` (the sp swap to next's kstack). Window (a) — interrupts re-enabled while still on the outgoing kstack — does NOT apply on RISC-V because `switch()` does not restore `sstatus` and `SIE` stays masked across the swap, so no trap iretq frame is in flight. Window (b) IS present and structurally identical to x86_64: a peer hart that observes `context_saved == 1` and dequeues `current` will pass step 6's Acquire spin, read `saved_state.sp` (still the OUTGOING sp because this hart has saved but not yet swapped), and execute its own sp restore onto the same outgoing kstack. Any push/pop the peer does then races this hart's continued use of the kstack until the `ld sp` retires. The symptom is less visible than the x86 iretq-frame case (no trap return address to corrupt) but the shared-kstack hazard is the same. Keeping the publication below the sp swap closes the window.

Per-arch step ordering: both arches follow the textbook sequence above literally — `sched.lock.release_lock_only()` (step 3) runs in Rust before the lockless `next.context_saved` Acquire spin (step 3.5), which precedes `arch::current::context::switch` (step 4); `context_saved.store(1, Release)` (step 5) lives inside the asm at the tail of step 4. Issue #144 collapsed an earlier RISC-V variant that inlined the `now_serving` lock-release advance into the asm tail (effective sequence 1 → 2 → 4-save → 4-load → 5 → 3): that ordering forced the step 3.5 spin to run under the local sched.lock and re-introduced the cross-CPU deadlock cycle described above. Releasing the lock in Rust on both arches keeps step 3.5 lockless and the deadlock geometry closed.

**First-dispatch trampoline runs interrupts-masked (issue #160).** A newly created thread's initial `saved_state` (`arch::*::context::new_state`) is restored by the first `switch()` into it. For a **user** thread the restore target is `user_thread_trampoline`, which runs in ring 0 and tail-calls `return_to_user`; the user thread becomes interruptible only at the `iretq`/`sret`, which loads the user RFLAGS/`sstatus` (IF/SPIE = 1, set by `init_user`) from the `TrapFrame`. The kernel-side trampoline itself MUST run with interrupts masked. The invariant: **`new_state` initialises the saved interrupt-enable bit to 0 for user threads** (`rflags = 0x002` on x86_64; RISC-V leaves `sstatus` untouched so `SIE` stays masked across the swap). If the trampoline runs with IF = 1, a timer can preempt it deep on the kstack between the `switch()` `popfq` and the `iretq`; the preempted thread is re-enqueued and later resumed through the scheduler, and the convoluted resume corrupts a kernel return address, faulting at `RIP = 0` (`#PF`, `cs = 0x8`). **Kernel threads (idle) take the other arm** — they have no trampoline and never `iretq` to user, so `new_state` keeps IF = 1 for them (`rflags = 0x200`) so the idle loop can wake from `hlt`; RISC-V idle instead calls `interrupts::enable()` in its entry. This mirrors the #117 invariant (interrupts must not be live on a kstack a thread does not exclusively own) but on the *first-run* path rather than the steady-state switch.

---

## Wake Protocol Invariants

Producer side (`enqueue_and_wake`, `core/kernel/src/sched/mod.rs`):

```
1. Acquire target scheduler.lock.
2. Read tcb.state. If Stopped or Exited, release the lock and RETURN — the
   wake is silently dropped (a concurrent set_state_under_all_locks(Stopped)
   or dealloc has already won; enqueueing now would re-introduce a freed or
   stop-pending TCB into the run queue).
3. Set tcb.state = Ready, ipc_state = None, blocked_on_object = null.
4. Enqueue tcb in target's priority queue.
   (Inside enqueue: non_empty.fetch_or(1 << prio, Release).)
5. Update tcb.preferred_cpu = target_cpu (so dealloc_object targets the
   correct scheduler).
6. set_reschedule_pending_for(target_cpu).
   (RESCHEDULE_PENDING.set_cpu(target_cpu, Release).)
7. Release target scheduler.lock.
8. wake_idle_cpu(target_cpu)  →  sends IPI (always; see below).
```

The producer-side `state`/`ipc_state`/`blocked_on_object` writes belong to `enqueue_and_wake` — wake primitives MUST NOT do them under the source IPC lock. See Lock Hierarchy rule 9.

### Target CPU selection (`select_target_cpu`)

`enqueue_and_wake` resolves `target_cpu` via `select_target_cpu`. The
selection policy is, in priority order: (1) hard affinity
(`cpu_affinity != AFFINITY_ANY`), (2) save-window pinning to
`preferred_cpu` while `context_saved == 0` (closes the cross-CPU
`schedule()` spin against the source CPU's in-flight save), (3) sticky
`preferred_cpu` when its load is within `LOAD_BALANCE_IMBALANCE_THRESHOLD`
of the global `min_load`, and (4) the least-loaded CPU. The
`LOAD_BALANCE_IMBALANCE_THRESHOLD` knob is shared with `try_pull_balance`
so the wake-side stickiness and the pull-balancer's imbalance test
agree on what counts as "real" load asymmetry. The sticky-CPU rule
originated from the #128 investigation as an independent
cache-warmth alignment with the documented soft-affinity intent in
`scheduler.md` § Soft Affinity; #128's actual root cause turned out
to be unrelated (`CSpaceId` namespace exhaustion, see commits on
that issue).

Consumer side (`idle_thread_entry`, `core/kernel/src/sched/mod.rs:444+`):

```
1. Mask interrupts.
2. pending = take_reschedule_pending(cpu)          // RESCHEDULE_PENDING.take_cpu(cpu, AcqRel)
3. has_work = scheduler_ptr(cpu).has_runnable()    // non_empty.load(Acquire)
4. if pending || has_work {
       enable interrupts;
       schedule(true);                              // pick up the work
       continue;
   }
5. halt_until_interrupt()                          // x86: sti;hlt   riscv: wfi (atomic)
```

**Invariants the protocol MUST satisfy:**

1. **The producer's enqueue MUST happen before its `set_reschedule_pending_for` call.** The non_empty Release in step 3 establishes happens-before with the consumer's `has_runnable` Acquire in step 4. Reordering steps 3 and 5 is forbidden.

2. **The consumer MUST mask interrupts before checking `pending` and `has_work`, and MUST NOT unmask before either entering schedule() or executing the atomic-halt instruction.** This closes the window between observing "no work" and halting.

3. **The atomic-halt instruction MUST be `sti;hlt` (x86) or `wfi` (riscv) issued under the same masked region**, such that an IPI arriving between step 4 and the halt is observed at the halt boundary and wakes the CPU immediately. `core/kernel/src/arch/{x86_64,riscv64}/cpu.rs::halt_until_interrupt` is responsible for this guarantee.

4. **Always-IPI MUST be the policy in `wake_idle_cpu`.** Predicating IPI delivery on a per-CPU "is idle" hint is a missed-wakeup race: the producer can observe `running` while the target CPU has just halted in `hlt`/`wfi`, and the producer's enqueue + `RESCHEDULE_PENDING` set sit unobserved until the next interrupt. The IPI MUST be sent for every cross-CPU wake (skipping only self-wakes). Spurious IPIs to running targets cost only a trap entry; the cost is negligible against the missed-wakeup risk.

5. **`take_reschedule_pending` MUST use AcqRel** (the Acquire half pairs with the producer's Release `set_cpu`; the Release half is conservative but avoids a separate-fence requirement).

**Why two notifications.** `non_empty` (per-CPU `AtomicU32`, "Ready thread at some
priority") is updated by enqueue/dequeue and is the dispatcher's notification.
`RESCHEDULE_PENDING` (global `AtomicCpuMask`, one bit per CPU) is set by
`enqueue_and_wake` and is consumed by both the idle loop and `schedule()` on
every entry to decide whether to skip optimisations. Collapsing the two would
require restructuring `schedule()`.

---

## BSP Boot Transient

The window during which the BSP is live but SMP state is not yet steady. Begins at `sched::init_storage` (Phase 4), ends at `sched::enter` (Phase 9).

**Phase boundaries:**

| Phase | Boundary | What changes |
|---|---|---|
| 4 | `init_storage` returns | `CPU_COUNT`, `SCHEDULERS_PTR`, `IDLE_TCBS_PTR` published. |
| 5 | `arch::current::timer::init` returns | BSP timer armed; timer ISR can fire. |
| 7 | Phase 7 returns | Capability system live. |
| 8 | `sched::init` returns | Idle TCBs constructed; per-CPU `current` set. |
| 9 | Init enqueued | Run queue non-empty; first scheduler decision possible. |
| 9 | `sched::enter` | Transient ends; init starts running. |

**Invariants:**

1. `init_storage` MUST run before the timer is armed. The timer ISR reads `SCHEDULERS_PTR`; an unarmed-storage tick dereferences `null`.

2. Every CPU's `current` MUST be non-null before interrupts are enabled on that CPU. `sched::init` sets `current = idle_tcb` per CPU.

3. Idle threads run with `slice_remaining = 0`; `timer_tick` treats this as "do not preempt".

4. `BOOT_TRANSIENT_ACTIVE: AtomicBool` is the gate `timer_tick` consults. Set true in `init_storage`, cleared in `sched::enter` immediately before `first_entry_to_user`. The implicit `slice_remaining == 0` short-circuit is retained as a backstop.

5. APs do not enter the transient. They come up in Phase 8 (after `sched::init` allocates idle TCBs and before Phase 9 begins) via `kernel_entry_ap`; by the time an AP arms its own timer, all SMP-related state is live.

---

## IPI Taxonomy

The kernel sends three IPIs. Each has a defined purpose and correctness role.

### x86_64

`core/kernel/src/arch/x86_64/interrupts.rs`:

| Vector | Constant | Purpose | Handler | Correctness role |
|---|---|---|---|---|
| 250 | `IPI_VECTOR_TLB_SHOOTDOWN` | TLB invalidation cascade | Flushes per-CPU TLB entries staged by the issuer. | Required for rewrites that could strand a dangerous stale entry — unmap, permission narrowing, or frame replacement — where the stale entry would alias a freed/reused frame or grant revoked rights. Fresh maps and permission widenings skip the IPI and rely instead on the page-fault handler's spurious-fault retry (the live PTE already permits the access). |
| 251 | `IPI_VECTOR_WAKEUP` | Wake target CPU from `hlt` | EOI only (no work). | Required for the wake protocol's "always-IPI" invariant. The handler does no real work; the IPI's value is the trap entry itself, which exits `hlt` and re-enters the idle loop's check. |

### riscv64

`core/kernel/src/arch/riscv64/interrupts.rs`:

The riscv64 build uses one SBI IPI extension (EID `0x735049`, FID `0`) for both TLB shootdown and wakeup. The supervisor-mode trap handler distinguishes the two by side-channel state — the shootdown path scans the per-CPU TLB shootdown request slots and services any whose pending mask names this hart; a wakeup-only IPI finds no slot naming it and falls through with no work, exactly mirroring the x86_64 wakeup-vector handler.

The same correctness rules apply: shootdown is required for TLB coherence; wakeup is required for the wake protocol.

There is no FPU flush IPI on either arch. x86-64 uses eager XSAVE on switch-out (`arch::x86_64::fpu::switch_out_save`), and RISC-V uses `sstatus.FS/VS` dirty tracking with the same switch-out save discipline. By the time a thread is observable as Ready on any CPU's run queue, the canonical extended-state contents are in its TCB area — no cross-CPU coordination is required.

### Future IPIs (out of scope)

Process-stop ("kill process across all CPUs") and scheduler-quiesce IPIs are not in the current kernel. If added, they MUST be documented in this section before landing. (Tagged-TLB invalidation does not add an IPI: it reuses the existing TLB-shootdown IPI, whose request slot now carries the target PCID/ASID — see [memory-internals.md](memory-internals.md).)

---

## IPI Watchdog Ladder

Every synchronous-IPI ack wait MUST route through `arch::current::interrupts::wait_for_ack` (file: `arch/x86_64/interrupts.rs`, mirrored in `arch/riscv64/interrupts.rs`). The helper bounds the wait against wall-clock time via TSC (`timer::elapsed_us`) and escalates through four phases keyed off the elapsed-microseconds delta from the start of the wait:

| Phase | Window | Action |
|---|---|---|
| A | 0 – 250 ms | Spin with `core::hint::spin_loop()` while `cond()` reports unacked. |
| B | 250 – 750 ms | Call `ctx.resend()` once at the boundary, then continue spinning. Recovers from a dropped IPI under emulators with non-deterministic LAPIC delivery. |
| C | 750 ms – 5 s | x86-64: set `NMI_BACKTRACE_REQUEST[target_cpu]` and send a vector-2 NMI to that CPU; the target's dedicated NMI handler dumps its `TrapFrame` to serial so the eventual Phase-D panic is diagnosable. RISC-V: emit a single logged warning (no S-mode NMI surface; Phase C degrades to a warn). |
| D | > 5 s | Print `target_cpu`, `op_name`, `elapsed_ms` to serial, then `crate::fatal`. |

`wait_for_ack` MUST be called with preemption disabled and `IF=1` / `sstatus.SIE=1` — the same envelope `mm::tlb_shootdown::shootdown` establishes. The `cond` closure MUST be side-effect-free beyond the atomic loads needed to inspect pending state (it runs many times per spin).

For broadcast IPIs (TLB shootdown), `target_cpu` names the lowest-numbered CPU still pending at the start of the wait; this drives the diagnostic dump and panic message but does not constrain the ack predicate, which checks the full pending mask. The `resend` closure SHOULD re-fire only to CPUs whose bit is still set, not the full original mask.

### `wait_icr_idle` discipline

`wait_icr_idle` (x86-64 only; polls the LAPIC ICR delivery-status bit) is **not** a `wait_for_ack` consumer — it spins on a hardware register that clears within microseconds on a healthy LAPIC. A 1 M iteration cap is far beyond any architectural timing; exhaustion indicates a hardware-level fault (stuck APIC, emulator bug) and panics immediately. The four callers (`send_init_ipi`, `send_sipi`, `send_tlb_shootdown_ipi`, `send_wakeup_ipi`) call it for its side effect only; the return type is `()`.

### `ipi_nmi_backtrace_stub` / `ipi_nmi_backtrace_handler`

The x86-64 IDT registers a dedicated stub at vector 2 (IST=2 per the NMI ABI) that builds the canonical `TrapFrame`, calls a returning handler, then writes back and `iretq`s. The handler reads `NMI_BACKTRACE_REQUEST[cpu]`:
- **Set** (watchdog-requested): dump the saved frame to serial and return; the stub's `iretq` resumes the interrupted code.
- **Clear** (real hardware NMI): tail-call `common_exception_handler` which never returns — the stub's `iretq` tail is dead code in that case.

NMI is not APIC-EOI'd; the handler does not call `acknowledge()`.

---

## Atomic Ordering Invariants

Pairing table for every load-bearing atomic in the scheduling and IPC paths. "Load-bearing" means the ordering choice is required for correctness; relaxations would introduce a race.

| Atomic | File:line | Set ordering | Read ordering | Pairing rationale |
|---|---|---|---|---|
| `RESCHEDULE_PENDING` (`AtomicCpuMask`) | `sched/mod.rs:189` (decl), `:196–207` (ops) | Release on `set_reschedule_pending_for` (`set_cpu`) | AcqRel on `take_reschedule_pending` (`take_cpu`) | Release publishes the producer's prior enqueue; AcqRel ensures the consumer sees the enqueue and synchronises both directions of the bit clear. |
| `non_empty` (per PerCpuScheduler) | `sched/run_queue.rs` (decl in `PerCpuScheduler`; writes in `enqueue`, `dequeue_highest`, `remove_from_queue`; read in `has_runnable`) | Release on `enqueue.fetch_or`, `dequeue_highest.fetch_and`, `remove_from_queue.fetch_and` | Acquire on `has_runnable.load` | Release publishes the queue-mutation stores; the lockless idle-loop Acquire is the only synchronisation edge with cross-CPU enqueues on RVWMO. |
| `context_saved` (per TCB) | `sched/thread.rs:254` (decl) | Release after `context::switch` returns on the outgoing CPU | Acquire on the remote-dequeue spin-loop | Closes the partial-`SavedState`-visibility race on RVWMO; see [Cross-CPU TCB Ownership](#cross-cpu-tcb-ownership) for the full sequence. |
| `bits` (Notification) | `ipc/notification.rs:39` (decl), `:109,130,237` (ops) | Relaxed `fetch_or` in `notification_send` (`:109`), Relaxed `swap` in `notification_wait` (`:237`) and `notification_send` slow path (`:130`) | (same — paired with the SeqCst fences below) | The Dekker fence pair below provides the cross-side ordering; the bits ops themselves are Relaxed because no other field needs to be synchronised relative to them. |
| `has_observer` (Notification) + `bits` Dekker pair | `ipc/notification.rs:54` (decl) | Relaxed store on `:231` (notification_wait), Relaxed load on `:118` (notification_send) | (same) | Paired SeqCst fences in `notification_send` (`:115`, between `bits.fetch_or` and `has_observer.load`) and `notification_wait` (`:234`, between `has_observer.store` and `bits.swap`) form the Dekker pattern: either `notification_send` observes `has_observer == 1` and falls through to the slow path lock acquisition, or `notification_wait`'s swap observes the OR'd bits and returns without parking. The fences are the only ordering edge; weakening to plain `Acquire`/`Release` is **insufficient** because the read-and-write sites span two distinct atomics. |
| `RESCHEDULE_PENDING` bit (per CPU) | (same as first row) | (same) | (same) | (single entry, listed once.) |
| `BOOT_TRANSIENT_ACTIVE` | `sched/mod.rs` (decl) | Release on `init_storage` (set true) and `sched::enter` (set false) | Acquire on every `timer_tick` entry | Single-writer (BSP). The Release/Acquire pair gates `timer_tick` against firing during Phase 4–9 when the run queue and scheduler state have not yet stabilised. |
| `CPU_LOAD[cpu]` | `sched/run_queue.rs:35` (decl) | Relaxed on `increment_load`, `decrement_load` | Relaxed on `current_load` | Advisory: `select_target_cpu` and the periodic load balancer consult this; transient inconsistency does not violate correctness. The counter MUST track queue occupancy: every `enqueue` increments, every `dequeue_highest` / `remove_from_queue` decrements. |
| `fault_handler` (per TCB) | `sched/thread.rs:247` (decl) | AcqRel `swap` in `sys_thread_set_fault_handler` (rebind/unbind) and the `dealloc_object(Thread)` binding release | Acquire `load` in `ipc::fault::has_handler` / `fault_dispatch` (the faulting thread, lock-free) | The binder holds the thread's `CONTROL` cap and runs on a different CPU than the target, which loads the pointer lock-free when it faults. The `swap` returns the previous object so the binding's `inc_ref` is released exactly once per rebind; the `fault_badge` Release store is ordered before this swap so a faulter observing the new handler also observes the matching badge. |
| `fault_badge` (per TCB) | `sched/thread.rs:253` (decl) | Release `store` in `sys_thread_set_fault_handler`, sequenced before the `fault_handler` swap | Acquire `load` in `fault_dispatch` | Paired with `fault_handler` above: written before the handler swap and read after the handler load, so the (handler, badge) pair is consistent for a faulter that observes the new binding. |
| `fault_outcome` (per TCB) | `sched/thread.rs:262` (decl) | Release to `Pending` by `fault_dispatch` before delivery; Release to `Resume`/`Kill` by the single wake-claim winner — `sys_ipc_reply` (genuine reply), `server_reply_wake` (handler death), `cancel_ipc_block` / `dealloc_object(Thread)` unlink / endpoint-dealloc send-drain / `sleep_check_wakeups` (cancellation) | Acquire `load` in `fault_dispatch` after `schedule()` returns | The disposition is written only by whoever wins the `reply_tcb` CAS (or, on the send queue, the unlink), so resume-vs-kill is unambiguous; the faulter reads it on resume. Any value other than `Resume` is treated as `Kill`, defensively covering a spurious wake that leaves `Pending`. |
| `LOAD_BALANCE_TICK` | `sched/mod.rs` (decl, balancer) | Relaxed on `fetch_add` (sole writer is the loaded-path victim selection in `try_pull_balance`) | Relaxed on the same `fetch_add` (consumes the previous value) | Advisory random-victim seed; correctness does not depend on ordering — a stale value just biases victim selection slightly. |
| `NEXT_THREAD_ID` | `sched/mod.rs` (counter) | Relaxed on `fetch_add` | n/a | Monotonic counter; no synchronisation needed. |
| `CPU_COUNT` | `sched/mod.rs:124` | Relaxed on store (`init_storage`) | Relaxed on every read | Single-writer at boot; the SCHEDULERS_PTR Release publishes the storage; readers establish happens-before via the pointer load, not via CPU_COUNT itself. |
| `SCHEDULERS_PTR`, `IDLE_TCBS_PTR`, `AP_TSS_PTR`, `AP_GDT_PTR`, `AP_IST_STACKS_PTR` | per-`AtomicPtr` declaration sites | Release on `store` in `init_storage` and per-arch initialisers | Acquire on `load` in `scheduler_ptr`, `idle_tcb_ptr`, AP startup helpers | Publishes the zeroed and constructed slab to every CPU; the Acquire establishes happens-before with the storage construction. |

**Rules:**
- Any new atomic in the scheduling or IPC path MUST be added to this table with its pairing rationale before merge.
- Any change from Release/Acquire to Relaxed (or the inverse) MUST be justified against this table; "looks fine on x86" is not justification — the riscv64 build is RVWMO and is the binding test.
- SeqCst is permitted only where a Dekker-style fence pair is the proven pattern; new SeqCst uses MUST cite the proof.

---

## Process-Death and Parked-Thread Protocol

The kernel does not auto-cascade IPC unblock on process exit. The contract:

1. **`procmgr` is the authoritative driver** of process-death cleanup. When a process dies, `procmgr` revokes the process's capabilities; the kernel's revocation path (see [capability-internals.md](capability-internals.md)) drives the unblock cascade for objects whose last reference is dropped.

2. **Kernel-side unblock sites that DO exist:**
   - `event_queue_drop` (`core/kernel/src/ipc/event_queue.rs:254–273`): when the EQ refcount hits zero, any parked consumer is woken with `wakeup_value = 0`. The consumer's syscall return path treats `wakeup_value == 0` as "object gone" via the `timed_out` companion flag (`core/kernel/src/sched/thread.rs:207–216`).
   - `wait_set_drop` (`core/kernel/src/ipc/wait_set.rs:490–545`): walks every member's source, clears the back-pointer under the source's lock, then wakes any blocked waiter on the wait set itself.
   - `notification` and `endpoint` do **not** auto-unblock parked threads on drop today. A blocked sender on an endpoint that loses its last cap holder will remain blocked indefinitely. This is by design at the kernel level — capability revocation is the higher-level mechanism.

3. **Wait-set member lifetime is refcounted.** `core/kernel/src/ipc/wait_set.rs` still holds raw `source_ptr`s into endpoint/notification/EQ objects, but each `WaitSetMember` now also holds a +1 cap-level reference on the source's `KernelObjectHeader`. `sys_wait_set_add` performs the `inc_ref` under the source's lock together with the back-pointer publication; `sys_wait_set_remove` and `wait_set_drop` perform the matching `dec_ref`. A source whose `dec_ref` drops to zero inside `wait_set_drop` is returned to the WaitSet arm of `dealloc_object_one` and pushed onto the cascade worklist — the source's own dealloc therefore runs after every IPC source/ws lock has been released, satisfying rule 5 of the Lock Hierarchy. Sources can no longer be reclaimed while a member references them, so `waitset_wait` cannot dereference a dangling `source_ptr`.

4. **Thread death observers fire from the dying thread's exit path** (`core/kernel/src/sched/thread.rs:34–55,256–278`). Each observer is an `(EventQueueState*, correlator: u32)` pair; the kernel posts `(correlator << 32) | exit_reason` to each observer's queue. This mechanism is the procmgr/svcmgr-facing API; it does not interact with the parked-thread protocol above.

---

## Off-Stack Scratch for Ceiling-Sized Arrays

Kernel scratch whose length is a compile-time ceiling (`MAX_CPUS`,
`MAX_SLEEPING`) MUST NOT be allocated as a stack-local array in either context
below. It MUST live off-stack via one of the two idioms in the table.

- **Timer-ISR-reachable paths.** `sleep_check_wakeups` is inlined into
  `timer_tick`, which runs in the timer ISR (`isr_timer`, IST=0) on the kernel
  stack of whatever thread the tick interrupted. A `[_; MAX_SLEEPING]` frame
  there overruns that borrowed stack.
- **All-CPU-locks lifecycle paths.** `set_state_under_all_locks`,
  `sys_thread_set_priority`, and `dealloc_object(Thread)` each save one
  interrupt-flag word per CPU across the all-CPU-locks region (Lock Hierarchy
  rule 4). A `[u64; MAX_CPUS]` frame on the caller's syscall stack scales with
  the CPU ceiling — 4 KiB at `MAX_CPUS = 512`.

The failure mode is silent and not size-checked by the compiler: the oversized
frame clobbers a saved return-address chain and the next `ret` faults with
`#PF rip=0` (reproduced for the timer-ISR case at ~5 % on x86_64 TCG-SMP;
PR #167).

| Off-stack idiom | Use when | Why no extra synchronisation | Site |
|---|---|---|---|
| CPU0-owned `static mut` singleton | The path runs in exactly one non-reentrant context — a CPU0-gated ISR path behind an interrupt gate (IF=0). | The path is non-reentrant, so the single buffer needs no lock. | `EXPIRED_SCRATCH` (`core/kernel/src/sched/mod.rs`) — `sleep_check_wakeups` expired-TCB snapshot (PR #167). |
| Per-CPU field on `PerCpuScheduler`, written under that CPU's own `scheduler.lock` | Several CPUs run the path serially and each needs its own slot. | Each CPU writes only its own slot, only while holding that CPU's `scheduler.lock`; the all-CPU-locks region serialises every writer of a given slot, so the field needs no atomicity. | `saved_lock_flags` (`core/kernel/src/sched/run_queue.rs`) — per-CPU flag word for all three all-CPU-locks sites above (issue #168). |

No `[_; MAX_CPUS]` or `[_; MAX_SLEEPING]` stack scratch remains in the kernel;
CPU-set state at the ceiling is carried as bitvectors
(`core/kernel/src/cpu_mask.rs`), not per-CPU stack arrays.

---

## Softlockup Watchdog

Permanent kernel feature. Detects "every CPU stalled in kernel mode" — the
failure class userspace cannot observe, because no userspace runs when every
CPU is wedged.

**Mechanism (`core/kernel/src/sched/mod.rs`):** `schedule()` updates a per-CPU
`LAST_NON_IDLE_TICK` whenever it dispatches a non-idle thread; the BSP
`timer_tick` increments a global tick counter and, once per stall, dumps
per-CPU TCB state (`current`, `state`, `ipc_state`, `blocked_on_object`,
priority, preferred_cpu, idle age, non-empty mask) plus the head of
`SLEEP_LIST` if every CPU's last dispatch is older than
`WATCHDOG_THRESHOLD_TICKS` (~3 s at the observed ~1 ms tick). Single-shot
via `WATCHDOG_FIRED`.

**Cost:** one Relaxed counter increment per BSP timer tick, one Relaxed
store per non-idle context switch, an O(MAX_CPUS) early-exit loop per tick.
Zero overhead when healthy.

**Catches:** all-CPUs-idle with work queued (lost-wake bugs); cross-CPU
`context_saved` deadlock; every TCB incorrectly `Blocked`.

**Does NOT catch:** a single CPU spinning IRQ-disabled while peers make
progress (no all-CPUs notification); BSP hardlockup (BSP timer stops, counter
stops, detector can't fire). A future hardlockup detector (NMI / always-on
S-mode timer) would close the latter gap; tracked as issue #33.

**Defers to an in-flight TLB shootdown:** a synchronous shootdown holds every
participating CPU (initiator preempt-disabled in `wait_for_ack`; peers spinning
in `pt_lock` or their own shootdown) until all remote CPUs ack. Under heavy
oversubscription that round-trip can exceed the threshold while still making
progress, so the detector skips firing while `tlb_shootdown::any_pending()`
reports any per-CPU request slot with CPUs still to ack. The shootdown's own
escalation ladder (NMI backtrace at 0.75 s, panic at 5 s in arch
`wait_for_ack`) is the authoritative detector for a genuinely stuck IPI; a
non-shootdown stall re-checks on the next tick once the pending slots drain.

**Why kernel-side:** when every CPU is in kernel mode, no userspace monitor
gets dispatched. The dump is also the only path that reads per-CPU
scheduler state without taking a lock that the stalled CPUs themselves hold.

**Bounded-spin diagnostics elsewhere:** two protocol-required spins (the
`context_saved` Acquire spin in `schedule()`; the cross-CPU drain spin in
`sys_thread_stop`) carry single-shot overlong-duration warnings. These are
not the watchdog; they fire only when the spin overruns and identify the
stuck participants. Zero overhead in healthy paths.

---

## Summarized By

[kernel/README.md](../README.md)
