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
- `core/kernel/src/ipc/{endpoint,signal,event_queue,wait_set}.rs`
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

1. **scheduler.lock is outermost on the IPC-blocking path.** Every IPC syscall handler (`sys_endpoint_call`, `sys_signal_wait`, `sys_event_recv`, `sys_wait_set_wait`, etc.) acquires the calling CPU's `scheduler.lock` before entering the IPC primitive's code. The IPC primitive is then permitted to acquire its own source lock under that scheduler lock.

2. **At most one source IPC lock at a time.** A code path holding `sig.lock` MUST NOT acquire `ep.lock`, `eq.lock`, or `ws.lock`. The single exception is `waitset_notify`, which is invoked from within a source lock (the source notifying the wait set) and acquires `ws.lock` as the inner lock — order `source.lock → ws.lock` only.

3. **`SLEEP_LIST_LOCK` is leaf-only.** It MAY be acquired from inside any source IPC lock. It MUST NOT contain calls that re-enter IPC or scheduler code while held.

4. **Cross-CPU scheduler-lock acquisition rule.** When a code path needs two CPU's `scheduler.lock`s simultaneously (load balancer, future cross-CPU migration), the lower-numbered CPU's lock MUST be acquired first. As of this document there is one such site (none in production code; the load-balancer claimed in `scheduler.md` does not yet exist).

5. **`enqueue_and_wake` MUST be invoked with no IPC source lock held.** A primitive that wakes a TCB (e.g. `signal_send`, `event_queue_post`, `waitset_notify`, `endpoint_call`'s server-wake branch, `endpoint_reply`) snapshots the wake parameters under its source lock, releases the source lock, then calls `enqueue_and_wake`. `enqueue_and_wake` acquires the *target CPU*'s scheduler.lock and dispatches an IPI; holding any source lock across that call would introduce a `source.lock → scheduler.lock` ordering that does not exist in the hierarchy.

6. **Derivation tree lock is ordered after IPC object locks.** `SYS_CAP_REVOKE` MUST NOT acquire IPC object locks while holding the derivation tree write lock — see [capability-internals.md](capability-internals.md) for the deferred-cleanup pattern.

7. **`cancel_ipc_block` MUST acquire the source lock matching `tcb.ipc_state`.** Every read or write of `source.waiter` (or the equivalent intrusive-queue field) requires the source lock; reads from non-owning CPUs without the source lock are races. The dealloc paths in `core/kernel/src/cap/object.rs` (Endpoint, Signal, EventQueue, WaitSet, and Thread arms) follow the same rule.

8. **Blocking commit MUST go through `commit_blocked_under_local_lock`.** A primitive that parks the calling thread (`signal_wait`, `event_queue_recv`, `endpoint_call`, `endpoint_recv`, `waitset_wait`) MUST commit the `Running → Blocked` transition via `crate::sched::commit_blocked_under_local_lock(tcb, ipc_state, blocked_on)`. The helper acquires the *current CPU*'s scheduler.lock, reads `state`, and only writes `Blocked` if `state ∈ {Running, Ready}`. On a `false` return (a concurrent `set_state_under_all_locks(Stopped)` has already won) the caller MUST roll back the source-side waiter registration before releasing the source IPC lock. Direct writes to `(*tcb).state = Blocked` from outside the local sched.lock are forbidden — they race the all-locks `Stopped` write in `sys_thread_stop` and silently clobber it. Lock order: source IPC lock (outer, held by the IPC primitive) → current CPU's scheduler.lock (inner, acquired by `commit_blocked_under_local_lock`).

9. **Wake commit MUST go through `enqueue_and_wake`.** Wake primitives MUST NOT write `(*tcb).state = Ready`, `ipc_state = None`, or `blocked_on_object = null` themselves under the source IPC lock; they MUST snapshot the wakeup payload (`wakeup_value`, `timed_out`) under the source lock and delegate the state writes to `enqueue_and_wake`, which performs them under the target CPU's scheduler.lock. The function reads `state` first; if `Stopped` or `Exited` the enqueue is *skipped* entirely (preventing UAF when a concurrent `dealloc_object(Thread)` is racing the wake). This rule applies equally to dealloc-time wake walks (`endpoint_dealloc` send/recv heads, `signal_dealloc` waiter, `event_queue_drop`, `wait_set_drop`).

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
| `Running` | `Ready` | `schedule(requeue_current=true)` (yield, preempt) | running CPU | running CPU's scheduler.lock |
| `Running` | `Blocked` | IPC blocking entry (`endpoint_call/recv`, `signal_wait`, `event_queue_recv`, `waitset_wait`) | running CPU | `commit_blocked_under_local_lock(tcb, ipc, blocked_on)`; on `false` the IPC primitive rolls back its waiter registration |
| `Blocked` | `Ready` | IPC wake (`signal_send`, `event_queue_post`, `endpoint_reply`, `endpoint_call` server-wake, `waitset_notify`) | wake-issuing CPU | source IPC lock to snapshot wakeup payload, *released*, then `enqueue_and_wake(target_cpu)` |
| `Blocked` | `Ready` | timeout from sleep list | timer-firing CPU | `SLEEP_LIST_LOCK` to drain expired entries (released first), then source IPC lock to arbitrate `(*src).waiter == tcb` and write the wake payload, then `enqueue_and_wake(target_cpu)` |
| `Blocked` | `Ready` | `cancel_ipc_block` (called from `sys_thread_stop` on a blocked target) | calling CPU | scheduler.lock (already held by caller) + source IPC lock matching `tcb.ipc_state` |
| `Running` | `Stopped` | `sys_thread_stop` on running target | calling CPU | `set_state_under_all_locks(Stopped)`; if running on a remote CPU, `prod_remote_cpu(run_cpu)` and spin until `sched_remote.current != tcb` |
| `Ready` | `Stopped` | `sys_thread_stop` on a Ready target | calling CPU | `set_state_under_all_locks(Stopped)`; the `schedule()` skip-loop drains the stale Ready entry on the next dequeue |
| `Blocked` | `Stopped` | `sys_thread_stop` on blocked target | calling CPU | `cancel_ipc_block` first (acquires the source IPC lock and unlinks the waiter), then `set_state_under_all_locks(Stopped)` |
| `*` | `Exited` | `sys_thread_exit` (self) or fault handler | running CPU | `set_state_under_all_locks(Exited)` (on the dying CPU), then `schedule(false)` |
| `*` | `Exited` | `dealloc_object(Thread)` (refcount → 0) | calling CPU | acquires every CPU's scheduler.lock in ascending order, writes `Exited`, walks `remove_from_queue` for every CPU, snapshots `running_on`, releases all; then waits for both `sched.current != tcb` *and* `tcb.context_saved == 1` (see Cross-CPU TCB Ownership) before freeing |

All `Running→Blocked` parks MUST route through `commit_blocked_under_local_lock`; all `Blocked→Ready` wakes MUST route through `enqueue_and_wake`. Direct `(*tcb).state` writes from an IPC primitive — under the source lock or otherwise — are forbidden; they race `set_state_under_all_locks(Stopped)` and silently clobber Stopped.

---

## Cross-CPU TCB Ownership

The TCB is owned in pieces. Different field groups have different lock disciplines. Cross-CPU access to any field MUST hold the lock specified for that field's group.

| Field group | Fields | Owning lock | Cross-CPU access rule |
|---|---|---|---|
| **Scheduling** | `state`, `priority`, `slice_remaining`, `cpu_affinity`, `preferred_cpu`, `run_queue_next` | The scheduler.lock of whichever CPU's run queue currently links the TCB. For threads not on any run queue (blocked or running), the *home* CPU's scheduler.lock — the one that would re-enqueue on wake. | Cross-CPU writers MUST acquire the home CPU's scheduler.lock. |
| **IPC blocking** | `ipc_state`, `blocked_on_object`, `ipc_msg`, `ipc_wait_next`, `wakeup_value`, `timed_out` | The source IPC lock matching `ipc_state` (or `None` if not blocked). | Cross-CPU writers MUST acquire the matching source lock; reads from another CPU MUST do the same. |
| **Reply slot** | `reply_tcb` | `AtomicPtr<ThreadControlBlock>`; lock-free with `Acquire`/`Release` ordering, and `compare_exchange` for cancel. | Endpoint paths set/clear it under `ep.lock`; the cancel path on a remote CPU uses `compare_exchange(client, null)` so it never clobbers a different client's binding. `reply_tcb` is the one TCB field with no single owning lock — multiple lock domains write it (the various `endpoint_*` paths under `ep.lock`, plus `cancel_ipc_block` from outside any lock), which is why it is atomic. |
| **Context save/restore** | `saved_state`, `kernel_stack_top`, `trap_frame`, `context_saved` | Owning-CPU's scheduler.lock for read; the running CPU writes `saved_state` during `Context::switch` (no lock; write is serialised with the next reader by `context_saved` Acquire/Release). | A remote CPU dequeueing this TCB MUST spin-wait on `context_saved` (Acquire load) before reading any other context field. |
| **Address-space / capability** | `address_space`, `cspace`, `iopb` | Set once at create-time / configure-time; treated as read-only after `sys_thread_start`. | No cross-CPU write is permitted; reads need no lock. |
| **Identity** | `thread_id`, `magic` | Immutable after construction. | Read freely. |
| **IPC buffer** | `ipc_buffer` | Set by `SYS_IPC_BUFFER_SET`; logically owned by the thread itself. | The thread reads it under no lock from its own kernel-mode syscall path; other CPUs MUST NOT read it. |
| **Death observers** | `death_observers`, `death_observer_count`, `sleep_deadline` | Owning-CPU's scheduler.lock for `death_observers`/`death_observer_count`; for `sleep_deadline`, the source IPC lock that initiated the timed wait + `SLEEP_LIST_LOCK`. | Cross-CPU writes follow the per-field rule above. |

**Magic-cookie discipline.** `magic == TCB_MAGIC` MUST be read on every dereference of a TCB pointer that crossed a CPU boundary or came from an intrusive list (run queue, IPC wait queue, sleep list, death observer). `core/kernel/src/sched/run_queue.rs:223,272` already does this for run-queue ops; the same pattern applies anywhere a stale pointer might be observed.

**`context_saved` protocol (`core/kernel/src/sched/thread.rs`).** This is the load-bearing cross-CPU synchronisation for context-switch correctness on RVWMO *and* the publication barrier protecting TCB lifetime against `dealloc_object(Thread)`:

```
Outgoing CPU (in schedule()):
  1. context_saved.store(0, Relaxed)               // before unlock
  2. sched.set_current(next)                       // sched.current = next
  3. sched.lock.release_lock_only()                // remote dequeue / dealloc can now observe
  4. arch::Context::switch(&out.saved_state, &in.saved_state)
  5. context_saved.store(1, Release)               // after switch completes

Remote dequeue (after dequeue_highest returns this TCB):
  6. while context_saved.load(Acquire) == 0 { spin_loop() }
  7. // saved_state is now safe to read on this CPU

dealloc_object(Thread) (after the all-locks region releases):
  8. if running_on == Some(cpu): spin until sched.current != tcb
  9. while context_saved.load(Acquire) == 0 { spin_loop() }    // unconditional
 10. // safe to free TCB body and kernel stack
```

The Release in step 5 pairs with both the Acquire in step 6 (cross-CPU dequeue) and the Acquire in step 9 (TCB free). Without step 9, the lock release at step 3 lets `dealloc_object(Thread)` observe `sched.current = idle` (set at step 2) *while step 4 is still writing into `tcb.saved_state`* — freeing the TCB at that point lets the next allocation reuse the memory and `switch()` then corrupts the new allocation. The check is unconditional on the result of `running_on`, because the all-locks `running_on` snapshot can race step 2/3 and miss the in-flight switch. New TCBs initialise `context_saved = 1`, so the wait is bounded for threads that never ran.

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
   (RESCHEDULE_PENDING.fetch_or(1 << target_cpu, Release).)
7. Release target scheduler.lock.
8. wake_idle_cpu(target_cpu)  →  sends IPI (always; see below).
```

The producer-side `state`/`ipc_state`/`blocked_on_object` writes belong to `enqueue_and_wake` — wake primitives MUST NOT do them under the source IPC lock. See Lock Hierarchy rule 9.

Consumer side (`idle_thread_entry`, `core/kernel/src/sched/mod.rs:444+`):

```
1. Mask interrupts.
2. pending = take_reschedule_pending(cpu)          // RESCHEDULE_PENDING.fetch_and(!bit, AcqRel)
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

5. **`take_reschedule_pending` MUST use AcqRel** (the Acquire half pairs with the producer's Release `fetch_or`; the Release half is conservative but avoids a separate-fence requirement).

**Why two signals.** `non_empty` (per-CPU `AtomicU32`, "Ready thread at some
priority") is updated by enqueue/dequeue and is the dispatcher's signal.
`RESCHEDULE_PENDING` (global `AtomicU64`, one bit per CPU) is set by
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

5. APs do not enter the transient. They come up in Phase 9 via `kernel_entry_ap` after the BSP is past `sched::init`; by the time an AP arms its own timer, all SMP-related state is live.

---

## IPI Taxonomy

The kernel sends two IPIs. Each has a defined purpose and correctness role.

### x86_64

`core/kernel/src/arch/x86_64/interrupts.rs`:

| Vector | Constant | Purpose | Handler | Correctness role |
|---|---|---|---|---|
| 250 | `IPI_VECTOR_TLB_SHOOTDOWN` | TLB invalidation cascade | Flushes per-CPU TLB entries staged by the issuer. | Required: a writer that modifies a page-table entry MUST shoot down peer CPUs' TLBs before guaranteeing the change is observable. |
| 251 | `IPI_VECTOR_WAKEUP` | Wake target CPU from `hlt` | EOI only (no work). | Required for the wake protocol's "always-IPI" invariant. The handler does no real work; the IPI's value is the trap entry itself, which exits `hlt` and re-enters the idle loop's check. |

### riscv64

`core/kernel/src/arch/riscv64/interrupts.rs`:

The riscv64 build uses one SBI IPI extension (EID `0x735049`, FID `0`) for both TLB shootdown and wakeup. The supervisor-mode trap handler distinguishes the two by side-channel state — the shootdown path consults a per-CPU pending-shootdown bitmap; the wakeup path falls through with no work, exactly mirroring the x86_64 wakeup-vector handler.

The same correctness rules apply: shootdown is required for TLB coherence; wakeup is required for the wake protocol.

### Future IPIs (out of scope)

Process-stop ("kill process across all CPUs"), TLB-shootdown-with-PCID variants, and scheduler-quiesce IPIs are not in the current kernel. If added, they MUST be documented in this section before landing.

---

## Atomic Ordering Invariants

Pairing table for every load-bearing atomic in the scheduling and IPC paths. "Load-bearing" means the ordering choice is required for correctness; relaxations would introduce a race.

| Atomic | File:line | Set ordering | Read ordering | Pairing rationale |
|---|---|---|---|---|
| `RESCHEDULE_PENDING` | `sched/mod.rs:148` (decl), `:155–169` (ops) | Release on `set_reschedule_pending_for` (`fetch_or`) | AcqRel on `take_reschedule_pending` (`fetch_and`) | Release publishes the producer's prior enqueue; AcqRel ensures the consumer sees the enqueue and synchronises both directions of the bit clear. |
| `non_empty` (per PerCpuScheduler) | `sched/run_queue.rs:159` (decl), `:239,281,327,352,358` (writes), `:308` (read) | Release on `enqueue.fetch_or`, `dequeue.fetch_and`, `remove_from_queue.fetch_and`, `change_priority.fetch_*` | Acquire on `has_runnable.load` | Release publishes the queue-mutation stores; the lockless idle-loop Acquire is the only synchronisation edge with cross-CPU enqueues on RVWMO. |
| `context_saved` (per TCB) | `sched/thread.rs:254` (decl) | Release after `Context::switch` returns on the outgoing CPU | Acquire on the remote-dequeue spin-loop | Closes the partial-`SavedState`-visibility race on RVWMO; see [Cross-CPU TCB Ownership](#cross-cpu-tcb-ownership) for the full sequence. |
| `bits` (Signal) | `ipc/signal.rs:39` (decl), `:109,130,237` (ops) | Relaxed `fetch_or` in `signal_send` (`:109`), Relaxed `swap` in `signal_wait` (`:237`) and `signal_send` slow path (`:130`) | (same — paired with the SeqCst fences below) | The Dekker fence pair below provides the cross-side ordering; the bits ops themselves are Relaxed because no other field needs to be synchronised relative to them. |
| `has_observer` (Signal) + `bits` Dekker pair | `ipc/signal.rs:54` (decl) | Relaxed store on `:231` (signal_wait), Relaxed load on `:118` (signal_send) | (same) | Paired SeqCst fences in `signal_send` (`:115`, between `bits.fetch_or` and `has_observer.load`) and `signal_wait` (`:234`, between `has_observer.store` and `bits.swap`) form the Dekker pattern: either `signal_send` observes `has_observer == 1` and falls through to the slow path lock acquisition, or `signal_wait`'s swap observes the OR'd bits and returns without parking. The fences are the only ordering edge; weakening to plain `Acquire`/`Release` is **insufficient** because the read-and-write sites span two distinct atomics. |
| `RESCHEDULE_PENDING` bit (per CPU) | (same as first row) | (same) | (same) | (single entry, listed once.) |
| `BOOT_TRANSIENT_ACTIVE` | `sched/mod.rs` (decl) | Release on `init_storage` (set true) and `sched::enter` (set false) | Acquire on every `timer_tick` entry | Single-writer (BSP). The Release/Acquire pair gates `timer_tick` against firing during Phase 4–9 when the run queue and scheduler state have not yet stabilised. |
| `CPU_LOAD[cpu]` | `sched/run_queue.rs:35` (decl) | Relaxed on `increment_load`, `decrement_load` | Relaxed on `current_load` | Advisory: `select_target_cpu` consults this for load balancing; transient inconsistency does not violate correctness. |
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
   - `signal` and `endpoint` do **not** auto-unblock parked threads on drop today. A blocked sender on an endpoint that loses its last cap holder will remain blocked indefinitely. This is by design at the kernel level — capability revocation is the higher-level mechanism.

3. **Wait-set member lifetime is manual.** `core/kernel/src/ipc/wait_set.rs` holds raw `source_ptr`s into endpoint/signal/EQ objects. If a source is dropped while a wait set still holds a member referencing it, `waitset_wait` will dereference a dangling pointer. The current contract requires the binder to remove the member before dropping the source.

4. **Thread death observers fire from the dying thread's exit path** (`core/kernel/src/sched/thread.rs:34–55,256–278`). Each observer is an `(EventQueueState*, correlator: u32)` pair; the kernel posts `(correlator << 32) | exit_reason` to each observer's queue. This mechanism is the procmgr/svcmgr-facing API; it does not interact with the parked-thread protocol above.

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
progress (no all-CPUs signal); BSP hardlockup (BSP timer stops, counter
stops, detector can't fire). A future hardlockup detector (NMI / always-on
S-mode timer) would close the latter gap; tracked in `TODO.md`.

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

None
