# Thread Lifecycle and Sleep List Invariants

This document specifies the cross-cutting invariants for thread lifecycle transitions (`sys_thread_{start,stop,resume,exit}` and `dealloc_object(Thread)`), the global sleep list (`SLEEP_LIST` + `SLEEP_LIST_LOCK`), and the timer-driven wakeup arbitration in `sleep_check_wakeups`. It is sibling to [scheduling-internals.md](scheduling-internals.md) and binds the same authority for the surfaces below; cross-cutting concurrency rules established there (lock hierarchy, cross-CPU TCB ownership, wake protocol) MUST hold here.

This document is the authoritative reference consulted before any change that touches:
- `core/kernel/src/sched/mod.rs` — `sleep_list_add`, `sleep_list_remove`, `sleep_check_wakeups`, `post_death_notification`.
- `core/kernel/src/syscall/{thread,mod}.rs` — `sys_thread_start`, `sys_thread_stop`, `sys_thread_set_priority`, `sys_exit`, `sys_thread_sleep`, `cancel_ipc_block`.
- `core/kernel/src/cap/object.rs` — `ObjectType::Thread` arm of `dealloc_object_one`.
- The fault handlers in `core/kernel/src/arch/{x86_64/idt.rs,riscv64/interrupts.rs}` that drive thread-fault exits.

---

## Document Boundary

Cross-cutting concerns owned by [scheduling-internals.md](scheduling-internals.md) — lock hierarchy, the global wake protocol, IPI taxonomy, BSP boot transient, atomic-ordering invariants, the IPC-blocking field group of TCB ownership — are NOT restated here. Where this document references them it links back; where this document adds rules they MUST be consistent with the parent invariants.

| Doc | Owns |
|---|---|
| [scheduling-internals.md](scheduling-internals.md) | Lock hierarchy, cross-CPU TCB ownership table, wake protocol, BSP boot transient, IPI taxonomy, atomic ordering pairings. |
| **This document** | Sleep-list capacity and BSP-servicing model; `timed_out` cross-CPU protocol; `sys_thread_{start,stop,resume,exit}` state-machine table; `dealloc_object(Thread)` cross-CPU drain protocol; `BlockedOnReply` edge between client cancel and server dealloc. |
| [scheduler.md](scheduler.md) | Scheduling algorithm (priority, FIFO, slice, affinity, idle role). |
| [ipc-internals.md](ipc-internals.md) | IPC primitive object layouts and syscall paths. |

---

## Surface

In scope:

- `core/kernel/src/sched/mod.rs` — sleep list + `post_death_notification`.
- `core/kernel/src/sched/thread.rs` — `ThreadState`, `IpcThreadState`, TCB.
- `core/kernel/src/syscall/{thread,mod}.rs` — lifecycle syscalls and `cancel_ipc_block`.
- `core/kernel/src/cap/object.rs` — `ObjectType::Thread` arm of `dealloc_object_one`.
- `core/kernel/src/arch/{x86_64/idt.rs,riscv64/interrupts.rs}` — fault → Exited transition.

---

## Sleep List Invariants

The sleep list is a single global fixed-capacity array of TCB pointers. A TCB is on the list when its `sleep_deadline != 0` AND it has been registered via `sleep_list_add`. The BSP timer tick scans the list, claims expired entries under `SLEEP_LIST_LOCK`, releases the lock, and arbitrates wake claims against concurrent IPC sources via the relevant source IPC lock (Signal / EventQueue / "plain sleep" only — `sys_thread_sleep` is a plain sleep with no source).

**Invariants the sleep list MUST hold:**

1. **`SLEEP_LIST_LOCK` is leaf-only.** Per [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 3. Wake direction is `source.lock → SLEEP_LIST_LOCK`; timer direction releases `SLEEP_LIST_LOCK` before any source lock — sequential, not nested.

2. **A TCB on the sleep list MUST be in `Blocked` state.** The timer arbitration relies on this; non-`Blocked` is treated as already-woken and the claim fails benignly.

3. **`sleep_deadline != 0` is the in-band "registered" signal.** Set before `sleep_list_add`; cleared by whichever path claims the wake (sender, timer, or `cancel_ipc_block`). `sleep_list_remove` is idempotent.

4. **Capacity is hard.** At `SLEEP_COUNT == MAX_SLEEPING`, `sleep_list_add` returns `Err(())`. Parking syscalls either roll back to an indefinite IPC wait (`sys_signal_wait`, `sys_event_recv`) or surface `OutOfMemory` (`sys_thread_sleep`). Silent drop is forbidden — it would hang the parker.

5. **`sleep_check_wakeups` is BSP-only.** APs' timer ticks do not touch the sleep list. A BSP stuck in an interrupt-disabled critical section delays all timeout wakes; this is a deliberate simplification, not an oversight.

6. **Snapshot-then-claim arbitration.** The timer drains `expired[..n]` under `SLEEP_LIST_LOCK`, releases, then for each entry snapshots `(ipc_state, blocked_on_object)` and dispatches:
   - `BlockedOnSignal` / `BlockedOnEventQueue`: take the source lock; claim iff `(*src).waiter == tcb`.
   - default (plain sleep, `None`): claim unconditionally; no concurrent waker.

   The snapshot is read without the source lock; the `waiter == tcb` check under the source lock is the authoritative arbitration (stale snapshot = benign skip).

7. **Wake-side `sleep_list_remove` MUST be inside the source IPC lock, preceded by clearing `sleep_deadline = 0`.** Producer half of the snapshot-then-claim protocol. See `signal_send` and `event_queue_post`.

8. **`sleep_list_add` from a parking syscall MUST re-acquire the source IPC lock and verify `(*src).waiter == tcb` before arming.** Without the recheck, a wake firing in the window between the IPC primitive releasing its source lock and the syscall arming the deadline leaves the TCB on the sleep list with stale state. The next unrelated `signal_wait` / `event_recv` on this TCB is then hijacked by `sleep_check_wakeups`, delivering `wakeup_value = 0` instead of real bits/payload. See `sys_signal_wait` and `sys_event_recv`.

---

## `timed_out` Cross-CPU Protocol

`tcb.timed_out: bool` is a single-cell out-of-band marker that distinguishes "data-delivered wake" from "timeout wake" for IPC primitives whose payload may itself be zero (notably `sys_event_recv`, contrast `sys_signal_wait` whose `wakeup_value == 0` is unambiguous because `signal_send` rejects zero-bit sends).

**Invariants:**

1. **`timed_out` is in the IPC blocking field group** per [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership). Cross-CPU writers MUST hold the matching source IPC lock at the moment of write. Today the only writer is `sleep_check_wakeups`'s `BlockedOnEventQueue` arm under `eq.lock`; this is correct.

2. **Reader is the resuming syscall.** After `schedule()` returns, the resuming syscall (currently `sys_event_recv` only) reads-and-clears `timed_out` and `wakeup_value` as a pair. The reader is single-CPU (the resuming CPU is `current_tcb`'s CPU); no lock required. Both fields MUST be cleared by the reader before the syscall returns, so a subsequent `sys_event_recv` on the same TCB starts from a clean slate.

3. **Mutual exclusion of payload paths.** Exactly one of two outcomes occurs after a timed wait blocks:
   - `event_queue_post` writes `wakeup_value = payload`, sets state = Ready, removes from sleep list, releases `eq.lock`. `timed_out` remains `false`.
   - `sleep_check_wakeups` BlockedOnEventQueue arm writes `wakeup_value = 0`, sets `timed_out = true`, sets state = Ready, releases `eq.lock`.
   
   The `(*eq).waiter == tcb` arbitration under `eq.lock` ensures exactly one of these paths fires per park. The reader can then trust that `timed_out == true` ⇔ "no payload" and `timed_out == false` ⇔ "wakeup_value is the payload" (which may legitimately be zero).

4. **No third writer.** `cancel_ipc_block` MUST NOT touch `timed_out`. A cancelled wait returns `Interrupted`, not "timed out"; the next time the cancelled thread is started by `sys_thread_start`, its trap-frame return slot already carries `Interrupted` (set by `cancel_ipc_block`) and the syscall layer never re-reads `timed_out` for that resume. Additional writers would race the reader and break the mutual-exclusion invariant.

---

## Lifecycle State Machine

This table is the authoritative per-transition rule set for the lifecycle syscalls. It refines the [ThreadState Transitions](scheduling-internals.md#threadstate-transitions) table in `scheduling-internals.md` by binding each `sys_thread_*` syscall to the canonical helper / lock(s) the handler uses for the target's `state` write.

| Syscall | Source state | Destination state | Performing CPU | Canonical state-write helper |
|---|---|---|---|---|
| `sys_cap_create_thread` | (uninit) | `Created` | calling CPU | none — TCB not yet visible to schedulers; written in-place during construction. |
| `sys_thread_configure` | `Created` | `Created` | calling CPU | does NOT touch `state`; mutates `trap_frame` and `saved_state.fs_base`. Target MUST be `Created`. |
| `sys_thread_start` (first start) | `Created` | `Ready` | calling CPU | `set_state_under_all_locks(target, Ready)` then `enqueue_and_wake(target_cpu)`. The all-locks write closes the dealloc race: a concurrent `dealloc_object(Thread)` on another CPU cannot free the TCB between the state write and `enqueue_and_wake`'s lock acquisition. |
| `sys_thread_start` (resume from stop) | `Stopped` | `Ready` | calling CPU | Same as first-start. The kernel uses `sys_thread_start` for both first-start and resume; this overload is intentional and `Stopped → Ready` is a permitted transition. |
| `sys_thread_stop` (running self) | `Running` | `Stopped` | calling CPU = running CPU | `set_state_under_all_locks(target, Stopped)`, then `schedule(false)` immediately yields. The skip-loop in `schedule()` never re-enqueues a `Stopped` TCB. |
| `sys_thread_stop` (running remote) | `Running` | `Stopped` | calling CPU ≠ running CPU | `set_state_under_all_locks(target, Stopped)` returns `Some(run_cpu)`; the syscall handler then calls `prod_remote_cpu(run_cpu)` (sends an IPI so the target traps into kernel and runs `schedule()`) and bounded-spins until `sched_remote.current != target_tcb`. The IPI is required for `sys_thread_read_regs` to observe a fresh `trap_frame` snapshot rather than stale registers from the target's previous kernel entry. |
| `sys_thread_stop` (Ready, on a run queue) | `Ready` | `Stopped` | calling CPU | `set_state_under_all_locks(target, Stopped)`. The `schedule()` skip-loop drains the stale Ready entry on the next dequeue. |
| `sys_thread_stop` (Blocked) | `Blocked` | `Stopped` | calling CPU | `cancel_ipc_block(target)` first (acquires the source IPC lock matching `tcb.ipc_state` and unlinks the waiter), then `set_state_under_all_locks(target, Stopped)`. |
| `sys_thread_stop` (Created or Exited or Stopped) | `*` | `*` | calling CPU | n/a — returns `InvalidState`. No state write. |
| `sys_thread_set_priority` | `*` | `*` (priority changed) | calling CPU | Direct write to `(*tcb).priority`. For threads currently on a run queue, the priority field is read by `dealloc_object(Thread)` *inside* the all-locks region (see Drain Protocol), and re-read by the next `enqueue_and_wake` under the target sched.lock; intermediate writes are benign. |
| `sys_thread_set_affinity` | `*` | `*` | calling CPU | Direct write to `cpu_affinity` only; takes effect on the next enqueue. |
| `sys_thread_read_regs` | `Stopped` | `Stopped` | calling CPU | none beyond the source-state check. Caller-supplied buffer is the destination; no scheduler-state mutation. |
| `sys_thread_write_regs` | `Stopped` | `Stopped` | calling CPU | none beyond the source-state check. Validates user `TrapFrame` then writes; target is not running (state == Stopped). |
| `sys_exit` (self) | `*` | `Exited` | running CPU = current CPU | `set_state_under_all_locks(self, Exited)`, then `post_death_notification`, then `schedule(false)`. The all-locks write ensures any peer-CPU `schedule()` reading `state` under its own sched.lock sees `Exited` and refuses to re-enqueue. |
| arch fault handler (page fault, GP fault, etc.) | `*` | `Exited` | trapping CPU = current CPU | Same as `sys_exit`. |
| `dealloc_object(Thread)` | `*` | `Exited` | calling CPU (refcount → 0) | Acquires every CPU's scheduler.lock in ascending order, writes `state = Exited`, walks `remove_from_queue` for every CPU, snapshots `running_on`, releases all. After release: spins on `sched.current != tcb` (if `running_on = Some(cpu)`), then unconditionally on `tcb.context_saved == 1`, then proceeds to source-IPC unlink + free. See Drain Protocol below. |

**Why the all-CPU lock acquire in `dealloc_object(Thread)`:**

`preferred_cpu` is updated by `enqueue_and_wake` under the target CPU's scheduler.lock. Between a reader of `preferred_cpu` and the lock acquisition, a concurrent `enqueue_and_wake` on another CPU can move the TCB. Locking only `preferred_cpu`'s scheduler then walking that one queue is racy: the TCB may have been re-enqueued elsewhere. The current implementation locks every CPU's scheduler.lock in ascending order (preventing ABBA per [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 4), writes `Exited` once, then iterates `remove_from_queue` over every CPU. After the all-locks release, the TCB cannot be in any run queue (the `Exited` state under each lock prevented re-enqueue, and the explicit removal cleared any prior link).

Cost on MAX_CPUS = 64 is up to 64 spinlock acquisitions per Thread dealloc, each leaf-leveled. This is acceptable for a teardown path that runs at most O(num-threads-created) times in the system's lifetime.

---

## `dealloc_object(Thread)` Drain Protocol

The teardown sequence binds the following ordered steps. Each step's preconditions and locks are stated explicitly.

```
1. Acquire every CPU's scheduler.lock in ascending CPU order.
2. Read tcb.priority INSIDE the all-locks region (a concurrent
   sys_thread_set_priority on another CPU writes priority under the home
   CPU's scheduler.lock; reading outside would race the write).
3. Write tcb.state = Exited.
4. For each CPU in 0..cpu_count: scheduler_for(cpu).remove_from_queue(tcb, prio).
5. Server-side BlockedOnReply check: if (*tcb).reply_tcb is non-null,
   compare_exchange(bound, null, AcqRel, Acquire) to claim the binding,
   then prepare the bound client for wake (set state = Ready, ipc_state = None,
   blocked_on = null, trap_frame.return = Interrupted). The actual
   enqueue_and_wake happens AFTER step 7 because it would deadlock against
   the held scheduler.locks.
6. For each CPU: check if scheduler_for(cpu).current == tcb; record running_on
   (at most one).
7. Release every scheduler.lock in descending order.
8. If a server_reply_wake was prepared in step 5, enqueue_and_wake(bound, ...).
9. If running_on was recorded, spin (re-acquire that CPU's lock per iteration)
   until scheduler_for(run_cpu).current != tcb.
10. Spin on tcb.context_saved.load(Acquire) == 1 (UNCONDITIONAL — see invariant 4).
11. Acquire the source IPC lock for tcb's blocked_on_object (if any) and unlink
    tcb from the source's wait queue / waiter slot. Branches:
      - BlockedOnSend / BlockedOnRecv: ep.lock; unlink_from_wait_queue.
      - BlockedOnSignal: sig.lock; clear waiter if it == tcb.
      - BlockedOnEventQueue: eq.lock; clear waiter if it == tcb.
      - BlockedOnWaitSet: ws.lock; clear waiter if it == tcb.
      - BlockedOnReply: blocked_on_object is the *server* TCB; mirror
                        cancel_ipc_block — compare_exchange
                        (*server).reply_tcb from tcb to null with AcqRel /
                        Acquire so the server's next endpoint_reply finds
                        no caller and returns None.
      - None: no source-side cleanup needed.
12. Clear tcb.blocked_on_object = null.
13. (x86_64 only) Release IOPB if bound.
14. Poison: tcb.magic = 0; tcb.priority = 0xFF.
15. drop_in_place(tcb).
16. retype_free + ancestor dec_ref + cascade.
```

**Invariants the drain protocol MUST hold:**

1. **Ascending-order lock acquire** prevents ABBA against any peer drain (the canonical cross-CPU scheduler-lock acquisition order, [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 4).

2. **Step 3 (state = Exited) commits under all locks.** No `schedule()` on any CPU can subsequently observe this TCB as `Ready` or `Running` for purposes of re-enqueue — the protection in `schedule()` reads `state` while holding its CPU's scheduler.lock and refuses to re-enqueue if `state ∈ {Exited, Stopped}`. `enqueue_and_wake` performs the same check before enqueueing (see [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 9).

3. **Step 9's `running_on` spin is bounded.** The remote CPU is mid-`schedule()`; once it sets `current = next_tcb` (which happens *before* the arch switch on x86 due to `release_lock_only`), the spin exits.

4. **Step 10's `context_saved` spin is the load-bearing UAF gate, and is unconditional.** On x86 (TSO), `schedule()` calls `set_current(next)` and `release_lock_only(sched.lock)` *before* `switch()` saves the dying thread's registers into `tcb.saved_state`. A peer CPU acquiring the same lock at any moment after the release can therefore observe `sched.current = idle` while `switch()` is still mid-save into `tcb.saved_state`. Freeing the TCB at that point lets the next allocation reuse the memory; `switch()` then corrupts the new allocation, producing hangs (`stress::thread_churn`, `bench thread_lifecycle`) or worse. Step 10 closes the window: `context_saved` is cleared by `schedule()` *before* the save and written `1` (Release) by `switch()` *after* the save; spinning on the Acquire load until it observes `1` guarantees the save has fully published. The spin is unconditional on the result of `running_on`, because the all-locks `running_on` snapshot can race past the lock release and miss the in-flight switch entirely. New TCBs initialise `context_saved = 1`, so the wait is bounded for threads that never ran.

5. **Step 11's source-IPC unlink MUST acquire the source's lock for every variant.** This is the symmetry rule with `cancel_ipc_block`: both clear IPC-blocking field-group writes from a non-owning CPU and MUST hold the matching source lock.

6. **Step 11 BlockedOnReply.** The client's `blocked_on_object` is the *server* TCB pointer (the server is the lifetime owner of `reply_tcb`). The dealloc'd client must claim its own slot via `compare_exchange(self, null, AcqRel, Acquire)` before freeing — otherwise a later `endpoint_reply` on the still-live server would load the freed client pointer and UAF on the message-copy write. Stores to `null` outside `ep.lock` MUST use compare_exchange (never an unconditional store) so a concurrent cancel cannot lose a peer client's binding.

7. **Step 14's poison precedes step 15's drop.** `magic = 0` and `priority = 0xFF` are the use-after-free traps — any later code that reads these fields and dereferences will fail loudly via the `debug_assert!((*tcb).magic == TCB_MAGIC, ...)` checks in the scheduler. Step 15 calls `drop_in_place(tcb)` on the in-place body; `ThreadControlBlock` has no Drop today, so this is a no-op kept for future fields whose drop semantics matter.

---

## BlockedOnReply Edge — Symmetry Rules

The `BlockedOnReply` state is structurally different from the other `BlockedOn*` states: there is no dedicated source lock. The "source" is the server TCB itself, and the slot the client is registered into is `(*server).reply_tcb: AtomicPtr<ThreadControlBlock>`. Three actors can mutate this slot from different lock domains:

1. **Server in `endpoint_call`** — sets `reply_tcb = caller` under `ep.lock`.
2. **Server in `endpoint_recv`** — sets `reply_tcb = caller` under `ep.lock`.
3. **Server in `endpoint_reply`** — loads `reply_tcb` (Acquire), stores `null` (Release) under `ep.lock`.
4. **Client cancel via `cancel_ipc_block`** — `compare_exchange(this_client, null, AcqRel, Acquire)` from the client's CPU's scheduler.lock, NOT under `ep.lock`.
5. **Client dealloc via `dealloc_object(Thread)`** — `compare_exchange(this_client, null, AcqRel, Acquire)` in the BlockedOnReply branch of the source-IPC unlink walk. Mirrors `cancel_ipc_block`'s discipline.
6. **Server dealloc via `dealloc_object(Thread)`** — under all-CPU scheduler.locks, reads `(*server).reply_tcb`; if non-null, `compare_exchange(bound, null, AcqRel, Acquire)` to claim the binding, then prepares the bound client for wake (state = Ready, ipc_state = None, blocked_on = null, trap_frame.return = `Interrupted`) and schedules an `enqueue_and_wake` for after the all-locks region releases. Without this, a client BlockedOnReply on a dying server would remain blocked indefinitely with a dangling `blocked_on_object` pointer to freed memory.

**Symmetry rule:** every actor that may invalidate a client's place in the reply slot MUST use `compare_exchange(this_client, null, ...)` (never an unconditional store) so concurrent actors can determine whether they got there first. Stores to `null` are only safe inside `ep.lock` because that lock ensures no other actor is concurrently setting a *different* non-null caller.

**Invariants on the BlockedOnReply protocol:**

1. The client's `blocked_on_object` is the server TCB pointer (NOT an endpoint or other source).
2. The server is the lifetime owner of the reply slot. As long as the server is alive, the slot is read/written under `ep.lock` for `endpoint_*` paths. Cancel and dealloc paths use atomic compare_exchange because they cannot acquire `ep.lock` (they don't know which endpoint this reply is for; the server may have moved on to a different endpoint between the original `call` and the cancel).
3. **Server-death-while-client-blocked-on-reply** is handled by actor 6 above: the dying server walks its `reply_tcb`, claims the bound client via compare_exchange, and wakes it with `Interrupted` so the client's syscall returns rather than dereferencing the freed server. The wake is dispatched after the dying server's all-locks region releases, since `enqueue_and_wake` itself acquires a scheduler.lock.

---

## Atomic Ordering for Sleep List and Lifecycle

This section lists ordering invariants specific to the sleep-list + lifecycle surface. Atomic invariants common with the global wake protocol (`RESCHEDULE_PENDING`, `non_empty`, `context_saved`, `BOOT_TRANSIENT_ACTIVE`) are NOT restated; see [scheduling-internals.md § Atomic Ordering Invariants](scheduling-internals.md#atomic-ordering-invariants).

| Atomic / field | Set ordering | Read ordering | Pairing rationale |
|---|---|---|---|
| `tcb.timed_out` (bool, plain field) | non-atomic store under `eq.lock` (timer arm) | non-atomic load by resuming syscall on the same CPU | Single-writer per park (eq.lock excludes any concurrent payload-delivery write); reader is local CPU after `schedule()` returns. No atomic required because the source IPC lock provides mutual exclusion at the write side and the `Blocked → Ready` transition under that same lock provides the happens-before edge to the reader. |
| `tcb.sleep_deadline` (u64, plain field) | non-atomic store under source IPC lock (when waker clears) OR under no lock (when registrant sets, before `sleep_list_add`) OR under `SLEEP_LIST_LOCK` (when timer claims) | non-atomic load under `SLEEP_LIST_LOCK` (timer snapshot pass) | The deadline read by `sleep_check_wakeups` under `SLEEP_LIST_LOCK` is the load-bearing observation; later state mutations follow the snapshot-then-claim arbitration. Cross-CPU writes are serialised either by the source IPC lock (waker's clear) or by the registrant being the parking thread itself (single-writer semantics during park). |
| `tcb.state` (enum, plain field) | non-atomic store under either every CPU's scheduler.lock (`set_state_under_all_locks`) or the current CPU's scheduler.lock (`commit_blocked_under_local_lock` and `enqueue_and_wake`) | non-atomic load by any CPU's scheduler under its own scheduler.lock | The state field is in the Scheduling field group per [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership). The all-locks vs single-CPU split exists because `Stopped`/`Exited` writes must be visible to *every* CPU's `schedule()` skip-check, while routine `Ready ↔ Running` and `Running ↔ Blocked` writes only need to coordinate with the local scheduler that owns the run-queue link. |
| `tcb.priority` (u8, plain field) | non-atomic store by `sys_thread_set_priority` (no lock) OR by `change_priority` under the home-CPU scheduler.lock when the TCB is being moved between priority queues | non-atomic load by `dealloc_object(Thread)` *inside* the all-locks region | Reading priority inside the all-locks region eliminates the torn-read risk against a concurrent `sys_thread_set_priority`. The next `enqueue_and_wake` after a priority change re-reads `priority` under the target sched.lock; intermediate writes are benign. |
| `tcb.reply_tcb` (`AtomicPtr<TCB>`) | Release on `endpoint_*` store under ep.lock; AcqRel on `compare_exchange` from cancel/client-dealloc/server-dealloc paths | Acquire on `endpoint_reply` load under ep.lock; Acquire on the server-dealloc snapshot under all sched.locks | The `compare_exchange` discipline lets non-`ep.lock`-holding actors (cancel, client dealloc, server dealloc) clear the slot only when it still references *their* TCB, so two concurrent invalidators cannot lose a third unrelated client's binding. |

---

## `sys_thread_sleep` and the Plain-Sleep Path

`sys_thread_sleep` is the simplest sleeper: no IPC source, only the timer. Sequence:

```
1. Compute deadline.
2. (*tcb).sleep_deadline = deadline; (*tcb).state = Blocked; (*tcb).ipc_state = None.
3. sleep_list_add(tcb).
4. schedule(false).
5. On resume: (*tcb).state has been set to Ready by sleep_check_wakeups's
   "_ => { plain sleep }" arm, sleep_deadline cleared; syscall returns Ok(0).
```

**Invariants:**

1. `ipc_state == None` is the discriminator that selects the plain-sleep arm in `sleep_check_wakeups`. The plain arm claims unconditionally because no IPC source is competing.
2. The plain sleep does not need a source-lock arbitration. The timer is the sole waker.
3. There is no cancel path for `sys_thread_sleep` today; if `sys_thread_stop` is called on a sleeper, `cancel_ipc_block`'s default arm (`IpcThreadState::None`) does no source-lock work, and the function then clears `sleep_deadline` and removes the TCB from the sleep list. This is correct.

---

## `sys_thread_stop` Cross-CPU Stop Protocol

`sys_thread_stop` MUST commit the target's `Stopped` state under every CPU's scheduler.lock so a concurrent `schedule()` on the remote CPU cannot read `state != Stopped` and re-enqueue the target. The handler then drains the target.

**Protocol (`core/kernel/src/syscall/thread.rs::sys_thread_stop`):**

1. Resolve the target Thread cap; reject `Created`, `Exited`, `Stopped` with `InvalidState`.
2. If `state == Blocked`, call `cancel_ipc_block(target)` — acquires the source IPC lock matching `tcb.ipc_state` and unlinks the waiter.
3. `set_state_under_all_locks(target, Stopped)` — acquires every CPU's scheduler.lock in ascending order, writes `state = Stopped`, snapshots `running_on` (the CPU whose `sched.current == target_tcb`, if any), releases all locks. Returns `Option<run_cpu>`.
4. **Self-stop fast path.** If the target is the calling thread, call `schedule(false)` immediately. The skip-loop in `schedule()` never re-enqueues a `Stopped` TCB.
5. **Cross-CPU drain.** If `running_on = Some(run_cpu)` and `run_cpu != current_cpu`:
   - `prod_remote_cpu(run_cpu)` — sends a wakeup IPI so the remote CPU traps into kernel and runs `schedule()` at the next instruction boundary. Without this, the remote CPU may continue running the target's user code until its next preemption tick (~1 ms), and `sys_thread_read_regs` would observe a stale `trap_frame` snapshot from a prior syscall rather than the freshly-saved registers from the stop-induced trap.
   - Bounded spin until `sched_remote.current != target_tcb`. The remote CPU's `schedule()` drains the `Stopped` target via the skip-loop and switches to either the next ready thread or its idle TCB; once that switch completes, the spin exits.

**Invariants:**

1. The cross-CPU IPI in step 5 is a correctness requirement, not a latency optimisation: it is the only mechanism that guarantees `sys_thread_read_regs` sees a fresh trap_frame.
2. For Ready targets on a remote run queue, no IPI is needed; the remote CPU's next `schedule()` drops the TCB via the skip-loop on its own timing.
3. The bounded spin in step 5 holds NO lock; it acquires `sched_remote.lock` briefly per iteration to read `current` and releases. IRQs are disabled in the syscall context (SYSCALL clears IF), so the spin-holder cannot itself service interrupts during the wait — but the remote CPU's IRQs are independent and the spin therefore terminates as soon as the remote drains.

---

## Summarized By

None
