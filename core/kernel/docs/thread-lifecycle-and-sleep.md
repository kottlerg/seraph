# Thread Lifecycle and Sleep List Invariants

This document specifies the cross-cutting invariants for thread lifecycle transitions
(`sys_thread_start` (first start and resume), `sys_thread_stop`, `sys_exit` / `sys_process_exit`,
and `dealloc_object(Thread)`), the global sleep list (`SLEEP_LIST` + `SLEEP_LIST_LOCK`), and the
timer-driven wakeup arbitration in `sleep_check_wakeups`. It is sibling to
[scheduling-internals.md](scheduling-internals.md) and binds the same authority for the surfaces
below; cross-cutting concurrency rules established there (lock hierarchy, cross-CPU TCB ownership,
wake protocol) MUST hold here.

This document is the authoritative reference consulted before any change that touches:
- `core/kernel/src/sched/mod.rs` — `sleep_list_add`, `sleep_list_remove`, `sleep_check_wakeups`,
  `sleep_wakeups_quiesce`, `sleep_deadline_after_ms`, `commit_cancelling_park`,
  `start_under_all_locks`, `with_held_frame`, `post_death_notification`.
- `core/kernel/src/syscall/{thread,mod}.rs` — `sys_thread_configure`, `sys_thread_start`,
  `sys_thread_stop`, `sys_thread_read_regs`, `sys_thread_write_regs`, `sys_thread_set_priority`,
  `sys_exit`, `sys_process_exit`, `sys_thread_sleep`, `cancel_ipc_block`.
- `core/kernel/src/cap/object.rs` — the `ObjectType::Thread` arm of `dealloc_object_one`, and the
  sleep-list removal and timer quiesce in its Notification and EventQueue arms.
- `core/kernel/src/ipc/mod.rs` — `WaitQueue`, `arm_timed_park` (called by `notification_wait`
  and `event_queue_recv`), and the waiter claims that drop a sleep-list entry: `claim_waiter`
  (called by `notification_send`, `event_queue_post`, `waitset_notify`, `waitset_add`, the timer's
  timed-wait arms, and `interrupt_all_waiters`) and `interrupt_all_waiters` (called by the
  Notification dealloc arm, `event_queue_drop`, and `wait_set_drop`).
- The fault handlers in `core/kernel/src/arch/{x86_64/idt.rs,riscv64/interrupts.rs}` that drive
  thread-fault exits.

---

## Document Boundary

Cross-cutting concerns owned by [scheduling-internals.md](scheduling-internals.md) — lock hierarchy,
the global wake protocol, IPI taxonomy, BSP boot transient, atomic-ordering invariants, the
IPC-blocking field group of TCB ownership — are NOT restated here. Where this document references
them it links back; where this document adds rules they MUST be consistent with the parent
invariants.

| Doc | Owns |
|---|---|
| [scheduling-internals.md](scheduling-internals.md) | Lock hierarchy, cross-CPU TCB ownership table, wake protocol, BSP boot transient, IPI taxonomy, atomic ordering pairings. |
| **This document** | Sleep-list invariants, capacity, and BSP-servicing model (including the timed-source quiesce); `timed_out` cross-CPU protocol; `sys_thread_start` / `sys_thread_stop` / `sys_exit` / `sys_process_exit` state-machine table and the stop protocol (`commit_cancelling_park`); `dealloc_object(Thread)` cross-CPU drain protocol; `BlockedOnReply` edge between client cancel and server dealloc. |
| [scheduler.md](scheduler.md) | Scheduling algorithm (priority, FIFO, slice, affinity, idle role). |
| [ipc-internals.md](ipc-internals.md) | IPC primitive object layouts and syscall paths. |

---

## Surface

In scope:

- `core/kernel/src/sched/mod.rs` — sleep list, timer quiesce, `commit_cancelling_park`,
  `start_under_all_locks`, `with_held_frame`, and `post_death_notification`.
- `core/kernel/src/sched/thread.rs` — `ThreadState`, `IpcThreadState`, TCB.
- `core/kernel/src/syscall/{thread,mod}.rs` — lifecycle and register-access syscalls and
  `cancel_ipc_block`.
- `core/kernel/src/cap/object.rs` — `ObjectType::Thread` arm of `dealloc_object_one`; the sleep-list
  removal and timer quiesce of the Notification and EventQueue arms.
- `core/kernel/src/ipc/mod.rs` — `WaitQueue`, `claim_waiter`, `interrupt_all_waiters`,
  `arm_timed_park`.
- `core/kernel/src/ipc/{notification,event_queue,wait_set}.rs` — the claimers that call them.
- `core/kernel/src/arch/{x86_64/idt.rs,riscv64/interrupts.rs}` — fault → Exited transition.

---

## Sleep List Invariants

The sleep list is a single global fixed-capacity array of TCB pointers. A TCB is on the list
after `sleep_list_add` registered it with a non-zero `sleep_deadline`. The BSP timer tick scans
the list, pops expired entries under `SLEEP_LIST_LOCK`, releases the lock, and arbitrates wake
claims against concurrent IPC sources via the relevant source IPC lock (Notification / EventQueue /
"plain sleep" only — `sys_thread_sleep` is a plain sleep with no source).

**Invariants the sleep list MUST hold:**

1. **`SLEEP_LIST_LOCK` is leaf-only.** Per
   [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 3. Wake
   direction is `source.lock → SLEEP_LIST_LOCK`, `cancel_ipc_block` nests it inside the target's
   `sched_lock`, and `sys_thread_sleep`'s full-list withdrawal nests it inside the sleeper's own;
   timer direction releases `SLEEP_LIST_LOCK` before any source lock — sequential, not nested.

2. **A listed TCB is a `Blocked` sleeper or timed waiter.** Its `ipc_state` is `None` (plain sleep)
   or `BlockedOnNotification` / `BlockedOnEventQueue` with a non-null `blocked_on_object`
   (debug-asserted at the pop). Its `state` may already be `Exited` (a `dealloc_object(Thread)` that
   has not yet reached its removal, drain step 11); the claim's `enqueue_and_wake` then aborts.

3. **An entry and its deadline go together.** `sleep_deadline` is set by the parker before
   `sleep_list_add`. Once added it is cleared only under `SLEEP_LIST_LOCK`, together with the entry:
   by the timer pop, or by `sleep_list_remove`, which removes every entry for the TCB and returns
   whether the deadline was still non-zero. `sys_thread_sleep` withdraws a park the full list
   refused through that same `sleep_list_remove`, under its `sched_lock`: the claim a cancel makes,
   so only one of them sees the deadline non-zero. The one other clear is the parker's own rollback
   of a deadline it never listed: `sys_thread_sleep` after a refused park commit (no lock), and
   `arm_timed_park` (the timed `notification_wait` / `event_queue_recv` arm) after a full list
   (under the source lock). `sleep_list_add` refuses
   (`SleepAddError::Cancelled`) a TCB whose deadline is already 0 under the lock — a cancellation
   landed between the park commit and the add — and never lists a TCB twice (a second add keeps
   the one entry, debug-asserted). So no entry outlives its park, and one `sleep_list_remove`
   leaves none behind.
   `sleep_deadline_after_ms` never yields 0.

4. **Capacity is hard.** At `SLEEP_COUNT == MAX_SLEEPING`, `sleep_list_add` refuses
   (`SleepAddError::Full`). A timed `sys_notification_wait` or `sys_event_recv` withdraws its park
   (`ipc::withdraw_timed_park`, under the source lock that has held it queued, so no waker or cancel
   can have claimed it) and reports an immediate timeout: `0` bits, or `WouldBlock`.
   `sys_thread_sleep` surfaces `OutOfMemory`, unless a stop or teardown already claimed the park:
   the sleeper then deschedules, a stopped one returning `Interrupted` when restarted and a
   torn-down one never returning (see § `sys_thread_sleep` and the Plain-Sleep Path). Silent drop is
   forbidden — it would hang the parker.

5. **`sleep_check_wakeups` is BSP-only.** APs' timer ticks do not touch the sleep list. A BSP stuck
   in an interrupt-disabled critical section delays all timeout wakes; this is a deliberate
   simplification, not an oversight.

6. **Snapshot-then-claim arbitration.** The timer pops `expired[..n]` under `SLEEP_LIST_LOCK`,
   snapshotting each entry's `(ipc_state, blocked_on_object, park_seq)` and clearing its
   `sleep_deadline`, releases the lock, then dispatches on the snapshot:
   - `None` (plain sleep): claimed at the pop — `wake_in_flight = 1` under `SLEEP_LIST_LOCK` — since
     no other waker competes.
   - `BlockedOnNotification` / `BlockedOnEventQueue`: take the source lock; claim iff the TCB is
     still in the source's waiter queue and its `park_seq` still equals the snapshot. The generation
     check rejects a later wait of the same thread on the same source (a sender claimed the popped
     park and the thread queued again before the timer took the lock): the TCB is queued again, but
     `park_seq` advanced at that park's commit, which runs under the same source lock. Membership
     is the TCB's `ipc_wait_queue` tag (the TCB outlives the batch, invariant 9); the TCB is written
     only once the claim is won.
   - any other binding: never claimed and never dereferenced (invariant 2 makes it unreachable).

7. **Every waiter claim removes the entry under the source lock.** A notification or event queue
   keeps its blocked threads in a FIFO (`WaitQueue`; a wait set holds at most one), and a waiter is
   claimed by removing it from that queue under the source lock. `notification_send`,
   `event_queue_post`, the Notification and EventQueue dealloc wakes (through `claim_waiter` and
   `interrupt_all_waiters`), and `cancel_ipc_block` (inline) call `sleep_list_remove` in the same
   source-lock critical section as that removal; the timer pops the entry before its own claim. So
   an entry bound to a source exists only while that source still queues the TCB. A deadline of 0
   read under the source lock means no entry (the parker arms under that lock, and every removal
   clears both together), so the wakers skip the remove for an untimed wait.

8. **A timed park arms its sleep-list entry in the source-lock critical section that queues and
   commits it.** `notification_wait` and `event_queue_recv` take the deadline and call
   `arm_timed_park` after a committed park, before releasing the source lock, so no waker can
   claim the TCB before its entry exists, and the syscall never locks the source again once the
   caller is claimable (a later lock through the unpinned capability could reach a source freed by
   a concurrent last-cap delete). An entry armed after a claim would outlive the wait it timed and
   hijack the TCB's next unrelated `notification_wait` / `event_recv`, delivering
   `wakeup_value = 0` instead of real bits or payload.

9. **A source or TCB outlives every batch that popped it.** The timer's arms use the pop-time
   source and TCB pointers, which hold no reference. A batch advances `TIMER_DISPATCH_SEQ` to odd
   under `SLEEP_LIST_LOCK` when its pop takes an entry, and back to even (Release) after its last
   claim. The Notification and EventQueue dealloc arms, after claiming every queued waiter
   (invariant 7), and the Thread arm, after its entry removal and IPC unlink (drain step 11), call
   `sleep_wakeups_quiesce` before the free: it takes and releases `SLEEP_LIST_LOCK`, which orders
   it after every pop that could have taken the object, reads the sequence with Acquire (so an even
   value orders the last batch's accesses before the free), and if it is odd spins (interrupts
   enabled, preemption disabled; spin site `dealloc:timer-dispatch`) until it changes. No later
   batch can snapshot the object, since no entry naming it remains.

---

## `timed_out` Cross-CPU Protocol

`tcb.timed_out: bool` is a single-cell out-of-band marker that distinguishes "data-delivered wake"
from "timeout wake" for IPC primitives whose payload may itself be zero (notably `sys_event_recv`,
contrast `sys_notification_wait` whose `wakeup_value == 0` is unambiguous because
`notification_send` rejects zero-bit sends).

**Invariants:**

1. **`timed_out` is in the IPC blocking field group** per
   [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership).
   Cross-CPU writers MUST hold the matching source IPC lock at the moment of write. Today the only
   writer is `sleep_check_wakeups`'s `BlockedOnEventQueue` arm under `eq.lock`; this is correct.

2. **Reader is the resuming syscall.** After `schedule()` returns, the resuming syscall (currently
   `sys_event_recv` only) reads-and-clears `timed_out` and `wakeup_value` as a pair. The reader is
   single-CPU (the resuming CPU is `current_tcb`'s CPU); no lock required. Both fields MUST be
   cleared by the reader before the syscall returns, so a subsequent `sys_event_recv` on the same
   TCB starts from a clean slate.

3. **Mutual exclusion of payload paths.** Of the wakes that deposit a result, exactly one occurs
   after a timed wait blocks (a cancellation, invariant 4, deposits none):
   - `event_queue_post` claims the waiter under `eq.lock` (removing its sleep-list entry), writes
     `wakeup_value = payload`, releases `eq.lock`, and then calls `enqueue_and_wake`, which writes
     the state. `timed_out` remains `false`.
   - `sleep_check_wakeups` BlockedOnEventQueue arm claims the waiter under `eq.lock`, writes
     `wakeup_value = 0` and `timed_out = true`, releases `eq.lock`, and then calls
     `enqueue_and_wake`.

   The removal of the TCB from `eq`'s waiter queue under `eq.lock` (with the timer's `park_seq`
   check, Sleep List Invariant 6) ensures exactly one of these paths fires per park. The reader can
   then trust that `timed_out == true` ⇔ "no payload" and `timed_out == false` ⇔ "wakeup_value is
   the payload" (which may legitimately be zero).

4. **No third writer.** The cancellers — `cancel_ipc_block` and the queue's destruction
   (`event_queue_drop`) — MUST NOT touch `timed_out`. A cancelled wait returns `Interrupted`, not
   "timed out": the canceller stamps the park episode `INTERRUPTED` at its waiter claim, and the
   resuming syscall consumes that disposition *before* the `timed_out`/`wakeup_value` read (clearing
   both in the interrupted branch — see
   [ipc-internals.md § Park Dispositions and Episodes](ipc-internals.md#park-dispositions-and-episodes)).
   Additional writers would race the reader and break the mutual-exclusion invariant.

---

## Lifecycle State Machine

This table is the authoritative per-transition rule set for the lifecycle syscalls. It refines the
[ThreadState Transitions](scheduling-internals.md#threadstate-transitions) table in
`scheduling-internals.md` by binding each `sys_thread_*` syscall to the canonical helper / lock(s)
the handler uses for the target's `state` write.

| Syscall | Source state | Destination state | Performing CPU | Canonical state-write helper |
|---|---|---|---|---|
| `sys_cap_create_thread` | (uninit) | `Created` | calling CPU | none — TCB not yet visible to schedulers; written in-place during construction. |
| `sys_thread_configure` | `Created` | `Created` | calling CPU | does NOT touch `state`; mutates the initial frame, `trap_frame` and `saved_state.fs_base`. Target MUST be `Created`, decided under its `sched_lock` and held across the writes, so a concurrent `sys_thread_start`'s commit (which takes that lock) lands wholly before (configure is refused) or after them. |
| `sys_thread_start` (first start) | `Created` | `Ready` | calling CPU | Refused for the caller itself (`InvalidArgument`). `start_under_all_locks(target, caller)`: a settle loop that, while the target is `Created` or `Stopped`, waits until it is `current` on no CPU (prodding the CPU still running it), its save is published (`context_saved == 1`; a never-dispatched `Created` thread is `current` nowhere and saved, so this passes at once) and no wake is owed, then commits `Ready`, advancing the TCB's `start_seq`, only if the all-CPU locks still show all three (`start_ready_to_link`), and otherwise takes another pass — a concurrent start and stop can run, park, and stop it again between a pass and the commit. Each pass ends the start when the target is no longer `Created`/`Stopped` (`InvalidArgument`), and a pass that must wait ends it when the caller itself has been stopped (read under the caller's `sched_lock`; the caller deschedules in place, as a self-stop does, and sees `Interrupted` on restart), so the loop never waits on a running thread or blocks its caller's stop. Then `enqueue_ready_thread(target_cpu, start_seq)`. Neither the all-locks commit nor the link overwrites an `Exited` mark a concurrent `dealloc_object(Thread)` committed; nothing pins the TCB between the two lock holds ([#443](https://github.com/kottlerg/seraph/issues/443) § Unpinned capability lookup). `enqueue_ready_thread` (not `enqueue_and_wake`) is used because the gated wake would coalesce an already-`Ready` thread and silently drop the link (see [scheduling-internals.md § ThreadState Transitions](scheduling-internals.md#threadstate-transitions)). The syscall's state precheck runs without a lock, so the commit re-checks the state under the locks: it refuses a target that is no longer `Created` or `Stopped` (`StateCommit::RefusedState` — a concurrent start resumed it, and it may since have parked, so a `Ready` overwrite would put a thread still on a wait queue on a run queue too) or that is `Exited` (`StateCommit::RefusedExited` — an object teardown or an exit on another CPU ended it), and the link refuses an `Exited` target (`ReadyLink::Exited`); the syscall then returns `InvalidArgument` and nothing is linked. Between two stops, at most one start commits: each commit advances `start_seq`, and a later start commits only after a stop has made the thread `Stopped` again. The commit and the link are separate lock holds, so the link is made only if the thread is still `Ready` at the commit's `start_seq`: a stop between them (and any restart, which links the thread itself) supersedes the start (`ReadyLink::Superseded`), which links nothing and returns success — it took effect and was stopped. |
| `sys_thread_start` (resume from stop) | `Stopped` | `Ready` | calling CPU | Same as first-start, but the settle loop's drain is load-bearing here: a thread stopped while Running may still be `current`/executing on a remote CPU, and a waker that claimed its stopped park may still owe it a wake. The loop waits for both while the target is still `Stopped` (a state `schedule()`'s requeue denylist rejects, so the owning CPU deschedules it without re-linking), and only then commits `Ready` and force-links it — otherwise `enqueue_ready_thread` would dispatch a still-live thread on a second CPU (the cross-CPU double-dispatch of #314/#293), or the late wake would link a later park (see [`sys_thread_stop` Cross-CPU Stop Protocol](#sys_thread_stop-cross-cpu-stop-protocol), invariant 4). The kernel uses `sys_thread_start` for both first-start and resume; this overload is intentional and `Stopped → Ready` is a permitted transition. |
| `sys_thread_stop` (running self) | `Running` | `Stopped` | calling CPU = running CPU | `commit_cancelling_park(target, Stopped, None)`, then `schedule(false)` immediately yields. The skip-loop in `schedule()` never re-enqueues a `Stopped` TCB. |
| `sys_thread_stop` (running remote) | `Running` | `Stopped` | calling CPU ≠ running CPU | `commit_cancelling_park(target, Stopped, None)` returns `StateCommit::Committed(Some(run_cpu))`; the syscall handler then calls `prod_remote_cpu(run_cpu)` (sends a wakeup IPI whose trap snapshots the target's registers; the remote CPU drops the `Stopped` target at the next slice-expiry `schedule(true)` it performs with preemption enabled, or at the target's own park or yield) and bounded-spins until `sched_remote.current != target_tcb` and the target's `context_saved` is set (`current` moves off the target before `switch()` publishes its save), or the target is no longer `Stopped` (an object teardown committed `Exited` over it; a start cannot commit while the target is `current` anywhere). A drain pass that must wait reads the stopper's own state under its `sched_lock`; a stopper that is itself `Stopped` (a peer stopping its stopper) or `Exited` deschedules in place and, when restarted, re-enters the drain only if its capability slot still names the target with Control rights, otherwise returning at once ([Cross-CPU Stop Protocol](#sys_thread_stop-cross-cpu-stop-protocol) step 4), so two threads stopping each other both end `Stopped`. The drain is what gives `sys_thread_read_regs` a fresh `trap_frame`: a drained call returns only once the target has left its CPU through a trap, so the snapshot is never the stale one from the target's previous kernel entry ([Cross-CPU Stop Protocol](#sys_thread_stop-cross-cpu-stop-protocol) invariant 1 states where this does not hold). |
| `sys_thread_stop` (Ready, on a run queue) | `Ready` | `Stopped` | calling CPU | `commit_cancelling_park(target, Stopped, None)`, whose all-locks commit removes the entry from every run queue inside the locked region; the `schedule()` skip-loop is only defence-in-depth. A target `current` on no CPU at the commit may still be finishing its switch out on the CPU it just left: the call waits (`await_stopped_save`, interrupts enabled; spin site `stop:save`) until its `context_saved` is set or a teardown commits `Exited`. |
| `sys_thread_stop` (Blocked) | `Blocked` | `Stopped` | calling CPU | `commit_cancelling_park(target, Stopped, None)`: `cancel_ipc_block(target)` (acquires the source IPC lock matching `tcb.ipc_state` and unlinks the waiter), then the all-locks commit, retried while the target's `park_seq` changed (see [`sys_thread_stop` Cross-CPU Stop Protocol](#sys_thread_stop-cross-cpu-stop-protocol)). A target that parks after an unlocked `Running` or `Ready` read takes this row too. A target `current` on no CPU at the commit may still be finishing its switch out on the CPU it just left: the call waits (`await_stopped_save`, interrupts enabled; spin site `stop:save`) until its `context_saved` is set or a teardown commits `Exited`. |
| `sys_thread_stop` (Created or Exited or Stopped) | `*` | `*` | calling CPU | n/a — returns `InvalidState`. No state write. An `Exited` target observed only at the locked commit (the thread died between the unlocked precheck and the commit) is refused there with the same `InvalidState`. |
| `sys_thread_set_priority` | `*` | `*` (priority changed) | calling CPU | Holds `(*tcb).sched_lock` across the `state` read and the `(*tcb).priority` write, and — when the target is `Ready` — relocates the queue entry via `sched::relocate_ready_priority`: lock the single `preferred_cpu`-hinted CPU's `scheduler.lock` and verify membership with `remove_from_queue` (O(1) locks), falling back on a miss to the ascending all-CPU walk. `remove_from_queue`'s boolean identifies the home CPU; the re-enqueue lands at the new priority on the located scheduler. The held `sched_lock` serialises with `dealloc_object(Thread)`, `migrate_ready_thread`, and `set_state_under_all_locks`. |
| `sys_thread_set_affinity` | `*` | `*` | calling CPU | Does NOT touch `state`; writes `cpu_affinity`. When the new affinity names a CPU other than the target's `preferred_cpu`, an unlocked `state` read picks the action: a `Ready` target is migrated at once (`migrate_ready_thread`); a `Running` target's CPU has reschedule-pending set and is prodded (`set_reschedule_pending_for`, `prod_remote_cpu`), so its next `schedule()` routes the thread cross-CPU; a `Blocked`, `Stopped` or `Created` target observes the affinity on its next enqueue. Clearing affinity (`AFFINITY_ANY`) migrates nothing. The syscall's `cpu_affinity` write and its `preferred_cpu` / `state` reads take no `sched_lock` (the Ready arm's `migrate_ready_thread` re-checks `state` under the target's `sched_lock` and both scheduler locks, and bails on a race), so they race other CPUs' scheduler paths, and the target is not pinned for the call, so these outcomes hold only when neither race occurs ([syscalls.md § `SYS_THREAD_SET_AFFINITY`](syscalls.md#sys_thread_set_affinity-38); defects tracked in [#443](https://github.com/kottlerg/seraph/issues/443)). |
| `sys_thread_read_regs` | `Stopped`, or `Blocked` (`BlockedOnFault`) | unchanged | calling CPU | `sched::with_held_frame`: under the target's `sched_lock`, the target, `Stopped` or fault-blocked, must be `current` on no CPU with its save published; a `Stopped` target not yet settled is refused (`InvalidState`) and a fault-blocked one still switching out is waited for (outside every lock, interrupts enabled, preemption disabled; spin site `regs:settle`). The frame is snapshotted under the lock and copied to the caller's buffer after it. No scheduler-state mutation. |
| `sys_thread_write_regs` | `Stopped`, or `Blocked` (`BlockedOnFault`) | unchanged | calling CPU | Copies and validates the user `TrapFrame`, then writes it through `sched::with_held_frame` (as for `sys_thread_read_regs`), so the target, `Stopped` or fault-blocked, is off every CPU with its save published for the write. |
| `sys_exit` (self) | `*` | `Exited` | running CPU = current CPU | `exit_under_all_locks(self, reason)` (the `Exited` commit with the exit reason in the same all-locks hold), then `post_death_notification`, then `schedule(false)`. The all-locks write ensures any peer-CPU `schedule()` reading `state` under its own sched.lock sees `Exited` and refuses to re-enqueue. |
| `sys_process_exit` (self) | `*` | `Exited` | running CPU = current CPU | `exit_under_all_locks(self, encode_exit_code(code))`, then `post_death_notification`, then `schedule(false)`, as for `sys_exit`; it makes no address-space death post. A refusal means a teardown already committed `EXIT_KILLED`; the post still carries this path's own reason. |
| arch fault handler (page fault, GP fault, etc.) | `*` | `Exited` | trapping CPU = current CPU | As for `sys_exit`, with reason `EXIT_FAULT_BASE + vector` (x86-64) or `EXIT_FAULT_BASE + cause` (riscv64), plus a `post_aspace_death_notification` to the address-space observers before `schedule(false)`. |
| `dealloc_object(Thread)` (caller ≠ tcb) | `*` | `Exited` | calling CPU (refcount → 0) | Acquires every CPU's scheduler.lock in ascending order, writes `state = Exited`, walks `remove_from_queue` for every CPU, releases all. After release: unconditionally scans every CPU until none has `sched.current == tcb`, then unconditionally on `tcb.context_saved == 1`, then proceeds to source-IPC unlink + free. See Drain Protocol below. |
| `dealloc_object(Thread)` (caller == tcb, self-teardown) | `Running` | `Exited` | calling CPU = running CPU | A thread deleting the last capability to its own `Thread` object cannot run the post-release scan (its CPU's `current == tcb` never clears from within the spin). Marks Exited + drains run queues only, queues the object on this CPU's deferred-reclaim stack, and returns; the syscall epilogue reschedules and the free completes off-CPU. See [Self-teardown](#self-teardown-the-caller-is-the-freed-thread) below. |
| `dealloc_object(CSpaceObj)` / `dealloc_object(AddressSpace)` — bound-thread stop (`stop_threads_bound_to`) | `*` | `Exited` | calling CPU (object refcount → 0) | For every registered thread bound to the dying object: `commit_cancelling_park(tcb, Exited, Some(EXIT_KILLED))` — `cancel_ipc_block` if `Blocked`, then the `Exited` commit with `EXIT_KILLED` recorded in the same all-locks hold, retried while `park_seq` changed (a commit refused because the thread exited on its own meanwhile writes neither, and that thread still posts its own reason — no death walk posts `EXIT_KILLED`; an observer bound after the stop receives it through the bind); running CPUs are prodded after the registry lock is released and the caller spins until no other CPU has a bound thread as `current` (and, for an `AddressSpace`, until `active_cpus` is empty). The thread is stopped, not freed: its object waits for its own last cap. If the caller's own thread is stopped — bound here, or by a concurrent teardown — nothing is freed: the object goes onto this CPU's deferred-reclaim stack (as in the self-teardown row) and the epilogue schedules the thread away. See [scheduling-internals.md § Thread Registry](scheduling-internals.md#thread-registry). |

**Why the all-CPU lock acquire in `dealloc_object(Thread)`:**

`preferred_cpu` is updated by `enqueue_and_wake` under the target CPU's scheduler.lock. Between a
reader of `preferred_cpu` and the lock acquisition, a concurrent `enqueue_and_wake` on another CPU
can move the TCB. Locking only `preferred_cpu`'s scheduler then walking that one queue is racy: the
TCB may have been re-enqueued elsewhere. The current implementation locks every CPU's scheduler.lock
in ascending order (preventing ABBA per
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 4), writes
`Exited` once, then iterates `remove_from_queue` over every CPU. After the all-locks release, the
TCB cannot be in any run queue (the `Exited` state under each lock prevented re-enqueue, and the
explicit removal cleared any prior link).

Cost on MAX_CPUS = 512 is up to 512 spinlock acquisitions per Thread dealloc, each leaf-leveled.
This is acceptable for a teardown path that runs at most O(num-threads-created) times in the
system's lifetime.

---

## `dealloc_object(Thread)` Drain Protocol

The teardown sequence binds the following ordered steps. Each step's preconditions and locks are
stated explicitly.

```
1. Acquire every CPU's scheduler.lock in ascending CPU order.
2. Read tcb.priority INSIDE the all-locks region. This read is serialised
   against sys_thread_set_priority's priority write by (*tcb).sched_lock —
   held outer here and the lock that writer takes — not by the CPU locks.
3. Write tcb.state = Exited.
4. For each CPU in 0..cpu_count: scheduler_for(cpu).remove_from_queue(tcb, prio).
5. Server-side BlockedOnReply check: if (*tcb).reply_tcb is non-null,
   compare_exchange(bound, null, AcqRel, Acquire) to claim the binding, then
   DEPOSIT only the resume disposition (park_disposition = INTERRUPTED for a
   syscall caller, or fault_outcome = Kill for a fault-blocked client) and leave
   the client BLOCKED. The client's Scheduling-group fields (state/ipc_state/
   blocked_on) are NOT written here — they are written only by the gated
   enqueue_and_wake (step 10) under the CLIENT's own sched_lock, never under the
   server's locks (pre-setting state = Ready here was the #284 residual: a
   concurrent dealloc(client) marking the client Exited under its sched_lock
   raced the unsynchronised Ready write). The wake's target CPU is NOT computed
   here either; it is recomputed at the wake site (step 10). The actual
   enqueue_and_wake happens AFTER step 7 because it would deadlock against
   the held scheduler.locks.
6. No in-region `current` snapshot is required: the post-release gate (step 8)
   scans every CPU unconditionally, so reclamation does not depend on an
   all-locks `running_on` reading (which names at most one CPU and can be stale
   the instant the locks drop).
7. Release every scheduler.lock in descending order.
8. `current`-anywhere gate (UNCONDITIONAL): scan every CPU, each under its own
   scheduler.lock; if some CPU has `scheduler_for(cpu).current == tcb`, spin on
   that CPU's lock until it switches away, then re-scan. Proceed only when a
   full scan finds no CPU running tcb. tcb is `Exited` and unlinked from every
   run queue (steps 3-4), so no CPU can re-install it after a clean scan.
9. Spin on tcb.context_saved.load(Acquire) == 1 (UNCONDITIONAL — see invariant 5).
   Steps 8-9 run with `preempt_disable` and interrupts enabled
   (`save_and_disable_interrupts` → `enable`); the local CPU MUST be
   able to service incoming flush / TLB-shootdown IPIs during the
   spin or it deadlocks against a peer CPU sending an IPI to it
   (observed locally and on `ubuntu-latest` CI). Preemption is
   disabled so a timer tick mid-spin cannot reschedule the dealloc
   caller off this CPU.
10. If a server_reply_wake was prepared in step 5, null the claimed client's
    blocked_on_object under the client's sched_lock, recompute the target CPU
    via select_target_cpu_excluding(bound, Some(this_cpu)) — excluding THIS
    dealloc CPU, which spins in this protocol's gates (steps 8-9 and 14), not
    in schedule(), and so cannot dispatch a client linked onto it (#351) —
    then enqueue_and_wake(bound, target). Recomputing here rather than
    snapshotting in step 5 also closes the double-enqueue straddle: the
    placement reflects the client's state at link time, not two unbounded
    gate-spins earlier (#289).
11. sleep_list_remove(tcb) — tcb is Exited and off every CPU, so no add can
    follow, and a timer pop that won the race still holds the full binding
    (Sleep List Invariant 6). Then snapshot tcb's (ipc_state,
    blocked_on_object) under tcb's sched_lock, release it, acquire the source
    IPC lock for blocked_on_object (if any) and unlink tcb from the source's
    wait or waiter queue. Known gap: nothing pins the source here, and a waker that
    claimed tcb before its Exited mark leaves the binding set until its wake
    lands (`enqueue_and_wake`'s abort arm clears it), so a concurrent last-cap
    delete can free the source first (#443 § Source pointer held past its
    free). Branches:
      - BlockedOnSend / BlockedOnRecv: ep.lock; unlink_from_wait_queue.
      - BlockedOnNotification: sig.lock; remove tcb from the waiter queue.
      - BlockedOnEventQueue: eq.lock; remove tcb from the waiter queue.
      - BlockedOnWaitSet: ws.lock; remove tcb from the waiter queue.
      - BlockedOnReply: blocked_on_object is the *server* TCB; mirror
                        cancel_ipc_block — compare_exchange
                        (*server).reply_tcb from tcb to null with AcqRel /
                        Acquire so the server's next endpoint_reply finds
                        no caller and returns None.
      - BlockedOnFault: blocked_on_object is the *handler* (server) TCB;
                        identical to BlockedOnReply — compare_exchange
                        (*handler).reply_tcb from tcb to null so a later
                        fault reply does not target this freed faulter. The
                        faulter never resumes, so no fault_outcome is recorded.
      - None: no source-side cleanup needed.
12. Clear tcb.blocked_on_object = null under tcb's sched_lock: the abort arm
    of a wake that claimed tcb before its Exited mark writes the same pair
    under that lock.
13. Release tcb's fault-handler binding, if any: atomically swap
    tcb.fault_handler to null and dec_ref the prior EndpointObject; if its
    refcount reaches 0, enqueue the orphaned endpoint header on the cascade
    worklist (step 19's mechanism) rather than recursing into dealloc_object.
    Done after the step-11 unlink so the endpoint dealloc cannot observe this
    thread still on its send queue.
14. Wake-in-flight gate (#160): spin, preempt-disabled with interrupts
    enabled, until tcb.wake_in_flight == 0 — a waker that claimed tcb (under a
    source lock, or the timer at its pop) set it before its enqueue_and_wake,
    which, on the Exited tcb, clears it after releasing tcb's sched_lock, as
    its last touch of the TCB. Then sleep_wakeups_quiesce(): a timer batch that popped
    tcb keeps its pointer until the batch ends (Sleep List Invariant 9).
15. (x86_64 only) Release IOPB if bound.
16. Unregister tcb from the live-thread registry.
17. Poison: tcb.magic = 0; tcb.priority = 0xFF.
18. drop_in_place(tcb).
19. retype_free + ancestor dec_ref + cascade (the worklist driven by
    dealloc_object; step 13's orphaned endpoint, if any, is processed here).
```

### Self-teardown (the caller is the freed thread)

Steps 8-9 assume the dealloc caller is a *different* thread than `tcb`: the
`current`-anywhere scan waits for whichever CPU runs `tcb` to switch away. When
the caller **is** `tcb` — a thread that deletes the last capability to its own
`Thread` object via `SYS_CAP_DELETE` or `SYS_CAP_REVOKE` — the running CPU's
`current == tcb` can never clear from within the scan (the spin holds preemption
disabled, so the thread never reschedules). Running steps 8-19 inline would wedge
that CPU (#341).

`dealloc_object_one` detects this case
(`tcb == scheduler_for(this_cpu).current`) and splits the protocol:

- **Inline, on the dying thread:** steps 1-4 only, via
  `set_state_under_all_locks(tcb, Exited)` (mark Exited + drain every run queue).
  The object header is then pushed onto this CPU's deferred-reclaim stack
  (`PerCpuScheduler::deferred_reclaim_head`) and `dealloc_object` returns without
  touching the UAF gate or `retype_free`.
- **Reschedule:** the syscall epilogue (`syscall::dispatch`) observes the
  `Exited` state — probed without a lock and confirmed under this CPU's
  scheduler lock, before its deferred-reclaim drain and again after it, since
  the drain's own waits can let a concurrent teardown stop the thread — and
  calls `schedule(false)` + `halt_loop()`, so the dead thread never returns
  to user-mode. `schedule()` refuses to re-enqueue an `Exited` thread
  (invariant 2), and the switch publishes `tcb.context_saved = 1`.
- **Off-CPU completion:** `drain_deferred_reclaim` — called from the syscall
  epilogue of the *next* live thread on this CPU, and from the idle loop — pops
  the object and re-enters `dealloc_object`. The thread is now off-CPU, so the
  self check is false and steps 5-19 run normally: step 8's scan finds no CPU
  running `tcb` on the first pass and step 9's `context_saved` gate is already
  satisfied. Any server-side reply-bound client (steps 5/10/11) is woken here.

The same stack carries `CSpace` and `AddressSpace` objects whose teardown
found the running thread itself stopped (see
[scheduling-internals.md § Thread Registry](scheduling-internals.md#thread-registry)); the drain
re-enters their arms the same way.

The drain runs only from contexts that are provably not one of the queued dead
threads (a live thread's syscall return, or the idle thread), so it can never
re-enter the wedge it exists to avoid.

**Invariants the drain protocol MUST hold:**

1. **Ascending-order lock acquire** prevents ABBA against any peer drain (the canonical cross-CPU
   scheduler-lock acquisition order,
   [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 4).

2. **Step 3 (state = Exited) commits under all locks.** No `schedule()` on any CPU can subsequently
   observe this TCB as `Ready` or `Running` for purposes of re-enqueue — the protection in
   `schedule()` reads `state` while holding its CPU's scheduler.lock and refuses to re-enqueue if
   `state ∈ {Exited, Stopped}`. `enqueue_and_wake` performs the same check before enqueueing (see
   [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 9).

3. **Step 8's `current`-anywhere scan is bounded.** A TCB is `current` on at most one CPU at a time.
   That CPU is mid-`schedule()`; once it sets `current = next_tcb` (which happens *before* the arch
   switch on both arches — `release_lock_only` runs in Rust before `switch()`), the inner spin
   exits. After it switches away no CPU can re-install tcb (it is `Exited` and unlinked from every
   run queue), so the next full scan is clean and the loop terminates. The scan does not rely on the
   all-locks `running_on` snapshot, which names at most one CPU and may be stale once the locks
   drop. This bound holds only when the dealloc caller is a *different* thread than `tcb`: the
   running CPU reaches `schedule()` and switches away. When the caller *is* `tcb` (self-teardown),
   it never reaches `schedule()` from within the spin, so steps 8-19 are skipped inline and deferred
   off-CPU instead — see [Self-teardown](#self-teardown-the-caller-is-the-freed-thread).

4. **No `fpu_owner` sweep is needed after eager save (#108).** The `#NM` handler only ever installs
   the currently Running thread on its CPU as `fpu_owner`. `switch_out_save` clears the slot on
   switch-out before the thread re-enters the Ready / Blocked / Stopped / Exited states. By the
   time steps 8 and 9 above have completed — the thread has switched out on every CPU and
   `context_saved == 1` — no CPU's owner slot can name this TCB. Steps 8-9's
   interrupt-enabled-while-spinning discipline is still required to prevent the spin from
   deadlocking against a peer CPU's TLB-shootdown IPI; without it, two CPUs in mutual TLB shootdown
   would deadlock.

5. **Step 9's `context_saved` spin is the load-bearing UAF gate, and is unconditional.** On both
   arches, `schedule()` calls `set_current(next)` and `release_lock_only(sched.lock)` *before*
   `switch()` saves the dying thread's registers into `tcb.saved_state`. A peer CPU acquiring the
   same lock at any moment after the release can therefore observe `sched.current = idle` while
   `switch()` is still mid-save into `tcb.saved_state`. Freeing the TCB at that point lets the next
   allocation reuse the memory; `switch()` then corrupts the new allocation, producing hangs
   (`stress::thread_churn`, `bench thread_lifecycle`) or worse. Step 9 closes the window:
   `context_saved` is cleared by `schedule()` *before* the save and written `1` (Release) by
   `switch()` *after* the save; spinning on the Acquire load until it observes `1` guarantees the
   save has fully published (the `context_saved` protocol of
   [scheduling-internals.md](scheduling-internals.md#cross-cpu-tcb-ownership) § Cross-CPU TCB
   Ownership). It is unconditional and runs after step 8's `current`-anywhere scan:
   that scan guarantees no CPU still names tcb as `current`, but a CPU that has just switched *away*
   may still be mid-save into `tcb.saved_state` (the save trails the `current = next` store and the
   lock release), and step 9 is what waits for that save. New TCBs initialise `context_saved = 1`,
   so the wait is bounded for threads that never ran.

6. **Step 11's source-IPC unlink MUST acquire the source's lock for every variant.** This is the
   symmetry rule with `cancel_ipc_block`: both clear IPC-blocking field-group writes from a
   non-owning CPU and MUST hold the matching source lock.

7. **Step 11 BlockedOnReply / BlockedOnFault.** The client's (or faulter's) `blocked_on_object` is
   the *server* / *handler* TCB pointer (the lifetime owner of `reply_tcb`). The dealloc'd thread
   must claim its own slot via `compare_exchange(self, null, AcqRel, Acquire)` before freeing —
   otherwise a later `endpoint_reply` / fault reply on the still-live server would load the freed
   pointer and UAF on the message-copy write. `BlockedOnFault` is handled identically (it reuses
   `reply_tcb`). Every claim outside `ep.lock` MUST use compare_exchange (never an unconditional
   store) so a concurrent cancel cannot lose a peer client's binding; the two exceptions are the
   slot-owning server's `swap(null)` claims, on the `SYS_IPC_REPLY` failure path (actor 7) and at
   `SYS_IPC_RECV` entry (actor 8), per the Symmetry rule in
   [BlockedOnReply Edge — Symmetry Rules](#blockedonreply-edge--symmetry-rules).

8. **Step 13 fault-handler binding release.** A thread that *holds* a fault-handler binding
   (independent of whether it is itself fault-blocked) owns one `inc_ref` on its `fault_handler`
   EndpointObject. The drain swaps the field to null and dec_refs; if the endpoint's refcount
   reaches 0 it is enqueued on the cascade worklist (step 19), not freed by a nested
   `dealloc_object` call — the function's worklist mechanism exists precisely to keep the cascade
   non-recursive. Ordering after step 11 ensures a queued faulter is off the endpoint's send queue
   before the endpoint can be torn down.

9. **Step 17's poison precedes step 18's drop.** `magic = 0` and `priority = 0xFF` are the
   use-after-free traps — any later code that reads these fields and dereferences will fail loudly
   via the `debug_assert!((*tcb).magic == TCB_MAGIC, ...)` checks in the scheduler. Step 18 calls
   `drop_in_place(tcb)` on the in-place body; `ThreadControlBlock` has no Drop today, so this is a
   no-op kept for future fields whose drop semantics matter.

---

## BlockedOnReply Edge — Symmetry Rules

The `BlockedOnReply` state is structurally different from the other `BlockedOn*` states: there is no
dedicated source lock. The "source" is the server TCB itself, and the slot the client is registered
into is `(*server).reply_tcb: AtomicPtr<ThreadControlBlock>`. The `BlockedOnFault` state (fault
redirection) reuses this same slot and discipline — the faulter is parked exactly as a caller and
the handler is the "server" — so every actor below applies to fault delivery as well, distinguished
only by `ipc_state` at the wake site. The following actors can mutate this slot from different lock
domains:

1. **Server in `endpoint_call`** — sets `reply_tcb = caller` under `ep.lock` by a Release `store`
   into an empty slot (actor 8 released any earlier binding when the server entered the receive
   that queued it; the store debug-asserts the slot is null). If the
   caller's park commit is refused (a concurrent stop or exit, or a coalesced wake),
   `rollback_uncommitted_call` rolls the binding back under the same `ep.lock` —
   `compare_exchange(caller, null)` on `reply_tcb`; on a win it stamps a cancelled deposit
   (INTERRUPTED, or KILL for a faulter) and clears `wake_in_flight`.
2. **Server in `endpoint_recv`** — dequeues a `BlockedOnSend` caller and rebinds it to
   `reply_tcb = caller` under `ep.lock` by the same store into an empty slot, then commits the
   caller's
   `BlockedOnSend → BlockedOnReply` (`ipc_state` + `blocked_on_object`) transition via
   `commit_reply_rebind_under_local_lock` (the caller's per-TCB `sched_lock`), mirroring
   `endpoint_call`'s `commit_blocked_under_local_lock`. If that commit fails (the caller
   died/stopped concurrently) it rolls the binding back — `compare_exchange(caller, null)` on
   `reply_tcb`; on a win it stamps a cancelled deposit (INTERRUPTED, or KILL for a faulter) and
   clears `wake_in_flight` — and skips to the next queued sender. See invariant 4 (#289).
3. **Server in `endpoint_reply`** — loads `reply_tcb` (Acquire), then claims it by
   `compare_exchange(caller, null, AcqRel, Acquire)` with no lock held; on a lost race it returns
   `None` and the winning claimant owns the wake.
4. **Client cancel via `cancel_ipc_block`** — `compare_exchange(this_client, null, AcqRel, Acquire)`
   under the client's per-TCB `sched_lock` — not a per-CPU scheduler.lock and not `ep.lock`. The
   lock is held across a re-read of the client's `blocked_on_object` and the CAS; a dying server
   nulls a claimed client's `blocked_on_object` under that same `sched_lock` before it is freed, so
   observing `blocked_on_object == server` under the lock pins the server alive for the CAS. On a
   CAS win the cancel clears the client's `(ipc_state, blocked_on_object)` binding in the same
   `sched_lock` hold: the server's `reply_tcb` is now null, so its dealloc (actor 6) no longer
   reaches this client, and a binding left naming the server would let a second canceller, or the
   client's own `dealloc_object(Thread)`, pass the re-read after the server is freed (see
   [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 7).
5. **Client dealloc via `dealloc_object(Thread)`** —
   `compare_exchange(this_client, null, AcqRel, Acquire)` in the BlockedOnReply branch of the
   source-IPC unlink walk. Mirrors `cancel_ipc_block`'s discipline.
6. **Server dealloc via `dealloc_object(Thread)`** — under all-CPU scheduler.locks, reads
   `(*server).reply_tcb`; if non-null, `compare_exchange(bound, null, AcqRel, Acquire)` to claim the
   binding, then prepares the bound client for wake and schedules an `enqueue_and_wake` for after
   the all-locks region releases. For a `BlockedOnReply` client it stamps the park episode
   `INTERRUPTED` (per the episode table in
   [ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes)); for a `BlockedOnFault`
   client (destruction of the handler thread) it instead records
   `fault_outcome = Kill` (read on entry to the branch, before `ipc_state` is cleared) so the
   faulter runs its kill path on resume. Without this, a client blocked on a dying server/handler
   would remain blocked indefinitely with a dangling `blocked_on_object` pointer to freed memory.
7. **Server on the `SYS_IPC_REPLY` failure path via `fail_reply_and_wake_caller`** —
   `swap(null, AcqRel)` with no lock held. A non-null result is the episode claim: it deposits a
   synthetic `IPC_REPLY_TRANSFER_FAILED` reply and wakes the caller. A null result means no caller
   is bound: none was published, or another claimant already won.
8. **Server at receive entry via `release_unreplied_caller`** — `endpoint_recv` first runs
   `swap(null, AcqRel)` with no lock held. A non-null result is a caller bound by an earlier
   receive the server never replied to; the swap is its episode claim: it stamps a cancelled
   deposit (INTERRUPTED, or KILL for a faulter) and wakes it with `enqueue_and_wake`, so the binding
   is never overwritten (the contract of [ipc-design.md](../../../docs/ipc-design.md) § The
   Call/Reply Model).

**Symmetry rule:** every actor that may invalidate a client's place in the reply slot MUST claim it
by an atomic read-modify-write that observes the bound client (never an unconditional store) so
concurrent actors can determine whether they got there first. Actors 3 through 6 and the
commit-failure rollbacks of actors 1 and 2 use `compare_exchange(this_client, null, ...)`. Actors 7
and 8 use `swap(null)`: only the slot-owning server performs them, while it is running
`SYS_IPC_REPLY` or entering `SYS_IPC_RECV`, and no publisher can install a different caller
meanwhile (`endpoint_call` binds only a server it dequeued from a receive queue, and
`endpoint_recv` runs only on the server itself), so a non-null result is as exclusive a claim as a
won CAS. The publish stores of actors 1 and 2 are plain stores, not claims: they write only an
empty slot, because actor 8 runs before any receive can bind. The single `fault_outcome` writer is
whichever actor wins this claim, so a fault's resume-vs-kill disposition is never decided by two
racing actors.

**Invariants on the BlockedOnReply protocol:**

1. The client's `blocked_on_object` is the server TCB pointer (NOT an endpoint or other source).
2. The server is the lifetime owner of the reply slot. As long as the server is alive,
   `endpoint_call` and `endpoint_recv` publish the slot under `ep.lock`. Their commit-failure
   rollback is itself a `compare_exchange(caller, null)` claim taken under `ep.lock`; every other
   claim (`endpoint_reply`, cancel, dealloc, and the failure-path and receive-entry `swap(null)`) is
   taken outside
   it. `endpoint_reply` takes no lock and claims by CAS; cancel and dealloc paths
   claim by it because they cannot acquire `ep.lock` (they don't know which endpoint this reply is
   for; the server may have moved on to a different endpoint between the original `call` and the
   cancel).
3. **Server-death-while-client-blocked-on-reply** is handled by actor 6 above: the dying server
   walks its `reply_tcb`, claims the bound client via compare_exchange, and wakes it with
   `Interrupted` so the client's syscall returns rather than dereferencing the freed server. The
   wake is dispatched after the dying server's all-locks region releases, since `enqueue_and_wake`
   itself acquires a scheduler.lock.
4. **Client-death-during-the-`endpoint_recv`-rebind** must not leave a dangling `reply_tcb` (#289).
   Client dealloc (actor 5) finds and clears the binding using the client's
   `(ipc_state, blocked_on_object)` pair; that pair is therefore published consistently with
   `reply_tcb`. `endpoint_call` already does this under the caller's per-TCB `sched_lock`
   (`commit_blocked_under_local_lock`); the `endpoint_recv` rebind (actor 2) MUST do the same via
   `commit_reply_rebind_under_local_lock` so the publication serialises with
   `dealloc_object(Thread)`'s all-CPU-locks `Exited` mark (and `dealloc` reads `ipc_state` *after*
   that mark). Otherwise a caller dying mid-rebind lets dealloc read a stale `BlockedOnSend` state,
   take the `BlockedOnSend` unlink arm, and never clear the server's `reply_tcb` — a dangling
   binding that a later `endpoint_reply` fires against the freed-or-reused slot: use-after-free if
   freed (`syscall/ipc.rs` magic assert), double-enqueue if reused-and-queued (the slot is woken
   twice — closed structurally by the `queued_on` single-link tag at the enqueue chokepoint; see
   [scheduling-internals.md](scheduling-internals.md) § Enqueue-chokepoint enforcement), or
   TCB-field corruption if reused-and-running (the residual #284 `#GP` / corrupt `iopb`). On a
   failed commit `endpoint_recv` rolls the binding back and skips the dead sender.

---

## Atomic Ordering for Sleep List and Lifecycle

This section lists ordering invariants specific to the sleep-list + lifecycle surface. Atomic
invariants common with the global wake protocol (`RESCHEDULE_PENDING`, `non_empty`, `context_saved`,
`BOOT_TRANSIENT_ACTIVE`) are NOT restated; see
[scheduling-internals.md § Atomic Ordering Invariants](scheduling-internals.md#atomic-ordering-invariants).

| Atomic / field | Set ordering | Read ordering | Pairing rationale |
|---|---|---|---|
| `tcb.timed_out` (bool, plain field) | non-atomic store under `eq.lock` (timer arm) | non-atomic load by resuming syscall on the same CPU | Single-writer per park (eq.lock excludes any concurrent payload-delivery write); reader is local CPU after `schedule()` returns. No atomic required because the source IPC lock provides mutual exclusion at the write side and the `Blocked → Ready` transition under that same lock provides the happens-before edge to the reader. |
| `tcb.sleep_deadline` (`AtomicU64`) | Relaxed store of the deadline by the parker before `sleep_list_add` (plain sleep: before the park commit; timed IPC wait: under the source lock); Relaxed store or `swap` of 0 only under `SLEEP_LIST_LOCK` (timer pop, `sleep_list_remove`), except a parker's own rollback of a deadline it never listed | Relaxed loads: under `SLEEP_LIST_LOCK` (pop, add, remove — the load-bearing observations); under the source lock (waker prechecks, Sleep List Invariant 7); lock-free by the softlockup watchdog (diagnostic) | The locks order every load-bearing access; the atomic type only makes the source-lock prechecks, which race the pop's clear, well defined. A precheck that reads a stale non-zero value calls a `sleep_list_remove` that finds nothing. |
| `tcb.park_seq` (`AtomicU32`) | Relaxed `fetch_add` under `(*tcb).sched_lock` by every commit that publishes a `Blocked` binding (`commit_blocked_under_local_lock`, `commit_reply_rebind_under_local_lock`); the IPC parks commit under their source lock too | Relaxed loads: under `(*tcb).sched_lock` (`commit_cancelling_park`'s snapshot, and the commit's re-read inside the all-locks hold); under `SLEEP_LIST_LOCK` (the timer pop's snapshot, while the popped park is still committed); under the source lock (the timer's notification and event-queue claim, Sleep List Invariant 6; `cancel_ipc_block`'s source-arm claim gate in all five source arms, Lock Hierarchy rule 7 of scheduling-internals.md) | Each reader holds a lock that orders it against the writes it compares: `sched_lock` for the stop protocol (`commit_cancelling_park`, and `cancel_ipc_block`'s own entry snapshot and tail re-read), and for the timer claim and the cancel's source-arm gate the source lock under which the waiter-queue entry and the park commit of the same park (or its `commit_reply_rebind_under_local_lock` rebind) are published. |
| `TIMER_DISPATCH_SEQ` (`AtomicU64`) | Relaxed `fetch_add` to odd under `SLEEP_LIST_LOCK` by a pop that took an entry; Release `fetch_add` to even after that batch's last claim | Acquire load under `SLEEP_LIST_LOCK`, then Acquire loads in the spin, by `sleep_wakeups_quiesce` | The lock orders the quiescer after the pops it must wait for; the Release/Acquire pair orders the batch's last access to the popped source or TCB before the quiescer's free, whether the quiescer returns at once or after the spin (Sleep List Invariant 9). |
| `tcb.state` (enum, plain field) | non-atomic store under either every CPU's scheduler.lock (`set_state_under_all_locks`) or the TCB's own `(*tcb).sched_lock` (`commit_blocked_under_local_lock` and `enqueue_and_wake`) | non-atomic load by any CPU's scheduler under its own scheduler.lock | The state field is in the Scheduling field group per [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership). The all-locks vs single-CPU split exists because `Stopped`/`Exited` writes must be visible to *every* CPU's `schedule()` skip-check, while routine `Ready ↔ Running` and `Running ↔ Blocked` writes only need to coordinate with the local scheduler that owns the run-queue link. |
| `tcb.priority` (u8, plain field) | non-atomic store by `sys_thread_set_priority` under `(*tcb).sched_lock` | non-atomic loads, each under the TCB's own `(*tcb).sched_lock`: `dealloc_object(Thread)` and `set_state_under_all_locks` (sched_lock held outer of their all-locks region), `migrate_ready_thread`, `enqueue_and_wake`, `enqueue_ready_thread`, and `schedule()`'s requeue arm | `(*tcb).sched_lock` is the serializer: every reader and writer of this field holds it. `schedule()`'s dispatch path deliberately does NOT read `(*next).priority` (it would race the store without `next.sched_lock`); it dispatches by run-queue index, which `dequeue_highest` already validated. After the store, `sys_thread_set_priority` relocates the Ready TCB's queue entry to the new priority (`relocate_ready_priority`, under the run-queue lock); the brief link-at-old / `priority`-new window inside the `sched_lock` region is benign because consumers dispatch by queue index, not by this field. |
| `tcb.reply_tcb` (`AtomicPtr<TCB>`) | Release on the `endpoint_call` / `endpoint_recv` publish store under ep.lock (into an empty slot: `release_unreplied_caller` cleared it at receive entry); AcqRel on `compare_exchange` from the commit-failure rollback (under ep.lock) and from `endpoint_reply`, cancel, client-dealloc, and server-dealloc paths (no ep.lock); AcqRel on the `swap` of `fail_reply_and_wake_caller` and `release_unreplied_caller` (no lock) | Acquire on `endpoint_reply`'s pre-CAS load (no lock); Acquire on the server-dealloc snapshot under all sched.locks; Acquire on `sys_ipc_reply`'s fault-reply and cap-pre-allocation peeks (no lock), which read before any claim and dereference the loaded caller unpinned (#443); Relaxed on the softlockup watchdog's diagnostic load (`watchdog_decode_blocked_on`) | Every claim is an atomic read-modify-write that observes the bound client. The `compare_exchange` clears the slot only when it still references the claimant's expected TCB, so two concurrent claimants cannot clear a third unrelated client's binding; both `swap`s are safe because only the slot-owning server performs them, while no publisher can install a different caller during its `SYS_IPC_REPLY` or at its `SYS_IPC_RECV` entry (per the Symmetry rule). The publish is a plain store, not a claim, into a slot actor 8 emptied at receive entry, so it never overwrites a binding (debug-asserted). The Release publish pairs with each claimant's Acquire. |

---

## `sys_thread_sleep` and the Plain-Sleep Path

`sys_thread_sleep` is the simplest sleeper: no IPC source, only the timer. Sequence:

```
1. deadline = sleep_deadline_after_ms(ms) (never 0).
2. (*tcb).sleep_deadline = deadline.
3. commit_blocked_under_local_lock(tcb, None, null): state = Blocked under
   sched_lock (a refusal rolls back the deadline and returns: RefusedWake →
   Ok(0), RefusedStop → deschedule, then Interrupted).
4. sleep_list_add(tcb): Ok, or Cancelled (a canceller already cleared the
   deadline and stamped the park; proceed to schedule), or Full (withdraw
   under sched_lock with sleep_list_remove: a true return restores Running
   and returns OutOfMemory; false means a canceller claimed the park and
   stamped it, so proceed to schedule).
5. schedule(false).
6. On resume: the syscall consumes the park disposition (Ok(0) on a timer
   wake, Interrupted on a cancel).
```

Step 6's disposition is the park episode's, per
[ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes) § Park Dispositions and
Episodes.

**Invariants:**

1. `ipc_state == None` is the discriminator that selects the plain-sleep arm in
   `sleep_check_wakeups`. The plain arm claims at the pop because no IPC source is competing.
2. The plain sleep needs no source-lock arbitration. The timer, `cancel_ipc_block` and, on a full
   list, the sleeper's own withdrawal arbitrate on the deadline under `SLEEP_LIST_LOCK`: the pop
   clears it with the entry, and `sleep_list_remove` clears it and returns whether it was still
   non-zero, so exactly one of them takes the episode.
3. The cancel path: `sys_thread_stop` (or an object-teardown stop) on a sleeper runs
   `cancel_ipc_block`, which, while it holds the target's `sched_lock` and sees `Blocked` with
   `ipc_state == None`, calls `sleep_list_remove`. A `true` return is the episode claim: the cancel
   stamps the park `INTERRUPTED`, so the restarted sleeper returns `Interrupted` instead of
   reporting the truncated sleep as success. It covers the window between step 3 and step 4: the
   entry is not listed yet, the remove clears the deadline, and step 4's add refuses with
   `Cancelled`, so no entry is left behind for a thread the stop has cancelled; when the add finds
   the list full instead, the sleeper withdraws the park with the same `sleep_list_remove` under
   `sched_lock`, so the cancel's claim and the withdrawal exclude each other, and a sleeper whose
   park a cancel claimed deschedules and returns `Interrupted` rather than `OutOfMemory`. Holding
   `sched_lock` keeps the park from changing under the remove, so a cancel never claims a later
   park. A `false` return means another claimant took the episode first, and the restarted sleeper
   returns what that claimant deposited: the timer's pop (its wake aborted by `enqueue_and_wake` if
   the stop commits first) deposits nothing, so the sleeper returns `Ok`, honest for a deadline that
   elapsed; a concurrent canceller stamped `INTERRUPTED`; or the sleeper's own full-list withdrawal
   won, and it returns `OutOfMemory` while the stop commits over the restored `Running`. A stop that
   wins against the park commit
   (`ParkCommit::RefusedStop`) makes `sys_thread_sleep` deschedule in place and return `Interrupted`
   directly.

---

## `sys_thread_stop` Cross-CPU Stop Protocol

`sys_thread_stop` MUST commit the target's `Stopped` state under every CPU's scheduler.lock so a
concurrent `schedule()` on the remote CPU cannot read `state != Stopped` and re-enqueue the target.
The handler then drains the target.

**Protocol (`core/kernel/src/syscall/thread.rs::sys_thread_stop`):**

1. Resolve the target Thread cap; reject `Created`, `Exited`, `Stopped` (an unlocked read) with
   `InvalidState`.
2. `commit_cancelling_park(target, Stopped, None)` loops over the sub-steps below:
   1. Snapshot `(state, park_seq)` under the target's `sched_lock`.
   2. If the snapshot is `Blocked`, call `cancel_ipc_block(target)` — acquires the source IPC lock
      matching `tcb.ipc_state`, unlinks a source waiter only while its `park_seq` still equals the
      value `cancel_ipc_block` snapshotted under `sched_lock` on entry (a park entered after that
      snapshot is left for the next pass; one entered between sub-step 1 and it is cancelled in this
      pass, and the commit's `park_seq` mismatch forces the retry; the reply and fault arms gate on
      a `blocked_on_object` re-read under `sched_lock` instead, so they may cancel a later park on
      the same server in this pass, which the mismatch then retries over), and on the claim win
      stamps the park episode `INTERRUPTED` (fault episodes: `fault_outcome = Kill`; see
      [ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes) § Park Dispositions and
      Episodes) so the restarted thread's resume reports the cancellation.
   3. The all-locks commit: acquire the target's `sched_lock`, then every CPU's scheduler.lock in
      ascending order; if `park_seq` still equals the snapshot, write `state = Stopped`, drain the
      run queues, and snapshot `running_on` (the CPU whose `sched.current == target_tcb`, if any);
      release all locks. A changed `park_seq` means the target parked, or was rebound, after the
      snapshot (a park this pass's cancel may or may not have claimed), so nothing is written and
      the loop repeats; the next pass cancels that park, finds it already cancelled, or finds a
      waker's claim and commits over it (see below). The commit returns `StateCommit`:
      `Committed(running_on)` on a write, or `RefusedExited` when the target exited after step 1's
      unlocked check; `commit_stopped` surfaces the refusal as `InvalidState` (table row
      `sys_thread_stop (Created or Exited or Stopped)`).

   So `Stopped` is never written over a live park: every park the commit lands on was cancelled by
   this stop or a concurrent one, or already claimed by a waker, so a stop never leaves a `Stopped`
   thread registered as a source's waiter or on the sleep list. The object-teardown stop
   (`stop_threads_bound_to`) commits `Exited` through the same loop. A park that a waker claimed
   first (removed from the queue, `wake_in_flight = 1`) is not cancelled; the stop commits over it
   and the waker's later `enqueue_and_wake` aborts on `Stopped`, clearing the park binding it owns
   and leaving the deposit for the resume (invariant 4). Until that wake lands the `Stopped` thread
   still carries the binding; `dealloc_object(Thread)` waits out the pin before it frees the thread,
   but its drain step 11 reads the binding first (#443 § Source pointer held past its free).
3. **Self-stop fast path.** If the target is the calling thread, call `schedule(false)` immediately.
   The skip-loop in `schedule()` never re-enqueues a `Stopped` TCB.
4. **Cross-CPU drain.** If `running_on = Some(run_cpu)` and `run_cpu != current_cpu`:
   - `prod_remote_cpu(run_cpu)` — sends a wakeup IPI. Its handler does no work
     ([scheduling-internals.md § IPI Taxonomy](scheduling-internals.md#ipi-taxonomy)): the trap it
     forces snapshots the target's user registers into its `TrapFrame` and returns to user mode,
     and the remote CPU drops the `Stopped` target at the next slice-expiry `schedule(true)` its
     `timer_tick` performs (one that finds preemption enabled there; a window that disables it
     resets the slice) or at the target's own park or yield, whose trap leaves the snapshot
     `sys_thread_read_regs` reads once the drain below completes.
   - Bounded spin until `sched_remote.current != target_tcb` and the target's `context_saved` is
     set, **or** the target is no longer `Stopped`. The remote CPU's `schedule()` drains the
     `Stopped` target via the skip-loop and switches to either the next ready thread or its idle
     TCB; `current` moves off the target before `switch()` publishes its save, so the spin waits for
     both and exits once that switch completes. The state re-check (read under `sched_remote.lock`,
     alongside `current`) covers the other exit: an object teardown (`stop_threads_bound_to`,
     `dealloc_object`) can commit `Exited` over the target while it is still `current` there, and
     the drain bails so it does not wait on a thread the teardown will reap. A start cannot move the
     target off `Stopped` meanwhile: its commit requires the target to be `current` on no CPU.
   - Each pass that must wait also reads the stopper's own `state` under its `sched_lock`, which
     every `Stopped`/`Exited` commit holds. A stopper that has itself been stopped (a peer holding
     its Control cap stopping it back, or an object teardown) leaves the spin envelope and calls
     `schedule(false)`: this preempt-disabled window suppresses the slice-expiry switch that would
     otherwise deschedule it, and the syscall epilogue reschedules only an `Exited` thread. When it
     is restarted it re-resolves its target through its own capability slot (nothing pins the
     slot across the park) and re-enters the drain only if the slot still names the target with
     Control rights, returning once the target has left its CPU; otherwise the caller no longer
     holds that capability in the slot (deleted, moved, or revoked) and the call returns at once,
     whether or not a target still reachable through another capability has left its CPU. Two
     threads stopping each other concurrently therefore both end `Stopped`, restartable by a
     third, instead of both spinning forever.
5. **Save wait.** Otherwise, if `running_on` is `None` and the target is not the caller, wait
   with interrupts enabled and preemption disabled until the target's `context_saved` is set
   or it is no longer `Stopped` (`await_stopped_save`; spin site `stop:save`): a target that left
   its CPU just before the commit may still be finishing its switch out there.

**Invariants:**

1. The drain spin in step 4 is the correctness requirement: it returns only once the remote CPU
   has descheduled the target through a trap, which is what gives `sys_thread_read_regs` a fresh
   `trap_frame`. The wakeup IPI contributes no descheduling (its handler does no work); it exits a
   `hlt` on an idle CPU and forces one register snapshot. A stopper restarted after its in-place
   park upholds this only through the slot it re-resolves: when that slot no longer names the
   target, the call returns without the drain. `sys_thread_read_regs` and `sys_thread_write_regs`
   do not rely on the drain: they act only on a thread that is `current` on no CPU with its save
   published and is `Stopped` or fault-blocked, under its `sched_lock`
   (`sched::with_held_frame`); a `Stopped` thread still on a CPU is refused with `InvalidState`,
   and a fault-blocked one still switching out is waited for.
2. For Ready targets on a remote run queue, no IPI and no drain are needed; the all-locks commit
   unlinks the TCB from every run queue at once, and the `schedule()` skip-loop is only
   defence-in-depth. Any target `current` on no CPU at the commit, `Ready` or `Blocked`, may
   still be finishing its switch out on the CPU it just left; step 5 waits for its save, so the
   call never returns with the save unpublished.
3. The bounded spin in step 4 holds NO lock; it acquires `sched_remote.lock` briefly per iteration
   to read `current` and the target's `state` (the latter coherent because the all-locks commit
   writes `state` under every CPU lock, including this one), then releases, and reads the target's
   `context_saved` with Acquire, lock-free. The syscall enters with interrupts disabled, so the spin
   runs under `preempt_disable` with interrupts re-enabled (`save_and_disable_interrupts` →
   `enable`, restored afterwards) — the discipline of drain-protocol steps 8-9: spinning with
   interrupts disabled would block an inbound TLB-shootdown IPI targeted at this CPU and deadlock
   it. The spin terminates as soon as the remote deschedules the target and publishes its save, or
   an object teardown commits `Exited` over it (a start cannot commit while the target is `current`
   anywhere).
4. **A restart waits out an owed wake.** A waker that claimed the stopped park may still be between
   its claim and its `enqueue_and_wake`. Each pass of `sys_thread_start`'s settle loop
   (`start_under_all_locks`) reads `wake_in_flight` under the target's `sched_lock` (ordered after
   the claim, whose source lock the stop's cancel or the thread's own park rollback took before
   committing or descheduling) and, while it is set, waits rather than commits (preemption
   disabled, interrupts enabled; spin site `start:settle`). The pin a reply
   binding sets at bind counts the same way: whichever actor wins the binding's claim either wakes
   the thread or, tearing the binding down, clears the pin (the reply-slot actors above; a binding
   is never overwritten, so one always wins). A `Stopped` thread that is off every CPU and on no
   queue cannot be claimed again, so the late wake always lands on `Stopped` and aborts — unless a
   concurrent start restarts it first, lets it park and be claimed, and a stop commits `Stopped`
   over that claim before this start commits (or stops it while it still runs). The commit
   therefore re-reads the pin, and that the thread is `current` nowhere with its save published,
   under its locks and, if either fails, refuses and takes another pass; a pass that finds the
   thread no longer `Stopped` ends the start, so the loop never waits on a pin a running thread's
   new park holds (a reply binding, say). Without the gate the
   restarted thread could run, park again, and be linked `Ready` by that wake while still queued on
   its new source.

---

## Summarized By

[Capability Subsystem Internals](capability-internals.md),
[IPC Subsystem Internals](ipc-internals.md),
[SMP Scheduler/IPC Hotpath Redesign — per-TCB `sched_lock` (authoritative serializer)](sched-ipc-redesign.md),
[Scheduler Internals](scheduler.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md),
[core/ktest/README.md](../../ktest/README.md),
[Capability Model](../../../docs/capability-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md)
