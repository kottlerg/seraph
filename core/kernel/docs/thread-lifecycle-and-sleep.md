# Thread Lifecycle and Sleep List Invariants

This document specifies the cross-cutting invariants for thread lifecycle transitions
(`sys_thread_start`, `sys_thread_stop`, `sys_exit` / `sys_process_exit`, and
`dealloc_object(Thread)`), the global sleep list (`SLEEP_LIST` + `SLEEP_LIST_LOCK`), and the
timer-driven wakeup arbitration in `sleep_check_wakeups`.

---

## Document Boundary

This document is a sibling of [scheduling-internals.md](scheduling-internals.md) and binds the
same authority for the surfaces below; cross-cutting concurrency rules established there (lock
hierarchy, cross-CPU TCB ownership, wake protocol) MUST hold here.

Cross-cutting concerns owned by [scheduling-internals.md](scheduling-internals.md) — lock hierarchy,
the global wake protocol, IPI taxonomy, BSP boot transient, atomic-ordering invariants, the
IPC-blocking field group of TCB ownership — are NOT restated here. Where this document references
them it links back; where this document adds rules they MUST be consistent with the parent
invariants.

| Doc | Owns |
|---|---|
| [scheduling-internals.md](scheduling-internals.md) | Lock hierarchy, cross-CPU TCB ownership table, wake protocol, BSP boot transient, IPI taxonomy, atomic ordering pairings. |
| **This document** | Sleep-list capacity and BSP-servicing model; `timed_out` cross-CPU protocol; lifecycle-syscall state-machine table; `dealloc_object(Thread)` cross-CPU drain protocol; the `BlockedOnReply` reply-slot claim protocol (every publisher and claimant of `reply_tcb`). |
| [scheduler.md](scheduler.md) | Scheduling algorithm (priority, FIFO, slice, affinity, idle role). |
| [ipc-internals.md](ipc-internals.md) | IPC primitive object layouts and syscall paths. |

---

## Surface

In scope (this document is the authoritative reference consulted before any change that
touches these):

- `core/kernel/src/sched/mod.rs` — `sleep_list_add`, `sleep_list_remove`, `sleep_check_wakeups`,
  `post_death_notification`, `set_state_under_all_locks`, `exit_under_all_locks`,
  `await_descheduled`, `wait_until_off_cpu` (drain steps 8-9), `stop_threads_bound_to`,
  `select_target_cpu_excluding`, `prod_remote_cpu`.
- `core/kernel/src/sched/thread.rs` — `ThreadState`, `IpcThreadState`, TCB.
- `core/kernel/src/syscall/{thread,mod}.rs` — `sys_thread_configure`, `sys_thread_start`,
  `sys_thread_stop`, `sys_thread_set_priority`, `sys_thread_set_affinity`,
  `sys_thread_read_regs`, `sys_thread_write_regs`, `sys_exit`, `sys_process_exit`,
  `sys_thread_sleep`, `cancel_ipc_block`, and the self-teardown epilogue of `syscall::dispatch`.
- `core/kernel/src/syscall/ipc.rs` — `sys_notification_wait`, `sys_event_recv` (sleep-list
  arming), `sys_ipc_reply`, `fail_reply_and_wake_caller`.
- `core/kernel/src/ipc/endpoint.rs` — `endpoint_call`, `endpoint_recv`, `endpoint_reply`
  (`reply_tcb` publish and claim).
- `core/kernel/src/ipc/{notification,event_queue}.rs` — `notification_send`, `event_queue_post`,
  `event_queue_drop` (wake-side sleep-list removal).
- `core/kernel/src/cap/object.rs` — `ObjectType::Thread` arm of `dealloc_object_one`,
  `push_deferred_reclaim`, `drain_deferred_reclaim` (§ Self-teardown).
- The fault handlers in `core/kernel/src/arch/{x86_64/idt.rs,riscv64/interrupts.rs}` that drive
  thread-fault exits (fault → `Exited` transition).

---

## Sleep List Invariants

The sleep list is a single global fixed-capacity array of TCB pointers. A TCB is on the list when
its `sleep_deadline != 0` AND it has been registered via `sleep_list_add`. The BSP timer tick scans
the list, claims expired entries under `SLEEP_LIST_LOCK`, releases the lock, and arbitrates wake
claims against concurrent IPC sources via the relevant source IPC lock (Notification / EventQueue /
"plain sleep" only — `sys_thread_sleep` is a plain sleep with no source).

**Invariants the sleep list MUST hold:**

1. **`SLEEP_LIST_LOCK` is leaf-only.** Per
   [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) rule 3. Wake
   direction is `source.lock → SLEEP_LIST_LOCK`; timer direction releases `SLEEP_LIST_LOCK` before
   any source lock — sequential, not nested.

2. **A TCB on the sleep list MUST be in `Blocked` state.** The timer's claim does not read
   `state`: a claimed entry goes to `enqueue_and_wake`, whose state gate under
   `(*tcb).sched_lock` links only a `Blocked`/`Created` target and coalesces any other (a
   `Running` target records `wake_pending`). `sys_thread_sleep` violates this rule when a stop
   lands between its park commit and its `sleep_list_add` (plain-sleep invariant 3 of
   [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path);
   [#443](https://github.com/kottlerg/seraph/issues/443)).

3. **`sleep_deadline != 0` is the in-band "registered" notification.** Set before `sleep_list_add`;
   cleared by whichever path claims the wake (sender, timer, or `cancel_ipc_block`).
   `sleep_list_remove` is idempotent.

4. **Capacity is hard.** At `SLEEP_COUNT == MAX_SLEEPING`, `sleep_list_add` returns `Err(())`.
   Parking syscalls either roll back to an indefinite IPC wait (`sys_notification_wait`,
   `sys_event_recv`) or surface `OutOfMemory` (`sys_thread_sleep`). Silent drop is forbidden — it
   would hang the parker.

5. **`sleep_check_wakeups` is BSP-only.** APs' timer ticks do not touch the sleep list. A BSP stuck
   in an interrupt-disabled critical section delays all timeout wakes; this is a deliberate
   simplification, not an oversight.

6. **Snapshot-then-claim arbitration.** Under `SLEEP_LIST_LOCK` the timer pops each expired entry
   into `expired[..n]`, snapshots its `(ipc_state, blocked_on_object)` (the TCB is provably alive
   there, since `dealloc_object(Thread)` removes its entry under the same lock before freeing,
   except through the stale plain-sleep entry
   ([#443](https://github.com/kottlerg/seraph/issues/443); see
   [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path))),
   and for a plain sleeper (`ipc_state == None`) sets `wake_in_flight = 1`. It then releases the
   lock and dispatches each entry off the snapshot, never dereferencing the TCB to choose an arm:
   - `BlockedOnNotification` / `BlockedOnEventQueue`: take the source lock; claim iff
     `(*src).waiter == tcb`.
   - `BlockedOnReply` / `BlockedOnFault` (defensive — neither is ever placed on the sleep list
     today, since IPC call/reply and fault delivery take no timeout, except through the stale
     plain-sleep entry ([#443](https://github.com/kottlerg/seraph/issues/443); see
     [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path))):
     `compare_exchange` the server/handler `reply_tcb` from `tcb` to null; claim iff won.
     Forecloses a future timeout surface letting the `default` arm mis-claim a reply/fault waiter
     and race a concurrent reply/cancel into a double-wake, except through the stale plain-sleep
     entry ([#443](https://github.com/kottlerg/seraph/issues/443); see
     [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path)).
     `BlockedOnFault` additionally records `fault_outcome = Kill` on a win (a timeout is a
     cancellation).
   - default (plain sleep, `None`): claim unconditionally; no concurrent waker, except through the
     stale plain-sleep entry ([#443](https://github.com/kottlerg/seraph/issues/443); see
     [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path)).

   The snapshot is read without the source lock; the `waiter == tcb` (or `reply_tcb` CAS) check
   under the source lock / on the atomic is the authoritative arbitration (stale snapshot = benign
   skip, except through the stale plain-sleep entry
   ([#443](https://github.com/kottlerg/seraph/issues/443); see
   [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path))).

7. **Wake-side `sleep_list_remove` MUST be inside the source IPC lock and MUST precede clearing
   `sleep_deadline = 0`** (the #117 order: clearing first leaves an entry whose
   `deadline == 0 <= now`, which the timer claims as expired, double-waking the waiter). Producer
   half of the snapshot-then-claim protocol. See
   `notification_send` and `event_queue_post`.

8. **`sleep_list_add` from a parking syscall MUST re-acquire the source IPC lock and verify
   `(*src).waiter == tcb` before arming.** Without the recheck, a wake firing in the window between
   the IPC primitive releasing its source lock and the syscall arming the deadline leaves the TCB on
   the sleep list with stale state. The next unrelated `notification_wait` / `event_recv` on this
   TCB is then hijacked by `sleep_check_wakeups`, delivering `wakeup_value = 0` instead of real
   bits/payload. See `sys_notification_wait` and `sys_event_recv`.

---

## `timed_out` Cross-CPU Protocol

`tcb.timed_out: bool` is a single-cell out-of-band marker that distinguishes "data-delivered wake"
from "timeout wake" for IPC primitives whose payload may itself be zero (notably `sys_event_recv`,
contrast `sys_notification_wait`, where a notification wake never carries 0 bits because
`notification_send` rejects zero-bit sends, so `wakeup_value == 0` means the timeout elapsed or the
notification was destroyed while the caller waited (#443)).

**Invariants:**

1. **`timed_out` is in the IPC blocking field group** per
   [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership).
   Cross-CPU writers MUST hold the matching source IPC lock at the moment of write.
   `sleep_check_wakeups`'s `BlockedOnEventQueue` arm writes it under `eq.lock`; this is correct.
   The defensive `BlockedOnReply` arm also writes `timed_out = true` (with `wakeup_value = 0`) on
   its `reply_tcb` CAS win, under no source lock; it is unreachable today because no syscall arms
   a reply waiter on the sleep list, except through the stale plain-sleep entry
   ([#443](https://github.com/kottlerg/seraph/issues/443); see
   [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path)).

2. **Reader is the resuming syscall.** After `schedule()` returns, the resuming syscall (currently
   `sys_event_recv` only) reads-and-clears `timed_out` and `wakeup_value` as a pair. The reader is
   single-CPU (the resuming CPU is `current_tcb`'s CPU); no lock required. Both fields MUST be
   cleared by the reader before the syscall returns, so a subsequent `sys_event_recv` on the same
   TCB starts from a clean slate.

3. **Mutual exclusion of payload paths.** Exactly one of three outcomes occurs after a timed wait
   blocks:
   - `event_queue_post` claims the waiter slot under `eq.lock`, writes `wakeup_value = payload`,
     sets `wake_in_flight = 1`, removes the sleep-list entry, releases `eq.lock`, and its caller
     then calls `enqueue_and_wake` (which writes `Ready` under the waiter's `sched_lock`).
     `timed_out` remains `false`.
   - `sleep_check_wakeups`' `BlockedOnEventQueue` arm claims the waiter slot under `eq.lock`,
     writes `wakeup_value = 0` and `timed_out = true`, sets `wake_in_flight = 1`, releases
     `eq.lock`, then calls `enqueue_and_wake`.
   - `event_queue_drop` (the queue is destroyed while the caller is parked) claims the waiter
     under `eq.lock`, writes `wakeup_value = 0`, and leaves `timed_out` `false`;
     `sys_event_recv` then returns success with a payload of `0` that was never posted (#443).

   The `(*eq).waiter == tcb` arbitration under `eq.lock` ensures exactly one of these paths fires
   per park. Apart from the destroyed-queue wake (#443), the reader can then trust that
   `timed_out == true` ⇔ "no payload" and `timed_out == false` ⇔ "wakeup_value is the payload"
   (which may legitimately be zero).

4. **No third writer.** `cancel_ipc_block` MUST NOT touch `timed_out`. A cancelled wait returns
   `Interrupted`, not "timed out": the cancel stamps the park episode `INTERRUPTED` at its
   waiter-slot claim, and the resuming syscall consumes that disposition *before* the
   `timed_out`/`wakeup_value` read (clearing both in the interrupted branch — see
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
| `sys_thread_configure` | `Created` | `Created` | calling CPU | does NOT touch `state`; mutates `trap_frame` and `saved_state.fs_base`. Target MUST be `Created`. |
| `sys_thread_start` (first start) | `Created` | `Ready` | calling CPU | `await_descheduled(target)` (drains the target off every CPU's `current` and waits `context_saved == 1`; a never-dispatched `Created` thread is `current` nowhere, so this returns immediately), then `set_state_under_all_locks(target, Ready)`, then `enqueue_ready_thread(target_cpu)`. The all-locks write closes the dealloc race: a concurrent `dealloc_object(Thread)` on another CPU cannot free the TCB between the state write and the link. `enqueue_ready_thread` (not `enqueue_and_wake`) is used because the gated wake would coalesce an already-`Ready` thread and silently drop the link (see [scheduling-internals.md § ThreadState Transitions](scheduling-internals.md#threadstate-transitions)). Both the commit and the link refuse an `Exited` target (`StateCommit::RefusedExited` / `false`): the syscall's state precheck ran without a lock, and an object teardown or an exit on another CPU may have ended the thread since; the syscall then returns `InvalidArgument` and nothing is linked. |
| `sys_thread_start` (resume from stop) | `Stopped` | `Ready` | calling CPU | Same as first-start, but the `await_descheduled` drain is load-bearing here: a thread stopped while Running may still be `current`/executing on a remote CPU. The drain runs while the target is still `Stopped` (a state `schedule()`'s requeue denylist rejects, so the owning CPU deschedules it without re-linking), and only then commits `Ready` and force-links it — otherwise `enqueue_ready_thread` would dispatch a still-live thread on a second CPU (the cross-CPU double-dispatch of #314/#293). The kernel uses `sys_thread_start` for both first-start and resume; this overload is intentional and `Stopped → Ready` is a permitted transition. |
| `sys_thread_stop` (running self) | `Running` | `Stopped` | calling CPU = running CPU | `set_state_under_all_locks(target, Stopped)`, then `schedule(false)` immediately yields. `schedule()`'s requeue arm never re-enqueues a `Stopped` current thread. |
| `sys_thread_stop` (running remote) | `Running` | `Stopped` | calling CPU ≠ running CPU | `set_state_under_all_locks(target, Stopped)` returns `StateCommit::Committed(Some(run_cpu))`; the syscall handler then calls `prod_remote_cpu(run_cpu)` (a wakeup IPI whose handler only acknowledges it; it does not force `schedule()`) and bounded-spins until `sched_remote.current != target_tcb` or the target is no longer `Stopped` (a concurrent `sys_thread_start` overtook the stop). The spin ends at the remote CPU's next `schedule()` entry: slice expiry (the requeue denylist drops the `Stopped` current), a `SYS_THREAD_YIELD`, a park whose commit returns `ParkCommit::RefusedStop`, or an exit (`sys_exit`, `sys_process_exit`, or a terminal fault). That entry also rewrites the target's `trap_frame`, so `sys_thread_read_regs` observes the registers of the descheduling kernel entry. The syscall epilogue does not deschedule a `Stopped` thread, because `running_thread_stopped` tests `Exited` only; a non-blocking syscall returns the target to userspace. |
| `sys_thread_stop` (Ready, on a run queue) | `Ready` | `Stopped` | calling CPU | `set_state_under_all_locks(target, Stopped)`, which also removes the TCB from every CPU's run queue inside the all-locks region (#117); the `schedule()` skip-loop is defence in depth only. |
| `sys_thread_stop` (Blocked) | `Blocked` | `Stopped` | calling CPU | `cancel_ipc_block(target)` first (acquires the source IPC lock matching `tcb.ipc_state` and unlinks the waiter), then `set_state_under_all_locks(target, Stopped)`. |
| `sys_thread_stop` (Created or Exited or Stopped) | `*` | `*` | calling CPU | n/a — returns `InvalidState`. No state write. An `Exited` target observed only at the locked commit (the thread died between the unlocked precheck and `set_state_under_all_locks`) is refused there with the same `InvalidState`. |
| `sys_thread_set_priority` | `*` | `*` (priority changed) | calling CPU | Holds `(*tcb).sched_lock` across the `state` read and the `(*tcb).priority` write, and — when the target is `Ready` — relocates the queue entry via `sched::relocate_ready_priority`: lock the single `preferred_cpu`-hinted CPU's `scheduler.lock` and verify membership with `remove_from_queue` (O(1) locks), falling back on a miss to the ascending all-CPU walk. `remove_from_queue`'s boolean identifies the home CPU; the re-enqueue lands at the new priority on the located scheduler. The held `sched_lock` serialises with `dealloc_object(Thread)`, `migrate_ready_thread`, and `set_state_under_all_locks`. |
| `sys_thread_set_affinity` | `*` | `*` | calling CPU | Under `preempt_disable`, writes `cpu_affinity` with no `sched_lock` held ([#443](https://github.com/kottlerg/seraph/issues/443)), then acts on an unlocked `state` read: a `Ready` target is moved with `migrate_ready_thread(tcb, old_cpu, new_cpu)` (`sched_lock`, then both CPU locks ascending; re-checks and bails on a race); a `Running` target gets `set_reschedule_pending_for(old_cpu)` + `prod_remote_cpu(old_cpu)`; a `Blocked`/`Stopped`/`Created` target takes the new affinity at its next `select_target_cpu`. `AFFINITY_ANY` or an unchanged CPU returns without migrating (see [syscalls.md § `SYS_THREAD_SET_AFFINITY`](syscalls.md#sys_thread_set_affinity-38)). |
| `sys_thread_read_regs` | `Stopped`, or `Blocked` (`BlockedOnFault`) | unchanged | calling CPU | none beyond the source-state check. Caller-supplied buffer is the destination; no scheduler-state mutation. |
| `sys_thread_write_regs` | `Stopped`, or `Blocked` (`BlockedOnFault`) | unchanged | calling CPU | none beyond the source-state check. Validates user `TrapFrame` then writes; target is not running (`Stopped`, or parked fault-blocked for its handler; see [fault-handling.md](../../../docs/fault-handling.md)). |
| `sys_exit` / `sys_process_exit` (self) | `*` | `Exited` | running CPU = current CPU | `exit_under_all_locks(self, reason)` (reason `0` for `sys_exit`, the encoded exit code for `sys_process_exit`): commits `Exited` and records `exit_reason` in one all-locks hold, returning `StateCommit::RefusedExited` without writing either if a teardown already committed `EXIT_KILLED`; then `post_death_notification(self, reason)` (this path's own reason, even after a refusal), then `schedule(false)`. The all-locks write ensures any peer-CPU `schedule()` sees `Exited` and refuses to re-enqueue. |
| arch fault handler (page fault, GP fault, etc.) | `*` | `Exited` | trapping CPU = current CPU | `exit_under_all_locks(tcb, 0x1000 + vector)` (x86_64) / `0x1000 + cause_code` (riscv64), then `post_death_notification` and `post_aspace_death_notification` with that reason, then `schedule(false)`. |
| `dealloc_object(Thread)` (caller ≠ tcb) | `*` | `Exited` | calling CPU (refcount → 0) | Acquires `(*tcb).sched_lock` (outer), then every CPU's scheduler.lock in ascending order, writes `state = Exited`, walks `remove_from_queue` for every CPU, releases all. After release: unconditionally scans every CPU until none has `sched.current == tcb`, then unconditionally on `tcb.context_saved == 1`, then the reply-bound client wake, source-IPC unlink, fault-handler release, sleep-list removal and wake-in-flight gate, registry unlink, and free. See Drain Protocol below. |
| `dealloc_object(Thread)` (caller == tcb, self-teardown) | `Running` | `Exited` | calling CPU = running CPU | A thread deleting the last capability to its own `Thread` object cannot run the post-release scan (its CPU's `current == tcb` never clears from within the spin). Marks Exited + drains run queues only, queues the object on this CPU's deferred-reclaim stack, and returns; the syscall epilogue reschedules and the free completes off-CPU. See [Self-teardown](#self-teardown-the-caller-is-the-freed-thread) below. |
| `dealloc_object(CSpaceObj)` / `dealloc_object(AddressSpace)` — bound-thread stop (`stop_threads_bound_to`) | `*` | `Exited` | calling CPU (object refcount → 0) | For every registered thread bound to the dying object: `cancel_ipc_block` if `Blocked`, then `exit_under_all_locks(tcb, EXIT_KILLED)` — the `Exited` commit with `EXIT_KILLED` recorded in the same all-locks hold (a commit refused because the thread exited on its own meanwhile writes neither, and that thread still posts its own reason — no death walk posts `EXIT_KILLED`; an observer bound after the stop receives it through the bind); running CPUs are prodded after the registry lock is released and the caller spins until no other CPU has a bound thread as `current` (and, for an `AddressSpace`, until `active_cpus` is empty). The thread is stopped, not freed: its object waits for its own last cap. If the caller's own thread is stopped — bound here, or by a concurrent teardown — nothing is freed: the object goes onto this CPU's deferred-reclaim stack (as in the self-teardown row) and the epilogue schedules the thread away. See [scheduling-internals.md § Thread Registry](scheduling-internals.md#thread-registry). |

**Why the all-CPU lock acquire in `dealloc_object(Thread)`:**

`preferred_cpu` is in the Scheduling field group serialised by `(*tcb).sched_lock`:
`enqueue_and_wake` and `enqueue_ready_thread` retarget it under `sched_lock` with the target
run-queue lock inner, and `schedule()`'s dispatch flip writes it under `next.sched_lock`. Between a
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
1. Acquire (*tcb).sched_lock (outermost), then every CPU's scheduler.lock in
   ascending CPU order.
2. Read tcb.priority INSIDE the all-locks region. This read is serialised
   against sys_thread_set_priority's priority write by (*tcb).sched_lock —
   held outer here and the lock that writer takes — not by the CPU locks.
3. Write tcb.state = Exited.
4. For each CPU in 0..cpu_count: scheduler_for(cpu).remove_from_queue(tcb, prio).
5. Server-side BlockedOnReply check: if (*tcb).reply_tcb is non-null,
   compare_exchange(bound, null, AcqRel, Acquire) to claim the binding, then
   set (*bound).wake_in_flight = 1 (pinning the client until the wake), then
   DEPOSIT only the resume disposition (park_disposition = INTERRUPTED for a
   syscall caller, or fault_outcome = Kill plus the episode stamp for a
   fault-blocked client) and leave the client BLOCKED. The client's
   state/ipc_state are NOT written here — only the gated enqueue_and_wake
   (step 10) writes them, under the CLIENT's own sched_lock, never under the
   server's locks (pre-setting state = Ready here was the #284 residual: a
   concurrent dealloc(client) marking the client Exited under its sched_lock
   raced the unsynchronised Ready write). The wake's target CPU is NOT computed
   here either; it is recomputed at the wake site (step 10). The actual
   enqueue_and_wake happens in step 10, after step 7, because it would
   deadlock against the held scheduler.locks.
6. No in-region `current` snapshot is required: the post-release gate (step 8)
   scans every CPU unconditionally, so reclamation does not depend on an
   all-locks `running_on` reading (which names at most one CPU and can be stale
   the instant the locks drop).
7. Release every scheduler.lock in descending order, then (*tcb).sched_lock.
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
10. If a server_reply_wake was prepared in step 5:
      - Under the client's sched_lock, clear (*bound).blocked_on_object if it
        still names this server (the #317 predecessor-of-free null
        cancel_ipc_block's closure lemma relies on; it runs while
        wake_in_flight still pins bound).
      - Recompute the target CPU now via
        select_target_cpu_excluding(bound, Some(this_cpu)) — excluding THIS
        dealloc CPU, which stays inside this teardown (preempt-disabled through
        the wake-in-flight gate below) and so cannot dispatch a client linked
        onto it (#351) — then enqueue_and_wake(bound, target). Recomputing here
        rather than snapshotting in step 5 also closes the double-enqueue
        straddle: the placement reflects the client's state at link time, not
        two unbounded gate-spins earlier (#289).
11. Acquire the source IPC lock for tcb's blocked_on_object (if any) and unlink
    tcb from the source's wait queue / waiter slot. Branches:
      - BlockedOnSend / BlockedOnRecv: ep.lock; unlink_from_wait_queue.
      - BlockedOnNotification: sig.lock; clear waiter if it == tcb.
      - BlockedOnEventQueue: eq.lock; clear waiter if it == tcb.
      - BlockedOnWaitSet: ws.lock; clear waiter if it == tcb.
      - BlockedOnReply: blocked_on_object is the *server* TCB; mirror
                        cancel_ipc_block — under tcb's own sched_lock,
                        re-read blocked_on_object == server (the #317
                        closure lemma pins the server alive), then
                        compare_exchange (*server).reply_tcb from tcb to
                        null with AcqRel / Acquire so the server's next
                        endpoint_reply finds no caller and returns None; on
                        a win clear tcb.wake_in_flight (no reply wake will
                        fire).
      - BlockedOnFault: blocked_on_object is the *handler* (server) TCB;
                        identical to BlockedOnReply — compare_exchange
                        (*handler).reply_tcb from tcb to null so a later
                        fault reply does not target this freed faulter. The
                        faulter never resumes, so no fault_outcome is recorded.
      - None: no source-side cleanup needed.
12. Clear tcb.blocked_on_object = null.
13. Release tcb's fault-handler binding, if any: atomically swap
    tcb.fault_handler to null and dec_ref the prior EndpointObject; if its
    refcount reaches 0, enqueue the orphaned endpoint header on the cascade
    worklist (step 20's mechanism) rather than recursing into dealloc_object.
    Done after the step-11 unlink so the endpoint dealloc cannot observe this
    thread still on its send queue.
14. sleep_list_remove(tcb) (outside the all-locks region). A timer that already
    popped a plain-sleep (None) entry set wake_in_flight = 1 at pop. A timed
    notification or event-queue entry's arm claims, and sets the flag, only
    under the source lock, so it either claimed before step 11's unlink or
    finds the waiter cleared and skips. The #443 stale entry's endpoint and
    wait-set snapshots carry no pin; see the Plain-Sleep Path below.
15. Wake-in-flight gate (#160): spin until tcb.wake_in_flight.load(Acquire) == 0,
    with preempt_disable and interrupts enabled as in the context_saved gate,
    so a waker's pending enqueue_and_wake (or a cancel/dealloc CAS win that
    clears the flag) completes before the free; a thread displaced from a
    server's reply binding never has the flag cleared (#443).
16. (x86_64 only) Release IOPB if bound.
17. thread_registry::unregister(tcb).
18. Poison: tcb.magic = 0; tcb.priority = 0xFF.
19. drop_in_place(tcb).
20. retype_free + ancestor dec_ref + cascade (the worklist driven by
    dealloc_object; step 13's orphaned endpoint, if any, is processed here).
```

### Self-teardown (the caller is the freed thread)

Steps 8-9 assume the dealloc caller is a *different* thread than `tcb`: the
`current`-anywhere scan waits for whichever CPU runs `tcb` to switch away. When
the caller **is** `tcb` — a thread that deletes the last capability to its own
`Thread` object via `SYS_CAP_REVOKE` (`SYS_CAP_DELETE` refuses a self thread-cap delete with
`InvalidState` before the dec-ref), or whose own object a batched move queued for deferred
reclaim (`cap::transfer::release_moved_object`) — the running CPU's
`current == tcb` can never clear from within the scan (the spin holds preemption
disabled, so the thread never reschedules). Running steps 8-20 inline would wedge
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
  self check is false and the full protocol (steps 1-20) runs: steps 1-4 re-commit the
  already-set `Exited` harmlessly, step 8's scan finds no CPU
  running `tcb` on the first pass and step 9's `context_saved` gate is already
  satisfied. Any server-side reply-bound client (steps 5/10/11) is woken here.

The same stack carries `CSpace` and `AddressSpace` objects whose teardown
found the running thread itself stopped (see
[scheduling-internals.md § Thread Registry](scheduling-internals.md#thread-registry)); the drain
re-enters their arms the same way.

The stack also receives `Thread`, `CSpace`, and `AddressSpace` objects whose last reference a
batched capability move dropped (`cap::transfer::release_moved_object`), pushed from a live
thread that may itself be the queued thread or bound to the queued object. The drain runs only
from a live thread's syscall return or the idle thread, so it is never one of the self-teardown's
dead threads; a draining thread that is the queued `Thread` (or bound to a queued object) is
caught by the arm's self net, which marks it `Exited`, re-queues the object, and returns, so the
drain never re-enters the wedge it exists to avoid.

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
   it never reaches `schedule()` from within the spin, so steps 8-20 are skipped inline and deferred
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

6. **Step 11's source-IPC unlink MUST acquire the source's lock for every lock-guarded variant**
   (`ep.lock`, `sig.lock`, `eq.lock`, `ws.lock`); the `BlockedOnReply` / `BlockedOnFault` arms
   instead hold the dying client's `sched_lock` across the `blocked_on_object` re-read and the
   `reply_tcb` CAS, exactly as `cancel_ipc_block` does. This is the
   symmetry rule with `cancel_ipc_block`: both clear IPC-blocking field-group writes from a
   non-owning CPU and MUST hold the matching source lock.

7. **Step 11 BlockedOnReply / BlockedOnFault.** The client's (or faulter's) `blocked_on_object` is
   the *server* / *handler* TCB pointer (the lifetime owner of `reply_tcb`). The dealloc'd thread
   must claim its own slot via `compare_exchange(self, null, AcqRel, Acquire)` before freeing —
   otherwise a later `endpoint_reply` / fault reply on the still-live server would load the freed
   pointer and UAF on the message-copy write. `BlockedOnFault` is handled identically (it reuses
   `reply_tcb`). Every claim outside `ep.lock` MUST use compare_exchange (never an unconditional
   store) so a concurrent cancel cannot lose a peer client's binding; the one exception is the
   slot-owning server's `SYS_IPC_REPLY` failure-path `swap(null)`, per the Symmetry rule in
   [BlockedOnReply Edge — Symmetry Rules](#blockedonreply-edge--symmetry-rules).

8. **Step 13 fault-handler binding release.** A thread that *holds* a fault-handler binding
   (independent of whether it is itself fault-blocked) owns one `inc_ref` on its `fault_handler`
   EndpointObject. The drain swaps the field to null and dec_refs; if the endpoint's refcount
   reaches 0 it is enqueued on the cascade worklist (step 20), not freed by a nested
   `dealloc_object` call — the function's worklist mechanism exists precisely to keep the cascade
   non-recursive. Ordering after step 11 ensures a queued faulter is off the endpoint's send queue
   before the endpoint can be torn down.

9. **Step 18's poison precedes step 19's drop.** `magic = 0` and `priority = 0xFF` are the
   use-after-free traps — any later code that reads these fields and dereferences will fail loudly
   via the `debug_assert!((*tcb).magic == TCB_MAGIC, ...)` checks in the scheduler. Step 19 calls
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

1. **Caller in `endpoint_call`** — sets the dequeued server's `reply_tcb = caller` under `ep.lock`
   by an unconditional Release `store` that overwrites any binding still pending (see the Symmetry
   rule; #443). If the caller's park commit is refused (a concurrent stop or exit, or a coalesced
   wake), `rollback_uncommitted_call` rolls the binding back under the same `ep.lock` —
   `compare_exchange(caller, null)` on `reply_tcb`; on a win it stamps a cancelled deposit
   (INTERRUPTED, or KILL for a faulter) and clears `wake_in_flight`.
2. **Server in `endpoint_recv`** — dequeues a `BlockedOnSend` caller and rebinds it to
   `reply_tcb = caller` under `ep.lock` by the same unconditional store, then commits the caller's
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
   observing `blocked_on_object == server` under the lock pins the server alive for the CAS (the
   CLOSURE LEMMA of
   [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership)).
5. **Client dealloc via `dealloc_object(Thread)`** —
   `compare_exchange(this_client, null, AcqRel, Acquire)` in the BlockedOnReply branch of the
   source-IPC unlink walk. Mirrors `cancel_ipc_block`'s discipline.
6. **Server dealloc via `dealloc_object(Thread)`** — under all-CPU scheduler.locks, reads
   `(*server).reply_tcb`; if non-null, `compare_exchange(bound, null, AcqRel, Acquire)` to claim the
   binding, then prepares the bound client for wake and schedules an `enqueue_and_wake` for after
   the all-locks region releases. For a `BlockedOnReply` client it stamps the park episode
   `INTERRUPTED` (per the episode table in
   [ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes)); for a `BlockedOnFault`
   client (handler-thread death) it instead records
   `fault_outcome = Kill` (read on entry to the branch, before `ipc_state` is cleared) so the
   faulter runs its kill path on resume. Without this, a client blocked on a dying server/handler
   would remain blocked indefinitely with a dangling `blocked_on_object` pointer to freed memory.
7. **Timer defensive arm in `sleep_check_wakeups`** — for `BlockedOnReply` / `BlockedOnFault`
   entries (never on the sleep list today, per Sleep List Invariant 6, except through the stale
   plain-sleep entry ([#443](https://github.com/kottlerg/seraph/issues/443); see
   [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path))),
   `compare_exchange(this_client, null, AcqRel, Acquire)`; on a `BlockedOnFault` win it records
   `fault_outcome = Kill`. Defensive — forecloses a future timeout surface racing a reply/cancel
   — except through the stale plain-sleep entry
   ([#443](https://github.com/kottlerg/seraph/issues/443); see
   [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path)),
   which reaches this CAS without actor 4's client-`sched_lock` re-read of `blocked_on_object`.
8. **Server on the `SYS_IPC_REPLY` failure path via `fail_reply_and_wake_caller`** —
   `swap(null, AcqRel)` with no lock held. A non-null result is the episode claim: it deposits a
   synthetic `IPC_REPLY_TRANSFER_FAILED` reply and wakes the caller. A null result means no caller
   is bound: none was published, or another claimant already won.

**Symmetry rule:** every actor that may invalidate a client's place in the reply slot MUST claim it
by an atomic read-modify-write that observes the bound client (never an unconditional store) so
concurrent actors can determine whether they got there first. Actors 3 through 7 and the
commit-failure rollbacks of actors 1 and 2 use `compare_exchange(this_client, null, ...)`. Actor 8
uses `swap(null)`: only the slot-owning server performs it, while it is running `SYS_IPC_REPLY`,
and no publisher can install a different caller during that syscall (`endpoint_call` binds only a
server it dequeued from a receive queue, and `endpoint_recv` runs only on the server itself), so a
non-null result is as exclusive a claim as a won CAS. The publish stores of actors 1 and 2 violate
this rule: they are unconditional, so when the server receives again while a reply is still
pending they overwrite the binding, and the displaced caller or faulter is outside the guarantees
of this document ([ipc-design.md](../../../docs/ipc-design.md) § The Call/Reply Model,
[#443](https://github.com/kottlerg/seraph/issues/443)). Among the reply-slot actors, the
`fault_outcome` writer is whichever actor wins this claim. The exception is `cancel_ipc_block`'s
`BlockedOnSend` arm, which stores `fault_outcome = Kill` for a send-queued faulter without a
claim. When `endpoint_recv` rebinds that faulter after the cancel's snapshot, that store races the
handler's fault-reply store ([#443](https://github.com/kottlerg/seraph/issues/443)).

**Invariants on the BlockedOnReply protocol:**

1. The client's `blocked_on_object` is the server TCB pointer (NOT an endpoint or other source).
2. The server is the lifetime owner of the reply slot. As long as the server is alive,
   `endpoint_call` and `endpoint_recv` publish the slot under `ep.lock`. Their commit-failure
   rollback is itself a `compare_exchange(caller, null)` claim taken under `ep.lock`; every other
   claim (`endpoint_reply`, cancel, dealloc, the timer arm, and the failure-path `swap(null)`) is
   taken outside it. `endpoint_reply` takes no lock and claims by CAS; cancel and dealloc paths
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
   freed (`core/kernel/src/syscall/ipc.rs` magic assert), double-enqueue if reused-and-queued (the
   slot is woken twice — closed structurally by the `queued_on` single-link tag at the enqueue
   chokepoint; see
   [scheduling-internals.md § ThreadState Transitions](scheduling-internals.md#threadstate-transitions)
   (Enqueue-chokepoint enforcement)), or TCB-field corruption if reused-and-running (the residual
   #284 `#GP` / corrupt `iopb`). On a failed commit `endpoint_recv` rolls the binding back and
   skips the dead sender.

---

## Atomic Ordering for Sleep List and Lifecycle

This section lists ordering invariants specific to the sleep-list + lifecycle surface. Atomic
invariants common with the global wake protocol (`RESCHEDULE_PENDING`, `non_empty`, `context_saved`,
`BOOT_TRANSIENT_ACTIVE`) are NOT restated; see
[scheduling-internals.md § Atomic Ordering Invariants](scheduling-internals.md#atomic-ordering-invariants).

| Atomic / field | Set ordering | Read ordering | Pairing rationale |
|---|---|---|---|
| `tcb.timed_out` (bool, plain field) | non-atomic store under `eq.lock` (timer `BlockedOnEventQueue` arm); under no lock in the defensive timer `BlockedOnReply` arm (unreachable today: no reply waiter is on the sleep list, except through the stale plain-sleep entry ([#443](https://github.com/kottlerg/seraph/issues/443); see [`sys_thread_sleep` and the Plain-Sleep Path](#sys_thread_sleep-and-the-plain-sleep-path))); cleared by the resuming syscall | non-atomic load by resuming syscall on the same CPU | Single-writer per park (eq.lock excludes any concurrent payload-delivery write); reader is local CPU after `schedule()` returns. No atomic required because the source IPC lock provides mutual exclusion at the write side and the `Blocked → Ready` commit, which `enqueue_and_wake` makes under the waiter's `sched_lock` and the run-queue lock after `eq.lock` is released, provides the happens-before edge to the reader through the run-queue Release / dispatch Acquire pairing. |
| `tcb.sleep_deadline` (u64, plain field) | non-atomic store under source IPC lock (when waker clears) OR, by a timed IPC registrant (`sys_notification_wait`, `sys_event_recv`), under its source lock (`sig.lock` / `eq.lock`) for both the set before `sleep_list_add` and the clear on the capacity fallback OR, by `sys_thread_sleep`, under no lock for the set before its park commit and for the clear on a `RefusedWake` / `RefusedStop` refusal, and under `(*tcb).sched_lock` for the clear in the capacity rollback OR, when the timer claims, after `SLEEP_LIST_LOCK` is released (under the source lock in the notification and event-queue arms, under no lock in the reply, fault and plain arms) OR under no lock by `cancel_ipc_block` after `sleep_list_remove` | non-atomic load under `SLEEP_LIST_LOCK` (timer snapshot pass) | The deadline read by `sleep_check_wakeups` under `SLEEP_LIST_LOCK` is the load-bearing observation; later state mutations follow the snapshot-then-claim arbitration. Every clear writes 0, so concurrent clears are benign. The registrant's set is single-writer, because it precedes `sleep_list_add`. |
| `tcb.state` (enum, plain field) | non-atomic store, always under the TCB's own `(*tcb).sched_lock`: alone in `commit_blocked_under_local_lock`, `enqueue_and_wake`, `enqueue_ready_thread`, `schedule()`'s requeue and dispatch flips, and the `sys_thread_sleep` capacity rollback; held outer of every CPU's scheduler.lock in `set_state_under_all_locks` / `exit_under_all_locks` | under `(*tcb).sched_lock` (dispatch flip, commits, wakes); `schedule()`'s dequeue skip-loop and `sys_thread_stop`'s drain spin confirm `Stopped`/`Exited` under a CPU's run-queue lock | The state field is in the Scheduling field group per [scheduling-internals.md § Cross-CPU TCB Ownership](scheduling-internals.md#cross-cpu-tcb-ownership). `(*tcb).sched_lock` serializes every store. The additional all-CPU-locks hold on `Stopped`/`Exited` writes is what makes those states visible to every CPU's run-queue-locked skip check. |
| `tcb.priority` (u8, plain field) | non-atomic store by `sys_thread_set_priority` under `(*tcb).sched_lock` | non-atomic loads, each under the TCB's own `(*tcb).sched_lock`: `dealloc_object(Thread)` and `set_state_under_all_locks` (sched_lock held outer of their all-locks region), `migrate_ready_thread`, `enqueue_and_wake`, `enqueue_ready_thread`, and `schedule()`'s requeue arm | `(*tcb).sched_lock` is the serializer: every writer and every functional reader of this field holds it; only `watchdog_dump`'s diagnostic reads race it, benignly. `schedule()`'s dispatch path deliberately does NOT read `(*next).priority` (it would race the store without `next.sched_lock`); it dispatches by run-queue index, which `dequeue_highest` already validated. After the store, `sys_thread_set_priority` relocates the Ready TCB's queue entry to the new priority (`relocate_ready_priority`, under the run-queue lock); the brief link-at-old / `priority`-new window inside the `sched_lock` region is benign because consumers dispatch by queue index, not by this field. |
| `tcb.reply_tcb` (`AtomicPtr<TCB>`) | Release on the `endpoint_call` / `endpoint_recv` publish store under ep.lock (unconditional; it overwrites a pending binding, #443); AcqRel on `compare_exchange` from the commit-failure rollback (under ep.lock) and from `endpoint_reply`, cancel, client-dealloc, server-dealloc, and timer paths (no ep.lock); AcqRel on `fail_reply_and_wake_caller`'s `swap` (no lock) | Acquire on `endpoint_reply`'s pre-CAS load (no lock); Acquire on the server-dealloc snapshot under all sched.locks; Acquire on `sys_ipc_reply`'s fault-reply and cap-pre-allocation peeks (no lock), which read before any claim and dereference the loaded caller unpinned (#443); Relaxed on the softlockup watchdog's diagnostic load (`watchdog_decode_blocked_on`) | Every claim is an atomic read-modify-write that observes the bound client. The `compare_exchange` clears the slot only when it still references the claimant's expected TCB, so two concurrent claimants cannot clear a third unrelated client's binding; the `swap` is safe because only the slot-owning server performs it, while no publisher can install a different caller during `SYS_IPC_REPLY` (per the Symmetry rule). The publish is a plain store, not a claim: a server that receives again while a reply is pending overwrites the binding and strands the displaced caller, in violation of the Symmetry rule (#443). The Release publish pairs with each claimant's Acquire. |

---

## `sys_thread_sleep` and the Plain-Sleep Path

`sys_thread_sleep` is the simplest sleeper: no IPC source, only the timer. Sequence:

```
1. If ms == 0 return Ok(0); compute deadline.
2. open_park_episode(tcb); (*tcb).sleep_deadline = deadline.
3. commit_blocked_under_local_lock(tcb, None, null) under (*tcb).sched_lock:
   - RefusedWake: clear sleep_deadline; return Ok(0).
   - RefusedStop: clear sleep_deadline; schedule(false); return Interrupted.
4. sleep_list_add(tcb); on Err (list full) restore Blocked -> Running and
   clear sleep_deadline under sched_lock; return OutOfMemory.
5. schedule(false).
6. On resume: the timer's "_ => { plain sleep }" arm cleared sleep_deadline
   and its enqueue_and_wake set Ready; consume_park_interrupted returns
   Interrupted on a cancel, else Ok(0).
```

Step 6's disposition is the park episode's, per
[ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes) § Park Dispositions and
Episodes.

**Invariants:**

1. `ipc_state == None` is the discriminator that selects the plain-sleep arm in
   `sleep_check_wakeups`. The plain arm claims unconditionally because no IPC source is competing,
   except through the stale plain-sleep entry
   ([#443](https://github.com/kottlerg/seraph/issues/443); see invariant 3).
2. The plain sleep needs no source-lock arbitration. The timer's pop of the entry under
   `SLEEP_LIST_LOCK` is the only wake claim. `cancel_ipc_block`'s `sleep_list_remove` takes the
   same lock, but nothing orders it against the sleeper's `sleep_list_add`: a remove that runs
   first finds no entry and does not stop the later add (invariant 3). The cancel's
   `INTERRUPTED` stamp is not gated on that removal.
3. The cancel path: `sys_thread_stop` on a sleeper runs `cancel_ipc_block`, whose
   `IpcThreadState::None` arm does no source-lock work; the function then removes the TCB from the
   sleep list (before clearing `sleep_deadline` — the #117 order) and stamps the park episode
   `INTERRUPTED` so the restarted sleeper returns `Interrupted` instead of reporting the truncated
   sleep as success. The stamp is NOT gated on the remove win (the plain-sleep cleanup row of
   [ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes) § Park Dispositions and
   Episodes): a plain sleeper has no competing depositor (the timer's claim deposits nothing), and
   a cancel landing between the commit and `sleep_list_add` finds no entry to remove yet must
   still cancel the park — that window is reachable in practice under TCG host-descheduling. In
   that window the sleeper's `sleep_list_add` runs after the cancel and inserts an entry with
   `sleep_deadline == 0` for a thread the stop then commits `Stopped`, against Sleep List
   invariants 2 and 3 ([#443](https://github.com/kottlerg/seraph/issues/443)). A later BSP tick
   pops that entry, at the first tick at which the TCB's `sleep_deadline` is 0 or has expired.
   While the thread is still `Stopped`, the plain arm claims it and `enqueue_and_wake` coalesces
   the claim. Once the thread has restarted, any `sleep_check_wakeups` arm may act on whatever
   park or run state the thread is in by then, through whichever arm the snapshotted `ipc_state`
   selects: among other effects, a spurious or premature wake, an `Interrupted` return, a kill, or
   a recorded `wake_pending` on a `Running` thread that delivers no payload. A thread still
   `Running` at the pop takes the plain arm, whose `enqueue_and_wake` records `wake_pending`; that
   refuses the thread's next park unless a `schedule()` pass clears it first. A `Ready` thread
   coalesces the claim silently. An endpoint or wait-set snapshot (`BlockedOnSend`,
   `BlockedOnRecv`, `BlockedOnWaitSet`) falls through to the default arm with no pop-time
   `wake_in_flight` pin, so its unconditional claim races both the source's waker and
   `dealloc_object(Thread)`. A reply or fault snapshot reaches the `reply_tcb` CAS of Symmetry
   actor 7 without the closure-lemma gate, so a server freed between the pop and the CAS is
   dereferenced after free. A restarted thread that parks again with a timeout adds a second
   entry beside the stale one; a `dealloc_object(Thread)` while both are listed removes only one
   through its single `sleep_list_remove`, so a later pop of the other dereferences the freed TCB.
   #443 records the arm-by-arm effects and the use-after-free windows, this duplicate-entry window
   among them. A timer claim racing the cancel resolves to `Interrupted`
   (honest for a sleep whose deadline elapsed concurrently with a stop). A stop that instead wins
   against the park commit (`ParkCommit::RefusedStop`) makes `sys_thread_sleep` deschedule in
   place and return `Interrupted` directly.

---

## `sys_thread_stop` Cross-CPU Stop Protocol

`sys_thread_stop` MUST commit the target's `Stopped` state under every CPU's scheduler.lock so a
concurrent `schedule()` on the remote CPU cannot read `state != Stopped` and re-enqueue the target.
The handler then drains the target.

**Protocol (`core/kernel/src/syscall/thread.rs::sys_thread_stop`):**

1. Resolve the target Thread cap; reject `Created`, `Exited`, `Stopped` with `InvalidState`.
2. If `state == Blocked`, call `cancel_ipc_block(target)` — acquires the source IPC lock matching
   `tcb.ipc_state`, unlinks the waiter, and on the claim win stamps the park episode `INTERRUPTED`
   (fault episodes: `fault_outcome = Kill`, written unconditionally for a send-queued faulter,
   [#443](https://github.com/kottlerg/seraph/issues/443); see
   [ipc-internals.md](ipc-internals.md#park-dispositions-and-episodes) § Park Dispositions and
   Episodes) so the restarted thread's resume reports the cancellation.
3. `set_state_under_all_locks(target, Stopped)` — acquires the target's `(*tcb).sched_lock` and
   then every CPU's scheduler.lock in ascending order, writes `state = Stopped`, removes the target
   from every CPU's run queue, snapshots `running_on` (the CPU whose
   `sched.current == target_tcb`, if any), releases all locks. Returns `StateCommit`:
   `Committed(running_on)` on a write, or `RefusedExited` when the target exited between step 1's
   unlocked check and the locked commit; `commit_stopped` surfaces the refusal as `InvalidState`
   (table row `sys_thread_stop (Created or Exited or Stopped)`).
4. **Self-stop fast path.** If the target is the calling thread, call `schedule(false)` immediately.
   `schedule()`'s requeue arm never re-enqueues a `Stopped` current thread.
5. **Cross-CPU drain.** If `running_on = Some(run_cpu)` and `run_cpu != current_cpu`:
   - `prod_remote_cpu(run_cpu)` — sends a wakeup IPI. The IPI interrupts the remote CPU, but its
     handler only acknowledges it and does not call `schedule()`, so the target keeps running
     until that CPU's next `schedule()` entry: slice expiry (up to `TIME_SLICE_TICKS` ticks), a
     `SYS_THREAD_YIELD`, a park whose commit returns `ParkCommit::RefusedStop`, or an exit
     (`sys_exit`, `sys_process_exit`, or a terminal fault). The syscall epilogue does not
     deschedule a `Stopped` thread (`running_thread_stopped` tests `Exited` only). The drain
     spin's latency is therefore bounded by one time slice.
   - Bounded spin until `sched_remote.current != target_tcb` **or** the target is no longer
     `Stopped`. The remote CPU's `schedule()` declines to requeue the `Stopped` target (requeue
     denylist) and switches to either the next ready thread or its idle TCB; once that switch
     completes, the spin exits. The state re-check (read under `sched_remote.lock`, alongside
     `current`) is load-bearing: a concurrent `sys_thread_start` may resume the target out of
     `Stopped` (last-writer-wins), moving it off `schedule()`'s requeue denylist and re-dispatching
     it onto its pinned CPU, where a sole runnable spinner never leaves `current`. Without the
     re-check the drain would spin forever — two CONTROL-cap holders racing stop/start could wedge a
     CPU. On that bail the stop has been overtaken; the target is left `Ready`/`Running` by the
     winning start.

**Invariants:**

1. The drain spin's exit condition in step 5 is what guarantees `sys_thread_read_regs` sees a
   fresh `trap_frame`: the remote CPU can deschedule the target only through a kernel entry (a
   timer tick at slice expiry, or a syscall or fault entry that yields, parks, or exits) and a
   `schedule()`, and that entry rewrites the frame. The IPI is a nudge, not a correctness
   requirement; after its acknowledgement the target resumes the interrupted code.
2. For Ready targets on a remote run queue, no IPI is needed: the all-locks `Stopped` commit
   unlinks the TCB from every CPU's run queue.
3. The bounded spin in step 5 holds NO lock; it acquires `sched_remote.lock` briefly per iteration
   to read `current` and the target's `state` (the latter coherent because
   `set_state_under_all_locks` writes `state` under every CPU lock, including this one), then
   releases. The syscall enters with interrupts disabled, so the spin runs under `preempt_disable`
   with interrupts re-enabled (`save_and_disable_interrupts` → `enable`, restored afterwards) — the
   discipline of drain-protocol steps 8-9: spinning with interrupts disabled would block an
   inbound TLB-shootdown IPI targeted at this CPU and deadlock it. The spin terminates as soon as
   the remote deschedules the target or a concurrent `sys_thread_start` resumes it.

---

## Summarized By

[IPC Subsystem Internals](ipc-internals.md),
[SMP Scheduler/IPC Hotpath Redesign — per-TCB `sched_lock` (authoritative serializer)](sched-ipc-redesign.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md)
