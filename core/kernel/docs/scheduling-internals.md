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
       source IPC lock                derivation tree lock
   (sig.lock | ep.lock |    (outer)   (cap revocation;
    eq.lock | ws.lock)                 see capability-internals.md)
        │         │
        │         └─────► SLEEP_LIST_LOCK   (leaf; held alone, or under a
        │                                    source lock — source.lock →
        │                                    SLEEP_LIST_LOCK is the only edge)
        │
        │                 THREAD_REGISTRY_LOCK (leaf; held strictly alone — never
        │                                    under any other lock. Diagnostic-only
        │                                    live-thread list; see § Thread Registry)
        ▼
   (*tcb).sched_lock                         (per-TCB Scheduling-group serializer)
        │
        ▼
   per-CPU scheduler.lock                    (inner; run-queue list structure only)
```

**Acquisition rules (MUST):**

1. **The source IPC lock is outermost on the IPC-blocking path; `(*tcb).sched_lock` sits beneath it and above the per-CPU scheduler.lock.** Every IPC syscall handler (`sys_endpoint_call`, `sys_notification_wait`, `sys_event_recv`, `sys_wait_set_wait`, etc.) acquires the relevant source lock (`sig.lock` | `ep.lock` | `eq.lock` | `ws.lock`) first; the park-commit then acquires the parking thread's `(*tcb).sched_lock` (via `commit_blocked_under_local_lock`), and the run-queue link acquires the per-CPU scheduler.lock under that. `(*tcb).sched_lock` is the single authoritative serializer of the TCB's Scheduling field group (`{state, ipc_state, queued_on, run_queue_next, preferred_cpu, blocked_on_object, wake_pending}`), keyed on the TCB pointer rather than on whichever CPU's queue currently links it. The per-CPU scheduler.lock no longer guards any TCB's `state`; it guards only that CPU's run-queue list structure (head/tail/`non_empty`/load). See § Cross-CPU TCB Ownership.

2. **At most one source IPC lock at a time.** A code path holding `sig.lock` MUST NOT acquire `ep.lock`, `eq.lock`, or `ws.lock`. The single exception is `waitset_notify`, which is invoked from within a source lock (the source notifying the wait set) and acquires `ws.lock` as the inner lock — order `source.lock → ws.lock` only.

3. **`SLEEP_LIST_LOCK` is leaf-only.** It MAY be acquired from inside any source IPC lock. It MUST NOT contain calls that re-enter IPC or scheduler code while held.

3a. **`THREAD_REGISTRY_LOCK` is strict-leaf-only.** The diagnostic live-thread registry (`core/kernel/src/sched/thread_registry.rs`) is linked at thread construction and unlinked at dealloc, both with `THREAD_REGISTRY_LOCK` held strictly alone — never nested under a source IPC lock, `(*tcb).sched_lock`, or a run-queue lock — so it adds no lock-order edge. The softlockup watchdog walks it via `try_for_each` (a non-blocking `try_lock`, so a contended or CPU-died lock degrades to a skipped section rather than a hang). See § Thread Registry.

4. **Per-TCB-then-cross-CPU acquisition rule.** A path mutating a TCB's Scheduling field group MUST acquire `(*tcb).sched_lock` FIRST (outermost among the scheduler locks), THEN any per-CPU scheduler.lock(s); when two or more per-CPU scheduler.locks are needed simultaneously, they MUST be taken in ascending-CPU order. Live production sites: `sched::migrate_ready_thread` (used by `sys_thread_set_affinity` active migration and the periodic load balancer; `(*tcb).sched_lock` then the two CPU locks ascending), `dealloc_object(Thread)` (`(*tcb).sched_lock` then the all-CPU walk in ascending order), `sched::set_state_under_all_locks` (lifecycle state writes; same shape), and `sys_thread_set_priority` (priority writes plus locate-and-relocate of the Ready TCB's queue entry; `(*tcb).sched_lock` then the all-CPU walk in ascending order). A path MUST NEVER hold two different TCBs' `sched_lock`s at once — `schedule()`'s outgoing-then-incoming flip releases `current.sched_lock` before acquiring `next.sched_lock`.

5. **`enqueue_and_wake` / `enqueue_ready_thread` acquire `(*tcb).sched_lock` then the target CPU's scheduler.lock.** They MAY be called WITH the source IPC lock still held OR after releasing it, because `source → (*tcb).sched_lock → run-queue lock` is exactly the hierarchy — there is no `source.lock → scheduler.lock` edge to violate. The single-waiter wakers (`notification_send`, `event_queue_post`, `endpoint_call`'s server-wake branch, `endpoint_reply`, and the `event_queue_drop` / `notification_dealloc` single-waiter dealloc wakes) snapshot the payload and set `wake_in_flight` under the source lock, RELEASE the source lock, then call `enqueue_and_wake` — releasing first bounds source-lock hold-time. Between that source-lock claim (waiter slot cleared, payload deposited, `wake_in_flight = 1`) and the waker's post-unlock `enqueue_and_wake`, the wake is half-complete and owned exclusively by the in-flight waker: code executing *as the claimed thread* in that window (it is still live, mid-park) has exactly one legal continuation — fall through to `schedule()`. Consuming the deposited payload and returning to user mode is forbidden; it strands the waker's run-queue link (#352). The `still_waiter` rechecks (the sleep-list arming in `sys_event_recv` / `sys_notification_wait`) respect this: they only add a timer on the not-claimed branch and fall through to `schedule()` on both branches. The `endpoint_dealloc` send/recv drain instead HOLDS `ep.lock` across the per-waiter `enqueue_and_wake` walk (a multi-waiter drain; sound precisely because the order is canonical, and `wake_in_flight = 1` per waiter blocks a racing `dealloc(waiter)` unlink from freeing a TCB mid-wake). `enqueue_and_wake` dispatches its wakeup IPI only after BOTH the run-queue lock and `(*tcb).sched_lock` are released (never IPI under `sched_lock`). `pull_unpinned_ready` is the one site that takes `(*tcb).sched_lock` via `try_lock_raw` while already holding a run-queue lock — the inverse of the canonical order; the `try` backs off on contention (a canonical holder makes it fail), so it is deadlock-free, and the source CPU's run-queue lock pins the candidate so the pointer cannot be freed under it. Its two run-queue locks are themselves `try_lock_raw` (ascending order retained): the pull runs from every CPU's tick with interrupts disabled, and blocking there lets every idle CPU queue on one victim's lock — the FIFO ticket convoy that livelocked the guest system-wide under vCPU oversubscription (#375). The wait-set cascade rule is unchanged in spirit: `wait_set_drop` releases its source/ws locks before reporting any zero-refcount source back to `dealloc_object_one`'s cascade worklist, so the source's own dealloc runs after every IPC source/ws lock has been released.

6. **Derivation tree lock is ordered after IPC object locks.** `SYS_CAP_REVOKE` MUST NOT acquire IPC object locks while holding the derivation tree write lock — see [capability-internals.md](capability-internals.md) for the deferred-cleanup pattern.

7. **`cancel_ipc_block` MUST acquire the source lock matching `tcb.ipc_state`.** It first snapshots `(state, ipc_state, blocked_on_object)` under `(*tcb).sched_lock` (the authoritative serializer; a bare read would race `enqueue_and_wake` / `commit_blocked` and observe a torn binding) and returns early if the thread is no longer `Blocked` — a concurrent waker won, so there is nothing to cancel. `sched_lock` is released BEFORE the source lock is taken (lock order is source IPC → `sched_lock`, so the two are never nested). Every read or write of `source.waiter` (or the equivalent intrusive-queue field) then requires the matching source lock; reads from non-owning CPUs without it are races. The dealloc paths in `core/kernel/src/cap/object.rs` (Endpoint, Notification, EventQueue, WaitSet, and Thread arms) follow the same source-lock rule. **The `BlockedOnReply`/`BlockedOnFault` reply binding is the exception with no source lock: its `server.reply_tcb` CAS dereferences the *server* TCB, which a concurrent `dealloc_object(Thread)` on the server could free (#317).** That CAS is instead performed under the *client's* `(*tcb).sched_lock`, gated by a `(*tcb).blocked_on_object == server` re-read — by `cancel_ipc_block` and by the two `dealloc_object(Thread)` client-side reply/fault arms alike. `dealloc_object(Thread)` on the *server* nulls a claimed client's `blocked_on_object` under that same client `sched_lock` strictly before `retype_free`. By the CLOSURE LEMMA (§ Cross-CPU TCB Ownership, Reply slot) observing `blocked_on == server` under the client lock proves the server is not yet freed, so the CAS dereferences live memory. Each site holds exactly one TCB's `sched_lock` and runs a wait-free CAS on the other TCB, preserving the never-two-`sched_lock`s rule.

8. **Blocking commit MUST go through `commit_blocked_under_local_lock`.** A primitive that parks the calling thread (`notification_wait`, `event_queue_recv`, `endpoint_call`, `waitset_wait`) MUST commit the `Running → Blocked` transition via `crate::sched::commit_blocked_under_local_lock(tcb, ipc_state, blocked_on)`. The helper acquires `(*tcb).sched_lock` (NOT the CPU lock), reads `state`, and writes `Blocked` only if `state ∈ {Running, Ready}` AND `wake_pending` is clear. It returns `false` — refusing to park — in two cases the caller handles identically: a concurrent `set_state_under_all_locks(Stopped|Exited)` already won (then `schedule()` drains the thread), or `wake_pending` is set (a waker raced ahead, found the thread still live, coalesced its link, and recorded the wake under `sched_lock`; the helper consumes the flag and leaves the thread `Running`, and `schedule()` requeues the runnable thread so it resumes and consumes the already-deposited payload). On `false` the caller MUST roll back the source-side waiter registration AND MUST NOT clobber any deposited `wakeup_value`/`ipc_msg`. `commit_reply_rebind_under_local_lock` is the sibling for `endpoint_recv`'s `BlockedOnSend → BlockedOnReply`/`BlockedOnFault` rebind of an already-`Blocked` send-queue-dequeued caller: it writes `ipc_state`/`blocked_on_object` under `(*tcb).sched_lock` (serialising the reply-binding publication with dealloc's `Exited` mark), returning `false` if a stop/exit already won, in which case `endpoint_recv` tears the binding down. Direct writes to `(*tcb).state = Blocked` from outside `sched_lock` are forbidden — they race the all-locks `Stopped` write in `sys_thread_stop` and silently clobber it. Lock order: source IPC lock (outer, held by the IPC primitive) → `(*tcb).sched_lock` (inner, acquired by the commit helper). After a successful commit, a caller whose source-side registration stands MUST reach `schedule()` before returning to user mode or attempting another commit: the wake deposited against the park is consumed only by a run-queue dequeue inside `schedule()`, and any other exit leaks the waker's link (`queued_on` tripwires in `commit_blocked_under_local_lock` and `PerCpuScheduler::enqueue` enforce this in debug builds; #352). The only sanctioned exception is a parker that un-commits under `sched_lock` while provably untargetable by any waker — `sys_thread_sleep`'s sleep-list-capacity rollback, which registered with no wake source. Non-blocking polls MUST NOT use the park path at all: `SYS_EVENT_RECV`'s `u64::MAX` try-once mode is `event_queue_try_recv`, a pure peek under `eq.lock` that takes no TCB and cannot register a waiter. For `sys_ipc_call`/fault park episodes, every deposit additionally carries a reply-disposition stamp consumed by the resume; see ipc-internals.md § Park Dispositions and Episodes.

9. **Wake commit MUST go through `enqueue_and_wake`.** Wake primitives MUST NOT write `(*tcb).state = Ready`, `ipc_state = None`, or `blocked_on_object = null` themselves under the source IPC lock; they snapshot the wakeup payload (`wakeup_value`, `timed_out`) under the source lock and delegate the state writes to `enqueue_and_wake`, which performs them under `(*tcb).sched_lock` → the target CPU's run-queue lock. The function reads `state` under `sched_lock` first and classifies: a `Blocked`/`Created` target is linked (`state=Ready`/`ipc_state=None`/`blocked_on_object=null` written, then enqueued); a `Running`/`Ready`/`Stopped`/`Exited` target is *coalesced* (not linked). `Running` additionally records `wake_pending` (the wake-before-park net rule 8 consumes); `Ready` is an already-linked same-event duplicate; `Stopped`/`Exited` mean a concurrent `dealloc_object(Thread)` or stop already won (preventing UAF / a re-introduced run-queue entry over a being-freed TCB). Every exit path clears the target's `wake_in_flight` so a waiting `dealloc_object(Thread)` can proceed. This rule applies equally to dealloc-time wake walks (`endpoint_dealloc` send/recv heads, `notification_dealloc` waiter, `event_queue_drop`, `wait_set_drop`). The DELIBERATE-placement sibling `enqueue_ready_thread` does NOT classify `state` — it unconditionally forces `→Ready` and links; it is used only where the caller owns the `→Ready` transition and has established the thread is not live on any CPU (`sys_thread_start` first-start/resume), since routing those through the gated `enqueue_and_wake` would coalesce their `Ready` target and strand it.

**Lock primitive.** All locks above are `crate::sync::Spinlock` (IRQ-disabling). Hold-time MUST be bounded (target ~10 µs on x86_64); no page-table walks, buddy allocations, IPC syscalls, or other long-latency operations under any spinlock.

---

## ThreadState Transitions

Thread lifecycle is `Created → Ready ↔ Running ↔ Blocked → Exited`, with `Stopped` as a terminal-pending sub-state of either `Running` or `Blocked`.

The transition table below pins every ThreadState write to a syscall/event, the CPU performing the write, and the canonical helper / locks held. Deviations from this table are bugs.

| From | To | Trigger | Performing CPU | Locks / canonical helper |
|---|---|---|---|---|
| (uninit) | `Created` | `sys_cap_create_thread` | calling CPU | none (TCB not yet visible) |
| `Created` | `Ready` | `sys_thread_start` (first start) | calling CPU | `set_state_under_all_locks(Ready)` then `enqueue_ready_thread(target_cpu)` (deliberate placer — NOT the gated `enqueue_and_wake`, which would coalesce a `Ready` target) |
| `Stopped` | `Ready` | `sys_thread_start` (resume from stop) | calling CPU | `set_state_under_all_locks(Ready)` then `enqueue_ready_thread(target_cpu)` |
| `Ready` | `Running` | `schedule()` selecting next | running CPU | `next.sched_lock` (the incoming dispatch flip; serialises with a concurrent `enqueue_and_wake(next)` which then coalesces) |
| `Running` | `Ready` | `schedule(requeue_current=true)` (yield, preempt) | running CPU | `current.sched_lock` (outer) → running CPU's scheduler.lock (inner); if `cpu_affinity` excludes the running CPU the requeue is linked directly on the target CPU under `current.sched_lock` + the target run-queue lock after dropping the local lock (inlined, not via `enqueue_and_wake`, to avoid re-acquiring `current.sched_lock`) |
| `Ready` (on CPU A) | `Ready` (on CPU B) | `sys_thread_set_affinity` (active migration) or periodic load balancer | calling CPU | `migrate_ready_thread(tcb, A, B)`; `(*tcb).sched_lock` (outer) then both scheduler.locks in ascending-CPU order (inner) |
| `Running` | `Blocked` | IPC blocking entry (`endpoint_call`, `notification_wait`, `event_queue_recv`, `waitset_wait`) | running CPU | `commit_blocked_under_local_lock(tcb, ipc, blocked_on)` (acquires `(*tcb).sched_lock`); on `false` (a stop/exit won, or `wake_pending` forced a refuse-to-park) the IPC primitive rolls back its waiter registration without clobbering the deposited payload. `endpoint_recv`'s dequeued sender rebinds via `commit_reply_rebind_under_local_lock` instead |
| `Blocked` | `Ready` | IPC wake (`notification_send`, `event_queue_post`, `endpoint_reply`, `endpoint_call` server-wake, `waitset_notify`) | wake-issuing CPU | source IPC lock to snapshot wakeup payload, *released*, then `enqueue_and_wake(target_cpu)` |
| `Blocked` | `Ready` | timeout from sleep list | timer-firing CPU | `SLEEP_LIST_LOCK` to drain expired entries (released first), then source IPC lock to arbitrate `(*src).waiter == tcb` and write the wake payload, then `enqueue_and_wake(target_cpu)` |
| `Blocked` | `Ready` | `cancel_ipc_block` (called from `sys_thread_stop` on a blocked target) | calling CPU | `(*tcb).sched_lock` to snapshot `(state, ipc_state, blocked_on_object)` and re-verify `Blocked` (released first), then the source IPC lock matching `tcb.ipc_state` to clear the binding |
| `Running` | `Blocked` (`BlockedOnFault`) | fault redirection — `ipc::fault::fault_dispatch` delivering a kernel-unresolvable fault to the thread's bound handler endpoint | running CPU (arch fault handler) | `commit_blocked_under_local_lock(tcb, BlockedOnFault, handler)`; kernel-synthesized, the faulter takes the caller role in the endpoint call/reply machinery |
| `Blocked` (`BlockedOnFault`) | `Ready` | fault reply (`sys_ipc_reply`) or cancellation (handler death via `server_reply_wake`, `cancel_ipc_block`, `dealloc_object(Thread)` unlink, endpoint-dealloc send-drain) | wake-issuing CPU | the wake-claim winner records `fault_outcome` (`Resume`/`Kill`) then `enqueue_and_wake(target_cpu)`; the faulter resumes inside `fault_dispatch` (re-executing its faulting instruction or running the kill path) rather than returning a syscall value |
| `Running` | `Stopped` | `sys_thread_stop` on running target | calling CPU | `set_state_under_all_locks(Stopped)`; if running on a remote CPU, `prod_remote_cpu(run_cpu)` and spin until `sched_remote.current != tcb` |
| `Ready` | `Stopped` | `sys_thread_stop` on a Ready target | calling CPU | `set_state_under_all_locks(Stopped)`; the helper also walks every CPU's run queue and calls `remove_from_queue` inside the all-locks region. See § *Stopped/Exited drain* below. |
| `Blocked` | `Stopped` | `sys_thread_stop` on blocked target | calling CPU | `cancel_ipc_block` first (acquires the source IPC lock and unlinks the waiter), then `set_state_under_all_locks(Stopped)` |
| `*` | `Exited` | `sys_thread_exit` (self) or fault handler | running CPU | `set_state_under_all_locks(Exited)` (on the dying CPU), then `schedule(false)` |
| `*` | `Exited` | `dealloc_object(Thread)` (refcount → 0) | calling CPU | acquires `(*tcb).sched_lock` (outer), then every CPU's scheduler.lock in ascending order, writes `Exited`, walks `remove_from_queue` for every CPU, releases all; then waits unconditionally for `sched.current != tcb` on *every* CPU *and* `tcb.context_saved == 1` (see Cross-CPU TCB Ownership) before freeing |

All `Running→Blocked` parks MUST route through `commit_blocked_under_local_lock` (or `commit_reply_rebind_under_local_lock` for `endpoint_recv`'s rebind); all `Blocked→Ready` *wakes* MUST route through `enqueue_and_wake`. The deliberate `→Ready` *placements* that the caller owns (the thread is provably not live) route through `enqueue_ready_thread` instead — currently only `sys_thread_start`. Direct `(*tcb).state` writes from an IPC primitive — under the source lock or otherwise — are forbidden; they race `set_state_under_all_locks(Stopped)` and silently clobber Stopped.

**Voluntary-block window — `schedule()` never requeues a `Blocked` `current` (issue #299).** Between a thread committing `Blocked` (`commit_blocked_under_local_lock` writes `Blocked` under `(*tcb).sched_lock`, then releases it) and reaching its own `schedule(false)`, interrupts are enabled and a timer tick can fire `schedule(true)` (`requeue_current = true`). The outgoing-requeue guard therefore excludes a `Blocked` `current` regardless of `requeue_current`: re-marking the parking thread `Ready` and enqueuing it would race the pending `enqueue_and_wake` (which links the same TCB on its `Blocked → Ready` wake) into a `queued_on` double-enqueue — in debug the `#244` enqueue tripwire panics under `scheduler.lock`, wedging that CPU. `cur_state` is read under `current.sched_lock` (held from the top of `schedule()`), so the `Blocked` observation is authoritative, not the racy `state` read a `timer_tick`-side guard would require. The parked thread is redispatched by its deposited wake (the resume-DEPOSIT model, Wake Protocol Invariants).

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
and produce two list entries for the same TCB. The skip loop in `schedule()`
(`sched/mod.rs`, the `dequeue_highest` Stopped/Exited skip) remains as
defence-in-depth and as the drain mechanism for legitimate paths that bypass
`set_state_under_all_locks` (none currently). The priority snapshot uses
`(*tcb).priority` read under `(*tcb).sched_lock` + all-CPU locks; this is
consistent with the matching reads in `dealloc_object(Thread)` and
`sys_thread_set_priority`, which all read/write the Scheduling field group
under the same `(*tcb).sched_lock`-outer / all-CPU-locks discipline.

**Priority change of a Ready TCB (issue #122).** `sys_thread_set_priority`
acquires `(*tcb).sched_lock` (outer), then writes `(*tcb).priority` and, when the
target is `Ready`, relocates its queue entry under every CPU's `scheduler.lock`
acquired in ascending order (inner). `sched_lock` is what makes the `state` read
race-free against `enqueue_and_wake` / `commit_blocked` / `schedule` — those all
write the Scheduling group under the same per-TCB lock. Identifying the home CPU
is itself a read of the Scheduling field group, so the syscall scans each
scheduler with `remove_from_queue(tcb, old_prio)` and re-enqueues on the same
scheduler at the new priority via `PerCpuScheduler::enqueue`. The
`sched_lock`-outer / all-locks region serialises this against
`migrate_ready_thread`, `dealloc_object(Thread)`, and
`set_state_under_all_locks`.

The "Ready ⇒ linked on exactly one queue" invariant has a transient
exception during any window where a caller publishes `state = Ready` on
a TCB but the matching link primitive has not yet acquired the
destination scheduler's lock. The known sites are:

- `schedule()`'s cross-CPU outgoing branch
  (`core/kernel/src/sched/mod.rs`), which writes `state = Ready` under
  `current.sched_lock`, releases the local run-queue lock, and only then
  links `current` directly on the destination CPU's queue (under the
  still-held `current.sched_lock` + the destination run-queue lock).
- `sys_thread_start` (`core/kernel/src/syscall/thread.rs`), which calls
  `set_state_under_all_locks(target, Ready)` to commit the state
  transition and then a separate `enqueue_ready_thread(target_cpu)` to
  commit the queue link.

(`dealloc_object(Thread)`'s server-side reply wake is no longer such a
site: it leaves the bound client `Blocked` and routes the deferred wake
through the gated `enqueue_and_wake`, which writes the client's
Scheduling-group fields under the *client's* own `sched_lock` and aborts
the link if a concurrent `dealloc(client)` already marked it `Exited` —
so no `Ready`-with-no-link window is published for that path.)

In each window the TCB is observably `Ready` with no queue link. A
racing `sys_thread_set_priority` taking the `sched_lock`-outer / all-CPU-locks
region sees no scheduler claim the TCB in its locate scan; it writes the new
priority and falls through without relocating. The pending link then reads
`(*tcb).priority` under the destination run-queue lock — neither
`enqueue_and_wake` nor `enqueue_ready_thread` takes a caller-supplied priority —
and links the TCB at whichever value was last committed under lock. No desync
results.

`migrate_ready_thread` (`core/kernel/src/sched/mod.rs`) is the other
known consumer of this transient. It acquires `(*tcb).sched_lock` (outer)
then both run-queue locks (ascending), reads `state` authoritatively under
`sched_lock`, and proceeds only if `state == Ready` AND
`remove_from_queue(src_cpu)` succeeds — the on-`src` remove is the sole
"located on src" arbiter (the earlier `preferred_cpu == src_cpu` heuristic
was dropped). During the transient, `tcb` is Ready-but-unlinked, so the
`remove_from_queue` returns `false`; `migrate_ready_thread` returns `false`
and leaves the pending link to place the TCB. The next caller of
`migrate_ready_thread` (or the load balancer) re-runs the migration if still
warranted.

`migrate_ready_thread` and the load balancer's `pull_unpinned_ready` both
funnel their validate-then-move through one primitive, `relocate_ready_thread`,
which reads `(state == Ready && context_saved == 1 && cpu_affinity permits
dst_cpu)` entirely under the caller-held `(*tcb).sched_lock` (the caller owns the
four-lock lifecycle and the post-move IPI). The affinity gate closes a
load-balancer affinity violation: `pull_unpinned_ready`'s `find_runnable`
predicate reads `cpu_affinity` *advisorily* under the run-queue lock, so a
concurrent `sys_thread_set_affinity` pinning the candidate away from `dst_cpu`
between the predicate and the move was previously honoured nowhere — the puller
would relocate a freshly-pinned thread to a forbidden CPU. Re-reading affinity
under `sched_lock` (the owning serializer) makes the puller decline; the
candidate is then placed correctly by the next `schedule()` cross-affinity arm
or balance tick (eventual consistency, not instant re-homing — #116). The
primitive takes the caller-located `priority` (the level `find_runnable` /
`migrate` found the candidate at), never re-reading `(*tcb).priority`, which a
concurrent `sys_thread_set_priority` could desync from the linked level.

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

**Enqueue-chokepoint enforcement (issues #244, #289).** Every run-queue
insertion — `enqueue_and_wake`, `schedule()`'s outgoing requeue,
`sys_thread_set_priority`'s re-enqueue, and `migrate_ready_thread`'s destination
link — funnels through `PerCpuScheduler::enqueue`. That chokepoint refuses a
double-link via the per-TCB `queued_on` tag: the priority level the TCB is
currently linked at, or `-1` when unlinked, written only under the owning
`scheduler.lock` (set on link, cleared in `dequeue_highest` /
`remove_from_queue`). If `queued_on >= 0` the TCB is already linked on *some*
CPU's run queue, and re-linking would self-cycle the intrusive list
(`tail.next = Some(tail)`, the `head=tail=tcb` corruption #244 reported). The tag
is global: unlike the earlier `run_queue_next.is_some() || is_tail` check it also
catches a TCB that is the sole element of a *different* priority queue or
*another CPU's* queue — the residual gap #289 hit, where a stale reply binding
woke an already-queued slot from a second `enqueue_and_wake`. Debug builds panic
(naming the prior link via the debug-only `last_enqueue` breadcrumb); release
builds skip the redundant link so the "Ready ⇒ linked on exactly one queue"
invariant holds by construction rather than corrupting. The skip is lossless: the
target TCB is already `Ready` and linked, so it is dispatched and consumes its
wakeup payload from where it is already queued. The guard precedes
`increment_load`, so a skipped link leaves the load counter exact. The legitimate
Ready-on-entry callers (the cross-CPU outgoing branch, `sys_thread_start`) reach
`PerCpuScheduler::enqueue` with the TCB *unlinked* (it was just `current`, or
`Created`/`Stopped`), so the guard never fires on them. This makes the invariant
self-enforcing at the single insertion chokepoint, closing the double-link class
(#22/#116/#117/#122/#142/#144/#244/#289) against any residual racing path.

---

## Cross-CPU TCB Ownership

The TCB is owned in pieces. Different field groups have different lock disciplines. Cross-CPU access to any field MUST hold the lock specified for that field's group.

| Field group | Fields | Owning lock | Cross-CPU access rule |
|---|---|---|---|
| **Scheduling** | `state`, `ipc_state`, `queued_on`, `run_queue_next`, `preferred_cpu`, `blocked_on_object`, `wake_pending` (plus `priority`, `slice_remaining`, `cpu_affinity`) | `(*tcb).sched_lock` — the single authoritative serializer, keyed on the TCB pointer (NOT positional). The same lock owns the group regardless of which CPU's run queue currently links the TCB, or whether it is linked at all. | Cross-CPU writers MUST acquire `(*tcb).sched_lock`. The per-CPU `scheduler.lock` is held *under* `sched_lock` only for the run-queue list structure (the intrusive `run_queue_next` link, `queued_on` tag, head/tail/`non_empty`/load); it no longer owns `state`. `wake_pending` is part of this group and is a plain `bool` accessed only under `sched_lock` (the lock-serialized wake-before-park refuse-to-park flag). |
| **IPC blocking** | `ipc_state`, `blocked_on_object` (committed under `sched_lock`; arbitrated under the source lock), `ipc_msg`, `ipc_wait_next`, `wakeup_value`, `timed_out` | For the `(ipc_state, blocked_on_object)` pair, both `(*tcb).sched_lock` (the commit / clear in `commit_blocked_under_local_lock` / `commit_reply_rebind_under_local_lock` / `enqueue_and_wake` / `cancel_ipc_block`'s snapshot) AND the source IPC lock matching `ipc_state` (the waiter-slot arbitration). The remaining fields (`ipc_msg`, `ipc_wait_next`, `wakeup_value`, `timed_out`) are owned by the source IPC lock alone. | A cross-CPU writer of the `(ipc_state, blocked_on_object)` pair MUST hold `sched_lock`; a writer of `source.waiter`/`ipc_wait_next` or the wakeup payload MUST hold the matching source lock; reads from another CPU MUST do the same. The two locks are never nested (order is source → `sched_lock`, but each commit/clear takes them disjointly). |
| **Reply slot** | `reply_tcb` | `AtomicPtr<ThreadControlBlock>`; lock-free with `Acquire`/`Release` ordering, and `compare_exchange` for cancel. | Endpoint paths set/clear it under `ep.lock`; cancel/dealloc paths on a remote CPU use `compare_exchange(client, null)` so they never clobber a different client's binding. `reply_tcb` is the one TCB field with no single owning lock — multiple lock domains write it (the various `endpoint_*` paths under `ep.lock`, plus `cancel_ipc_block`, the `dealloc_object(Thread)` reply-bound waker, and the fault-redirection reply/cancel paths, from outside any lock), which is why it is atomic. The fault redirection (`BlockedOnFault`) reuses this slot identically: `fault_dispatch` parks the faulter exactly as a caller, so every CAS claimant arbitrates over the same slot. **The binding must be published consistently with the `(ipc_state, blocked_on_object)` pair `dealloc_object(Thread)` uses to find and clear it (#289):** `endpoint_call` commits that pair under `(*tcb).sched_lock` via `commit_blocked_under_local_lock`; the `BlockedOnSend → BlockedOnReply` rebind in `endpoint_recv` does the same via `commit_reply_rebind_under_local_lock`, serialising with dealloc's `Exited` mark on the shared per-TCB `sched_lock` (dealloc takes `sched_lock` outer before its all-CPU locks). If the caller died concurrently the commit fails and `endpoint_recv` tears the binding down (CAS `reply_tcb` back to null, clear `wake_in_flight`) before skipping the dead sender — without this, dealloc reads a stale `BlockedOnSend` state, takes the wrong unlink arm, and leaves a dangling `reply_tcb` that fires against the freed/reused slot (#289 use-after-free / double-enqueue; #284 TCB-field corruption). **Stop-path UAF (#317) — CLOSURE LEMMA:** the client-side `reply_tcb` CAS (`cancel_ipc_block`, and `dealloc_object(Thread)`'s own `BlockedOnReply`/`BlockedOnFault` client arms) dereferences the *server*, which `dealloc_object(Thread)` on the server may concurrently `retype_free`. The CAS therefore runs under the *client's* `(*tcb).sched_lock` gated by a `blocked_on_object == server` re-read, and `dealloc_object(Thread)` on the server nulls a claimed client's `blocked_on_object` under that same client `sched_lock` *strictly before* `retype_free` (and before clearing the client's `wake_in_flight`, so an Exited client cannot be freed first). Hence observing `blocked_on == server` under the client lock witnesses the server is not yet freed, and the CAS dereferences live memory; the symmetric `endpoint_reply → client` deref stays pinned by the client's `wake_in_flight` as before. No new atomic — `reply_tcb`'s `Release`-publish / `AcqRel`-CAS / `Acquire`-load pairing is unchanged; this is a lock-scope tightening of the existing rules. The reply/fault timeout-arms in `sleep_check_wakeups` are exempt only because no syscall arms a reply/fault waiter on the sleep list (no timeout surface); if one is ever added it MUST adopt the same client-`sched_lock`-held re-read + CAS. |
| **Context save/restore** | `saved_state`, `kernel_stack_top`, `trap_frame`, `context_saved` | Owning-CPU's scheduler.lock for read; the running CPU writes `saved_state` during `context::switch` (no lock; write is serialised with the next reader by `context_saved` Acquire/Release). | A remote CPU dequeueing this TCB MUST spin-wait on `context_saved` (Acquire load) before reading any other context field. |
| **Address-space / capability** | `address_space`, `cspace`, `iopb` | Set once at create-time / configure-time; treated as read-only after `sys_thread_start`. | No cross-CPU write is permitted; reads need no lock. |
| **Identity** | `thread_id`, `magic` | Immutable after construction. | Read freely. |
| **IPC buffer** | `ipc_buffer` | Set by `SYS_IPC_BUFFER_SET`; logically owned by the thread itself. | The thread reads it under no lock from its own kernel-mode syscall path; other CPUs MUST NOT read it. |
| **Death observers** | `death_observers`, `death_observer_count`, `sleep_deadline` | The thread's own `sched_lock` for `death_observers`/`death_observer_count` (`sys_thread_bind_notification` appends under it; `post_death_notification` snapshots under it before posting); for `sleep_deadline`, the source IPC lock that initiated the timed wait + `SLEEP_LIST_LOCK`. | Cross-CPU writes follow the per-field rule above. |

**`sched_lock` (`core/kernel/src/sched/thread.rs`).** A per-TCB IRQ-disabling ticket `Spinlock` (the same `crate::sync::Spinlock` as every other lock here), keyed on the TCB pointer. It is not an atomic, but it is the serializer the entire Scheduling field group depends on; the per-TCB keying is what collapses the positional-ownership race class — two CPUs can no longer select two different locks for one TCB. Lock order: source IPC lock → `(*tcb).sched_lock` → per-CPU `scheduler.lock`. A path MUST NEVER hold two different TCBs' `sched_lock`s simultaneously.

**Magic-cookie discipline.** `magic == TCB_MAGIC` MUST be read on every dereference of a TCB pointer that crossed a CPU boundary or came from an intrusive list (run queue, IPC wait queue, sleep list, death observer). the run-queue ops `enqueue` / `dequeue_highest` in `core/kernel/src/sched/run_queue.rs` already do this; the same pattern applies anywhere a stale pointer might be observed.

**`cpu_affinity` enforcement invariant.** A thread with `cpu_affinity = X` (X ≠ `AFFINITY_ANY`) MUST NOT be linked on CPU Y's run queue, nor dispatched out of `schedule()` on CPU Y, for any Y ≠ X. The enforcement points are:

- `select_target_cpu` + `enqueue_and_wake` (`core/kernel/src/sched/mod.rs`) honour `cpu_affinity` on every placement.
- `migrate_ready_thread` is the active-relocation primitive.
- `schedule()`'s outgoing-thread re-enqueue branch (`core/kernel/src/sched/mod.rs`, the `cross_cpu` arm) routes the requeue cross-CPU when the *outgoing* thread's affinity no longer permits the current CPU.

The dispatch-side skip loop in `schedule()` (`core/kernel/src/sched/mod.rs`, the `dequeue_highest` Stopped/Exited skip) only filters `Stopped` / `Exited` — it does **NOT** consult `cpu_affinity` on the *incoming* dequeued thread. A `cpu_affinity` write that lands between an `enqueue_and_wake` and the matching `migrate_ready_thread` is therefore a window in which `schedule()` on the source CPU can still dispatch the target locally in violation of the new affinity. Syscalls that mutate `cpu_affinity` and then dispatch on an unlocked state read (`sys_thread_set_affinity`) MUST bracket the read-and-act sequence with `percpu::preempt_disable` / `preempt_enable` so a local timer-driven `schedule()` cannot dispatch the target on the source CPU during the in-flight migration. See issue #116.

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

Load balancer (pull_unpinned_ready / migrate_ready_thread, picking a Ready candidate):
 11. relocate a Ready candidate cross-CPU ONLY if context_saved.load(Acquire) == 1
     // a Ready-but-cs==0 candidate is mid-handoff (woken-while-current, still live on src); skip it
 12. // cs==1 ⇒ candidate has switched out and is current nowhere — safe to remove from src, link on dst
```

Step 3.5 is the outgoing CPU's cross-CPU dispatch barrier: when this CPU is about to switch INTO `next`, it must observe `next.context_saved == 1` from the CPU that previously ran `next`. Step 3.5 MUST run with the local `sched.lock` already released (step 3). Holding the lock across the spin re-introduces issue #144's cross-CPU deadlock: a peer CPU's cross-CPU `enqueue_and_wake` (e.g. its own outgoing-branch re-enqueue) targets this CPU's lock; if this CPU is spinning on `next.context_saved` under the lock while waiting on the peer to publish, the peer cannot reach its own `switch()` and the cycle never breaks. Step 3.5 runs lockless on both arches.

The Release in step 5 pairs with the Acquire in step 6 (cross-CPU dequeue), the Acquire in step 3.5 (outgoing-CPU dispatch barrier), the Acquire in step 9 (TCB free), and the Acquire in step 11 (load-balance relocation). Step 8 is the prerequisite: it scans *every* CPU and will not let the free proceed while any CPU still names `tcb` as `current`, so it does not rely on an all-locks `running_on` snapshot (which names at most one CPU and can be stale once the locks drop). Step 9 then closes the residual window step 8 cannot see: the lock release at step 3 lets a peer observe `sched.current = next` (set at step 2) *while step 4 is still writing into `tcb.saved_state`* — a CPU that has just switched *away* passes step 8 but its register save may still be in flight, and freeing the TCB there lets the next allocation reuse the memory while `switch()` corrupts it. Step 9 is unconditional; new TCBs initialise `context_saved = 1`, so the wait is bounded for threads that never ran.

The same drain (the all-CPU `current`-scan of step 8 + the `cs == 1` spin of step 9, factored into the `await_descheduled` helper) is reused by `sys_thread_start` to resume a thread. A thread stopped while Running may still be `current` on a remote CPU, so the start path drains it to not-`current`-anywhere + `cs == 1` **before** it commits `Ready` and force-links it (`enqueue_ready_thread`), while the target is still `Stopped`/`Created` — a state `schedule()`'s requeue denylist rejects, so the owning CPU deschedules it without re-linking. Without the drain a resumed thread could be force-linked on a second CPU while still live on the first — the same cross-CPU double-dispatch class as #314/#293.

**Step 11 — load-balancer liveness gate (issue #314/#293).** A thread can legitimately be `Ready` and linked on a run queue while it is *still `current`/live* on a CPU: the **wake-before-deschedule transient**. A thread that commits `Blocked` (e.g. an `ipc_call` that registers a reply binding) clears `context_saved = 0` and then, before it reaches its own `schedule()` to switch away, a fast waker (e.g. the server's `ipc_reply`) runs `enqueue_and_wake`, observes `Blocked`, and links it `Ready` on its `preferred_cpu` (the CPU it is still running on, pinned because `cs == 0`). The thread is now `Ready` + linked + `cs == 0` while `sched.current` on that CPU still names it. This is harmless on its own — the owning CPU's `schedule()` re-dispatches it (the `next == current` re-mark) or deschedules it. But a **cross-CPU relocator must NOT touch it**: `pull_unpinned_ready` (load balancer) and `migrate_ready_thread` (load balancer + `sys_thread_set_affinity`) would remove it from the source queue and re-link it on another CPU, which then dispatches it — marking the thread `Running` on two CPUs at once (the cross-CPU double-dispatch behind #314's torn context / double-enqueue and #293's release-mode lost wake). Therefore both relocators gate their pick on `context_saved == 1` (step 11). `cs == 1` is published only by `switch()` *after* the rsp/sp swap (step 5), so a `Ready`+linked thread observed at `cs == 1` has provably switched out and is `current` on no CPU. The gate is race-stable: the relocator reads `cs` under the source run-queue lock it holds across the remove, and a `Ready`+queued thread cannot transition `cs` `1 → 0` without first being dispatched (which needs that same lock). The complementary invariant — every park commit clears `cs = 0` (folded into `commit_blocked_under_local_lock`, on top of the IPC primitives' pre-clears) — guarantees the gate excludes *every* woken-while-current thread, not just the IPC ones. The owning CPU's local dispatch path (`dequeue_highest`) MUST NOT adopt this gate: it is the only path that can advance a mid-handoff thread back to `cs == 1`, so gating it would make such a thread permanently un-dispatchable.

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
1. Acquire (*tcb).sched_lock (the Scheduling-group serializer; outer).
2. Read tcb.state under sched_lock and classify:
   - Running  → set wake_pending = true; clear wake_in_flight; release
                sched_lock; RETURN (coalesce; the wake-before-park net —
                commit_blocked refuses to park and the resume path delivers
                the already-deposited payload).
   - Ready    → clear wake_in_flight; release sched_lock; RETURN (coalesce;
                already linked, a same-event duplicate — do NOT set
                wake_pending).
   - Stopped/Exited → clear wake_in_flight; release sched_lock; RETURN
                (a concurrent stop / dealloc won; linking would re-introduce a
                freed or stop-pending TCB).
   - Blocked/Created → fall through to the link path.
3. Acquire target scheduler.lock UNDER sched_lock (inner).
4. Set tcb.state = Ready, ipc_state = None, blocked_on_object = null,
   wake_pending = false; read priority under the run-queue lock (so a
   concurrent sys_thread_set_priority's all-CPU region serialises against
   the link).
5. Enqueue tcb in target's priority queue; the enqueue reports whether it
   created the link (false = the release-mode single-link skip).
   (Inside enqueue: non_empty.fetch_or(1 << prio, Release); queued_on = prio.)
5a. iff the link was created: preferred_cpu = target_cpu. preferred_cpu is
   retargeted only by the writer that actually created the link, under the
   same sched_lock → run-queue lock pair, so on a release skip the field
   keeps naming the surviving link's CPU (#359) and the preferred_cpu-keyed
   consumers (select_target_cpu's save-window pinning and sticky routing,
   the load balancer) stay coherent with the queue that actually holds the
   thread.
6. set_reschedule_pending_for(target_cpu).
   (RESCHEDULE_PENDING.set_cpu(target_cpu, Release).)
7. Clear wake_in_flight (so a waiting dealloc_object(Thread) may proceed).
8. Release target scheduler.lock (inner), then (*tcb).sched_lock (outer).
9. wake_idle_cpu(target_cpu)  →  sends IPI (always; see below). NEVER under
   sched_lock.
```

The producer-side `state`/`ipc_state`/`blocked_on_object` writes belong to `enqueue_and_wake` (performed under `sched_lock` → run-queue lock) — wake primitives MUST NOT do them under the source IPC lock. The live/not-live classification at step 2 is the "enqueue requires not-live" gate; it is mutually exclusive with `schedule()`'s `Ready→Running` dispatch flip and `commit_blocked`'s `Running→Blocked` commit because all three contend for the same per-TCB `sched_lock`. See Lock Hierarchy rules 8 and 9.

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

`select_target_cpu_excluding(tcb, exclude)` is the same policy with one CPU
removed from the save-window-pin / sticky / min-load branches (hard affinity
still wins, and the excluded CPU is returned only as a single-CPU fallback).
`dealloc_object(Thread)`'s deferred reply-wake calls it with
`exclude = Some(dealloc_cpu)`: the dealloc CPU is wedged in a preempt-disabled
UAF gate, **not** in `schedule()`, so the save-window pin's deadlock-avoidance
rationale does not apply to it — pinning a `context_saved == 0` woken client
there strands it on a CPU that cannot re-enter the scheduler until the dealloc
returns, which it cannot do while that client is the only runnable thread
(#351). The target is also recomputed at the *wake* site rather than snapshotted
inside the all-CPU-locks region: snapshotting two unbounded gate-spins before
the link let the client's state drift, widening the double-enqueue straddle
(#289). A peer dispatches the `cs == 0` client safely because the consumer-side
`schedule()` waits on the `context_saved` Acquire publication barrier before the
register switch.

Consumer side (`idle_thread_entry`, `core/kernel/src/sched/mod.rs`):

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

| Atomic | Location | Set ordering | Read ordering | Pairing rationale |
|---|---|---|---|---|
| `RESCHEDULE_PENDING` (`AtomicCpuMask`) | `sched/mod.rs` (decl; ops `set_reschedule_pending_for` / `take_reschedule_pending`) | Release on `set_reschedule_pending_for` (`set_cpu`) | AcqRel on `take_reschedule_pending` (`take_cpu`) | Release publishes the producer's prior enqueue; AcqRel ensures the consumer sees the enqueue and synchronises both directions of the bit clear. |
| `non_empty` (per PerCpuScheduler) | `sched/run_queue.rs` (decl in `PerCpuScheduler`; writes in `enqueue`, `dequeue_highest`, `remove_from_queue`; read in `has_runnable`) | Release on `enqueue.fetch_or`, `dequeue_highest.fetch_and`, `remove_from_queue.fetch_and` | Acquire on `has_runnable.load` | Release publishes the queue-mutation stores; the lockless idle-loop Acquire is the only synchronisation edge with cross-CPU enqueues on RVWMO. |
| `queued_on` (per TCB, `AtomicI16`) | `sched/thread.rs` (decl); writes in `PerCpuScheduler::enqueue` (set to priority), `dequeue_highest` / `remove_from_queue` (set to `-1`); read in the `PerCpuScheduler::enqueue` double-link guard, `schedule()`'s `already_queued` requeue guard, and the `commit_blocked_under_local_lock` debug tripwire | Relaxed `store` | Relaxed `load` | The global single-link tag (#244/#289). Every load-bearing access — set, clear, and the guard reads — is performed under the owning `scheduler.lock` (the `schedule()` guard read under the current CPU's run-queue lock), which supplies all required ordering; the atomic type exists only so a cross-CPU `enqueue_and_wake` guard read of a TCB linked on *another* CPU is well-defined, not for lock-free synchronisation. A `>= 0` value means linked at that priority on the CPU that set it. The `commit_blocked` tripwire reads it Relaxed under `(*tcb).sched_lock` with no run-queue lock — sound because every `-1 → >= 0` writer either classifies the target not-live under that same `sched_lock` (`enqueue_and_wake`, `enqueue_ready_thread` via its not-live caller contract) or runs as / while holding the same lock as the parking thread itself (`schedule()`'s requeue arms, `relocate_ready_thread`, `sys_thread_set_priority`), all excluded while the thread executes its own park commit. (The lock-free softlockup-watchdog dump also reads the field; diagnostic-only, not load-bearing.) |
| `context_saved` (per TCB) | `sched/thread.rs` (decl) | Release after `context::switch` returns on the outgoing CPU; **Relaxed clears to `0`** at the park commits (`commit_blocked_under_local_lock` and the IPC pre-clears) and `schedule()`'s switch-away / cross-affinity arms, each performed while the thread is `current` on the storing CPU | Acquire on the remote-dequeue spin-loop; **also Acquire** in the load-balancer liveness gate (`pull_unpinned_ready` / `migrate_ready_thread`, step 11) and `await_descheduled` | Closes the partial-`SavedState`-visibility race on RVWMO, and (step 11) gates cross-CPU relocation/resume on a committed save — `cs == 1` ⇒ switched out and `current` nowhere; see [Cross-CPU TCB Ownership](#cross-cpu-tcb-ownership) (steps 5/6/9/11) for the full sequence. The Relaxed `0`-clears are sufficient: every consumer reaches the cleared value transitively through a lock release/acquire chain (the waker/relocator hold `sched_lock` and the run-queue lock), the same argument the pre-existing IPC pre-clears rely on. |
| `bits` (Notification) | `ipc/notification.rs` (decl; ops in `notification_send` / `notification_wait`) | Relaxed `fetch_or` in `notification_send`, Relaxed `swap` in `notification_wait` and `notification_send` slow path | (same — paired with the SeqCst fences below) | The Dekker fence pair below provides the cross-side ordering; the bits ops themselves are Relaxed because no other field needs to be synchronised relative to them. |
| `has_observer` (Notification) + `bits` Dekker pair | `ipc/notification.rs` (decl) | Relaxed store in `notification_wait`, Relaxed load in `notification_send` | (same) | Paired SeqCst fences in `notification_send` (between `bits.fetch_or` and `has_observer.load`) and `notification_wait` (between `has_observer.store` and `bits.swap`) form the Dekker pattern: either `notification_send` observes `has_observer == 1` and falls through to the slow path lock acquisition, or `notification_wait`'s swap observes the OR'd bits and returns without parking. The fences are the only ordering edge; weakening to plain `Acquire`/`Release` is **insufficient** because the read-and-write sites span two distinct atomics. |
| `send_nonempty` (per Endpoint, `AtomicU32`) | `ipc/endpoint.rs` (decl); Release `store` in `EndpointState::refresh_send_ready` (called under `ep.lock` at every `send_head` mutation); Acquire `load` in `wait_set::source_is_ready` | Release `store` under `ep.lock` | Acquire `load` (lockless) | Atomic shadow of send-queue non-emptiness. The wait-set level-readiness self-heal reads it *without* `ep.lock` (taking `ep.lock` there would invert the `ep.lock → ws.lock` order `waitset_notify` uses and deadlock). The Release pairs with the lockless Acquire so a queued sender whose enqueue fired no edge notify is never missed on RVWMO (the wait-set self-heal that publishes the queue level to the lockless reader; #285-adjacent). |
| `count` (per EventQueue, `AtomicU32`) | `ipc/event_queue.rs` (decl); Release `fetch_add` in `event_queue_post` and Release `fetch_sub` in `event_queue_recv`, both under `eq.lock`; Acquire `load` in `wait_set::source_is_ready` | Release `fetch_add`/`fetch_sub` under `eq.lock` | Acquire `load` (lockless) | Current ring occupancy. Same discipline and rationale as `send_nonempty`: the wait-set self-heal Acquire-loads it without `eq.lock` (which it cannot take — it would invert `eq.lock → ws.lock`), and the Release stores publish the level so a non-empty queue is never missed by the lockless `source_is_ready` reader on RVWMO. Mirrors `NotificationState::bits`. (In-`lock` occupancy checks in `event_queue_post`/`recv` read it Relaxed — the lock orders those.) |
| `RESCHEDULE_PENDING` bit (per CPU) | (same as first row) | (same) | (same) | (single entry, listed once.) |
| `BOOT_TRANSIENT_ACTIVE` | `sched/mod.rs` (decl) | Release on `init_storage` (set true) and `sched::enter` (set false) | Acquire on every `timer_tick` entry | Single-writer (BSP). The Release/Acquire pair gates `timer_tick` against firing during Phase 4–9 when the run queue and scheduler state have not yet stabilised. |
| `CPU_LOAD[cpu]` | `sched/run_queue.rs` (decl) | Relaxed on `increment_load`, `decrement_load` | Relaxed on `current_load` | Advisory: `select_target_cpu` and the periodic load balancer consult this; transient inconsistency does not violate correctness. The counter MUST track queue occupancy: every `enqueue` increments, every `dequeue_highest` / `remove_from_queue` decrements. |
| `fault_handler` (per TCB) | `sched/thread.rs` (decl) | AcqRel `swap` in `sys_thread_set_fault_handler` (rebind/unbind) and the `dealloc_object(Thread)` binding release | Acquire `load` in `ipc::fault::has_handler` / `fault_dispatch` (the faulting thread, lock-free) | The binder holds the thread's `CONTROL` cap and runs on a different CPU than the target, which loads the pointer lock-free when it faults. The `swap` returns the previous object so the binding's `inc_ref` is released exactly once per rebind; the `fault_badge` Release store is ordered before this swap so a faulter observing the new handler also observes the matching badge. |
| `fault_badge` (per TCB) | `sched/thread.rs` (decl) | Release `store` in `sys_thread_set_fault_handler`, sequenced before the `fault_handler` swap | Acquire `load` in `fault_dispatch` | Paired with `fault_handler` above: written before the handler swap and read after the handler load, so the (handler, badge) pair is consistent for a faulter that observes the new binding. |
| `fault_outcome` (per TCB) | `sched/thread.rs` (decl) | Release to `Pending` by `fault_dispatch` before delivery; Release to `Resume`/`Kill` by the single wake-claim winner — `sys_ipc_reply` (genuine reply), `server_reply_wake` (handler death), `cancel_ipc_block` / `dealloc_object(Thread)` unlink / endpoint-dealloc send-drain / `sleep_check_wakeups` (cancellation) | Acquire `load` in `fault_dispatch` after `schedule()` returns | The disposition is written only by whoever wins the `reply_tcb` CAS (or, on the send queue, the unlink), so resume-vs-kill is unambiguous; the faulter reads it on resume. Any value other than `Resume` is treated as `Kill`, defensively covering a spurious wake that leaves `Pending`. |
| `LOAD_BALANCE_TICK` | `sched/mod.rs` (decl, balancer) | Relaxed on `fetch_add` (sole writer is the loaded-path victim selection in `try_pull_balance`) | Relaxed on the same `fetch_add` (consumes the previous value) | Advisory random-victim seed; correctness does not depend on ordering — a stale value just biases victim selection slightly. |
| `NEXT_THREAD_ID` | `sched/mod.rs` (counter) | Relaxed on `fetch_add` | n/a | Monotonic counter; no synchronisation needed. |
| `CPU_COUNT` | `sched/mod.rs` (decl) | Relaxed on store (`init_storage`) | Relaxed on every read | Single-writer at boot; the SCHEDULERS_PTR Release publishes the storage; readers establish happens-before via the pointer load, not via CPU_COUNT itself. |
| `SCHEDULERS_PTR`, `IDLE_TCBS_PTR`, `AP_TSS_PTR`, `AP_GDT_PTR`, `AP_IST_STACKS_PTR` | per-`AtomicPtr` declaration sites | Release on `store` in `init_storage` and per-arch initialisers | Acquire on `load` in `scheduler_ptr`, `idle_tcb_ptr`, AP startup helpers | Publishes the zeroed and constructed slab to every CPU; the Acquire establishes happens-before with the storage construction. |

**Rules:**
- The per-TCB `sched_lock` (a `crate::sync::Spinlock`, not an atomic; see § Cross-CPU TCB Ownership) is the serializer the Scheduling-group fields above rely on: `state`/`ipc_state`/`blocked_on_object`/`preferred_cpu`/`wake_pending` are plain (non-atomic) fields written under it, and `queued_on`'s atomicity exists only for a well-defined cross-CPU guard read — not for lock-free synchronisation. It is listed here for cross-reference only.
- Any new atomic in the scheduling or IPC path MUST be added to this table with its pairing rationale before merge.
- Any change from Release/Acquire to Relaxed (or the inverse) MUST be justified against this table; "looks fine on x86" is not justification — the riscv64 build is RVWMO and is the binding test.
- SeqCst is permitted only where a Dekker-style fence pair is the proven pattern; new SeqCst uses MUST cite the proof.

---

## Process-Death and Parked-Thread Protocol

The kernel does not auto-cascade IPC unblock on process exit. The contract:

1. **`procmgr` is the authoritative driver** of process-death cleanup. When a process dies, `procmgr` revokes the process's capabilities; the kernel's revocation path (see [capability-internals.md](capability-internals.md)) drives the unblock cascade for objects whose last reference is dropped.

2. **Kernel-side unblock sites that DO exist:**
   - `event_queue_drop` (`core/kernel/src/ipc/event_queue.rs`): when the EQ refcount hits zero, any parked consumer is woken with `wakeup_value = 0`. The consumer's syscall return path treats `wakeup_value == 0` as "object gone" via the `timed_out` companion flag (`core/kernel/src/sched/thread.rs`).
   - `wait_set_drop` (`core/kernel/src/ipc/wait_set.rs`): walks every member's source, clears the back-pointer under the source's lock, then wakes any blocked waiter on the wait set itself.
   - `notification` and `endpoint` do **not** auto-unblock parked threads on drop today. A blocked sender on an endpoint that loses its last cap holder will remain blocked indefinitely. This is by design at the kernel level — capability revocation is the higher-level mechanism.

3. **Wait-set member lifetime is refcounted.** `core/kernel/src/ipc/wait_set.rs` still holds raw `source_ptr`s into endpoint/notification/EQ objects, but each `WaitSetMember` now also holds a +1 cap-level reference on the source's `KernelObjectHeader`. `sys_wait_set_add` performs the `inc_ref` under the source's lock together with the back-pointer publication; `sys_wait_set_remove` and `wait_set_drop` perform the matching `dec_ref`. A source whose `dec_ref` drops to zero inside `wait_set_drop` is returned to the WaitSet arm of `dealloc_object_one` and pushed onto the cascade worklist — the source's own dealloc therefore runs after every IPC source/ws lock has been released, satisfying rule 5 of the Lock Hierarchy. Sources can no longer be reclaimed while a member references them, so `waitset_wait` cannot dereference a dangling `source_ptr`.

4. **Thread death observers fire from the dying thread's exit path** (`core/kernel/src/sched/thread.rs`). Each observer is an `(EventQueueState*, correlator: u32)` pair; the kernel posts `(correlator << 32) | exit_reason` to each observer's queue. This mechanism is the procmgr/svcmgr-facing API; it does not interact with the parked-thread protocol above. `sys_thread_bind_notification` and `post_death_notification` serialise on the target thread's `sched_lock`: the bind appends an observer while the thread is live, and the death path snapshots the observer set under the lock before posting. A bind that arrives *after* the thread has exited reads the retained `exit_reason` (written before the `Exited` commit) and posts it to the new observer immediately, so a supervisor that binds after the thread was started never loses the death (#106 Window 2). When a post wakes a blocked observer, `post_death_notification` / `post_aspace_death_notification` route the wake through `select_target_cpu` + `enqueue_and_wake` — the same save-window-pinned producer path as every other waker (§ Target CPU selection). A death post that enqueued on the *dying* thread's CPU instead would bypass the `context_saved == 0` pin and land an observer still mid-block on a foreign CPU, whose `schedule()` then spins on the observer's in-flight register save; if the observer is concurrently mid-block on its own CPU the save never publishes and both CPUs deadlock (#289).

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

Permanent kernel feature: a suite of wedge detectors sharing one
once-per-boot dump latch (`WATCHDOG_FIRED`, claimed via
`watchdog_claim_dump`) and one dump body (`watchdog_dump(reason)`). The
first detector to trip wins; one dump per boot keeps the serial log
readable, prevents a dump storm when many CPUs observe the same stall, and
the first dump is the uncontaminated evidence. The dump is callable from
any CPU in interrupt context: shared structures are read benign-racily or
via try-lock (`SLEEP_LIST_LOCK`, the registry walk) so a wedged lock holder
cannot deadlock the dump itself.

Three detectors feed the latch:

**1. All-idle softlockup (BSP, every tick).** Detects "every CPU stalled in
kernel mode" — the failure class userspace cannot observe, because no
userspace runs when every CPU is wedged. `schedule()` updates a per-CPU
`LAST_NON_IDLE_TICK` whenever it dispatches a non-idle thread; the BSP
`timer_tick` increments a global tick counter and fires if every CPU's last
dispatch is older than `WATCHDOG_THRESHOLD_TICKS` (~3 s at the observed
~1 ms tick).

**2. Owed-wake detector (BSP, every `DETECTOR_SCAN_INTERVAL_TICKS` ≈
0.5 s).** Detects a single `Blocked` thread whose wake is provably owed but
never arrived — the lost-wakeup wedge signature (#375), invisible to the
all-idle check whenever any other thread keeps any CPU busy. Walks the
live-thread registry reading only plain TCB scalars (no IPC-object
dereference: unlike the dump's `blocked_on` decode, this runs on a LIVE
system where a blocking object can be freed concurrently). Three rules:
expired `sleep_deadline` past a 2 s grace window (a healthy sleeper is
claimed, and its deadline cleared, within one BSP tick); `wake_in_flight`
stuck set (a waker claimed the thread but its `enqueue_and_wake` never
completed — normally microseconds); and `wake_pending` observed while
`Blocked` (a coalesced wake survived the park commit that must consume it).
The deadline rule is debounced by its grace window; the other two must
persist across two consecutive scans (`OWED_WAKE_LAST`) so a legitimately
mid-wake observation cannot false-positive. Indefinite waits (endpoint recv
loops) match no rule. Each park commit stamps `park_started_tick` for the
age checks.

**3. Timer-heartbeat cross-checks.** Every CPU stamps `TICK_HEARTBEAT[cpu]`
with `timer::current_tick()` on each `timer_tick` entry (`current_tick`
derives from a globally consistent counter on both arches — TSC / `time`
CSR — so cross-CPU age comparison is sound). Each AP compares the BSP's
stamp against its own (`bsp_stall_check`): a BSP wedged interrupts-off
kills the sleep-list waker and every BSP-hosted detector at once — total
silence — so the AP-side check is the only detector that can name that
state (#375). Symmetrically the BSP scans AP stamps
(`ap_silence_check`) and fires on an AP silent past the grace window.
Both defer to an in-flight TLB shootdown, as below.

The heartbeat checks measure staleness in wall time, so their grace scales
with CPU count (`heartbeat_stall_ticks`, stepping at multiples of 128 CPUs:
<256 CPUs → 8 s, 256..384 → 16 s, 512 → 32 s). The 8 s base is sized above
the slowest legitimate
single-syscall CPU occupancy observed (a debug-build aperture-mapping
syscall held the BSP just past 2 s on a slow TCG CI runner), and the
CPU-count scaling covers oversubscribed wide guests, where vCPUs
legitimately starve of timer service for seconds (the #376 512-vCPU runs
saw a healthy BSP 2 s stale at ~7% aggregate tick delivery). A real wedge
exceeds any finite threshold — the grace costs only detection latency. The owed-wake
rules deliberately do not scale: rule 1's pop-before-scan ordering and
rules 2–3's two-scan persistence ride the BSP's own cadence, which
self-stretches under starvation.

Attaching GDB to a live guest (xtask `--debug-listen`) freezes every vCPU
while guest-visible time keeps advancing, so on resume the heartbeat checks
read the stop window as staleness and fire once. A dump immediately after a
debugger detach is that artifact, not a wedge.

Tripwires outside the latch: the two `wake_pending` clears in `schedule()`
(the same-thread re-mark and the dispatch flip) print a single-shot line
(`WAKE_PENDING_CLEAR_TRIPPED`) if the flag was live when cleared — the only
sanctioned consumer of a coalesced wake is `commit_blocked_under_local_lock`
(§ Wake Protocol Invariants), so a live clear at either site is a lost wake
named at its exact destruction point.

Each per-CPU dump line carries a **spin-site breadcrumb**: a wedged CPU that
never returned to the scheduler is stuck in a protocol-spin, and the
breadcrumb (`spin_site_enter`/`spin_site_exit`, set around each gate) names
which one — `dealloc:not-current`, `dealloc:context-saved`,
`dealloc:wake-in-flight`, or `schedule:context-saved`. The
`dealloc_object(Thread)` gates carried no overlong-duration warning of their
own, so a wedge there showed only an opaque `current = Exited` in
`SYS_CAP_DELETE` (#351); the breadcrumb makes it explicit. The `schedule()`
context-saved dispatch barrier reports both ways: the breadcrumb names it in
cross-CPU dumps, and its own single-shot warning fires after 100 ms of
spinning (`CS_SPIN_WARN_US`, time-based so it is meaningful under TCG's
variable instruction rate).

The dump then walks the live-thread registry (§ Thread Registry) and prints
every non-running registered thread. For a `Blocked` thread it shows the
`wake_pending`/`wake_in_flight` flags and a decode of `blocked_on_object`:
whether the blocking object still names the thread as its waiter
(`waiter_is_self` / `reply_is_self`) or holds data with a cleared waiter slot
(`count > 0`) — distinguishing a wake that was never issued from one deposited
but never linked. For a `Ready`/`Stopped` thread it shows
`context_saved`/`queued_on`/affinity/`preferred_cpu` — why a runnable thread is
neither dispatched by its wedged owner CPU nor stolen by an idle one (e.g. the
save-window pin holds a `context_saved == 0` thread on its owner). The per-CPU
`current` dump shows only each CPU's running/idle thread, so both victim shapes
— a `Blocked` waiter on an IPC object, or a `Ready` thread stranded in a wedged
CPU's run queue — were invisible before this enumeration (#351).

**Cost:** per tick per CPU, one `current_tick()` read plus one Relaxed
heartbeat store (APs add one Relaxed load + compare for the BSP check); one
Relaxed counter increment per BSP tick and an O(`cpu_count`) early-exit
loop; the registry scan and AP-stamp sweep run only on the 0.5 s cadence;
one plain stamp store per park commit. Zero dump overhead when healthy.

**Catches:** all-CPUs-idle with work queued (lost-wake bugs); cross-CPU
`context_saved` deadlock; every TCB incorrectly `Blocked`; a single thread
wedged `Blocked` while the system stays busy (owed-wake rules); a BSP or AP
wedged interrupts-off while at least one other CPU still ticks (heartbeat
cross-checks).

**Does NOT catch:** every CPU wedged interrupts-off simultaneously (no
heartbeat check runs anywhere — the all-idle detector is also dead because
its counter stops). Only an NMI / always-on S-mode timer hardlockup
detector closes that; tracked as issue #33. A `Blocked` thread whose waker
genuinely never claimed it (no deadline, no `wake_in_flight`, no
`wake_pending`) is indistinguishable from a legitimate indefinite wait by
TCB scalars alone and is also not flagged.

**Defers to an in-flight TLB shootdown:** a synchronous shootdown holds every
participating CPU (initiator preempt-disabled in `wait_for_ack`; peers spinning
in `pt_lock` or their own shootdown) until all remote CPUs ack. Under heavy
oversubscription that round-trip can exceed the threshold while still making
progress, so the all-idle detector and both heartbeat cross-checks skip firing
while `tlb_shootdown::any_pending()` reports any per-CPU request slot with
CPUs still to ack. The shootdown's own escalation ladder (NMI backtrace at
0.75 s, panic at 5 s in arch `wait_for_ack`) is the authoritative detector
for a genuinely stuck IPI; a non-shootdown stall re-checks on the next tick
once the pending slots drain.

**Why kernel-side:** when every CPU is in kernel mode, no userspace monitor
gets dispatched. The dump is also the only path that reads per-CPU
scheduler state without taking a lock that the stalled CPUs themselves hold.

**Bounded-spin diagnostics elsewhere:** two protocol-required spins (the
`context_saved` Acquire spin in `schedule()`, which also reports a spin-site
breadcrumb as above; the cross-CPU drain spin in `sys_thread_stop`) carry
single-shot overlong-duration warnings. These are not the watchdog; they
fire only when the spin overruns and identify the stuck participants. Zero
overhead in healthy paths.

## Thread Registry

`core/kernel/src/sched/thread_registry.rs` is a diagnostic-only intrusive
doubly-linked list of every live TCB, threaded through `registry_next` /
`registry_prev` and guarded by the strict-leaf `THREAD_REGISTRY_LOCK` (Lock
Hierarchy rule 3a). It exists solely so the softlockup watchdog can enumerate
`Blocked` waiters that the per-CPU `current` dump cannot reach.

**Membership.** `register` splices a TCB onto the head; `unregister` removes it.
A thread is registered on the success path of `sys_cap_create_thread` (after its
cap is inserted — the rollback arm frees the TCB via `retype_free` without ever
registering it, so register-on-success keeps the two symmetric) and on
init's bootstrap thread. It is unregistered in the `dealloc_object(Thread)` arm
strictly before the TCB is poisoned/freed: the walk holds `THREAD_REGISTRY_LOCK`
across every dereference, so unlinking before the free guarantees the watchdog
never observes a dangling node. Idle TCBs are deliberately not registered — they
are never `Blocked` and are already shown by the per-CPU `current` dump.

**Walk.** `try_for_each` takes the lock with a non-blocking `try_lock`: if it is
contended (a register/unregister in flight) or a CPU died holding it, the walk is
skipped rather than spun on — the watchdog must never block. A `MAX_WALK` bound
caps a corrupted-into-a-cycle list so the already-fatal dump still terminates.

**Not a scheduling structure.** The registry is never read on any hot path; it
adds one leaf-lock acquire at thread create/destroy and nothing elsewhere.

---

## Summarized By

[kernel/README.md](../README.md)
