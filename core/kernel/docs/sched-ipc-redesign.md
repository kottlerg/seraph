# SMP Scheduler/IPC Hotpath Redesign — per-TCB `sched_lock` (authoritative serializer)

Status: IMPLEMENTED in #292. This document is the design rationale for the
structural fix to the recurring cross-CPU TCB-lifecycle race class behind #116
#117 #128 #144 #160 #207 #225 #244 #282 #289 #284. The authoritative,
binding invariants live in [scheduling-internals.md](scheduling-internals.md);
this document records WHY the per-TCB `sched_lock` design was chosen and HOW it
was migrated, and is retained for the code comments that cite its rationale
sections (`§2`, `§2.1`).

## 0. History — why this is the SECOND design in this doc

The first attempt in this file was a per-TCB `running_on` liveness atomic with
**owner-routed** wakes (link a woken thread directly onto the CPU it is live on).
It was implemented, committed (`1db7092`), and CI-validated — and **regressed**:
it fixed the one #284 cell (x86_64/debug/usertest) but broke four previously-clean
cells with dense run-queue double-enqueues (`mod.rs` enqueue tripwire) from
multiple sites/states, plus release-mode chain corruption (#PF `cr2=0`,
`ipi never acked`). Apples-to-apples 12-cell: baseline 3 fails → owner-route 7
fails. That attempt was reverted to `e0db329` before this design was built.

Root cause of the failure: **owner-route links a thread while it is still
`current`/live on the target CPU**, which races `schedule()`'s own
requeue-from-state path and the cross-CPU `queued_on` Relaxed read → double-link.
`running_on` was a *third* positional signal layered onto machinery that already
routes by `preferred_cpu`/`queued_on`/`sched.current`; under load they disagree
and the disagreements race. (Note: the audit's *actual* `running_on` design,
scored[3], used **defer-and-replay**, not owner-route — it never links a live
thread. The deviation was the defect, not `running_on` itself.)

Lesson, and the reason for this design: a minimal layered signal cannot kill the
class because it does not establish a **single authority**. The audit's #1-scored
design does exactly that.

### 0.1 Decision: per-TCB `sched_lock` over `running_on`-with-defer (final-state merits)

After the owner-route failure we evaluated the two remaining `running_on`-family
options against per-TCB `sched_lock`, on end-state architecture only (ignoring
migration effort). Decision: **per-TCB `sched_lock`** (this document's design).

Evidence (audit adversarial per-design panel; `scored[]` totals out of 21):
- `scored[0]` per-TCB `sched_lock`: **19** (correctness 7, simplicity 6, completeness 6).
- `scored[3]` `running_on`+**defer**: **13** (correctness **4**, simplicity 3.5, completeness 5.5) — the lowest of all four designs.
- (`scored[1]` home_cpu+inbox 19.5, `scored[2]` park_claim epoch 19.5 — slightly
  higher panel scores but more bespoke/lock-free schemes that perpetuate the
  "subtle invariant easy to miss on a new transition" pattern that caused the
  plague; `sched_lock` is the standard, obviously-correct per-object authority and
  scores highest on simplicity, which is what a year-plagued foundational
  subsystem needs most.)

Why `running_on`-with-defer (B) loses on the merits, not just the score:
1. **Its release/replay half is unsound (audit-confirmed).** The claim half excludes
   double-dispatch, but the deferred wake "has no driver for the case it exists to
   serve" — a *parked* thread's deferred wake is never replayed (replay only drains
   `current.wake_pending` at schedule() entry) → a **reintroduced lost-wake**. It
   does NOT make the class impossible by construction.
2. **It adds to the multi-signal web instead of collapsing it.** Scheduling state
   would span SIX sync fields (`running_on`, `wake_pending`, `context_saved`,
   `queued_on`, `wake_in_flight`, `preferred_cpu`) and THREE hand-off protocols,
   plus a hand-tuned cs-before-`running_on` Release law and an RVWMO fence in the
   hottest path. That is the *opposite* of the mandate (one authority).

Why `sched_lock` (A) wins:
1. **Correctness by construction, not by timing.** "Enqueue-requires-not-live" holds
   because the enqueuer holds the SAME lock the dispatcher must hold to mark a
   thread Running — mutual exclusion. The wake-before-park lost-wake is closed by a
   *lock-serialized* `wake_pending` refuse-to-park, not a schedule()-timing replay.
2. **It collapses the documented root** (the pre-redesign positional ownership; §1)
   into one per-TCB authority — the standard, conventional answer ("what guards
   this object's state? its lock"), the most reason-about-able for future
   contributors.
3. **Steady-state cost is competitive** — one mostly-uncontended ticket-lock acquire
   per dispatch/wake (contention only on the exact rare race we serialize), vs B's
   CAS + two fenced Release stores + `wake_pending` checks + a defer-path IPI. Perf
   does not favor B.

Caveat carried forward: the audit *synthesis* recommended the owner-route hybrid
(which we built and which failed); do NOT re-trust it. The per-design panel above
is the authority. Decision is final unless burn-in of `sched_lock` itself forces
the documented owner-token-CAS fallback (§5).

## 1. The class, and the model defect

Before this redesign, `scheduling-internals.md` § Cross-CPU TCB Ownership made the
owning lock of a TCB's Scheduling field group "the `scheduler.lock` of whichever
CPU's run queue currently links the TCB" — a lock **selected by reading the very
fields it guards**. Two CPUs could therefore pick two different locks for one TCB
at the same instant. No single lock serialized `{state, ipc_state, queued_on,
run_queue_next, preferred_cpu, blocked_on_object}` across CPUs. Every prior fix
patched one interleaving of this.

Three structural roots (CI-proven for #284):
- (a) `context_saved` means "saved at least once," not "parked" (stays 1 for a
  thread's whole run), so it cannot gate exclusivity for a Running thread.
- (b) `queued_on == -1` while running (cleared at own dispatch), so the
  single-link guard is blind to a foreign enqueue of a live thread.
- (c) cross-CPU enqueues of one thread take *different* per-CPU locks →
  unserialized.

## 2. Chosen design — one `sched_lock` per TCB (audit scored[0])

Add one IRQ-disabling ticket `Spinlock` per TCB, `sched_lock`, as the **single
authoritative serializer** for that TCB's entire Scheduling field group, keyed on
the TCB pointer (not positionally on a CPU). Strict lock order:

    source IPC lock (outer) → (*tcb).sched_lock → per-CPU run-queue lock (inner)

The per-CPU run-queue lock is **demoted** to protecting only the intrusive list
structure (head/tail/non_empty/load) of one CPU; it no longer "owns" any TCB's
`state`.

**The invariant that kills the class — "enqueue requires not-live."**
`enqueue_and_wake` acquires `(*tcb).sched_lock` FIRST (before `select_target_cpu`,
before any run-queue lock), reads `state` under it, and links ONLY a not-live
thread (`Blocked`, or `Created`/`Stopped` for start/resume). If `state` is
`Running`/`Ready` the wake is **coalesced** (no-op against the live/queued
incarnation) — now SAFE, not a #289 lost-wake, because the read is serialized
against the parking commit (below). A `Running` thread can no longer be linked on
a foreign CPU: the enqueuer holds the SAME lock the dispatcher must hold to mark
it Running → mutually exclusive. Root (c) gone by construction; (b) irrelevant
(decision keys off `state` under the owning lock, not `queued_on`); (a)
irrelevant (exclusivity no longer depends on `context_saved`).

**Wake-before-park preserved without the #289 lost-wake.** Park-commit and
wake-decision now contend for the SAME per-TCB lock. Add `wake_pending: bool` to
the Scheduling group. A waker that finds `state==Running` sets `wake_pending=true`
under `sched_lock` and aborts the link. `commit_blocked_under_local_lock`, before
writing `Blocked`, re-reads `wake_pending` under `sched_lock`; if set, it
**refuses to park** (returns false, thread stays runnable) — the wake-before-park
refuse-to-park semantic, now lock-serialized instead of
schedule()-timing-dependent. No wake is lost.

### 2.1 Resume-model constraint on refuse-to-park (verified, load-bearing)

The blocking-syscall resume model is uniformly **DEPOSIT, not re-check**: every
blocking syscall (`sys_notification_wait`/`sys_event_recv`/`sys_wait_set_wait`/
`sys_ipc_call`/`sys_ipc_recv`), on resume after `schedule()`, reads a TCB field
the waker wrote (`wakeup_value`/`timed_out`/`ipc_msg`) and returns it WITHOUT
re-reading the source object (traced: e.g. `sys_notification_wait` reads
`(*tcb).wakeup_value`; `sys_ipc_call` reads `(*tcb).ipc_msg`). There is NO
re-check loop anywhere.

The refuse-to-park is therefore lost-wake-safe ONLY via this invariant chain,
which the `enqueue_and_wake` gate and its callers preserve:
1. Every `enqueue_and_wake` caller deposits its payload BEFORE calling
   `enqueue_and_wake`. So `wake_pending` set ⇒ payload already deposited — no
   spurious-zero/garbage wake. (`wake_pending` is set inside `enqueue_and_wake`,
   strictly after the upstream deposit under the source lock.)
2. Refuse-to-park leaves `state==Running`, so the caller's existing `!committed`
   rollback routes the thread through `schedule()`, which REQUEUES a runnable
   thread (vs. DRAINS a Stopped/Exited one) → it resumes at the line after
   `schedule()` and reads the deposited field. The single `false` return serves
   both the stop/exit and the refuse-to-park case because the post-`schedule()`
   outcome is **state-driven**, not return-value-driven.
3. Each primitive's `!committed` rollback MUST NOT clobber the deposited field
   (it may clear only the waiter slot + restore `context_saved`). This holds for
   every primitive — `notification_wait`, `event_queue_recv`, `waitset_wait`, and
   the three endpoint sites.

`wake_pending` is only reachable for wakers NOT serialized with the parker by a
source lock — the IPC reply / cross-path races behind #284/#289. Source-lock-
serialized parkers (notification/event/waitset; and the ep-serialized reply)
always take order (ii): the parker commits `Blocked` under the source lock
before any waker can run `enqueue_and_wake`, so they never set `wake_pending`.

**Why a `Ready` coalesce can always be dropped (the linchpin for
`enqueue_and_wake`'s `Ready` arm).** The register-waiter → `commit_blocked` sequence runs entirely
under the source IPC lock, which is IRQ-disabling (`lock_raw`). So (1) the
parking CPU cannot be preempted into `Ready` mid-registration — a thread goes
`Running → Blocked` atomically w.r.t. preemption, never transiting `Ready` while
it is a pending-but-unparked waiter; and (2) a remote waker needs that same
source lock, so it can only run after the parker has committed `Blocked`.
Therefore a thread a waker observes as `Ready` is ALWAYS an already-woken thread
(its waiter slot was cleared by the wake that made it `Ready`), i.e. a stale
duplicate — never a wake-before-park case. Dropping it loses nothing, and there
is no "preempted-mid-registration" window that would require `wake_pending` on
the `Ready` arm. (`Running` keeps `wake_pending` purely as the belt-and-
suspenders net for any future waker that is not source-lock-serialized.)

## 3. What the implementation does (the migration, ordered as it landed)

The redesign was migrated as an ordered sequence of incremental, individually
buildable-and-bootable changes. The description below records the final shape of
each change; the binding statement of the resulting invariants is
[scheduling-internals.md](scheduling-internals.md).

- **`Spinlock::try_lock_raw`** (`sync.rs`) — a CAS try-acquire returning `None`
  on contention. It exists for the `pull_unpinned_ready` back-off (the one site
  that needs `sched_lock` after a run-queue lock, the inverse of the canonical
  order). It landed together with that sole consumer plus a host unit test, not
  ahead of it (an unused `pub fn` would have stood as a `dead_code` warning).

- **`sched_lock: Spinlock` and `wake_pending: bool`** are TCB fields at the end
  of the `=== Scheduling state ===` group, initialised (`Spinlock::new()`,
  `wake_pending = false`) at every ctor site (idle in `mod.rs`, init in
  `main.rs`, create-thread in `cap.rs`, host `make_tcb` in `run_queue.rs`; a
  zeroed ticket lock is already unlocked). These are additive — adding them alone
  is no behavior change.

- **`commit_blocked_under_local_lock` / `commit_reply_rebind_under_local_lock`**
  acquire `(*tcb).sched_lock` (not the CPU lock), consult `wake_pending`, and
  refuse to park when it is set. IPC primitives keep the source IPC lock outer;
  only the commit-helper internals changed, not the call sites.

- **`enqueue_and_wake`** is the exclusivity gate. Its signature is unchanged
  (`target_cpu` is the caller-computed placement *hint* from `select_target_cpu`;
  exclusivity is decided by `state` under `sched_lock`, not by the CPU choice).
  It acquires `(*tcb).sched_lock` first and classifies `state`:
  - `Stopped|Exited` → clear `wake_in_flight`, return (a stop/dealloc won).
  - `Running` → set `wake_pending`, clear `wake_in_flight`, return. The
    wake-before-park net: the thread is mid-park; its `commit_blocked` sees the
    flag and refuses. Safe per §2.1 (the payload was deposited upstream).
  - `Ready` → clear `wake_in_flight`, return (coalesce; do NOT set
    `wake_pending`). The thread is already linked, will be dispatched, and will
    consume the deposited payload; a `Ready` coalesce is only ever a same-event
    duplicate (single-waiter-slot ⇒ a distinct event cannot target an
    already-woken thread). Setting `wake_pending` here would risk a spurious
    refuse-to-park on the thread's NEXT block.
  - `Blocked|Created` → link: acquire the target run-queue lock (`sched_lock`
    outer → CPU lock inner), set `Ready`/`ipc_state`/`preferred_cpu`, clear
    `wake_pending` (defensive), `sched.enqueue` (the `queued_on` guard intact),
    reschedule-pending, clear `wake_in_flight`, release the CPU lock, release
    `sched_lock`, then `wake_idle_cpu` (never IPI under `sched_lock`).

  Because the gate coalesces `Ready`, a caller that *deliberately* sets
  `state=Ready` before linking (a placement it owns, not a wake) cannot go
  through `enqueue_and_wake` — it would silently fail to link. The deliberate
  `→Ready` placer is `enqueue_ready_thread(tcb, target_cpu)`: `enqueue_and_wake`'s
  link tail WITHOUT the gate (force `Ready` + link under `sched_lock` → run-queue
  lock, clear `wake_pending`/`wake_in_flight`, IPI). Its sole live caller is
  `sys_thread_start` (first-start / resume). The IPC primitives instead pass a
  `Blocked` thread and defer the `Blocked→Ready` flip to `enqueue_and_wake`
  (`sleep_check_wakeups` likewise — its stale "transitioned to Ready" comments
  were corrected). `schedule()`'s cross-affinity requeue and the
  `dealloc_object(Thread)` reply-bound wake are NOT deliberate-placer callers (see
  the `schedule()` and teardown notes below).

- **`schedule()` dispatch** moved its `state` writes under `sched_lock`. The
  forcing reason is a data race, not tidiness: every `state` write `schedule()`
  does (`current` Running→Ready requeue; `next` Ready→Running dispatch) is read by
  `enqueue_and_wake`/`set_state`/`commit_*` under `sched_lock`. With those writes
  still under the per-CPU lock once the readers moved to `sched_lock`, a
  `schedule()` CPU-lock write and a `sched_lock` reader are a data race (UB) —
  reachable in the #284 stale-wake scenario (a waker targets a live
  `current`/`next`). This change and the `set_state`/dealloc change below close
  the race only together (both the writer and `set_state` must be on
  `sched_lock`).

  Lock order across the function: `current.sched_lock` (outer) → CPU lock (inner)
  for the outgoing half; release the CPU lock then `current.sched_lock`; then
  `next.sched_lock` alone for the incoming flip. It NEVER holds two TCB
  `sched_lock`s at once.
  - Top: read `current` (CPU-local). Acquire `current.sched_lock` (if `current`
    non-null), then the CPU lock.
  - **Outgoing requeue** under both: flip `current` Running→Ready + enqueue. The
    local arm calls `sched.enqueue` under the CPU lock. The cross-affinity arm
    flips under `current.sched_lock`, drops the LOCAL CPU lock (keeping
    `preempt_disable`), enqueues **directly** on the target under
    `current.sched_lock` + the target run-queue lock (mirroring
    `migrate_ready_thread`), then relocks — it does NOT call
    `enqueue_and_wake`/`enqueue_ready_thread` (they would re-acquire
    `current.sched_lock` → re-entrant deadlock).
  - `next = dequeue_highest()` + skip Stopped/Exited (CPU lock).
  - `next == current`: re-mark Running (under `current.sched_lock`, held), release
    the CPU lock, release `current.sched_lock`, return (NO switch; `context_saved`
    untouched).
  - `next != current`: clear `current.context_saved = 0` (under the CPU lock,
    BEFORE the release — a remote puller of the just-requeued `current` must see
    `cs=0` and spin); `set_current(next)` (claim; `next.state` stays Ready);
    capture `current_state`/`save_flag`; release the CPU lock, release
    `current.sched_lock`.
  - **Incoming flip:** if `next != idle`, acquire `next.sched_lock`; if
    `state == Ready` → flip Running + set `preferred_cpu`; else idle-fallback —
    `next` was `set_state`'d Stopped/Exited in the dequeue→flip window (reachable:
    `dealloc_object(Thread)` marks Exited under all-CPU locks BEFORE its
    not-current spin blocks). `next` is now off-queue and drained, so re-claim
    `idle` (`set_current(idle)` under a re-taken CPU lock) and dispatch idle this
    cycle; the next tick re-schedules. Release `next.sched_lock`.
  - THEN trap-stack / AS-switch / IOPB / FPU for the final `next` (all CPU-local,
    safe with the CPU lock released, IRQs still off), the `next_state` pointer,
    the `context_saved` spin, `switch()`, `restore_interrupts_from`. The
    AS-switch/FPU is AFTER the flip/idle-fallback — never load a Stopped/Exited
    `next`'s (being-torn-down) address space.

  **`preferred_cpu` must stay authoritative on the two same-CPU `current` arms.**
  The local-requeue else-arm and the `next == current` re-mark both set
  `(*current).preferred_cpu = cpu`. Leaving it stale lets a `preferred_cpu`-keyed
  path (wake routing via `select_target_cpu`, or `migrate_ready_thread`) target a
  CPU other than the one `current` is actually linked on / running on, which is
  the residual cross-CPU double-dispatch the burn-in chased: a second waker links
  the thread on the stale-`preferred_cpu` CPU while it is already linked here.

- **`set_state_under_all_locks` and the `dealloc_object(Thread)` arm** acquire
  `(*tcb).sched_lock` first (outermost), then all CPU locks ascending. Lifecycle
  Stopped/Exited now serializes with wake/commit/dispatch on the same per-TCB
  lock — the other half of the `schedule()` data-race fix. dealloc's lifetime
  gates (the not-current scan, the `context_saved` spin, the `wake_in_flight`
  spin) are unchanged.

- **The remaining stragglers route through `sched_lock`:** `sys_thread_sleep`
  (which previously wrote `Blocked` with no lock — the old documented divergence)
  now commits via `commit_blocked_under_local_lock`; `migrate_ready_thread` and
  `pull_unpinned_ready` acquire `sched_lock` (the migrate as the outer lock; the
  pull via `try_lock_raw` after the run-queue locks) and read `state == Ready`
  authoritatively, dropping the old `preferred_cpu == src` heuristic
  (`remove_from_queue(src)` is the sole on-src arbiter); `cancel_ipc_block`
  snapshots `(state, ipc_state, blocked_on_object)` under `sched_lock` and clears
  the binding with a re-verify (closing finding D, stale-binding).
  `sys_thread_set_priority` — missed by the first lifecycle pass — was likewise
  wrapped `sched_lock`-first (it reads `state` and mutates `queued_on` under the
  all-CPU locks, an unserialized Scheduling-group writer otherwise).

- **Scaffolding retained, not removed.** `queued_on` (#244), `wake_in_flight`
  (#160), `reply_tcb` (#289), and `context_saved` (#117/#207/#144) are all kept —
  each closes a distinct race the per-TCB lock does not subsume. `select_target_cpu`'s
  save-window pin is retained as a cross-CPU-spin-avoidance cache hint (it is a
  placement hint only, never an exclusivity mechanism).

## 4. Teardown co-fixes (audit findings B/C/E; D folded into the straggler pass)

These race fixes are independent of the lock and landed in the same migration
(each a verified-reachable race):
- **B (dealloc double-wakes):** the IPC dealloc arms (`event_queue_drop`,
  Notification dealloc and endpoint dealloc drain in `cap/object.rs`) snapshot the
  waiter and set `wake_in_flight` under the source lock (`eq`/`sig`/`ep`) before
  `enqueue_and_wake` — the discipline `notification_send`/`event_queue_post`
  already use. (`event_queue_drop`'s old "under eq.lock" comment was a lie — no
  lock was held; it now takes `eq.lock`. The endpoint drain holds `ep.lock` across
  the per-waiter `enqueue_and_wake` walk, which is sound because
  `ep.lock → sched_lock → run-queue` is the canonical order.)
- **C (sleep-list UAF/lost-wake):** `dealloc_object(Thread)` calls
  `sleep_list_remove(tcb)` before free (no such call existed before — a killed
  plain sleeper left a dangling pointer the next timer tick dereferenced), placed
  OUTSIDE the all-locks region (no `sched.lock`→`SLEEP_LIST` order edge). And
  `sleep_check_wakeups` SNAPSHOTS `(ipc_state, blocked_on)` under
  `SLEEP_LIST_LOCK` at pop (the `ExpiredWaiter` struct), claiming a plain sleeper
  with `wake_in_flight = 1` there so dealloc's existing gate covers an
  already-popped timer wake; the IPC arms claim under their own source lock at the
  win, and the per-entry claim never dereferences a possibly-freed TCB to choose
  its arm (correct by construction, not by timing).
- **E (stop vs shootdown):** `sys_thread_stop`'s cross-CPU drain spin
  (`syscall/thread.rs`) ran at IF=0 and could deadlock against an in-flight TLB
  shootdown; it now runs under `preempt_disable` + IF-enabled (the #207 pattern
  dealloc's UAF gate uses).
- **Reply-bound double-dispatch (the prime remaining #284 suspect):**
  `dealloc(server)` previously pre-set the client `bound`'s `state = Ready` under
  the SERVER's locks (not `bound`'s `sched_lock`) and linked it via the
  unconditional `enqueue_ready_thread`; a concurrent `dealloc(bound)` reaping the
  client marked it `Exited` under `bound.sched_lock`, and the two raced into a
  freed-but-linked run-queue corruption (#284). The fix stops pre-setting `Ready`:
  it deposits only the resume disposition (Interrupted/Kill) + refreshes
  `bound.wake_in_flight = 1`, leaves `bound` Blocked, and routes the deferred wake
  through the GATED `enqueue_and_wake` — which writes `bound`'s Scheduling-group
  fields under `bound`'s OWN `sched_lock` and, if `dealloc(bound)` already won the
  reap, observes `Exited` and ABORTS the link (no resurrection). This is why the
  `dealloc_object(Thread)` reply-bound wake is no longer a deliberate-`Ready`
  placer (§3).

## 5. Risks & fallback

- **PERF / #116 timing (primary risk):** the added `sched_lock` acquire in the
  dispatch hot path is the perturbation that historically widened the #116 idle
  stall. Burn-in `stress::concurrent_ipc` + the idle-stall reproducer both arches.
  If it regresses: fall back to a lock-free owner-token CAS on the dispatch fast
  path while keeping the full `Spinlock` on the wake/stop/dealloc slow paths.
- **Lock-order discipline (permanent):** source IPC → `sched_lock` → CPU lock,
  everywhere. `schedule()`'s release-then-acquire of `current.sched_lock` before
  `next.sched_lock` is the one place the order would invert if done naively.
- **Largest diff of the four designs** — landed incrementally with per-change
  burn-in.

## 6. Validation gate

The migration was gated on:

1. The full `burnin.yml` 12-cell matrix (x86_64+riscv64 × debug+release ×
   ktest/svctest/usertest, ×20) — all green, AND no regression vs the e0db329
   baseline (the baseline itself fails 3 cells: x86_64/release/usertest,
   riscv64/release/usertest, and #284 in x86_64/debug/usertest).
2. A targeted x86_64/debug/usertest ×200 (throwaway matrix branch) — zero double-
   enqueue / torn-SavedState / `ipi never acked` / stuck-`context_saved`.

Plus host `cargo xtask test`. The additive changes gated on the pass marker; the
`schedule()`/lifecycle and teardown co-fixes gated on the full matrix + the ×200
cell.

## 7. Known residual (separate surface)

One race is acknowledged but deliberately NOT closed by this redesign, because it
is a different review surface (the rare STOP path, not thread-churn) and needs a
server-lifetime mechanism this work does not introduce: `cancel_ipc_block(bound)`
CAS-dereferences the server's `reply_tcb` after snapshotting `blocked_on =
server`; a `dealloc(server)` that frees the server while `cancel` stalls past the
free is a latent use-after-free. This redesign does not widen it materially (the
reply-binding clear moved only within the dealloc path, still well before the
server free) but does not close it. It is tracked as issue #317 and needs a
refcount/epoch on the server's lifetime to fix. The lower-frequency cross-CPU
lost-wake / torn-context tail that survived this redesign's burn-in is tracked in
issue #314 (with #316).

---

## Summarized By

None
