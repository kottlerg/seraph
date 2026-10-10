# Scheduler Internals

The Seraph kernel scheduler is preemptive, priority-based, and SMP-aware. Scheduling
policy is minimal: whenever a CPU schedules (block, yield, slice expiry, or idle wake), it
selects its highest-priority runnable thread. A wake does not preempt a running thread, so a
newly runnable higher-priority thread waits until the running thread blocks or yields or its
slice expires. Using SMT topology to spread threads across physical cores rather than
packing them onto one is design intent, not yet implemented
([#267](https://github.com/kottlerg/seraph/issues/267)).

The scheduler interacts with two subsystems:

- **IPC** — IPC interacts with the scheduler only through its park and wake primitives and
  performs no direct context switch (see
  [ipc-internals.md § IPC Scheduling Interaction](ipc-internals.md#ipc-scheduling-interaction))
- **Architecture layer** — context save/restore and the preemption timer are implemented
  by the arch-dispatch surface defined in [arch-interface.md](arch-interface.md)

---

## Scheduling Algorithm

### Priority Levels

There are `NUM_PRIORITY_LEVELS` = 32 priority levels, numbered 0 (lowest) through
31 (highest):

- **Priority 0** — reserved for idle threads (one per CPU; never preempted).
- **Priorities 1–30** — available to userspace. `PRIORITY_MAX` = 30.
- **Priority 31** — reserved; cannot be requested by userspace.

Threads are created at an explicit priority stated at `SYS_CAP_CREATE_THREAD`
time through its `SchedControl`-cap and priority arguments: with no
`SchedControl` (both arguments zero) the thread is created at the floor
(`PRIORITY_MIN` = 1); with a `SchedControl` cap, priority 0 selects the cap's
band floor and a nonzero priority must lie within the cap's `[min, max]` band.
Priority is changed afterwards via `SYS_THREAD_SET_PRIORITY`. The kernel does
not implement dynamic priority adjustment or aging. Both syscalls' argument and error
contracts are in [syscalls.md](syscalls.md).

The one kernel-assigned exception is init's boot thread, created at
`INIT_PRIORITY` (= 30, the top settable level): init is the root of all
userspace authority and nothing may preempt it.

### Priority Authority

Assigning a priority is capability-gated. `SYS_THREAD_SET_PRIORITY` takes two
caps: a Thread cap with the Control right (selecting *which* thread) and a
`SchedControl` cap (governing *which level*). A `SchedControl` carries a
`[min, max]` priority band; the call succeeds only if the requested level lies
within that band. `SYS_CAP_CREATE_THREAD` applies the same rule at creation:
placing a new thread above the floor requires a `SchedControl` cap whose band
covers the level. There is no ambient authority — a process holding no
`SchedControl` (or one whose band excludes the level) cannot set that priority.
Lowering is not special-cased; every assignment is checked against the band. See
[syscalls.md](syscalls.md) § `SYS_THREAD_SET_PRIORITY` for the band check and its errors.

The kernel does **not** define a normal/elevated boundary. The numeric level
space is uniform; any partition into tiers is userspace policy, expressed by how
`SchedControl` bands are distributed:

- The root `SchedControl` spans `[1, PRIORITY_MAX]`, is created at boot, and is
  held by init.
- Init narrows it with `SYS_SCHED_SPLIT` into the baseline band `[1, 28]`
  (`sched_policy::BASELINE_PRIORITY_MAX` in `shared/ipc`) and an elevated
  remainder `[29, PRIORITY_MAX]` that never leaves init — init's own boot thread
  (kernel-placed at `INIT_PRIORITY` = 30) is the only occupant above the
  baseline. After init's reap the remainder stays in init's CSpace, which the
  kernel pins (it is the root CSpace), so it remains alive but unreachable;
  releasing it at the reap is design intent, not yet implemented
  ([#443](https://github.com/kottlerg/seraph/issues/443); see
  [process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap)).
- Every spawned process receives a band through
  `ProcessInfo.sched_control_cap`. Init hands memmgr and procmgr each a copy of the
  baseline, and procmgr mints every other process's band from its copy at
  create time, whole or `SYS_SCHED_SPLIT`-narrowed to the `[1, band_max]` the
  spawner requested, and creates the child's initial thread at the requested
  level under its own baseline authority. The per-service level map is pure
  userspace policy — `shared/ipc`'s `sched_policy` module for the
  init/procmgr/devmgr/vfsd-assigned levels, svcmgr `.svc` recipes
  (`priority = ...` / `sched_max = ...`) for supervised services. The mint is specified in
  [procmgr ipc-interface.md](../../../services/procmgr/docs/ipc-interface.md) § Label 1:
  `CREATE_PROCESS`.

`SchedControl` is the sole authority; see
[capability-model.md § SchedControl](../../../docs/capability-model.md) for the
cap shape, `SYS_SCHED_SPLIT`-based band splitting, and delegation. `cap_derive`
cannot shrink a band — it attenuates rights only ([syscalls.md](syscalls.md) § `SYS_CAP_DERIVE`).

### Run Queue Structure

Each CPU has a set of 32 run queues, one per priority level:

```rust
pub struct PerCpuScheduler
{
    /// Per-priority run queues. Each is an intrusive FIFO of ready TCBs.
    queues: [RunQueue; NUM_PRIORITY_LEVELS],

    /// Bitmask with one bit set per non-empty priority level.
    /// Allows O(1) selection of the highest non-empty priority.
    non_empty: AtomicU32,

    /// Currently running TCB on this CPU.
    current: *mut ThreadControlBlock,

    /// The idle TCB for this CPU.
    idle: *mut ThreadControlBlock,

    /// Lock protecting this struct. Held briefly during enqueue/dequeue.
    lock: Spinlock,

    /// Run-queue load counter; read via current_load() by the load balancer and select_target_cpu.
    load: AtomicU32,
}

struct RunQueue
{
    head: Option<*mut ThreadControlBlock>,
    tail: Option<*mut ThreadControlBlock>,
}
```

The `non_empty` bitmask enables O(1) selection of the highest-priority non-empty
queue: `31 - non_empty.leading_zeros()` (`PerCpuScheduler::dequeue_highest`), the same
expression on both architectures. Enqueue sets the corresponding bit;
dequeue clears it if the queue becomes empty.

### Time Slice Policy

Each thread receives a configurable time slice. The preemption timer fires
periodically at a configurable interval; each timer interrupt decrements a per-thread
slice counter. When the counter reaches zero, the thread is preempted. The time
slice duration and timer period are implementation constants, not part of the ABI.

Time slices are equal across all priority levels. Priority determines which thread
runs next, not how much time each thread gets relative to others. Slice expiry never hands
the CPU to a lower level: the expiring thread is requeued at its level's tail and the highest
non-empty level runs next. A thread that never blocks keeps any lower-priority thread on its
CPU from running until the higher-priority thread blocks or the load balancer moves the
lower-priority thread elsewhere.

Within a priority level, threads share the CPU in round-robin order (FIFO queue
drained cyclically).

### Selection

```
pick_next(cpu):
    // non_empty is a bitmask; find highest set bit
    if non_empty == 0: return idle_tcb
    priority = highest_set_bit(non_empty)
    tcb = queues[priority].dequeue()
    if queues[priority].is_empty():
        non_empty &= ~(1 << priority)
    return tcb
```

---

## Thread Control Block

The TCB is the kernel's per-thread state. A thread's TCB lives in its Thread slab, which
`SYS_CAP_CREATE_THREAD` retypes from the caller's Memory capability (boot code carves init's
thread from the SEED reserve): the kernel stack, then the page holding the `ThreadObject` and
TCB, then the extended-state area (see
[memory-internals.md § Kernel Stack Allocation](memory-internals.md#kernel-stack-allocation)).
Idle threads' TCBs live in a per-CPU array allocated at boot.

```rust
pub struct ThreadControlBlock
{
    // === Scheduling state ===

    /// Current state of this thread.
    state: ThreadState,

    /// Scheduling priority (0–31).
    priority: u8,

    /// Remaining time slice ticks before preemption.
    slice_remaining: u32,

    /// Which CPU this thread is assigned to (or AFFINITY_ANY).
    cpu_affinity: u32,

    /// Soft affinity: preferred CPU (hint only; overridden by load balancing).
    preferred_cpu: u32,

    /// Intrusive run-queue link (next TCB in the same priority queue).
    run_queue_next: Option<*mut ThreadControlBlock>,

    // === IPC state ===

    /// Inline message buffer for in-flight IPC data (the staged message).
    ipc_msg: Message,

    /// Caller bound for the implicit reply (published at the call/recv rendezvous;
    /// cleared by the reply or by a cancel, dealloc, or rollback claim).
    reply_tcb: AtomicPtr<ThreadControlBlock>,

    /// Wakeup value (notification bits, event payload, or wait-set member badge).
    wakeup_value: u64,

    /// Intrusive IPC wait queue link.
    ipc_wait_next: Option<*mut ThreadControlBlock>,

    // === Context ===

    /// Architecture-specific saved register state.
    saved_state: arch::current::context::SavedState,

    /// Kernel stack top (used to restore RSP0/kernel SP on context switch).
    kernel_stack_top: u64,

    /// Address space this thread runs in.
    address_space: *mut AddressSpace,

    // === Capability reference ===

    /// CSpace bound to this thread (set at SYS_CAP_CREATE_THREAD).
    cspace: *mut CSpace,

    // === Identity ===

    /// Unique thread identifier.
    thread_id: u32,
}
```

### Thread States

```
Created ──(SYS_THREAD_START)──► Ready ──(scheduled)──► Running
                                  ▲                       │
                                  │    (preempted or      │
                                  │     yield)            │
                                  │◄──────────────────────┘
                                  │
                          (IPC block, notification wait, etc.)
                                  │
                                Blocked
                                  │
                          (wakeup / IPC reply)
                                  │
                                  ▼
                                Ready

Running / Ready / Blocked ──(SYS_THREAD_STOP)──► Stopped ──(SYS_THREAD_START)──► Ready
Running ──(SYS_THREAD_EXIT)──► Exited (TCB freed when its last Thread capability is deleted)
```

Per-syscall transitions are specified in
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#lifecycle-state-machine)
§ Lifecycle State Machine.

State transitions are governed by the per-field-group ownership rules in
[scheduling-internals.md](scheduling-internals.md). Cross-CPU writes to TCB
fields are subject to the lock hierarchy specified in that document.

---

## Context Switch Mechanism

### What Gets Saved and Restored

On each context switch, the arch `context::switch` function (see
[arch-interface.md](arch-interface.md) § `context`) saves and restores the minimal register
set needed for correct execution:

**x86-64 (callee-saved registers):**
- `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`
- `rip` (return address, via the call to `context::switch`)
- `rsp` (stack pointer)
- The `fs_base` MSR (TLS base pointer)
- `rflags`
- The kernel stack pointer is stored separately in the TSS `RSP0` field

Caller-saved registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`) are not saved
— by calling convention the caller has already saved them if needed.

**RISC-V (callee-saved registers):**
- `s0`–`s11` (saved registers)
- `ra` (return address — `context::switch` returns here)
- `sp` (stack pointer)
- `a0` (argument delivered on a new kernel thread's first entry; meaningful only at
  thread creation)

`tp` is not in `SavedState`: it is a per-hart kernel register that is never
thread-switched, and the user-mode TLS pointer lives in the trap frame's `tp`.

The full user register file (all 31 general-purpose registers on RISC-V, plus `sepc`
and `sstatus`) is saved in the thread's trap frame, not in `SavedState`. `SavedState`
holds only the kernel-mode callee-saved state. Floating-point, SIMD, and vector state
is in neither: it lives in the TCB's extended-state area, saved eagerly by the arch
`fpu::switch_out_save` on switch-out of a user thread and restored lazily on the
thread's first FP/SIMD/vector instruction after it is switched back in (`#NM` on
x86-64, the illegal-instruction trap with `sstatus.FS`/`VS` Off on RISC-V).

### Switch Sequence

```
context_switch(current_tcb, next_tcb):
    // 1. Update the kernel trap stack pointer so the next privilege-level
    //    transition (syscall, interrupt, or exception) lands on next_tcb's stack.
    //    x86-64: writes TSS.RSP0 and PerCpuData::kernel_rsp (the SYSCALL entry stack).
    //    RISC-V: writes PerCpuData::kernel_rsp (read by trap_entry to switch from the
    //    user stack). A kernel/idle thread passes 0.
    arch::current::cpu::set_kernel_trap_stack(next_tcb.kernel_stack_top)

    // 2. Switch address space if different.
    if current_tcb.address_space != next_tcb.address_space:
        arch::current::paging::activate(next_tcb.address_space.root_phys)
        // Update active_cpus on both address spaces (for TLB shootdown tracking)

    // 3. Perform the register-level switch.
    //    Saves current callee-saved registers, publishes context_saved = 1 once the
    //    save is committed, restores next's, returns into next_tcb.
    arch::current::context::switch(
        &mut current_tcb.saved_state,
        &next_tcb.saved_state,
        &current_tcb.context_saved,
    )
    // Execution continues in next_tcb from here.
```

---

## SMP Scheduling

### Per-CPU Run Queues

Each CPU maintains its own `PerCpuScheduler`. Threads are assigned to CPUs. A thread
on CPU N's run queue runs only on CPU N unless migrated (see Load Balancing). This
design eliminates the need for a global run queue lock on the common path and is
cache-friendly — a thread's TCB is typically hot in CPU N's caches.

### Thread Assignment

`SYS_CAP_CREATE_THREAD` takes no affinity argument: every thread is created with
`cpu_affinity = AFFINITY_ANY` and `preferred_cpu = 0`. `SYS_THREAD_START` places it via
`select_target_cpu`. A hard affinity set by `SYS_THREAD_SET_AFFINITY` before the start wins
unconditionally. Otherwise the thread stays on `preferred_cpu` if that CPU's load
(`current_load()`) is within `LOAD_BALANCE_IMBALANCE_THRESHOLD` of the least-loaded CPU's,
and goes to the least-loaded CPU if not. The placement is recorded in `tcb.preferred_cpu`
and used for subsequent wakeups.

### Load Balancing

A pull-based balancer runs on every CPU's `timer_tick` (see
`sched::try_pull_balance`). It consumes each CPU's run-queue load counter
(`PerCpuScheduler::current_load()`, maintained by `enqueue` / `dequeue_highest` /
`remove_from_queue`) and migrates at most one `Ready` thread per tick per CPU.

Victim selection is mode-dependent:

- **Loaded CPU (`my_load > 0`)** — pick a pseudo-random victim
  (splitmix-style hash of the global `LOAD_BALANCE_TICK` counter and the
  local CPU id). Skip if the victim is not significantly busier than us
  (`their_load <= my_load + LOAD_BALANCE_IMBALANCE_THRESHOLD`).
- **Idle CPU (`my_load == 0`)** — scan all other CPUs and pull from the
  heaviest. Scanning is cheap (one Relaxed atomic load per CPU) and
  guarantees an idle CPU finds work on the first tick that sees an
  imbalance. Pure random victim selection converges only
  probabilistically and on small topologies sometimes wastes many ticks
  before picking the busy CPU.

Migration goes through `pull_unpinned_ready(src_cpu, dst_cpu)`, which shares the
validate-then-move core `relocate_ready_thread` with `migrate_ready_thread`:

```
pull_unpinned_ready(src, dst):
    if !try_lock(min(src, dst).scheduler.lock): return   // ascending-CPU order
    if !try_lock(max(src, dst).scheduler.lock):
        unlock(min); return
    (tcb, prio) = src.find_runnable(|t| t.cpu_affinity == AFFINITY_ANY
                                        && t.context_saved.load(Acquire) == 1)
    if tcb is None: unlock both; return
    if !try_lock(tcb.sched_lock): unlock both; return  // taken after run-queue locks
    // relocate_ready_thread: revalidate under sched_lock, then move.
    moved = false
    if tcb.state == Ready && tcb.context_saved == 1
       && (tcb.cpu_affinity == AFFINITY_ANY || tcb.cpu_affinity == dst):
        src.remove_from_queue(tcb, prio)       // decrements src's load counter
        dst.enqueue(tcb, prio)                 // increments dst's load counter
        tcb.preferred_cpu = dst
        set_reschedule_pending_for(dst)
        moved = true
    unlock tcb.sched_lock; unlock both
    if moved: wake_idle_cpu(dst)               // always-IPI
```

The `context_saved == 1` predicate is the load-balancer liveness gate of
[scheduling-internals.md](scheduling-internals.md) § Cross-CPU TCB Ownership step 11: a
`Ready` thread with `context_saved == 0` is mid-handoff, still `current` on `src`, and
relocating it would dispatch it on two CPUs at once (#314/#293). The candidate's
`sched_lock` is try-acquired because it is taken after the run-queue locks, the reverse of
the canonical order; a failed try defers the pull. `relocate_ready_thread` re-checks
`Ready`, `context_saved == 1`, and affinity under that `sched_lock`. This narrows, but does
not close, a race with `sys_thread_set_affinity` between the `find_runnable` predicate and
the move. That syscall writes `cpu_affinity` without the target's `sched_lock`
([#443](https://github.com/kottlerg/seraph/issues/443)), so a pin landing after the re-check
can leave the thread linked, and dispatched, on `dst` until its next `schedule()`
cross-affinity requeue.

Lock order follows [scheduling-internals.md](scheduling-internals.md) § Lock Hierarchy rule 4
(ascending CPU id), and both acquisitions are **try-locks**: the pull runs
from every CPU's timer tick with interrupts disabled, and under a
pinned-heavy imbalance every idle CPU converges on the same victim every
tick. Queuing there forms a FIFO ticket convoy of interrupts-off spinners
that silences ticks, IPIs, and serial output system-wide and livelocks the
guest under host vCPU oversubscription (#375). A contended pull is simply
deferred to a later tick. Pinned threads (`cpu_affinity != AFFINITY_ANY`)
are invisible to the `find_runnable` predicate and are never migrated.

Hot-path cost per CPU per tick:
- Idle CPU: one Relaxed load per remote CPU to find the heaviest victim.
- Loaded CPU: one Relaxed increment + one Relaxed load for the victim.
- Scheduler locks are try-acquired, and only when an imbalance above
  `LOAD_BALANCE_IMBALANCE_THRESHOLD` is observed.

---

## SMT Awareness

On systems with Simultaneous Multi-Threading (Hyper-Threading on Intel, SMT on AMD),
multiple logical CPUs share physical execution resources on the same core.

SMT topology awareness is design intent, not yet implemented
([#267](https://github.com/kottlerg/seraph/issues/267)). The kernel records no physical-core
or sibling topology, and `try_pull_balance` and `select_target_cpu` place threads by per-CPU
`current_load()` alone. The subsections below describe the intended design.

### Topology Detection

Physical core membership would be detected at boot via CPUID (x86-64 extended topology
leaf) or the device tree (RISC-V). Each `PerCpuData` would record:

```rust
struct PerCpuData
{
    cpu_id: u32,
    physical_core_id: u32,
    smt_sibling_mask: u64,  // bitmask of logical CPUs sharing this physical core
}
```

### Scheduling Preference

The load balancer would prefer to spread threads across distinct physical cores rather
than filling one core's SMT siblings:

```
when assigning a new thread to a CPU:
    prefer a CPU whose physical_core is not already occupied by another thread
    over a CPU that is a SMT sibling of a running thread
```

This preference would be soft — if all physical cores are occupied, threads would be
distributed across SMT siblings. The preference would be implemented as a tie-break in the
load metric rather than as a hard constraint.

SMT awareness would have no effect on the scheduler's correctness — it is a performance
optimisation to avoid resource sharing between threads that could otherwise run
independently.

---

## Preemption

### Timer-Driven Preemption

The preemption timer (started on the BSP in
[Phase 5](initialization.md#phase-5-architecture-hardware-initialisation) and on each AP
during its [Phase 8](initialization.md#phase-8-scheduler-and-smp-bringup) startup) fires at
the configured periodic interval on each CPU. The tick handler, `timer_tick`, runs:

```
timer_tick():
    if current.slice_remaining == 0:          // idle thread
        try_pull_balance(cpu); return
    current.slice_remaining -= 1
    if current.slice_remaining == 0:
        current.slice_remaining = TIME_SLICE_TICKS
        try_pull_balance(cpu)
        if preemption_disabled(): return      // see § Kernel-Mode Preemption Points
        schedule(requeue_current = true)      // requeue at its level's tail, then dequeue_highest
    else:
        try_pull_balance(cpu)
```

On slice expiry the current thread goes back to the tail of its priority's FIFO, and
`dequeue_highest` picks the next thread. If no other thread at its priority or higher is
queued, the current thread is reselected and keeps running with no context switch, even
though its slice expired.

This ensures that a thread at a unique highest priority is never preempted needlessly
— only when a peer or superior competitor exists.

### Kernel-Mode Preemption Points

Syscall context is not preemptible. Syscall entry masks interrupts, and they stay masked
for the whole syscall except in bounded preempt-disabled, interrupt-enabled windows. When
`timer_tick` reaches a slice expiry while `percpu::preemption_disabled()` holds, it resets
the slice and skips the switch, and the thread is rescheduled at its next slice expiry.
Kernel-mode preemption therefore happens only at a slice expiry with preemption enabled.
The model, the spinlock hold-time bound, and lock ordering are specified in
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) (its
numbered ordering rules and the "Lock primitive" and "Bare spin locks" paragraphs).

---

## Idle Thread

Each CPU has one idle thread (priority 0) that runs when no other thread is ready.

Each iteration of `idle_thread_entry` first drains this CPU's deferred-reclaim queue
(`cap::object::drain_deferred_reclaim`) with interrupts enabled. It then masks interrupts
and checks `take_reschedule_pending` and `has_runnable` together. If either is set, it
re-enables interrupts and calls `schedule(true)` when the run queue has work, then loops.
Otherwise it halts through the atomic enable-and-halt `arch::current::cpu::halt_until_interrupt`.
Masking before the check means a wake IPI that lands between the check and the halt stays
pending and ends the halt. The protocol is specified in
[scheduling-internals.md](scheduling-internals.md#wake-protocol-invariants) § Wake Protocol
Invariants.

The timer never preempts the idle thread. Its `slice_remaining` is fixed at 0, and
`timer_tick` returns before the decrement for a zero slice; the check keys on the zero
slice, not on priority 0. Because its time slice is permanently zero, the timer never
deschedules it inside a teardown wait. The idle thread yields voluntarily via
`schedule(true)` when its run queue has work.

---

## Priority Inversion Mitigation

The kernel does not implement priority inheritance. The rationale: priority inheritance
adds significant complexity for a benefit that only applies to mutex-based shared
state, which Seraph avoids by design (message passing preferred over shared memory).

The primary locking primitive in the kernel is a spinlock, not a blocking mutex.
Spinlocks do not cause priority inversion: no context that holds one can be descheduled, so
a waiter spins only for the holder's bounded hold time, never behind a preempted holder.
Spinlock-hold intervals are bounded by policy
([scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy),
"Lock primitive").

If priority inversion is observed in practice at the userspace IPC level (a
high-priority thread blocked waiting for a low-priority server), the correct fix is
to use a higher-priority server thread, not to add kernel priority inheritance.

---

## Affinity

### Hard Affinity

`tcb.cpu_affinity != AFFINITY_ANY` specifies a single CPU the thread must run on.
Wakeups always enqueue the thread on the specified CPU's run queue. If the
specified CPU id is not below `CPU_COUNT`, `SYS_THREAD_SET_AFFINITY` fails with
`InvalidArgument`. `SYS_CAP_CREATE_THREAD` takes no affinity and creates every thread with
`cpu_affinity = AFFINITY_ANY`.

Hard affinity is intended for:
- Interrupt-handling threads that must run on specific CPUs (NUMA, IRQ affinity)
- Real-time threads that must not suffer migration latency

### Active migration on affinity change

`SYS_THREAD_SET_AFFINITY` starts the migration during the call rather than leaving it to the
next enqueue ([syscalls.md](syscalls.md) § `SYS_THREAD_SET_AFFINITY`). Clearing to
`AFFINITY_ANY`, or naming the CPU in the thread's `preferred_cpu`, does no migration work.
Otherwise, by target state:

- **Ready** thread queued on the old CPU: the syscall calls
  `migrate_ready_thread`. It takes the target's `sched_lock` and then both scheduler locks
  (lower-numbered CPU first; see [scheduling-internals.md](scheduling-internals.md) § Lock
  Hierarchy rule 4) and revalidates `Ready`, `context_saved == 1`, and the affinity under
  them (`relocate_ready_thread`). It then moves the TCB from the source CPU's run queue to
  the destination's and, on a committed move, sends a wakeup IPI to the destination. A lost
  race leaves the thread where it is.
- **Running** thread on a different CPU: the syscall sets the
  **source** CPU's reschedule-pending flag and sends a wakeup IPI to the
  **source** CPU (where the thread is currently running). The IPI itself
  does not call `schedule()`; the running thread observes the new
  affinity at its next entry to `schedule()` — preempt-on-slice-expiry,
  voluntary yield, or IPC block. The re-enqueue site in `schedule()`
  checks `cpu_affinity != current_cpu` and routes the requeue cross-CPU —
  linking the thread directly on the destination's run queue, setting its
  reschedule-pending flag, and IPIing it — instead of doing a local enqueue
  (see [scheduling-internals.md](scheduling-internals.md) § ThreadState Transitions).
  Worst-case latency is therefore one time slice
  (`TIME_SLICE_TICKS` × tick period), not one tick.
- **Blocked / Stopped / Created**: the new affinity takes effect on the
  next wake via `select_target_cpu`; no migration work is needed.

The syscall writes `cpu_affinity`, and reads `preferred_cpu` and `state`, without the target's
`sched_lock`, so those accesses race other CPUs' scheduler paths
([#443](https://github.com/kottlerg/seraph/issues/443)). `lookup_cap` does not pin the target
Thread (see [capability-internals.md](capability-internals.md) § Storage: Hybrid Two-Level Radix
and [#443](https://github.com/kottlerg/seraph/issues/443)). The outcomes above hold only absent
those hazards.

### Soft Affinity

`tcb.preferred_cpu` records the CPU the thread was last assigned to. The
wake-side placement (`select_target_cpu`) honours it as a sticky cache-
warmth hint: it scans all CPUs for `min_load`, and if `preferred_cpu`'s
load is within `LOAD_BALANCE_IMBALANCE_THRESHOLD` of `min_load`, the
thread is re-placed on its preferred CPU. Beyond that threshold the
thread is migrated to the least-loaded CPU. The threshold is the same
hysteresis the pull balancer uses to decide an imbalance is real, so
soft affinity, wake placement, and pull balancing share one knob.

Hard affinity (`cpu_affinity != AFFINITY_ANY`) and save-window pinning
(`context_saved == 0`) both short-circuit ahead of the soft-affinity
check; see `select_target_cpu` in `core/kernel/src/sched/mod.rs` for
the full policy.

The scheduler does not expose soft affinity as a syscall parameter — it is an internal
optimisation.

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Initialization Sequence](initialization.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md)
