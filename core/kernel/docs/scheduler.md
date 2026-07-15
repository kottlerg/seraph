# Scheduler Internals

The Seraph kernel scheduler is preemptive, priority-based, and SMP-aware. Scheduling
policy is minimal: the highest-priority runnable thread runs. SMT topology is used
to prefer spreading threads across physical cores rather than packing them onto one.

The scheduler interacts with two subsystems:

- **IPC** — IPC operations may block threads, wake threads, and trigger direct context
  switches (see [ipc-internals.md](ipc-internals.md))
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
not implement dynamic priority adjustment or aging.

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
Lowering is not special-cased; every assignment is checked against the band.

The kernel does **not** define a normal/elevated boundary. The numeric level
space is uniform; any partition into tiers is userspace policy, expressed by how
`SchedControl` bands are distributed:

- The root `SchedControl` spans `[1, PRIORITY_MAX]`, is created at boot, and is
  held by init.
- Init narrows it with `SYS_SCHED_SPLIT` into the baseline band `[1, 28]`
  (`sched_policy::BASELINE_PRIORITY_MAX` in `shared/ipc`) and an elevated
  remainder `[29, PRIORITY_MAX]` that never leaves init and dies at its reap —
  init's own boot thread (kernel-placed at `INIT_PRIORITY` = 30) is the only
  occupant above the baseline.
- Every spawned process receives a band through
  `ProcessInfo.sched_control_cap`: procmgr mints it from its baseline copy at
  create time, whole or `SYS_SCHED_SPLIT`-narrowed to the `[1, band_max]` the
  spawner requested, and creates the child's initial thread at the requested
  level under its own baseline authority. The per-service level map is pure
  userspace policy — `shared/ipc`'s `sched_policy` module for the
  init/procmgr/devmgr/vfsd-assigned levels, svcmgr `.svc` recipes
  (`priority = ...` / `sched_max = ...`) for supervised services.

`SchedControl` is the sole authority; see
[capability-model.md § SchedControl](../../../docs/capability-model.md) for the
cap shape, `SYS_SCHED_SPLIT`-based band splitting, and delegation. `cap_derive`
cannot shrink a band — it attenuates rights only.

### Run Queue Structure

Each CPU has a set of 32 run queues, one per priority level:

```rust
pub struct PerCpuScheduler
{
    /// Per-priority run queues. Each is an intrusive FIFO of ready TCBs.
    queues: [RunQueue; NUM_PRIORITY_LEVELS],

    /// Bitmask with one bit set per non-empty priority level.
    /// Allows O(1) selection of the highest non-empty priority.
    non_empty: u32,

    /// Currently running TCB on this CPU.
    current: *mut ThreadControlBlock,

    /// The idle TCB for this CPU.
    idle: *mut ThreadControlBlock,

    /// Lock protecting this struct. Held briefly during enqueue/dequeue.
    lock: Spinlock,
}

struct RunQueue
{
    head: Option<*mut ThreadControlBlock>,
    tail: Option<*mut ThreadControlBlock>,
}
```

The `non_empty` bitmask enables O(1) selection of the highest-priority non-empty
queue: `31 - non_empty.leading_zeros()` on x86-64 (using `BSR`), or
`31 - non_empty.leading_zeros()` on RISC-V. Enqueue sets the corresponding bit;
dequeue clears it if the queue becomes empty.

### Time Slice Policy

Each thread receives a configurable time slice. The preemption timer fires
periodically at a configurable interval; each timer interrupt decrements a per-thread
slice counter. When the counter reaches zero, the thread is preempted. The time
slice duration and timer period are implementation constants, not part of the ABI.

Time slices are equal across all priority levels. Priority determines which thread
runs next, not how much time each thread gets relative to others. A high-priority
thread that runs continuously will consume its full time slice before yielding to a
lower-priority thread (unless blocked).

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

The TCB is the kernel's per-thread state. It is allocated from the `tcb_cache` slab.

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

    /// Single-use reply capability for the pending IPC call (if any).
    reply_cap_slot: Option<ReplyCapability>,

    /// Pending send message buffer (used while BlockedOnSend).
    pending_send: PendingSendBuffer,

    /// Wakeup value (payload for notification/event wakeup).
    wakeup_value: u64,

    /// Badge from a wait set wakeup.
    wakeup_badge: u64,

    /// Intrusive IPC wait queue link.
    ipc_wait_next: Option<*mut ThreadControlBlock>,

    // === Context ===

    /// Architecture-specific saved register state.
    saved_state: arch::current::context::SavedState,

    /// Kernel stack top (used to restore RSP0/kernel SP on context switch).
    kernel_stack_top: VirtAddr,

    /// Address space this thread runs in.
    address_space: *mut AddressSpace,

    // === Capability reference ===

    /// CSpace bound to this thread (set via sys_thread_configure).
    cspace: *mut CSpace,

    // === Identity ===

    /// Unique thread identifier.
    thread_id: ThreadId,
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

Running ──(SYS_THREAD_STOP)──► Stopped
Running ──(SYS_THREAD_EXIT)──► Exited (TCB freed)
```

State transitions are governed by the per-field-group ownership rules in
[scheduling-internals.md](scheduling-internals.md). Cross-CPU writes to TCB
fields are subject to the lock hierarchy specified in that document.

---

## Context Switch Mechanism

### What Gets Saved and Restored

On each context switch, the arch `context::switch` function saves and restores the
minimal register set needed for correct execution:

**x86-64 (callee-saved registers):**
- `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`
- `rip` (return address, via the call to `context::switch`)
- `rsp` (stack pointer)
- The `fs_base` MSR (TLS base pointer)
- The kernel stack pointer is stored separately in the TSS `RSP0` field

Caller-saved registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`) are not saved
— by calling convention the caller has already saved them if needed.

**RISC-V (callee-saved registers):**
- `s0`–`s11` (saved registers)
- `ra` (return address — `context::switch` returns here)
- `sp` (stack pointer)
- `tp` (thread pointer, used for TLS)

The full user register file (all 31 general-purpose registers plus `sepc`, `sstatus`,
and the floating-point state) is saved in the thread's trap frame, not in
`SavedState`. `SavedState` holds only the kernel-mode callee-saved state.

### Switch Sequence

```
context_switch(current_tcb, next_tcb):
    // 1. Update the kernel trap stack pointer so the next privilege-level
    //    transition (syscall, interrupt, or exception) lands on next_tcb's stack.
    //    x86-64: writes TSS.RSP0 and SYSCALL_KERNEL_RSP.
    //    RISC-V: writes sscratch (read by trap_entry to switch from user stack).
    arch::current::cpu::set_kernel_trap_stack(next_tcb.kernel_stack_top)

    // 2. Switch address space if different.
    if current_tcb.address_space != next_tcb.address_space:
        arch::current::paging::activate(next_tcb.address_space.root_phys)
        // Update active_cpus on both address spaces (for TLB shootdown tracking)

    // 3. Perform the register-level switch.
    //    Saves current callee-saved registers, restores next's, returns into next_tcb.
    arch::current::context::switch(
        &mut current_tcb.saved_state,
        &next_tcb.saved_state,
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

When a new thread is created (`SYS_CAP_CREATE_THREAD`):

- If `cpu_affinity` is `AFFINITY_ANY`, the kernel assigns it to the CPU with the
  lowest total thread count (a simple load metric)
- If `cpu_affinity` specifies a CPU, the thread is assigned there unconditionally

The assignment is recorded in `tcb.preferred_cpu` and used for subsequent wakeups.

### Load Balancing

A pull-based balancer runs on every CPU's `timer_tick` (see
`sched::try_pull_balance`). It consumes the per-CPU `CPU_LOAD` counters
maintained by `enqueue` / `dequeue_highest` / `remove_from_queue` and
migrates at most one `Ready` thread per tick per CPU.

Victim selection is mode-dependent:

- **Loaded CPU (`my_load > 0`)** — pick a pseudo-random victim
  (splitmix-style hash of the global `LOAD_BALANCE_TICK` counter and the
  local CPU id). Skip if the victim is not significantly busier than us
  (`their_load <= my_load + IMBALANCE_THRESHOLD`).
- **Idle CPU (`my_load == 0`)** — scan all other CPUs and pull from the
  heaviest. Scanning is cheap (one Relaxed atomic load per CPU) and
  guarantees an idle CPU finds work on the first tick that sees an
  imbalance. Pure random victim selection converges only
  probabilistically and on small topologies sometimes wastes many ticks
  before picking the busy CPU.

Migration uses the shared `sched::migrate_ready_thread`-style helper
`pull_unpinned_ready(src_cpu, dst_cpu)`:

```
pull_unpinned_ready(src, dst):
    if !try_lock(min(src, dst).scheduler.lock): return   // ascending-CPU order
    if !try_lock(max(src, dst).scheduler.lock):
        unlock(min); return
    tcb = src.find_runnable(|t| t.cpu_affinity == AFFINITY_ANY)
    if tcb is None: unlock both; return
    src.remove_from_queue(tcb, tcb.priority)  // decrements CPU_LOAD[src]
    dst.enqueue(tcb, tcb.priority)            // increments CPU_LOAD[dst]
    tcb.preferred_cpu = dst
    set_reschedule_pending_for(dst)
    unlock both
    wake_idle_cpu(dst)                        // always-IPI
```

Lock order follows scheduling-internals.md § Lock Hierarchy rule 4
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
  `IMBALANCE_THRESHOLD` is observed.

---

## SMT Awareness

On systems with Simultaneous Multi-Threading (Hyper-Threading on Intel, SMT on AMD),
multiple logical CPUs share physical execution resources on the same core. The
scheduler is aware of this topology.

### Topology Detection

Physical core membership is detected at boot via CPUID (x86-64 extended topology leaf)
or the device tree (RISC-V). Each `PerCpuData` records:

```rust
struct PerCpuData
{
    cpu_id: u32,
    physical_core_id: u32,
    smt_sibling_mask: u64,  // bitmask of logical CPUs sharing this physical core
}
```

### Scheduling Preference

The load balancer prefers to spread threads across distinct physical cores rather than
filling one core's SMT siblings:

```
when assigning a new thread to a CPU:
    prefer a CPU whose physical_core is not already occupied by another thread
    over a CPU that is a SMT sibling of a running thread
```

This preference is soft — if all physical cores are occupied, threads are distributed
across SMT siblings. The preference is implemented as a tie-break in the load metric
rather than as a hard constraint.

SMT awareness has no effect on the scheduler's correctness — it is a performance
optimisation to avoid resource sharing between threads that could otherwise run
independently.

---

## Preemption

### Timer-Driven Preemption

The preemption timer (configured in Phase 5 of initialization) fires at the
configured periodic interval on each CPU. The timer interrupt handler:

```
timer_interrupt_handler():
    current_tcb.slice_remaining -= 1
    if current_tcb.slice_remaining == 0:
        current_tcb.slice_remaining = TIME_SLICE_TICKS
        // Check if a higher or equal-priority thread is waiting
        if any_runnable_at_or_above(current_tcb.priority):
            enqueue(current_tcb, current_tcb.priority)
            next = pick_next(current_cpu)
            context_switch(current_tcb, next)
    // else: continue current thread
```

The preemption check is: "is there anyone else ready to run at this priority or
higher?" If yes, the current thread is re-enqueued and another is picked. If not,
the thread continues without preemption even if its time slice expired.

This ensures that a thread at a unique highest priority is never preempted needlessly
— only when a peer or superior competitor exists.

### Kernel-Mode Preemption Points

The kernel is preemptible in most kernel-mode execution paths. A thread executing a
syscall may be preempted while the timer fires if:

- No spinlock is held
- No interrupt-disabled section is active

Spinlock-hold intervals must be short (< ~10 µs) by policy. Code that holds a
spinlock must not call anything that blocks or takes another lock (except in defined
lock-ordering sequences).

The scheduler does not preempt the kernel while a spinlock is held. Instead, a
`preemption_pending` flag is set per-CPU; preemption occurs when the last spinlock
is released.

---

## Idle Thread

Each CPU has one idle thread (priority 0) that runs when no other thread is ready.

```rust
fn idle_thread_entry(cpu_id: u64) -> !
{
    loop
    {
        // Check for pending work before halting, to avoid a race where
        // a wakeup IPI arrives between the check and the halt instruction.
        if has_runnable_threads(cpu_id)
        {
            schedule();
        }
        // Halt until the next interrupt (timer or IPI).
        arch::current::cpu::halt_until_interrupt();
    }
}
```

The idle thread is the only thread that cannot be preempted by the timer (its time
slice counter is not decremented — priority 0 is handled specially). It yields
voluntarily via the `schedule()` call when work becomes available.

---

## Priority Inversion Mitigation

The kernel does not implement priority inheritance. The rationale: priority inheritance
adds significant complexity for a benefit that only applies to mutex-based shared
state, which Seraph avoids by design (message passing preferred over shared memory).

The primary locking primitive in the kernel is a spinlock, not a blocking mutex.
Spinlocks do not cause priority inversion — the waiting thread spins rather than
blocking. Spinlock-hold intervals are bounded by policy.

If priority inversion is observed in practice at the userspace IPC level (a
high-priority thread blocked waiting for a low-priority server), the correct fix is
to use a higher-priority server thread, not to add kernel priority inheritance.

---

## Affinity

### Hard Affinity

`tcb.cpu_affinity != AFFINITY_ANY` specifies a single CPU the thread must run on.
Wakeups always enqueue the thread on the specified CPU's run queue. If the
specified CPU is offline, `SYS_CAP_CREATE_THREAD` fails with `InvalidArgument`.

Hard affinity is intended for:
- Interrupt-handling threads that must run on specific CPUs (NUMA, IRQ affinity)
- Real-time threads that must not suffer migration latency

### Active migration on affinity change

`SYS_THREAD_SET_AFFINITY` enforces the new affinity immediately rather than
deferring to the next enqueue:

- **Ready** thread queued on the old CPU: the syscall calls
  `migrate_ready_thread` which dequeues the TCB from the source CPU's run
  queue and re-enqueues it on the destination under both scheduler locks
  (lower-numbered CPU first; see scheduling-internals.md § Lock Hierarchy
  rule 4) and sends a wakeup IPI to the destination.
- **Running** thread on a different CPU: the syscall sets the
  **source** CPU's reschedule-pending flag and sends a wakeup IPI to the
  **source** CPU (where the thread is currently running). The IPI itself
  does not call `schedule()`; the running thread observes the new
  affinity at its next entry to `schedule()` — preempt-on-slice-expiry,
  voluntary yield, or IPC block. The re-enqueue site in `schedule()`
  checks `cpu_affinity != current_cpu` and routes the requeue cross-CPU
  via `enqueue_and_wake` (which then sets the destination's
  reschedule-pending flag and IPIs it) instead of doing a local enqueue.
  Worst-case latency is therefore one time slice
  (`TIME_SLICE_TICKS` × tick period), not one tick.
- **Blocked / Stopped / Created**: the new affinity takes effect on the
  next wake via `select_target_cpu`; no migration work is needed.

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

[kernel/README.md](../README.md)
